// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Reaching user memory without dereferencing a user address (ADR 0048,
//! rule 5; kernel specification, "Access to user memory").
//!
//! The kernel walks the address space's tables in software, through its
//! direct map, and reaches each frame through the direct map too. A page
//! that isn't mapped fails at once with "not resident", and a mapping of
//! device memory with "not RAM". A span is checked page by page before any
//! byte moves, so a call moves all of its bytes or none. The kernel never
//! takes a fault here, whether or not the processor has PAN.
//!
//! C15: a write also breaks copy-on-write and marks the page dirty; C10
//! checks only the mapping's write right. The pinned IPC buffer (C14) is
//! reached through its pin, not through these functions.

use super::phys::{DirectMem, Window};
use super::space::AddressSpace;
use kmem::user::{Access, Bytes, DirectMap, UserError, copy_from_user, copy_to_user};

/// Bytes of RAM through the direct map. The walk and the direct-map check
/// come first, so every physical address here is RAM that the direct map
/// covers with the access needed.
///
/// User memory is shared with threads outside the Rust abstract machine: a
/// user thread on another core may write a frame while the kernel copies it
/// (C12). So the kernel touches it only with volatile accesses, as memory
/// shared with a device is, never with `copy_nonoverlapping`, whose source
/// the compiler may assume is stable. A racing write leaves some mix of old
/// and new bytes, and never a fault. Aligned words move as words, the rest
/// as bytes.
impl Bytes for DirectMem {
    fn read(&self, pa: u64, buf: &mut [u8]) {
        let src = self.va(pa);
        let mut i = 0;
        while i < buf.len() {
            let at = src + i as u64;
            if at.is_multiple_of(8) && buf.len() - i >= 8 {
                // SAFETY: `pa` and the `buf.len()` bytes after it are RAM in
                // the direct map, within one page, which `copy_from_user`
                // checked; `at` is aligned.
                let w = unsafe { core::ptr::read_volatile(at as *const u64) };
                buf[i..i + 8].copy_from_slice(&w.to_ne_bytes());
                i += 8;
            } else {
                // SAFETY: as above.
                buf[i] = unsafe { core::ptr::read_volatile(at as *const u8) };
                i += 1;
            }
        }
    }

    fn write(&self, pa: u64, buf: &[u8]) {
        let dst = self.va(pa);
        let mut i = 0;
        while i < buf.len() {
            let at = dst + i as u64;
            if at.is_multiple_of(8) && buf.len() - i >= 8 {
                let mut w = [0u8; 8];
                w.copy_from_slice(&buf[i..i + 8]);
                // SAFETY: as for `read`; `copy_to_user` checked that the
                // direct map covers the bytes read-write.
                unsafe { core::ptr::write_volatile(at as *mut u64, u64::from_ne_bytes(w)) };
                i += 8;
            } else {
                // SAFETY: as above.
                unsafe { core::ptr::write_volatile(at as *mut u8, buf[i]) };
                i += 1;
            }
        }
    }
}

/// What the kernel's direct map covers, from the memory map as `mm::init`
/// divided it: a read needs the frame in the direct map, a write needs it
/// in the read-write part, so a wrong mapping of a boot object can't make
/// the kernel store through a read-only alias and fault.
struct KernelDirectMap;

impl DirectMap for KernelDirectMap {
    fn covers(&self, pa: u64, len: u64, access: Access) -> bool {
        super::classified().direct_map_covers(pa, len, access == Access::Write)
    }
}

/// Copies `buf.len()` bytes from user address `va` in `space` into `buf`.
/// Fails before any byte moves if any page fails.
pub fn read_user(space: &AddressSpace, va: u64, buf: &mut [u8]) -> Result<(), UserError> {
    copy_from_user(&DirectMem, &KernelDirectMap, space.root(), va, buf)
}

/// Copies `buf` to user address `va` in `space`. Fails before any byte
/// moves if any page fails.
pub fn write_user(space: &AddressSpace, va: u64, buf: &[u8]) -> Result<(), UserError> {
    copy_to_user(&DirectMem, &KernelDirectMap, space.root(), va, buf)
}
