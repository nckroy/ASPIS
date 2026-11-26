// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Reaching user memory without dereferencing a user address (ADR 0048,
//! rule 5; kernel specification, "Access to user memory").
//!
//! The kernel walks the address space's tables in software, through its
//! direct map, and reaches the frame through the direct map too. A page that
//! isn't mapped fails at once with "not resident"; a mapping of device
//! memory fails at once with "not RAM", so the kernel never touches MMIO on
//! a user's behalf. The kernel never takes a page fault here.
//!
//! The pinned IPC buffer is the one exception the record allows, and isn't
//! reached through these functions.
//!
//! The error names are internal: K30 settles the names callers see.

use crate::PAGE_SIZE;
use crate::layout::USER_TOP;
use crate::table::{PhysMem, Walk, walk};

/// What the kernel is about to do with user memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

/// Why user memory couldn't be reached. In every case no byte was moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserError {
    /// The address isn't in the lower half.
    NotUserAddress,
    /// No page is mapped there. The caller touches the page in user mode,
    /// which faults to its pager, and retries.
    NotResident,
    /// The address is mapped to device memory, or to a frame outside the
    /// direct map.
    NotRam,
    /// The mapping doesn't give the access: a write to a read-only page.
    NoRight,
}

/// Bytes of physical RAM, as the kernel reaches them through the direct map.
pub trait Bytes {
    /// Copies `buf.len()` bytes from physical address `pa`.
    fn read(&self, pa: u64, buf: &mut [u8]);
    /// Copies `buf` to physical address `pa`.
    fn write(&self, pa: u64, buf: &[u8]);
}

/// What the kernel's direct map covers: a check made after the walk, as
/// defense in depth, so that a wrong user mapping can't make the kernel
/// touch memory outside the direct map, or write through its read-only part.
pub trait DirectMap {
    /// Whether the direct map covers all of `[pa, pa + len)` for `access`:
    /// read-only or read-write for a read, read-write for a write.
    fn covers(&self, pa: u64, len: u64, access: Access) -> bool;
}

/// Translates user address `va` in the address space whose level-0 table is
/// at `root`, for `access`, and returns the physical address.
///
/// C15: a write must also find the page in a frame its object owns, copying
/// a shared copy-on-write page first, and marks the page dirty (kernel
/// specification, "Access to user memory", steps 2 and 3). C10 checks only
/// the mapping's write right (step 1).
pub fn translate(mem: &impl PhysMem, root: u64, va: u64, access: Access) -> Result<u64, UserError> {
    if va >= USER_TOP {
        return Err(UserError::NotUserAddress);
    }
    match walk(mem, root, va) {
        Walk::Invalid { .. } => Err(UserError::NotResident),
        Walk::Leaf { leaf, .. } if leaf.device_bit => Err(UserError::NotRam),
        Walk::Leaf { leaf, .. } if !leaf.el0_read => Err(UserError::NoRight),
        Walk::Leaf { leaf, .. } if access == Access::Write && !leaf.el0_write => {
            Err(UserError::NoRight)
        }
        w @ Walk::Leaf { .. } => w.pa(va).ok_or(UserError::NotResident),
    }
}

/// Calls `f(pa, offset, len)` for each page-bounded piece of
/// `[va, va + len)`, after checking every piece: so either all pieces are
/// visited or none is.
fn each_piece(
    mem: &impl PhysMem,
    map: &impl DirectMap,
    root: u64,
    va: u64,
    len: usize,
    access: Access,
    mut f: impl FnMut(u64, usize, usize),
) -> Result<(), UserError> {
    let end = va
        .checked_add(len as u64)
        .filter(|&end| end <= USER_TOP)
        .ok_or(UserError::NotUserAddress)?;
    // Check every page first, so a failure moves nothing. Nothing changes
    // the tables in between: the kernel holds its lock throughout (C12).
    for pass in [false, true] {
        let mut at = va;
        while at < end {
            let piece = (PAGE_SIZE - (at & (PAGE_SIZE - 1))).min(end - at);
            let pa = translate(mem, root, at, access)?;
            if !pass && !map.covers(pa, piece, access) {
                // A write through the read-only part of the direct map is
                // refused, not attempted.
                let readable = map.covers(pa, piece, Access::Read);
                return Err(if access == Access::Write && readable {
                    UserError::NoRight
                } else {
                    UserError::NotRam
                });
            }
            if pass {
                f(pa, (at - va) as usize, piece as usize);
            }
            at += piece;
        }
    }
    Ok(())
}

/// Copies `buf.len()` bytes from user address `va` into `buf`. Fails before
/// any byte moves if any page fails.
pub fn copy_from_user<M: PhysMem + Bytes>(
    mem: &M,
    map: &impl DirectMap,
    root: u64,
    va: u64,
    buf: &mut [u8],
) -> Result<(), UserError> {
    let len = buf.len();
    each_piece(mem, map, root, va, len, Access::Read, |pa, off, n| {
        if let Some(dst) = buf.get_mut(off..off + n) {
            Bytes::read(mem, pa, dst);
        }
    })
}

/// Copies `buf` to user address `va`. Fails before any byte moves if any
/// page fails.
pub fn copy_to_user<M: PhysMem + Bytes>(
    mem: &M,
    map: &impl DirectMap,
    root: u64,
    va: u64,
    buf: &[u8],
) -> Result<(), UserError> {
    each_piece(
        mem,
        map,
        root,
        va,
        buf.len(),
        Access::Write,
        |pa, off, n| {
            if let Some(src) = buf.get(off..off + n) {
                Bytes::write(mem, pa, src);
            }
        },
    )
}
