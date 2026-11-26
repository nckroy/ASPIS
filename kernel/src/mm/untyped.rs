// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The boot untyped pieces: the RAM the boot allocator never handed out, and
//! the device untyped memory, as naturally aligned power-of-two pieces
//! (ADR 0048, rule 1; kernel specification, "Boot memory" and "Untyped
//! memory and kernel records").
//!
//! Every piece goes to the root server, in the root job, as an untyped
//! capability in the boot capability space ([`crate::cap::boot`]), which
//! carries the piece's watermark as seL4's does. From then on a piece is
//! named only by its capability: retype and reset go through
//! `kcap::ops::retype`, which checks through the derivation tree that
//! nothing made from a piece is still in use before it resets the piece.
//! C16: every boot piece is the root job's.
//!
//! Free untyped memory is always zero, so the kernel zeroes every RAM piece
//! once, here. Device pieces are MMIO, and are never written.

use super::arch;
use core::sync::atomic::{AtomicBool, Ordering};
use kmem::layout::direct_va;
use kmem::memmap::ClassSet;
use kmem::untyped::{Untyped, decompose};

/// The most pieces the boot capability space holds, RAM and device together
/// (kernel specification, "Boot memory"): 16 untyped CNodes of 128 slots.
/// QEMU's maps need fewer than 100: 34 to 39 RAM pieces and 36 to 41 device
/// pieces on `a72-v2` and `max-v3`, with 1 or 3 GiB. A fragmented map on
/// real hardware needs more, so this leaves ample room; a test build panics
/// if it is ever reached.
pub const MAX_PIECES: usize = 2048;

/// What [`build`] made of boot memory.
#[derive(Clone, Copy, Debug, Default)]
pub struct Counts {
    /// RAM pieces, then device pieces, in address order within each.
    pub ram: usize,
    pub device: usize,
    /// Pieces beyond [`MAX_PIECES`], which go unused, and their bytes.
    pub dropped: usize,
    pub dropped_bytes: u64,
    /// Bytes of RAM untyped memory.
    pub ram_bytes: u64,
}

/// Set once [`build`] has run.
static BUILT: AtomicBool = AtomicBool::new(false);

/// Divides boot memory into pieces, once the boot allocator is sealed:
/// `ram` is the RAM it never handed out, `device` the device untyped
/// memory. Zeroes every RAM piece, then gives each piece to `place`, RAM
/// pieces first, then device pieces, in address order within each, at most
/// [`MAX_PIECES`] of them.
///
/// It runs once: a second build would give the same memory out twice
/// (ADR 0048, rule 1), so it panics instead.
pub fn build(ram: &ClassSet, device: &ClassSet, mut place: impl FnMut(Untyped)) -> Counts {
    assert!(
        !BUILT.swap(true, Ordering::Relaxed),
        "the boot untyped pieces are built twice"
    );
    let mut counts = Counts::default();
    let mut push = |base: u64, bits: u8, device: bool| {
        let Some(piece) = Untyped::new(base, bits, device) else {
            // `decompose` yields only aligned pieces of allowed sizes.
            panic!("bad untyped piece {base:#x}, 2^{bits}");
        };
        if counts.ram + counts.device == MAX_PIECES {
            // A test build fails, so the cap is raised before a real map
            // needs it. In production the piece goes unused, and the boot
            // log says so.
            #[cfg(aspis_test_build)]
            panic!("the boot capability space is full at {MAX_PIECES} untyped pieces");
            #[cfg(not(aspis_test_build))]
            {
                counts.dropped += 1;
                counts.dropped_bytes += piece.size();
                return;
            }
        }
        if !device {
            // `classify` leaves RAM beyond the direct map out of usable
            // memory, so this is a kernel bug, not a range to skip.
            let Some(va) = direct_va(base) else {
                panic!("untyped piece {base:#x} is beyond the direct map");
            };
            // SAFETY: a piece of usable RAM that the boot allocator never
            // handed out, mapped read-write in the direct map, which
            // nothing uses.
            unsafe { arch::zero(va, piece.size()) };
            counts.ram_bytes += piece.size();
            counts.ram += 1;
        } else {
            counts.device += 1;
        }
        place(piece);
    };
    for (s, e) in ram.iter() {
        for (base, bits) in decompose(s, e) {
            push(base, bits, false);
        }
    }
    for (s, e) in device.iter() {
        for (base, bits) in decompose(s, e) {
            push(base, bits, true);
        }
    }
    // The zeroes reach every table walker before any piece is retyped into
    // a translation table.
    arch::dsb_ishst();
    counts
}
