// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The boot untyped table: the RAM the boot allocator never handed out, and
//! the device untyped memory, as naturally aligned power-of-two pieces
//! (ADR 0048, rule 1; kernel specification, "Boot memory" and "Untyped
//! memory and kernel records").
//!
//! Every piece goes to the root server, in the root job. C16: the root job
//! holds them. C11: the root server gets an untyped capability to each,
//! which carries the piece's watermark; until then a piece is named by its
//! index in this table.
//!
//! Free untyped memory is always zero, so the kernel zeroes every RAM piece
//! once, here. Device pieces are MMIO, and are never written.

use super::BootCell;
use super::arch;
use core::sync::atomic::{AtomicBool, Ordering};
use kmem::layout::direct_va;
use kmem::memmap::ClassSet;
use kmem::untyped::{ObjectType, RetypeError, Untyped, decompose};

/// The most pieces the table holds, RAM and device together (kernel
/// specification, "Boot memory"). QEMU's maps need fewer than 100: 34 to 39
/// RAM pieces and 36 to 41 device pieces on `a72-v2` and `max-v3`, with 1 or
/// 3 GiB. A fragmented map on real hardware needs more, so this leaves
/// ample room; a test build panics if it is ever reached.
pub const MAX_PIECES: usize = 2048;

/// The boot untyped table.
pub struct Table {
    pieces: [Option<Untyped>; MAX_PIECES],
    len: usize,
    /// RAM pieces, then device pieces, in address order within each.
    pub ram: usize,
    pub device: usize,
    /// Pieces beyond [`MAX_PIECES`], which go unused, and their bytes.
    pub dropped: usize,
    pub dropped_bytes: u64,
    /// Bytes of RAM untyped memory.
    pub ram_bytes: u64,
}

static TABLE: BootCell<Table> = BootCell::new(Table {
    pieces: [None; MAX_PIECES],
    len: 0,
    ram: 0,
    device: 0,
    dropped: 0,
    dropped_bytes: 0,
    ram_bytes: 0,
});

impl Table {
    fn push(&mut self, base: u64, bits: u8, device: bool) {
        let Some(piece) = Untyped::new(base, bits, device) else {
            // `decompose` yields only aligned pieces of allowed sizes.
            panic!("bad untyped piece {base:#x}, 2^{bits}");
        };
        if self.len == MAX_PIECES {
            // A test build fails, so the cap is raised before a real map
            // needs it. In production the piece goes unused, and the boot
            // log says so.
            #[cfg(aspis_test_build)]
            panic!("the boot untyped table is full at {MAX_PIECES} pieces");
            #[cfg(not(aspis_test_build))]
            {
                self.dropped += 1;
                self.dropped_bytes += piece.size();
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
            self.ram_bytes += piece.size();
            self.ram += 1;
        } else {
            self.device += 1;
        }
        self.pieces[self.len] = Some(piece);
        self.len += 1;
    }
}

/// A piece of the boot untyped table, by its index.
///
/// C11: an untyped capability names a piece, and carries its watermark.
/// C16: every boot piece is the root job's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UntypedId(u16);

/// How much a reset clears before it records its progress: seL4's
/// `resetUntypedCap` works in chunks of this size, with a preemption point
/// after each (kernel specification, "Untyped memory and kernel records").
const RESET_CHUNK: u64 = 64 * 1024;

/// Set once [`build`] has run.
static BUILT: AtomicBool = AtomicBool::new(false);

/// Builds the table, once the boot allocator is sealed: `ram` is the RAM it
/// never handed out, `device` the device untyped memory. Zeroes every RAM
/// piece.
///
/// It runs once: a second build would give the same memory out twice
/// (ADR 0048, rule 1), so it panics instead.
pub fn build(ram: &ClassSet, device: &ClassSet) -> &'static Table {
    assert!(
        !BUILT.swap(true, Ordering::Relaxed),
        "the boot untyped table is built twice"
    );
    // SAFETY: the first call, from `mm::seal`, before anything reads the
    // table.
    let t = unsafe { TABLE.get_mut() };
    for (s, e) in ram.iter() {
        for (base, bits) in decompose(s, e) {
            t.push(base, bits, false);
        }
    }
    for (s, e) in device.iter() {
        for (base, bits) in decompose(s, e) {
            t.push(base, bits, true);
        }
    }
    // The zeroes reach every table walker before any piece is retyped into
    // a translation table.
    arch::dsb_ishst();
    t
}

/// The number of pieces in the table, and a copy of piece `i`. The borrow
/// of the table ends before this returns, so callers may call `f`s that
/// retype or reset pieces.
fn piece(i: usize) -> Option<Untyped> {
    // SAFETY: C12: under the kernel lock; one CPU now. The shared reference
    // lives only for this copy.
    let t = unsafe { TABLE.get() };
    t.pieces[..t.len].get(i).copied().flatten()
}

fn len() -> usize {
    // SAFETY: as for `piece`.
    unsafe { TABLE.get() }.len
}

/// The first piece for which `f` holds. `f` gets a copy of each piece, and
/// no reference to the table is live while it runs.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub fn find(mut f: impl FnMut(&Untyped) -> bool) -> Option<UntypedId> {
    (0..len())
        .find(|&i| piece(i).is_some_and(|p| f(&p)))
        .map(|i| UntypedId(i as u16))
}

/// The piece `id` names, as it is now.
pub fn get(id: UntypedId) -> Untyped {
    // SAFETY: as for `find`.
    let t = unsafe { TABLE.get() };
    match t.pieces.get(id.0 as usize).copied().flatten() {
        Some(u) => u,
        // An `UntypedId` is only made by `find`, from a piece in the table.
        None => panic!("no untyped piece {}", id.0),
    }
}

/// Makes `count` objects of type `ty` from piece `id`, and returns the
/// physical address of the first (ADR 0048, rule 1). The memory is zero,
/// since free untyped memory always is.
///
/// C11: the caller names the piece by a capability, and the objects get
/// capabilities of their own, as children of it in the derivation tree.
pub fn retype(id: UntypedId, ty: ObjectType, count: u64) -> Result<u64, RetypeError> {
    // SAFETY: as for `find`; no other reference to the table is live.
    let t = unsafe { TABLE.get_mut() };
    match t.pieces.get_mut(id.0 as usize) {
        Some(Some(u)) => u.retype(ty, count),
        _ => panic!("no untyped piece {}", id.0),
    }
}

/// Resets piece `id`: clears what was retyped from it, from the top down in
/// [`RESET_CHUNK`] pieces, and lowers its watermark to zero, so its free
/// memory is zero again. A device piece is never written: its watermark
/// just drops to zero.
///
/// C10 has no preemption points, so it runs the reset to the end; C13a
/// adds one after each chunk, and the watermark records the progress.
///
/// # Safety
///
/// Nothing made from the piece may still be in use: no address space made
/// from it may be active or hold an ASID, and no mapping may lead to its
/// frames or tables. C11 checks this through the derivation tree, as seL4
/// does; until then the caller promises it.
pub unsafe fn reset(id: UntypedId) {
    // SAFETY: as for `find`; no other reference to the table is live.
    let t = unsafe { TABLE.get_mut() };
    let Some(Some(u)) = t.pieces.get_mut(id.0 as usize) else {
        panic!("no untyped piece {}", id.0);
    };
    u.begin_reset();
    while let Some((pa, len)) = u.reset_step(RESET_CHUNK) {
        // kmem never yields a range of device memory: zeroing MMIO would
        // write to device registers, and it isn't in the direct map.
        assert!(!u.is_device(), "reset tried to clear device memory");
        let Some(va) = direct_va(pa) else {
            panic!("untyped piece {pa:#x} is beyond the direct map");
        };
        // SAFETY: RAM of the piece below its watermark, in the direct map,
        // read-write, which the caller promises nothing uses.
        unsafe { arch::zero(va, len) };
    }
    // The zeroes reach every table walker before the memory is retyped
    // into a translation table again.
    arch::dsb_ishst();
}

/// Calls `f` with a copy of each piece. No reference to the table is live
/// while `f` runs.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub fn for_each(mut f: impl FnMut(&Untyped)) {
    for i in 0..len() {
        if let Some(p) = piece(i) {
            f(&p);
        }
    }
}
