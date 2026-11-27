// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The boot capability space (kernel specification, "What the root server
//! receives"; ADR 0048, rule 2): the root CNode, and the untyped CNodes that
//! hold an untyped capability to every piece of boot memory.
//!
//! `mm::seal` takes the CNodes' pages from the boot allocator before it
//! seals it, and builds the space with [`BootSpace`]. The CNodes are boot
//! objects: they belong to no job, are never destroyed, and no untyped
//! capability covers their memory (ADR 0048, rule 2).
//!
//! **Originals.** The kernel keeps the original capability to each boot
//! CNode in a page of its own, the originals page, which no CNode
//! capability names, so no lookup reaches it. Each original is a root of
//! the derivation tree, and the root CNode holds a copy of it, as its
//! child. A delete or a revoke through the root CNode therefore never
//! removes the last capability to a boot CNode, so none is ever destroyed
//! (ADR 0048, rule 2; ADR 0049, rule 4). The originals page holds the root
//! CNode's original in slot 0 and the untyped CNodes' in slots 1 to 16.
//! From C12 it also holds the scheduler's boot objects' originals: the
//! scheduling-control CNode's in slot 17, the first thread's in slot 18 and
//! its scheduling context's in slot 19 ([`place_scheduling`]).
//!
//! **The root CNode** is one page: radix 7, 128 slots. Its capability has a
//! 50-bit guard of zeros, so that a 64-bit capability address is the root
//! index shifted left by 7, then the index in the CNode found there. Root
//! slot `r` itself is named at depth 57 by `r`.
//!
//! | Root slots | Hold |
//! |---|---|
//! | 0 | Nothing |
//! | 1 | A copy of the root CNode's capability |
//! | 2 | The first thread (C12), suspended, at priority and maximum controlled priority 255 |
//! | 3 | Kept for the first thread's address space (C17 loads the root server's image) |
//! | 4 | The scheduling-control CNode (C12): slot n holds core n's scheduling control |
//! | 5 | The first thread's scheduling context (C12), bound to it |
//! | 6 to 15 | Kept for later boot capabilities: C13's interrupt control, C15's boot memory objects, C16's root job |
//! | 16 to 31 | Copies of the untyped CNodes' capabilities; each CNode is one page of 128 slots |
//! | 32 to 127 | Free: the tests use them now, and later the root server |
//!
//! **The untyped CNodes** hold an untyped capability to each boot piece, RAM
//! pieces then device pieces, each in address order, from slot 0 of the
//! first CNode on. Each is a root of the derivation tree, with no parent.
//! There are always 16, which hold [`MAX_PIECES`], the most the kernel
//! makes. Taking their pages from the free set can split it into more
//! pieces, so a fixed count is what always fits.
//!
//! C19: the root server receives the root CNode's capability, and the
//! layout of root slots 2 to 15.

use super::DirectSlots;
use crate::mm::untyped::MAX_PIECES;
use core::sync::atomic::{AtomicU64, Ordering};
use kcap::SlotRef;
use kcap::cap::Cap;
use kcap::mdb;
use kcap::ops;
use kmem::untyped::Untyped;

/// The radix of every boot CNode: one page of 32-byte slots.
pub const RADIX: u8 = 7;
/// Slots in each boot CNode.
pub const SLOTS: u64 = 1 << RADIX;
/// The root CNode capability's guard: zeros, so that two levels of radix 7
/// use up a 64-bit address.
pub const ROOT_GUARD_BITS: u8 = 64 - 2 * RADIX;
/// The depth that names a root slot itself.
pub const ROOT_DEPTH: u32 = (ROOT_GUARD_BITS + RADIX) as u32;
/// The root slot that holds the root CNode's own capability.
pub const ROOT_SELF: u64 = 1;
/// The root slot of the first untyped CNode.
pub const FIRST_UNTYPED_CNODE: u64 = 16;
/// The number of untyped CNodes.
pub const UNTYPED_CNODES: usize = 16;
/// The first free root slot.
pub const FIRST_FREE: u64 = 32;
/// The root slot of the first thread (C12).
pub const FIRST_THREAD: u64 = 2;
/// The root slot of the scheduling-control CNode (C12).
pub const SCHED_CONTROL: u64 = 4;
/// The root slot of the first thread's scheduling context (C12).
pub const FIRST_CONTEXT: u64 = 5;
/// The originals of the scheduler's boot objects (C12).
pub const ORIGINAL_SCHED_CONTROL: u64 = 17;
pub const ORIGINAL_FIRST_THREAD: u64 = 18;
pub const ORIGINAL_FIRST_CONTEXT: u64 = 19;

const _: () = assert!(UNTYPED_CNODES as u64 * SLOTS >= MAX_PIECES as u64);
const _: () = assert!(FIRST_UNTYPED_CNODE + UNTYPED_CNODES as u64 <= FIRST_FREE);

/// The root CNode's physical address with bit 0 set, once
/// [`BootSpace::new`] has run; 0 before. The bit keeps a root CNode at
/// physical address 0, as RAM starts on the Raspberry Pi 4, apart from
/// "not built".
static ROOT: AtomicU64 = AtomicU64::new(0);
/// The originals page's physical address, with bit 0 set once built.
static ORIGINALS: AtomicU64 = AtomicU64::new(0);

/// The root CNode's capability, from which the kernel looks capabilities up
/// until threads have root CNodes of their own (C12).
pub fn root() -> Cap {
    Cap::CNode {
        ptr: root_ptr(),
        radix: RADIX,
        guard_size: ROOT_GUARD_BITS,
        guard: 0,
    }
}

fn root_ptr() -> u64 {
    let v = ROOT.load(Ordering::Relaxed);
    assert_ne!(v, 0, "the boot capability space isn't built");
    v & !1
}

/// Slot `i` of the originals page, where the kernel keeps the original of
/// each boot CNode's capability. No lookup reaches it.
pub fn original(i: u64) -> SlotRef {
    assert!(i < SLOTS, "original {i} is out of range");
    let v = ORIGINALS.load(Ordering::Relaxed);
    assert_ne!(v, 0, "the boot capability space isn't built");
    SlotRef(v & !1).offset(i)
}

/// Root slot `i`.
pub fn root_slot(i: u64) -> SlotRef {
    assert!(i < SLOTS, "root slot {i} is out of range");
    SlotRef(root_ptr()).offset(i)
}

/// The capability address of slot `index` of the CNode in root slot `r`.
pub const fn address(r: u64, index: u64) -> u64 {
    r << RADIX | index
}

/// The boot capability space while `mm::seal` builds it.
pub struct BootSpace {
    cnodes: [u64; UNTYPED_CNODES],
    count: usize,
}

impl BootSpace {
    /// Starts the space in zeroed pages: the root CNode at `root`, the
    /// originals page at `originals`, the untyped CNodes at `cnodes`. Each
    /// original is a root of the tree, and the root CNode holds a copy of
    /// each, as its child.
    pub fn new(root: u64, originals: u64, cnodes: [u64; UNTYPED_CNODES]) -> BootSpace {
        assert!(
            ROOT.swap(root | 1, Ordering::Relaxed) == 0
                && ORIGINALS.swap(originals | 1, Ordering::Relaxed) == 0,
            "the boot capability space is built twice"
        );
        let mem = &mut DirectSlots;
        mdb::insert_root(mem, original(0), self::root());
        for (i, &pa) in cnodes.iter().enumerate() {
            let cnode = Cap::CNode {
                ptr: pa,
                radix: RADIX,
                guard_size: 0,
                guard: 0,
            };
            mdb::insert_root(mem, original(1 + i as u64), cnode);
        }
        let place = |from: u64, to: u64| {
            if let Err(e) = ops::copy(&mut DirectSlots, original(from), root_slot(to)) {
                panic!("can't copy boot CNode {from} into root slot {to}: {e:?}");
            }
        };
        place(0, ROOT_SELF);
        for i in 0..UNTYPED_CNODES as u64 {
            place(1 + i, FIRST_UNTYPED_CNODE + i);
        }
        BootSpace { cnodes, count: 0 }
    }

    /// Puts an untyped capability to `piece` in the next slot of the
    /// untyped CNodes. `mm::untyped::build` gives at most [`MAX_PIECES`].
    pub fn add_untyped(&mut self, piece: &Untyped) {
        let Some(&cnode) = self.cnodes.get(self.count / SLOTS as usize) else {
            panic!("more than {MAX_PIECES} untyped pieces");
        };
        let slot = SlotRef(cnode).offset(self.count as u64 % SLOTS);
        let cap = Cap::Untyped {
            base: piece.base(),
            bits: piece.bits(),
            device: piece.is_device(),
            watermark: 0,
        };
        mdb::insert_root(&mut DirectSlots, slot, cap);
        self.count += 1;
    }

    /// How many untyped capabilities the space holds.
    pub fn untyped_count(&self) -> usize {
        self.count
    }
}

/// Places the scheduler's boot objects (C12; `crate::sched::boot`), in
/// zeroed boot pages that `mm::seal` took before it sealed the allocator:
/// each original is a root of the tree in the originals page, and the root
/// CNode holds a copy of each. The first thread's context is one page, of
/// 2^12 bytes.
pub fn place_scheduling(p: crate::sched::boot::Pages) {
    let mem = &mut DirectSlots;
    let cnode = Cap::CNode {
        ptr: p.control,
        radix: RADIX,
        guard_size: 0,
        guard: 0,
    };
    let thread = Cap::Thread {
        ptr: p.thread,
        rights: kcap::rights::Rights::ALL,
    };
    let context = Cap::SchedContext {
        ptr: p.context,
        bits: kmem::untyped::MAX_SCHED_CONTEXT_BITS,
        binding: None,
    };
    for (o, r, c) in [
        (ORIGINAL_SCHED_CONTROL, SCHED_CONTROL, cnode),
        (ORIGINAL_FIRST_THREAD, FIRST_THREAD, thread),
        (ORIGINAL_FIRST_CONTEXT, FIRST_CONTEXT, context),
    ] {
        mdb::insert_root(mem, original(o), c);
        if let Err(e) = ops::copy(&mut DirectSlots, original(o), root_slot(r)) {
            panic!("can't copy boot object {o} into root slot {r}: {e:?}");
        }
    }
}

/// Calls `f` with the slot and capability of every untyped capability in
/// the untyped CNodes, in slot order, as they are now.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub fn for_each_untyped(mut f: impl FnMut(SlotRef, Cap)) {
    for r in FIRST_UNTYPED_CNODE..FIRST_UNTYPED_CNODE + UNTYPED_CNODES as u64 {
        let Cap::CNode { ptr, radix, .. } = super::cap(root_slot(r)) else {
            continue;
        };
        for i in 0..1u64 << radix {
            let s = SlotRef(ptr).offset(i);
            if let c @ Cap::Untyped { .. } = super::cap(s) {
                f(s, c);
            }
        }
    }
}
