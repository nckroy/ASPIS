// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! What the in-QEMU tests share: a test's own corner of the boot capability
//! space, which it leaves as it found it.
//!
//! A [`Scratch`] takes free untyped pieces from the untyped CNodes, retypes
//! a scratch CNode from the RAM piece into the first free root slot, and
//! puts every object the test makes there. [`Scratch::finish`] revokes the
//! pieces, which destroys everything made from them, resets them, and
//! checks that they are free and zero again, with nothing deriving from
//! them, and that root slots 32 to 127 are empty. So tests run in any order.

use super::boot::{self, FIRST_FREE, RADIX, SLOTS};
use super::{cap, retype};
use kcap::SlotRef;
use kcap::cap::Cap;
use kcap::mdb;
use kcap::ops::Error;
use kmem::untyped::ObjectType;

/// The free untyped piece of RAM or device memory with the fewest bits at
/// or above `min_bits`, and nothing deriving from it. Its watermark may be
/// above 0, left by an earlier test: the next retype resets it first.
pub fn free_piece(device: bool, min_bits: u8) -> SlotRef {
    let mut best: Option<(u8, SlotRef)> = None;
    boot::for_each_untyped(|s, c| {
        let Cap::Untyped {
            bits, device: d, ..
        } = c
        else {
            return;
        };
        if d == device
            && bits >= min_bits
            && !mdb::has_children(&super::DirectSlots, s)
            && best.is_none_or(|(b, _)| bits < b)
        {
            best = Some((bits, s));
        }
    });
    match best {
        Some((_, s)) => s,
        None => panic!("no free untyped piece (device: {device}) of 2^{min_bits} bytes"),
    }
}

/// The untyped piece's watermark.
pub fn watermark(s: SlotRef) -> u64 {
    match cap(s) {
        Cap::Untyped { watermark, .. } => watermark,
        c => panic!("{c:x?} isn't untyped"),
    }
}

/// The base of the object a capability names.
pub fn base(s: SlotRef) -> u64 {
    match cap(s).object() {
        Some((b, _)) => b,
        None => panic!("slot {:#x} is empty", s.0),
    }
}

/// A test's corner of the boot capability space.
pub struct Scratch {
    /// The RAM piece the scratch CNode, and by default every object, comes
    /// from.
    pub ram: SlotRef,
    /// A device piece, if the test asked for one.
    pub dev: Option<SlotRef>,
    /// The root slot that holds the scratch CNode.
    pub root_index: u64,
    next: u64,
}

impl Scratch {
    /// A scratch CNode of 128 slots from a free RAM piece of at least
    /// `2^min_bits` bytes, in the first free root slot.
    pub fn new(min_bits: u8) -> Scratch {
        let ram = free_piece(false, min_bits);
        let root_index = (FIRST_FREE..SLOTS)
            .find(|&i| cap(boot::root_slot(i)).is_null())
            .expect("no free root slot");
        retype(
            ram,
            ObjectType::CNode(RADIX),
            boot::root_slot(boot::ROOT_SELF),
            root_index,
            1,
        )
        .unwrap_or_else(|e| panic!("no scratch CNode: {e:?}"));
        Scratch {
            ram,
            dev: None,
            root_index,
            next: 0,
        }
    }

    /// [`Scratch::new`], with a free device piece too.
    pub fn with_device(min_bits: u8) -> Scratch {
        let mut s = Scratch::new(min_bits);
        s.dev = Some(free_piece(true, 12));
        s
    }

    /// The device piece.
    pub fn dev(&self) -> SlotRef {
        self.dev.expect("the test took no device piece")
    }

    /// The scratch CNode's capability's slot, in the root CNode.
    pub fn cnode(&self) -> SlotRef {
        boot::root_slot(self.root_index)
    }

    /// Slot `i` of the scratch CNode.
    pub fn slot(&self, i: u64) -> SlotRef {
        match cap(self.cnode()) {
            Cap::CNode { ptr, .. } => SlotRef(ptr).offset(i),
            c => panic!("the scratch CNode is gone: {c:x?}"),
        }
    }

    /// The capability address of slot `i` of the scratch CNode.
    pub fn addr(&self, i: u64) -> u64 {
        boot::address(self.root_index, i)
    }

    /// The index in the scratch CNode of its slot `s`.
    pub fn index_of(&self, s: SlotRef) -> u64 {
        let first = self.slot(0).0;
        assert!(
            s.0 >= first && s.0 < self.slot(SLOTS - 1).0 + kcap::SLOT_SIZE,
            "slot {:#x} isn't in the scratch CNode",
            s.0
        );
        (s.0 - first) >> kcap::SLOT_BITS
    }

    /// The capability address of `s`, a slot of the scratch CNode.
    pub fn addr_of(&self, s: SlotRef) -> u64 {
        self.addr(self.index_of(s))
    }

    /// A free slot of the scratch CNode.
    pub fn take(&mut self) -> SlotRef {
        assert!(self.next < SLOTS, "the scratch CNode is full");
        self.next += 1;
        self.slot(self.next - 1)
    }

    /// Makes `count` objects of type `ty` from the untyped capability in
    /// `ut`, in the next free slots, and returns the first slot.
    pub fn try_make(&mut self, ut: SlotRef, ty: ObjectType, count: u64) -> Result<SlotRef, Error> {
        let i = self.next;
        retype(ut, ty, self.cnode(), i, count)?;
        self.next += count;
        Ok(self.slot(i))
    }

    /// Makes one object of type `ty` from the untyped capability in `ut`,
    /// in the next free slot, and returns the slot.
    pub fn make_from(&mut self, ut: SlotRef, ty: ObjectType) -> SlotRef {
        self.try_make(ut, ty, 1)
            .unwrap_or_else(|e| panic!("can't make {ty:?}: {e:?}"))
    }

    /// Makes one object from the RAM piece.
    pub fn make(&mut self, ty: ObjectType) -> SlotRef {
        let ram = self.ram;
        self.make_from(ram, ty)
    }

    /// Revokes and resets the pieces, and checks that the boot capability
    /// space is as the test found it.
    pub fn finish(self) {
        for p in [Some(self.ram), self.dev].into_iter().flatten() {
            super::revoke(p);
            assert!(!mdb::has_children(&super::DirectSlots, p));
            super::reset(p).unwrap_or_else(|e| panic!("can't reset the piece: {e:?}"));
            assert_eq!(watermark(p), 0);
        }
        for i in FIRST_FREE..SLOTS {
            assert!(
                cap(boot::root_slot(i)).is_null(),
                "root slot {i} isn't empty"
            );
        }
    }
}
