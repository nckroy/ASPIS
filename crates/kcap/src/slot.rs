// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Slots, and the memory that holds them (kernel specification, "Capability
//! spaces and lookup").
//!
//! A slot is four words, as seL4's `cte_t` is on AArch64. Words 0 and 1
//! hold the capability ([`crate::cap`]). Words 2 and 3 place it in the
//! derivation tree ([`crate::mdb`]):
//!
//! - word 2: the previous slot in the tree's list, in bits 0 to 43, and the
//!   slot's depth in the tree, in bits 48 to 63;
//! - word 3: the next slot in the list, in bits 0 to 43, and the slot's
//!   barrier, in bits 48 to 63, as the slot's depth less the barrier, or 0
//!   when it has none ([`Slot::barrier`]).
//!
//! A link is stored as the slot's address shifted right by 5, plus 1, and 0
//! means none, so a slot at physical address 0 still links. All four words
//! zero is an empty slot. Free untyped memory is zero, so a CNode made by
//! retype starts with every slot empty.

use crate::SlotRef;
use crate::cap::Cap;

/// The memory that holds slots: the kernel's direct map, or a fake on the
/// host.
pub trait Mem {
    /// The four words of a slot.
    fn read(&self, slot: SlotRef) -> [u64; 4];
    /// Writes the four words of a slot.
    fn write(&mut self, slot: SlotRef, words: [u64; 4]);
    /// Zeroes `[pa, pa + len)` of RAM, for a reset of untyped memory
    /// (ADR 0048, rule 1). `pa` is aligned to 4 KiB; `len` ends where the
    /// piece's watermark did, so it may end partway through a page.
    fn clear(&mut self, pa: u64, len: u64);
    /// Reports a slot that holds no valid capability or links. Kernel memory
    /// is corrupt: the kernel panics.
    fn corrupt(&self, slot: SlotRef) -> !;
}

/// The deepest a capability can sit in the derivation tree. A derivation
/// past it is refused.
pub const MAX_DEPTH: u16 = u16::MAX;

const LINK_MASK: u64 = (1 << 44) - 1;

/// A slot, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub cap: Cap,
    pub prev: Option<SlotRef>,
    pub next: Option<SlotRef>,
    /// The slot's depth in the derivation tree: 0 for a root.
    pub depth: u16,
    /// The depth of the shallowest capability that was deleted between this
    /// slot and the one before it while this slot derived from it, if any.
    /// Always less than [`Slot::depth`]. Nothing at that depth or deeper
    /// that comes before this slot is its ancestor ([`crate::mdb`]).
    pub barrier: Option<u16>,
}

impl Slot {
    /// An empty slot.
    pub const EMPTY: Slot = Slot {
        cap: Cap::Null,
        prev: None,
        next: None,
        depth: 0,
        barrier: None,
    };

    /// A capability with no links, at `depth`.
    pub const fn unlinked(cap: Cap, depth: u16) -> Slot {
        Slot {
            cap,
            prev: None,
            next: None,
            depth,
            barrier: None,
        }
    }

    pub const fn is_empty(&self) -> bool {
        self.cap.is_null()
    }

    /// The slot's four words.
    pub const fn encode(&self) -> [u64; 4] {
        let [w0, w1] = self.cap.encode();
        [
            w0,
            w1,
            encode_link(self.prev) | (self.depth as u64) << 48,
            encode_link(self.next) | (self.gap() as u64) << 48,
        ]
    }

    /// The barrier as the word holds it: the depth less the barrier, or 0
    /// for none.
    const fn gap(&self) -> u16 {
        match self.barrier {
            Some(b) if b < self.depth => self.depth - b,
            _ => 0,
        }
    }

    /// The slot in four words, or `None` if they hold no valid slot: an
    /// invalid capability, a stray bit, links or a depth on an empty
    /// slot, or a barrier word larger than the depth.
    pub fn decode(w: [u64; 4]) -> Option<Slot> {
        let cap = Cap::decode([w[0], w[1]])?;
        let depth = (w[2] >> 48) as u16;
        let gap = (w[3] >> 48) as u16;
        if gap > depth {
            return None;
        }
        let slot = Slot {
            cap,
            prev: decode_link(w[2] & LINK_MASK),
            next: decode_link(w[3] & LINK_MASK),
            depth,
            barrier: (gap != 0).then_some(depth - gap),
        };
        let empty_ok = !cap.is_null() || slot == Slot::EMPTY;
        (empty_ok && slot.encode() == w).then_some(slot)
    }
}

const fn encode_link(link: Option<SlotRef>) -> u64 {
    match link {
        None => 0,
        Some(s) => ((s.0 >> 5) + 1) & LINK_MASK,
    }
}

const fn decode_link(w: u64) -> Option<SlotRef> {
    if w == 0 {
        None
    } else {
        Some(SlotRef((w - 1) << 5))
    }
}

/// Reads a slot, reporting corruption to [`Mem::corrupt`].
pub fn read<M: Mem>(mem: &M, slot: SlotRef) -> Slot {
    match Slot::decode(mem.read(slot)) {
        Some(s) => s,
        None => mem.corrupt(slot),
    }
}

/// Writes a slot.
pub fn write<M: Mem>(mem: &mut M, slot: SlotRef, s: &Slot) {
    mem.write(slot, s.encode());
}

/// The capability in a slot.
pub fn cap<M: Mem>(mem: &M, slot: SlotRef) -> Cap {
    read(mem, slot).cap
}

/// Replaces a slot's capability, keeping its place in the tree.
pub fn set_cap<M: Mem>(mem: &mut M, slot: SlotRef, cap: Cap) {
    let mut s = read(mem, slot);
    s.cap = cap;
    write(mem, slot, &s);
}

/// Whether a slot is empty.
pub fn is_empty<M: Mem>(mem: &M, slot: SlotRef) -> bool {
    read(mem, slot).is_empty()
}
