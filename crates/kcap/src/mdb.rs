// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The derivation tree (ADR 0049, rule 4; kernel specification, "Derivation
//! and revocation").
//!
//! As in seL4's mapping database, the tree is a doubly linked list of slots
//! in depth-first order. Unlike seL4's, every derivation is a true child of
//! the capability it came from, as rule 4 requires: each slot records its
//! depth, and a new capability is inserted right after its parent, one level
//! deeper. seL4 instead marks some capabilities revocable and makes a plain
//! copy its source's sibling, so revoking a plain copy reaches nothing.
//!
//! **Descendants.** b descends from a when b lies in the contiguous run of
//! slots after a, each deeper than a, with no barrier at a's depth or
//! shallower, and related to a: inside a's range when a is untyped;
//! otherwise naming the same object, and carrying a's badge when a is a
//! badged endpoint (as seL4's `isMDBParentOf` checks badges). With the
//! depths and barriers kept as below, the run is exactly a's subtree; the
//! relation is a second check.
//!
//! **Deleting a slot that has children** leaves the children where they
//! are, at their depth, and records a *barrier* on the next slot: the
//! deleted slot's depth. A slot's barrier is the shallowest depth among the
//! capabilities deleted between it and the slot before it, while it was in
//! their runs. No capability that comes before it at the barrier's depth or
//! deeper is its ancestor, so a run stops there. So the children stay in
//! the run of every ancestor that remains, and join no other capability's
//! run: revoking a capability deletes exactly its descendants, never a
//! sibling's. Each delete does O(1) work: no depth is ever lowered.
//!
//! The cost is depth. A capability keeps the depth it was made at after its
//! ancestors go, so a chain of copies, each made from the last and the last
//! then deleted, deepens by one per link, and a derivation past
//! [`MAX_DEPTH`] is refused.
//!
//! **Every capability to one object is contiguous** in the list: an object's
//! first capability is inserted after the untyped it came from, every copy
//! after its source, and a removal keeps the rest together. So a capability
//! is final, the last to its object, when neither neighbor names the same
//! object (seL4's `isFinalCapability`).

use crate::SlotRef;
use crate::cap::Cap;
use crate::slot::{self, MAX_DEPTH, Mem, Slot};

/// Why an insertion failed. Nothing was changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertError {
    /// The new capability would sit deeper than [`MAX_DEPTH`].
    TooDeep,
}

/// Whether `b`, deeper than `a` and in its run, is related to `a` so that it
/// descends from it.
fn related(a: &Cap, b: &Cap) -> bool {
    match *a {
        Cap::Untyped { base, bits, .. } => match b.object() {
            Some((ob, _)) => ob >= base && ob - base < 1 << bits,
            None => false,
        },
        Cap::Null | Cap::Zombie { .. } => false,
        _ => {
            a.same_object(b)
                && match (a, b) {
                    (Cap::Endpoint { badge: ba, .. }, Cap::Endpoint { badge: bb, .. })
                        if *ba != 0 =>
                    {
                        ba == bb
                    }
                    _ => true,
                }
        }
    }
}

/// Whether slot contents `b`, the slot after `a` or after one of `a`'s
/// descendants, belong to the run of descendants of `a`.
pub fn derives_from(a: &Slot, b: &Slot) -> bool {
    b.depth > a.depth && b.barrier.is_none_or(|x| x > a.depth) && related(&a.cap, &b.cap)
}

/// The first descendant of `parent`, if it has any: the next slot, if that
/// derives from it.
pub fn first_child<M: Mem>(mem: &M, parent: SlotRef) -> Option<SlotRef> {
    let p = slot::read(mem, parent);
    let next = p.next?;
    derives_from(&p, &slot::read(mem, next)).then_some(next)
}

/// Whether anything derives from the capability in `slot`.
pub fn has_children<M: Mem>(mem: &M, slot: SlotRef) -> bool {
    first_child(mem, slot).is_some()
}

/// Whether the capability in `slot` is the last one to its object. A zombie
/// always is.
pub fn is_final<M: Mem>(mem: &M, slot: SlotRef) -> bool {
    let s = slot::read(mem, slot);
    if s.cap.is_zombie() {
        return true;
    }
    let same = |n: Option<SlotRef>| match n {
        Some(n) => s.cap.same_object(&slot::read(mem, n).cap),
        None => false,
    };
    !same(s.prev) && !same(s.next)
}

/// Inserts `cap` into the empty slot `new`, as a child of the capability in
/// `parent`: right after it in the list, one level deeper.
pub fn insert_child<M: Mem>(
    mem: &mut M,
    parent: SlotRef,
    new: SlotRef,
    cap: Cap,
) -> Result<(), InsertError> {
    let mut p = slot::read(mem, parent);
    if p.depth == MAX_DEPTH {
        return Err(InsertError::TooDeep);
    }
    let next = p.next;
    slot::write(
        mem,
        new,
        &Slot {
            cap,
            prev: Some(parent),
            next,
            depth: p.depth + 1,
            barrier: None,
        },
    );
    p.next = Some(new);
    slot::write(mem, parent, &p);
    if let Some(n) = next {
        let mut ns = slot::read(mem, n);
        ns.prev = Some(new);
        slot::write(mem, n, &ns);
    }
    Ok(())
}

/// Puts `cap` into the empty slot `new` as a root of the tree, with no
/// parent: the kernel's boot capabilities.
pub fn insert_root<M: Mem>(mem: &mut M, new: SlotRef, cap: Cap) {
    slot::write(mem, new, &Slot::unlinked(cap, 0));
}

/// Removes a slot from the tree and empties it. Its children stay where they
/// are, and the next slot takes a barrier (module docs).
pub fn unlink<M: Mem>(mem: &mut M, slot: SlotRef) {
    let s = slot::read(mem, slot);
    if let Some(p) = s.prev {
        let mut ps = slot::read(mem, p);
        ps.next = s.next;
        slot::write(mem, p, &ps);
    }
    if let Some(n) = s.next {
        let mut ns = slot::read(mem, n);
        ns.prev = s.prev;
        ns.barrier = barrier_after(&s, &ns);
        slot::write(mem, n, &ns);
    }
    slot::write(mem, slot, &Slot::EMPTY);
}

/// The barrier of `next` once `gone`, the slot before it, is removed: the
/// shallowest of its own, `gone`'s, and `gone`'s depth, among those
/// shallower than `next`. A deleted capability deeper than or as deep as
/// `next` had `next` in no run, and leaves no barrier.
fn barrier_after(gone: &Slot, next: &Slot) -> Option<u16> {
    [next.barrier, gone.barrier, Some(gone.depth)]
        .into_iter()
        .flatten()
        .filter(|&b| b < next.depth)
        .min()
}

/// Moves the contents of slots along a permutation of at most three slots:
/// the contents of `moves[i].0` go to `moves[i].1`. The sources and the
/// destinations must be the same set of distinct slots. An empty slot moves
/// as nothing. Each capability keeps its place in the tree, with its links,
/// as seL4's `cteMove` and `cteSwap` do, and the neighbors' links follow it,
/// even when the moved slots are each other's neighbors.
pub fn permute<M: Mem>(mem: &mut M, moves: &[(SlotRef, SlotRef)]) {
    let n = moves.len().min(3);
    let moves = &moves[..n];
    let map = |s: Option<SlotRef>| {
        s.map(|s| {
            moves
                .iter()
                .find(|(from, _)| *from == s)
                .map_or(s, |&(_, to)| to)
        })
    };
    let mut olds = [Slot::EMPTY; 3];
    for (i, &(from, _)) in moves.iter().enumerate() {
        olds[i] = slot::read(mem, from);
    }
    // The neighbors outside the permutation, each once.
    let mut outside = [SlotRef(0); 6];
    let mut count = 0;
    for old in olds.iter().take(n) {
        if old.is_empty() {
            continue;
        }
        for nb in [old.prev, old.next].into_iter().flatten() {
            let moved = moves.iter().any(|(from, _)| *from == nb);
            if !moved && !outside[..count].contains(&nb) {
                outside[count] = nb;
                count += 1;
            }
        }
    }
    for (i, &(_, to)) in moves.iter().enumerate() {
        let old = olds[i];
        let new = if old.is_empty() {
            Slot::EMPTY
        } else {
            Slot {
                cap: old.cap,
                prev: map(old.prev),
                next: map(old.next),
                depth: old.depth,
                barrier: old.barrier,
            }
        };
        slot::write(mem, to, &new);
    }
    for &nb in &outside[..count] {
        let mut s = slot::read(mem, nb);
        s.prev = map(s.prev);
        s.next = map(s.next);
        slot::write(mem, nb, &s);
    }
}

/// Moves the capability in `from` into the empty slot `to`, with its place
/// in the tree.
pub fn move_slot<M: Mem>(mem: &mut M, from: SlotRef, to: SlotRef) {
    if from != to {
        permute(mem, &[(from, to), (to, from)]);
    }
}

/// Swaps the contents of two slots, each with its place in the tree.
pub fn swap_slots<M: Mem>(mem: &mut M, a: SlotRef, b: SlotRef) {
    if a != b {
        permute(mem, &[(a, b), (b, a)]);
    }
}

/// What [`verify`] found wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// A slot links to an empty slot.
    LinkToEmpty(SlotRef),
    /// A slot's neighbor doesn't link back to it.
    OneWayLink(SlotRef),
    /// The list has a cycle, or slots that no list head reaches.
    Cycle,
}

/// Checks the tree's links over `slots`, which must include every slot that
/// any of them links to: every link is two-way and leads to a full slot, and
/// following the lists from their heads reaches each full slot exactly once.
/// The tests and the kernel's own checks use it.
pub fn verify<M: Mem, I>(mem: &M, slots: I) -> Result<(), VerifyError>
where
    I: Iterator<Item = SlotRef> + Clone,
{
    let mut full = 0u64;
    for s in slots.clone() {
        let sl = slot::read(mem, s);
        if sl.is_empty() {
            continue;
        }
        full += 1;
        if let Some(p) = sl.prev {
            let ps = slot::read(mem, p);
            if ps.is_empty() {
                return Err(VerifyError::LinkToEmpty(s));
            }
            if ps.next != Some(s) {
                return Err(VerifyError::OneWayLink(s));
            }
        }
        if let Some(n) = sl.next {
            let ns = slot::read(mem, n);
            if ns.is_empty() {
                return Err(VerifyError::LinkToEmpty(s));
            }
            if ns.prev != Some(s) {
                return Err(VerifyError::OneWayLink(s));
            }
        }
    }
    let mut reached = 0u64;
    for s in slots {
        let sl = slot::read(mem, s);
        if sl.is_empty() || sl.prev.is_some() {
            continue;
        }
        let mut at = Some(s);
        while let Some(x) = at {
            reached += 1;
            if reached > full {
                return Err(VerifyError::Cycle);
            }
            at = slot::read(mem, x).next;
        }
    }
    if reached == full {
        Ok(())
    } else {
        Err(VerifyError::Cycle)
    }
}
