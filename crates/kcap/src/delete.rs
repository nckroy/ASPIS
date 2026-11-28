// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Complete, preemptible delete and revoke (ADR 0049, rule 4; ADR 0052,
//! rule 2; kernel specification, "Derivation and revocation").
//!
//! **Delete** removes one slot. If the capability is a binding, its unbind
//! hook runs first, whether or not it is final. If it is the last capability
//! to an object without slots, the object's finish hook runs. If it is the
//! last capability to an object with slots (a CNode, an address space, a
//! thread or a wait set), it becomes a zombie in place, keeping its place in
//! the tree, and the deletion goes on to clear the object's slots, one unit
//! at a time. If it is the last capability to an endpoint or an eventcount
//! (C14), it becomes a queue zombie in place, and the deletion releases the
//! object's waiters, one per unit, before it finishes the object.
//!
//! **Revoke** deletes every descendant of a capability and leaves the
//! capability itself. It keeps no state of its own: each unit it takes the
//! first descendant afresh and takes one unit of deleting it, so the tree's
//! list order decides the order, most recently derived first, as seL4's
//! `cteRevoke`. A descendant that became a zombie keeps its place, and so
//! stays the first descendant until its object is finished. So a preempted
//! revoke, restarted, does exactly what an unpreempted one does.
//!
//! **Zombies.** Zombie(o, n) means that slots `[0, n)` of o's slot array are
//! still to clear; slots `n` and up are empty, but for the zombie's own slot
//! if it lies there. Because the zombie stays in the tree, o's untyped
//! memory can't be reset until o is finished. A deletion runs from the slot
//! S it started at. One step at a slot s that holds Zombie(o, n), with e
//! the end slot o[n-1] and o0 the park slot o[0]:
//!
//! 1. n = 0: run o's finish hook, and empty s.
//! 2. e is s itself, or empty: n - 1.
//! 3. e holds a capability that isn't final, or is the last to an object
//!    without slots: delete it in place (unbind, finish, unlink). n - 1.
//! 4. e holds the last capability to an object p with slots: unbind it if it
//!    is a binding, and make it Zombie(p) in place.
//! 5. e holds Zombie(p, m):
//!    - if p is a queue zombie, step e once, in place (below);
//!    - if m = 0, step e once, in place: p is finished there;
//!    - else if s lies among o's own slots, step e once, in place. This is
//!      depth one at most: e lies in o, so never among p's slots;
//!    - else if n = 1 and s is S, and S doesn't lie among p's slots, step
//!      e once, in place. Such a step may hand over into o0 but never moves
//!      S's zombie, so S keeps Zombie(o) until o is finished;
//!    - else if n = 1, hand over: finish o, empty s, and move Zombie(p) into
//!      s, where its object is cleared next. At S this happens only when S
//!      lies among p's slots: a cycle that S entered;
//!    - else if p's park slot is s or S, swap o0 and e, so p is handed over
//!      last;
//!    - else defer p: o0 takes Zombie(p), p's park slot takes o0's old
//!      contents, and e takes the park slot's old contents. The zombies
//!      waiting at o0 and in each one's park slot form a stack that the
//!      hand-overs unwind.
//!
//! **Queue zombies** (C14). An endpoint or an eventcount has no slots, so
//! its zombie has an empty slot array, and none of the rules above reads
//! its words. Zombie(o, 1) means o's queue is still to drain: each step
//! asks the drain hook to release one waiter, and the step that leaves
//! none, or finds none, finishes o and empties the slot. A nested queue zombie, at o's end
//! slot, at a park slot or at S itself, is always stepped in place: it has
//! no slots of its own, so nothing is handed over or deferred to it, and
//! its step never recurses. Its queue only shrinks: a zombie can't be
//! named, so no thread joins it (kernel specification, "Why deletion
//! ends"). seL4's `cancelAllIPC` releases every waiter at once instead;
//! ASPIS bounds the work under the lock (ADR 0052, rule 2).
//!
//! seL4's `reduceZombie` instead parks a nested object's zombie in that
//! object's own first slot and leaves it for a later revocation of its
//! untyped memory. ASPIS finishes it in the same deletion, as ADR 0049,
//! rule 4 requires ("when the last capability to an object is deleted, the
//! object is destroyed"), with O(1) work per step, no recursion and no
//! memory of its own. ADR 0047, rule 3 lists this departure, and the kernel
//! specification gives the argument that it ends.
//!
//! **What moves.** Only zombies and the contents of park slots move, each
//! with its place in the tree. A park slot never holds a binding, so a
//! binding never moves: its unbind hook may find its object from the slot's
//! address. A binding's unbind runs when it is deleted, or first made a
//! zombie (C12, C13b and C14 must keep that rule for the bindings they add).
//!
//! **Anyone may step any zombie.** Each zombie needs only its own object, so
//! a revocation that reaches a waiting zombie through the tree may step it
//! where it is, and the deletion it waits in stays consistent. Another
//! deletion may also move a zombie out of the slot its deletion started at,
//! when that slot lies in an object the other deletion clears. So a delete
//! returns once its slot is empty; the object it made a zombie is then
//! finished, or adopted by the deletion of an enclosing object, which
//! finishes it.

use crate::SlotRef;
use crate::cap::{Cap, SlotArray};
use crate::mdb;
use crate::preempt::{Budget, Pending, Preempted};
use crate::slot::{self, Mem};

/// The kernel's work when a deletion removes a binding or the last
/// capability to an object.
///
/// Each hook returns the units of work it took (kernel specification, K23):
/// 1 for work of constant size, more when it ends waits, which count the
/// waiter nodes they unlink (C14's wait sets, and the take-backs that end
/// a holder's wait on one). A step that runs two hooks counts its base unit
/// once: 1, and each hook's units beyond its first.
pub trait Hooks {
    /// The last capability to an object is gone: for an object without
    /// slots or queue, the capability itself; for one with slots, its
    /// zombie, once every slot is clear; for an endpoint or an eventcount,
    /// its queue zombie, once no waiter is left (C14). C11's kernel
    /// deactivates an address space and releases its ASID; a CNode, a
    /// frame and untyped memory need nothing. C12's reply object and
    /// scheduling context may take a context back, which ends its holder's
    /// wait. Returns the units it took, at least 1.
    fn finish(&mut self, cap: &Cap) -> u32;

    /// A binding is being removed from `slot`: the capability is about to be
    /// deleted or made a zombie. C11's kernel unmaps a frame binding from
    /// the address space whose record holds `slot`. C12's context binding
    /// may take a donated context back, which ends its holder's wait.
    /// Returns the units it took, at least 1.
    fn unbind(&mut self, slot: SlotRef, cap: &Cap) -> u32;

    /// The last capability to an object with slots or a queue, `cap`, is
    /// about to become a zombie: before any of the object's slots is
    /// cleared or any waiter released (C12, C14). Returns the units of work
    /// it took, at least 1.
    ///
    /// A thread's object stops here: the kernel takes it out of every queue
    /// and ends its wait, so it never runs again while its zombie clears its
    /// slots across preemptions, as seL4's `finaliseCap` suspends a thread
    /// when it makes its zombie; its units count the waits it ends, a
    /// take-back's included (C14). A wait set's wait ends "object destroyed",
    /// and its entries leave their eventcounts' trees: one unit and one per
    /// entry it unlinks (C14). A CNode, an address space, an endpoint and
    /// an eventcount need nothing.
    fn zombify(&mut self, _cap: &Cap) -> u32 {
        1
    }

    /// One step of the queue zombie `zombie` (an endpoint's or an
    /// eventcount's, C14): release one waiter, if any is left. Returns
    /// true when none is left, and the object may be finished.
    fn drain(&mut self, _zombie: &Cap) -> bool {
        true
    }
}

/// One unit of deleting the slot `s`: delete or zombify its capability, or
/// one step of its zombie. Returns the units it took: 1, or more when a
/// hook did more ([`Hooks`]).
pub fn delete_unit<M: Mem, H: Hooks>(mem: &mut M, hooks: &mut H, s: SlotRef) -> u32 {
    let cap = slot::cap(mem, s);
    match cap {
        Cap::Null => 1,
        Cap::Zombie { .. } => step(mem, hooks, s, s),
        _ => remove(mem, hooks, s, cap),
    }
}

/// Removes a capability that isn't a zombie: unbind it if it is a binding;
/// then, if it is the last to an object with slots or a queue, make it a
/// zombie in place; otherwise finish its object if it is the last, and
/// unlink it. Returns the units it took.
fn remove<M: Mem, H: Hooks>(mem: &mut M, hooks: &mut H, s: SlotRef, cap: Cap) -> u32 {
    let last = mdb::is_final(mem, s);
    let mut units = 1u32;
    if cap.is_binding() {
        units = add(units, hooks.unbind(s, &cap));
    }
    match (last, cap.zombie()) {
        (true, Some(z)) => {
            units = add(units, hooks.zombify(&cap));
            slot::set_cap(mem, s, z);
        }
        _ => {
            if last {
                units = add(units, hooks.finish(&cap));
            }
            mdb::unlink(mem, s);
        }
    }
    units
}

/// A step's `units` with a hook's `more` added: its units beyond its first,
/// which the step's base unit covers ([`Hooks`]).
fn add(units: u32, more: u32) -> u32 {
    units.saturating_add(more.saturating_sub(1))
}

/// One step of the zombie in slot `s` (module docs), for the deletion that
/// started at `outer`. When `s` isn't `outer`, this is a step delegated
/// from `outer`'s zombie to its end slot, which delegates no further but to
/// a queue zombie, whose step delegates nothing. Returns the units it took.
fn step<M: Mem, H: Hooks>(mem: &mut M, hooks: &mut H, s: SlotRef, outer: SlotRef) -> u32 {
    let zombie = slot::cap(mem, s);
    let Cap::Zombie { kind, ptr, n } = zombie else {
        return 1;
    };
    // A queue zombie first: it has no slot array (module docs).
    if kind.is_queue() {
        if n == 0 || hooks.drain(&zombie) {
            let units = hooks.finish(&zombie);
            mdb::unlink(mem, s);
            return units.max(1);
        }
        return 1;
    }
    let top = s == outer;
    let Some(array) = SlotArray::of(kind, ptr) else {
        mem.corrupt(s);
    };
    let set_n = |mem: &mut M, n| slot::set_cap(mem, s, Cap::Zombie { kind, ptr, n });
    // Rule 1: every slot is clear.
    if n == 0 {
        let units = hooks.finish(&zombie);
        mdb::unlink(mem, s);
        return units.max(1);
    }
    let e = array.slot(n - 1);
    let ec = if e == s { Cap::Null } else { slot::cap(mem, e) };
    match ec {
        // Rule 2.
        Cap::Null => set_n(mem, n - 1),
        // Rule 5, for a queue zombie: it has no slots, so it is stepped
        // where it is, whoever started the deletion.
        Cap::Zombie { kind: pk, .. } if pk.is_queue() => return step(mem, hooks, e, outer),
        // Rule 5.
        Cap::Zombie {
            kind: pk,
            ptr: pp,
            n: pn,
        } => {
            let Some(nested) = SlotArray::of(pk, pp) else {
                mem.corrupt(e);
            };
            if pn == 0 {
                // p is clear: finish it where it is (rule 1 at e).
                return step(mem, hooks, e, outer);
            } else if array.contains(s) {
                // s lies in o: work on the nested zombie where it is.
                if top {
                    return step(mem, hooks, e, outer);
                } else {
                    // e lies among the slots of the object whose zombie
                    // delegated to it, so its own object can't hold it.
                    mem.corrupt(e);
                }
            } else if n == 1 && top && !nested.contains(outer) {
                // o is clear but for its park slot: clear p there, and keep
                // o's zombie, with its place in the tree, until p is done.
                return step(mem, hooks, e, outer);
            } else if n == 1 {
                // Hand over: o is clear but for e.
                let units = hooks.finish(&zombie);
                mdb::unlink(mem, s);
                mdb::move_slot(mem, e, s);
                return units.max(1);
            } else {
                let o0 = array.park();
                let p0 = nested.park();
                if p0 == s || p0 == outer {
                    swap_or_corrupt(mem, o0, e);
                } else {
                    mdb::permute(mem, &[(e, o0), (o0, p0), (p0, e)]);
                }
            }
        }
        // Rules 3 and 4.
        other => {
            let units = remove(mem, hooks, e, other);
            if slot::is_empty(mem, e) {
                set_n(mem, n - 1);
            }
            return units;
        }
    }
    1
}

fn swap_or_corrupt<M: Mem>(mem: &mut M, a: SlotRef, b: SlotRef) {
    if a == b {
        mem.corrupt(a);
    }
    mdb::swap_slots(mem, a, b);
}

/// Deletes the capability in `s`, with everything only it reaches. On
/// [`Preempted`], call again with the same slot to go on.
///
/// [`Preempted`] always leaves `s` holding the deletion's zombie: the unit
/// that empties the slot still counts against the budget, but a preemption
/// point after it finds the deletion done, and it returns `Ok`, as seL4's
/// `finaliseSlot` takes its last preemption point before `emptySlot`.
/// Otherwise a call made again would find the slot empty, and anything
/// another thread put there meanwhile would be deleted in its place
/// (kernel specification, "The kernel lock and long operations").
pub fn delete<M: Mem, H: Hooks, P: Pending>(
    mem: &mut M,
    hooks: &mut H,
    s: SlotRef,
    budget: &mut Budget<P>,
) -> Result<(), Preempted> {
    while !slot::is_empty(mem, s) {
        let units = delete_unit(mem, hooks, s);
        if slot::is_empty(mem, s) {
            // Done: the units count towards the next check, but this
            // check's result can't stop a deletion that has ended.
            let _ = budget.tick(units);
            return Ok(());
        }
        budget.tick(units)?;
    }
    Ok(())
}

/// Deletes every descendant of the capability in `r`, and leaves `r`. On
/// [`Preempted`], call again with the same slot to go on.
///
/// Each unit takes the first descendant afresh and takes one unit of
/// deleting it. A descendant made a zombie keeps its place, so it stays the
/// first descendant until its object, and every object that only it
/// reached, is finished. The one exception is a cycle the descendant's slot
/// lies in: objects that hold each other's last capabilities, one of them
/// holding the descendant. Then the hand-over moves the nested zombie into
/// the slot, with its place among the descendants of its own untyped
/// memory, and the revoke goes on without it: what is left of the cycle can
/// be named by no lookup, and revoking its untyped memory finishes it.
///
/// If `r` itself lies in a descendant's object, the revoke deletes it
/// partway and stops, as seL4's does. Its remaining descendants stay under
/// its parent.
pub fn revoke<M: Mem, H: Hooks, P: Pending>(
    mem: &mut M,
    hooks: &mut H,
    r: SlotRef,
    budget: &mut Budget<P>,
) -> Result<(), Preempted> {
    while let Some(d) = mdb::first_child(mem, r) {
        let units = delete_unit(mem, hooks, d);
        budget.tick(units)?;
    }
    Ok(())
}
