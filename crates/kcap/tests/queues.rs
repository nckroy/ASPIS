// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! C14's objects in deletion: queue zombies and wait sets (kernel
//! specification, "Derivation and revocation"; ADR 0049, rule 4; ADR 0052,
//! rule 2).
//!
//! Deleting the last capability to an endpoint or an eventcount leaves a
//! queue zombie, which releases one waiter per unit. Its object has no
//! slots, and the test memory poisons its words, so any deletion that read
//! them as slots would panic. Every scenario runs never preempted,
//! preempted after every unit, and preempted at random, and must end the
//! same way. A wait set is an object with slots: its entries' copies are
//! cleared as any zombie's slots are, and its zombify reports the units it
//! took.

mod common;

use common::{MODES, Mode, ObjKey, World, budget, key, ram, root, sl};
use kcap::SlotRef;
use kcap::cap::{Binding, Cap, SlotArray, ZombieKind};
use kcap::delete;
use kcap::mdb;
use kcap::ops::{self, Error, copy, move_cap};
use kcap::preempt::{Always, Budget};
use kcap::rights::Rights;
use kmem::untyped::ObjectType;

/// Makes one object from `ut` into slot `idx` of the CNode `dest`.
fn into(w: &mut World, ut: SlotRef, ty: ObjectType, dest: Cap, idx: u64) -> SlotRef {
    w.retype_into(ut, ty, dest, idx, 1)
        .unwrap_or_else(|e| panic!("{ty:?}: {e:?}"));
    cslot(dest, idx)
}

/// Slot `i` of a CNode.
fn cslot(c: Cap, i: u64) -> SlotRef {
    let Cap::CNode { ptr, .. } = c else {
        panic!("not a CNode: {c:x?}")
    };
    SlotRef(ptr).offset(i)
}

/// A child piece of `2^bits` bytes in root slot `i`.
fn piece(w: &mut World, bits: u8, i: u64) -> SlotRef {
    w.retype(ram(), ObjectType::Untyped(bits), i, 1).unwrap();
    sl(i)
}

/// Gives the endpoint or eventcount in `s` `k` modeled waiters.
fn wait_on(w: &mut World, s: SlotRef, k: u64) {
    let (base, _) = w.cap(s).object().unwrap();
    w.log.waiters.insert(base, k);
}

/// What a scenario ends with, for comparing the three ways.
#[derive(Debug, PartialEq)]
struct End {
    slots: std::collections::BTreeMap<u64, [u64; 4]>,
    finished: Vec<ObjKey>,
    unbound: Vec<(u64, [u64; 2])>,
    drained: u64,
}

fn end(w: &World) -> End {
    let mut finished: Vec<ObjKey> = w.log.finished.iter().map(key).collect();
    finished.sort();
    let mut unbound: Vec<(u64, [u64; 2])> = w
        .log
        .unbound
        .iter()
        .map(|(s, c)| (s.0, c.encode()))
        .collect();
    unbound.sort();
    End {
        slots: w.mem.snapshot(),
        finished,
        unbound,
        drained: w.log.drained,
    }
}

/// Runs a scenario all three ways and checks they agree. Returns the
/// unpreempted world.
fn three_ways(scenario: impl Fn(&mut World, Mode)) -> World {
    let mut first: Option<(World, End)> = None;
    for mode in MODES {
        let mut w = World::new();
        scenario(&mut w, mode);
        w.check();
        let e = end(&w);
        match &first {
            None => first = Some((w, e)),
            Some((_, e0)) => assert_eq!(&e, e0, "{mode:?} ends differently"),
        }
    }
    first.map(|(w, _)| w).unwrap()
}

/// Deletes `s` one unit at a time, checking the tree after each; returns
/// the units it took.
fn units_to_delete(w: &mut World, s: SlotRef) -> u64 {
    let mut units = 0;
    while !w.empty(s) {
        delete::delete_unit(&mut w.mem, &mut w.log, s);
        units += 1;
        w.check();
        assert!(units < 100_000, "the delete never ends");
    }
    units
}

#[test]
fn the_last_endpoint_drains_one_waiter_per_unit() {
    for ty in [ObjectType::Endpoint, ObjectType::Eventcount] {
        for k in [0u64, 1, 5, 300] {
            let mut w = World::new();
            let e = w.make(ty, 40);
            wait_on(&mut w, e, k);
            let zombie = w.cap(e).zombie().unwrap();
            // One unit makes the queue zombie in place, keeping its place
            // in the tree; then each unit releases one waiter, and the one
            // that leaves none, or finds none, finishes the object.
            delete::delete_unit(&mut w.mem, &mut w.log, e);
            assert_eq!(w.cap(e), zombie, "{ty:?}");
            assert!(w.log.finished.is_empty());
            let units = 1 + units_to_delete(&mut w, e);
            assert_eq!(units, 1 + k.max(1), "{ty:?} with {k} waiters");
            assert_eq!(w.log.drained, k);
            assert_eq!(w.log.finished, [zombie]);
            assert_eq!(w.log.order.first(), Some(&'z'));
            assert_eq!(w.log.order.last(), Some(&'f'));
            assert!(!mdb::has_children(&w.mem, ram()) || w.log.live.len() == 3);
        }
    }
}

#[test]
fn a_copy_that_isnt_the_last_drains_nothing() {
    let mut w = World::new();
    let e = w.make(ObjectType::Endpoint, 40);
    wait_on(&mut w, e, 7);
    copy(&mut w.mem, e, sl(41)).unwrap();
    w.delete(sl(41));
    assert_eq!((w.log.drained, w.log.finished.len()), (0, 0));
    assert!(w.log.zombified.is_empty());
    // The original is now the last: its deletion drains all seven.
    w.delete(e);
    assert_eq!(w.log.drained, 7);
    assert_eq!(w.log.finished.len(), 1);
}

#[test]
fn restarted_deletes_and_revokes_end_as_unpreempted_ones() {
    let w = three_ways(|w, mode| {
        let p = piece(w, 20, 20);
        let cn = into(w, p, ObjectType::CNode(4), root(), 32);
        let c = w.cap(cn);
        for i in 0..8 {
            let ty = if i % 2 == 0 {
                ObjectType::Endpoint
            } else {
                ObjectType::Eventcount
            };
            let s = into(w, p, ty, c, i);
            wait_on(w, s, 3 * i);
        }
        // A copy of one inside the CNode, and another outside it.
        copy(&mut w.mem, cslot(c, 0), cslot(c, 9)).unwrap();
        copy(&mut w.mem, cslot(c, 1), sl(50)).unwrap();
        // Deleting the CNode finishes the endpoints and eventcounts whose
        // last capability it held; the one with a copy outside survives.
        w.delete_mode(cn, mode);
        assert!(!w.empty(sl(50)));
        w.revoke_mode(p, mode);
        assert!(!mdb::has_children(&w.mem, p));
    });
    // The CNode and eight queue objects, every waiter released once.
    assert_eq!(w.log.finished.len(), 9);
    assert_eq!(w.log.drained, (0..8).map(|i| 3 * i).sum::<u64>());
}

/// Deletes `s` under a budget whose every check preempts, restarting the
/// call as a system call would, until it ends.
fn delete_always(w: &mut World, s: SlotRef) -> usize {
    let mut restarts = 0;
    loop {
        let mut b = Budget::with_threshold(Always, 1);
        match delete::delete(&mut w.mem, &mut w.log, s, &mut b) {
            Ok(()) => return restarts,
            Err(_) => restarts += 1,
        }
        w.check();
        assert!(restarts < 1_000_000, "the delete never ends");
    }
}

#[test]
fn queue_zombie_is_s() {
    // The deletion starts at the queue object's own last capability.
    let mut w = World::new();
    let e = w.make(ObjectType::Eventcount, 40);
    wait_on(&mut w, e, 50);
    let restarts = delete_always(&mut w, e);
    assert!(w.empty(e));
    assert_eq!((w.log.drained, w.log.finished.len()), (50, 1));
    // Zombify, then 50 drains: every unit but the last, which empties the
    // slot and so ends the call, is a restart.
    assert_eq!(restarts, 50, "one restart per unit but the last");
}

#[test]
fn a_deletion_that_empties_its_slot_is_never_preempted() {
    // The unit that empties the slot ticks the budget, but a preemption
    // point after it can't stop a deletion that has ended: it returns Ok,
    // so a preempted delete always leaves its zombie in the slot, and a
    // restart never deletes what another thread put there since.
    let mut w = World::new();
    let e = w.make(ObjectType::Eventcount, 40);
    let c = sl(41);
    copy(&mut w.mem, e, c).unwrap();
    let mut b = Budget::with_threshold(Always, 1);
    // A copy that isn't the last: one unit, which empties the slot.
    assert_eq!(delete::delete(&mut w.mem, &mut w.log, c, &mut b), Ok(()));
    assert!(w.empty(c));
    // The last capability, with waiters: preempted while the zombie
    // drains, and never once the slot is empty.
    wait_on(&mut w, e, 3);
    let mut seen_empty_preempted = false;
    loop {
        let mut b = Budget::with_threshold(Always, 1);
        let r = delete::delete(&mut w.mem, &mut w.log, e, &mut b);
        if r.is_err() && w.empty(e) {
            seen_empty_preempted = true;
        }
        if r.is_ok() {
            break;
        }
        assert!(matches!(w.cap(e), Cap::Zombie { .. }));
    }
    assert!(!seen_empty_preempted, "preempted with its slot empty");
    assert!(w.empty(e));
    w.check();
}

#[test]
fn queue_zombie_at_end_slot() {
    // A CNode's last slot holds an endpoint's last capability: its zombie
    // drains where it is, at the CNode's end slot, and the CNode's zombie
    // waits for it.
    let mut w = World::new();
    let cn = w.make(ObjectType::CNode(2), 40);
    let c = w.cap(cn);
    let ep = into(&mut w, ram(), ObjectType::Endpoint, c, 3);
    wait_on(&mut w, ep, 20);
    delete_always(&mut w, cn);
    assert!(w.empty(cn));
    assert_eq!((w.log.drained, w.log.finished.len()), (20, 2));
    let Cap::Zombie {
        kind: ZombieKind::Endpoint,
        ..
    } = w.log.finished[0]
    else {
        panic!("the endpoint wasn't finished first: {:x?}", w.log.finished)
    };
}

#[test]
fn queue_zombie_at_park_slot() {
    // A CNode's slot 0, its park slot, holds an eventcount's last
    // capability, and slot 1 an endpoint's: each drains in place.
    let mut w = World::new();
    let cn = w.make(ObjectType::CNode(1), 40);
    let c = w.cap(cn);
    let ec = into(&mut w, ram(), ObjectType::Eventcount, c, 0);
    let ep = into(&mut w, ram(), ObjectType::Endpoint, c, 1);
    wait_on(&mut w, ec, 9);
    wait_on(&mut w, ep, 4);
    delete_always(&mut w, cn);
    assert!(w.empty(cn));
    assert_eq!((w.log.drained, w.log.finished.len()), (13, 3));
}

#[test]
fn queue_zombie_in_cnode_cycle() {
    // Two CNodes hold each other's last capabilities, and each holds an
    // endpoint or eventcount with waiters, one of them in a park slot.
    // Revoking their piece, every check preempting, finishes the cycle and
    // releases every waiter once.
    for p_park in [true, false] {
        let mut w = World::new();
        let p = piece(&mut w, 20, 20);
        let o = into(&mut w, p, ObjectType::CNode(2), root(), 32);
        let q = into(&mut w, p, ObjectType::CNode(2), root(), 33);
        let (oc, qc) = (w.cap(o), w.cap(q));
        let a = into(&mut w, p, ObjectType::Endpoint, oc, 0);
        let b = into(&mut w, p, ObjectType::Eventcount, qc, 2);
        let d = into(&mut w, p, ObjectType::Eventcount, oc, 1);
        wait_on(&mut w, a, 6);
        wait_on(&mut w, b, 5);
        wait_on(&mut w, d, 0);
        move_cap(&mut w.mem, o, cslot(qc, if p_park { 0 } else { 1 })).unwrap();
        move_cap(&mut w.mem, q, cslot(oc, 3)).unwrap();
        w.check();
        let mut restarts = 0;
        loop {
            let mut bud = Budget::with_threshold(Always, 1);
            if delete::revoke(&mut w.mem, &mut w.log, p, &mut bud).is_ok() {
                break;
            }
            w.check();
            restarts += 1;
            assert!(restarts < 1_000_000);
        }
        w.check();
        assert!(!mdb::has_children(&w.mem, p));
        assert_eq!((w.log.drained, w.log.finished.len()), (11, 5));
    }
}

/// A wait set of `2^bits` bytes in root slot `i`, with an entry for each
/// of `ecs`, in entry slots 1, 2 and on.
fn wait_set(w: &mut World, bits: u8, i: u64, ecs: &[SlotRef]) -> (SlotRef, SlotArray) {
    let s = w.make(ObjectType::WaitSet(bits), i);
    let Cap::WaitSet { ptr, .. } = w.cap(s) else {
        panic!()
    };
    let a = SlotArray::of_wait_set(ptr, bits);
    for (j, &e) in ecs.iter().enumerate() {
        let dst = a.slot(1 + j as u64);
        let b = ops::bind_entry(&mut w.mem, e, dst, bits).unwrap();
        assert_eq!(b.binding(), Some(Binding::WaitSetEntry));
        assert_eq!(w.depth(dst), w.depth(e) + 1);
    }
    (s, a)
}

#[test]
fn wait_sets_hold_their_entries_as_bindings() {
    for bits in 7u8..=12 {
        let mut w = World::new();
        let n = kmem::untyped::wait_set_entries(bits);
        let ecs: Vec<SlotRef> = (0..n)
            .map(|i| w.make(ObjectType::Eventcount, 64 + i))
            .collect();
        let (s, a) = wait_set(&mut w, bits, 40, &ecs);
        assert_eq!(a.count, 1 << (bits - 6));
        w.check();
        // An entry's role needs an eventcount; its slot is taken once.
        let ep = w.make(ObjectType::Endpoint, 41);
        assert_eq!(
            ops::bind_entry(&mut w.mem, ep, a.slot(a.count - 1), bits).err(),
            if n + 1 == a.count {
                Some(Error::DestNotEmpty)
            } else {
                Some(Error::WrongKind)
            }
        );
        assert_eq!(
            ops::bind_entry(&mut w.mem, ecs[0], a.slot(1), bits),
            Err(Error::DestNotEmpty)
        );
        // An entry never moves, and a copy of it is the plain eventcount.
        assert_eq!(
            move_cap(&mut w.mem, a.slot(1), sl(60)),
            Err(Error::NotDerivable)
        );
        copy(&mut w.mem, a.slot(1), sl(61)).unwrap();
        assert_eq!(w.cap(sl(61)).binding(), None);
        assert!(w.cap(sl(61)).same_object(&w.cap(ecs[0])));
        // Revoking an eventcount's capability removes its entry: the unbind
        // runs once, at the entry's slot, and the copy made from it goes.
        w.revoke(ecs[0]);
        assert!(w.empty(a.slot(1)) && w.empty(sl(61)));
        assert_eq!(w.log.unbound.len(), 1);
        assert_eq!(w.log.unbound[0].0, a.slot(1));
        // Deleting the set: its zombify reports 1 plus the entries it
        // unlinks, which the deletion counts, then each entry's unbind runs
        // once as its slot is cleared.
        let (base, _) = w.cap(s).object().unwrap();
        w.log.zombify_units.insert(base, n as u32);
        let units = delete::delete_unit(&mut w.mem, &mut w.log, s);
        assert_eq!(units, (n as u32).max(1));
        assert_eq!(
            w.cap(s),
            Cap::Zombie {
                kind: ZombieKind::WaitSet { bits },
                ptr: base,
                n: a.count
            }
        );
        w.check();
        w.delete_mode(s, Mode::Every);
        assert_eq!(w.log.unbound.len() as u64, n);
        assert!((1..a.count).all(|i| w.empty(a.slot(i))));
        assert_eq!(
            w.log.zombified.last().map(|c| c.kind()),
            Some(kcap::cap::Kind::WaitSet)
        );
        w.check();
    }
}

#[test]
fn a_wait_set_in_its_own_entry_cycle_is_finished_by_its_piece() {
    // A wait set's entries hold copies of eventcounts whose last
    // capabilities lie in a CNode that the set can't hold, so no cycle
    // forms through a wait set; revoking the piece finishes everything,
    // all three ways.
    let w = three_ways(|w, mode| {
        let p = piece(w, 20, 20);
        let cn = into(w, p, ObjectType::CNode(2), root(), 32);
        let c = w.cap(cn);
        let e0 = into(w, p, ObjectType::Eventcount, c, 0);
        let e1 = into(w, p, ObjectType::Eventcount, c, 1);
        wait_on(w, e0, 2);
        let ws = into(w, p, ObjectType::WaitSet(8), c, 2);
        let Cap::WaitSet { ptr, bits, .. } = w.cap(ws) else {
            panic!()
        };
        let a = SlotArray::of_wait_set(ptr, bits);
        ops::bind_entry(&mut w.mem, e0, a.slot(1), bits).unwrap();
        ops::bind_entry(&mut w.mem, e1, a.slot(3), bits).unwrap();
        ops::bind_entry(&mut w.mem, e1, a.slot(2), bits).unwrap();
        w.revoke_mode(p, mode);
        assert!(!mdb::has_children(&w.mem, p));
    });
    // The CNode, two eventcounts and the wait set; three entries unbound.
    assert_eq!(w.log.finished.len(), 4);
    assert_eq!(w.log.unbound.len(), 3);
    assert_eq!(w.log.drained, 2);
}

#[test]
fn bindings_in_thread_slots_6_and_7() {
    // C14's thread roles: a bound eventcount in slot 6 and the IPC
    // buffer's frame in slot 7 (kernel specification K07 and K29). Each is
    // a child of the capability presented; each unbind runs once.
    let mut w = World::new();
    let t = w.make(ObjectType::Thread, 40);
    let ec = w.make(ObjectType::Eventcount, 41);
    let fr = w.make(ObjectType::Frame4K, 42);
    let Cap::Thread { ptr, .. } = w.cap(t) else {
        panic!()
    };
    let a = SlotArray::of_thread(ptr);
    let (s6, s7) = (a.slot(6), a.slot(7));
    assert_eq!(
        ops::bind_copy(&mut w.mem, fr, s6, Binding::BoundEventcount),
        Err(Error::WrongKind)
    );
    assert_eq!(
        ops::bind_copy(&mut w.mem, ec, s7, Binding::IpcBuffer),
        Err(Error::WrongKind)
    );
    let b6 = ops::bind_copy(&mut w.mem, ec, s6, Binding::BoundEventcount).unwrap();
    let b7 = ops::bind_copy(&mut w.mem, fr, s7, Binding::IpcBuffer).unwrap();
    assert_eq!(
        (b6.binding(), b7.binding()),
        (Some(Binding::BoundEventcount), Some(Binding::IpcBuffer))
    );
    assert_eq!((w.cap(s6), w.cap(s7)), (b6, b7));
    w.check();
    // The kept copies never move; copies of them drop the role.
    assert_eq!(move_cap(&mut w.mem, s7, sl(60)), Err(Error::NotDerivable));
    copy(&mut w.mem, s7, sl(61)).unwrap();
    copy(&mut w.mem, s6, sl(62)).unwrap();
    assert_eq!(
        (w.cap(sl(61)).binding(), w.cap(sl(62)).binding()),
        (None, None)
    );
    assert!(matches!(
        w.cap(sl(61)),
        Cap::Frame {
            mapping: None,
            binding: None,
            rights: Rights::ALL,
            ..
        }
    ));
    // Revoking the frame unregisters the buffer: slot 7's unbind runs, and
    // the copy made from it goes too.
    w.revoke(fr);
    assert!(w.empty(s7) && w.empty(sl(61)));
    assert_eq!(w.log.unbound, [(s7, b7)]);
    // Deleting the thread unbinds slot 6, once.
    w.delete(t);
    assert_eq!(w.log.unbound.len(), 2);
    assert_eq!(w.log.unbound[1], (s6, b6));
    assert!(
        !w.empty(sl(62)),
        "the copy of the binding stays under the eventcount"
    );
    w.check();
}

#[test]
fn zombify_units_reach_the_budget() {
    // A wait set's zombify reports its units; a delete ticks its budget
    // with them, so a check comes after them, not after one.
    let mut w = World::new();
    let ws = w.make(ObjectType::WaitSet(12), 40);
    let (base, _) = w.cap(ws).object().unwrap();
    w.log.zombify_units.insert(base, 61);
    let mut b = budget(Mode::Never);
    // Never preempted: it runs to the end, whatever the units.
    delete::delete(&mut w.mem, &mut w.log, ws, &mut b).unwrap();
    assert!(w.empty(ws));
    // Under a budget that checks every 100 units, 61 units of zombify and
    // the 64 slot steps after it reach one check within the first 100.
    let mut w = World::new();
    let ws = w.make(ObjectType::WaitSet(12), 40);
    let (base, _) = w.cap(ws).object().unwrap();
    w.log.zombify_units.insert(base, 61);
    let mut b = Budget::new(Always);
    assert!(delete::delete(&mut w.mem, &mut w.log, ws, &mut b).is_err());
    assert!(w.cap(ws).is_zombie());
    let Cap::Zombie { n, .. } = w.cap(ws) else {
        panic!()
    };
    // 61 + (64 - n) units were done when the check came: at least 100.
    assert_eq!(61 + (64 - n), 100);
}

#[test]
fn hook_units_reach_the_step() {
    // K23 (C14): a deletion step counts the units its hooks report, not
    // one. A thread's zombify ends its waits, a reply object's finish may
    // take a context back, and a context binding's unbind may too; each
    // can end a wait on a wait set of 60 entries.
    let mut w = World::new();
    let t = w.make(ObjectType::Thread, 40);
    let (tb, _) = w.cap(t).object().unwrap();
    w.log.zombify_units.insert(tb, 121);
    assert_eq!(delete::delete_unit(&mut w.mem, &mut w.log, t), 121);
    assert!(w.cap(t).is_zombie());
    // A reply object's last capability: its finish's units.
    let r = w.make(ObjectType::Reply, 41);
    let (rb, _) = w.cap(r).object().unwrap();
    w.log.finish_units.insert(rb, 62);
    assert_eq!(delete::delete_unit(&mut w.mem, &mut w.log, r), 62);
    assert!(w.empty(r));
    // A context bound in a thread's slot 5, not its last capability: the
    // unbind's units. Both hooks run when the binding is also the last:
    // the step's base unit is counted once.
    let t2 = w.make(ObjectType::Thread, 42);
    let c = w.make(ObjectType::SchedContext(8), 43);
    let Cap::Thread { ptr, .. } = w.cap(t2) else {
        panic!()
    };
    let s5 = SlotArray::of_thread(ptr).slot(5);
    ops::bind_copy(&mut w.mem, c, s5, Binding::Context).unwrap();
    let (cb, _) = w.cap(c).object().unwrap();
    w.log.unbind_units.insert(cb, 60);
    w.log.finish_units.insert(cb, 7);
    assert_eq!(delete::delete_unit(&mut w.mem, &mut w.log, s5), 60);
    ops::bind_copy(&mut w.mem, c, s5, Binding::Context).unwrap();
    assert_eq!(delete::delete_unit(&mut w.mem, &mut w.log, c), 1);
    assert_eq!(
        delete::delete_unit(&mut w.mem, &mut w.log, s5),
        1 + 59 + 6,
        "the last capability, a binding: unbind, then finish"
    );
    assert!(w.empty(s5));
    // A budget sees them: 121 units reach a check at once.
    let mut w = World::new();
    let t = w.make(ObjectType::Thread, 40);
    let (tb, _) = w.cap(t).object().unwrap();
    w.log.zombify_units.insert(tb, 121);
    let mut b = Budget::new(Always);
    assert!(delete::delete(&mut w.mem, &mut w.log, t, &mut b).is_err());
    let Cap::Zombie { n, .. } = w.cap(t) else {
        panic!("not a zombie: {:x?}", w.cap(t))
    };
    assert_eq!(n, kcap::cap::THREAD_SLOTS, "no slot step ran");
    w.check();
}
