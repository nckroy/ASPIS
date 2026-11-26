// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Delete and revoke: complete, preemptible, with no recursion. Every
//! scenario runs three ways (never preempted, preempted after every unit,
//! and preempted at random) and must end in the same state, with the same
//! objects finished and the same bindings unbound.

mod common;

use common::{MODES, Mode, ObjKey, World, budget, key, ram, root, sl};
use kcap::SlotRef;
use kcap::cap::{Cap, Mapping, SlotArray};
use kcap::delete;
use kcap::mdb;
use kcap::ops::{self, MintData, copy, mint, move_cap};
use kcap::preempt::Preempted;
use kcap::rights::Rights;
use kmem::untyped::ObjectType;

/// A child piece of `2^bits` bytes in root slot `i`.
fn piece(w: &mut World, bits: u8, i: u64) -> SlotRef {
    w.retype(ram(), ObjectType::Untyped(bits), i, 1).unwrap();
    sl(i)
}

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

/// Maps `frame` into `space` at `va`, read-only.
fn map(w: &mut World, frame: SlotRef, space: SlotRef, va: u64) -> SlotRef {
    let m = Mapping {
        va,
        write: false,
        exec: false,
    };
    ops::bind_mapping(&mut w.mem, frame, space, m).unwrap().0
}

/// What a scenario ends with, for comparing the three ways.
#[derive(Debug, PartialEq)]
struct End {
    slots: std::collections::BTreeMap<u64, [u64; 4]>,
    finished: Vec<ObjKey>,
    unbound: Vec<(u64, [u64; 2])>,
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

#[test]
fn revoke_leaves_the_capability_and_deletes_copies_of_copies_and_mints() {
    let w = three_ways(|w, mode| {
        let ep = w.make(ObjectType::Endpoint, 32);
        copy(&mut w.mem, ep, sl(33)).unwrap();
        copy(&mut w.mem, sl(33), sl(34)).unwrap();
        mint(&mut w.mem, ep, sl(35), Rights::READ, MintData::Badge(5)).unwrap();
        copy(&mut w.mem, sl(35), sl(36)).unwrap();
        mint(&mut w.mem, sl(34), sl(37), Rights::WRITE, MintData::None).unwrap();
        w.revoke_mode(ep, mode);
        assert!(!w.empty(ep));
        for i in 33..=37 {
            assert!(w.empty(sl(i)), "slot {i} survived");
        }
        // The endpoint isn't finished: its original remains.
        assert!(w.log.finished.is_empty());
        assert!(!mdb::has_children(&w.mem, ep));
    });
    assert!(w.log.finished.is_empty());
}

#[test]
fn revoking_a_plain_copy_deletes_what_derives_from_it() {
    three_ways(|w, mode| {
        let ep = w.make(ObjectType::Endpoint, 32);
        copy(&mut w.mem, ep, sl(33)).unwrap();
        copy(&mut w.mem, ep, sl(40)).unwrap();
        copy(&mut w.mem, sl(33), sl(34)).unwrap();
        copy(&mut w.mem, sl(34), sl(35)).unwrap();
        // Every copy is its source's child (ADR 0049, rule 4), so revoking
        // the copy in 33 reaches 34 and 35, but not its sibling in 40.
        w.revoke_mode(sl(33), mode);
        assert!(!w.empty(sl(33)) && !w.empty(sl(40)));
        assert!(w.empty(sl(34)) && w.empty(sl(35)));
        assert_eq!(w.descendants(ep), [sl(40), sl(33)]);
    });
}

#[test]
fn deleting_a_middle_copy_leaves_its_children_under_the_original() {
    three_ways(|w, mode| {
        let ep = w.make(ObjectType::Endpoint, 32);
        copy(&mut w.mem, ep, sl(33)).unwrap();
        copy(&mut w.mem, sl(33), sl(34)).unwrap();
        w.delete_mode(sl(33), mode);
        assert!(
            w.log.finished.is_empty(),
            "a copy's delete finished its object"
        );
        assert_eq!(w.descendants(ep), [sl(34)]);
        w.revoke_mode(ep, mode);
        assert!(w.empty(sl(34)));
    });
}

#[test]
fn deleting_the_last_capability_finishes_the_object_and_clears_a_cnode() {
    let w = three_ways(|w, mode| {
        let cn = w.make(ObjectType::CNode(3), 32);
        let c = w.cap(cn);
        copy(&mut w.mem, cn, sl(33)).unwrap();
        for i in 0..8 {
            into(w, ram(), ObjectType::Endpoint, c, i);
        }
        // A copy of an endpoint outside the CNode survives it.
        copy(&mut w.mem, cslot(c, 5), sl(34)).unwrap();
        w.delete_mode(sl(33), mode);
        assert!(w.log.finished.is_empty(), "the CNode went with a copy");
        w.delete_mode(cn, mode);
        for i in 0..8 {
            assert!(w.empty(cslot(c, i)));
        }
        assert!(!w.empty(sl(34)));
        // The CNode and seven endpoints are finished; the eighth lives on.
        assert_eq!(w.log.finished.len(), 8);
    });
    assert!(w.log.finished.iter().any(|c| c.is_zombie()));
}

#[test]
fn deep_nesting_needs_no_recursion() {
    // 10,000 CNodes, each holding the last capability to the next, deleted
    // on the default test stack.
    for mode in [Mode::Never, Mode::Every] {
        let mut w = World::new();
        let p = piece(&mut w, 22, 20);
        let first = into(&mut w, p, ObjectType::CNode(1), root(), 32);
        let mut c = w.cap(first);
        for _ in 0..10_000 {
            let s = into(&mut w, p, ObjectType::CNode(1), c, 1);
            c = w.cap(s);
        }
        let restarts = w.delete_mode(sl(32), mode);
        if matches!(mode, Mode::Every) {
            assert!(restarts > 10_000);
        }
        assert_eq!(w.log.finished.len(), 10_001);
        assert!(!mdb::has_children(&w.mem, p));
        w.check();
    }
}

#[test]
fn address_spaces_in_a_cnode_unbind_their_mappings() {
    let w = three_ways(|w, mode| {
        let p = piece(w, 20, 20);
        let cn = into(w, p, ObjectType::CNode(2), root(), 32);
        let c = w.cap(cn);
        let f = w.make(ObjectType::Frame4K, 33);
        let mut bindings = Vec::new();
        for i in 0..3 {
            let s = into(w, p, ObjectType::AddressSpace, c, i);
            for k in 0..4 {
                bindings.push(map(w, f, s, 0x10_0000 + k * 0x1000));
            }
        }
        w.delete_mode(cn, mode);
        assert_eq!(w.log.unbound.len(), 12);
        for b in &bindings {
            assert!(w.log.unbound.iter().any(|(s, _)| s == b));
        }
        // The frame survives; its bindings are gone.
        assert!(!mdb::has_children(&w.mem, f));
        // CNode and three address spaces finished.
        assert_eq!(w.log.finished.len(), 4);
    });
    assert_eq!(w.log.unbound.len(), 12);
}

#[test]
fn revoking_a_frame_unbinds_every_mapping_even_with_a_copy_elsewhere() {
    three_ways(|w, mode| {
        let f = w.make(ObjectType::Frame4K, 32);
        copy(&mut w.mem, f, sl(33)).unwrap();
        let a = w.make(ObjectType::AddressSpace, 34);
        let b = w.make(ObjectType::AddressSpace, 35);
        map(w, f, a, 0x1000);
        map(w, f, b, 0x1000);
        // A mapping made from the copy is a descendant of the original too.
        map(w, sl(33), b, 0x2000);
        // Deleting one binding unbinds it, though it isn't final.
        let one = SlotArray::of_address_space(w.cap(b).object().unwrap().0).slot(1);
        w.delete_mode(one, mode);
        assert_eq!(w.log.unbound.len(), 1);
        w.revoke_mode(f, mode);
        assert_eq!(w.log.unbound.len(), 3);
        assert!(w.empty(sl(33)));
        assert!(w.log.finished.is_empty());
    });
}

#[test]
fn wide_trees_go_in_one_revoke() {
    three_ways(|w, mode| {
        let p = piece(w, 22, 20);
        let cn = into(w, p, ObjectType::CNode(8), root(), 32);
        let c = w.cap(cn);
        w.retype_into(p, ObjectType::Endpoint, c, 0, 200).unwrap();
        for i in 0..50 {
            copy(&mut w.mem, cslot(c, i), cslot(c, 200 + i)).unwrap();
        }
        w.revoke_mode(p, mode);
        assert!(!mdb::has_children(&w.mem, p));
        // The CNode and 200 endpoints.
        assert_eq!(w.log.finished.len(), 201);
    });
}

#[test]
fn dead_cycles_are_finished_by_revoking_their_untyped() {
    for p_first in [false, true] {
        for p_park in [true, false] {
            three_ways(|w, mode| {
                let p = piece(w, 20, 20);
                // Two CNodes, each holding the other's last capability: O's
                // in P's park slot (or another slot of P), P's in O's last.
                let (o, q) = if p_first {
                    let q = into(w, p, ObjectType::CNode(2), root(), 33);
                    (into(w, p, ObjectType::CNode(2), root(), 32), q)
                } else {
                    let o = into(w, p, ObjectType::CNode(2), root(), 32);
                    (o, into(w, p, ObjectType::CNode(2), root(), 33))
                };
                let (oc, qc) = (w.cap(o), w.cap(q));
                into(w, p, ObjectType::Endpoint, oc, 1);
                into(w, p, ObjectType::Endpoint, qc, 2);
                move_cap(&mut w.mem, o, cslot(qc, if p_park { 0 } else { 1 })).unwrap();
                move_cap(&mut w.mem, q, cslot(oc, 3)).unwrap();
                // A CNode holding its own last capability.
                let s = into(w, p, ObjectType::CNode(1), root(), 34);
                let sc = w.cap(s);
                into(w, p, ObjectType::Endpoint, sc, 0);
                move_cap(&mut w.mem, s, cslot(sc, 1)).unwrap();
                w.check();
                w.revoke_mode(p, mode);
                assert!(!mdb::has_children(&w.mem, p));
                // Three CNodes and three endpoints.
                assert_eq!(w.log.finished.len(), 6);
            });
        }
    }
}

#[test]
fn a_cycle_through_the_deleted_slot_is_finished_whole() {
    // Delete reaches the cycle through one of its own slots: O's last
    // capability in P's park slot, P's in O's last slot. Revoking O's
    // capability from outside isn't possible (it is the last), so reach it
    // through a copy that is then deleted first.
    three_ways(|w, mode| {
        let p = piece(w, 20, 20);
        let o = into(w, p, ObjectType::CNode(2), root(), 32);
        let q = into(w, p, ObjectType::CNode(2), root(), 33);
        let (oc, qc) = (w.cap(o), w.cap(q));
        into(w, p, ObjectType::Endpoint, oc, 1);
        into(w, p, ObjectType::Endpoint, qc, 3);
        move_cap(&mut w.mem, q, cslot(oc, 3)).unwrap();
        move_cap(&mut w.mem, o, cslot(qc, 0)).unwrap();
        // Delete P's park slot directly: it holds O's last capability.
        w.delete_mode(cslot(qc, 0), mode);
        assert_eq!(w.log.finished.len(), 4, "the cycle wasn't finished whole");
        assert!(!mdb::has_children(&w.mem, p));
    });
}

#[test]
fn a_revoke_that_meets_a_waiting_zombie_leaves_the_deletion_consistent() {
    let mut waited = 0;
    for units in 1..8 {
        let mut w = World::new();
        let p = piece(&mut w, 20, 20);
        let q = piece(&mut w, 20, 21);
        // C0 from P holds the last capability to C1, from Q, which holds
        // endpoints from Q.
        let c0 = into(&mut w, p, ObjectType::CNode(2), root(), 32);
        let c0c = w.cap(c0);
        let c1 = into(&mut w, q, ObjectType::CNode(2), c0c, 3);
        let c1c = w.cap(c1);
        into(&mut w, q, ObjectType::Endpoint, c1c, 0);
        into(&mut w, q, ObjectType::Endpoint, c1c, 2);
        into(&mut w, p, ObjectType::Endpoint, c0c, 1);
        // Delete C0 part of the way: C1's zombie may now wait in C0's park
        // slot, and C1's first slot in C0's last.
        let mut b = budget(Mode::Every);
        for _ in 0..units {
            let _ = delete::delete(&mut w.mem, &mut w.log, c0, &mut b);
        }
        w.check();
        if w.cap(cslot(c0c, 0)).is_zombie() {
            waited += 1;
        }
        // Revoking Q reaches C1, wherever its zombie is.
        w.revoke(q);
        w.check();
        assert!(!mdb::has_children(&w.mem, q));
        // The deletion resumes and finishes C0.
        w.delete(c0);
        w.check();
        assert!(!mdb::has_children(&w.mem, p), "after {units} units");
        // Only the boot objects and the two pieces are left.
        assert_eq!(w.log.live.len(), 5, "{:x?}", w.log.live);
        assert_eq!(w.log.finished.len(), 5);
    }
    assert!(waited > 0, "C1's zombie never waited in C0's park slot");
}

#[test]
fn revoking_an_untyped_finishes_everything_once_and_it_resets() {
    three_ways(|w, mode| {
        let p = piece(w, 22, 20);
        let made_before = w.log.live.len();
        let a = into(w, p, ObjectType::CNode(3), root(), 32);
        let ac = w.cap(a);
        let b = into(w, p, ObjectType::CNode(2), ac, 7);
        let bc = w.cap(b);
        let s = into(w, p, ObjectType::AddressSpace, bc, 1);
        let f = into(w, p, ObjectType::Frame4K, bc, 2);
        map(w, f, s, 0x4000);
        let e = into(w, p, ObjectType::Endpoint, ac, 0);
        mint(&mut w.mem, e, cslot(bc, 3), Rights::ALL, MintData::Badge(9)).unwrap();
        copy(&mut w.mem, a, sl(33)).unwrap();
        w.revoke_mode(p, mode);
        assert!(!mdb::has_children(&w.mem, p));
        assert_eq!(w.log.live.len(), made_before, "{:x?}", w.log.live);
        assert_eq!(w.log.unbound.len(), 1);
        // The next retype resets the piece and starts from its base.
        let base = w.cap(p).object().unwrap().0;
        w.retype(p, ObjectType::Frame4K, 40, 1).unwrap();
        assert_eq!(w.cap(sl(40)).object().unwrap().0, base);
    });
}

#[test]
fn a_revoke_whose_own_slot_is_inside_a_descendant_stops_as_sel4_does() {
    for mode in MODES {
        let mut w = World::new();
        let p = piece(&mut w, 20, 20);
        copy(&mut w.mem, ram(), sl(21)).unwrap_err();
        // A copy R of P, kept in a CNode made from R.
        w.revoke(p);
        copy(&mut w.mem, p, sl(21)).unwrap();
        let r = sl(21);
        // The endpoint in 33 comes first, so it is last in the revoke's
        // order, after the CNode that holds R.
        into(&mut w, r, ObjectType::Endpoint, root(), 33);
        let cn = into(&mut w, r, ObjectType::CNode(2), root(), 32);
        let c = w.cap(cn);
        into(&mut w, r, ObjectType::Endpoint, c, 0);
        move_cap(&mut w.mem, r, cslot(c, 2)).unwrap();
        let r = cslot(c, 2);
        let mut b = budget(mode);
        while delete::revoke(&mut w.mem, &mut w.log, r, &mut b) == Err(Preempted) {}
        w.check();
        // R went with the CNode; the endpoint in 33 is left, and still
        // descends from P.
        assert!(w.empty(r));
        assert!(!w.empty(sl(33)));
        for s in w.mem.full() {
            let cap = w.cap(s);
            if matches!(cap, Cap::Endpoint { .. }) {
                assert!(w.descendants(p).contains(&s), "orphan at {:#x}", s.0);
            }
        }
        w.revoke(p);
        assert!(!mdb::has_children(&w.mem, p));
        w.check();
    }
}

#[test]
fn a_preempted_revoke_finishes_nested_objects_from_another_piece() {
    // C0, from P, holds the last capability to C1, from Q, which holds two
    // endpoints from Q. Revoking P finishes all four, however often it is
    // preempted: C0's zombie keeps its place among P's descendants until C1
    // is finished in C0's park slot.
    let w = three_ways(|w, mode| {
        let p = piece(w, 20, 20);
        let q = piece(w, 20, 21);
        let c0 = into(w, p, ObjectType::CNode(2), root(), 32);
        let c0c = w.cap(c0);
        let c1 = into(w, q, ObjectType::CNode(2), c0c, 3);
        let c1c = w.cap(c1);
        into(w, q, ObjectType::Endpoint, c1c, 0);
        into(w, q, ObjectType::Endpoint, c1c, 2);
        w.revoke_mode(p, mode);
        assert!(w.empty(c0));
        assert_eq!(w.log.finished.len(), 4);
        assert!(!mdb::has_children(&w.mem, q));
    });
    assert_eq!(w.log.finished.len(), 4);
}

#[test]
fn a_zombie_with_nothing_left_to_clear_is_finished_before_anything_moves() {
    // O and P from U, E from V. A copy of E sits in O's park slot, and P's
    // only capability in O's last slot. O's deletion makes P a zombie and
    // stops; something else then sweeps P to n = 0 without finishing it.
    // O's deletion must finish P where it is, not defer it: a deferral
    // would put O's park slot, with the copy of E, into P's swept park
    // slot, inside P's finished memory.
    let mut w = World::new();
    let u = piece(&mut w, 20, 20);
    let v = piece(&mut w, 20, 21);
    let o = into(&mut w, u, ObjectType::CNode(2), root(), 40);
    let oc = w.cap(o);
    let p = into(&mut w, u, ObjectType::CNode(1), root(), 41);
    let e = into(&mut w, v, ObjectType::Endpoint, root(), 42);
    copy(&mut w.mem, e, cslot(oc, 0)).unwrap();
    move_cap(&mut w.mem, p, cslot(oc, 3)).unwrap();
    let mut b = budget(Mode::Every);
    assert_eq!(
        delete::delete(&mut w.mem, &mut w.log, o, &mut b),
        Err(Preempted)
    );
    assert_eq!(
        delete::delete(&mut w.mem, &mut w.log, o, &mut b),
        Err(Preempted)
    );
    assert!(matches!(w.cap(cslot(oc, 3)), Cap::Zombie { n: 2, .. }));
    // Anyone may step any zombie: two steps sweep P to n = 0.
    delete::delete_unit(&mut w.mem, &mut w.log, cslot(oc, 3));
    delete::delete_unit(&mut w.mem, &mut w.log, cslot(oc, 3));
    assert!(matches!(w.cap(cslot(oc, 3)), Cap::Zombie { n: 0, .. }));
    w.check();
    w.delete(o);
    w.check();
    // O and P are finished; the copy of E went with O, and E lives on.
    assert_eq!(w.log.finished.len(), 2);
    assert!(!w.empty(e));
    assert!(!mdb::has_children(&w.mem, e));
    // U resets with nothing of V's left in its memory.
    w.revoke(u);
    let mut bb = budget(Mode::Never);
    ops::reset(&mut w.mem, u, &mut bb).unwrap();
    mdb::verify(&w.mem, w.mem.full().into_iter()).unwrap();
    w.check();
}

#[test]
fn interleaved_deletes_finish_each_object_once() {
    // A deletion of the CNode O, preempted, whose slot lies in Q; then Q's
    // own deletion, which reaches O's zombie and adopts it. Whichever runs,
    // each object is finished exactly once (the log checks it).
    for units in 1..10 {
        let mut w = World::new();
        let p = piece(&mut w, 20, 20);
        let q = into(&mut w, p, ObjectType::CNode(2), root(), 32);
        let qc = w.cap(q);
        let o = into(&mut w, p, ObjectType::CNode(2), qc, 3);
        let ocap = w.cap(o);
        into(&mut w, p, ObjectType::Endpoint, ocap, 0);
        into(&mut w, p, ObjectType::Endpoint, ocap, 2);
        let inner = into(&mut w, p, ObjectType::CNode(1), ocap, 1);
        let ic = w.cap(inner);
        into(&mut w, p, ObjectType::Endpoint, ic, 1);
        into(&mut w, p, ObjectType::Endpoint, qc, 1);
        let mut b = budget(Mode::Every);
        for _ in 0..units {
            let _ = delete::delete(&mut w.mem, &mut w.log, o, &mut b);
        }
        w.check();
        let mut b = budget(Mode::Every);
        for _ in 0..units {
            let _ = delete::delete(&mut w.mem, &mut w.log, q, &mut b);
        }
        w.check();
        // The first delete resumes: it returns once its slot is empty.
        w.delete_mode(o, Mode::Every);
        w.check();
        w.delete_mode(q, Mode::Every);
        w.check();
        // Q, O, the inner CNode and four endpoints.
        assert_eq!(w.log.finished.len(), 7, "after {units} units");
        assert!(!mdb::has_children(&w.mem, p));
    }
}
