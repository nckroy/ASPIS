// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! C12's capabilities: threads, scheduling contexts, scheduling control and
//! reply objects; the copies a thread keeps as its bindings; and a thread's
//! deletion, which stops the thread before its slots are cleared (kernel
//! specification, "Kernel bindings that hold capabilities", K07).

mod common;

use common::{MODES, Mode, World, dev, key, ram, sl};
use kcap::SlotRef;
use kcap::cap::{Binding, Cap, SlotArray, THREAD_SLOTS};
use kcap::mdb;
use kcap::ops::{self, Error, copy, move_cap};
use kcap::rights::Rights;
use kmem::untyped::{ObjectType, RetypeError};

/// Slot `i` of the thread whose capability is in `t`.
fn tslot(w: &World, t: SlotRef, i: u64) -> SlotRef {
    let Cap::Thread { ptr, .. } = w.cap(t) else {
        panic!("not a thread: {:x?}", w.cap(t))
    };
    SlotArray::of_thread(ptr).slot(i)
}

#[test]
fn retype_makes_each_kind_with_every_right() {
    let mut w = World::new();
    let t = w.make(ObjectType::Thread, 40);
    let c = w.make(ObjectType::SchedContext(8), 41);
    let r = w.make(ObjectType::Reply, 42);
    assert!(matches!(
        w.cap(t),
        Cap::Thread {
            rights: Rights::ALL,
            ..
        }
    ));
    assert!(matches!(
        w.cap(c),
        Cap::SchedContext {
            bits: 8,
            binding: None,
            ..
        }
    ));
    assert!(matches!(
        w.cap(r),
        Cap::Reply {
            rights: Rights::ALL,
            ..
        }
    ));
    // A thread is aligned to its 2 KiB, so its eight slots lie in it.
    let Cap::Thread { ptr, .. } = w.cap(t) else {
        panic!()
    };
    assert_eq!(ptr % 2048, 0);
    // Device memory makes none of them, and a context's size is checked.
    let d = dev();
    for ty in [
        ObjectType::Thread,
        ObjectType::SchedContext(12),
        ObjectType::Reply,
    ] {
        assert_eq!(
            w.retype(d, ty, 50, 1),
            Err(Error::Retype(RetypeError::DeviceMemory))
        );
    }
    assert_eq!(
        w.retype(ram(), ObjectType::SchedContext(13), 50, 1),
        Err(Error::Retype(RetypeError::BadSize))
    );
    w.check();
}

#[test]
fn a_binding_is_a_child_that_revoking_reaches() {
    let mut w = World::new();
    let t = w.make(ObjectType::Thread, 40);
    let ep = w.make(ObjectType::Endpoint, 41);
    let sc = w.make(ObjectType::SchedContext(9), 42);
    let s3 = tslot(&w, t, 3);
    let s4 = tslot(&w, t, 4);
    let s5 = tslot(&w, t, 5);
    // The role must fit the kind.
    assert_eq!(
        ops::bind_copy(&mut w.mem, ep, s5, Binding::Context),
        Err(Error::WrongKind)
    );
    assert_eq!(
        ops::bind_copy(&mut w.mem, sc, s3, Binding::FaultEndpoint),
        Err(Error::WrongKind)
    );
    let b = ops::bind_copy(&mut w.mem, ep, s3, Binding::FaultEndpoint).unwrap();
    assert_eq!(b.binding(), Some(Binding::FaultEndpoint));
    assert_eq!(w.cap(s3), b);
    assert_eq!(w.depth(s3), w.depth(ep) + 1);
    assert_eq!(
        ops::bind_copy(&mut w.mem, ep, s3, Binding::FaultEndpoint),
        Err(Error::DestNotEmpty)
    );
    ops::bind_copy(&mut w.mem, ep, s4, Binding::TimeoutEndpoint).unwrap();
    ops::bind_copy(&mut w.mem, sc, s5, Binding::Context).unwrap();
    w.check();
    // A binding never moves, and a copy of it is the plain capability, a
    // child of the binding.
    assert_eq!(move_cap(&mut w.mem, s3, sl(60)), Err(Error::NotDerivable));
    copy(&mut w.mem, s5, sl(61)).unwrap();
    assert_eq!(w.cap(sl(61)).binding(), None);
    assert!(w.cap(sl(61)).same_object(&w.cap(sc)));
    assert_eq!(w.depth(sl(61)), w.depth(s5) + 1);
    // Revoking the capability presented deletes the thread's copy, and its
    // unbind runs; the copy made from the binding goes with it.
    w.revoke(sc);
    assert!(w.empty(s5) && w.empty(sl(61)));
    assert_eq!(w.log.unbound.len(), 1);
    assert_eq!(w.log.unbound[0].0, s5);
    // Deleting the capability presented leaves the thread's copy, behind a
    // barrier, under the endpoint's untyped memory (kernel specification,
    // "Fault delivery").
    w.delete(ep);
    assert!(!w.empty(s3) && !w.empty(s4));
    assert_eq!(w.log.unbound.len(), 1);
    w.check();
}

#[test]
fn scheduling_control_copies_as_a_child_and_moves() {
    // As in seL4 17.0.0, whose `deriveCap` returns a scheduling-control
    // capability unchanged: a copy is a child, so its holder can hand
    // control on and take it back.
    let mut w = World::new();
    let ctl = sl(40);
    mdb::insert_root(&mut w.mem, ctl, Cap::SchedControl { core: 2 });
    w.log.live.insert(key(&Cap::SchedControl { core: 2 }));
    copy(&mut w.mem, ctl, sl(41)).unwrap();
    assert_eq!(w.cap(sl(41)), Cap::SchedControl { core: 2 });
    assert_eq!(w.depth(sl(41)), 1);
    copy(&mut w.mem, sl(41), sl(42)).unwrap();
    move_cap(&mut w.mem, sl(42), sl(43)).unwrap();
    assert!(w.empty(sl(42)));
    assert_eq!(w.log.unbound.len(), 0);
    w.revoke(ctl);
    assert!(w.empty(sl(41)) && w.empty(sl(43)));
    assert_eq!(
        w.log.finished.len(),
        0,
        "a copy's deletion finished control"
    );
    // The last one finishes its "object": nothing to do, but finished once.
    w.delete(ctl);
    assert_eq!(w.log.finished, vec![Cap::SchedControl { core: 2 }]);
    w.check();
}

/// A thread whose slot 1 holds the last capability to a CNode with an
/// endpoint copy in it, and whose slots 3, 4 and 5 hold bindings; then the
/// thread's last capability is deleted under `mode`.
fn thread_teardown(mode: Mode) -> World {
    let mut w = World::new();
    let t = w.make(ObjectType::Thread, 40);
    let cn = w.make(ObjectType::CNode(2), 41);
    let ep = w.make(ObjectType::Endpoint, 42);
    let sc = w.make(ObjectType::SchedContext(8), 43);
    let Cap::CNode { ptr: cnp, .. } = w.cap(cn) else {
        panic!()
    };
    copy(&mut w.mem, ep, SlotRef(cnp).offset(1)).unwrap();
    let (s1, s3, s4, s5) = (
        tslot(&w, t, 1),
        tslot(&w, t, 3),
        tslot(&w, t, 4),
        tslot(&w, t, 5),
    );
    move_cap(&mut w.mem, cn, s1).unwrap();
    ops::bind_copy(&mut w.mem, ep, s3, Binding::FaultEndpoint).unwrap();
    ops::bind_copy(&mut w.mem, ep, s4, Binding::TimeoutEndpoint).unwrap();
    ops::bind_copy(&mut w.mem, sc, s5, Binding::Context).unwrap();
    w.check();
    let Cap::Thread { ptr, .. } = w.cap(t) else {
        panic!()
    };
    w.delete_mode(t, mode);
    assert!(w.empty(t));
    for i in 0..THREAD_SLOTS {
        let s = SlotArray::of_thread(ptr).slot(i);
        assert!(w.empty(s), "thread slot {i} isn't clear");
    }
    w.check();
    w
}

#[test]
fn a_thread_stops_before_its_slots_are_cleared() {
    for mode in MODES {
        let w = thread_teardown(mode);
        // The kernel's zombify hook ran first, once, for the thread; then
        // the bindings' unbinds, slot 5 first, as the zombie clears from
        // its last slot down; then the finishes.
        assert_eq!(w.log.zombified.len(), 2, "{mode:?}: {:x?}", w.log.zombified);
        assert!(matches!(w.log.zombified[0], Cap::Thread { .. }));
        assert!(matches!(w.log.zombified[1], Cap::CNode { .. }));
        let first_unbind = w.log.order.iter().position(|&c| c == 'u').unwrap();
        assert_eq!(w.log.order[0], 'z', "{mode:?}: {:?}", w.log.order);
        assert!(first_unbind > 0);
        let roles: Vec<_> = w.log.unbound.iter().map(|(_, c)| c.binding()).collect();
        assert_eq!(
            roles,
            vec![
                Some(Binding::Context),
                Some(Binding::TimeoutEndpoint),
                Some(Binding::FaultEndpoint)
            ],
            "{mode:?}"
        );
        // The CNode in slot 1 was the last capability to it: it was
        // finished in the same deletion, and the thread last.
        assert!(matches!(w.log.finished.last(), Some(Cap::Zombie { .. })));
        assert_eq!(w.log.finished.len(), 2, "{mode:?}: {:x?}", w.log.finished);
    }
    // Every way ends in the same slots.
    let ends: Vec<_> = MODES
        .iter()
        .map(|&m| thread_teardown(m).mem.snapshot())
        .collect();
    assert!(ends.windows(2).all(|p| p[0] == p[1]));
}
