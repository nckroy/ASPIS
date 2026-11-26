// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Capability transfer: up to three capabilities per message (ADR 0049,
//! rule 6), with seL4's unwrapping and its stopping rules.

mod common;

use common::{World, ram, root, sl};
use kcap::SlotRef;
use kcap::cap::{Cap, ZombieKind};
use kcap::mdb;
use kcap::ops::{MintData, mint};
use kcap::rights::Rights;
use kcap::transfer::{Send, Transferred, transfer};
use kmem::untyped::ObjectType;

/// A receiver's CNode in root slot 50, and its slots.
fn receiver(w: &mut World) -> Cap {
    w.retype(ram(), ObjectType::CNode(3), 50, 1).unwrap();
    w.cap(sl(50))
}

fn rslot(c: Cap, i: u64) -> SlotRef {
    let Cap::CNode { ptr, .. } = c else { panic!() };
    SlotRef(ptr).offset(i)
}

fn ep_ptr(w: &World, s: SlotRef) -> u64 {
    w.cap(s).object().unwrap().0
}

fn send<'a>(addrs: &'a [u64], grant: bool, endpoint: u64) -> Send<'a> {
    Send {
        root: root(),
        addrs,
        grant,
        endpoint,
    }
}

#[test]
fn up_to_three_capabilities_move_as_children_of_the_sender_s() {
    for n in 0..=3usize {
        let mut w = World::new();
        let transit = w.make(ObjectType::Endpoint, 32);
        let r = receiver(&mut w);
        for i in 0..3 {
            w.make(ObjectType::Frame4K, 33 + i);
        }
        let addrs: Vec<u64> = (0..n as u64).map(|i| 33 + i).collect();
        let recv = [rslot(r, 0), rslot(r, 1), rslot(r, 2)];
        let tp = ep_ptr(&w, transit);
        let t = transfer(&mut w.mem, &send(&addrs, true, tp), &recv);
        assert_eq!(
            t,
            Transferred {
                count: n,
                unwrapped: 0,
                badges: [0; 3]
            }
        );
        for i in 0..n as u64 {
            assert_eq!(w.cap(rslot(r, i)), w.cap(sl(33 + i)));
            assert_eq!(w.descendants(sl(33 + i)), [rslot(r, i)]);
        }
        for i in n as u64..3 {
            assert!(w.empty(rslot(r, i)));
        }
        w.check();
    }
}

#[test]
fn the_transit_endpoint_is_unwrapped_in_its_position() {
    let mut w = World::new();
    let transit = w.make(ObjectType::Endpoint, 32);
    mint(
        &mut w.mem,
        transit,
        sl(33),
        Rights::ALL,
        MintData::Badge(77),
    )
    .unwrap();
    let other = w.make(ObjectType::Endpoint, 34);
    let f = w.make(ObjectType::Frame4K, 35);
    let r = receiver(&mut w);
    let recv = [rslot(r, 0), rslot(r, 1)];
    // Frame, transit (badged), other endpoint.
    let tp = ep_ptr(&w, transit);
    let t = transfer(&mut w.mem, &send(&[35, 33, 34], true, tp), &recv);
    assert_eq!(t.count, 3);
    assert_eq!(t.unwrapped, 0b010);
    assert_eq!(t.badges, [0, 77, 0]);
    // The unwrapped one filled no slot, so the other endpoint took slot 1.
    assert_eq!(w.cap(rslot(r, 0)), w.cap(f));
    assert_eq!(w.cap(rslot(r, 1)), w.cap(other));
    w.check();
}

#[test]
fn without_grant_nothing_moves_or_unwraps() {
    let mut w = World::new();
    let transit = w.make(ObjectType::Endpoint, 32);
    w.make(ObjectType::Frame4K, 33);
    let r = receiver(&mut w);
    let tp = ep_ptr(&w, transit);
    let t = transfer(
        &mut w.mem,
        &send(&[32, 33], false, tp),
        &[rslot(r, 0), rslot(r, 1)],
    );
    assert_eq!(t, Transferred::default());
    assert!(w.empty(rslot(r, 0)) && w.empty(rslot(r, 1)));
}

#[test]
fn a_failed_lookup_moves_nothing() {
    let mut w = World::new();
    let transit = w.make(ObjectType::Endpoint, 32);
    w.make(ObjectType::Frame4K, 33);
    let r = receiver(&mut w);
    let tp = ep_ptr(&w, transit);
    // Slot 99 is empty; 1 << 40 fails the guard.
    for bad in [99, 1 << 40] {
        let t = transfer(
            &mut w.mem,
            &send(&[33, bad], true, tp),
            &[rslot(r, 0), rslot(r, 1)],
        );
        assert_eq!(t, Transferred::default());
        assert!(w.empty(rslot(r, 0)));
    }
}

#[test]
fn transfer_stops_at_the_first_that_can_t_move() {
    let mut w = World::new();
    let transit = w.make(ObjectType::Endpoint, 32);
    let f = w.make(ObjectType::Frame4K, 33);
    // An untyped piece with children can't be derived.
    w.retype(ram(), ObjectType::Untyped(14), 34, 1).unwrap();
    w.retype(sl(34), ObjectType::Endpoint, 35, 1).unwrap();
    let r = receiver(&mut w);
    let tp = ep_ptr(&w, transit);
    // Stops at the untyped: one moved.
    let t = transfer(
        &mut w.mem,
        &send(&[33, 34, 35], true, tp),
        &[rslot(r, 0), rslot(r, 1), rslot(r, 2)],
    );
    assert_eq!(t.count, 1);
    assert!(w.empty(rslot(r, 1)));
    // An occupied receive slot stops it.
    let t = transfer(
        &mut w.mem,
        &send(&[35, 33], true, tp),
        &[rslot(r, 0), rslot(r, 1)],
    );
    assert_eq!(t.count, 0);
    // Running out of receive slots stops it, but unwrapping needs none.
    let t = transfer(&mut w.mem, &send(&[35, 32, 33], true, tp), &[rslot(r, 3)]);
    assert_eq!((t.count, t.unwrapped), (2, 0b10));
    assert_eq!(w.cap(rslot(r, 3)), w.cap(sl(35)));
    // A zombie can't be derived.
    mdb::insert_root(
        &mut w.mem,
        sl(36),
        Cap::Zombie {
            kind: ZombieKind::CNode { radix: 1 },
            ptr: 0x7000_0000,
            n: 2,
        },
    );
    let t = transfer(&mut w.mem, &send(&[36], true, tp), &[rslot(r, 4)]);
    assert_eq!(t.count, 0);
    assert!(w.empty(rslot(r, 4)));
    assert_eq!(w.cap(rslot(r, 0)), w.cap(f));
}
