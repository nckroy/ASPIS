// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Copy, mint, mutate and move: rights only drop, a badge is set once, a
//! guard by mint or mutate, and every copy is a child of its source.

mod common;

use common::{World, ram, sl};
use kcap::cap::{Cap, Kind, Mapping, ZombieKind};
use kcap::mdb;
use kcap::ops::{self, Error, Guard, MintData, copy, identify, mint, move_cap, mutate};
use kcap::rights::Rights;
use kcap::slot;
use kmem::untyped::ObjectType;

#[test]
fn a_copy_is_a_child_with_the_same_rights() {
    let mut w = World::new();
    let ep = w.make(ObjectType::Endpoint, 32);
    copy(&mut w.mem, ep, sl(33)).unwrap();
    assert_eq!(w.cap(sl(33)), w.cap(ep));
    assert_eq!(w.depth(sl(33)), w.depth(ep) + 1);
    assert_eq!(w.descendants(ep), [sl(33)]);
    // A copy of the copy is its child, and so the original's descendant.
    copy(&mut w.mem, sl(33), sl(34)).unwrap();
    assert_eq!(w.descendants(sl(33)), [sl(34)]);
    assert_eq!(w.descendants(ep), [sl(33), sl(34)]);
    // Neither is final while the others exist.
    assert!(!mdb::is_final(&w.mem, ep));
    w.check();
}

#[test]
fn rights_can_only_be_dropped() {
    let mut w = World::new();
    let f = w.make(ObjectType::Frame4K, 32);
    let rw = Rights::READ.union(Rights::WRITE);
    mint(&mut w.mem, f, sl(33), rw, MintData::None).unwrap();
    assert_eq!(w.cap(sl(33)).rights(), rw);
    mint(&mut w.mem, sl(33), sl(34), Rights::READ, MintData::None).unwrap();
    assert_eq!(w.cap(sl(34)).rights(), Rights::READ);
    // Asking for every right from a read-only copy gives read only.
    mint(&mut w.mem, sl(34), sl(35), Rights::ALL, MintData::None).unwrap();
    assert_eq!(w.cap(sl(35)).rights(), Rights::READ);
    copy(&mut w.mem, sl(35), sl(36)).unwrap();
    assert_eq!(w.cap(sl(36)).rights(), Rights::READ);
    // Untyped and CNode capabilities carry no rights, and mint leaves them so.
    let cn = w.make(ObjectType::CNode(2), 40);
    mint(&mut w.mem, cn, sl(41), Rights::READ, MintData::None).unwrap();
    assert_eq!(w.cap(sl(41)), w.cap(cn));
    assert_eq!(identify(&w.cap(sl(41))), (Kind::CNode, Rights::NONE));
    w.check();
}

#[test]
fn a_badge_is_set_once() {
    let mut w = World::new();
    let ep = w.make(ObjectType::Endpoint, 32);
    mint(&mut w.mem, ep, sl(33), Rights::ALL, MintData::Badge(7)).unwrap();
    let Cap::Endpoint { badge, .. } = w.cap(sl(33)) else {
        panic!()
    };
    assert_eq!(badge, 7);
    // A badged capability's copies keep its badge, and can't be rebadged.
    copy(&mut w.mem, sl(33), sl(34)).unwrap();
    assert_eq!(w.cap(sl(34)), w.cap(sl(33)));
    assert_eq!(
        mint(&mut w.mem, sl(33), sl(35), Rights::ALL, MintData::Badge(8)),
        Err(Error::InvalidData)
    );
    // Badge 0 means unbadged, so it can't be minted.
    assert_eq!(
        mint(&mut w.mem, ep, sl(35), Rights::ALL, MintData::Badge(0)),
        Err(Error::InvalidData)
    );
    // Only endpoints take a badge.
    let f = w.make(ObjectType::Frame4K, 40);
    assert_eq!(
        mint(&mut w.mem, f, sl(41), Rights::ALL, MintData::Badge(1)),
        Err(Error::InvalidData)
    );
    assert!(w.empty(sl(35)) && w.empty(sl(41)));
    w.check();
}

#[test]
fn a_guard_is_set_by_mint_and_mutate() {
    let mut w = World::new();
    let cn = w.make(ObjectType::CNode(4), 32);
    let g = Guard {
        size: 60,
        value: 0xabc,
    };
    mint(&mut w.mem, cn, sl(33), Rights::ALL, MintData::Guard(g)).unwrap();
    let Cap::CNode {
        guard_size, guard, ..
    } = w.cap(sl(33))
    else {
        panic!()
    };
    assert_eq!((guard_size, guard), (60, 0xabc));
    // A guard too wide for the radix, or wider than its size, is refused.
    for bad in [
        Guard { size: 61, value: 0 },
        Guard { size: 64, value: 0 },
        Guard { size: 3, value: 8 },
    ] {
        assert_eq!(
            mint(&mut w.mem, cn, sl(34), Rights::ALL, MintData::Guard(bad)),
            Err(Error::InvalidData)
        );
        assert_eq!(mutate(&mut w.mem, cn, sl(34), bad), Err(Error::InvalidData));
    }
    // Mutate moves the capability with its new guard, and keeps its place
    // in the tree: the copy in 33 is still its child.
    let depth = w.depth(cn);
    mutate(&mut w.mem, cn, sl(34), Guard { size: 2, value: 3 }).unwrap();
    assert!(w.empty(cn));
    assert_eq!(w.depth(sl(34)), depth);
    let Cap::CNode {
        guard_size, guard, ..
    } = w.cap(sl(34))
    else {
        panic!()
    };
    assert_eq!((guard_size, guard), (2, 3));
    assert_eq!(w.descendants(sl(34)), [sl(33)]);
    w.check();
}

#[test]
fn mutate_never_sets_a_badge() {
    let mut w = World::new();
    let ep = w.make(ObjectType::Endpoint, 32);
    // Mutate takes only a guard, and an endpoint has none.
    assert_eq!(
        mutate(&mut w.mem, ep, sl(33), Guard { size: 0, value: 0 }),
        Err(Error::InvalidData)
    );
    assert!(w.empty(sl(33)));
    assert_eq!(w.cap(ep), {
        let Cap::Endpoint { ptr, rights, .. } = w.cap(ep) else {
            panic!()
        };
        Cap::Endpoint {
            ptr,
            rights,
            badge: 0,
        }
    });
}

#[test]
fn the_destination_must_be_empty_and_different() {
    let mut w = World::new();
    let ep = w.make(ObjectType::Endpoint, 32);
    let f = w.make(ObjectType::Frame4K, 33);
    assert_eq!(copy(&mut w.mem, ep, f), Err(Error::DestNotEmpty));
    assert_eq!(copy(&mut w.mem, ep, ep), Err(Error::SameSlot));
    assert_eq!(move_cap(&mut w.mem, ep, f), Err(Error::DestNotEmpty));
    assert_eq!(copy(&mut w.mem, sl(40), sl(41)), Err(Error::Empty));
    assert_eq!(move_cap(&mut w.mem, sl(40), sl(41)), Err(Error::Empty));
    w.check();
}

#[test]
fn move_keeps_the_place_in_the_tree() {
    let mut w = World::new();
    let ep = w.make(ObjectType::Endpoint, 32);
    copy(&mut w.mem, ep, sl(33)).unwrap();
    copy(&mut w.mem, sl(33), sl(34)).unwrap();
    // Move the middle one, and then the original past its own child.
    move_cap(&mut w.mem, sl(33), sl(50)).unwrap();
    assert_eq!(w.descendants(ep), [sl(50), sl(34)]);
    move_cap(&mut w.mem, ep, sl(51)).unwrap();
    assert_eq!(w.descendants(sl(51)), [sl(50), sl(34)]);
    assert_eq!(w.descendants(sl(50)), [sl(34)]);
    w.check();
}

#[test]
fn zombies_and_bindings_neither_move_nor_copy() {
    let mut w = World::new();
    let z = sl(40);
    let zombie = Cap::Zombie {
        kind: ZombieKind::CNode { radix: 1 },
        ptr: 0x4000_0000,
        n: 2,
    };
    mdb::insert_root(&mut w.mem, z, zombie);
    assert_eq!(move_cap(&mut w.mem, z, sl(41)), Err(Error::NotDerivable));
    assert_eq!(copy(&mut w.mem, z, sl(41)), Err(Error::NotDerivable));
    // A binding: copying it gives the frame without its mapping, a child of
    // the binding; moving it is refused.
    let f = w.make(ObjectType::Frame4K, 32);
    let space = w.make(ObjectType::AddressSpace, 33);
    let m = Mapping {
        va: 0x1000,
        write: true,
        exec: false,
    };
    let (b, binding) = ops::bind_mapping(&mut w.mem, f, space, m).unwrap();
    assert!(binding.is_binding());
    assert_eq!(move_cap(&mut w.mem, b, sl(42)), Err(Error::NotDerivable));
    copy(&mut w.mem, b, sl(42)).unwrap();
    assert_eq!(w.cap(sl(42)), w.cap(f));
    assert_eq!(w.descendants(b), [sl(42)]);
    assert_eq!(w.descendants(f), [b, sl(42)]);
}

#[test]
fn untyped_copies_mark_their_source_full() {
    let mut w = World::new();
    let ut = ram();
    w.retype(ut, ObjectType::Untyped(16), 32, 1).unwrap();
    let child = sl(32);
    copy(&mut w.mem, child, sl(33)).unwrap();
    let Cap::Untyped { watermark, .. } = w.cap(child) else {
        panic!()
    };
    assert_eq!(watermark, 1 << 16, "the source wasn't marked full");
    let Cap::Untyped { watermark, .. } = w.cap(sl(33)) else {
        panic!()
    };
    assert_eq!(watermark, 0, "the copy keeps the source's watermark");
    // The source can't make anything while the copy lives.
    assert_eq!(
        w.retype(child, ObjectType::Frame4K, 40, 1),
        Err(Error::Retype(kmem::untyped::RetypeError::NoRoom))
    );
    // An untyped capability with children can't be copied.
    w.retype(sl(33), ObjectType::Frame4K, 40, 1).unwrap();
    assert_eq!(copy(&mut w.mem, sl(33), sl(41)), Err(Error::NotDerivable));
    // Once the copy and its children go, the source resets and makes
    // objects from its start.
    w.revoke(child);
    assert!(w.empty(sl(33)) && w.empty(sl(40)));
    w.retype(child, ObjectType::Frame4K, 40, 1).unwrap();
    let Cap::Frame { base, .. } = w.cap(sl(40)) else {
        panic!()
    };
    let Cap::Untyped { base: ub, .. } = w.cap(child) else {
        panic!()
    };
    assert_eq!(base, ub);
    w.check();
}

#[test]
fn identify_reads_every_kind_without_a_badge() {
    let mut w = World::new();
    let ep = w.make(ObjectType::Endpoint, 32);
    mint(&mut w.mem, ep, sl(33), Rights::WRITE, MintData::Badge(42)).unwrap();
    assert_eq!(identify(&w.cap(sl(33))), (Kind::Endpoint, Rights::WRITE));
    let f = w.make(ObjectType::Frame4K, 34);
    assert_eq!(identify(&w.cap(f)), (Kind::Frame, Rights::ALL));
    let s = w.make(ObjectType::AddressSpace, 35);
    assert_eq!(identify(&w.cap(s)), (Kind::AddressSpace, Rights::ALL));
    assert_eq!(identify(&w.cap(ram())), (Kind::Untyped, Rights::NONE));
    assert_eq!(identify(&w.cap(sl(1))), (Kind::CNode, Rights::NONE));
    assert_eq!(identify(&w.cap(sl(100))), (Kind::Null, Rights::NONE));
}

#[test]
fn derivation_stops_at_the_deepest_level() {
    let mut w = World::new();
    let ep = w.make(ObjectType::Endpoint, 32);
    // Put the endpoint at the deepest level by hand, then try to copy.
    let mut s = slot::read(&w.mem, ep);
    s.depth = slot::MAX_DEPTH;
    slot::write(&mut w.mem, ep, &s);
    assert_eq!(copy(&mut w.mem, ep, sl(33)), Err(Error::TooDeep));
    assert!(w.empty(sl(33)));
}
