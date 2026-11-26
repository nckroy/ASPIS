// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Sessions and badges (ADR 0049, rules 3 and 5): a manager keeps a badged
//! copy for each session, hands the client a copy derived from it, and
//! revokes what it derived to end the session.

mod common;

use common::{MODES, World, sl};
use kcap::cap::{Cap, Mapping};
use kcap::mdb;
use kcap::ops::{self, Error, MintData, copy, mint};
use kcap::rights::Rights;
use kmem::untyped::ObjectType;

fn badge(w: &World, s: kcap::SlotRef) -> u64 {
    match w.cap(s) {
        Cap::Endpoint { badge, .. } => badge,
        c => panic!("not an endpoint: {c:x?}"),
    }
}

/// Binds a session: the manager mints and keeps a badged copy in `kept`,
/// and the client gets a copy of it in `client`, with send rights only.
fn bind(w: &mut World, ep: kcap::SlotRef, b: u64, kept: u64, client: u64) {
    mint(&mut w.mem, ep, sl(kept), Rights::ALL, MintData::Badge(b)).unwrap();
    let send = Rights::WRITE.union(Rights::GRANT_REPLY);
    mint(&mut w.mem, sl(kept), sl(client), send, MintData::None).unwrap();
}

/// Releases a badge: revoke the kept copy, cancel the badge's queued sends
/// (C14's; nothing is queued in C11), then delete the kept copy.
fn release(w: &mut World, kept: u64, mode: common::Mode) {
    w.revoke_mode(sl(kept), mode);
    w.delete_mode(sl(kept), mode);
}

#[test]
fn revoking_one_session_leaves_the_others() {
    for mode in MODES {
        let mut w = World::new();
        let ep = w.make(ObjectType::Endpoint, 32);
        for k in 0..4 {
            bind(&mut w, ep, 100 + k, 40 + k, 60 + k);
            // The client passes its copy on.
            copy(&mut w.mem, sl(60 + k), sl(80 + k)).unwrap();
        }
        release(&mut w, 41, mode);
        assert!(w.empty(sl(41)) && w.empty(sl(61)) && w.empty(sl(81)));
        for k in [0, 2, 3] {
            assert_eq!(badge(&w, sl(60 + k)), 100 + k);
            assert_eq!(badge(&w, sl(80 + k)), 100 + k);
        }
        // The badge can be reused now, for a new session.
        bind(&mut w, ep, 101, 41, 61);
        assert_eq!(badge(&w, sl(61)), 101);
        assert_eq!(w.descendants(sl(41)), [sl(61)]);
        w.check();
    }
}

#[test]
fn a_session_may_have_several_badges() {
    let mut w = World::new();
    let ep = w.make(ObjectType::Endpoint, 32);
    // session_dup: another badge for the same session, made the same way.
    bind(&mut w, ep, 7, 40, 60);
    bind(&mut w, ep, 8, 41, 61);
    release(&mut w, 40, common::Mode::Never);
    assert!(w.empty(sl(60)));
    assert_eq!(badge(&w, sl(61)), 8);
    // Ending the session releases every badge.
    release(&mut w, 41, common::Mode::Never);
    assert!(w.empty(sl(61)));
    assert!(!mdb::has_children(&w.mem, ep));
    w.check();
}

#[test]
fn a_client_copy_whose_kept_copy_was_deleted_stays_with_its_badge() {
    let mut w = World::new();
    let ep = w.make(ObjectType::Endpoint, 32);
    bind(&mut w, ep, 1, 40, 60);
    bind(&mut w, ep, 2, 41, 61);
    // Deleting a kept copy without revoking leaves the client's copy. It
    // doesn't join the other badge's session: a badged capability's
    // descendants carry its badge.
    w.delete(sl(40));
    w.revoke(sl(41));
    assert!(!w.empty(sl(60)), "badge 2's revoke reached badge 1's copy");
    assert!(w.empty(sl(61)));
    // The unbadged original still reaches it.
    w.revoke(ep);
    assert!(w.empty(sl(60)));
    w.check();
}

#[test]
fn the_badge_is_set_once_through_every_copy() {
    let mut w = World::new();
    let ep = w.make(ObjectType::Endpoint, 32);
    bind(&mut w, ep, 9, 40, 60);
    // Neither the client nor anyone it passes to can change the badge.
    assert_eq!(
        mint(&mut w.mem, sl(60), sl(70), Rights::ALL, MintData::Badge(10)),
        Err(Error::InvalidData)
    );
    copy(&mut w.mem, sl(60), sl(70)).unwrap();
    assert_eq!(badge(&w, sl(70)), 9);
    // Rights only drop: the client's copy has no read right, so neither do
    // its copies.
    assert!(!w.cap(sl(70)).rights().contains(Rights::READ));
}

#[test]
fn bindings_made_from_a_session_go_with_it() {
    let mut w = World::new();
    // The manager shares a frame with a session the same way: it keeps a
    // copy and hands the client a copy of that. The client maps it.
    let f = w.make(ObjectType::Frame4K, 32);
    let space = w.make(ObjectType::AddressSpace, 33);
    copy(&mut w.mem, f, sl(40)).unwrap();
    copy(&mut w.mem, sl(40), sl(60)).unwrap();
    let m = Mapping {
        va: 0x40_0000,
        write: true,
        exec: false,
    };
    let (b, _) = ops::bind_mapping(&mut w.mem, sl(60), space, m).unwrap();
    w.revoke(sl(40));
    assert!(w.empty(sl(60)) && w.empty(b));
    assert_eq!(w.log.unbound.len(), 1);
    assert_eq!(w.log.unbound[0].0, b);
    w.check();
}
