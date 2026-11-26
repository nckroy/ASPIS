// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Retype through untyped capabilities: alignment and the watermark, the
//! fan-out limit, destination slots, device memory, the reset when nothing
//! derives from a piece (preempted and resumed), and the page tables that
//! Map takes.

mod common;

use common::{DEV, Mode, World, budget, dev, ram, sl};
use kcap::cap::{Cap, FrameSize};
use kcap::mdb;
use kcap::ops::{self, Error, RESET_CHUNK, copy};
use kmem::untyped::{ObjectType, RetypeError};

fn base(c: Cap) -> u64 {
    c.object().map(|(b, _)| b).unwrap_or(u64::MAX)
}

fn watermark(w: &World, s: kcap::SlotRef) -> u64 {
    let Cap::Untyped { watermark, .. } = w.cap(s) else {
        panic!("not untyped")
    };
    watermark
}

/// A child piece of `2^bits` bytes in root slot `i`.
fn piece(w: &mut World, bits: u8, i: u64) -> kcap::SlotRef {
    w.retype(ram(), ObjectType::Untyped(bits), i, 1).unwrap();
    sl(i)
}

#[test]
fn retype_aligns_objects_and_moves_the_watermark() {
    let mut w = World::new();
    let p = piece(&mut w, 16, 32);
    let pb = base(w.cap(p));
    w.retype(p, ObjectType::Frame4K, 40, 1).unwrap();
    assert_eq!(base(w.cap(sl(40))), pb);
    // An address space is 8 KiB, aligned to 8 KiB.
    w.retype(p, ObjectType::AddressSpace, 41, 1).unwrap();
    assert_eq!(base(w.cap(sl(41))), pb + 0x2000);
    assert_eq!(watermark(&w, p), 0x4000);
    w.retype(p, ObjectType::Endpoint, 42, 3).unwrap();
    assert_eq!(base(w.cap(sl(44))), pb + 0x4080);
    w.retype(p, ObjectType::CNode(7), 45, 1).unwrap();
    assert_eq!(base(w.cap(sl(45))), pb + 0x5000);
    assert_eq!(watermark(&w, p), 0x6000);
    // Each new capability is a child of the piece.
    let d = w.descendants(p);
    assert_eq!(d.len(), 6);
    for s in [40, 41, 42, 43, 44, 45] {
        assert!(d.contains(&sl(s)));
        assert_eq!(w.depth(sl(s)), w.depth(p) + 1);
    }
    w.check();
}

#[test]
fn retype_refuses_what_doesnt_fit_and_changes_nothing() {
    let mut w = World::new();
    let p = piece(&mut w, 16, 32);
    w.retype(p, ObjectType::Frame4K, 40, 1).unwrap();
    let before = w.mem.snapshot();
    let refuse = |w: &mut World, ty, first, count, want: Error| {
        assert_eq!(w.retype(p, ty, first, count), Err(want), "{ty:?} x{count}");
    };
    refuse(
        &mut w,
        ObjectType::Frame4K,
        41,
        0,
        Error::Retype(RetypeError::ZeroCount),
    );
    refuse(
        &mut w,
        ObjectType::Frame2M,
        41,
        1,
        Error::Retype(RetypeError::TooBig),
    );
    refuse(
        &mut w,
        ObjectType::Frame4K,
        41,
        16,
        Error::Retype(RetypeError::NoRoom),
    );
    refuse(
        &mut w,
        ObjectType::CNode(0),
        41,
        1,
        Error::Retype(RetypeError::BadSize),
    );
    refuse(
        &mut w,
        ObjectType::Untyped(11),
        41,
        1,
        Error::Retype(RetypeError::BadSize),
    );
    // Page tables have no capability: Map takes them with take_page.
    refuse(&mut w, ObjectType::PageTable, 41, 1, Error::BadType);
    // Destination slots must be empty and inside the CNode.
    refuse(&mut w, ObjectType::Frame4K, 40, 1, Error::DestNotEmpty);
    refuse(&mut w, ObjectType::Frame4K, 255, 2, Error::BadRange);
    refuse(&mut w, ObjectType::Frame4K, u64::MAX, 2, Error::BadRange);
    // The piece must be untyped memory.
    assert_eq!(
        ops::retype(
            &mut w.mem,
            sl(40),
            ObjectType::Frame4K,
            &w.root.clone(),
            41,
            1,
            &mut budget(Mode::Never)
        ),
        Err(Error::WrongKind)
    );
    assert_eq!(
        w.mem.snapshot(),
        before,
        "a refused retype changed something"
    );
}

#[test]
fn fan_out_is_256_objects() {
    let mut w = World::new();
    let p = piece(&mut w, 22, 32);
    // A CNode of 512 slots to receive them.
    w.retype(ram(), ObjectType::CNode(9), 33, 1).unwrap();
    let cn = w.cap(sl(33));
    assert_eq!(
        w.retype_into(p, ObjectType::Frame4K, cn, 0, 257),
        Err(Error::BadRange)
    );
    w.retype_into(p, ObjectType::Frame4K, cn, 0, 256).unwrap();
    assert_eq!(w.descendants(p).len(), 256);
    w.check();
}

#[test]
fn device_memory_makes_only_frames_and_untyped() {
    let mut w = World::new();
    for ty in [
        ObjectType::CNode(1),
        ObjectType::Endpoint,
        ObjectType::AddressSpace,
    ] {
        assert_eq!(
            w.retype(dev(), ty, 32, 1),
            Err(Error::Retype(RetypeError::DeviceMemory))
        );
    }
    w.retype(dev(), ObjectType::Frame4K, 32, 1).unwrap();
    let Cap::Frame {
        device, base, size, ..
    } = w.cap(sl(32))
    else {
        panic!()
    };
    assert!(device);
    assert_eq!((base, size), (DEV, FrameSize::Small));
    w.retype(dev(), ObjectType::Untyped(12), 33, 1).unwrap();
    let Cap::Untyped { device, .. } = w.cap(sl(33)) else {
        panic!()
    };
    assert!(device);
    // A device reset only drops the watermark: nothing is cleared.
    w.revoke(dev());
    w.mem.cleared.clear();
    w.retype(dev(), ObjectType::Frame4K, 32, 1).unwrap();
    assert!(w.mem.cleared.is_empty(), "MMIO was cleared");
    assert_eq!(base_of(&w, 32), DEV);
    w.check();
}

fn base_of(w: &World, i: u64) -> u64 {
    base(w.cap(sl(i)))
}

#[test]
fn a_piece_resets_when_nothing_derives_from_it() {
    let mut w = World::new();
    let p = piece(&mut w, 20, 32);
    let pb = base(w.cap(p));
    w.retype(p, ObjectType::Frame4K, 40, 3).unwrap();
    w.retype(p, ObjectType::CNode(4), 43, 1).unwrap();
    let used = watermark(&w, p);
    w.revoke(p);
    assert!(!mdb::has_children(&w.mem, p));
    // The watermark stays until the next retype resets the piece, which then
    // makes objects from its start.
    assert_eq!(watermark(&w, p), used);
    w.mem.cleared.clear();
    w.retype(p, ObjectType::Frame4K, 40, 1).unwrap();
    assert_eq!(base_of(&w, 40), pb);
    assert_eq!(watermark(&w, p), 0x1000);
    // The clears cover exactly what was used, from the top down.
    let mut at = used;
    for &(pa, len) in &w.mem.cleared {
        assert_eq!(pa + len, pb + at, "clears out of order or with gaps");
        assert!(len <= RESET_CHUNK);
        at -= len;
    }
    assert_eq!(at, 0);
    w.check();
}

#[test]
fn a_full_piece_resets_after_its_copy_goes() {
    let mut w = World::new();
    let p = piece(&mut w, 18, 32);
    copy(&mut w.mem, p, sl(33)).unwrap();
    assert_eq!(watermark(&w, p), 1 << 18);
    w.delete(sl(33));
    w.mem.cleared.clear();
    w.retype(p, ObjectType::Frame4K, 40, 1).unwrap();
    // A full watermark clears the whole piece.
    let total: u64 = w.mem.cleared.iter().map(|&(_, l)| l).sum();
    assert_eq!(total, 1 << 18);
    w.check();
}

#[test]
fn a_reset_resumes_after_preemption_at_every_chunk() {
    for mode in [Mode::Every, Mode::Random(0xc1ea)] {
        let mut w = World::new();
        let p = piece(&mut w, 22, 32);
        let pb = base(w.cap(p));
        w.retype(p, ObjectType::Frame2M, 40, 2).unwrap();
        w.revoke(p);
        w.mem.cleared.clear();
        let mut b = budget(mode);
        let mut restarts = 0;
        let root = w.root;
        loop {
            match ops::retype(&mut w.mem, p, ObjectType::Frame4K, &root, 40, 1, &mut b) {
                Ok(()) => break,
                Err(Error::Preempted) => {
                    restarts += 1;
                    // Progress is in the watermark: what is left to clear.
                    let (pa, _) = *w.mem.cleared.last().unwrap();
                    assert_eq!(watermark(&w, p), pa - pb);
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        w.note_made(root, 40, 1);
        assert!(restarts > 0);
        // Every chunk cleared exactly once, top down, covering [0, 4 MiB).
        let mut at = 4 << 20;
        for &(pa, len) in &w.mem.cleared {
            assert_eq!(pa + len, pb + at);
            at -= len;
        }
        assert_eq!(at, 0);
        assert_eq!(base_of(&w, 40), pb);
        w.check();
    }
}

#[test]
fn a_copy_and_its_original_never_hand_out_the_same_memory() {
    let mut w = World::new();
    let p = piece(&mut w, 16, 32);
    w.retype(p, ObjectType::Frame4K, 40, 2).unwrap();
    // The original has children, so it can't be copied; revoke, then copy.
    assert_eq!(copy(&mut w.mem, p, sl(33)), Err(Error::NotDerivable));
    w.revoke(p);
    copy(&mut w.mem, p, sl(33)).unwrap();
    // The copy resets and makes from its start; the original is full.
    w.retype(sl(33), ObjectType::Frame4K, 40, 4).unwrap();
    assert_eq!(
        w.retype(p, ObjectType::Frame4K, 44, 1),
        Err(Error::Retype(RetypeError::NoRoom))
    );
    // Its objects are the original's descendants too.
    assert_eq!(w.descendants(p).len(), 5);
    w.check();
}

#[test]
fn map_takes_tables_only_from_the_space_s_own_piece() {
    let mut w = World::new();
    let p = piece(&mut w, 16, 32);
    let q = piece(&mut w, 16, 33);
    w.retype(p, ObjectType::AddressSpace, 40, 1).unwrap();
    let Cap::AddressSpace { base: sb, .. } = w.cap(sl(40)) else {
        panic!()
    };
    // The other piece doesn't contain the space: refused, unchanged.
    let before = w.mem.snapshot();
    assert_eq!(ops::take_page(&mut w.mem, q, sb), Err(Error::BadRegion));
    assert_eq!(ops::take_page(&mut w.mem, dev(), sb), Err(Error::BadRegion));
    assert_eq!(w.mem.snapshot(), before);
    // The space's own piece gives pages from its watermark.
    let wm = watermark(&w, p);
    let pa = ops::take_page(&mut w.mem, p, sb).unwrap();
    assert_eq!(pa, base(w.cap(p)) + wm);
    assert_eq!(watermark(&w, p), wm + 0x1000);
    // A piece with nothing made from it gives none: a reset would clear
    // what it gave.
    w.revoke(p);
    assert_eq!(ops::take_page(&mut w.mem, p, sb), Err(Error::BadRegion));
    w.check();
}

#[test]
fn reset_alone_clears_a_piece_once_nothing_derives_from_it() {
    for mode in [Mode::Never, Mode::Every] {
        let mut w = World::new();
        let p = piece(&mut w, 20, 32);
        let pb = base(w.cap(p));
        w.retype(p, ObjectType::Frame4K, 40, 20).unwrap();
        let used = watermark(&w, p);
        // Refused while anything derives from the piece, unchanged.
        let before = w.mem.snapshot();
        let mut b = budget(Mode::Never);
        assert_eq!(ops::reset(&mut w.mem, p, &mut b), Err(Error::InUse));
        assert_eq!(w.mem.snapshot(), before);
        assert_eq!(
            ops::reset(&mut w.mem, sl(40), &mut b),
            Err(Error::WrongKind)
        );
        assert_eq!(ops::reset(&mut w.mem, sl(99), &mut b), Err(Error::Empty));
        w.revoke(p);
        w.mem.cleared.clear();
        let mut b = budget(mode);
        let mut restarts = 0;
        while ops::reset(&mut w.mem, p, &mut b) == Err(Error::Preempted) {
            restarts += 1;
        }
        assert_eq!(restarts > 0, matches!(mode, Mode::Every));
        assert_eq!(watermark(&w, p), 0);
        // Exactly what was used, top down, once.
        let mut at = used;
        for &(pa, len) in &w.mem.cleared {
            assert_eq!(pa + len, pb + at);
            at -= len;
        }
        assert_eq!(at, 0);
        // A device piece only drops its watermark.
        w.retype(dev(), ObjectType::Frame4K, 41, 1).unwrap();
        w.revoke(dev());
        w.mem.cleared.clear();
        let mut b = budget(Mode::Never);
        assert_eq!(ops::reset(&mut w.mem, dev(), &mut b), Ok(()));
        assert_eq!(watermark(&w, dev()), 0);
        assert!(w.mem.cleared.is_empty());
        w.check();
    }
}
