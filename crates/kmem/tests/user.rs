// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Reaching user memory by a software walk (ADR 0048, rule 5).

mod common;

use common::{FakeDirectMap, FakeMem, Frames};
use kmem::PAGE_SIZE;
use kmem::desc::{Half, UserPerm, user_leaf};
use kmem::layout::USER_TOP;
use kmem::table::{PhysMem, Tables};
use kmem::user::{Access, Bytes, UserError, copy_from_user, copy_to_user, translate};

const ROOT: u64 = 0x6000_0000_0000;
const RW: UserPerm = UserPerm {
    write: true,
    exec: false,
};
const RX: UserPerm = UserPerm {
    write: false,
    exec: true,
};

/// RAM the direct map covers read-write.
const RAM: (u64, u64) = (0x4000_0000, 0x5000_0000);
/// A kept range, read-only in the direct map.
const KEPT: (u64, u64) = (0x5000_0000, 0x5100_0000);

struct Space {
    mem: FakeMem,
    map: FakeDirectMap,
}

impl Space {
    /// - `0x40_0000`, `0x40_1000`: RAM, read-write, consecutive frames that
    ///   aren't physically adjacent;
    /// - `0x41_0000`: RAM, read-execute;
    /// - `0x50_0000`: device memory;
    /// - `0x51_0000`: a kept frame, which a buggy mapping made writable;
    /// - `0x52_0000`: a frame outside the direct map;
    /// - `0x40_2000` and everything else: nothing.
    fn new() -> Self {
        let mem = FakeMem::new();
        let t = Tables::new(&mem, ROOT, Half::User);
        let mut src = Frames::new();
        let mut map = |va, pa, perm, device| {
            t.map(
                va,
                pa,
                PAGE_SIZE,
                &mut |p, l| user_leaf(p, l, perm, device),
                &mut src,
            )
            .unwrap()
        };
        map(0x40_0000, 0x4000_5000, RW, false);
        map(0x40_1000, 0x4000_9000, RW, false);
        map(0x41_0000, 0x4001_0000, RX, false);
        map(0x50_0000, 0x0900_0000, RW, true);
        map(0x51_0000, 0x5000_0000, RW, false);
        map(0x52_0000, 0x7000_0000, RW, false);
        let mut dm = FakeDirectMap::default();
        dm.rw.insert(RAM.0, RAM.1).unwrap();
        dm.ro.insert(KEPT.0, KEPT.1).unwrap();
        Self { mem, map: dm }
    }

    fn read(&self, va: u64, buf: &mut [u8]) -> Result<(), UserError> {
        copy_from_user(&self.mem, &self.map, ROOT, va, buf)
    }

    fn write(&self, va: u64, buf: &[u8]) -> Result<(), UserError> {
        copy_to_user(&self.mem, &self.map, ROOT, va, buf)
    }
}

#[test]
fn translate_finds_ram_and_refuses_the_rest() {
    let s = Space::new();
    let tr = |va, access| translate(&s.mem, ROOT, va, access);
    assert_eq!(tr(0x40_0123, Access::Read), Ok(0x4000_5123));
    assert_eq!(tr(0x40_1fff, Access::Write), Ok(0x4000_9fff));
    assert_eq!(tr(0x41_0008, Access::Read), Ok(0x4001_0008));
    assert_eq!(tr(0x41_0008, Access::Write), Err(UserError::NoRight));
    assert_eq!(tr(0x50_0000, Access::Read), Err(UserError::NotRam));
    assert_eq!(tr(USER_TOP, Access::Read), Err(UserError::NotUserAddress));
    assert_eq!(
        tr(0xffff_8000_0000_0000, Access::Read),
        Err(UserError::NotUserAddress)
    );
}

#[test]
fn every_missing_level_is_not_resident() {
    let s = Space::new();
    for va in [
        0x40_2000,         // level 3: no page in a table that exists
        0x60_0000,         // level 2: no level-3 table
        0x4000_0000,       // level 1: no level-2 table
        0x80_0000_0000,    // level 0: no level-1 table
        USER_TOP - 0x1000, // the last page
    ] {
        assert_eq!(
            translate(&s.mem, ROOT, va, Access::Read),
            Err(UserError::NotResident),
            "{va:#x}"
        );
    }
}

#[test]
fn copies_cross_a_page_boundary() {
    let s = Space::new();
    let data: Vec<u8> = (0..64u8).collect();
    s.write(0x40_0fe0, &data).unwrap();
    // The bytes landed in two separate frames.
    let mut half = [0u8; 32];
    Bytes::read(&s.mem, 0x4000_5fe0, &mut half);
    assert_eq!(half[..], data[..32]);
    Bytes::read(&s.mem, 0x4000_9000, &mut half);
    assert_eq!(half[..], data[32..]);
    let mut back = vec![0u8; 64];
    s.read(0x40_0fe0, &mut back).unwrap();
    assert_eq!(back, data);
    // Zero bytes are always fine.
    s.read(0x40_0000, &mut []).unwrap();
}

#[test]
fn a_bad_page_anywhere_moves_nothing() {
    let s = Space::new();
    let before = vec![0xaa; 2 * PAGE_SIZE as usize];
    s.write(0x40_0000, &before).unwrap();
    // The span runs from two good pages into a hole.
    let ones = vec![1u8; 2 * PAGE_SIZE as usize + 16];
    assert_eq!(s.write(0x40_0000, &ones), Err(UserError::NotResident));
    let mut buf = vec![0u8; 2 * PAGE_SIZE as usize];
    s.read(0x40_0000, &mut buf).unwrap();
    assert_eq!(buf, before, "a failed write moved bytes");
    // A failed read leaves the buffer alone too.
    let mut buf = vec![7u8; 2 * PAGE_SIZE as usize + 16];
    assert_eq!(s.read(0x40_0000, &mut buf), Err(UserError::NotResident));
    assert!(buf.iter().all(|&b| b == 7));
    // Running off the end of the lower half.
    assert_eq!(
        s.read(USER_TOP - 8, &mut [0; 16]),
        Err(UserError::NotUserAddress)
    );
}

#[test]
fn writes_need_the_write_right_and_the_writable_direct_map() {
    let s = Space::new();
    // A read-execute mapping.
    assert_eq!(s.write(0x41_0000, &[1]), Err(UserError::NoRight));
    let mut b = [0u8; 4];
    s.read(0x41_0000, &mut b).unwrap();
    // Device memory, either way.
    assert_eq!(s.read(0x50_0000, &mut b), Err(UserError::NotRam));
    assert_eq!(s.write(0x50_0000, &b), Err(UserError::NotRam));
    // A kept frame mapped writable by mistake: readable, never written
    // through the read-only part of the direct map.
    s.read(0x51_0000, &mut b).unwrap();
    assert_eq!(s.write(0x51_0000, &b), Err(UserError::NoRight));
    // A frame the direct map doesn't cover at all.
    assert_eq!(s.read(0x52_0000, &mut b), Err(UserError::NotRam));
    assert_eq!(s.write(0x52_0000, &b), Err(UserError::NotRam));
    // The tables themselves weren't touched by any of it.
    assert_ne!(PhysMem::read(&s.mem, ROOT, 0), 0);
}
