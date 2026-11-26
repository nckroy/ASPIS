// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Building, walking and unmapping translation tables.

mod common;

use common::{FakeMem, Frames};
use kmem::desc::{Half, KernelPerm, LeafError, MemType, UserPerm, kernel_leaf, user_leaf};
use kmem::layout::{DIRECT_MAP_BASE, USER_TOP};
use kmem::table::{MapError, PhysMem, Tables, UnmapError, Walk};
use kmem::{BLOCK_1G, BLOCK_2M, PAGE_SIZE};

const ROOT: u64 = 0x6000_0000_0000;
const RW: UserPerm = UserPerm {
    write: true,
    exec: false,
};

fn user_rw(pa: u64, level: u8) -> Result<u64, LeafError> {
    user_leaf(pa, level, RW, false)
}

/// Every leaf as `(va, pa, level)`.
fn leaves<M: PhysMem>(t: &Tables<'_, M>) -> Vec<(u64, u64, u8)> {
    let mut out = Vec::new();
    t.for_each_leaf(&mut |va, l| out.push((va, l.pa, l.level)));
    out
}

fn count_levels(v: &[(u64, u64, u8)]) -> [usize; 4] {
    let mut n = [0; 4];
    for &(_, _, l) in v {
        n[l as usize] += 1;
    }
    n
}

#[test]
fn picks_the_largest_blocks_alignment_allows() {
    let mem = FakeMem::new();
    let t = Tables::new(&mem, ROOT, Half::User);
    let mut src = Frames::new();
    // Starts 8 KiB below a 2 MiB boundary, runs past a 1 GiB boundary.
    let va = BLOCK_1G - BLOCK_2M - 2 * PAGE_SIZE;
    let len = 2 * PAGE_SIZE + BLOCK_2M + BLOCK_1G + BLOCK_2M + PAGE_SIZE;
    t.map(va, va, len, &mut user_rw, &mut src).unwrap();
    let got = leaves(&t);
    // 2 pages, one 2 MiB block, one 1 GiB block, one 2 MiB block, one page.
    assert_eq!(count_levels(&got), [0, 1, 2, 3]);
    let total: u64 = got.iter().map(|&(_, _, l)| kmem::desc::level_size(l)).sum();
    assert_eq!(total, len);
    for (va, pa, _) in got {
        assert_eq!(va, pa, "identity mapping");
    }

    // A physical address aligned differently forces pages throughout.
    let mem = FakeMem::new();
    let t = Tables::new(&mem, ROOT, Half::User);
    t.map(
        BLOCK_1G,
        BLOCK_1G + PAGE_SIZE,
        BLOCK_2M,
        &mut user_rw,
        &mut Frames::new(),
    )
    .unwrap();
    assert_eq!(count_levels(&leaves(&t)), [0, 0, 0, 512]);
}

#[test]
fn walk_and_for_each_leaf_agree_with_what_was_mapped() {
    let mem = FakeMem::new();
    let t = Tables::new(&mem, ROOT, Half::User);
    let mut src = Frames::new();
    let maps = [
        (0x40_0000u64, 0x8000_0000u64, 3 * PAGE_SIZE),
        (0x4000_0000, 0x1_0000_0000, BLOCK_2M),
        (0x80_0000_0000, 0x2_0000_0000, BLOCK_1G),
    ];
    for &(va, pa, len) in &maps {
        t.map(va, pa, len, &mut user_rw, &mut src).unwrap();
    }
    for &(va, pa, len) in &maps {
        for off in [0, PAGE_SIZE + 8, len - 1] {
            let w = t.walk(va + off);
            assert_eq!(w.pa(va + off), Some(pa + off), "va {:#x}", va + off);
        }
    }
    assert_eq!(t.walk(0x40_3000), Walk::Invalid { level: 3 });
    assert_eq!(t.walk(0x60_0000), Walk::Invalid { level: 2 });
    assert_eq!(t.walk(0x1_0000_0000), Walk::Invalid { level: 1 });
    assert_eq!(t.walk(0xc0_0000_0000), Walk::Invalid { level: 1 });
    assert_eq!(t.walk(0x100_0000_0000), Walk::Invalid { level: 0 });
    assert_eq!(t.walk(0x8000_0000_0000), Walk::Invalid { level: 0 });

    let got = leaves(&t);
    let mapped: u64 = got.iter().map(|&(_, _, l)| kmem::desc::level_size(l)).sum();
    assert_eq!(mapped, maps.iter().map(|m| m.2).sum::<u64>());
    for (va, pa, _) in got {
        assert_eq!(t.walk(va).pa(va), Some(pa));
    }
}

#[test]
fn an_occupied_range_is_refused_and_nothing_changes() {
    let mem = FakeMem::new();
    let t = Tables::new(&mem, ROOT, Half::User);
    let mut src = Frames::new();
    t.map(0x20_0000, 0x4000_0000, BLOCK_2M, &mut user_rw, &mut src)
        .unwrap();
    let before = leaves(&t);
    let tables = src.count;
    // Overlaps the block from below, page by page.
    assert_eq!(
        t.map(0x1f_0000, 0x5000_0000, 0x2_0000, &mut user_rw, &mut src),
        Err(MapError::Occupied)
    );
    // A page inside the block.
    assert_eq!(
        t.map(0x30_0000, 0x5000_0000, PAGE_SIZE, &mut user_rw, &mut src),
        Err(MapError::Occupied)
    );
    assert_eq!(leaves(&t), before);
    assert_eq!(src.count, tables, "a refused map made tables");
}

#[test]
fn writable_executable_and_executable_device_mappings_are_refused() {
    let mem = FakeMem::new();
    let t = Tables::new(&mem, ROOT, Half::User);
    let mut src = Frames::new();
    let wx = UserPerm {
        write: true,
        exec: true,
    };
    let rx = UserPerm {
        write: false,
        exec: true,
    };
    assert_eq!(
        t.map(
            0,
            0x4000_0000,
            PAGE_SIZE,
            &mut |pa, l| user_leaf(pa, l, wx, false),
            &mut src
        ),
        Err(MapError::WriteExecute)
    );
    assert_eq!(
        t.map(
            0,
            0x900_0000,
            PAGE_SIZE,
            &mut |pa, l| user_leaf(pa, l, rx, true),
            &mut src
        ),
        Err(MapError::DeviceExecute)
    );
    assert!(leaves(&t).is_empty());
    assert_eq!(src.count, 0);
}

#[test]
fn ranges_outside_the_half_are_refused() {
    let mem = FakeMem::new();
    let mut src = Frames::new();
    let user = Tables::new(&mem, ROOT, Half::User);
    assert_eq!(
        user.map(
            USER_TOP - PAGE_SIZE,
            0,
            2 * PAGE_SIZE,
            &mut user_rw,
            &mut src
        ),
        Err(MapError::OutOfRange)
    );
    assert_eq!(
        user.map(
            0,
            (1 << 48) - PAGE_SIZE,
            2 * PAGE_SIZE,
            &mut user_rw,
            &mut src
        ),
        Err(MapError::OutOfRange)
    );
    assert_eq!(
        user.map(0x1000, 0, 0x800, &mut user_rw, &mut src),
        Err(MapError::Misaligned)
    );
    let kernel = Tables::new(&mem, ROOT + 0x10_0000, Half::Kernel);
    let rw = |pa, l| {
        kernel_leaf(
            pa,
            l,
            MemType::Normal,
            KernelPerm {
                write: true,
                exec: false,
            },
        )
    };
    assert_eq!(
        kernel.map(0x1000, 0, PAGE_SIZE, &mut { rw }, &mut src),
        Err(MapError::OutOfRange)
    );
    // The very top page of the kernel's half is fine.
    kernel
        .map(
            u64::MAX - PAGE_SIZE + 1,
            0x4000_0000,
            PAGE_SIZE,
            &mut { rw },
            &mut src,
        )
        .unwrap();
    assert_eq!(
        kernel.unmap(u64::MAX - PAGE_SIZE + 1, PAGE_SIZE, &mut |_, _| {}),
        Ok(1)
    );
}

#[test]
fn running_out_of_tables_is_reported() {
    let mem = FakeMem::new();
    let t = Tables::new(&mem, ROOT, Half::User);
    assert_eq!(
        t.map(
            0x40_0000,
            0x4000_0000,
            PAGE_SIZE,
            &mut user_rw,
            &mut Frames::limited(1)
        ),
        Err(MapError::NoMemory)
    );
}

#[test]
fn unmap_removes_leaves_skips_holes_and_never_cuts_a_block() {
    let mem = FakeMem::new();
    let t = Tables::new(&mem, ROOT, Half::User);
    let mut src = Frames::new();
    t.map(0x20_0000, 0x4000_0000, BLOCK_2M, &mut user_rw, &mut src)
        .unwrap();
    t.map(
        0x40_0000,
        0x5000_0000,
        4 * PAGE_SIZE,
        &mut user_rw,
        &mut src,
    )
    .unwrap();
    t.map(0x40_6000, 0x5000_6000, PAGE_SIZE, &mut user_rw, &mut src)
        .unwrap();

    // Cutting the block is refused, and nothing changes.
    let before = leaves(&t);
    for (va, len) in [
        (0x30_0000, PAGE_SIZE),
        (0x10_0000, BLOCK_2M),
        (0x3f_f000, 0x2000),
    ] {
        assert_eq!(t.unmap(va, len, &mut |_, _| {}), Err(UnmapError::CutsBlock));
    }
    assert_eq!(leaves(&t), before);

    // Pages, a hole, and one more page.
    let mut seen = Vec::new();
    assert_eq!(
        t.unmap(0x40_1000, 0x6000, &mut |va, level| seen.push((va, level))),
        Ok(4)
    );
    assert_eq!(
        seen,
        [
            (0x40_1000, 3),
            (0x40_2000, 3),
            (0x40_3000, 3),
            (0x40_6000, 3)
        ]
    );
    assert!(t.walk(0x40_0000).pa(0x40_0000).is_some());
    assert_eq!(t.walk(0x40_1000), Walk::Invalid { level: 3 });

    // The whole block, then an empty range.
    assert_eq!(t.unmap(0x20_0000, BLOCK_2M, &mut |_, _| {}), Ok(1));
    assert_eq!(t.unmap(0x20_0000, 0x1000_0000, &mut |_, _| {}), Ok(1));
    assert!(leaves(&t).is_empty());
    assert_eq!(t.unmap(0, 1 << 40, &mut |_, _| {}), Ok(0));
}

#[test]
fn a_gigabyte_with_three_holes_needs_few_tables() {
    let mem = FakeMem::new();
    let t = Tables::new(&mem, ROOT, Half::User);
    let mut src = Frames::new();
    let base = 4 * BLOCK_1G;
    let holes = [base + 0x1234_5000, base + 0x2000_0000, base + 0x3fff_f000];
    let mut at = base;
    for &h in &holes {
        t.map(at, at, h - at, &mut user_rw, &mut src).unwrap();
        at = h + PAGE_SIZE;
    }
    t.map(at, at, base + BLOCK_1G - at, &mut user_rw, &mut src)
        .unwrap();
    // One level-1 table, one level-2 table, and one level-3 table for each
    // 2 MiB block that holds a hole.
    assert_eq!(src.count, 1 + 1 + 3);
    let got = leaves(&t);
    assert_eq!(got.iter().filter(|l| l.2 == 2).count(), 512 - 3);
    assert_eq!(got.iter().filter(|l| l.2 == 3).count(), 3 * 511);
    for h in holes {
        assert_eq!(t.walk(h), Walk::Invalid { level: 3 });
    }
}

#[test]
fn table_bits_are_folded_into_each_leaf() {
    let mem = FakeMem::new();
    let mut src = Frames::new();
    // A raw executable leaf, bypassing the encoders: the user tables'
    // PXNTable still forbids the kernel to execute it.
    let raw = |pa: u64, _| Ok(pa | 0b11 | (1 << 10) | (1 << 6) | (1 << 7));
    let user = Tables::new(&mem, ROOT, Half::User);
    user.map(0x40_0000, 0x4000_0000, PAGE_SIZE, &mut { raw }, &mut src)
        .unwrap();
    let Walk::Leaf { leaf, .. } = user.walk(0x40_0000) else {
        panic!()
    };
    assert!(leaf.pxn && !leaf.uxn);
    // And the kernel's UXNTable forbids EL0 to execute anything there.
    let kernel = Tables::new(&mem, ROOT + 0x10_0000, Half::Kernel);
    kernel
        .map(
            DIRECT_MAP_BASE,
            0x4000_0000,
            PAGE_SIZE,
            &mut { raw },
            &mut src,
        )
        .unwrap();
    let mut n = 0;
    kernel.for_each_leaf(&mut |va, leaf| {
        assert_eq!(va, DIRECT_MAP_BASE);
        assert!(leaf.uxn && !leaf.pxn);
        n += 1;
    });
    assert_eq!(n, 1);
}

#[test]
fn reserved_encodings_read_as_holes() {
    let mem = FakeMem::new();
    let t = Tables::new(&mem, ROOT, Half::User);
    // 0b01 at level 0 is no block with a 4 KiB granule.
    mem.write(ROOT, 0, 0x4000_0000 | 0b01);
    assert_eq!(t.walk(0x1000), Walk::Invalid { level: 0 });
    assert!(leaves(&t).is_empty());
    // 0b01 at level 3 is reserved.
    mem.write(ROOT, 0, 0x5000_0000 | 0b11);
    mem.write(0x5000_0000, 0, 0x5000_1000 | 0b11);
    mem.write(0x5000_1000, 0, 0x5000_2000 | 0b11);
    mem.write(0x5000_2000, 1, 0x4000_0000 | 0b01);
    assert_eq!(t.walk(0x1000), Walk::Invalid { level: 3 });
    assert!(leaves(&t).is_empty());
}
