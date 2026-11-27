// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The redistributor walk, over fake registers.

use kirq::affinity::Affinity;
use kirq::layout::Frame;
use kirq::redist::{RedistRegs, find, walk};
use kirq::regs::gicr::{TYPER_LAST, TYPER_VLPIS};
use std::collections::HashMap;

/// Fake redistributors: `RD_base` to (`PIDR2`, `TYPER`). Anything else
/// reads as zero, as a hole in the region would.
#[derive(Default)]
struct Fake {
    frames: HashMap<u64, (u32, u64)>,
    reads: Vec<u64>,
}

impl Fake {
    fn add(&mut self, at: u64, rev: u8, affinity: u32, flags: u64) {
        self.frames.insert(
            at,
            (u32::from(rev) << 4 | 0xb, u64::from(affinity) << 32 | flags),
        );
    }
}

impl RedistRegs for Fake {
    fn pidr2(&mut self, rd: u64) -> u32 {
        self.reads.push(rd);
        self.frames.get(&rd).map_or(0, |f| f.0)
    }
    fn typer(&mut self, rd: u64) -> u64 {
        self.frames.get(&rd).map_or(0, |f| f.1)
    }
}

const BASE: u64 = 0x80a_0000;
const FRAME: u64 = 0x2_0000;

fn a(aff0: u8) -> Affinity {
    Affinity {
        aff0,
        ..Affinity::default()
    }
}

fn qemu(cores: u8) -> Fake {
    let mut f = Fake::default();
    for i in 0..cores {
        let last = if i + 1 == cores { TYPER_LAST } else { 0 };
        f.add(BASE + u64::from(i) * FRAME, 3, u32::from(i), last);
    }
    f
}

fn region(size: u64) -> [Frame; 1] {
    [Frame { base: BASE, size }]
}

#[test]
fn each_core_of_four_is_found_and_a_fifth_is_not() {
    let mut f = qemu(4);
    let r = region(0xf6_0000);
    for i in 0..4 {
        assert_eq!(
            find(&r, None, &mut f, a(i)),
            Some(BASE + u64::from(i) * FRAME)
        );
    }
    f.reads.clear();
    assert_eq!(find(&r, None, &mut f, a(4)), None);
    // The walk stopped at Last, not at the region's end.
    assert_eq!(f.reads.len(), 4);
}

#[test]
fn vlpis_frames_step_by_four_frames() {
    // GICv4 redistributors: ArchRev 4, with VLPIS.
    let mut f = Fake::default();
    f.add(BASE, 4, 0, TYPER_VLPIS);
    f.add(BASE + 2 * FRAME, 4, 1, TYPER_VLPIS | TYPER_LAST);
    // A frame at the two-frame step would be found wrongly.
    f.add(BASE + FRAME, 4, 9, 0);
    let r = region(0x10_0000);
    assert_eq!(find(&r, None, &mut f, a(1)), Some(BASE + 2 * FRAME));
    assert_eq!(find(&r, None, &mut f, a(9)), None);
}

#[test]
fn an_explicit_stride_wins() {
    let mut f = Fake::default();
    f.add(BASE, 3, 0, 0);
    f.add(BASE + 0x8_0000, 3, 1, TYPER_LAST);
    let r = region(0x10_0000);
    assert_eq!(
        find(&r, Some(0x8_0000), &mut f, a(1)),
        Some(BASE + 0x8_0000)
    );
    assert_eq!(find(&r, None, &mut f, a(1)), None);
}

#[test]
fn two_regions_are_walked_in_order() {
    let mut f = Fake::default();
    f.add(BASE, 3, 0, TYPER_LAST);
    f.add(0x1000_0000, 3, 1, 0);
    f.add(0x1000_0000 + FRAME, 3, 2, TYPER_LAST);
    let r = [
        Frame {
            base: BASE,
            size: FRAME,
        },
        Frame {
            base: 0x1000_0000,
            size: 4 * FRAME,
        },
    ];
    let mut seen = Vec::new();
    assert_eq!(
        walk(&r, None, &mut f, |rd, typer| {
            seen.push((rd, Affinity::from_gicr_typer(typer)));
            false
        }),
        None
    );
    assert_eq!(
        seen,
        [
            (BASE, a(0)),
            (0x1000_0000, a(1)),
            (0x1000_0000 + FRAME, a(2))
        ]
    );
}

#[test]
fn a_region_without_last_stops_at_its_end() {
    let mut f = Fake::default();
    for i in 0..4 {
        f.add(BASE + i * FRAME, 3, i as u32, 0);
    }
    // Two frames fit; the third would cross the end.
    let r = region(2 * FRAME + 0x1_0000);
    f.reads.clear();
    assert_eq!(find(&r, None, &mut f, a(2)), None);
    assert_eq!(f.reads, [BASE, BASE + FRAME]);
}

#[test]
fn a_frame_that_isnt_a_redistributor_ends_its_region() {
    let mut f = qemu(2);
    // ArchRev 2 at the second frame: not a GICv3 redistributor.
    f.add(BASE + FRAME, 2, 1, TYPER_LAST);
    assert_eq!(find(&region(0xf6_0000), None, &mut f, a(1)), None);
    // A hole that reads zero ends it too.
    let mut f = Fake::default();
    f.add(BASE + FRAME, 3, 1, TYPER_LAST);
    assert_eq!(find(&region(0xf6_0000), None, &mut f, a(1)), None);
}

#[test]
fn every_affinity_field_is_compared() {
    let mut f = Fake::default();
    let far = Affinity {
        aff3: 1,
        aff2: 2,
        aff1: 3,
        aff0: 4,
    };
    f.add(
        BASE,
        3,
        Affinity {
            aff3: 1,
            aff2: 2,
            aff1: 3,
            aff0: 5,
        }
        .packed(),
        0,
    );
    f.add(
        BASE + FRAME,
        3,
        Affinity {
            aff3: 0,
            aff2: 2,
            aff1: 3,
            aff0: 4,
        }
        .packed(),
        0,
    );
    f.add(BASE + 2 * FRAME, 3, far.packed(), TYPER_LAST);
    assert_eq!(
        find(&region(0xf6_0000), None, &mut f, far),
        Some(BASE + 2 * FRAME)
    );
    assert_eq!(Affinity::from_gicr_typer(f.typer(BASE + 2 * FRAME)), far);
}
