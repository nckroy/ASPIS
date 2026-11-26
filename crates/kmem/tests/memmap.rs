// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Dividing the memory map (ADR 0048, rules 1 and 4).

mod common;

use common::Lcg;
use kmem::boot_alloc::BootAlloc;
use kmem::layout::DIRECT_MAP_PA_LIMIT;
use kmem::memmap::{ClassSet, Classified, Region, RegionKind};

const MIB: u64 = 1 << 20;
const PAGE: u64 = 4096;

fn region(base: u64, len: u64, kind: RegionKind) -> Region {
    Region {
        base,
        pages: len.div_ceil(PAGE),
        kind,
    }
}

const UART: (u64, u64) = (0x0900_0000, 0x1000);
const GICD: (u64, u64) = (0x0800_0000, 0x1_0000);
const GICR: (u64, u64) = (0x080a_0000, 0xf6_0000);

/// A map like the one QEMU `virt` with EDK2 gives: RAM at 1 GiB, the stub's
/// typed ranges carved out of it, a framebuffer the firmware also reports
/// inside usable RAM, firmware memory at the top, and flash MMIO.
fn qemu_like() -> Vec<Region> {
    use RegionKind::*;
    vec![
        region(0x0400_0000, 64 * MIB, Mmio),
        region(0x4000_0000, 128 * MIB, Usable),
        region(0x4800_0000, 32 * MIB, KernelImage),
        region(0x4a00_0000, 0x7f00_0000 - 0x4a00_0000, Usable),
        region(0x5000_0000, 3 * MIB, Framebuffer),
        region(0x7f00_0000, 4 * MIB, InitialImage),
        region(0x7f40_0000, 16 * 1024, BootInformation),
        region(0x7f41_0000, PAGE, Seed),
        region(0x7f40_4000, 0x7f80_0000 - 0x7f40_4000, Usable),
        region(0x7f80_0000, 8 * MIB, Usable),
        region(0x7fff_0000, 64 * 1024, Excluded),
    ]
}

fn classify(regions: &[Region], devices: &[(u64, u64)], pa_bits: u8) -> Box<Classified> {
    let mut c = Box::new(Classified::new());
    c.classify(regions.iter().copied(), devices, pa_bits)
        .unwrap();
    c
}

fn sets(c: &Classified) -> [(&'static str, &ClassSet); 6] {
    [
        ("usable", &c.usable),
        ("kept", &c.kept),
        ("framebuffer", &c.framebuffer),
        ("seed", &c.seed),
        ("excluded", &c.excluded),
        ("mmio", &c.mmio),
    ]
}

fn assert_disjoint(c: &Classified) {
    let s = sets(c);
    for (i, (na, a)) in s.iter().enumerate() {
        for (nb, b) in &s[i + 1..] {
            assert!(!a.intersects(*b), "{na} and {nb} overlap");
        }
        assert!(
            !a.intersects(&c.device) || *na == "mmio",
            "{na} overlaps device memory"
        );
    }
}

#[test]
fn a_qemu_like_map() {
    let c = classify(&qemu_like(), &[UART, GICD, GICR], 40);
    assert_disjoint(&c);

    // The framebuffer is split out of usable RAM, and kept whole.
    assert!(c.framebuffer.contains(0x5000_0000, 0x5030_0000));
    assert!(!c.usable.overlaps(0x5000_0000, 0x5030_0000));
    assert!(c.usable.contains(0x4a00_0000, 0x5000_0000));
    assert!(c.usable.contains(0x5030_0000, 0x7f00_0000));

    // The kept ranges: image, initial image and boot information.
    assert_eq!(c.kept.total(), 32 * MIB + 4 * MIB + 16 * 1024);
    assert!(c.seed.contains(0x7f41_0000, 0x7f41_1000));
    assert!(!c.usable.overlaps(0x7fff_0000, 0x8000_0000));
    assert!(c.usable.contains(0x7f80_0000, 0x7fff_0000));

    // Device untyped: flash and the gaps, up to 2^40, less RAM, the UART
    // and the GIC.
    assert!(c.device.contains(0x0400_0000, 0x0800_0000));
    assert!(c.device.contains(0x8000_0000, 1 << 40));
    for (base, size) in [UART, GICD, GICR] {
        assert!(!c.device.overlaps(base, base + size), "{base:#x}");
    }
    assert!(!c.device.overlaps(0x4000_0000, 0x8000_0000));
    assert!(!c.device.overlaps(1 << 40, u64::MAX));
    assert_eq!(c.above_direct_limit, 0);

    // The direct map: usable read-write, kept read-only, nothing else.
    let rw: u64 = c.direct_map_rw().map(|(s, e)| e - s).sum();
    let ro: u64 = c.direct_map_ro().map(|(s, e)| e - s).sum();
    assert_eq!(rw, c.usable.total());
    assert_eq!(ro, c.kept.total());
    assert!(c.direct_map_covers(0x4800_0000, PAGE, false));
    assert!(!c.direct_map_covers(0x4800_0000, PAGE, true));
    assert!(c.direct_map_covers(0x4000_0000, PAGE, true));
    assert!(!c.direct_map_covers(0x7f41_0000, PAGE, false), "the seed");
    assert!(
        !c.direct_map_covers(0x5000_0000, PAGE, false),
        "the framebuffer"
    );
    assert!(!c.direct_map_covers(0x0900_0000, PAGE, false), "the UART");
}

#[test]
fn the_more_restrictive_type_wins() {
    use RegionKind::*;
    let c = classify(
        &[
            region(0, 64 * MIB, Usable),
            region(MIB, MIB, Mmio),
            region(2 * MIB, 2 * MIB, KernelImage),
            region(3 * MIB, 2 * MIB, Framebuffer),
            region(4 * MIB + PAGE, PAGE, Seed),
            region(4 * MIB + 2 * PAGE, 8 * MIB, Excluded),
            region(10 * MIB, 4 * MIB, InitialImage),
        ],
        &[],
        32,
    );
    assert_disjoint(&c);
    assert_eq!(c.mmio.as_slice(), &[(MIB, 2 * MIB)]);
    // The initial image lost what the excluded range claimed.
    assert_eq!(
        c.kept.as_slice(),
        &[(2 * MIB, 3 * MIB), (12 * MIB + 2 * PAGE, 14 * MIB)]
    );
    assert_eq!(c.framebuffer.as_slice(), &[(3 * MIB, 4 * MIB + PAGE)]);
    assert_eq!(c.seed.as_slice(), &[(4 * MIB + PAGE, 4 * MIB + 2 * PAGE)]);
    assert_eq!(
        c.excluded.as_slice(),
        &[(4 * MIB + 2 * PAGE, 12 * MIB + 2 * PAGE)]
    );
    assert_eq!(c.usable.as_slice(), &[(0, MIB), (14 * MIB, 64 * MIB)]);
}

#[test]
fn usable_rounds_inward_and_the_rest_outward() {
    use RegionKind::*;
    let c = classify(
        &[
            region(0x1000_0800, 3 * PAGE, Usable),
            region(0x2000_0800, PAGE, Excluded),
            region(0x3000_0800, PAGE, KernelImage),
        ],
        &[(0x900_0800, 0x10)],
        32,
    );
    assert_eq!(c.usable.as_slice(), &[(0x1000_1000, 0x1000_3000)]);
    assert_eq!(c.excluded.as_slice(), &[(0x2000_0000, 0x2000_2000)]);
    assert_eq!(c.kept.as_slice(), &[(0x3000_0000, 0x3000_2000)]);
    assert!(!c.device.overlaps(0x900_0000, 0x900_1000));
    assert!(c.device.contains(0x8ff_f000, 0x900_0000));
    // The partial pages around usable RAM aren't device memory either.
    assert!(!c.device.overlaps(0x1000_0000, 0x1000_4000));
}

#[test]
fn ram_beyond_the_direct_maps_reach_is_unused() {
    use RegionKind::*;
    let c = classify(
        &[region(DIRECT_MAP_PA_LIMIT - 2 * MIB, 4 * MIB, Usable)],
        &[],
        48,
    );
    assert_eq!(
        c.usable.as_slice(),
        &[(DIRECT_MAP_PA_LIMIT - 2 * MIB, DIRECT_MAP_PA_LIMIT)]
    );
    assert_eq!(c.above_direct_limit, 2 * MIB);
    // It is RAM, so it isn't device memory.
    assert!(
        !c.device
            .overlaps(DIRECT_MAP_PA_LIMIT, DIRECT_MAP_PA_LIMIT + 2 * MIB)
    );
    assert!(c.device.contains(0, DIRECT_MAP_PA_LIMIT - 2 * MIB));
    assert!(c.device.contains(DIRECT_MAP_PA_LIMIT + 2 * MIB, 1 << 48));
}

#[test]
fn reclassifying_starts_over() {
    let mut c = Box::new(Classified::new());
    c.classify(qemu_like(), &[UART], 40).unwrap();
    c.classify([region(0x4000_0000, MIB, RegionKind::Usable)], &[], 32)
        .unwrap();
    assert_eq!(c.usable.as_slice(), &[(0x4000_0000, 0x4010_0000)]);
    assert!(c.kept.is_empty() && c.framebuffer.is_empty() && c.mmio.is_empty());
}

/// The class a page should land in, by precedence, or `None` for a gap.
fn expected(regions: &[Region], page: u64) -> Option<RegionKind> {
    use RegionKind::*;
    let rank = |k: RegionKind| match k {
        Excluded => 0,
        Seed => 1,
        Framebuffer => 2,
        KernelImage | InitialImage | BootInformation => 3,
        Mmio => 4,
        Usable => 5,
    };
    regions
        .iter()
        .filter(|r| {
            let (s, e) = r.rounded();
            s <= page && page + PAGE <= e
        })
        .min_by_key(|r| rank(r.kind))
        .map(|r| match r.kind {
            InitialImage | BootInformation => KernelImage,
            k => k,
        })
}

#[test]
fn random_maps_divide_exactly() {
    use RegionKind::*;
    const KINDS: [RegionKind; 8] = [
        Usable,
        Usable,
        Usable,
        KernelImage,
        InitialImage,
        BootInformation,
        Framebuffer,
        Seed,
    ];
    const PAGES: u64 = 1024;
    let mut rng = Lcg(0xa5915);
    let mut c = Box::new(Classified::new());
    let mut alloc = Box::new(BootAlloc::new());
    for round in 0..300 {
        let n = 1 + rng.below(12) as usize;
        let regions: Vec<Region> = (0..n)
            .map(|_| {
                let kind = match rng.below(10) {
                    8 => Mmio,
                    9 => Excluded,
                    k => KINDS[k as usize],
                };
                // Some bases are not page-aligned.
                let base = rng.below(PAGES) * PAGE + if rng.below(4) == 0 { 0x800 } else { 0 };
                region(base, 1 + rng.below(64) * PAGE, kind)
            })
            .collect();
        let devices = [(rng.below(PAGES) * PAGE, PAGE)];
        c.classify(regions.iter().copied(), &devices, 32).unwrap();
        assert_disjoint(&c);

        // Each page lands where precedence says.
        for p in 0..PAGES + 70 {
            let page = p * PAGE;
            let inside = |s: &ClassSet| s.contains(page, page + PAGE);
            let got = [
                (Usable, inside(&c.usable)),
                (KernelImage, inside(&c.kept)),
                (Framebuffer, inside(&c.framebuffer)),
                (Seed, inside(&c.seed)),
                (Excluded, inside(&c.excluded)),
                (Mmio, inside(&c.mmio)),
            ];
            let classes: Vec<_> = got.iter().filter(|g| g.1).map(|g| g.0).collect();
            let want = expected(&regions, page);
            assert_eq!(
                classes,
                want.into_iter().collect::<Vec<_>>(),
                "round {round} page {page:#x}"
            );
            // Device memory is the MMIO and the gaps, less the kernel's
            // devices; partial usable pages count as RAM, not as gaps.
            let in_any = regions.iter().any(|r| {
                let (s, e) = r.outward();
                r.kind != Mmio && s < page + PAGE && page < e
            });
            let kernel_dev = devices
                .iter()
                .any(|&(b, s)| b < page + PAGE && page < b + s);
            assert_eq!(
                c.device.contains(page, page + PAGE),
                !in_any && !kernel_dev && want.is_none_or(|k| k == Mmio),
                "round {round} device page {page:#x}"
            );
        }

        // The direct map never reaches excluded, seed, framebuffer or MMIO
        // memory, or a gap.
        for (s, e) in c.direct_map_rw().chain(c.direct_map_ro()) {
            for bad in [&c.excluded, &c.seed, &c.framebuffer, &c.mmio, &c.device] {
                assert!(!bad.overlaps(s, e));
            }
        }

        // Usable RAM = what the boot allocator took + what becomes untyped.
        alloc.start(&c.usable).unwrap();
        for _ in 0..rng.below(20) {
            let _ = alloc.alloc(None);
        }
        alloc.seal();
        assert_eq!(
            alloc.taken().total() + alloc.free().total(),
            c.usable.total()
        );
        assert!(!alloc.taken().intersects(alloc.free()));
        for (s, e) in alloc.taken().iter().chain(alloc.free().iter()) {
            assert!(c.usable.contains(s, e));
        }
    }
}
