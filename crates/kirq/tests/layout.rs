// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The GIC node's `reg` entries, by role, as QEMU's `virt` and the Linux
//! bindings give them.

use kirq::layout::{Frame, GicKind, GicLayout, LayoutError, MAX_REDIST_REGIONS};

const V2: [(u64, u64); 2] = [(0x800_0000, 0x1_0000), (0x801_0000, 0x1_0000)];
const V2_VIRT: [(u64, u64); 4] = [
    (0x800_0000, 0x1_0000),
    (0x801_0000, 0x1_0000),
    (0x803_0000, 0x1_0000),
    (0x804_0000, 0x1_0000),
];
const V3: [(u64, u64); 2] = [(0x800_0000, 0x1_0000), (0x80a_0000, 0xf6_0000)];

fn f(base: u64, size: u64) -> Frame {
    Frame { base, size }
}

fn mapped(l: &GicLayout) -> Vec<Frame> {
    l.mapped().collect()
}

#[test]
fn compatible_strings_name_versions() {
    assert_eq!(
        GicKind::from_compatible("arm,cortex-a15-gic"),
        Some(GicKind::V2)
    );
    assert_eq!(GicKind::from_compatible("arm,gic-400"), Some(GicKind::V2));
    assert_eq!(GicKind::from_compatible("arm,gic-v3"), Some(GicKind::V3));
    assert_eq!(GicKind::from_compatible("arm,gic-v4"), None);
}

#[test]
fn gicv2_maps_the_distributor_and_cpu_interface() {
    for regs in [&V2[..], &V2_VIRT[..]] {
        let l = GicLayout::new(GicKind::V2, regs, None, None).unwrap();
        assert_eq!(l.dist, f(0x800_0000, 0x1_0000));
        assert_eq!(l.cpu, Some(f(0x801_0000, 0x1_0000)));
        assert!(l.redistributor_regions().is_empty());
        // GICH and GICV are never mapped.
        assert_eq!(
            mapped(&l),
            [f(0x800_0000, 0x1_0000), f(0x801_0000, 0x1_0000)]
        );
    }
}

#[test]
fn gicv2_ignores_the_gicv3_properties() {
    let l = GicLayout::new(GicKind::V2, &V2, Some(&[0, 0, 0, 0]), Some(&[1])).unwrap();
    assert_eq!(l.stride, None);
}

#[test]
fn gicv3_maps_the_distributor_and_one_redistributor_region() {
    let l = GicLayout::new(GicKind::V3, &V3, Some(&1u32.to_be_bytes()), None).unwrap();
    assert_eq!(l.cpu, None);
    assert_eq!(l.redistributor_regions(), [f(0x80a_0000, 0xf6_0000)]);
    assert_eq!(
        mapped(&l),
        [f(0x800_0000, 0x1_0000), f(0x80a_0000, 0xf6_0000)]
    );
    // The default is one region.
    assert_eq!(GicLayout::new(GicKind::V3, &V3, None, None).unwrap(), l);
}

#[test]
fn gicv3_never_maps_its_legacy_or_virtual_frames() {
    // With virtualization: GICC, GICH and GICV follow the regions.
    let regs = [
        V3[0],
        V3[1],
        (0x2c00_0000, 0x2000),
        (0x2c01_0000, 0x2000),
        (0x2c02_0000, 0x2000),
    ];
    let l = GicLayout::new(GicKind::V3, &regs, None, None).unwrap();
    assert_eq!(
        mapped(&l),
        [f(0x800_0000, 0x1_0000), f(0x80a_0000, 0xf6_0000)]
    );
}

#[test]
fn gicv3_with_two_regions_and_a_stride() {
    let regs = [
        V3[0],
        (0x80a_0000, 0x4_0000),
        (0x1000_0000, 0x10_0000),
        (0x2c00_0000, 0x2000),
    ];
    let l = GicLayout::new(
        GicKind::V3,
        &regs,
        Some(&2u32.to_be_bytes()),
        Some(&0x4_0000u64.to_be_bytes()),
    )
    .unwrap();
    assert_eq!(
        l.redistributor_regions(),
        [f(0x80a_0000, 0x4_0000), f(0x1000_0000, 0x10_0000)]
    );
    assert_eq!(l.stride, Some(0x4_0000));
    assert_eq!(mapped(&l).len(), 3);
    // A one-cell stride is read too.
    let l = GicLayout::new(GicKind::V3, &V3, None, Some(&0x2_0000u32.to_be_bytes())).unwrap();
    assert_eq!(l.stride, Some(0x2_0000));
}

#[test]
fn malformed_nodes_are_refused() {
    assert_eq!(
        GicLayout::new(GicKind::V2, &V2[..1], None, None),
        Err(LayoutError::TooFewRegs { need: 2, have: 1 })
    );
    assert_eq!(
        GicLayout::new(GicKind::V3, &V3[..1], None, None),
        Err(LayoutError::TooFewRegs { need: 2, have: 1 })
    );
    assert_eq!(
        GicLayout::new(GicKind::V3, &[], None, None),
        Err(LayoutError::TooFewRegs { need: 1, have: 0 })
    );
    // More regions than there are entries.
    assert_eq!(
        GicLayout::new(GicKind::V3, &V3, Some(&2u32.to_be_bytes()), None),
        Err(LayoutError::TooFewRegs { need: 3, have: 2 })
    );
    for bad in [0u32, MAX_REDIST_REGIONS as u32 + 1] {
        assert_eq!(
            GicLayout::new(GicKind::V3, &V3, Some(&bad.to_be_bytes()), None),
            Err(LayoutError::RedistRegions)
        );
    }
    assert_eq!(
        GicLayout::new(GicKind::V3, &V3, Some(&[0, 1]), None),
        Err(LayoutError::RedistRegions)
    );
    for bad in [
        &0u64.to_be_bytes()[..],
        &0x1000u64.to_be_bytes(),
        &[0, 1, 0],
    ] {
        assert_eq!(
            GicLayout::new(GicKind::V3, &V3, None, Some(bad)),
            Err(LayoutError::Stride)
        );
    }
    // Frames too small, or unaligned.
    assert_eq!(
        GicLayout::new(GicKind::V3, &[(0x800_0000, 0x1000), V3[1]], None, None),
        Err(LayoutError::Frame("distributor"))
    );
    assert_eq!(
        GicLayout::new(GicKind::V3, &[V3[0], (0x80a_0000, 0x1_0000)], None, None),
        Err(LayoutError::Frame("redistributor region"))
    );
    assert_eq!(
        GicLayout::new(GicKind::V2, &[V2[0], (0x801_0800, 0x1000)], None, None),
        Err(LayoutError::Frame("CPU interface"))
    );
    assert_eq!(
        GicLayout::new(
            GicKind::V2,
            &[(u64::MAX - 0xfff, 0x2000), V2[1]],
            None,
            None
        ),
        Err(LayoutError::Frame("distributor"))
    );
}
