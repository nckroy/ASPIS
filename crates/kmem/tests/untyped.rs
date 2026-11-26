// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Untyped memory: decomposition, retype and reset.

mod common;

use common::Lcg;
use kmem::untyped::{MAX_BITS, MIN_BITS, ObjectType, RetypeError, Untyped, decompose};

const KIB: u64 = 1024;

#[test]
fn decomposition_tiles_the_range_with_aligned_pieces() {
    let mut rng = Lcg(0xdec0);
    let mut cases = vec![
        (0, 1 << 32),
        (0x4000_0000, 0x7f00_0000),
        (0x1000, 0x2000),
        (0x4a00_3000, 0x5000_0000),
        (0, 1 << 48),
    ];
    for _ in 0..500 {
        let a = rng.below(1 << 36) << 12;
        let b = a + (rng.below(1 << 24) << 12);
        cases.push((a, b));
    }
    for (start, end) in cases {
        let mut at = start;
        for (base, bits) in decompose(start, end) {
            assert_eq!(base, at, "pieces of [{start:#x}, {end:#x}) leave a gap");
            assert!((MIN_BITS..=MAX_BITS).contains(&bits));
            assert_eq!(base % (1 << bits), 0, "piece at {base:#x} misaligned");
            // Largest first: the piece twice the size wouldn't fit or align.
            if bits < MAX_BITS {
                let twice = 1u64 << (bits + 1);
                assert!(base % twice != 0 || base + twice > end);
            }
            at = base + (1 << bits);
        }
        assert_eq!(at, end.max(start));
    }
    // An unaligned range is rounded inward.
    let v: Vec<_> = decompose(0x800, 0x3800).collect();
    assert_eq!(v, [(0x1000, 12), (0x2000, 12)]);
    assert_eq!(decompose(0x1800, 0x1c00).count(), 0);
}

#[test]
fn retype_aligns_each_object_to_its_size() {
    let mut u = Untyped::new(0x4000_0000, 16, false).unwrap();
    assert_eq!(u.retype(ObjectType::Frame4K, 1), Ok(0x4000_0000));
    // An address space is 8 KiB, aligned to 8 KiB.
    assert_eq!(u.retype(ObjectType::AddressSpace, 1), Ok(0x4000_2000));
    assert_eq!(u.watermark(), 16 * KIB);
    assert_eq!(u.retype(ObjectType::PageTable, 3), Ok(0x4000_4000));
    assert_eq!(u.retype(ObjectType::Untyped(14), 1), Ok(0x4000_8000));
    assert_eq!(u.watermark(), 48 * KIB);
    assert_eq!(u.free(), 16 * KIB);
}

#[test]
fn retype_refuses_what_doesnt_fit() {
    let mut u = Untyped::new(0x4000_0000, 16, false).unwrap();
    assert_eq!(
        u.retype(ObjectType::Frame4K, 0),
        Err(RetypeError::ZeroCount)
    );
    assert_eq!(u.retype(ObjectType::Frame2M, 1), Err(RetypeError::TooBig));
    assert_eq!(
        u.retype(ObjectType::Untyped(11), 1),
        Err(RetypeError::BadSize)
    );
    assert_eq!(
        u.retype(ObjectType::Untyped(48), 1),
        Err(RetypeError::BadSize)
    );
    assert_eq!(u.retype(ObjectType::Frame4K, 17), Err(RetypeError::NoRoom));
    assert_eq!(
        u.retype(ObjectType::Frame4K, u64::MAX),
        Err(RetypeError::NoRoom)
    );
    assert_eq!(u.watermark(), 0, "a refused retype changed the watermark");
    assert!(u.retype(ObjectType::Frame4K, 15).is_ok());
    // 4 KiB left, but an address space must be 8 KiB aligned.
    assert_eq!(
        u.retype(ObjectType::AddressSpace, 1),
        Err(RetypeError::NoRoom)
    );
    assert_eq!(u.watermark(), 60 * KIB);
    assert!(u.retype(ObjectType::PageTable, 1).is_ok());
    assert_eq!(u.retype(ObjectType::PageTable, 1), Err(RetypeError::NoRoom));
}

#[test]
fn device_untyped_makes_only_frames_and_device_untyped() {
    let mut u = Untyped::new(0x900_0000, 21, true).unwrap();
    assert!(u.is_device());
    assert_eq!(
        u.retype(ObjectType::PageTable, 1),
        Err(RetypeError::DeviceMemory)
    );
    assert_eq!(
        u.retype(ObjectType::AddressSpace, 1),
        Err(RetypeError::DeviceMemory)
    );
    assert_eq!(u.retype(ObjectType::Frame4K, 1), Ok(0x900_0000));
    assert_eq!(u.retype(ObjectType::Untyped(12), 1), Ok(0x900_1000));
    assert_eq!(u.retype(ObjectType::Frame2M, 1), Err(RetypeError::NoRoom));
}

#[test]
fn pieces_must_be_aligned_and_sized() {
    assert!(Untyped::new(0x1000, 13, false).is_none());
    assert!(Untyped::new(0, 11, false).is_none());
    assert!(Untyped::new(0, 48, false).is_none());
    assert!(Untyped::new(1 << 47, 47, false).is_some());
}

#[test]
fn reset_clears_from_the_top_down_and_ends_at_zero() {
    let mut u = Untyped::new(0x4000_0000, 20, false).unwrap();
    u.retype(ObjectType::Frame4K, 1).unwrap();
    u.retype(ObjectType::Untyped(17), 1).unwrap();
    assert_eq!(u.watermark(), 256 * KIB);
    u.begin_reset();
    let mut steps = Vec::new();
    while let Some(r) = u.reset_step(64 * KIB) {
        steps.push(r);
        // The watermark records progress: what is left to clear.
        assert_eq!(u.watermark(), r.0 - 0x4000_0000);
    }
    let want: Vec<_> = (0..4)
        .rev()
        .map(|i| (0x4000_0000 + i * 64 * KIB, 64 * KIB))
        .collect();
    assert_eq!(steps, want);
    assert_eq!(u.watermark(), 0);
    // An unaligned watermark clears the partial chunk first.
    u.retype(ObjectType::Frame4K, 17).unwrap();
    u.begin_reset();
    assert_eq!(u.reset_step(64 * KIB), Some((0x4001_0000, 4 * KIB)));
    assert_eq!(u.reset_step(64 * KIB), Some((0x4000_0000, 64 * KIB)));
    assert_eq!(u.reset_step(64 * KIB), None);
    // The piece is whole again.
    assert_eq!(u.retype(ObjectType::Untyped(20), 1), Ok(0x4000_0000));
}

#[test]
fn a_device_piece_is_never_cleared() {
    let mut u = Untyped::new(0x900_0000, 16, true).unwrap();
    u.retype(ObjectType::Frame4K, 3).unwrap();
    u.begin_reset();
    assert_eq!(u.watermark(), 0);
    assert_eq!(u.reset_step(64 * KIB), None);
    // Even without begin_reset, a step yields nothing to clear.
    u.retype(ObjectType::Frame4K, 1).unwrap();
    assert_eq!(u.reset_step(4 * KIB), None);
    assert_eq!(u.watermark(), 0);
}
