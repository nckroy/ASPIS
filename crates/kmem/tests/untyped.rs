// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Untyped memory: decomposition, retype and reset.

mod common;

use common::Lcg;
use kmem::untyped::{
    EVENTCOUNT_BITS, MAX_BITS, MAX_RADIX, MAX_SCHED_CONTEXT_BITS, MAX_WAIT_SET_BITS,
    MAX_WAIT_SET_ENTRIES, MIN_BITS, MIN_SCHED_CONTEXT_BITS, MIN_WAIT_SET_BITS, ObjectType,
    RetypeError, THREAD_BITS, Untyped, decompose, wait_set_entries,
};

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
    // The kernel keeps no slots or endpoints in MMIO (C11).
    assert_eq!(
        u.retype(ObjectType::CNode(1), 1),
        Err(RetypeError::DeviceMemory)
    );
    assert_eq!(
        u.retype(ObjectType::Endpoint, 1),
        Err(RetypeError::DeviceMemory)
    );
}

#[test]
fn cnodes_and_endpoints_have_their_sizes() {
    // A CNode is 2^(radix + 5) bytes; an endpoint is 64 bytes for now.
    assert_eq!(ObjectType::CNode(1).size_bits(), 6);
    assert_eq!(ObjectType::CNode(7).size_bits(), 12);
    assert_eq!(ObjectType::CNode(MAX_RADIX).size_bits(), MAX_BITS);
    assert_eq!(ObjectType::Endpoint.size_bits(), 6);
    let mut u = Untyped::new(0x4000_0000, 14, false).unwrap();
    assert_eq!(u.retype(ObjectType::Endpoint, 1), Ok(0x4000_0000));
    // A CNode of 4 KiB is aligned to 4 KiB, past the endpoint.
    assert_eq!(u.retype(ObjectType::CNode(7), 1), Ok(0x4000_1000));
    assert_eq!(u.retype(ObjectType::CNode(1), 2), Ok(0x4000_2000));
    assert_eq!(u.watermark(), 0x2080);
    // A radix out of range is refused before anything changes.
    for radix in [0, MAX_RADIX + 1, u8::MAX] {
        assert_eq!(
            u.retype(ObjectType::CNode(radix), 1),
            Err(RetypeError::BadSize)
        );
    }
    assert_eq!(u.retype(ObjectType::CNode(10), 1), Err(RetypeError::TooBig));
    assert_eq!(u.watermark(), 0x2080);
}

#[test]
fn threads_contexts_and_replies_have_their_sizes() {
    // C12: a thread is 2 KiB, a scheduling context 256 bytes to 4 KiB, and
    // a reply object 128 bytes (kernel specification K07 and K15).
    assert_eq!(ObjectType::Thread.size_bits(), THREAD_BITS);
    assert_eq!(THREAD_BITS, 11);
    assert_eq!(ObjectType::Reply.size_bits(), 7);
    for bits in MIN_SCHED_CONTEXT_BITS..=MAX_SCHED_CONTEXT_BITS {
        assert_eq!(ObjectType::SchedContext(bits).size_bits(), bits);
        assert!(ObjectType::SchedContext(bits).size_ok());
    }
    let mut u = Untyped::new(0x4000_0000, 14, false).unwrap();
    for bits in [0, 7, 13, u8::MAX] {
        assert_eq!(
            u.retype(ObjectType::SchedContext(bits), 1),
            Err(RetypeError::BadSize)
        );
    }
    assert_eq!(u.retype(ObjectType::Reply, 1), Ok(0x4000_0000));
    // Aligned to its size, past the reply.
    assert_eq!(u.retype(ObjectType::Thread, 1), Ok(0x4000_0800));
    assert_eq!(u.retype(ObjectType::SchedContext(8), 2), Ok(0x4000_1000));
    assert_eq!(u.retype(ObjectType::SchedContext(12), 1), Ok(0x4000_2000));
    assert_eq!(u.watermark(), 0x3000);
    // The kernel keeps none of them in MMIO.
    let mut d = Untyped::new(0x900_0000, 21, true).unwrap();
    for ty in [
        ObjectType::Thread,
        ObjectType::SchedContext(8),
        ObjectType::Reply,
    ] {
        assert_eq!(d.retype(ty, 1), Err(RetypeError::DeviceMemory));
    }
}

#[test]
fn eventcounts_and_wait_sets_have_their_sizes() {
    // C14: an eventcount and an endpoint are 64 bytes; a wait set is 128
    // bytes to 4 KiB, holding 1, 3, 7, 15, 31 or 60 entries (kernel
    // specification K07 and K33).
    assert_eq!(ObjectType::Eventcount.size_bits(), EVENTCOUNT_BITS);
    assert_eq!(EVENTCOUNT_BITS, 6);
    assert_eq!(ObjectType::Endpoint.size_bits(), 6);
    assert!(ObjectType::Eventcount.size_ok());
    let entries: Vec<u64> = (MIN_WAIT_SET_BITS..=MAX_WAIT_SET_BITS)
        .map(|bits| {
            assert_eq!(ObjectType::WaitSet(bits).size_bits(), bits);
            assert!(ObjectType::WaitSet(bits).size_ok());
            wait_set_entries(bits)
        })
        .collect();
    assert_eq!(entries, [1, 3, 7, 15, 31, 60]);
    assert_eq!(wait_set_entries(MAX_WAIT_SET_BITS), MAX_WAIT_SET_ENTRIES);
    for bits in [0, 6, 13, u8::MAX] {
        assert!(!ObjectType::WaitSet(bits).size_ok());
        assert_eq!(wait_set_entries(bits), 0);
    }
    let mut u = Untyped::new(0x4000_0000, 14, false).unwrap();
    for bits in [0, 6, 13, u8::MAX] {
        assert_eq!(
            u.retype(ObjectType::WaitSet(bits), 1),
            Err(RetypeError::BadSize)
        );
    }
    assert_eq!(u.retype(ObjectType::Eventcount, 3), Ok(0x4000_0000));
    // Each wait set is aligned to its size, past the eventcounts.
    assert_eq!(u.retype(ObjectType::WaitSet(7), 1), Ok(0x4000_0100));
    assert_eq!(u.retype(ObjectType::WaitSet(12), 2), Ok(0x4000_1000));
    assert_eq!(u.retype(ObjectType::WaitSet(9), 1), Ok(0x4000_3000));
    assert_eq!(u.watermark(), 0x3200);
    // The kernel keeps none of them in MMIO.
    let mut d = Untyped::new(0x900_0000, 21, true).unwrap();
    for ty in [ObjectType::Eventcount, ObjectType::WaitSet(7)] {
        assert_eq!(d.retype(ty, 1), Err(RetypeError::DeviceMemory));
    }
}

#[test]
fn a_piece_round_trips_through_its_parts() {
    let mut u = Untyped::new(0x4000_0000, 16, false).unwrap();
    u.retype(ObjectType::Frame4K, 3).unwrap();
    let back = Untyped::from_parts(u.base(), u.bits(), u.is_device(), u.watermark());
    assert_eq!(back, Some(u));
    // A watermark past the end, or a misaligned base, is refused.
    assert!(Untyped::from_parts(0x4000_0000, 16, false, 64 * KIB + 1).is_none());
    assert!(Untyped::from_parts(0x4000_0000, 16, false, 64 * KIB).is_some());
    assert!(Untyped::from_parts(0x4000_1000, 16, false, 0).is_none());
    // Full: nothing more can be made until a reset.
    u.set_full();
    assert_eq!(u.watermark(), 64 * KIB);
    assert_eq!(u.retype(ObjectType::Frame4K, 1), Err(RetypeError::NoRoom));
    u.begin_reset();
    let mut cleared = 0;
    while let Some((_, len)) = u.reset_step(64 * KIB) {
        cleared += len;
    }
    assert_eq!(cleared, 64 * KIB);
    assert_eq!(u.retype(ObjectType::Frame4K, 1), Ok(0x4000_0000));
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
