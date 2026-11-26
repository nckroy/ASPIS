// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The boot allocator: top-down, limited on request, sealed after boot (ADR
//! 0048, rule 1).

use kmem::boot_alloc::{AllocError, BootAlloc};
use kmem::memmap::ClassSet;

const PAGE: u64 = 4096;
const GIB: u64 = 1 << 30;

fn usable(ranges: &[(u64, u64)]) -> ClassSet {
    let mut s = ClassSet::new();
    for &(a, b) in ranges {
        s.insert(a, b).unwrap();
    }
    s
}

#[test]
fn pages_come_top_down_and_cross_to_the_next_range() {
    let mut a = BootAlloc::new();
    a.start(&usable(&[(0x1000, 0x3000), (0x10_0000, 0x10_2000)]))
        .unwrap();
    let got: Vec<u64> = (0..4).map(|_| a.alloc(None).unwrap()).collect();
    assert_eq!(got, [0x10_1000, 0x10_0000, 0x2000, 0x1000]);
    assert_eq!(a.alloc(None), Err(AllocError::Exhausted));
    assert_eq!(a.taken().total(), 4 * PAGE);
    assert!(a.free().is_empty());
}

#[test]
fn a_limit_is_honored() {
    let mut a = BootAlloc::new();
    // RAM from 1 GiB to 6 GiB; the bootstrap identity map reaches 4 GiB.
    a.start(&usable(&[(GIB, 6 * GIB)])).unwrap();
    let early = Some((GIB, 4 * GIB));
    assert_eq!(a.alloc(early), Ok(4 * GIB - PAGE));
    assert_eq!(a.alloc(early), Ok(4 * GIB - 2 * PAGE));
    // Unlimited, it takes from the very top.
    assert_eq!(a.alloc(None), Ok(6 * GIB - PAGE));
    // The taken pages and the free ones still add up.
    assert_eq!(a.taken().total() + a.free().total(), 5 * GIB);
    // A limit with no usable RAM in it.
    assert_eq!(a.alloc(Some((0, GIB))), Err(AllocError::Exhausted));
    // A limit narrower than a page.
    assert_eq!(
        a.alloc(Some((GIB, GIB + 0x800))),
        Err(AllocError::Exhausted)
    );
}

#[test]
fn a_sealed_allocator_refuses_every_request() {
    let mut a = BootAlloc::new();
    a.start(&usable(&[(0, 16 * PAGE)])).unwrap();
    a.alloc(None).unwrap();
    a.seal();
    assert!(a.is_sealed());
    assert_eq!(a.alloc(None), Err(AllocError::Sealed));
    assert_eq!(a.alloc(Some((0, 16 * PAGE))), Err(AllocError::Sealed));
    // What it never handed out is left for untyped memory.
    assert_eq!(a.free().as_slice(), &[(0, 15 * PAGE)]);
    assert_eq!(a.taken().as_slice(), &[(15 * PAGE, 16 * PAGE)]);
}
