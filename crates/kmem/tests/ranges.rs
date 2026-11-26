// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Range sets, checked against a bitmap model.

mod common;

use common::Lcg;
use kmem::ranges::{Full, RangeSet};

#[test]
fn insert_merges_touching_and_overlapping_ranges() {
    let mut s = RangeSet::<8>::new();
    s.insert(10, 20).unwrap();
    s.insert(30, 40).unwrap();
    s.insert(20, 30).unwrap();
    assert_eq!(s.as_slice(), &[(10, 40)]);
    s.insert(50, 60).unwrap();
    s.insert(5, 55).unwrap();
    assert_eq!(s.as_slice(), &[(5, 60)]);
    s.insert(7, 7).unwrap();
    assert_eq!(s.len(), 1);
}

#[test]
fn remove_splits_and_trims() {
    let mut s = RangeSet::<8>::new();
    s.insert(0, 100).unwrap();
    s.remove(40, 60).unwrap();
    assert_eq!(s.as_slice(), &[(0, 40), (60, 100)]);
    s.remove(30, 70).unwrap();
    assert_eq!(s.as_slice(), &[(0, 30), (70, 100)]);
    s.remove(0, 100).unwrap();
    assert!(s.is_empty());
}

#[test]
fn a_full_set_is_left_unchanged() {
    let mut s = RangeSet::<2>::new();
    s.insert(0, 10).unwrap();
    s.insert(20, 30).unwrap();
    assert_eq!(s.insert(40, 50), Err(Full));
    assert_eq!(s.remove(2, 4), Err(Full));
    assert_eq!(s.as_slice(), &[(0, 10), (20, 30)]);
    // Merging needs no new slot.
    s.insert(10, 20).unwrap();
    assert_eq!(s.as_slice(), &[(0, 30)]);
}

#[test]
fn queries() {
    let mut s = RangeSet::<8>::new();
    s.insert(10, 20).unwrap();
    s.insert(30, 40).unwrap();
    assert!(s.contains(12, 18) && s.contains(10, 20) && s.contains(5, 5));
    assert!(!s.contains(15, 35));
    assert!(s.overlaps(19, 31) && !s.overlaps(20, 30));
    assert_eq!(s.total(), 20);
    let mut c = s.clone();
    c.clip(15, 35);
    assert_eq!(c.as_slice(), &[(15, 20), (30, 35)]);
}

#[test]
fn random_operations_match_a_bitmap() {
    const DOMAIN: u64 = 256;
    let mut rng = Lcg(0x5eed);
    for _ in 0..200 {
        let mut s = RangeSet::<64>::new();
        let mut model = [false; DOMAIN as usize];
        for _ in 0..60 {
            let a = rng.below(DOMAIN);
            let b = rng.below(DOMAIN + 1);
            let (a, b) = (a.min(b), a.max(b));
            let add = rng.below(3) != 0;
            let r = if add { s.insert(a, b) } else { s.remove(a, b) };
            if r.is_ok() {
                for m in &mut model[a as usize..b as usize] {
                    *m = add;
                }
            }
            // Sorted, disjoint, coalesced, non-empty.
            let v = s.as_slice();
            for w in v.windows(2) {
                assert!(w[0].1 < w[1].0, "{v:?}");
            }
            assert!(v.iter().all(|&(a, b)| a < b));
            for (i, &m) in model.iter().enumerate() {
                assert_eq!(s.contains(i as u64, i as u64 + 1), m, "{i} in {v:?}");
            }
        }
    }
}
