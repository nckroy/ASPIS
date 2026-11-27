// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The share check is exact: it admits exact fits and refuses anything past
//! the share; releases return it to zero.

mod common;

use common::Lcg;
use ksched::share::{MAX_DEN, Refused, Share, Used, gcd};

const WHOLE: Share = Share::WHOLE;

#[test]
fn gcd_works() {
    assert_eq!(gcd(0, 0), 0);
    assert_eq!(gcd(0, 7), 7);
    assert_eq!(gcd(12, 18), 6);
    assert_eq!(gcd(1 << 90, 3 << 80), 1 << 80);
    assert_eq!(gcd(1_000_003, 999_983), 1);
}

#[test]
fn exact_fits_are_admitted() {
    // Three 1 ms in 3 ms fill a core exactly.
    let mut u = Used::EMPTY;
    for _ in 0..3 {
        u = u.admit(WHOLE, 1_000, 3_000).unwrap();
    }
    assert_eq!(u.fraction(), (1, 1));
    assert_eq!(u.admit(WHOLE, 10, 3_600_000_000), Err(Refused::PastShare));
    // Sevenths, and a mix: 1/2 + 1/3 + 1/6.
    let mut u = Used::EMPTY;
    for _ in 0..7 {
        u = u.admit(WHOLE, 10, 70).unwrap();
    }
    assert_eq!(u.fraction(), (1, 1));
    let u = Used::EMPTY
        .admit(WHOLE, 500, 1_000)
        .and_then(|u| u.admit(WHOLE, 100, 300))
        .and_then(|u| u.admit(WHOLE, 100, 600))
        .unwrap();
    assert_eq!(u.fraction(), (1, 1));
}

#[test]
fn past_the_share_is_refused() {
    let half = Share::new(500, 1_000);
    let u = Used::EMPTY.admit(half, 500, 1_000).unwrap();
    assert_eq!(u.admit(half, 10, 3_600_000_000), Err(Refused::PastShare));
    // A share of 1 ms in 3 ms, which no fixed-point fraction holds exactly:
    // a context of exactly the share fits, and a microsecond more doesn't.
    let third = Share::new(1_000, 3_000);
    assert!(Used::EMPTY.admit(third, 1_000, 3_000).is_ok());
    assert!(Used::EMPTY.admit(third, 333_333, 1_000_000).is_ok());
    assert_eq!(
        Used::EMPTY.admit(third, 333_334, 1_000_000),
        Err(Refused::PastShare)
    );
    assert_eq!(
        Used::EMPTY.admit(third, 1_001, 3_000),
        Err(Refused::PastShare)
    );
    // Round-robin takes a whole core.
    assert!(Used::EMPTY.admit(WHOLE, 1_000, 1_000).is_ok());
    assert_eq!(
        Used::EMPTY.admit(Share::new(999_999, 1_000_000), 1_000, 1_000),
        Err(Refused::PastShare)
    );
    // No share admits nothing.
    assert_eq!(
        Used::EMPTY.admit(Share::new(0, 1_000), 10, 1_000),
        Err(Refused::PastShare)
    );
}

#[test]
fn release_returns_exactly() {
    let u = Used::EMPTY.admit(WHOLE, 1_000, 3_000).unwrap();
    let v = u.admit(WHOLE, 250, 1_000).unwrap();
    assert_eq!(v.release(250, 1_000), u);
    assert_eq!(u.release(1_000, 3_000), Used::EMPTY);
    // Reconfiguring a context of a full core.
    let full = Used::EMPTY.admit(WHOLE, 1_000, 1_000).unwrap();
    let half = full
        .reconfigure(WHOLE, (1_000, 1_000), (500, 1_000))
        .unwrap();
    assert_eq!(half.fraction(), (1, 2));
    let two = half.admit(WHOLE, 250, 1_000).unwrap();
    assert_eq!(
        two.reconfigure(WHOLE, (250, 1_000), (501, 1_000)),
        Err(Refused::PastShare)
    );
    assert_eq!(
        two.reconfigure(WHOLE, (250, 1_000), (500, 1_000))
            .unwrap()
            .fraction(),
        (1, 1)
    );
}

#[test]
fn too_fine_is_refused_and_release_stays_safe() {
    // Pairwise coprime periods near an hour.
    let ps = [
        3_599_999_993u64,
        3_599_999_977,
        3_599_999_947,
        3_599_999_929,
    ];
    let mut u = Used::EMPTY;
    let mut admitted = 0;
    for p in ps {
        match u.admit(WHOLE, 10, p) {
            Ok(v) => {
                u = v;
                admitted += 1;
            }
            Err(e) => {
                assert_eq!(e, Refused::TooFine);
                break;
            }
        }
    }
    assert!((2..4).contains(&admitted));
    assert!(u.fraction().1 <= MAX_DEN);
    // Releasing them all returns to zero.
    for p in &ps[..admitted] {
        u = u.release(10, *p);
    }
    assert_eq!(u, Used::EMPTY);
}

/// Against an exact model in floating fractions over a common denominator:
/// random admits and releases never let the sum pass the share, and admit
/// every fit.
#[test]
fn random_against_exact_sums() {
    let mut rng = Lcg(7);
    let periods = [1_000u64, 2_000, 3_000, 5_000, 7_000, 10_000, 12_000];
    let lcm: u128 = 420_000; // the periods' least common multiple, in µs
    for _ in 0..common::runs(200) {
        let sp = periods[rng.below(periods.len() as u64) as usize];
        let share = Share::new(rng.below(sp) + 1, sp);
        let mut u = Used::EMPTY;
        let mut held: Vec<(u64, u64)> = vec![];
        for _ in 0..40 {
            if !held.is_empty() && rng.chance(40) {
                let i = rng.below(held.len() as u64) as usize;
                let (b, p) = held.swap_remove(i);
                u = u.release(b, p);
            } else {
                let p = periods[rng.below(periods.len() as u64) as usize];
                let b = rng.below(p - 9) + 10;
                let sum: u128 = held
                    .iter()
                    .map(|&(b, p)| b as u128 * (lcm / p as u128))
                    .sum::<u128>()
                    + b as u128 * (lcm / p as u128);
                let fits = sum * share.period_us as u128 <= share.budget_us as u128 * lcm;
                match u.admit(share, b, p) {
                    Ok(v) => {
                        assert!(fits, "admitted past the share");
                        u = v;
                        held.push((b, p));
                    }
                    Err(Refused::PastShare) => assert!(!fits, "refused a fit"),
                    Err(Refused::TooFine) => panic!("small periods are never too fine"),
                }
            }
            assert!(u.within(share));
            assert_eq!(u.count() as usize, held.len());
        }
    }
}
