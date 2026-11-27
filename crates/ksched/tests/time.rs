// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Conversions between microseconds and counts round in the direction that
//! keeps the guarantee, and never overflow.

use ksched::time::{
    self, BATCH_GAP_US, Clock, Invalid, MAX_PERIOD_US, MIN_BUDGET_US, NEVER, Wakeups,
};

const FREQS: [u64; 5] = [1_000_000, 19_200_000, 54_000_000, 62_500_000, 1_000_000_000];

#[test]
fn no_clock_at_zero_hertz() {
    assert!(Clock::new(0).is_none());
}

#[test]
fn rounding_directions() {
    for f in FREQS {
        let c = Clock::new(f).unwrap();
        for us in [0, 1, 3, 7, 10, 333, 1_000, 999_999, MAX_PERIOD_US] {
            let lo = c.counts_floor(us);
            let hi = c.counts_ceil(us);
            assert!(lo <= hi && hi - lo <= 1);
            // Exact in u128.
            let exact = us as u128 * f as u128;
            assert!(lo as u128 * 1_000_000 <= exact);
            assert!(hi as u128 * 1_000_000 >= exact);
            assert!(c.us_ceil(lo) <= us);
        }
    }
    // QEMU's 62.5 MHz: 1 µs is 62.5 counts.
    let q = Clock::new(62_500_000).unwrap();
    assert_eq!(q.counts_floor(1), 62);
    assert_eq!(q.counts_ceil(1), 63);
    assert_eq!(q.counts_floor(2), 125);
}

#[test]
fn budgets_round_down_and_periods_up() {
    let q = Clock::new(62_500_000).unwrap();
    let b = q.budget(1);
    assert_eq!(b, 62);
    assert_eq!(q.period(1, b), 63);
    // A budget is never 0 counts, and a period never below its budget.
    let slow = Clock::new(1).unwrap();
    assert_eq!(slow.budget(10), 1);
    assert_eq!(slow.period(10, 1), 1);
}

#[test]
fn extremes_saturate() {
    let c = Clock::new(u64::MAX).unwrap();
    assert_eq!(c.counts_floor(u64::MAX), u64::MAX);
    assert_eq!(c.counts_ceil(u64::MAX), u64::MAX);
    let one = Clock::new(1).unwrap();
    assert_eq!(one.us_floor(u64::MAX), u64::MAX);
    assert_eq!(one.counts_floor(u64::MAX), u64::MAX / 1_000_000);
}

#[test]
fn limits() {
    assert_eq!(time::check_limits(MIN_BUDGET_US, MIN_BUDGET_US), Ok(()));
    assert_eq!(
        time::check_limits(MIN_BUDGET_US - 1, 1000),
        Err(Invalid::BudgetTooShort)
    );
    assert_eq!(time::check_limits(20, 19), Err(Invalid::BudgetPastPeriod));
    assert_eq!(time::check_limits(10, MAX_PERIOD_US), Ok(()));
    assert_eq!(
        time::check_limits(10, MAX_PERIOD_US + 1),
        Err(Invalid::PeriodTooLong)
    );
}

#[test]
fn compare_value_is_the_earliest() {
    let c = Clock::new(62_500_000).unwrap();
    assert_eq!(time::compare_value(c, 5, Wakeups::default()), NEVER);
    let w = Wakeups {
        budget_end: Some(900),
        release: Some(700),
        deadline: Some(800),
        batch_pending: false,
    };
    assert_eq!(time::compare_value(c, 5, w), 700);
    // A passed time fires at once: it is returned as is.
    let w = Wakeups {
        deadline: Some(3),
        ..w
    };
    assert_eq!(time::compare_value(c, 5, w), 3);
    // Batch work left: at most the batch gap ahead.
    let w = Wakeups {
        batch_pending: true,
        ..Wakeups::default()
    };
    assert_eq!(
        time::compare_value(c, 1000, w),
        1000 + c.counts_ceil(BATCH_GAP_US)
    );
    let w = Wakeups {
        batch_pending: true,
        ..Wakeups::default()
    };
    assert_eq!(time::compare_value(c, u64::MAX - 1, w), u64::MAX);
}
