// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The sporadic server, against a simulated thread that runs, blocks and
//! wakes at random: the refills always sum to the budget, stay in order
//! without overlap and within the maximum, and in every window of one
//! period the thread uses at most its budget.

mod common;

use common::Lcg;
use ksched::refill::{Charged, Invalid, MIN_REFILLS, Refill, Refills, State};

/// Runs a simulated thread for `steps` dispatches and returns the intervals
/// it ran in. Each run uses at most the head refill's amount, as the
/// kernel's timer stops it at the budget's end.
fn simulate(rng: &mut Lcg, budget: u64, period: u64, max: u32, steps: usize) -> Vec<(u64, u64)> {
    let mut st = State::default();
    let mut ring = vec![Refill::default(); 16];
    let mut r = Refills::new(&mut st, &mut ring);
    r.configure(budget, period, max, 2, 0).unwrap();
    let mut now = rng.below(period);
    let mut used = vec![];
    for _ in 0..steps {
        if !r.sufficient(now) {
            now = r.next_release(now).unwrap_or(now + 1).max(now + 1);
            continue;
        }
        let avail = r.head().amount;
        let run = (rng.below(avail) + 1).min(avail);
        let charged = r.charge(now, run, now + run);
        used.push((now, now + run));
        now += run;
        assert!(r.check(), "refills broken: {:?}", r.st);
        assert_eq!(r.sum(), budget);
        assert!(r.count() <= max.max(MIN_REFILLS));
        if charged == Charged::Ready && rng.chance(50) {
            continue;
        }
        // Block for a while, then wake.
        now += rng.below(period * 2);
        r.unblock(now);
        assert!(r.check());
    }
    used
}

/// The most time used in any window of length `period`.
fn worst_window(used: &[(u64, u64)], period: u64) -> u64 {
    let mut worst = 0;
    for &(start, _) in used {
        let (a, b) = (start, start + period);
        let sum: u64 = used
            .iter()
            .map(|&(s, e)| e.min(b).saturating_sub(s.max(a)))
            .sum();
        worst = worst.max(sum);
    }
    worst
}

#[test]
fn sliding_window_holds() {
    let mut rng = Lcg(3);
    for run in 0..common::runs(300) {
        let period = 50 + rng.below(500);
        let budget = 2 + rng.below(period - 2);
        let max = 2 + rng.below(6) as u32;
        let used = simulate(&mut rng, budget, period, max, 300);
        let w = worst_window(&used, period);
        assert!(
            w <= budget,
            "run {run}: {w} used in one period, budget {budget} of {period}, {max} refills"
        );
    }
}

#[test]
fn round_robin_refills_whole() {
    let mut st = State::default();
    let mut ring = [Refill::default(); 2];
    let mut r = Refills::new(&mut st, &mut ring);
    r.configure(100, 100, 5, 2, 0).unwrap();
    assert!(r.is_round_robin());
    assert_eq!(r.count(), 1);
    assert_eq!(r.charge(0, 60, 60), Charged::Ready);
    assert_eq!(r.head().amount, 40);
    assert_eq!(r.charge(60, 39, 99), Charged::Exhausted);
    assert_eq!(
        r.head(),
        Refill {
            time: 99,
            amount: 100
        }
    );
    assert!(r.ready(99));
}

#[test]
fn configuration_limits() {
    let mut st = State::default();
    let mut ring = [Refill::default(); 4];
    let mut r = Refills::new(&mut st, &mut ring);
    assert_eq!(r.configure(0, 10, 2, 1, 0), Err(Invalid::Budget));
    assert_eq!(r.configure(11, 10, 2, 1, 0), Err(Invalid::Budget));
    assert_eq!(r.configure(5, 10, 5, 1, 0), Err(Invalid::TooManyRefills));
    assert_eq!(r.configure(5, 10, 4, 1, 0), Ok(()));
    // Fewer than two are raised to seL4's minimum.
    assert_eq!(r.configure(5, 10, 0, 1, 0), Ok(()));
    assert_eq!(r.st.max, MIN_REFILLS);
}

#[test]
fn overruns_keep_the_sum() {
    let mut rng = Lcg(9);
    for _ in 0..common::runs(200) {
        let mut st = State::default();
        let mut ring = vec![Refill::default(); 8];
        let mut r = Refills::new(&mut st, &mut ring);
        let period = 100 + rng.below(1000);
        let budget = 10 + rng.below(period - 10);
        r.configure(budget, period, 2 + rng.below(6) as u32, 2, 0)
            .unwrap();
        let mut now = 0;
        for _ in 0..200 {
            if !r.ready(now) {
                now = r.next_release(now).unwrap();
            }
            let over = rng.below(budget * 2);
            let usage = r.head().amount + over;
            r.charge(now, usage, now + usage);
            now += usage;
            assert!(r.check(), "{:?}", r.st);
            assert_eq!(r.sum(), budget);
        }
    }
}

#[test]
fn reconfigure_keeps_the_head() {
    let mut st = State::default();
    let mut ring = [Refill::default(); 8];
    let mut r = Refills::new(&mut st, &mut ring);
    r.configure(50, 100, 4, 2, 0).unwrap();
    r.charge(0, 30, 30);
    // 20 left in the head; a new budget of 80 adds 60 a period later.
    r.reconfigure(80, 200, 4, 2, 30).unwrap();
    assert!(r.check());
    assert_eq!(r.sum(), 80);
    assert_eq!(
        r.head(),
        Refill {
            time: 30,
            amount: 20
        }
    );
    assert_eq!(
        r.get(1),
        Refill {
            time: 230,
            amount: 60
        }
    );
    // A smaller budget cuts the head.
    r.reconfigure(10, 200, 4, 2, 40).unwrap();
    assert_eq!(r.count(), 1);
    assert_eq!(
        r.head(),
        Refill {
            time: 40,
            amount: 10
        }
    );
}

#[test]
fn a_full_ring_merges_later() {
    let mut st = State::default();
    let mut ring = [Refill::default(); 2];
    let mut r = Refills::new(&mut st, &mut ring);
    r.configure(40, 100, 2, 1, 0).unwrap();
    // Three separate uses: the third can't get a slot of its own.
    r.charge(0, 10, 10);
    r.charge(20, 10, 30);
    assert!(r.check());
    r.charge(40, 10, 50);
    assert!(r.check());
    assert_eq!(r.count(), 2);
    assert_eq!(r.sum(), 40);
    // Nothing is usable earlier than one period after its use.
    for i in 1..r.count() {
        assert!(r.get(i).time >= 100);
    }
}
