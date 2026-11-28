// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! A batch never passes its units, and no source with work starves: each
//! gets at least a third of a batch, whatever the others hold, while units
//! cost one; and with C14's costlier units, each progresses at least once
//! in every few batches.

use ksched::BATCH_UNITS;
use ksched::batch::{Batcher, MAX_SOURCES, MAX_UNIT_COST, Sources};

/// Three sources with `left` units each; `refill` adds units to source 0
/// after every batch, like refills coming due at every tick.
struct Work {
    left: [u64; 3],
    done: [u64; 3],
}

impl Sources for Work {
    fn count(&self) -> usize {
        3
    }
    fn has_work(&mut self, i: usize) -> bool {
        self.left[i] > 0
    }
    fn unit(&mut self, i: usize) {
        self.left[i] -= 1;
        self.done[i] += 1;
    }
}

#[test]
fn bounded_and_fair() {
    let mut b = Batcher::new();
    let mut w = Work {
        left: [u64::MAX / 2, 1_000, 1_000],
        done: [0; 3],
    };
    for n in 1..=10 {
        let r = b.run(&mut w, BATCH_UNITS);
        assert_eq!(r.units, BATCH_UNITS);
        assert!(r.more);
        for i in 0..3 {
            assert!(r.per_source[i] >= BATCH_UNITS / 3, "{r:?}");
        }
        assert!(w.done[1] >= 33 * n && w.done[2] >= 33 * n);
    }
}

#[test]
fn a_dry_source_passes_its_units_on() {
    let mut b = Batcher::new();
    let mut w = Work {
        left: [0, 0, 250],
        done: [0; 3],
    };
    let r = b.run(&mut w, BATCH_UNITS);
    assert_eq!(r.per_source, [0, 0, 100, 0]);
    assert!(r.more);
    b.run(&mut w, BATCH_UNITS);
    let r = b.run(&mut w, BATCH_UNITS);
    assert_eq!(r.units, 50);
    assert!(!r.more);
    let r = b.run(&mut w, BATCH_UNITS);
    assert_eq!(r.units, 0);
}

/// However the work is spread, a source's unit waits at most
/// `ceil(units ahead / 33)` batches.
#[test]
fn waiting_is_bounded() {
    for start in [[5u64, 300, 7], [1_000, 1, 1_000], [0, 99, 1]] {
        let mut b = Batcher::new();
        let mut w = Work {
            left: start,
            done: [0; 3],
        };
        let mut batches = 0;
        while w.left.iter().any(|&x| x > 0) {
            let before = w.left;
            b.run(&mut w, BATCH_UNITS);
            batches += 1;
            for i in 0..3 {
                if before[i] > 0 {
                    assert!(w.done[i] as u32 >= (BATCH_UNITS / 3).min(start[i] as u32));
                }
            }
        }
        let total: u64 = start.iter().sum();
        assert_eq!(batches, total.div_ceil(BATCH_UNITS as u64));
    }
}

/// Sources whose units each cost what a seeded generator says, up to
/// `MAX_UNIT_COST`, as waking wait-set waiters does (C14; K24).
struct Costly {
    left: Vec<u64>,
    done: Vec<u64>,
    costs: Vec<Vec<u32>>,
    /// The cost of the unit the last `cost` call reported, per source.
    told: Vec<Option<u32>>,
    ran_units: u32,
}

impl Costly {
    fn new(costs: Vec<Vec<u32>>) -> Costly {
        let n = costs.len();
        Costly {
            left: costs.iter().map(|c| c.len() as u64).collect(),
            done: vec![0; n],
            costs,
            told: vec![None; n],
            ran_units: 0,
        }
    }
}

impl Sources for Costly {
    fn count(&self) -> usize {
        self.costs.len()
    }
    fn has_work(&mut self, i: usize) -> bool {
        self.left[i] > 0
    }
    fn cost(&mut self, i: usize) -> u32 {
        let c = self.costs[i][self.done[i] as usize];
        self.told[i] = Some(c);
        c
    }
    fn unit(&mut self, i: usize) {
        // A unit runs only after its cost was asked for.
        let c = self.told[i].take().expect("a unit ran without its cost");
        assert_eq!(c, self.costs[i][self.done[i] as usize]);
        self.ran_units += c;
        self.left[i] -= 1;
        self.done[i] += 1;
    }
}

#[test]
fn costs_never_exceed_batch() {
    let mut seed = 0x5eed_u64;
    let mut rnd = |n: u32| {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((seed >> 33) % n as u64) as u32
    };
    for _ in 0..200 {
        let costs: Vec<Vec<u32>> = (0..3)
            .map(|_| (0..rnd(80)).map(|_| 1 + rnd(MAX_UNIT_COST)).collect())
            .collect();
        let total: u64 = costs.iter().flatten().map(|&c| c as u64).sum();
        let mut w = Costly::new(costs);
        let mut b = Batcher::new();
        let mut sum = 0u64;
        let mut batches = 0;
        loop {
            let before = w.ran_units;
            let r = b.run(&mut w, BATCH_UNITS);
            assert!(r.units <= BATCH_UNITS, "{r:?}");
            assert_eq!(r.units, w.ran_units - before, "per-batch units counted");
            assert_eq!(r.per_source.iter().sum::<u32>(), r.units);
            sum += r.units as u64;
            batches += 1;
            if !r.more {
                break;
            }
            assert!(r.units > 0, "a batch with work left did nothing");
            assert!(batches < 100_000);
        }
        assert_eq!(sum, total);
        assert!(w.left.iter().all(|&l| l == 0));
    }
}

#[test]
fn every_source_progresses_with_max_cost_units() {
    // Every unit of every source costs the most a unit can: the batch's
    // first source always runs one, and the first source moves on each
    // batch, so each source with work runs within MAX_SOURCES batches.
    for n in 1..=MAX_SOURCES {
        let costs = vec![vec![MAX_UNIT_COST; 50]; n];
        let mut w = Costly::new(costs);
        let mut b = Batcher::new();
        let mut last = vec![0usize; n];
        for batch in 1..=200 {
            let before = w.done.clone();
            let r = b.run(&mut w, BATCH_UNITS);
            assert!(r.units <= BATCH_UNITS && r.units >= MAX_UNIT_COST);
            for i in 0..n {
                if w.done[i] > before[i] {
                    last[i] = batch;
                }
                if w.left[i] > 0 || w.done[i] > before[i] {
                    assert!(
                        batch - last[i] < MAX_SOURCES,
                        "source {i} of {n} waited from batch {} to {batch}",
                        last[i]
                    );
                }
            }
            if !r.more {
                break;
            }
        }
        assert!(w.left.iter().all(|&l| l == 0));
    }
    // Cheap units fill what a costly one leaves: a source of 61-unit
    // units and one of 1-unit units share each batch.
    let mut w = Costly::new(vec![vec![MAX_UNIT_COST; 10], vec![1; 1000]]);
    let mut b = Batcher::new();
    let r = b.run(&mut w, BATCH_UNITS);
    assert_eq!(r.units, BATCH_UNITS);
    assert_eq!(
        r.per_source[..2],
        [MAX_UNIT_COST, BATCH_UNITS - MAX_UNIT_COST]
    );
}
