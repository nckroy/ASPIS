// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! A batch never passes its units, and no source with work starves: each
//! gets at least a third of a batch, whatever the others hold.

use ksched::BATCH_UNITS;
use ksched::batch::{Batcher, Sources};

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
