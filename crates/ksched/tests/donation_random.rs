// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Seeded random runs of every action the spec enables, with the
//! invariants checked after each, half of them with C14's queued sends and
//! faults. 10^4 runs per change at most; nightly, `KSCHED_RUNS_SCALE` times
//! as many (`common::runs`).

mod common;

use common::Lcg;
use common::actions::{self, Flags};
use common::store::Host;

const ALL: Flags = Flags {
    destroy: true,
    set_tep: true,
    suspend: true,
    refine: false,
    walks: true,
    queue: false,
};

fn run(seed: u64, nt: usize, nr: usize, ns: usize, steps: usize) {
    let flags = Flags {
        queue: seed % 2 == 1,
        ..ALL
    };
    let mut rng = Lcg(seed);
    let tep: Vec<usize> = (1..=nt).filter(|_| rng.chance(60)).collect();
    let mut h = Host::init(nt, nr, ns, &tep);
    for _ in 0..steps {
        let Some(op) = actions::pick(&mut h, &mut rng, flags) else {
            break;
        };
        actions::apply(&mut h, op);
        h.check();
    }
    // Every walk ends.
    h.drain();
    h.check();
    assert!(h.work.is_empty());
    assert_eq!(h.root, 0, "a walk left in the tree");
}

#[test]
fn small_universes() {
    for seed in 0..common::runs(6_000) {
        run(seed, 4, 3, 1, 60);
    }
}

#[test]
fn larger_universes() {
    for seed in 0..common::runs(3_000) / 3 {
        run(1_000_000 + seed, 8, 7, 3, 150);
    }
}

#[test]
fn long_chains() {
    // Many passive servers on one context: deep chains, many walks.
    for seed in 0..common::runs(300) / 3 {
        run(2_000_000 + seed, 24, 23, 1, 400);
    }
}
