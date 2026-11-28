// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Seeded random runs of every action the endpoint and eventcount specs
//! enable, in universes larger than the traces', with every invariant
//! checked after each step: donation's, the endpoints' and the
//! eventcounts'. A few thousand runs per change; nightly,
//! `KSCHED_RUNS_SCALE` times as many (`common::runs`), as for `ksched`.

mod common;

use common::Lcg;
use common::{ec_actions, ep_actions};

fn endpoint_run(seed: u64, k: ep_actions::Consts, steps: usize) {
    let mut rng = Lcg(seed);
    let mut w = ep_actions::World::init(k);
    for _ in 0..steps {
        let Some(op) = w.pick(&mut rng) else {
            break;
        };
        w.apply(op);
        w.h.check();
    }
}

fn eventcount_run(seed: u64, k: ec_actions::Consts, steps: usize) {
    let mut rng = Lcg(seed);
    let mut w = ec_actions::World::init(k, seed);
    for _ in 0..steps {
        let Some(op) = w.pick(&mut rng) else {
            break;
        };
        w.apply(op);
        w.check();
    }
    // Every pending wake is done in the end, and the work list empties.
    w.h.run_work();
    w.check();
    assert!(w.h.work.is_empty());
}

#[test]
fn endpoints() {
    let k = ep_actions::Consts {
        nt: 6,
        nr: 4,
        prios: vec![1, 2, 3],
        nb: 3,
        with_prio: true,
        with_badge: true,
        with_destroy: true,
    };
    for seed in 0..common::runs(2_000) {
        endpoint_run(seed, k.clone(), 120);
    }
}

#[test]
fn endpoints_without_destruction() {
    // Long runs where the endpoint stays up, so queues grow long.
    let k = ep_actions::Consts {
        nt: 12,
        nr: 6,
        prios: vec![1, 2, 3, 4],
        nb: 4,
        with_prio: true,
        with_badge: false,
        with_destroy: false,
    };
    for seed in 0..common::runs(300) {
        endpoint_run(1_000_000 + seed, k.clone(), 400);
    }
}

#[test]
fn eventcounts() {
    let k = ec_actions::Consts {
        nt: 5,
        ne: 3,
        nw: 2,
        ni: 3,
        max: 4,
        with_sets: true,
        with_bound: true,
        with_destroy: true,
        window: None,
    };
    for seed in 0..common::runs(2_000) {
        eventcount_run(2_000_000 + seed, k, 150);
    }
}

#[test]
fn eventcounts_far_from_the_maximum() {
    // Many waiters on few eventcounts, with room to advance.
    let k = ec_actions::Consts {
        nt: 10,
        ne: 2,
        nw: 3,
        ni: 7,
        max: 40,
        with_sets: true,
        with_bound: true,
        with_destroy: false,
        window: None,
    };
    for seed in 0..common::runs(300) {
        eventcount_run(3_000_000 + seed, k, 400);
    }
}
