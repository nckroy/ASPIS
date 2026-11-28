// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Traces for TLC, as `endpoint_traces.rs`'s: seeded runs of kipc's
//! eventcount module, each state projected onto `specs/Eventcount.tla`'s
//! record. With `KIPC_TRACE_OUT_EC` set, they are written there as the
//! TLA+ module `EventcountTraces`, which `specs/EventcountTrace.tla`
//! checks step by step.
//!
//! The universe is the trace model's constants
//! (specs/EventcountTrace.cfg): four threads, two eventcounts, two wait
//! sets of two entries each, a maximum of 12, every action enabled. The
//! counts start 12 below 2^64 - 1. Waits and entries take targets from the
//! count to two past it, so waiters gather just ahead of the count, and
//! an advance reaches several of them at once: a preempted advance or an
//! interrupt's leaves several reached waiters on the work list, for cancels
//! and deadlines to meet between its units. Every fourth trace favors
//! advances, so it reaches the real maximum, and refused advances and
//! waits at the maximum are checked too. Trace validation evaluates only
//! the trace's states, so a larger maximum costs TLC almost nothing.
//!
//! The test counts the steps that matter and fails if a change to the
//! harness loses them.

mod common;

use common::ec_actions::{Consts, Op, World};
use common::{Lcg, trace_shape, write_traces};

const CONSTS: Consts = Consts {
    nt: 4,
    ne: 2,
    nw: 2,
    ni: 2,
    max: 12,
    with_sets: true,
    with_bound: true,
    with_destroy: true,
    window: Some(2),
};

/// What the traces exercised, over every trace.
#[derive(Debug, Default)]
struct Seen {
    /// States with an eventcount pending and two or more reached waiters
    /// still linked: a work list with several wakes left.
    pending_many: u64,
    /// Advances, by system call or interrupt, after which two or more
    /// reached waiters are linked or were woken.
    advances_many: u64,
    /// Traces in which an eventcount reached its real maximum.
    saturated: u64,
}

#[test]
fn write_eventcount_traces() {
    let (count, steps) = trace_shape();
    let mut out = vec![];
    let mut seen = Seen::default();
    for seed in 0..count {
        let mut rng = Lcg(0xec + seed);
        let mut w = World::init(CONSTS, seed);
        let advance = if seed % 4 == 0 { 35 } else { 0 };
        let mut trace = vec![w.project()];
        let mut saturated = false;
        for _ in 0..steps {
            let Some(op) = w.pick_with(&mut rng, advance) else {
                break;
            };
            let before = (1..=CONSTS.ne).map(|e| linked(&w, e)).collect::<Vec<_>>();
            w.apply(op);
            w.check();
            if let Op::Advance(e) | Op::IrqAdvance(e) = op {
                // Reached now, linked still or woken by the advance itself.
                let woken = before[e - 1].saturating_sub(linked(&w, e));
                if w.reached_linked(e) + woken >= 2 {
                    seen.advances_many += 1;
                }
            }
            if (1..=CONSTS.ne).any(|e| w.h.ecs[e].pending && w.reached_linked(e) >= 2) {
                seen.pending_many += 1;
            }
            saturated |= (1..=CONSTS.ne).any(|e| w.at_max(e));
            trace.push(w.project());
        }
        seen.saturated += u64::from(saturated);
        out.push(trace);
    }
    eprintln!("eventcount traces: {seen:?}");
    // The seeds are fixed, so the counts are too. The per-change shape,
    // 100 traces of 80 steps, gave 201, 91 and 26 on 2026-11-27, where
    // C14's first harness, with targets 1..=3, gave 29 pending work lists
    // and 17 advances. Each count only grows with more traces, which add
    // seeds, and with longer ones, which extend each seed's trace, so a run
    // with fewer traces or shorter ones, from KIPC_TRACES or
    // KIPC_TRACE_STEPS, isn't held to them; nightly's longer traces pass
    // them.
    if count >= 100 && steps >= 80 {
        assert!(
            seen.pending_many >= 120,
            "too few pending work lists: {seen:?}"
        );
        assert!(
            seen.advances_many >= 60,
            "too few advances reaching several: {seen:?}"
        );
        assert!(
            seen.saturated >= 10,
            "too few traces at the maximum: {seen:?}"
        );
    }
    write_traces(
        "KIPC_TRACE_OUT_EC",
        "EventcountTraces",
        "crates/kipc/tests/eventcount_traces.rs",
        &out,
    );
}

/// How many nodes are linked on eventcount `e`, reached or not.
fn linked(w: &World, e: usize) -> usize {
    w.h.nodes.iter().filter(|n| n.ec == e as u64).count()
}
