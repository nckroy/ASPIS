// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Traces for TLC (kernel specification, "Model checking"; trace
//! validation, Cirstea and others, arXiv 2404.16075): seeded runs of
//! kipc's endpoint module, each state projected onto
//! `specs/IpcEndpoint.tla`'s record. With `KIPC_TRACE_OUT_EP` set, they are
//! written there as the TLA+ module `IpcEndpointTraces`, which
//! `specs/IpcEndpointTrace.tla` checks step by step against the spec's
//! `Next`; `cargo xtask tlc` does both. Without it, the runs only check
//! the invariants.
//!
//! The universe is the trace model's constants
//! (specs/IpcEndpointTrace.cfg): four threads, three reply objects, two
//! priorities, two badges, every action enabled.

mod common;

use common::ep_actions::{Consts, World};
use common::{Lcg, trace_shape, write_traces};

fn consts() -> Consts {
    Consts {
        nt: 4,
        nr: 3,
        prios: vec![1, 2],
        nb: 2,
        with_prio: true,
        with_badge: true,
        with_destroy: true,
    }
}

#[test]
fn write_endpoint_traces() {
    let (count, steps) = trace_shape();
    let mut out = vec![];
    for seed in 0..count {
        let mut rng = Lcg(0xe9 + seed);
        let mut w = World::init(consts());
        let mut trace = vec![w.project()];
        for _ in 0..steps {
            let Some(op) = w.pick(&mut rng) else {
                break;
            };
            w.apply(op);
            w.h.check();
            trace.push(w.project());
        }
        out.push(trace);
    }
    write_traces(
        "KIPC_TRACE_OUT_EP",
        "IpcEndpointTraces",
        "crates/kipc/tests/endpoint_traces.rs",
        &out,
    );
}
