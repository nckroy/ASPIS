// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! A long chain followed in bounded batches ends in the same state as one
//! followed at once (kernel specification, "Model checking"): the same
//! seeded operations run twice, once with every walk drained right after
//! the operation that queued it, once with walk steps interleaved at
//! random, and the states are compared once the walks end. As in the
//! spec's refinement model, the operations that would interfere with a
//! pending walk aren't chosen on its objects. Half the runs queue sends and
//! faults (C14's `WithQueue`).

mod common;

use common::Lcg;
use common::actions::{self, Flags, Op};
use common::store::{Host, project};

const BATCHED: Flags = Flags {
    destroy: true,
    set_tep: true,
    suspend: true,
    refine: true,
    walks: true,
    queue: false,
};

#[test]
fn batched_equals_at_once() {
    for seed in 0..common::runs(2_000) {
        let flags = Flags {
            queue: seed % 2 == 1,
            ..BATCHED
        };
        let mut rng = Lcg(seed);
        let (nt, nr) = (6, 5);
        let tep: Vec<usize> = (1..=nt).filter(|_| rng.chance(60)).collect();
        let mut batched = Host::init(nt, nr, 2, &tep);
        let mut at_once = Host::init(nt, nr, 2, &tep);
        for _ in 0..100 {
            let Some(op) = actions::pick(&mut batched, &mut rng, flags) else {
                break;
            };
            actions::apply(&mut batched, op);
            batched.check();
            if let Op::WalkStep(_) = op {
                continue;
            }
            actions::apply(&mut at_once, op);
            at_once.drain();
            at_once.check();
            // Once the batched side's walks end, the two agree.
            let mut finished = clone(&batched);
            finished.drain();
            assert_eq!(
                project(&mut finished),
                project(&mut at_once),
                "seed {seed}, after {op:?}"
            );
        }
    }
}

fn clone(h: &Host) -> Host {
    Host {
        threads: h.threads.clone(),
        replies: h.replies.clone(),
        nodes: h.nodes.clone(),
        scs: h.scs.clone(),
        talive: h.talive.clone(),
        ralive: h.ralive.clone(),
        scalive: h.scalive.clone(),
        root: h.root,
        seq: h.seq,
        work: h.work.clone(),
        faults: vec![],
        withdrawn: vec![],
        other_canceled: vec![],
        wait_costs: h.wait_costs.clone(),

        steps: vec![],
    }
}
