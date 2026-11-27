// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The engine-neutral replay (ADR 0068, rule 7): every target's committed
//! seeds, generated seeds and regressions, through the same entry
//! functions the fuzz targets call, under plain `cargo test`. So a
//! regression fails locally without libFuzzer.

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};

use fuzz_gate::TARGETS;

#[test]
fn every_seed_and_regression_passes() {
    // One thread per target, each with room for the matcher's depth.
    let handles: Vec<_> = TARGETS
        .iter()
        .map(|t| {
            std::thread::Builder::new()
                .stack_size(16 << 20)
                .spawn(move || {
                    let mut failed = Vec::new();
                    let seeds = common::all_seeds(t);
                    for (name, bytes) in &seeds {
                        if catch_unwind(AssertUnwindSafe(|| (t.run)(bytes))).is_err() {
                            failed.push(format!("{}: {name}", t.name));
                        }
                    }
                    (t.name, seeds.len(), failed)
                })
                .unwrap()
        })
        .collect();
    let mut failed = Vec::new();
    for h in handles {
        let (name, n, f) = h.join().unwrap();
        eprintln!("{name}: {n} inputs replayed");
        failed.extend(f);
    }
    assert!(
        failed.is_empty(),
        "inputs that fail:\n{}",
        failed.join("\n")
    );
}
