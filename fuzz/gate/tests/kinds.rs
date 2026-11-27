// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Every error kind of every target's parser is reached by some seed
//! ("The gate for each target", item 4), and the kinds the seeds reach
//! are the table's.

mod common;

use std::collections::BTreeSet;

use fuzz_gate::TARGETS;

#[test]
fn every_kind_is_reached() {
    let handles: Vec<_> = TARGETS
        .iter()
        .map(|t| {
            std::thread::Builder::new()
                .stack_size(16 << 20)
                .spawn(move || {
                    let mut reached = BTreeSet::new();
                    for (name, bytes) in common::all_seeds(t) {
                        for k in (t.kinds_of)(&bytes) {
                            assert!(t.kinds.contains(&k), "{}: {name} reaches {k}", t.name);
                            reached.insert(k);
                        }
                    }
                    let missing: Vec<_> =
                        t.kinds.iter().filter(|k| !reached.contains(*k)).collect();
                    (t.name, reached.len(), t.kinds.len(), missing)
                })
                .unwrap()
        })
        .collect();
    let mut missing = Vec::new();
    for h in handles {
        let (name, reached, total, m) = h.join().unwrap();
        eprintln!("{name}: {reached}/{total} kinds reached");
        missing.extend(m.iter().map(|k| format!("{name}: {k}")));
    }
    assert!(
        missing.is_empty(),
        "kinds no seed reaches (add a seed to fuzz/seeds/<target>/):\n{}",
        missing.join("\n")
    );
}

#[test]
fn kinds_are_unique() {
    for t in TARGETS {
        let set: BTreeSet<_> = t.kinds.iter().collect();
        assert_eq!(set.len(), t.kinds.len(), "{}", t.name);
    }
}
