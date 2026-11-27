// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The `idl-` targets' limits hold on their seeds ("The gate for each
//! target", item 1; fuzz/README.md, "Passing the gate", step 2). This
//! test build (opt-level 1) is faster than the fuzz build, which adds
//! debug assertions, overflow checks and coverage instrumentation: on
//! `idl-front-end`'s costliest seed the fuzz binary took about twice as
//! long. So each time here is multiplied by [`FUZZ_BUILD`] first. The
//! README sets a timeout so the slowest seed takes under a quarter of it
//! on the machine that measures; this test holds the slowest seed to
//! half, so a CI runner up to twice as slow still passes. The peak
//! memory stays under half the bound. It prints each target's slowest
//! three seeds and peak, as `fuzz measure` does. `fuzz replay` runs the
//! same seeds in the fuzz binary, under the timeout itself.
//!
//! `idl-front-end`'s costliest seed is `dense-minors`
//! (`idl_targets::dense_minors_file`): the largest file of its kind that
//! checks, at the most minors C07's entry visits, 19.
//!
//! It is its own test binary, with one test, so no other test's
//! allocations reach the peak it measures.

mod common;

use std::time::Instant;

use fuzz_gate::{TARGETS, idl_targets};

/// How many times longer the fuzz build takes than this test build:
/// measured about 2 on `idl-front-end`'s `dense-minors`.
const FUZZ_BUILD: f64 = 2.0;

/// Counts allocations, so the peak can be measured.
#[global_allocator]
static ALLOC: fuzz_alloc::Bounded = fuzz_alloc::Bounded::unlimited();

#[test]
fn idl_targets_stay_within_their_bounds() {
    common::on_big_stack(|| {
        for t in TARGETS.iter().filter(|t| t.name.starts_with("idl-")) {
            let seeds = common::all_seeds(t);
            // The first run loads the embedded interfaces and grammars,
            // once a process, as libFuzzer's first input does.
            (t.run)(&seeds[0].1);
            let mut times = Vec::new();
            let mut peak = 0usize;
            for (name, bytes) in &seeds {
                fuzz_alloc::reset_peak();
                let base = fuzz_alloc::live();
                let start = Instant::now();
                (t.run)(bytes);
                let secs = start.elapsed().as_secs_f64();
                peak = peak.max(fuzz_alloc::peak().saturating_sub(base));
                times.push((secs, name.as_str()));
            }
            times.sort_by(|a, b| b.0.total_cmp(&a.0));
            let slowest: Vec<String> = times
                .iter()
                .take(3)
                .map(|(s, n)| format!("{n} {:.1} ms", s * 1e3))
                .collect();
            eprintln!(
                "{}: {} seeds; slowest {}; peak {:.1} MiB",
                t.name,
                seeds.len(),
                slowest.join(", "),
                peak as f64 / f64::from(1u32 << 20)
            );
            assert!(
                times[0].0 * FUZZ_BUILD < f64::from(t.timeout_s) / 2.0,
                "{}: {} took {:.0} ms, which in the fuzz build is over half the {} s timeout",
                t.name,
                times[0].1,
                times[0].0 * 1e3,
                t.timeout_s
            );
            assert!(
                peak < (t.malloc_limit_mb as usize) << 19,
                "{}: a peak of {peak} bytes, over half of {} MiB",
                t.name,
                t.malloc_limit_mb
            );
        }
        let file = idl_targets::dense_minors_file(idl_targets::DENSE_MINORS);
        assert_eq!(idl_targets::front_end_kinds(&file), ["ok"]);
        let limits = idl::Limits::default();
        let c = idl::check(&file, &mut |_: &_| None, &limits).unwrap();
        assert_eq!(idl::fuzz::minors(&c).len(), 19);
        // Each struct adds about 6 KiB to the canonical form, so three
        // more put it over the limit: the seed is near the largest file
        // of its kind that checks.
        let form = idl::generate::canonical(&c, c.unit().version.minor).len();
        assert!(
            form <= limits.source && form + (18 << 10) > limits.source,
            "{form}"
        );
    });
}
