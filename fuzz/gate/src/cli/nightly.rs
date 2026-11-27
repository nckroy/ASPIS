// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `nightly`: every target for a fixed time on the merged, cached corpus
//! (ADR 0068, rule 8; docs/design/call-language.md, "Nightly" and "The
//! harness").
//!
//! It builds and replays, then runs each target in turn, and after each
//! run merges the target's corpus (`-merge=1` into a fresh directory,
//! which then replaces it), so the cache the nightly saves stays small.
//! It keeps going after a finding, and fails at the end, so one target's
//! finding doesn't cost the others their night. Then it reports
//! coverage and the run records.
//!
//! `--budget s` caps the fuzzing time of all the targets together: each
//! gets `--time` seconds or its share of the budget, whichever is less,
//! so a new target shortens the others' runs instead of pushing the job
//! past its time limit. `--shard i/n` runs every n-th target from the
//! i-th: the nightly job is a matrix of two shards, since one job's
//! share fell well under `--time` at 11 targets.

use std::{fs, process::Command};

use fuzz_gate::{Target, harness};

use crate::{
    binary,
    cli::{
        campaign::{self, parse_opts},
        coverage,
    },
    fail, fuzz_build, replay_targets, root, shard_targets,
};

/// Merges a target's corpus into a fresh directory, keeping only inputs
/// that add coverage, and swaps it in.
fn merge(t: &Target) -> bool {
    let corpus = fuzz_build().join("corpus").join(t.name);
    let fresh = fuzz_build().join("corpus.new").join(t.name);
    if fresh.exists() {
        fs::remove_dir_all(&fresh).unwrap();
    }
    fs::create_dir_all(&fresh).unwrap();
    let before = fs::read_dir(&corpus).map(|r| r.count()).unwrap_or(0);
    let artifacts = fuzz_build().join("artifacts").join(t.name);
    let ok = Command::new(binary(t.name))
        .current_dir(root())
        .arg("-merge=1")
        .args(harness::libfuzzer_flags(t))
        .arg(format!("-artifact_prefix={}/", artifacts.display()))
        .arg(&fresh)
        .arg(&corpus)
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!(
            "xtask fuzz: merge {}: failed; the corpus is kept as it was",
            t.name
        );
        return false;
    }
    fs::remove_dir_all(&corpus).unwrap();
    fs::rename(&fresh, &corpus).unwrap();
    let after = fs::read_dir(&corpus).map(|r| r.count()).unwrap_or(0);
    eprintln!("xtask fuzz: merge {}: {before} inputs to {after}", t.name);
    true
}

/// `nightly [--time s] [--budget s] [--jobs n] [--seed s] [--shard i/n]`.
pub fn nightly(args: &[String]) {
    const USAGE: &str = "usage: cargo xtask fuzz nightly [--time s] [--budget s] [--jobs n] [--seed s] [--shard i/n]";
    let mut spec = None;
    let mut budget = None;
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--shard" => spec = it.next().cloned(),
            "--budget" => {
                budget = Some(
                    it.next()
                        .and_then(|n| n.parse::<u32>().ok())
                        .unwrap_or_else(|| fail(USAGE)),
                )
            }
            _ => rest.push(a.clone()),
        }
    }
    let (mut opts, pos) = parse_opts(&rest, 600);
    if !pos.is_empty() {
        fail(USAGE);
    }
    let targets = shard_targets(spec.as_deref());
    if let Some(b) = budget {
        opts.time = harness::time_box(targets.len(), opts.time, b);
    }
    eprintln!(
        "xtask fuzz: nightly: {} for {} s each, {} worker{}, -seed={}",
        targets
            .iter()
            .map(|t| t.name)
            .collect::<Vec<_>>()
            .join(", "),
        opts.time,
        opts.jobs,
        if opts.jobs == 1 { "" } else { "s" },
        opts.seed
    );

    crate::build();
    let mut failed: Vec<String> = replay_targets(&targets, &[], 1)
        .into_iter()
        .map(|t| format!("{t} (replay)"))
        .collect();
    for t in &targets {
        if failed
            .iter()
            .any(|f| f.starts_with(&format!("{} ", t.name)))
        {
            continue;
        }
        if !campaign::run_target(t, &opts).passed {
            failed.push(format!("{} (finding)", t.name));
        }
        if !merge(t) {
            failed.push(format!("{} (merge)", t.name));
        }
    }
    failed.extend(
        coverage::coverage_of(&targets)
            .into_iter()
            .map(|t| format!("{t} (coverage)")),
    );
    let names: Vec<String> = targets.iter().map(|t| t.name.to_string()).collect();
    campaign::report(&names);
    if !failed.is_empty() {
        fail(format!("nightly: {}", failed.join(", ")));
    }
    eprintln!("xtask fuzz: nightly: no finding");
}
