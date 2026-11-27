// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The target table agrees with the files: the bins, the target files,
//! the seed and regression directories, the embedded grammars, the
//! crates each target covers, and the product lock.

mod common;

use std::collections::BTreeSet;

use common::{root, tracked};
use fuzz_gate::{PROBES, TARGETS, harness, repo};

#[test]
fn names_are_unique_and_plain() {
    let mut names = BTreeSet::new();
    for t in TARGETS {
        assert!(names.insert(t.name), "{} twice", t.name);
        assert!(
            harness::valid_name(t.name) && !t.name.contains('.'),
            "{}",
            t.name
        );
    }
    for p in PROBES {
        assert!(!names.contains(p), "{p} is a probe and a target");
    }
}

#[test]
fn bins_files_and_table_agree() {
    let manifest = std::fs::read_to_string(root().join("fuzz/Cargo.toml")).unwrap();
    let mut bins = BTreeSet::new();
    let mut in_bin = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
        } else if in_bin && let Some(v) = line.strip_prefix("name = ") {
            bins.insert(v.trim_matches('"').to_string());
        }
    }
    let files: BTreeSet<String> = tracked(&["fuzz/fuzz_targets"])
        .iter()
        .map(|p| {
            p.strip_prefix("fuzz/fuzz_targets/")
                .and_then(|f| f.strip_suffix(".rs"))
                .unwrap_or_else(|| panic!("{p} isn't a target file"))
                .to_string()
        })
        .collect();
    let table: BTreeSet<String> = TARGETS
        .iter()
        .map(|t| t.name)
        .chain(PROBES.iter().copied())
        .map(String::from)
        .collect();
    assert_eq!(bins, table, "fuzz/Cargo.toml's [[bin]]s and TARGETS");
    assert_eq!(files, table, "fuzz/fuzz_targets/ and TARGETS");
}

#[test]
fn committed_inputs_belong_to_targets() {
    for kind in ["seeds", "regressions"] {
        for p in tracked(&[&format!("fuzz/{kind}")]) {
            let rest = p.strip_prefix(&format!("fuzz/{kind}/")).unwrap();
            let (target, name) = rest
                .split_once('/')
                .unwrap_or_else(|| panic!("{p} isn't in a target's directory"));
            assert!(
                fuzz_gate::target(target).is_some(),
                "{p}: no target {target}"
            );
            assert!(
                harness::valid_name(name) && !name.contains('/'),
                "{p}: names are lowercase letters, digits, hyphens and dots"
            );
        }
    }
}

#[test]
fn every_seed_fits_max_len() {
    for t in TARGETS {
        for (name, bytes) in common::all_seeds(t) {
            assert!(
                bytes.len() <= t.max_len,
                "{}: {name} is {} octets, over max_len {}",
                t.name,
                bytes.len(),
                t.max_len
            );
        }
        for (name, _) in (t.seeds)() {
            assert!(harness::valid_name(&name), "{}: generated {name}", t.name);
        }
    }
}

#[test]
fn limits_are_sane() {
    for t in TARGETS {
        assert!(t.timeout_s >= 1, "{}", t.name);
        assert!(
            t.malloc_limit_mb >= 1 && t.malloc_limit_mb < t.rss_limit_mb,
            "{}",
            t.name
        );
        assert!(t.max_len >= 1024, "{}", t.name);
    }
}

#[test]
fn paths_exist_and_parsers_forbid_unsafe() {
    for t in TARGETS {
        for p in t.paths {
            assert!(root().join(p).exists(), "{}: {p} doesn't exist", t.name);
            // A crate a target covers parses input from across a trust
            // boundary (ADR 0068, rule 2).
            if let Some(name) = p.strip_prefix("crates/") {
                let lib = std::fs::read_to_string(root().join(p).join("src/lib.rs")).unwrap();
                assert!(
                    lib.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]"),
                    "crates/{name} doesn't forbid unsafe code"
                );
            }
        }
    }
}

#[test]
fn every_grammar_is_embedded() {
    let tracked: BTreeSet<String> = tracked(&["grammars/*.abnf", "crates/abnf/tests/data/*.abnf"])
        .into_iter()
        .collect();
    let embedded: BTreeSet<String> = repo::GRAMMARS.iter().map(|g| g.path.to_string()).collect();
    assert_eq!(embedded, tracked);
    for g in repo::GRAMMARS {
        assert_eq!(
            std::fs::read(root().join(g.path)).unwrap(),
            g.text,
            "{}",
            g.path
        );
        assert_eq!(
            std::fs::read(root().join(g.vectors_path)).unwrap(),
            g.vectors,
            "{}",
            g.vectors_path
        );
    }
}

#[test]
fn the_product_lock_holds_no_fuzz_engine() {
    let lock = std::fs::read_to_string(root().join("Cargo.lock")).unwrap();
    assert_eq!(harness::engine_crates_in(&lock), Vec::<&str>::new());
}
