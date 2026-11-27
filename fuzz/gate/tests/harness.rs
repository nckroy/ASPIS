// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The harness's pure logic: libFuzzer's status lines (as captured from
//! real runs in C71), `/usr/bin/time -p`, the targets a change selects,
//! smoke time boxes, dictionary escaping, and run records.

use fuzz_gate::{
    TARGETS, dict,
    harness::{self, RunRecord, Status},
};

/// A normal-mode run of kargs-parse, abridged.
const NORMAL: &str = "INFO: Seed: 7
#190\tINITED cov: 268 ft: 1171 corp: 172/45Kb exec/s: 0 rss: 27Mb
#131072\tpulse  cov: 268 ft: 1219 corp: 198/54Kb lim: 3257 exec/s: 65536 rss: 28Mb
#203700\tREDUCE cov: 268 ft: 1226 corp: 199/51Kb lim: 3477 exec/s: 67900 rss: 28Mb L: 122/3185 MS: 1 EraseBytes-
#203850\tDONE   cov: 268 ft: 1226 corp: 199/51Kb lim: 3477 exec/s: 50962 rss: 28Mb
Done 203850 runs in 4 second(s)
stat::number_of_executed_units: 203850
real 4.00
user 3.90
sys 0.09
";

/// A fork-mode run with two workers, abridged.
const FORK: &str = "INFO: -fork=2: fuzzing in separate process(s)
#152147: cov: 266 ft: 608 corp: 70 exec/s: 76073 oom/timeout/crash: 0/0/0 time: 2s job: 1 dft_time: 0
#810072: cov: 275 ft: 1209 corp: 253 exec/s: 82597 oom/timeout/crash: 1/2/3 time: 6s job: 3 dft_time: 0
INFO: fuzzed for 6 seconds, wrapping up soon
INFO: exiting: 0 time: 6s
real 6.12
user 10.57
sys 1.60
";

#[test]
fn status_lines() {
    assert_eq!(
        harness::last_status(NORMAL),
        Status {
            execs: 203_850,
            cov: 268,
            ft: 1226,
            corpus: 199,
            ..Status::default()
        }
    );
    assert_eq!(
        harness::last_status(FORK),
        Status {
            execs: 810_072,
            cov: 275,
            ft: 1209,
            corpus: 253,
            ooms: 1,
            timeouts: 2,
            crashes: 3,
        }
    );
    assert_eq!(harness::status_line("INFO: Seed: 7"), None);
    assert_eq!(harness::status_line("#12 no coverage here"), None);
}

#[test]
fn measured_cpu_time() {
    let (cpu, wall) = harness::time_p(NORMAL).unwrap();
    assert!((cpu - 3.99).abs() < 1e-9 && (wall - 4.0).abs() < 1e-9);
    let (cpu, wall) = harness::time_p(FORK).unwrap();
    assert!((cpu - 12.17).abs() < 1e-9 && (wall - 6.12).abs() < 1e-9);
    assert_eq!(harness::time_p("real 1.0\n"), None);
}

fn names(paths: &[&str]) -> Vec<&'static str> {
    let paths: Vec<String> = paths.iter().map(|p| p.to_string()).collect();
    harness::selected_by(TARGETS, &paths)
        .iter()
        .map(|t| t.name)
        .collect()
}

#[test]
fn a_change_selects_its_targets() {
    assert_eq!(
        names(&["crates/kargs/src/lib.rs"]),
        ["kargs-parse", "kargs-grub"]
    );
    // grammars/ also selects the ABNF targets that read every grammar.
    assert_eq!(
        names(&["grammars/kernel-args.vectors"]),
        [
            "abnf-grammar",
            "abnf-match",
            "abnf-vectors",
            "kargs-parse",
            "kargs-grub"
        ]
    );
    assert_eq!(
        names(&["grammars/constraint.abnf"]),
        [
            "abnf-grammar",
            "abnf-match",
            "abnf-vectors",
            "abnf-constraint"
        ]
    );
    // crates/abnf is the reference matcher, so it selects kargs-parse,
    // whose oracle matches against kernel-args.abnf, and the idl-
    // targets, whose oracles match against names.abnf, idl.abnf and the
    // generated grammars.
    assert_eq!(
        names(&["crates/abnf/src/matcher.rs"]),
        [
            "abnf-grammar",
            "abnf-match",
            "abnf-vectors",
            "abnf-constraint",
            "abnf-generated",
            "kargs-parse",
            "idl-names",
            "idl-front-end",
            "idl-decode",
            "idl-generated"
        ]
    );
    // C07's crates and files (docs/design/call-language.md, "Per change").
    let idl3 = ["idl-front-end", "idl-decode", "idl-generated"];
    let idl4 = ["idl-names", "idl-front-end", "idl-decode", "idl-generated"];
    assert_eq!(names(&["crates/idl-rt/src/names.rs"]), idl4);
    assert_eq!(names(&["crates/idl/src/value.rs"]), idl3);
    for p in ["crates/interfaces/build.rs", "crates/idl-fixtures/build.rs"] {
        assert_eq!(names(&[p]), ["idl-decode", "idl-generated"], "{p}");
    }
    assert_eq!(names(&["interfaces/aspis/rpc/v1.idl"]), idl3);
    assert_eq!(
        names(&["crates/idl/tests/data/interfaces/org/example/kinds/v1.2.vectors"]),
        idl3
    );
    assert_eq!(names(&["tools/idlc/src/main.rs"]), idl3);
    // The front end hashes each canonical form with aspis-crypto's SHA3-256.
    assert_eq!(names(&["crates/crypto/src/hash.rs"]), ["idl-front-end"]);
    let abnf3 = ["abnf-grammar", "abnf-match", "abnf-vectors"];
    let with = |more: &[&'static str]| -> Vec<&'static str> {
        abnf3.iter().chain(more).copied().collect()
    };
    assert_eq!(
        names(&["grammars/names.abnf"]),
        with(&["idl-names", "idl-front-end"])
    );
    assert_eq!(names(&["grammars/names.vectors"]), with(&["idl-names"]));
    assert_eq!(names(&["grammars/idl.vectors"]), with(&["idl-front-end"]));
    assert_eq!(
        names(&["grammars/json.abnf"]),
        with(&["idl-names", "idl-front-end"])
    );
    assert_eq!(names(&["grammars/core.abnf"]), with(&idl4));
    assert!(names(&["crates/idl-other/src/lib.rs"]).is_empty());
    // The oracle copies the stub's buffers.
    assert_eq!(names(&["boot/stub/src/main.rs"]), ["kargs-grub"]);
    let all: Vec<&str> = TARGETS.iter().map(|t| t.name).collect();
    assert_eq!(names(&["fuzz/gate/src/lib.rs"]), all);
    assert_eq!(names(&["fuzz/Cargo.lock"]), all);
    assert_eq!(names(&["rust-toolchain.toml"]), all);
    assert_eq!(names(&["xtask/src/fuzz.rs"]), all);
    assert!(names(&["xtask/src/main.rs"]).is_empty());
    assert_eq!(
        names(&["fuzz/seeds/abnf-constraint/x"]),
        ["abnf-constraint"]
    );
    assert_eq!(names(&["fuzz/fuzz_targets/kargs-grub.rs"]), ["kargs-grub"]);
    assert!(names(&["docs/x.md"]).is_empty());
    assert!(names(&["crates/kargs-other/src/lib.rs"]).is_empty());
    assert!(names(&["fuzz/README.md"]).is_empty());
}

#[test]
fn time_boxes() {
    assert_eq!(harness::time_box(0, 60, 600), 0);
    assert_eq!(harness::time_box(7, 60, 600), 60);
    assert_eq!(harness::time_box(10, 60, 600), 60);
    assert_eq!(harness::time_box(20, 60, 600), 30);
    for n in 1..100 {
        assert!(n as u32 * harness::time_box(n, 60, 600) <= 600.max(n as u32));
    }
}

#[test]
fn dictionary_entries() {
    assert_eq!(dict::escape(b"a=b"), "\"a=b\"");
    assert_eq!(dict::escape(b"\"\\"), "\"\\\"\\\\\"");
    assert_eq!(
        dict::escape(&[0, 0x7f, 0xff, b'\t']),
        "\"\\x00\\x7F\\xFF\\x09\""
    );
    let d = dict::render(vec![
        b"b".to_vec(),
        vec![],
        b"a".to_vec(),
        b"b".to_vec(),
        vec![b'x'; 65],
    ]);
    assert_eq!(d, "\"a\"\n\"b\"\n");
    // Every target's dictionary renders, and each but abnf-generated's
    // has entries.
    for t in TARGETS {
        let d = dict::render((t.dict)());
        assert_eq!(d.is_empty(), t.name == "abnf-generated", "{}", t.name);
        assert!(
            d.lines().all(|l| l.starts_with('"') && l.ends_with('"')),
            "{}",
            t.name
        );
    }
}

#[test]
fn run_records_round_trip() {
    let r = RunRecord {
        utc: harness::utc(1_795_000_000),
        build: "0123456789abcdef".into(),
        commit: "7e86e3e1a2b3".into(),
        dirty: true,
        rustc: "1.100.0".into(),
        cargo_fuzz: "0.13.2".into(),
        seed: 42,
        workers: 2,
        wall_s: 1800.0,
        fuzz_s: 1790.0,
        fuzz_execs: 999_000,
        cpu_s: 3590.5,
        status: Status {
            execs: 1_000_000,
            cov: 1555,
            ft: 3074,
            corpus: 242,
            ooms: 0,
            timeouts: 0,
            crashes: 0,
        },
        artifacts: 0,
        clean: true,
    };
    let line = r.to_line();
    assert_eq!(RunRecord::from_line(&line), Some(r.clone()));
    assert_eq!(
        line.split('\t').count(),
        harness::RUN_HEADER.split('\t').count()
    );
    assert!(!r.finding());
    let found = RunRecord {
        artifacts: 1,
        ..r.clone()
    };
    // A crash on an input whose artifact was already on disk writes no new
    // file: the unclean end alone makes it a finding.
    let unclean = RunRecord {
        clean: false,
        ..r.clone()
    };
    assert!(unclean.finding());
    assert_eq!(
        RunRecord::from_line(&unclean.to_line()),
        Some(unclean.clone())
    );
    // A run of another build isn't counted.
    let other = RunRecord {
        build: "fedcba9876543210".into(),
        ..r.clone()
    };
    let s = harness::summarize(
        &[r.clone(), found, unclean, other.clone(), r.clone()],
        "0123456789abcdef",
    );
    assert_eq!(s.runs, 4);
    assert_eq!(s.findings, 2);
    assert!((s.clean_cpu_s - 3590.5).abs() < 1e-9);
    assert!((s.cpu_s - 4.0 * 3590.5).abs() < 1e-9);
    assert!((s.asked_s - 4.0 * 3600.0).abs() < 1e-9);
    assert_eq!(harness::summarize(&[other], "0123456789abcdef").runs, 0);
    assert_eq!(RunRecord::from_line("too\tfew"), None);
    // An older harness's record, without a build or fuzzing time, isn't
    // read.
    let old = "2026-11-27T01:20:34Z\t7e86e3e930b6\t1\t1.100.0\t0.13.2\t5\t1\t11.1\t11.1\t11.1\t5520\t1567\t3064\t246\t0\t0\t0\t0";
    assert_eq!(RunRecord::from_line(old), None);
}

#[test]
fn utc_times() {
    assert_eq!(harness::utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(harness::utc(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(harness::utc(1_795_000_000), "2026-11-18T11:06:40Z");
}

#[test]
fn nightly_shards() {
    assert_eq!(harness::shard("1/1"), Some((1, 1)));
    assert_eq!(harness::shard("2/3"), Some((2, 3)));
    assert_eq!(harness::shard("0/3"), None);
    assert_eq!(harness::shard("4/3"), None);
    assert_eq!(harness::shard("1/0"), None);
    assert_eq!(harness::shard("x"), None);
    // At most 8 targets a shard in the nightly's 2 shards, so each
    // target's share of a shard's 4200 s budget stays at about 8 minutes
    // or more (525 s at 8; up to 7 keep the full 600 s). At 17 targets a
    // shard would hold 9 (466 s), and a third shard comes
    // (docs/design/call-language.md, "Seams for later", `--shard`).
    for i in 1..=2 {
        let n = (0..TARGETS.len())
            .filter(|&k| harness::in_shard(k, (i, 2)))
            .count();
        assert!(n <= 8, "shard {i}/2 holds {n} targets: add a third shard");
    }
    // Every target is in exactly one shard, for any count of shards.
    for n in 1..=TARGETS.len() + 1 {
        for k in 0..TARGETS.len() {
            let owners = (1..=n).filter(|&i| harness::in_shard(k, (i, n))).count();
            assert_eq!(owners, 1, "target {k}, {n} shards");
        }
    }
}

#[test]
fn coverage_is_counted_on_the_parsers() {
    let dirs = |name: &str| harness::coverage_dirs(fuzz_gate::target(name).unwrap());
    assert_eq!(dirs("abnf-grammar"), ["crates/abnf/src"]);
    assert_eq!(dirs("abnf-constraint"), ["crates/abnf/src"]);
    assert_eq!(dirs("kargs-parse"), ["crates/kargs/src"]);
    assert_eq!(dirs("idl-names"), ["crates/idl-rt/src"]);
    assert_eq!(
        dirs("idl-front-end"),
        ["crates/idl/src", "crates/idl-rt/src"]
    );
    assert_eq!(dirs("idl-decode"), ["crates/idl-rt/src", "crates/idl/src"]);
    assert_eq!(
        dirs("idl-generated"),
        ["crates/idl-rt/src", "crates/idl/src"]
    );
    // The extra paths select a target, but aren't counted in its coverage.
    for t in TARGETS {
        for p in t.extra_paths {
            assert!(
                !harness::coverage_dirs(t).contains(&format!("{p}/src")),
                "{}: {p}",
                t.name
            );
        }
    }
    // Every target reports on at least one crate.
    for t in TARGETS {
        assert!(!harness::coverage_dirs(t).is_empty(), "{}", t.name);
    }
}

/// `llvm-cov report` on kargs-grub's seeds and corpus (llvm-tools of
/// Rust 1.100.0, captured in C71).
const LLVM_COV: &str = "\
Filename                      Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
lib.rs                            219                49    77.63%          24                 5    79.17%         205                37    81.95%           0                 0         -
grub.rs                           101                 3    97.03%          10                 0   100.00%          70                 0   100.00%           0                 0         -
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
TOTAL                             320                52    83.75%          34                 5    85.29%         275                37    86.55%           0                 0         -
";

#[test]
fn coverage_reports() {
    let c = harness::coverage_totals(LLVM_COV).unwrap();
    assert_eq!(
        c,
        harness::Coverage {
            regions: 320,
            regions_missed: 52,
            functions: 34,
            functions_missed: 5,
            lines: 275,
            lines_missed: 37,
        }
    );
    assert!((c.regions_percent() - 83.75).abs() < 0.01);
    assert!((c.functions_percent() - 85.29).abs() < 0.01);
    assert!((c.lines_percent() - 86.55).abs() < 0.01);
    assert_eq!(harness::coverage_totals("no totals"), None);
}
