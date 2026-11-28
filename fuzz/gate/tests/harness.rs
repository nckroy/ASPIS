// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The harness's pure logic: libFuzzer's status lines (as captured from
//! real runs in C71), `/usr/bin/time -p`, the targets a change selects,
//! smoke time boxes, dictionary escaping, and run records.

use fuzz_gate::{
    TARGETS, dict,
    harness::{self, InnerLog, RunRecord, Status},
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

/// A real fork-mode run, stopped by the harness's SIGINT: idl-front-end,
/// `-fork=2`, 2,300 s, on aarch64 macOS. Abridged: most of the parent's
/// status lines are left out, and so are the inner log's `NEW` and
/// `REDUCE` lines, which the console copy it was taken from drops. After
/// its last status line, the parent prints one job's whole log.
const FORK_INTERRUPTED: &str = include_str!("data/fork-interrupted.log");

#[test]
fn a_fork_mode_run_reports_the_parents_figures() {
    let parent = Status {
        execs: 550_972,
        cov: 7690,
        ft: 26_849,
        corpus: 2397,
        ..Status::default()
    };
    assert_eq!(harness::last_status(FORK_INTERRUPTED), parent);
    // The parent counts only its jobs' executions, all after its corpus
    // load.
    assert_eq!(harness::fuzz_execs(FORK_INTERRUPTED), 550_972);
    // The inner log is left out, and /usr/bin/time's lines after it are
    // still read.
    let own: Vec<&str> = harness::own_lines(FORK_INTERRUPTED).collect();
    assert_eq!(
        own.last(),
        Some(
            &"#550972: cov: 7690 ft: 26849 corp: 2397 exec/s: 71 oom/timeout/crash: 0/0/0 time: 2366s job: 95 dft_time: 0"
        )
    );
    assert!(!own.iter().any(|l| l.contains("INITED")));
    let (cpu, wall) = harness::time_p(FORK_INTERRUPTED).unwrap();
    assert!((cpu - 4648.52).abs() < 1e-6 && (wall - 2366.12).abs() < 1e-9);
}

/// A fork-mode run with `-ignore_crashes=1`, in the formats and control
/// flow of libFuzzer's `FuzzerFork.cpp` (abridged: no `NEW` lines). The
/// parent prints a job's status line before it counts that job. Jobs 1
/// and 2 crash: the parent counts each and prints only its `ERROR:` lines,
/// and goes on. Jobs 3 and 4 exit 0. After job 4 the run is over its time
/// budget, so the parent stops its jobs and exits with job 4's exit code,
/// 0. With crashes ignored it never prints an inner log. Its last status
/// line carries the crashes counted before job 4.
const FORK_CRASHES: &str = "INFO: -fork=2: fuzzing in separate process(s)
INFO: -fork=2: 70 seed inputs, starting to fuzz in /tmp/libFuzzerTemp.FuzzWithFork7.dir
#152147: cov: 266 ft: 608 corp: 70 exec/s: 76073 oom/timeout/crash: 0/0/0 time: 2s job: 1 dft_time: 0
==4101== ERROR: libFuzzer: deadly signal
#310072: cov: 270 ft: 900 corp: 120 exec/s: 80000 oom/timeout/crash: 0/0/1 time: 4s job: 2 dft_time: 0
==4102== ERROR: libFuzzer: deadly signal
#420311: cov: 275 ft: 1209 corp: 253 exec/s: 82597 oom/timeout/crash: 0/0/2 time: 6s job: 3 dft_time: 0
#530118: cov: 276 ft: 1250 corp: 260 exec/s: 80000 oom/timeout/crash: 0/0/2 time: 8s job: 4 dft_time: 0
INFO: fuzzed for 8 seconds, wrapping up soon
INFO: exiting: 0 time: 8s
real 8.12
user 14.57
sys 1.60
";

/// A fork-mode run that ends on a finding, with `-ignore_ooms=1
/// -ignore_timeouts=1 -ignore_crashes=0`, abridged to its first and last
/// status lines. The parent counted the OOMs and timeouts of jobs 1 to 5
/// and went on. Then job 6 crashed: its status line, printed before the
/// parent counts it, shows no crash. The parent printed job 6's whole log,
/// with its own status and `stat::` lines, and exited with its exit code.
/// This is the Linux shape. On macOS the parent compares and exits with a
/// job's raw wait status, so it would count no OOM or timeout here, and
/// it would print `INFO: exiting: 19712` (77 << 8) and exit 0, the low
/// byte; the tests below take the run's exit status from their case.
const FORK_FINDING: &str = "INFO: -fork=2: fuzzing in separate process(s)
INFO: -fork=2: 70 seed inputs, starting to fuzz in /tmp/libFuzzerTemp.FuzzWithFork8.dir
#152147: cov: 266 ft: 608 corp: 70 exec/s: 76073 oom/timeout/crash: 0/0/0 time: 1s job: 1 dft_time: 0
#810072: cov: 275 ft: 1209 corp: 253 exec/s: 82597 oom/timeout/crash: 2/3/0 time: 6s job: 6 dft_time: 0
INFO: log from the inner process:
INFO: Seed: 9
INFO: seed corpus: files: 9 min: 1b max: 40b total: 120b rss: 27Mb
#10\tINITED cov: 250 ft: 400 corp: 9/120b exec/s: 0 rss: 27Mb
#4096\tpulse  cov: 251 ft: 410 corp: 12/200b lim: 40 exec/s: 4096 rss: 28Mb
==4106== ERROR: libFuzzer: deadly signal
SUMMARY: libFuzzer: deadly signal
stat::number_of_executed_units: 900000
stat::average_exec_per_sec:     4096
INFO: exiting: 77 time: 6s
real 6.20
user 10.60
sys 1.60
";

#[test]
fn a_fork_mode_parent_reports_its_counts() {
    assert_eq!(
        harness::last_status(FORK_CRASHES),
        Status {
            execs: 530_118,
            cov: 276,
            ft: 1250,
            corpus: 260,
            crashes: 2,
            ..Status::default()
        }
    );
    assert_eq!(harness::fuzz_execs(FORK_CRASHES), 530_118);
    let (cpu, wall) = harness::time_p(FORK_CRASHES).unwrap();
    assert!((cpu - 16.17).abs() < 1e-9 && (wall - 8.12).abs() < 1e-9);
    // The inner job's lines, its stat:: count among them, are left out.
    assert_eq!(
        harness::last_status(FORK_FINDING),
        Status {
            execs: 810_072,
            cov: 275,
            ft: 1209,
            corpus: 253,
            ooms: 2,
            timeouts: 3,
            crashes: 0,
        }
    );
    assert_eq!(harness::fuzz_execs(FORK_FINDING), 810_072);
    let (cpu, wall) = harness::time_p(FORK_FINDING).unwrap();
    assert!((cpu - 12.2).abs() < 1e-9 && (wall - 6.2).abs() < 1e-9);
}

/// What `run`'s stderr loop makes of a log: the first inner log's start,
/// with the harness's flag to stop the run set from line `stop` on (or
/// never).
fn inner_log(log: &str, stop: Option<usize>) -> InnerLog {
    log.lines()
        .enumerate()
        .find_map(|(i, l)| InnerLog::starts(l, stop.is_some_and(|s| i >= s)))
        .unwrap_or_default()
}

/// The line of `log` that starts with `prefix`.
fn line_of(log: &str, prefix: &str) -> usize {
    log.lines().position(|l| l.starts_with(prefix)).unwrap()
}

#[test]
fn a_fork_mode_inner_log_before_the_stop_is_a_finding() {
    let log = FORK_FINDING;
    // macOS: job 6 crashed, the parent printed its log and exited with
    // its raw wait status, whose low byte is 0. The harness hadn't
    // stopped the run, and no new artifact need be written: the inner
    // log alone makes it unclean.
    let inner = inner_log(log, None);
    assert_eq!(inner, InnerLog::BeforeStop);
    assert!(harness::inner_log_is_finding(inner, log));
    assert!(!harness::ended_cleanly(Some(0), false, true, inner, log));
    // The harness's timer may fire while the parent waits for its other
    // jobs: the inner log was read before the flag was set, so it is
    // still a finding, even when the run then exits 72 or 0.
    let stop = Some(log.lines().count() - 3);
    assert_eq!(inner_log(log, stop), InnerLog::BeforeStop);
    assert!(!harness::ended_cleanly(Some(0), true, true, inner, log));
    assert!(!harness::ended_cleanly(
        Some(harness::INTERRUPTED),
        true,
        true,
        inner,
        log
    ));
    // Linux: the same finding exits 77, unclean by its exit status alone.
    assert!(!harness::ended_cleanly(Some(77), false, true, inner, log));
    assert!(!harness::ended_cleanly(
        Some(77),
        false,
        true,
        InnerLog::Absent,
        ""
    ));
    // A stopped job's log that began before the harness's flag was set
    // was no SIGINT of the harness's: it is a finding too.
    let unasked = inner_log(FORK_INTERRUPTED, None);
    assert_eq!(unasked, InnerLog::BeforeStop);
    assert!(harness::inner_log_is_stop(FORK_INTERRUPTED));
    assert!(!harness::ended_cleanly(
        Some(0),
        false,
        true,
        unasked,
        FORK_INTERRUPTED
    ));
}

#[test]
fn a_fork_mode_finding_read_after_the_stop_is_a_finding() {
    let log = FORK_FINDING;
    // Job 6 crashed just before the time box. The parent merged first,
    // and the harness read the inner log's first line only after its
    // timer set the flag. The log is a finding's, not a stopped job's, so
    // the run is unclean, on macOS with exit 0 and no new artifact.
    let stop = line_of(log, harness::INNER_LOG);
    let inner = inner_log(log, Some(stop));
    assert_eq!(inner, InnerLog::AfterStop);
    assert!(!harness::inner_log_is_stop(log));
    assert!(harness::inner_log_is_finding(inner, log));
    assert!(!harness::ended_cleanly(Some(0), true, true, inner, log));
    let stop = line_of(log, "#810072:");
    assert_eq!(inner_log(log, Some(stop)), InnerLog::AfterStop);
    assert!(!harness::ended_cleanly(Some(0), true, true, inner, log));
    // A timeout's and an OOM's logs are findings' too.
    for report in [
        "==4106== ERROR: libFuzzer: timeout after 10 seconds",
        "==4106== ERROR: libFuzzer: out-of-memory (used: 2100Mb; exceeds: 2048Mb)",
    ] {
        let log = format!(
            "#9: cov: 1 ft: 1 corp: 1 exec/s: 1 oom/timeout/crash: 0/0/0 time: 1s job: 1 dft_time: 0\n{}\n#4096\tpulse  cov: 251 ft: 410 corp: 12/200b lim: 40 exec/s: 4096 rss: 28Mb\n{report}\nINFO: exiting: 0 time: 6s\n",
            harness::INNER_LOG
        );
        assert!(!harness::inner_log_is_stop(&log));
        assert!(!harness::ended_cleanly(
            Some(0),
            true,
            true,
            InnerLog::AfterStop,
            &log
        ));
    }
    // A log with a finding's report is a finding's, even if it also has
    // the interrupt line.
    let both = format!(
        "{}\n==4106== ERROR: libFuzzer: deadly signal\n==4106== libFuzzer: run interrupted; exiting\n",
        harness::INNER_LOG
    );
    assert!(!harness::inner_log_is_stop(&both));
    // No inner log is no stopped job's.
    assert!(!harness::inner_log_is_stop(FORK));
    assert!(!harness::inner_log_is_stop(
        "==96053== libFuzzer: run interrupted; exiting\n"
    ));
}

#[test]
fn a_fork_mode_inner_log_after_the_stop_is_clean() {
    let log = FORK_INTERRUPTED;
    // The real macOS run, stopped by the harness: the flag was set before
    // the SIGINT, so before the stopped job's log began, and that log
    // ends in the job's "run interrupted" line. The parent exited with
    // the job's raw status, 18432 (72 << 8), so 0.
    let stop = line_of(log, harness::INNER_LOG);
    let inner = inner_log(log, Some(stop));
    assert_eq!(inner, InnerLog::AfterStop);
    assert!(harness::inner_log_is_stop(log));
    assert!(!harness::inner_log_is_finding(inner, log));
    assert!(harness::ended_cleanly(Some(0), true, true, inner, log));
    // The flag set well before the inner log, as when the parent was
    // merging when the SIGINT came.
    let stop = line_of(log, "#550972:");
    assert_eq!(inner_log(log, Some(stop)), InnerLog::AfterStop);
    // Linux, or a SIGINT while no job or merge subprocess ran: no inner
    // log, exit 72.
    assert!(harness::ended_cleanly(
        Some(harness::INTERRUPTED),
        true,
        true,
        InnerLog::Absent,
        ""
    ));
    // A run that ran out its backstop or exits 0 by itself, with no inner
    // log, is clean; 72 without the harness's stop isn't.
    assert_eq!(inner_log(FORK, None), InnerLog::Absent);
    assert_eq!(inner_log(FORK_CRASHES, None), InnerLog::Absent);
    assert!(!harness::inner_log_is_finding(InnerLog::Absent, FORK));
    assert!(harness::ended_cleanly(
        Some(0),
        false,
        true,
        InnerLog::Absent,
        FORK_CRASHES
    ));
    assert!(!harness::ended_cleanly(
        Some(harness::INTERRUPTED),
        false,
        true,
        InnerLog::Absent,
        FORK
    ));
    // Killed by a signal: no exit code.
    assert!(!harness::ended_cleanly(
        None,
        true,
        true,
        InnerLog::Absent,
        ""
    ));
}

#[test]
fn a_normal_mode_run_ends_by_its_exit_status() {
    assert_eq!(inner_log(NORMAL, None), InnerLog::Absent);
    assert!(harness::ended_cleanly(
        Some(0),
        false,
        false,
        InnerLog::Absent,
        NORMAL
    ));
    assert!(harness::ended_cleanly(
        Some(harness::INTERRUPTED),
        true,
        false,
        InnerLog::Absent,
        NORMAL
    ));
    for code in [Some(1), Some(70), Some(71), Some(77), None] {
        assert!(!harness::ended_cleanly(
            code,
            true,
            false,
            InnerLog::Absent,
            NORMAL
        ));
    }
    assert!(!harness::ended_cleanly(
        Some(harness::INTERRUPTED),
        false,
        false,
        InnerLog::Absent,
        NORMAL
    ));
    // In normal mode an inner-log line, which only a target could print,
    // changes nothing, before the stop or after it.
    for inner in [InnerLog::BeforeStop, InnerLog::AfterStop] {
        assert!(harness::ended_cleanly(
            Some(0),
            false,
            false,
            inner,
            FORK_FINDING
        ));
    }
    // Only the marker line starts an inner log.
    assert_eq!(InnerLog::starts("INFO: Seed: 7", false), None);
    assert_eq!(
        InnerLog::starts("INFO: log from the inner process:", true),
        Some(InnerLog::AfterStop)
    );
}

#[test]
fn executions_after_the_corpus_load() {
    // Normal mode: the INITED line's count is the corpus load's.
    assert_eq!(harness::fuzz_execs(NORMAL), 203_850 - 190);
    assert_eq!(
        harness::fuzzing_start("#190\tINITED cov: 268 ft: 1171 corp: 172/45Kb exec/s: 0 rss: 27Mb"),
        Some(190)
    );
    // Fork mode's start line has no count; the parent counts none of
    // its load.
    assert_eq!(
        harness::fuzzing_start(
            "INFO: -fork=2: 70 seed inputs, starting to fuzz in /tmp/libFuzzerTemp.FuzzWithFork7.dir"
        ),
        Some(0)
    );
    assert_eq!(harness::fuzzing_start("INFO: Seed: 7"), None);
    // A run that never finished its load counts every execution.
    assert_eq!(
        harness::fuzz_execs("#40\tNEW cov: 1 ft: 1 corp: 1/1b\n"),
        40
    );
    // Normal mode has no inner log, so every line is its own.
    assert_eq!(harness::own_lines(NORMAL).count(), NORMAL.lines().count());
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
