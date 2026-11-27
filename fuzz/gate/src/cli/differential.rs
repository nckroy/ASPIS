// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `differential`: the two ABNF checkers against each other (ADR 0068,
//! rule 6; docs/design/call-language.md, "Differential tests").
//!
//! Case `i` of seed `S` is [`generate::seeded`]`(S, i)`. crates/abnf
//! loads its grammar and judges each input context-free, as the Python
//! checker does, and the case is written as `case-<i>.abnf` and
//! `case-<i>.vectors` with Rust's verdicts as the tags. Then
//! `tools/ci/check-grammars.py`, unchanged, judges them with the Python
//! `abnf` package. Any FAIL line is a disagreement.
//!
//! The Python checker runs on batches of [`BATCH`] cases, each in its own
//! directory beside a copy of `grammars/core.abnf`, with a wall-clock
//! timeout. Exit 1 with FAIL lines is a disagreement. A traceback, an
//! exit status other than 0 or 1, or a timeout is a Python-limit event:
//! the batch is bisected to the case that causes it, each case with a
//! shorter timeout, and the case is recorded apart from disagreements. A
//! Python-limit event isn't a disagreement: under 1 % of the cases they
//! are logged, and above it the run fails, so the generator is steered
//! around the construct.
//!
//! `--budget` stops starting batches after that many seconds, so the
//! nightly job reports what it has before its time limit. `--self-test`
//! shows the harness detects a disagreement and a Python-limit event.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use abnf::Kind;
use fuzz_gate::{abnf_targets::load_generated, generate};

use crate::{fail, fuzz_build, root, tracked};

/// Cases a Python run judges.
const BATCH: u64 = 50;

/// The most a bisected case may take: one slow case is enough to
/// classify it.
const BISECT_TIMEOUT: Duration = Duration::from_secs(30);

/// What the Python checker said about a directory.
enum Python {
    /// Exit 0: every vector agrees.
    Agrees,
    /// Exit 1, with these FAIL lines.
    Disagrees(Vec<String>),
    /// A traceback, another exit status, or the timeout.
    Limit(String),
}

/// The Python interpreter: `$ASPIS_PYTHON`, or `python3`.
fn python() -> String {
    std::env::var("ASPIS_PYTHON").unwrap_or_else(|_| "python3".into())
}

/// Runs the Python checker on `dir`, killing it after `timeout`.
fn check_dir(dir: &Path, timeout: Duration) -> Python {
    let mut child = Command::new(python())
        .arg("-I")
        .arg(root().join("tools/ci/check-grammars.py"))
        .arg(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| fail(format!("{}: {e}", python())));
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let reader = thread::spawn(move || {
        let mut o = String::new();
        let _ = out.read_to_string(&mut o);
        o
    });
    let err_reader = thread::spawn(move || {
        let mut e = String::new();
        let _ = err.read_to_string(&mut e);
        e
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break Some(s);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stdout = reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    if stderr.contains("ModuleNotFoundError") || stderr.contains("ImportError") {
        fail(format!(
            "{} can't import abnf: install abnf==2.9.1 (as ci.yml does), or set ASPIS_PYTHON\n{stderr}",
            python()
        ));
    }
    match status {
        None => Python::Limit(format!("no answer within {} s", timeout.as_secs())),
        Some(_) if stderr.contains("Traceback") => Python::Limit(stderr),
        Some(s) if s.success() => Python::Agrees,
        Some(s) if s.code() == Some(1) => Python::Disagrees(
            stdout
                .lines()
                .filter(|l| l.starts_with("FAIL"))
                .map(String::from)
                .collect(),
        ),
        Some(s) => Python::Limit(format!("exit {s}\n{stderr}")),
    }
}

/// Totals over the cases.
#[derive(Default)]
struct Tally {
    cases: usize,
    ok: usize,
    err: usize,
    exhausted: usize,
    load_failures: Vec<String>,
    /// Derived inputs crates/abnf doesn't match: a bug in the generator
    /// or the matcher, which both checkers could share.
    unmatched_derivations: Vec<String>,
    disagreements: Vec<String>,
    limits: Vec<String>,
}

/// Writes case `i` into `dir`, and counts its verdicts.
fn write_case(dir: &Path, seed: u64, i: u64, tally: &Mutex<Tally>) {
    let c = generate::seeded(seed, i);
    let abnf = dir.join(format!("case-{i}.abnf"));
    fs::write(&abnf, &c.text).unwrap();
    let g = match load_generated(&c.text, Kind::Auto) {
        Ok(g) => g,
        Err(e) => {
            tally
                .lock()
                .unwrap()
                .load_failures
                .push(format!("{}: crates/abnf: {e}", abnf.display()));
            return;
        }
    };
    let mut verdicts = Vec::new();
    let (mut ok, mut err, mut exhausted) = (0, 0, 0);
    let mut unmatched = Vec::new();
    for (k, input) in c.inputs.iter().enumerate() {
        let r = g.rule(&c.rules[input.rule].name).expect("defined");
        let m = g.matches(r, &input.octets);
        if input.origin == generate::Origin::Derived && m == Ok(false) {
            unmatched.push(format!(
                "{}: input {k}: crates/abnf doesn't match its own derivation",
                abnf.display()
            ));
        }
        verdicts.push(match m {
            Ok(v) => {
                if v {
                    ok += 1;
                } else {
                    err += 1;
                }
                Some(v)
            }
            Err(_) => {
                exhausted += 1;
                None
            }
        });
    }
    fs::write(
        dir.join(format!("case-{i}.vectors")),
        generate::vectors_text(&c, &verdicts),
    )
    .unwrap();
    let mut t = tally.lock().unwrap();
    t.unmatched_derivations.extend(unmatched);
    t.cases += 1;
    t.ok += ok;
    t.err += err;
    t.exhausted += exhausted;
}

/// A fresh directory holding a copy of `grammars/core.abnf`, whose rule
/// names the Python checker reserves.
fn fresh(dir: &Path) {
    if dir.exists() {
        fs::remove_dir_all(dir).unwrap();
    }
    fs::create_dir_all(dir).unwrap();
    fs::copy(root().join("grammars/core.abnf"), dir.join("core.abnf")).unwrap();
}

/// Judges one batch; on a Python-limit event, judges each case alone to
/// find the one that causes it.
fn judge(dir: &Path, seed: u64, cases: &[u64], timeout: Duration, tally: &Mutex<Tally>) {
    match check_dir(dir, timeout) {
        Python::Agrees => {}
        Python::Disagrees(lines) => tally.lock().unwrap().disagreements.extend(lines),
        Python::Limit(why) if cases.len() == 1 => tally.lock().unwrap().limits.push(format!(
            "seed {seed} case {}: {}",
            cases[0],
            why.lines().last().unwrap_or("")
        )),
        Python::Limit(_) => {
            for &i in cases {
                let one = dir.join(format!("bisect-{i}"));
                fresh(&one);
                for ext in ["abnf", "vectors"] {
                    let f = format!("case-{i}.{ext}");
                    fs::copy(dir.join(&f), one.join(&f)).unwrap();
                }
                judge(&one, seed, &[i], timeout.min(BISECT_TIMEOUT), tally);
            }
        }
    }
}

/// The committed differential cases, `fuzz/differential/*`: each was a
/// disagreement once, and both checkers must now agree on it.
fn committed_cases(timeout: Duration, tally: &Mutex<Tally>) -> usize {
    let files = tracked("fuzz/differential");
    if files.is_empty() {
        return 0;
    }
    let dir = fuzz_build().join("differential/committed");
    fresh(&dir);
    for f in &files {
        let name = Path::new(f).file_name().unwrap();
        fs::copy(root().join(f), dir.join(name)).unwrap();
    }
    let mut t = tally.lock().unwrap();
    match check_dir(&dir, timeout) {
        Python::Agrees => {}
        Python::Disagrees(lines) => t
            .disagreements
            .extend(lines.into_iter().map(|l| format!("fuzz/differential: {l}"))),
        Python::Limit(why) => t.disagreements.push(format!(
            "fuzz/differential: the Python checker failed: {why}"
        )),
    }
    files.len()
}

/// `--self-test`: one case with a flipped tag must give a disagreement,
/// and the same case with no time must give a Python-limit event.
fn self_test() {
    let dir = fuzz_build().join("differential/self-test");
    fresh(&dir);
    // The first case of seed 0 whose inputs all get a verdict.
    let (i, c, mut verdicts) = (0..)
        .find_map(|i| {
            let c = generate::seeded(0, i);
            let g = load_generated(&c.text, Kind::Auto).ok()?;
            let v: Option<Vec<bool>> = c
                .inputs
                .iter()
                .map(|x| g.matches(g.rule(&c.rules[x.rule].name)?, &x.octets).ok())
                .collect();
            Some((i, c, v?)).filter(|(_, c, _)| !c.inputs.is_empty())
        })
        .unwrap();
    verdicts[0] = !verdicts[0];
    fs::write(dir.join(format!("case-{i}.abnf")), &c.text).unwrap();
    let tags: Vec<Option<bool>> = verdicts.into_iter().map(Some).collect();
    fs::write(
        dir.join(format!("case-{i}.vectors")),
        generate::vectors_text(&c, &tags),
    )
    .unwrap();
    match check_dir(&dir, Duration::from_secs(300)) {
        Python::Disagrees(lines) if !lines.is_empty() => {
            eprintln!(
                "xtask fuzz: differential: a flipped tag disagrees: {}",
                lines[0]
            );
        }
        Python::Disagrees(_) => fail("differential self-test: exit 1 without a FAIL line"),
        Python::Agrees => fail("differential self-test: a flipped tag isn't a disagreement"),
        Python::Limit(why) => fail(format!(
            "differential self-test: a Python-limit event: {why}"
        )),
    }
    match check_dir(&dir, Duration::ZERO) {
        Python::Limit(_) => {
            eprintln!("xtask fuzz: differential: no time gives a Python-limit event")
        }
        _ => fail("differential self-test: no time isn't a Python-limit event"),
    }
    eprintln!("xtask fuzz: differential: the self-test passed");
}

/// `differential [--seed S] [--cases N] [--jobs n] [--timeout s]
/// [--budget s] [--self-test]`.
pub fn differential(args: &[String]) {
    let mut seed = 0u64;
    let mut cases = 300u64;
    let mut jobs = thread::available_parallelism().map_or(1, |n| n.get());
    let mut timeout = 300u64;
    let mut budget = None;
    if args.iter().any(|a| a == "--self-test") {
        return self_test();
    }
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut num = |what: &str| -> u64 {
            it.next()
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| fail(format!("{what} takes a number")))
        };
        match a.as_str() {
            "--seed" => seed = num("--seed"),
            "--cases" => cases = num("--cases"),
            "--jobs" => jobs = (num("--jobs") as usize).max(1),
            "--timeout" => timeout = num("--timeout"),
            "--budget" => budget = Some(Duration::from_secs(num("--budget"))),
            other => fail(format!(
                "differential: unknown option {other}; usage: cargo xtask fuzz differential [--seed S] [--cases N] [--jobs n] [--timeout s] [--budget s] [--self-test]"
            )),
        }
    }
    let timeout = Duration::from_secs(timeout);
    let top = fuzz_build().join("differential").join(seed.to_string());
    if top.exists() {
        fs::remove_dir_all(&top).unwrap();
    }
    eprintln!(
        "xtask fuzz: differential: seed {seed}, {cases} cases, batches of {BATCH}, {jobs} at once, Python {}",
        python()
    );
    let start = Instant::now();
    let tally = Mutex::new(Tally::default());
    let batches = cases.div_ceil(BATCH);
    let next = AtomicUsize::new(0);
    thread::scope(|s| {
        for _ in 0..jobs.min(batches as usize).max(1) {
            s.spawn(|| {
                loop {
                    if budget.is_some_and(|b| start.elapsed() > b) {
                        break;
                    }
                    let b = next.fetch_add(1, Ordering::Relaxed) as u64;
                    if b >= batches {
                        break;
                    }
                    let dir: PathBuf = top.join(format!("batch-{b}"));
                    fresh(&dir);
                    let ids: Vec<u64> = (b * BATCH..((b + 1) * BATCH).min(cases)).collect();
                    // The loader and matcher need room for their depth.
                    thread::scope(|inner| {
                        thread::Builder::new()
                            .stack_size(64 << 20)
                            .spawn_scoped(inner, || {
                                for &i in &ids {
                                    write_case(&dir, seed, i, &tally);
                                }
                            })
                            .unwrap();
                    });
                    judge(&dir, seed, &ids, timeout, &tally);
                }
            });
        }
    });
    let committed = committed_cases(timeout, &tally);
    let t = tally.into_inner().unwrap();
    let inputs = t.ok + t.err + t.exhausted;
    let pct = |n: usize| 100.0 * n as f64 / inputs.max(1) as f64;
    eprintln!(
        "xtask fuzz: differential: {} cases, {inputs} inputs ({:.0} % ok, {:.0} % err, {} exhausted and dropped), {committed} committed files, {:.0} s",
        t.cases,
        pct(t.ok),
        pct(t.err),
        t.exhausted,
        start.elapsed().as_secs_f64()
    );
    let mut problems = Vec::new();
    if (t.cases as u64) < cases {
        eprintln!(
            "xtask fuzz: differential: the budget ran out after {} of {cases} cases",
            t.cases
        );
    }
    for l in &t.unmatched_derivations {
        eprintln!("xtask fuzz: differential: {l}");
    }
    if !t.unmatched_derivations.is_empty() {
        problems.push(format!(
            "{} derivations crates/abnf doesn't match",
            t.unmatched_derivations.len()
        ));
    }
    for l in &t.load_failures {
        eprintln!("xtask fuzz: differential: a generated grammar doesn't load: {l}");
    }
    if !t.load_failures.is_empty() {
        problems.push(format!("{} load failures", t.load_failures.len()));
    }
    for l in &t.disagreements {
        eprintln!("xtask fuzz: differential: {l}");
    }
    if !t.disagreements.is_empty() {
        problems.push(format!("{} disagreements", t.disagreements.len()));
    }
    for l in &t.limits {
        eprintln!("xtask fuzz: differential: a Python-limit event: {l}");
    }
    // A Python-limit event isn't a disagreement, but more than one case in
    // a hundred means the generator needs steering ("Triage and
    // disclosure").
    if t.limits.len() * 100 > t.cases.max(1) {
        problems.push(format!("{} Python-limit events", t.limits.len()));
    }
    if inputs > 0 && (t.ok * 5 < inputs || t.err * 5 < inputs) {
        problems.push("ok or err is under 20 % of the inputs: the generator is too weak".into());
    }
    if t.exhausted * 100 >= inputs.max(1) {
        problems.push(format!(
            "{} inputs ran out of a budget (1 % or more)",
            t.exhausted
        ));
    }
    if !problems.is_empty() {
        fail(format!(
            "differential, seed {seed}: {} (the cases are in {}; triage: fuzz/README.md)",
            problems.join(", "),
            top.display()
        ));
    }
    eprintln!("xtask fuzz: differential: the checkers agree");
}
