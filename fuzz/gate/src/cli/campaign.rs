// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Fuzzing campaigns: `run`, `smoke`, `tmin` and `report`
//! (docs/design/call-language.md, "The harness"; ADR 0068, rules 5 and 7).
//!
//! libFuzzer is run directly, never through `cargo fuzz run`, so the
//! corpus, findings and logs stay under `build/fuzz/`. Each run is timed
//! by `/usr/bin/time -p` (POSIX, on macOS and Linux alike), whose user
//! and sys seconds include the fork-mode children libFuzzer waits for:
//! that measured CPU time, not workers times wall time, is what the
//! gate's CPU-hour counts.
//!
//! A run's `--time` is fuzzing time. libFuzzer's `-max_total_time` counts
//! from the process's start, and libFuzzer first runs every seed,
//! regression and corpus input, so the harness gives it a generous
//! `-max_total_time` as a backstop and stops it with SIGINT `--time`
//! seconds after the corpus load ends ([`harness::fuzzing_starts`]).
//! `/usr/bin/time` ignores SIGINT, so it still reports. Each record
//! names the target binary's build, and `report` counts only the runs of
//! the binary built now.

use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::process::CommandExt,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use fuzz_gate::{
    TARGETS, Target,
    harness::{self, RunRecord},
};

use crate::{binary, committed, fail, fuzz_build, output, root, selected};

/// What one run is asked for.
pub struct RunOpts {
    /// Seconds of fuzzing, after the corpus load.
    pub time: u32,
    /// Fork-mode workers; 1 runs in-process.
    pub jobs: u32,
    /// libFuzzer's `-seed`, printed so the run can be repeated.
    pub seed: u64,
}

/// The flags `run`, `smoke` and `nightly` share: `--time`, `--jobs` and
/// `--seed`. Anything else is returned as positional.
pub fn parse_opts(args: &[String], time: u32) -> (RunOpts, Vec<String>) {
    let mut opts = RunOpts {
        time,
        jobs: 1,
        seed: default_seed(),
    };
    let mut pos = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut num = |what: &str| -> u64 {
            it.next()
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| fail(format!("{what} takes a number")))
        };
        match a.as_str() {
            "--time" => opts.time = num("--time") as u32,
            "--jobs" => opts.jobs = (num("--jobs") as u32).max(1),
            "--seed" => opts.seed = num("--seed"),
            _ => pos.push(a.clone()),
        }
    }
    (opts, pos)
}

/// A seed from the clock, for runs that aren't given one. libFuzzer's
/// seeds are 32-bit.
fn default_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() % u64::from(u32::MAX))
        .unwrap_or(1)
        .max(1)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The files in `dir`, by name.
fn listing(dir: &Path) -> BTreeSet<String> {
    fs::read_dir(dir)
        .map(|r| {
            r.filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// The commit, whether the tree is dirty, rustc's version and
/// cargo-fuzz's, for a run record.
fn provenance() -> (String, bool, String, String) {
    let git = |args: &[&str]| output(Command::new("git").args(args).current_dir(root()));
    let commit = git(&["rev-parse", "--short=12", "HEAD"]).trim().to_string();
    let dirty = !git(&["status", "--porcelain", "--untracked-files=no"])
        .trim()
        .is_empty();
    let rustc = output(Command::new("rustc").arg("--version").current_dir(root()));
    let rustc = rustc.split_whitespace().nth(1).unwrap_or("?").to_string();
    let fuzz = crate::installed("fuzz").unwrap_or_else(|| "?".into());
    (
        if commit.is_empty() {
            "?".into()
        } else {
            commit
        },
        dirty,
        rustc,
        fuzz,
    )
}

/// The build id of a target's binary ([`harness::build_id`]), or `None`
/// if it isn't built.
pub fn current_build(t: &Target) -> Option<String> {
    fs::read(binary(t.name)).ok().map(|b| harness::build_id(&b))
}

/// The target's dictionary, if `build` wrote a non-empty one.
pub fn dict_path(t: &Target) -> Option<PathBuf> {
    let p = fuzz_build()
        .join("dict/targets")
        .join(format!("{}.dict", t.name));
    fs::metadata(&p).is_ok_and(|m| m.len() > 0).then_some(p)
}

/// Appends a record to `build/fuzz/runs/<t>.tsv`, with the header first
/// in a new file.
fn record(t: &Target, r: &RunRecord) {
    let dir = fuzz_build().join("runs");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{}.tsv", t.name));
    let new = !path.exists();
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
    if new {
        writeln!(f, "{}", harness::RUN_HEADER).unwrap();
    }
    writeln!(f, "{}", r.to_line()).unwrap();
}

/// A target's run records.
pub fn records(t: &Target) -> Vec<RunRecord> {
    let path = fuzz_build().join("runs").join(format!("{}.tsv", t.name));
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter_map(RunRecord::from_line)
        .collect()
}

/// What one run gave.
pub struct Outcome {
    /// No finding, and libFuzzer ended cleanly (or was stopped on time).
    pub passed: bool,
    /// Seconds of fuzzing after the corpus load.
    pub fuzz_s: f64,
}

/// Fuzzes one target for `opts.time` seconds after its corpus load, and
/// records the run. It passes when libFuzzer exits cleanly, or is stopped
/// on time, and the run left no finding: fork mode would otherwise carry
/// on past timeouts and OOMs, so they are made to stop it
/// (`-ignore_timeouts=0 -ignore_ooms=0`), and any new file in the
/// artifacts directory fails the run. In fork mode, a job's log that the
/// parent prints fails it too, whatever the exit status, unless it began
/// after the stop and is a stopped job's ([`harness::ended_cleanly`]).
pub fn run_target(t: &Target, opts: &RunOpts) -> Outcome {
    let bin = binary(t.name);
    if !bin.is_file() {
        fail(format!(
            "{} isn't built: run cargo xtask fuzz build",
            bin.display()
        ));
    }
    let build = current_build(t).unwrap_or_else(|| fail(format!("{}: unreadable", bin.display())));
    let seeds = fuzz_build().join("seeds").join(t.name);
    if !seeds.is_dir() {
        fail(format!("{}: no seeds: run cargo xtask fuzz build", t.name));
    }
    if !Path::new("/usr/bin/time").is_file() {
        fail("/usr/bin/time is missing: it measures each run's CPU time");
    }
    let corpus = fuzz_build().join("corpus").join(t.name);
    let artifacts = fuzz_build().join("artifacts").join(t.name);
    let logs = fuzz_build().join("logs");
    for d in [&corpus, &artifacts, &logs] {
        fs::create_dir_all(d).unwrap();
    }
    let before = listing(&artifacts);

    // The backstop: room for a corpus load as long as the run, and ten
    // minutes more. The harness stops the run first, unless in fork mode
    // its SIGINT lands while only a merge subprocess runs
    // (harness::INNER_LOG).
    let backstop = u64::from(opts.time) * 2 + 600;
    let mut cmd = Command::new("/usr/bin/time");
    cmd.arg("-p")
        .arg(&bin)
        .current_dir(root())
        .arg(format!("-max_total_time={backstop}"))
        .args(harness::libfuzzer_flags(t))
        .arg(format!("-seed={}", opts.seed))
        .arg(format!("-artifact_prefix={}/", artifacts.display()))
        .arg("-print_final_stats=1")
        // Its own process group, so SIGINT reaches libFuzzer and its
        // fork-mode children, and /usr/bin/time, which ignores it.
        .process_group(0);
    if let Some(d) = dict_path(t) {
        cmd.arg(format!("-dict={}", d.display()));
    }
    if opts.jobs > 1 {
        cmd.arg(format!("-fork={}", opts.jobs)).args([
            "-ignore_timeouts=0",
            "-ignore_ooms=0",
            "-ignore_crashes=0",
        ]);
    }
    // New inputs go to the first directory; the others are read only.
    cmd.arg(&corpus).arg(&seeds);
    let regressions = fuzz_build().join("regressions").join(t.name);
    if regressions.is_dir() {
        cmd.arg(&regressions);
    }
    eprintln!(
        "xtask fuzz: run {}: {} s after the corpus load, {} worker{}, -seed={}, build {build}",
        t.name,
        opts.time,
        opts.jobs,
        if opts.jobs == 1 { "" } else { "s" },
        opts.seed
    );

    // libFuzzer writes to stderr. The whole log goes to a file; progress
    // lines that add an input are left out of the console.
    // One log a target and seed, so two runs of a target can share its
    // corpus at once.
    let log_path = logs.join(format!("{}-{}.log", t.name, opts.seed));
    let mut log = fs::File::create(&log_path).unwrap();
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| fail(format!("{}: {e}", bin.display())));
    let group = child.id();
    let done = Arc::new(AtomicBool::new(false));
    let interrupted = Arc::new(AtomicBool::new(false));
    let mut started: Option<Instant> = None;
    // Whether a fork-mode parent has started printing a job's log, whose
    // lines are that job's, not the run's (harness::own_lines), and
    // whether it started before the stop (harness::InnerLog). The timer
    // sets `interrupted` before it sends the SIGINT, and the flag is read
    // only after the line is, so an inner log the SIGINT caused always
    // reads as after the stop. A finding's may too, so one after the stop
    // is clean only if it is a stopped job's (harness::inner_log_is_stop).
    let mut inner = harness::InnerLog::Absent;
    let mut text = String::new();
    for line in BufReader::new(child.stderr.take().unwrap()).lines() {
        let line = line.unwrap_or_default();
        writeln!(log, "{line}").unwrap();
        if !(line.contains("\tNEW ") || line.contains("\tREDUCE ")) {
            eprintln!("  {line}");
        }
        if inner == harness::InnerLog::Absent
            && let Some(at) = harness::InnerLog::starts(&line, interrupted.load(Ordering::SeqCst))
        {
            inner = at;
        }
        if started.is_none() && inner == harness::InnerLog::Absent && harness::fuzzing_starts(&line)
        {
            started = Some(Instant::now());
            let (done, interrupted) = (done.clone(), interrupted.clone());
            let secs = u64::from(opts.time);
            thread::spawn(move || {
                thread::sleep(Duration::from_secs(secs));
                if !done.load(Ordering::SeqCst) {
                    interrupted.store(true, Ordering::SeqCst);
                    let _ = Command::new("kill")
                        .args(["-INT", "--", &format!("-{group}")])
                        .status();
                }
            });
        }
        text.push_str(&line);
        text.push('\n');
    }
    let exit = child.wait().unwrap();
    done.store(true, Ordering::SeqCst);
    let fuzz_s = started.map_or(0.0, |at| at.elapsed().as_secs_f64());
    let fork = opts.jobs > 1;
    let clean = harness::ended_cleanly(
        exit.code(),
        interrupted.load(Ordering::SeqCst),
        fork,
        inner,
        &text,
    );

    let status = harness::last_status(&text);
    let (cpu_s, wall_s) = harness::time_p(&text).unwrap_or((0.0, 0.0));
    let new: Vec<String> = listing(&artifacts).difference(&before).cloned().collect();
    let (commit, dirty, rustc, cargo_fuzz) = provenance();
    let r = RunRecord {
        utc: harness::utc(now()),
        build,
        commit,
        dirty,
        rustc,
        cargo_fuzz,
        seed: opts.seed,
        workers: opts.jobs,
        wall_s,
        fuzz_s,
        fuzz_execs: harness::fuzz_execs(&text),
        cpu_s,
        status,
        artifacts: new.len() as u64,
        clean,
    };
    record(t, &r);
    let passed = !r.finding();
    eprintln!(
        "xtask fuzz: run {}: {} ({} execs, {} after the load; cov {}, ft {}, corpus {}; {:.0} s fuzzing of {:.0} s; {:.0} CPU-s measured, {:.0} asked; log {})",
        t.name,
        if passed { "no finding" } else { "FINDING" },
        status.execs,
        r.fuzz_execs,
        status.cov,
        status.ft,
        status.corpus,
        fuzz_s,
        wall_s,
        cpu_s,
        r.asked_s(),
        log_path.display()
    );
    if passed && fuzz_s < f64::from(opts.time) {
        eprintln!(
            "xtask fuzz: run {}: warning: {fuzz_s:.0} s of fuzzing, under the {} s asked (the corpus load took {:.0} s)",
            t.name,
            opts.time,
            wall_s - fuzz_s
        );
    }
    for a in &new {
        eprintln!("xtask fuzz: finding: {}", artifacts.join(a).display());
    }
    if fork && harness::inner_log_is_finding(inner, &text) {
        eprintln!(
            "xtask fuzz: finding: a job ended on a finding; its log follows \"{}\" in {}",
            harness::INNER_LOG,
            log_path.display()
        );
    }
    Outcome { passed, fuzz_s }
}

/// `run <target> [--time s] [--jobs n] [--seed s]`.
pub fn run(args: &[String]) {
    let (opts, pos) = parse_opts(args, 60);
    let [name] = pos.as_slice() else {
        fail("usage: cargo xtask fuzz run <target> [--time s] [--jobs n] [--seed s]")
    };
    let t = selected(Some(name))[0];
    if !run_target(t, &opts).passed {
        fail(format!("run {}: a finding (cargo xtask fuzz tmin)", t.name));
    }
}

/// The paths a change touches, against the merge base with `base`: the
/// committed changes, the working tree's, and new files. `None` when
/// there is no usable base, which selects every target.
fn changed_since(base: &str) -> Option<Vec<String>> {
    if base.is_empty() || base.bytes().all(|b| b == b'0') {
        return None;
    }
    let mb = Command::new("git")
        .args(["merge-base", base, "HEAD"])
        .current_dir(root())
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let mb = String::from_utf8_lossy(&mb.stdout).trim().to_string();
    let diff = Command::new("git")
        .args(["diff", "--name-only", &mb])
        .current_dir(root())
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let mut paths: Vec<String> = String::from_utf8_lossy(&diff.stdout)
        .lines()
        .map(String::from)
        .collect();
    // New files git doesn't track yet, but doesn't ignore either.
    let new = Command::new("git")
        .args(["ls-files", "--others", "--exclude-standard"])
        .current_dir(root())
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    paths.extend(
        String::from_utf8_lossy(&new.stdout)
            .lines()
            .map(String::from),
    );
    Some(paths)
}

/// `smoke --base <rev> [--budget s] [--seed s]`: fuzzes, one after
/// another, each target whose paths changed since the merge base with
/// `<rev>`, for 60 s each and `--budget` (600 s) in all ("Per change").
/// The seconds are fuzzing after each target's corpus load, which comes
/// on top. A target that got under half its time box fails the smoke
/// run, since its fuzzing didn't happen.
pub fn smoke(args: &[String]) {
    let mut base = String::new();
    let mut budget = 600u32;
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--base" => base = it.next().cloned().unwrap_or_default(),
            "--budget" => {
                budget = it
                    .next()
                    .and_then(|n| n.parse().ok())
                    .unwrap_or_else(|| fail("--budget takes seconds"))
            }
            _ => rest.push(a.clone()),
        }
    }
    let (mut opts, pos) = parse_opts(&rest, 60);
    if !pos.is_empty() {
        fail("usage: cargo xtask fuzz smoke --base <rev> [--budget s] [--seed s]");
    }
    let targets: Vec<&Target> = match changed_since(&base) {
        None => {
            eprintln!("xtask fuzz: smoke: no base, so every target");
            TARGETS.iter().collect()
        }
        Some(paths) => harness::selected_by(TARGETS, &paths),
    };
    if targets.is_empty() {
        eprintln!("xtask fuzz: smoke: the change selects no target");
        return;
    }
    opts.time = harness::time_box(targets.len(), 60, budget);
    opts.jobs = 1;
    eprintln!(
        "xtask fuzz: smoke: {} for {} s each, -seed={} (repeat one with cargo xtask fuzz run <target> --time {} --seed {})",
        targets
            .iter()
            .map(|t| t.name)
            .collect::<Vec<_>>()
            .join(", "),
        opts.time,
        opts.seed,
        opts.time,
        opts.seed
    );
    let mut failed = Vec::new();
    let mut short = Vec::new();
    for t in &targets {
        let o = run_target(t, &opts);
        if !o.passed {
            failed.push(t.name);
        } else if o.fuzz_s < f64::from(opts.time) / 2.0 {
            short.push(format!("{} ({:.0} s)", t.name, o.fuzz_s));
        }
    }
    if !failed.is_empty() {
        fail(format!("smoke: findings in {}", failed.join(", ")));
    }
    if !short.is_empty() {
        fail(format!(
            "smoke: under half the {} s time box of fuzzing: {}",
            opts.time,
            short.join(", ")
        ));
    }
}

/// `tmin <target> <input>`: minimizes a crashing input for a minute, to
/// `build/fuzz/artifacts/<t>/minimized-<name>` ("Triage and disclosure").
pub fn tmin(args: &[String]) {
    let [name, input] = args else {
        fail("usage: cargo xtask fuzz tmin <target> <input>")
    };
    let t = selected(Some(name))[0];
    let input = PathBuf::from(input);
    let file = input
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| fail("tmin takes a file"));
    let artifacts = fuzz_build().join("artifacts").join(t.name);
    fs::create_dir_all(&artifacts).unwrap();
    let out = artifacts.join(format!("minimized-{file}"));
    let s = Command::new(binary(t.name))
        .current_dir(root())
        .args(["-minimize_crash=1", "-max_total_time=60"])
        .args(harness::libfuzzer_flags(t))
        .arg(format!("-exact_artifact_path={}", out.display()))
        .arg(&input)
        .status()
        .unwrap_or_else(|e| fail(format!("{}: {e}", t.name)));
    if !out.is_file() {
        fail(format!(
            "tmin {}: no minimized input ({s}); does {} crash? cargo xtask fuzz replay {} {}",
            t.name,
            input.display(),
            t.name,
            input.display()
        ));
    }
    eprintln!(
        "xtask fuzz: minimized to {} ({} octets)",
        out.display(),
        fs::metadata(&out).map(|m| m.len()).unwrap_or(0)
    );
}

/// The error kinds a target's seeds, regressions and corpus reach.
fn kinds_reached(t: &'static Target) -> (BTreeSet<&'static str>, usize, Vec<String>) {
    let mut inputs = committed("seeds", t.name);
    inputs.extend((t.seeds)());
    inputs.extend(committed("regressions", t.name));
    let corpus = fuzz_build().join("corpus").join(t.name);
    for f in listing(&corpus) {
        if let Ok(b) = fs::read(corpus.join(&f)) {
            inputs.push((format!("corpus/{f}"), b));
        }
    }
    // The matcher's depth needs a big stack.
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || {
            let mut reached = BTreeSet::new();
            let mut panics = Vec::new();
            for (name, bytes) in &inputs {
                match catch_unwind(AssertUnwindSafe(|| (t.kinds_of)(bytes))) {
                    Ok(k) => reached.extend(k),
                    Err(_) => panics.push(name.clone()),
                }
            }
            (reached, inputs.len(), panics)
        })
        .unwrap()
        .join()
        .unwrap()
}

/// `report [<target>...]`: each target's campaigns from its run records,
/// and the error kinds its inputs reach, as the gate's evidence
/// ("The gate for each target", items 4 and 5). Only the runs of the
/// binary built now count; runs of earlier builds are listed apart.
pub fn report(args: &[String]) {
    let targets: Vec<&'static Target> = if args.is_empty() {
        selected(None)
    } else {
        args.iter().flat_map(|a| selected(Some(a))).collect()
    };
    println!(
        "| Target | Build | Runs | CPU-h measured | CPU-h asked | CPU-h since last finding | Findings | Execs | cov | ft | Corpus | Kinds reached | Other builds' runs |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|");
    let mut panics = Vec::new();
    for t in targets {
        let build = current_build(t).unwrap_or_else(|| "not built".into());
        let all = records(t);
        let s = harness::summarize(&all, &build);
        let (reached, n, p) = kinds_reached(t);
        panics.extend(p.into_iter().map(|p| format!("{}: {p}", t.name)));
        let hit = t.kinds.iter().filter(|k| reached.contains(*k)).count();
        let last = s.last.as_ref().map(|r| r.status).unwrap_or_default();
        println!(
            "| `{}` | `{build}` | {} | {:.2} | {:.2} | {:.2} | {} | {} | {} | {} | {} | {}/{} ({n} inputs) | {} |",
            t.name,
            s.runs,
            s.cpu_s / 3600.0,
            s.asked_s / 3600.0,
            s.clean_cpu_s / 3600.0,
            s.findings,
            s.execs,
            last.cov,
            last.ft,
            last.corpus,
            hit,
            t.kinds.len(),
            all.len() - s.runs
        );
    }
    if !panics.is_empty() {
        fail(format!(
            "inputs that panic (run cargo xtask fuzz replay):\n{}",
            panics.join("\n")
        ));
    }
}
