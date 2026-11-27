// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `cargo xtask tlc [--nightly]`: the TLA+ specs in `specs/`, checked with
//! TLC (ADR 0068, rule 10; call-language specification, "Model checking").
//!
//! - **The tools.** TLC v1.7.4's `tla2tools.jar`, fetched into `build/tla/`
//!   if missing and checked against its pinned SHA-256 before every run. A
//!   JRE, 11 or later, from `JAVA_HOME` or the path; CI uses the runner's
//!   Java 21.
//!   The JRE is a CI-only tool, outside ADR 0008, rule 4 (call-language
//!   specification, "Engine and tools").
//! - **Where it runs.** The specs are copied into `build/tla/run/` and
//!   checked there, so TLC's state files never land in `specs/`.
//! - **What it runs.** The per-change models, each with its own `.cfg`
//!   beside `SchedDonation.tla`, then trace validation: the `donation_traces`
//!   test of `crates/ksched` writes seeded traces of the Rust, and
//!   `SchedDonationTrace.tla` checks them step by step. `--nightly` adds the
//!   nightly model and longer traces.
//! - **Its budget.** One budget for everything: 10 minutes per change, 60
//!   nightly. A run past it is killed, and fails. TLC uses at most
//!   min(4, cores / 2) workers, never `auto`, at low priority (`nice -n 10`),
//!   since other work shares the machine.

use crate::{build_dir, fail, root};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

const JAR_URL: &str = "https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar";
/// The release asset's SHA-256 (2,274,532 bytes). GitHub records no digest
/// for it; it was computed from the asset on 2026-11-26.
const JAR_SHA256: &str = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88";

/// The per-change models: (spec, config). Each config is `specs/<config>.cfg`.
const CI_MODELS: [(&str, &str); 5] = [
    ("SchedDonation", "SchedDonation"),
    ("SchedDonation", "SchedDonationTwo"),
    ("SchedDonation", "SchedDonationRefine"),
    ("SchedDonation", "SchedDonationDestroy"),
    ("SchedDonation", "SchedDonationSuspend"),
];
const NIGHTLY_MODELS: [(&str, &str); 1] = [("SchedDonation", "SchedDonation.nightly")];
/// The traces of the Rust that trace validation checks, per change and
/// nightly; nightly's are longer.
const TRACES: u64 = 100;

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The jar, fetched if missing, and checked.
fn jar() -> PathBuf {
    let dir = build_dir().join("tla");
    fs::create_dir_all(&dir).unwrap();
    let jar = dir.join("tla2tools.jar");
    if !jar.exists() {
        eprintln!("xtask: fetching {JAR_URL}");
        let part = dir.join("tla2tools.jar.part");
        let ok = Command::new("curl")
            .args(["-fsSL", "--retry", "3", "-o"])
            .arg(&part)
            .arg(JAR_URL)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            let _ = fs::remove_file(&part);
            fail("couldn't fetch tla2tools.jar");
        }
        fs::rename(&part, &jar).unwrap();
    }
    let got = sha256_hex(&fs::read(&jar).unwrap());
    if got != JAR_SHA256 {
        let _ = fs::remove_file(&jar);
        fail(format!(
            "tla2tools.jar's SHA-256 is {got}, not the pinned {JAR_SHA256}: deleted"
        ));
    }
    jar
}

/// The JRE, version 11 or later.
fn java() -> PathBuf {
    let java = std::env::var_os("JAVA_HOME")
        .map(|h| Path::new(&h).join("bin/java"))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("java"));
    let out = Command::new(&java)
        .arg("-version")
        .output()
        .unwrap_or_else(|e| fail(format!("{}: {e}", java.display())));
    // `java -version` writes to stderr: `openjdk version "21.0.13" ...`.
    let text = String::from_utf8_lossy(&out.stderr);
    let major = text
        .split('"')
        .nth(1)
        .and_then(|v| v.split('.').next())
        .and_then(|m| m.parse::<u32>().ok())
        .unwrap_or(0);
    if major < 11 {
        fail(format!(
            "TLC needs Java 11 or later; found: {}",
            text.trim()
        ));
    }
    java
}

/// The specs' files, from git where it can (iCloud's conflict copies, with
/// spaces in their names, are never listed), else from the directory.
fn spec_files() -> Vec<PathBuf> {
    let listed = Command::new("git")
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "specs",
        ])
        .current_dir(root())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    let mut files: Vec<PathBuf> = match listed {
        Some(text) => text.lines().map(|l| root().join(l)).collect(),
        None => fs::read_dir(root().join("specs"))
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect(),
    };
    files.retain(|p| {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or(" ");
        !name.contains(' ') && (name.ends_with(".tla") || name.ends_with(".cfg")) && p.exists()
    });
    files.sort();
    files
}

/// Workers: min(4, cores / 2), at least 1.
fn workers() -> usize {
    let cores = std::thread::available_parallelism().map_or(2, |n| n.get());
    (cores / 2).clamp(1, 4)
}

/// Runs `cmd` with its output in `log`, killing it at `deadline`. Returns
/// whether it succeeded.
fn run_until(mut cmd: Command, log: &Path, deadline: Instant) -> bool {
    let out = fs::File::create(log).unwrap();
    let err = out.try_clone().unwrap();
    let mut child = cmd
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap_or_else(|e| fail(format!("{cmd:?}: {e}")));
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.success();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("xtask: past the TLC budget: killed");
            return false;
        }
        sleep(Duration::from_millis(200));
    }
}

/// A command at low priority, where `nice` exists.
fn niced(program: &Path) -> Command {
    if Command::new("nice")
        .args(["-n", "10", "true"])
        .status()
        .is_ok_and(|s| s.success())
    {
        let mut c = Command::new("nice");
        c.args(["-n", "10"]).arg(program);
        c
    } else {
        Command::new(program)
    }
}

/// The lines of a TLC log worth showing.
fn summary(log: &Path) -> String {
    let text = fs::read_to_string(log).unwrap_or_default();
    text.lines()
        .filter(|l| {
            (l.contains("distinct states found") && !l.starts_with("Progress"))
                || l.starts_with("Error")
                || l.contains("is violated")
                || l.starts_with("Finished in")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// From a TLC log: the initial states, and the distinct states found.
fn state_counts(log: &Path) -> Option<(u64, u64)> {
    let text = fs::read_to_string(log).ok()?;
    let number = |line: &str, before: &str| -> Option<u64> {
        let head = line.split(before).next()?;
        head.split_whitespace()
            .last()?
            .replace(',', "")
            .parse()
            .ok()
    };
    let init = text
        .lines()
        .find(|l| l.starts_with("Finished computing initial states"))
        .and_then(|l| number(l, " distinct states generated"))?;
    let found = text
        .lines()
        .rfind(|l| l.contains("distinct states found") && !l.starts_with("Progress"))
        .and_then(|l| number(l, " distinct states found"))?;
    Some((init, found))
}

fn tlc(java: &Path, jar: &Path, dir: &Path, spec: &str, cfg: &str, deadlock_ok: bool) -> Command {
    let mut c = niced(java);
    c.current_dir(dir)
        .arg("-XX:+UseParallelGC")
        .arg("-cp")
        .arg(jar)
        .arg("tlc2.TLC")
        .args(["-workers", &workers().to_string(), "-cleanup"]);
    if deadlock_ok {
        c.arg("-deadlock");
    }
    c.args(["-config", &format!("{cfg}.cfg"), &format!("{spec}.tla")]);
    c
}

pub fn check(nightly: bool) {
    let start = Instant::now();
    let budget = Duration::from_secs(if nightly { 3600 } else { 600 });
    let deadline = start + budget;
    let jar = jar();
    let java = java();
    let dir = build_dir().join("tla/run");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    for f in spec_files() {
        fs::copy(&f, dir.join(f.file_name().unwrap())).unwrap();
    }
    let mut models: Vec<(&str, &str)> = CI_MODELS.to_vec();
    if nightly {
        models.extend(NIGHTLY_MODELS);
    }
    let mut failed = vec![];
    for (spec, cfg) in models {
        let t0 = Instant::now();
        let log = dir.join(format!("{cfg}.log"));
        // Terminal states are legal in these models: every thread may be
        // blocked or stranded.
        let ok = run_until(tlc(&java, &jar, &dir, spec, cfg, true), &log, deadline);
        eprintln!(
            "xtask: TLC {cfg}: {} in {:.0?}\n{}",
            if ok { "passed" } else { "FAILED" },
            t0.elapsed(),
            summary(&log)
        );
        if !ok {
            failed.push(cfg.to_string());
        }
    }

    // Trace validation: traces of the Rust, then TLC over them.
    let t0 = Instant::now();
    let traces = dir.join("SchedDonationTraces.tla");
    let mut test = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    test.current_dir(root())
        .args(["test", "--locked", "--quiet", "-p", "ksched", "--test"])
        .arg("donation_traces")
        .env("KSCHED_TRACE_OUT", &traces)
        .env("KSCHED_TRACES", TRACES.to_string());
    if nightly {
        test.env("KSCHED_TRACE_STEPS", "200");
    }
    let log = dir.join("traces-build.log");
    if !run_until(test, &log, deadline) || !traces.exists() {
        eprintln!("{}", fs::read_to_string(&log).unwrap_or_default());
        failed.push("writing traces".into());
    } else {
        let log = dir.join("SchedDonationTrace.log");
        // Deadlock checking stays on: a step the spec doesn't allow
        // deadlocks.
        let ran = run_until(
            tlc(
                &java,
                &jar,
                &dir,
                "SchedDonationTrace",
                "SchedDonationTrace",
                false,
            ),
            &log,
            deadline,
        );
        // TLC passes a model with no initial state, so the run must have
        // started every trace, and visited at least one state of each.
        let counted = state_counts(&log);
        let ok = ran && counted.is_some_and(|(init, found)| init == TRACES && found >= TRACES);
        if ran && !ok {
            eprintln!(
                "xtask: trace validation checked {counted:?} (initial, distinct) states, not {TRACES} traces"
            );
        }
        eprintln!(
            "xtask: TLC trace validation: {} in {:.0?}\n{}",
            if ok { "passed" } else { "FAILED" },
            t0.elapsed(),
            summary(&log)
        );
        if !ok {
            failed.push("trace validation".into());
        }
    }
    if failed.is_empty() {
        eprintln!(
            "xtask: TLC passed in {:.0?} (budget {:.0?})",
            start.elapsed(),
            budget
        );
    } else {
        fail(format!("TLC failed: {}", failed.join(", ")));
    }
}
