// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `cargo xtask fuzz`: the fuzzing harness (ADR 0068, rules 3, 5 and 7;
//! docs/design/call-language.md, "The harness").
//!
//! ```text
//! cargo xtask fuzz list [--shard i/n] [--names]
//!                                            the targets and their limits
//! cargo xtask fuzz install                   the pinned cargo-fuzz and cargo-deny
//! cargo xtask fuzz build                     check the tools and the locks,
//!                                            build every target, check the
//!                                            oracle, and write the seeds
//! cargo xtask fuzz replay [<target> [<file>...]] [--repeat <n>]
//!                                            every seed, regression and
//!                                            corpus input, once (-runs=0)
//! cargo xtask fuzz measure [<target>] [--corpus]
//!                                            each target's slowest seeds (and
//!                                            corpus inputs) and peak memory,
//!                                            in-process
//! cargo xtask fuzz kinds [<target>] [--each]  the error kinds the seeds
//!                                            reach, against the table's
//! cargo xtask fuzz run <target> [--time s] [--jobs n] [--seed s]
//!                                            fuzz one target for s seconds
//!                                            after its corpus load, and
//!                                            record the run in build/fuzz/runs/
//! cargo xtask fuzz smoke --base <rev> [--budget s] [--seed s]
//!                                            fuzz the targets a change
//!                                            selects, 60 s each, 600 s in
//!                                            all, after each corpus load
//! cargo xtask fuzz tmin <target> <input>     minimize a finding
//! cargo xtask fuzz differential [--seed S] [--cases N] [--jobs n]
//!                               [--timeout s] [--budget s] [--self-test]
//!                                            the two ABNF checkers, on
//!                                            generated grammars
//! cargo xtask fuzz report [<target>...]      each target's CPU time,
//!                                            findings and kinds reached,
//!                                            for the binary built now
//! cargo xtask fuzz coverage [<target>...]    line, region and function
//!                                            coverage of each target's
//!                                            crates, from its inputs
//! cargo xtask fuzz nightly [--time s] [--budget s] [--jobs n] [--seed s]
//!                          [--shard i/n]     build, replay, run each
//!                                            target, merge its corpus,
//!                                            and report coverage
//! ```
//!
//! There is no `kernel` command yet: the kernel-call fuzzer is built once
//! C17's interface library exists (docs/design/build-plan.md).
//!
//! cargo-fuzz is used for `build` only: `cargo fuzz run`, `tmin` and
//! `coverage` write under fuzz/, which is in iCloud in the real checkout.
//! Everything that grows lives under `build/fuzz/`: the fuzz build
//! (`target/`), the seeds and regressions libFuzzer reads (`seeds/<t>/`,
//! `regressions/<t>/`), the corpus (`corpus/<t>/`) and findings
//! (`artifacts/<t>/`), the dictionaries (`dict/targets/<t>.dict`), the
//! logs and run records (`logs/`, `runs/<t>.tsv`), the differential's
//! cases (`differential/<seed>/`), and the coverage build and reports
//! (`target-coverage/`, `coverage/`). libFuzzer is only ever given those
//! directories, so it never reads an iCloud conflict copy.

mod cli {
    pub mod campaign;
    pub mod coverage;
    pub mod differential;
    pub mod nightly;
}

use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, exit},
    time::Instant,
};

use fuzz_gate::{PROBES, TARGETS, Target, harness};

/// Counts the harness's own allocations, so `measure` can read each
/// seed's peak (the targets themselves declare their limits).
#[global_allocator]
static ALLOC: fuzz_alloc::Bounded = fuzz_alloc::Bounded::unlimited();

/// The repository root.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

fn fuzz_build() -> PathBuf {
    root().join("build/fuzz")
}

fn fail(msg: impl AsRef<str>) -> ! {
    eprintln!("xtask fuzz: {}", msg.as_ref());
    exit(1)
}

fn cargo() -> Command {
    let mut c = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.current_dir(root());
    c
}

fn status(cmd: &mut Command) -> ExitStatus {
    cmd.status()
        .unwrap_or_else(|e| fail(format!("{:?}: {e}", cmd.get_program())))
}

fn run_cmd(cmd: &mut Command) {
    let s = status(cmd);
    if !s.success() {
        fail(format!("{cmd:?} failed: {s}"));
    }
}

fn output(cmd: &mut Command) -> String {
    let out = cmd
        .output()
        .unwrap_or_else(|e| fail(format!("{:?}: {e}", cmd.get_program())));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or_default();
    match args.first().map(String::as_str) {
        Some("list") => list(rest),
        Some("install") => install(),
        Some("build") => build(),
        Some("replay") => replay(rest),
        Some("measure") => measure(rest),
        Some("kinds") => kinds(rest),
        Some("run") => cli::campaign::run(rest),
        Some("smoke") => cli::campaign::smoke(rest),
        Some("tmin") => cli::campaign::tmin(rest),
        Some("report") => cli::campaign::report(rest),
        Some("differential") => cli::differential::differential(rest),
        Some("coverage") => cli::coverage::coverage(rest),
        Some("nightly") => cli::nightly::nightly(rest),
        _ => {
            eprintln!(
                "usage: cargo xtask fuzz list|install|build|replay|measure|kinds|run|smoke|tmin|differential|report|coverage|nightly [options]"
            );
            exit(2)
        }
    }
}

/// The targets named on the command line, or all of them.
fn selected(name: Option<&String>) -> Vec<&'static Target> {
    match name {
        None => TARGETS.iter().collect(),
        Some(n) => vec![fuzz_gate::target(n).unwrap_or_else(|| fail(format!("no target {n}")))],
    }
}

/// The targets in `--shard i/n`, or all of them.
pub fn shard_targets(spec: Option<&str>) -> Vec<&'static Target> {
    let Some(spec) = spec else {
        return TARGETS.iter().collect();
    };
    let s = harness::shard(spec)
        .unwrap_or_else(|| fail(format!("--shard {spec}: give i/n, 1 <= i <= n")));
    TARGETS
        .iter()
        .enumerate()
        .filter(|(k, _)| harness::in_shard(*k, s))
        .map(|(_, t)| t)
        .collect()
}

/// `list [--shard i/n] [--names]`. `--names` prints only the names, for a
/// nightly shard's step outputs.
fn list(args: &[String]) {
    let mut spec = None;
    let mut names = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--shard" => spec = it.next().map(String::as_str),
            "--names" => names = true,
            _ => fail("usage: cargo xtask fuzz list [--shard i/n] [--names]"),
        }
    }
    for t in shard_targets(spec) {
        if names {
            println!("{}", t.name);
            continue;
        }
        let grammar = t.grammar.map_or("-".into(), |(g, r)| format!("{g}/{r}"));
        println!(
            "{:<16} {:<9} ADR {:<26} max_len {:>8}  timeout {}s  memory {} MiB  grammar {grammar}  paths {}",
            t.name,
            t.chunk,
            t.adr,
            t.max_len,
            t.timeout_s,
            t.malloc_limit_mb,
            t.paths.join(", ")
        );
    }
}

/// The pinned version of a tool, from fuzz/Cargo.toml.
fn pin(tool: &str) -> String {
    let manifest = fs::read_to_string(root().join("fuzz/Cargo.toml"))
        .unwrap_or_else(|e| fail(format!("fuzz/Cargo.toml: {e}")));
    harness::pin(&manifest, tool)
        .unwrap_or_else(|| fail(format!("fuzz/Cargo.toml pins no {tool}")))
        .to_string()
}

/// The installed version of `cargo <sub>`, if any.
fn installed(sub: &str) -> Option<String> {
    let out = cargo().args([sub, "--version"]).output().ok()?;
    harness::version_of(
        &String::from_utf8_lossy(&out.stdout),
        &format!("cargo-{sub}"),
    )
    .map(String::from)
}

const TOOLS: [&str; 2] = ["fuzz", "deny"];

fn install() {
    for sub in TOOLS {
        let tool = format!("cargo-{sub}");
        let want = pin(&tool);
        if installed(sub).as_deref() == Some(want.as_str()) {
            eprintln!("xtask fuzz: {tool} {want} is installed");
            continue;
        }
        run_cmd(cargo().args(["install", "--locked", &tool, "--version", &want]));
    }
}

/// Fails unless each tool is its pinned version.
fn check_tools() {
    for sub in TOOLS {
        let tool = format!("cargo-{sub}");
        let want = pin(&tool);
        match installed(sub) {
            Some(v) if v == want => {}
            got => fail(format!(
                "{tool} is {}, not {want}: run cargo xtask fuzz install",
                got.as_deref().unwrap_or("missing")
            )),
        }
    }
}

/// The host's target triple, which cargo-fuzz builds for.
fn host() -> String {
    let vv = output(Command::new("rustc").arg("-vV").current_dir(root()));
    harness::host_triple(&vv)
        .unwrap_or_else(|| fail("rustc -vV names no host"))
        .to_string()
}

/// A target's libFuzzer binary.
fn binary(name: &str) -> PathBuf {
    fuzz_build()
        .join("target")
        .join(host())
        .join("release")
        .join(name)
}

/// The files under `dir`, tracked or new, as git lists them: iCloud's
/// conflict copies are ignored, so they never appear.
fn tracked(dir: &str) -> Vec<String> {
    let out = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            dir,
        ])
        .current_dir(root())
        .output()
        .unwrap_or_else(|e| fail(format!("git ls-files: {e}")));
    if !out.status.success() {
        fail("git ls-files failed");
    }
    out.stdout
        .split(|&b| b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).into_owned())
        // A file deleted but still in the index is gone.
        .filter(|p| root().join(p).is_file())
        .collect()
}

/// The committed files of `fuzz/<kind>/<target>/`, by name.
fn committed(kind: &str, t: &str) -> Vec<(String, Vec<u8>)> {
    tracked(&format!("fuzz/{kind}/{t}"))
        .into_iter()
        .map(|p| {
            let bytes = fs::read(root().join(&p)).unwrap_or_else(|e| fail(format!("{p}: {e}")));
            let name = p.rsplit('/').next().unwrap_or(&p).to_string();
            if !harness::valid_name(&name) {
                fail(format!(
                    "{p}: names are lowercase letters, digits, hyphens and dots"
                ));
            }
            (name, bytes)
        })
        .collect()
}

/// Writes `files` into a fresh `dir`, failing on a repeated name or a file
/// over the target's `max_len` (which libFuzzer would truncate).
fn write_dir(t: &Target, dir: &Path, files: &[(String, Vec<u8>)]) {
    if dir.exists() {
        fs::remove_dir_all(dir).unwrap_or_else(|e| fail(format!("{}: {e}", dir.display())));
    }
    fs::create_dir_all(dir).unwrap();
    let mut names = BTreeSet::new();
    for (name, bytes) in files {
        if !names.insert(name) {
            fail(format!("{}: two seeds named {name}", t.name));
        }
        if bytes.len() > t.max_len {
            fail(format!(
                "{}: seed {name} is {} octets, over max_len {}",
                t.name,
                bytes.len(),
                t.max_len
            ));
        }
        fs::write(dir.join(name), bytes).unwrap();
    }
}

pub fn build() {
    // 1. The pinned tools.
    check_tools();

    // 2. The product lock holds no fuzz engine (ADR 0068, rule 3).
    let lock = fs::read_to_string(root().join("Cargo.lock")).unwrap();
    let found = harness::engine_crates_in(&lock);
    if !found.is_empty() {
        fail(format!("Cargo.lock names {}", found.join(", ")));
    }

    // 3. The fuzz lock as committed: cargo-fuzz has no --locked, so this
    //    fails first if the lock would change.
    run_cmd(cargo().args(["fetch", "--locked", "--manifest-path", "fuzz/Cargo.toml"]));

    // 4. The fuzz workspace's licenses and sources.
    run_cmd(cargo().args([
        "deny",
        "--manifest-path",
        "fuzz/Cargo.toml",
        "--workspace",
        "--config",
        "fuzz/deny.toml",
        "check",
        "licenses",
        "bans",
        "sources",
    ]));

    // 5. Every target, with no sanitizer, and never -O: the oracle needs
    //    the debug assertions and overflow checks (ADR 0068, rule 2).
    run_cmd(
        cargo()
            .args(["fuzz", "build", "-s", "none", "--fuzz-dir", "fuzz"])
            .arg("--target-dir")
            .arg(fuzz_build().join("target"))
            .env_remove("RUSTFLAGS"),
    );

    // 6. cargo-fuzz's targets are the table's, and the probes.
    let listed: BTreeSet<String> = output(cargo().args(["fuzz", "list", "--fuzz-dir", "fuzz"]))
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let want: BTreeSet<String> = TARGETS
        .iter()
        .map(|t| t.name)
        .chain(PROBES.iter().copied())
        .map(String::from)
        .collect();
    if listed != want {
        fail(format!(
            "cargo fuzz list gives {listed:?}, but TARGETS and PROBES give {want:?}"
        ));
    }

    // 7. The oracle fires in this build.
    probe();

    // 8. The seeds and regressions libFuzzer reads, and the
    //    dictionaries, under build/. The dictionaries sit in their own
    //    directory, beside C07's per-grammar ones.
    let dicts = fuzz_build().join("dict/targets");
    fs::create_dir_all(&dicts).unwrap();
    for t in TARGETS {
        fs::write(
            dicts.join(format!("{}.dict", t.name)),
            fuzz_gate::dict::render((t.dict)()),
        )
        .unwrap();
        let mut seeds = committed("seeds", t.name);
        seeds.extend((t.seeds)());
        write_dir(t, &fuzz_build().join("seeds").join(t.name), &seeds);
        let regressions = committed("regressions", t.name);
        write_dir(
            t,
            &fuzz_build().join("regressions").join(t.name),
            &regressions,
        );
        eprintln!(
            "xtask fuzz: {}: {} seeds, {} regressions",
            t.name,
            seeds.len(),
            regressions.len()
        );
    }
    eprintln!("xtask fuzz: built {} targets", TARGETS.len());
}

/// Runs the oracle probe on an input, and checks that it crashes with the
/// expected message.
fn probe() {
    let dir = fuzz_build().join("probe");
    fs::create_dir_all(&dir).unwrap();
    for (input, expect) in [
        ("overflow", "attempt to add with overflow"),
        ("debug", "aspis-debug-assertions"),
        ("alloc", "fuzz-alloc: a request of"),
    ] {
        let file = dir.join(input);
        fs::write(&file, input).unwrap();
        let out = Command::new(binary("oracle-probe"))
            .arg(format!("-artifact_prefix={}/", dir.display()))
            .arg(&file)
            .output()
            .unwrap_or_else(|e| fail(format!("oracle-probe: {e}")));
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || !stderr.contains(expect) {
            fail(format!(
                "oracle-probe {input}: expected a crash with \"{expect}\", got {}:\n{stderr}",
                out.status
            ));
        }
    }
    eprintln!("xtask fuzz: overflow checks, debug assertions and the memory bound fire");
}

/// The directories a target replays: its seeds, regressions and corpus,
/// all under build/fuzz/.
pub fn replay_dirs(t: &Target) -> Vec<PathBuf> {
    ["seeds", "regressions", "corpus"]
        .iter()
        .map(|d| fuzz_build().join(d).join(t.name))
        .filter(|d| d.is_dir())
        .collect()
}

fn count(dirs: &[PathBuf]) -> usize {
    dirs.iter()
        .filter_map(|d| fs::read_dir(d).ok())
        .map(|r| r.count())
        .sum()
}

fn replay(args: &[String]) {
    let mut repeat = 1u32;
    let mut pos = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--repeat" {
            repeat = it
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| fail("--repeat takes a count"));
        } else {
            pos.push(a);
        }
    }
    let targets = selected(pos.first().copied());
    let files: Vec<PathBuf> = pos.iter().skip(1).map(PathBuf::from).collect();
    let failed = replay_targets(&targets, &files, repeat);
    if !failed.is_empty() {
        fail(format!("replay failed: {}", failed.join(", ")));
    }
}

/// Replays each target `repeat` times over `files`, or over its seeds,
/// regressions and corpus when `files` is empty. It returns the targets
/// that failed.
pub fn replay_targets(
    targets: &[&'static Target],
    files: &[PathBuf],
    repeat: u32,
) -> Vec<&'static str> {
    let mut failed = Vec::new();
    for t in targets {
        let bin = binary(t.name);
        if !bin.is_file() {
            fail(format!(
                "{} isn't built: run cargo xtask fuzz build",
                bin.display()
            ));
        }
        let inputs = if files.is_empty() {
            replay_dirs(t)
        } else {
            files.to_vec()
        };
        if files.is_empty() && !fuzz_build().join("seeds").join(t.name).is_dir() {
            fail(format!("{}: no seeds: run cargo xtask fuzz build", t.name));
        }
        let artifacts = fuzz_build().join("artifacts").join(t.name);
        fs::create_dir_all(&artifacts).unwrap();
        let n = if files.is_empty() {
            count(&inputs)
        } else {
            files.len()
        };
        for i in 0..repeat {
            let start = Instant::now();
            let s = status(
                Command::new(&bin)
                    .current_dir(root())
                    .arg("-runs=0")
                    .args(harness::libfuzzer_flags(t))
                    .arg(format!("-artifact_prefix={}/", artifacts.display()))
                    .args(&inputs),
            );
            let secs = start.elapsed().as_secs_f64();
            if s.success() {
                eprintln!(
                    "xtask fuzz: replay {}: {n} inputs pass ({secs:.1} s){}",
                    t.name,
                    if repeat > 1 {
                        format!(", run {}/{repeat}", i + 1)
                    } else {
                        String::new()
                    }
                );
            } else {
                failed.push(t.name);
                break;
            }
        }
    }
    failed
}

/// Runs every seed of each target in-process, and prints its slowest
/// seeds and its peak memory: the numbers its timeout and memory bound
/// are set from (C71 stage 1; "The harness").
fn measure(args: &[String]) {
    let corpus = args.iter().any(|a| a == "--corpus");
    let name = args.iter().find(|a| !a.starts_with("--"));
    for t in selected(name) {
        let mut seeds = committed("seeds", t.name);
        seeds.extend((t.seeds)());
        seeds.extend(committed("regressions", t.name));
        // `--corpus` adds the corpus, to see where a campaign's time goes.
        let dir = fuzz_build().join("corpus").join(t.name);
        if corpus && let Ok(entries) = fs::read_dir(&dir) {
            for e in entries.filter_map(Result::ok) {
                if let Ok(b) = fs::read(e.path()) {
                    seeds.push((format!("corpus/{}", e.file_name().to_string_lossy()), b));
                }
            }
        }
        let mut times = Vec::new();
        let mut peak = (0usize, String::new());
        for (name, bytes) in &seeds {
            fuzz_alloc::reset_peak();
            let base = fuzz_alloc::live();
            let start = Instant::now();
            (t.run)(bytes);
            let secs = start.elapsed().as_secs_f64();
            let p = fuzz_alloc::peak().saturating_sub(base);
            if p > peak.0 {
                peak = (p, name.clone());
            }
            times.push((secs, name.clone()));
        }
        times.sort_by(|a, b| b.0.total_cmp(&a.0));
        let total: f64 = times.iter().map(|t| t.0).sum();
        let top: f64 = times.iter().take(times.len() / 10).map(|t| t.0).sum();
        let slowest: Vec<String> = times
            .iter()
            .take(3)
            .map(|(s, n)| format!("{n} {:.0} ms", s * 1000.0))
            .collect();
        println!(
            "{}: {} inputs, {:.1} ms on average, {:.0} % of the time in the slowest tenth; slowest {}; peak {:.1} MiB ({}); limits {} s, {} MiB",
            t.name,
            seeds.len(),
            1000.0 * total / seeds.len().max(1) as f64,
            100.0 * top / total.max(1e-12),
            slowest.join(", "),
            peak.0 as f64 / f64::from(1u32 << 20),
            peak.1,
            t.timeout_s,
            t.malloc_limit_mb
        );
    }
}

/// Prints the error kinds each target's seeds and regressions reach,
/// against its table ("The gate for each target", item 4). `--each`
/// prints every seed's kinds too.
fn kinds(args: &[String]) {
    let each = args.iter().any(|a| a == "--each");
    let name = args.iter().find(|a| !a.starts_with("--"));
    let mut missing_any = false;
    for t in selected(name) {
        let mut seeds = committed("seeds", t.name);
        seeds.extend((t.seeds)());
        seeds.extend(committed("regressions", t.name));
        let mut reached = BTreeSet::new();
        for (name, bytes) in &seeds {
            let k = (t.kinds_of)(bytes);
            if each {
                println!("{} {name}: {}", t.name, k.join(" "));
            }
            reached.extend(k);
        }
        let missing: Vec<&str> = t
            .kinds
            .iter()
            .copied()
            .filter(|k| !reached.contains(k))
            .collect();
        missing_any |= !missing.is_empty();
        println!(
            "{}: {}/{} kinds reached{}",
            t.name,
            t.kinds.len() - missing.len(),
            t.kinds.len(),
            if missing.is_empty() {
                String::new()
            } else {
                format!("; missing {}", missing.join(", "))
            }
        );
    }
    if missing_any {
        exit(1);
    }
}
