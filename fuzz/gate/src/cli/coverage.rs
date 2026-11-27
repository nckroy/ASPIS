// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `coverage`: the coverage report a chunk's pull request reviews
//! (ADR 0068, rule 5; docs/design/call-language.md, "The gate for each
//! target", item 5, and "The harness").
//!
//! It does what `cargo fuzz coverage` does, but keeps everything under
//! `build/fuzz/`: `cargo fuzz coverage` writes under `fuzz/`, which is in
//! iCloud in the real checkout.
//!
//! 1. `cargo fuzz build -s none` with `RUSTFLAGS=-Cinstrument-coverage`,
//!    into `build/fuzz/target-coverage/`;
//! 2. each target's binary once over its seeds, regressions and corpus
//!    (`-runs=0`), writing `build/fuzz/coverage/<t>/raw/*.profraw`;
//! 3. `llvm-profdata merge -sparse`, from the pinned `llvm-tools`
//!    component;
//! 4. `llvm-cov report` (`report.txt`), `export -summary-only`
//!    (`summary.json`) and `show -format=html` (`html/`), on the `src/`
//!    of the target's crates only;
//! 5. one table for all of them, printed and written to
//!    `build/fuzz/coverage/summary.md`.
//!
//! Lines, regions and functions are counted. Branch coverage needs an
//! unstable `-Z` option, so it isn't.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use fuzz_gate::{
    Target,
    harness::{self, Coverage},
};

use crate::{cargo, fail, fuzz_build, host, output, replay_dirs, root, run_cmd, selected};

/// The coverage build's directory.
fn target_dir() -> PathBuf {
    fuzz_build().join("target-coverage")
}

/// The pinned toolchain's LLVM tools (`llvm-tools` in
/// rust-toolchain.toml).
fn llvm_tool(name: &str) -> PathBuf {
    let sysroot = output(
        Command::new("rustc")
            .args(["--print", "sysroot"])
            .current_dir(root()),
    );
    let p = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(host())
        .join("bin")
        .join(name);
    if !p.is_file() {
        fail(format!(
            "{} is missing: rust-toolchain.toml's llvm-tools component provides it",
            p.display()
        ));
    }
    p
}

/// Builds every target with coverage instrumentation.
fn build() {
    run_cmd(
        cargo()
            .args(["fuzz", "build", "-s", "none", "--fuzz-dir", "fuzz"])
            .arg("--target-dir")
            .arg(target_dir())
            .env("RUSTFLAGS", "-Cinstrument-coverage"),
    );
}

/// One target's coverage, or why there is none.
fn one(t: &Target) -> Result<Coverage, String> {
    let dir = fuzz_build().join("coverage").join(t.name);
    if dir.exists() {
        fs::remove_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let raw = dir.join("raw");
    fs::create_dir_all(&raw).unwrap();
    let bin = target_dir().join(host()).join("release").join(t.name);
    let inputs = replay_dirs(t);
    if inputs.is_empty() {
        return Err("no seeds: run cargo xtask fuzz build".into());
    }
    let s = Command::new(&bin)
        .current_dir(root())
        .arg("-runs=0")
        .args(harness::libfuzzer_flags(t))
        .arg(format!("-artifact_prefix={}/", dir.display()))
        .args(&inputs)
        .env("LLVM_PROFILE_FILE", raw.join("%m_%p.profraw"))
        .output()
        .map_err(|e| format!("{}: {e}", bin.display()))?;
    if !s.status.success() {
        return Err(format!(
            "the instrumented replay failed ({}); run cargo xtask fuzz replay {}",
            s.status, t.name
        ));
    }
    let profraw: Vec<PathBuf> = fs::read_dir(&raw)
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "profraw"))
        .collect();
    if profraw.is_empty() {
        return Err("the replay wrote no profile".into());
    }
    let profdata = dir.join("merged.profdata");
    let merged = Command::new(llvm_tool("llvm-profdata"))
        .args(["merge", "-sparse"])
        .args(&profraw)
        .arg("-o")
        .arg(&profdata)
        .status()
        .map_err(|e| e.to_string())?;
    if !merged.success() {
        return Err(format!("llvm-profdata merge failed: {merged}"));
    }
    let sources: Vec<PathBuf> = harness::coverage_dirs(t)
        .iter()
        .map(|d| root().join(d))
        .collect();
    let cov = |sub: &str, extra: &[&str]| {
        let mut c = Command::new(llvm_tool("llvm-cov"));
        c.arg(sub)
            .arg(&bin)
            .arg(format!("-instr-profile={}", profdata.display()))
            .args(extra)
            .args(&sources);
        c
    };
    let report = output(&mut cov("report", &["-show-branch-summary=false"]));
    fs::write(dir.join("report.txt"), &report).unwrap();
    let json = output(&mut cov("export", &["-summary-only"]));
    fs::write(dir.join("summary.json"), json).unwrap();
    let html = dir.join("html");
    let shown = cov(
        "show",
        &["-format=html", &format!("-output-dir={}", html.display())],
    )
    .status()
    .map_err(|e| e.to_string())?;
    if !shown.success() {
        return Err(format!("llvm-cov show failed: {shown}"));
    }
    harness::coverage_totals(&report)
        .ok_or_else(|| format!("llvm-cov report gave no totals:\n{report}"))
}

/// A crate's coverage over every target in `covering`: their merged
/// profiles, with all their binaries, written to
/// `build/fuzz/coverage/crates/<crate>/report.txt`.
fn union(src: &str, covering: &[&Target]) -> Result<Coverage, String> {
    let name = src.trim_end_matches("/src").replace('/', "-");
    let dir = fuzz_build().join("coverage/crates").join(name);
    fs::create_dir_all(&dir).unwrap();
    let profdata = dir.join("merged.profdata");
    let merged = Command::new(llvm_tool("llvm-profdata"))
        .args(["merge", "-sparse"])
        .args(covering.iter().map(|t| {
            fuzz_build()
                .join("coverage")
                .join(t.name)
                .join("merged.profdata")
        }))
        .arg("-o")
        .arg(&profdata)
        .status()
        .map_err(|e| e.to_string())?;
    if !merged.success() {
        return Err(format!("llvm-profdata merge failed: {merged}"));
    }
    let bins = covering
        .iter()
        .map(|t| target_dir().join(host()).join("release").join(t.name));
    let mut cmd = Command::new(llvm_tool("llvm-cov"));
    cmd.arg("report");
    for (i, b) in bins.enumerate() {
        if i > 0 {
            cmd.arg("-object");
        }
        cmd.arg(b);
    }
    let report = output(
        cmd.arg(format!("-instr-profile={}", profdata.display()))
            .arg("-show-branch-summary=false")
            .arg(root().join(src)),
    );
    fs::write(dir.join("report.txt"), &report).unwrap();
    harness::coverage_totals(&report)
        .ok_or_else(|| format!("llvm-cov report gave no totals:\n{report}"))
}

/// Measures `targets`' coverage, and writes the summary table. It returns
/// the targets whose coverage couldn't be measured.
pub fn coverage_of(targets: &[&'static Target]) -> Vec<&'static str> {
    build();
    let mut table =
        String::from("| Target | Crates | Lines | Regions | Functions |\n|---|---|---|---|---|\n");
    let mut failed = Vec::new();
    for t in targets {
        match one(t) {
            Ok(c) => {
                eprintln!(
                    "xtask fuzz: coverage {}: lines {:.1} %, regions {:.1} %, functions {:.1} %",
                    t.name,
                    c.lines_percent(),
                    c.regions_percent(),
                    c.functions_percent()
                );
                table.push_str(&format!(
                    "| `{}` | {} | {:.1} % ({}/{}) | {:.1} % ({}/{}) | {:.1} % ({}/{}) |\n",
                    t.name,
                    harness::coverage_dirs(t)
                        .iter()
                        .map(|d| format!("`{d}`"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    c.lines_percent(),
                    c.lines - c.lines_missed,
                    c.lines,
                    c.regions_percent(),
                    c.regions - c.regions_missed,
                    c.regions,
                    c.functions_percent(),
                    c.functions - c.functions_missed,
                    c.functions,
                ));
            }
            Err(e) => {
                eprintln!("xtask fuzz: coverage {}: {e}", t.name);
                table.push_str(&format!("| `{}` | | not measured | | |\n", t.name));
                failed.push(t.name);
            }
        }
    }
    // Each crate's coverage over every target that covers it: the
    // targets' profiles merged, and their binaries reported together.
    let mut crates: Vec<String> = targets
        .iter()
        .filter(|t| !failed.contains(&t.name))
        .flat_map(|t| harness::coverage_dirs(t))
        .collect();
    crates.sort();
    crates.dedup();
    table.push_str("\n| Crate | Targets | Lines | Regions | Functions |\n|---|---|---|---|---|\n");
    for c in &crates {
        let covering: Vec<&Target> = targets
            .iter()
            .copied()
            .filter(|t| !failed.contains(&t.name) && harness::coverage_dirs(t).contains(c))
            .collect();
        match union(c, &covering) {
            Ok(v) => table.push_str(&format!(
                "| `{c}` | {} | {:.1} % ({}/{}) | {:.1} % ({}/{}) | {:.1} % ({}/{}) |\n",
                covering.len(),
                v.lines_percent(),
                v.lines - v.lines_missed,
                v.lines,
                v.regions_percent(),
                v.regions - v.regions_missed,
                v.regions,
                v.functions_percent(),
                v.functions - v.functions_missed,
                v.functions,
            )),
            Err(e) => {
                eprintln!("xtask fuzz: coverage of {c}: {e}");
                table.push_str(&format!(
                    "| `{c}` | {} | not measured | | |\n",
                    covering.len()
                ));
            }
        }
    }
    fs::create_dir_all(fuzz_build().join("coverage")).unwrap();
    let summary = fuzz_build().join("coverage/summary.md");
    fs::write(&summary, &table).unwrap();
    print!("{table}");
    eprintln!(
        "xtask fuzz: coverage reports in {}",
        fuzz_build().join("coverage").display()
    );
    failed
}

/// `coverage [<target>...]`.
pub fn coverage(args: &[String]) {
    let targets: Vec<&'static Target> = if args.is_empty() {
        selected(None)
    } else {
        args.iter().flat_map(|a| selected(Some(a))).collect()
    };
    let failed = coverage_of(&targets);
    if !failed.is_empty() {
        fail(format!("coverage not measured: {}", failed.join(", ")));
    }
}
