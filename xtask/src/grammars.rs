// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `cargo xtask grammars`: every grammar in `grammars/` and its vectors,
//! through the Rust checker, `crates/abnf` (ADR 0062, rule 8; ADR 0013,
//! rule 6). CI runs it on every change, documents included, beside the
//! Python checker.
//!
//! It also checks that `grammars/core.abnf` is byte for byte the block in
//! docs/design/call-language.md ("The core grammar"), so the note and the
//! file can't drift apart.

use std::{collections::BTreeSet, fs, process::Command};

use abnf::{Grammar, Kind, LoadOptions, vectors};

use crate::{fail, root};

/// The files under `grammars/`, tracked or new. Listing them with git
/// skips iCloud's conflict copies, which `.gitignore` excludes.
fn tracked() -> BTreeSet<String> {
    let out = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .args(["--", "grammars"])
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
        .collect()
}

/// The abnf block under "### The core grammar" in the call-language note.
fn core_in_note() -> Option<String> {
    let note = fs::read_to_string(root().join("docs/design/call-language.md")).ok()?;
    let mut lines = note
        .lines()
        .skip_while(|l| *l != "### The core grammar")
        .skip_while(|l| *l != "```abnf")
        .skip(1);
    let mut block = String::new();
    for l in lines.by_ref() {
        if l == "```" {
            return Some(block);
        }
        block.push_str(l);
        block.push('\n');
    }
    None
}

/// Checks every grammar and its vectors, and fails if any disagree.
pub fn check() {
    let files = tracked();
    let mut failed = false;

    let core = fs::read(root().join("grammars/core.abnf")).unwrap_or_default();
    match core_in_note() {
        Some(block) if block.as_bytes() == core => {}
        Some(_) => {
            println!(
                "FAIL grammars/core.abnf: differs from the block in docs/design/call-language.md"
            );
            failed = true;
        }
        None => {
            println!("FAIL docs/design/call-language.md: no abnf block under \"The core grammar\"");
            failed = true;
        }
    }

    let grammars: Vec<&String> = files.iter().filter(|p| p.ends_with(".abnf")).collect();
    if grammars.is_empty() {
        fail("no grammars in grammars/");
    }
    for path in grammars {
        let name = path
            .trim_start_matches("grammars/")
            .trim_end_matches(".abnf");
        let text = fs::read(root().join(path)).unwrap_or_else(|e| fail(format!("{path}: {e}")));
        let opts = LoadOptions {
            kind: if name == "core" {
                Kind::Core
            } else {
                Kind::Auto
            },
            ..LoadOptions::default()
        };
        // A used grammar is a tracked file beside this one.
        let mut resolve = |used: &str| {
            let p = format!("grammars/{used}.abnf");
            files
                .contains(&p)
                .then(|| fs::read(root().join(&p)).ok())
                .flatten()
        };
        let g = match Grammar::load(name, &text, &mut resolve, &opts) {
            Ok(g) => g,
            Err(e) => {
                println!("FAIL grammars/{}.abnf:{}: {}", e.file, e.line, e.kind);
                failed = true;
                continue;
            }
        };
        let prose = match g.prose_constraints() {
            0 => String::new(),
            n => format!(" ({n} prose constraints, not checked)"),
        };
        let vpath = format!("grammars/{name}.vectors");
        if !files.contains(&vpath) {
            println!("ok   {path}: loads (no vectors){prose}");
            continue;
        }
        let vtext = fs::read(root().join(&vpath)).unwrap_or_else(|e| fail(format!("{vpath}: {e}")));
        let vf = match vectors::parse(&vtext) {
            Ok(vf) => vf,
            Err(e) => {
                println!("FAIL {vpath}:{e}");
                failed = true;
                continue;
            }
        };
        let report = vectors::check(&g, &vf);
        for (line, verdict) in &report.results {
            let tag = vf
                .vectors
                .iter()
                .find(|v| v.line == *line)
                .map_or("?", |v| match v.tag {
                    vectors::Tag::Ok => "ok",
                    vectors::Tag::Err => "err",
                    vectors::Tag::Errc => "errc",
                });
            let why = match *verdict {
                vectors::Verdict::Agrees => continue,
                vectors::Verdict::Disagrees {
                    context_free,
                    constrained,
                } => match (tag, context_free, constrained) {
                    (_, false, _) => "but the grammar rejects it".to_string(),
                    ("err", true, false) => {
                        "but the grammar accepts it, and only a constraint rejects it".to_string()
                    }
                    ("err", true, true) => "but the grammar accepts it".to_string(),
                    (_, true, false) => "but it breaks a constraint".to_string(),
                    (_, true, true) => "but it keeps every constraint".to_string(),
                },
                vectors::Verdict::Exhausted(e) => format!("but {e}"),
                vectors::Verdict::UnknownRule => "but the grammar has no such rule".to_string(),
            };
            println!("FAIL {vpath}:{line}: {tag}, {why}");
        }
        let errc = match report.errc {
            0 => String::new(),
            n => format!(" ({n} errc)"),
        };
        let status = if report.disagree == 0 { "ok  " } else { "FAIL" };
        // The check stops at the first vector over a budget.
        let unjudged = match report.unjudged {
            0 => String::new(),
            n => format!(", {n} not judged"),
        };
        println!(
            "{status} {path}: {} vectors agree{errc}, {} disagree{unjudged}{prose}",
            report.agree, report.disagree
        );
        failed |= report.disagree > 0;
    }
    if failed {
        fail("grammars disagree with their vectors");
    }
    eprintln!("xtask: grammars agree with their vectors");
}
