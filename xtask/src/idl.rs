// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `cargo xtask idl [--write]`: `idlc check` over every IDL file under the
//! interface roots (ADR 0067, rules 7 and 9). It checks each file at its
//! version, its lock (each published minor's hash, and the step from each
//! minor to the next), and that every generated grammar and vector file is
//! what idlc generates now. `--write` regenerates them, and creates a lock
//! with no entries for a file that has none.
//!
//! It also checks that `crates/idl-rt/src/rpc/v1.rs`, `aspis.rpc`'s
//! binding, is what `idlc rust --runtime` generates now; `--write`
//! regenerates it. idlc builds idl-rt without that binding, so a stale one
//! never stops the regeneration.
//!
//! The files come from git, tracked or new, so iCloud's conflict copies
//! never reach idlc. A minor is published with `cargo run -p idlc -- lock
//! FILE`, which appends its hash to the lock.

use std::{env, fs, process::Command};

use crate::{fail, grammars, root, run_cmd};

/// The committed binding of `aspis.rpc`, and its source.
const RPC_RS: &str = "crates/idl-rt/src/rpc/v1.rs";
const RPC_IDL: &str = "interfaces/aspis/rpc/v1.idl";

pub fn check(write: bool) {
    let files: Vec<String> = grammars::tracked(&grammars::INTERFACE_ROOTS)
        .into_iter()
        .filter(|p| {
            p.rsplit('/').next().is_some_and(|n| {
                n.strip_prefix('v')
                    .and_then(|r| r.strip_suffix(".idl"))
                    .is_some_and(|m| !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()))
            })
        })
        .collect();
    if files.is_empty() {
        fail("no IDL files under the interface roots");
    }
    let mut cmd = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir(root())
        .args(["run", "--locked", "-q", "-p", "idlc", "--", "check"]);
    if write {
        cmd.arg("--write");
    }
    for r in grammars::INTERFACE_ROOTS {
        cmd.args(["--root", r]);
    }
    cmd.args(["--grammars", "grammars"]).args(&files);
    run_cmd(&mut cmd);
    rpc_binding(write);
    eprintln!("xtask: interfaces, locks, generated grammars and the rpc binding are current");
}

/// Compares (or, with `write`, rewrites) idl-rt's `aspis.rpc` binding.
fn rpc_binding(write: bool) {
    let out = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .current_dir(root())
        .args([
            "run",
            "--locked",
            "-q",
            "-p",
            "idlc",
            "--",
            "rust",
            "--runtime",
        ])
        .args(["--root", "interfaces", RPC_IDL])
        .output()
        .unwrap_or_else(|e| fail(format!("idlc: {e}")));
    if !out.status.success() {
        eprint!("{}", String::from_utf8_lossy(&out.stdout));
        eprint!("{}", String::from_utf8_lossy(&out.stderr));
        fail("idlc rust failed");
    }
    let path = root().join(RPC_RS);
    if write {
        fs::write(&path, &out.stdout).unwrap_or_else(|e| fail(format!("{RPC_RS}: {e}")));
        return;
    }
    if fs::read(&path).ok().as_deref() != Some(&out.stdout[..]) {
        fail(format!(
            "{RPC_RS} differs from what idlc generates; run cargo xtask idl --write"
        ));
    }
}
