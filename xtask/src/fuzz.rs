// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `cargo xtask fuzz <command>`: forwards to the fuzzing harness, the
//! `fuzz-gate` binary in the `fuzz/` workspace (ADR 0068;
//! docs/design/call-language.md, "The harness").
//!
//! The harness, the target table and the seeds live in `fuzz/`, a separate
//! workspace, so nothing about fuzzing enters this workspace or its lock
//! file (ADR 0068, rule 3). Its host builds go to `build/fuzz/target-host`.

use std::{
    env,
    path::PathBuf,
    process::{Command, exit},
};

use crate::{build_dir, fail, root};

/// The fuzz workspace's manifest.
pub const MANIFEST: &str = "fuzz/Cargo.toml";

/// The target directory for the fuzz workspace's host builds: the harness,
/// its tests and clippy.
pub fn host_target_dir() -> PathBuf {
    build_dir().join("fuzz/target-host")
}

/// `cargo` in the repository root, for the fuzz workspace.
pub fn cargo() -> Command {
    let mut c = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.current_dir(root());
    c
}

/// Runs the harness with `args`, and exits with its status.
pub fn run(args: &[String]) -> ! {
    let status = cargo()
        .args(["run", "--locked", "--quiet", "--manifest-path", MANIFEST])
        .args(["-p", "fuzz-gate", "--target-dir"])
        .arg(host_target_dir())
        .arg("--")
        .args(args)
        .status()
        .unwrap_or_else(|e| fail(format!("cargo run -p fuzz-gate: {e}")));
    exit(status.code().unwrap_or(1))
}
