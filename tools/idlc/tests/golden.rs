// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `idlc rust` against golden files: the generated bindings of the
//! catalog and eventcount examples, so a change to the Rust back end shows
//! in review as a change to these files (docs/design/call-language.md,
//! "Crates": tests are golden files and round trips). `IDLC_BLESS=1`
//! rewrites them.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn golden(idl: &str, name: &str) {
    let out = Command::new(env!("CARGO_BIN_EXE_idlc"))
        .arg("rust")
        .arg("--root")
        .arg(repo().join("interfaces"))
        .arg(repo().join(idl))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.rs"));
    if env::var_os("IDLC_BLESS").is_some() {
        fs::write(&path, &out.stdout).unwrap();
    }
    let want = fs::read(&path).unwrap_or_default();
    assert!(
        out.stdout == want,
        "{} differs from what idlc generates; run with IDLC_BLESS=1 to rewrite it",
        path.display()
    );
}

#[test]
fn catalog() {
    golden("interfaces/aspis/catalog/v1.idl", "catalog");
}

#[test]
fn eventcount() {
    golden("interfaces/aspis/kernel/eventcount/v1.idl", "eventcount");
}

#[test]
fn the_runtime_flavor_is_idl_rts_copy() {
    let out = Command::new(env!("CARGO_BIN_EXE_idlc"))
        .args(["rust", "--runtime", "--root"])
        .arg(repo().join("interfaces"))
        .arg(repo().join("interfaces/aspis/rpc/v1.idl"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let committed = fs::read(repo().join("crates/idl-rt/src/rpc/v1.rs")).unwrap();
    assert!(
        out.stdout == committed,
        "crates/idl-rt/src/rpc/v1.rs is stale; run cargo xtask idl --write"
    );
}
