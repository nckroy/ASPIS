// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `idlc` end to end (ADR 0067, rule 7; docs/design/call-language.md,
//! "The lock and the canonical form"): the repository's files check; an
//! edited published minor, a bad lock and a stale generated file fail;
//! `lock` publishes once; `check --write` makes a new file's lock and
//! generated files.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Runs idlc; returns whether it succeeded, and its output.
fn idlc(args: &[&str], roots: &[&Path]) -> (bool, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_idlc"));
    cmd.arg(args[0]);
    for r in roots {
        cmd.arg("--root").arg(r);
    }
    cmd.arg("--grammars").arg(repo().join("grammars"));
    cmd.args(&args[1..]);
    let out = cmd.output().unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), text)
}

/// A fresh copy of the catalog example under a root of its own.
fn catalog_copy(name: &str) -> (PathBuf, PathBuf) {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&root);
    let dir = root.join("aspis/catalog");
    fs::create_dir_all(&dir).unwrap();
    for e in fs::read_dir(repo().join("interfaces/aspis/catalog")).unwrap() {
        let e = e.unwrap();
        fs::copy(e.path(), dir.join(e.file_name())).unwrap();
    }
    (root, dir.join("v1.idl"))
}

#[test]
fn the_repositorys_files_check() {
    let roots = [
        repo().join("interfaces"),
        repo().join("crates/idl/tests/data/interfaces"),
    ];
    let roots: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
    let (ok, out) = idlc(&["check"], &roots);
    assert!(ok, "{out}");
    assert!(
        out.contains("ok   ") && out.contains("org.example.kinds/1.2"),
        "{out}"
    );
}

#[test]
fn an_edited_published_minor_fails() {
    let (root, idl) = catalog_copy("edited");
    let src = fs::read_to_string(&idl).unwrap();
    // withdrawn is in 1.0, which the lock publishes.
    fs::write(&idl, src.replace("withdrawn = 2", "retired = 2")).unwrap();
    let (ok, out) = idlc(&["check", idl.to_str().unwrap()], &[&root]);
    assert!(!ok);
    assert!(out.contains("a published minor changed"), "{out}");
}

#[test]
fn bad_locks_fail() {
    let (root, idl) = catalog_copy("locks");
    let lock = idl.with_extension("idl.lock");
    let text = fs::read_to_string(&lock).unwrap();
    // A gap: minor 1 without minor 0.
    fs::write(&lock, text.replace("1.0 sha3-256", "1.1 sha3-256")).unwrap();
    let (ok, out) = idlc(&["check", idl.to_str().unwrap()], &[&root]);
    assert!(!ok);
    assert!(out.contains("expected minor 1.0"), "{out}");
    // Nothing published, so the version can only be 1.0.
    let empty: String = text
        .lines()
        .filter(|l| l.starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect();
    fs::write(&lock, empty).unwrap();
    let (ok, out) = idlc(&["check", idl.to_str().unwrap()], &[&root]);
    assert!(!ok);
    assert!(
        out.contains("the version is the newest published minor"),
        "{out}"
    );
}

#[test]
fn a_stale_generated_file_fails() {
    let (root, idl) = catalog_copy("stale");
    let dir = idl.parent().unwrap();
    fs::write(dir.join("v1.5.abnf"), "x = %x00\n").unwrap();
    let (ok, out) = idlc(&["check", idl.to_str().unwrap()], &[&root]);
    assert!(!ok);
    assert!(
        out.contains("v1.5.abnf: error: a generated file for no minor"),
        "{out}"
    );
    // An edited generated file fails too.
    fs::remove_file(dir.join("v1.5.abnf")).unwrap();
    let g = dir.join("v1.1.vectors");
    let text = fs::read_to_string(&g).unwrap();
    fs::write(&g, text.replacen("ok@", "err@", 1)).unwrap();
    let (ok, out) = idlc(&["check", idl.to_str().unwrap()], &[&root]);
    assert!(!ok);
    assert!(out.contains("differs from what idlc generates"), "{out}");
}

#[test]
fn lock_publishes_once() {
    let (root, idl) = catalog_copy("publish");
    let lock = idl.with_extension("idl.lock");
    let before = fs::read_to_string(&lock).unwrap();
    let (ok, out) = idlc(&["lock", idl.to_str().unwrap()], &[&root]);
    assert!(ok, "{out}");
    assert!(out.contains("published 1.1"), "{out}");
    let after = fs::read_to_string(&lock).unwrap();
    assert!(after.starts_with(&before) && after.lines().count() == before.lines().count() + 1);
    let (ok, out) = idlc(&["lock", idl.to_str().unwrap()], &[&root]);
    assert!(ok, "{out}");
    assert!(out.contains("already published"), "{out}");
    assert_eq!(fs::read_to_string(&lock).unwrap(), after);
    // The published hash is the canonical form's.
    let (ok, canon) = idlc(&["canon", idl.to_str().unwrap(), "1"], &[&root]);
    assert!(ok && canon.starts_with("edition 2026;\n"), "{canon}");
}

#[test]
fn check_write_makes_a_new_files_lock_and_grammars() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("new");
    let _ = fs::remove_dir_all(&root);
    let dir = root.join("org/example/tiny");
    fs::create_dir_all(&dir).unwrap();
    let idl = dir.join("v1.idl");
    fs::write(
        &idl,
        "// SPDX-FileCopyrightText: 2026 Example\n// SPDX-License-Identifier: Apache-2.0\n\
         edition 2026;\n\
         [id(org.example.tiny), object_id(hex(00000000000000000000000000000000000000000000000000000000000000d1)), version(1.0)]\n\
         interface tiny {\n    @1 echo(x: string<8>) -> string<8>;\n}\n",
    )
    .unwrap();
    let (ok, _) = idlc(&["check", idl.to_str().unwrap()], &[&root]);
    assert!(!ok, "no lock yet");
    let (ok, out) = idlc(&["check", "--write", idl.to_str().unwrap()], &[&root]);
    assert!(ok, "{out}");
    let (ok, out) = idlc(&["check", idl.to_str().unwrap()], &[&root]);
    assert!(ok, "{out}");
    // The generated files carry the IDL file's own notice.
    let g = fs::read_to_string(dir.join("v1.0.abnf")).unwrap();
    assert!(g.starts_with(
        "; SPDX-FileCopyrightText: 2026 Example\n; SPDX-License-Identifier: Apache-2.0\n; uses: core\n"
    ));
    assert!(dir.join("v1.0.text.vectors").exists() && dir.join("v1.idl.lock").exists());
    // A walk of the root finds the file when none is named.
    let (ok, out) = idlc(&["build"], &[&root]);
    assert!(ok && out.contains("org.example.tiny/1.0"), "{out}");
}

/// `x.v1` and `x` major 1 would share the Rust module `x::v1`: each is
/// refused while the other is under the roots.
#[test]
fn a_module_path_clash_fails() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("clash");
    let _ = fs::remove_dir_all(&root);
    let tiny = |name: &str, last: &str, id: &str| {
        format!(
            "// SPDX-FileCopyrightText: 2026 Example\n// SPDX-License-Identifier: Apache-2.0\n\
             edition 2026;\n\
             [id({name}), object_id(hex({id})), version(1.0)]\n\
             interface {last} {{\n    @1 echo(x: string<8>) -> string<8>;\n}}\n"
        )
    };
    let id = |b: &str| format!("{}{b}", "0".repeat(62));
    let parent = root.join("org/example/v1.idl");
    let child = root.join("org/example/v1/v1.idl");
    fs::create_dir_all(child.parent().unwrap()).unwrap();
    fs::write(&parent, tiny("org.example", "example", &id("e1"))).unwrap();
    fs::write(&child, tiny("org.example.v1", "v1", &id("e2"))).unwrap();
    for f in [&parent, &child] {
        let (ok, out) = idlc(&["build", f.to_str().unwrap()], &[&root]);
        assert!(!ok, "{out}");
        assert!(out.contains("rename one"), "{out}");
    }
    // Alone, each is fine.
    fs::remove_file(&parent).unwrap();
    let (ok, out) = idlc(&["build", "--write", child.to_str().unwrap()], &[&root]);
    assert!(ok, "{out}");
}
