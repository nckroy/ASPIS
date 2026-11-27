// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The most minors a major may have, at their most costly (docs/design/
//! call-language.md, "Types", Limits): `version(M.m)` names m up to
//! 1,023, because idlc and the catalog do work for each minor. The worst
//! case an earlier review built, a 1 MB file whose projection changes at
//! every minor, retargeted to 1,023 changing minors with a lock of 1,023
//! published minors, builds and checks in bounded time.

use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Runs idlc over `root`; returns whether it succeeded, its output, and
/// how long it took.
fn idlc(cmd: &str, write: bool, root: &Path) -> (bool, String, Duration) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_idlc"));
    c.arg(cmd);
    if write {
        c.arg("--write");
    }
    c.arg("--root")
        .arg(root)
        .arg("--grammars")
        .arg(repo().join("grammars"));
    let start = Instant::now();
    let out = c.output().unwrap();
    let took = start.elapsed();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), text, took)
}

/// The review's case: a closed enum of 4096 values with 60-character
/// names, then six enums of 4000 values each, whose values come one
/// after another in 24,000 steps. Here the steps fall on the minors 1 to
/// 1,023, so the projection changes at every one of them.
fn worst_case(version: &str) -> String {
    let mut s = String::from(
        "// SPDX-FileCopyrightText: 2026 Nicole Roy\n// SPDX-License-Identifier: MPL-2.0\nedition 2026;\n",
    );
    writeln!(
        s,
        "[id(org.example.x), object_id(hex({}a1)), version({version})]\ninterface x {{",
        "0".repeat(62)
    )
    .unwrap();
    s += "[closed] enum big: u16 { ";
    for i in 1..=4096 {
        let n = i.to_string();
        write!(s, "{}{n} = {i}, ", "v".repeat(60 - n.len())).unwrap();
    }
    s += "}\n";
    for j in 0..6u32 {
        write!(s, "enum s{j}: u16 {{ z = 0, ").unwrap();
        for i in 1..=4000u32 {
            let k = 4000 * j + i;
            let minor = (k * 1023).div_ceil(24_000);
            write!(s, "[since(1.{minor})] v{i} = {i}, ").unwrap();
        }
        s += "}\n";
    }
    s += "@1 m(a: u8) -> u8;\n}\n";
    s
}

/// A debug build on a laptop takes about 11 s to build it and 21 s to
/// check it; CI's runners are slower, so the bound leaves room. Before the
/// limit, the review's 24,000 minors took minutes to build and over 28
/// minutes to check.
#[test]
fn the_most_minors_build_and_check_in_bounded_time() {
    let src = worst_case("1.1023");
    assert!(src.len() > 900_000, "{}", src.len());
    let mut none = |_: &idl_rt::names::InterfaceRef<'_>| None;
    let c = idl::check(src.as_bytes(), &mut none, &idl::Limits::default())
        .unwrap_or_else(|d| panic!("{d:?}"));
    let changes = idl::project::changes(c.file(), 1);
    assert_eq!(changes.len(), 1023);
    // A lock of the 1,023 minors 0 to 1,022, so 1.1023 is in development.
    let mut lock = String::from(
        "# SPDX-FileCopyrightText: 2026 Nicole Roy\n# SPDX-License-Identifier: MPL-2.0\n# org.example.x/1: the most minors.\n",
    );
    let mut last: Option<(idl::ast::File, Vec<String>)> = None;
    for m in 0..idl::MAX_MINOR {
        let p = idl::project::project(c.file(), m);
        let (text, lines) =
            idl::canon::canonical_reusing(&p, last.as_ref().map(|(f, l)| (f, l.as_slice())));
        let h = idl::hash::sha3_256(text.as_bytes());
        writeln!(lock, "1.{m} sha3-256 {}", idl::lock::hex(&h)).unwrap();
        last = Some((p, lines));
    }
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("most-minors");
    let _ = fs::remove_dir_all(&root);
    let dir = root.join("org/example/x");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("v1.idl"), &src).unwrap();
    fs::write(dir.join("v1.idl.lock"), &lock).unwrap();

    let (ok, out, build) = idlc("build", true, &root);
    assert!(ok, "{out}");
    let (ok, out, check) = idlc("check", false, &root);
    assert!(ok, "{out}");
    assert!(out.contains("org.example.x/1.1023"), "{out}");
    eprintln!("1,023 changing minors: build {build:?}, check {check:?}");
    assert!(
        build + check < Duration::from_secs(300),
        "build {build:?}, check {check:?}"
    );

    // One minor more is refused (the lock reader's own limit, 1,024
    // entries, is tested with idl::lock).
    fs::write(dir.join("v1.idl"), worst_case("1.1024")).unwrap();
    let (ok, out, _) = idlc("check", false, &root);
    assert!(!ok && out.contains("at most 1024 minors"), "{out}");
}
