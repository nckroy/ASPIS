// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! What the tests share: the repository's tracked files, each target's
//! seeds, and a thread with room for the matcher's depth.

#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::Command,
};

use fuzz_gate::Target;

/// The repository root.
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// The files git lists under the given paths (or globs), tracked or new.
/// iCloud's conflict copies are ignored, so they never appear.
pub fn tracked(paths: &[&str]) -> Vec<String> {
    let out = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
        ])
        .args(paths)
        .current_dir(root())
        .output()
        .expect("git ls-files");
    assert!(out.status.success(), "git ls-files failed");
    out.stdout
        .split(|&b| b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8(p.to_vec()).unwrap())
        .filter(|p| root().join(p).is_file())
        .collect()
}

/// The committed files of `fuzz/<kind>/<target>/`, by name.
pub fn committed(kind: &str, target: &str) -> Vec<(String, Vec<u8>)> {
    tracked(&[&format!("fuzz/{kind}/{target}")])
        .into_iter()
        .map(|p| {
            let bytes = std::fs::read(root().join(&p)).unwrap();
            (p, bytes)
        })
        .collect()
}

/// Every seed a target replays: committed, generated and regressions,
/// each with a name that says where it came from.
pub fn all_seeds(t: &Target) -> Vec<(String, Vec<u8>)> {
    let mut out = committed("seeds", t.name);
    out.extend(
        (t.seeds)()
            .into_iter()
            .map(|(n, b)| (format!("generated {n}"), b)),
    );
    out.extend(committed("regressions", t.name));
    out
}

/// Runs `f` on a thread with a 16 MiB stack: the matcher's 768 levels
/// need about 560 KiB at opt-level 1, and a test thread has 2 MiB.
pub fn on_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(16 << 20)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}
