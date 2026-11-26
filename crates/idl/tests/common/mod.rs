// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Helpers shared by the idl crate's tests: the repository's IDL files, a
//! resolver over the interface roots, and a deterministic generator.

#![allow(dead_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use idl::{Checked, Diagnostic, Limits};
use idl_rt::names::InterfaceRef;

/// The repository's root.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The interface roots: the repository's, and the test fixtures'.
pub fn roots() -> [PathBuf; 2] {
    [
        repo().join("interfaces"),
        repo().join("crates/idl/tests/data/interfaces"),
    ]
}

/// Every `v<M>.idl` file under the roots, sorted. Paths with a space in
/// any component are iCloud's conflict copies, and are skipped.
pub fn idl_files() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut dirs: Vec<PathBuf> = roots().into_iter().collect();
    while let Some(d) = dirs.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            if name.contains(' ') {
                continue;
            }
            if p.is_dir() {
                dirs.push(p);
            } else if name.starts_with('v') && name.ends_with(".idl") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// The file an interface major lives in, under any root.
pub fn path_of(name: &str, major: u16) -> Option<PathBuf> {
    roots()
        .into_iter()
        .map(|r| r.join(name.replace('.', "/")).join(format!("v{major}.idl")))
        .find(|p| p.exists())
}

/// A resolver over the roots.
pub fn resolver() -> impl FnMut(&InterfaceRef<'_>) -> Option<Vec<u8>> {
    |r: &InterfaceRef<'_>| path_of(r.name, r.major).and_then(|p| fs::read(p).ok())
}

/// Checks a source with the roots as its imports.
pub fn check(src: &[u8]) -> Result<Checked, Vec<Diagnostic>> {
    let mut r = resolver();
    idl::check(src, &mut r, &Limits::default())
}

/// Checks a file under the roots, panicking with its diagnostics.
pub fn check_file(p: &Path) -> Checked {
    let src = fs::read(p).unwrap();
    match check(&src) {
        Ok(c) => c,
        Err(d) => panic!("{}: {d:#?}", p.display()),
    }
}

/// A small deterministic generator (SplitMix64), so a failure replays.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}
