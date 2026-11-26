// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Helpers shared by the generated bindings' tests: the interface roots,
//! every IDL file under them, checking a file, loading its generated
//! grammars, and the generated modules.

#![allow(dead_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use abnf::{Grammar, Kind, LoadOptions, vectors::VectorFile};
use idl::Limits;
use idl_rt::{names::InterfaceRef, rules::Module};

pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The interface roots: the repository's, and the compiler's fixtures.
pub fn roots() -> [PathBuf; 2] {
    [
        repo().join("interfaces"),
        repo().join("crates/idl/tests/data/interfaces"),
    ]
}

/// Every generated module: crates/interfaces' and crates/idl-fixtures'.
pub fn modules() -> Vec<&'static Module> {
    aspis_interfaces::MODULES
        .iter()
        .chain(idl_fixtures::MODULES)
        .copied()
        .collect()
}

/// Every `v<M>.idl` under a root, with the interface's name from its
/// path. Paths with a space are iCloud's copies, and are skipped.
pub fn idl_files(root: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.contains(' ') {
                continue;
            }
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else if n.starts_with('v') && n.ends_with(".idl") {
                let rel = d.strip_prefix(root).unwrap();
                let name: Vec<String> = rel
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect();
                out.push((name.join("."), p));
            }
        }
    }
    out.sort();
    out
}

/// Every IDL file under both roots.
pub fn all_idl_files() -> Vec<(String, PathBuf)> {
    roots().iter().flat_map(|r| idl_files(r)).collect()
}

/// Checks an IDL file, with both roots as its imports.
pub fn check(path: &Path) -> idl::Checked {
    let src = fs::read(path).unwrap();
    let mut resolve = |r: &InterfaceRef<'_>| {
        roots()
            .iter()
            .map(|root| {
                root.join(r.name.replace('.', "/"))
                    .join(format!("v{}.idl", r.major))
            })
            .find(|p| p.exists())
            .and_then(|p| fs::read(p).ok())
    };
    idl::check(&src, &mut resolve, &Limits::default()).unwrap()
}

/// Loads a generated grammar beside an IDL file, as the catalog loads a
/// publisher's: strict, with `; uses:` names from `grammars/`.
pub fn grammar(path: &Path) -> Option<Grammar> {
    let text = fs::read(path).ok()?;
    let mut shared = |name: &str| fs::read(repo().join(format!("grammars/{name}.abnf"))).ok();
    let opts = LoadOptions {
        kind: Kind::Strict,
        ..LoadOptions::default()
    };
    let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
    Some(
        Grammar::load(&stem, &text, &mut shared, &opts)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display())),
    )
}

/// Reads a vector file.
pub fn vectors(path: &Path) -> Option<VectorFile> {
    let text = fs::read(path).ok()?;
    Some(abnf::vectors::parse(&text).unwrap_or_else(|e| panic!("{}: {e:?}", path.display())))
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
}
