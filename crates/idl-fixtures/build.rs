// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Generates the Rust bindings of the IDL compiler's test fixtures, under
//! `crates/idl/tests/data/interfaces/`, as crates/interfaces does for the
//! real interfaces. Each fixture has a module at its version (`v1`), and
//! one per earlier minor, generated from that minor's projection (`v1_0`,
//! `v1_1`), so tests can read a newer minor's messages with a real older
//! binding (ADR 0068, rule 6).
//!
//! A path with a space in any component is one of iCloud's conflict
//! copies, and is skipped.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use idl::{
    Limits,
    rust::{Flavor, Tree},
};
use idl_rt::names::InterfaceRef;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../idl/tests/data/interfaces");
    // A directory is scanned whole, so a new file regenerates too.
    println!("cargo:rerun-if-changed={}", root.display());
    let mut tree = Tree::default();
    for f in walk(&root) {
        println!("cargo:rerun-if-changed={}", f.display());
        let src = fs::read(&f).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        let mut resolve = |r: &InterfaceRef<'_>| {
            let p = root
                .join(r.name.replace('.', "/"))
                .join(format!("v{}.idl", r.major));
            fs::read(p).ok()
        };
        let c = idl::check(&src, &mut resolve, &Limits::default())
            .unwrap_or_else(|d| panic!("{}: {d:?}", f.display()));
        let unit = c.unit();
        let source = f.file_name().unwrap_or_default().to_string_lossy();
        let spdx = idl::generate::spdx_lines(&src);
        let (major, v) = (unit.major(), unit.version.minor);
        let module = format!("v{major}");
        let code = idl::rust::generate(&c, Flavor::Crate, &module, &source, &spdx);
        tree.add(&unit.name, &module, code);
        for m in 0..v {
            let p = c.project(m);
            let module = format!("v{major}_{m}");
            let code = idl::rust::generate(&p, Flavor::Crate, &module, &source, &spdx);
            tree.add(&unit.name, &module, code);
        }
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("fixtures.rs");
    fs::write(&out, tree.render()).unwrap_or_else(|e| panic!("{}: {e}", out.display()));
}

/// Every `v<M>.idl` under a root, sorted.
fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(d) = dirs.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.contains(' ') {
                continue;
            }
            let p = e.path();
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
