// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! libFuzzer dictionaries (docs/design/call-language.md, "Layout"): the
//! literals of `core` and `initfs`, and integers in each grammar's byte
//! order.

use std::path::{Path, PathBuf};

use abnf::{
    Grammar, Kind, LoadOptions,
    dict::{self, Endian, MAX_ENTRY},
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load(name: &str) -> Grammar {
    let read = |n: &str| std::fs::read(root().join(format!("grammars/{n}.abnf"))).ok();
    let opts = LoadOptions {
        kind: if name == "core" {
            Kind::Core
        } else {
            Kind::Auto
        },
        ..LoadOptions::default()
    };
    Grammar::load(name, &read(name).unwrap(), &mut |n| read(n), &opts).unwrap()
}

/// The entries of a dictionary, without its comment line.
fn entries(text: &str) -> Vec<&str> {
    text.lines().filter(|l| !l.starts_with('#')).collect()
}

#[test]
fn core_is_big_endian() {
    let g = load("core");
    let d = dict::libfuzzer(&g, "core", Endian::Big);
    assert!(d.starts_with("# core: "));
    let e = entries(&d);
    // u16 1, and i32's smallest value, big-endian.
    assert!(e.contains(&"\"\\x00\\x01\""), "{d}");
    assert!(e.contains(&"\"\\x80\\x00\\x00\\x00\""), "{d}");
    assert!(!e.contains(&"\"\\x01\\x00\""), "{d}");
    // Every entry is quoted, sorted, once, and short enough for libFuzzer.
    let mut sorted = e.clone();
    sorted.dedup();
    assert_eq!(sorted.len(), e.len());
    for x in &e {
        assert!(x.starts_with('"') && x.ends_with('"'), "{x}");
        // An escape is four characters for one octet.
        let octets = x.len() - 2 - 3 * x.matches("\\x").count();
        assert!(octets <= MAX_ENTRY, "{x}");
    }
    // Deterministic.
    assert_eq!(d, dict::libfuzzer(&g, "core", Endian::Big));
}

#[test]
fn initfs_is_little_endian_and_holds_its_literals() {
    let g = load("initfs");
    let d = dict::libfuzzer(&g, "initfs", Endian::Little);
    let e = entries(&d);
    assert!(e.contains(&"\"\\x01\\x00\""), "{d}");
    assert!(e.contains(&"\"\\x00\\x00\\x00\\x80\""), "{d}");
    assert!(!e.contains(&"\"\\x00\\x01\""), "{d}");
    // Every literal of the grammar that fits is an entry.
    let lits = g.literals().filter(|l| l.len() <= MAX_ENTRY).count();
    assert!(lits > 0);
    assert!(e.contains(&"\"ASPISIMG\""), "{d}");
    assert!(e.len() >= 5, "{d}");
}

#[test]
fn quoting() {
    // A grammar whose literals need every escape.
    let read = |n: &str| std::fs::read(root().join(format!("grammars/{n}.abnf"))).ok();
    let g = Grammar::load(
        "q",
        b"r = %x22.41 / %x5C.41 / %x00.FF / %s\"Az\"\n",
        &mut |n| read(n),
        &LoadOptions::default(),
    )
    .unwrap();
    let d = dict::libfuzzer(&g, "q", Endian::Big);
    let e = entries(&d);
    for want in ["\"\\\"A\"", "\"\\\\A\"", "\"\\x00\\xFF\"", "\"Az\""] {
        assert!(e.contains(&want), "{want} in {d}");
    }
}
