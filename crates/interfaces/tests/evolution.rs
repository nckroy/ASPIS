// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Old and new minor versions of a generated interface (ADR 0068, rule 6;
//! ADR 0065, rules 10 and 11; docs/design/call-language.md, "Differential
//! tests", the row "Old and new minor versions", and "Rules for readers").
//!
//! The fixtures have a real binding of each earlier minor, generated from
//! that minor's projection (`kinds::v1_0`, `v1_1`, `base::v1_0`), so its
//! types lack the later fields and arms, and the unknown carriers and the
//! re-encoding take their own code paths:
//!
//! - an old binding reads every newer minor's tolerant messages (replies,
//!   opening replies, stream items, error details and types), preserves
//!   the parts it doesn't know, and re-encodes them byte for byte;
//! - the newest binding reads every older minor's messages, requests too,
//!   at its own minor, and re-encodes them byte for byte.

mod common;

use abnf::vectors::Tag;
use idl_fixtures::org::example::{base, kinds};
use idl_rt::{
    rules::{Module, Op, Verdict},
    wire::{DecodeCx, EncodeCx, Mode, Writer, decode_all},
};

/// A rule an old reader reads tolerantly: every rule but a request's and a
/// strict type form's (`r-`).
fn tolerant(rule: &str) -> bool {
    !rule.ends_with("--req") && !rule.starts_with("r-")
}

/// Each fixture's modules, oldest first: (minor, module).
fn fixtures() -> Vec<(&'static str, Vec<(u16, &'static Module)>)> {
    vec![
        (
            "crates/idl/tests/data/interfaces/org/example/kinds/v1.idl",
            vec![
                (0, &kinds::v1_0::MODULE),
                (1, &kinds::v1_1::MODULE),
                (2, &kinds::v1::MODULE),
            ],
        ),
        (
            "crates/idl/tests/data/interfaces/org/example/base/v1.idl",
            vec![(0, &base::v1_0::MODULE), (1, &base::v1::MODULE)],
        ),
    ]
}

fn reencodes(m: &Module, rule: &str, minor: u16, caps: u8, octets: &[u8]) -> Result<(), String> {
    let mut out = vec![0u8; octets.len() + 64];
    match (m.rule)(rule, minor, caps, octets, Op::Encode(&mut out)) {
        Verdict::Ok { len, .. } if out[..len] == *octets => Ok(()),
        v => Err(format!("{v:?}")),
    }
}

#[test]
fn old_bindings_read_newer_replies_and_preserve_them() {
    let mut checked = 0;
    let mut failures = Vec::new();
    for (path, modules) in fixtures() {
        let path = common::repo().join(path);
        for &(old, module) in &modules {
            assert_eq!(module.minor, old, "{path:?}");
            for &(new, _) in modules.iter().filter(|(n, _)| *n > old) {
                let v = common::vectors(&path.with_file_name(format!("v1.{new}.vectors"))).unwrap();
                for x in v
                    .vectors
                    .iter()
                    .filter(|x| x.tag == Tag::Ok && tolerant(&x.rule))
                {
                    if !module.rules.contains(&x.rule.as_str()) {
                        // A method or type newer than the old binding.
                        continue;
                    }
                    checked += 1;
                    if let Err(e) = reencodes(module, &x.rule, old, x.caps, &x.octets) {
                        failures.push(format!(
                            "{} 1.{old} reading 1.{new} line {} ({}): {e}",
                            module.name, x.line, x.rule
                        ));
                    }
                }
            }
        }
    }
    eprintln!("{checked} old-reads-new checks");
    assert!(checked > 300, "only {checked}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn the_newest_binding_reads_older_messages() {
    let mut checked = 0;
    let mut failures = Vec::new();
    for (path, modules) in fixtures() {
        let path = common::repo().join(path);
        let &(newest, module) = modules.last().unwrap();
        for &(old, _) in modules.iter().filter(|(n, _)| *n < newest) {
            let v = common::vectors(&path.with_file_name(format!("v1.{old}.vectors"))).unwrap();
            for x in v.vectors.iter().filter(|x| x.tag == Tag::Ok) {
                checked += 1;
                if let Err(e) = reencodes(module, &x.rule, newest, x.caps, &x.octets) {
                    failures.push(format!(
                        "{} 1.{newest} reading 1.{old} line {} ({}): {e}",
                        module.name, x.line, x.rule
                    ));
                }
            }
        }
    }
    eprintln!("{checked} new-reads-old checks");
    assert!(checked > 300, "only {checked}");
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The typed view of it: a 1.0 binding's `thing` holds a 1.1 `thing`'s
/// field `extra` in its preserved tail, and writes it back.
#[test]
fn an_old_struct_keeps_a_newer_field_in_its_tail() {
    // A 1.1 thing with `extra` set, encoded by the 1.1 binding.
    let new = kinds::v1_1::types::Thing {
        key: 7,
        count: 1,
        tags: idl_rt::view::Seq::Slice(&[]),
        blob: None,
        nested: None,
        pt: None,
        secret: None,
        extra: Some(0x0102_0304_0506_0708),
        unknown_: idl_rt::view::Unknown::default(),
    };
    let mut buf = [0u8; 256];
    let mut w = Writer::new(&mut buf);
    new.encode(&mut w, &EncodeCx::ANY).unwrap();
    let len = w.len();
    let octets = &buf[..len];

    let mut cx = DecodeCx::new(0, Mode::Tolerant, 0);
    let old = decode_all(octets, &mut cx, kinds::v1_0::types::Thing::decode).unwrap();
    assert_eq!((old.key, old.count), (7, 1));
    assert_eq!(old.unknown_.count(), 1);
    let (tag, value) = old.unknown_.iter().next().unwrap();
    assert_eq!(tag, 8, "extra is the struct's eighth field");
    assert_eq!(value, &0x0102_0304_0506_0708u64.to_be_bytes());
    let mut again = [0u8; 256];
    let mut w = Writer::new(&mut again);
    old.encode(&mut w, &EncodeCx::ANY).unwrap();
    let n = w.len();
    assert_eq!(&again[..n], octets);

    // The 1.1 binding reads the same octets at minor 0 as the 1.0 one
    // does: `extra` is unknown there.
    let mut cx = DecodeCx::new(0, Mode::Tolerant, 0);
    let at0 = decode_all(octets, &mut cx, kinds::v1_1::types::Thing::decode).unwrap();
    assert_eq!(at0.extra, None);
    assert_eq!(at0.unknown_.count(), 1);
}
