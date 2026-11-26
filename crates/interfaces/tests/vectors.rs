// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Every generated decoder against every committed wire vector, at every
//! minor (ADR 0013, rule 3; ADR 0067, rule 9): an ok vector decodes and
//! re-encodes to the same octets, and its JSON is what crates/idl's
//! dynamic codec writes; an err or errc vector is refused.
//!
//! The modules are crates/interfaces' and crates/idl-fixtures': each
//! interface at its version, and each fixture also at every earlier minor,
//! from that minor's projection. A module reads the vectors of its own
//! minor and of every earlier one.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use abnf::vectors::{self, Tag};
use idl::{
    Limits,
    schema::{Schema, Top},
    value,
};
use idl_rt::{
    json::JsonWriter,
    names::InterfaceRef,
    rules::{Module, Op, Verdict},
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn roots() -> [PathBuf; 2] {
    [
        repo().join("interfaces"),
        repo().join("crates/idl/tests/data/interfaces"),
    ]
}

fn modules() -> Vec<&'static Module> {
    aspis_interfaces::MODULES
        .iter()
        .chain(idl_fixtures::MODULES)
        .copied()
        .collect()
}

/// Every `v<M>.idl` under a root, with the interface's name from its
/// path. Paths with a space are iCloud's copies, and are skipped.
fn idl_files(root: &Path) -> Vec<(String, PathBuf)> {
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

fn check(path: &Path) -> idl::Checked {
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

#[test]
fn generated_decoders_agree_with_every_vector() {
    let modules = modules();
    let mut checked = 0;
    let mut failures = Vec::new();
    for root in roots() {
        for (name, path) in idl_files(&root) {
            let c = check(&path);
            let (major, v) = (c.unit().major(), c.unit().version.minor);
            assert_eq!(c.unit().name, name, "{}", path.display());
            let mine: Vec<&Module> = modules
                .iter()
                .copied()
                .filter(|m| m.name == name && m.major == major)
                .collect();
            assert!(!mine.is_empty(), "no generated module for {name}/{major}");
            for m in 0..=v {
                let vf = path.with_file_name(format!("v{major}.{m}.vectors"));
                let Ok(text) = fs::read(&vf) else {
                    // A [kernel] interface has no wire grammar.
                    assert!(c.unit().is_kernel(), "{} is missing", vf.display());
                    continue;
                };
                let file = vectors::parse(&text).unwrap();
                let s = Schema::new(&c, m);
                let tops: BTreeMap<String, Top> =
                    s.tops().into_iter().map(|t| (s.top_rule(t), t)).collect();
                for module in mine.iter().filter(|x| x.minor >= m) {
                    for vec in &file.vectors {
                        checked += 1;
                        let at = format!(
                            "{}:{} ({} at {major}.{m}, module minor {})",
                            vf.display(),
                            vec.line,
                            vec.rule,
                            module.minor
                        );
                        let mut out = vec![0u8; vec.octets.len() + 64];
                        let verdict = (module.rule)(
                            &vec.rule,
                            m,
                            vec.caps,
                            &vec.octets,
                            Op::Encode(&mut out),
                        );
                        match (vec.tag, verdict) {
                            (Tag::Ok, Verdict::Ok { len, .. }) => {
                                if out[..len] != vec.octets[..] {
                                    failures.push(format!("{at}: re-encodes differently"));
                                }
                            }
                            (Tag::Ok, v) => failures.push(format!("{at}: ok vector gives {v:?}")),
                            (_, Verdict::Malformed | Verdict::FieldTooNew) => {}
                            (_, v) => failures.push(format!("{at}: refused vector gives {v:?}")),
                        }
                        if vec.tag != Tag::Ok {
                            continue;
                        }
                        // The JSON, against the dynamic codec's.
                        let Some(&top) = tops.get(&vec.rule) else {
                            failures.push(format!("{at}: no such rule at the minor"));
                            continue;
                        };
                        let mut buf = vec![0u8; 1 << 16];
                        let mut j = JsonWriter::new(&mut buf);
                        (module.rule)(&vec.rule, m, vec.caps, &vec.octets, Op::Json(&mut j));
                        let got = j.finish().unwrap().to_vec();
                        let d = value::decode(&s, top, &vec.octets, vec.caps).unwrap();
                        let mut buf2 = vec![0u8; 1 << 16];
                        let mut j2 = JsonWriter::new(&mut buf2);
                        value::to_json(&s, top, &d.value, &mut j2);
                        let want = j2.finish().unwrap();
                        if got != want {
                            failures.push(format!(
                                "{at}: JSON {} but the dynamic codec writes {}",
                                String::from_utf8_lossy(&got),
                                String::from_utf8_lossy(want)
                            ));
                        }
                    }
                }
            }
        }
    }
    eprintln!("{checked} vector checks");
    assert!(checked > 1000, "only {checked} vectors");
    assert!(
        failures.is_empty(),
        "{} failures, first ones:\n{}",
        failures.len(),
        failures
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn every_module_knows_its_rules() {
    for m in modules() {
        let v = (m.rule)("no-such-rule", m.minor, 0, &[], Op::Encode(&mut []));
        assert_eq!(v, Verdict::NoRule, "{}", m.name);
    }
}
