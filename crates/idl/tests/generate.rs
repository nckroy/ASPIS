// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The generated grammars and vectors (ADR 0067, rule 9; docs/design/
//! call-language.md, "Generated grammars"): they are what the committed
//! files hold, load strictly as the catalog loads them, keep the
//! generator's invariants, and keep the vector evolution rule.

mod common;

use std::{collections::BTreeMap, fs, path::PathBuf};

use abnf::{Context, Grammar, Kind, LoadOptions, vectors};
use idl::{
    generate,
    schema::{Mode, Schema},
    value,
};

fn shared(name: &str) -> Option<Vec<u8>> {
    fs::read(common::repo().join(format!("grammars/{name}.abnf"))).ok()
}

fn strict(name: &str, text: &[u8]) -> Grammar {
    let opts = LoadOptions {
        kind: Kind::Strict,
        ..LoadOptions::default()
    };
    Grammar::load(name, text, &mut shared, &opts).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Every generated file of every minor: (path, text).
fn generated() -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    for p in common::idl_files() {
        let c = common::check_file(&p);
        let src = fs::read(&p).unwrap();
        let spdx = generate::spdx_lines(&src);
        let dir = p.parent().unwrap();
        let major = c.unit().major();
        let mut generator = generate::Generator::new(&c, "v1.idl", &spdx);
        for m in 0..=c.unit().version.minor {
            let g = generator
                .minor(m, &mut shared)
                .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
            let stem = dir.join(format!("v{major}.{m}"));
            if let Some((grammar, vectors)) = g.wire {
                out.push((stem.with_extension(format!("{m}.abnf")), grammar));
                out.push((stem.with_extension(format!("{m}.vectors")), vectors));
            }
            out.push((stem.with_extension(format!("{m}.text.abnf")), g.text.0));
            out.push((stem.with_extension(format!("{m}.text.vectors")), g.text.1));
        }
    }
    out
}

/// Generation is deterministic, and the committed files are current.
#[test]
fn the_committed_files_are_current() {
    let files = generated();
    assert!(files.len() >= 20);
    for (path, text) in files {
        let have = fs::read_to_string(&path).unwrap_or_default();
        assert!(
            have == text,
            "{} is stale: run cargo xtask idl --write",
            path.display()
        );
    }
}

/// Every generated grammar loads strictly (no prose, no prose-val), as the
/// catalog loads a publisher's grammars, and its vectors agree.
#[test]
fn grammars_load_strictly_and_vectors_agree() {
    for (path, text) in generated() {
        if path.extension().is_some_and(|e| e == "abnf") {
            let g = strict("generated", text.as_bytes());
            let vpath = path.with_extension("vectors");
            let vf = vectors::parse(&fs::read(&vpath).unwrap()).unwrap();
            let r = vectors::check(&g, &vf);
            assert_eq!(r.disagree, 0, "{}", vpath.display());
            assert!(r.agree > 10, "{}", vpath.display());
        }
    }
}

/// Rule names: every rule carries one of the prefixes, and helpers use the
/// third hyphen, so no member name can make one.
#[test]
fn rule_names_are_prefixed() {
    for (path, text) in generated() {
        if path.extension().is_none_or(|e| e != "abnf") {
            continue;
        }
        for line in text.lines() {
            let Some((name, _)) = line.split_once(" = ") else {
                continue;
            };
            if line.starts_with([' ', ';']) {
                continue;
            }
            let mut rest = name;
            while let Some(r) = rest.strip_prefix('u') {
                let digits = r.find("--").unwrap_or(0);
                assert!(digits > 0, "{name}");
                rest = &r[digits + 2..];
            }
            assert!(
                ["t-", "r-", "m-", "e-"].iter().any(|p| rest.starts_with(p)),
                "{}: {name}",
                path.display()
            );
            assert!(!name.contains("----"), "{name}");
        }
    }
}

/// A rule bound by `exactly R octets` with no variable repetition is
/// exactly one rule reference, so its target is that rule's whole match
/// (the length-prefixed pattern, "The struct encoding").
#[test]
fn length_prefixed_bodies_are_one_reference() {
    for (path, text) in generated() {
        if path.extension().is_none_or(|e| e != "abnf") {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let Some((name, def)) = line.split_once(" = ") else {
                continue;
            };
            let bound = lines[i + 1..]
                .iter()
                .take_while(|l| l.starts_with("    ;"))
                .any(|l| l.contains("constraint: exactly") && l.ends_with(" octets"));
            if bound && !def.contains('*') {
                assert!(
                    def.split(' ').count() == 1
                        && def.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                    "{}: {name} = {def}",
                    path.display()
                );
            }
        }
    }
}

/// `aspis.rpc` 1.0 stays unpublished while its `error_key` accepts code
/// 0, which the envelope's `error-key` rule calls malformed ("The system
/// errors"). Once the generated rule refuses code 0, C18 may publish it.
#[test]
fn rpc_stays_unpublished_while_error_key_accepts_code_0() {
    let dir = common::repo().join("interfaces/aspis/rpc");
    let text = fs::read_to_string(dir.join("v1.0.abnf")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.starts_with("t-error-key = "))
        .unwrap();
    // The struct's rule and its own sub-rules, with their constraints.
    let refuses_0 = lines[at..]
        .iter()
        .take_while(|l| l.starts_with("t-error-key") || l.starts_with(' '))
        .any(|l| l.contains("constraint: not 0"));
    let lock = idl::lock::parse(&fs::read(dir.join("v1.idl.lock")).unwrap(), 1).unwrap();
    assert!(
        refuses_0 || lock.published().is_none(),
        "aspis.rpc 1.0 is published, but its error_key accepts code 0"
    );
}

/// The catalog example's grammar, as the note shows it.
#[test]
fn the_catalogs_grammar() {
    let text =
        fs::read_to_string(common::repo().join("interfaces/aspis/catalog/v1.1.abnf")).unwrap();
    for line in [
        "; uses: core",
        "t-change = u64 t-change-kind object-id t-change---tail",
        "t-change--publisher = %x00.04 %x00.00.00.20 object-id",
        "t-change---unknown-tag = %x00 %x05-FF / %x01-FF OCTET",
        "    ; constraint: at least 5",
        "t-change-kind = u8",
        "m-watch--req = r-query m-watch--req---tail",
        "m-watch--req--after = %x00.02 %x00.00.00.08 u64",
        "m-watch--open = m-watch--open---id u64 m-watch--rep",
        "m-watch--item = t-change",
        "r-query = t-selector r-query---tail",
        "t-selector---unknown-tag = %x00 %x04-FF / %x01-FF OCTET",
        "    ; constraint: not one of 0, 1, 2, 3",
        "m-register--req = cap-ref u32 m-register--req--proof m-register--req---tail",
    ] {
        assert!(text.lines().any(|l| l == line), "missing: {line}");
    }
    let text =
        fs::read_to_string(common::repo().join("interfaces/aspis/catalog/v1.1.text.abnf")).unwrap();
    assert!(text.contains("; uses: core, names, json\n"));
    assert!(text.contains("m-register--args--proof = %x22 %s\"proof\" %x22 \":\" json-null\n"));
}

/// Every ok vector of a tolerant rule of M.m matches M.(m-1)'s grammar, and
/// every request vector gets the same answer from M.(m-1)'s grammar as
/// from its decoder ("The compatibility check").
#[test]
fn old_grammars_read_new_vectors() {
    let mut checked = 0;
    for p in common::idl_files() {
        let c = common::check_file(&p);
        let dir = p.parent().unwrap();
        let major = c.unit().major();
        let mut grammars: BTreeMap<u16, Grammar> = BTreeMap::new();
        for m in 0..=c.unit().version.minor {
            let path = dir.join(format!("v{major}.{m}.abnf"));
            let Ok(text) = fs::read(&path) else {
                continue;
            };
            grammars.insert(m, strict("generated", &text));
            let Some(prev) = m.checked_sub(1).and_then(|p| grammars.get(&p)) else {
                continue;
            };
            let s = Schema::new(&c, m - 1);
            let tops: BTreeMap<String, _> =
                s.tops().into_iter().map(|t| (s.top_rule(t), t)).collect();
            let vf = vectors::parse(&fs::read(path.with_extension("vectors")).unwrap()).unwrap();
            for v in vf.vectors.iter().filter(|v| v.tag == vectors::Tag::Ok) {
                let (Some(&top), Some(r)) = (tops.get(&v.rule), prev.rule(&v.rule)) else {
                    continue;
                };
                let cx = Context {
                    caps: v.caps,
                    unwrapped: v.unwrapped,
                };
                let ok = prev.matches_constrained(r, &v.octets, &cx).unwrap();
                if s.mode(top) == Mode::Tolerant {
                    assert!(ok, "{} {}:{}", p.display(), m, v.line);
                } else {
                    let decoded = value::decode(&s, top, &v.octets, v.caps).is_ok();
                    assert_eq!(ok, decoded, "{} {}:{}", p.display(), m, v.line);
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 500, "{checked}");
}

// ---- A file's budget, across its minors ------------------------------------

/// An interface `x` at `version`, with `body`.
fn interface(version: &str, body: &str) -> idl::Checked {
    let src = format!(
        "edition 2026;\n[id(org.example.x), object_id(reserved(0x0301)), version({version})]\ninterface x {{\n{body}}}\n"
    );
    common::check(src.as_bytes()).unwrap_or_else(|d| panic!("{d:?}"))
}

/// An enum of `values` values, `aliases` aliases of it, and one method.
fn enum_aliases(values: u16, aliases: usize) -> String {
    let mut body = String::from("enum e: u16 {");
    for i in 1..=values {
        body += &format!(" v{i} = {i},");
    }
    body += " }\n";
    for k in 0..aliases {
        body += &format!("alias a{k} = e;\n");
    }
    body + "@1 m(a: u8) -> u8;\n"
}

/// A generated file without the header line that names its minor.
fn body(text: &str) -> String {
    text.lines()
        .filter(|l| !l.contains("org.example.x/1."))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Vector lines, not comments or directives.
fn vectors_in(text: &str) -> usize {
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count()
}

/// The review's case: a 9 KB file at `version(1.65535)`, an enum of 128
/// values and 500 aliases of it. Every minor's vectors cost about 0.5 s
/// and 2 MB when each minor had a budget of its own, so all of them
/// would take hours and over 100 GB. One budget for the file bounds them:
/// the minors after it is spent reuse their grammars and have no vectors.
#[test]
fn a_files_minors_share_one_budget() {
    let c = interface("1.65535", &enum_aliases(128, 500));
    let start = std::time::Instant::now();
    let mut g = generate::Generator::new(&c, "v1.idl", &[]);
    let (mut lines, mut bytes, mut made) = (0, 0, 0);
    let first = g.minor(0, &mut shared).unwrap();
    for m in 0..=65_535u16 {
        let x = if m == 0 {
            first.clone()
        } else {
            g.minor(m, &mut shared).unwrap()
        };
        let (wg, wv) = x.wire.as_ref().unwrap();
        // The same grammars at every minor, under each minor's header.
        assert_eq!(body(wg), body(&first.wire.as_ref().unwrap().0), "1.{m}");
        assert_eq!(body(&x.text.0), body(&first.text.0), "1.{m}");
        assert!(wg.contains(&format!("org.example.x/1.{m}: the wire grammar")));
        lines += vectors_in(wv) + vectors_in(&x.text.1);
        bytes += wv.len() + x.text.1.len();
        // Vectors are made again only while the budget runs out.
        let (grammars, vectors) = g.same_as_before();
        assert!(m == 0 || grammars, "1.{m}");
        made += usize::from(!vectors);
    }
    assert!(made <= 3, "vectors made at {made} minors");
    let took = start.elapsed();
    // Minor 0 has vectors; the budget ran out in it, so the last has none.
    assert!(vectors_in(&first.wire.as_ref().unwrap().1) > 1000);
    let last = g.minor(65_535, &mut shared).unwrap();
    assert_eq!(vectors_in(&last.wire.unwrap().1), 0);
    assert!(g.budget().is_spent());
    assert!(lines < 3 * idl::vectors::FILE_BUDGET, "{lines} lines");
    eprintln!("65,536 minors: {took:?}, {lines} vector lines, {bytes} octets of vectors");
    assert!(took.as_secs() < 60, "{took:?}");
}

/// The review's other case: a 59 KB file of one minor, an enum of 4096
/// values and 256 aliases of it. Its 524 K samples took 43 s to match
/// against their grammars. The steps of those matches come from the
/// file's budget too.
#[test]
fn matching_samples_has_a_budget() {
    let c = interface("1.0", &enum_aliases(4096, 256));
    let start = std::time::Instant::now();
    let mut g = generate::Generator::new(&c, "v1.idl", &[]);
    let x = g.minor(0, &mut shared).unwrap();
    let took = start.elapsed();
    let lines = vectors_in(&x.wire.unwrap().1) + vectors_in(&x.text.1);
    eprintln!("one minor: {took:?}, {lines} vector lines");
    assert!(lines > 1000, "{lines}");
    assert!(g.budget().is_spent());
    assert!(took.as_secs() < 60, "{took:?}");
    // The same at a thousand minors, the rest of them reused.
    let c = interface("1.1000", &enum_aliases(4096, 256));
    let start = std::time::Instant::now();
    let mut g = generate::Generator::new(&c, "v1.idl", &[]);
    for m in 0..=1000 {
        g.minor(m, &mut shared).unwrap();
    }
    let took = start.elapsed();
    eprintln!("1001 minors: {took:?}");
    assert!(took.as_secs() < 60, "{took:?}");
}

/// A minor that reuses the one before's files has what generating it
/// afresh gives, while the budget lasts. The projection changes at 1.2
/// and 1.5 only.
#[test]
fn a_reused_minor_is_what_generating_it_gives() {
    let c = interface(
        "1.6",
        "struct s { a: u8, [since(1.2)] b: u16?, [since(1.5)] c: string<8>? }\n\
         enum k: u8 { one = 1, [since(1.5)] two = 2 }\n\
         @1 m(a: s, k: k) -> u8;\n\
         [since(1.2)] @2 n(a: u8) -> s;\n",
    );
    let mut g = generate::Generator::new(&c, "v1.idl", &[]);
    for m in 0..=6 {
        let got = g.minor(m, &mut shared).unwrap();
        let alone = generate::Generator::new(&c, "v1.idl", &[])
            .minor(m, &mut shared)
            .unwrap();
        assert_eq!(got, alone, "1.{m}");
        let changed = [0, 2, 5].contains(&m);
        assert_eq!(g.same_as_before(), (!changed, !changed), "1.{m}");
        assert_eq!(
            generate::generate(&c, m, "v1.idl", &[], &mut shared).unwrap(),
            got
        );
    }
    assert!(!g.budget().is_spent());
}
