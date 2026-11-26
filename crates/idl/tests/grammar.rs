// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The IDL parser against its normative grammar, `grammars/idl.abnf`
//! (ADR 0067, rule 11; docs/design/call-language.md, "Differential
//! tests"): the parser accepts an input exactly when crates/abnf's
//! matcher, with its constraints, accepts it. The inputs are every vector,
//! every IDL file in the repository, every canonical form, and
//! deterministic mutations of them.

mod common;

use std::fs;

use abnf::{Context, Grammar, LoadOptions, vectors};
use common::Rng;
use idl::{
    Code, Limits,
    parse::{Rule, parse_rule},
};

fn grammar() -> Grammar {
    let dir = common::repo().join("grammars");
    let text = fs::read(dir.join("idl.abnf")).unwrap();
    let mut resolve = |n: &str| fs::read(dir.join(format!("{n}.abnf"))).ok();
    Grammar::load("idl", &text, &mut resolve, &LoadOptions::default()).unwrap()
}

/// The parser's verdict, or None when it stopped at one of its own limits,
/// which the grammar doesn't have.
fn parser(rule: Rule, input: &[u8]) -> Option<bool> {
    match parse_rule(rule, input, &Limits::default()) {
        Ok(()) => Some(true),
        Err(d) if d.code == Code::Limit => None,
        Err(_) => Some(false),
    }
}

fn agree(g: &Grammar, rule: &str, input: &[u8], what: &str) {
    let r = Rule::from_name(rule).unwrap();
    let Some(ours) = parser(r, input) else { return };
    let theirs = g
        .matches_constrained(g.rule(rule).unwrap(), input, &Context::default())
        .unwrap_or_else(|e| panic!("{what}: the matcher ran out: {e}"));
    assert_eq!(
        ours,
        theirs,
        "{what}: the parser says {ours}, the grammar {theirs}: {:?}",
        String::from_utf8_lossy(input)
    );
}

#[test]
fn every_vector() {
    let vf =
        vectors::parse(&fs::read(common::repo().join("grammars/idl.vectors")).unwrap()).unwrap();
    for v in &vf.vectors {
        let r =
            Rule::from_name(&v.rule).unwrap_or_else(|| panic!("no parser entry for {}", v.rule));
        let want = v.tag == vectors::Tag::Ok;
        assert_eq!(
            parser(r, &v.octets),
            Some(want),
            "idl.vectors line {}: {:?}",
            v.line,
            String::from_utf8_lossy(&v.octets)
        );
    }
}

#[test]
fn every_file_and_canonical_form() {
    let g = grammar();
    let files = common::idl_files();
    assert!(files.len() >= 6, "found {} IDL files", files.len());
    for p in &files {
        let src = fs::read(p).unwrap();
        agree(&g, "idl-file", &src, &p.display().to_string());
        assert_eq!(parser(Rule::IdlFile, &src), Some(true), "{}", p.display());
        let checked = common::check_file(p);
        let v = checked.unit().version;
        for m in 0..=v.minor {
            let canon = idl::canon::canonical(&idl::project::project(checked.file(), m));
            agree(
                &g,
                "idl-file",
                canon.as_bytes(),
                &format!("{} at {}.{m}", p.display(), v.major),
            );
            assert_eq!(
                parser(Rule::IdlFile, canon.as_bytes()),
                Some(true),
                "{canon}"
            );
        }
    }
}

/// One octet deleted, inserted or replaced, at a random place. The
/// inserted octets favor the IDL's own punctuation and keywords' letters.
fn mutate(rng: &mut Rng, src: &[u8]) -> Vec<u8> {
    const OCTETS: &[u8] = b" \n/!@<>{}[](),.:;=?-_0123456789axzABZ\t\r\x00\x80\xc3";
    let mut out = src.to_vec();
    let at = rng.below(out.len() + 1);
    let b = OCTETS[rng.below(OCTETS.len())];
    match rng.below(3) {
        0 if at < out.len() => {
            out.remove(at);
        }
        1 if at < out.len() => out[at] = b,
        _ => out.insert(at, b),
    }
    out
}

#[test]
fn mutations_of_files() {
    let g = grammar();
    let mut rng = Rng(0x6964_6c2d_6d75_7461);
    for p in common::idl_files() {
        let src = fs::read(&p).unwrap();
        for i in 0..150 {
            let m = mutate(&mut rng, &src);
            agree(&g, "idl-file", &m, &format!("{} mutation {i}", p.display()));
        }
    }
}

#[test]
fn mutations_of_vectors() {
    let g = grammar();
    let vf =
        vectors::parse(&fs::read(common::repo().join("grammars/idl.vectors")).unwrap()).unwrap();
    let mut rng = Rng(0x7665_6374);
    for v in vf.vectors.iter().filter(|v| v.octets.len() < 2000) {
        let mut m = v.octets.clone();
        for i in 0..12 {
            m = if i % 4 == 0 {
                mutate(&mut rng, &v.octets)
            } else {
                mutate(&mut rng, &m)
            };
            agree(&g, &v.rule, &m, &format!("line {} mutation {i}", v.line));
        }
    }
}
