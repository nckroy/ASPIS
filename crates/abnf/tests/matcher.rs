// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The matcher: exact answers for ABNF's ambiguity, and every vocabulary
//! form enforced, through `tests/data/vocabulary.abnf` and its vectors
//! (ADR 0062, rules 7 and 8; docs/design/call-language.md, "How
//! constraints bind").

use std::path::{Path, PathBuf};

use abnf::{
    Context, Grammar, LoadOptions,
    vectors::{self, Tag, Verdict},
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn core_text() -> Vec<u8> {
    std::fs::read(root().join("grammars/core.abnf")).expect("grammars/core.abnf")
}

fn load(text: &str) -> Grammar {
    let core = core_text();
    Grammar::load(
        "t",
        text.as_bytes(),
        &mut |_| Some(core.clone()),
        &LoadOptions::default(),
    )
    .unwrap_or_else(|e| panic!("{e}"))
}

fn vocabulary() -> (Grammar, vectors::VectorFile) {
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let text = std::fs::read(data.join("vocabulary.abnf")).unwrap();
    let core = core_text();
    let g = Grammar::load(
        "vocabulary",
        &text,
        &mut |n| (n == "core").then(|| core.clone()),
        &LoadOptions::default(),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let f = vectors::parse(&std::fs::read(data.join("vocabulary.vectors")).unwrap()).unwrap();
    (g, f)
}

/// Context-free.
fn m(g: &Grammar, rule: &str, input: &[u8]) -> bool {
    g.matches(g.rule(rule).unwrap(), input).unwrap()
}

/// With constraints, and no capabilities.
fn c(g: &Grammar, rule: &str, input: &[u8]) -> bool {
    g.matches_constrained(g.rule(rule).unwrap(), input, &Context::default())
        .unwrap()
}

#[test]
fn ambiguity_is_answered_exactly() {
    let g = load(
        "a = *\"a\" \"a\"\n\
         b = (\"a\" / \"ab\") \"c\"\n\
         x = 2*3(\"x\" / \"xx\") \"y\"\n\
         n = *(*\"a\" *\"b\")\n",
    );
    assert!(m(&g, "a", b"aaa"));
    assert!(m(&g, "a", b"a"));
    assert!(!m(&g, "a", b""));
    assert!(m(&g, "b", b"abc"));
    assert!(m(&g, "b", b"ac"));
    assert!(m(&g, "x", b"xxy"));
    assert!(m(&g, "x", b"xxxxxxy"));
    assert!(!m(&g, "x", b"xy"));
    assert!(!m(&g, "x", b"xxxxxxxy"));
    // Nested nullable repetitions end.
    assert!(m(&g, "n", b"abba"));
    assert!(m(&g, "n", b""));
}

#[test]
fn case_rules() {
    let g = load("i = \"abc\"\ns = %s\"abc\"\nj = %i\"abc\"\n");
    assert!(m(&g, "i", b"aBc") && m(&g, "j", b"ABC"));
    assert!(m(&g, "s", b"abc") && !m(&g, "s", b"aBc"));
}

#[test]
fn a_prose_val_matches_nothing() {
    let g = Grammar::load(
        "t",
        b"p = <anything at all> / \"x\"\n",
        &mut |_| Some(core_text()),
        &LoadOptions::default(),
    )
    .unwrap();
    assert!(m(&g, "p", b"x"));
    assert!(!m(&g, "p", b""));
    assert!(!m(&g, "p", b"anything at all"));
}

/// Every vector of the vocabulary grammar agrees, and each `errc` vector
/// matches context-free but not with constraints.
#[test]
fn the_vocabulary_is_enforced() {
    let (g, f) = vocabulary();
    let report = vectors::check(&g, &f);
    let bad: Vec<_> = report
        .results
        .iter()
        .filter(|(_, v)| *v != Verdict::Agrees)
        .collect();
    assert!(bad.is_empty(), "vocabulary.vectors: {bad:?}");
    assert!(report.errc >= 45, "{} errc vectors", report.errc);
    for v in f.vectors.iter().filter(|v| v.tag == Tag::Errc) {
        let r = g.rule(&v.rule).unwrap();
        assert_eq!(g.matches(r, &v.octets), Ok(true), "line {}", v.line);
        let cx = Context {
            caps: v.caps,
            unwrapped: v.unwrapped,
        };
        assert_eq!(
            g.matches_constrained(r, &v.octets, &cx),
            Ok(false),
            "line {}",
            v.line
        );
    }
}

#[test]
fn context_free_mode_ignores_every_constraint() {
    let (g, _) = vocabulary();
    assert!(m(&g, "small", b"\x00"));
    assert!(!c(&g, "small", b"\x00"));
    assert!(m(&g, "frame-rest", b"\x00\xaa"));
    assert!(!c(&g, "frame-rest", b"\x00\xaa"));
}

/// Constraints in a used grammar hold too: core's `octets` inside `entry`.
#[test]
fn constraints_of_used_rules_hold() {
    let (g, _) = vocabulary();
    let entry = b"\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x02\xaa\xbb";
    assert!(c(&g, "entry", entry));
    let short = b"\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x03\xaa\xbb";
    assert!(m(&g, "entry", short) && !c(&g, "entry", short));
}

/// A whole body names its capability indexes in order, each once, and all
/// of them; a core rule's fragment needs only range and no repeats.
#[test]
fn capability_indexes() {
    let g = load("; uses: core\npair = cap-ref cap-ref\ntwice = cap-ref\n");
    let cx = |caps| Context { caps, unwrapped: 0 };
    let run = |rule: &str, input: &[u8], caps| {
        g.matches_constrained(g.rule(rule).unwrap(), input, &cx(caps))
            .unwrap()
    };
    assert!(run("pair", b"\x00\x01", 2));
    assert!(!run("pair", b"\x01\x00", 2));
    assert!(!run("pair", b"\x00\x00", 2));
    assert!(!run("pair", b"\x00\x01", 3));
    assert!(!run("twice", b"\x00", 2));
    assert!(run("twice", b"\x00", 1));
    assert!(run("cap-ref", b"\x01", 2));
    assert!(!run("cap-ref", b"\x02", 2));
    // The unwrapped mask changes nothing.
    let with_mask = Context {
        caps: 2,
        unwrapped: 3,
    };
    let pair = g.rule("pair").unwrap();
    assert_eq!(
        g.matches_constrained(pair, b"\x00\x01", &with_mask),
        Ok(true)
    );
}

#[test]
fn deterministic() {
    let (g, f) = vocabulary();
    let first = vectors::check(&g, &f).results;
    for _ in 0..3 {
        assert_eq!(vectors::check(&g, &f).results, first);
    }
}
