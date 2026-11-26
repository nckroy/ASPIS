// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! How constraints bind (docs/design/call-language.md, "How constraints
//! bind"; ADR 0062, rule 7): attachment, strictness, the load-time checks,
//! the choice of target, and where R is looked up.

use std::path::Path;

use abnf::{
    Context, Grammar, GrammarError, GrammarErrorKind as K, Kind, LoadOptions,
    constraint::{Constraint, Misuse},
};

fn core_text() -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../grammars/core.abnf");
    std::fs::read(p).expect("grammars/core.abnf")
}

fn load_kind(text: &str, kind: Kind) -> Result<Grammar, GrammarError> {
    let core = core_text();
    let opts = LoadOptions {
        kind,
        ..LoadOptions::default()
    };
    Grammar::load("t", text.as_bytes(), &mut |_| Some(core.clone()), &opts)
}

/// Loads `text` after `; uses: core`, so it is strict.
fn load(text: &str) -> Result<Grammar, GrammarError> {
    load_kind(&format!("; uses: core\n{text}"), Kind::Auto)
}

fn misuse(text: &str) -> Misuse {
    match load(text).expect_err("should not load").kind {
        K::Constraint(m) => m,
        other => panic!("{other:?}"),
    }
}

fn c(g: &Grammar, rule: &str, input: &[u8]) -> bool {
    g.matches_constrained(g.rule(rule).unwrap(), input, &Context::default())
        .unwrap()
}

#[test]
fn attachment() {
    // On the rule's line, and on a continuation line.
    let g = load("a = u8 ; constraint: not 0\nb = u8\n    ; constraint: not 1\n").unwrap();
    assert_eq!(g.constraints(g.rule("a").unwrap())[0].1, Constraint::Not(0));
    assert_eq!(g.constraints(g.rule("b").unwrap())[0].1, Constraint::Not(1));
    // At column 0, between rules, or after a blank line: outside every rule.
    let e = load("a = u8\n; constraint: not 0\nb = u8\n").unwrap_err();
    assert_eq!((e.kind, e.line), (K::Attachment, 3));
    assert_eq!(
        load("a = u8\n\n; constraint: not 0\n").unwrap_err().kind,
        K::Attachment
    );
}

#[test]
fn prose_and_strictness() {
    let prose = "a = u8 ; constraint: a power of two.\n";
    // Strict: core, a grammar that uses core, or the caller's choice.
    assert_eq!(load(prose).unwrap_err().kind, K::Prose);
    assert_eq!(
        load_kind("a = OCTET ; constraint: a power of two.\n", Kind::Strict)
            .unwrap_err()
            .kind,
        K::Prose
    );
    assert_eq!(
        load("a = u8 ; constraint:not 0\n").unwrap_err().kind,
        K::Prose,
        "no space after the marker"
    );
    // Lenient: counted, never enforced.
    let g = load_kind("a = OCTET ; constraint: a power of two.\n", Kind::Auto).unwrap();
    assert_eq!(g.prose_constraints(), 1);
    assert!(c(&g, "a", b"\x03"));
    // A vocabulary form in a lenient grammar is enforced.
    let g = load_kind("a = OCTET ; constraint: not 3\n", Kind::Auto).unwrap();
    assert_eq!(g.prose_constraints(), 0);
    assert!(!c(&g, "a", b"\x03"));
}

/// Every form loads where it applies.
#[test]
fn every_form_loads() {
    let g = load(
        "n = u8\n\
         o = n *OCTET ; constraint: exactly n octets\n\
         e = n *u8 ; constraint: exactly n u8 elements\n\
         w = n *OCTET ; constraint: exactly n words\n\
         h = n 7OCTET *OCTET ; constraint: header words n\n\
         v = i16 ; constraint: at most -1\n\
         l = i16 ; constraint: at least -5\n\
         r = i16 ; constraint: in -5..-1\n\
         x = u8 ; constraint: not 0\n\
         y = u8 ; constraint: not one of 1, 2\n\
         s = 1*%x61-7A ; constraint: length at most 3\n\
         k = 1*%x61-7A ; constraint: not word if\n\
         a = *n ; constraint: ascending n\n\
         t = *tail-field ; constraint: ascending tags\n\
         p = u8 ; constraint: capability index\n\
         f = 4OCTET ; constraint: canonical float\n\
         m = *OCTET ; constraint: remaining octets\n",
    )
    .unwrap();
    assert_eq!(g.prose_constraints(), 0);
    assert!(c(&g, "a", b"\x01\x02\x05"));
    assert!(!c(&g, "a", b"\x01\x05\x02"));
    assert!(c(&g, "r", b"\xff\xfb") && !c(&g, "r", b"\x00\x00"));
    assert!(c(&g, "h", b"\x02\x00\x00\x00\x00\x00\x00\x00abcdefgh"));
    assert!(!c(&g, "h", b"\x02\x00\x00\x00\x00\x00\x00\x00abcdefg"));
}

#[test]
fn misuses_are_load_errors() {
    assert_eq!(
        misuse("a = u8 *OCTET ; constraint: exactly nosuch octets\n"),
        Misuse::Undefined("nosuch".into())
    );
    assert_eq!(
        misuse("a = *OCTET ; constraint: at most 3\n"),
        Misuse::NoReading("a".into())
    );
    assert_eq!(
        misuse("r = *OCTET\na = r *OCTET ; constraint: exactly r octets\n"),
        Misuse::NoReading("r".into())
    );
    assert_eq!(
        misuse("r = 17OCTET\na = r ; constraint: not 0\n"),
        Misuse::NoReading("a".into()),
        "unsigned readings are 1 to 16 octets"
    );
    assert_eq!(
        misuse("a = u8 ; constraint: at least -1\n"),
        Misuse::Negative
    );
    assert_eq!(
        misuse("a = 1*DIGIT ; constraint: not -1\n"),
        Misuse::Negative
    );
    assert_eq!(misuse("a = u8 ; constraint: in 5..1\n"), Misuse::EmptyRange);
    assert_eq!(
        misuse("a = u8 *OCTET / \"x\" ; constraint: exactly u8 octets\n"),
        Misuse::NotOneConcatenation
    );
    assert_eq!(
        misuse("a = u8 *OCTET ; constraint: exactly u8 octets\na =/ \"x\"\n"),
        Misuse::NotOneConcatenation,
        "=/ makes an alternation"
    );
    assert_eq!(
        misuse("a = u8 4OCTET ; constraint: exactly u8 OCTET elements\n"),
        Misuse::NoRepetition
    );
    assert_eq!(
        misuse("a = *u8 ; constraint: ascending nosuch\n"),
        Misuse::Undefined("nosuch".into())
    );
    assert_eq!(
        misuse("a = [u8] ; constraint: ascending u8\n"),
        Misuse::NoRepetition,
        "an option is no target"
    );
    assert_eq!(
        misuse("a = u8 *u16 ; constraint: exactly u8 u8 elements\n"),
        Misuse::WrongElement("u8".into())
    );
    assert_eq!(
        misuse("a = u8 *u16 ; constraint: exactly u8 nosuch elements\n"),
        Misuse::Undefined("nosuch".into())
    );
    assert_eq!(
        misuse("a = *u8 ; constraint: ascending tags\n"),
        Misuse::ShortTags
    );
    assert_eq!(
        misuse("a = u16 ; constraint: canonical float\n"),
        Misuse::NotFloat
    );
    // The line is the constraint's.
    let e = load("a = u8\n  ; constraint: in 5..1\n").unwrap_err();
    assert_eq!(e.line, 3);
}

/// The target is the first element with a variable repeat: not a fixed
/// count and not an option.
#[test]
fn the_target_is_the_first_variable_repetition() {
    let g = load("a = u8 2OCTET [%x00] *%x41 *%x42 ; constraint: exactly u8 octets\n").unwrap();
    // u8 is 0, so `*%x41` holds nothing; the option still takes %x00.
    assert!(c(&g, "a", b"\x00zz\x00"));
    assert!(c(&g, "a", b"\x01zz\x00AB"));
    assert!(!c(&g, "a", b"\x02zz\x00AB"));
    // No variable repetition: the whole match is the target.
    let g = load("n = u8\nw = 2OCTET ; constraint: exactly n octets\nx = n w\n").unwrap();
    assert!(c(&g, "x", b"\x02ab"));
    assert!(!c(&g, "x", b"\x03ab"));
}

/// Several forms on one target apply together, and each can fail alone.
#[test]
fn forms_on_one_target_apply_together() {
    let g = load(
        "item = u8\n\
         run = u8 *item\n\
         \x20     ; constraint: exactly u8 octets\n\
         \x20     ; constraint: ascending item\n",
    )
    .unwrap();
    assert!(c(&g, "run", b"\x03\x01\x02\x03"));
    assert!(!c(&g, "run", b"\x03\x01\x03\x02"), "ascending only");
    assert!(!c(&g, "run", b"\x02\x01\x02\x03"), "exactly only");
    // And with core's tail: ascending tags, and the count.
    let g = load("").unwrap();
    let field = |t: u8| [0, t, 0, 0, 0, 0];
    let tail = |n: u8, tags: &[u8]| {
        let mut v = vec![0, 0, 0, n];
        for &t in tags {
            v.extend(field(t));
        }
        v
    };
    assert!(c(&g, "tail", &tail(2, &[1, 2])));
    assert!(!c(&g, "tail", &tail(2, &[2, 1])), "ascending tags only");
    assert!(!c(&g, "tail", &tail(3, &[1, 2])), "the count only");
}

/// R is the latest match in the rule, else in the rules that called it,
/// never one buried inside another rule's match.
#[test]
fn where_r_is_found() {
    let g = load(
        "rest = *OCTET ; constraint: exactly len32 octets\n\
         direct = len32 rest\n\
         buried = octets rest\n\
         latest = len32 len32 rest\n",
    )
    .unwrap();
    assert!(c(&g, "direct", b"\x00\x00\x00\x01\xbb"));
    // The len32 inside octets binds in octets, not in buried.
    assert!(!c(&g, "buried", b"\x00\x00\x00\x01\xaa\xbb"));
    // The second len32 is the latest.
    assert!(c(&g, "latest", b"\x00\x00\x00\x05\x00\x00\x00\x01\xbb"));
    assert!(!c(&g, "latest", b"\x00\x00\x00\x01\x00\x00\x00\x05\xbb"));
    // Alone, rest has no R.
    assert!(!c(&g, "rest", b""));
}
