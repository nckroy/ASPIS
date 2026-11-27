// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The grammar generator keeps its guarantees (docs/design/call-language.md,
//! "The harness"): every grammar loads, with no left recursion and no
//! undefined rule; every rule derives a string; every derivation matches;
//! generation is deterministic; the verdicts are balanced enough to test
//! both answers; and every construct appears.

mod common;

use std::collections::BTreeSet;

use abnf::{GrammarErrorKind, Kind};
use fuzz_gate::{
    abnf_targets::load_generated,
    generate::{self, Base, Bytes, CharCase, Elem, NumVal, Origin, Repeat},
};

const SEEDS: u64 = 10_000;

#[test]
fn every_grammar_loads_and_every_derivation_matches() {
    common::on_big_stack(|| {
        let (mut ok, mut err, mut exhausted) = (0usize, 0usize, 0usize);
        for i in 0..SEEDS {
            let c = generate::seeded(0, i);
            let text = String::from_utf8_lossy(&c.text).into_owned();
            let g = match load_generated(&c.text, Kind::Auto) {
                Ok(g) => g,
                Err(e) => {
                    assert!(
                        !matches!(
                            e.kind,
                            GrammarErrorKind::LeftRecursive(_) | GrammarErrorKind::Undefined(_)
                        ),
                        "case {i}: {e}\n{text}"
                    );
                    panic!("case {i} doesn't load: {e}\n{text}");
                }
            };
            for (r, s) in c.shortest.iter().enumerate() {
                let id = g.rule(&c.rules[r].name).unwrap();
                assert_ne!(
                    g.matches(id, s),
                    Ok(false),
                    "case {i}: {}'s shortest derivation {s:?}\n{text}",
                    c.rules[r].name
                );
            }
            for input in &c.inputs {
                let id = g.rule(&c.rules[input.rule].name).unwrap();
                match g.matches(id, &input.octets) {
                    Ok(true) => ok += 1,
                    Ok(false) => {
                        assert_ne!(
                            input.origin,
                            Origin::Derived,
                            "case {i}: {:?} doesn't match {}\n{text}",
                            input.octets,
                            c.rules[input.rule].name
                        );
                        err += 1;
                    }
                    Err(_) => exhausted += 1,
                }
            }
        }
        let total = ok + err + exhausted;
        eprintln!("{SEEDS} cases, {total} inputs: {ok} ok, {err} err, {exhausted} exhausted");
        assert!(ok * 5 >= total, "fewer than 20 % of the inputs match");
        assert!(
            err * 5 >= total,
            "fewer than 20 % of the inputs don't match"
        );
        assert!(exhausted * 100 < total, "1 % or more ran out of a budget");
    });
}

#[test]
fn generation_is_deterministic() {
    for i in 0..200 {
        assert_eq!(generate::seeded(7, i), generate::seeded(7, i));
    }
    let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    assert_eq!(
        generate::case(&mut Bytes(&data)),
        generate::case(&mut Bytes(&data))
    );
}

#[test]
fn zeros_make_the_smallest_case() {
    for data in [&[][..], &[0u8; 4096][..]] {
        let c = generate::case(&mut Bytes(data));
        assert_eq!(c.rules.len(), 1);
        assert!(c.inputs.is_empty());
        assert_eq!(c.text, b"r0= \"a\"\n");
    }
}

/// A name for each construct an element is, so the test can see which
/// ones appear.
fn constructs(e: &Elem, out: &mut BTreeSet<String>) {
    e.visit(&mut |e| {
        let name = match e {
            Elem::Alt(_) => "alternation".into(),
            Elem::Cat(_) => "concatenation".into(),
            Elem::Group(_) => "group".into(),
            Elem::Opt(_) => "option".into(),
            Elem::Rep(r, _) => format!(
                "repeat {}",
                match r {
                    Repeat::Star => "*",
                    Repeat::AtLeast(1) => "1*",
                    Repeat::AtLeast(_) => "n*",
                    Repeat::Between(..) => "n*m",
                    Repeat::Exactly(_) => "n",
                    Repeat::AtMost(_) => "*m",
                    Repeat::Zero => "0*0",
                }
            ),
            Elem::Char { text, case } => format!(
                "char-val {} {}",
                match case {
                    CharCase::Plain => "plain",
                    CharCase::Sensitive => "%s",
                    CharCase::Insensitive => "%i",
                },
                if text.is_empty() { "empty" } else { "text" }
            ),
            Elem::Num { base, val } => format!(
                "num-val {} {}",
                match base {
                    Base::Bin => "b",
                    Base::Dec => "d",
                    Base::Hex => "x",
                },
                match val {
                    NumVal::Single(_) => "single",
                    NumVal::Range(..) => "range",
                    NumVal::Seq(_) => "concatenated",
                }
            ),
            Elem::Core(c) => format!("core {}", c.name()),
            Elem::Ref(_) => "reference".into(),
        };
        out.insert(name);
    });
}

#[test]
fn every_construct_appears() {
    let mut seen = BTreeSet::new();
    let mut text = BTreeSet::new();
    let mut origins = BTreeSet::new();
    for i in 0..1000 {
        let c = generate::seeded(1, i);
        for r in &c.rules {
            constructs(&r.body, &mut seen);
        }
        let t = String::from_utf8(c.text.clone()).unwrap();
        for (feature, present) in [
            ("=/", t.contains("=/")),
            ("CRLF", t.contains("\r\n")),
            ("tab", t.contains('\t')),
            ("comment", t.contains("; a note")),
            ("continuation", t.contains("\n ") || t.contains("\n\t")),
            (
                "upper-case reference",
                t.contains(" R") || t.contains("\tR"),
            ),
            ("%S", t.contains("%S")),
            ("%X", t.contains("%X")),
            (
                "mixed-case hex",
                t.contains("%x") && t.chars().any(|c| c.is_ascii_uppercase()),
            ),
            (
                "upper-case rule name",
                t.starts_with('R') || t.contains("\nR"),
            ),
            (
                "lower-case core rule",
                t.contains("alpha") || t.contains("wsp") || t.contains("octet"),
            ),
        ] {
            if present {
                text.insert(feature);
            }
        }
        origins.extend(c.inputs.iter().map(|i| format!("{:?}", i.origin)));
    }
    let mut want: Vec<String> = [
        "alternation",
        "concatenation",
        "group",
        "option",
        "reference",
        "repeat *",
        "repeat 1*",
        "repeat n*",
        "repeat n*m",
        "repeat n",
        "repeat *m",
        "repeat 0*0",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for case in ["plain", "%s", "%i"] {
        want.push(format!("char-val {case} text"));
        want.push(format!("char-val {case} empty"));
    }
    for base in ["b", "d", "x"] {
        for kind in ["single", "range", "concatenated"] {
            want.push(format!("num-val {base} {kind}"));
        }
    }
    for c in generate::CoreRule::ALL {
        want.push(format!("core {}", c.name()));
    }
    let missing: Vec<&String> = want.iter().filter(|w| !seen.contains(*w)).collect();
    assert!(
        missing.is_empty(),
        "constructs never generated: {missing:?}"
    );
    assert_eq!(text.len(), 11, "text features seen: {text:?}");
    assert_eq!(origins.len(), 3, "input origins seen: {origins:?}");
}
