// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The repository's own grammars and vectors (ADR 0013, rule 6; ADR 0062,
//! rule 8), read by path from the workspace root.

use std::path::{Path, PathBuf};

use abnf::{
    Grammar, Kind, LoadOptions,
    constraint::{self, Constraint},
    vectors::{self, Tag, Verdict},
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> Vec<u8> {
    std::fs::read(root().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn load(name: &str) -> Grammar {
    let kind = if name == "core" {
        Kind::Core
    } else {
        Kind::Auto
    };
    let opts = LoadOptions {
        kind,
        ..LoadOptions::default()
    };
    let text = read(&format!("grammars/{name}.abnf"));
    Grammar::load(
        name,
        &text,
        &mut |n| Some(read(&format!("grammars/{n}.abnf"))),
        &opts,
    )
    .unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Every vector of the grammar agrees, constraints enforced: each `ok`
/// keeps them, and each `errc` matches context-free but breaks one.
/// Returns how many vectors agree, and how many of those are `errc`.
fn agrees(name: &str) -> (usize, usize) {
    let g = load(name);
    let f = vectors::parse(&read(&format!("grammars/{name}.vectors"))).unwrap();
    let report = vectors::check(&g, &f);
    let bad: Vec<&(usize, Verdict)> = report
        .results
        .iter()
        .filter(|(_, v)| *v != Verdict::Agrees)
        .collect();
    assert!(bad.is_empty(), "{name}.vectors: {bad:?}");
    (report.agree, report.errc)
}

/// The core grammar is byte for byte the block in the call-language note,
/// so they can't drift apart. `cargo xtask grammars` checks the same on
/// every change, documents included.
#[test]
fn core_matches_the_note() {
    let note = String::from_utf8(read("docs/design/call-language.md")).unwrap();
    let block: String = note
        .lines()
        .skip_while(|l| *l != "### The core grammar")
        .skip_while(|l| *l != "```abnf")
        .skip(1)
        .take_while(|l| *l != "```")
        .map(|l| format!("{l}\n"))
        .collect();
    assert_eq!(block.as_bytes(), read("grammars/core.abnf"));
}

#[test]
fn core() {
    let g = load("core");
    assert_eq!(g.prose_constraints(), 0);
    let u8_ = g.rule("u8").unwrap();
    assert!(g.is_core(u8_));
    assert_eq!(g.fixed_width(u8_), Some(1));
    assert_eq!(g.fixed_width(g.rule("uuid").unwrap()), Some(16));
    assert!(g.is_signed(g.rule("i64").unwrap()));
    let tail = g.rule("tail").unwrap();
    let forms: Vec<&Constraint> = g.constraints(tail).iter().map(|(_, c)| c).collect();
    assert_eq!(
        forms,
        [
            &Constraint::AscendingTags,
            &Constraint::ExactlyElements("tail-count".into(), "tail-field".into())
        ]
    );
    // Every form core uses has an errc vector that only it rejects.
    let (all, errc) = agrees("core");
    assert!(all >= 160 && errc >= 27, "{all} vectors, {errc} errc");
}

#[test]
fn constraint_grammar() {
    assert!(agrees("constraint").0 >= 60);
}

#[test]
fn hand_written_grammars_stay_lenient() {
    let g = load("initfs");
    assert!(g.prose_constraints() > 0);
    assert!(g.rule("u8").is_none(), "initfs doesn't use core");
    assert!(agrees("initfs").0 > 0);
    assert_eq!(load("kernel-args").prose_constraints(), 0);
    assert!(agrees("kernel-args").0 > 0);
}

/// `constraint::parse` and `constraint::constraint_text` agree with every
/// line of `grammars/constraint.vectors`, the vocabulary's own vectors.
#[test]
fn the_vocabulary_parser_agrees_with_its_grammar() {
    let f = vectors::parse(&read("grammars/constraint.vectors")).unwrap();
    let mut checked = 0;
    for v in &f.vectors {
        let text = std::str::from_utf8(&v.octets).unwrap();
        let parses = match v.rule.as_str() {
            "constraint" => constraint::parse(text).is_ok(),
            "constraint-comment" => {
                matches!(constraint::constraint_text(text), Some(Ok(t)) if constraint::parse(t).is_ok())
            }
            other => panic!("line {}: an unexpected rule {other}", v.line),
        };
        let expect = v.tag != Tag::Err;
        assert_eq!(parses, expect, "constraint.vectors:{}: {text:?}", v.line);
        checked += 1;
    }
    assert!(checked >= 60);
}

/// `OutOfRange` means the grammar allows the text, so a syntax error
/// anywhere in it comes first: a regression from C71's `abnf-constraint`
/// fuzz target (`fuzz/regressions/abnf-constraint/`), where an
/// out-of-range first integer hid a malformed second one.
#[test]
fn out_of_range_only_for_well_formed_text() {
    use constraint::ConstraintError::{OutOfRange, Syntax};
    let p = |t: &str| constraint::parse(t);
    assert_eq!(p("in 92233720368570248578.."), Err(Syntax));
    assert_eq!(p("in 92233720368570248578..x"), Err(Syntax));
    assert_eq!(p("in 92233720368570248578..1"), Err(OutOfRange));
    assert_eq!(p("not one of 99999999999999999999, x"), Err(Syntax));
    assert_eq!(p("not one of 99999999999999999999, 1"), Err(OutOfRange));
    assert_eq!(p("length at most -99999999999999999999"), Err(Syntax));
    assert_eq!(p("length at most 99999999999999999999"), Err(OutOfRange));
}

/// The parser's readings of each form, beyond what the vectors show.
#[test]
fn the_vocabulary_readings() {
    use Constraint as C;
    let p = |t: &str| constraint::parse(t);
    assert_eq!(
        p("exactly len32 octets"),
        Ok(C::ExactlyOctets("len32".into()))
    );
    assert_eq!(p("in -5..5"), Ok(C::In(-5, 5)));
    assert_eq!(
        p("in -9223372036854775808..18446744073709551615"),
        Ok(C::In(i128::from(i64::MIN), i128::from(u64::MAX)))
    );
    assert_eq!(
        p("at most 18446744073709551616"),
        Err(constraint::ConstraintError::OutOfRange)
    );
    assert_eq!(
        p("at least -9223372036854775809"),
        Err(constraint::ConstraintError::OutOfRange)
    );
    assert_eq!(
        p("at most 99999999999999999999999999999999999999999"),
        Err(constraint::ConstraintError::OutOfRange)
    );
    assert_eq!(p("not one of 1, -2"), Ok(C::NotOneOf(vec![1, -2])));
    assert_eq!(
        p("not word a b"),
        Ok(C::NotWord(vec!["a".into(), "b".into()]))
    );
    assert_eq!(p("length at most 0"), Ok(C::LengthAtMost(0)));
    assert_eq!(p("ascending tags"), Ok(C::AscendingTags));
    assert_eq!(p("ascending Tags"), Ok(C::Ascending("Tags".into())));
    assert_eq!(constraint::constraint_text("; plain comment"), None);
    assert_eq!(constraint::constraint_text("; constraint:x"), Some(Err(())));
    assert_eq!(
        constraint::constraint_text(";\tconstraint:  not 0 \t"),
        Some(Ok("not 0"))
    );
}
