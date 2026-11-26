// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The vector reader and the verdicts (docs/design/call-language.md,
//! "Vector files"; ADR 0062, rule 8).

use std::time::{Duration, Instant};

use abnf::{
    Exhausted, Grammar, Limits, LoadOptions,
    vectors::{self, Tag, Vector, VectorErrorKind as E, Verdict},
};

fn parse(text: &str) -> Result<vectors::VectorFile, E> {
    vectors::parse(text.as_bytes()).map_err(|e| e.kind)
}

fn one(text: &str) -> Vector {
    let mut f = parse(text).expect("reads");
    assert_eq!(f.vectors.len(), 1);
    f.vectors.remove(0)
}

#[test]
fn escapes_and_bodies() {
    let v = one("# rule: r\nok\ta\\tb\\\\c\\\"d\\x00\\xFf\\x7e \u{e9}\n");
    assert_eq!(v.octets, b"a\tb\\c\"d\x00\xff\x7e \xc3\xa9");
    assert_eq!((v.line, v.tag, v.rule.as_str()), (2, Tag::Ok, "r"));
    // A later tab is part of the body.
    assert_eq!(one("ok@r\ta\tb").octets, b"a\tb");
    // An empty body is an empty vector.
    assert_eq!(one("err@r\t").octets, b"");
    assert_eq!(parse("ok@r\t\\q").unwrap_err(), E::Escape);
    assert_eq!(parse("ok@r\t\\x4").unwrap_err(), E::Escape);
    assert_eq!(parse("ok@r\t\\x4g").unwrap_err(), E::Escape);
    assert_eq!(parse("ok@r\t\\x+1").unwrap_err(), E::Escape);
    assert_eq!(parse("ok@r\t\\").unwrap_err(), E::Escape);
}

#[test]
fn lines_and_tags() {
    assert_eq!(
        parse("# rule: r\nok").unwrap_err(),
        E::Line,
        "every line has its tab"
    );
    assert_eq!(parse("# rule: r\nok x").unwrap_err(), E::Line);
    assert_eq!(parse("# rule: r\nOK\tx").unwrap_err(), E::Line);
    assert_eq!(parse("# rule: r\nerrx\tx").unwrap_err(), E::Line);
    assert_eq!(parse("ok@\tx").unwrap_err(), E::Line);
    assert_eq!(parse("ok@1r\tx").unwrap_err(), E::Line);
    assert_eq!(one("errc@Some-Rule2\tx").tag, Tag::Errc);
    assert_eq!(parse("ok\tx").unwrap_err(), E::NoRule);
    // "# rule:" holds for the whole file, wherever it is.
    assert_eq!(one("ok\tx\n# rule: late").rule, "late");
    // Comments and empty lines are skipped.
    let f =
        parse("# a comment\n\n#rules are fine here\n# Rule: not a directive\nok@r\tx\n").unwrap();
    assert_eq!(f.vectors.len(), 1);
}

#[test]
fn directives() {
    let f = parse("# rule: r\n# max-length: 4096\nok\tx\n").unwrap();
    assert_eq!((f.rule.as_deref(), f.max_length), (Some("r"), Some(4096)));
    assert_eq!(
        parse("# rule: r\n# rule: r\n").unwrap_err(),
        E::RepeatedDirective
    );
    assert_eq!(
        parse("# max-length: 1\n# max-length: 2\n").unwrap_err(),
        E::RepeatedDirective
    );
    for bad in [
        "# rule:r",
        "#rule: r",
        "# rule : r",
        "# rule: r ",
        "# rule: 1r",
        "# rule:  r",
        "# max-length: -1",
        "# max-length: 0x10",
        "# max-length: 99999999999999999999",
        "# caps: 4",
        "# caps: 9",
        "#caps: 2",
        "# caps:2",
        "# unwrapped: 8",
        "# unwrapped: 10",
        "\t# not a directive line, but a vector with no tag",
    ] {
        assert!(parse(bad).is_err(), "{bad:?} should not read");
    }
    // Positional: caps and unwrapped hold until changed, and caps resets
    // the mask.
    let f = parse(
        "ok@r\ta\n# caps: 3\n# unwrapped: 5\nok@r\tb\n# caps: 2\nok@r\tc\n# unwrapped: 3\nok@r\td\n",
    )
    .unwrap();
    let got: Vec<(u8, u8)> = f.vectors.iter().map(|v| (v.caps, v.unwrapped)).collect();
    assert_eq!(got, [(0, 0), (3, 5), (2, 0), (2, 3)]);
    assert_eq!(
        parse("# caps: 1\n# unwrapped: 2\n").unwrap_err(),
        E::UnwrappedBeyondCaps
    );
    assert_eq!(
        parse("# unwrapped: 1\n").unwrap_err(),
        E::UnwrappedBeyondCaps
    );
    assert!(parse("# unwrapped: 0\n").is_ok());
}

#[test]
fn text_encoding() {
    assert_eq!(
        vectors::parse(b"ok@r\t\xff\n").unwrap_err().kind,
        E::NotUtf8
    );
    let e = vectors::parse(b"# rule: r\nok\tx\r\n").unwrap_err();
    assert_eq!((e.line, e.kind), (2, E::CarriageReturn));
}

fn grammar(text: &str, limits: Limits) -> Grammar {
    let core = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../grammars/core.abnf"
    ))
    .unwrap();
    let opts = LoadOptions {
        limits,
        ..LoadOptions::default()
    };
    Grammar::load("t", text.as_bytes(), &mut |_| Some(core.clone()), &opts).unwrap()
}

/// The verdicts: `ok` needs the full judgment, `err` the context-free one
/// to fail, and `errc` the context-free one to hold and the full one to
/// fail (ADR 0062, rule 8).
#[test]
fn verdicts() {
    let g = grammar(
        "; uses: core\n\
         ab = \"a\" \"b\"\n\
         small = u8\n\
         \x20     ; constraint: at most 9\n",
        Limits::default(),
    );
    let file = "# rule: ab\n# max-length: 2\n\
                ok\tab\n\
                ok\tabc\n\
                err\tabc\n\
                err\tab\n\
                errc\tab\n\
                errc\ta\n\
                ok@nosuch\tab\n\
                err\tAB\n\
                ok@small\t\\x09\n\
                ok@small\t\\x0a\n\
                errc@small\t\\x0a\n\
                err@small\t\\x0a\n";
    let report = vectors::check(&g, &vectors::parse(file.as_bytes()).unwrap());
    let verdicts: Vec<Verdict> = report.results.iter().map(|(_, v)| *v).collect();
    let no = |context_free, constrained| Verdict::Disagrees {
        context_free,
        constrained,
    };
    assert_eq!(
        verdicts,
        [
            Verdict::Agrees,
            no(false, false),
            Verdict::Agrees,
            no(true, true),
            // An errc vector that keeps every constraint disagrees.
            no(true, true),
            no(false, false),
            Verdict::UnknownRule,
            // Char-vals ignore case.
            no(true, true),
            Verdict::Agrees,
            no(true, false),
            Verdict::Agrees,
            no(true, false),
        ]
    );
    assert_eq!((report.agree, report.errc, report.disagree), (4, 1, 8));
    let lines: Vec<usize> = report.results.iter().map(|(l, _)| *l).collect();
    assert_eq!(lines, (3..=14).collect::<Vec<usize>>());
}

#[test]
fn max_length_belongs_to_the_context_free_judgment() {
    let g = grammar("r = *\"a\"\n", Limits::default());
    let f =
        vectors::parse(b"# rule: r\n# max-length: 3\nok\taaa\nerr\taaaa\nerrc\taaaa\n").unwrap();
    let verdicts: Vec<Verdict> = vectors::check(&g, &f)
        .results
        .iter()
        .map(|(_, v)| *v)
        .collect();
    assert_eq!(
        verdicts,
        [
            Verdict::Agrees,
            Verdict::Agrees,
            Verdict::Disagrees {
                context_free: false,
                constrained: false,
            }
        ]
    );
}

/// The capability directives reach the constrained judgment: a whole
/// body names every capability, in order.
#[test]
fn caps_directives_reach_the_judgment() {
    let g = grammar("; uses: core\npair = cap-ref cap-ref\n", Limits::default());
    let f = vectors::parse(
        b"# rule: pair\nerrc\t\\x00\\x01\n# caps: 2\nok\t\\x00\\x01\n# unwrapped: 3\nok\t\\x00\\x01\n",
    )
    .unwrap();
    let report = vectors::check(&g, &f);
    assert_eq!(
        (report.agree, report.disagree),
        (3, 0),
        "{:?}",
        report.results
    );
}

#[test]
fn exhaustion_is_a_failure() {
    let limits = Limits {
        input_octets: 4,
        ..Limits::default()
    };
    let g = grammar("r = *\"a\"\n", limits);
    let f = vectors::parse(b"# rule: r\nok\taaaa\nok\taaaaa\nerr\taaaaa\n").unwrap();
    let report = vectors::check(&g, &f);
    assert_eq!(report.results[0].1, Verdict::Agrees);
    // The check stops at the first vector over a budget.
    assert_eq!(report.results[1].1, Verdict::Exhausted(Exhausted::Input));
    assert_eq!(report.results.len(), 2);
    assert_eq!((report.agree, report.disagree, report.unjudged), (1, 1, 1));
}

/// A file of many vectors, each of which would exhaust its own budget,
/// costs no more than one budget: the check stops at the first.
#[test]
fn a_file_of_exhausting_vectors_stops_at_the_first() {
    let g = grammar("x = 4294967295\"\"\n", Limits::default());
    let text = format!("# rule: x\n{}", "ok\t\n".repeat(10_000));
    let f = vectors::parse(text.as_bytes()).unwrap();
    let start = Instant::now();
    let report = vectors::check(&g, &f);
    assert_eq!(report.results, [(2, Verdict::Exhausted(Exhausted::Steps))]);
    assert_eq!(report.unjudged, 9_999);
    assert!(start.elapsed() < Duration::from_secs(10));
}

/// Vectors that each stay within their own budget still share one budget
/// for the whole file.
#[test]
fn a_file_shares_one_step_budget() {
    // Each match of 1,000 empty strings takes a few thousand steps.
    let limits = Limits {
        file_steps: 1_000_000,
        ..Limits::default()
    };
    let g = grammar("x = 1000\"\"\n", limits);
    let text = format!("# rule: x\n{}", "ok\t\n".repeat(10_000));
    let f = vectors::parse(text.as_bytes()).unwrap();
    let report = vectors::check(&g, &f);
    assert!(report.agree > 0, "{:?}", &report.results[..1]);
    assert_eq!(
        report.results.last().map(|r| r.1),
        Some(Verdict::Exhausted(Exhausted::Steps))
    );
    assert_eq!(report.disagree, 1);
    assert_eq!(report.agree + report.disagree + report.unjudged, 10_000);
}
