// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Loading grammars: every RFC 5234 construct, the errors the checker
//! raises at load, `; uses:`, reserved names (ADR 0062, rule 3), the
//! limits, and that loading stays fast and shallow on large grammars.

use std::{collections::BTreeMap, path::Path, time::Instant};

use abnf::{Grammar, GrammarError, GrammarErrorKind as K, Kind, Limits, LoadOptions};

fn core_text() -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../grammars/core.abnf");
    std::fs::read(p).expect("grammars/core.abnf")
}

/// Loads `text` as grammar "t", with `others` as the grammars it may use,
/// and the repository's core.
fn load_with(
    text: &str,
    others: &[(&str, &str)],
    opts: &LoadOptions,
) -> Result<Grammar, GrammarError> {
    let mut files: BTreeMap<String, Vec<u8>> = others
        .iter()
        .map(|(n, t)| (n.to_string(), t.as_bytes().to_vec()))
        .collect();
    files.entry("core".into()).or_insert_with(core_text);
    Grammar::load("t", text.as_bytes(), &mut |n| files.get(n).cloned(), opts)
}

fn load(text: &str) -> Result<Grammar, GrammarError> {
    load_with(text, &[], &LoadOptions::default())
}

fn kind(text: &str) -> K {
    load(text).expect_err("should not load").kind
}

/// Whether `input` matches `rule`, context-free.
fn m(g: &Grammar, rule: &str, input: &[u8]) -> bool {
    g.matches(g.rule(rule).expect("rule"), input)
        .expect("within budget")
}

#[test]
fn rulelist_comments_and_continuation() {
    let g = load(
        "; a header comment\n\
         \n\
         a = \"x\"   ; a comment\n\
         \x20   \"y\" ; continued on an indented line\n\
         \x20   ; a comment-only continuation\n\
         ; between rules\n\
         b = a\n",
    )
    .unwrap();
    assert!(m(&g, "a", b"xy"));
    assert!(m(&g, "B", b"XY"), "rule names and char-vals ignore case");
    assert!(!m(&g, "a", b"x"));
}

#[test]
fn line_ends() {
    let crlf = load("a = \"x\"\r\n  \"y\"\r\nb = a\r\n").unwrap();
    assert!(m(&crlf, "b", b"xy"));
    let no_final_newline = load("a = \"x\"").unwrap();
    assert!(m(&no_final_newline, "a", b"x"));
    assert_eq!(
        kind("a = \"x\"\r b = \"y\"\n"),
        K::NotAscii,
        "a CR not before LF"
    );
    assert_eq!(kind("a = \"\u{e9}\"\n"), K::NotAscii);
    assert_eq!(kind("a = \"x\"\x0c\n"), K::NotAscii);
}

#[test]
fn a_blank_line_ends_a_rule() {
    assert_eq!(kind("a = \"x\"\n\n  \"y\"\n"), K::Syntax);
    assert_eq!(
        kind("  a = \"x\"\n"),
        K::Syntax,
        "a rule starts at column 0"
    );
    // An indented comment after a blank line belongs to no rule.
    assert!(load("a = \"x\"\n\n  ; fine\nb = \"y\"\n").is_ok());
}

#[test]
fn repetition() {
    let g = load(
        "r1 = 3\"a\"\nr2 = 2*\"a\"\nr3 = *2\"a\"\nr4 = 1*2\"a\"\nr5 = *\"a\"\n\
         r6 = 0\"a\"\nr7 = [\"a\"] \"b\"\nr8 = (\"a\" / \"b\") \"c\"\n",
    )
    .unwrap();
    assert!(m(&g, "r1", b"aaa") && !m(&g, "r1", b"aa") && !m(&g, "r1", b"aaaa"));
    assert!(m(&g, "r2", b"aa") && m(&g, "r2", b"aaaaa") && !m(&g, "r2", b"a"));
    assert!(m(&g, "r3", b"") && m(&g, "r3", b"aa") && !m(&g, "r3", b"aaa"));
    assert!(m(&g, "r4", b"a") && m(&g, "r4", b"aa") && !m(&g, "r4", b""));
    assert!(m(&g, "r5", b"") && m(&g, "r5", b"aaaaaaaa"));
    assert!(m(&g, "r6", b"") && !m(&g, "r6", b"a"));
    assert!(m(&g, "r7", b"ab") && m(&g, "r7", b"b"));
    assert!(m(&g, "r8", b"ac") && m(&g, "r8", b"bc") && !m(&g, "r8", b"c"));
    assert_eq!(kind("a = 3*2\"a\"\n"), K::RepeatRange);
    assert_eq!(kind("a = 4294967296\"a\"\n"), K::RepeatRange);
    assert_eq!(kind("a = *4294967296\"a\"\n"), K::RepeatRange);
    assert!(load("a = 4294967295\"a\"\n").is_ok());
    assert_eq!(
        kind("a = 3 \"a\"\n"),
        K::Syntax,
        "a repeat joins its element"
    );
}

#[test]
fn char_vals() {
    let g = load(
        "d = \"Ab\"\ni = %i\"Ab\"\ns = %s\"Ab\"\nt2 = %S\"x\"\ne = \"\"\nq = \"a\" \"\" \"b\"\n",
    )
    .unwrap();
    assert!(m(&g, "d", b"ab") && m(&g, "d", b"AB"));
    assert!(m(&g, "i", b"aB"));
    assert!(m(&g, "s", b"Ab") && !m(&g, "s", b"ab"));
    assert!(m(&g, "t2", b"x") && !m(&g, "t2", b"X"));
    assert!(m(&g, "e", b"") && !m(&g, "e", b"x"));
    assert!(m(&g, "q", b"ab"));
    assert_eq!(
        kind("a = \"x\ty\"\n"),
        K::Syntax,
        "a tab isn't char-val text"
    );
    assert_eq!(kind("a = \"open\n"), K::Syntax);
}

#[test]
fn num_vals() {
    let g =
        load("b = %b1000001\nd = %d65.66\nx = %x41-43\nx2 = %X7a\nhi = %xFF\nlo = %x00\n").unwrap();
    assert!(
        m(&g, "b", b"A") && !m(&g, "b", b"a"),
        "num-vals are case-sensitive"
    );
    assert!(m(&g, "d", b"AB"));
    assert!(m(&g, "x", b"B") && !m(&g, "x", b"D"));
    assert!(m(&g, "x2", b"z"));
    assert!(m(&g, "hi", &[0xff]) && m(&g, "lo", &[0]));
    assert_eq!(kind("a = %x100\n"), K::OctetValue);
    assert_eq!(kind("a = %d256\n"), K::OctetValue);
    assert_eq!(kind("a = %b100000000\n"), K::OctetValue);
    assert_eq!(kind("a = %x41.100\n"), K::OctetValue);
    assert_eq!(kind("a = %x99999999999\n"), K::OctetValue);
    assert_eq!(kind("a = %x39-30\n"), K::EmptyRange);
    assert_eq!(kind("a = %q41\n"), K::Syntax);
    assert_eq!(kind("a = %x30-39.41\n"), K::Syntax);
}

#[test]
fn prose_vals() {
    // A lenient grammar may hold one. Unless it is a rule name, it matches
    // nothing, as in abnf 2.9.1.
    let g = load("a = <anything at all> / \"x\"\n").unwrap();
    assert!(!m(&g, "a", b"anything at all") && m(&g, "a", b"x"));
    // One that is exactly a rule name names that rule (RFC 5234 section
    // 2.1), as abnf 2.9.1 reads it, in any letter case.
    let g = load("a = <b>\nb = \"x\"\nc = <B> \"y\"\nd = <DIGIT>\n").unwrap();
    assert!(m(&g, "a", b"x") && !m(&g, "a", b"<b>"));
    assert!(m(&g, "c", b"xy") && m(&g, "d", b"7"));
    // So an undefined one is an undefined name.
    assert_eq!(kind("a = <b>\n"), K::Undefined("b".into()));
    // In a strict grammar it is still a prose-val.
    assert_eq!(kind("; uses: core\na = <u8>\n"), K::ProseVal);
    // A strict one may not.
    assert_eq!(kind("; uses: core\na = <prose>\n"), K::ProseVal);
    let strict = LoadOptions {
        kind: Kind::Strict,
        ..LoadOptions::default()
    };
    assert_eq!(
        load_with("a = <prose>\n", &[], &strict).unwrap_err().kind,
        K::ProseVal
    );
}

#[test]
fn incremental_alternatives() {
    let g = load("a = \"x\"\nb = \"z\"\na =/ \"y\"\nA =/ \"w\"\n").unwrap();
    assert!(m(&g, "a", b"x") && m(&g, "a", b"y") && m(&g, "a", b"w"));
    assert_eq!(kind("a =/ \"x\"\n"), K::IncrementalUndefined("a".into()));
    // Only on a rule this file defines.
    let e = load_with(
        "; uses: u\nb = a\na =/ \"y\"\n",
        &[("u", "a = \"x\"\n")],
        &LoadOptions::default(),
    )
    .unwrap_err();
    assert_eq!(e.kind, K::IncrementalUndefined("a".into()));
}

#[test]
fn duplicates_and_undefined_names() {
    let e = load("a = \"x\"\nA = \"y\"\n").unwrap_err();
    assert_eq!(
        (e.file.as_str(), e.line, e.kind),
        ("t", 2, K::Duplicate("A".into()))
    );
    assert_eq!(kind("OCTET = %x00\n"), K::Duplicate("OCTET".into()));
    assert_eq!(kind("digit = %x30\n"), K::Duplicate("digit".into()));
    let e = load("a = \"x\" b\n").unwrap_err();
    assert_eq!((e.line, e.kind), (1, K::Undefined("b".into())));
    // RFC 5234's own rules are always there.
    let g = load("a = ALPHA DIGIT HEXDIG\n").unwrap();
    assert!(m(&g, "a", b"z9f"));
}

#[test]
fn left_recursion() {
    assert_eq!(kind("a = a \"x\" / \"y\"\n"), K::LeftRecursive("a".into()));
    assert_eq!(
        kind("a = b \"x\"\nb = a / \"y\"\n"),
        K::LeftRecursive("a".into())
    );
    assert_eq!(
        kind("a = *\"z\" a \"x\" / \"y\"\n"),
        K::LeftRecursive("a".into())
    );
    assert_eq!(
        kind("a = [b] a / \"y\"\nb = \"q\"\n"),
        K::LeftRecursive("a".into())
    );
    assert_eq!(kind("a = *a\n"), K::LeftRecursive("a".into()));
    // Recursion after an octet is fine.
    let g = load("a = \"(\" a \")\" / \"x\"\n").unwrap();
    assert!(m(&g, "a", b"((x))") && !m(&g, "a", b"((x)"));
}

#[test]
fn uses() {
    let opts = LoadOptions::default();
    let u = ("u", "; uses: core\nu-rule = u16\n");
    let v = ("v", "; uses: u\nv-rule = u-rule u8\n");
    // Transitive: v uses u, which uses core.
    let g = load_with("; uses: v\na = v-rule\n", &[u, v], &opts).unwrap();
    assert!(m(&g, "a", &[1, 2, 3]));
    assert!(g.is_core(g.rule("u16").unwrap()) && !g.is_core(g.rule("u-rule").unwrap()));
    // A diamond loads each file once.
    let w = ("w", "; uses: core\nw-rule = u8\n");
    assert!(load_with("; uses: u, w\na = u-rule w-rule\n", &[u, w], &opts).is_ok());
    assert!(load_with("; uses: core, u\na = u-rule u8\n", &[u], &opts).is_ok());
    // A cycle, an unknown name and malformed or misplaced lines.
    let c1 = ("c1", "; uses: c2\nx = \"x\"\n");
    let c2 = ("c2", "; uses: c1\ny = \"y\"\n");
    let uses_err = |text: &str, others: &[(&str, &str)]| {
        matches!(load_with(text, others, &opts).unwrap_err().kind, K::Uses(_))
    };
    assert!(uses_err("; uses: c1\na = x\n", &[c1, c2]));
    assert!(
        uses_err("; uses: t\na = \"x\"\n", &[]),
        "a grammar can't use itself"
    );
    assert!(uses_err("; uses: nosuch\na = \"x\"\n", &[]));
    assert!(uses_err(";uses: core\na = \"x\"\n", &[]));
    assert!(uses_err("; uses: core,u\na = \"x\"\n", &[u]));
    assert!(uses_err("; uses: Core\na = \"x\"\n", &[]));
    assert!(uses_err("; uses: core \na = \"x\"\n", &[]));
    assert!(uses_err("; uses: core, core\na = \"x\"\n", &[]));
    assert!(uses_err("  ; uses: core\na = \"x\"\n", &[]));
    assert!(uses_err("a = \"x\"\n; uses: core\n", &[]));
    assert!(uses_err("a = \"x\" ; uses: core\n", &[]));
    // Depth: a chain of uses longer than the limit.
    let chain: Vec<(String, String)> = (0..12)
        .map(|i| {
            (
                format!("d{i}"),
                format!("; uses: d{}\nr{i} = \"x\"\n", i + 1),
            )
        })
        .chain([("d12".to_string(), "r12 = \"x\"\n".to_string())])
        .collect();
    let chain: Vec<(&str, &str)> = chain
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    assert!(uses_err("; uses: d0\na = r0\n", &chain));
    let deep = LoadOptions {
        limits: Limits {
            uses_depth: 16,
            ..Limits::default()
        },
        ..LoadOptions::default()
    };
    assert!(load_with("; uses: d0\na = r0\n", &chain, &deep).is_ok());
}

#[test]
fn reserved_names() {
    assert_eq!(kind("U8 = OCTET\n"), K::Reserved("U8".into()));
    assert_eq!(kind("text-Char = OCTET\n"), K::Reserved("text-Char".into()));
    assert_eq!(kind("a = \"x\"\nu16 =/ \"y\"\n"), K::Reserved("u16".into()));
    // Through a non-core grammar it uses.
    let e = load_with(
        "; uses: u\na = b\n",
        &[("u", "b = \"x\"\nCAP-REF = %x00\n")],
        &LoadOptions::default(),
    )
    .unwrap_err();
    assert_eq!(
        (e.file.as_str(), e.kind),
        ("u", K::Reserved("CAP-REF".into()))
    );
    // A grammar merely named "core" is not core: only the caller says so.
    let e = Grammar::load(
        "core",
        b"u8 = OCTET\n",
        &mut |_| Some(core_text()),
        &LoadOptions::default(),
    )
    .unwrap_err();
    assert_eq!(e.kind, K::Reserved("u8".into()));
    let core = LoadOptions {
        kind: Kind::Core,
        ..LoadOptions::default()
    };
    let g = Grammar::load("core", &core_text(), &mut |_| None, &core).unwrap();
    assert!(g.is_core(g.rule("u8").unwrap()));
    // Without core, nothing is known to be reserved: an error.
    let e = Grammar::load("t", b"a = \"x\"\n", &mut |_| None, &LoadOptions::default()).unwrap_err();
    assert!(matches!(e.kind, K::Uses(_)));
}

#[test]
fn constraint_comments_and_strictness() {
    // A constraint outside every rule is an error.
    assert_eq!(
        kind("a = \"x\"\n; constraint: not 0\nb = \"y\"\n"),
        K::Attachment
    );
    assert_eq!(kind("a = \"x\"\n\n  ; constraint: not 0\n"), K::Attachment);
    // Prose is counted in a lenient grammar...
    let g = load("a = 2OCTET\n  ; constraint: a power of two.\n  ; constraint:not 0\n").unwrap();
    assert_eq!(g.prose_constraints(), 2);
    // ... and is an error in a strict one.
    assert_eq!(
        kind("; uses: core\na = u16\n  ; constraint: a power of two.\n"),
        K::Prose
    );
    // Vocabulary constraints bind to their rule, on its line or a
    // continuation line.
    let g = load("; uses: core\na = u16 ; constraint: not 0\n  ; constraint: at most 9\n").unwrap();
    assert_eq!(g.constraints(g.rule("a").unwrap()).len(), 2);
    assert_eq!(g.prose_constraints(), 0);
}

#[test]
fn analyses() {
    let g = load(
        "; uses: core\nfixed = u16 u32 [\"\"]\nvar = 1*3u8\nsig = i32\nsig2 = sig\nnum = \"0\" / %x31-39 *4DIGIT\n",
    )
    .unwrap();
    let r = |n: &str| g.rule(n).unwrap();
    assert_eq!(g.fixed_width(r("fixed")), Some(6));
    assert_eq!(g.fixed_width(r("var")), None);
    assert_eq!(g.min_width(r("var")), 1);
    assert_eq!(g.fixed_width(r("object-id")), Some(32));
    assert!(g.is_signed(r("sig2")) && g.is_signed(r("i8")) && !g.is_signed(r("u8")));
    assert!(g.is_digit_only(r("num")) && !g.is_digit_only(r("u8")));
    assert!(g.literals().any(|l| l == b"0"));
}

#[test]
fn size_limits() {
    let tight = |f: fn(&mut Limits)| {
        let mut limits = Limits::default();
        f(&mut limits);
        LoadOptions {
            limits,
            ..LoadOptions::default()
        }
    };
    let text = "a = \"x\" \"y\"\nb = a a\nc = b b\n";
    assert!(load_with(text, &[], &tight(|l| l.rules = 3)).is_ok());
    assert_eq!(
        load_with(text, &[], &tight(|l| l.rules = 2))
            .unwrap_err()
            .kind,
        K::TooLarge
    );
    assert_eq!(
        load_with(text, &[], &tight(|l| l.nodes = 4))
            .unwrap_err()
            .kind,
        K::TooLarge
    );
    assert_eq!(
        load_with(text, &[], &tight(|l| l.grammar_octets = 10))
            .unwrap_err()
            .kind,
        K::TooLarge
    );
    let nested = "a = ((((\"x\"))))\n";
    assert!(load_with(nested, &[], &tight(|l| l.nesting = 4)).is_ok());
    assert_eq!(
        load_with(nested, &[], &tight(|l| l.nesting = 3))
            .unwrap_err()
            .kind,
        K::TooDeep
    );
}

#[test]
fn deep_nesting_is_an_error_not_a_crash() {
    let text = format!("a = {}\"x\"{}\n", "(".repeat(10_000), ")".repeat(10_000));
    assert_eq!(kind(&text), K::TooDeep);
    let text = format!("a = {}\"x\"{}\n", "[".repeat(10_000), "]".repeat(10_000));
    assert_eq!(kind(&text), K::TooDeep);
}

/// A chain of 16,000 one-name rules, in either order, loads within the
/// default limits on a small stack and in little time: no analysis
/// recurses along references or iterates to a fixpoint.
#[test]
fn long_chains_load_fast_on_a_small_stack() {
    const N: usize = 16_000;
    let forward: String = (0..N)
        .map(|i| {
            if i + 1 < N {
                format!("a{i} = a{}\n", i + 1)
            } else {
                format!("a{i} = \"x\"\n")
            }
        })
        .collect();
    let backward: String = (0..N)
        .rev()
        .map(|i| {
            if i + 1 < N {
                format!("a{i} = a{}\n", i + 1)
            } else {
                format!("a{i} = \"x\"\n")
            }
        })
        .collect();
    // A cycle through every rule, entered after an octet each time.
    let ring: String = (0..N)
        .map(|i| format!("a{i} = \"x\" a{} / \"y\"\n", (i + 1) % N))
        .collect();
    for text in [forward, backward, ring] {
        let t = std::thread::Builder::new()
            .stack_size(256 << 10)
            .spawn(move || {
                let start = Instant::now();
                let g = load(&text).expect("loads");
                assert!(g.rule("a0").is_some());
                start.elapsed()
            })
            .unwrap();
        let took = t.join().expect("no stack overflow");
        assert!(took.as_secs() < 5, "loading took {took:?}");
    }
}
