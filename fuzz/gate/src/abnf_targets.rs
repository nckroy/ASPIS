// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The ABNF toolchain's targets (C06; ADR 0062, rule 8; ADR 0027,
//! rule 2): `abnf-grammar` for the text parser and loader, `abnf-match`
//! for the matcher, `abnf-vectors` for the vector-file reader and checker,
//! and `abnf-constraint` for the constraint vocabulary's reader.
//!
//! The catalog runs this code on publishers' grammars and vectors, so
//! every input must end within its budgets with an answer or an error,
//! never a panic.

use std::{
    collections::BTreeSet,
    fmt::{self, Write as _},
    hash::{DefaultHasher, Hasher},
};

use abnf::{
    Context, Exhausted, Grammar, GrammarError, GrammarErrorKind, Kind, Limits, LoadOptions,
    constraint::{self, Constraint, ConstraintError, Misuse},
    vectors::{self, VectorErrorKind, VectorFile, Verdict},
};

use crate::{FUZZ_LIMITS, SYNTHETIC_LIMITS, generate, oracle, repo, seeds};

// ---- abnf-grammar ------------------------------------------------------

kinds! {
    /// The kinds `abnf-grammar` reaches: a grammar that loads, each
    /// [`GrammarErrorKind`], and each [`Misuse`] as `constraint-<misuse>`.
    pub const GRAMMAR_KINDS = ["ok"];
    fn grammar_kind(k: &GrammarErrorKind) {
        GrammarErrorKind::Syntax => "syntax",
        GrammarErrorKind::NotAscii => "not-ascii",
        GrammarErrorKind::OctetValue => "octet-value",
        GrammarErrorKind::EmptyRange => "empty-range",
        GrammarErrorKind::RepeatRange => "repeat-range",
        GrammarErrorKind::Duplicate(_) => "duplicate",
        GrammarErrorKind::IncrementalUndefined(_) => "incremental-undefined",
        GrammarErrorKind::Undefined(_) => "undefined",
        GrammarErrorKind::LeftRecursive(_) => "left-recursive",
        GrammarErrorKind::Reserved(_) => "reserved",
        GrammarErrorKind::Uses(_) => "uses",
        GrammarErrorKind::Attachment => "attachment",
        GrammarErrorKind::Prose => "prose",
        GrammarErrorKind::ProseVal => "prose-val",
        GrammarErrorKind::TooLarge => "too-large",
        GrammarErrorKind::TooDeep => "too-deep",
        GrammarErrorKind::Constraint(Misuse::Undefined(_)) => "constraint-undefined",
        GrammarErrorKind::Constraint(Misuse::NoReading(_)) => "constraint-no-reading",
        GrammarErrorKind::Constraint(Misuse::Negative) => "constraint-negative",
        GrammarErrorKind::Constraint(Misuse::EmptyRange) => "constraint-empty-range",
        GrammarErrorKind::Constraint(Misuse::NotOneConcatenation) => "constraint-not-one-concatenation",
        GrammarErrorKind::Constraint(Misuse::NoRepetition) => "constraint-no-repetition",
        GrammarErrorKind::Constraint(Misuse::WrongElement(_)) => "constraint-wrong-element",
        GrammarErrorKind::Constraint(Misuse::ShortTags) => "constraint-short-tags",
        GrammarErrorKind::Constraint(Misuse::NotFloat) => "constraint-not-float",
    }
}

/// The length of the synthetic `; uses:` chain the resolver offers:
/// `chain-1` uses `chain-2`, and so on to `chain-16`, so a grammar can
/// reach any depth up to 16 and pass the loader's limit of 8.
const CHAIN: usize = 16;

/// `abnf-grammar`'s resolver: the repository's grammars by name, and the
/// synthetic chain.
fn grammar_resolve(name: &str) -> Option<Vec<u8>> {
    if let Some(n) = name.strip_prefix("chain-") {
        let n: usize = n.parse().ok().filter(|n| (1..=CHAIN).contains(n))?;
        let uses = match n {
            CHAIN => String::new(),
            _ => format!("; uses: chain-{}\n", n + 1),
        };
        return Some(format!("{uses}chain-rule-{n} = \"c\"\n").into_bytes());
    }
    repo::resolve(name)
}

/// The match budgets for the matches `abnf-grammar` runs on what it
/// loads: 100,000 steps each, and at most 40 matches an input, so 4 M
/// steps in all, about half a second at the costliest steps measured
/// (see [`SYNTHETIC_LIMITS`]). The steps fields don't bound loading, so the
/// load limits stay the defaults.
const GRAMMAR_LIMITS: Limits = Limits {
    steps_max: 100_000,
    ..FUZZ_LIMITS
};

/// The per-rule checks look at this many rules, and the matches at the
/// first [`MATCHED_RULES`] of them, against at most [`MATCHED_LITERALS`]
/// literals and the empty string.
const CHECKED_RULES: usize = 16;
const MATCHED_RULES: usize = 4;
const MATCHED_LITERALS: usize = 4;
/// The core-grammar load runs only on inputs this short: it repeats work
/// the other loads did, and the 1 MiB inputs would leave too little of
/// the timeout.
const CORE_LOAD_MAX: usize = 64 << 10;

fn load(text: &[u8], kind: Kind) -> Result<Grammar, GrammarError> {
    let opts = LoadOptions {
        limits: GRAMMAR_LIMITS,
        kind,
    };
    Grammar::load("fuzzed", text, &mut grammar_resolve, &opts)
}

/// Feeds formatted text to a hasher, so two results compare without
/// holding the text.
struct HashWriter(DefaultHasher);

impl fmt::Write for HashWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.write(s.as_bytes());
        Ok(())
    }
}

/// A digest of everything a load gives: the grammar's whole state, or the
/// error. `DefaultHasher::new()` has fixed keys, so it is the same in
/// every run.
fn fingerprint(r: &Result<Grammar, GrammarError>) -> u64 {
    let mut h = HashWriter(DefaultHasher::new());
    write!(h, "{r:?}").expect("hashing can't fail");
    h.0.finish()
}

/// The rule names a text defines, in order, each once: a rule starts at
/// column 0 with a letter (RFC 5234, section 4), and no other line can.
fn defined_names(text: &[u8]) -> Vec<&str> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for line in text.split(|&b| b == b'\n') {
        if !line.first().is_some_and(u8::is_ascii_alphabetic) {
            continue;
        }
        let end = line
            .iter()
            .position(|&b| !(b.is_ascii_alphanumeric() || b == b'-'))
            .unwrap_or(line.len());
        let name = core::str::from_utf8(&line[..end]).expect("ASCII");
        if seen.insert(name.to_ascii_lowercase()) {
            out.push(name);
            if out.len() == CHECKED_RULES {
                break;
            }
        }
    }
    out
}

/// Every accessor of one rule, as one comparable value.
fn accessors(g: &Grammar, name: &str) -> String {
    let r = g
        .rule(name)
        .unwrap_or_else(|| panic!("{name} starts a definition, but the grammar hasn't it"));
    assert!(
        g.name(r).eq_ignore_ascii_case(name),
        "{name} finds {}",
        g.name(r)
    );
    format!(
        "{} {} {:?} {} {:?} {} {}",
        g.name(r),
        g.is_core(r),
        g.constraints(r),
        g.min_width(r),
        g.fixed_width(r),
        g.is_digit_only(r),
        g.is_signed(r),
    )
}

/// The matches `abnf-grammar` runs on a loaded grammar: constraints only
/// narrow a match.
fn match_some(g: &Grammar, names: &[&str]) {
    let mut inputs: Vec<&[u8]> = vec![b""];
    for l in g.literals() {
        if inputs.len() > MATCHED_LITERALS {
            break;
        }
        if !inputs.contains(&l) {
            inputs.push(l);
        }
    }
    for name in names.iter().take(MATCHED_RULES) {
        let r = g.rule(name).expect("checked by accessors");
        for input in &inputs {
            let cf = g.matches(r, input);
            let c = g.matches_constrained(r, input, &Context::default());
            if let (Ok(true), Ok(false)) = (c, cf) {
                panic!("{name}: {input:?} keeps the constraints but doesn't match");
            }
        }
    }
}

/// The errors only a strict load gives.
fn is_prose(k: &GrammarErrorKind) -> bool {
    matches!(k, GrammarErrorKind::Prose | GrammarErrorKind::ProseVal)
}

/// The loads `abnf-grammar` makes, and its checks between them.
fn grammar_loads(text: &[u8]) -> Vec<Result<(), GrammarErrorKind>> {
    let auto = load(text, Kind::Auto);
    // Deterministic: a second load gives the same, state and all.
    assert_eq!(
        fingerprint(&auto),
        fingerprint(&load(text, Kind::Auto)),
        "two loads differ"
    );
    let strict = load(text, Kind::Strict);
    let names = defined_names(text);
    match (&auto, &strict) {
        (Err(e), Ok(_)) => panic!("a strict load succeeds where Auto fails: {e}"),
        (Ok(a), Ok(s)) => {
            assert_eq!(s.prose_constraints(), 0, "a strict grammar has no prose");
            assert!(
                a.literals().eq(s.literals()),
                "Auto and Strict have different literals"
            );
            for n in &names {
                assert_eq!(accessors(a, n), accessors(s, n), "{n} differs");
            }
        }
        // Strictness only adds the prose errors, so where Auto loads,
        // Strict fails only on prose; where both fail, Strict fails as
        // Auto does or on prose, which it checks first.
        (Ok(a), Err(e)) => {
            assert!(
                is_prose(&e.kind),
                "Auto loads, but Strict fails with something other than prose: {e}"
            );
            for n in &names {
                accessors(a, n);
            }
        }
        (Err(a), Err(s)) => assert!(
            a.kind == s.kind || is_prose(&s.kind),
            "Auto and Strict fail differently: {a}, and {s}"
        ),
    }
    if let Ok(a) = &auto {
        let _ = a.prose_constraints();
        let _ = a.limits();
        match_some(a, &names);
    }
    let mut out = vec![auto.map(drop), strict.map(drop)];
    if text.len() <= CORE_LOAD_MAX {
        let core = load(text, Kind::Core);
        if let Ok(c) = &core {
            for n in &names {
                accessors(c, n);
            }
        }
        out.push(core.map(drop));
    }
    out.into_iter()
        .map(|r| {
            r.map_err(|e| {
                let _ = e.to_string();
                e.kind
            })
        })
        .collect()
}

/// `abnf-grammar`: grammar text, loaded as Auto, Strict and Core.
pub fn grammar(text: &[u8]) {
    grammar_loads(text);
}

/// The kinds a grammar text reaches in any of its loads.
pub fn grammar_kinds(text: &[u8]) -> Vec<&'static str> {
    grammar_loads(text)
        .iter()
        .map(|r| match r {
            Ok(()) => "ok",
            Err(k) => grammar_kind(k),
        })
        .collect()
}

/// `abnf-grammar`'s generated seeds: every repository grammar, and the
/// inputs at and just over each of the loader's limits.
pub fn grammar_seeds() -> Vec<(String, Vec<u8>)> {
    let d = abnf::Limits::default();
    let mut out: Vec<(String, Vec<u8>)> = repo::GRAMMARS
        .iter()
        .map(|g| (format!("{}-abnf", g.name), g.text.to_vec()))
        .collect();
    let rules = |n: usize| -> Vec<u8> {
        (0..n)
            .flat_map(|i| format!("r{i} = \"x\"\n").into_bytes())
            .collect()
    };
    out.push(("rules-max".into(), rules(d.rules)));
    out.push(("rules-over".into(), rules(d.rules + 1)));
    // One concatenation of references: each is a node, and so are the
    // concatenation and `x`'s literal, so n references make n + 2 nodes.
    let refs = |n: usize| -> Vec<u8> {
        let mut t = b"a =".to_vec();
        for _ in 0..n {
            t.extend_from_slice(b" x");
        }
        t.extend_from_slice(b"\nx = \"y\"\n");
        t
    };
    out.push(("nodes-max".into(), refs(d.nodes - 2)));
    out.push(("nodes-over".into(), refs(d.nodes - 1)));
    let nest = |n: usize| -> Vec<u8> {
        format!("a = {}\"x\"{}\n", "(".repeat(n), ")".repeat(n)).into_bytes()
    };
    out.push(("nesting-max".into(), nest(d.nesting)));
    out.push(("nesting-over".into(), nest(d.nesting + 1)));
    let chain = |depth: usize| -> Vec<u8> {
        let first = CHAIN - depth + 1;
        format!("; uses: chain-{first}\nm = chain-rule-{first}\n").into_bytes()
    };
    out.push(("uses-max".into(), chain(d.uses_depth)));
    out.push(("uses-over".into(), chain(d.uses_depth + 1)));
    // A long alternation, exactly as long as the limit, and one octet
    // longer.
    let octets = |n: usize| -> Vec<u8> {
        let mut t = b"a = \"x\"".to_vec();
        while t.len() + 6 < n {
            t.extend_from_slice(b" / \"x\"");
        }
        t.resize(n - 1, b' ');
        t.push(b'\n');
        t
    };
    out.push(("octets-max".into(), octets(d.grammar_octets)));
    out.push(("octets-over".into(), octets(d.grammar_octets + 1)));
    out
}

// ---- abnf-match --------------------------------------------------------

kinds! {
    /// The kinds `abnf-match` reaches: a match, no match, and each
    /// [`Exhausted`].
    pub const MATCH_KINDS = [];
    fn match_kind(r: &Result<bool, Exhausted>) {
        Ok(true) => "match",
        Ok(false) => "no-match",
        Err(Exhausted::Input) => "input",
        Err(Exhausted::Steps) => "steps",
        Err(Exhausted::Memory) => "memory",
        Err(Exhausted::Depth) => "depth",
    }
}

/// A frame read: the grammar, the rule, the context and the octets.
struct Framed<'a> {
    grammar: &'static Grammar,
    rule: abnf::RuleId,
    cx: Context,
    input: &'a [u8],
}

/// Reads `abnf-match`'s frame (see [`seeds::frame`]). An input that
/// doesn't name a grammar and a rule isn't matched.
fn unframe(data: &[u8]) -> Option<Framed<'_>> {
    let nl = data.iter().take(64).position(|&b| b == b'\n')?;
    let header = core::str::from_utf8(&data[..nl]).ok()?;
    let (g, r) = header.split_once('/')?;
    let grammar = repo::matchable(g)?;
    let rule = grammar.rule(r)?;
    let (&cx, input) = data[nl + 1..].split_first()?;
    let caps = cx & 0x0f;
    let mask = ((1u16 << caps.min(8)) - 1) as u8;
    Some(Framed {
        grammar,
        rule,
        cx: Context {
            caps,
            unwrapped: (cx >> 4) & mask,
        },
        input,
    })
}

/// `abnf-match` matches an input a second time, to show the matcher is
/// deterministic, only when it is this short: on long inputs the second
/// pair of matches would halve the target's speed for little gain.
const REMATCH_MAX: usize = 1 << 10;

fn run_match(data: &[u8]) -> Option<[Result<bool, Exhausted>; 2]> {
    let f = unframe(data)?;
    let g = f.grammar;
    let cf = g.matches(f.rule, f.input);
    let c = g.matches_constrained(f.rule, f.input, &f.cx);
    // Deterministic.
    if f.input.len() <= REMATCH_MAX {
        assert_eq!(g.matches(f.rule, f.input), cf);
        assert_eq!(g.matches_constrained(f.rule, f.input, &f.cx), c);
    }
    // Over the input limit, both refuse before they start.
    if f.input.len() > g.limits().input_octets {
        assert_eq!(cf, Err(Exhausted::Input));
        assert_eq!(c, Err(Exhausted::Input));
    }
    // Constraints only narrow a match.
    if let (Ok(true), Ok(false)) = (c, cf) {
        panic!("keeps the constraints but doesn't match");
    }
    Some([cf, c])
}

/// `abnf-match`: a framed input, matched context-free and with
/// constraints.
pub fn match_framed(data: &[u8]) {
    run_match(data);
}

/// The kinds a framed input reaches, context-free or constrained.
pub fn match_kinds(data: &[u8]) -> Vec<&'static str> {
    run_match(data)
        .map(|rs| rs.iter().map(match_kind).collect())
        .unwrap_or_default()
}

/// `abnf-match`'s generated seeds: every vector line of every embedded
/// file, framed with its grammar, rule and context; and a short input
/// that reaches each fixture's budget. The fixtures' budgets are small,
/// so no seed is long: libFuzzer's length control starts from the
/// longest seed, and long seeds keep it from exploring short inputs.
pub fn match_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = seeds::framed_vectors();
    out.push((
        "fixture-input".into(),
        seeds::frame("fixture-input", "s", 0, 0, &[b'a'; 257]),
    ));
    let mut deep = vec![b'('; 100];
    deep.push(b'x');
    out.push((
        "fixture-depth".into(),
        seeds::frame("fixture-depth", "a", 0, 0, &deep),
    ));
    out.push((
        "fixture-steps".into(),
        seeds::frame("fixture-steps", "s", 0, 0, &[b'a'; 200]),
    ));
    out.push((
        "fixture-memory".into(),
        seeds::frame("fixture-memory", "s", 0, 0, &[b'a'; 200]),
    ));
    out.push((
        "fixture-nullable".into(),
        seeds::frame("fixture-nullable", "x", 0, 0, b""),
    ));
    out
}

// ---- abnf-vectors ------------------------------------------------------

kinds! {
    /// The kinds `abnf-vectors` reaches: each [`VectorErrorKind`], and
    /// each [`Verdict`].
    pub const VECTORS_KINDS = [];
    fn vector_error_kind(k: VectorErrorKind) {
        VectorErrorKind::NotUtf8 => "not-utf8",
        VectorErrorKind::CarriageReturn => "carriage-return",
        VectorErrorKind::Directive => "directive",
        VectorErrorKind::RepeatedDirective => "repeated-directive",
        VectorErrorKind::UnwrappedBeyondCaps => "unwrapped-beyond-caps",
        VectorErrorKind::Line => "line",
        VectorErrorKind::Escape => "escape",
        VectorErrorKind::NoRule => "no-rule",
    }
    fn verdict_kind(v: &Verdict) {
        Verdict::Agrees => "agrees",
        Verdict::Disagrees { .. } => "disagrees",
        Verdict::Exhausted(_) => "exhausted",
        Verdict::UnknownRule => "unknown-rule",
    }
}

/// The grammar a vector file is checked against: the first repository
/// grammar that defines its `# rule:`, or else its first vector's rule;
/// failing both, core.
fn grammar_for(f: &VectorFile) -> &'static Grammar {
    f.rule
        .as_deref()
        .or(f.vectors.first().map(|v| v.rule.as_str()))
        .and_then(repo::defining)
        .or_else(|| repo::loaded("core"))
        .expect("core is embedded")
}

fn run_vectors(text: &[u8]) -> Vec<&'static str> {
    let parsed = vectors::parse(text);
    assert_eq!(parsed, vectors::parse(text));
    match parsed {
        Err(e) => {
            let _ = e.to_string();
            vec![vector_error_kind(e.kind)]
        }
        Ok(f) => {
            let g = grammar_for(&f);
            let r = vectors::check(g, &f);
            oracle::check_report(&f, &r);
            // Deterministic.
            let again = vectors::check(g, &f);
            assert_eq!(
                (&r.results, r.agree, r.errc, r.disagree, r.unjudged),
                (
                    &again.results,
                    again.agree,
                    again.errc,
                    again.disagree,
                    again.unjudged
                )
            );
            r.results.iter().map(|(_, v)| verdict_kind(v)).collect()
        }
    }
}

/// `abnf-vectors`: a vector file, read and checked.
pub fn vectors(text: &[u8]) {
    run_vectors(text);
}

/// The kinds a vector file reaches.
pub fn vectors_kinds(text: &[u8]) -> Vec<&'static str> {
    run_vectors(text)
}

/// Vector files over this many octets are seeds line by line only: a
/// whole 27 KB file is slow to check, and libFuzzer spends its time
/// mutating it.
const WHOLE_FILE_MAX: usize = 10_000;

/// `abnf-vectors`'s generated seeds: every embedded vector file whole,
/// unless it is long, and every vector line on its own, after the file's
/// `# rule:` and `# max-length:` and the `# caps:` and `# unwrapped:` in
/// force at the line.
pub fn vectors_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for g in repo::GRAMMARS {
        if g.vectors.len() <= WHOLE_FILE_MAX {
            out.push((format!("{}-vectors", g.name), g.vectors.to_vec()));
        }
        let f = vectors::parse(g.vectors).expect("the repository's vectors read");
        let lines: Vec<&[u8]> = g.vectors.split(|&b| b == b'\n').collect();
        for v in &f.vectors {
            let mut seed = Vec::new();
            for l in &lines {
                if l.starts_with(b"# rule:") || l.starts_with(b"# max-length:") {
                    seed.extend_from_slice(l);
                    seed.push(b'\n');
                }
            }
            if v.caps != 0 || v.unwrapped != 0 {
                seed.extend_from_slice(format!("# caps: {}\n", v.caps).as_bytes());
            }
            if v.unwrapped != 0 {
                seed.extend_from_slice(format!("# unwrapped: {:x}\n", v.unwrapped).as_bytes());
            }
            seed.extend_from_slice(lines[v.line - 1]);
            seed.push(b'\n');
            out.push((seeds::name(g, v.line), seed));
        }
    }
    out
}

// ---- abnf-constraint ---------------------------------------------------

kinds! {
    /// The kinds `abnf-constraint` reaches: text that isn't UTF-8; what
    /// [`constraint::constraint_text`] finds; each [`ConstraintError`];
    /// and each [`Constraint`] form.
    pub const CONSTRAINT_KINDS = ["not-utf8", "not-a-comment", "marker-without-space", "comment"];
    fn constraint_kind(r: &Result<Constraint, ConstraintError>) {
        Err(ConstraintError::Syntax) => "syntax",
        Err(ConstraintError::OutOfRange) => "out-of-range",
        Ok(Constraint::ExactlyOctets(_)) => "exactly-octets",
        Ok(Constraint::ExactlyElements(..)) => "exactly-elements",
        Ok(Constraint::ExactlyWords(_)) => "exactly-words",
        Ok(Constraint::HeaderWords(_)) => "header-words",
        Ok(Constraint::AtMost(_)) => "at-most",
        Ok(Constraint::AtLeast(_)) => "at-least",
        Ok(Constraint::In(..)) => "in",
        Ok(Constraint::Not(_)) => "not",
        Ok(Constraint::NotOneOf(_)) => "not-one-of",
        Ok(Constraint::LengthAtMost(_)) => "length-at-most",
        Ok(Constraint::NotWord(_)) => "not-word",
        Ok(Constraint::Ascending(_)) => "ascending",
        Ok(Constraint::AscendingTags) => "ascending-tags",
        Ok(Constraint::CapabilityIndex) => "capability-index",
        Ok(Constraint::CanonicalFloat) => "canonical-float",
        Ok(Constraint::RemainingOctets) => "remaining-octets",
    }
}

/// A parsed constraint's own invariants: its integers are in range, and
/// its words are as the grammar writes them.
fn check_constraint(c: &Constraint) {
    use Constraint as C;
    let int = |n: &i128| assert!((constraint::INTEGER_MIN..=constraint::INTEGER_MAX).contains(n));
    match c {
        C::AtMost(n) | C::AtLeast(n) | C::Not(n) => int(n),
        C::In(n, m) => {
            int(n);
            int(m);
        }
        C::NotOneOf(list) => {
            assert!(list.len() >= 2, "not one of takes two or more");
            list.iter().for_each(int);
        }
        C::NotWord(words) => {
            assert!(!words.is_empty());
            for w in words {
                assert!(!w.is_empty() && !w.contains([' ', ',']));
            }
        }
        C::ExactlyOctets(r) | C::ExactlyWords(r) | C::HeaderWords(r) | C::Ascending(r) => {
            assert!(!r.is_empty());
        }
        C::ExactlyElements(r, e) => assert!(!r.is_empty() && !e.is_empty()),
        C::LengthAtMost(_)
        | C::AscendingTags
        | C::CapabilityIndex
        | C::CanonicalFloat
        | C::RemainingOctets => {}
    }
}

fn run_constraint(data: &[u8]) -> Vec<&'static str> {
    let Ok(s) = core::str::from_utf8(data) else {
        oracle::check_constraint_agreement(
            data,
            oracle::constraint_accepts,
            oracle::comment_accepts,
        );
        return vec!["not-utf8"];
    };
    let mut kinds = Vec::new();
    let text = constraint::constraint_text(s);
    assert_eq!(text, constraint::constraint_text(s));
    match text {
        None => kinds.push("not-a-comment"),
        Some(Err(())) => kinds.push("marker-without-space"),
        Some(Ok(t)) => {
            kinds.push("comment");
            // The text is the comment's tail, trimmed.
            assert!(s.contains(t));
            assert!(!t.ends_with([' ', '\t']) && !t.starts_with(' '));
            let p = constraint::parse(t);
            if let Ok(c) = &p {
                check_constraint(c);
            }
            kinds.push(constraint_kind(&p));
        }
    }
    let p = constraint::parse(s);
    assert_eq!(p, constraint::parse(s));
    if let Ok(c) = &p {
        check_constraint(c);
        let _ = format!("{c:?}");
    }
    kinds.push(constraint_kind(&p));
    // The text form is canonical, so it round-trips ("The gate for each
    // target", item 2), and both readers agree with
    // grammars/constraint.abnf (item 3).
    oracle::check_constraint_round_trip(s, oracle::render_constraint);
    if let Some(Ok(t)) = text {
        oracle::check_constraint_round_trip(t, oracle::render_constraint);
    }
    oracle::check_constraint_agreement(data, oracle::constraint_accepts, oracle::comment_accepts);
    kinds
}

/// `abnf-constraint`: one line, read as a comment and as a constraint.
pub fn constraint(data: &[u8]) {
    run_constraint(data);
}

/// The kinds a line reaches.
pub fn constraint_kinds(data: &[u8]) -> Vec<&'static str> {
    run_constraint(data)
}

/// `abnf-constraint`'s generated seeds: every vector line of
/// `grammars/constraint.vectors`.
pub fn constraint_seeds() -> Vec<(String, Vec<u8>)> {
    seeds::octets_of("constraint")
}

// ---- abnf-generated ----------------------------------------------------

/// `abnf-generated` has no error kinds of its own: every grammar it makes
/// is valid. Its seeds must reach both verdicts; running out of steps,
/// memory or depth is allowed but not asked for.
pub const GENERATED_KINDS: &[&str] = &["match", "no-match"];

/// Loads a generated case's grammar.
pub fn load_generated(text: &[u8], kind: Kind) -> Result<Grammar, GrammarError> {
    let opts = LoadOptions {
        limits: SYNTHETIC_LIMITS,
        kind,
    };
    Grammar::load("generated", text, &mut repo::resolve, &opts)
}

fn run_generated(data: &[u8]) -> Vec<&'static str> {
    let c = generate::case(&mut generate::Bytes(data));
    // Generation is deterministic too: the differential's seeds rely on it.
    assert_eq!(
        c,
        generate::case(&mut generate::Bytes(data)),
        "two generations differ"
    );
    let text = String::from_utf8_lossy(&c.text);
    // Valid by construction, so a load failure is a bug in the generator
    // or the loader; a strict load accepts it too, since it has no prose.
    let g = load_generated(&c.text, Kind::Auto)
        .unwrap_or_else(|e| panic!("a generated grammar doesn't load: {e}\n{text}"));
    if let Err(e) = load_generated(&c.text, Kind::Strict) {
        panic!("a generated grammar doesn't load strictly: {e}\n{text}");
    }
    // Every literal it writes is in the grammar's literals.
    for lit in generate::literals(&c) {
        assert!(
            g.literals().any(|l| l == lit.as_slice()),
            "{:?} isn't among the literals\n{text}",
            String::from_utf8_lossy(&lit)
        );
    }
    // Inputs are at most 64 octets, far under the input limit, so the
    // matcher never refuses one as too long. Its other budgets may run
    // out on a valid grammar: a match can be exponential
    // (`R0 = "" / 2*2( HTAB R0 )` on 36 octets takes more than 256 M
    // steps), and repetitions of mutually recursive rules nest past the
    // depth limit (C71's corpus has both), so those are allowed here, and
    // the differential fails when 1 % of its inputs run out. With
    // constraints on, the matcher takes more steps (it runs its states
    // in groups), so there only a verdict is compared.
    let work_only = |m: &Result<bool, Exhausted>, what: &str| {
        assert_ne!(
            *m,
            Err(Exhausted::Input),
            "{what}: refused as too long, on at most 64 octets\n{text}"
        );
    };
    let mut kinds = Vec::new();
    for (i, s) in c.shortest.iter().enumerate() {
        let r = g.rule(&c.rules[i].name).expect("every rule is defined");
        let m = g.matches(r, s);
        work_only(&m, &c.rules[i].name);
        assert!(
            !matches!(m, Ok(false)),
            "{}'s shortest derivation {s:?} doesn't match\n{text}",
            c.rules[i].name
        );
    }
    for input in &c.inputs {
        let name = &c.rules[input.rule].name;
        let r = g.rule(name).expect("every rule is defined");
        let cf = g.matches(r, &input.octets);
        // No constraints, so where both give a verdict they are the same.
        // With constraints on, the matcher runs its states in groups and
        // takes more steps, so one may run out of budget where the other
        // answers: that is no disagreement.
        let c = g.matches_constrained(r, &input.octets, &Context::default());
        work_only(&cf, name);
        work_only(&c, name);
        if let (Ok(a), Ok(b)) = (cf, c) {
            assert_eq!(
                a, b,
                "{name}: constrained and context-free matches differ\n{text}"
            );
        }
        if input.origin == generate::Origin::Derived {
            assert!(
                !matches!(cf, Ok(false)),
                "{name}: the derivation {:?} doesn't match\n{text}",
                input.octets
            );
        }
        if cf.is_ok() {
            kinds.push(match_kind(&cf));
        }
    }
    kinds
}

/// `abnf-generated`: libFuzzer's bytes drive [`generate::case`], and the
/// grammar it makes is loaded and matched.
pub fn generated(data: &[u8]) {
    run_generated(data);
}

/// The match results a case's inputs reach.
pub fn generated_kinds(data: &[u8]) -> Vec<&'static str> {
    run_generated(data)
}

/// `abnf-generated`'s seeds: 64 byte strings from [`generate::SplitMix64`].
pub fn generated_seeds() -> Vec<(String, Vec<u8>)> {
    (0..64u64)
        .map(|i| {
            let mut src = generate::SplitMix64(i);
            let bytes = (0..64).flat_map(|_| src.next_u64().to_le_bytes()).collect();
            (format!("generated-{i}"), bytes)
        })
        .collect()
}
