// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The gate's oracles beyond "no panic" ("The gate for each target",
//! items 2 and 3): agreement with the grammar, and round trips through an
//! encoder.
//!
//! Each check takes the subject it judges as a parameter, so
//! `tests/oracles.rs` can hand it a deliberately wrong subject and show
//! that the check catches it. The targets pass the real one.

use abnf::{
    Context, Exhausted,
    constraint::{self, Constraint, ConstraintError},
    vectors::{Report, Tag, VectorFile, Verdict},
};
use kargs::{Arg, MAX_LEN, Value};

use crate::{AGREEMENT_MAX, repo};

// ---- Agreement with the grammar (item 3) -------------------------------

/// Whether the repository grammar `grammar` accepts `input` as `rule`,
/// with its constraints: C06's matcher is the reference every decoder
/// with a grammar agrees with. The grammar is loaded with
/// [`ORACLE_LIMITS`](crate::ORACLE_LIMITS), which hold every input a
/// target takes and give a linear step budget, so on the linear
/// repository grammars the matcher must give a verdict: running out of a
/// budget is itself a finding ("The gate for each target", item 6).
pub fn grammar_accepts(grammar: &str, rule: &str, input: &[u8]) -> bool {
    let g = repo::oracle(grammar).unwrap_or_else(|| panic!("no repository grammar {grammar}"));
    let r = g
        .rule(rule)
        .unwrap_or_else(|| panic!("{grammar} has no rule {rule}"));
    g.matches_constrained(r, input, &Context::default())
        .unwrap_or_else(|e| {
            panic!(
                "{grammar}/{rule}: the reference matcher ran out of a budget ({e:?}) on {} octets",
                input.len()
            )
        })
}

/// How many times, at most, a rule of `grammars/names.abnf` or
/// `grammars/idl.abnf` makes C06's constrained matcher walk one run of
/// name octets. Measured: `action-ref` takes about 3.2 times a run's
/// n² / 2 steps (it tries a name three times), `idl-file` about 2.1 (a
/// type name), and every other rule about 1. This is about 2.5 times the
/// worst, so a run that does explain running out of steps is never taken
/// for a finding.
pub const NAME_RUN_TRIES: u64 = 8;

/// The steps C06's constrained matcher can spend on the runs of name
/// octets in `input` (`a-z`, `0-9` and `_`): n² / 2 for a run of n,
/// [`NAME_RUN_TRIES`] times. A run's every end is a candidate the
/// constraint `length at most 63` then refuses, so the match of a label
/// or member name is quadratic in the run.
pub fn name_run_steps(input: &[u8]) -> u64 {
    input
        .split(|&b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
        .map(|r| (r.len() as u64).pow(2) / 2 * NAME_RUN_TRIES)
        .sum()
}

/// Whether the runs of name octets in `input` can explain the reference
/// matcher running out of steps: [`name_run_steps`] reaches the step
/// budget [`ORACLE_LIMITS`](crate::ORACLE_LIMITS) gives an input of its
/// length. A run costs at most `4n` steps an octet, against a budget of
/// 1,000 an octet, so only runs of a few hundred octets can: never the
/// 64 hex digits of an `object_id` or an interface ID's text.
pub fn name_runs_explain_exhaustion(input: &[u8]) -> bool {
    let l = &crate::ORACLE_LIMITS;
    name_run_steps(input) >= l.steps_base + l.steps_per_octet * input.len() as u64
}

/// [`grammar_accepts`] for `grammars/names.abnf` and the grammars that
/// use it (`idl.abnf`), or None when the reference matcher ran out of
/// steps on an input whose runs of name octets explain it
/// ([`name_runs_explain_exhaustion`]). With its constraints on, C06's
/// matcher takes steps quadratic in such a run's length (about n² / 2
/// for a label of n octets, where the context-free match takes about
/// 10n), so a run of a few hundred octets can pass
/// [`ORACLE_LIMITS`](crate::ORACLE_LIMITS)' linear budget (at about 720
/// octets for `action-ref`), and such an input is left unjudged rather
/// than failed. Running out of budget on any other input, or of any
/// other budget, is still a finding ("The gate for each target", item 6).
pub fn names_grammar_accepts(grammar: &str, rule: &str, input: &[u8]) -> Option<bool> {
    let g = repo::oracle(grammar).unwrap_or_else(|| panic!("no repository grammar {grammar}"));
    let r = g
        .rule(rule)
        .unwrap_or_else(|| panic!("{grammar} has no rule {rule}"));
    names_verdict(
        grammar,
        rule,
        input,
        g.matches_constrained(r, input, &Context::default()),
    )
}

/// The verdict [`names_grammar_accepts`] takes from the matcher's
/// result: separate so `tests/oracles.rs` can show that running out of
/// steps is still a finding when the input's name runs don't explain it.
pub fn names_verdict(
    grammar: &str,
    rule: &str,
    input: &[u8],
    result: Result<bool, Exhausted>,
) -> Option<bool> {
    match result {
        Ok(v) => Some(v),
        Err(Exhausted::Steps) if name_runs_explain_exhaustion(input) => None,
        Err(e) => panic!(
            "{grammar}/{rule}: the reference matcher ran out of a budget ({e:?}) on {} octets",
            input.len()
        ),
    }
}

/// The kernel-argument parser as the agreement check sees it: a line is
/// accepted when every argument parses, and it is within [`MAX_LEN`].
pub fn kargs_accepts(line: &[u8]) -> bool {
    line.len() <= MAX_LEN && kargs::parse(line).all(|a| a.is_ok())
}

/// `kargs-parse`'s agreement: `accepts` takes a line exactly when
/// `grammars/kernel-args.abnf` matches it as `kernel-args` and it is
/// within [`MAX_LEN`] (ADR 0041, rule 5). This generalizes
/// `crates/kargs/tests/reference.rs` from its small alphabet to any input.
pub fn check_kargs_agreement(line: &[u8], accepts: impl Fn(&[u8]) -> bool) {
    let subject = accepts(line);
    if line.len() > MAX_LEN {
        assert!(!subject, "a line over {MAX_LEN} octets is accepted");
        return;
    }
    let grammar = grammar_accepts("kernel-args", "kernel-args", line);
    assert_eq!(
        subject,
        grammar,
        "the parser {} the line, but the grammar {} it",
        verb(subject),
        verb(grammar)
    );
}

fn verb(accepts: bool) -> &'static str {
    if accepts { "accepts" } else { "rejects" }
}

/// The constraint reader as the agreement check sees it: `parse` reads
/// the text, and `OutOfRange` is a reading the grammar allows but no core
/// integer holds.
pub fn constraint_accepts(text: &str) -> bool {
    matches!(
        constraint::parse(text),
        Ok(_) | Err(ConstraintError::OutOfRange)
    )
}

/// The comment reader as the agreement check sees it: a comment is a
/// constraint comment when [`constraint::constraint_text`] finds text in
/// it, and that text is a constraint.
pub fn comment_accepts(comment: &str) -> bool {
    matches!(constraint::constraint_text(comment), Some(Ok(t)) if constraint_accepts(t))
}

/// `abnf-constraint`'s agreement (ADR 0062, rules 7 and 8): `parse`
/// accepts the text exactly when `grammars/constraint.abnf` matches it as
/// `constraint`, and `comment` accepts it exactly when the grammar matches
/// it as `constraint-comment`. Text that isn't UTF-8 can't be either: the
/// grammar is ASCII. Every input up to [`AGREEMENT_MAX`] octets is
/// judged; a longer one isn't compared (see [`AGREEMENT_MAX`]).
pub fn check_constraint_agreement(
    data: &[u8],
    parse: impl Fn(&str) -> bool,
    comment: impl Fn(&str) -> bool,
) {
    if data.len() > AGREEMENT_MAX {
        return;
    }
    let Ok(s) = core::str::from_utf8(data) else {
        for rule in ["constraint", "constraint-comment"] {
            assert!(
                !grammar_accepts("constraint", rule, data),
                "the grammar accepts text that isn't UTF-8 as {rule}"
            );
        }
        return;
    };
    for (rule, subject) in [("constraint", parse(s)), ("constraint-comment", comment(s))] {
        let grammar = grammar_accepts("constraint", rule, data);
        assert_eq!(
            subject,
            grammar,
            "as {rule}, the reader {} the text, but the grammar {} it",
            verb(subject),
            verb(grammar)
        );
    }
}

/// The rules of `grammars/names.abnf` that `idl-names` holds the name
/// parsers to: the three references, and the parts the parsers expose.
pub const NAMES_RULES: [&str; 7] = [
    "interface-ref",
    "action-ref",
    "error-ref",
    "name",
    "label",
    "member-name",
    "number",
];

/// C07's name parsers as the agreement check sees them (ADR 0063,
/// rule 10), one per rule of [`NAMES_RULES`], mapped as
/// `crates/idl-rt/tests/names.rs` maps them: a reference parses whole,
/// and a number takes the whole input.
pub fn names_accepts(rule: &str, input: &[u8]) -> bool {
    use idl_rt::names;
    match rule {
        "interface-ref" => names::parse_interface_ref(input).is_ok(),
        "action-ref" => names::parse_action_ref(input).is_ok(),
        "error-ref" => names::parse_error_ref(input).is_ok(),
        "name" => names::is_name(input),
        "label" => names::is_label(input),
        "member-name" => names::is_member_name(input),
        "number" => matches!(names::number(input), Some((_, n)) if n == input.len()),
        _ => panic!("no name parser for {rule}"),
    }
}

/// `idl-names`' agreement (ADR 0063, rule 10; "The gate for each target",
/// item 3): for every rule of [`NAMES_RULES`], `parse` accepts the input
/// exactly when `grammars/names.abnf` matches it with its constraints.
/// This generalizes `crates/idl-rt/tests/names.rs` from its small
/// alphabet to any input. Every input up to [`AGREEMENT_MAX`] octets is
/// judged (`idl-names`' inputs are all shorter), except as a rule's
/// matcher leaves a long name run unjudged ([`names_grammar_accepts`]).
pub fn check_names_agreement(input: &[u8], parse: impl Fn(&str, &[u8]) -> bool) {
    if input.len() > AGREEMENT_MAX {
        return;
    }
    for rule in NAMES_RULES {
        let subject = parse(rule, input);
        let Some(grammar) = names_grammar_accepts("names", rule, input) else {
            continue;
        };
        assert_eq!(
            subject,
            grammar,
            "as {rule}, the parser {} the input, but the grammar {} it",
            verb(subject),
            verb(grammar)
        );
    }
}

/// The IDL parser's verdict on a whole file, as `crates/idl/tests/grammar.rs`
/// reads it: accepted, rejected, or none when the parser stopped at one of
/// its own limits ([`idl::Limits`]), which the grammar doesn't have.
pub fn idl_file_verdict(input: &[u8]) -> Option<bool> {
    use idl::{
        Code, Limits,
        parse::{Rule, parse_rule},
    };
    match parse_rule(Rule::IdlFile, input, &Limits::default()) {
        Ok(()) => Some(true),
        Err(d) if d.code == Code::Limit => None,
        Err(_) => Some(false),
    }
}

/// `idl-front-end`'s agreement (ADR 0067, rule 11): the parser accepts a
/// file exactly when `grammars/idl.abnf` matches it as `idl-file` with its
/// constraints. An input the parser gives no verdict on, at one of its
/// own limits, isn't compared, and neither is one over
/// [`AGREEMENT_MAX`] octets (`tests/linear.rs` judges longer files
/// outside the fuzzer) or one with a long name run the matcher leaves
/// unjudged ([`names_grammar_accepts`]).
pub fn check_idl_agreement(input: &[u8], parser: impl Fn(&[u8]) -> Option<bool>) {
    if input.len() > AGREEMENT_MAX {
        return;
    }
    let Some(subject) = parser(input) else {
        return;
    };
    let Some(grammar) = names_grammar_accepts("idl", "idl-file", input) else {
        return;
    };
    assert_eq!(
        subject,
        grammar,
        "the parser {} the file, but the grammar {} it",
        verb(subject),
        verb(grammar)
    );
}

// ---- Round trips (item 2) ----------------------------------------------

/// The constraint's canonical text: words separated by one space,
/// integers in decimal without leading zeros, and rule names as written.
/// It is the encoder the round trip holds `parse` to.
pub fn render_constraint(c: &Constraint) -> String {
    use Constraint as C;
    let join = |v: &[i128]| v.iter().map(i128::to_string).collect::<Vec<_>>().join(", ");
    match c {
        C::ExactlyOctets(r) => format!("exactly {r} octets"),
        C::ExactlyElements(r, e) => format!("exactly {r} {e} elements"),
        C::ExactlyWords(r) => format!("exactly {r} words"),
        C::HeaderWords(r) => format!("header words {r}"),
        C::AtMost(n) => format!("at most {n}"),
        C::AtLeast(n) => format!("at least {n}"),
        C::In(n, m) => format!("in {n}..{m}"),
        C::Not(n) => format!("not {n}"),
        C::NotOneOf(list) => format!("not one of {}", join(list)),
        C::LengthAtMost(n) => format!("length at most {n}"),
        C::NotWord(words) => format!("not word {}", words.join(" ")),
        C::Ascending(r) => format!("ascending {r}"),
        C::AscendingTags => "ascending tags".into(),
        C::CapabilityIndex => "capability index".into(),
        C::CanonicalFloat => "canonical float".into(),
        C::RemainingOctets => "remaining octets".into(),
    }
}

/// The constraint round trip. The text form is canonical
/// ("Strict requests, tolerant reads"), so every text `parse` reads is
/// exactly `render`'s text for what it read, and reading that again gives
/// the same constraint.
pub fn check_constraint_round_trip(text: &str, render: impl Fn(&Constraint) -> String) {
    let Ok(c) = constraint::parse(text) else {
        return;
    };
    let t = render(&c);
    assert_eq!(t, text, "the text isn't the canonical form of {c:?}");
    assert_eq!(
        constraint::parse(&t),
        Ok(c),
        "the canonical text reads back differently"
    );
}

/// A value's text with its escapes processed. A buffer as long as the raw
/// text always suffices.
pub fn unescaped(v: &Value<'_>) -> Vec<u8> {
    let mut buf = vec![0u8; v.raw().len()];
    let s = v
        .unescape(&mut buf)
        .unwrap_or_else(|e| panic!("unescaping {v:?} into {} bytes: {e}", v.raw().len()));
    s.as_bytes().to_vec()
}

/// Whether an unescaped value can be written bare: one or more
/// `bare-char`s (printable, not SP or DQUOTE).
fn bare_ok(text: &[u8]) -> bool {
    !text.is_empty()
        && text
            .iter()
            .all(|&b| b == 0x21 || (0x23..=0x7e).contains(&b))
}

/// The arguments as a canonical line: single spaces between them, a value
/// bare when it can be, and quoted with `\"` and `\\` escapes otherwise.
/// It is the encoder the kernel-argument round trip holds the parser to.
pub fn render_kargs(args: &[Arg<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        out.extend_from_slice(a.key.as_bytes());
        let Some(v) = a.value else { continue };
        out.push(b'=');
        let text = unescaped(&v);
        if bare_ok(&text) {
            out.extend_from_slice(&text);
        } else {
            out.push(b'"');
            for b in text {
                if b == b'"' || b == b'\\' {
                    out.push(b'\\');
                }
                out.push(b);
            }
            out.push(b'"');
        }
    }
    out
}

/// What a line means: each argument's key and unescaped value, in order.
pub type Meaning = Vec<(String, Option<Vec<u8>>)>;

/// The meaning of a line every argument of which parses, or `None`.
pub fn kargs_meaning(line: &[u8]) -> Option<Meaning> {
    kargs::parse(line)
        .map(|a| {
            a.ok()
                .map(|a| (a.key.to_string(), a.value.map(|v| unescaped(&v))))
        })
        .collect()
}

/// The kernel-argument round trip: a line that parses, rendered by
/// `render`, parses to the same keys and unescaped values; and the
/// rendered line is a fixed point, so `render(parse(b)) == b` for every
/// canonical `b`. The kernel-argument form isn't canonical (any number of
/// spaces separate arguments), so this is the round trip that holds.
pub fn check_kargs_round_trip(line: &[u8], render: impl Fn(&[Arg<'_>]) -> Vec<u8>) {
    let Some(meaning) = kargs_meaning(line) else {
        return;
    };
    let args: Vec<Arg<'_>> = kargs::parse(line).map_while(Result::ok).collect();
    let canonical = render(&args);
    assert!(
        canonical.len() <= line.len(),
        "the canonical form is longer than the line"
    );
    assert_eq!(
        kargs_meaning(&canonical).as_ref(),
        Some(&meaning),
        "the canonical line {:?} means something else",
        String::from_utf8_lossy(&canonical)
    );
    let again: Vec<Arg<'_>> = kargs::parse(&canonical).map_while(Result::ok).collect();
    assert_eq!(
        render(&again),
        canonical,
        "the canonical form isn't a fixed point"
    );
}

/// The words a GRUB menu entry holds for a line's arguments, after GRUB's
/// own script parser has removed the grammar's quotes: `key`, or
/// `key=value` with the value unescaped.
pub fn grub_words(meaning: &Meaning) -> Vec<Vec<u8>> {
    meaning
        .iter()
        .map(|(k, v)| {
            let mut w = k.as_bytes().to_vec();
            if let Some(v) = v {
                w.push(b'=');
                w.extend_from_slice(v);
            }
            w
        })
        .collect()
}

/// GRUB 2.14's `grub_create_loader_cmdline` (grub-core/lib/cmdline.c),
/// as the arm64 `linux` command calls it: `BOOT_IMAGE=<path>` first, then
/// each word with a backslash before every `\`, `'` and `"`, wrapped in
/// double quotes when it holds a space, and one space between words.
pub fn grub_encode(words: &[Vec<u8>]) -> Vec<u8> {
    let boot_image = b"BOOT_IMAGE=/aspis.efi".to_vec();
    let mut out = Vec::new();
    for (i, w) in core::iter::once(&boot_image).chain(words).enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        let space = w.contains(&b' ');
        if space {
            out.push(b'"');
        }
        for &b in w {
            if matches!(b, b'\\' | b'\'' | b'"') {
                out.push(b'\\');
            }
            out.push(b);
        }
        if space {
            out.push(b'"');
        }
    }
    out
}

/// The stub's conversion, with the stub's buffers: `2n + 16` octets of
/// output and `n + 1` for one word (`boot/stub/src/main.rs`).
pub fn stub_convert(line: &[u8]) -> (Result<usize, kargs::GrubError>, Vec<u8>) {
    let mut out = vec![0u8; line.len() * 2 + 16];
    let mut word = vec![0u8; line.len() + 1];
    let r = kargs::from_grub(line, &mut out, &mut word);
    if let Ok(n) = r {
        out.truncate(n);
    }
    (r, out)
}

/// The GRUB round trip (ADR 0041, rule 5): a line that parses as kernel
/// arguments, put through GRUB's encoding by `encode` and back through
/// the stub's conversion, means the same to the kernel.
pub fn check_grub_round_trip(line: &[u8], encode: impl Fn(&[Vec<u8>]) -> Vec<u8>) {
    let Some(meaning) = kargs_meaning(line) else {
        return;
    };
    let grub = encode(&grub_words(&meaning));
    assert!(kargs::is_grub(&grub), "GRUB's line starts with BOOT_IMAGE=");
    let (r, out) = stub_convert(&grub);
    assert!(r.is_ok(), "the stub can't convert GRUB's line: {r:?}");
    assert_eq!(
        kargs_meaning(&out).as_ref(),
        Some(&meaning),
        "through GRUB and the stub, the line {:?} became {:?}",
        String::from_utf8_lossy(line),
        String::from_utf8_lossy(&out)
    );
}

// ---- The vector checker's report ---------------------------------------

/// The invariants of a [`Report`] on a vector file: every vector is
/// judged or left unjudged; `errc` lines are among those that agree; the
/// check stops at the first vector over a budget, so at most one verdict
/// is [`Verdict::Exhausted`], and it is last; and the results follow the
/// vectors in order.
pub fn check_report(f: &VectorFile, r: &Report) {
    assert_eq!(
        r.agree + r.disagree + r.unjudged,
        f.vectors.len(),
        "every vector is judged or unjudged"
    );
    assert_eq!(
        r.results.len(),
        r.agree + r.disagree,
        "one result per judged vector"
    );
    assert!(r.errc <= r.agree, "errc lines are among those that agree");
    let exhausted: Vec<usize> = r
        .results
        .iter()
        .enumerate()
        .filter(|(_, (_, v))| matches!(v, Verdict::Exhausted(_)))
        .map(|(i, _)| i)
        .collect();
    assert!(
        exhausted.len() <= 1,
        "the check stops at the first exhausted"
    );
    if let Some(&i) = exhausted.first() {
        assert_eq!(i + 1, r.results.len(), "an exhausted verdict is last");
    } else {
        assert_eq!(r.unjudged, 0, "nothing is unjudged unless a budget ran out");
    }
    // The counts are the verdicts': agreeing ones, and the `errc` lines
    // among them. Constraints only narrow a match, so a vector that keeps
    // them matches the context-free grammar too.
    let mut agree = 0;
    let mut errc = 0;
    for ((line, verdict), v) in r.results.iter().zip(&f.vectors) {
        assert_eq!(*line, v.line, "results follow the vectors");
        match verdict {
            Verdict::Agrees => {
                agree += 1;
                errc += usize::from(v.tag == Tag::Errc);
            }
            Verdict::Disagrees {
                context_free,
                constrained,
            } => assert!(
                context_free | !constrained,
                "line {line}: keeps the constraints but doesn't match"
            ),
            Verdict::Exhausted(_) | Verdict::UnknownRule => {}
        }
    }
    assert_eq!(agree, r.agree, "the count of agreeing vectors");
    assert_eq!(errc, r.errc, "the count of agreeing errc vectors");
}
