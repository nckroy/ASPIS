// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The conformance runner (ADR 0013, rule 3; ADR 0067, rule 9; ADR 0068,
//! rules 4 and 6; docs/design/call-language.md, "Back ends", "The gate for
//! each target", "Differential tests").
//!
//! It checks a binding of one interface major, an
//! [`idl_rt::conformance::Subject`], against one minor's generated
//! grammars and vectors, and against [`crate::value`], the dynamic codec.
//! CI runs it on every interface and fixture; the catalog can run it on a
//! publisher's grammars and vectors (it is `no_std` with `alloc`, and does
//! no I/O), and an application's compiler run uses the same runner (parity,
//! ADR 0027, rule 3).
//!
//! For each wire vector:
//!
//! 1. an ok vector decodes and re-encodes to the same octets; an err or
//!    errc vector is refused;
//! 2. on the vector and on deterministic mutations of each ok vector (bit
//!    flips, truncations, insertions, deletions; fixed seeds), the
//!    subject's verdict maps to the grammar's: decoded, or decoded with
//!    `value_too_new`, means the grammar must accept with its constraints;
//!    `malformed` or `field_too_new` means it must reject. The dynamic
//!    codec must agree, and an accepted mutation must re-encode to itself;
//! 3. an ok vector's JSON, from the subject, is the dynamic codec's, and
//!    matches the text grammar in its text rule, bare and placed in a call
//!    (`m-*--call`) or a reply (`m-*--reply`); the call or reply without
//!    its JSON, the default form, matches there too.
//!
//! A `[kernel]` interface has no wire grammar ([0013], rule 3). Its subject
//! still has codecs, so the runner feeds it the dynamic codec's encodings
//! of the vector generator's samples, checks item 3, and checks item 2
//! against the dynamic codec alone.
//!
//! A match that runs out of crates/abnf's budget is counted as unjudged,
//! never as a verdict. So is every match after the file's [`Budget`] is
//! spent: one budget serves all of a file's minors, for the samples of a
//! `[kernel]` interface and for every match, so a file costs the runner
//! no more than [`budget`] allows, whatever minor it declares.

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use abnf::{Context, Grammar, vectors::Tag, vectors::VectorFile};
use idl_rt::{
    conformance::Subject,
    json::JsonWriter,
    rules::{Op, Verdict},
};

use crate::{
    Checked,
    schema::{Schema, Top},
    value,
    vectors::{Budget, FILE_BUDGET, escape, samples},
};

/// The ID the runner calls methods on in the call text.
const TARGET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Mutations of each ok vector.
pub const MUTATIONS: usize = 24;

/// The most steps the runner's matches may take for one file, every
/// minor together: each vector and its mutations against the wire
/// grammar, and each JSON against the text grammar, some 30 matches for
/// each ok vector.
pub const STEPS: u64 = 1 << 28;

/// A budget for one file's runs, shared by all its minors: the samples'
/// values of [`crate::vectors::FILE_BUDGET`], and [`STEPS`].
pub fn budget() -> Budget {
    Budget::new(FILE_BUDGET, STEPS)
}

/// What the runner found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Checks made.
    pub checks: usize,
    /// Grammar matches that ran out of their budget, so judged nothing.
    pub unjudged: usize,
    /// What disagreed, one line each.
    pub failures: Vec<String>,
}

/// What one input's differential found, when everything agreed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Judged {
    /// The subject, the grammar and the dynamic codec all accepted it.
    Accepted,
    /// They all refused it.
    Refused,
    /// The grammar ran out of its budget; the subject and the dynamic codec
    /// agreed.
    Unjudged,
}

/// A small deterministic generator (SplitMix64), so a failure replays.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// Deterministic mutations of a message, from a seed: one bit flipped, a
/// truncation, an octet inserted, an octet deleted, an octet replaced by 0
/// or 0xFF, a run of octets doubled.
pub fn mutations(octets: &[u8], seed: u64, n: usize) -> Vec<Vec<u8>> {
    let mut rng = Rng(seed);
    let mut out = Vec::with_capacity(n);
    for k in 0..n {
        let mut m = octets.to_vec();
        let at = rng.below(m.len());
        match k % 6 {
            0 if !m.is_empty() => m[at] ^= 1 << rng.below(8),
            1 => m.truncate(at),
            2 => m.insert(at, rng.next() as u8),
            3 if !m.is_empty() => {
                m.remove(at);
            }
            4 if !m.is_empty() => m[at] = if rng.next() & 1 == 0 { 0 } else { 0xFF },
            _ => {
                let len = rng.below(m.len().saturating_sub(at).min(8)) + 1;
                let end = (at + len).min(m.len());
                let run = m[at..end].to_vec();
                m.splice(at..at, run);
            }
        }
        if m != octets {
            out.push(m);
        }
    }
    out
}

/// The subject's verdict on one input: Ok(accepted), or a failure.
fn subject_verdict(
    subject: &dyn Subject,
    rule: &str,
    minor: u16,
    caps: u8,
    data: &[u8],
) -> Result<bool, String> {
    let mut out = vec![0u8; data.len() + 64];
    match subject.run(rule, minor, caps, data, Op::Encode(&mut out)) {
        Verdict::Ok { len, .. } if out[..len] == *data => Ok(true),
        Verdict::Ok { len, .. } => Err(format!(
            "accepted, and re-encodes differently: {}",
            escape(&out[..len])
        )),
        Verdict::Malformed | Verdict::FieldTooNew => Ok(false),
        Verdict::Encode(e) => Err(format!("accepted, and doesn't re-encode: {e:?}")),
        Verdict::NoRule => Err("the subject has no such rule".into()),
    }
}

/// The grammar's verdict, with its constraints: Some(accepted), or None
/// when the match ran out of its budget, or the file's.
fn grammar_verdict(
    g: &Grammar,
    rule: &str,
    data: &[u8],
    caps: u8,
    budget: &Budget,
) -> Result<Option<bool>, String> {
    let r = g
        .rule(rule)
        .ok_or_else(|| format!("the grammar has no rule {rule}"))?;
    let cx = Context { caps, unwrapped: 0 };
    Ok(match budget.matches(g, r, data, None) {
        Ok(Some(false)) => Some(false),
        Ok(Some(true)) => budget.matches(g, r, data, Some(&cx)).ok().flatten(),
        Ok(None) | Err(_) => None,
    })
}

/// The top-level body of each rule at the schema's minor.
fn tops_by_rule(s: &Schema<'_>) -> BTreeMap<String, Top> {
    let mut out = BTreeMap::new();
    for t in s.tops() {
        out.entry(s.top_rule(t)).or_insert(t);
    }
    out
}

/// One input through the subject, the grammar (when there is one) and the
/// dynamic codec, at a minor, with a capability count. Everything must
/// agree, and an accepted input must re-encode to itself.
pub fn judge(
    subject: &dyn Subject,
    s: &Schema<'_>,
    grammar: Option<&Grammar>,
    rule: &str,
    caps: u8,
    data: &[u8],
) -> Result<Judged, String> {
    let minor = s.version().minor;
    let top = tops_by_rule(s)
        .remove(rule)
        .ok_or_else(|| format!("no rule {rule} at minor {minor}"))?;
    judge_top(
        subject,
        s,
        grammar,
        rule,
        top,
        caps,
        data,
        &Budget::default(),
    )
}

/// [`judge`], with the rule's top-level body found, and the grammar's
/// matches taking their steps from `budget`.
#[allow(clippy::too_many_arguments)]
fn judge_top(
    subject: &dyn Subject,
    s: &Schema<'_>,
    grammar: Option<&Grammar>,
    rule: &str,
    top: Top,
    caps: u8,
    data: &[u8],
    budget: &Budget,
) -> Result<Judged, String> {
    let minor = s.version().minor;
    let ours = subject_verdict(subject, rule, minor, caps, data)?;
    let dynamic = value::decode(s, top, data, caps).is_ok();
    if ours != dynamic {
        return Err(format!(
            "the subject {} it, and the dynamic codec {}",
            if ours { "accepts" } else { "refuses" },
            if dynamic { "accepts" } else { "refuses" }
        ));
    }
    let Some(g) = grammar else {
        return Ok(if ours {
            Judged::Accepted
        } else {
            Judged::Refused
        });
    };
    match grammar_verdict(g, rule, data, caps, budget)? {
        None => Ok(Judged::Unjudged),
        Some(gv) if gv == ours => Ok(if ours {
            Judged::Accepted
        } else {
            Judged::Refused
        }),
        Some(gv) => Err(format!(
            "the subject {} it, and the grammar {}",
            if ours { "accepts" } else { "refuses" },
            if gv { "accepts" } else { "refuses" }
        )),
    }
}

/// The differential fuzz-target entry for one rule: decoder against
/// matcher, and against the dynamic codec ("Differential tests", the
/// first row). It panics when they disagree, or when an accepted input
/// doesn't re-encode to itself.
pub fn differential(
    subject: &dyn Subject,
    s: &Schema<'_>,
    grammar: Option<&Grammar>,
    rule: &str,
    caps: u8,
    data: &[u8],
) {
    if let Err(e) = judge(subject, s, grammar, rule, caps, data) {
        panic!(
            "{}/{} {rule} at minor {}: {e}: {}",
            subject.name(),
            subject.major(),
            s.version().minor,
            escape(data)
        );
    }
}

/// The text rule that holds a wire rule's JSON, and how to place that JSON
/// in a call or a reply: `m-x--req` is `m-x--args` and `m-x--call`;
/// `m-x--rep` and `m-x--open` are `m-x--results` and `m-x--reply`; any
/// other rule keeps its name ("Generated grammars").
fn text_rules(rule: &str) -> (String, Option<(String, bool)>) {
    if let Some(m) = rule.strip_suffix("--req") {
        (format!("{m}--args"), Some((format!("{m}--call"), true)))
    } else if let Some(m) = rule
        .strip_suffix("--rep")
        .or_else(|| rule.strip_suffix("--open"))
    {
        (
            format!("{m}--results"),
            Some((format!("{m}--reply"), false)),
        )
    } else {
        (rule.to_string(), None)
    }
}

/// Checks an accepted message's JSON (item 3).
#[allow(clippy::too_many_arguments)]
fn check_json(
    subject: &dyn Subject,
    s: &Schema<'_>,
    text: &Grammar,
    rule: &str,
    top: Top,
    caps: u8,
    data: &[u8],
    budget: &Budget,
) -> Result<(), String> {
    let minor = s.version().minor;
    let mut buf = vec![0u8; 8 * data.len() + 1024];
    let mut j = JsonWriter::new(&mut buf);
    subject.run(rule, minor, caps, data, Op::Json(&mut j));
    let ours = j
        .finish()
        .map_err(|_| String::from("the subject's JSON overflows"))?
        .to_vec();
    let d = value::decode(s, top, data, caps).map_err(|e| format!("{e:?}"))?;
    let mut buf2 = vec![0u8; 8 * data.len() + 1024];
    let mut j2 = JsonWriter::new(&mut buf2);
    value::to_json(s, top, &d.value, &mut j2);
    let want = j2
        .finish()
        .map_err(|_| String::from("the dynamic codec's JSON overflows"))?;
    if ours != want {
        return Err(format!(
            "JSON {} but the dynamic codec writes {}",
            String::from_utf8_lossy(&ours),
            String::from_utf8_lossy(want)
        ));
    }
    let json = String::from_utf8(ours).map_err(|_| String::from("the JSON isn't UTF-8"))?;
    let (bare, placed) = text_rules(rule);
    let mut lines = vec![(bare, json.clone())];
    if let Some((r, call)) = placed {
        let unit = s.model.unit(s.root);
        // Arguments and results are opt-in (ADR 0063, rule 9): the bare
        // form, then the form with them.
        let head = if call {
            let target = if s.is_kernel() { "-" } else { TARGET };
            let Top::Request(i) = top else {
                return Err(format!("{rule} isn't a request"));
            };
            let action = format!("{}/{}/{}", unit.name, unit.major(), s.member_name(i));
            format!("{action} {target}")
        } else {
            String::from("ok")
        };
        lines.push((r.clone(), head.clone()));
        lines.push((r, format!("{head} {json}")));
    }
    for (r, line) in lines {
        match grammar_verdict(text, &r, line.as_bytes(), 0, budget)? {
            Some(true) | None => {}
            Some(false) => {
                return Err(format!(
                    "the text grammar's {r} rejects the JSON: {}",
                    escape(line.as_bytes())
                ));
            }
        }
    }
    Ok(())
}

/// Runs every check on one minor: `wire` is the minor's wire grammar and
/// vectors (None for a `[kernel]` interface), `text` its text grammar.
/// The subject reads at `minor`, which may be older than its own.
/// `budget` is the file's, from [`budget`], shared by its runs at every
/// minor, lowest first.
pub fn run(
    subject: &dyn Subject,
    checked: &Checked,
    minor: u16,
    wire: Option<(&Grammar, &VectorFile)>,
    text: &Grammar,
    budget: &Budget,
) -> Report {
    let s = Schema::new(checked, minor);
    let mut report = Report::default();
    let at = |rule: &str, what: &str| {
        format!(
            "{}/{}.{minor} {rule}: {what}",
            subject.name(),
            subject.major()
        )
    };
    if subject.minor() < minor {
        report.failures.push(at(
            "-",
            &format!("the subject knows minors up to {}", subject.minor()),
        ));
        return report;
    }
    // The inputs: the wire vectors, or the samples' encodings.
    let inputs: Vec<(usize, Tag, String, Vec<u8>, u8)> = match wire {
        Some((_, file)) => file
            .vectors
            .iter()
            .map(|v| (v.line, v.tag, v.rule.clone(), v.octets.clone(), v.caps))
            .collect(),
        None => match samples(&s, budget) {
            Ok(list) => list
                .into_iter()
                .enumerate()
                .map(|(i, x)| (i + 1, Tag::Ok, s.top_rule(x.top), x.octets, x.caps))
                .collect(),
            Err(e) => {
                report.failures.push(at("-", &e));
                return report;
            }
        },
    };
    let grammar = wire.map(|(g, _)| g);
    let tops = tops_by_rule(&s);
    for (line, tag, rule, octets, caps) in inputs {
        let here = |what: &str| at(&rule, &format!("line {line}: {what}: {}", escape(&octets)));
        let Some(&top) = tops.get(&rule) else {
            report.checks += 1;
            report
                .failures
                .push(here(&format!("no rule {rule} at minor {minor}")));
            continue;
        };
        // Item 1, and item 2 on the vector itself.
        report.checks += 1;
        match judge_top(subject, &s, grammar, &rule, top, caps, &octets, budget) {
            Ok(Judged::Accepted) if tag == Tag::Ok => {}
            Ok(Judged::Refused) if tag != Tag::Ok => {}
            Ok(Judged::Unjudged) => report.unjudged += 1,
            Ok(j) => report
                .failures
                .push(here(&format!("tagged {tag:?}, and judged {j:?}"))),
            Err(e) => report.failures.push(here(&e)),
        }
        if tag != Tag::Ok {
            continue;
        }
        // Item 3.
        report.checks += 1;
        if let Err(e) = check_json(subject, &s, text, &rule, top, caps, &octets, budget) {
            report.failures.push(here(&e));
        }
        // Item 2, on mutations.
        let seed = (line as u64) << 16 | u64::from(minor);
        for m in mutations(&octets, seed, MUTATIONS) {
            report.checks += 1;
            match judge_top(subject, &s, grammar, &rule, top, caps, &m, budget) {
                Ok(Judged::Unjudged) => report.unjudged += 1,
                Ok(_) => {}
                Err(e) => report.failures.push(at(
                    &rule,
                    &format!("line {line}, mutated: {e}: {}", escape(&m)),
                )),
            }
        }
    }
    report
}
