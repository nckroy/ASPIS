// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Vector files (ADR 0013, rule 6; ADR 0062, rule 8), read exactly as
//! `tools/ci/check-grammars.py` reads them (docs/design/call-language.md,
//! "Vector files").
//!
//! A file is UTF-8 text, split into lines at LF; a CR anywhere is an
//! error, so it is written `\x0d`. Empty lines and lines starting with `#`
//! are skipped, except the directives:
//!
//! - `# rule: NAME` and `# max-length: N` hold for the whole file, and each
//!   appears at most once;
//! - `# caps: N` (0 to 3) sets the capability count for the lines after it
//!   and resets the unwrapped mask; `# unwrapped: H` (one hex digit, whose
//!   bits are below the count) sets the mask. Both start at 0.
//!
//! A `#` line naming one of these keywords is a directive and must be
//! exactly `# keyword: value`. Every other line is a vector: `ok`, `err`
//! or `errc`, an optional `@rule`, a tab, then the octets with the escapes
//! `\t`, `\\`, `\"` and `\xHH`. Every other octet stands for itself.

use alloc::{string::String, vec::Vec};
use core::fmt;

use crate::{Context, Exhausted, Grammar, constraint::is_rulename, matcher};

/// A vector's tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    /// The octets match the rule and keep its constraints.
    Ok,
    /// The octets don't match the rule's context-free grammar.
    Err,
    /// The octets match the context-free grammar but break a constraint.
    Errc,
}

/// One vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vector {
    pub line: usize,
    pub tag: Tag,
    /// The rule it tests: its `@rule`, or the file's `# rule:`.
    pub rule: String,
    pub octets: Vec<u8>,
    /// The capability count, from `# caps:`.
    pub caps: u8,
    /// The unwrapped mask, from `# unwrapped:`.
    pub unwrapped: u8,
}

/// A vector file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorFile {
    pub rule: Option<String>,
    pub max_length: Option<u64>,
    pub vectors: Vec<Vector>,
}

/// Why a vector file doesn't read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorErrorKind {
    /// The file isn't UTF-8.
    NotUtf8,
    /// A CR, which a vector writes as `\x0d`.
    CarriageReturn,
    /// A directive that isn't exactly `# keyword: value`, or whose value
    /// is out of range.
    Directive,
    /// A second `# rule:` or `# max-length:`.
    RepeatedDirective,
    /// `# unwrapped:` bits at or above the capability count.
    UnwrappedBeyondCaps,
    /// No tab, or a tag that isn't `ok`, `err` or `errc` with an optional
    /// `@rule`.
    Line,
    /// A backslash not followed by `t`, `\`, `"`, or `x` and two hex
    /// digits.
    Escape,
    /// A line with no `@rule` in a file with no `# rule:`.
    NoRule,
}

/// A vector file error, with its line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorError {
    pub line: usize,
    pub kind: VectorErrorKind,
}

impl fmt::Display for VectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use VectorErrorKind as K;
        let what = match self.kind {
            K::NotUtf8 => "not UTF-8",
            K::CarriageReturn => "a CR; write it as \\x0d",
            K::Directive => "a malformed directive",
            K::RepeatedDirective => "a second '# rule:' or '# max-length:'",
            K::UnwrappedBeyondCaps => "unwrapped bits beyond the capability count",
            K::Line => "expected 'ok', 'err' or 'errc', an optional '@rule', and a tab",
            K::Escape => "a bad escape",
            K::NoRule => "no '@rule' and no '# rule:' directive",
        };
        write!(f, "{}: {what}", self.line)
    }
}

const KEYWORDS: [&str; 4] = ["rule", "max-length", "caps", "unwrapped"];

/// The directive a `#` line names, if it names one: `#`, spaces or tabs,
/// a keyword, spaces or tabs, then `:`.
fn directive_keyword(line: &str) -> Option<&'static str> {
    let rest = line.strip_prefix('#')?.trim_start_matches([' ', '\t']);
    KEYWORDS.into_iter().find(|k| {
        rest.strip_prefix(k)
            .is_some_and(|r| r.trim_start_matches([' ', '\t']).starts_with(':'))
    })
}

/// A directive's value: the line must be exactly `# keyword: value`, with
/// the value not starting or ending with whitespace.
fn directive_value<'l>(line: &'l str, keyword: &str) -> Option<&'l str> {
    let v = line
        .strip_prefix("# ")?
        .strip_prefix(keyword)?
        .strip_prefix(": ")?;
    let edge = |c: Option<char>| c.is_none_or(char::is_whitespace);
    (!edge(v.chars().next()) && !edge(v.chars().last())).then_some(v)
}

/// Decodes a vector's body.
fn decode(body: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(body.len());
    let mut b = body.bytes();
    while let Some(c) = b.next() {
        if c != b'\\' {
            out.push(c);
            continue;
        }
        match b.next()? {
            b't' => out.push(b'\t'),
            b'\\' => out.push(b'\\'),
            b'"' => out.push(b'"'),
            b'x' => {
                let hex = |c: u8| (c as char).to_digit(16);
                let hi = hex(b.next()?)?;
                let lo = hex(b.next()?)?;
                out.push(u8::try_from(hi * 16 + lo).ok()?);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Reads a vector file.
pub fn parse(text: &[u8]) -> Result<VectorFile, VectorError> {
    use VectorErrorKind as K;
    let fail = |line, kind| Err(VectorError { line, kind });
    let text = match core::str::from_utf8(text) {
        Ok(t) => t,
        Err(_) => return fail(0, K::NotUtf8),
    };
    if let Some(i) = text.find('\r') {
        return fail(text[..i].matches('\n').count() + 1, K::CarriageReturn);
    }
    let lines = || text.split('\n').enumerate().map(|(i, l)| (i + 1, l));

    // The whole-file directives, wherever they are.
    let (mut rule, mut max_length) = (None, None);
    for (n, line) in lines() {
        let Some(k) = directive_keyword(line) else {
            continue;
        };
        let Some(v) = directive_value(line, k) else {
            return fail(n, K::Directive);
        };
        let valid = match k {
            "rule" => is_rulename(v),
            "max-length" => v.bytes().all(|b| b.is_ascii_digit()) && v.parse::<u64>().is_ok(),
            "caps" => matches!(v, "0" | "1" | "2" | "3"),
            _ => v.len() == 1 && v.bytes().all(|b| b.is_ascii_hexdigit()),
        };
        if !valid {
            return fail(n, K::Directive);
        }
        match k {
            "rule" if rule.replace(String::from(v)).is_some() => {
                return fail(n, K::RepeatedDirective);
            }
            "max-length" if max_length.replace(v.parse::<u64>().unwrap_or(0)).is_some() => {
                return fail(n, K::RepeatedDirective);
            }
            _ => {}
        }
    }

    let mut vectors = Vec::new();
    let (mut caps, mut unwrapped) = (0u8, 0u8);
    for (n, line) in lines() {
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            match (
                directive_keyword(line),
                directive_keyword(line).and_then(|k| directive_value(line, k)),
            ) {
                (Some("caps"), Some(v)) => {
                    caps = v.parse().unwrap_or(0);
                    unwrapped = 0;
                }
                (Some("unwrapped"), Some(v)) => {
                    unwrapped = u8::from_str_radix(v, 16).unwrap_or(0);
                    if unwrapped >> caps != 0 {
                        return fail(n, K::UnwrappedBeyondCaps);
                    }
                }
                _ => {}
            }
            continue;
        }
        let Some((head, body)) = line.split_once('\t') else {
            return fail(n, K::Line);
        };
        let (tag, at) = match head.split_once('@') {
            Some((t, r)) if is_rulename(r) => (t, Some(r)),
            Some(_) => return fail(n, K::Line),
            None => (head, None),
        };
        let tag = match tag {
            "ok" => Tag::Ok,
            "err" => Tag::Err,
            "errc" => Tag::Errc,
            _ => return fail(n, K::Line),
        };
        let Some(rule) = at.map(String::from).or_else(|| rule.clone()) else {
            return fail(n, K::NoRule);
        };
        let Some(octets) = decode(body) else {
            return fail(n, K::Escape);
        };
        vectors.push(Vector {
            line: n,
            tag,
            rule,
            octets,
            caps,
            unwrapped,
        });
    }
    Ok(VectorFile {
        rule,
        max_length,
        vectors,
    })
}

/// One vector's result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The grammar agrees with the tag.
    Agrees,
    /// The grammar doesn't. `context_free` says whether the octets match
    /// the context-free grammar (within `# max-length:`), and
    /// `constrained` whether they also keep every constraint.
    Disagrees {
        context_free: bool,
        constrained: bool,
    },
    /// The match ran out of a budget: a failure, never a verdict.
    Exhausted(Exhausted),
    /// The grammar has no rule by the vector's name.
    UnknownRule,
}

/// The results of a vector file.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Each judged vector's line and verdict.
    pub results: Vec<(usize, Verdict)>,
    pub agree: usize,
    /// `errc` vectors among those that agree.
    pub errc: usize,
    /// Vectors that don't agree, for any reason.
    pub disagree: usize,
    /// Vectors not judged: those after the first one that ran out of a
    /// budget.
    pub unjudged: usize,
}

/// Checks every vector of `f` against `g` (ADR 0062, rule 8).
///
/// Each vector gets two judgments. The context-free one, `cf`, is the
/// Python checker's: the octets match the rule, within `# max-length:`.
/// The full one also keeps every constraint, against the vector's
/// `# caps:` count. `ok` agrees when the full judgment holds, `err` when
/// the context-free one fails, and `errc` when the context-free one holds
/// and the full one fails. An unknown rule, or a budget run out, never
/// agrees.
///
/// Every match takes its steps from one allowance for the whole file,
/// [`Limits::file_steps`](crate::Limits::file_steps), and the check stops
/// at the first vector that runs out of any budget. So a publisher's file
/// costs the catalog no more than that, however many vectors it holds
/// (ADR 0027, rule 2).
pub fn check(g: &Grammar, f: &VectorFile) -> Report {
    let mut report = Report::default();
    let mut allowance = g.limits().file_steps;
    for (i, v) in f.vectors.iter().enumerate() {
        let verdict =
            match g.rule(&v.rule) {
                None => Verdict::UnknownRule,
                Some(r) => {
                    let within = f.max_length.is_none_or(|m| v.octets.len() as u64 <= m);
                    let cx = Context {
                        caps: v.caps,
                        unwrapped: v.unwrapped,
                    };
                    // Constraints only narrow a match, so the full judgment
                    // runs only where the context-free one holds.
                    let judged =
                        match within {
                            false => Ok((false, false)),
                            true => matcher::matches(g, r, &v.octets, None, &mut allowance)
                                .and_then(|cf| match cf {
                                    false => Ok((false, false)),
                                    true => {
                                        matcher::matches(g, r, &v.octets, Some(&cx), &mut allowance)
                                            .map(|full| (true, full))
                                    }
                                }),
                        };
                    match judged {
                        Err(e) => Verdict::Exhausted(e),
                        Ok((cf, full)) => {
                            let agrees = match v.tag {
                                Tag::Ok => full,
                                Tag::Err => !cf,
                                Tag::Errc => cf && !full,
                            };
                            if agrees {
                                Verdict::Agrees
                            } else {
                                Verdict::Disagrees {
                                    context_free: cf,
                                    constrained: full,
                                }
                            }
                        }
                    }
                }
            };
        if verdict == Verdict::Agrees {
            report.agree += 1;
            if v.tag == Tag::Errc {
                report.errc += 1;
            }
        } else {
            report.disagree += 1;
        }
        report.results.push((v.line, verdict));
        if matches!(verdict, Verdict::Exhausted(_)) {
            report.unjudged = f.vectors.len() - i - 1;
            break;
        }
    }
    report
}
