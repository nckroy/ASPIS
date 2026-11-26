// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The constraint vocabulary (ADR 0062, rule 7): the closed set of forms a
//! `; constraint:` comment may take in a generated grammar.
//!
//! [`parse`] reads a constraint's text exactly as `grammars/constraint.abnf`
//! defines `constraint`, and [`constraint_text`] finds the text in a comment
//! as that file's `constraint-comment` does. A host test holds both to
//! `grammars/constraint.vectors`. Text that doesn't parse is prose, which
//! only a lenient grammar may hold (docs/design/call-language.md, "The
//! constraint vocabulary").

use alloc::{string::String, vec::Vec};

use crate::{
    Grammar,
    grammar::Rule,
    syntax::{Node, NodeId},
};

/// The smallest integer a constraint may name: the least i64.
pub const INTEGER_MIN: i128 = i64::MIN as i128;
/// The largest integer a constraint may name: the greatest u64.
pub const INTEGER_MAX: i128 = u64::MAX as i128;

/// One constraint. A `String` is a rule name as written; rule names are
/// case-insensitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    /// `exactly R octets`
    ExactlyOctets(String),
    /// `exactly R E elements`
    ExactlyElements(String, String),
    /// `exactly R words`
    ExactlyWords(String),
    /// `header words R`
    HeaderWords(String),
    /// `at most N`
    AtMost(i128),
    /// `at least N`
    AtLeast(i128),
    /// `in N..M`
    In(i128, i128),
    /// `not N`
    Not(i128),
    /// `not one of N, M, ...`: at least two integers.
    NotOneOf(Vec<i128>),
    /// `length at most N`
    LengthAtMost(u64),
    /// `not word W1 W2 ...`
    NotWord(Vec<String>),
    /// `ascending R`
    Ascending(String),
    /// `ascending tags`
    AscendingTags,
    /// `capability index`
    CapabilityIndex,
    /// `canonical float`
    CanonicalFloat,
    /// `remaining octets`
    RemainingOctets,
}

/// Why a constraint's text isn't in the vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintError {
    /// The text matches no form of `grammars/constraint.abnf`.
    Syntax,
    /// An integer outside -2^63 to 2^64 - 1, which the grammar allows but
    /// no core integer can hold.
    OutOfRange,
}

/// Finds a constraint in a comment, given from its `;` to the end of its
/// line. `None`: not a constraint comment (no `constraint:` marker after
/// the `;` and any spaces or tabs). `Some(Err(()))`: a marker with no space
/// after it, which can only be prose. `Some(Ok(text))`: the text after the
/// marker and its spaces, without trailing spaces or tabs.
pub fn constraint_text(comment: &str) -> Option<Result<&str, ()>> {
    let rest = comment.strip_prefix(';')?;
    let rest = rest.trim_start_matches([' ', '\t']);
    let rest = rest.strip_prefix("constraint:")?;
    let text = rest.trim_start_matches(' ');
    if text.len() == rest.len() {
        return Some(Err(()));
    }
    Some(Ok(text.trim_end_matches([' ', '\t'])))
}

/// Parses a constraint's text: what follows `constraint:` and its spaces.
pub fn parse(text: &str) -> Result<Constraint, ConstraintError> {
    use Constraint as C;
    // Words are separated by exactly one space: an empty word means two
    // spaces, or a space at either end.
    let words: Vec<&str> = text.split(' ').collect();
    if words.iter().any(|w| w.is_empty()) {
        return Err(ConstraintError::Syntax);
    }
    let rule = |w: &str| {
        if is_rulename(w) {
            Ok(String::from(w))
        } else {
            Err(ConstraintError::Syntax)
        }
    };
    match words.as_slice() {
        ["exactly", r, "octets"] => Ok(C::ExactlyOctets(rule(r)?)),
        ["exactly", r, e, "elements"] => Ok(C::ExactlyElements(rule(r)?, rule(e)?)),
        ["exactly", r, "words"] => Ok(C::ExactlyWords(rule(r)?)),
        ["header", "words", r] => Ok(C::HeaderWords(rule(r)?)),
        ["at", "most", n] => Ok(C::AtMost(integer(n)?)),
        ["at", "least", n] => Ok(C::AtLeast(integer(n)?)),
        ["in", range] => {
            let (n, m) = range.split_once("..").ok_or(ConstraintError::Syntax)?;
            Ok(C::In(integer(n)?, integer(m)?))
        }
        ["not", "one", "of", list @ ..] => {
            // `integer 1*( "," SP integer )`: every item but the last ends
            // with a comma.
            let (last, init) = list.split_last().ok_or(ConstraintError::Syntax)?;
            if init.is_empty() {
                return Err(ConstraintError::Syntax);
            }
            let mut values = Vec::with_capacity(list.len());
            for item in init {
                let n = item.strip_suffix(',').ok_or(ConstraintError::Syntax)?;
                values.push(integer(n)?);
            }
            values.push(integer(last)?);
            Ok(C::NotOneOf(values))
        }
        ["not", "word", list @ ..] if !list.is_empty() => {
            // `word = 1*( %x21-2B / %x2D-7E )`: printable, no comma.
            if list
                .iter()
                .any(|w| !w.bytes().all(|b| matches!(b, 0x21..=0x2B | 0x2D..=0x7E)))
            {
                return Err(ConstraintError::Syntax);
            }
            Ok(C::NotWord(list.iter().map(|w| String::from(*w)).collect()))
        }
        ["not", n] => Ok(C::Not(integer(n)?)),
        ["length", "at", "most", n] => match integer(n)? {
            _ if n.starts_with('-') => Err(ConstraintError::Syntax),
            v => u64::try_from(v)
                .map(C::LengthAtMost)
                .map_err(|_| ConstraintError::OutOfRange),
        },
        // "ascending tags" is always the tags form (grammars/constraint.abnf).
        ["ascending", "tags"] => Ok(C::AscendingTags),
        ["ascending", r] => Ok(C::Ascending(rule(r)?)),
        ["capability", "index"] => Ok(C::CapabilityIndex),
        ["canonical", "float"] => Ok(C::CanonicalFloat),
        ["remaining", "octets"] => Ok(C::RemainingOctets),
        _ => Err(ConstraintError::Syntax),
    }
}

/// `rulename = ALPHA *(ALPHA / DIGIT / "-")` (RFC 5234).
pub(crate) fn is_rulename(w: &str) -> bool {
    let mut b = w.bytes();
    b.next().is_some_and(|c| c.is_ascii_alphabetic())
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'-')
}

/// `integer = natural / "-" positive`, `natural = "0" / positive`,
/// `positive = %x31-39 *DIGIT`, within -2^63 to 2^64 - 1.
fn integer(w: &str) -> Result<i128, ConstraintError> {
    let (negative, digits) = match w.strip_prefix('-') {
        Some(d) => (true, d),
        None => (false, w),
    };
    let well_formed = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" && !negative || !digits.starts_with('0'));
    if !well_formed {
        return Err(ConstraintError::Syntax);
    }
    // At most 20 digits fit; more are out of range, not malformed.
    let mut v: i128 = 0;
    for b in digits.bytes() {
        v = v
            .checked_mul(10)
            .and_then(|v| v.checked_add(i128::from(b - b'0')))
            .ok_or(ConstraintError::OutOfRange)?;
        if v > INTEGER_MAX + 1 {
            return Err(ConstraintError::OutOfRange);
        }
    }
    let v = if negative { -v } else { v };
    if (INTEGER_MIN..=INTEGER_MAX).contains(&v) {
        Ok(v)
    } else {
        Err(ConstraintError::OutOfRange)
    }
}

// ---- Binding and enforcement ------------------------------------------
//
// Loading compiles each rule's constraints into checks on the rule's own
// match and a target: the repetition (or whole match) that the forms about
// "the next repetition" act on. docs/design/call-language.md, "How
// constraints bind", gives the rules this follows; the matcher enforces
// them.

/// A vocabulary constraint that can't apply where it is written: a load
/// error in any grammar, strict or lenient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Misuse {
    /// A rule name in the constraint that no rule defines.
    Undefined(String),
    /// A rule with no integer reading (signed, decimal, or unsigned of 1 to
    /// 16 octets), named as R or carrying a value form.
    NoReading(String),
    /// A negative bound on a rule that doesn't read as signed.
    Negative,
    /// `in N..M` with N above M.
    EmptyRange,
    /// A form about the next repetition, on a rule whose definition isn't
    /// one concatenation.
    NotOneConcatenation,
    /// `exactly R E elements`, `ascending R` or `ascending tags` on a rule
    /// with no variable repetition to act on.
    NoRepetition,
    /// `exactly R E elements`, but the repetition doesn't repeat rule E.
    WrongElement(String),
    /// `ascending tags`, but an element may be shorter than its 2-octet tag.
    ShortTags,
    /// `canonical float` on a rule that isn't 4 or 8 octets wide.
    NotFloat,
}

impl core::fmt::Display for Misuse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Misuse::Undefined(n) => write!(f, "{n} is not defined"),
            Misuse::NoReading(n) => write!(f, "{n} has no integer reading"),
            Misuse::Negative => f.write_str("a negative bound on a rule that isn't signed"),
            Misuse::EmptyRange => f.write_str("a range whose first value is above its last"),
            Misuse::NotOneConcatenation => {
                f.write_str("the rule's definition isn't one concatenation")
            }
            Misuse::NoRepetition => f.write_str("the rule has no variable repetition to act on"),
            Misuse::WrongElement(e) => write!(f, "the repetition doesn't repeat {e}"),
            Misuse::ShortTags => f.write_str("an element may be shorter than its 2-octet tag"),
            Misuse::NotFloat => f.write_str("the rule isn't 4 or 8 octets wide"),
        }
    }
}

/// An integer as a constraint compares it. The variants are in the
/// integers' order, so the derived order is theirs: every negative value,
/// then every other value that fits 128 bits, then a decimal too large for
/// that, which is greater than every bound and fits no length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Value {
    Negative(i128),
    NonNegative(u128),
    Huge,
}

impl Value {
    fn from_i128(v: i128) -> Value {
        match u128::try_from(v) {
            Ok(u) => Value::NonNegative(u),
            Err(_) => Value::Negative(v),
        }
    }

    /// The value as a count of octets, words or elements. A negative or
    /// huge value, or one beyond any input, counts nothing, so the form
    /// that reads it matches nothing.
    pub(crate) fn count(self) -> Option<u32> {
        match self {
            Value::NonNegative(v) => u32::try_from(v).ok(),
            _ => None,
        }
    }
}

/// How a rule's match reads as an integer, decided when the grammar loads
/// ("How constraints bind", values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reading {
    /// Two's complement: core `i8` to `i64`, or a one-name chain to one.
    Signed,
    /// The decimal number it spells: every octet it can match is a digit.
    Decimal,
    /// Unsigned big-endian: a fixed width of 1 to 16 octets.
    Unsigned,
}

impl Reading {
    /// A rule's reading, if it has one. Every vocabulary form reads
    /// big-endian, so a little-endian grammar writes its constraints as
    /// prose.
    pub(crate) fn of(rule: &Rule) -> Option<Reading> {
        if rule.signed {
            Some(Reading::Signed)
        } else if rule.digit_only {
            Some(Reading::Decimal)
        } else if rule.fixed_width.is_some_and(|w| (1..=16).contains(&w)) {
            Some(Reading::Unsigned)
        } else {
            None
        }
    }

    /// Reads a match. An empty match has no value, and neither has one of
    /// another width than the reading allows (which loading rules out).
    pub(crate) fn read(self, octets: &[u8]) -> Option<Value> {
        if octets.is_empty() {
            return None;
        }
        match self {
            Reading::Signed => {
                if octets.len() > 16 {
                    return None;
                }
                let negative = octets.first().is_some_and(|b| b & 0x80 != 0);
                let start: i128 = if negative { -1 } else { 0 };
                let v = octets
                    .iter()
                    .fold(start, |v, &b| v.wrapping_shl(8) | i128::from(b));
                Some(Value::from_i128(v))
            }
            Reading::Unsigned => {
                if octets.len() > 16 {
                    return None;
                }
                let v = octets
                    .iter()
                    .fold(0u128, |v, &b| v.wrapping_shl(8) | u128::from(b));
                Some(Value::NonNegative(v))
            }
            Reading::Decimal => {
                let mut v: u128 = 0;
                for &b in octets {
                    if !b.is_ascii_digit() {
                        return None;
                    }
                    match v
                        .checked_mul(10)
                        .and_then(|v| v.checked_add(u128::from(b - b'0')))
                    {
                        Some(n) => v = n,
                        None => return Some(Value::Huge),
                    }
                }
                Some(Value::NonNegative(v))
            }
        }
    }
}

/// A check on a rule's own match. Loading sorts and deduplicates a rule's
/// checks, and the lists inside `NotOneOf` and `NotWord`, so that the
/// matcher can search the lists by halves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Check {
    AtMost(Value),
    AtLeast(Value),
    In(Value, Value),
    Not(Value),
    NotOneOf(Vec<Value>),
    LengthAtMost(u64),
    NotWord(Vec<Vec<u8>>),
    CanonicalFloat,
    CapabilityIndex,
}

/// Where a target must end. Each names R by its rule index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Bound {
    /// `exactly R octets`: R octets after the target's start. Also the
    /// message's end for what is inside.
    Octets(u32),
    /// `exactly R words`: 8 × R octets after the target's start. Also the
    /// message's end for what is inside.
    Words(u32),
    /// `header words R`: 8 × R octets after the rule's first octet.
    HeaderWords(u32),
    /// `remaining octets`: at the message's end.
    Remaining,
}

/// What a rule's target forms ask of it, applied together in one run.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    /// The repetition the forms act on, or `None` for the rule's whole
    /// match.
    pub node: Option<NodeId>,
    /// Where the target must end; several must agree.
    pub bounds: Vec<Bound>,
    /// `exactly R E elements`: the R of each, all of which must agree.
    pub elements: Vec<u32>,
    /// `ascending R`: each R.
    pub ascending: Vec<u32>,
    /// `ascending tags`.
    pub tags: bool,
}

/// One rule's compiled constraints.
#[derive(Debug, Clone, Default)]
pub(crate) struct RuleConstraints {
    pub reading: Option<Reading>,
    pub checks: Vec<Check>,
    pub target: Option<Target>,
    /// Whether checking a match reads its octets one by one: to read its
    /// value, or to compare it with `not word` words. The matcher charges
    /// a step for each octet.
    pub reads_span: bool,
}

/// Every rule's compiled constraints, and the rules the matcher must watch.
#[derive(Debug, Default)]
pub(crate) struct Compiled {
    pub rules: Vec<RuleConstraints>,
    /// Rules named as R by some constraint: their matches are recorded as
    /// bindings.
    pub bound: Vec<bool>,
    /// Rules named by some `ascending R`.
    pub watched: Vec<bool>,
    /// Rules whose matches the matcher must see one start at a time: they
    /// carry a constraint, or are bound or watched.
    pub spanned: Vec<bool>,
}

/// A misuse, with the rule index and the constraint's line.
pub(crate) type CompileError = (usize, usize, Misuse);

/// Validates and compiles every rule's constraints.
pub(crate) fn compile(g: &Grammar) -> Result<Compiled, CompileError> {
    let n = g.rules.len();
    let mut out = Compiled {
        rules: Vec::with_capacity(n),
        bound: alloc::vec![false; n],
        watched: alloc::vec![false; n],
        spanned: alloc::vec![false; n],
    };
    for (r, rule) in g.rules.iter().enumerate() {
        let reading = Reading::of(rule);
        let mut rc = RuleConstraints {
            reading,
            ..RuleConstraints::default()
        };
        for (line, c) in &rule.constraints {
            let fail = |m| (r, *line, m);
            // R, by name: a defined rule with an integer reading.
            let named = |name: &str| -> Result<u32, CompileError> {
                let id = g
                    .rule(name)
                    .ok_or_else(|| fail(Misuse::Undefined(name.into())))?;
                if Reading::of(&g.rules[id.index()]).is_none() {
                    return Err(fail(Misuse::NoReading(name.into())));
                }
                Ok(id.0)
            };
            // A value form: the rule reads as an integer, and only a signed
            // one takes negative bounds.
            let value = |bounds: &[i128]| -> Result<Vec<Value>, CompileError> {
                let Some(rd) = reading else {
                    return Err(fail(Misuse::NoReading(rule.name.clone())));
                };
                if rd != Reading::Signed && bounds.iter().any(|&b| b < 0) {
                    return Err(fail(Misuse::Negative));
                }
                Ok(bounds.iter().map(|&b| Value::from_i128(b)).collect())
            };
            let first = |v: Vec<Value>| v.first().copied().unwrap_or(Value::Huge);
            match c {
                Constraint::AtMost(nb) => rc.checks.push(Check::AtMost(first(value(&[*nb])?))),
                Constraint::AtLeast(nb) => {
                    rc.checks.push(Check::AtLeast(first(value(&[*nb])?)));
                }
                Constraint::Not(nb) => rc.checks.push(Check::Not(first(value(&[*nb])?))),
                Constraint::In(lo, hi) => {
                    let v = value(&[*lo, *hi])?;
                    if lo > hi {
                        return Err(fail(Misuse::EmptyRange));
                    }
                    rc.checks.push(Check::In(v[0], v[1]));
                }
                Constraint::NotOneOf(list) => {
                    let mut values = value(list)?;
                    values.sort_unstable();
                    values.dedup();
                    rc.checks.push(Check::NotOneOf(values));
                }
                Constraint::CapabilityIndex => {
                    value(&[])?;
                    rc.checks.push(Check::CapabilityIndex);
                }
                Constraint::LengthAtMost(nb) => rc.checks.push(Check::LengthAtMost(*nb)),
                Constraint::NotWord(words) => {
                    let mut words: Vec<Vec<u8>> =
                        words.iter().map(|w| w.as_bytes().to_vec()).collect();
                    words.sort_unstable();
                    words.dedup();
                    rc.checks.push(Check::NotWord(words));
                }
                Constraint::CanonicalFloat => {
                    if !matches!(rule.fixed_width, Some(4 | 8)) {
                        return Err(fail(Misuse::NotFloat));
                    }
                    rc.checks.push(Check::CanonicalFloat);
                }
                Constraint::ExactlyOctets(name)
                | Constraint::ExactlyWords(name)
                | Constraint::HeaderWords(name)
                | Constraint::ExactlyElements(name, _)
                | Constraint::Ascending(name) => {
                    let rid = named(name)?;
                    out.bound[rid as usize] = true;
                    let t = target(g, r, &mut rc.target).map_err(fail)?;
                    match c {
                        Constraint::ExactlyOctets(_) => t.bounds.push(Bound::Octets(rid)),
                        Constraint::ExactlyWords(_) => t.bounds.push(Bound::Words(rid)),
                        Constraint::HeaderWords(_) => t.bounds.push(Bound::HeaderWords(rid)),
                        Constraint::ExactlyElements(_, e) => {
                            let element = repeated(g, t).map_err(fail)?;
                            let eid = g
                                .rule(e)
                                .ok_or_else(|| fail(Misuse::Undefined(e.clone())))?;
                            if !matches!(g.nodes[element as usize], Node::Ref(x) if x == eid.0) {
                                return Err(fail(Misuse::WrongElement(e.clone())));
                            }
                            t.elements.push(rid);
                        }
                        _ => {
                            repeated(g, t).map_err(fail)?;
                            out.watched[rid as usize] = true;
                            t.ascending.push(rid);
                        }
                    }
                }
                Constraint::AscendingTags => {
                    let t = target(g, r, &mut rc.target).map_err(fail)?;
                    let element = repeated(g, t).map_err(fail)?;
                    if g.node_min[element as usize] < 2 {
                        return Err(fail(Misuse::ShortTags));
                    }
                    t.tags = true;
                }
                Constraint::RemainingOctets => {
                    target(g, r, &mut rc.target)
                        .map_err(fail)?
                        .bounds
                        .push(Bound::Remaining);
                }
            }
        }
        // A constraint written twice, or a check that another implies,
        // is checked once: the matcher's work per state is then bounded
        // by the distinct constraints, which it also charges as steps.
        rc.checks.sort_unstable();
        rc.checks.dedup();
        if let Some(t) = rc.target.as_mut() {
            t.bounds.sort_unstable();
            t.bounds.dedup();
            t.elements.sort_unstable();
            t.elements.dedup();
            t.ascending.sort_unstable();
            t.ascending.dedup();
        }
        out.spanned[r] = !rc.checks.is_empty() || rc.target.is_some();
        out.rules.push(rc);
    }
    for r in 0..n {
        out.spanned[r] |= out.bound[r] || out.watched[r];
        let rc = &mut out.rules[r];
        rc.reads_span =
            rc.reading.is_some() || rc.checks.iter().any(|c| matches!(c, Check::NotWord(_)));
    }
    Ok(out)
}

/// The rule's target, found the first time a form needs it: the first
/// element of its one concatenation with a variable repeat (`*`, `n*`, `*m`
/// or `n*m` with n below m; not a fixed count, not an option), or else its
/// whole match.
fn target<'t>(
    g: &Grammar,
    r: usize,
    slot: &'t mut Option<Target>,
) -> Result<&'t mut Target, Misuse> {
    if slot.is_none() {
        let body = g.rules[r].body;
        let items: &[NodeId] = match &g.nodes[body as usize] {
            Node::Alt(_) => return Err(Misuse::NotOneConcatenation),
            Node::Cat(items) => items,
            _ => core::slice::from_ref(&g.rules[r].body),
        };
        let node = items.iter().copied().find(|&n| {
            matches!(g.nodes[n as usize],
                Node::Rep { min, max, option: false, .. } if max != Some(min))
        });
        *slot = Some(Target {
            node,
            bounds: Vec::new(),
            elements: Vec::new(),
            ascending: Vec::new(),
            tags: false,
        });
    }
    slot.as_mut().ok_or(Misuse::NoRepetition)
}

/// The element a target repeats, for the forms that need a repetition.
fn repeated(g: &Grammar, t: &Target) -> Result<NodeId, Misuse> {
    match t.node.map(|n| &g.nodes[n as usize]) {
        Some(Node::Rep { node, .. }) => Ok(*node),
        _ => Err(Misuse::NoRepetition),
    }
}
