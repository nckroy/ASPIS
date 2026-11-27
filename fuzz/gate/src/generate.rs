// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The structured grammar generator: valid RFC 5234 grammars, and inputs
//! for them (docs/design/call-language.md, "The harness"). The
//! `abnf-generated` target drives it from libFuzzer's bytes, and the ABNF
//! differential (ADR 0068, rule 6) from a seeded [`SplitMix64`], so the
//! loader and matcher are tested on grammars no byte mutation would reach,
//! and the two checkers are compared on them.
//!
//! What it makes is valid by construction:
//!
//! - **No left recursion.** A reference to a later rule may appear
//!   anywhere. A reference to the same or an earlier rule appears only
//!   after an element that consumes at least one octet, in the same
//!   concatenation or an enclosing one; references count as consuming
//!   nothing there. So every call that reads no octet first goes to a
//!   later rule, and there is no cycle of them.
//! - **Every rule is productive.** Each rule's first alternative refers
//!   only to later rules, so by induction from the last rule each one
//!   derives a string. [`Case::shortest`] holds each rule's shortest
//!   derivation, which the sampler falls back to at its depth bound.
//! - **Bounded.** At most [`RULES`] rules, element nesting [`DEPTH`], small
//!   repeat counts, and inputs of at most [`INPUT_MAX`] octets. That keeps
//!   the Python checker's recursion well under its limit, and its
//!   memoized backtracking fast (probed with abnf 2.9.1 in C71: three
//!   nullable repetitions inside a repetition take 50 ms on 40 octets).
//!
//! There are no prose-vals and no constraints: the Python checker reads
//! neither, and the matcher's constraints have their own targets.

use std::fmt::Write as _;

/// A source of choices. `below(n)` is in `0..n`, for `n >= 1`. Choice 0 is
/// always the one that ends soonest, so a source that gives only zeros
/// makes the smallest case.
pub trait Source {
    fn below(&mut self, n: u32) -> u32;
}

/// libFuzzer's bytes as a [`Source`]: one octet a choice (two when `n`
/// is over 256), and 0 once they run out.
pub struct Bytes<'a>(pub &'a [u8]);

impl Source for Bytes<'_> {
    fn below(&mut self, n: u32) -> u32 {
        let take = if n > 256 { 2 } else { 1 };
        let (now, rest) = self.0.split_at(take.min(self.0.len()));
        self.0 = rest;
        let v = now.iter().fold(0u32, |v, &b| (v << 8) | u32::from(b));
        v % n.max(1)
    }
}

/// SplitMix64 (Steele, Lea and Flood, 2014): a small, seeded generator,
/// so a differential case is a seed and an index.
pub struct SplitMix64(pub u64);

impl SplitMix64 {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl Source for SplitMix64 {
    fn below(&mut self, n: u32) -> u32 {
        (self.next_u64() % u64::from(n.max(1))) as u32
    }
}

/// The most rules a case defines.
pub const RULES: u32 = 6;
/// The deepest element nesting.
pub const DEPTH: u32 = 4;
/// The most inputs a case has.
pub const INPUTS: u32 = 16;
/// The longest input.
pub const INPUT_MAX: usize = 64;
/// The deepest chain of rule references the sampler follows before it
/// takes each rule's shortest derivation.
const REF_DEPTH: u32 = 8;

/// RFC 5234's core rules (appendix B.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreRule {
    Alpha,
    Bit,
    Char,
    Cr,
    Crlf,
    Ctl,
    Digit,
    Dquote,
    Hexdig,
    Htab,
    Lf,
    Lwsp,
    Octet,
    Sp,
    Vchar,
    Wsp,
}

impl CoreRule {
    pub const ALL: [CoreRule; 16] = [
        CoreRule::Alpha,
        CoreRule::Bit,
        CoreRule::Char,
        CoreRule::Cr,
        CoreRule::Crlf,
        CoreRule::Ctl,
        CoreRule::Digit,
        CoreRule::Dquote,
        CoreRule::Hexdig,
        CoreRule::Htab,
        CoreRule::Lf,
        CoreRule::Lwsp,
        CoreRule::Octet,
        CoreRule::Sp,
        CoreRule::Vchar,
        CoreRule::Wsp,
    ];

    pub fn name(self) -> &'static str {
        match self {
            CoreRule::Alpha => "ALPHA",
            CoreRule::Bit => "BIT",
            CoreRule::Char => "CHAR",
            CoreRule::Cr => "CR",
            CoreRule::Crlf => "CRLF",
            CoreRule::Ctl => "CTL",
            CoreRule::Digit => "DIGIT",
            CoreRule::Dquote => "DQUOTE",
            CoreRule::Hexdig => "HEXDIG",
            CoreRule::Htab => "HTAB",
            CoreRule::Lf => "LF",
            CoreRule::Lwsp => "LWSP",
            CoreRule::Octet => "OCTET",
            CoreRule::Sp => "SP",
            CoreRule::Vchar => "VCHAR",
            CoreRule::Wsp => "WSP",
        }
    }

    /// The fewest octets a match holds: 0 for LWSP, 2 for CRLF, else 1.
    pub fn min_len(self) -> usize {
        match self {
            CoreRule::Lwsp => 0,
            CoreRule::Crlf => 2,
            _ => 1,
        }
    }

    /// The shortest match.
    fn shortest(self) -> &'static [u8] {
        match self {
            CoreRule::Alpha => b"A",
            CoreRule::Bit | CoreRule::Digit | CoreRule::Hexdig => b"0",
            CoreRule::Char => b"\x01",
            CoreRule::Cr => b"\r",
            CoreRule::Crlf => b"\r\n",
            CoreRule::Ctl | CoreRule::Octet => b"\0",
            CoreRule::Dquote => b"\"",
            CoreRule::Htab => b"\t",
            CoreRule::Lf => b"\n",
            CoreRule::Lwsp => b"",
            CoreRule::Sp | CoreRule::Wsp => b" ",
            CoreRule::Vchar => b"!",
        }
    }

    /// A random match.
    fn sample(self, src: &mut dyn Source, out: &mut Vec<u8>) {
        let pick = |src: &mut dyn Source, set: &[u8]| set[src.below(set.len() as u32) as usize];
        let range =
            |src: &mut dyn Source, lo: u8, hi: u8| lo + src.below(u32::from(hi - lo) + 1) as u8;
        match self {
            CoreRule::Alpha => {
                let c = range(src, b'A', b'Z');
                out.push(if src.below(2) == 0 { c } else { c | 0x20 });
            }
            CoreRule::Bit => out.push(pick(src, b"01")),
            CoreRule::Char => out.push(range(src, 0x01, 0x7f)),
            CoreRule::Cr => out.push(b'\r'),
            CoreRule::Crlf => out.extend_from_slice(b"\r\n"),
            CoreRule::Ctl => out.push(pick(src, b"\0\x01\t\n\r\x1f\x7f")),
            CoreRule::Digit => out.push(range(src, b'0', b'9')),
            CoreRule::Dquote => out.push(b'"'),
            // HEXDIG's letters are quoted strings, so either case matches.
            CoreRule::Hexdig => out.push(pick(src, b"09AFaf")),
            CoreRule::Htab => out.push(b'\t'),
            CoreRule::Lf => out.push(b'\n'),
            CoreRule::Lwsp => {
                for _ in 0..src.below(3) {
                    if src.below(3) == 2 {
                        out.extend_from_slice(b"\r\n");
                    }
                    out.push(pick(src, b" \t"));
                }
            }
            CoreRule::Octet => out.push(src.below(256) as u8),
            CoreRule::Sp => out.push(b' '),
            CoreRule::Vchar => out.push(range(src, 0x21, 0x7e)),
            CoreRule::Wsp => out.push(pick(src, b" \t")),
        }
    }
}

/// How a char-val is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharCase {
    /// `"..."`: case-insensitive.
    Plain,
    /// `%s"..."` (RFC 7405).
    Sensitive,
    /// `%i"..."` (RFC 7405).
    Insensitive,
}

/// A num-val's base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    Bin,
    Dec,
    Hex,
}

/// A num-val's values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NumVal {
    Single(u8),
    Range(u8, u8),
    /// Two or more values joined by `.`.
    Seq(Vec<u8>),
}

/// A repeat prefix (RFC 5234, section 3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repeat {
    /// `*`
    Star,
    /// `n*`
    AtLeast(u32),
    /// `n*m`
    Between(u32, u32),
    /// `n`
    Exactly(u32),
    /// `*m`
    AtMost(u32),
    /// `0*0`, which matches only the empty string.
    Zero,
}

impl Repeat {
    pub fn min(self) -> u32 {
        match self {
            Repeat::Star | Repeat::AtMost(_) | Repeat::Zero => 0,
            Repeat::AtLeast(n) | Repeat::Between(n, _) | Repeat::Exactly(n) => n,
        }
    }

    pub fn max(self) -> Option<u32> {
        match self {
            Repeat::Star | Repeat::AtLeast(_) => None,
            Repeat::Between(_, m) | Repeat::AtMost(m) => Some(m),
            Repeat::Exactly(n) => Some(n),
            Repeat::Zero => Some(0),
        }
    }
}

/// A grammar element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Elem {
    /// Two or more alternatives.
    Alt(Vec<Elem>),
    /// Two or more elements in sequence.
    Cat(Vec<Elem>),
    /// `( ... )`
    Group(Box<Elem>),
    /// `[ ... ]`
    Opt(Box<Elem>),
    Rep(Repeat, Box<Elem>),
    Char {
        text: Vec<u8>,
        case: CharCase,
    },
    Num {
        base: Base,
        val: NumVal,
    },
    Core(CoreRule),
    /// A reference to rule `rule` of the case.
    Ref(usize),
}

impl Elem {
    /// The fewest octets a match holds, counting references as nothing:
    /// a lower bound, which is what the guard against left recursion
    /// needs.
    pub fn min_len(&self) -> usize {
        match self {
            Elem::Alt(c) => c.iter().map(Elem::min_len).min().unwrap_or(0),
            Elem::Cat(c) => c.iter().map(Elem::min_len).sum(),
            Elem::Group(e) => e.min_len(),
            Elem::Opt(_) | Elem::Ref(_) => 0,
            Elem::Rep(r, e) => r.min() as usize * e.min_len(),
            Elem::Char { text, .. } => text.len(),
            Elem::Num { val, .. } => match val {
                NumVal::Seq(v) => v.len(),
                _ => 1,
            },
            Elem::Core(c) => c.min_len(),
        }
    }

    /// Calls `f` on this element and every element inside it.
    pub fn visit(&self, f: &mut dyn FnMut(&Elem)) {
        f(self);
        match self {
            Elem::Alt(c) | Elem::Cat(c) => c.iter().for_each(|e| e.visit(f)),
            Elem::Group(e) | Elem::Opt(e) | Elem::Rep(_, e) => e.visit(f),
            _ => {}
        }
    }
}

/// One rule: its body, and the spelling its definition uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub body: Elem,
}

/// Why an input was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Derived by the sampler: it must match.
    Derived,
    /// A derivation with one octet inserted, deleted, replaced or
    /// flipped in case.
    Mutated,
    /// Random octets over the grammar's alphabet.
    Random,
}

/// One input: the rule it is matched against, its octets, and why it was
/// made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub rule: usize,
    pub octets: Vec<u8>,
    pub origin: Origin,
}

/// A generated grammar, its text and its inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Case {
    pub rules: Vec<Rule>,
    /// The grammar's text, as the loaders read it.
    pub text: Vec<u8>,
    /// Each rule's shortest derivation.
    pub shortest: Vec<Vec<u8>>,
    pub inputs: Vec<Input>,
}

/// The rule name `r<i>`, in a letter case the source picks: rule names
/// are case-insensitive (RFC 5234, section 2.1).
fn spell(src: &mut dyn Source, i: usize) -> String {
    let r = if src.below(4) == 3 { 'R' } else { 'r' };
    format!("{r}{i}")
}

/// What an element may refer to.
#[derive(Clone, Copy)]
struct Scope {
    /// The rule being defined.
    rule: usize,
    rules: usize,
    /// Whether this alternative may refer to the same or an earlier rule.
    back: bool,
    /// Whether an octet has been consumed before this element, in every
    /// way of reaching it.
    guarded: bool,
}

/// Octets char-vals and num-vals draw from: letters of both cases,
/// digits, punctuation, and the octets at the edges of ASCII.
const CHARS: &[u8] = b"aAbBzZ09-. !~";
const VALUES: &[u8] = &[
    0x00, 0x09, 0x0a, 0x0d, 0x20, 0x30, 0x41, 0x5a, 0x61, 0x7a, 0x7f, 0x80, 0xff,
];

fn char_val(src: &mut dyn Source) -> Elem {
    // Mostly one or two octets; sometimes none.
    let len = [1, 1, 2, 3, 0][src.below(5) as usize];
    let text = (0..len)
        .map(|_| CHARS[src.below(CHARS.len() as u32) as usize])
        .collect();
    let case = [CharCase::Plain, CharCase::Sensitive, CharCase::Insensitive][src.below(3) as usize];
    Elem::Char { text, case }
}

fn value(src: &mut dyn Source) -> u8 {
    if src.below(4) == 3 {
        src.below(256) as u8
    } else {
        VALUES[src.below(VALUES.len() as u32) as usize]
    }
}

fn num_val(src: &mut dyn Source) -> Elem {
    let base = [Base::Hex, Base::Dec, Base::Bin][src.below(3) as usize];
    let val = match src.below(3) {
        0 => NumVal::Single(value(src)),
        1 => {
            let (a, b) = (value(src), value(src));
            NumVal::Range(a.min(b), a.max(b))
        }
        _ => NumVal::Seq((0..2 + src.below(2)).map(|_| value(src)).collect()),
    };
    Elem::Num { base, val }
}

/// A reference the scope allows, or a core rule when it allows none.
fn reference(src: &mut dyn Source, s: Scope) -> Elem {
    let lo = if s.back && s.guarded { 0 } else { s.rule + 1 };
    if lo >= s.rules || src.below(4) == 0 {
        return Elem::Core(CoreRule::ALL[src.below(16) as usize]);
    }
    Elem::Ref(lo + src.below((s.rules - lo) as u32) as usize)
}

fn repeat(src: &mut dyn Source) -> Repeat {
    match src.below(7) {
        0 => Repeat::Star,
        1 => Repeat::AtLeast(1),
        2 => Repeat::AtLeast(2),
        3 => {
            let n = src.below(3);
            Repeat::Between(n, n + src.below(4))
        }
        4 => Repeat::Exactly(1 + src.below(3)),
        5 => Repeat::AtMost(1 + src.below(3)),
        _ => Repeat::Zero,
    }
}

fn elem(src: &mut dyn Source, s: Scope, depth: u32) -> Elem {
    let kinds = if depth >= DEPTH { 4 } else { 9 };
    match src.below(kinds) {
        0 => char_val(src),
        1 => num_val(src),
        2 => Elem::Core(CoreRule::ALL[src.below(16) as usize]),
        3 => reference(src, s),
        4 => {
            // In a concatenation, what comes after a consuming element is
            // guarded.
            let n = 2 + src.below(2);
            let mut c: Vec<Elem> = Vec::new();
            for _ in 0..n {
                let consumed: usize = c.iter().map(Elem::min_len).sum();
                let inner = Scope {
                    guarded: s.guarded || consumed >= 1,
                    ..s
                };
                c.push(elem(src, inner, depth + 1));
            }
            Elem::Cat(c)
        }
        5 => Elem::Alt(
            (0..2 + src.below(2))
                .map(|_| elem(src, s, depth + 1))
                .collect(),
        ),
        6 => Elem::Group(Box::new(elem(src, s, depth + 1))),
        7 => Elem::Opt(Box::new(elem(src, s, depth + 1))),
        _ => {
            let r = repeat(src);
            Elem::Rep(r, Box::new(elem(src, s, depth + 1)))
        }
    }
}

/// A rule's body: its first alternative refers only to later rules; the
/// others may refer back, after a consuming element.
fn body(src: &mut dyn Source, rule: usize, rules: usize) -> Elem {
    let scope = |back| Scope {
        rule,
        rules,
        back,
        guarded: false,
    };
    let first = elem(src, scope(false), 1);
    let more = src.below(3);
    if more == 0 {
        return first;
    }
    let mut alts = vec![first];
    alts.extend((0..more).map(|_| elem(src, scope(true), 1)));
    Elem::Alt(alts)
}

// ---- Printing ----------------------------------------------------------

/// Writes a case's text, with the source choosing the layout: spaces or
/// tabs, continuation lines, comments, `=/` splits, LF or CRLF.
struct Printer<'a> {
    src: &'a mut dyn Source,
    out: String,
    nl: &'static str,
}

impl Printer<'_> {
    /// One or more c-wsp between elements: a space, a tab, or a line end
    /// (after an optional comment) followed by a space or tab.
    fn sep(&mut self) {
        match self.src.below(8) {
            0..=3 => self.out.push(' '),
            4 => self.out.push('\t'),
            5 => self.out.push_str("  "),
            6 => {
                self.out.push_str(self.nl);
                self.out.push(' ');
            }
            _ => {
                self.out.push_str(" ; a note");
                self.out.push_str(self.nl);
                self.out.push('\t');
            }
        }
    }

    /// Zero or more c-wsp, inside groups and around `/`.
    fn opt_sep(&mut self) {
        if self.src.below(2) == 1 {
            self.sep();
        }
    }

    fn alt(&mut self, e: &Elem, names: &[String]) {
        match e {
            Elem::Alt(c) => {
                for (i, x) in c.iter().enumerate() {
                    if i > 0 {
                        self.opt_sep();
                        self.out.push('/');
                        self.opt_sep();
                        if !self.out.ends_with([' ', '\t']) {
                            self.out.push(' ');
                        }
                    }
                    self.cat(x, names);
                }
            }
            _ => self.cat(e, names),
        }
    }

    fn cat(&mut self, e: &Elem, names: &[String]) {
        match e {
            Elem::Cat(c) => {
                for (i, x) in c.iter().enumerate() {
                    if i > 0 {
                        self.sep();
                    }
                    self.rep(x, names);
                }
            }
            Elem::Alt(_) => self.group(e, names, '(', ')'),
            _ => self.rep(e, names),
        }
    }

    fn rep(&mut self, e: &Elem, names: &[String]) {
        match e {
            Elem::Rep(r, inner) => {
                match *r {
                    Repeat::Star => self.out.push('*'),
                    Repeat::AtLeast(n) => write!(self.out, "{n}*").unwrap(),
                    Repeat::Between(n, m) => {
                        // `n*m` with n = 0 may drop the 0.
                        if n == 0 && self.src.below(2) == 1 {
                            write!(self.out, "*{m}").unwrap();
                        } else {
                            write!(self.out, "{n}*{m}").unwrap();
                        }
                    }
                    Repeat::Exactly(n) => write!(self.out, "{n}").unwrap(),
                    Repeat::AtMost(m) => write!(self.out, "*{m}").unwrap(),
                    Repeat::Zero => self.out.push_str("0*0"),
                }
                self.atom(inner, names);
            }
            _ => self.atom(e, names),
        }
    }

    fn group(&mut self, e: &Elem, names: &[String], open: char, close: char) {
        self.out.push(open);
        self.opt_sep();
        self.alt(e, names);
        self.opt_sep();
        self.out.push(close);
    }

    fn atom(&mut self, e: &Elem, names: &[String]) {
        match e {
            Elem::Group(inner) => self.group(inner, names, '(', ')'),
            Elem::Opt(inner) => self.group(inner, names, '[', ']'),
            Elem::Alt(_) | Elem::Cat(_) | Elem::Rep(..) => self.group(e, names, '(', ')'),
            Elem::Char { text, case } => {
                match case {
                    CharCase::Plain => {}
                    CharCase::Sensitive => {
                        self.out
                            .push_str(if self.src.below(4) == 3 { "%S" } else { "%s" })
                    }
                    CharCase::Insensitive => {
                        self.out
                            .push_str(if self.src.below(4) == 3 { "%I" } else { "%i" })
                    }
                }
                self.out.push('"');
                self.out.push_str(std::str::from_utf8(text).expect("ASCII"));
                self.out.push('"');
            }
            Elem::Num { base, val } => {
                let upper = self.src.below(4) == 3;
                let (letter, radix) = match base {
                    Base::Bin => ('b', 2),
                    Base::Dec => ('d', 10),
                    Base::Hex => ('x', 16),
                };
                self.out.push('%');
                self.out.push(if upper {
                    letter.to_ascii_uppercase()
                } else {
                    letter
                });
                let digits = |p: &mut Self, v: u8| {
                    let s = match radix {
                        2 => format!("{v:b}"),
                        10 => format!("{v}"),
                        // Hex digits are case-insensitive: mix them.
                        _ if p.src.below(2) == 1 => format!("{v:X}"),
                        _ => format!("{v:x}"),
                    };
                    p.out.push_str(&s);
                };
                match val {
                    NumVal::Single(v) => digits(self, *v),
                    NumVal::Range(a, b) => {
                        digits(self, *a);
                        self.out.push('-');
                        digits(self, *b);
                    }
                    NumVal::Seq(v) => {
                        for (i, x) in v.iter().enumerate() {
                            if i > 0 {
                                self.out.push('.');
                            }
                            digits(self, *x);
                        }
                    }
                }
            }
            Elem::Core(c) => {
                let name = c.name();
                if self.src.below(4) == 3 {
                    self.out.push_str(&name.to_ascii_lowercase());
                } else {
                    self.out.push_str(name);
                }
            }
            Elem::Ref(j) => {
                // References spell names in any case.
                let n = &names[*j];
                if self.src.below(2) == 1 {
                    self.out.push_str(&n.to_ascii_uppercase());
                } else {
                    self.out.push_str(&n.to_ascii_lowercase());
                }
            }
        }
    }

    /// `name = elements` and a line end, with a second `name =/ ...` line
    /// for the last alternatives when the source splits the rule.
    fn rule(
        &mut self,
        i: usize,
        rules: &[Rule],
        names: &[String],
        deferred: &mut Vec<(usize, Vec<Elem>)>,
    ) {
        let r = &rules[i];
        self.out.push_str(&r.name);
        self.opt_sep();
        self.out.push('=');
        if !self.out.ends_with([' ', '\t']) {
            self.out.push(' ');
        }
        match &r.body {
            Elem::Alt(c) if self.src.below(3) == 2 => {
                let k = 1 + self.src.below(c.len() as u32 - 1) as usize;
                let (head, tail) = c.split_at(k);
                match head {
                    [one] => self.alt(one, names),
                    _ => self.alt(&Elem::Alt(head.to_vec()), names),
                }
                deferred.push((i, tail.to_vec()));
            }
            b => self.alt(b, names),
        }
        self.out.push_str(self.nl);
    }

    fn incremental(&mut self, i: usize, tail: &[Elem], rules: &[Rule], names: &[String]) {
        self.out.push_str(&rules[i].name);
        self.out.push_str(" =/ ");
        match tail {
            [one] => self.alt(one, names),
            _ => self.alt(&Elem::Alt(tail.to_vec()), names),
        }
        self.out.push_str(self.nl);
    }
}

fn print(src: &mut dyn Source, rules: &[Rule]) -> Vec<u8> {
    let names: Vec<String> = rules.iter().map(|r| r.name.clone()).collect();
    let nl = if src.below(4) == 3 { "\r\n" } else { "\n" };
    let mut p = Printer {
        src,
        out: String::new(),
        nl,
    };
    if p.src.below(3) == 2 {
        p.out.push_str("; a generated grammar");
        p.out.push_str(nl);
    }
    let mut deferred = Vec::new();
    for i in 0..rules.len() {
        p.rule(i, rules, &names, &mut deferred);
        if p.src.below(4) == 3 {
            p.out.push_str(nl);
        }
    }
    // An incremental alternative follows its rule's definition.
    for (i, tail) in deferred {
        p.incremental(i, &tail, rules, &names);
    }
    p.out.into_bytes()
}

// ---- Derivations -------------------------------------------------------

/// The shortest derivation of `e`, given each rule's shortest so far, or
/// `None` if it refers to a rule that has none yet.
fn shortest_of(e: &Elem, table: &[Option<Vec<u8>>]) -> Option<Vec<u8>> {
    Some(match e {
        Elem::Alt(c) => c
            .iter()
            .filter_map(|x| shortest_of(x, table))
            .min_by_key(Vec::len)?,
        Elem::Cat(c) => {
            let mut out = Vec::new();
            for x in c {
                out.extend(shortest_of(x, table)?);
            }
            out
        }
        Elem::Group(x) => shortest_of(x, table)?,
        Elem::Opt(_) => Vec::new(),
        Elem::Rep(r, x) => match r.min() {
            0 => Vec::new(),
            n => shortest_of(x, table)?.repeat(n as usize),
        },
        Elem::Char { text, .. } => text.clone(),
        Elem::Num { val, .. } => match val {
            NumVal::Single(v) | NumVal::Range(v, _) => vec![*v],
            NumVal::Seq(v) => v.clone(),
        },
        Elem::Core(c) => c.shortest().to_vec(),
        Elem::Ref(j) => table[*j].clone()?,
    })
}

/// Each rule's shortest derivation, as a fixed point. Every rule is
/// productive, so each gets one.
fn shortest(rules: &[Rule]) -> Vec<Option<Vec<u8>>> {
    let mut table: Vec<Option<Vec<u8>>> = vec![None; rules.len()];
    // Each pass can only shorten an entry or fill one in.
    for _ in 0..64 {
        let mut changed = false;
        for (i, r) in rules.iter().enumerate() {
            if let Some(s) = shortest_of(&r.body, &table)
                && table[i].as_ref().is_none_or(|t| s.len() < t.len())
            {
                table[i] = Some(s);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    table
}

/// The most elements one derivation visits. Elements that derive nothing
/// (an empty option, `LWSP`, `0*0`) don't grow the output, so the length
/// bound alone wouldn't bound the work.
const SAMPLE_WORK: u32 = 4096;

/// The sampler: a random derivation of `e`, or `None` when it would be
/// longer than [`INPUT_MAX`] or take more than [`SAMPLE_WORK`].
struct Sampler<'a> {
    rules: &'a [Rule],
    shortest: &'a [Vec<u8>],
    work: std::cell::Cell<u32>,
}

impl Sampler<'_> {
    fn derive(&self, src: &mut dyn Source, e: &Elem, refs: u32, out: &mut Vec<u8>) -> Option<()> {
        self.work.set(self.work.get() + 1);
        if self.work.get() > SAMPLE_WORK {
            return None;
        }
        match e {
            Elem::Alt(c) => {
                let i = src.below(c.len() as u32) as usize;
                self.derive(src, &c[i], refs, out)?;
            }
            Elem::Cat(c) => {
                for x in c {
                    self.derive(src, x, refs, out)?;
                }
            }
            Elem::Group(x) => self.derive(src, x, refs, out)?,
            Elem::Opt(x) => {
                if src.below(2) == 1 {
                    self.derive(src, x, refs, out)?;
                }
            }
            Elem::Rep(r, x) => {
                let extra = match r.max() {
                    Some(m) => src.below(m - r.min() + 1).min(3),
                    None => src.below(3),
                };
                for _ in 0..r.min() + extra {
                    self.derive(src, x, refs, out)?;
                }
            }
            Elem::Char { text, case } => {
                for &b in text {
                    let flip = *case != CharCase::Sensitive
                        && b.is_ascii_alphabetic()
                        && src.below(2) == 1;
                    out.push(if flip { b ^ 0x20 } else { b });
                }
            }
            Elem::Num { val, .. } => match val {
                NumVal::Single(v) => out.push(*v),
                NumVal::Range(a, b) => out.push(*a + src.below(u32::from(b - a) + 1) as u8),
                NumVal::Seq(v) => out.extend_from_slice(v),
            },
            Elem::Core(c) => c.sample(src, out),
            Elem::Ref(j) => {
                if refs >= REF_DEPTH {
                    out.extend_from_slice(&self.shortest[*j]);
                } else {
                    self.derive(src, &self.rules[*j].body, refs + 1, out)?;
                }
            }
        }
        (out.len() <= INPUT_MAX).then_some(())
    }
}

/// The octets inputs draw from: every octet the grammar names, the other
/// letter case of each letter, and the edges of ASCII.
fn alphabet(rules: &[Rule]) -> Vec<u8> {
    let mut a: Vec<u8> = vec![
        0x00, 0x7f, 0x80, 0xff, b' ', b'\t', b'\r', b'\n', b'A', b'0',
    ];
    for r in rules {
        r.body.visit(&mut |e| match e {
            Elem::Char { text, .. } => {
                for &b in text {
                    a.push(b);
                    if b.is_ascii_alphabetic() {
                        a.push(b ^ 0x20);
                    }
                }
            }
            Elem::Num { val, .. } => match val {
                NumVal::Single(v) => a.push(*v),
                NumVal::Range(x, y) => a.extend([*x, *y, x.saturating_sub(1), y.saturating_add(1)]),
                NumVal::Seq(v) => a.extend_from_slice(v),
            },
            _ => {}
        });
    }
    a.sort_unstable();
    a.dedup();
    a
}

fn mutate(src: &mut dyn Source, alphabet: &[u8], s: &mut Vec<u8>) {
    let any = |src: &mut dyn Source| alphabet[src.below(alphabet.len() as u32) as usize];
    let at = src.below(s.len() as u32 + 1) as usize;
    match src.below(4) {
        0 if s.len() < INPUT_MAX => {
            let b = any(src);
            s.insert(at, b);
        }
        1 if at < s.len() => {
            s.remove(at);
        }
        2 if at < s.len() => s[at] = any(src),
        _ => {
            if let Some(b) = s.iter_mut().find(|b| b.is_ascii_alphabetic()) {
                *b ^= 0x20;
            } else if s.len() < INPUT_MAX {
                let b = any(src);
                s.insert(at, b);
            }
        }
    }
}

/// Generates one case from `src`.
pub fn case(src: &mut dyn Source) -> Case {
    let n = 1 + src.below(RULES) as usize;
    let rules: Vec<Rule> = (0..n)
        .map(|i| Rule {
            name: spell(src, i),
            body: body(src, i, n),
        })
        .collect();
    let text = print(src, &rules);
    let shortest: Vec<Vec<u8>> = shortest(&rules)
        .into_iter()
        .enumerate()
        .map(|(i, s)| {
            s.unwrap_or_else(|| {
                panic!("rule {i} derives nothing: the generator's productivity guarantee broke")
            })
        })
        .collect();
    let sampler = Sampler {
        rules: &rules,
        shortest: &shortest,
        work: std::cell::Cell::new(0),
    };
    let alphabet = alphabet(&rules);
    let mut inputs = Vec::new();
    for _ in 0..src.below(INPUTS + 1) {
        let rule = src.below(n as u32) as usize;
        let origin = match src.below(10) {
            0..=4 => Origin::Derived,
            5..=7 => Origin::Mutated,
            _ => Origin::Random,
        };
        let octets = match origin {
            Origin::Random => (0..src.below(17))
                .map(|_| alphabet[src.below(alphabet.len() as u32) as usize])
                .collect(),
            _ => {
                let mut out = Vec::new();
                sampler.work.set(0);
                if sampler
                    .derive(src, &rules[rule].body, 0, &mut out)
                    .is_none()
                {
                    continue;
                }
                if origin == Origin::Mutated {
                    mutate(src, &alphabet, &mut out);
                }
                out
            }
        };
        inputs.push(Input {
            rule,
            octets,
            origin,
        });
    }
    Case {
        rules,
        text,
        shortest,
        inputs,
    }
}

/// The case the differential makes for `seed` and `index`.
pub fn seeded(seed: u64, index: u64) -> Case {
    let mut src = SplitMix64(seed ^ index.wrapping_mul(0xd1b5_4a32_d192_ed03));
    case(&mut src)
}

/// Every literal the case's text writes: each non-empty char-val, and each
/// num-val concatenation. [`abnf::Grammar::literals`] must give each one.
pub fn literals(c: &Case) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for r in &c.rules {
        r.body.visit(&mut |e| match e {
            Elem::Char { text, .. } if !text.is_empty() => out.push(text.clone()),
            Elem::Num {
                val: NumVal::Seq(v),
                ..
            } => out.push(v.clone()),
            _ => {}
        });
    }
    out
}

/// A vector body, escaped as vector files write it: `\t`, `\\`, `\"` and
/// `\xHH`, with other printable ASCII as itself.
pub fn escape(octets: &[u8]) -> String {
    let mut s = String::new();
    for &b in octets {
        match b {
            b'\t' => s.push_str("\\t"),
            b'\\' => s.push_str("\\\\"),
            b'"' => s.push_str("\\\""),
            0x20..=0x7e => s.push(b as char),
            _ => write!(s, "\\x{b:02x}").unwrap(),
        }
    }
    s
}

/// The case's vector file, with each input tagged `ok` or `err` by
/// `verdicts` (`None` drops the input: it had no verdict).
pub fn vectors_text(c: &Case, verdicts: &[Option<bool>]) -> String {
    let mut s = format!("# rule: {}\n", c.rules[0].name);
    for (input, v) in c.inputs.iter().zip(verdicts) {
        let Some(ok) = v else { continue };
        let tag = if *ok { "ok" } else { "err" };
        if input.rule == 0 {
            writeln!(s, "{tag}\t{}", escape(&input.octets)).unwrap();
        } else {
            writeln!(
                s,
                "{tag}@{}\t{}",
                c.rules[input.rule].name,
                escape(&input.octets)
            )
            .unwrap();
        }
    }
    s
}
