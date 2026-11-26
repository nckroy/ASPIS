// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The ABNF checker for ASPIS grammars (ADR 0062, rule 8; ADR 0013,
//! rule 6).
//!
//! It parses RFC 5234 ABNF, as RFC 7405 updates it, in the binary-octet
//! encoding: one terminal value is one octet. It matches test vectors
//! against a grammar, and it reads the constraint vocabulary
//! ([`constraint`]). It is the Rust half of a differential pair with
//! `tools/ci/check-grammars.py` (ADR 0068, rule 6).
//!
//! The catalog runs it on publishers' grammars (ADR 0027, rule 2), so it
//! bounds everything it does ([`Limits`]): the size and nesting of a grammar
//! when it loads, the input, steps, memory and recursion depth of each
//! match, and the steps of a whole vector file. A match over a budget ends
//! with [`Exhausted`], never with an answer. Nothing here panics on any input, and nothing reads files: a
//! grammar's `; uses:` names reach the caller's resolver.
//!
//! The design is recorded in docs/design/call-language.md, at L22 ("The
//! constraint vocabulary's grammar and the Rust checker"), and in "How
//! constraints bind".
//!
//! [`dict`] writes a grammar's libFuzzer dictionary.
//!
//! [`Grammar::matches`] reads a grammar as context-free, as the Python
//! checker does. [`Grammar::matches_constrained`] also enforces every
//! vocabulary constraint, and [`vectors::check`] judges a vector file with
//! both.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod constraint;
pub mod dict;
mod grammar;
mod matcher;
mod syntax;
pub mod vectors;

use alloc::string::String;
use core::fmt;

pub use grammar::{Grammar, RuleId};

/// What a constrained match is checked against: the values a vector line
/// can't carry in its octets (docs/design/call-language.md, "Vector
/// files"; ADR 0062, rule 8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Context {
    /// The message's capability count, from `# caps:`: 0 to 3 on the wire
    /// ("Capability indexes"). The checker reads indexes 0 to 7, so a
    /// count above 8 allows no more than 8.
    pub caps: u8,
    /// The unwrapped mask, from `# unwrapped:`. A position delivered
    /// unwrapped still has its index, so the mask never changes a verdict;
    /// it is carried for generated bindings' conformance tests.
    pub unwrapped: u8,
}

/// The budgets that bound loading and matching. The defaults suit the
/// repository's grammars and the catalog's checks of publishers' vectors;
/// L22 in docs/design/call-language.md gives the arithmetic behind them.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Octets of grammar text, the main file and every file it uses.
    pub grammar_octets: usize,
    /// Rules defined, across every file (RFC 5234's own rules excluded).
    pub rules: usize,
    /// Grammar elements, across every file.
    pub nodes: usize,
    /// Groups and options nested inside one another.
    pub nesting: usize,
    /// `; uses:` chains: a file that uses a file that uses ... this deep.
    pub uses_depth: usize,
    /// Octets of one input. A vector is one line of text; checking whole
    /// messages is the generated decoders' job.
    pub input_octets: usize,
    /// Steps any match may take, whatever its length.
    pub steps_base: u64,
    /// Further steps for each octet of input.
    pub steps_per_octet: u64,
    /// The most steps any match may take. A linear grammar takes some 20
    /// steps an octet; 100 M steps is a few seconds.
    pub steps_max: u64,
    /// The most steps [`vectors::check`] takes over one vector file, every
    /// match together. It stops at the first vector over any budget, so a
    /// file costs no more than this whatever its length.
    pub file_steps: u64,
    /// Octets of match state held at once.
    pub memory: usize,
    /// Nested matcher calls: grammar nesting, repetitions and rule calls
    /// together, each one level. The default needs about 560 KiB of stack
    /// built at opt-level 1 (the workspace's dev and test profile) or "s"
    /// (release), and about 1.5 MiB at opt-level 0, whatever mix of
    /// groups, repetitions, calls and constraints it nests (measured; the
    /// tests run it on 1 MiB). Scale it to the stack the checker runs on.
    pub depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            grammar_octets: 1 << 20,
            rules: 16_384,
            nodes: 262_144,
            nesting: 64,
            uses_depth: 8,
            input_octets: 64 << 10,
            steps_base: 1_000_000,
            steps_per_octet: 10_000,
            steps_max: 100_000_000,
            file_steps: 500_000_000,
            memory: 64 << 20,
            depth: 768,
        }
    }
}

/// What the text being loaded is, which decides its strictness and the
/// reserved names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `grammars/core.abnf` itself. Its rule names are the reserved names,
    /// and it is strict. Only the repository's own tooling says this.
    Core,
    /// A hand-written grammar: strict if it uses `core`, directly or
    /// through another grammar, and lenient otherwise.
    Auto,
    /// Always strict, as the catalog loads every publisher's grammar.
    Strict,
}

/// How to load a grammar.
#[derive(Debug, Clone)]
pub struct LoadOptions {
    pub limits: Limits,
    pub kind: Kind,
}

impl Default for LoadOptions {
    fn default() -> Self {
        LoadOptions {
            limits: Limits::default(),
            kind: Kind::Auto,
        }
    }
}

/// A grammar that doesn't load: the file it is in (a grammar name, as
/// `; uses:` gives it), the line, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrammarError {
    pub file: String,
    pub line: usize,
    pub kind: GrammarErrorKind,
}

/// Why a grammar doesn't load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrammarErrorKind {
    /// Not RFC 5234 ABNF.
    Syntax,
    /// An octet that isn't ASCII text, or a CR not before LF.
    NotAscii,
    /// A num-val above 255: one terminal value is one octet (ADR 0062,
    /// rule 1).
    OctetValue,
    /// A num-val range whose first value is above its last.
    EmptyRange,
    /// A repeat count above 2^32 - 1, or `n*m` with n above m.
    RepeatRange,
    /// A rule defined twice with `=`, in any letter case, or a redefinition
    /// of an RFC 5234 core rule or of a rule from a used grammar.
    Duplicate(String),
    /// `=/` on a rule this file hasn't defined.
    IncrementalUndefined(String),
    /// A rule name that nothing defines.
    Undefined(String),
    /// A rule that can call itself before it reads an octet.
    LeftRecursive(String),
    /// A definition of a core rule name, in any letter case (ADR 0062,
    /// rule 3).
    Reserved(String),
    /// A malformed or misplaced `; uses:` line, a cycle, a grammar the
    /// resolver doesn't have, or a chain deeper than the limit.
    Uses(String),
    /// A constraint comment outside every rule.
    Attachment,
    /// Constraint text outside the vocabulary, in a strict grammar.
    Prose,
    /// A prose-val, `<...>`, in a strict grammar.
    ProseVal,
    /// Over a size limit: grammar octets, rules or nodes.
    TooLarge,
    /// Groups and options nested deeper than the limit.
    TooDeep,
    /// A vocabulary constraint that can't apply where it is written
    /// (docs/design/call-language.md, "How constraints bind").
    Constraint(constraint::Misuse),
}

impl fmt::Display for GrammarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.kind)
    }
}

impl fmt::Display for GrammarErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use GrammarErrorKind as K;
        match self {
            K::Syntax => f.write_str("not RFC 5234 ABNF"),
            K::NotAscii => f.write_str("not ASCII text (or a CR not before LF)"),
            K::OctetValue => f.write_str("a terminal value is one octet (ADR 0062, rule 1)"),
            K::EmptyRange => f.write_str("a range whose first value is above its last"),
            K::RepeatRange => f.write_str("a repeat count out of range"),
            K::Duplicate(n) => write!(f, "{n} is already defined"),
            K::IncrementalUndefined(n) => write!(f, "'=/' on {n}, which this file hasn't defined"),
            K::Undefined(n) => write!(f, "{n} is not defined"),
            K::LeftRecursive(n) => write!(f, "{n} is left-recursive"),
            K::Reserved(n) => write!(f, "defines core rule name {n} (ADR 0062, rule 3)"),
            K::Uses(m) => write!(f, "uses: {m}"),
            K::Attachment => f.write_str("a constraint comment outside every rule"),
            K::Prose => f.write_str("a constraint outside the vocabulary, in a strict grammar"),
            K::ProseVal => f.write_str("a prose-val in a strict grammar"),
            K::TooLarge => f.write_str("over the grammar size limit"),
            K::TooDeep => f.write_str("groups and options nested too deep"),
            K::Constraint(m) => write!(f, "constraint: {m}"),
        }
    }
}

/// A match that ran out of a budget. It is never a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exhausted {
    /// The input is longer than [`Limits::input_octets`].
    Input,
    /// Over the steps budget.
    Steps,
    /// Over [`Limits::memory`].
    Memory,
    /// Over [`Limits::depth`].
    Depth,
}

impl fmt::Display for Exhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Exhausted::Input => "the input is over the size limit",
            Exhausted::Steps => "the match ran out of steps",
            Exhausted::Memory => "the match ran out of memory",
            Exhausted::Depth => "the match nested too deep",
        })
    }
}
