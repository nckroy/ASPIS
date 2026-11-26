// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! What the conformance runner drives (ADR 0013, rule 3; ADR 0067, rule 9;
//! docs/design/call-language.md, "Back ends").
//!
//! A [`Subject`] is a binding of one interface major: it decodes a message
//! as one of the generated grammars' rules, at a minor, and re-encodes it
//! or writes its JSON. crates/idl's `conformance` module checks a subject
//! against the interface's grammars and vectors, and against crates/idl's
//! dynamic codec. Every generated Rust module is a subject through its
//! `MODULE`, a [`Module`]; a binding in another language, or a hand-written
//! decoder, can implement the trait itself.

use crate::rules::{Module, Op, Verdict};

/// A binding of one interface major, by grammar rule name.
pub trait Subject {
    /// The interface's name, such as `aspis.catalog`.
    fn name(&self) -> &str;
    fn major(&self) -> u16;
    /// The newest minor the binding knows. It reads every earlier one too.
    fn minor(&self) -> u16;
    /// Decodes `input` as `rule` at `minor`, with `caps` capabilities in
    /// the message's list, then re-encodes it or writes its JSON.
    fn run(&self, rule: &str, minor: u16, caps: u8, input: &[u8], op: Op<'_, '_>) -> Verdict;
}

impl Subject for Module {
    fn name(&self) -> &str {
        self.name
    }

    fn major(&self) -> u16 {
        self.major
    }

    fn minor(&self) -> u16 {
        self.minor
    }

    fn run(&self, rule: &str, minor: u16, caps: u8, input: &[u8], op: Op<'_, '_>) -> Verdict {
        (self.rule)(rule, minor, caps, input, op)
    }
}
