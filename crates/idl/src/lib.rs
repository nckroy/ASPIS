// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The ASPIS IDL compiler's front end (ADR 0067, rule 11).
//!
//! It is `no_std` with `alloc`, forbids `unsafe`, and does no I/O, so the
//! catalog can run the same checks as CI on publishers' interfaces (ADR
//! 0027, rule 2). Its passes:
//!
//! - [`parse`]: the hand-written parser, which accepts exactly what
//!   `grammars/idl.abnf` accepts ([`ast`]);
//! - [`model`]: resolves names and `use` imports, through a resolver the
//!   caller gives, and runs the checker's rules ([`check`]);
//! - [`layout`]: positions, encodings, worst-case sizes, capability
//!   counts and locality;
//! - [`project`], [`canon`] and [`hash`]: a minor's canonical form and its
//!   SHA3-256 hash, which the lock records;
//! - [`compat`]: the step check between two minors;
//! - [`schema`] and [`value`]: a file read at one minor, and the dynamic
//!   value model with its interpretive codec and JSON (L33);
//! - [`abnf_gen`], [`vectors`] and [`generate`]: each minor's wire and
//!   canonical-text grammars and their vectors, labeled with crates/abnf;
//! - [`lock`]: the lock file;
//! - [`rust`]: the Rust `no_std` back end: types, codecs, client stubs,
//!   server dispatchers and metadata, generated as text;
//! - [`doc`]: the doc model, and the checker's rule for cross-references;
//! - [`conformance`]: the conformance runner, which checks a generated
//!   binding against its grammars and vectors;
//! - [`fuzz`]: entry functions for fuzz targets, and a structured value
//!   generator (ADR 0068).
//!
//! Every pass is bounded ([`Limits`]) and collects [`Diagnostic`]s rather
//! than panicking. The design, and every choice C07 made, is in
//! docs/design/call-language.md ("The IDL").

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod abnf_gen;
pub mod ast;
pub mod canon;
pub mod check;
pub mod compat;
pub mod conformance;
pub mod diag;
pub mod doc;
pub mod fuzz;
pub mod generate;
pub mod hash;
pub mod ids;
pub mod layout;
mod lex;
pub mod lock;
pub mod model;
pub mod parse;
pub mod project;
pub mod rust;
pub mod schema;
pub mod value;
pub mod vectors;

pub use diag::{Code, Diagnostic, Span};
pub use model::{Checked, check};

/// The front end's budgets. The defaults are the ones
/// docs/design/call-language.md gives ("Types", "Limits"); the catalog
/// runs with them on publishers' files.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Octets of one source file.
    pub source: usize,
    /// Types nested inside one another: `seq<seq<...>>` (ADR 0068, rule
    /// 5's explicit depth limit).
    pub nesting: usize,
    /// Members of one interface.
    pub members: usize,
    /// Items in one list: fields, parameters, arms or values.
    pub fields: usize,
    /// `use` lines in one file.
    pub uses: usize,
    /// Attributes on one item, and arguments of one attribute.
    pub attrs: usize,
    /// Imports of imports, this deep.
    pub import_depth: usize,
    /// Interfaces loaded through `use`, in all.
    pub imports: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            source: 1 << 20,
            nesting: 32,
            members: 4096,
            fields: 4096,
            uses: 16,
            attrs: 64,
            import_depth: 8,
            imports: 64,
        }
    }
}
