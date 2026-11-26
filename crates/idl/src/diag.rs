// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Diagnostics: what is wrong, and where. The front end collects them and
//! never panics on any input (ADR 0068, rule 5).

use alloc::string::String;
use core::fmt;

/// A byte range of the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Span {
        Span {
            start: start as u32,
            end: end as u32,
        }
    }
}

/// What kind of problem a diagnostic reports. Tests match on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Code {
    /// The source doesn't match `grammars/idl.abnf` with its constraints.
    Syntax,
    /// Over one of the front end's [`crate::Limits`].
    Limit,
    /// The interface header: `id`, `object_id`, `version`, the label.
    Header,
    /// A name declared twice, or two names whose generated Rust names
    /// collide.
    Duplicate,
    /// A method number, arm, value, code or constant out of range.
    Number,
    /// An attribute that is unknown, misplaced, repeated or malformed.
    Attribute,
    /// `since` or `deprecated` that breaks the minor-version rules.
    Since,
    /// A name that resolves to nothing, or to the wrong kind of thing.
    Reference,
    /// A type that breaks a rule of "Types" or "Open and closed types".
    Type,
    /// A capability or slot in the wrong place, or too many.
    Capability,
    /// A worst-case size over a limit.
    Size,
    /// A stream method that breaks "Server streams in the IDL".
    Stream,
    /// An action group that isn't declared, or is never used.
    Group,
    /// An `error(...)` list naming what isn't the interface's error.
    ErrorList,
    /// A `use` line whose interface can't be loaded or checked.
    Import,
    /// A doc comment's cross-reference that names nothing in its own
    /// interface or an import.
    Doc,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::Syntax => "syntax",
            Code::Limit => "limit",
            Code::Header => "header",
            Code::Duplicate => "duplicate",
            Code::Number => "number",
            Code::Attribute => "attribute",
            Code::Since => "since",
            Code::Reference => "reference",
            Code::Type => "type",
            Code::Capability => "capability",
            Code::Size => "size",
            Code::Stream => "stream",
            Code::Group => "group",
            Code::ErrorList => "error-list",
            Code::Import => "import",
            Code::Doc => "doc",
        }
    }
}

/// One problem in a source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub span: Span,
    pub code: Code,
    pub message: String,
}

impl Diagnostic {
    pub fn new(span: Span, code: Code, message: impl Into<String>) -> Diagnostic {
        Diagnostic {
            span,
            code,
            message: message.into(),
        }
    }

    /// The 1-based line and column (in octets) where it starts.
    pub fn line_col(&self, src: &[u8]) -> (usize, usize) {
        line_col(src, self.span.start as usize)
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

/// The 1-based line and column (in octets) of a byte offset.
pub fn line_col(src: &[u8], offset: usize) -> (usize, usize) {
    let before = &src[..offset.min(src.len())];
    let line = before.iter().filter(|&&b| b == b'\n').count() + 1;
    let col = before.len()
        - before
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1)
        + 1;
    (line, col)
}
