// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The scanner under the parser: a cursor over the source's octets, with
//! `grammars/idl.abnf`'s whitespace, comments and doc comments.
//!
//! The parser works on octets, not on a token stream, because the grammar
//! is whitespace-sensitive in a few places (`w` after keywords, none
//! inside a dotted name or `version-lit`). Every scan here is linear and
//! iterative.

use alloc::string::String;

use crate::diag::{Code, Diagnostic, Span};

/// The length of the UTF-8 character at the start of `s`, as RFC 3629
/// defines it and `core.abnf` writes it out: no overlong forms, no
/// surrogates, nothing above U+10FFFF. ASCII, NUL included, is one octet.
pub fn utf8_len(s: &[u8]) -> Option<usize> {
    let tail = |i: usize| s.get(i).is_some_and(|b| (0x80..=0xBF).contains(b));
    let in_range = |i: usize, lo: u8, hi: u8| s.get(i).is_some_and(|b| (lo..=hi).contains(b));
    match *s.first()? {
        0x00..=0x7F => Some(1),
        0xC2..=0xDF if tail(1) => Some(2),
        0xE0 if in_range(1, 0xA0, 0xBF) && tail(2) => Some(3),
        0xE1..=0xEC | 0xEE..=0xEF if tail(1) && tail(2) => Some(3),
        0xED if in_range(1, 0x80, 0x9F) && tail(2) => Some(3),
        0xF0 if in_range(1, 0x90, 0xBF) && tail(2) && tail(3) => Some(4),
        0xF1..=0xF3 if tail(1) && tail(2) && tail(3) => Some(4),
        0xF4 if in_range(1, 0x80, 0x8F) && tail(2) && tail(3) => Some(4),
        _ => None,
    }
}

/// A position in the source.
pub struct Cursor<'a> {
    pub src: &'a [u8],
    pub pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(src: &'a [u8]) -> Cursor<'a> {
        Cursor { src, pos: 0 }
    }

    pub fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    pub fn peek_at(&self, k: usize) -> Option<u8> {
        self.src.get(self.pos + k).copied()
    }

    pub fn at_eof(&self) -> bool {
        self.pos >= self.src.len()
    }

    pub fn at(&self, lit: &[u8]) -> bool {
        self.src[self.pos.min(self.src.len())..].starts_with(lit)
    }

    pub fn eat(&mut self, b: u8) -> bool {
        if self.peek() == Some(b) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    pub fn eat_lit(&mut self, lit: &[u8]) -> bool {
        if self.at(lit) {
            self.pos += lit.len();
            true
        } else {
            false
        }
    }

    /// An error at the cursor.
    pub fn error(&self, message: impl Into<String>) -> Diagnostic {
        Diagnostic::new(Span::new(self.pos, self.pos), Code::Syntax, message)
    }

    /// The run of `[a-z0-9_]` at the cursor, without moving. The grammar's
    /// names, keywords and type words are all made of these octets.
    pub fn peek_word(&self) -> &'a str {
        let rest = &self.src[self.pos.min(self.src.len())..];
        let n = rest
            .iter()
            .take_while(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || **b == b'_')
            .count();
        // ASCII, so always UTF-8.
        core::str::from_utf8(&rest[..n]).unwrap_or("")
    }

    /// The run of `[a-z0-9_]` at the cursor.
    pub fn word(&mut self) -> &'a str {
        let w = self.peek_word();
        self.pos += w.len();
        w
    }

    /// The octet just after the word at the cursor.
    pub fn after_word(&self) -> Option<u8> {
        self.peek_at(self.peek_word().len())
    }

    /// Whether the cursor is at a doc comment: `///` for an item, `//!`
    /// for the file.
    pub fn at_doc(&self, file: bool) -> bool {
        self.at(if file { b"//!" } else { b"///" })
    }

    /// `s`: whitespace (`WSP / CR / LF`) and plain comments. Returns
    /// whether it took anything, which is what `w` needs. It stops before a
    /// doc comment, which is never whitespace.
    pub fn trivia(&mut self) -> Result<bool, Diagnostic> {
        let start = self.pos;
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => self.pos += 1,
                Some(b'/')
                    if self.peek_at(1) == Some(b'/')
                        && !matches!(self.peek_at(2), Some(b'/' | b'!')) =>
                {
                    self.comment()?
                }
                _ => return Ok(self.pos > start),
            }
        }
    }

    /// `comment = "//" [ comment-start *doc-char ] LF`, at "//" not
    /// followed by "/" or "!".
    fn comment(&mut self) -> Result<(), Diagnostic> {
        self.pos += 2;
        self.line_rest("a comment")?;
        Ok(())
    }

    /// `*doc-char LF`: every UTF-8 character up to the line feed, which it
    /// takes. Returns the text before the line feed.
    fn line_rest(&mut self, what: &str) -> Result<&'a [u8], Diagnostic> {
        let start = self.pos;
        loop {
            match self.peek() {
                None => {
                    return Err(self.error(alloc::format!("{what} must end with a line feed")));
                }
                Some(b'\n') => {
                    self.pos += 1;
                    return Ok(&self.src[start..self.pos - 1]);
                }
                Some(0) => return Err(self.error(alloc::format!("a NUL octet in {what}"))),
                Some(_) => match utf8_len(&self.src[self.pos..]) {
                    Some(n) => self.pos += n,
                    None => return Err(self.error(alloc::format!("{what} isn't UTF-8"))),
                },
            }
        }
    }

    /// One doc line, at `///` or `//!`: the text after the marker, without
    /// the line feed.
    pub fn doc_line(&mut self) -> Result<String, Diagnostic> {
        self.pos += 3;
        let text = self.line_rest("a doc comment")?;
        // line_rest took only whole UTF-8 characters.
        Ok(String::from(core::str::from_utf8(text).unwrap_or("")))
    }
}
