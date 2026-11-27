// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel-argument parser (ADR 0041, rule 5).
//!
//! The grammar is `grammars/kernel-args.abnf`, copied from the record:
//!
//! ```text
//! kernel-args = *SP [ arg *( 1*SP arg ) *SP ]
//! arg         = key [ "=" value ]
//! key         = segment *( "." segment )
//! segment     = lower *( lower / DIGIT / "-" )
//! lower       = %x61-7A
//! value       = bare / quoted
//! bare        = 1*bare-char
//! bare-char   = %x21 / %x23-7E
//! quoted      = DQUOTE *( q-char / escape ) DQUOTE
//! q-char      = %x20-21 / %x23-5B / %x5D-7E
//! escape      = "\" ( DQUOTE / "\" )
//! ```
//!
//! The line is at most [`MAX_LEN`] bytes. A longer line is rejected whole:
//! [`parse`] yields [`ErrorKind::TooLong`] first and nothing else, so the
//! kernel uses no arguments from it.
//!
//! Otherwise [`parse`] yields the arguments in order. At the first error it
//! yields that error once and stops, so the kernel uses only the arguments
//! before the error, as the record requires.
//!
//! The parser takes the line exactly as given. A caller holding a
//! NUL-terminated string strips the terminator first.
//!
//! The crate is `no_std`, allocates nothing and never panics on its input.

#![no_std]
// It parses the boot command line, so it is fuzzed with no sanitizer
// (ADR 0068, rule 2).
#![forbid(unsafe_code)]
#![deny(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable
)]

use core::fmt;
use core::iter::FusedIterator;

/// The longest command line accepted, in bytes (ADR 0041, rule 5).
pub const MAX_LEN: usize = 4096;

const SP: u8 = b' ';
const DQUOTE: u8 = b'"';
const BACKSLASH: u8 = b'\\';

/// One kernel argument: a key and, if it has one, a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arg<'a> {
    /// The key, such as `console.cell`.
    pub key: &'a str,
    /// The value after `=`, or `None` for a key on its own.
    pub value: Option<Value<'a>>,
}

/// An argument's value, as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value<'a> {
    /// A value without quotes. It has no escapes: a backslash is itself.
    Bare(&'a str),
    /// The raw text between the quotes, with `\"` and `\\` not yet
    /// processed. Use [`Value::unescape`] to process them.
    Quoted(&'a str),
}

impl<'a> Value<'a> {
    /// The value's text as written: a bare value whole, or the text between
    /// the quotes of a quoted value, escapes included.
    pub fn raw(&self) -> &'a str {
        match *self {
            Value::Bare(s) | Value::Quoted(s) => s,
        }
    }

    /// Writes the value's text into `buf` with escapes processed, and
    /// returns it. `\"` becomes `"` and `\\` becomes `\`; a bare value is
    /// copied as it is.
    ///
    /// The result is never longer than [`Value::raw`], so a buffer that
    /// long always suffices.
    pub fn unescape<'b>(&self, buf: &'b mut [u8]) -> Result<&'b str, UnescapeError> {
        let mut written = 0usize;
        let mut put = |b: u8, n: &mut usize| -> Result<(), UnescapeError> {
            let slot = buf.get_mut(*n).ok_or(UnescapeError::BufferTooSmall)?;
            *slot = b;
            *n = n.checked_add(1).ok_or(UnescapeError::BufferTooSmall)?;
            Ok(())
        };
        match *self {
            Value::Bare(s) => {
                for &b in s.as_bytes() {
                    if !is_bare_char(b) {
                        return Err(UnescapeError::BadChar);
                    }
                    put(b, &mut written)?;
                }
            }
            Value::Quoted(s) => {
                let mut bytes = s.as_bytes().iter().copied();
                while let Some(b) = bytes.next() {
                    if b == BACKSLASH {
                        match bytes.next() {
                            Some(e @ (DQUOTE | BACKSLASH)) => put(e, &mut written)?,
                            _ => return Err(UnescapeError::BadEscape),
                        }
                    } else if is_q_char(b) {
                        put(b, &mut written)?;
                    } else {
                        return Err(UnescapeError::BadChar);
                    }
                }
            }
        }
        // Every byte written is printable ASCII, so this cannot fail.
        let out = buf.get(..written).ok_or(UnescapeError::BufferTooSmall)?;
        core::str::from_utf8(out).map_err(|_| UnescapeError::BadChar)
    }
}

/// Why [`Value::unescape`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnescapeError {
    /// The buffer is shorter than the unescaped text.
    BufferTooSmall,
    /// A backslash is followed by something other than `"` or `\`, or ends
    /// the text. Only a hand-built [`Value`] can have this.
    BadEscape,
    /// The text holds a byte its form doesn't allow. Only a hand-built
    /// [`Value`] can have this.
    BadChar,
}

impl fmt::Display for UnescapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            UnescapeError::BufferTooSmall => "buffer too small",
            UnescapeError::BadEscape => "bad escape",
            UnescapeError::BadChar => "character not allowed",
        })
    }
}

/// A parse error, and the byte offset in the line where it was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// The byte offset into the line.
    pub offset: usize,
    /// What is wrong.
    pub kind: ErrorKind,
}

/// What is wrong with a command line.
///
/// A byte at or above 0x80 is always [`ErrorKind::NotAscii`] and a control
/// byte is always [`ErrorKind::ControlChar`], wherever it is found. The other
/// kinds depend on where the parser is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// The line is longer than [`MAX_LEN`]. The offset is [`MAX_LEN`].
    TooLong,
    /// A byte outside ASCII.
    NotAscii,
    /// A control byte (0x00–0x1F or 0x7F), such as a tab.
    ControlChar,
    /// The key doesn't match `key`: an empty key or segment, a segment not
    /// starting with a lowercase letter, or a character a key can't hold.
    BadKey,
    /// `=` with no value after it. Use `""` for an empty value.
    EmptyValue,
    /// A `"` inside a bare value.
    QuoteInBare,
    /// A quoted value with no closing `"`. The offset is the opening `"`.
    UnterminatedQuote,
    /// A backslash in a quoted value followed by a printable character other
    /// than `"` or `\`. The offset is the backslash.
    BadEscape,
    /// Something other than a space right after a quoted value.
    MissingSpace,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::TooLong => "command line too long",
            ErrorKind::NotAscii => "byte outside ASCII",
            ErrorKind::ControlChar => "control character",
            ErrorKind::BadKey => "bad key",
            ErrorKind::EmptyValue => "empty value after '='",
            ErrorKind::QuoteInBare => "'\"' in an unquoted value",
            ErrorKind::UnterminatedQuote => "unterminated quoted value",
            ErrorKind::BadEscape => "bad escape in quoted value",
            ErrorKind::MissingSpace => "no space after quoted value",
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.kind, self.offset)
    }
}

/// Parses a command line. See the [crate documentation](crate) for how
/// errors and overlong lines are handled.
pub fn parse(line: &[u8]) -> Args<'_> {
    Args {
        line,
        pos: 0,
        done: false,
    }
}

/// The iterator [`parse`] returns.
#[derive(Debug, Clone)]
pub struct Args<'a> {
    line: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> Iterator for Args<'a> {
    type Item = Result<Arg<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if self.line.len() > MAX_LEN {
            self.done = true;
            return Some(Err(Error {
                offset: MAX_LEN,
                kind: ErrorKind::TooLong,
            }));
        }
        self.skip_spaces();
        if self.peek().is_none() {
            self.done = true;
            return None;
        }
        let result = self.arg();
        if result.is_err() {
            self.done = true;
        }
        Some(result)
    }
}

impl FusedIterator for Args<'_> {}

impl<'a> Args<'a> {
    fn peek(&self) -> Option<u8> {
        self.line.get(self.pos).copied()
    }

    /// Moves past one byte. Only called after `peek` returned `Some`, so
    /// `pos < line.len() <= MAX_LEN` and the addition cannot overflow.
    fn bump(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn skip_spaces(&mut self) {
        while self.peek() == Some(SP) {
            self.bump();
        }
    }

    fn err(&self, kind: ErrorKind) -> Error {
        Error {
            offset: self.pos,
            kind,
        }
    }

    /// An error at the current byte: `NotAscii` or `ControlChar` if the byte
    /// is one of those, `fallback` otherwise.
    fn err_here(&self, fallback: ErrorKind) -> Error {
        self.err(match self.peek() {
            Some(b) => classify(b, fallback),
            None => fallback,
        })
    }

    /// The text from `start` to the current position. Every byte in it has
    /// been checked to be printable ASCII.
    fn text(&self, start: usize) -> Result<&'a str, Error> {
        let bytes = self
            .line
            .get(start..self.pos)
            .ok_or(self.err(ErrorKind::BadKey))?;
        core::str::from_utf8(bytes).map_err(|_| self.err(ErrorKind::NotAscii))
    }

    /// One `arg`, starting at a byte that is not a space. On success the
    /// position is at a space or the end of the line.
    fn arg(&mut self) -> Result<Arg<'a>, Error> {
        let key = self.key()?;
        match self.peek() {
            None | Some(SP) => Ok(Arg { key, value: None }),
            Some(b'=') => {
                self.bump();
                let value = self.value()?;
                Ok(Arg {
                    key,
                    value: Some(value),
                })
            }
            Some(_) => Err(self.err_here(ErrorKind::BadKey)),
        }
    }

    /// `key = segment *( "." segment )`
    fn key(&mut self) -> Result<&'a str, Error> {
        let start = self.pos;
        loop {
            // segment = lower *( lower / DIGIT / "-" )
            match self.peek() {
                Some(b) if b.is_ascii_lowercase() => self.bump(),
                _ => return Err(self.err_here(ErrorKind::BadKey)),
            }
            while let Some(b) = self.peek() {
                if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' {
                    self.bump();
                } else {
                    break;
                }
            }
            if self.peek() == Some(b'.') {
                self.bump();
            } else {
                return self.text(start);
            }
        }
    }

    /// `value = bare / quoted`, starting just after the `=`.
    fn value(&mut self) -> Result<Value<'a>, Error> {
        match self.peek() {
            None | Some(SP) => Err(self.err(ErrorKind::EmptyValue)),
            Some(DQUOTE) => self.quoted(),
            Some(_) => self.bare(),
        }
    }

    /// `bare = 1*bare-char`, ending at a space or the end of the line.
    fn bare(&mut self) -> Result<Value<'a>, Error> {
        let start = self.pos;
        loop {
            match self.peek() {
                None | Some(SP) => return self.text(start).map(Value::Bare),
                Some(b) if is_bare_char(b) => self.bump(),
                Some(DQUOTE) => return Err(self.err(ErrorKind::QuoteInBare)),
                Some(b) => return Err(self.err(classify(b, ErrorKind::ControlChar))),
            }
        }
    }

    /// `quoted = DQUOTE *( q-char / escape ) DQUOTE`, starting at the
    /// opening quote. It must be followed by a space or the end of the line.
    fn quoted(&mut self) -> Result<Value<'a>, Error> {
        let open = self.pos;
        self.bump();
        let start = self.pos;
        loop {
            match self.peek() {
                None => {
                    return Err(Error {
                        offset: open,
                        kind: ErrorKind::UnterminatedQuote,
                    });
                }
                Some(DQUOTE) => break,
                Some(BACKSLASH) => {
                    let backslash = self.pos;
                    self.bump();
                    match self.peek() {
                        Some(DQUOTE | BACKSLASH) => self.bump(),
                        None => {
                            return Err(Error {
                                offset: open,
                                kind: ErrorKind::UnterminatedQuote,
                            });
                        }
                        Some(b) if b.is_ascii_graphic() || b == SP => {
                            return Err(Error {
                                offset: backslash,
                                kind: ErrorKind::BadEscape,
                            });
                        }
                        Some(b) => return Err(self.err(classify(b, ErrorKind::BadEscape))),
                    }
                }
                Some(b) if is_q_char(b) => self.bump(),
                Some(b) => return Err(self.err(classify(b, ErrorKind::ControlChar))),
            }
        }
        let raw = self.text(start)?;
        self.bump(); // the closing quote
        match self.peek() {
            None | Some(SP) => Ok(Value::Quoted(raw)),
            Some(_) => Err(self.err_here(ErrorKind::MissingSpace)),
        }
    }
}

/// `NotAscii` or `ControlChar` for such a byte, `fallback` otherwise.
fn classify(b: u8, fallback: ErrorKind) -> ErrorKind {
    if !b.is_ascii() {
        ErrorKind::NotAscii
    } else if b.is_ascii_control() {
        ErrorKind::ControlChar
    } else {
        fallback
    }
}

/// `bare-char = %x21 / %x23-7E`
fn is_bare_char(b: u8) -> bool {
    b == 0x21 || (0x23..=0x7E).contains(&b)
}

/// `q-char = %x20-21 / %x23-5B / %x5D-7E`
fn is_q_char(b: u8) -> bool {
    (0x20..=0x21).contains(&b) || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b)
}

/// The result of [`lookup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lookup<'a> {
    /// `None` if the key doesn't occur before the first error. Otherwise
    /// the last occurrence's value: `Some(None)` for the key on its own.
    pub value: Option<Option<Value<'a>>>,
    /// How many times the key occurs before the first error. More than one
    /// is a repeat, which the kernel logs (ADR 0041, rule 5).
    pub count: usize,
}

mod grub;
pub use grub::{GrubError, from_grub, is_grub};

/// Finds `key` in a command line. The last occurrence counts, and only
/// arguments before the first error are searched (ADR 0041, rule 5).
pub fn lookup<'a>(line: &'a [u8], key: &str) -> Lookup<'a> {
    let mut found = Lookup {
        value: None,
        count: 0,
    };
    for arg in parse(line).map_while(Result::ok) {
        if arg.key == key {
            found.value = Some(arg.value);
            found.count = found.count.saturating_add(1);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]

    use super::*;

    fn arg<'a>(key: &'a str, value: Option<Value<'a>>) -> Result<Arg<'a>, Error> {
        Ok(Arg { key, value })
    }

    fn error(offset: usize, kind: ErrorKind) -> Result<Arg<'static>, Error> {
        Err(Error { offset, kind })
    }

    fn check(line: &[u8], want: &[Result<Arg<'_>, Error>]) {
        let mut got = parse(line);
        for w in want {
            assert_eq!(got.next().as_ref(), Some(w), "line {line:?}");
        }
        assert_eq!(got.next(), None, "line {line:?}");
        assert_eq!(got.next(), None, "line {line:?}");
    }

    #[test]
    fn empty_and_spaces() {
        check(b"", &[]);
        check(b"     ", &[]);
    }

    #[test]
    fn several_args() {
        check(
            b"  console=fb,uart console.cell=24  quiet root.x=\"a b\\\"c\"  ",
            &[
                arg("console", Some(Value::Bare("fb,uart"))),
                arg("console.cell", Some(Value::Bare("24"))),
                arg("quiet", None),
                arg("root.x", Some(Value::Quoted("a b\\\"c"))),
            ],
        );
    }

    #[test]
    fn errors_stop_iteration() {
        check(
            b"a=1 B=2 c=3",
            &[
                arg("a", Some(Value::Bare("1"))),
                error(4, ErrorKind::BadKey),
            ],
        );
        check(b"a.", &[error(2, ErrorKind::BadKey)]);
        check(b"a..b", &[error(2, ErrorKind::BadKey)]);
        check(b"1a", &[error(0, ErrorKind::BadKey)]);
        check(b"-a", &[error(0, ErrorKind::BadKey)]);
        check(b"=a", &[error(0, ErrorKind::BadKey)]);
        check(b"a= b", &[error(2, ErrorKind::EmptyValue)]);
        check(b"a=", &[error(2, ErrorKind::EmptyValue)]);
        check(b"a=b\"c", &[error(3, ErrorKind::QuoteInBare)]);
        check(b"a=\"xy", &[error(2, ErrorKind::UnterminatedQuote)]);
        check(b"a=\"x\\", &[error(2, ErrorKind::UnterminatedQuote)]);
        check(b"a=\"x\\n\"", &[error(4, ErrorKind::BadEscape)]);
        check(b"a=\"x\"y", &[error(5, ErrorKind::MissingSpace)]);
        check(b"a=\"x\"\"y\"", &[error(5, ErrorKind::MissingSpace)]);
        check(b"a\tb", &[error(1, ErrorKind::ControlChar)]);
        check(b"a=\"\t\"", &[error(3, ErrorKind::ControlChar)]);
        check(b"a=\xc3\xa9", &[error(2, ErrorKind::NotAscii)]);
        check(b"a=x\x7f", &[error(3, ErrorKind::ControlChar)]);
        check(b"a=\"\\\xc3\"", &[error(4, ErrorKind::NotAscii)]);
    }

    #[test]
    fn too_long() {
        let mut line = [b'a'; MAX_LEN + 1];
        check(
            &line[..MAX_LEN],
            &[arg(core::str::from_utf8(&line[..MAX_LEN]).unwrap(), None)],
        );
        line[1] = b' ';
        check(&line, &[error(MAX_LEN, ErrorKind::TooLong)]);
    }

    #[test]
    fn lookup_last_wins() {
        let line = b"log.level=info console=fb log.level=\"debug\" x";
        assert_eq!(
            lookup(line, "log.level"),
            Lookup {
                value: Some(Some(Value::Quoted("debug"))),
                count: 2
            }
        );
        assert_eq!(
            lookup(line, "x"),
            Lookup {
                value: Some(None),
                count: 1
            }
        );
        assert_eq!(
            lookup(line, "nope"),
            Lookup {
                value: None,
                count: 0
            }
        );
        // Arguments after an error are not used.
        assert_eq!(lookup(b"a=1 B a=2", "a").count, 1);
        assert_eq!(
            lookup(b"a=1 B a=2", "a").value,
            Some(Some(Value::Bare("1")))
        );
    }

    #[test]
    fn unescape() {
        let mut buf = [0u8; 16];
        assert_eq!(
            Value::Quoted(r#"a\"b\\c"#).unescape(&mut buf),
            Ok(r#"a"b\c"#)
        );
        assert_eq!(Value::Quoted("").unescape(&mut buf), Ok(""));
        assert_eq!(Value::Bare(r"a\b").unescape(&mut buf), Ok(r"a\b"));
        assert_eq!(
            Value::Quoted(r"a\n").unescape(&mut buf),
            Err(UnescapeError::BadEscape)
        );
        assert_eq!(
            Value::Quoted(r"a\").unescape(&mut buf),
            Err(UnescapeError::BadEscape)
        );
        assert_eq!(
            Value::Quoted("a\"").unescape(&mut buf),
            Err(UnescapeError::BadChar)
        );
        assert_eq!(
            Value::Bare("a b").unescape(&mut buf),
            Err(UnescapeError::BadChar)
        );
        let mut small = [0u8; 2];
        assert_eq!(
            Value::Quoted(r#"\"\"\""#).unescape(&mut small),
            Err(UnescapeError::BufferTooSmall)
        );
        assert_eq!(Value::Quoted(r#"\"\""#).unescape(&mut small), Ok("\"\""));
    }

    #[test]
    fn unescape_parsed_values() {
        let line = br#"k="say \"hi\" \\o/" j=plain"#;
        let mut buf = [0u8; 32];
        let mut it = parse(line);
        let v = it.next().unwrap().unwrap().value.unwrap();
        assert_eq!(v.raw(), r#"say \"hi\" \\o/"#);
        assert_eq!(v.unescape(&mut buf), Ok(r#"say "hi" \o/"#));
        let v = it.next().unwrap().unwrap().value.unwrap();
        assert_eq!(v.unescape(&mut buf), Ok("plain"));
    }
}
