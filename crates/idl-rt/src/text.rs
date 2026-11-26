// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The canonical call text (ADR 0063, rule 9; docs/design/
//! call-language.md, "The canonical call text", `grammars/names.abnf`'s
//! `call-text` and `reply-text`).
//!
//! A call is `action-name SP target [SP args]`, where the target is the
//! object's ID as 64 lowercase hex digits until D34 gives the text form
//! (L01), or `-` for a `[kernel]` call. A reply is `ok [SP results]`, or
//! `outcome-word SP error-ref`. Arguments and results are opt-in: the
//! caller passes None for the default form, without them, or the writer
//! of the JSON mapping's compact object, which generated code supplies,
//! `{}` when empty. Everything goes into a caller's buffer, with no
//! allocator.

use crate::{
    error::{ErrorKey, Outcome},
    json::{JsonWriter, Overflow},
};

/// A call's target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target<'a> {
    /// An object, by ID.
    Object(&'a [u8; 32]),
    /// A `[kernel]` call, named by capability (ADR 0050).
    Kernel,
}

/// A simple cursor over the caller's buffer.
struct Out<'b> {
    buf: &'b mut [u8],
    len: usize,
}

impl Out<'_> {
    fn put(&mut self, b: &[u8]) -> Result<(), Overflow> {
        let dst = self
            .buf
            .get_mut(self.len..self.len + b.len())
            .ok_or(Overflow)?;
        dst.copy_from_slice(b);
        self.len += b.len();
        Ok(())
    }

    fn hex(&mut self, b: &[u8]) -> Result<(), Overflow> {
        const H: &[u8; 16] = b"0123456789abcdef";
        for &x in b {
            self.put(&[H[usize::from(x >> 4)], H[usize::from(x & 15)]])?;
        }
        Ok(())
    }

    fn decimal(&mut self, v: u64) -> Result<(), Overflow> {
        let mut d = [0u8; 20];
        let mut i = d.len();
        let mut v = v;
        loop {
            i -= 1;
            d[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.put(&d[i..])
    }

    /// Writes JSON after what is there.
    fn json(&mut self, f: &mut dyn FnMut(&mut JsonWriter<'_>)) -> Result<(), Overflow> {
        let mut j = JsonWriter::new(&mut self.buf[self.len..]);
        f(&mut j);
        let n = j.finish()?.len();
        self.len += n;
        Ok(())
    }
}

/// Writes a call's text: `action SP target`, then `SP args` when `args`
/// is given. Returns its length.
pub fn call_text(
    buf: &mut [u8],
    action: &str,
    target: Target<'_>,
    args: Option<&mut dyn FnMut(&mut JsonWriter<'_>)>,
) -> Result<usize, Overflow> {
    let mut o = Out { buf, len: 0 };
    o.put(action.as_bytes())?;
    o.put(b" ")?;
    match target {
        Target::Object(id) => o.hex(id)?,
        Target::Kernel => o.put(b"-")?,
    }
    if let Some(args) = args {
        o.put(b" ")?;
        o.json(args)?;
    }
    Ok(o.len)
}

/// Writes a reply's text: `ok`, then `SP results` when `results` is
/// given. Returns its length.
pub fn reply_ok(
    buf: &mut [u8],
    results: Option<&mut dyn FnMut(&mut JsonWriter<'_>)>,
) -> Result<usize, Overflow> {
    let mut o = Out { buf, len: 0 };
    o.put(b"ok")?;
    if let Some(results) = results {
        o.put(b" ")?;
        o.json(results)?;
    }
    Ok(o.len)
}

/// An error's name, where the writer knows it: the interface's name and
/// the error's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorName<'a> {
    pub interface: &'a str,
    pub error: &'a str,
}

/// Writes an error reply's text: `outcome-word SP error-ref`. The
/// reference is `name/major!error` when the name is known, and
/// `<id-text>/major!#code` otherwise. Returns its length.
pub fn reply_error(
    buf: &mut [u8],
    outcome: Outcome,
    key: &ErrorKey,
    name: Option<ErrorName<'_>>,
) -> Result<usize, Overflow> {
    let mut o = Out { buf, len: 0 };
    o.put(outcome.word().as_bytes())?;
    o.put(b" ")?;
    match name {
        Some(n) => {
            o.put(n.interface.as_bytes())?;
            o.put(b"/")?;
            o.decimal(u64::from(key.major))?;
            o.put(b"!")?;
            o.put(n.error.as_bytes())?;
        }
        None => {
            o.hex(&key.interface)?;
            o.put(b"/")?;
            o.decimal(u64::from(key.major))?;
            o.put(b"!#")?;
            o.decimal(u64::from(key.code))?;
        }
    }
    Ok(o.len)
}
