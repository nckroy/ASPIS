// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The IDL's JSON mapping, as the canonical call text writes it (ADR 0063,
//! rule 9; ADR 0067, rule 8; docs/design/call-language.md, "The JSON
//! mapping").
//!
//! [`JsonWriter`] writes compact JSON, with no insignificant whitespace,
//! into a caller's buffer, with no allocator. It produces I-JSON (RFC
//! 7493), except that a string may hold the Unicode noncharacters the
//! wire's `text-char` allows: strings escaped as RFC 8785 §3.2.2.2 does, `u64` and `i64` as
//! strings of digits, floats laid out as ECMAScript's Number::toString
//! does (RFC 8785 §3.2.2.3) with `-0` kept, and `[format(json)]` strings
//! embedded only when they are I-JSON themselves ([`JsonWriter::embedded`]).
//! `grammars/json.abnf` is the grammar of what it writes.
//!
//! Commas are the writer's: a value written inside an object or an array
//! takes one when it isn't the first. Keys are written with
//! [`JsonWriter::key`], which the next value follows.

use core::fmt::Write as _;

/// The output didn't fit the buffer, or nested deeper than
/// [`MAX_DEPTH`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Overflow;

/// The deepest nesting of objects and arrays the writer tracks.
pub const MAX_DEPTH: usize = 256;

/// How deep an embedded `[format(json)]` value may nest before it is
/// written as a string instead.
pub const EMBED_DEPTH: usize = 32;

/// How many members one object of an embedded `[format(json)]` value may
/// have before the value is written as a string instead. It bounds the
/// duplicate-name check, so checking a value takes time linear in its
/// length.
pub const EMBED_MEMBERS: usize = 64;

/// Writes compact JSON into a buffer.
pub struct JsonWriter<'b> {
    buf: &'b mut [u8],
    len: usize,
    overflow: bool,
    depth: usize,
    /// One bit per open object or array: set once it holds a value.
    used: [u64; MAX_DEPTH / 64],
    /// A key was just written, so the next value takes no comma.
    after_key: bool,
}

impl<'b> JsonWriter<'b> {
    pub fn new(buf: &'b mut [u8]) -> JsonWriter<'b> {
        JsonWriter {
            buf,
            len: 0,
            overflow: false,
            depth: 0,
            used: [0; MAX_DEPTH / 64],
            after_key: false,
        }
    }

    /// What was written, or [`Overflow`] if anything didn't fit.
    pub fn finish(&self) -> Result<&[u8], Overflow> {
        if self.overflow {
            Err(Overflow)
        } else {
            Ok(&self.buf[..self.len])
        }
    }

    /// Octets written so far.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, b: &[u8]) {
        match self.buf.get_mut(self.len..self.len + b.len()) {
            Some(dst) if !self.overflow => {
                dst.copy_from_slice(b);
                self.len += b.len();
            }
            _ => self.overflow = true,
        }
    }

    /// Before a value: a comma, unless it is the first in its container
    /// or follows a key.
    fn sep(&mut self) {
        if self.after_key {
            self.after_key = false;
            return;
        }
        if self.depth == 0 {
            return;
        }
        let (w, bit) = ((self.depth - 1) / 64, 1u64 << ((self.depth - 1) % 64));
        if self.used[w] & bit != 0 {
            self.push(b",");
        }
        self.used[w] |= bit;
    }

    fn open(&mut self, c: u8) {
        self.sep();
        self.push(&[c]);
        if self.depth >= MAX_DEPTH {
            self.overflow = true;
            return;
        }
        self.depth += 1;
        let (w, bit) = ((self.depth - 1) / 64, 1u64 << ((self.depth - 1) % 64));
        self.used[w] &= !bit;
    }

    fn close(&mut self, c: u8) {
        self.push(&[c]);
        self.depth = self.depth.saturating_sub(1);
    }

    pub fn begin_object(&mut self) {
        self.open(b'{');
    }

    pub fn end_object(&mut self) {
        self.close(b'}');
    }

    pub fn begin_array(&mut self) {
        self.open(b'[');
    }

    pub fn end_array(&mut self) {
        self.close(b']');
    }

    /// An object member's key: `"name":`. The next value is its value.
    pub fn key(&mut self, name: &str) {
        self.sep();
        self.quoted(name);
        self.push(b":");
        self.after_key = true;
    }

    /// An unknown tail field's or arm's key: `"@<tag>":` (docs/design/
    /// call-language.md, "The JSON mapping").
    pub fn tag_key(&mut self, tag: u16) {
        self.sep();
        self.push(b"\"@");
        self.digits(u64::from(tag));
        self.push(b"\":");
        self.after_key = true;
    }

    pub fn null(&mut self) {
        self.sep();
        self.push(b"null");
    }

    pub fn bool(&mut self, v: bool) {
        self.sep();
        self.push(if v { b"true" } else { b"false" });
    }

    fn digits(&mut self, v: u64) {
        let mut tmp = [0u8; 20];
        let mut i = tmp.len();
        let mut v = v;
        loop {
            i -= 1;
            tmp[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        self.push(&tmp[i..]);
    }

    /// `u8` to `u32` (and an enum's unknown value): a number.
    pub fn uint(&mut self, v: u64) {
        self.sep();
        self.digits(v);
    }

    /// `i8` to `i32`: a number.
    pub fn int(&mut self, v: i64) {
        self.sep();
        if v < 0 {
            self.push(b"-");
        }
        self.digits(v.unsigned_abs());
    }

    /// `u64`: a string of digits, since I-JSON can't carry it exactly as a
    /// number (RFC 7493, §2.2).
    pub fn u64_string(&mut self, v: u64) {
        self.sep();
        self.push(b"\"");
        self.digits(v);
        self.push(b"\"");
    }

    /// `i64`: a string of digits, with `-` when negative.
    pub fn i64_string(&mut self, v: i64) {
        self.sep();
        self.push(b"\"");
        if v < 0 {
            self.push(b"-");
        }
        self.digits(v.unsigned_abs());
        self.push(b"\"");
    }

    /// `f64`: RFC 8785's serialization, except that negative zero is `-0`.
    pub fn f64(&mut self, v: f64) {
        self.sep();
        let mut d = Digits::new();
        // `{:e}` writes the shortest digits that read back as `v`.
        let _ = write!(d, "{:e}", v.abs());
        self.float(v.is_sign_negative(), v.is_nan(), v.is_infinite(), &d);
    }

    /// `f32`: the shortest decimal that reads back as the same binary32,
    /// laid out as for `f64`.
    pub fn f32(&mut self, v: f32) {
        self.sep();
        let mut d = Digits::new();
        let _ = write!(d, "{:e}", v.abs());
        self.float(v.is_sign_negative(), v.is_nan(), v.is_infinite(), &d);
    }

    /// Lays out `{:e}`'s digits as ECMAScript's Number::toString does:
    /// with k significant digits and the decimal exponent n (the value is
    /// 0.d1d2...dk × 10^n), decimal notation for -6 < n <= 21, and
    /// otherwise exponent notation with an explicit sign.
    fn float(&mut self, negative: bool, nan: bool, inf: bool, d: &Digits) {
        if nan {
            self.push(b"\"NaN\"");
            return;
        }
        if inf {
            self.push(if negative {
                b"\"-Infinity\""
            } else {
                b"\"Infinity\""
            });
            return;
        }
        if negative {
            self.push(b"-");
        }
        let text = d.as_bytes();
        let Some(e) = text.iter().position(|&b| b == b'e') else {
            self.overflow = true;
            return;
        };
        let (mantissa, exp) = (&text[..e], &text[e + 1..]);
        // The significant digits, without the point.
        let mut digits = [0u8; 32];
        let mut k = 0;
        for &b in mantissa.iter().filter(|b| b.is_ascii_digit()) {
            if k < digits.len() {
                digits[k] = b;
                k += 1;
            }
        }
        let s = &digits[..k];
        if s == b"0" {
            self.push(b"0");
            return;
        }
        let mut x: i32 = 0;
        let (neg_exp, exp_digits) = match exp.split_first() {
            Some((b'-', rest)) => (true, rest),
            _ => (false, exp),
        };
        for &b in exp_digits {
            x = x * 10 + i32::from(b - b'0');
        }
        if neg_exp {
            x = -x;
        }
        // {:e} gives d.ddd × 10^x, so n = x + 1.
        let n = x + 1;
        let k = k as i32;
        if k <= n && n <= 21 {
            self.push(s);
            for _ in 0..(n - k) {
                self.push(b"0");
            }
        } else if 0 < n && n <= 21 {
            self.push(&s[..n as usize]);
            self.push(b".");
            self.push(&s[n as usize..]);
        } else if -6 < n && n <= 0 {
            self.push(b"0.");
            for _ in 0..(-n) {
                self.push(b"0");
            }
            self.push(s);
        } else {
            self.push(&s[..1]);
            if k > 1 {
                self.push(b".");
                self.push(&s[1..]);
            }
            self.push(b"e");
            let e = n - 1;
            self.push(if e < 0 { b"-" } else { b"+" });
            self.digits(u64::from(e.unsigned_abs()));
        }
    }

    /// A string, escaped as RFC 8785 §3.2.2.2 does: `"` and `\`, the five
    /// short escapes, and other control characters as `\u00xx` in
    /// lowercase hex. Everything else is written as it is.
    pub fn string(&mut self, s: &str) {
        self.sep();
        self.quoted(s);
    }

    fn quoted(&mut self, s: &str) {
        self.push(b"\"");
        let bytes = s.as_bytes();
        let mut start = 0;
        for (i, &b) in bytes.iter().enumerate() {
            let esc: &[u8] = match b {
                b'"' => b"\\\"",
                b'\\' => b"\\\\",
                0x08 => b"\\b",
                0x09 => b"\\t",
                0x0A => b"\\n",
                0x0C => b"\\f",
                0x0D => b"\\r",
                0x00..=0x1F => b"",
                _ => continue,
            };
            self.push(&bytes[start..i]);
            if esc.is_empty() {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                self.push(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[usize::from(b >> 4)],
                    HEX[usize::from(b & 15)],
                ]);
            } else {
                self.push(esc);
            }
            start = i + 1;
        }
        self.push(&bytes[start..]);
        self.push(b"\"");
    }

    /// `bytes<N>`: base64url without padding (RFC 4648, §5).
    pub fn bytes(&mut self, data: &[u8]) {
        self.sep();
        self.push(b"\"");
        const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for chunk in data.chunks(3) {
            let n = chunk.len();
            let v = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            let c = [
                B64[(v >> 18) as usize & 63],
                B64[(v >> 12) as usize & 63],
                B64[(v >> 6) as usize & 63],
                B64[v as usize & 63],
            ];
            self.push(&c[..n + 1]);
        }
        self.push(b"\"");
    }

    fn hex(&mut self, data: &[u8]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &b in data {
            self.push(&[HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
        }
    }

    /// `id`: 64 lowercase hex digits, until D34 gives the object-ID text
    /// form (L01).
    pub fn id(&mut self, id: &[u8; 32]) {
        self.sep();
        self.push(b"\"");
        self.hex(id);
        self.push(b"\"");
    }

    /// `uuid`: RFC 9562's 36-character lowercase form.
    pub fn uuid(&mut self, u: &[u8; 16]) {
        self.sep();
        self.push(b"\"");
        self.hex(&u[..4]);
        self.push(b"-");
        self.hex(&u[4..6]);
        self.push(b"-");
        self.hex(&u[6..8]);
        self.push(b"-");
        self.hex(&u[8..10]);
        self.push(b"-");
        self.hex(&u[10..]);
        self.push(b"\"");
    }

    /// `cap<...>`: `{"cap":N}`, the capability's index in the message's
    /// list, never a badge or an export ID.
    pub fn cap(&mut self, index: u8) {
        self.sep();
        self.push(b"{\"cap\":");
        self.digits(u64::from(index));
        self.push(b"}");
    }

    /// A `[format(json)]` string: embedded as JSON when it is an RFC 8259
    /// value that is also I-JSON (no duplicate member names, compared
    /// after unescaping, and no unpaired surrogate escapes), nests at most
    /// [`EMBED_DEPTH`] deep, has at most [`EMBED_MEMBERS`] members in any
    /// object, and isn't the bare literal `null`, which under a field's
    /// key means redacted. It is re-written without insignificant
    /// whitespace, its tokens otherwise unchanged. Any other text is
    /// written as a JSON string, so the output is always I-JSON. One
    /// pass checks it, in time linear in its length.
    pub fn embedded(&mut self, text: &str) {
        let t = text.as_bytes();
        let start = skip_ws(t, 0);
        let valid = u32::try_from(t.len()).is_ok()
            && match value(t, start, 0) {
                Some(end) => skip_ws(t, end) == t.len() && &t[start..end] != b"null",
                None => false,
            };
        if !valid {
            self.string(text);
            return;
        }
        self.sep();
        let mut i = 0;
        while i < t.len() {
            match t[i] {
                b' ' | b'\t' | b'\n' | b'\r' => i += 1,
                b'"' => {
                    let end = string_end(t, i).unwrap_or(t.len());
                    self.push(&t[i..end]);
                    i = end;
                }
                _ => {
                    self.push(&t[i..i + 1]);
                    i += 1;
                }
            }
        }
    }
}

/// A fixed buffer for `{:e}`'s output.
struct Digits {
    buf: [u8; 64],
    len: usize,
}

impl Digits {
    fn new() -> Digits {
        Digits {
            buf: [0; 64],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl core::fmt::Write for Digits {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let dst = self
            .buf
            .get_mut(self.len..self.len + s.len())
            .ok_or(core::fmt::Error)?;
        dst.copy_from_slice(s.as_bytes());
        self.len += s.len();
        Ok(())
    }
}

// ---- Validating embedded JSON (RFC 8259, RFC 7493) ---------------------

fn skip_ws(t: &[u8], mut i: usize) -> usize {
    while matches!(t.get(i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        i += 1;
    }
    i
}

/// The end of the value starting at `i`, or None when it isn't a value
/// [`JsonWriter::embedded`] embeds. Recursion follows the value's
/// nesting, which is bounded by [`EMBED_DEPTH`]. Each object's keys are
/// kept as offsets, at most [`EMBED_MEMBERS`] of them, and each new key is
/// compared with the earlier ones: a duplicate is None. The text is
/// shorter than 4 GiB, so offsets fit a u32.
fn value(t: &[u8], i: usize, depth: usize) -> Option<usize> {
    match *t.get(i)? {
        b'{' | b'[' if depth >= EMBED_DEPTH => None,
        b'{' => {
            let mut keys = [0u32; EMBED_MEMBERS];
            let mut n = 0;
            let mut i = skip_ws(t, i + 1);
            if t.get(i) == Some(&b'}') {
                return Some(i + 1);
            }
            loop {
                if t.get(i) != Some(&b'"') || n == EMBED_MEMBERS {
                    return None;
                }
                let key = i;
                let end = string_end(t, key)?;
                if keys[..n].iter().any(|&k| same_string(t, k as usize, key)) {
                    return None;
                }
                keys[n] = u32::try_from(key).ok()?;
                n += 1;
                i = skip_ws(t, end);
                if t.get(i) != Some(&b':') {
                    return None;
                }
                i = skip_ws(t, value(t, skip_ws(t, i + 1), depth + 1)?);
                match t.get(i)? {
                    b',' => i = skip_ws(t, i + 1),
                    b'}' => return Some(i + 1),
                    _ => return None,
                }
            }
        }
        b'[' => {
            let mut i = skip_ws(t, i + 1);
            if t.get(i) == Some(&b']') {
                return Some(i + 1);
            }
            loop {
                i = skip_ws(t, value(t, i, depth + 1)?);
                match t.get(i)? {
                    b',' => i = skip_ws(t, i + 1),
                    b']' => return Some(i + 1),
                    _ => return None,
                }
            }
        }
        b'"' => string_end(t, i),
        b't' => literal(t, i, b"true"),
        b'f' => literal(t, i, b"false"),
        b'n' => literal(t, i, b"null"),
        _ => number(t, i),
    }
}

fn literal(t: &[u8], i: usize, word: &[u8]) -> Option<usize> {
    (t.get(i..i + word.len()) == Some(word)).then_some(i + word.len())
}

/// `number = [ minus ] int [ frac ] [ exp ]` (RFC 8259, §6).
fn number(t: &[u8], mut i: usize) -> Option<usize> {
    let digits = |t: &[u8], mut i: usize| {
        let s = i;
        while t.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        (i > s).then_some(i)
    };
    if t.get(i) == Some(&b'-') {
        i += 1;
    }
    i = match t.get(i)? {
        b'0' => i + 1,
        b'1'..=b'9' => digits(t, i)?,
        _ => return None,
    };
    if t.get(i) == Some(&b'.') {
        i = digits(t, i + 1)?;
    }
    if matches!(t.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(t.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        i = digits(t, i)?;
    }
    Some(i)
}

/// The end of the string starting at `i` (its opening quote), or None if
/// it is malformed or holds an unpaired surrogate escape (RFC 7493, §2.1).
fn string_end(t: &[u8], i: usize) -> Option<usize> {
    let mut chars = Chars { t, i: i + 1 };
    loop {
        match chars.next_char()? {
            Some(_) => {}
            None => return Some(chars.i),
        }
    }
}

/// Reads a JSON string's characters, unescaped.
struct Chars<'t> {
    t: &'t [u8],
    i: usize,
}

impl Chars<'_> {
    /// The next character: `Some(Some(c))`, or `Some(None)` at the closing
    /// quote (then `i` is past it), or None when malformed.
    fn next_char(&mut self) -> Option<Option<u32>> {
        let b = *self.t.get(self.i)?;
        match b {
            b'"' => {
                self.i += 1;
                Some(None)
            }
            b'\\' => {
                let e = *self.t.get(self.i + 1)?;
                self.i += 2;
                let c = match e {
                    b'"' => 0x22,
                    b'\\' => 0x5C,
                    b'/' => 0x2F,
                    b'b' => 0x08,
                    b'f' => 0x0C,
                    b'n' => 0x0A,
                    b'r' => 0x0D,
                    b't' => 0x09,
                    b'u' => {
                        let hi = self.hex4()?;
                        match hi {
                            0xD800..=0xDBFF => {
                                if self.t.get(self.i..self.i + 2) != Some(b"\\u") {
                                    return None;
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return None;
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            }
                            0xDC00..=0xDFFF => return None,
                            c => c,
                        }
                    }
                    _ => return None,
                };
                Some(Some(c))
            }
            0x00..=0x1F => None,
            _ => {
                // The text is UTF-8 already: take one character.
                let n = match b {
                    0x00..=0x7F => 1,
                    0xC0..=0xDF => 2,
                    0xE0..=0xEF => 3,
                    _ => 4,
                };
                let s = core::str::from_utf8(self.t.get(self.i..self.i + n)?).ok()?;
                self.i += n;
                s.chars().next().map(|c| Some(u32::from(c)))
            }
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let h = self.t.get(self.i..self.i + 4)?;
        let mut v = 0;
        for &c in h {
            v = v * 16 + (c as char).to_digit(16)?;
        }
        self.i += 4;
        Some(v)
    }
}

/// Whether two strings, each starting at its opening quote, hold the same
/// characters once unescaped.
fn same_string(t: &[u8], a: usize, b: usize) -> bool {
    let mut x = Chars { t, i: a + 1 };
    let mut y = Chars { t, i: b + 1 };
    loop {
        match (x.next_char(), y.next_char()) {
            (Some(Some(c)), Some(Some(d))) if c == d => {}
            (Some(None), Some(None)) => return true,
            _ => return false,
        }
    }
}
