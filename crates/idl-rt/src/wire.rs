// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The wire encoding's core codecs, for generated decoders and encoders
//! (ADR 0062; ADR 0065, rules 2 and 11; docs/design/call-language.md,
//! "The core grammar", "The struct encoding", "Rules for readers").
//!
//! Every value is big-endian and unpadded, and each has one encoding: a
//! decoder rejects anything else as malformed. A [`Reader`] reads one
//! span of a message without allocating. A [`Writer`] writes into a
//! caller's buffer, or only measures. A [`DecodeCx`] carries what the
//! reading depends on: the session's minor, strict or tolerant reading,
//! and the capability list; it records what a strict read must refuse
//! without stopping it, so a later malformed part still wins ("Refusing
//! what is too new"). An [`EncodeCx`] says whether to refuse what is newer
//! than the session's minor, as a client stub must.

use crate::cap::CapRef;
use crate::meta::CapType;
use crate::view::{Bytes, Str, Unknown};

/// An object ID's 32 octets.
pub type Id = [u8; 32];
/// A UUID's 16 octets.
pub type Uuid = [u8; 16];

/// The canonical NaNs (ADR 0062): every other NaN is malformed.
pub const NAN32: u32 = 0x7FC0_0000;
pub const NAN64: u64 = 0x7FF8_0000_0000_0000;

/// The most tail fields an open struct may have: tags are u16, and 0 is
/// never one.
pub const MAX_TAIL: u32 = 65_535;

/// Whether `c` is one of the 66 Unicode noncharacters: U+FDD0 to U+FDEF,
/// and the last two code points of each plane, U+FFFE and U+FFFF to
/// U+10FFFE and U+10FFFF. Wire text never holds one (ADR 0062, rule 4),
/// so the JSON mapping's output is I-JSON (RFC 7493, section 2.1).
pub fn is_noncharacter(c: char) -> bool {
    let c = u32::from(c);
    (0xFDD0..=0xFDEF).contains(&c) || c & 0xFFFE == 0xFFFE
}

/// Whether `s` is wire text, core.abnf's `*text-char`: UTF-8 (which a
/// `str` is) without U+0000 or a noncharacter (ADR 0062, rule 4).
pub fn is_text(s: &str) -> bool {
    !s.chars().any(|c| c == '\0' || is_noncharacter(c))
}

/// Why a message doesn't decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// It doesn't match the grammar, or breaks a constraint.
    Malformed,
    /// A strict read met tail fields unknown at the session's minor
    /// (`field_too_new`, ADR 0065, rule 11).
    FieldTooNew(Tags),
}

/// Up to 8 tail tags: what `field_too_new` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tags {
    tags: [u16; 8],
    len: u8,
}

impl Tags {
    /// Adds a tag; past the eighth, tags are dropped.
    pub fn push(&mut self, tag: u16) {
        if let Some(t) = self.tags.get_mut(usize::from(self.len)) {
            *t = tag;
            self.len += 1;
        }
    }

    pub fn as_slice(&self) -> &[u16] {
        &self.tags[..usize::from(self.len)]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// How strictly a message is read ("Strict requests, tolerant reads").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A client's request: an unknown tail field is `field_too_new`, and a
    /// known value newer than the minor is `value_too_new`.
    Strict,
    /// Replies, stream items, error details, and the requests the kernel
    /// sends: unknown parts are skipped and preserved.
    Tolerant,
}

/// What a decoder reads against, and what it found to refuse.
#[derive(Debug, Clone)]
pub struct DecodeCx {
    /// The session's minor: everything newer is unknown.
    pub minor: u16,
    pub mode: Mode,
    /// The capabilities in the message's list.
    caps: u8,
    seen: u8,
    cap_types: [Option<&'static CapType>; crate::cap::MAX_CAPS as usize],
    too_new_fields: Tags,
    value_too_new: Option<u16>,
}

impl DecodeCx {
    pub fn new(minor: u16, mode: Mode, caps: u8) -> DecodeCx {
        DecodeCx {
            minor,
            mode,
            caps,
            seen: 0,
            cap_types: [None; crate::cap::MAX_CAPS as usize],
            too_new_fields: Tags::default(),
            value_too_new: None,
        }
    }

    /// Records a known enum value, flag bit or union arm whose `since`
    /// minor is `since`: in a strict read, one newer than the minor is
    /// `value_too_new`. Decoding goes on.
    pub fn value(&mut self, since: u16) {
        if self.mode == Mode::Strict && since > self.minor {
            self.value_too_new = Some(self.value_too_new.map_or(since, |v| v.max(since)));
        }
    }

    /// The newest `since` minor [`DecodeCx::value`] found too new.
    pub fn value_too_new(&self) -> Option<u16> {
        self.value_too_new
    }

    /// The tail tags a strict read found too new.
    pub fn fields_too_new(&self) -> &Tags {
        &self.too_new_fields
    }

    /// Reads a capability's index. Indexes ascend in encoding order, each
    /// once, all below the count and below [`crate::cap::MAX_CAPS`]
    /// ("Capability indexes").
    pub fn cap(&mut self, index: u8, ty: &'static CapType) -> Result<CapRef, DecodeError> {
        let Some(t) = self.cap_types.get_mut(usize::from(index)) else {
            return Err(DecodeError::Malformed);
        };
        if index != self.seen || index >= self.caps {
            return Err(DecodeError::Malformed);
        }
        *t = Some(ty);
        self.seen += 1;
        Ok(CapRef(index))
    }

    /// The declared type of the capability at an index, once decoded.
    pub fn cap_type(&self, index: u8) -> Option<&'static CapType> {
        self.cap_types.get(usize::from(index)).copied().flatten()
    }

    /// The capabilities the message names.
    pub fn caps(&self) -> u8 {
        self.caps
    }

    /// What a decoder at the minor makes of the whole message, once read:
    /// every capability named, then the unknown fields a strict read
    /// refuses.
    pub fn finish(&self) -> Result<(), DecodeError> {
        if self.seen != self.caps {
            return Err(DecodeError::Malformed);
        }
        if !self.too_new_fields.is_empty() {
            return Err(DecodeError::FieldTooNew(self.too_new_fields));
        }
        Ok(())
    }
}

/// Decodes a whole message: `f` must read every octet, and name every
/// capability (`DecodeCx::finish`).
pub fn decode_all<'a, T>(
    input: &'a [u8],
    cx: &mut DecodeCx,
    f: impl FnOnce(&mut Reader<'a>, &mut DecodeCx) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let mut r = Reader::new(input);
    let v = f(&mut r, cx)?;
    if !r.is_empty() {
        return Err(DecodeError::Malformed);
    }
    cx.finish()?;
    Ok(v)
}

/// Reads exactly `octets` with `f`: a tail field's or an open union arm's
/// value, whose length came first.
pub fn exact<'a, T>(
    octets: &'a [u8],
    cx: &mut DecodeCx,
    f: impl FnOnce(&mut Reader<'a>, &mut DecodeCx) -> Result<T, DecodeError>,
) -> Result<T, DecodeError> {
    let mut r = Reader::new(octets);
    let v = f(&mut r, cx)?;
    if r.is_empty() {
        Ok(v)
    } else {
        Err(DecodeError::Malformed)
    }
}

/// A `[nonzero]` field's integer, as read: 0 is malformed
/// (docs/design/call-language.md, "Attributes").
pub fn nonzero<T: Default + PartialEq>(v: T) -> Result<T, DecodeError> {
    if v == T::default() {
        Err(DecodeError::Malformed)
    } else {
        Ok(v)
    }
}

/// A `[nonzero]` field's integer, to be written: 0 is refused, since no
/// decoder would accept it.
pub fn nonzero_enc<T: Default + PartialEq>(v: T) -> Result<T, EncodeError> {
    if v == T::default() {
        Err(EncodeError::Bounds)
    } else {
        Ok(v)
    }
}

/// How many of a body's fields are known at `minor`: each entry is a
/// field's effective `since` minor, by position. Fields are only appended
/// and `since` never decreases, so the known ones are a prefix.
pub fn known(since: &[u16], minor: u16) -> usize {
    since.iter().take_while(|&&s| s <= minor).count()
}

/// A cursor over one span of a message.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

type R<T> = Result<T, DecodeError>;

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }

    /// Octets read so far.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// The octets from `start` to where the reader is.
    pub fn since(&self, start: usize) -> &'a [u8] {
        let buf: &'a [u8] = self.buf;
        buf.get(start..self.pos).unwrap_or(&[])
    }

    pub fn take(&mut self, n: usize) -> R<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Malformed)?;
        let buf: &'a [u8] = self.buf;
        let b = buf.get(self.pos..end).ok_or(DecodeError::Malformed)?;
        self.pos = end;
        Ok(b)
    }

    fn array<const N: usize>(&mut self) -> R<[u8; N]> {
        let mut a = [0u8; N];
        a.copy_from_slice(self.take(N)?);
        Ok(a)
    }

    pub fn u8(&mut self) -> R<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> R<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> R<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> R<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub fn i8(&mut self) -> R<i8> {
        Ok(i8::from_be_bytes(self.array()?))
    }

    pub fn i16(&mut self) -> R<i16> {
        Ok(i16::from_be_bytes(self.array()?))
    }

    pub fn i32(&mut self) -> R<i32> {
        Ok(i32::from_be_bytes(self.array()?))
    }

    pub fn i64(&mut self) -> R<i64> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    /// A strict boolean: `%x00` or `%x01`.
    pub fn bool(&mut self) -> R<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::Malformed),
        }
    }

    /// An optional value's presence octet, outside an open struct.
    pub fn presence(&mut self) -> R<bool> {
        self.bool()
    }

    /// An `f32`: any NaN but the canonical one is malformed.
    pub fn f32(&mut self) -> R<f32> {
        let b = self.u32()?;
        let v = f32::from_bits(b);
        if v.is_nan() && b != NAN32 {
            return Err(DecodeError::Malformed);
        }
        Ok(v)
    }

    /// An `f64`: any NaN but the canonical one is malformed.
    pub fn f64(&mut self) -> R<f64> {
        let b = self.u64()?;
        let v = f64::from_bits(b);
        if v.is_nan() && b != NAN64 {
            return Err(DecodeError::Malformed);
        }
        Ok(v)
    }

    pub fn id(&mut self) -> R<Id> {
        self.array()
    }

    pub fn uuid(&mut self) -> R<Uuid> {
        self.array()
    }

    /// `octets`: a `len32`, then that many octets.
    pub fn octets(&mut self) -> R<&'a [u8]> {
        let n = self.u32()?;
        self.take(n as usize)
    }

    /// `string<N>`: at most `max` octets of UTF-8, without U+0000 or a
    /// noncharacter ([`is_text`]; ADR 0062, rule 4).
    pub fn str(&mut self, max: u32) -> R<Str<'a>> {
        let n = self.u32()?;
        if n > max {
            return Err(DecodeError::Malformed);
        }
        let s = core::str::from_utf8(self.take(n as usize)?).map_err(|_| DecodeError::Malformed)?;
        if !is_text(s) {
            return Err(DecodeError::Malformed);
        }
        Ok(Str::Borrowed(s))
    }

    /// `bytes<N>`: at most `max` octets.
    pub fn bytes(&mut self, max: u32) -> R<Bytes<'a>> {
        let n = self.u32()?;
        if n > max {
            return Err(DecodeError::Malformed);
        }
        Ok(Bytes::Borrowed(self.take(n as usize)?))
    }

    /// A `count32` of at most `max`.
    pub fn count(&mut self, max: u32) -> R<u32> {
        let n = self.u32()?;
        if n > max {
            return Err(DecodeError::Malformed);
        }
        Ok(n)
    }
}

/// Reads an open struct's tail ("The struct encoding"). Generated code
/// reads the head, then calls [`Tail::next`] until it returns None,
/// decoding each known optional field, then [`Tail::finish`].
#[derive(Debug)]
pub struct Tail {
    remaining: u32,
    prev: u16,
    known: usize,
    /// Where the first unknown field starts, and how many there are.
    unknown_at: Option<usize>,
    unknown: u32,
}

impl Tail {
    /// Reads the tail's count. `known` is how many of the body's fields
    /// (required ones included) the reader knows at its minor.
    pub fn read(r: &mut Reader<'_>, known: usize) -> R<Tail> {
        let remaining = r.u32()?;
        if remaining > MAX_TAIL {
            return Err(DecodeError::Malformed);
        }
        Ok(Tail {
            remaining,
            prev: 0,
            known,
            unknown_at: None,
            unknown: 0,
        })
    }

    /// The next tail field whose tag the reader knows: its tag and its
    /// octets. Tags must ascend, so 0, a repeat and a step back are
    /// malformed. An unknown tag is preserved in a tolerant read, and
    /// recorded as `field_too_new` in a strict one.
    pub fn next<'a>(
        &mut self,
        r: &mut Reader<'a>,
        cx: &mut DecodeCx,
    ) -> R<Option<(u16, &'a [u8])>> {
        while self.remaining > 0 {
            self.remaining -= 1;
            let start = r.pos();
            let tag = r.u16()?;
            if tag <= self.prev {
                return Err(DecodeError::Malformed);
            }
            self.prev = tag;
            let octets = r.octets()?;
            if usize::from(tag) <= self.known {
                return Ok(Some((tag, octets)));
            }
            match cx.mode {
                Mode::Tolerant => {
                    self.unknown_at.get_or_insert(start);
                    self.unknown += 1;
                }
                Mode::Strict => cx.too_new_fields.push(tag),
            }
        }
        Ok(None)
    }

    /// Reads a tail in which the reader knows no optional field: every
    /// known tag is a required field's position, so it is malformed.
    pub fn read_unknown<'a>(r: &mut Reader<'a>, cx: &mut DecodeCx, known: usize) -> R<Unknown<'a>> {
        let mut t = Tail::read(r, known)?;
        if t.next(r, cx)?.is_some() {
            return Err(DecodeError::Malformed);
        }
        Ok(t.finish(r))
    }

    /// The unknown fields a tolerant read preserved: they follow every
    /// known one, since tags ascend.
    pub fn finish<'a>(self, r: &Reader<'a>) -> Unknown<'a> {
        match self.unknown_at {
            Some(at) => Unknown::wire(r.since(at), self.unknown),
            None => Unknown::default(),
        }
    }
}

/// Why a value doesn't encode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The buffer is too small.
    Overflow,
    /// A value is outside its declared bound: a string over its length,
    /// or holding U+0000 or a noncharacter, or 0 in a `[nonzero]` field.
    Bounds,
    /// A field newer than the session's minor is set: its tag, as a
    /// one-element slice, so a stub can report it with no storage.
    FieldTooNew(&'static [u16]),
    /// An enum value, flag bit or union arm newer than the session's minor
    /// is set: its `since` minor.
    ValueTooNew(u16),
    /// Capabilities out of order, or more than three.
    Caps,
    /// Preserved unknown fields would not follow the known ones: a field a
    /// decoder kept as unknown was set as well.
    Unknown,
    /// Encoded octets to carry, such as an error envelope's cause, don't
    /// decode.
    Malformed,
}

/// What an encoder checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeCx {
    /// The session's minor.
    pub minor: u16,
    /// Refuse what is newer than the minor: a client never sends it
    /// (ADR 0065, rule 11). Re-encoding a decoded value doesn't check.
    pub check: bool,
}

impl EncodeCx {
    /// Re-encoding, or a server's reply: nothing is refused.
    pub const ANY: EncodeCx = EncodeCx {
        minor: u16::MAX,
        check: false,
    };

    /// A client stub's request, at the session's minor.
    pub fn at(minor: u16) -> EncodeCx {
        EncodeCx { minor, check: true }
    }

    /// A tail field, added in minor `since`, is set. `tag` is its tag as
    /// a one-element slice.
    pub fn field(&self, since: u16, tag: &'static [u16]) -> Result<(), EncodeError> {
        if self.check && since > self.minor {
            Err(EncodeError::FieldTooNew(tag))
        } else {
            Ok(())
        }
    }

    /// A value added in minor `since` is set.
    pub fn value(&self, since: u16) -> Result<(), EncodeError> {
        if self.check && since > self.minor {
            Err(EncodeError::ValueTooNew(since))
        } else {
            Ok(())
        }
    }
}

/// Writes into a caller's buffer, or only measures.
#[derive(Debug)]
pub struct Writer<'b> {
    buf: &'b mut [u8],
    len: usize,
    measure: bool,
}

type W = Result<(), EncodeError>;

impl<'b> Writer<'b> {
    pub fn new(buf: &'b mut [u8]) -> Writer<'b> {
        Writer {
            buf,
            len: 0,
            measure: false,
        }
    }

    /// A writer that keeps nothing, and counts the octets.
    pub fn measure() -> Writer<'static> {
        Writer {
            buf: &mut [],
            len: 0,
            measure: true,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// What was written (empty when measuring).
    pub fn written(&self) -> &[u8] {
        if self.measure {
            &[]
        } else {
            &self.buf[..self.len]
        }
    }

    pub fn put(&mut self, b: &[u8]) -> W {
        let end = self.len.checked_add(b.len()).ok_or(EncodeError::Overflow)?;
        if !self.measure {
            self.buf
                .get_mut(self.len..end)
                .ok_or(EncodeError::Overflow)?
                .copy_from_slice(b);
        }
        self.len = end;
        Ok(())
    }

    pub fn u8(&mut self, v: u8) -> W {
        self.put(&[v])
    }

    pub fn u16(&mut self, v: u16) -> W {
        self.put(&v.to_be_bytes())
    }

    pub fn u32(&mut self, v: u32) -> W {
        self.put(&v.to_be_bytes())
    }

    pub fn u64(&mut self, v: u64) -> W {
        self.put(&v.to_be_bytes())
    }

    pub fn i8(&mut self, v: i8) -> W {
        self.put(&v.to_be_bytes())
    }

    pub fn i16(&mut self, v: i16) -> W {
        self.put(&v.to_be_bytes())
    }

    pub fn i32(&mut self, v: i32) -> W {
        self.put(&v.to_be_bytes())
    }

    pub fn i64(&mut self, v: i64) -> W {
        self.put(&v.to_be_bytes())
    }

    pub fn bool(&mut self, v: bool) -> W {
        self.u8(u8::from(v))
    }

    /// An `f32`; every NaN is written as the canonical one.
    pub fn f32(&mut self, v: f32) -> W {
        self.u32(if v.is_nan() { NAN32 } else { v.to_bits() })
    }

    /// An `f64`; every NaN is written as the canonical one.
    pub fn f64(&mut self, v: f64) -> W {
        self.u64(if v.is_nan() { NAN64 } else { v.to_bits() })
    }

    /// `octets`: a `len32`, then the octets.
    pub fn octets(&mut self, b: &[u8]) -> W {
        let n = u32::try_from(b.len()).map_err(|_| EncodeError::Bounds)?;
        self.u32(n)?;
        self.put(b)
    }

    /// `string<N>`: refused when over its bound, or when it holds U+0000
    /// or a noncharacter ([`is_text`]), which no decoder accepts.
    pub fn str(&mut self, s: &str, max: u32) -> W {
        if s.len() > max as usize || !is_text(s) {
            return Err(EncodeError::Bounds);
        }
        self.octets(s.as_bytes())
    }

    /// `bytes<N>`.
    pub fn bytes(&mut self, b: &[u8], max: u32) -> W {
        if b.len() > max as usize {
            return Err(EncodeError::Bounds);
        }
        self.octets(b)
    }

    /// A sequence's `count32`, at most `max`.
    pub fn count(&mut self, n: usize, max: u32) -> W {
        if n > max as usize {
            return Err(EncodeError::Bounds);
        }
        self.u32(n as u32)
    }

    /// An array's length, which must be exactly `n`; nothing is written.
    pub fn array(&mut self, len: usize, n: u32) -> W {
        if len != n as usize {
            return Err(EncodeError::Bounds);
        }
        Ok(())
    }

    /// Reserves a `len32`, to patch with [`Writer::end_len`] once the
    /// value is written.
    pub fn begin_len(&mut self) -> Result<usize, EncodeError> {
        let at = self.len;
        self.put(&[0; 4])?;
        Ok(at)
    }

    /// Patches the `len32` at `at` with the octets written after it.
    pub fn end_len(&mut self, at: usize) -> W {
        let n = self.len - at - 4;
        let n = u32::try_from(n).map_err(|_| EncodeError::Bounds)?;
        self.patch(at, n)
    }

    fn patch(&mut self, at: usize, v: u32) -> W {
        if !self.measure {
            self.buf
                .get_mut(at..at + 4)
                .ok_or(EncodeError::Overflow)?
                .copy_from_slice(&v.to_be_bytes());
        }
        Ok(())
    }

    /// Starts an open struct's tail.
    pub fn tail(&mut self) -> Result<TailWriter, EncodeError> {
        Ok(TailWriter {
            at: self.begin_len()?,
            count: 0,
            last: 0,
        })
    }
}

/// Writes an open struct's tail: present known fields in ascending tag
/// order, then the preserved unknown ones.
#[derive(Debug)]
pub struct TailWriter {
    at: usize,
    count: u32,
    last: u16,
}

impl TailWriter {
    /// Starts a tail field: its tag, and a `len32` to patch.
    pub fn begin(&mut self, w: &mut Writer<'_>, tag: u16) -> Result<usize, EncodeError> {
        if tag <= self.last {
            return Err(EncodeError::Unknown);
        }
        self.last = tag;
        w.u16(tag)?;
        w.begin_len()
    }

    /// Ends the tail field `begin` started.
    pub fn end(&mut self, w: &mut Writer<'_>, at: usize) -> W {
        self.count += 1;
        w.end_len(at)
    }

    /// The preserved unknown fields, unchanged and in order. Their tags
    /// must follow every field already written.
    pub fn unknown(&mut self, w: &mut Writer<'_>, u: &Unknown<'_>) -> W {
        let Some(first) = u.first_tag() else {
            return Ok(());
        };
        if first <= self.last {
            return Err(EncodeError::Unknown);
        }
        self.last = u.last_tag().unwrap_or(first);
        self.count += u.count();
        w.put(u.raw())
    }

    /// Writes the count.
    pub fn finish(self, w: &mut Writer<'_>) -> W {
        w.patch(self.at, self.count)
    }
}

/// A stream method's opening reply: the stream ID (never 0), the start
/// position, then the method's results ("Server streams in the IDL").
#[derive(Debug, Clone, PartialEq)]
pub struct Opened<R> {
    pub id: u32,
    pub start: u64,
    pub reply: R,
}

impl<R> Opened<R> {
    pub fn decode<'a>(
        r: &mut Reader<'a>,
        cx: &mut DecodeCx,
        reply: impl FnOnce(&mut Reader<'a>, &mut DecodeCx) -> Result<R, DecodeError>,
    ) -> Result<Self, DecodeError> {
        let id = r.u32()?;
        if id == 0 {
            return Err(DecodeError::Malformed);
        }
        let start = r.u64()?;
        Ok(Opened {
            id,
            start,
            reply: reply(r, cx)?,
        })
    }

    pub fn encode(
        &self,
        w: &mut Writer<'_>,
        reply: impl FnOnce(&R, &mut Writer<'_>) -> Result<(), EncodeError>,
    ) -> W {
        if self.id == 0 {
            return Err(EncodeError::Bounds);
        }
        w.u32(self.id)?;
        w.u64(self.start)?;
        reply(&self.reply, w)
    }
}
