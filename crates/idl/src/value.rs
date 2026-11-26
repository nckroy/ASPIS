// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The dynamic value model: any IDL value as a tree, with an interpretive
//! encoder and decoder driven by the [`Schema`], and its JSON (ADR 0067,
//! rules 8 and 9; docs/design/call-language.md, "The struct encoding",
//! "Rules for readers", "The JSON mapping").
//!
//! It is the seam for dynamic invocation (L33), and what generates and
//! labels the vectors of every generated grammar: the decoder at minor m
//! accepts exactly what grammar m accepts with its constraints, which the
//! vector generator checks on every line it writes.
//!
//! Decoding follows "Rules for readers":
//!
//! - Every member of the checked file whose `since` is above the minor is
//!   unknown. A strict read (a client's request) refuses an unknown tail
//!   field with `field_too_new`; a tolerant one skips it by its length and
//!   preserves it.
//! - An open union's unknown arm, and an open enum's or flags type's
//!   unknown value, are accepted and preserved in both modes. In a strict
//!   read, a known one that is newer than the minor is recorded as
//!   `value_too_new`, and decoding goes on to the end: a later malformed
//!   part still makes the message malformed. A newer arm is kept as raw
//!   octets, never read with its type, as the grammar at the minor reads
//!   it.
//! - Anything unknown in a closed type is malformed.

use alloc::{boxed::Box, string::String, vec, vec::Vec};

use idl_rt::json::JsonWriter;

use crate::{
    ast::{BaseType, IntType, Type},
    model::TypeId,
    schema::{Body, Def, Mode, Schema, Top},
};

/// A value of any IDL type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    /// Any integer type: its width comes from the schema.
    Int(i128),
    /// `f32`, as its bits.
    F32(u32),
    /// `f64`, as its bits.
    F64(u64),
    Id([u8; 32]),
    Uuid([u8; 16]),
    Text(String),
    Bytes(Vec<u8>),
    /// A sequence or an array; for a stream's opening reply, the stream
    /// ID, the start position and the results.
    List(Vec<Value>),
    /// An optional value outside an open struct: `presence`, then it.
    Opt(Option<Box<Value>>),
    /// A struct, a method's parameters or results, or an error's detail.
    Struct(Fields),
    /// A known union arm: its tag and value.
    Arm(u16, Box<Value>),
    /// An open union's arm unknown at the minor: its tag and raw octets.
    UnknownArm(u16, Vec<u8>),
    /// An enum's raw value, known or not.
    Enum(u64),
    /// A flags type's raw bits, known or not.
    Flags(u64),
    /// A capability's index in the message's list.
    Cap(u8),
    /// A capability-space address (`slot<...>`, `[kernel]` interfaces
    /// only).
    Slot(u64),
}

/// A struct-shaped value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fields {
    /// One entry per field known at the minor, in declaration order: None
    /// for an absent optional field.
    pub known: Vec<Option<Value>>,
    /// Tail fields unknown at the minor, preserved: tag and raw octets,
    /// in tag order.
    pub unknown: Vec<(u16, Vec<u8>)>,
}

/// Why a message doesn't decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// It doesn't match the grammar, or breaks a constraint: `malformed`.
    Malformed,
    /// A strict read found tail fields unknown at the minor: their tags,
    /// up to 8 (`field_too_new`, ADR 0065, rule 11).
    FieldTooNew(Vec<u16>),
}

/// A decoded message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub value: Value,
    /// In a strict read, the newest `since` minor of a known enum value,
    /// flag bit or union arm that is newer than the minor
    /// (`value_too_new`). The message still matches the grammar.
    pub value_too_new: Option<u16>,
}

/// The ID and start position a stream method's opening reply carries
/// in generated vectors.
pub const OPEN_ID: u32 = 1;
pub const OPEN_START: u64 = 42;

// ---- Encoding -------------------------------------------------------------

/// A deliberate corruption the encoder can make once, at the first place
/// it applies, for the err and errc vectors (docs/design/call-language.md,
/// "Evolution vectors").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fault {
    /// A tail's fields in descending order.
    TailSwap,
    /// A tail's first field twice.
    TailDup,
    /// A tail field with tag 0.
    TailTagZero,
    /// A tail field whose tag is a required field's position.
    TailRequired,
    /// A tail field newer than the minor (one tag past the known ones).
    NewerField,
    /// A length one more than its octets.
    LenPlus,
    /// A sequence with one element more than its bound.
    CountOver,
    /// A string or byte string one octet over its bound (bounds of 64 or
    /// less).
    StringOver,
    /// A string holding the overlong `%xC0 %x80`.
    Utf8Bad,
    /// `bool` as `%x02`.
    BoolTwo,
    /// A NaN other than the canonical one.
    NanPayload,
    /// An open union's arm tag 0.
    ArmTagZero,
    /// A closed union's arm that it doesn't declare.
    ClosedArm,
    /// A closed enum's value that it doesn't declare.
    ClosedEnum,
    /// A closed flags type's bit that it doesn't declare.
    ClosedFlag,
    /// The first capability index one above where it should be.
    CapHigh,
    /// The second capability index repeating the first.
    CapRepeat,
    /// The opening reply's stream ID 0.
    StreamIdZero,
}

/// The interpretive encoder.
pub struct Encoder<'s, 'm> {
    s: &'s Schema<'m>,
    out: Vec<u8>,
    /// Capability indexes written so far.
    caps: u8,
    /// Write each capability's index as its place in the encoding, not as
    /// the value says: how generated vectors number them.
    renumber: bool,
    fault: Option<Fault>,
    fired: bool,
    first_cap: Option<u8>,
}

/// An encoded message: its octets, and the capability count it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    pub octets: Vec<u8>,
    pub caps: u8,
    /// Whether the requested fault applied.
    pub fired: bool,
}

/// Encodes a value as the body `top` describes. Capability indexes are
/// renumbered in encoding order when `renumber` is set.
pub fn encode(s: &Schema<'_>, top: Top, v: &Value, renumber: bool) -> Encoded {
    encode_with(s, top, v, renumber, None)
}

/// [`encode`], with a fault applied at its first chance.
pub fn encode_with(
    s: &Schema<'_>,
    top: Top,
    v: &Value,
    renumber: bool,
    fault: Option<Fault>,
) -> Encoded {
    let mut e = Encoder {
        s,
        out: Vec::new(),
        caps: 0,
        renumber,
        fault,
        fired: false,
        first_cap: None,
    };
    e.top(top, v);
    Encoded {
        octets: e.out,
        caps: e.caps,
        fired: e.fired,
    }
}

impl Encoder<'_, '_> {
    /// Whether the fault applies here; it applies once.
    fn fire(&mut self, f: Fault) -> bool {
        if self.fault == Some(f) && !self.fired {
            self.fired = true;
            true
        } else {
            false
        }
    }

    fn put(&mut self, b: &[u8]) {
        self.out.extend_from_slice(b);
    }

    fn len32(&mut self, n: usize) {
        let mut n = n as u32;
        if self.fire(Fault::LenPlus) {
            n = n.wrapping_add(1);
        }
        self.put(&n.to_be_bytes());
    }

    /// Encodes into a buffer of its own.
    fn sub(&mut self, f: impl FnOnce(&mut Self)) -> Vec<u8> {
        let saved = core::mem::take(&mut self.out);
        f(self);
        core::mem::replace(&mut self.out, saved)
    }

    fn top(&mut self, top: Top, v: &Value) {
        let s = self.s;
        match top {
            Top::Request(i) => self.body(&s.params(i), v),
            Top::Reply(i) => self.body(&s.results(i), v),
            Top::Open(i) => {
                let (id, start, rest) = match v {
                    Value::List(l) if l.len() == 3 => (&l[0], &l[1], &l[2]),
                    _ => return,
                };
                let mut id = match id {
                    Value::Int(n) => *n as u32,
                    _ => OPEN_ID,
                };
                if self.fire(Fault::StreamIdZero) {
                    id = 0;
                }
                self.put(&id.to_be_bytes());
                let start = match start {
                    Value::Int(n) => *n as u64,
                    _ => OPEN_START,
                };
                self.put(&start.to_be_bytes());
                self.body(&s.results(i), rest);
            }
            Top::Item(i) => {
                if let Some(id) = s.item(i) {
                    self.named(id, v);
                }
            }
            Top::Error(i) => self.body(&s.detail(i), v),
            Top::Type(id, _) => self.named(id, v),
        }
    }

    fn body(&mut self, b: &Body<'_>, v: &Value) {
        let Value::Struct(fv) = v else {
            return;
        };
        let fields: Vec<_> = self.s.known_iter(b).collect();
        if b.closed {
            for (f, val) in fields.iter().zip(&fv.known) {
                if f.optional() {
                    match val {
                        None => self.put(&[0]),
                        Some(x) => {
                            self.put(&[1]);
                            self.ty(b.unit, &f.field.ty, x);
                        }
                    }
                } else if let Some(x) = val {
                    self.ty(b.unit, &f.field.ty, x);
                }
            }
            return;
        }
        // The head: required fields, in order.
        for (f, val) in fields.iter().zip(&fv.known) {
            if !f.optional()
                && let Some(x) = val
            {
                self.ty(b.unit, &f.field.ty, x);
            }
        }
        // The tail: present optional fields, then the unknown ones.
        let mut tail: Vec<(u16, Vec<u8>)> = Vec::new();
        for (f, val) in fields.iter().zip(&fv.known) {
            if f.optional()
                && let Some(x) = val
            {
                let octets = self.sub(|e| e.ty(b.unit, &f.field.ty, x));
                tail.push((f.pos, octets));
            }
        }
        tail.extend(fv.unknown.iter().cloned());
        if !tail.is_empty() && self.fire(Fault::TailTagZero) {
            tail[0].0 = 0;
        }
        if tail.len() >= 2 && self.fire(Fault::TailSwap) {
            tail.reverse();
        }
        if !tail.is_empty() && self.fire(Fault::TailDup) {
            let first = tail[0].clone();
            tail.insert(0, first);
        }
        if let Some(req) = fields.iter().find(|f| !f.optional())
            && self.fire(Fault::TailRequired)
        {
            tail.insert(0, (req.pos, vec![0]));
        }
        if self.fire(Fault::NewerField) {
            let next = fields.len() as u16 + 1;
            if tail.last().is_none_or(|t| t.0 < next) {
                tail.push((next, vec![0, 1]));
            }
        }
        self.put(&(tail.len() as u32).to_be_bytes());
        for (tag, octets) in tail {
            self.put(&tag.to_be_bytes());
            self.len32(octets.len());
            self.put(&octets);
        }
    }

    fn named(&mut self, id: TypeId, v: &Value) {
        let s = self.s;
        match s.def(id) {
            Def::Alias(t) => self.ty(id.unit, t, v),
            Def::Struct { .. } => self.body(&s.struct_body(id), v),
            Def::Union { closed, .. } => match v {
                Value::Arm(tag, x) => {
                    let Some(arm) = s.arm(id, *tag) else {
                        return;
                    };
                    if closed {
                        let mut tag = *tag;
                        if self.fire(Fault::ClosedArm) {
                            tag = s.arm_numbers(id).into_iter().max().unwrap_or(0) + 1;
                        }
                        self.put(&tag.to_be_bytes());
                        self.ty(id.unit, arm.ty, x);
                    } else {
                        let mut tag = *tag;
                        if self.fire(Fault::ArmTagZero) {
                            tag = 0;
                        }
                        self.put(&tag.to_be_bytes());
                        let octets = self.sub(|e| e.ty(id.unit, arm.ty, x));
                        self.len32(octets.len());
                        self.put(&octets);
                    }
                }
                Value::UnknownArm(tag, raw) => {
                    self.put(&tag.to_be_bytes());
                    self.len32(raw.len());
                    self.put(raw);
                }
                _ => {}
            },
            Def::Enum {
                flags,
                width,
                closed,
                ..
            } => {
                let mut raw = match v {
                    Value::Enum(x) | Value::Flags(x) => *x,
                    _ => 0,
                };
                if closed && !flags && self.fire(Fault::ClosedEnum) {
                    let declared = s.value_numbers(id);
                    let max = width.range().1 as u64;
                    raw = (0..=max)
                        .rev()
                        .find(|x| !declared.contains(x))
                        .unwrap_or(raw);
                }
                if closed && flags && self.fire(Fault::ClosedFlag) {
                    let mask = s.value_numbers(id).iter().fold(0u64, |m, b| m | b);
                    let bits = 8 * width.octets() as u32;
                    if let Some(b) = (0..bits).rev().find(|b| mask & (1 << b) == 0) {
                        raw |= 1 << b;
                    }
                }
                self.put(&raw.to_be_bytes()[8 - width.octets() as usize..]);
            }
        }
    }

    fn ty(&mut self, u: usize, t: &Type, v: &Value) {
        if t.optional {
            match v {
                Value::Opt(None) => self.put(&[0]),
                Value::Opt(Some(x)) => {
                    self.put(&[1]);
                    self.base(u, t, x);
                }
                // A tail field's value is the bare value.
                x => self.base(u, t, x),
            }
        } else {
            self.base(u, t, v);
        }
    }

    fn base(&mut self, u: usize, t: &Type, v: &Value) {
        let s = self.s;
        match (&t.base, v) {
            (BaseType::Bool, Value::Bool(b)) => {
                let o = if self.fire(Fault::BoolTwo) {
                    2
                } else {
                    u8::from(*b)
                };
                self.put(&[o]);
            }
            (BaseType::Int(w), Value::Int(n)) => {
                let bytes = (*n as u64).to_be_bytes();
                self.put(&bytes[8 - w.octets() as usize..]);
            }
            (BaseType::F32, Value::F32(b)) => {
                let b = if self.fire(Fault::NanPayload) {
                    0x7FC0_0001
                } else {
                    *b
                };
                self.put(&b.to_be_bytes());
            }
            (BaseType::F64, Value::F64(b)) => {
                let b = if self.fire(Fault::NanPayload) {
                    0x7FF8_0000_0000_0001
                } else {
                    *b
                };
                self.put(&b.to_be_bytes());
            }
            (BaseType::Id, Value::Id(id)) => self.put(id),
            (BaseType::Uuid, Value::Uuid(id)) => self.put(id),
            (BaseType::String(b), Value::Text(x)) => {
                let max = s.bound(u, b);
                if self.fire(Fault::Utf8Bad) {
                    self.len32(2);
                    self.put(&[0xC0, 0x80]);
                } else if max <= 64 && self.fire(Fault::StringOver) {
                    self.len32(max as usize + 1);
                    self.put(&vec![b'x'; max as usize + 1]);
                } else {
                    self.len32(x.len());
                    self.put(x.as_bytes());
                }
            }
            (BaseType::Bytes(b), Value::Bytes(x)) => {
                let max = s.bound(u, b);
                if max <= 64 && self.fire(Fault::StringOver) {
                    self.len32(max as usize + 1);
                    self.put(&vec![0x5A; max as usize + 1]);
                } else {
                    self.len32(x.len());
                    self.put(x);
                }
            }
            (BaseType::Seq(e, b), Value::List(items)) => {
                let max = s.bound(u, b);
                if !items.is_empty() && max <= 64 && self.fire(Fault::CountOver) {
                    self.put(&(max as u32 + 1).to_be_bytes());
                    for k in 0..=max as usize {
                        self.ty(u, e, &items[k.min(items.len() - 1)]);
                    }
                } else {
                    self.put(&(items.len() as u32).to_be_bytes());
                    for x in items {
                        self.ty(u, e, x);
                    }
                }
            }
            (BaseType::Array(e, _), Value::List(items)) => {
                for x in items {
                    self.ty(u, e, x);
                }
            }
            (BaseType::Cap(..), Value::Cap(i)) => {
                let mut i = if self.renumber { self.caps } else { *i };
                if self.fire(Fault::CapHigh) {
                    i += 1;
                }
                if self.caps == 1
                    && let Some(first) = self.first_cap
                    && self.fire(Fault::CapRepeat)
                {
                    i = first;
                }
                self.first_cap.get_or_insert(i);
                self.caps += 1;
                self.put(&[i]);
            }
            (BaseType::Slot(..), Value::Slot(x)) => self.put(&x.to_be_bytes()),
            (BaseType::Ref(r), v) => {
                if let Some(id) = s.resolve(u, r) {
                    self.named(id, v);
                }
            }
            // A value that doesn't fit its type writes nothing; decoding
            // it back then fails, which the vector generator reports.
            _ => {}
        }
    }
}

// ---- Decoding -------------------------------------------------------------

struct Decoder<'s, 'm> {
    s: &'s Schema<'m>,
    mode: Mode,
    caps: u8,
    seen_caps: u8,
    too_new_fields: Vec<u16>,
    too_new_value: Option<u16>,
}

/// A cursor over one span of the input.
struct Reader<'i> {
    buf: &'i [u8],
    pos: usize,
}

type R<T> = Result<T, DecodeError>;

impl<'i> Reader<'i> {
    fn take(&mut self, n: usize) -> R<&'i [u8]> {
        let end = self.pos.checked_add(n).ok_or(DecodeError::Malformed)?;
        let b = self.buf.get(self.pos..end).ok_or(DecodeError::Malformed)?;
        self.pos = end;
        Ok(b)
    }

    fn u8(&mut self) -> R<u8> {
        Ok(self.take(1)?[0])
    }

    fn uint(&mut self, n: usize) -> R<u64> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0u64, |v, &b| (v << 8) | u64::from(b)))
    }

    fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// Decodes `input` as the body `top` describes, at the schema's minor,
/// with `caps` capabilities in the message ("Capability indexes").
pub fn decode(s: &Schema<'_>, top: Top, input: &[u8], caps: u8) -> Result<Decoded, DecodeError> {
    let mut d = Decoder {
        s,
        mode: s.mode(top),
        caps,
        seen_caps: 0,
        too_new_fields: Vec::new(),
        too_new_value: None,
    };
    let mut r = Reader { buf: input, pos: 0 };
    let value = d.top(top, &mut r)?;
    // The whole input, and every capability named once.
    if !r.done() || d.seen_caps != caps {
        return Err(DecodeError::Malformed);
    }
    if !d.too_new_fields.is_empty() {
        return Err(DecodeError::FieldTooNew(d.too_new_fields));
    }
    Ok(Decoded {
        value,
        value_too_new: d.too_new_value,
    })
}

impl Decoder<'_, '_> {
    fn too_new(&mut self, since: u16) {
        if self.mode == Mode::Strict {
            self.too_new_value = Some(self.too_new_value.map_or(since, |v| v.max(since)));
        }
    }

    fn top(&mut self, top: Top, r: &mut Reader<'_>) -> R<Value> {
        let s = self.s;
        match top {
            Top::Request(i) => self.body(&s.params(i), r),
            Top::Reply(i) => self.body(&s.results(i), r),
            Top::Open(i) => {
                let id = r.uint(4)?;
                if id == 0 {
                    return Err(DecodeError::Malformed);
                }
                let start = r.uint(8)?;
                let rest = self.body(&s.results(i), r)?;
                Ok(Value::List(vec![
                    Value::Int(i128::from(id)),
                    Value::Int(i128::from(start)),
                    rest,
                ]))
            }
            Top::Item(i) => match s.item(i) {
                Some(id) => self.named(id, r),
                None => Err(DecodeError::Malformed),
            },
            Top::Error(i) => self.body(&s.detail(i), r),
            Top::Type(id, _) => self.named(id, r),
        }
    }

    /// Reads exactly `octets` with `f`.
    fn exact(
        &mut self,
        octets: &[u8],
        f: impl FnOnce(&mut Self, &mut Reader<'_>) -> R<Value>,
    ) -> R<Value> {
        let mut sub = Reader {
            buf: octets,
            pos: 0,
        };
        let v = f(self, &mut sub)?;
        if sub.done() {
            Ok(v)
        } else {
            Err(DecodeError::Malformed)
        }
    }

    fn body(&mut self, b: &Body<'_>, r: &mut Reader<'_>) -> R<Value> {
        let fields: Vec<_> = self.s.known_iter(b).collect();
        let mut known: Vec<Option<Value>> = vec![None; fields.len()];
        if b.closed {
            for (k, f) in fields.iter().enumerate() {
                // An optional field of a closed struct is `presence`, then
                // the value; the value is kept bare, as a tail field's is.
                known[k] = if f.optional() {
                    match r.u8()? {
                        0 => None,
                        1 => Some(self.base(b.unit, &f.field.ty, r)?),
                        _ => return Err(DecodeError::Malformed),
                    }
                } else {
                    Some(self.ty(b.unit, &f.field.ty, false, r)?)
                };
            }
            return Ok(Value::Struct(Fields {
                known,
                unknown: Vec::new(),
            }));
        }
        for (k, f) in fields.iter().enumerate() {
            if !f.optional() {
                known[k] = Some(self.ty(b.unit, &f.field.ty, false, r)?);
            }
        }
        let count = r.uint(4)?;
        if count > 65_535 {
            return Err(DecodeError::Malformed);
        }
        let mut unknown = Vec::new();
        let mut prev = 0u16;
        for _ in 0..count {
            let tag = r.uint(2)? as u16;
            if tag <= prev {
                // Out of order, repeated, or 0.
                return Err(DecodeError::Malformed);
            }
            prev = tag;
            let len = r.uint(4)? as usize;
            let octets = r.take(len)?;
            match fields.get(usize::from(tag) - 1) {
                Some(f) if f.optional() => {
                    let v = self.exact(octets, |d, sub| d.ty(b.unit, &f.field.ty, true, sub))?;
                    known[usize::from(tag) - 1] = Some(v);
                }
                // A required field's position: no alternative matches.
                Some(_) => return Err(DecodeError::Malformed),
                None => match self.mode {
                    Mode::Tolerant => unknown.push((tag, octets.to_vec())),
                    Mode::Strict => {
                        if self.too_new_fields.len() < 8 {
                            self.too_new_fields.push(tag);
                        }
                    }
                },
            }
        }
        Ok(Value::Struct(Fields { known, unknown }))
    }

    fn named(&mut self, id: TypeId, r: &mut Reader<'_>) -> R<Value> {
        let s = self.s;
        match s.def(id) {
            Def::Alias(t) => self.ty(id.unit, t, false, r),
            Def::Struct { .. } => self.body(&s.struct_body(id), r),
            Def::Union { closed, .. } => {
                let tag = r.uint(2)? as u16;
                if tag == 0 {
                    return Err(DecodeError::Malformed);
                }
                let arm = s.arm(id, tag);
                if closed {
                    return match arm {
                        Some(a) if a.known => {
                            let v = self.ty(id.unit, a.ty, false, r)?;
                            Ok(Value::Arm(tag, Box::new(v)))
                        }
                        _ => Err(DecodeError::Malformed),
                    };
                }
                let len = r.uint(4)? as usize;
                let octets = r.take(len)?;
                match arm {
                    Some(a) if a.known => {
                        let ty = a.ty;
                        let v = self.exact(octets, |d, sub| d.ty(id.unit, ty, false, sub))?;
                        Ok(Value::Arm(tag, Box::new(v)))
                    }
                    other => {
                        // Newer than the minor, or unknown to everyone:
                        // raw octets, never read with the arm's type.
                        if let Some(a) = other {
                            self.too_new(a.since.minor);
                        }
                        Ok(Value::UnknownArm(tag, octets.to_vec()))
                    }
                }
            }
            Def::Enum {
                flags,
                width,
                closed,
                ..
            } => {
                let raw = r.uint(width.octets() as usize)?;
                if flags {
                    let (declared, newer) = s.flag_bits(id);
                    if closed && raw & !declared != 0 {
                        return Err(DecodeError::Malformed);
                    }
                    for (bit, since) in newer {
                        if raw & bit != 0 {
                            self.too_new(since);
                        }
                    }
                    Ok(Value::Flags(raw))
                } else {
                    match s.value(id, raw) {
                        Some(v) if !v.known => self.too_new(v.since.minor),
                        Some(_) => {}
                        None if closed => return Err(DecodeError::Malformed),
                        None => {}
                    }
                    Ok(Value::Enum(raw))
                }
            }
        }
    }

    /// A type expression. `in_tail`: the value of an open struct's tail
    /// field, whose `?` the tail carries, so no presence octet.
    fn ty(&mut self, u: usize, t: &Type, in_tail: bool, r: &mut Reader<'_>) -> R<Value> {
        if t.optional && !in_tail {
            return match r.u8()? {
                0 => Ok(Value::Opt(None)),
                1 => Ok(Value::Opt(Some(Box::new(self.base(u, t, r)?)))),
                _ => Err(DecodeError::Malformed),
            };
        }
        self.base(u, t, r)
    }

    fn base(&mut self, u: usize, t: &Type, r: &mut Reader<'_>) -> R<Value> {
        let s = self.s;
        Ok(match &t.base {
            BaseType::Bool => match r.u8()? {
                0 => Value::Bool(false),
                1 => Value::Bool(true),
                _ => return Err(DecodeError::Malformed),
            },
            BaseType::Int(w) => Value::Int(int(*w, r.uint(w.octets() as usize)?)),
            BaseType::F32 => {
                let b = r.uint(4)? as u32;
                if f32::from_bits(b).is_nan() && b != 0x7FC0_0000 {
                    return Err(DecodeError::Malformed);
                }
                Value::F32(b)
            }
            BaseType::F64 => {
                let b = r.uint(8)?;
                if f64::from_bits(b).is_nan() && b != 0x7FF8_0000_0000_0000 {
                    return Err(DecodeError::Malformed);
                }
                Value::F64(b)
            }
            BaseType::Id => {
                let mut id = [0u8; 32];
                id.copy_from_slice(r.take(32)?);
                Value::Id(id)
            }
            BaseType::Uuid => {
                let mut id = [0u8; 16];
                id.copy_from_slice(r.take(16)?);
                Value::Uuid(id)
            }
            BaseType::String(b) => {
                let len = r.uint(4)?;
                if len > s.bound(u, b) {
                    return Err(DecodeError::Malformed);
                }
                let text = core::str::from_utf8(r.take(len as usize)?)
                    .map_err(|_| DecodeError::Malformed)?;
                // UTF-8 without U+0000 (ADR 0062).
                if text.contains('\0') {
                    return Err(DecodeError::Malformed);
                }
                Value::Text(text.into())
            }
            BaseType::Bytes(b) => {
                let len = r.uint(4)?;
                if len > s.bound(u, b) {
                    return Err(DecodeError::Malformed);
                }
                Value::Bytes(r.take(len as usize)?.to_vec())
            }
            BaseType::Seq(e, b) => {
                let n = r.uint(4)?;
                if n > s.bound(u, b) {
                    return Err(DecodeError::Malformed);
                }
                let mut items = Vec::new();
                for _ in 0..n {
                    items.push(self.ty(u, e, false, r)?);
                }
                Value::List(items)
            }
            BaseType::Array(e, b) => {
                let mut items = Vec::new();
                for _ in 0..s.bound(u, b) {
                    items.push(self.ty(u, e, false, r)?);
                }
                Value::List(items)
            }
            BaseType::Cap(..) => {
                // Indexes ascend in encoding order, each once, all below
                // the count ("Capability indexes").
                let i = r.u8()?;
                if i != self.seen_caps || i >= self.caps {
                    return Err(DecodeError::Malformed);
                }
                self.seen_caps += 1;
                Value::Cap(i)
            }
            BaseType::Slot(..) => Value::Slot(r.uint(8)?),
            BaseType::Ref(rf) => match s.resolve(u, rf) {
                Some(id) => self.named(id, r)?,
                None => return Err(DecodeError::Malformed),
            },
        })
    }
}

/// An integer of a width, read as its type reads it.
fn int(w: IntType, raw: u64) -> i128 {
    if w.signed() {
        let bits = 64 - 8 * w.octets() as u32;
        i128::from(((raw << bits) as i64) >> bits)
    } else {
        i128::from(raw)
    }
}

// ---- JSON ----------------------------------------------------------------

/// Writes a decoded value's JSON, as the schema's minor reads it (ADR
/// 0067, rule 8): a request's parameters or a reply's results as one
/// object, keys in declaration order, `[sensitive]` fields and slots as
/// `null` under their keys, absent optional fields omitted, and unknown
/// members as `"@<tag>"` with their octets in base64url.
pub fn to_json(s: &Schema<'_>, top: Top, v: &Value, w: &mut JsonWriter<'_>) {
    let j = Json { s };
    match top {
        Top::Request(i) => j.body(&s.params(i), v, w),
        Top::Reply(i) => j.body(&s.results(i), v, w),
        Top::Open(i) => {
            if let Value::List(l) = v
                && let Some(rest) = l.get(2)
            {
                j.body(&s.results(i), rest, w);
            }
        }
        Top::Item(i) => {
            if let Some(id) = s.item(i) {
                j.named(id, v, w);
            }
        }
        Top::Error(i) => j.body(&s.detail(i), v, w),
        Top::Type(id, _) => j.named(id, v, w),
    }
}

struct Json<'s, 'm> {
    s: &'s Schema<'m>,
}

impl Json<'_, '_> {
    fn body(&self, b: &Body<'_>, v: &Value, w: &mut JsonWriter<'_>) {
        let Value::Struct(fv) = v else {
            w.null();
            return;
        };
        w.begin_object();
        for (f, val) in self.s.known_iter(b).zip(&fv.known) {
            if f.redacted() {
                w.key(&f.field.name.name);
                w.null();
                continue;
            }
            let Some(x) = val else {
                continue;
            };
            w.key(&f.field.name.name);
            self.ty(b.unit, &f.field.ty, f.json(), x, w);
        }
        for (tag, raw) in &fv.unknown {
            w.tag_key(*tag);
            w.bytes(raw);
        }
        w.end_object();
    }

    fn named(&self, id: TypeId, v: &Value, w: &mut JsonWriter<'_>) {
        let s = self.s;
        match s.def(id) {
            Def::Alias(t) => self.ty(id.unit, t, false, v, w),
            Def::Struct { .. } => self.body(&s.struct_body(id), v, w),
            Def::Union { .. } => {
                w.begin_object();
                match v {
                    Value::Arm(tag, x) => {
                        if let Some(a) = s.arm(id, *tag) {
                            w.key(a.name);
                            let json = crate::ast::has_attr(a.attrs, "format");
                            self.ty(id.unit, a.ty, json, x, w);
                        }
                    }
                    Value::UnknownArm(tag, raw) => {
                        w.tag_key(*tag);
                        w.bytes(raw);
                    }
                    _ => {}
                }
                w.end_object();
            }
            Def::Enum { flags, width, .. } => {
                match v {
                    Value::Enum(x) => match s.value(id, *x).filter(|k| k.known) {
                        Some(k) => w.string(k.name),
                        None => w.uint(*x),
                    },
                    Value::Flags(x) if flags => {
                        // At most 64 bits.
                        let values = s.values(id);
                        let mut known: Vec<_> = values.iter().filter(|k| k.known).collect();
                        known.sort_by_key(|k| k.value);
                        w.begin_array();
                        let mut rest = *x;
                        for k in known {
                            if x & k.value != 0 {
                                w.string(k.name);
                                rest &= !k.value;
                            }
                        }
                        if rest != 0 {
                            if width == IntType::U64 {
                                w.u64_string(rest);
                            } else {
                                w.uint(rest);
                            }
                        }
                        w.end_array();
                    }
                    _ => w.null(),
                }
            }
        }
    }

    fn ty(&self, u: usize, t: &Type, json: bool, v: &Value, w: &mut JsonWriter<'_>) {
        if let Value::Opt(o) = v {
            match o {
                None => w.null(),
                Some(x) => self.base(u, t, json, x, w),
            }
            return;
        }
        self.base(u, t, json, v, w);
    }

    fn base(&self, u: usize, t: &Type, json: bool, v: &Value, w: &mut JsonWriter<'_>) {
        match (&t.base, v) {
            (BaseType::Bool, Value::Bool(b)) => w.bool(*b),
            (BaseType::Int(i), Value::Int(n)) => match i {
                IntType::U64 => w.u64_string(*n as u64),
                IntType::I64 => w.i64_string(*n as i64),
                _ if i.signed() => w.int(*n as i64),
                _ => w.uint(*n as u64),
            },
            (BaseType::F32, Value::F32(b)) => w.f32(f32::from_bits(*b)),
            (BaseType::F64, Value::F64(b)) => w.f64(f64::from_bits(*b)),
            (BaseType::Id, Value::Id(id)) => w.id(id),
            (BaseType::Uuid, Value::Uuid(id)) => w.uuid(id),
            (BaseType::String(_), Value::Text(x)) if json => w.embedded(x),
            (BaseType::String(_), Value::Text(x)) => w.string(x),
            (BaseType::Bytes(_), Value::Bytes(x)) => w.bytes(x),
            (BaseType::Seq(e, _) | BaseType::Array(e, _), Value::List(items)) => {
                w.begin_array();
                for x in items {
                    self.ty(u, e, false, x, w);
                }
                w.end_array();
            }
            (BaseType::Cap(..), Value::Cap(i)) => w.cap(*i),
            (BaseType::Slot(..), _) => w.null(),
            (BaseType::Ref(r), v) => match self.s.resolve(u, r) {
                Some(id) => self.named(id, v, w),
                None => w.null(),
            },
            _ => w.null(),
        }
    }
}
