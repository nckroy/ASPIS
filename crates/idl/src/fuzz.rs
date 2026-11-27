// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Fuzz support (ADR 0068, rules 3 to 5; docs/design/call-language.md,
//! "Back ends", row 7, "Engine and tools", "The gate for each target").
//!
//! C71's harness wraps these in libFuzzer targets inside `fuzz/`, its own
//! workspace. Nothing here depends on `arbitrary` or any fuzz crate, even
//! behind `cfg(fuzzing)`: a target dependency would still enter the
//! product's `Cargo.lock`, which rule 3 keeps free of fuzz dependencies.
//! The functions are plain and public, so the crates' replay tests run
//! them under `cargo test` over every vector line and over mutations.
//!
//! - [`front_end`]: the IDL front end, projection, the canonical form and
//!   the compatibility check, as the catalog runs them on publishers'
//!   files. It panics only when a property breaks.
//! - [`generate`]: a structured value generator, driven by raw octets:
//!   any input gives a value that encodes to a valid message of the rule,
//!   unless the rule's smallest value is too large to make.
//!   C71 may wrap it in `arbitrary` inside `fuzz/`.
//! - The decoders' targets are each generated module's `fuzz::decode` and
//!   [`crate::conformance::differential`].

use alloc::{boxed::Box, collections::BTreeSet, string::String, vec, vec::Vec};

use idl_rt::names::InterfaceRef;

use crate::{
    Checked, Limits,
    ast::{BaseType, File, Type},
    canon, compat, doc,
    model::TypeId,
    project,
    schema::{Body, Def, Mode, Schema, Top},
    value::{Fields, Value},
};

/// The IDL front end's fuzz target ("Trust-boundary parsers": the IDL
/// front end, projection and compatibility checker). Imports resolve to
/// nothing, so a file with a `use` line stops at the checker.
///
/// Properties: nothing panics; for a file that checks, each visited
/// minor's canonical form parses back, checks, and gives itself again,
/// and projecting it again changes nothing (ADR 0067, rule 7). It visits
/// the minors [`minors`] picks, a bounded number, so its work stays a
/// fixed multiple of the file's, whatever minor the file declares.
pub fn front_end(data: &[u8]) {
    front_end_with(data, &mut |_: &InterfaceRef<'_>| None);
}

/// [`front_end`], with imports resolved by `resolve`, as the catalog
/// resolves them from its registered interfaces. A canonical form names
/// its imports as the file does, so it resolves through the same
/// resolver.
pub fn front_end_with(data: &[u8], resolve: &mut crate::model::Resolver<'_>) {
    let limits = Limits::default();
    let Ok(c) = crate::check(data, resolve, &limits) else {
        return;
    };
    let _ = doc::model(&c);
    let mut prev: Option<(u16, File)> = None;
    for m in minors(&c) {
        let p = project::project(c.file(), m);
        let canon = canon::canonical(&p);
        let back = match crate::check(canon.as_bytes(), resolve, &limits) {
            Ok(b) => b,
            Err(d) => panic!("minor {m}'s canonical form doesn't check: {d:?}\n{canon}"),
        };
        assert!(
            canon::canonical(back.file()) == canon,
            "minor {m}'s canonical form isn't stable:\n{canon}"
        );
        assert!(
            canon::canonical(&project::project(back.file(), m)) == canon,
            "projecting minor {m}'s canonical form again changes it:\n{canon}"
        );
        let _ = crate::hash::sha3_256(canon.as_bytes());
        // A file's own minors may still break the step rules; that is a
        // diagnostic for its author, not a broken property.
        if let Some((k, prev)) = &prev
            && *k + 1 == m
        {
            let _ = compat::step(prev, &p);
        }
        prev = Some((m, p));
    }
}

/// The most `since` and `deprecated` minors [`front_end`] visits in one
/// file: the lowest half and the highest half of them.
pub const MINORS: usize = 8;

/// The minors [`front_end`] visits, in order: 0, the file's version and
/// the minor before it, and up to [`MINORS`] of the minors at which a
/// projection changes, each with the minor before it for the step check.
/// A projection changes only at a minor some `since` or `deprecated`
/// names; between them, only the header's version moves. So a file that
/// declares `version(1.1023)` costs a few passes, not 1,024.
pub fn minors(c: &Checked) -> Vec<u16> {
    let v = c.unit().version.minor;
    let major = c.unit().major();
    let changes: Vec<u16> = project::changes(c.file(), major)
        .into_iter()
        .filter(|&k| k > 0 && k <= v)
        .collect();
    let half = MINORS / 2;
    let picked = if changes.len() <= MINORS {
        changes
    } else {
        let mut p = changes[..half].to_vec();
        p.extend_from_slice(&changes[changes.len() - half..]);
        p
    };
    let mut out = BTreeSet::from([0, v, v.saturating_sub(1)]);
    for k in picked {
        out.insert(k);
        out.insert(k - 1);
    }
    out.into_iter().collect()
}

/// Octets read as choices. Past the end every choice is 0, which is
/// always the smallest: an absent optional, an empty sequence, the first
/// arm.
struct Src<'d> {
    data: &'d [u8],
    pos: usize,
    /// Values left to make before every choice is the smallest, so a value
    /// stays small whatever the input.
    budget: usize,
}

impl Src<'_> {
    fn byte(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        if self.budget == 0 { 0 } else { b }
    }

    fn u64(&mut self) -> u64 {
        (0..8).fold(0, |v, _| v << 8 | u64::from(self.byte()))
    }

    /// A number below `n`, or 0.
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.u64() % n }
    }

    fn flag(&mut self) -> bool {
        self.byte() & 1 == 1
    }
}

/// The most values one generated message holds, before every choice is
/// the smallest. Fixed-size arrays and required fields still take their
/// full count, up to [`MAX_VALUES`].
pub const BUDGET: usize = 256;

/// The most values [`generate`] makes for one message, whatever its
/// input, counted as [`crate::vectors::cost`] counts them: each value,
/// and each slot of a struct, present or absent. A type the checker
/// accepts can still have a smallest value of millions: an array of 4000
/// arrays of 4000 octets, or a struct whose two fields are the struct
/// below it, 23 deep. Such a rule gets no value.
pub const MAX_VALUES: usize = 1 << 16;
/// The longest string, byte string or sequence generated, short of its
/// bound.
const MAX_LEN: u64 = 32;
const MAX_COUNT: u64 = 4;

/// A value of `top` at the schema's minor, chosen by `data`. Any input
/// gives a value that the dynamic codec encodes (with capability indexes
/// renumbered) into a message the rule accepts: it holds only what is
/// known at the minor, except unknown enum values, flag bits and union
/// arms of open types, and, in a tolerant rule, unknown tail fields.
/// None when the value would hold more than [`MAX_VALUES`] values.
pub fn generate(s: &Schema<'_>, top: Top, data: &[u8]) -> Option<Value> {
    let mut g = Gen {
        s,
        src: Src {
            data,
            pos: 0,
            budget: BUDGET,
        },
        mode: s.mode(top),
        made: 0,
    };
    let v = g.top(top);
    (g.made <= MAX_VALUES).then_some(v)
}

struct Gen<'s, 'm, 'd> {
    s: &'s Schema<'m>,
    src: Src<'d>,
    mode: Mode,
    /// Values made, struct slots included; past [`MAX_VALUES`], every
    /// value made is a placeholder, and the result is thrown away.
    made: usize,
}

impl Gen<'_, '_, '_> {
    fn top(&mut self, top: Top) -> Value {
        let s = self.s;
        match top {
            Top::Request(i) => self.body(&s.params(i)),
            Top::Reply(i) => self.body(&s.results(i)),
            Top::Open(i) => {
                // A stream ID is never 0 ("Stream messages").
                let id = self.src.below(u64::from(u32::MAX)) + 1;
                let start = self.src.u64();
                Value::List(vec![
                    Value::Int(i128::from(id)),
                    Value::Int(i128::from(start)),
                    self.body(&s.results(i)),
                ])
            }
            Top::Item(i) => match s.item(i) {
                Some(id) => self.named(id),
                None => Value::Struct(Fields::default()),
            },
            Top::Error(i) => self.body(&s.detail(i)),
            Top::Type(id, _) => self.named(id),
        }
    }

    /// Counts `n` values made: false once over [`MAX_VALUES`].
    fn make(&mut self, n: usize) -> bool {
        self.made = self.made.saturating_add(n);
        self.made <= MAX_VALUES
    }

    /// Spends a value of the choice budget; false once over
    /// [`MAX_VALUES`].
    fn spend(&mut self) -> bool {
        self.src.budget = self.src.budget.saturating_sub(1);
        self.make(1)
    }

    fn body(&mut self, b: &Body<'_>) -> Value {
        let s = self.s;
        if !self.spend() || !self.make(s.known_count(b)) {
            return Value::Bool(false);
        }
        let mut known = Vec::new();
        for f in s.known_fields(b) {
            if self.made > MAX_VALUES {
                return Value::Bool(false);
            }
            known.push(if f.optional() && !self.src.flag() {
                None
            } else {
                Some(crate::vectors::nonzero(&f, self.bare(b.unit, &f.field.ty)))
            });
        }
        // Unknown tail fields, in a tolerant rule's open body: tags past
        // every field any minor declares, ascending.
        let mut unknown = Vec::new();
        if self.mode == Mode::Tolerant && !b.closed {
            let first = (b.fields.len() + 1).min(65_000) as u16;
            let n = self.src.below(3);
            for k in 0..n as u16 {
                let len = self.src.below(4) as usize;
                let octets = (0..len).map(|_| self.src.byte()).collect();
                unknown.push((first + 2 * k + (self.src.byte() & 1) as u16, octets));
            }
        }
        Value::Struct(Fields { known, unknown })
    }

    /// A type expression where `?` is the container's: an element, an
    /// alias's target, an arm.
    fn elem(&mut self, u: usize, t: &Type) -> Value {
        if t.optional {
            if self.src.flag() {
                Value::Opt(Some(Box::new(self.bare(u, t))))
            } else {
                Value::Opt(None)
            }
        } else {
            self.bare(u, t)
        }
    }

    /// A type expression's value, without its `?`.
    fn bare(&mut self, u: usize, t: &Type) -> Value {
        if !self.spend() {
            return Value::Bool(false);
        }
        let s = self.s;
        match &t.base {
            BaseType::Bool => Value::Bool(self.src.flag()),
            BaseType::Int(w) => {
                let (lo, hi) = w.range();
                let span = (hi - lo + 1) as u128;
                let x = u128::from(self.src.u64()) % span;
                Value::Int(lo + x as i128)
            }
            BaseType::F32 => {
                let b = self.src.u64() as u32;
                // One NaN encoding (ADR 0062, rule 2).
                Value::F32(if f32::from_bits(b).is_nan() {
                    0x7FC0_0000
                } else {
                    b
                })
            }
            BaseType::F64 => {
                let b = self.src.u64();
                Value::F64(if f64::from_bits(b).is_nan() {
                    0x7FF8_0000_0000_0000
                } else {
                    b
                })
            }
            BaseType::Id => Value::Id(core::array::from_fn(|_| self.src.byte())),
            BaseType::Uuid => Value::Uuid(core::array::from_fn(|_| self.src.byte())),
            BaseType::String(b) => {
                let max = s.bound(u, b).min(MAX_LEN);
                let want = self.src.below(max + 1);
                let mut text = String::new();
                while (text.len() as u64) < want {
                    // ASCII without U+0000, and now and then a two- or
                    // four-octet character, when it fits.
                    let c = match self.src.byte() {
                        0 => 'a',
                        b @ 1..=0x7F => char::from(b),
                        0x80..=0xBF => '\u{e9}',
                        _ => '\u{1F600}',
                    };
                    if text.len() as u64 + c.len_utf8() as u64 > want {
                        break;
                    }
                    text.push(c);
                }
                Value::Text(text)
            }
            BaseType::Bytes(b) => {
                let n = self.src.below(s.bound(u, b).min(MAX_LEN) + 1);
                Value::Bytes((0..n).map(|_| self.src.byte()).collect())
            }
            BaseType::Seq(e, b) => {
                let n = self.src.below(s.bound(u, b).min(MAX_COUNT) + 1);
                Value::List((0..n).map(|_| self.elem(u, e)).collect())
            }
            BaseType::Array(e, b) => {
                let mut out = Vec::new();
                for _ in 0..s.bound(u, b) {
                    if self.made > MAX_VALUES {
                        break;
                    }
                    out.push(self.elem(u, e));
                }
                Value::List(out)
            }
            // The encoder numbers capabilities in encoding order.
            BaseType::Cap(..) => Value::Cap(0),
            BaseType::Slot(..) => Value::Slot(self.src.u64()),
            BaseType::Ref(r) => match s.resolve(u, r) {
                Some(id) => self.named(id),
                None => Value::Bool(false),
            },
        }
    }

    fn named(&mut self, id: TypeId) -> Value {
        if !self.spend() {
            return Value::Bool(false);
        }
        let s = self.s;
        match s.def(id) {
            Def::Alias(t) => self.elem(id.unit, t),
            Def::Struct { .. } => self.body(&s.struct_body(id)),
            Def::Union { closed, .. } => {
                let known: Vec<_> = s.arms(id).into_iter().filter(|a| a.known).collect();
                let pick = self.src.below(known.len() as u64 + u64::from(!closed)) as usize;
                match known.get(pick) {
                    Some(a) => Value::Arm(a.tag, Box::new(self.elem(id.unit, a.ty))),
                    None => {
                        // An arm unknown at the minor: any tag but 0 and
                        // the known ones.
                        let mut tag = self.src.below(65_535) as u16 + 1;
                        while known.iter().any(|a| a.tag == tag) {
                            tag = tag.wrapping_add(1).max(1);
                        }
                        let len = self.src.below(4) as usize;
                        Value::UnknownArm(tag, (0..len).map(|_| self.src.byte()).collect())
                    }
                }
            }
            Def::Enum {
                flags,
                width,
                closed,
                ..
            } => {
                let known: Vec<u64> = s
                    .values(id)
                    .iter()
                    .filter(|v| v.known)
                    .map(|v| v.value)
                    .collect();
                let max = width.range().1 as u64;
                if flags {
                    let bits = if closed {
                        known.iter().fold(0, |m, b| m | b)
                    } else {
                        max
                    };
                    Value::Flags(self.src.u64() & bits)
                } else if closed || (self.src.flag() && !known.is_empty()) {
                    let k = self.src.below(known.len() as u64) as usize;
                    Value::Enum(known.get(k).copied().unwrap_or(0))
                } else {
                    // Any value, known or not, of an open enum.
                    Value::Enum(self.src.u64() & max)
                }
            }
        }
    }
}
