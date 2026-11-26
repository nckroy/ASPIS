// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The vectors of each generated grammar, generated whole (ADR 0013, rule
//! 6; ADR 0062, rule 8; docs/design/call-language.md, "Generated
//! grammars", "Evolution vectors").
//!
//! For every rule a minor's grammar names, the generator builds sample
//! values: a minimal one, one with every optional present and small
//! contents, and one variant per feature (each optional present and
//! absent, each known arm, enum value and flag bit, integer extremes,
//! strings, byte strings, sequences, floats), plus, where the type is
//! open, an unknown tail field, arm, enum value or flag bits. Each is
//! encoded, decoded back, and must re-encode to the same octets: those are
//! the `ok` lines.
//!
//! Then it corrupts them, once per kind of [`Fault`], and truncates and
//! extends them. Each corruption's tag comes from crates/abnf's two
//! judgments: `err` when the context-free grammar rejects it, `errc` when
//! only a constraint does. The dynamic decoder must reject exactly what the
//! constrained grammar rejects, or generation fails: so generation finds
//! grammar and decoder bugs, and the Python checker stays an independent
//! judge of every line. A corruption the grammar accepts is dropped.
//!
//! The text vectors are the same values' JSON, in their text rules, and
//! corruptions of them that the text grammar rejects.

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec,
    vec::Vec,
};
use core::cell::Cell;

use abnf::{Context, Exhausted, Grammar, RuleId};
use idl_rt::json::JsonWriter;

use crate::{
    ast::{BaseType, Type},
    model::TypeId,
    schema::{Body, Def, Mode, Schema, Top},
    value::{self, Encoded, Fault, Fields, OPEN_ID, OPEN_START, Value},
};

/// The longest vector line written.
pub const MAX_LINE: usize = 4096;

/// One `ok` vector and the value behind it.
#[derive(Debug, Clone)]
pub struct Sample {
    pub top: Top,
    pub value: Value,
    pub octets: Vec<u8>,
    pub caps: u8,
}

/// A vector line before it is written.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Line {
    tag: &'static str,
    rule: String,
    octets: Vec<u8>,
    caps: u8,
    unwrapped: u8,
}

/// Every fault kind the generator applies to each rule's samples.
const FAULTS: [Fault; 18] = [
    Fault::TailSwap,
    Fault::TailDup,
    Fault::TailTagZero,
    Fault::TailRequired,
    Fault::NewerField,
    Fault::LenPlus,
    Fault::CountOver,
    Fault::StringOver,
    Fault::Utf8Bad,
    Fault::BoolTwo,
    Fault::NanPayload,
    Fault::ArmTagZero,
    Fault::ClosedArm,
    Fault::ClosedEnum,
    Fault::ClosedFlag,
    Fault::CapHigh,
    Fault::CapRepeat,
    Fault::StreamIdZero,
];

/// A corruption kind, for the coverage check: a fault, or a generic one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Fault(Fault),
    Truncate,
    Extend,
    CapUnnamed,
}

// ---- Sample values ---------------------------------------------------------

/// The most values one rule's samples may make, in all. A type the
/// checker accepts can still have a minimal value of millions of values,
/// or billions: a fixed-size array of arrays, a struct whose two fields
/// are the struct below it, 32 deep, or a struct of 4096 optional fields,
/// each of whose variants is a copy of the rest. So a rule's samples stop
/// at the budget, and those already complete are kept. Vector lines are
/// at most [`MAX_LINE`] characters anyway.
///
/// A value's cost is what it allocates ([`cost`]): each value, each
/// element of a list, and each slot of a struct, present or absent. So
/// the budget bounds the memory a rule's samples hold, not only how many
/// values they hold.
pub const BUDGET: usize = 1 << 16;

/// The most values the samples of one file may make, every rule of every
/// minor together. A file declares up to 4096 types and methods, each
/// with rules of its own, and up to 65,536 minors, so a budget for each
/// rule alone, or each minor, would still let a small file cost hours and
/// gigabytes. One [`Budget`] serves all of a file's minors.
pub const FILE_BUDGET: usize = 1 << 18;

/// The most steps that matching one file's samples and corruptions
/// against their grammars may take, every grammar of every minor
/// together (crates/abnf's steps, [`Grammar::matches_within`]). A
/// sample's value budget says nothing about its match: an enum of 4096
/// values is one value, and its rule an alternation of 4096.
pub const STEPS: u64 = 1 << 26;

/// What one file's vectors may still cost, shared by all its minors: the
/// values its samples may make ([`FILE_BUDGET`]) and the steps its
/// matches may take ([`STEPS`]). Once either runs out, the budget is
/// spent: the minor being generated keeps the vectors already made, its
/// samples are still matched while steps are left, and every later minor
/// gets none.
#[derive(Debug)]
pub struct Budget {
    values: Cell<usize>,
    steps: Cell<u64>,
    /// The values ran out.
    no_values: Cell<bool>,
    /// The steps ran out.
    no_steps: Cell<bool>,
}

impl Default for Budget {
    fn default() -> Self {
        Budget::new(FILE_BUDGET, STEPS)
    }
}

impl Budget {
    /// A budget of `values` values and `steps` steps.
    pub fn new(values: usize, steps: u64) -> Self {
        Budget {
            values: Cell::new(values),
            steps: Cell::new(steps),
            no_values: Cell::new(false),
            no_steps: Cell::new(false),
        }
    }

    /// Values left.
    pub fn values(&self) -> usize {
        self.values.get()
    }

    /// Steps left.
    pub fn steps(&self) -> u64 {
        self.steps.get()
    }

    /// Whether either has run out.
    pub fn is_spent(&self) -> bool {
        self.no_values.get() || self.no_steps.get()
    }

    /// Takes `n` values: false, and spent, when fewer are left.
    fn take(&self, n: usize) -> bool {
        let left = self.values.get();
        if self.no_values.get() || n > left {
            self.no_values.set(true);
            return false;
        }
        self.values.set(left - n);
        true
    }

    /// Takes what a minor generated before cost, if all of it is left.
    pub(crate) fn charge(&self, values: usize, steps: u64) -> bool {
        if self.is_spent() || values > self.values.get() || steps > self.steps.get() {
            return false;
        }
        self.values.set(self.values.get() - values);
        self.steps.set(self.steps.get() - steps);
        true
    }

    /// A match against a grammar, its steps taken from the budget: None
    /// once the steps are spent, or when this match spends them. A match
    /// over crates/abnf's own limits for one match is an error.
    pub fn matches(
        &self,
        g: &Grammar,
        r: RuleId,
        octets: &[u8],
        cx: Option<&Context>,
    ) -> Result<Option<bool>, Exhausted> {
        if self.no_steps.get() {
            return Ok(None);
        }
        let mut left = self.steps.get();
        let got = g.matches_within(r, octets, cx, &mut left);
        self.steps.set(left);
        match got {
            Err(Exhausted::Steps) if left == 0 => {
                self.no_steps.set(true);
                Ok(None)
            }
            Err(e) => Err(e),
            Ok(v) => Ok(Some(v)),
        }
    }
}

struct Gen<'s, 'm> {
    s: &'s Schema<'m>,
    /// Values left to make for this rule.
    budget: Cell<usize>,
    /// What the whole file may still cost, shared by every rule's
    /// generator, in every minor.
    file: &'s Budget,
    /// A budget ran out: every value made since may hold a placeholder.
    spent: Cell<bool>,
}

/// What a value costs the budget: itself, and everything it holds, each
/// of a struct's slots included, whether its field is present or not.
/// The octets of a string or byte string are at most 64.
pub fn cost(v: &Value) -> usize {
    1 + match v {
        Value::List(l) => l.iter().map(cost).sum(),
        Value::Opt(Some(b)) | Value::Arm(_, b) => cost(b),
        Value::Struct(f) => {
            f.known.len() + f.unknown.len() + f.known.iter().flatten().map(cost).sum::<usize>()
        }
        _ => 0,
    }
}

/// A string of `n` octets, cut at a character boundary.
fn cut(text: &str, n: u64) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if (out.len() + c.len_utf8()) as u64 > n {
            break;
        }
        out.push(c);
    }
    out
}

fn pattern<const N: usize>() -> [u8; N] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(1))
}

impl<'s, 'm> Gen<'s, 'm> {
    fn new(s: &'s Schema<'m>, file: &'s Budget) -> Self {
        Gen {
            s,
            budget: Cell::new(BUDGET),
            file,
            spent: Cell::new(false),
        }
    }

    /// Spends `n` values of the rule's budget and the file's: false once
    /// either has run out.
    fn spend(&self, n: usize) -> bool {
        let b = self.budget.get();
        if self.spent.get() || n > b || !self.file.take(n) {
            self.spent.set(true);
            return false;
        }
        self.budget.set(b - n);
        true
    }

    /// Keeps a finished sample, if the budget lasted while it was made:
    /// false once it has run out, when the caller stops.
    fn keep(&self, out: &mut Vec<Value>, v: Value) -> bool {
        if !self.spend(1) {
            return false;
        }
        out.push(v);
        true
    }

    /// A copy of `v`, paid for; a placeholder once the budget is gone.
    fn copy(&self, v: &Value) -> Value {
        if self.spend(cost(v)) {
            v.clone()
        } else {
            Value::Bool(false)
        }
    }

    /// `n` copies of `v` as a list, paid for.
    fn list(&self, v: Value, n: usize) -> Value {
        if self.spend(cost(&v).saturating_mul(n)) {
            Value::List(vec![v; n])
        } else {
            Value::Bool(false)
        }
    }

    /// A tag no field of the body declares at any minor.
    fn free_tail_tag(&self, b: &Body<'_>) -> u16 {
        (b.fields.len() + 1).min(65_535) as u16
    }

    /// A struct's slots, paid for before they are made: false once the
    /// budget is gone, when the caller makes a placeholder instead.
    fn slots(&self, b: &Body<'_>) -> bool {
        self.spend(self.s.known_count(b))
    }

    fn minimal_body(&self, b: &Body<'_>) -> Value {
        if !self.slots(b) {
            return Value::Bool(false);
        }
        let known = self
            .s
            .known_fields(b)
            .iter()
            .map(|f| (!f.optional()).then(|| self.minimal(b.unit, &f.field.ty)))
            .collect();
        Value::Struct(Fields {
            known,
            unknown: Vec::new(),
        })
    }

    fn full_body(&self, b: &Body<'_>) -> Value {
        if !self.slots(b) {
            return Value::Bool(false);
        }
        let known = self
            .s
            .known_fields(b)
            .iter()
            .map(|f| Some(self.full(b.unit, &f.field.ty)))
            .collect();
        Value::Struct(Fields {
            known,
            unknown: Vec::new(),
        })
    }

    /// A body's samples: minimal, full, and each field's variants with
    /// the rest minimal; with an unknown tail field when read tolerantly.
    fn body_samples(&self, b: &Body<'_>, mode: Mode) -> Vec<Value> {
        let mut out = Vec::new();
        let min = self.minimal_body(b);
        if !self.keep(&mut out, self.copy(&min)) {
            return out;
        }
        let full = self.full_body(b);
        if !self.keep(&mut out, full) {
            return out;
        }
        for (k, f) in self.s.known_fields(b).iter().enumerate() {
            let mut vs: Vec<Option<Value>> = self
                .variants(b.unit, &f.field.ty)
                .into_iter()
                .map(Some)
                .collect();
            if f.optional() {
                vs.push(None);
            }
            for v in vs {
                let Value::Struct(mut fv) = self.copy(&min) else {
                    return out;
                };
                fv.known[k] = v;
                if !self.keep(&mut out, Value::Struct(fv)) {
                    return out;
                }
            }
        }
        if mode == Mode::Tolerant && !b.closed {
            let full = self.full_body(b);
            for v in [min, full] {
                if let Value::Struct(mut fv) = v {
                    if !self.spend(1) {
                        return out;
                    }
                    fv.unknown.push((self.free_tail_tag(b), vec![0x01, 0x02]));
                    if !self.keep(&mut out, Value::Struct(fv)) {
                        return out;
                    }
                }
            }
        }
        out
    }

    /// The smallest value of a type expression, without its `?`.
    fn minimal(&self, u: usize, t: &Type) -> Value {
        let s = self.s;
        if !self.spend(1) {
            return Value::Bool(false);
        }
        match &t.base {
            BaseType::Bool => Value::Bool(false),
            BaseType::Int(_) => Value::Int(0),
            BaseType::F32 => Value::F32(0),
            BaseType::F64 => Value::F64(0),
            BaseType::Id => Value::Id([0; 32]),
            BaseType::Uuid => Value::Uuid([0; 16]),
            BaseType::String(_) => Value::Text(String::new()),
            BaseType::Bytes(_) => Value::Bytes(Vec::new()),
            BaseType::Seq(..) => Value::List(Vec::new()),
            BaseType::Array(e, b) => self.list(self.minimal_elem(u, e), s.bound(u, b) as usize),
            BaseType::Cap(..) => Value::Cap(0),
            BaseType::Slot(..) => Value::Slot(0),
            BaseType::Ref(r) => match s.resolve(u, r) {
                Some(id) => self.minimal_named(id),
                None => Value::Bool(false),
            },
        }
    }

    fn minimal_elem(&self, u: usize, t: &Type) -> Value {
        if t.optional {
            Value::Opt(None)
        } else {
            self.minimal(u, t)
        }
    }

    fn minimal_named(&self, id: TypeId) -> Value {
        let s = self.s;
        match s.def(id) {
            Def::Alias(t) => self.minimal_elem(id.unit, t),
            Def::Struct { .. } => self.minimal_body(&s.struct_body(id)),
            Def::Union { .. } => match s.arms(id).into_iter().find(|a| a.known) {
                Some(a) => Value::Arm(a.tag, Box::new(self.minimal_elem(id.unit, a.ty))),
                None => Value::UnknownArm(self.free_arm(id), vec![0x01]),
            },
            Def::Enum { flags: true, .. } => Value::Flags(0),
            Def::Enum { .. } => match s.values(id).into_iter().find(|v| v.known) {
                Some(v) => Value::Enum(v.value),
                None => Value::Enum(self.free_value(id)),
            },
        }
    }

    /// A value with every optional present and small contents.
    fn full(&self, u: usize, t: &Type) -> Value {
        let s = self.s;
        if !self.spend(1) {
            return Value::Bool(false);
        }
        match &t.base {
            BaseType::Bool => Value::Bool(true),
            BaseType::Int(_) => Value::Int(1),
            BaseType::F32 => Value::F32(1.5f32.to_bits()),
            BaseType::F64 => Value::F64(1.5f64.to_bits()),
            BaseType::Id => Value::Id(pattern()),
            BaseType::Uuid => Value::Uuid(pattern()),
            BaseType::String(b) => Value::Text(cut("aspis", s.bound(u, b))),
            BaseType::Bytes(b) => {
                let n = s.bound(u, b).min(3) as usize;
                Value::Bytes([0x00, 0xFF, 0x41][..n].to_vec())
            }
            BaseType::Seq(e, _) => Value::List(vec![self.full_elem(u, e)]),
            BaseType::Array(e, b) => self.list(self.full_elem(u, e), s.bound(u, b) as usize),
            BaseType::Cap(..) => Value::Cap(0),
            BaseType::Slot(..) => Value::Slot(7),
            // A named type inside a full value is kept small: its own rule's
            // vectors vary it. Deeply nested values make the context-free
            // grammar's many readings explode in the Python checker, which
            // backtracks (docs/design/call-language.md, "Generated
            // grammars").
            BaseType::Ref(r) => match s.resolve(u, r) {
                Some(id) => self.nested(id),
                None => Value::Bool(false),
            },
        }
    }

    /// A named type inside a full value: a struct minimal, a union's last
    /// arm minimal, an enum's last value, all of a flags type's bits.
    fn nested(&self, id: TypeId) -> Value {
        let s = self.s;
        match s.def(id) {
            Def::Alias(t) => self.full_elem(id.unit, t),
            Def::Struct { .. } => self.minimal_named(id),
            Def::Union { .. } => match s.arms(id).into_iter().rev().find(|a| a.known) {
                Some(a) => Value::Arm(a.tag, Box::new(self.minimal_elem(id.unit, a.ty))),
                None => Value::UnknownArm(self.free_arm(id), vec![0x01]),
            },
            Def::Enum { .. } => self.full_named(id),
        }
    }

    fn full_elem(&self, u: usize, t: &Type) -> Value {
        if t.optional {
            Value::Opt(Some(Box::new(self.full(u, t))))
        } else {
            self.full(u, t)
        }
    }

    fn full_named(&self, id: TypeId) -> Value {
        let s = self.s;
        match s.def(id) {
            Def::Alias(t) => self.full_elem(id.unit, t),
            Def::Struct { .. } => self.full_body(&s.struct_body(id)),
            Def::Union { .. } => match s.arms(id).into_iter().rev().find(|a| a.known) {
                Some(a) => Value::Arm(a.tag, Box::new(self.full_elem(id.unit, a.ty))),
                None => Value::UnknownArm(self.free_arm(id), vec![0x01]),
            },
            Def::Enum { flags: true, .. } => Value::Flags(
                s.values(id)
                    .iter()
                    .filter(|v| v.known)
                    .fold(0, |m, v| m | v.value),
            ),
            Def::Enum { .. } => match s.values(id).into_iter().rev().find(|v| v.known) {
                Some(v) => Value::Enum(v.value),
                None => Value::Enum(self.free_value(id)),
            },
        }
    }

    /// An arm tag no minor declares.
    fn free_arm(&self, id: TypeId) -> u16 {
        let max = self.s.arm_numbers(id).into_iter().max().unwrap_or(0);
        max.saturating_add(1).max(1)
    }

    /// An enum value no minor declares: the largest free one.
    fn free_value(&self, id: TypeId) -> u64 {
        let Def::Enum { width, .. } = self.s.def(id) else {
            return 0;
        };
        let declared = self.s.value_numbers(id);
        let max = width.range().1 as u64;
        (0..=max)
            .rev()
            .take(1024)
            .find(|v| !declared.contains(v))
            .unwrap_or(max)
    }

    /// One variant per feature of a type expression where it stands (a
    /// field's bare value for a field, which carries the `?` itself).
    fn variants(&self, u: usize, t: &Type) -> Vec<Value> {
        let s = self.s;
        let mut out = Vec::new();
        if !self.spend(1) {
            return out;
        }
        match &t.base {
            BaseType::Bool => out.extend([Value::Bool(false), Value::Bool(true)]),
            BaseType::Int(w) => {
                let (lo, hi) = w.range();
                out.extend([Value::Int(lo), Value::Int(hi), Value::Int(1)]);
            }
            BaseType::F32 => out.extend(
                [
                    0.0f32.to_bits(),
                    (-0.0f32).to_bits(),
                    0x7FC0_0000,
                    f32::INFINITY.to_bits(),
                    f32::NEG_INFINITY.to_bits(),
                    1.5f32.to_bits(),
                ]
                .map(Value::F32),
            ),
            BaseType::F64 => out.extend(
                [
                    0.0f64.to_bits(),
                    (-0.0f64).to_bits(),
                    0x7FF8_0000_0000_0000,
                    f64::INFINITY.to_bits(),
                    f64::NEG_INFINITY.to_bits(),
                    1.5f64.to_bits(),
                ]
                .map(Value::F64),
            ),
            BaseType::Id => out.extend([Value::Id([0; 32]), Value::Id(pattern())]),
            BaseType::Uuid => out.extend([Value::Uuid([0; 16]), Value::Uuid(pattern())]),
            BaseType::String(b) => {
                let n = s.bound(u, b);
                for text in ["", "aspis", "\u{1F600}", "a\"\\\n\u{1}/\u{e9}"] {
                    if text.len() as u64 <= n {
                        out.push(Value::Text(text.into()));
                    }
                }
                if n <= 64 {
                    out.push(Value::Text("x".repeat(n as usize)));
                }
            }
            BaseType::Bytes(b) => {
                let n = s.bound(u, b);
                out.push(Value::Bytes(Vec::new()));
                out.push(Value::Bytes(
                    [0x00, 0xFF, 0x41][..n.min(3) as usize].to_vec(),
                ));
                if n <= 64 {
                    out.push(Value::Bytes(vec![0xA5; n as usize]));
                }
            }
            BaseType::Seq(e, b) => {
                let n = s.bound(u, b) as usize;
                let min = self.minimal_elem(u, e);
                out.push(Value::List(Vec::new()));
                out.push(Value::List(vec![self.copy(&min)]));
                if n >= 2 {
                    out.push(Value::List(vec![self.copy(&min), self.full_elem(u, e)]));
                }
                if n <= 4 {
                    out.push(self.list(min, n));
                }
            }
            BaseType::Array(e, b) => {
                let n = s.bound(u, b) as usize;
                out.push(self.list(self.minimal_elem(u, e), n));
                out.push(self.list(self.full_elem(u, e), n));
            }
            BaseType::Cap(..) => out.push(Value::Cap(0)),
            BaseType::Slot(..) => out.extend([Value::Slot(0), Value::Slot(u64::MAX)]),
            BaseType::Ref(r) => {
                if let Some(id) = s.resolve(u, r) {
                    out.extend(self.named_variants(id, false));
                }
            }
        }
        out
    }

    /// A named type's variants. `deep`: as the top of its own rule, so a
    /// struct's or union's members vary too; otherwise only its minimal
    /// and full values, each arm, and each value. Each is kept only if the
    /// budget lasted while it was made.
    fn named_variants(&self, id: TypeId, deep: bool) -> Vec<Value> {
        let s = self.s;
        let mut out = Vec::new();
        if !self.spend(1) {
            return out;
        }
        let mut vs = Vec::new();
        match s.def(id) {
            Def::Alias(t) => {
                let opt = t.optional;
                for v in self.variants(id.unit, t) {
                    vs.push(if opt {
                        Value::Opt(Some(Box::new(v)))
                    } else {
                        v
                    });
                }
                if opt {
                    vs.push(Value::Opt(None));
                }
            }
            Def::Struct { .. } if deep => {
                let mode = Mode::Tolerant;
                return self.body_samples(&s.struct_body(id), mode);
            }
            Def::Struct { .. } => {
                let min = self.minimal_named(id);
                if !self.keep(&mut out, min) {
                    return out;
                }
                vs.push(self.full_named(id));
            }
            Def::Union { closed, .. } => {
                for a in s.arms(id).into_iter().filter(|a| a.known) {
                    let mut arm = vec![
                        self.minimal_elem(id.unit, a.ty),
                        self.full_elem(id.unit, a.ty),
                    ];
                    if deep {
                        arm.extend(self.variants(id.unit, a.ty).into_iter().map(|v| {
                            if a.ty.optional {
                                Value::Opt(Some(Box::new(v)))
                            } else {
                                v
                            }
                        }));
                    }
                    for v in arm {
                        if !self.keep(&mut out, Value::Arm(a.tag, Box::new(v))) {
                            return out;
                        }
                    }
                }
                if !closed {
                    vs.push(Value::UnknownArm(self.free_arm(id), vec![0x01, 0x02]));
                }
            }
            Def::Enum {
                flags: false,
                closed,
                ..
            } => {
                for v in s.values(id).into_iter().filter(|v| v.known) {
                    vs.push(Value::Enum(v.value));
                }
                if !closed {
                    vs.push(Value::Enum(self.free_value(id)));
                }
            }
            Def::Enum {
                flags: true,
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
                vs.push(Value::Flags(0));
                vs.extend(known.iter().map(|&b| Value::Flags(b)));
                vs.push(Value::Flags(known.iter().fold(0, |m, b| m | b)));
                if !closed {
                    let declared = s.value_numbers(id).iter().fold(0u64, |m, b| m | b);
                    let bits = 8 * width.octets() as u32;
                    if let Some(b) = (0..bits).rev().find(|b| declared & (1 << b) == 0) {
                        vs.push(Value::Flags(1 << b));
                    }
                }
            }
        }
        for v in vs {
            if !self.keep(&mut out, v) {
                break;
            }
        }
        out
    }

    /// Every sample of a top-level rule.
    fn samples(&self, top: Top) -> Vec<Value> {
        let s = self.s;
        let mode = s.mode(top);
        match top {
            Top::Request(i) => self.body_samples(&s.params(i), mode),
            Top::Reply(i) => self.body_samples(&s.results(i), mode),
            Top::Open(i) => self
                .body_samples(&s.results(i), mode)
                .into_iter()
                .take(2)
                .map(|v| {
                    Value::List(vec![
                        Value::Int(i128::from(OPEN_ID)),
                        Value::Int(i128::from(OPEN_START)),
                        v,
                    ])
                })
                .collect(),
            Top::Item(i) => match s.item(i) {
                Some(id) => self.named_variants(id, false),
                None => Vec::new(),
            },
            Top::Error(i) => self.body_samples(&s.detail(i), mode),
            Top::Type(id, mode) => match s.def(id) {
                Def::Struct { .. } => self.body_samples(&s.struct_body(id), mode),
                _ => self.named_variants(id, true),
            },
        }
    }
}

// ---- Labeling -------------------------------------------------------------

/// The samples of every rule of a schema: encoded, decoded back, and
/// re-encoded identically. A sample that doesn't round-trip is a bug in
/// the codec, reported as an error. They take their values from the
/// file's `budget`, and a minor that starts with it spent gets none.
pub fn samples(s: &Schema<'_>, budget: &Budget) -> Result<Vec<Sample>, String> {
    let mut out = Vec::new();
    if budget.is_spent() {
        return Ok(out);
    }
    for top in s.tops() {
        let mut seen = BTreeSet::new();
        // Each rule has its own budget, and all share the file's.
        let g = Gen::new(s, budget);
        let vs = g.samples(top);
        for v in vs {
            let enc = value::encode(s, top, &v, true);
            let dec = value::decode(s, top, &enc.octets, enc.caps).map_err(|e| {
                format!(
                    "{}: a sample doesn't decode ({e:?}): {}",
                    s.top_rule(top),
                    escape(&enc.octets)
                )
            })?;
            let again = value::encode(s, top, &dec.value, false);
            if again.octets != enc.octets {
                return Err(format!(
                    "{}: a sample re-encodes differently: {}",
                    s.top_rule(top),
                    escape(&enc.octets)
                ));
            }
            if seen.insert((enc.octets.clone(), enc.caps)) {
                out.push(Sample {
                    top,
                    value: dec.value,
                    octets: enc.octets,
                    caps: enc.caps,
                });
            }
        }
    }
    Ok(out)
}

/// The grammar's two judgments of a line, context-free and constrained,
/// their steps taken from the budget: None once it is spent.
fn judge(
    g: &Grammar,
    rule: &str,
    octets: &[u8],
    caps: u8,
    budget: &Budget,
) -> Result<Option<(bool, bool)>, String> {
    let r = g
        .rule(rule)
        .ok_or_else(|| format!("the grammar has no rule {rule}"))?;
    let at = |e: Exhausted| format!("{rule}: {e}");
    let Some(cf) = budget.matches(g, r, octets, None).map_err(at)? else {
        return Ok(None);
    };
    if !cf {
        return Ok(Some((false, false)));
    }
    let cx = Context { caps, unwrapped: 0 };
    Ok(budget
        .matches(g, r, octets, Some(&cx))
        .map_err(at)?
        .map(|full| (true, full)))
}

/// Each rule's place among a schema's rules, found once: a file may have
/// thousands of rules and a million samples.
fn ranks(tops: &[Top]) -> BTreeMap<Top, usize> {
    let mut out = BTreeMap::new();
    for (i, &t) in tops.iter().enumerate() {
        out.entry(t).or_insert(i);
    }
    out
}

/// The samples of each rule, in their order.
fn by_top(samples: &[Sample]) -> BTreeMap<Top, Vec<&Sample>> {
    let mut out: BTreeMap<Top, Vec<&Sample>> = BTreeMap::new();
    for x in samples {
        out.entry(x.top).or_default().push(x);
    }
    out
}

/// The wire vectors of a schema's minor, against its loaded grammar. The
/// matches take their steps from the file's `budget`; once it is spent,
/// the lines already judged are kept and no more are made.
pub fn wire(
    s: &Schema<'_>,
    g: &Grammar,
    samples: &[Sample],
    budget: &Budget,
) -> Result<Vec<String>, String> {
    let mut lines: Vec<(usize, Line)> = Vec::new();
    let mut fired: BTreeSet<Kind> = BTreeSet::new();
    let mut kept: BTreeSet<Kind> = BTreeSet::new();
    let tops = s.tops();
    let order = ranks(&tops);
    let order = |t: Top| order.get(&t).copied().unwrap_or(usize::MAX);
    let mut by_top = by_top(samples);
    'rules: for &top in &tops {
        let mut mine: Vec<&Sample> = by_top.remove(&top).unwrap_or_default();
        let rule = s.top_rule(top);
        for sample in &mine {
            let Some((_, full)) = judge(g, &rule, &sample.octets, sample.caps, budget)? else {
                break 'rules;
            };
            if !full {
                return Err(format!(
                    "{rule}: the grammar rejects an encoding the decoder accepts: {}",
                    escape(&sample.octets)
                ));
            }
            let line = Line {
                tag: "ok",
                rule: rule.clone(),
                octets: sample.octets.clone(),
                caps: sample.caps,
                unwrapped: 0,
            };
            lines.push((order(top), line.clone()));
            if sample.caps > 0 {
                // A position delivered unwrapped still has its index.
                lines.push((
                    order(top),
                    Line {
                        unwrapped: 1,
                        ..line
                    },
                ));
            }
        }

        // Corruptions: each fault on up to two samples of the rule where
        // it applies, and the generic ones on its first two samples.
        // Shortest first, so corruptions stay small: the context-free
        // reading of a long corrupt line is slow to rule out.
        mine.sort_by_key(|x| x.octets.len());
        let mut candidates: Vec<(Kind, Vec<u8>, u8)> = Vec::new();
        for f in FAULTS {
            let mut n = 0;
            for x in &mine {
                let Encoded {
                    octets,
                    caps,
                    fired,
                } = value::encode_with(s, top, &x.value, false, Some(f));
                if fired {
                    candidates.push((Kind::Fault(f), octets, caps));
                    n += 1;
                    if n == 2 {
                        break;
                    }
                }
            }
        }
        for x in mine.iter().take(2) {
            if !x.octets.is_empty() {
                let mut t = x.octets.clone();
                t.pop();
                candidates.push((Kind::Truncate, t, x.caps));
            }
            let mut e = x.octets.clone();
            e.push(0);
            candidates.push((Kind::Extend, e, x.caps));
        }
        if let Some(x) = mine.iter().find(|x| x.caps > 0 && x.caps < 3) {
            candidates.push((Kind::CapUnnamed, x.octets.clone(), x.caps + 1));
        }
        for (kind, octets, caps) in candidates {
            let Some((cf, full)) = judge(g, &rule, &octets, caps, budget)? else {
                break 'rules;
            };
            fired.insert(kind);
            let accepted = value::decode(s, top, &octets, caps).is_ok();
            if accepted != full {
                return Err(format!(
                    "{rule}: the decoder {} what the grammar {} ({kind:?}): {}",
                    if accepted { "accepts" } else { "rejects" },
                    if full { "accepts" } else { "rejects" },
                    escape(&octets)
                ));
            }
            if full {
                continue;
            }
            kept.insert(kind);
            lines.push((
                order(top),
                Line {
                    tag: if cf { "errc" } else { "err" },
                    rule: rule.clone(),
                    octets,
                    caps,
                    unwrapped: 0,
                },
            ));
        }
    }

    // Every kind of corruption that applied somewhere is rejected
    // somewhere. A newer field is accepted where reading is tolerant. A
    // spent budget cut the samples or their corruptions short, so it says
    // nothing about the rest.
    if !budget.is_spent() {
        for k in &fired {
            if !kept.contains(k) && *k != Kind::Fault(Fault::NewerField) {
                return Err(format!("no corruption of kind {k:?} was rejected"));
            }
        }
    }
    Ok(render(lines))
}

/// Writes lines grouped by rule, `ok` first, with the `# caps:` and
/// `# unwrapped:` directives they need.
fn render(mut lines: Vec<(usize, Line)>) -> Vec<String> {
    lines.sort_by(|a, b| {
        (a.0, a.1.tag != "ok", a.1.caps, a.1.unwrapped).cmp(&(
            b.0,
            b.1.tag != "ok",
            b.1.caps,
            b.1.unwrapped,
        ))
    });
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let (mut caps, mut unwrapped) = (0u8, 0u8);
    for (_, l) in lines {
        let text = format!("{}@{}\t{}", l.tag, l.rule, escape(&l.octets));
        if text.len() > MAX_LINE || !seen.insert((text.clone(), l.caps, l.unwrapped)) {
            continue;
        }
        if l.caps != caps || (unwrapped != 0 && l.unwrapped == 0) {
            out.push(format!("# caps: {}", l.caps));
            caps = l.caps;
            unwrapped = 0;
        }
        if l.unwrapped != unwrapped {
            out.push(format!("# unwrapped: {:x}", l.unwrapped));
            unwrapped = l.unwrapped;
        }
        out.push(text);
    }
    out
}

/// A vector's body: printable ASCII as itself, `\\` and `\t`, and every
/// other octet as `\xHH`. In text vectors, UTF-8 sequences stay escaped
/// too, so the files are ASCII.
pub fn escape(octets: &[u8]) -> String {
    let mut s = String::new();
    for &b in octets {
        match b {
            b'\\' => s.push_str("\\\\"),
            b'\t' => s.push_str("\\t"),
            0x20..=0x7E => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s
}

// ---- Text vectors -----------------------------------------------------------

/// The ID the text vectors call methods on.
const TARGET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The most octets of JSON one sample may write.
const MAX_JSON: usize = 1 << 16;

fn json(s: &Schema<'_>, top: Top, v: &Value, buf: &mut [u8]) -> Result<String, String> {
    let mut w = JsonWriter::new(buf);
    value::to_json(s, top, v, &mut w);
    let out = w.finish().map_err(|_| String::from("JSON over 64 KiB"))?;
    String::from_utf8(out.to_vec()).map_err(|_| String::from("JSON isn't UTF-8"))
}

/// The text vectors of a schema's minor, from the wire samples, against
/// the loaded text grammar. The matches take their steps from the file's
/// `budget`, as [`wire`]'s do.
pub fn text(
    s: &Schema<'_>,
    g: &Grammar,
    samples: &[Sample],
    budget: &Budget,
) -> Result<Vec<String>, String> {
    let unit = s.model.unit(s.root);
    let target = if s.is_kernel() { "-" } else { TARGET };
    let tops = s.tops();
    let order = ranks(&tops);
    let order = |t: Top| order.get(&t).copied().unwrap_or(usize::MAX);
    let ok = |o: usize, rule: String, text: String| {
        (
            o,
            Line {
                tag: "ok",
                rule,
                octets: text.into_bytes(),
                caps: 0,
                unwrapped: 0,
            },
        )
    };
    let mut buf = vec![0u8; MAX_JSON];
    let mut lines: Vec<(usize, Line)> = Vec::new();
    let mut rejected = 0;
    let mut by_top = by_top(samples);
    // Each rule's lines come from one top-level rule's samples.
    'rules: for &top in &tops {
        let mine = by_top.remove(&top).unwrap_or_default();
        let o = order(top);
        let mut these: Vec<(usize, Line)> = Vec::new();
        let mut methods_done = BTreeSet::new();
        for x in mine {
            let j = json(s, x.top, &x.value, &mut buf)?;
            let m = |i: usize| crate::schema::kebab(s.member_name(i));
            let action = |i: usize| format!("{}/{}/{}", unit.name, unit.major(), s.member_name(i));
            match x.top {
                Top::Request(i) => {
                    these.push(ok(o, format!("m-{}--args", m(i)), j.clone()));
                    let call = format!("m-{}--call", m(i));
                    these.push(ok(o, call.clone(), format!("{} {target} {j}", action(i))));
                    if methods_done.insert((i, 0)) {
                        // Arguments are opt-in (ADR 0063, rule 8).
                        these.push(ok(o, call, format!("{} {target}", action(i))));
                    }
                }
                Top::Reply(i) => {
                    these.push(ok(o, format!("m-{}--results", m(i)), j.clone()));
                    let reply = format!("m-{}--reply", m(i));
                    these.push(ok(o, reply.clone(), format!("ok {j}")));
                    if methods_done.insert((i, 1)) {
                        these.push(ok(o, reply.clone(), "ok".into()));
                        for e in s.error_list(i) {
                            let text = format!("failed {}/{}!{e}", unit.name, unit.major());
                            these.push(ok(o, reply.clone(), text));
                        }
                        these.push(ok(o, reply.clone(), "refused aspis.rpc/1!malformed".into()));
                        these.push(ok(o, reply, format!("indeterminate {TARGET}/1!#17")));
                    }
                }
                // The opening reply's JSON is the reply's results.
                Top::Open(_) => {}
                _ => these.push(ok(o, s.top_rule(x.top), j)),
            }
        }
        // Every ok line matches its rule, constraints included.
        for (k, (_, l)) in these.iter().enumerate() {
            let Some((_, full)) = judge(g, &l.rule, &l.octets, 0, budget)? else {
                lines.extend(these.into_iter().take(k));
                break 'rules;
            };
            if !full {
                return Err(format!(
                    "{}: the text grammar rejects the JSON the mapping writes: {}",
                    l.rule,
                    escape(&l.octets)
                ));
            }
        }
        // Corruptions of each rule's first two lines with a JSON value.
        let mut firsts: Vec<(usize, String, String)> = Vec::new();
        for (o, l) in &these {
            let text = String::from_utf8_lossy(&l.octets).into_owned();
            let n = firsts.iter().filter(|f| f.1 == l.rule).count();
            if n < 2 && text.contains(['{', '[', '"']) {
                firsts.push((*o, l.rule.clone(), text));
            }
        }
        lines.append(&mut these);
        for (o, rule, text) in firsts {
            for bad in text_faults(&text) {
                let Some((cf, full)) = judge(g, &rule, bad.as_bytes(), 0, budget)? else {
                    break 'rules;
                };
                if full {
                    continue;
                }
                rejected += 1;
                lines.push((
                    o,
                    Line {
                        tag: if cf { "errc" } else { "err" },
                        rule: rule.clone(),
                        octets: bad.into_bytes(),
                        caps: 0,
                        unwrapped: 0,
                    },
                ));
            }
        }
    }
    if rejected == 0 && !lines.is_empty() && !budget.is_spent() {
        return Err("no corruption of the text was rejected".into());
    }
    Ok(render(lines))
}

/// Corruptions of a text line: insignificant whitespace, uppercase, a
/// number where a string of digits belongs, a value where a redacted
/// `null` belongs, a number above its bound, and two keys swapped.
fn text_faults(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(i) = text.find(['{', '[', ':']) {
        out.push(format!("{} {}", &text[..=i], &text[i + 1..]));
    }
    for (from, to) in [
        ("ok", "OK"),
        ("true", "True"),
        ("null", "Null"),
        ("false", "FALSE"),
    ] {
        if let Some(i) = text.find(from) {
            out.push(format!("{}{to}{}", &text[..i], &text[i + from.len()..]));
        }
    }
    // A quoted run of digits, unquoted.
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            let j = b[i + 1..]
                .iter()
                .position(|&c| c == b'"')
                .map(|j| i + 1 + j);
            if let Some(j) = j {
                if j > i + 1 && b[i + 1..j].iter().all(u8::is_ascii_digit) {
                    out.push(format!(
                        "{}{}{}",
                        &text[..i],
                        &text[i + 1..j],
                        &text[j + 1..]
                    ));
                    break;
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    if let Some(i) = text.find(":null") {
        out.push(format!("{}:\"x\"{}", &text[..i], &text[i + 5..]));
    }
    // A bare number, made too large for any bound below 2^64.
    let mut i = 0;
    let mut quoted = false;
    while i < b.len() {
        match b[i] {
            b'"' => quoted = !quoted,
            b'\\' if quoted => i += 1,
            c if !quoted
                && c.is_ascii_digit()
                && i > 0
                && matches!(b[i - 1], b':' | b',' | b'[') =>
            {
                let j = b[i..]
                    .iter()
                    .position(|c| !c.is_ascii_digit())
                    .map_or(b.len(), |j| i + j);
                out.push(format!("{}99999999999999999999{}", &text[..i], &text[j..]));
                break;
            }
            _ => {}
        }
        i += 1;
    }
    if let Some(sw) = swap_first_keys(text) {
        out.push(sw);
    }
    out
}

/// The text with its first object's first two members swapped.
fn swap_first_keys(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let b = text.as_bytes();
    // Member boundaries at depth 1 of that object.
    let mut depth = 0;
    let mut quoted = false;
    let mut commas = Vec::new();
    let mut end = None;
    let mut i = start;
    while i < b.len() {
        let c = b[i];
        if quoted {
            if c == b'\\' {
                i += 1;
            } else if c == b'"' {
                quoted = false;
            }
        } else {
            match c {
                b'"' => quoted = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                b',' if depth == 1 => commas.push(i),
                _ => {}
            }
        }
        i += 1;
    }
    let end = end?;
    let first = &text[start + 1..*commas.first()?];
    let second = &text[commas[0] + 1..*commas.get(1).unwrap_or(&end)];
    let rest = &text[*commas.get(1).unwrap_or(&end)..];
    Some(format!("{}{second},{first}{rest}", &text[..=start]))
}
