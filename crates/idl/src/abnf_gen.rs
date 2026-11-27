// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The ABNF back end: each minor's wire grammar and canonical-text grammar
//! (ADR 0067, rule 9; ADR 0013, rule 3; docs/design/call-language.md,
//! "Generated grammars", "The struct encoding").
//!
//! Both grammars use only C06's constraint vocabulary, so both checkers
//! load them strictly. The wire grammar says `; uses: core`; the text
//! grammar `; uses: core, names, json`.
//!
//! Rule names are one to one with what they name:
//!
//! - `t-<type>` is a type's tolerant form; `r-<type>` its strict form, for
//!   requests, made only for a type that holds an open struct through
//!   members known at the minor. `m-<method>--req`, `--rep`, `--open` and
//!   `--item` are a method's bodies; `e-<error>` an error's detail. An
//!   imported type's rules carry the prefix `u<k>--`, k being its `use`
//!   line's place, 1-based, in the file projected to the minor
//!   ([`crate::schema::Schema::units`]).
//! - `<rule>--<member>` is a field, parameter or arm.
//! - Helpers take a third hyphen: `---tail`, `---opt`, `---unknown`,
//!   `---unknown-tag`, `---len`, `---body`, `---count`, `---elem`,
//!   `---value`, `---o<k>`, and in text grammars `---digits`, `---neg`,
//!   `---number`, `---bits`, `---unknowns`, `---a<k>` and `---b<k>`. A
//!   member name starts with a letter and never holds `__`, so no member
//!   name makes one.
//!
//! A length-prefixed value (an open union's arm, or a tail field whose
//! size varies) is `%x<tag> X---len X---body`, where `X---body` is always
//! exactly one rule reference and carries `exactly X---len octets`: its
//! target is then its whole match. A value whose size is fixed takes its
//! literal length instead.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::{
    ast::{self, BaseType, IntType, Type},
    layout::Facts,
    model::TypeId,
    schema::{Body, Def, Fld, Mode, Schema, Top, kebab},
};

/// The rules of one generated grammar, in the order they are defined.
struct Rules {
    text: String,
    defined: BTreeSet<String>,
}

impl Rules {
    fn new() -> Rules {
        Rules {
            text: String::new(),
            defined: BTreeSet::new(),
        }
    }

    /// Defines a rule, once.
    fn def(&mut self, name: &str, body: &str, constraints: &[String]) {
        let at = self.text.len();
        self.def_at(at, name, body, constraints);
    }

    /// Defines a rule at an earlier place in the text: a rule goes before
    /// the helpers it was defined after, so a grammar reads top down.
    fn def_at(&mut self, at: usize, name: &str, body: &str, constraints: &[String]) {
        if !self.defined.insert(name.to_string()) {
            return;
        }
        let mut r = format!("{name} = {body}\n");
        for c in constraints {
            r.push_str("    ; constraint: ");
            r.push_str(c);
            r.push('\n');
        }
        self.text.insert_str(at, &r);
    }

    /// Where the next rule goes.
    fn mark(&self) -> usize {
        self.text.len()
    }

    fn comment(&mut self, c: &str) {
        self.text.push_str("\n; ");
        self.text.push_str(c);
        self.text.push('\n');
    }
}

/// `%xHH.HH`: a value's octets as a literal.
fn lit(octets: &[u8]) -> String {
    let mut s = String::from("%x");
    for (i, b) in octets.iter().enumerate() {
        if i > 0 {
            s.push('.');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// A value's facts where it stands, `?` included: `presence` then the
/// value, for an optional outside an open struct.
fn facts_of(s: &Schema<'_>, u: usize, t: &Type) -> Facts {
    let f = s.facts(u, t);
    if t.optional {
        Facts {
            min: 1,
            max: f.max.saturating_add(1),
            fixed: false,
            ..f
        }
    } else {
        f
    }
}

/// The describing comment of a top-level rule.
fn describe(s: &Schema<'_>, top: Top) -> String {
    let m = |i: usize| format!("method {} \"{}\"", s.method(i).ordinal, s.member_name(i));
    match top {
        Top::Request(i) if s.mode(top) == Mode::Strict => format!("{}: the request, strict", m(i)),
        Top::Request(i) => format!(
            "{}: the request, read tolerantly (the kernel sends it)",
            m(i)
        ),
        Top::Reply(i) => format!("{}: the reply", m(i)),
        Top::Open(i) => format!(
            "{}: the opening reply: its stream ID, start position and reply struct",
            m(i)
        ),
        Top::Item(i) => format!("{}: a stream item", m(i)),
        Top::Error(i) => format!("error \"{}\": its detail", s.member_name(i)),
        Top::Type(id, Mode::Strict) => format!("{}, strict", s.type_name(id)),
        Top::Type(id, Mode::Tolerant) => s.type_name(id).to_string(),
    }
}

// ---- The wire grammar ----------------------------------------------------

/// The wire grammar of the schema's minor, after `preamble` (comment
/// lines, ending with a line feed).
pub fn wire(s: &Schema<'_>, preamble: &str) -> String {
    let mut w = Wire {
        s,
        r: Rules::new(),
        pending: Vec::new(),
    };
    for top in s.tops() {
        w.r.comment(&describe(s, top));
        w.top(top);
    }
    if !w.pending.is_empty() {
        w.r.comment("types the use lines import, read at the minor each names");
        w.drain();
    }
    let mut out = String::from(preamble);
    out.push_str(&w.r.text);
    out
}

struct Wire<'s, 'm> {
    s: &'s Schema<'m>,
    r: Rules,
    pending: Vec<(TypeId, Mode)>,
}

impl Wire<'_, '_> {
    fn top(&mut self, top: Top) {
        let s = self.s;
        let name = s.top_rule(top);
        match top {
            Top::Request(i) => self.body(&name, &s.params(i), s.mode(top)),
            Top::Reply(i) => self.body(&name, &s.results(i), Mode::Tolerant),
            Top::Open(i) => {
                let rep = s.top_rule(Top::Reply(i));
                self.r.def(&name, &format!("{name}---id u64 {rep}"), &[]);
                self.r
                    .def(&format!("{name}---id"), "u32", &["not 0".into()]);
            }
            Top::Item(i) => {
                if let Some(id) = s.item(i) {
                    let t = self.named(id, Mode::Tolerant);
                    self.r.def(&name, &t, &[]);
                }
            }
            Top::Error(i) => self.body(&name, &s.detail(i), Mode::Tolerant),
            Top::Type(id, mode) => self.emit(id, mode),
        }
    }

    /// Emits every type the rules so far refer to.
    fn drain(&mut self) {
        while let Some((id, mode)) = self.pending.pop() {
            self.emit(id, mode);
        }
    }

    /// A named type's rule name, queued for emission.
    fn named(&mut self, id: TypeId, mode: Mode) -> String {
        let mode = if self.s.has_strict(id) {
            mode
        } else {
            Mode::Tolerant
        };
        let name = self.s.type_rule(id, mode);
        if !self.r.defined.contains(&name) {
            self.pending.push((id, mode));
        }
        name
    }

    fn emit(&mut self, id: TypeId, mode: Mode) {
        let s = self.s;
        let mode = if s.has_strict(id) {
            mode
        } else {
            Mode::Tolerant
        };
        let name = s.type_rule(id, mode);
        if self.r.defined.contains(&name) {
            return;
        }
        match s.def(id) {
            Def::Alias(t) => {
                let e = self.elem(id.unit, t, &name, mode);
                if e != name {
                    self.r.def(&name, &e, &[]);
                }
            }
            Def::Struct { .. } => self.body(&name, &s.struct_body(id), mode),
            Def::Union { closed, .. } => self.union(&name, id, closed, mode),
            Def::Enum {
                flags,
                width,
                closed,
                ..
            } => self.enumeration(&name, id, flags, width, closed),
        }
    }

    /// An open or closed struct ("The struct encoding").
    fn body(&mut self, name: &str, b: &Body<'_>, mode: Mode) {
        let s = self.s;
        let at = self.r.mark();
        let fields = s.known_fields(b);
        let mut head = Vec::new();
        if b.closed {
            for f in &fields {
                let fname = format!("{name}--{}", kebab(&f.field.name.name));
                head.push(self.field(b.unit, f, &fname, mode));
            }
            let body = if head.is_empty() {
                "0OCTET".to_string()
            } else {
                head.join(" ")
            };
            self.r.def_at(at, name, &body, &[]);
            return;
        }
        let mut opts = Vec::new();
        for f in &fields {
            let fname = format!("{name}--{}", kebab(&f.field.name.name));
            if f.optional() {
                let at = self.r.mark();
                let def =
                    self.prefixed(&fname, f.pos, b.unit, &f.field.ty, true, f.nonzero(), mode);
                self.r.def_at(at, &fname, &def, &[]);
                opts.push(fname);
            } else {
                head.push(self.field(b.unit, f, &fname, mode));
            }
        }
        // The position after the last field known at the minor, so an
        // unknown tag is never a required field's position. Its range is
        // also written context-free, so a known tag never matches the
        // unknown alternative: fewer readings for a backtracking checker.
        // The constraint says the same.
        let p = fields.len() + 1;
        if mode == Mode::Tolerant
            && let Some(range) = u16_ranges(&[(p as u32, 65_535)])
        {
            let unknown = format!("{name}---unknown");
            self.r.def(&unknown, &format!("{unknown}-tag octets"), &[]);
            self.r.def(
                &format!("{unknown}-tag"),
                &range,
                &[format!("at least {p}")],
            );
            opts.push(unknown);
        }
        // A strict tail holds at most one of each known optional field.
        let tail_max = if mode == Mode::Tolerant {
            u64::from(u32::MAX)
        } else {
            opts.len() as u64
        };
        if opts.is_empty() {
            // A strict struct with no optional field: the empty tail.
            head.push("%x00.00.00.00".into());
        } else {
            let tail = format!("{name}---tail");
            let opt = format!("{name}---opt");
            self.r.def(
                &tail,
                &format!("tail-count {}{opt}", upto(tail_max)),
                &[
                    "ascending tags".into(),
                    format!("exactly tail-count {opt} elements"),
                ],
            );
            self.r.def(&opt, &opts.join(" / "), &[]);
            head.push(tail);
        }
        self.r.def_at(at, name, &head.join(" "), &[]);
    }

    /// A field outside a tail: in a closed struct, or a required field of
    /// an open one. A `[nonzero]` integer is a rule of its own, `not 0`
    /// (docs/design/call-language.md, "Attributes").
    fn field(&mut self, u: usize, f: &Fld<'_>, x: &str, mode: Mode) -> String {
        let t = &f.field.ty;
        let BaseType::Int(w) = t.base else {
            return self.elem(u, t, x, mode);
        };
        if !f.nonzero() {
            return self.elem(u, t, x, mode);
        }
        if t.optional {
            let v = format!("{x}---value");
            self.r.def(x, &format!("%x00 / %x01 {v}"), &[]);
            self.r.def(&v, w.word(), &["not 0".into()]);
        } else {
            self.r.def(x, w.word(), &["not 0".into()]);
        }
        x.to_string()
    }

    /// A tagged value: `%x<tag>`, its length, then the value. `bare`: a
    /// tail field, whose `?` the tail carries. `nonzero`: a `[nonzero]`
    /// field's integer, whose value rule says `not 0`.
    #[allow(clippy::too_many_arguments)]
    fn prefixed(
        &mut self,
        x: &str,
        tag: u16,
        u: usize,
        t: &Type,
        bare: bool,
        nonzero: bool,
        mode: Mode,
    ) -> String {
        let facts = if bare {
            self.s.facts(u, t)
        } else {
            facts_of(self.s, u, t)
        };
        let value_name = format!("{x}---value");
        let value = match (&t.base, nonzero && bare) {
            (BaseType::Int(w), true) => {
                self.r.def(&value_name, w.word(), &["not 0".into()]);
                value_name.clone()
            }
            _ if bare => self.base(u, t, &value_name, mode),
            _ => self.elem(u, t, &value_name, mode),
        };
        let tag = lit(&tag.to_be_bytes());
        if !facts.open && facts.min == facts.max && facts.max <= u64::from(u32::MAX) {
            let len = lit(&(facts.max as u32).to_be_bytes());
            return format!("{tag} {len} {value}");
        }
        let len = format!("{x}---len");
        let body = format!("{x}---body");
        // A value that can't grow has a known range of sizes; one that
        // holds an open struct or union can grow by any later minor.
        let range = if facts.open {
            vec![]
        } else {
            vec![format!("in {}..{}", facts.min, facts.max)]
        };
        self.r.def(&len, "len32", &range);
        self.r
            .def(&body, &value, &[format!("exactly {len} octets")]);
        format!("{tag} {len} {body}")
    }

    fn union(&mut self, name: &str, id: TypeId, closed: bool, mode: Mode) {
        let s = self.s;
        let top = self.r.mark();
        let arms: Vec<_> = s.arms(id).into_iter().filter(|a| a.known).collect();
        let mut alts = Vec::new();
        for a in &arms {
            let aname = format!("{name}--{}", kebab(a.name));
            let at = self.r.mark();
            let def = if closed {
                let v = self.elem(id.unit, a.ty, &format!("{aname}---value"), mode);
                format!("{} {v}", lit(&a.tag.to_be_bytes()))
            } else {
                self.prefixed(&aname, a.tag, id.unit, a.ty, false, false, mode)
            };
            self.r.def_at(at, &aname, &def, &[]);
            alts.push(aname);
        }
        let mut free = Vec::new();
        let mut next = 1u32;
        for &t in arms.iter().map(|a| &a.tag).collect::<BTreeSet<_>>() {
            if u32::from(t) > next {
                free.push((next, u32::from(t) - 1));
            }
            next = u32::from(t) + 1;
        }
        free.push((next, 65_535));
        if let (false, Some(range)) = (closed, u16_ranges(&free)) {
            // An unknown arm, in both forms: a request may carry an arm the
            // server doesn't know ("Rules for readers"). Its tags are also
            // written context-free, as an unknown tail tag's are.
            let unknown = format!("{name}---unknown");
            self.r.def(&unknown, &format!("{unknown}-tag octets"), &[]);
            let mut tags: Vec<u16> = arms.iter().map(|a| a.tag).collect();
            tags.sort_unstable();
            let c = if tags.is_empty() {
                "not 0".to_string()
            } else {
                let list: Vec<String> = core::iter::once(0)
                    .chain(tags)
                    .map(|t| t.to_string())
                    .collect();
                format!("not one of {}", list.join(", "))
            };
            self.r.def(&format!("{unknown}-tag"), &range, &[c]);
            alts.push(unknown);
        }
        self.r.def_at(top, name, &alts.join(" / "), &[]);
    }

    fn enumeration(&mut self, name: &str, id: TypeId, flags: bool, width: IntType, closed: bool) {
        let s = self.s;
        let n = width.octets() as usize;
        if !closed {
            self.r.def(name, width.word(), &[]);
            return;
        }
        let values = s.values(id);
        if !flags {
            let alts: Vec<String> = values
                .iter()
                .map(|v| lit(&v.value.to_be_bytes()[8 - n..]))
                .collect();
            self.r.def(name, &alts.join(" / "), &[]);
            return;
        }
        // Closed flags: one rule per octet, each the octet values whose
        // bits are all declared. Bits are independent, so this is exact.
        let mask = values.iter().fold(0u64, |m, v| m | v.value);
        let at = self.r.mark();
        let mut parts = Vec::new();
        for k in 0..n {
            let m = (mask >> (8 * (n - 1 - k))) as u8;
            let part = format!("{name}---o{}", k + 1);
            self.r.def(&part, &octet_set(m), &[]);
            parts.push(part);
        }
        self.r.def_at(at, name, &parts.join(" "), &[]);
    }

    /// A type expression where it stands alone: an optional one is
    /// `presence`, then the value.
    fn elem(&mut self, u: usize, t: &Type, x: &str, mode: Mode) -> String {
        if !t.optional {
            return self.base(u, t, x, mode);
        }
        let at = self.r.mark();
        let v = self.base(u, t, &format!("{x}---value"), mode);
        self.r.def_at(at, x, &format!("%x00 / %x01 {v}"), &[]);
        x.to_string()
    }

    /// A type expression without its `?`: a rule name, defining `x` when
    /// the type needs a rule of its own.
    fn base(&mut self, u: usize, t: &Type, x: &str, mode: Mode) -> String {
        let s = self.s;
        match &t.base {
            BaseType::Bool => "bool".into(),
            BaseType::Int(w) => w.word().into(),
            BaseType::F32 => "f32".into(),
            BaseType::F64 => "f64".into(),
            BaseType::Id => "object-id".into(),
            BaseType::Uuid => "uuid".into(),
            BaseType::Cap(..) => "cap-ref".into(),
            BaseType::Slot(..) => "u64".into(),
            BaseType::String(b) | BaseType::Bytes(b) => {
                let max = s.bound(u, b);
                let chars = if matches!(t.base, BaseType::String(_)) {
                    "text-char"
                } else {
                    "OCTET"
                };
                let len = format!("{x}---len");
                self.r.def(
                    x,
                    &format!("{len} {}{chars}", upto(max)),
                    &[format!("exactly {len} octets")],
                );
                self.r.def(&len, "len32", &at_most(max));
                x.into()
            }
            BaseType::Seq(e, b) => {
                let max = s.bound(u, b);
                let at = self.r.mark();
                let el = self.elem(u, e, &format!("{x}---elem"), mode);
                let count = format!("{x}---count");
                self.r.def_at(
                    at,
                    x,
                    &format!("{count} {}{el}", upto(max)),
                    &[format!("exactly {count} {el} elements")],
                );
                self.r.def(&count, "count32", &at_most(max));
                x.into()
            }
            BaseType::Array(e, b) => {
                let n = s.bound(u, b);
                let at = self.r.mark();
                let el = self.elem(u, e, &format!("{x}---elem"), mode);
                self.r.def_at(at, x, &format!("{n}{el}"), &[]);
                x.into()
            }
            BaseType::Ref(r) => match s.resolve(u, r) {
                Some(id) => self.named(id, mode),
                None => "OCTET".into(),
            },
        }
    }
}

/// A repetition bounded by a declared maximum, `*N`, so the context-free
/// grammar is as tight as it can be: fewer readings, and a backtracking
/// checker stays fast. No bound at the width's maximum.
fn upto(max: u64) -> String {
    if max >= u64::from(u32::MAX) {
        "*".into()
    } else {
        format!("*{max}")
    }
}

/// `at most N` on a `len32` or `count32`, unless N is the width's maximum.
fn at_most(max: u64) -> Vec<String> {
    if max >= u64::from(u32::MAX) {
        Vec::new()
    } else {
        vec![format!("at most {max}")]
    }
}

/// The u16 values in the given inclusive ranges, as big-endian octet
/// alternatives, or None when the ranges hold no value.
fn u16_ranges(ranges: &[(u32, u32)]) -> Option<String> {
    let byte = |lo: u32, hi: u32| {
        if lo == 0 && hi == 255 {
            "OCTET".to_string()
        } else if lo == hi {
            format!("%x{lo:02X}")
        } else {
            format!("%x{lo:02X}-{hi:02X}")
        }
    };
    let mut alts = Vec::new();
    for &(a, b) in ranges {
        if a > b || b > 65_535 {
            continue;
        }
        let (ha, la, hb, lb) = (a >> 8, a & 255, b >> 8, b & 255);
        if ha == hb {
            alts.push(format!("{} {}", byte(ha, ha), byte(la, lb)));
            continue;
        }
        let (mut h0, mut h1) = (ha, hb);
        if la != 0 {
            alts.push(format!("{} {}", byte(ha, ha), byte(la, 255)));
            h0 += 1;
        }
        if lb != 255 {
            alts.push(format!("{} {}", byte(hb, hb), byte(0, lb)));
            h1 -= 1;
        }
        if h0 <= h1 {
            alts.push(format!("{} OCTET", byte(h0, h1)));
        }
    }
    (!alts.is_empty()).then(|| alts.join(" / "))
}

/// The octet values whose set bits are all in `mask`, as ABNF
/// alternatives with runs merged into ranges.
fn octet_set(mask: u8) -> String {
    if mask == 0xFF {
        return "OCTET".into();
    }
    let ok: Vec<u8> = (0..=255u8).filter(|v| v & !mask == 0).collect();
    let mut alts = Vec::new();
    let mut i = 0;
    while i < ok.len() {
        let mut j = i;
        while j + 1 < ok.len() && ok[j + 1] == ok[j] + 1 {
            j += 1;
        }
        if i == j {
            alts.push(format!("%x{:02X}", ok[i]));
        } else {
            alts.push(format!("%x{:02X}-{:02X}", ok[i], ok[j]));
        }
        i = j + 1;
    }
    alts.join(" / ")
}

// ---- The canonical-text grammar -------------------------------------------

/// The canonical-text grammar of the schema's minor (ADR 0063, rules 8 and
/// 9): each method's call text and reply text, and the JSON of every body
/// and type, after `preamble`.
pub fn text(s: &Schema<'_>, preamble: &str) -> String {
    let mut w = Text {
        s,
        r: Rules::new(),
        pending: Vec::new(),
    };
    let unit = s.model.unit(s.root);
    let target = if s.is_kernel() { "\"-\"" } else { "id-text" };
    for top in s.tops() {
        w.r.comment(&describe(s, top));
        match top {
            Top::Request(i) => {
                let m = kebab(s.member_name(i));
                let args = format!("m-{m}--args");
                w.body(&args, &s.params(i), s.mode(top));
                w.r.def(
                    &format!("m-{m}--call"),
                    &format!(
                        "%s\"{}/{}/{}\" SP {target} [ SP {args} ]",
                        unit.name,
                        unit.major(),
                        s.member_name(i)
                    ),
                    &[],
                );
            }
            Top::Reply(i) => {
                let m = kebab(s.member_name(i));
                let results = format!("m-{m}--results");
                w.body(&results, &s.results(i), Mode::Tolerant);
                w.r.def(
                    &format!("m-{m}--reply"),
                    &format!("%s\"ok\" [ SP {results} ] / outcome-word SP error-ref"),
                    &[],
                );
            }
            // The opening reply's JSON is the reply's results.
            Top::Open(_) => {}
            Top::Item(i) => {
                if let Some(id) = s.item(i) {
                    let t = w.named(id, Mode::Tolerant);
                    w.r.def(&s.top_rule(top), &t, &[]);
                }
            }
            Top::Error(i) => w.body(&s.top_rule(top), &s.detail(i), Mode::Tolerant),
            Top::Type(id, mode) => w.emit(id, mode),
        }
    }
    if !w.pending.is_empty() {
        w.r.comment("types the use lines import, read at the minor each names");
        w.drain();
    }
    let mut out = String::from(preamble);
    out.push_str(&w.r.text);
    out
}

struct Text<'s, 'm> {
    s: &'s Schema<'m>,
    r: Rules,
    pending: Vec<(TypeId, Mode)>,
}

/// One item of a comma-separated list: its expression, and whether it may
/// be absent.
type Item = (String, bool);

impl Text<'_, '_> {
    fn drain(&mut self) {
        while let Some((id, mode)) = self.pending.pop() {
            self.emit(id, mode);
        }
    }

    fn named(&mut self, id: TypeId, mode: Mode) -> String {
        let mode = if self.s.has_strict(id) {
            mode
        } else {
            Mode::Tolerant
        };
        let name = self.s.type_rule(id, mode);
        if !self.r.defined.contains(&name) {
            self.pending.push((id, mode));
        }
        name
    }

    fn emit(&mut self, id: TypeId, mode: Mode) {
        let s = self.s;
        let mode = if s.has_strict(id) {
            mode
        } else {
            Mode::Tolerant
        };
        let name = s.type_rule(id, mode);
        if self.r.defined.contains(&name) {
            return;
        }
        match s.def(id) {
            Def::Alias(t) => {
                let e = self.elem(id.unit, t, false, &name, mode);
                if e != name {
                    self.r.def(&name, &e, &[]);
                }
            }
            Def::Struct { .. } => self.body(&name, &s.struct_body(id), mode),
            Def::Union { closed, .. } => self.union(&name, id, closed, mode),
            Def::Enum { flags, width, .. } => self.enumeration(&name, id, flags, width),
        }
    }

    /// The comma-separated list of `items`, in order, each present or
    /// (when optional) absent. Returns an expression that matches the
    /// list when at least one item is present, and whether the list may
    /// be empty. With `asc`, the last item is the unknown members, whose
    /// tags (rule `asc`) must ascend.
    ///
    /// `X---a<k>` matches items k.. after something was written, so each
    /// present item takes a comma; `X---b<k>` matches them with nothing
    /// written before, and at least one present.
    fn list(&mut self, x: &str, items: &[Item], asc: Option<&str>) -> (String, bool) {
        let n = items.len();
        let join = |a: &str, b: &str| match (a.is_empty(), b.is_empty()) {
            (_, true) => a.to_string(),
            (true, _) => b.to_string(),
            _ => format!("{a} {b}"),
        };
        // Helper rules, defined below only if the list refers to them.
        let mut defs: Vec<(String, String, Vec<String>)> = Vec::new();
        let mut a = vec![String::new(); n + 1];
        // Whether every item from k on is required, found once, so a list
        // of 4096 costs no more than linear work.
        let mut required = vec![true; n + 1];
        for k in (0..n).rev() {
            required[k] = required[k + 1] && !items[k].1;
        }
        for k in (1..n).rev() {
            let (item, optional) = &items[k];
            if required[k] {
                a[k] = join(&format!("\",\" {item}"), &a[k + 1]);
                continue;
            }
            let name = format!("{x}---a{k}");
            if let (Some(tag), true, true) = (asc, k == n - 1, *optional) {
                // The unknown members, after something: their tags ascend
                // inside this one repetition.
                defs.push((
                    name.clone(),
                    format!("*1( \",\" {item} )"),
                    vec![format!("ascending {tag}")],
                ));
            } else {
                let first = if *optional {
                    format!("[ \",\" {item} ]")
                } else {
                    format!("\",\" {item}")
                };
                defs.push((name.clone(), join(&first, &a[k + 1]), vec![]));
            }
            a[k] = name;
        }
        let mut b = vec![String::new(); n];
        for k in (0..n).rev() {
            let (item, optional) = &items[k];
            let first = join(item, &a[k + 1]);
            b[k] = if !optional || k == n - 1 {
                first
            } else {
                let name = format!("{x}---b{k}");
                defs.push((name.clone(), format!("{first} / {}", b[k + 1]), vec![]));
                name
            };
        }
        // Define what the list reaches, in order of first reference.
        let index: BTreeMap<&str, usize> = defs
            .iter()
            .enumerate()
            .map(|(i, d)| (d.0.as_str(), i))
            .collect();
        let mut todo = vec![b[0].clone()];
        let mut reached = BTreeSet::new();
        while let Some(text) = todo.pop() {
            for word in text.split([' ', '(', ')', '[', ']']) {
                if let Some(&i) = index.get(word)
                    && reached.insert(word.to_string())
                {
                    todo.push(defs[i].1.clone());
                }
            }
        }
        for (name, body, c) in defs.iter().rev() {
            if reached.contains(name) {
                self.r.def(name, body, c);
            }
        }
        let empty = items.iter().all(|(_, o)| *o);
        (b[0].clone(), empty)
    }

    fn body(&mut self, name: &str, b: &Body<'_>, mode: Mode) {
        let s = self.s;
        let top = self.r.mark();
        let mut items: Vec<Item> = Vec::new();
        for f in s.known_fields(b) {
            let fname = format!("{name}--{}", kebab(&f.field.name.name));
            let at = self.r.mark();
            let value = match (&f.field.ty.base, f.nonzero()) {
                _ if f.redacted() => "json-null".to_string(),
                // A `[nonzero]` integer's number is `not 0`.
                (BaseType::Int(w), true) => {
                    let x = format!("{fname}---value");
                    self.int(&x, *w, true);
                    x
                }
                // A struct field's `?` means the key may be absent.
                _ => self.base(
                    b.unit,
                    &f.field.ty,
                    f.json(),
                    &format!("{fname}---value"),
                    mode,
                ),
            };
            self.r.def_at(
                at,
                &fname,
                &format!("%x22 %s\"{}\" %x22 \":\" {value}", f.field.name.name),
                &[],
            );
            items.push((fname, f.optional() && !f.redacted()));
        }
        let mut asc = None;
        if mode == Mode::Tolerant && !b.closed {
            let p = s.known_fields(b).len() + 1;
            let unknown = format!("{name}---unknown");
            let tag = format!("{unknown}-tag");
            self.r.def(
                &unknown,
                &format!("%x22 \"@\" {tag} %x22 \":\" json-bytes"),
                &[],
            );
            let range = if p <= 65_535 {
                format!("in {p}..65535")
            } else {
                format!("at least {p}")
            };
            self.r.def(&tag, "json-uint", &[range]);
            let unknowns = format!("{name}---unknowns");
            self.r
                .def(&unknowns, &format!("{unknown} *( \",\" {unknown} )"), &[]);
            items.push((unknowns, true));
            asc = Some(tag);
        }
        if items.is_empty() {
            self.r.def_at(top, name, "\"{\" \"}\"", &[]);
            return;
        }
        let (e, empty) = self.list(name, &items, asc.as_deref());
        match (empty, &asc) {
            (false, _) => self.r.def_at(top, name, &format!("\"{{\" {e} \"}}\""), &[]),
            (true, Some(tag)) => self.r.def_at(
                top,
                name,
                &format!("\"{{\" *1( {e} ) \"}}\""),
                &[format!("ascending {tag}")],
            ),
            (true, None) => self
                .r
                .def_at(top, name, &format!("\"{{\" [ {e} ] \"}}\""), &[]),
        }
    }

    fn union(&mut self, name: &str, id: TypeId, closed: bool, mode: Mode) {
        let s = self.s;
        let top = self.r.mark();
        let arms: Vec<_> = s.arms(id).into_iter().filter(|a| a.known).collect();
        let mut alts = Vec::new();
        for a in &arms {
            let aname = format!("{name}--{}", kebab(a.name));
            let json = ast::has_attr(a.attrs, "format");
            let at = self.r.mark();
            let v = self.elem(id.unit, a.ty, json, &format!("{aname}---value"), mode);
            self.r.def_at(
                at,
                &aname,
                &format!("%x22 %s\"{}\" %x22 \":\" {v}", a.name),
                &[],
            );
            alts.push(aname);
        }
        if !closed {
            let unknown = format!("{name}---unknown");
            let tag = format!("{unknown}-tag");
            self.r.def(
                &unknown,
                &format!("%x22 \"@\" {tag} %x22 \":\" json-bytes"),
                &[],
            );
            let mut tags: Vec<u16> = arms.iter().map(|a| a.tag).collect();
            tags.sort_unstable();
            let not = if tags.is_empty() {
                "not 0".to_string()
            } else {
                let list: Vec<String> = core::iter::once(0)
                    .chain(tags)
                    .map(|t| t.to_string())
                    .collect();
                format!("not one of {}", list.join(", "))
            };
            self.r
                .def(&tag, "json-uint", &[not, "at most 65535".into()]);
            alts.push(unknown);
        }
        self.r.def_at(
            top,
            name,
            &format!("\"{{\" ( {} ) \"}}\"", alts.join(" / ")),
            &[],
        );
    }

    fn enumeration(&mut self, name: &str, id: TypeId, flags: bool, width: IntType) {
        let s = self.s;
        let closed = matches!(s.def(id), Def::Enum { closed: true, .. });
        let mut values: Vec<_> = s.values(id).into_iter().filter(|v| v.known).collect();
        let max = width.range().1 as u64;
        if !flags {
            let mut alts = Vec::new();
            if !values.is_empty() {
                let names: Vec<String> =
                    values.iter().map(|v| format!("%s\"{}\"", v.name)).collect();
                alts.push(format!("%x22 ( {} ) %x22", names.join(" / ")));
            }
            if !closed {
                // An unknown value is its number.
                let number = format!("{name}---number");
                let mut known: Vec<u64> = values.iter().map(|v| v.value).collect();
                known.sort_unstable();
                let mut c = Vec::new();
                match known.as_slice() {
                    [] => {}
                    [one] => c.push(format!("not {one}")),
                    many => c.push(format!(
                        "not one of {}",
                        many.iter()
                            .map(|v| v.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                }
                c.push(format!("at most {max}"));
                self.r.def(&number, "json-uint", &c);
                alts.push(number);
            }
            self.r.def(name, &alts.join(" / "), &[]);
            return;
        }
        // Flags: the set bits' names in value order, then any unknown bits
        // as one integer. Whether those bits include a known one isn't
        // expressible, so the text grammar doesn't check it.
        values.sort_by_key(|v| v.value);
        let mut items: Vec<Item> = values
            .iter()
            .map(|v| (format!("%x22 %s\"{}\" %x22", v.name), true))
            .collect();
        if !closed {
            let bits = format!("{name}---bits");
            let c = vec!["not 0".to_string(), format!("at most {max}")];
            if width == IntType::U64 {
                let digits = format!("{bits}---digits");
                self.r.def(&bits, &format!("%x22 {digits} %x22"), &[]);
                self.r.def(&digits, "json-uint", &c);
            } else {
                self.r.def(&bits, "json-uint", &c);
            }
            items.push((bits, true));
        }
        if items.is_empty() {
            self.r.def(name, "\"[\" \"]\"", &[]);
            return;
        }
        let (e, _) = self.list(name, &items, None);
        self.r.def(name, &format!("\"[\" [ {e} ] \"]\""), &[]);
    }

    /// A type expression where it stands alone: an optional one is `null`
    /// or the value.
    fn elem(&mut self, u: usize, t: &Type, json: bool, x: &str, mode: Mode) -> String {
        if !t.optional {
            return self.base(u, t, json, x, mode);
        }
        let at = self.r.mark();
        let v = self.base(u, t, json, &format!("{x}---value"), mode);
        self.r.def_at(at, x, &format!("json-null / {v}"), &[]);
        x.to_string()
    }

    fn base(&mut self, u: usize, t: &Type, json: bool, x: &str, mode: Mode) -> String {
        let s = self.s;
        match &t.base {
            BaseType::Bool => "json-bool".into(),
            BaseType::F32 | BaseType::F64 => "json-float".into(),
            BaseType::Id => "json-id".into(),
            BaseType::Uuid => "json-uuid".into(),
            BaseType::Cap(..) => "json-cap".into(),
            BaseType::Slot(..) => "json-null".into(),
            BaseType::String(_) if json => "json-embedded".into(),
            // A string's length after escaping isn't expressible: the
            // wire grammar holds its bound.
            BaseType::String(_) => "json-string".into(),
            BaseType::Int(w) => {
                self.int(x, *w, false);
                x.into()
            }
            BaseType::Bytes(b) => {
                let max = s.bound(u, b);
                self.r
                    .def(x, &format!("%x22 {} %x22", base64_bounded(max)), &[]);
                x.into()
            }
            BaseType::Seq(e, b) | BaseType::Array(e, b) => {
                let n = s.bound(u, b);
                let at = self.r.mark();
                let el = self.elem(u, e, false, &format!("{x}---elem"), mode);
                let def = match (&t.base, n) {
                    (BaseType::Array(..), 1) => format!("\"[\" {el} \"]\""),
                    (BaseType::Array(..), n) => {
                        format!("\"[\" {el} {}( \",\" {el} ) \"]\"", n - 1)
                    }
                    (_, 1) => format!("\"[\" [ {el} ] \"]\""),
                    (_, n) if n >= u64::from(u32::MAX) => {
                        format!("\"[\" [ {el} *( \",\" {el} ) ] \"]\"")
                    }
                    (_, n) => format!("\"[\" [ {el} *{}( \",\" {el} ) ] \"]\"", n - 1),
                };
                self.r.def_at(at, x, &def, &[]);
                x.into()
            }
            BaseType::Ref(r) => match s.resolve(u, r) {
                Some(id) => self.named(id, mode),
                None => "json-null".into(),
            },
        }
    }

    /// An integer, bounded on rules that read as the decimal number they
    /// spell ("How constraints bind"). `u64` and `i64` are strings.
    /// `nonzero`: a `[nonzero]` field's, whose digits are `not 0`.
    fn int(&mut self, x: &str, w: IntType, nonzero: bool) {
        let (min, max) = w.range();
        let digits = format!("{x}---digits");
        let neg = format!("{x}---neg");
        let at = self.r.mark();
        let mut bound = vec![format!("at most {max}")];
        if nonzero {
            bound.push("not 0".into());
        }
        let number = if w.signed() {
            self.r.def(
                &neg,
                "json-uint-nz",
                &[format!("at most {}", min.unsigned_abs())],
            );
            self.r.def(&digits, "json-uint", &bound);
            format!("\"-\" {neg} / {digits}")
        } else if w == IntType::U64 {
            self.r.def(&digits, "json-uint", &bound);
            digits.clone()
        } else {
            self.r.def(x, "json-uint", &bound);
            return;
        };
        let def = match w {
            IntType::U64 => format!("%x22 {number} %x22"),
            IntType::I64 => format!("%x22 ( {number} ) %x22"),
            _ => number,
        };
        self.r.def_at(at, x, &def, &[]);
    }
}

/// Unpadded base64url of at most `max` octets: q full groups of 3 octets,
/// then a remainder of 1 or 2, within the bound.
fn base64_bounded(max: u64) -> String {
    if max >= u64::from(u32::MAX) {
        return "*json-b64-4 [ json-b64-2 / json-b64-3 ]".into();
    }
    let (q, r) = (max / 3, max % 3);
    let groups = |n: u64| match n {
        0 => String::new(),
        n => format!("*{n}json-b64-4 "),
    };
    match (q, r) {
        (_, 2) => format!("{}[ json-b64-2 / json-b64-3 ]", groups(q)),
        (0, 1) => "[ json-b64-2 ]".into(),
        (q, 1) => format!(
            "( {}[ json-b64-2 / json-b64-3 ] / {q}json-b64-4 [ json-b64-2 ] )",
            groups(q - 1)
        ),
        (q, _) => format!(
            "( {}[ json-b64-2 / json-b64-3 ] / {q}json-b64-4 )",
            groups(q - 1)
        ),
    }
}
