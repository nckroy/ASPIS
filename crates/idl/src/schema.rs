// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! One checked file, read at one of its minors: what the grammar
//! generator ([`crate::abnf_gen`]) and the dynamic codec
//! ([`crate::value`]) both walk, so the two can't disagree about which
//! members exist, where fields sit, or what a rule is called.
//!
//! The schema reads the newest model, and treats every member of the
//! checked file whose effective `since` is above the minor as unknown
//! (docs/design/call-language.md, "Rules for readers"). An imported
//! interface was already projected to the minor its `use` line names, so
//! all of its members are known (ADR 0067, rule 4; "Generated grammars").

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    rc::Rc,
    string::String,
    vec,
    vec::Vec,
};
use core::cell::RefCell;

use crate::{
    ast::{self, Arm, Attr, BaseType, Field, IntType, MemberKind, Type, Version},
    layout::{self, Facts, KERNEL_CALLED, Types, since_of},
    model::{Checked, Model, NO_UNIT, TypeId},
};

/// How strictly a message is read (ADR 0065, rule 11; "Strict requests,
/// tolerant reads").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    /// A request a client sent: an unknown tail field is `field_too_new`.
    Strict,
    /// Replies, stream items, error details, and the requests the kernel
    /// sends: unknown tail fields are skipped and preserved.
    Tolerant,
}

/// A message body or a type that a generated grammar names as a rule, and
/// that vectors test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Top {
    /// `m-<method>--req`: the method's parameters (a member index).
    Request(usize),
    /// `m-<method>--rep`: the method's results.
    Reply(usize),
    /// `m-<method>--open`: a stream method's opening reply.
    Open(usize),
    /// `m-<method>--item`: a stream item.
    Item(usize),
    /// `e-<error>`: an error's detail (a member index).
    Error(usize),
    /// `t-<type>` (tolerant) or `r-<type>` (strict).
    Type(TypeId, Mode),
}

/// What a named type is.
#[derive(Debug, Clone, Copy)]
pub enum Def<'m> {
    Alias(&'m Type),
    Struct {
        fields: &'m [Field],
        closed: bool,
    },
    Union {
        arms: &'m [Arm],
        closed: bool,
    },
    Enum {
        flags: bool,
        width: IntType,
        values: &'m [ast::Value],
        closed: bool,
    },
}

/// A struct-shaped body: a struct type, a method's parameters or
/// results, or an error's detail.
#[derive(Debug, Clone, Copy)]
pub struct Body<'m> {
    /// The unit its types and bounds resolve in.
    pub unit: usize,
    pub fields: &'m [Field],
    /// The container's effective `since`, which a field's own `since`
    /// never precedes.
    pub since: Version,
    pub closed: bool,
}

/// One field of a body, at the schema's minor.
#[derive(Debug, Clone, Copy)]
pub struct Fld<'m> {
    /// Its position: the 1-based tag (ADR 0065, rule 2).
    pub pos: u16,
    pub field: &'m Field,
    pub known: bool,
}

impl Fld<'_> {
    pub fn optional(&self) -> bool {
        self.field.ty.optional
    }

    pub fn sensitive(&self) -> bool {
        ast::has_attr(&self.field.attrs, "sensitive")
    }

    /// `[nonzero]`: an integer whose value 0 is invalid. A decoder
    /// refuses 0 as malformed, and an encoder refuses to write it.
    pub fn nonzero(&self) -> bool {
        ast::has_attr(&self.field.attrs, "nonzero")
    }

    /// `[format(json)]`: the string holds JSON text.
    pub fn json(&self) -> bool {
        ast::has_attr(&self.field.attrs, "format")
    }

    /// Rendered as `null` under its key, always: a `[sensitive]` field or
    /// a `slot<...>` ("The canonical call text").
    pub fn redacted(&self) -> bool {
        self.sensitive() || matches!(self.field.ty.base, BaseType::Slot(..))
    }
}

/// A union arm at the schema's minor.
#[derive(Debug, Clone, Copy)]
pub struct ArmInfo<'m> {
    pub tag: u16,
    pub name: &'m str,
    pub ty: &'m Type,
    pub attrs: &'m [Attr],
    pub known: bool,
    pub since: Version,
}

/// An enum or flags value at the schema's minor.
#[derive(Debug, Clone, Copy)]
pub struct ValueInfo<'m> {
    pub value: u64,
    pub name: &'m str,
    pub known: bool,
    pub since: Version,
}

/// A checked file at one minor.
pub struct Schema<'m> {
    pub model: &'m Model,
    pub root: usize,
    pub minor: u16,
    /// Rule-name prefixes: "" for the root, `u<k>--` for the k-th `use`
    /// line of its file projected to the minor, `u<k>--u<j>--` for an
    /// import of an import. Only the units the minor reaches have one.
    prefixes: BTreeMap<usize, String>,
    /// Those units, in breadth-first order from the root.
    order: Vec<usize>,
    /// The results of each method of the root, as fields: one unnamed
    /// result is the field `result`.
    results: BTreeMap<usize, Vec<Field>>,
    /// Named types that hold an open struct through members known at the
    /// minor, so a request reads them with their strict form, `r-`.
    strict: BTreeSet<TypeId>,
    facts: RefCell<Types<'m>>,
    /// Each union's arms and each enum's or flags type's values, by tag or
    /// value, built once: the dynamic codec looks one up per value it
    /// reads, so a large enum costs a lookup, not a scan.
    tables: RefCell<BTreeMap<TypeId, Rc<Table<'m>>>>,
    /// How many fields of each body are known, by the address and length
    /// of its field list, which the model and the schema own unchanged.
    known: RefCell<BTreeMap<(usize, usize), usize>>,
}

/// A named type's arms or values, by tag or value.
#[derive(Default)]
struct Table<'m> {
    arms: BTreeMap<u16, ArmInfo<'m>>,
    values: BTreeMap<u64, ValueInfo<'m>>,
}

impl<'m> Schema<'m> {
    /// The checked file read at `minor`, which is at most its version.
    pub fn new(checked: &'m Checked, minor: u16) -> Schema<'m> {
        let model = &checked.model;
        let root = checked.root;
        let mut prefixes = BTreeMap::new();
        prefixes.insert(root, String::new());
        // The prefixes are a function of the file projected to the minor,
        // which the lock's hash covers, and of the imports, each already
        // projected to its `use` minor: so no edit to a later minor's lines
        // can rename a published grammar's rules. The root's lines are
        // numbered by their places in that projection, and a line the
        // minor doesn't use takes no part: it gets no prefix, and neither
        // does a unit only it reaches. None of the minor's rules names
        // them, and if it took a place in the breadth-first walk, it could
        // take a unit that a used line reaches through an import.
        let (_, kept) = crate::project::project_uses(checked.file(), minor);
        let mut order = vec![root];
        let mut i = 0;
        while i < order.len() {
            let u = order[i];
            i += 1;
            let p = prefixes[&u].clone();
            let uses = &model.unit(u).uses;
            let lines: Vec<usize> = if u == root {
                kept.clone()
            } else {
                (0..uses.len()).collect()
            };
            for (place, k) in lines.into_iter().enumerate() {
                let t = uses[k];
                if t != NO_UNIT && !prefixes.contains_key(&t) {
                    prefixes.insert(t, format!("{p}u{}--", place + 1));
                    order.push(t);
                }
            }
        }
        let mut results = BTreeMap::new();
        for (i, m) in model.unit(root).members().iter().enumerate() {
            if let MemberKind::Method(method) = &m.kind {
                let fields = method
                    .results
                    .as_ref()
                    .map(layout::result_fields)
                    .unwrap_or_default();
                results.insert(i, fields);
            }
        }
        let mut s = Schema {
            model,
            root,
            minor,
            prefixes,
            order,
            results,
            strict: BTreeSet::new(),
            facts: RefCell::new(Types::new(model)),
            tables: RefCell::new(BTreeMap::new()),
            known: RefCell::new(BTreeMap::new()),
        };
        s.strict = s.strict_types();
        s
    }

    /// The minor as a version of the root's major.
    pub fn version(&self) -> Version {
        Version {
            major: self.model.unit(self.root).major(),
            minor: self.minor,
        }
    }

    fn base(&self, u: usize) -> Version {
        Version {
            major: self.model.unit(u).major(),
            minor: 0,
        }
    }

    /// Whether a member of unit `u` with these attributes, inside a
    /// container whose effective `since` is `container`, exists at the
    /// minor.
    pub fn known(&self, u: usize, attrs: &[Attr], container: Version) -> bool {
        u != self.root || since_of(attrs, container).minor <= self.minor
    }

    /// The effective `since` of a top-level member.
    pub fn member_since(&self, u: usize, member: usize) -> Version {
        since_of(&self.model.unit(u).members()[member].attrs, self.base(u))
    }

    /// Whether a top-level member of the root exists at the minor.
    pub fn member_known(&self, member: usize) -> bool {
        self.member_since(self.root, member).minor <= self.minor
    }

    /// The units the minor reaches, the root first, in breadth-first
    /// order: each one with a rule-name prefix.
    pub fn units(&self) -> &[usize] {
        &self.order
    }

    /// The rule-name prefix of a unit.
    pub fn prefix(&self, u: usize) -> &str {
        self.prefixes.get(&u).map_or("", String::as_str)
    }

    /// Whether the root is `[kernel]`: no wire grammar (ADR 0059, rule 2).
    pub fn is_kernel(&self) -> bool {
        self.model.unit(self.root).is_kernel()
    }

    /// Whether the root is an interface the kernel calls: its requests are
    /// read tolerantly (ADR 0063, rule 3; "Messages the kernel sends").
    pub fn kernel_called(&self) -> bool {
        KERNEL_CALLED.contains(&self.model.unit(self.root).name.as_str())
    }

    /// The mode a body is read in.
    pub fn mode(&self, top: Top) -> Mode {
        match top {
            Top::Request(_) if !self.kernel_called() => Mode::Strict,
            Top::Type(_, m) => m,
            _ => Mode::Tolerant,
        }
    }

    pub fn def(&self, id: TypeId) -> Def<'m> {
        let m = self.model.member(id);
        let closed = ast::has_attr(&m.attrs, "closed");
        match &m.kind {
            MemberKind::Alias { ty, .. } => Def::Alias(ty),
            MemberKind::Struct { fields, .. } => Def::Struct { fields, closed },
            MemberKind::Union { arms, .. } => Def::Union { arms, closed },
            MemberKind::Enum {
                flags,
                width,
                values,
                ..
            } => Def::Enum {
                flags: *flags,
                width: *width,
                values,
                closed,
            },
            // The checker passed: a type reference names a type.
            _ => Def::Struct {
                fields: &[],
                closed: true,
            },
        }
    }

    /// A named type's name, as declared.
    pub fn type_name(&self, id: TypeId) -> &'m str {
        self.model.member(id).name().map_or("", |n| n.name.as_str())
    }

    /// A named type's effective `since`.
    pub fn type_since(&self, id: TypeId) -> Version {
        self.member_since(id.unit, id.member)
    }

    /// A struct type as a body.
    pub fn struct_body(&self, id: TypeId) -> Body<'m> {
        let (fields, closed) = match self.def(id) {
            Def::Struct { fields, closed } => (fields, closed),
            _ => (&[][..], true),
        };
        Body {
            unit: id.unit,
            fields,
            since: self.type_since(id),
            closed,
        }
    }

    /// The method a member index names.
    pub fn method(&self, member: usize) -> &'m ast::Method {
        match &self.model.unit(self.root).members()[member].kind {
            MemberKind::Method(m) => m,
            _ => unreachable_method(),
        }
    }

    pub fn member_attrs(&self, member: usize) -> &'m [Attr] {
        &self.model.unit(self.root).members()[member].attrs
    }

    pub fn member_name(&self, member: usize) -> &'m str {
        self.model.unit(self.root).members()[member]
            .name()
            .map_or("", |n| n.name.as_str())
    }

    /// A method's parameters.
    pub fn params(&self, member: usize) -> Body<'m> {
        Body {
            unit: self.root,
            fields: &self.method(member).params,
            since: self.member_since(self.root, member),
            closed: false,
        }
    }

    /// A method's results.
    pub fn results(&self, member: usize) -> Body<'_> {
        Body {
            unit: self.root,
            fields: self.results.get(&member).map_or(&[][..], Vec::as_slice),
            since: self.member_since(self.root, member),
            closed: false,
        }
    }

    /// A stream method's item type.
    pub fn item(&self, member: usize) -> Option<TypeId> {
        let r = self.method(member).results.as_ref()?.stream.as_ref()?;
        self.model.resolve(self.root, r)
    }

    /// An error's detail.
    pub fn detail(&self, member: usize) -> Body<'m> {
        let fields = match &self.model.unit(self.root).members()[member].kind {
            MemberKind::Error {
                fields: Some(f), ..
            } => f.as_slice(),
            _ => &[],
        };
        Body {
            unit: self.root,
            fields,
            since: self.member_since(self.root, member),
            closed: false,
        }
    }

    /// A body's fields, with their positions and whether each is known.
    pub fn fields<'b>(&self, b: &Body<'b>) -> Vec<Fld<'b>> {
        b.fields
            .iter()
            .enumerate()
            .map(|(i, f)| Fld {
                pos: (i + 1) as u16,
                field: f,
                known: self.known(b.unit, &f.attrs, b.since),
            })
            .collect()
    }

    /// The fields known at the minor: a prefix, since fields are only
    /// appended (ADR 0065, rule 2).
    pub fn known_fields<'b>(&self, b: &Body<'b>) -> Vec<Fld<'b>> {
        self.known_iter(b).collect()
    }

    /// How many of a body's fields are known at the minor, counted once
    /// for each body.
    pub fn known_count(&self, b: &Body<'_>) -> usize {
        let key = (b.fields.as_ptr() as usize, b.fields.len());
        if let Some(&n) = self.known.borrow().get(&key) {
            return n;
        }
        let n = b
            .fields
            .iter()
            .take_while(|f| self.known(b.unit, &f.attrs, b.since))
            .count();
        self.known.borrow_mut().insert(key, n);
        n
    }

    /// [`Schema::known_fields`], without building a list.
    pub fn known_iter<'b>(&self, b: &Body<'b>) -> impl Iterator<Item = Fld<'b>> + use<'b> {
        b.fields[..self.known_count(b)]
            .iter()
            .enumerate()
            .map(|(i, f)| Fld {
                pos: (i + 1) as u16,
                field: f,
                known: true,
            })
    }

    fn table(&self, id: TypeId) -> Rc<Table<'m>> {
        if let Some(t) = self.tables.borrow().get(&id) {
            return t.clone();
        }
        let t = Rc::new(Table {
            arms: self.arms(id).into_iter().map(|a| (a.tag, a)).collect(),
            values: self.values(id).into_iter().map(|v| (v.value, v)).collect(),
        });
        self.tables.borrow_mut().insert(id, t.clone());
        t
    }

    /// A union's arm with this tag, if one is declared and not retired.
    pub fn arm(&self, id: TypeId, tag: u16) -> Option<ArmInfo<'m>> {
        self.table(id).arms.get(&tag).copied()
    }

    /// An enum's or flags type's value, if one is declared and not
    /// retired.
    pub fn value(&self, id: TypeId, raw: u64) -> Option<ValueInfo<'m>> {
        self.table(id).values.get(&raw).copied()
    }

    /// A flags type's declared bits, not retired, and those of them newer
    /// than the minor, each with its `since` minor. A flags type has at
    /// most 64.
    pub fn flag_bits(&self, id: TypeId) -> (u64, Vec<(u64, u16)>) {
        let t = self.table(id);
        let declared = t.values.keys().fold(0u64, |m, v| m | v);
        let newer = t
            .values
            .values()
            .filter(|v| !v.known)
            .map(|v| (v.value, v.since.minor))
            .collect();
        (declared, newer)
    }

    /// A union's arms, retired ones left out.
    pub fn arms(&self, id: TypeId) -> Vec<ArmInfo<'m>> {
        let since = self.type_since(id);
        let Def::Union { arms, .. } = self.def(id) else {
            return Vec::new();
        };
        arms.iter()
            .filter_map(|a| match a {
                Arm::Arm {
                    attrs,
                    ordinal,
                    name,
                    ty,
                    ..
                } => Some(ArmInfo {
                    tag: *ordinal,
                    name: &name.name,
                    ty,
                    attrs,
                    known: self.known(id.unit, attrs, since),
                    since: since_of(attrs, since),
                }),
                Arm::Reserved { .. } => None,
            })
            .collect()
    }

    /// Every arm number a union declares, retired ones included.
    pub fn arm_numbers(&self, id: TypeId) -> Vec<u16> {
        let Def::Union { arms, .. } = self.def(id) else {
            return Vec::new();
        };
        arms.iter()
            .map(|a| match a {
                Arm::Arm { ordinal, .. } | Arm::Reserved { ordinal, .. } => *ordinal,
            })
            .collect()
    }

    /// An enum's or flags type's values, retired ones left out.
    pub fn values(&self, id: TypeId) -> Vec<ValueInfo<'m>> {
        let since = self.type_since(id);
        let Def::Enum { values, .. } = self.def(id) else {
            return Vec::new();
        };
        values
            .iter()
            .filter_map(|v| match v {
                ast::Value::Value {
                    attrs, name, value, ..
                } => Some(ValueInfo {
                    value: value.value.and_then(|v| u64::try_from(v).ok()).unwrap_or(0),
                    name: &name.name,
                    known: self.known(id.unit, attrs, since),
                    since: since_of(attrs, since),
                }),
                ast::Value::Reserved { .. } => None,
            })
            .collect()
    }

    /// Every value an enum or flags type declares, retired ones included.
    pub fn value_numbers(&self, id: TypeId) -> Vec<u64> {
        let Def::Enum { values, .. } = self.def(id) else {
            return Vec::new();
        };
        values
            .iter()
            .filter_map(|v| match v {
                ast::Value::Value { value, .. } | ast::Value::Reserved { value, .. } => {
                    value.value.and_then(|v| u64::try_from(v).ok())
                }
            })
            .collect()
    }

    /// A bound's value.
    pub fn bound(&self, u: usize, b: &ast::Bound) -> u64 {
        self.model
            .bound(u, b)
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(0)
    }

    pub fn resolve(&self, u: usize, r: &ast::TypeRef) -> Option<TypeId> {
        self.model.resolve(u, r)
    }

    /// The layout facts of a type expression, without its `?`. Facts of a
    /// type that holds no open struct or union are the same at every
    /// minor, since a closed type never changes.
    pub fn facts(&self, u: usize, t: &Type) -> Facts {
        self.facts.borrow_mut().base(u, t)
    }

    /// Whether a type expression is read with a strict form in a request:
    /// it holds an open struct through members known at the minor.
    pub fn is_strict(&self, u: usize, t: &Type) -> bool {
        match &t.base {
            BaseType::Seq(e, _) | BaseType::Array(e, _) => self.is_strict(u, e),
            BaseType::Ref(r) => self
                .resolve(u, r)
                .is_some_and(|id| self.strict.contains(&id)),
            _ => false,
        }
    }

    /// Whether a named type has a strict form, `r-<type>`.
    pub fn has_strict(&self, id: TypeId) -> bool {
        self.strict.contains(&id)
    }

    /// The named types with a strict form. Strictness spreads from each
    /// open struct to every type that refers to it, along reverse edges
    /// with a worklist: linear in types and references, and no long chain
    /// of references can overflow the stack.
    fn strict_types(&self) -> BTreeSet<TypeId> {
        let mut referrers: BTreeMap<TypeId, Vec<TypeId>> = BTreeMap::new();
        let mut work = Vec::new();
        for (u, unit) in self.model.units.iter().enumerate() {
            if !self.prefixes.contains_key(&u) {
                continue;
            }
            for (m, member) in unit.members().iter().enumerate() {
                if !member.is_type() {
                    continue;
                }
                let id = TypeId { unit: u, member: m };
                let mut refs = Vec::new();
                match self.def(id) {
                    Def::Alias(t) => self.refs(id.unit, t, &mut refs),
                    Def::Struct { fields, closed } => {
                        let since = self.type_since(id);
                        for f in fields {
                            if self.known(id.unit, &f.attrs, since) {
                                self.refs(id.unit, &f.ty, &mut refs);
                            }
                        }
                        if !closed {
                            work.push(id);
                        }
                    }
                    Def::Union { .. } => {
                        for a in self.arms(id).iter().filter(|a| a.known) {
                            self.refs(id.unit, a.ty, &mut refs);
                        }
                    }
                    Def::Enum { .. } => {}
                }
                for r in refs {
                    referrers.entry(r).or_default().push(id);
                }
            }
        }
        let mut strict: BTreeSet<TypeId> = work.iter().copied().collect();
        while let Some(id) = work.pop() {
            for &by in referrers.get(&id).map_or(&[][..], Vec::as_slice) {
                if strict.insert(by) {
                    work.push(by);
                }
            }
        }
        strict
    }

    fn refs(&self, u: usize, t: &Type, out: &mut Vec<TypeId>) {
        layout::walk_refs(self.model, u, t, &mut |id| out.push(id));
    }

    /// The rule name of a named type in a generated grammar: `t-<type>`, or
    /// `r-<type>` for its strict form, after the unit's prefix. Names map
    /// `_` to `-` ("Generated grammars").
    pub fn type_rule(&self, id: TypeId, mode: Mode) -> String {
        let form = if mode == Mode::Strict && self.has_strict(id) {
            "r-"
        } else {
            "t-"
        };
        format!(
            "{}{form}{}",
            self.prefix(id.unit),
            kebab(self.type_name(id))
        )
    }

    /// The rule name of a top-level body.
    pub fn top_rule(&self, top: Top) -> String {
        let m = |i: usize, s: &str| format!("m-{}--{s}", kebab(self.member_name(i)));
        match top {
            Top::Request(i) => m(i, "req"),
            Top::Reply(i) => m(i, "rep"),
            Top::Open(i) => m(i, "open"),
            Top::Item(i) => m(i, "item"),
            Top::Error(i) => format!("e-{}", kebab(self.member_name(i))),
            Top::Type(id, mode) => self.type_rule(id, mode),
        }
    }

    /// Every top-level body that exists at the minor, in the order the
    /// generated files list them: methods, errors, then the root's types.
    pub fn tops(&self) -> Vec<Top> {
        let mut out = Vec::new();
        let unit = self.model.unit(self.root);
        for (i, m) in unit.members().iter().enumerate() {
            if !self.member_known(i) {
                continue;
            }
            if let MemberKind::Method(method) = &m.kind {
                out.push(Top::Request(i));
                if !ast::has_attr(&m.attrs, "oneway") {
                    out.push(Top::Reply(i));
                    if method.results.as_ref().is_some_and(|r| r.stream.is_some()) {
                        out.push(Top::Open(i));
                        out.push(Top::Item(i));
                    }
                }
            }
        }
        for (i, m) in unit.members().iter().enumerate() {
            if self.member_known(i) && matches!(m.kind, MemberKind::Error { .. }) {
                out.push(Top::Error(i));
            }
        }
        for (i, m) in unit.members().iter().enumerate() {
            if self.member_known(i) && m.is_type() {
                let id = TypeId {
                    unit: self.root,
                    member: i,
                };
                out.push(Top::Type(id, Mode::Tolerant));
                if self.has_strict(id) {
                    out.push(Top::Type(id, Mode::Strict));
                }
            }
        }
        out
    }

    /// Whether a method is one-way.
    pub fn oneway(&self, member: usize) -> bool {
        ast::has_attr(self.member_attrs(member), "oneway")
    }

    /// The errors a method lists, known at the minor.
    pub fn error_list(&self, member: usize) -> Vec<&'m str> {
        let unit = self.model.unit(self.root);
        self.method(member)
            .errors
            .iter()
            .filter(|e| {
                unit.errors
                    .get(&e.name)
                    .is_some_and(|&i| self.member_known(i))
            })
            .map(|e| e.name.as_str())
            .collect()
    }
}

/// A member name as a rule-name part: `_` becomes `-`.
pub fn kebab(name: &str) -> String {
    name.replace('_', "-")
}

fn unreachable_method() -> &'static ast::Method {
    // A member index the schema hands out always names a method; this is
    // only reached through a caller's mistake.
    panic!("not a method")
}
