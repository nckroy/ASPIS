// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The checker: what the grammar can't say (ADR 0067; docs/design/
//! call-language.md, "The IDL grammar", "Types", "Attributes", "How
//! numbers stay stable", "Capability types", "Server streams in the IDL").
//!
//! It runs in two phases. The first checks the header, names, numbers,
//! attributes, `since`, references, bounds and type cycles. When that is
//! clean, every type resolves and none contains itself, so the second can
//! compute the layout and check what depends on it: closed types, element
//! types, capabilities, streams and worst-case sizes.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    ast::{
        self, Arm, Attr, AttrArg, BaseType, Bound, Field, IdLit, IfaceRef, IntType, Member,
        MemberKind, ResultsKind, Type, Value, Version,
    },
    diag::{Code, Diagnostic, Span},
    layout::{self, Facts, KERNEL_CALLED, Types, is_kernel_object, result_fields, since_of},
    model::{Model, TypeId, Unit},
};

/// What an attribute list belongs to ("Attributes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Item {
    Interface,
    /// A struct, union, enum or flags type.
    Type,
    Object,
    /// A constant or an alias.
    Plain,
    Error,
    Method,
    Reserved,
    /// A field, parameter, result, error-detail field or object attribute.
    Field,
    Arm,
    Value,
}

impl Item {
    fn allows(self, name: &str) -> bool {
        let list: &[&str] = match self {
            Item::Interface => &["id", "object_id", "version", "kernel", "local", "groups"],
            Item::Type => &["closed", "since", "deprecated"],
            Item::Object => &["type", "parents", "since", "deprecated"],
            Item::Plain => &["since", "deprecated"],
            Item::Error => &["refused", "retry", "since", "deprecated"],
            Item::Method => &[
                "local",
                "oneway",
                "group",
                "idempotent",
                "readonly",
                "lossy",
                "coalescing",
                "requires",
                "static",
                "since",
                "deprecated",
            ],
            Item::Reserved => &[],
            Item::Field => &["since", "deprecated", "sensitive", "format"],
            Item::Arm => &["since", "deprecated", "format"],
            Item::Value => &["since", "deprecated"],
        };
        list.contains(&name)
    }

    fn what(self) -> &'static str {
        match self {
            Item::Interface => "an interface",
            Item::Type => "a type",
            Item::Object => "an object",
            Item::Plain => "a constant or an alias",
            Item::Error => "an error",
            Item::Method => "a method",
            Item::Reserved => "a reserved method",
            Item::Field => "a field",
            Item::Arm => "a union arm",
            Item::Value => "an enum or flags value",
        }
    }
}

/// The highest IDL method number: `0xFF00` up are the call protocol's own
/// ("Method numbers").
pub const MAX_METHOD: u16 = 0xFEFF;

/// A member name's generated Rust type or variant name: UpperCamelCase.
pub fn camel(name: &str) -> String {
    let mut out = String::new();
    for part in name.split('_') {
        let mut chars = part.chars();
        if let Some(c) = chars.next() {
            out.push(c.to_ascii_uppercase());
            out.extend(chars);
        }
    }
    out
}

/// Runs every rule on unit `u`, with the front end's `limits`.
pub fn run(model: &Model, u: usize, limits: &crate::Limits) -> Vec<Diagnostic> {
    let unit = model.unit(u);
    let mut c = Checker {
        model,
        u,
        unit,
        nesting: limits.nesting,
        base: Version {
            major: unit.major(),
            minor: 0,
        },
        diags: Vec::new(),
    };
    c.header();
    c.names();
    c.declarations();
    c.cycles();
    if c.diags.is_empty() {
        c.with_layout();
    }
    c.diags.sort_by_key(|d| d.span.start);
    c.diags
}

struct Checker<'m> {
    model: &'m Model,
    u: usize,
    unit: &'m Unit,
    /// How deep a value may nest ([`crate::Limits::nesting`]).
    nesting: usize,
    /// M.0.
    base: Version,
    diags: Vec<Diagnostic>,
}

impl<'m> Checker<'m> {
    fn err(&mut self, span: Span, code: Code, message: impl Into<String>) {
        self.diags.push(Diagnostic::new(span, code, message));
    }

    fn members(&self) -> &'m [Member] {
        &self.unit.file.interface.members
    }

    fn kernel(&self) -> bool {
        self.unit.is_kernel()
    }

    // ---- The header (rule 1 of the checker's list) -------------------------

    fn header(&mut self) {
        let iface = &self.unit.file.interface;
        self.attrs(&iface.attrs, Item::Interface);
        let span = iface.name.span;
        match ast::attr(&iface.attrs, "id").and_then(|a| a.args.as_deref()) {
            Some([AttrArg::Name(n, s)]) => {
                if n.rsplit('.').next() != Some(iface.name.name.as_str()) {
                    self.err(
                        span,
                        Code::Header,
                        format!(
                            "the interface is named '{}', but id({n}) ends with another label",
                            iface.name.name
                        ),
                    );
                }
                let called = KERNEL_CALLED.contains(&n.as_str());
                if called && (self.kernel() || !ast::has_attr(&iface.attrs, "local")) {
                    self.err(*s, Code::Header, format!("{n} is an interface the kernel calls: it is [local], not [kernel] (ADR 0063, rule 3)"));
                }
            }
            _ => self.err(
                span,
                Code::Header,
                "the header needs id(...), the interface's full dotted name",
            ),
        }
        if ast::version_attr(&iface.attrs, "version").is_none() {
            self.err(
                span,
                Code::Header,
                "the header needs version(M.m), the newest minor described",
            );
        }
        if ast::attr(&iface.attrs, "object_id").is_none() {
            self.err(
                span,
                Code::Header,
                "the header needs object_id(reserved(n)) or object_id(hex(...))",
            );
        }
    }

    // ---- Attributes ----------------------------------------------------------

    /// The closed attribute set: each where the table allows it, once, with
    /// the right arguments.
    fn attrs(&mut self, attrs: &[Attr], item: Item) {
        let mut seen = BTreeSet::new();
        for a in attrs {
            let name = a.name.name.as_str();
            if !crate::canon::ATTRIBUTE_ORDER.contains(&name) {
                self.err(
                    a.span,
                    Code::Attribute,
                    format!("unknown attribute '{name}': the attribute set is closed"),
                );
                continue;
            }
            if !item.allows(name) {
                self.err(
                    a.span,
                    Code::Attribute,
                    format!("[{name}] can't stand on {}", item.what()),
                );
                continue;
            }
            if !seen.insert(name) {
                self.err(a.span, Code::Attribute, format!("[{name}] is given twice"));
                continue;
            }
            self.attr_args(a);
        }
    }

    fn attr_args(&mut self, a: &Attr) {
        let name = a.name.name.as_str();
        let args = a.args.as_deref();
        let ok = match name {
            "kernel" | "local" | "oneway" | "idempotent" | "readonly" | "lossy" | "coalescing" | "static"
            | "sensitive" | "closed" | "refused" => args.is_none(),
            "version" | "since" | "deprecated" => matches!(args, Some([AttrArg::Version(..)])),
            "id" | "type" => matches!(args, Some([AttrArg::Name(..)])),
            "object_id" => match args {
                Some([AttrArg::Id(IdLit::Reserved(n), _)]) => n.value.is_some_and(|v| u64::try_from(v).is_ok()),
                Some([AttrArg::Id(IdLit::Hex(_), _)]) => true,
                _ => false,
            },
            "parents" => args.is_some_and(|a| a.iter().all(|x| matches!(x, AttrArg::Name(..)))),
            "groups" | "group" => args.is_some_and(|a| a.iter().all(|x| matches!(x, AttrArg::Member(..)))),
            "requires" => args.is_some_and(|a| {
                a.iter().all(|x| matches!(x, AttrArg::Member(r, _) if ["read", "write", "grant", "grant_reply"].contains(&r.as_str())))
            }),
            "retry" => matches!(args, Some([AttrArg::Member(r, _)]) if ["never", "later", "rebind", "higher"].contains(&r.as_str())),
            "format" => matches!(args, Some([AttrArg::Member(f, _)]) if f == "json"),
            _ => true,
        };
        if !ok {
            let shape = match name {
                "version" | "since" | "deprecated" => "a version, M.m",
                "id" | "type" => "one dotted name",
                "object_id" => "reserved(n), n a u64, or hex(...)",
                "parents" => "dotted type names",
                "groups" | "group" => "group names",
                "requires" => "rights: read, write, grant, grant_reply",
                "retry" => "never, later, rebind or higher",
                "format" => "json",
                _ => "no arguments",
            };
            self.err(a.span, Code::Attribute, format!("[{name}] takes {shape}"));
        }
        if let Some(args) = args {
            let mut seen = BTreeSet::new();
            for x in args {
                if let AttrArg::Member(n, s) | AttrArg::Name(n, s) = x
                    && !seen.insert(n.as_str())
                {
                    self.err(*s, Code::Attribute, format!("'{n}' is given twice"));
                }
            }
        }
    }

    // ---- Names (rule 3) -------------------------------------------------------

    fn names(&mut self) {
        // Declared types share one namespace with imported names and
        // objects; constants, errors and methods have their own. Rust
        // forms collide where two names give one UpperCamelCase name.
        let mut types: BTreeMap<String, Span> = BTreeMap::new();
        let mut type_rust: BTreeMap<String, String> = BTreeMap::new();
        let mut consts = BTreeMap::new();
        let mut errors = BTreeMap::new();
        let mut error_rust: BTreeMap<String, String> = BTreeMap::new();
        let mut methods = BTreeMap::new();
        let unit = self.unit;
        for use_ in &unit.file.uses {
            for n in &use_.names {
                self.declare(&mut types, &mut type_rust, &n.name, n.span, "type");
            }
        }
        for m in self.members() {
            let Some(n) = m.name() else { continue };
            match &m.kind {
                MemberKind::Const { .. } => self.unique(&mut consts, &n.name, n.span, "constant"),
                MemberKind::Error { .. } => {
                    self.declare(&mut errors, &mut error_rust, &n.name, n.span, "error")
                }
                MemberKind::Method(_) => self.unique(&mut methods, &n.name, n.span, "method"),
                _ => self.declare(&mut types, &mut type_rust, &n.name, n.span, "type"),
            }
        }
    }

    fn unique(&mut self, seen: &mut BTreeMap<String, Span>, name: &str, span: Span, what: &str) {
        if seen.insert(name.to_string(), span).is_some() {
            self.err(
                span,
                Code::Duplicate,
                format!("{what} '{name}' is declared twice"),
            );
        }
    }

    /// A name that is unique, and whose Rust name is unique too.
    fn declare(
        &mut self,
        seen: &mut BTreeMap<String, Span>,
        rust: &mut BTreeMap<String, String>,
        name: &str,
        span: Span,
        what: &str,
    ) {
        if seen.insert(name.to_string(), span).is_some() {
            self.err(
                span,
                Code::Duplicate,
                format!("{what} '{name}' is declared twice"),
            );
            return;
        }
        if let Some(other) = rust.insert(camel(name), name.to_string()) {
            self.err(
                span,
                Code::Duplicate,
                format!(
                    "{what} '{name}' and '{other}' both become the Rust name {}",
                    camel(name)
                ),
            );
        }
    }

    // ---- Members ------------------------------------------------------------

    fn declarations(&mut self) {
        let unit = self.unit;
        // Method numbers (rule 2).
        let mut numbers: BTreeMap<u16, ()> = BTreeMap::new();
        let mut codes: BTreeMap<i128, ()> = BTreeMap::new();
        let declared_groups: Vec<(String, Span)> = ast::attr(&unit.file.interface.attrs, "groups")
            .and_then(|a| a.args.as_ref())
            .map(|args| {
                args.iter()
                    .filter_map(|a| match a {
                        AttrArg::Member(n, s) => Some((n.clone(), *s)),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut used_groups = BTreeSet::new();

        for m in self.members() {
            let since = self.since_attr(&m.attrs, self.base, m.span);
            match &m.kind {
                MemberKind::Const { name, ty, value } => {
                    self.attrs(&m.attrs, Item::Plain);
                    let (lo, hi) = ty.range();
                    if !value.value.is_some_and(|v| (lo..=hi).contains(&v)) {
                        self.err(
                            value.span,
                            Code::Number,
                            format!("constant '{}' is out of range for {}", name.name, ty.word()),
                        );
                    }
                }
                MemberKind::Alias { ty, .. } => {
                    self.attrs(&m.attrs, Item::Plain);
                    if ty.optional {
                        self.err(ty.span, Code::Type, "an alias names a type, not an optional one: write '?' where it is used");
                    }
                    self.ty(ty, since, false);
                }
                MemberKind::Struct { fields, .. } => {
                    self.attrs(&m.attrs, Item::Type);
                    let closed = ast::has_attr(&m.attrs, "closed");
                    self.fields(fields, since, closed);
                }
                MemberKind::Object { name, fields } => {
                    self.attrs(&m.attrs, Item::Object);
                    match ast::attr(&m.attrs, "type").and_then(|a| a.args.as_deref()) {
                        Some([AttrArg::Name(t, s)]) => {
                            if t.rsplit('.').next() != Some(name.name.as_str()) {
                                self.err(*s, Code::Header, format!("object '{}' needs a type(...) whose last label is its name", name.name));
                            }
                        }
                        _ => self.err(
                            name.span,
                            Code::Header,
                            format!(
                                "object '{}' needs type(...), its full dotted name",
                                name.name
                            ),
                        ),
                    }
                    self.fields(fields, since, false);
                }
                MemberKind::Union { name, arms } => {
                    self.attrs(&m.attrs, Item::Type);
                    let closed = ast::has_attr(&m.attrs, "closed");
                    self.arms(name.span, arms, since, closed);
                }
                MemberKind::Enum {
                    flags,
                    name,
                    width,
                    width_span,
                    values,
                } => {
                    self.attrs(&m.attrs, Item::Type);
                    if !flags && *width == IntType::U64 {
                        self.err(
                            *width_span,
                            Code::Type,
                            format!("enum '{}' is u8, u16 or u32", name.name),
                        );
                    }
                    let closed = ast::has_attr(&m.attrs, "closed");
                    self.values(values, *flags, *width, since, closed);
                }
                MemberKind::Error { name, code, fields } => {
                    self.attrs(&m.attrs, Item::Error);
                    match code.value {
                        Some(v @ 1..=65535) => {
                            if codes.insert(v, ()).is_some() {
                                self.err(
                                    code.span,
                                    Code::Number,
                                    format!("error code {v} is used twice"),
                                );
                            }
                        }
                        _ => self.err(
                            code.span,
                            Code::Number,
                            format!("error '{}' needs a code from 1 to 65535", name.name),
                        ),
                    }
                    if let Some(fs) = fields {
                        self.fields(fs, since, false);
                    }
                }
                MemberKind::Method(method) => {
                    self.attrs(&m.attrs, Item::Method);
                    if method.ordinal > MAX_METHOD {
                        self.err(
                            method.ordinal_span,
                            Code::Number,
                            "IDL methods use 1 to 65279: 0xFF00 up are the call protocol's",
                        );
                    }
                    if numbers.insert(method.ordinal, ()).is_some() {
                        self.err(
                            method.ordinal_span,
                            Code::Number,
                            format!("method number {} is used twice", method.ordinal),
                        );
                    }
                    self.method(m, method, since, &declared_groups, &mut used_groups);
                }
                MemberKind::Reserved { ordinal } => {
                    self.attrs(&m.attrs, Item::Reserved);
                    if *ordinal > MAX_METHOD {
                        self.err(
                            m.span,
                            Code::Number,
                            "IDL methods use 1 to 65279: 0xFF00 up are the call protocol's",
                        );
                    }
                    if numbers.insert(*ordinal, ()).is_some() {
                        self.err(
                            m.span,
                            Code::Number,
                            format!("method number {ordinal} is used twice"),
                        );
                    }
                }
            }
        }
        // Rule 10: every declared group has a method.
        let mut seen = BTreeSet::new();
        for (g, s) in &declared_groups {
            if !seen.insert(g.clone()) {
                continue;
            }
            if !used_groups.contains(g) {
                self.err(
                    *s,
                    Code::Group,
                    format!("group '{g}' has no method: a group exists where a method names it"),
                );
            }
        }
    }

    /// A member's `since` and `deprecated` (rule 5). Returns its effective
    /// `since`: its own, or its container's.
    fn since_attr(&mut self, attrs: &[Attr], container: Version, span: Span) -> Version {
        let version = self.unit.version;
        for a in attrs {
            let name = a.name.name.as_str();
            if name != "since" && name != "deprecated" {
                continue;
            }
            let Some(v) = ast::version_attr(core::slice::from_ref(a), name) else {
                continue;
            };
            if v.major != version.major || v.minor > version.minor {
                self.err(
                    a.span,
                    Code::Since,
                    format!(
                        "[{name}({}.{})] must name a minor of {}.0 to {}.{}",
                        v.major, v.minor, version.major, version.major, version.minor
                    ),
                );
            }
            if name == "since" && v < container {
                self.err(
                    a.span,
                    Code::Since,
                    format!(
                        "[since({}.{})] is before its container's, {}.{}",
                        v.major, v.minor, container.major, container.minor
                    ),
                );
            }
        }
        let effective = since_of(attrs, container);
        if let Some(d) = ast::version_attr(attrs, "deprecated")
            && d < effective
        {
            self.err(span, Code::Since, "deprecated before it was added");
        }
        effective
    }

    /// Struct fields, parameters, results, error details and object
    /// attributes: appended in order, and new ones optional (rule 5).
    fn fields(&mut self, fields: &[Field], container: Version, closed: bool) {
        let mut names = BTreeSet::new();
        let mut last = container;
        for (i, f) in fields.iter().enumerate() {
            self.attrs(&f.attrs, Item::Field);
            if !names.insert(f.name.name.as_str()) {
                self.err(
                    f.name.span,
                    Code::Duplicate,
                    format!("field '{}' is declared twice", f.name.name),
                );
            }
            if let Some((n, s)) = f.ordinal
                && usize::from(n) != i + 1
            {
                self.err(
                    s,
                    Code::Number,
                    format!("field '{}' is at position {}, not {n}", f.name.name, i + 1),
                );
            }
            let since = self.since_attr(&f.attrs, container, f.span);
            if since < last {
                self.err(
                    f.span,
                    Code::Since,
                    format!(
                        "field '{}' comes after a field of a later minor: fields are only appended",
                        f.name.name
                    ),
                );
            }
            last = last.max(since);
            if since > container {
                if closed {
                    self.err(
                        f.span,
                        Code::Since,
                        "a closed type never changes within its major",
                    );
                } else if !f.ty.optional {
                    self.err(
                        f.span,
                        Code::Since,
                        format!(
                            "field '{}' is newer than its container, so it must be optional",
                            f.name.name
                        ),
                    );
                }
            }
            if ast::has_attr(&f.attrs, "format") {
                self.format_json(&f.ty);
            }
            self.ty(&f.ty, since, false);
        }
    }

    fn format_json(&mut self, t: &Type) {
        if !matches!(t.base, BaseType::String(_)) {
            self.err(
                t.span,
                Code::Attribute,
                "[format(json)] stands only on string<N>",
            );
        }
    }

    fn arms(&mut self, span: Span, arms: &[Arm], container: Version, closed: bool) {
        let mut names = BTreeSet::new();
        let mut rust = BTreeMap::new();
        let mut numbers = BTreeSet::new();
        let mut any = false;
        for a in arms {
            let (ordinal, s) = match a {
                Arm::Arm {
                    attrs,
                    ordinal,
                    name,
                    ty,
                    span,
                    ..
                } => {
                    any = true;
                    self.attrs(attrs, Item::Arm);
                    if !names.insert(name.name.as_str()) {
                        self.err(
                            name.span,
                            Code::Duplicate,
                            format!("arm '{}' is declared twice", name.name),
                        );
                    } else if let Some(o) = rust.insert(camel(&name.name), name.name.clone()) {
                        self.err(
                            name.span,
                            Code::Duplicate,
                            format!(
                                "arms '{}' and '{o}' both become the Rust name {}",
                                name.name,
                                camel(&name.name)
                            ),
                        );
                    }
                    let since = self.since_attr(attrs, container, *span);
                    if since > container && closed {
                        self.err(
                            *span,
                            Code::Since,
                            "a closed type never changes within its major",
                        );
                    }
                    if ast::has_attr(attrs, "format") {
                        self.format_json(ty);
                    }
                    self.ty(ty, since, false);
                    (*ordinal, *span)
                }
                Arm::Reserved { ordinal, span } => (*ordinal, *span),
            };
            if !numbers.insert(ordinal) {
                self.err(s, Code::Number, format!("arm @{ordinal} is used twice"));
            }
        }
        if closed && !any {
            self.err(span, Code::Type, "a closed union needs an arm");
        }
    }

    fn values(
        &mut self,
        values: &[Value],
        flags: bool,
        width: IntType,
        container: Version,
        closed: bool,
    ) {
        let mut names = BTreeSet::new();
        let mut rust = BTreeMap::new();
        let mut numbers = BTreeSet::new();
        let (_, max) = width.range();
        for v in values {
            let (lit, span) = match v {
                Value::Value {
                    attrs,
                    name,
                    value,
                    span,
                    ..
                } => {
                    self.attrs(attrs, Item::Value);
                    if !names.insert(name.name.as_str()) {
                        self.err(
                            name.span,
                            Code::Duplicate,
                            format!("value '{}' is declared twice", name.name),
                        );
                    } else if let Some(o) = rust.insert(camel(&name.name), name.name.clone()) {
                        self.err(
                            name.span,
                            Code::Duplicate,
                            format!(
                                "values '{}' and '{o}' both become the Rust name {}",
                                name.name,
                                camel(&name.name)
                            ),
                        );
                    }
                    let since = self.since_attr(attrs, container, *span);
                    if since > container && closed {
                        self.err(
                            *span,
                            Code::Since,
                            "a closed type never changes within its major",
                        );
                    }
                    (value, *span)
                }
                Value::Reserved { value, span } => (value, *span),
            };
            match lit.value {
                Some(n) if (0..=max).contains(&n) => {
                    if flags && n.count_ones() != 1 {
                        self.err(lit.span, Code::Number, "a flag's value is a single bit");
                    }
                    if !numbers.insert(n) {
                        self.err(span, Code::Number, format!("value {n} is used twice"));
                    }
                }
                _ => self.err(
                    lit.span,
                    Code::Number,
                    format!("a value of 0 to {max}, for {}", width.word()),
                ),
            }
        }
    }

    /// A type expression used by an item whose effective `since` is
    /// `since`: references resolve, bounds are in range, and capability
    /// and slot types are well formed (rules 6, 7 and 13).
    fn ty(&mut self, t: &Type, since: Version, element: bool) {
        match &t.base {
            BaseType::String(b) | BaseType::Bytes(b) => self.bound(b, u64::from(u32::MAX), since),
            BaseType::Seq(e, b) => {
                self.bound(b, u64::from(u32::MAX), since);
                self.ty(e, since, true);
            }
            BaseType::Array(e, b) => {
                self.bound(b, 65_535, since);
                self.ty(e, since, true);
            }
            BaseType::Cap(r, quals) => {
                if element {
                    self.err(
                        t.span,
                        Code::Capability,
                        "a capability can't be a sequence's or an array's element",
                    );
                }
                self.cap(r, quals);
            }
            BaseType::Slot(r, quals) => {
                if !self.kernel() {
                    self.err(
                        t.span,
                        Code::Capability,
                        "slot<...> stands only in [kernel] interfaces",
                    );
                }
                if element {
                    self.err(
                        t.span,
                        Code::Capability,
                        "a slot can't be a sequence's or an array's element",
                    );
                }
                if !is_kernel_object(&r.name) {
                    self.err(
                        r.span,
                        Code::Capability,
                        "a slot names a kernel object's interface, aspis.kernel.*",
                    );
                }
                self.cap(r, quals);
            }
            BaseType::Ref(r) => match self.model.resolve(self.u, r) {
                Some(id) => {
                    if id.unit == self.u {
                        let target = since_of(&self.model.member(id).attrs, self.base);
                        if target > since {
                            self.err(
                                r.name.span,
                                Code::Since,
                                format!("'{}' is newer than what uses it", r.name.name),
                            );
                        }
                    }
                }
                None => {
                    let what = if self.unit.objects.contains_key(&r.name.name) {
                        "is an object type, which no field may hold"
                    } else if self.unit.consts.contains_key(&r.name.name)
                        || self.unit.errors.contains_key(&r.name.name)
                    {
                        "isn't a type"
                    } else {
                        "names no declared or imported type"
                    };
                    self.err(
                        r.name.span,
                        Code::Reference,
                        format!("'{}' {what}", r.name.name),
                    );
                }
            },
            _ => {}
        }
    }

    fn bound(&mut self, b: &Bound, max: u64, since: Version) {
        let (value, span) = match b {
            Bound::Lit(l) => (l.value, l.span),
            Bound::Const(c) => match self.unit.consts.get(&c.name) {
                Some(&m) => {
                    let target = since_of(&self.members()[m].attrs, self.base);
                    if target > since {
                        self.err(
                            c.span,
                            Code::Since,
                            format!("'{}' is newer than what uses it", c.name),
                        );
                    }
                    (self.model.bound(self.u, b), c.span)
                }
                None => {
                    self.err(
                        c.span,
                        Code::Reference,
                        format!("'{}' names no constant", c.name),
                    );
                    return;
                }
            },
        };
        if !value.is_some_and(|v| v >= 1 && v <= i128::from(max)) {
            self.err(span, Code::Type, format!("a bound is 1 to {max}"));
        }
    }

    /// A capability's interface and qualifiers ("Capability types"). The
    /// interface isn't resolved: the kernel's are C17's (rule 13).
    fn cap(&mut self, r: &IfaceRef, quals: &[(ast::CapQual, Span)]) {
        let mut seen = BTreeSet::new();
        for (q, s) in quals {
            if !seen.insert(*q) {
                self.err(
                    *s,
                    Code::Capability,
                    format!("'{}' is given twice", q.word()),
                );
            }
            if !is_kernel_object(&r.name) {
                self.err(*s, Code::Capability, "rights qualifiers stand only on a kernel object's capability, aspis.kernel.*: a session capability's rights are computed");
            } else if *q == ast::CapQual::Immutable && r.name != "aspis.kernel.memory" {
                self.err(
                    *s,
                    Code::Capability,
                    "'immutable' stands only on aspis.kernel.memory",
                );
            }
        }
    }

    fn method(
        &mut self,
        m: &Member,
        method: &ast::Method,
        since: Version,
        declared: &[(String, Span)],
        used: &mut BTreeSet<String>,
    ) {
        let kernel = self.kernel();
        let local = self.unit.is_local();
        for a in &m.attrs {
            let name = a.name.name.as_str();
            if (name == "requires" || name == "static") && !kernel {
                self.err(
                    a.span,
                    Code::Attribute,
                    format!("[{name}] stands only on a method of a [kernel] interface"),
                );
            }
            if name == "oneway" && !local {
                self.err(
                    a.span,
                    Code::Attribute,
                    "[oneway] stands only on a method of a [local] interface",
                );
            }
        }
        let oneway = ast::has_attr(&m.attrs, "oneway");
        if oneway && (method.results.is_some() || !method.errors.is_empty()) {
            self.err(
                method.name.span,
                Code::Attribute,
                "a [oneway] method has no results and no error(...) list",
            );
        }
        let stream = method.results.as_ref().and_then(|r| r.stream.as_ref());
        let lossy = ast::has_attr(&m.attrs, "lossy");
        let coalescing = ast::has_attr(&m.attrs, "coalescing");
        if (lossy || coalescing) && stream.is_none() {
            self.err(
                method.name.span,
                Code::Attribute,
                "[lossy] and [coalescing] stand only on a stream method",
            );
        }
        if lossy && coalescing {
            self.err(
                method.name.span,
                Code::Attribute,
                "a stream is [lossy] or [coalescing], not both",
            );
        }
        // Groups (rule 10).
        if let Some(a) = ast::attr(&m.attrs, "group") {
            for g in a.args.iter().flatten() {
                if let AttrArg::Member(g, s) = g {
                    if declared.iter().any(|(d, _)| d == g) {
                        used.insert(g.clone());
                    } else {
                        self.err(
                            *s,
                            Code::Group,
                            format!("group '{g}' isn't declared in the header's groups(...)"),
                        );
                    }
                }
            }
        }
        // Errors (rule 11).
        let mut listed = BTreeSet::new();
        for e in &method.errors {
            if !self.unit.errors.contains_key(&e.name) {
                self.err(
                    e.span,
                    Code::ErrorList,
                    format!(
                        "'{}' isn't an error of this interface: system errors are never listed",
                        e.name
                    ),
                );
            } else if !listed.insert(e.name.as_str()) {
                self.err(
                    e.span,
                    Code::ErrorList,
                    format!("'{}' is listed twice", e.name),
                );
            }
        }
        // Parameters and results are open structs.
        let mut names = BTreeSet::new();
        for p in &method.params {
            names.insert(p.name.name.as_str());
        }
        self.fields(&method.params, since, false);
        if let Some(r) = &method.results {
            match &r.kind {
                ResultsKind::Fields(fs) => self.fields(fs, since, false),
                ResultsKind::Single(t) => self.ty(t, since, false),
                ResultsKind::None => {}
            }
            if let Some(s) = &r.stream {
                // Rule 9: a resume parameter, `after: u64?`.
                let after = method.params.iter().any(|p| {
                    p.name.name == "after"
                        && p.ty.optional
                        && p.ty.base == BaseType::Int(IntType::U64)
                });
                if !after {
                    self.err(s.name.span, Code::Stream, "a stream method needs the parameter 'after: u64?', so the binding can resume it");
                }
                match self.model.resolve(self.u, s) {
                    Some(id) => {
                        if !matches!(self.model.member(id).kind, MemberKind::Struct { .. }) {
                            self.err(
                                s.name.span,
                                Code::Stream,
                                "a stream's item type is a struct",
                            );
                        }
                    }
                    None => self.err(
                        s.name.span,
                        Code::Reference,
                        format!("'{}' names no declared or imported type", s.name.name),
                    ),
                }
            }
        }
    }

    // ---- Type cycles (rule 6) ---------------------------------------------

    /// No type contains itself, through fields, arms, elements or aliases.
    /// Imported types can't reach back, so only local types are walked.
    fn cycles(&mut self) {
        if !self.diags.is_empty() {
            return;
        }
        let model = self.model;
        let u = self.u;
        let mut done = BTreeSet::new();
        for (i, m) in self.members().iter().enumerate() {
            if !m.is_type() || done.contains(&i) {
                continue;
            }
            // An iterative depth-first walk: each entry is a type and the
            // index of its next reference.
            let mut path: Vec<(usize, Vec<usize>, usize)> = Vec::new();
            let refs = |i: usize| {
                let mut v = Vec::new();
                layout::for_each_ref(model, TypeId { unit: u, member: i }, &mut |d| {
                    if d.unit == u {
                        v.push(d.member)
                    }
                });
                v
            };
            path.push((i, refs(i), 0));
            while let Some((top, deps, next)) = path.last_mut() {
                let top = *top;
                let Some(&d) = deps.get(*next) else {
                    done.insert(top);
                    path.pop();
                    continue;
                };
                *next += 1;
                if done.contains(&d) {
                    continue;
                }
                if path.iter().any(|(p, _, _)| *p == d) {
                    let name = self.members()[d]
                        .name()
                        .map(|n| n.name.clone())
                        .unwrap_or_default();
                    let span = self.members()[d].span;
                    self.err(
                        span,
                        Code::Type,
                        format!(
                            "type '{name}' contains itself: recursive types aren't in edition 2026"
                        ),
                    );
                    return;
                }
                path.push((d, refs(d), 0));
            }
        }
    }

    // ---- Rules that need the layout ---------------------------------------

    fn with_layout(&mut self) {
        let model = self.model;
        let u = self.u;
        let base = self.base;
        let mut types = Types::new(model);
        let members = self.members();
        for (i, m) in members.iter().enumerate() {
            let since = since_of(&m.attrs, base);
            let closed = ast::has_attr(&m.attrs, "closed");
            if let MemberKind::Struct { .. } | MemberKind::Union { .. } | MemberKind::Alias { .. } =
                &m.kind
            {
                // Each declared type is the top of its own rule, so its
                // value walkers and samples start there.
                let t = types.named(TypeId { unit: u, member: i });
                let name = m.name().map(|n| n.name.as_str()).unwrap_or_default();
                self.depth(m.span, &format!("type '{name}'"), t.depth);
                if t.max > layout::MAX_REPLY {
                    self.err(
                        m.span,
                        Code::Size,
                        format!(
                            "type '{name}' may reach {} octets, over {}: no message could hold it",
                            t.max,
                            layout::MAX_REPLY
                        ),
                    );
                }
            }
            match &m.kind {
                MemberKind::Struct { fields, .. } => {
                    for f in fields {
                        let t = types.base(u, &f.ty);
                        self.elements(&mut types, &f.ty);
                        if closed && t.open {
                            self.err(f.span, Code::Type, "a closed type holds no open struct or open union, which a later minor could grow");
                        }
                        self.new_member_caps(&f.attrs, since, &t, f.span);
                    }
                }
                MemberKind::Union { arms, .. } => {
                    for a in arms {
                        if let Arm::Arm {
                            attrs, ty, span, ..
                        } = a
                        {
                            let t = types.ty(u, ty);
                            self.elements(&mut types, ty);
                            if closed && t.open {
                                self.err(*span, Code::Type, "a closed type holds no open struct or open union, which a later minor could grow");
                            }
                            self.new_member_caps(attrs, since, &t, *span);
                        }
                    }
                }
                MemberKind::Alias { ty, .. } => self.elements(&mut types, ty),
                MemberKind::Object { fields, .. } => {
                    for f in fields {
                        let t = types.base(u, &f.ty);
                        self.elements(&mut types, &f.ty);
                        if t.has_float || t.has_bytes || t.has_cap || t.has_slot {
                            self.err(f.span, Code::Type, "an object's attributes have a Cedar mapping: no floats, bytes, capabilities or slots");
                        }
                    }
                }
                MemberKind::Error { fields, .. } => {
                    let all = fields.as_deref().unwrap_or(&[]);
                    let d = types.fields(u, all, true).depth;
                    let name = m.name().map(|n| n.name.as_str()).unwrap_or_default();
                    self.depth(m.span, &format!("error '{name}''s detail"), d);
                    for f in fields.iter().flatten() {
                        let t = types.base(u, &f.ty);
                        self.elements(&mut types, &f.ty);
                        if t.has_cap || t.has_slot {
                            self.err(f.span, Code::Capability, "errors carry no capabilities");
                        }
                    }
                }
                MemberKind::Method(method) => {
                    let name = &method.name.name;
                    let d = types.fields(u, &method.params, true).depth;
                    self.depth(method.name.span, &format!("method '{name}''s request"), d);
                    let mut all = method.params.clone();
                    if let Some(r) = &method.results {
                        let d = types.fields(u, &result_fields(r), true).depth;
                        self.depth(method.name.span, &format!("method '{name}''s reply"), d);
                        all.extend(result_fields(r));
                        if let Some(s) = &r.stream
                            && let Some(id) = model.resolve(u, s)
                        {
                            let t = types.named(id);
                            if t.has_cap || t.has_slot {
                                self.err(
                                    s.name.span,
                                    Code::Capability,
                                    "a stream item holds no capability",
                                );
                            }
                        }
                    }
                    for f in &all {
                        let t = types.base(u, &f.ty);
                        self.elements(&mut types, &f.ty);
                        self.new_member_caps(&f.attrs, since, &t, f.span);
                    }
                }
                _ => {}
            }
        }
        self.sizes();
    }

    /// No capability or slot inside a sequence's or an array's element,
    /// directly or nested (rule 6). And no element that encodes to zero
    /// octets, such as a closed struct with no fields: a decoder's work
    /// would follow a count the sender picks, not the input's length.
    fn elements(&mut self, types: &mut Types<'_>, t: &Type) {
        match &t.base {
            BaseType::Seq(e, _) | BaseType::Array(e, _) => {
                let f = types.ty(self.u, e);
                if f.has_cap || f.has_slot {
                    self.err(
                        e.span,
                        Code::Capability,
                        "a sequence's or an array's element holds no capability or slot",
                    );
                }
                if f.min == 0 {
                    self.err(
                        e.span,
                        Code::Type,
                        "a sequence's or an array's element encodes to at least one octet",
                    );
                }
                self.elements(types, e);
            }
            _ => {}
        }
    }

    /// A value nests at most [`crate::Limits::nesting`] deep, counted
    /// through named types ("Types", Limits), so every value walker's
    /// recursion is bounded (ADR 0068, rule 5).
    fn depth(&mut self, span: Span, what: &str, depth: u32) {
        if depth as usize > self.nesting {
            self.err(
                span,
                Code::Limit,
                format!(
                    "{what} nests {depth} deep, over {}: each type expression is a level, through named types",
                    self.nesting
                ),
            );
        }
    }

    /// A field or arm newer than its container holds no capability:
    /// preserved octets never do ("Rules for readers").
    fn new_member_caps(&mut self, attrs: &[Attr], container: Version, t: &Facts, span: Span) {
        if since_of(attrs, container) > container && (t.has_cap || t.has_slot) {
            self.err(span, Code::Capability, "a field or arm added in a minor holds no capability: new capabilities come with new methods");
        }
    }

    /// Worst-case sizes and capability counts (rules 7 and 8).
    fn sizes(&mut self) {
        let layout = layout::compute(self.model, self.u);
        let kernel = self.kernel();
        for ml in &layout.methods {
            let span = match &self.members()[ml.member].kind {
                MemberKind::Method(m) => m.name.span,
                _ => self.members()[ml.member].span,
            };
            let name = &ml.name;
            if ml.request.max > layout::MAX_REQUEST {
                self.err(
                    span,
                    Code::Size,
                    format!(
                        "method '{name}''s request may reach {} octets, over {}",
                        ml.request.max,
                        layout::MAX_REQUEST
                    ),
                );
            }
            self.caps(span, name, "request", ml.request, kernel);
            if let Some(r) = ml.reply {
                if r.max > layout::MAX_REPLY {
                    self.err(
                        span,
                        Code::Size,
                        format!(
                            "method '{name}''s reply may reach {} octets, over {}",
                            r.max,
                            layout::MAX_REPLY
                        ),
                    );
                }
                self.caps(span, name, "reply", r, kernel);
            }
            if let Some(s) = ml.stream
                && s.item_max > layout::MAX_ITEM
            {
                self.err(
                    span,
                    Code::Size,
                    format!(
                        "method '{name}''s stream item may reach {} octets, over {}",
                        s.item_max,
                        layout::MAX_ITEM
                    ),
                );
            }
        }
        for el in &layout.errors {
            if el.detail.max > layout::MAX_DETAIL {
                let span = self.members()[el.member].span;
                self.err(span, Code::Size, format!("an error's detail may reach {} octets, over {}: the envelope must stay within 768", el.detail.max, layout::MAX_DETAIL));
            }
        }
    }

    fn caps(&mut self, span: Span, name: &str, dir: &str, b: layout::Body, kernel: bool) {
        if b.caps > layout::MAX_CAPS {
            self.err(span, Code::Capability, format!("method '{name}''s {dir} may carry {} capabilities: at most 3 (a builder session carries more)", b.caps));
        } else if b.may_spill && !kernel && b.caps > layout::MAX_CAPS - 1 {
            self.err(span, Code::Capability, format!("method '{name}''s {dir} may spill, so it carries at most 2 capabilities, not {}", b.caps));
        }
    }
}
