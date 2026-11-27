// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The canonical form: the octets the lock and the catalog hash (ADR 0067,
//! rule 7; docs/design/call-language.md, "The lock and the canonical
//! form").
//!
//! It is the projected source with comments and docs removed, every
//! derived number written out, attributes in a fixed order and fixed
//! whitespace. It is itself a valid `idl-file`, so it parses back.
//!
//! - `edition 2026;`, then the `use` lines, then the header and
//!   `interface name {`, one member per line, then `}`. LF line ends, no
//!   indentation, no blank lines, and a final LF.
//! - One space after `,` and `:`, around `=` and `->`, after `]`, between
//!   words, and before `{`, `stream<...>` and `error(...)`; none
//!   elsewhere.
//! - Members in source order. Struct, union, enum, flags, error and object
//!   bodies on one line. Every field writes its position, `@n`.
//! - Attributes in the order of the note's attribute table. Set-valued
//!   lists sorted: `groups`, `group`, `requires`, `parents`, a
//!   capability's qualifiers, and a `use` line's names. So reordering a
//!   set is no change.
//! - Integers in decimal, `reserved(n)` included; `hex(...)` as written.
//!   Interface references always carry their minor. Bounds keep a
//!   constant's name. An imported type is written by its bare name, which
//!   its `use` line brings into scope.
//! - What means the same is written the same: a `since` no later than the
//!   container's, `retry(never)`, `[local]` beside `[kernel]` and an
//!   empty detail block are left out, and results that are one field
//!   named `result` are written as the bare type.

use alloc::{format, string::String, vec::Vec};

use crate::{
    ast::{
        self, Arm, Attr, AttrArg, BaseType, Bound, Field, File, IdLit, IfaceRef, IntLit, Member,
        MemberKind, Results, ResultsKind, Type, Value, Version,
    },
    layout::since_of,
};

/// The attribute table's order (docs/design/call-language.md,
/// "Attributes").
pub const ATTRIBUTE_ORDER: [&str; 24] = [
    "id",
    "object_id",
    "type",
    "parents",
    "version",
    "kernel",
    "local",
    "oneway",
    "groups",
    "group",
    "idempotent",
    "readonly",
    "lossy",
    "coalescing",
    "requires",
    "static",
    "since",
    "deprecated",
    "sensitive",
    "nonzero",
    "closed",
    "refused",
    "retry",
    "format",
];

/// Attributes whose arguments are a set.
const SETS: [&str; 4] = ["groups", "group", "requires", "parents"];

/// The canonical form of a file, which should already be projected to the
/// minor its `version(...)` names.
pub fn canonical(file: &File) -> String {
    canonical_reusing(file, None).0
}

/// [`canonical`], and each member's line. A member that is the same as
/// written in `prev`, another projection of the same source with the
/// lines this gave it, takes its line from there. idlc hashes every
/// published minor of a file, and from one minor to the next most members
/// stay the same.
pub fn canonical_reusing(file: &File, prev: Option<(&File, &[String])>) -> (String, Vec<String>) {
    let major = ast::version_attr(&file.interface.attrs, "version").map_or(0, |v| v.major);
    let base = Version { major, minor: 0 };
    let mut out = header(file);
    let mut lines = Vec::with_capacity(file.interface.members.len());
    let (pm, pl): (&[Member], &[String]) = match prev {
        Some((f, l)) if l.len() == f.interface.members.len() => (&f.interface.members, l),
        _ => (&[], &[]),
    };
    let mut j = 0;
    for m in &file.interface.members {
        let line = match pm.get(j) {
            Some(p) if p == m => {
                j += 1;
                pl[j - 1].clone()
            }
            Some(p) => {
                // The same member, changed: step past it.
                if p.name().map(|n| &n.name) == m.name().map(|n| &n.name)
                    && core::mem::discriminant(&p.kind) == core::mem::discriminant(&m.kind)
                {
                    j += 1;
                }
                member(m, base)
            }
            None => member(m, base),
        };
        out.push_str(&line);
        out.push('\n');
        lines.push(line);
    }
    out.push_str("}\n");
    (out, lines)
}

/// The canonical form's lines before the members: the edition, the `use`
/// lines, and the header up to `{`.
fn header(file: &File) -> String {
    let major = ast::version_attr(&file.interface.attrs, "version").map_or(0, |v| v.major);
    let base = Version { major, minor: 0 };
    let kernel = ast::has_attr(&file.interface.attrs, "kernel");
    let mut out = String::from("edition 2026;\n");
    for u in &file.uses {
        let mut names: Vec<&str> = u.names.iter().map(|n| n.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        out.push_str(&format!(
            "use {}.{{{}}};\n",
            iface_ref(&u.iface),
            names.join(", ")
        ));
    }
    let header: Vec<Attr> = file
        .interface
        .attrs
        .iter()
        .filter(|a| !(kernel && a.name.name == "local"))
        .cloned()
        .collect();
    out.push_str(&attrs(&header, base));
    out.push_str(&format!("interface {} {{\n", file.interface.name.name));
    out
}

/// One member, on one line, without the line feed.
pub fn member(m: &Member, base: Version) -> String {
    let since = since_of(&m.attrs, base);
    let a = attrs(&m.attrs, base);
    match &m.kind {
        MemberKind::Const { name, ty, value } => {
            format!("{a}const {}: {} = {};", name.name, ty.word(), int(value))
        }
        MemberKind::Alias { name, ty } => format!("{a}alias {} = {};", name.name, type_text(ty)),
        MemberKind::Struct { name, fields } => {
            format!("{a}struct {} {{{}}}", name.name, field_list(fields, since))
        }
        MemberKind::Object { name, fields } => {
            format!("{a}object {} {{{}}}", name.name, field_list(fields, since))
        }
        MemberKind::Union { name, arms } => {
            let arms: Vec<String> = arms.iter().map(|x| arm(x, since)).collect();
            format!("{a}union {} {{{}}}", name.name, arms.join(", "))
        }
        MemberKind::Enum {
            flags,
            name,
            width,
            values,
            ..
        } => {
            let kw = if *flags { "flags" } else { "enum" };
            let mut s = format!("{a}{kw} {}: {} {{", name.name, width.word());
            for (i, v) in values.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                value(&mut s, v, since);
            }
            s.push('}');
            s
        }
        MemberKind::Error { name, code, fields } => match fields.as_deref() {
            Some(fs) if !fs.is_empty() => {
                format!(
                    "{a}error {} = {} {{{}}};",
                    name.name,
                    int(code),
                    field_list(fs, since)
                )
            }
            _ => format!("{a}error {} = {};", name.name, int(code)),
        },
        MemberKind::Method(method) => {
            let mut s = format!(
                "{a}@{} {}({})",
                method.ordinal,
                method.name.name,
                field_list(&method.params, since)
            );
            if let Some(r) = &method.results {
                s.push_str(" -> ");
                s.push_str(&results(r, since));
            }
            if !method.errors.is_empty() {
                let names: Vec<&str> = method.errors.iter().map(|e| e.name.as_str()).collect();
                s.push_str(&format!(" error({})", names.join(", ")));
            }
            s.push(';');
            s
        }
        MemberKind::Reserved { ordinal } => format!("reserved @{ordinal};"),
    }
}

/// A method's results.
pub fn results(r: &Results, since: Version) -> String {
    let mut s = match &r.kind {
        ResultsKind::None => String::new(),
        ResultsKind::Single(t) => type_text(t),
        ResultsKind::Fields(fs) => match fs.as_slice() {
            [f] if f.name.name == "result" && attrs(&f.attrs, since).is_empty() => type_text(&f.ty),
            _ => format!("({})", field_list(fs, since)),
        },
    };
    if let Some(t) = &r.stream {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(&format!("stream<{}>", t.name.name));
    }
    s
}

/// Fields, with their positions, separated by ", ".
pub fn field_list(fields: &[Field], since: Version) -> String {
    let v: Vec<String> = fields
        .iter()
        .enumerate()
        .map(|(i, f)| field(f, i + 1, since))
        .collect();
    v.join(", ")
}

/// One field at a position.
pub fn field(f: &Field, position: usize, since: Version) -> String {
    format!(
        "{}@{} {}: {}",
        attrs(&f.attrs, since),
        position,
        f.name.name,
        type_text(&f.ty)
    )
}

fn arm(a: &Arm, since: Version) -> String {
    match a {
        Arm::Arm {
            attrs: at,
            ordinal,
            name,
            ty,
            ..
        } => format!(
            "{}@{ordinal} {}: {}",
            attrs(at, since),
            name.name,
            type_text(ty)
        ),
        Arm::Reserved { ordinal, .. } => format!("reserved @{ordinal}"),
    }
}

/// One enum or flags value, appended to `out`: a type may hold thousands,
/// and a file's every published minor is written out for its hash.
fn value(out: &mut String, v: &Value, since: Version) {
    match v {
        Value::Value {
            attrs: at,
            name,
            value,
            ..
        } => {
            if !at.is_empty() {
                out.push_str(&attrs(at, since));
            }
            out.push_str(&name.name);
            out.push_str(" = ");
            out.push_str(&int(value));
        }
        Value::Reserved { value, .. } => {
            out.push_str("reserved ");
            out.push_str(&int(value));
        }
    }
}

/// Attributes in table order, with a trailing space, or "" when there are
/// none. `since` is the container's effective `since`.
pub fn attrs(list: &[Attr], since: Version) -> String {
    if list.is_empty() {
        return String::new();
    }
    let mut v: Vec<(usize, String)> = Vec::new();
    for a in list {
        let name = a.name.name.as_str();
        let rank = ATTRIBUTE_ORDER
            .iter()
            .position(|n| *n == name)
            .unwrap_or(ATTRIBUTE_ORDER.len());
        match (name, a.args.as_deref()) {
            ("since", Some([AttrArg::Version(s, _)])) if *s <= since => continue,
            ("retry", Some([AttrArg::Member(w, _)])) if w == "never" => continue,
            _ => {}
        }
        let text = match &a.args {
            None => String::from(name),
            Some(args) => {
                let mut args: Vec<String> = args.iter().map(arg).collect();
                if SETS.contains(&name) {
                    args.sort_unstable();
                    args.dedup();
                }
                format!("{name}({})", args.join(", "))
            }
        };
        v.push((rank, text));
    }
    if v.is_empty() {
        return String::new();
    }
    v.sort_by_key(|(rank, _)| *rank);
    let texts: Vec<String> = v.into_iter().map(|(_, t)| t).collect();
    format!("[{}] ", texts.join(", "))
}

fn arg(a: &AttrArg) -> String {
    match a {
        AttrArg::Version(v, _) => format!("{}.{}", v.major, v.minor),
        AttrArg::Int(i) => int(i),
        AttrArg::Name(n, _) | AttrArg::Member(n, _) => n.clone(),
        AttrArg::Id(IdLit::Reserved(n), _) => format!("reserved({})", int(n)),
        AttrArg::Id(IdLit::Hex(id), _) => {
            let mut s = String::from("hex(");
            for b in id {
                s.push_str(&format!("{b:02x}"));
            }
            s.push(')');
            s
        }
    }
}

fn int(i: &IntLit) -> String {
    match i.value {
        Some(v) => format!("{v}"),
        // The checker refuses a literal too large for any type.
        None => String::from("0"),
    }
}

/// An interface reference, always with its minor.
pub fn iface_ref(r: &IfaceRef) -> String {
    format!("{}/{}.{}", r.name, r.major, r.minor_or_zero())
}

fn bound(b: &Bound) -> String {
    match b {
        Bound::Lit(i) => int(i),
        Bound::Const(c) => c.name.clone(),
    }
}

/// A type expression.
pub fn type_text(t: &Type) -> String {
    let mut s = match &t.base {
        BaseType::Bool => String::from("bool"),
        BaseType::Int(i) => String::from(i.word()),
        BaseType::F32 => String::from("f32"),
        BaseType::F64 => String::from("f64"),
        BaseType::Id => String::from("id"),
        BaseType::Uuid => String::from("uuid"),
        BaseType::String(b) => format!("string<{}>", bound(b)),
        BaseType::Bytes(b) => format!("bytes<{}>", bound(b)),
        BaseType::Seq(e, b) => format!("seq<{}, {}>", type_text(e), bound(b)),
        BaseType::Array(e, b) => format!("array<{}, {}>", type_text(e), bound(b)),
        BaseType::Cap(r, q) | BaseType::Slot(r, q) => {
            let kw = if matches!(t.base, BaseType::Cap(..)) {
                "cap"
            } else {
                "slot"
            };
            let mut quals: Vec<_> = q.iter().map(|(q, _)| *q).collect();
            quals.sort_unstable();
            quals.dedup();
            let mut s = format!("{kw}<{}", iface_ref(r));
            for q in quals {
                s.push_str(", ");
                s.push_str(q.word());
            }
            s.push('>');
            s
        }
        BaseType::Ref(r) => r.name.name.clone(),
    };
    if t.optional {
        s.push('?');
    }
    s
}
