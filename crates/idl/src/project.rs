// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Projection: a file as one of its minors saw it (ADR 0067, rule 7;
//! docs/design/call-language.md, "The lock and the canonical form").
//!
//! Projecting to M.m drops every item whose `since` is above M.m (a
//! member's `since` is never below its container's), every
//! `deprecated(M.k)` with k above m, every entry of an `error(...)` list
//! that names a dropped error, and every declared action group that no
//! remaining method names. A method left with no results has none, as if
//! it had never had them. It sets `version(M.m)`.
//!
//! It also drops every imported name that nothing left in the file
//! references, and a `use` line left with no names. So an import added
//! for a later minor, as a new line or a new name, changes no earlier
//! minor's canonical form.

use alloc::{collections::BTreeSet, string::String, vec::Vec};

use crate::{
    ast::{
        self, Arm, Attr, AttrArg, BaseType, Field, File, MemberKind, ResultsKind, Type, Value,
        Version,
    },
    layout::since_of,
};

/// Projects a checked file to minor `minor` of its major.
pub fn project(file: &File, minor: u16) -> File {
    project_uses(file, minor).0
}

/// Projects a checked file, as [`project`] does, and also returns the
/// index in the source of each `use` line the projection keeps.
pub fn project_uses(file: &File, minor: u16) -> (File, Vec<usize>) {
    let mut f = file.clone();
    let major = ast::version_attr(&f.interface.attrs, "version").map_or(0, |v| v.major);
    let base = Version { major, minor: 0 };
    let target = Version { major, minor };
    let kept = |attrs: &[Attr], container: Version| since_of(attrs, container) <= target;

    f.interface
        .members
        .retain(|m| matches!(m.kind, MemberKind::Reserved { .. }) || kept(&m.attrs, base));
    let errors: BTreeSet<String> = f
        .interface
        .members
        .iter()
        .filter(|m| matches!(m.kind, MemberKind::Error { .. }))
        .filter_map(|m| m.name().map(|n| n.name.clone()))
        .collect();

    let fields = |fs: &mut Vec<Field>, container: Version| {
        fs.retain(|fl| kept(&fl.attrs, container));
        for fl in fs.iter_mut() {
            strip_deprecated(&mut fl.attrs, target);
        }
    };
    for m in &mut f.interface.members {
        let container = since_of(&m.attrs, base);
        strip_deprecated(&mut m.attrs, target);
        match &mut m.kind {
            MemberKind::Struct { fields: fs, .. } | MemberKind::Object { fields: fs, .. } => {
                fields(fs, container)
            }
            MemberKind::Error {
                fields: Some(fs), ..
            } => fields(fs, container),
            MemberKind::Union { arms, .. } => {
                arms.retain(|a| match a {
                    Arm::Arm { attrs, .. } => kept(attrs, container),
                    Arm::Reserved { .. } => true,
                });
                for a in arms.iter_mut() {
                    if let Arm::Arm { attrs, .. } = a {
                        strip_deprecated(attrs, target);
                    }
                }
            }
            MemberKind::Enum { values, .. } => {
                values.retain(|v| match v {
                    Value::Value { attrs, .. } => kept(attrs, container),
                    Value::Reserved { .. } => true,
                });
                for v in values.iter_mut() {
                    if let Value::Value { attrs, .. } = v {
                        strip_deprecated(attrs, target);
                    }
                }
            }
            MemberKind::Method(method) => {
                fields(&mut method.params, container);
                if let Some(r) = &mut method.results
                    && let ResultsKind::Fields(fs) = &mut r.kind
                {
                    fields(fs, container);
                    // A method whose results all came later had none: no
                    // `-> ()`, which isn't IDL, and the canonical form the
                    // minor had before them.
                    if fs.is_empty() {
                        r.kind = ResultsKind::None;
                    }
                }
                if method
                    .results
                    .as_ref()
                    .is_some_and(|r| matches!(r.kind, ResultsKind::None) && r.stream.is_none())
                {
                    method.results = None;
                }
                method.errors.retain(|e| errors.contains(&e.name));
            }
            _ => {}
        }
    }

    // Groups exist where a method names them.
    let used: BTreeSet<String> = f
        .interface
        .members
        .iter()
        .filter(|m| matches!(m.kind, MemberKind::Method(_)))
        .filter_map(|m| ast::attr(&m.attrs, "group"))
        .flat_map(|a| a.args.iter().flatten())
        .filter_map(|a| match a {
            AttrArg::Member(g, _) => Some(g.clone()),
            _ => None,
        })
        .collect();
    let attrs = &mut f.interface.attrs;
    for a in attrs.iter_mut() {
        match a.name.name.as_str() {
            "groups" => {
                if let Some(args) = &mut a.args {
                    args.retain(|g| matches!(g, AttrArg::Member(n, _) if used.contains(n)));
                }
            }
            "version" => {
                if let Some(args) = &mut a.args
                    && let Some(AttrArg::Version(v, _)) = args.first_mut()
                {
                    *v = target;
                }
            }
            _ => {}
        }
    }
    attrs.retain(|a| a.name.name != "groups" || a.args.as_ref().is_some_and(|g| !g.is_empty()));

    // Imports exist where something left names them.
    let named = referenced(&f);
    let mut kept = Vec::new();
    let uses = core::mem::take(&mut f.uses);
    for (k, mut u) in uses.into_iter().enumerate() {
        u.names.retain(|n| named.contains(&n.name));
        if !u.names.is_empty() {
            kept.push(k);
            f.uses.push(u);
        }
    }
    (f, kept)
}

/// The type names a file's members reference.
fn referenced(f: &File) -> BTreeSet<String> {
    fn ty(t: &Type, out: &mut BTreeSet<String>) {
        match &t.base {
            BaseType::Ref(r) => {
                out.insert(r.name.name.clone());
            }
            BaseType::Seq(e, _) | BaseType::Array(e, _) => ty(e, out),
            _ => {}
        }
    }
    let fields = |fs: &[Field], out: &mut BTreeSet<String>| {
        for fl in fs {
            ty(&fl.ty, out);
        }
    };
    let mut out = BTreeSet::new();
    for m in &f.interface.members {
        match &m.kind {
            MemberKind::Alias { ty: t, .. } => ty(t, &mut out),
            MemberKind::Struct { fields: fs, .. } | MemberKind::Object { fields: fs, .. } => {
                fields(fs, &mut out)
            }
            MemberKind::Error {
                fields: Some(fs), ..
            } => fields(fs, &mut out),
            MemberKind::Union { arms, .. } => {
                for a in arms {
                    if let Arm::Arm { ty: t, .. } = a {
                        ty(t, &mut out);
                    }
                }
            }
            MemberKind::Method(method) => {
                fields(&method.params, &mut out);
                if let Some(r) = &method.results {
                    match &r.kind {
                        ResultsKind::Single(t) => ty(t, &mut out),
                        ResultsKind::Fields(fs) => fields(fs, &mut out),
                        ResultsKind::None => {}
                    }
                    if let Some(s) = &r.stream {
                        out.insert(s.name.name.clone());
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Drops `deprecated(M.k)` when k is above the target minor.
fn strip_deprecated(attrs: &mut Vec<Attr>, target: Version) {
    attrs.retain(|a| {
        a.name.name != "deprecated"
            || ast::version_attr(core::slice::from_ref(a), "deprecated").is_none_or(|v| v <= target)
    });
}

/// Every minor of `major` that a `since` or `deprecated` in the file
/// names. Projecting to M.m and to M.(m-1) gives the same file, apart from
/// its `version(M.m)`, unless m is one of them: nothing else in a
/// projection depends on the minor.
pub fn changes(f: &File, major: u16) -> BTreeSet<u16> {
    let mut out = BTreeSet::new();
    let mut add = |attrs: &[Attr]| {
        for name in ["since", "deprecated"] {
            if let Some(v) = ast::version_attr(attrs, name)
                && v.major == major
            {
                out.insert(v.minor);
            }
        }
    };
    for m in &f.interface.members {
        add(&m.attrs);
        match &m.kind {
            MemberKind::Struct { fields, .. } | MemberKind::Object { fields, .. } => {
                fields.iter().for_each(|fl| add(&fl.attrs))
            }
            MemberKind::Error {
                fields: Some(fields),
                ..
            } => fields.iter().for_each(|fl| add(&fl.attrs)),
            MemberKind::Union { arms, .. } => arms.iter().for_each(|a| {
                if let Arm::Arm { attrs, .. } = a {
                    add(attrs)
                }
            }),
            MemberKind::Enum { values, .. } => values.iter().for_each(|v| {
                if let ast::Value::Value { attrs, .. } = v {
                    add(attrs)
                }
            }),
            MemberKind::Method(method) => {
                method.params.iter().for_each(|fl| add(&fl.attrs));
                if let Some(r) = &method.results
                    && let ResultsKind::Fields(fs) = &r.kind
                {
                    fs.iter().for_each(|fl| add(&fl.attrs));
                }
            }
            _ => {}
        }
    }
    out
}
