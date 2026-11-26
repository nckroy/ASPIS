// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The compatibility check between two minors (ADR 0065, rule 13; ADR
//! 0067, rule 7; docs/design/call-language.md, "The compatibility
//! check").
//!
//! [`step`] compares two projected files, M.(m-1) and M.m, structurally.
//! It works on two projections of one source, as `idlc check` makes them,
//! and on a stored canonical form parsed back beside a new source, as the
//! catalog will. The lock's hash catches any change to a published minor;
//! this check says what m adds to m-1, and refuses anything ADR 0065, rule
//! 13 doesn't allow.
//!
//! Items are compared through their canonical text, without
//! `deprecated(...)`, which a minor may add. Both files must have passed
//! the checker.

use alloc::{collections::BTreeSet, format, string::String, vec::Vec};

use crate::{
    ast::{self, Arm, Attr, Field, File, Member, MemberKind, Value, Version},
    canon,
    layout::{result_fields, since_of},
};

/// One thing a step does that a minor may not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// What kind of change: "header", "use", "removed", "reordered",
    /// "changed", "closed", "required", "since", "error-list".
    pub kind: &'static str,
    pub message: String,
}

/// Checks that `next` (M.m) only adds to `prev` (M.(m-1)) what a minor may.
pub fn step(prev: &File, next: &File) -> Vec<Violation> {
    let mut s = Step {
        out: Vec::new(),
        target: ast::version_attr(&next.interface.attrs, "version")
            .unwrap_or(Version { major: 0, minor: 0 }),
        base: Version { major: 0, minor: 0 },
        next,
    };
    s.base = Version {
        major: s.target.major,
        minor: 0,
    };
    s.header(prev, next);
    s.uses(prev, next);
    s.members(prev, next);
    s.out
}

struct Step<'a> {
    out: Vec<Violation>,
    /// M.m.
    target: Version,
    /// M.0.
    base: Version,
    next: &'a File,
}

/// A member's key: its kind and name, or a reserved method's number.
fn key(m: &Member) -> String {
    match &m.kind {
        MemberKind::Reserved { ordinal } => format!("reserved @{ordinal}"),
        MemberKind::Const { name, .. } => format!("const {}", name.name),
        MemberKind::Error { name, .. } => format!("error {}", name.name),
        MemberKind::Method(m) => format!("method {}", m.name.name),
        _ => format!("type {}", m.name().map_or("", |n| n.name.as_str())),
    }
}

/// Attributes without `deprecated(...)`, which a minor may add.
fn without_deprecated(attrs: &[Attr]) -> Vec<Attr> {
    attrs
        .iter()
        .filter(|a| a.name.name != "deprecated")
        .cloned()
        .collect()
}

fn field_text(f: &Field, position: usize, since: Version) -> String {
    let mut f = f.clone();
    f.attrs = without_deprecated(&f.attrs);
    canon::field(&f, position, since)
}

impl Step<'_> {
    fn violation(&mut self, kind: &'static str, message: String) {
        self.out.push(Violation { kind, message });
    }

    fn header(&mut self, prev: &File, next: &File) {
        let pv = ast::version_attr(&prev.interface.attrs, "version");
        let nv = ast::version_attr(&next.interface.attrs, "version");
        match (pv, nv) {
            (Some(p), Some(n))
                if p.major == n.major && u32::from(p.minor) + 1 == u32::from(n.minor) => {}
            _ => self.violation(
                "header",
                "the step must go from M.(m-1) to M.m of one major".into(),
            ),
        }
        let base = self.base;
        let text = |f: &File, name: &str| {
            ast::attr(&f.interface.attrs, name)
                .map(|a| canon::attrs(core::slice::from_ref(a), base))
                .unwrap_or_default()
        };
        for name in ["id", "object_id", "kernel"] {
            if text(prev, name) != text(next, name) {
                self.violation("header", format!("the header's {name} changed"));
            }
        }
        // Every [kernel] interface is [local], so the canonical form leaves
        // `local` out beside `kernel`: what means the same compares the
        // same.
        let local = |f: &File| {
            ast::has_attr(&f.interface.attrs, "local")
                || ast::has_attr(&f.interface.attrs, "kernel")
        };
        if local(prev) != local(next) {
            self.violation("header", "the header's local changed".into());
        }
        if prev.interface.name.name != next.interface.name.name {
            self.violation("header", "the interface's name changed".into());
        }
        let groups = |f: &File| -> BTreeSet<String> {
            ast::attr(&f.interface.attrs, "groups")
                .and_then(|a| a.args.as_ref())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| match x {
                            ast::AttrArg::Member(g, _) => Some(g.clone()),
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let (pg, ng) = (groups(prev), groups(next));
        for g in pg.difference(&ng) {
            self.violation("removed", format!("group '{g}' was removed"));
        }
    }

    /// An import never changes within the major: each name the earlier
    /// minor imports, the later one imports from the same interface and
    /// minor. New names and new lines may come; a projection holds only
    /// the names it uses (crate::project). A new line comes last: each
    /// line of the earlier minor keeps its place, so its types keep their
    /// `u<k>` rule names from one minor's grammar to the next.
    fn uses(&mut self, prev: &File, next: &File) {
        for (k, p) in prev.uses.iter().enumerate() {
            let same = next
                .uses
                .get(k)
                .is_some_and(|n| canon::iface_ref(&n.iface) == canon::iface_ref(&p.iface));
            if !same {
                self.violation(
                    "use",
                    format!(
                        "the use line of {} moved from place {}: add a new line last",
                        canon::iface_ref(&p.iface),
                        k + 1
                    ),
                );
            }
        }
        let imports = |f: &File| {
            let mut m: alloc::collections::BTreeMap<String, String> =
                alloc::collections::BTreeMap::new();
            for u in &f.uses {
                for n in &u.names {
                    m.entry(n.name.clone())
                        .or_insert_with(|| canon::iface_ref(&u.iface));
                }
            }
            m
        };
        let after = imports(next);
        for (name, from) in imports(prev) {
            match after.get(&name) {
                Some(f) if *f == from => {}
                Some(f) => self.violation(
                    "use",
                    format!("'{name}' was imported from {from}, and is now imported from {f}"),
                ),
                None => self.violation("use", format!("the import of '{name}' was removed")),
            }
        }
    }

    fn members(&mut self, prev: &File, next: &File) {
        let nkeys: Vec<String> = next.interface.members.iter().map(key).collect();
        let pkeys: BTreeSet<String> = prev.interface.members.iter().map(key).collect();
        let mut last = None;
        for p in &prev.interface.members {
            let k = key(p);
            let Some(j) = nkeys.iter().position(|n| *n == k) else {
                self.violation("removed", format!("{k} was removed or renamed"));
                continue;
            };
            if last.is_some_and(|l| j < l) {
                self.violation("reordered", format!("{k} moved"));
            }
            last = Some(j);
            self.member(p, &next.interface.members[j], &k);
        }
        for (n, k) in next.interface.members.iter().zip(&nkeys) {
            if pkeys.contains(k) || matches!(n.kind, MemberKind::Reserved { .. }) {
                continue;
            }
            if since_of(&n.attrs, self.base) != self.target {
                self.violation(
                    "since",
                    format!(
                        "{k} is new, so it needs [since({}.{})]",
                        self.target.major, self.target.minor
                    ),
                );
            }
        }
    }

    fn member(&mut self, p: &Member, n: &Member, k: &str) {
        let since = since_of(&p.attrs, self.base);
        if since != since_of(&n.attrs, self.base) {
            self.violation("changed", format!("{k}'s since changed"));
        }
        let closed = ast::has_attr(&p.attrs, "closed");
        let same_attrs = canon::attrs(&without_deprecated(&p.attrs), self.base)
            == canon::attrs(&without_deprecated(&n.attrs), self.base);
        match (&p.kind, &n.kind) {
            (MemberKind::Struct { fields: pf, .. }, MemberKind::Struct { fields: nf, .. })
            | (MemberKind::Object { fields: pf, .. }, MemberKind::Object { fields: nf, .. }) => {
                if !same_attrs {
                    self.violation("changed", format!("{k}'s attributes changed"));
                }
                self.fields(k, pf, nf, since, closed);
            }
            (MemberKind::Union { arms: pa, .. }, MemberKind::Union { arms: na, .. }) => {
                if !same_attrs {
                    self.violation("changed", format!("{k}'s attributes changed"));
                }
                self.arms(k, pa, na, since, closed);
            }
            (
                MemberKind::Enum {
                    flags: pf,
                    width: pw,
                    values: pv,
                    ..
                },
                MemberKind::Enum {
                    flags: nf,
                    width: nw,
                    values: nv,
                    ..
                },
            ) => {
                if !same_attrs || pf != nf || pw != nw {
                    self.violation(
                        "changed",
                        format!("{k} changed its kind, width or attributes"),
                    );
                }
                self.values(k, pv, nv, since, closed);
            }
            (
                MemberKind::Error {
                    code: pc,
                    fields: pf,
                    ..
                },
                MemberKind::Error {
                    code: nc,
                    fields: nf,
                    ..
                },
            ) => {
                if !same_attrs || pc.value != nc.value {
                    self.violation("changed", format!("{k} changed its code or outcome"));
                }
                self.fields(
                    k,
                    pf.as_deref().unwrap_or(&[]),
                    nf.as_deref().unwrap_or(&[]),
                    since,
                    false,
                );
            }
            (MemberKind::Method(pm), MemberKind::Method(nm)) => {
                if !same_attrs || pm.ordinal != nm.ordinal {
                    self.violation("changed", format!("{k} changed its number or attributes"));
                }
                self.fields(
                    &format!("{k}'s parameters"),
                    &pm.params,
                    &nm.params,
                    since,
                    false,
                );
                let pr = pm.results.as_ref().map(result_fields).unwrap_or_default();
                let nr = nm.results.as_ref().map(result_fields).unwrap_or_default();
                self.fields(&format!("{k}'s results"), &pr, &nr, since, false);
                let ps = pm
                    .results
                    .as_ref()
                    .and_then(|r| r.stream.as_ref())
                    .map(|t| &t.name.name);
                let ns = nm
                    .results
                    .as_ref()
                    .and_then(|r| r.stream.as_ref())
                    .map(|t| &t.name.name);
                // No results are an empty list of them, which a minor may
                // append to: the fields above compare the rest.
                if ps != ns {
                    self.violation("changed", format!("{k}'s results changed"));
                }
                // Edition 2026's error lists have no per-entry since: an
                // entry added in m names an error new in m.
                let perr: BTreeSet<&str> = pm.errors.iter().map(|e| e.name.as_str()).collect();
                let nerr: BTreeSet<&str> = nm.errors.iter().map(|e| e.name.as_str()).collect();
                for e in perr.difference(&nerr) {
                    self.violation("error-list", format!("{k} no longer lists '{e}'"));
                }
                for e in nerr.difference(&perr) {
                    let new = self.next.interface.members.iter().any(|m| {
                        matches!(m.kind, MemberKind::Error { .. })
                            && m.name().is_some_and(|n| n.name == *e)
                            && since_of(&m.attrs, self.base) == self.target
                    });
                    if !new {
                        self.violation("error-list", format!("{k} adds '{e}' to its error list, which only an error new in this minor may join"));
                    }
                }
            }
            (MemberKind::Reserved { .. }, MemberKind::Reserved { .. }) => {}
            _ => {
                let mut pt = p.clone();
                let mut nt = n.clone();
                pt.attrs = without_deprecated(&pt.attrs);
                nt.attrs = without_deprecated(&nt.attrs);
                if canon::member(&pt, self.base) != canon::member(&nt, self.base) {
                    self.violation("changed", format!("{k} changed"));
                }
            }
        }
    }

    /// An open struct's fields are only appended, each new one optional and
    /// of this minor. A closed struct never changes.
    fn fields(&mut self, k: &str, prev: &[Field], next: &[Field], since: Version, closed: bool) {
        for (i, p) in prev.iter().enumerate() {
            match next.get(i) {
                Some(n) if field_text(p, i + 1, since) == field_text(n, i + 1, since) => {}
                Some(n) if p.name.name == n.name.name => {
                    self.violation("changed", format!("{k}: field '{}' changed", p.name.name))
                }
                _ => self.violation(
                    "removed",
                    format!("{k}: field '{}' was removed, renamed or moved", p.name.name),
                ),
            }
        }
        for n in next.iter().skip(prev.len()) {
            if closed {
                self.violation(
                    "closed",
                    format!("{k} is closed, and gained field '{}'", n.name.name),
                );
            } else if !n.ty.optional {
                self.violation(
                    "required",
                    format!("{k}: new field '{}' must be optional", n.name.name),
                );
            } else if since_of(&n.attrs, since) != self.target {
                self.violation(
                    "since",
                    format!(
                        "{k}: new field '{}' needs [since({}.{})]",
                        n.name.name, self.target.major, self.target.minor
                    ),
                );
            }
        }
    }

    fn arms(&mut self, k: &str, prev: &[Arm], next: &[Arm], since: Version, closed: bool) {
        let text = |a: &Arm| match a {
            Arm::Arm {
                attrs,
                ordinal,
                name,
                ty,
                ..
            } => format!(
                "{}@{ordinal} {}: {}",
                canon::attrs(&without_deprecated(attrs), since),
                name.name,
                canon::type_text(ty)
            ),
            Arm::Reserved { ordinal, .. } => format!("reserved @{ordinal}"),
        };
        let ord = |a: &Arm| match a {
            Arm::Arm { ordinal, .. } | Arm::Reserved { ordinal, .. } => *ordinal,
        };
        let ntexts: Vec<String> = next.iter().map(text).collect();
        for p in prev {
            if !ntexts.contains(&text(p)) {
                self.violation(
                    "changed",
                    format!("{k}: arm @{} was removed or changed", ord(p)),
                );
            }
        }
        let ptexts: Vec<String> = prev.iter().map(text).collect();
        for n in next {
            if ptexts.contains(&text(n)) || matches!(n, Arm::Reserved { .. }) {
                continue;
            }
            if closed {
                self.violation(
                    "closed",
                    format!("{k} is closed, and gained arm @{}", ord(n)),
                );
            } else if let Arm::Arm { attrs, .. } = n
                && since_of(attrs, since) != self.target
            {
                self.violation(
                    "since",
                    format!(
                        "{k}: new arm @{} needs [since({}.{})]",
                        ord(n),
                        self.target.major,
                        self.target.minor
                    ),
                );
            }
        }
    }

    fn values(&mut self, k: &str, prev: &[Value], next: &[Value], since: Version, closed: bool) {
        let text = |v: &Value| match v {
            Value::Value {
                attrs, name, value, ..
            } => {
                format!(
                    "{}{} = {:?}",
                    canon::attrs(&without_deprecated(attrs), since),
                    name.name,
                    value.value
                )
            }
            Value::Reserved { value, .. } => format!("reserved {:?}", value.value),
        };
        let ntexts: Vec<String> = next.iter().map(text).collect();
        for p in prev {
            if !ntexts.contains(&text(p)) {
                self.violation(
                    "changed",
                    format!("{k}: value {} was removed or changed", text(p)),
                );
            }
        }
        let ptexts: Vec<String> = prev.iter().map(text).collect();
        for n in next {
            if ptexts.contains(&text(n)) || matches!(n, Value::Reserved { .. }) {
                continue;
            }
            if closed {
                self.violation(
                    "closed",
                    format!("{k} is closed, and gained value {}", text(n)),
                );
            } else if let Value::Value { attrs, .. } = n
                && since_of(attrs, since) != self.target
            {
                self.violation(
                    "since",
                    format!(
                        "{k}: new value {} needs [since({}.{})]",
                        text(n),
                        self.target.major,
                        self.target.minor
                    ),
                );
            }
        }
    }
}
