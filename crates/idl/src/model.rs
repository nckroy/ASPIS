// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Names bound, and `use` imports loaded: the model the checker, the
//! layout and the back ends read.
//!
//! [`check`] is the front end's entry point. It parses a file, loads every
//! interface its `use` lines name through the caller's resolver, checks
//! each one in full at its own version, projects it to the minor the `use`
//! line names, and checks the file itself ([`crate::check`]).
//!
//! An imported type is read at the minor its `use` line names, never at a
//! later one, so a later minor of the imported interface never changes
//! the importer (docs/design/call-language.md, "Generated grammars").

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use idl_rt::names::InterfaceRef;

use crate::{
    Limits,
    ast::{self, AttrArg, Bound, File, IntType, Member, MemberKind, TypeRef, Use, Version},
    check as rules,
    diag::{Code, Diagnostic},
    layout::{self, Layout},
    parse, project,
};

/// The resolver: the source of an interface major's IDL file, such as
/// `interfaces/aspis/base/v1.idl` for `aspis.base/1`, or None. The minor in
/// the reference is always None: the file holds every minor.
pub type Resolver<'r> = dyn FnMut(&InterfaceRef<'_>) -> Option<alloc::vec::Vec<u8>> + 'r;

/// A unit index that stands for an import that failed to load.
pub const NO_UNIT: usize = usize::MAX;

/// One interface file at one minor, with its names bound.
#[derive(Debug, Clone)]
pub struct Unit {
    pub file: File,
    /// The `id(...)` name, or "" when the header lacks it.
    pub name: String,
    /// `version(M.m)`, or 0.0 when the header lacks it.
    pub version: Version,
    /// The unit each `use` line loaded, or [`NO_UNIT`].
    pub uses: Vec<usize>,
    /// Declared types (structs, unions, enums, flags, aliases): member
    /// indexes by name.
    pub types: BTreeMap<String, usize>,
    /// Objects, by name.
    pub objects: BTreeMap<String, usize>,
    pub consts: BTreeMap<String, usize>,
    pub errors: BTreeMap<String, usize>,
    pub methods: BTreeMap<String, usize>,
}

impl Unit {
    fn new(file: File, uses: Vec<usize>) -> Unit {
        let attrs = &file.interface.attrs;
        let name = match ast::attr(attrs, "id").and_then(|a| a.args.as_deref()) {
            Some([AttrArg::Name(n, _)]) => n.clone(),
            _ => String::new(),
        };
        let version = ast::version_attr(attrs, "version").unwrap_or(Version { major: 0, minor: 0 });
        let mut u = Unit {
            file,
            name,
            version,
            uses,
            types: BTreeMap::new(),
            objects: BTreeMap::new(),
            consts: BTreeMap::new(),
            errors: BTreeMap::new(),
            methods: BTreeMap::new(),
        };
        for (i, m) in u.file.interface.members.iter().enumerate() {
            let table = match &m.kind {
                MemberKind::Const { .. } => &mut u.consts,
                MemberKind::Error { .. } => &mut u.errors,
                MemberKind::Method(_) => &mut u.methods,
                MemberKind::Object { .. } => &mut u.objects,
                MemberKind::Reserved { .. } => continue,
                _ => &mut u.types,
            };
            if let Some(n) = m.name() {
                // The first declaration wins; the checker reports the rest.
                table.entry(n.name.clone()).or_insert(i);
            }
        }
        u
    }

    pub fn major(&self) -> u16 {
        self.version.major
    }

    pub fn members(&self) -> &[Member] {
        &self.file.interface.members
    }

    /// Whether the interface is `[kernel]`.
    pub fn is_kernel(&self) -> bool {
        ast::has_attr(&self.file.interface.attrs, "kernel")
    }

    /// Whether the interface is local: `[local]`, or `[kernel]`, which
    /// implies it.
    pub fn is_local(&self) -> bool {
        self.is_kernel() || ast::has_attr(&self.file.interface.attrs, "local")
    }
}

/// A declared type: its unit and its member index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TypeId {
    pub unit: usize,
    pub member: usize,
}

/// Every unit a check loaded.
#[derive(Debug, Clone, Default)]
pub struct Model {
    pub units: Vec<Unit>,
}

impl Model {
    pub fn unit(&self, u: usize) -> &Unit {
        &self.units[u]
    }

    pub fn member(&self, id: TypeId) -> &Member {
        &self.units[id.unit].file.interface.members[id.member]
    }

    /// Resolves a type reference made in unit `u`: a local type, a name a
    /// `use` line imports, or a qualified `iface/M.name` that a `use` line
    /// names.
    pub fn resolve(&self, u: usize, r: &TypeRef) -> Option<TypeId> {
        let unit = &self.units[u];
        match &r.iface {
            None => {
                if let Some(&m) = unit.types.get(&r.name.name) {
                    return Some(TypeId { unit: u, member: m });
                }
                self.imported(u, |_| true, &r.name.name)
            }
            Some(i) => self.imported(
                u,
                |use_| use_.iface.name == i.name && use_.iface.major == i.major,
                &r.name.name,
            ),
        }
    }

    /// A name brought in by a `use` line of unit `u` that `which` selects.
    fn imported(&self, u: usize, which: impl Fn(&Use) -> bool, name: &str) -> Option<TypeId> {
        let unit = &self.units[u];
        for (k, use_) in unit.file.uses.iter().enumerate() {
            if !which(use_) || !use_.names.iter().any(|n| n.name == name) {
                continue;
            }
            let target = *unit.uses.get(k)?;
            if target == NO_UNIT {
                return None;
            }
            let &m = self.units[target].types.get(name)?;
            return Some(TypeId {
                unit: target,
                member: m,
            });
        }
        None
    }

    /// A constant of unit `u`: its type and value.
    pub fn constant(&self, u: usize, name: &str) -> Option<(IntType, Option<i128>)> {
        let unit = &self.units[u];
        let &m = unit.consts.get(name)?;
        match &unit.members()[m].kind {
            MemberKind::Const { ty, value, .. } => Some((*ty, value.value)),
            _ => None,
        }
    }

    /// A bound's value, when it has one.
    pub fn bound(&self, u: usize, b: &Bound) -> Option<i128> {
        match b {
            Bound::Lit(l) => l.value,
            Bound::Const(c) => self.constant(u, &c.name)?.1,
        }
    }
}

/// A checked file: the model of it and its imports, and its layout.
#[derive(Debug, Clone)]
pub struct Checked {
    pub model: Model,
    /// The checked file's unit.
    pub root: usize,
    pub layout: Layout,
}

impl Checked {
    /// The checked file's unit.
    pub fn unit(&self) -> &Unit {
        self.model.unit(self.root)
    }

    pub fn file(&self) -> &File {
        &self.unit().file
    }

    /// The file projected to one of its minors, with its own layout. The
    /// imports stay as they are: each is already at its `use` minor.
    pub fn project(&self, minor: u16) -> Checked {
        let (file, kept) = project::project_uses(self.file(), minor);
        let mut model = self.model.clone();
        let all = &model.units[self.root].uses;
        let uses = kept.iter().map(|&k| all[k]).collect();
        model.units.push(Unit::new(file, uses));
        let root = model.units.len() - 1;
        let layout = layout::compute(&model, root);
        Checked {
            model,
            root,
            layout,
        }
    }
}

/// Parses and checks an IDL file, loading its imports through `resolve`.
pub fn check(
    src: &[u8],
    resolve: &mut Resolver<'_>,
    limits: &Limits,
) -> Result<Checked, Vec<Diagnostic>> {
    let mut loader = Loader {
        resolve,
        limits,
        model: Model::default(),
        by_minor: BTreeMap::new(),
        files: BTreeMap::new(),
        stack: Vec::new(),
    };
    let file = parse::parse(src, limits).map_err(|d| vec![d])?;
    let root = loader.check_file(file, 0)?;
    let layout = layout::compute(&loader.model, root);
    Ok(Checked {
        model: loader.model,
        root,
        layout,
    })
}

struct Loader<'l, 'r> {
    resolve: &'l mut Resolver<'r>,
    limits: &'l Limits,
    model: Model,
    /// Units loaded for `use` lines, by interface, major and minor.
    by_minor: BTreeMap<(String, u16, u16), usize>,
    /// Imported files checked at their own version, by interface and major:
    /// the file, or None when it failed.
    files: BTreeMap<(String, u16), Option<File>>,
    /// The imports being loaded, to find cycles.
    stack: Vec<(String, u16)>,
}

impl Loader<'_, '_> {
    /// Loads a parsed file's imports and checks it. Returns its unit.
    fn check_file(&mut self, file: File, depth: usize) -> Result<usize, Vec<Diagnostic>> {
        let mut diags = Vec::new();
        let mut uses = Vec::new();
        for u in &file.uses {
            match self.import(u, depth) {
                Ok(i) => uses.push(i),
                Err(message) => {
                    diags.push(Diagnostic::new(u.iface.span, Code::Import, message));
                    uses.push(NO_UNIT);
                }
            }
        }
        if !diags.is_empty() {
            return Err(diags);
        }
        self.model.units.push(Unit::new(file, uses));
        let unit = self.model.units.len() - 1;
        let mut diags = rules::run(&self.model, unit, self.limits);
        diags.extend(crate::doc::check(&self.model, unit));
        if diags.is_empty() {
            Ok(unit)
        } else {
            Err(diags)
        }
    }

    /// Loads the interface a `use` line names, at its minor.
    fn import(&mut self, u: &Use, depth: usize) -> Result<usize, String> {
        let name = u.iface.name.clone();
        let major = u.iface.major;
        let minor = u.iface.minor_or_zero();
        if let Some(&i) = self.by_minor.get(&(name.clone(), major, minor)) {
            return Ok(i);
        }
        let key = (name.clone(), major);
        if self.stack.contains(&key) {
            return Err(format!(
                "{name}/{major} imports itself, through its own use lines"
            ));
        }
        if depth >= self.limits.import_depth {
            return Err(format!(
                "imports nested more than {} deep",
                self.limits.import_depth
            ));
        }
        let full = match self.files.get(&key) {
            Some(Some(f)) => f.clone(),
            Some(None) => return Err(format!("{name}/{major} has errors")),
            None => {
                if self.files.len() >= self.limits.imports {
                    return Err(format!(
                        "more than {} interfaces imported",
                        self.limits.imports
                    ));
                }
                let r = InterfaceRef {
                    name: &name,
                    major,
                    minor: None,
                };
                let src =
                    (self.resolve)(&r).ok_or_else(|| format!("no IDL file for {name}/{major}"))?;
                self.stack.push(key.clone());
                let checked = parse::parse(&src, self.limits)
                    .map_err(|d| vec![d])
                    .and_then(|f| self.check_file(f, depth + 1));
                self.stack.pop();
                match checked {
                    Ok(unit) => {
                        let f = self.model.units[unit].file.clone();
                        self.files.insert(key, Some(f.clone()));
                        f
                    }
                    Err(d) => {
                        self.files.insert(key, None);
                        let first = d.first().map(|d| d.to_string()).unwrap_or_default();
                        return Err(format!("{name}/{major} has errors: {first}"));
                    }
                }
            }
        };
        let full_unit = Unit::new(full, Vec::new());
        if full_unit.name != name || full_unit.major() != major {
            return Err(format!(
                "the IDL file for {name}/{major} declares {}/{}",
                full_unit.name,
                full_unit.major()
            ));
        }
        if full_unit.version.minor < minor {
            return Err(format!(
                "{name}/{major} describes minors up to {}, not {minor}",
                full_unit.version.minor
            ));
        }
        // The imported file at the use line's minor. Its own use lines were
        // loaded when it was checked, so these find them.
        let (projected, _) = project::project_uses(&full_unit.file, minor);
        let mut uses = Vec::new();
        for pu in &projected.uses {
            uses.push(self.import(pu, depth + 1)?);
        }
        let unit = Unit::new(projected, uses);
        for n in &u.names {
            if !unit.types.contains_key(&n.name) {
                return Err(format!(
                    "{name}/{major}.{minor} declares no type '{}'",
                    n.name
                ));
            }
        }
        self.model.units.push(unit);
        let i = self.model.units.len() - 1;
        self.by_minor.insert((name, major, minor), i);
        Ok(i)
    }
}
