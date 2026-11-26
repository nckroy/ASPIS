// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! What the encoding makes of each type: worst-case sizes, capability
//! counts, locality and the rights a session needs (docs/design/
//! call-language.md, "Types", "The struct encoding", "Capability
//! indexes", "Local methods and interfaces", "Rights a session needs").
//!
//! Sizes are in octets and saturate at u64's maximum. The layout is
//! computed only for a model the checker passed, so every type resolves
//! and no type contains itself.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::String,
    vec::Vec,
};

use crate::{
    ast::{self, Arm, BaseType, CapQual, Field, IfaceRef, MemberKind, ResultsKind, Type, Version},
    model::{Model, TypeId},
};

/// The interfaces the kernel calls, which user-space servers implement
/// (ADR 0063, rule 3). A capability to one is a session capability.
pub const KERNEL_CALLED: [&str; 3] = [
    "aspis.kernel.fault",
    "aspis.kernel.pager",
    "aspis.kernel.memory_request",
];

/// The largest request body that never spills beside the largest header
/// ("Spilling"): above it, a request may carry 2 capabilities, not 3.
pub const INLINE_REQUEST: u64 = 704;
/// The same for a reply, an opening reply or a stream item.
pub const INLINE_REPLY: u64 = 952;
/// The most capability positions in one message, in each direction.
pub const MAX_CAPS: u32 = 3;
/// A request's worst case, with the largest header, is at most 2^24
/// octets (0064, rule 14): the body at most this.
pub const MAX_REQUEST: u64 = (1 << 24) - 256;
/// A reply's body, after its 8-octet header.
pub const MAX_REPLY: u64 = (1 << 24) - 8;
/// An opening reply's stream ID (u32) and start position (u64).
pub const STREAM_OPEN: u64 = 12;
/// A stream entry's kind, position and length.
pub const STREAM_ENTRY: u64 = 13;
/// A stream item: one entry in a batch of one, after the 8-octet header
/// and the 4-octet entry count.
pub const MAX_ITEM: u64 = (1 << 24) - 8 - 4 - STREAM_ENTRY;
/// An error's detail: the 768-octet envelope less its 46 octets of fixed
/// fields and empty tail, less the 14 octets of a `retry_after` the
/// runtime may add ("The error envelope").
pub const MAX_DETAIL: u64 = 768 - 46 - 14;

/// What a type's encoding comes to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Facts {
    /// The fewest octets a value takes.
    pub min: u64,
    /// The most octets a value of the known members takes.
    pub max: u64,
    /// The most capability positions a value holds: an optional one
    /// counts, and a union counts its largest arm.
    pub caps: u32,
    /// Holds a capability somewhere.
    pub has_cap: bool,
    /// Holds a `slot<...>` somewhere.
    pub has_slot: bool,
    /// Holds a capability of a kind that can't cross nodes.
    pub non_remotable: bool,
    /// Holds `f32` or `f64` somewhere.
    pub has_float: bool,
    /// Holds `bytes<N>` somewhere.
    pub has_bytes: bool,
    /// Fixed-width, in the note's sense ("Open and closed types"): usable
    /// as an `N × size` array element.
    pub fixed: bool,
    /// Is or holds an open struct or an open union, which a later minor
    /// could grow.
    pub open: bool,
    /// How deep a value nests, counted as type expressions are ("Types",
    /// Limits): each type expression is one level, and a named type adds
    /// its own, an alias its target's, a struct its deepest field's and a
    /// union its deepest arm's. An enum or flags type adds none. So
    /// `seq<u8>` is 2 deep, and a struct whose deepest field is `u8` is 1.
    /// Every value walker recurses about once a level, so the checker
    /// bounds this, through named types, as the parser bounds one
    /// expression's nesting.
    pub depth: u32,
}

impl Facts {
    fn fixed(n: u64) -> Facts {
        Facts {
            min: n,
            max: n,
            fixed: true,
            ..Facts::default()
        }
    }

    /// The flags of both, for a value that holds both.
    fn flags(mut self, o: &Facts) -> Facts {
        self.has_cap |= o.has_cap;
        self.has_slot |= o.has_slot;
        self.non_remotable |= o.non_remotable;
        self.has_float |= o.has_float;
        self.has_bytes |= o.has_bytes;
        self.open |= o.open;
        self
    }

    /// `presence`, then the value: an optional outside an open struct.
    fn optional(self) -> Facts {
        Facts {
            min: 1,
            max: self.max.saturating_add(1),
            fixed: false,
            ..self
        }
    }
}

/// Whether a capability of this kind can cross nodes: a session
/// capability, or an immutable memory object ("Translation between
/// nodes").
pub fn remotable(iface: &IfaceRef, quals: &[(CapQual, crate::diag::Span)]) -> bool {
    if !is_kernel_object(&iface.name) {
        return true;
    }
    iface.name == "aspis.kernel.memory" && quals.iter().any(|(q, _)| *q == CapQual::Immutable)
}

/// Whether an interface name is a kernel object's: `aspis.kernel.*`, except
/// the interfaces the kernel calls.
pub fn is_kernel_object(name: &str) -> bool {
    name.starts_with("aspis.kernel.") && !KERNEL_CALLED.contains(&name)
}

/// The facts of every declared type, computed on demand.
pub struct Types<'m> {
    model: &'m Model,
    memo: BTreeMap<TypeId, Facts>,
}

impl<'m> Types<'m> {
    pub fn new(model: &'m Model) -> Types<'m> {
        Types {
            model,
            memo: BTreeMap::new(),
        }
    }

    /// The facts of a declared type. The walk over named types is
    /// iterative, so a long chain of references can't overflow the stack;
    /// recursion follows only the nesting of one type expression.
    pub fn named(&mut self, id: TypeId) -> Facts {
        // Each entry is a type, and whether its references were pushed.
        let mut stack = alloc::vec![(id, false)];
        let mut open = BTreeSet::new();
        while let Some((top, expanded)) = stack.pop() {
            if self.memo.contains_key(&top) {
                continue;
            }
            if expanded {
                let f = self.compute(top);
                self.memo.insert(top, f);
                open.remove(&top);
                continue;
            }
            if !open.insert(top) {
                // A cycle, which the checker reports: stop here.
                continue;
            }
            stack.push((top, true));
            let memo = &self.memo;
            for_each_ref(self.model, top, &mut |d| {
                if !memo.contains_key(&d) {
                    stack.push((d, false));
                }
            });
        }
        self.memo.get(&id).copied().unwrap_or_default()
    }

    fn compute(&mut self, id: TypeId) -> Facts {
        let u = id.unit;
        match &self.model.member(id).kind {
            MemberKind::Alias { ty, .. } => self.ty(u, ty),
            MemberKind::Struct { fields, .. } => {
                let closed = ast::has_attr(&self.model.member(id).attrs, "closed");
                self.fields(u, fields, !closed)
            }
            MemberKind::Union { arms, .. } => {
                let closed = ast::has_attr(&self.model.member(id).attrs, "closed");
                self.union(u, arms, !closed)
            }
            MemberKind::Enum { width, .. } => Facts::fixed(width.octets()),
            _ => Facts::default(),
        }
    }

    /// A struct's fields: an open struct's head and tail, or a closed
    /// struct's head ("The struct encoding").
    pub fn fields(&mut self, u: usize, fields: &[Field], open: bool) -> Facts {
        let mut f = Facts {
            min: if open { 4 } else { 0 },
            max: if open { 4 } else { 0 },
            fixed: !open,
            open,
            ..Facts::default()
        };
        for field in fields {
            let mut t = self.base(u, &field.ty);
            if field.ty.optional {
                t = if open {
                    // A tail field: tag, length, then the value.
                    Facts {
                        min: 0,
                        max: t.max.saturating_add(6),
                        fixed: false,
                        ..t
                    }
                } else {
                    t.optional()
                };
            }
            f.min = f.min.saturating_add(t.min);
            f.max = f.max.saturating_add(t.max);
            f.caps = f.caps.saturating_add(t.caps);
            f.fixed &= t.fixed;
            f.depth = f.depth.max(t.depth);
            f = f.flags(&t);
        }
        f
    }

    fn union(&mut self, u: usize, arms: &[Arm], open: bool) -> Facts {
        let prefix = if open { 6 } else { 2 };
        let mut f = Facts {
            open,
            ..Facts::default()
        };
        let mut min: Option<u64> = None;
        let mut max = 0u64;
        for arm in arms {
            if let Arm::Arm { ty, .. } = arm {
                let t = self.ty(u, ty);
                min = Some(min.map_or(t.min, |m| m.min(t.min)));
                max = max.max(t.max);
                f.caps = f.caps.max(t.caps);
                f.depth = f.depth.max(t.depth);
                f = f.flags(&t);
            }
        }
        f.min = min.unwrap_or(0).saturating_add(prefix);
        f.max = max.saturating_add(prefix);
        f
    }

    /// A type expression where it stands alone: an optional one is
    /// `presence`, then the value.
    pub fn ty(&mut self, u: usize, t: &Type) -> Facts {
        let f = self.base(u, t);
        if t.optional { f.optional() } else { f }
    }

    /// A type expression without its `?`.
    pub fn base(&mut self, u: usize, t: &Type) -> Facts {
        let mut f = self.base_inner(u, t);
        // `..e` copied the element's depth, or a named type's own.
        f.depth = match &t.base {
            BaseType::Seq(..) | BaseType::Array(..) | BaseType::Ref(_) => f.depth,
            _ => 0,
        }
        .saturating_add(1);
        f
    }

    fn base_inner(&mut self, u: usize, t: &Type) -> Facts {
        match &t.base {
            BaseType::Bool => Facts::fixed(1),
            BaseType::Int(i) => Facts::fixed(i.octets()),
            BaseType::F32 => Facts {
                has_float: true,
                ..Facts::fixed(4)
            },
            BaseType::F64 => Facts {
                has_float: true,
                ..Facts::fixed(8)
            },
            BaseType::Id => Facts::fixed(32),
            BaseType::Uuid => Facts::fixed(16),
            BaseType::String(b) | BaseType::Bytes(b) => {
                let n = self.bound(u, b);
                Facts {
                    min: 4,
                    max: n.saturating_add(4),
                    has_bytes: matches!(t.base, BaseType::Bytes(_)),
                    ..Facts::default()
                }
            }
            BaseType::Seq(e, b) => {
                let n = self.bound(u, b);
                let e = self.ty(u, e);
                Facts {
                    min: 4,
                    max: n.saturating_mul(e.max).saturating_add(4),
                    caps: 0,
                    fixed: false,
                    ..e
                }
            }
            BaseType::Array(e, b) => {
                let n = self.bound(u, b);
                let e = self.ty(u, e);
                Facts {
                    min: n.saturating_mul(e.min),
                    max: n.saturating_mul(e.max),
                    caps: e.caps.saturating_mul(n.min(u64::from(u32::MAX)) as u32),
                    ..e
                }
            }
            BaseType::Cap(iface, quals) => Facts {
                caps: 1,
                has_cap: true,
                non_remotable: !remotable(iface, quals),
                ..Facts::fixed(1)
            },
            BaseType::Slot(..) => Facts {
                has_slot: true,
                non_remotable: true,
                ..Facts::fixed(8)
            },
            BaseType::Ref(r) => match self.model.resolve(u, r) {
                Some(id) => self.named(id),
                None => Facts::default(),
            },
        }
    }

    fn bound(&self, u: usize, b: &ast::Bound) -> u64 {
        self.model
            .bound(u, b)
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(0)
    }
}

/// Calls `f` with every declared type a type member refers to directly,
/// through its fields, arms or alias target, at any nesting.
pub fn for_each_ref(model: &Model, id: TypeId, f: &mut dyn FnMut(TypeId)) {
    let u = id.unit;
    let mut visit = |t: &Type| walk_refs(model, u, t, f);
    match &model.member(id).kind {
        MemberKind::Alias { ty, .. } => visit(ty),
        MemberKind::Struct { fields, .. } | MemberKind::Object { fields, .. } => {
            fields.iter().for_each(|fl| visit(&fl.ty))
        }
        MemberKind::Union { arms, .. } => arms.iter().for_each(|a| {
            if let Arm::Arm { ty, .. } = a {
                visit(ty)
            }
        }),
        _ => {}
    }
}

/// Calls `f` with every declared type a type expression names.
pub fn walk_refs(model: &Model, u: usize, t: &Type, f: &mut dyn FnMut(TypeId)) {
    match &t.base {
        BaseType::Seq(e, _) | BaseType::Array(e, _) => walk_refs(model, u, e, f),
        BaseType::Ref(r) => {
            if let Some(id) = model.resolve(u, r) {
                f(id)
            }
        }
        _ => {}
    }
}

/// A message body's worst case.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Body {
    pub min: u64,
    pub max: u64,
    /// Capability positions, in the worst case.
    pub caps: u32,
    /// Whether the body may spill beside the largest header ("Spilling").
    pub may_spill: bool,
}

/// A stream method's kind ("Server streams in the IDL").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Lossless,
    Lossy,
    Coalescing,
}

/// What the layout records of a stream method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamLayout {
    pub kind: StreamKind,
    pub item: Option<TypeId>,
    /// The item's worst case.
    pub item_max: u64,
    /// The worst-case entry: the item, plus 13 octets of kind, position
    /// and length. The QUIC window always fits one ("Remote push within
    /// QUIC's credit").
    pub entry_max: u64,
}

/// The rights a session capability carries ("Rights a session needs").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionRights {
    pub write: bool,
    pub grant_reply: bool,
    /// When any request carries capabilities.
    pub grant: bool,
}

/// What the layout records of one method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodLayout {
    /// The method's member index.
    pub member: usize,
    pub number: u16,
    pub name: String,
    pub since: Version,
    pub request: Body,
    /// The reply, or, for a stream method, the opening reply with its
    /// stream ID and start position. None for a one-way method.
    pub reply: Option<Body>,
    pub stream: Option<StreamLayout>,
    /// `[local]` written, or inferred from a capability that can't cross
    /// nodes.
    pub local: bool,
    pub local_inferred: bool,
    pub oneway: bool,
    pub idempotent: bool,
    pub readonly: bool,
}

/// What the layout records of one error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorLayout {
    pub member: usize,
    pub code: u16,
    /// The detail struct, an open struct.
    pub detail: Body,
}

/// The layout of one interface file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Layout {
    pub methods: Vec<MethodLayout>,
    pub errors: Vec<ErrorLayout>,
    pub session_rights: SessionRights,
}

/// The fields a method's results form: one unnamed result is the field
/// `result`.
pub fn result_fields(r: &ast::Results) -> Vec<Field> {
    match &r.kind {
        ResultsKind::None => Vec::new(),
        ResultsKind::Fields(f) => f.clone(),
        ResultsKind::Single(t) => alloc::vec![Field {
            docs: Vec::new(),
            attrs: Vec::new(),
            ordinal: None,
            name: ast::Ident {
                name: "result".into(),
                span: t.span,
            },
            ty: t.clone(),
            span: t.span,
        }],
    }
}

/// The effective `since` of a member: its own, or its container's.
pub fn since_of(attrs: &[ast::Attr], container: Version) -> Version {
    ast::version_attr(attrs, "since").map_or(container, |v| v.max(container))
}

/// Computes the layout of unit `u`.
pub fn compute(model: &Model, u: usize) -> Layout {
    let unit = model.unit(u);
    let base = Version {
        major: unit.major(),
        minor: 0,
    };
    let mut types = Types::new(model);
    let mut layout = Layout {
        session_rights: SessionRights {
            write: true,
            grant_reply: true,
            grant: false,
        },
        ..Layout::default()
    };
    for (i, m) in unit.members().iter().enumerate() {
        match &m.kind {
            MemberKind::Method(method) => {
                let req = types.fields(u, &method.params, true);
                let request = Body {
                    min: req.min,
                    max: req.max,
                    caps: req.caps,
                    may_spill: req.max > INLINE_REQUEST,
                };
                let oneway = ast::has_attr(&m.attrs, "oneway");
                let mut local_inferred = req.non_remotable;
                let (reply, stream) = match &method.results {
                    _ if oneway => (None, None),
                    None => {
                        let f = types.fields(u, &[], true);
                        (Some(body(f, 0)), None)
                    }
                    Some(r) => {
                        let f = types.fields(u, &result_fields(r), true);
                        local_inferred |= f.non_remotable;
                        let stream = r.stream.as_ref().map(|s| {
                            let item = model.resolve(u, s);
                            let item_max = item.map_or(0, |id| types.named(id).max);
                            let kind = if ast::has_attr(&m.attrs, "lossy") {
                                StreamKind::Lossy
                            } else if ast::has_attr(&m.attrs, "coalescing") {
                                StreamKind::Coalescing
                            } else {
                                StreamKind::Lossless
                            };
                            StreamLayout {
                                kind,
                                item,
                                item_max,
                                entry_max: item_max.saturating_add(STREAM_ENTRY),
                            }
                        });
                        let extra = if stream.is_some() { STREAM_OPEN } else { 0 };
                        (Some(body(f, extra)), stream)
                    }
                };
                if request.caps > 0 {
                    layout.session_rights.grant = true;
                }
                layout.methods.push(MethodLayout {
                    member: i,
                    number: method.ordinal,
                    name: method.name.name.clone(),
                    since: since_of(&m.attrs, base),
                    request,
                    reply,
                    stream,
                    local: local_inferred || ast::has_attr(&m.attrs, "local"),
                    local_inferred,
                    oneway,
                    idempotent: ast::has_attr(&m.attrs, "idempotent"),
                    readonly: ast::has_attr(&m.attrs, "readonly"),
                });
            }
            MemberKind::Error { code, fields, .. } => {
                let f = types.fields(u, fields.as_deref().unwrap_or(&[]), true);
                layout.errors.push(ErrorLayout {
                    member: i,
                    code: code.value.and_then(|v| u16::try_from(v).ok()).unwrap_or(0),
                    detail: body(f, 0),
                });
            }
            _ => {}
        }
    }
    layout
}

/// A reply-side body: `extra` octets before the struct, and the spill
/// threshold of a reply.
fn body(f: Facts, extra: u64) -> Body {
    let max = f.max.saturating_add(extra);
    Body {
        min: f.min.saturating_add(extra),
        max,
        caps: f.caps,
        may_spill: max > INLINE_REPLY,
    }
}
