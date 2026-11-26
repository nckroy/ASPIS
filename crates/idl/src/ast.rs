// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The syntax tree of an IDL file, as `grammars/idl.abnf` shapes it.
//!
//! The tree keeps what the source says, with byte spans for diagnostics.
//! It resolves nothing: names are text until [`crate::model`] binds them.
//! Doc comments are kept, but they are outside the canonical form (ADR
//! 0067, rule 5).

use alloc::{boxed::Box, string::String, vec::Vec};

use crate::diag::Span;

/// A name as written, with its span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ident {
    pub name: String,
    pub span: Span,
}

/// An integer literal: `int-lit`. The grammar puts no bound on its digits,
/// so the value is None when it doesn't fit an i128; the checker refuses
/// it then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntLit {
    pub value: Option<i128>,
    pub span: Span,
}

/// `version-lit`: `M.m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
}

/// `interface-ref`: `name/major[.minor]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceRef {
    pub name: String,
    pub major: u16,
    /// The minor as written; a missing one means `.0`.
    pub minor: Option<u16>,
    pub span: Span,
}

impl IfaceRef {
    pub fn minor_or_zero(&self) -> u16 {
        self.minor.unwrap_or(0)
    }
}

/// `id-lit`: an object ID, until D34 gives its text form (L01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdLit {
    /// `reserved(n)`: the reserved authority with sequence number n (L02).
    Reserved(IntLit),
    /// `hex(...)`: the 32 octets.
    Hex([u8; 32]),
}

/// One argument of an attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrArg {
    Version(Version, Span),
    Int(IntLit),
    /// A dotted name: `interface-name`.
    Name(String, Span),
    /// A `member-name`.
    Member(String, Span),
    Id(IdLit, Span),
}

impl AttrArg {
    pub fn span(&self) -> Span {
        match self {
            AttrArg::Version(_, s)
            | AttrArg::Name(_, s)
            | AttrArg::Member(_, s)
            | AttrArg::Id(_, s) => *s,
            AttrArg::Int(i) => i.span,
        }
    }
}

/// `attr`: a name, and its arguments when it has parentheses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    pub name: Ident,
    pub args: Option<Vec<AttrArg>>,
    pub span: Span,
}

/// The integer widths: `int-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntType {
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
}

impl IntType {
    pub fn from_word(w: &str) -> Option<IntType> {
        Some(match w {
            "u8" => IntType::U8,
            "u16" => IntType::U16,
            "u32" => IntType::U32,
            "u64" => IntType::U64,
            "i8" => IntType::I8,
            "i16" => IntType::I16,
            "i32" => IntType::I32,
            "i64" => IntType::I64,
            _ => return None,
        })
    }

    pub fn word(self) -> &'static str {
        match self {
            IntType::U8 => "u8",
            IntType::U16 => "u16",
            IntType::U32 => "u32",
            IntType::U64 => "u64",
            IntType::I8 => "i8",
            IntType::I16 => "i16",
            IntType::I32 => "i32",
            IntType::I64 => "i64",
        }
    }

    /// The width in octets.
    pub fn octets(self) -> u64 {
        match self {
            IntType::U8 | IntType::I8 => 1,
            IntType::U16 | IntType::I16 => 2,
            IntType::U32 | IntType::I32 => 4,
            IntType::U64 | IntType::I64 => 8,
        }
    }

    pub fn signed(self) -> bool {
        matches!(
            self,
            IntType::I8 | IntType::I16 | IntType::I32 | IntType::I64
        )
    }

    /// The values the type holds.
    pub fn range(self) -> (i128, i128) {
        let bits = 8 * self.octets() as u32;
        if self.signed() {
            (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
        } else {
            (0, (1i128 << bits) - 1)
        }
    }
}

/// A capability's qualifier: one of the four rights (ADR 0049, rule 2),
/// or `immutable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapQual {
    Grant,
    GrantReply,
    Immutable,
    Read,
    Write,
}

impl CapQual {
    pub fn from_word(w: &str) -> Option<CapQual> {
        Some(match w {
            "read" => CapQual::Read,
            "write" => CapQual::Write,
            "grant" => CapQual::Grant,
            "grant_reply" => CapQual::GrantReply,
            "immutable" => CapQual::Immutable,
            _ => return None,
        })
    }

    /// The word, as written. The order of the variants is the words'
    /// alphabetical order, which the canonical form sorts by.
    pub fn word(self) -> &'static str {
        match self {
            CapQual::Read => "read",
            CapQual::Write => "write",
            CapQual::Grant => "grant",
            CapQual::GrantReply => "grant_reply",
            CapQual::Immutable => "immutable",
        }
    }
}

/// `bound`: a literal, or a constant's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bound {
    Lit(IntLit),
    Const(Ident),
}

/// `type-ref`: a declared type, local or imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeRef {
    /// The interface of a qualified reference, `iface/M.name`.
    pub iface: Option<IfaceRef>,
    pub name: Ident,
}

/// `base-type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseType {
    Bool,
    Int(IntType),
    F32,
    F64,
    Id,
    Uuid,
    String(Bound),
    Bytes(Bound),
    Seq(Box<Type>, Bound),
    Array(Box<Type>, Bound),
    Cap(IfaceRef, Vec<(CapQual, Span)>),
    Slot(IfaceRef, Vec<(CapQual, Span)>),
    Ref(TypeRef),
}

/// `type`: a base type, optional when it ends in `?`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Type {
    pub base: BaseType,
    pub optional: bool,
    pub span: Span,
}

/// `field`: in a struct, an object, an error's detail, or a method's
/// parameters or results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub docs: Vec<String>,
    pub attrs: Vec<Attr>,
    /// The position, when written as `@n`.
    pub ordinal: Option<(u16, Span)>,
    pub name: Ident,
    pub ty: Type,
    pub span: Span,
}

/// `arm`: a union's arm, or a retired one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arm {
    Arm {
        docs: Vec<String>,
        attrs: Vec<Attr>,
        ordinal: u16,
        name: Ident,
        ty: Type,
        span: Span,
    },
    Reserved {
        ordinal: u16,
        span: Span,
    },
}

/// `value`: an enum's or flags type's value, or a retired one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Value {
        docs: Vec<String>,
        attrs: Vec<Attr>,
        name: Ident,
        value: IntLit,
        span: Span,
    },
    Reserved {
        value: IntLit,
        span: Span,
    },
}

/// A method's results, after `->`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Results {
    pub kind: ResultsKind,
    /// `stream<T>`, the method's server stream.
    pub stream: Option<TypeRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultsKind {
    /// Only a stream.
    None,
    /// `-> T`: one unnamed result, the key `result` in JSON.
    Single(Type),
    /// `-> (a: T, ...)`.
    Fields(Vec<Field>),
}

/// `method`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Method {
    pub ordinal: u16,
    pub ordinal_span: Span,
    pub name: Ident,
    pub params: Vec<Field>,
    pub results: Option<Results>,
    /// `error(...)`: the interface's own errors it may return.
    pub errors: Vec<Ident>,
}

/// What a member declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberKind {
    Const {
        name: Ident,
        ty: IntType,
        value: IntLit,
    },
    Alias {
        name: Ident,
        ty: Type,
    },
    Struct {
        name: Ident,
        fields: Vec<Field>,
    },
    Object {
        name: Ident,
        fields: Vec<Field>,
    },
    Union {
        name: Ident,
        arms: Vec<Arm>,
    },
    Enum {
        /// `flags` rather than `enum`.
        flags: bool,
        name: Ident,
        width: IntType,
        width_span: Span,
        values: Vec<Value>,
    },
    Error {
        name: Ident,
        code: IntLit,
        /// The detail fields; None when no block is written.
        fields: Option<Vec<Field>>,
    },
    Method(Method),
    /// `reserved @n;`: a retired method number.
    Reserved {
        ordinal: u16,
    },
}

/// `member`: one declaration inside the interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub docs: Vec<String>,
    pub attrs: Vec<Attr>,
    pub kind: MemberKind,
    pub span: Span,
}

impl Member {
    /// The declared name, if the member has one.
    pub fn name(&self) -> Option<&Ident> {
        match &self.kind {
            MemberKind::Const { name, .. }
            | MemberKind::Alias { name, .. }
            | MemberKind::Struct { name, .. }
            | MemberKind::Object { name, .. }
            | MemberKind::Union { name, .. }
            | MemberKind::Enum { name, .. }
            | MemberKind::Error { name, .. } => Some(name),
            MemberKind::Method(m) => Some(&m.name),
            MemberKind::Reserved { .. } => None,
        }
    }

    /// Whether it declares a type that fields may use.
    pub fn is_type(&self) -> bool {
        matches!(
            self.kind,
            MemberKind::Alias { .. }
                | MemberKind::Struct { .. }
                | MemberKind::Union { .. }
                | MemberKind::Enum { .. }
        )
    }
}

/// `use-decl`: named types of another interface's major.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Use {
    pub iface: IfaceRef,
    pub names: Vec<Ident>,
    pub span: Span,
}

/// `interface`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub docs: Vec<String>,
    pub attrs: Vec<Attr>,
    pub name: Ident,
    pub members: Vec<Member>,
    pub span: Span,
}

/// `idl-file`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// The `//!` lines, without the `//!`.
    pub docs: Vec<String>,
    pub uses: Vec<Use>,
    pub interface: Interface,
}

/// Finds an attribute by name.
pub fn attr<'a>(attrs: &'a [Attr], name: &str) -> Option<&'a Attr> {
    attrs.iter().find(|a| a.name.name == name)
}

/// Whether an attribute is present.
pub fn has_attr(attrs: &[Attr], name: &str) -> bool {
    attr(attrs, name).is_some()
}

/// The version argument of an attribute such as `since(M.m)`.
pub fn version_attr(attrs: &[Attr], name: &str) -> Option<Version> {
    match attr(attrs, name)?.args.as_deref() {
        Some([AttrArg::Version(v, _)]) => Some(*v),
        _ => None,
    }
}
