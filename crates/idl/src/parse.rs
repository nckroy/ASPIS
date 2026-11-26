// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The hand-written recursive-descent parser (ADR 0067, rule 11).
//!
//! Each function follows one rule of `grammars/idl.abnf`, and the parser
//! accepts exactly what that grammar accepts with its constraints:
//! `tests/grammar.rs` runs both over every vector, every IDL file in the
//! repository and deterministic mutations of them. Where the grammar
//! would let a name end early (ABNF doesn't munch), the context never lets
//! a name be followed by a name character, so scanning a whole word gives
//! the same answer.
//!
//! The only recursion is through nested types, `seq<seq<...>>`, and
//! [`Limits::nesting`] bounds it. The parser stops at the first error.

use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

use idl_rt::names::{self, is_label, is_member_name};

use crate::{
    Limits,
    ast::*,
    diag::{Code, Diagnostic, Span},
    lex::Cursor,
};

/// The built-in type words, which no declared type may take: the
/// constraint on `decl-name`.
pub const BUILTIN_TYPES: [&str; 20] = [
    "bool", "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "f32", "f64", "id", "uuid",
    "string", "bytes", "seq", "array", "cap", "slot", "stream",
];

type R<T> = Result<T, Diagnostic>;

/// Parses an IDL file.
pub fn parse(src: &[u8], limits: &Limits) -> R<File> {
    if src.len() > limits.source {
        return Err(Diagnostic::new(
            Span::new(0, 0),
            Code::Limit,
            format!("the file is over {} octets", limits.source),
        ));
    }
    let mut p = Parser::new(src, limits);
    p.file()
}

/// The rules `grammars/idl.vectors` tests on their own, besides
/// `idl-file`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    IdlFile,
    Type,
    Attrs,
    Comment,
    Docs,
    IntLit,
    IdLit,
    Results,
    Method,
}

impl Rule {
    pub fn from_name(name: &str) -> Option<Rule> {
        Some(match name {
            "idl-file" => Rule::IdlFile,
            "type" => Rule::Type,
            "attrs" => Rule::Attrs,
            "comment" => Rule::Comment,
            "docs" => Rule::Docs,
            "int-lit" => Rule::IntLit,
            "id-lit" => Rule::IdLit,
            "results" => Rule::Results,
            "method" => Rule::Method,
            _ => return None,
        })
    }
}

/// Whether `src` is exactly one match of `rule`, as the parser reads it.
/// The grammar tests compare it with crates/abnf's constrained match.
pub fn parse_rule(rule: Rule, src: &[u8], limits: &Limits) -> R<()> {
    let mut p = Parser::new(src, limits);
    match rule {
        Rule::IdlFile => {
            p.file()?;
        }
        Rule::Type => {
            p.ty()?;
        }
        Rule::Attrs => {
            p.attrs()?;
        }
        Rule::Comment => {
            if !(p.c.at(b"//") && !matches!(p.c.peek_at(2), Some(b'/' | b'!'))) {
                return Err(p.c.error("expected a comment"));
            }
            p.c.trivia()?;
            // The rule is one comment: no whitespace after it.
            let end = p.c.pos;
            let line_end = src.iter().position(|&b| b == b'\n').map_or(0, |i| i + 1);
            if end != line_end {
                return Err(p.c.error("expected the end of the comment"));
            }
        }
        Rule::Docs => {
            p.c.trivia()?;
            if !p.c.at_doc(false) {
                return Err(p.c.error("expected a doc comment"));
            }
            loop {
                p.c.doc_line()?;
                let save = p.c.pos;
                p.c.trivia()?;
                if !p.c.at_doc(false) {
                    p.c.pos = save;
                    break;
                }
            }
        }
        Rule::IntLit => {
            p.int_lit()?;
        }
        Rule::IdLit => {
            p.id_lit()?;
        }
        Rule::Results => {
            p.results()?;
        }
        Rule::Method => {
            p.method(Vec::new(), Vec::new(), p.c.pos)?;
        }
    }
    if !p.c.at_eof() {
        return Err(p.c.error("expected the end of the input"));
    }
    Ok(())
}

struct Parser<'a> {
    c: Cursor<'a>,
    limits: &'a Limits,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn new(src: &'a [u8], limits: &'a Limits) -> Parser<'a> {
        Parser {
            c: Cursor::new(src),
            limits,
            depth: 0,
        }
    }

    fn span_from(&self, start: usize) -> Span {
        Span::new(start, self.c.pos)
    }

    fn limit(&self, what: &str) -> Diagnostic {
        Diagnostic::new(
            Span::new(self.c.pos, self.c.pos),
            Code::Limit,
            format!("too many {what}"),
        )
    }

    /// `s`.
    fn s(&mut self) -> R<()> {
        self.c.trivia().map(|_| ())
    }

    /// `w`.
    fn w(&mut self) -> R<()> {
        match self.c.trivia()? {
            true => Ok(()),
            false => Err(self.c.error("expected whitespace")),
        }
    }

    fn expect(&mut self, b: u8) -> R<()> {
        match self.c.eat(b) {
            true => Ok(()),
            false => Err(self.c.error(format!("expected '{}'", b as char))),
        }
    }

    /// A keyword: exactly this word.
    fn keyword(&mut self, kw: &str) -> R<()> {
        if self.c.peek_word() == kw {
            self.c.pos += kw.len();
            Ok(())
        } else {
            Err(self.c.error(format!("expected '{kw}'")))
        }
    }

    /// `docs s`, when the cursor is at a doc comment; nothing otherwise.
    fn docs(&mut self) -> R<Vec<String>> {
        let mut docs = Vec::new();
        while self.c.at_doc(false) {
            docs.push(self.c.doc_line()?);
            self.s()?;
        }
        Ok(docs)
    }

    /// `[ attrs s ]`.
    fn opt_attrs(&mut self) -> R<Vec<Attr>> {
        if self.c.peek() == Some(b'[') {
            let a = self.attrs()?;
            self.s()?;
            Ok(a)
        } else {
            Ok(Vec::new())
        }
    }

    // ---- Files -----------------------------------------------------------

    /// `idl-file = s edition [ file-docs ] s *( use-decl s ) interface s`.
    fn file(&mut self) -> R<File> {
        self.s()?;
        // edition = %s"edition" w "2026" s ";"
        self.keyword("edition")?;
        self.w()?;
        if !self.c.eat_lit(b"2026") {
            return Err(self.c.error("expected '2026', the only edition"));
        }
        self.s()?;
        self.expect(b';')?;
        self.s()?;
        let mut docs = Vec::new();
        while self.c.at_doc(true) {
            docs.push(self.c.doc_line()?);
            self.s()?;
        }
        let mut uses = Vec::new();
        while self.c.peek_word() == "use" {
            if uses.len() == self.limits.uses {
                return Err(self.limit("use lines"));
            }
            uses.push(self.use_decl()?);
            self.s()?;
        }
        let interface = self.interface()?;
        self.s()?;
        if !self.c.at_eof() {
            return Err(self.c.error("expected the end of the file"));
        }
        Ok(File {
            docs,
            uses,
            interface,
        })
    }

    /// `use-decl = %s"use" w interface-ref ".{" s decl-name *( s "," s
    /// decl-name ) s "}" s ";"`.
    fn use_decl(&mut self) -> R<Use> {
        let start = self.c.pos;
        self.keyword("use")?;
        self.w()?;
        let iface = self.iface_ref()?;
        if !self.c.eat_lit(b".{") {
            return Err(self.c.error("expected '.{'"));
        }
        self.s()?;
        let mut names = vec![self.decl_name()?];
        loop {
            self.s()?;
            if self.c.eat(b',') {
                self.s()?;
                if names.len() == self.limits.members {
                    return Err(self.limit("imported names"));
                }
                names.push(self.decl_name()?);
            } else {
                break;
            }
        }
        self.expect(b'}')?;
        self.s()?;
        self.expect(b';')?;
        Ok(Use {
            iface,
            names,
            span: self.span_from(start),
        })
    }

    /// `interface = [ docs s ] attrs s %s"interface" w label s "{" *( s
    /// member ) s "}"`.
    fn interface(&mut self) -> R<Interface> {
        let start = self.c.pos;
        let docs = self.docs()?;
        if self.c.peek() != Some(b'[') {
            return Err(self
                .c
                .error("expected the interface's attributes, '[id(...), ...]'"));
        }
        let attrs = self.attrs()?;
        self.s()?;
        self.keyword("interface")?;
        self.w()?;
        let name_start = self.c.pos;
        let label = self.c.word();
        if !is_label(label.as_bytes()) {
            self.c.pos = name_start;
            return Err(self.c.error("expected the interface's name, a label"));
        }
        let name = Ident {
            name: label.into(),
            span: self.span_from(name_start),
        };
        self.s()?;
        self.expect(b'{')?;
        let mut members = Vec::new();
        loop {
            self.s()?;
            if self.c.eat(b'}') {
                break;
            }
            if members.len() == self.limits.members {
                return Err(self.limit("members"));
            }
            members.push(self.member()?);
        }
        Ok(Interface {
            docs,
            attrs,
            name,
            members,
            span: self.span_from(start),
        })
    }

    // ---- Members ---------------------------------------------------------

    /// `member`.
    fn member(&mut self) -> R<Member> {
        let start = self.c.pos;
        let docs = self.docs()?;
        let attrs = self.opt_attrs()?;
        if self.c.peek() == Some(b'@') {
            return self.method(docs, attrs, start);
        }
        let kind = match self.c.peek_word() {
            "const" => {
                // const-decl = %s"const" w member-name s ":" s int-type s
                //              "=" s int-lit s ";"
                self.keyword("const")?;
                self.w()?;
                let name = self.member_name()?;
                self.s()?;
                self.expect(b':')?;
                self.s()?;
                let ty = self.int_type()?;
                self.s()?;
                self.expect(b'=')?;
                self.s()?;
                let value = self.int_lit()?;
                self.s()?;
                self.expect(b';')?;
                MemberKind::Const { name, ty, value }
            }
            "alias" => {
                // alias-decl = %s"alias" w decl-name s "=" s type s ";"
                self.keyword("alias")?;
                self.w()?;
                let name = self.decl_name()?;
                self.s()?;
                self.expect(b'=')?;
                self.s()?;
                let ty = self.ty()?;
                self.s()?;
                self.expect(b';')?;
                MemberKind::Alias { name, ty }
            }
            kw @ ("struct" | "object") => {
                self.keyword(kw)?;
                self.w()?;
                let name = self.decl_name()?;
                self.s()?;
                let fields = self.field_list(b'{', b'}', false)?;
                if kw == "struct" {
                    MemberKind::Struct { name, fields }
                } else {
                    MemberKind::Object { name, fields }
                }
            }
            "union" => {
                self.keyword("union")?;
                self.w()?;
                let name = self.decl_name()?;
                self.s()?;
                let arms = self.list(b'{', b'}', |p| p.arm())?;
                MemberKind::Union { name, arms }
            }
            kw @ ("enum" | "flags") => {
                self.keyword(kw)?;
                self.w()?;
                let name = self.decl_name()?;
                self.s()?;
                self.expect(b':')?;
                self.s()?;
                let width_start = self.c.pos;
                let width = match IntType::from_word(self.c.peek_word()) {
                    Some(t) if !t.signed() => {
                        self.c.pos += t.word().len();
                        t
                    }
                    _ => return Err(self.c.error("expected u8, u16, u32 or u64")),
                };
                let width_span = self.span_from(width_start);
                self.s()?;
                let values = self.list(b'{', b'}', |p| p.value())?;
                MemberKind::Enum {
                    flags: kw == "flags",
                    name,
                    width,
                    width_span,
                    values,
                }
            }
            "error" => {
                // error-decl = %s"error" w member-name s "=" s int-lit
                //              [ s field-block ] s ";"
                self.keyword("error")?;
                self.w()?;
                let name = self.member_name()?;
                self.s()?;
                self.expect(b'=')?;
                self.s()?;
                let code = self.int_lit()?;
                self.s()?;
                let fields = if self.c.peek() == Some(b'{') {
                    let f = self.field_list(b'{', b'}', false)?;
                    self.s()?;
                    Some(f)
                } else {
                    None
                };
                self.expect(b';')?;
                MemberKind::Error { name, code, fields }
            }
            "reserved" => {
                // reserved-method = %s"reserved" w "@" ordinal s ";"
                self.keyword("reserved")?;
                self.w()?;
                self.expect(b'@')?;
                let (ordinal, _) = self.ordinal()?;
                self.s()?;
                self.expect(b';')?;
                MemberKind::Reserved { ordinal }
            }
            _ => return Err(self.c.error("expected a declaration")),
        };
        Ok(Member {
            docs,
            attrs,
            kind,
            span: self.span_from(start),
        })
    }

    /// `method = "@" ordinal w member-name s "(" s [ field *( s "," s field
    /// ) [ s "," ] ] s ")" [ s "->" s results ] [ w %s"error" s "(" s
    /// member-name *( s "," s member-name ) s ")" ] s ";"`.
    fn method(&mut self, docs: Vec<String>, attrs: Vec<Attr>, start: usize) -> R<Member> {
        self.expect(b'@')?;
        let (ordinal, ordinal_span) = self.ordinal()?;
        self.w()?;
        let name = self.member_name()?;
        self.s()?;
        let params = self.field_list(b'(', b')', false)?;
        let save = self.c.pos;
        self.s()?;
        let results = if self.c.eat_lit(b"->") {
            self.s()?;
            Some(self.results()?)
        } else {
            self.c.pos = save;
            None
        };
        let save = self.c.pos;
        let spaced = self.c.trivia()?;
        let mut errors = Vec::new();
        if spaced && self.c.peek_word() == "error" {
            self.keyword("error")?;
            self.s()?;
            self.expect(b'(')?;
            self.s()?;
            errors.push(self.member_name()?);
            loop {
                self.s()?;
                if !self.c.eat(b',') {
                    break;
                }
                self.s()?;
                if errors.len() == self.limits.members {
                    return Err(self.limit("errors"));
                }
                errors.push(self.member_name()?);
            }
            self.expect(b')')?;
        } else {
            self.c.pos = save;
        }
        self.s()?;
        self.expect(b';')?;
        Ok(Member {
            docs,
            attrs,
            kind: MemberKind::Method(Method {
                ordinal,
                ordinal_span,
                name,
                params,
                results,
                errors,
            }),
            span: self.span_from(start),
        })
    }

    /// `results = type [ w stream-type ] / "(" s field *( s "," s field ) [
    /// s "," ] s ")" [ s stream-type ] / stream-type`. It takes no
    /// whitespace after itself.
    fn results(&mut self) -> R<Results> {
        let kind = if self.c.peek() == Some(b'(') {
            ResultsKind::Fields(self.field_list(b'(', b')', true)?)
        } else if self.at_stream() {
            return Ok(Results {
                kind: ResultsKind::None,
                stream: Some(self.stream_type()?),
            });
        } else {
            ResultsKind::Single(self.ty()?)
        };
        let save = self.c.pos;
        let spaced = self.c.trivia()?;
        // After a type, the stream needs whitespace; after ")", it doesn't.
        let needs_space = matches!(kind, ResultsKind::Single(_));
        let stream = if (spaced || !needs_space) && self.at_stream() {
            Some(self.stream_type()?)
        } else {
            self.c.pos = save;
            None
        };
        Ok(Results { kind, stream })
    }

    fn at_stream(&self) -> bool {
        self.c.peek_word() == "stream" && self.c.after_word() == Some(b'<')
    }

    /// `stream-type = %s"stream" "<" s type-ref s ">"`.
    fn stream_type(&mut self) -> R<TypeRef> {
        self.keyword("stream")?;
        self.expect(b'<')?;
        self.s()?;
        let t = self.type_ref()?;
        self.s()?;
        self.expect(b'>')?;
        Ok(t)
    }

    /// A comma-separated list between `open` and `close`, with an optional
    /// trailing comma: `open s [ item *( s "," s item ) [ s "," ] ] s
    /// close`. With `one`, at least one item.
    fn list<T>(
        &mut self,
        open: u8,
        close: u8,
        mut item: impl FnMut(&mut Self) -> R<T>,
    ) -> R<Vec<T>> {
        self.expect(open)?;
        self.s()?;
        let mut out = Vec::new();
        if self.c.eat(close) {
            return Ok(out);
        }
        loop {
            if out.len() == self.limits.fields {
                return Err(self.limit("items in a list"));
            }
            out.push(item(self)?);
            self.s()?;
            if self.c.eat(b',') {
                self.s()?;
                if self.c.eat(close) {
                    return Ok(out);
                }
            } else {
                self.expect(close)?;
                return Ok(out);
            }
        }
    }

    /// `field-block`, a method's parameters, or a results list (`one`).
    fn field_list(&mut self, open: u8, close: u8, one: bool) -> R<Vec<Field>> {
        let fields = self.list(open, close, |p| p.field())?;
        if one && fields.is_empty() {
            return Err(self.c.error("expected at least one result"));
        }
        Ok(fields)
    }

    /// `field = [ docs s ] [ attrs s ] [ "@" ordinal w ] member-name s ":"
    /// s type`.
    fn field(&mut self) -> R<Field> {
        let start = self.c.pos;
        let docs = self.docs()?;
        let attrs = self.opt_attrs()?;
        let ordinal = if self.c.eat(b'@') {
            let o = self.ordinal()?;
            self.w()?;
            Some(o)
        } else {
            None
        };
        let name = self.member_name()?;
        self.s()?;
        self.expect(b':')?;
        self.s()?;
        let ty = self.ty()?;
        Ok(Field {
            docs,
            attrs,
            ordinal,
            name,
            ty,
            span: self.span_from(start),
        })
    }

    /// `arm = [ docs s ] [ attrs s ] "@" ordinal w member-name s ":" s type
    /// / %s"reserved" w "@" ordinal`.
    fn arm(&mut self) -> R<Arm> {
        let start = self.c.pos;
        let docs = self.docs()?;
        let attrs = self.opt_attrs()?;
        if docs.is_empty() && attrs.is_empty() && self.c.peek_word() == "reserved" {
            self.keyword("reserved")?;
            self.w()?;
            self.expect(b'@')?;
            let (ordinal, _) = self.ordinal()?;
            return Ok(Arm::Reserved {
                ordinal,
                span: self.span_from(start),
            });
        }
        self.expect(b'@')?;
        let (ordinal, _) = self.ordinal()?;
        self.w()?;
        let name = self.member_name()?;
        self.s()?;
        self.expect(b':')?;
        self.s()?;
        let ty = self.ty()?;
        Ok(Arm::Arm {
            docs,
            attrs,
            ordinal,
            name,
            ty,
            span: self.span_from(start),
        })
    }

    /// `value = [ docs s ] [ attrs s ] member-name s "=" s int-lit /
    /// %s"reserved" w int-lit`. A value may be named `reserved`.
    fn value(&mut self) -> R<Value> {
        let start = self.c.pos;
        let docs = self.docs()?;
        let attrs = self.opt_attrs()?;
        if docs.is_empty() && attrs.is_empty() && self.c.peek_word() == "reserved" {
            let save = self.c.pos;
            self.keyword("reserved")?;
            let spaced = self.c.trivia()?;
            if self.c.peek() != Some(b'=') {
                if !spaced {
                    return Err(self.c.error("expected whitespace"));
                }
                let value = self.int_lit()?;
                return Ok(Value::Reserved {
                    value,
                    span: self.span_from(start),
                });
            }
            self.c.pos = save;
        }
        let name = self.member_name()?;
        self.s()?;
        self.expect(b'=')?;
        self.s()?;
        let value = self.int_lit()?;
        Ok(Value::Value {
            docs,
            attrs,
            name,
            value,
            span: self.span_from(start),
        })
    }

    // ---- Types -------------------------------------------------------------

    /// `type = base-type [ "?" ]`.
    fn ty(&mut self) -> R<Type> {
        let start = self.c.pos;
        if self.depth == self.limits.nesting {
            return Err(Diagnostic::new(
                self.span_from(start),
                Code::Limit,
                format!("types nested more than {} deep", self.limits.nesting),
            ));
        }
        self.depth += 1;
        let base = self.base_type();
        self.depth -= 1;
        let base = base?;
        let optional = self.c.eat(b'?');
        Ok(Type {
            base,
            optional,
            span: self.span_from(start),
        })
    }

    /// `base-type`.
    fn base_type(&mut self) -> R<BaseType> {
        let word = self.c.peek_word();
        let generic = self.c.after_word() == Some(b'<');
        let simple = match word {
            "bool" => Some(BaseType::Bool),
            "f32" => Some(BaseType::F32),
            "f64" => Some(BaseType::F64),
            "id" => Some(BaseType::Id),
            "uuid" => Some(BaseType::Uuid),
            w => IntType::from_word(w).map(BaseType::Int),
        };
        if let Some(t) = simple {
            self.c.pos += word.len();
            return Ok(t);
        }
        match (word, generic) {
            ("string" | "bytes", true) => {
                self.c.pos += word.len() + 1;
                self.s()?;
                let b = self.bound()?;
                self.s()?;
                self.expect(b'>')?;
                Ok(if word == "string" {
                    BaseType::String(b)
                } else {
                    BaseType::Bytes(b)
                })
            }
            ("seq" | "array", true) => {
                self.c.pos += word.len() + 1;
                self.s()?;
                let t = Box::new(self.ty()?);
                self.s()?;
                self.expect(b',')?;
                self.s()?;
                let b = self.bound()?;
                self.s()?;
                self.expect(b'>')?;
                Ok(if word == "seq" {
                    BaseType::Seq(t, b)
                } else {
                    BaseType::Array(t, b)
                })
            }
            ("cap" | "slot", true) => {
                self.c.pos += word.len() + 1;
                self.s()?;
                let iface = self.iface_ref()?;
                let mut quals = Vec::new();
                loop {
                    self.s()?;
                    if !self.c.eat(b',') {
                        break;
                    }
                    self.s()?;
                    let start = self.c.pos;
                    match CapQual::from_word(self.c.peek_word()) {
                        Some(q) => {
                            self.c.pos += q.word().len();
                            if quals.len() == self.limits.attrs {
                                return Err(self.limit("qualifiers"));
                            }
                            quals.push((q, self.span_from(start)));
                        }
                        None => {
                            return Err(self
                                .c
                                .error("expected read, write, grant, grant_reply or immutable"));
                        }
                    }
                }
                self.expect(b'>')?;
                Ok(if word == "cap" {
                    BaseType::Cap(iface, quals)
                } else {
                    BaseType::Slot(iface, quals)
                })
            }
            _ => Ok(BaseType::Ref(self.type_ref()?)),
        }
    }

    /// `bound = int-lit / member-name`.
    fn bound(&mut self) -> R<Bound> {
        match self.c.peek() {
            Some(b'0'..=b'9' | b'-') => Ok(Bound::Lit(self.int_lit()?)),
            _ => Ok(Bound::Const(self.member_name()?)),
        }
    }

    /// `type-ref = decl-name / interface-ref "." decl-name`.
    fn type_ref(&mut self) -> R<TypeRef> {
        if self.c.after_word() == Some(b'.') {
            let iface = self.iface_ref()?;
            self.expect(b'.')?;
            let name = self.decl_name()?;
            Ok(TypeRef {
                iface: Some(iface),
                name,
            })
        } else {
            Ok(TypeRef {
                iface: None,
                name: self.decl_name()?,
            })
        }
    }

    /// `int-type`.
    fn int_type(&mut self) -> R<IntType> {
        match IntType::from_word(self.c.peek_word()) {
            Some(t) => {
                self.c.pos += t.word().len();
                Ok(t)
            }
            None => Err(self.c.error("expected an integer type")),
        }
    }

    // ---- Names, numbers and literals --------------------------------------

    /// `member-name`, with its constraints.
    fn member_name(&mut self) -> R<Ident> {
        let start = self.c.pos;
        let w = self.c.peek_word();
        if !is_member_name(w.as_bytes()) {
            return Err(self.c.error(
                "expected a member name: lower snake_case, at most 63 octets, not a reserved word",
            ));
        }
        self.c.pos += w.len();
        Ok(Ident {
            name: w.into(),
            span: self.span_from(start),
        })
    }

    /// `decl-name`: a member name that isn't a built-in type's word.
    fn decl_name(&mut self) -> R<Ident> {
        if BUILTIN_TYPES.contains(&self.c.peek_word()) {
            return Err(self
                .c
                .error("a built-in type's name can't name a declared type"));
        }
        self.member_name()
    }

    /// A dotted `name`: labels joined by ".", at least two, at most 255
    /// octets.
    fn dotted_name(&mut self) -> R<String> {
        let start = self.c.pos;
        let mut labels = 0;
        loop {
            let l = self.c.peek_word();
            if !is_label(l.as_bytes()) {
                return Err(self
                    .c
                    .error("expected a label: lowercase, at most 63 octets"));
            }
            self.c.pos += l.len();
            labels += 1;
            // A "." continues the name only when a label follows; in a
            // type-ref, ".name" after the major isn't reached here.
            if self.c.peek() == Some(b'.') && self.c.peek_at(1).is_some_and(|b| b != b'{') {
                self.c.pos += 1;
            } else {
                break;
            }
        }
        let text = &self.c.src[start..self.c.pos];
        if labels < 2 || text.len() > names::MAX_NAME {
            self.c.pos = start;
            return Err(self
                .c
                .error("expected a name of two or more labels, at most 255 octets"));
        }
        Ok(String::from(core::str::from_utf8(text).unwrap_or("")))
    }

    /// `interface-ref = interface-name "/" major [ "." minor ]`.
    fn iface_ref(&mut self) -> R<IfaceRef> {
        let start = self.c.pos;
        let name = self.dotted_name()?;
        self.expect(b'/')?;
        let major = self.number()?;
        let minor = if self.c.peek() == Some(b'.')
            && self.c.peek_at(1).is_some_and(|b| b.is_ascii_digit())
        {
            self.c.pos += 1;
            Some(self.number()?)
        } else {
            None
        };
        Ok(IfaceRef {
            name,
            major,
            minor,
            span: self.span_from(start),
        })
    }

    /// `number = "0" / %x31-39 *4DIGIT`, at most 65535.
    fn number(&mut self) -> R<u16> {
        let rest = &self.c.src[self.c.pos..];
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        match names::number(rest) {
            Some((v, n)) if n == digits => {
                self.c.pos += n;
                Ok(v)
            }
            _ => Err(self
                .c
                .error("expected a number from 0 to 65535, without leading zeros")),
        }
    }

    /// `ordinal`: a number from 1 to 65535.
    fn ordinal(&mut self) -> R<(u16, Span)> {
        let start = self.c.pos;
        match self.number()? {
            0 => {
                self.c.pos = start;
                Err(self.c.error("expected a number from 1 to 65535"))
            }
            n => Ok((n, self.span_from(start))),
        }
    }

    /// `int-lit = [ "-" ] ( "0" / %x31-39 *DIGIT ) / %s"0x" 1*( DIGIT /
    /// %x61-66 )`.
    fn int_lit(&mut self) -> R<IntLit> {
        let start = self.c.pos;
        if self.c.eat_lit(b"0x") {
            let rest = &self.c.src[self.c.pos..];
            let n = rest
                .iter()
                .take_while(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
                .count();
            if n == 0 {
                return Err(self.c.error("expected lowercase hex digits"));
            }
            let value = rest[..n].iter().try_fold(0i128, |v, &b| {
                let d = if b.is_ascii_digit() {
                    b - b'0'
                } else {
                    b - b'a' + 10
                };
                v.checked_mul(16)?.checked_add(i128::from(d))
            });
            self.c.pos += n;
            return Ok(IntLit {
                value,
                span: self.span_from(start),
            });
        }
        let neg = self.c.eat(b'-');
        let rest = &self.c.src[self.c.pos..];
        let n = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        if n == 0 || (n > 1 && rest[0] == b'0') {
            return Err(self.c.error("expected an integer, without leading zeros"));
        }
        let value = rest[..n]
            .iter()
            .try_fold(0i128, |v, &b| {
                v.checked_mul(10)?.checked_add(i128::from(b - b'0'))
            })
            .map(|v| if neg { -v } else { v });
        self.c.pos += n;
        Ok(IntLit {
            value,
            span: self.span_from(start),
        })
    }

    /// `id-lit = %s"reserved(" s int-lit s ")" / %s"hex(" 64( DIGIT /
    /// %x61-66 ) ")"`.
    fn id_lit(&mut self) -> R<IdLit> {
        if self.c.eat_lit(b"reserved(") {
            self.s()?;
            let n = self.int_lit()?;
            self.s()?;
            self.expect(b')')?;
            Ok(IdLit::Reserved(n))
        } else if self.c.eat_lit(b"hex(") {
            let rest = &self.c.src[self.c.pos..];
            let mut id = [0u8; 32];
            for (i, b) in id.iter_mut().enumerate() {
                let nibble = |c: Option<&u8>| match c {
                    Some(&c) if c.is_ascii_digit() => Some(c - b'0'),
                    Some(&c) if (b'a'..=b'f').contains(&c) => Some(c - b'a' + 10),
                    _ => None,
                };
                match (nibble(rest.get(2 * i)), nibble(rest.get(2 * i + 1))) {
                    (Some(h), Some(l)) => *b = h << 4 | l,
                    _ => return Err(self.c.error("expected 64 lowercase hex digits")),
                }
            }
            self.c.pos += 64;
            self.expect(b')')?;
            Ok(IdLit::Hex(id))
        } else {
            Err(self.c.error("expected reserved(n) or hex(...)"))
        }
    }

    // ---- Attributes ----------------------------------------------------------

    /// `attrs = "[" s attr *( s "," s attr ) s "]"`.
    fn attrs(&mut self) -> R<Vec<Attr>> {
        self.expect(b'[')?;
        self.s()?;
        let mut out = vec![self.attr()?];
        loop {
            self.s()?;
            if !self.c.eat(b',') {
                break;
            }
            self.s()?;
            if out.len() == self.limits.attrs {
                return Err(self.limit("attributes"));
            }
            out.push(self.attr()?);
        }
        self.expect(b']')?;
        Ok(out)
    }

    /// `attr = member-name [ "(" s attr-arg *( s "," s attr-arg ) s ")" ]`.
    fn attr(&mut self) -> R<Attr> {
        let start = self.c.pos;
        let name = self.member_name()?;
        let args = if self.c.eat(b'(') {
            self.s()?;
            let mut args = vec![self.attr_arg()?];
            loop {
                self.s()?;
                if !self.c.eat(b',') {
                    break;
                }
                self.s()?;
                if args.len() == self.limits.attrs {
                    return Err(self.limit("attribute arguments"));
                }
                args.push(self.attr_arg()?);
            }
            self.expect(b')')?;
            Some(args)
        } else {
            None
        };
        Ok(Attr {
            name,
            args,
            span: self.span_from(start),
        })
    }

    /// `attr-arg = version-lit / int-lit / interface-name / member-name /
    /// id-lit`.
    fn attr_arg(&mut self) -> R<AttrArg> {
        let start = self.c.pos;
        match self.c.peek() {
            Some(b'0'..=b'9') if !self.c.at(b"0x") => {
                let digits = self.c.src[start..]
                    .iter()
                    .take_while(|b| b.is_ascii_digit())
                    .count();
                if self.c.peek_at(digits) == Some(b'.') {
                    // version-lit = number "." number
                    let major = self.number()?;
                    self.expect(b'.')?;
                    let minor = self.number()?;
                    Ok(AttrArg::Version(
                        Version { major, minor },
                        self.span_from(start),
                    ))
                } else {
                    Ok(AttrArg::Int(self.int_lit()?))
                }
            }
            Some(b'0'..=b'9' | b'-') => Ok(AttrArg::Int(self.int_lit()?)),
            Some(b'a'..=b'z' | b'_') => {
                let word = self.c.peek_word();
                let paren = self.c.after_word() == Some(b'(');
                if (word == "reserved" || word == "hex") && paren {
                    let id = self.id_lit()?;
                    Ok(AttrArg::Id(id, self.span_from(start)))
                } else if self.c.after_word() == Some(b'.') {
                    let name = self.dotted_name()?;
                    Ok(AttrArg::Name(name, self.span_from(start)))
                } else {
                    let m = self.member_name()?;
                    Ok(AttrArg::Member(m.name, m.span))
                }
            }
            _ => Err(self.c.error("expected an attribute argument")),
        }
    }
}
