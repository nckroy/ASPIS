// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The doc model (docs/design/call-language.md, "Doc comments"; Back ends,
//! row 6; L32).
//!
//! Doc comments use a CommonMark subset: paragraphs, lists, code spans,
//! fenced code and links, with cross-references written
//! `[aspis.catalog/1.watch]`. This module reads them into a typed tree per
//! item: [`parse`] for one comment, [`model`] for a whole file. Syntax it
//! doesn't recognize stays text, so a comment always reads.
//!
//! There is no file format yet: dm's renderer and the catalog browser
//! decide what they need (L32). It is an API, and the Rust back end turns
//! comments into rustdoc with [`rustdoc`].
//!
//! [`check`] is the checker's rule for doc comments: a cross-reference
//! into the same interface, or into one its `use` lines import, must
//! resolve. A reference to any other interface isn't checked, since the
//! compiler doesn't have it.
//!
//! Every function here is linear in the comment's length, and nothing
//! recurses (ADR 0068, rule 5).

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    Code, Diagnostic, Span,
    ast::{Arm, Field, Member, MemberKind, ResultsKind, Value},
    model::{Model, NO_UNIT, Unit},
};

/// One doc comment: its blocks, in order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Doc {
    pub blocks: Vec<Block>,
}

/// A block of a doc comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// Lines up to a blank line, a list or a fence.
    Paragraph(Vec<Inline>),
    /// Items that start with `- `, `* ` or `1. `. A line indented under an
    /// item continues it.
    List {
        ordered: bool,
        items: Vec<Vec<Inline>>,
    },
    /// A fenced code block: the info string after the fence, and the
    /// lines between the fences, each ending in a newline.
    Code { info: String, text: String },
}

/// Text inside a paragraph or a list item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inline {
    /// Plain text. A line break inside a paragraph is a space.
    Text(String),
    /// `` `code` ``.
    Code(String),
    /// `[text](url)`, or `<url>` with the URL as its text.
    Link { text: String, url: String },
    /// `[aspis.catalog/1.watch]`.
    XRef(XRef),
}

/// A cross-reference: an interface major, and a path inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XRef {
    pub interface: String,
    pub major: u16,
    /// Empty for the interface itself; a member, then a part of it: a
    /// field, parameter, result, arm or value.
    pub path: Vec<String>,
}

impl core::fmt::Display for XRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}/{}", self.interface, self.major)?;
        for p in &self.path {
            write!(f, ".{p}")?;
        }
        Ok(())
    }
}

/// A comment's text: the lines without their `///` or `//!`, and without
/// the one space that usually follows it.
fn strip(line: &str) -> &str {
    line.strip_prefix(' ').unwrap_or(line)
}

/// A fence line: three or more backticks after at most three spaces, and
/// the info string after them.
fn fence(line: &str) -> Option<&str> {
    let t = line.trim_start_matches(' ');
    if line.len() - t.len() > 3 {
        return None;
    }
    let rest = t.strip_prefix("```")?;
    Some(rest.trim_start_matches('`').trim())
}

/// A list marker at the start of a line: whether it is ordered, and the
/// item's text after the marker.
fn list_item(line: &str) -> Option<(bool, &str)> {
    if let Some(rest) = line.strip_prefix("- ").or_else(|| line.strip_prefix("* ")) {
        return Some((false, rest));
    }
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    if (1..=9).contains(&digits) {
        let rest = &line[digits..];
        if let Some(rest) = rest.strip_prefix(". ").or_else(|| rest.strip_prefix(") ")) {
            return Some((true, rest));
        }
    }
    None
}

/// Reads one doc comment's lines into its blocks.
pub fn parse(lines: &[String]) -> Doc {
    let mut blocks = Vec::new();
    let mut para: Vec<&str> = Vec::new();
    // The open list: ordered, and each item's lines.
    let mut list: Option<(bool, Vec<Vec<&str>>)> = None;
    let mut code: Option<(String, String)> = None;

    fn flush_para(para: &mut Vec<&str>, blocks: &mut Vec<Block>) {
        if !para.is_empty() {
            blocks.push(Block::Paragraph(inline(&para.join("\n"))));
            para.clear();
        }
    }
    fn flush_list(list: &mut Option<(bool, Vec<Vec<&str>>)>, blocks: &mut Vec<Block>) {
        if let Some((ordered, items)) = list.take() {
            let items = items.iter().map(|l| inline(&l.join("\n"))).collect();
            blocks.push(Block::List { ordered, items });
        }
    }

    for raw in lines {
        let line = strip(raw);
        if let Some((info, text)) = &mut code {
            if fence(line).is_some_and(str::is_empty) {
                blocks.push(Block::Code {
                    info: core::mem::take(info),
                    text: core::mem::take(text),
                });
                code = None;
            } else {
                text.push_str(line);
                text.push('\n');
            }
            continue;
        }
        if let Some(info) = fence(line) {
            flush_para(&mut para, &mut blocks);
            flush_list(&mut list, &mut blocks);
            code = Some((info.to_string(), String::new()));
            continue;
        }
        if line.trim().is_empty() {
            flush_para(&mut para, &mut blocks);
            flush_list(&mut list, &mut blocks);
            continue;
        }
        if let Some((ordered, rest)) = list_item(line) {
            flush_para(&mut para, &mut blocks);
            match &mut list {
                Some((o, items)) if *o == ordered => items.push(alloc::vec![rest]),
                _ => {
                    flush_list(&mut list, &mut blocks);
                    list = Some((ordered, alloc::vec![alloc::vec![rest]]));
                }
            }
            continue;
        }
        if let Some((_, items)) = &mut list {
            // A line indented under an item continues it; any other line
            // ends the list.
            if line.starts_with("  ") {
                if let Some(item) = items.last_mut() {
                    item.push(line.trim_start());
                }
                continue;
            }
            flush_list(&mut list, &mut blocks);
        }
        para.push(line);
    }
    // An unclosed fence runs to the end of the comment, as in CommonMark.
    if let Some((info, text)) = code {
        blocks.push(Block::Code { info, text });
    }
    flush_para(&mut para, &mut blocks);
    flush_list(&mut list, &mut blocks);
    Doc { blocks }
}

/// An inline token: its kind and the byte range it covers.
enum Token {
    Text,
    Code(usize, usize),
    Link {
        text: (usize, usize),
        url: (usize, usize),
    },
    XRef(XRef),
}

/// Splits text into inline tokens, each with its byte range. Anything that
/// isn't a code span, a link or a cross-reference is text.
fn tokens(s: &str) -> Vec<(Token, usize, usize)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut text_start = 0;
    let mut i = 0;
    // Each run of backticks (start, length), and for each the next run of
    // the same length, so finding where a code span closes never rescans
    // the text: the scan is linear (ADR 0068, rule 5).
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut k = 0;
    while k < b.len() {
        if b[k] == b'`' {
            let n = b[k..].iter().take_while(|&&c| c == b'`').count();
            runs.push((k, n));
            k += n;
        } else {
            k += 1;
        }
    }
    let mut close_of: Vec<Option<usize>> = alloc::vec![None; runs.len()];
    let mut next_of_len: alloc::collections::BTreeMap<usize, usize> = Default::default();
    for (r, &(_, n)) in runs.iter().enumerate().rev() {
        close_of[r] = next_of_len.insert(n, r);
    }
    let mut ri = 0;
    let push = |out: &mut Vec<(Token, usize, usize)>, text_start: usize, t, at, end| {
        if text_start < at {
            out.push((Token::Text, text_start, at));
        }
        out.push((t, at, end));
    };
    while i < b.len() {
        match b[i] {
            b'`' => {
                // A code span: a run of n backticks, up to the next run of
                // exactly n, found through `close_of` in constant time.
                while runs.get(ri).is_some_and(|r| r.0 < i) {
                    ri += 1;
                }
                let n = runs.get(ri).map_or(1, |r| r.1);
                match close_of.get(ri).copied().flatten() {
                    Some(k) => {
                        let j = runs[k].0;
                        push(&mut out, text_start, Token::Code(i + n, j), i, j + n);
                        i = j + n;
                        text_start = i;
                    }
                    None => i += n,
                }
            }
            b'[' => {
                let Some(close) = b[i + 1..].iter().position(|&c| c == b']' || c == b'[') else {
                    i += 1;
                    continue;
                };
                let close = i + 1 + close;
                if b[close] != b']' {
                    i = close;
                    continue;
                }
                let inner = (i + 1, close);
                // `[text](url)`: a link.
                if b.get(close + 1) == Some(&b'(')
                    && let Some(end) = b[close + 2..].iter().position(|&c| {
                        // Stopping where another token could start keeps
                        // the scan linear.
                        matches!(c, b')' | b'(' | b'[' | b'<' | b'`') || c.is_ascii_whitespace()
                    })
                {
                    let end = close + 2 + end;
                    let url = (close + 2, end);
                    if b[end] == b')' && url.0 < url.1 {
                        push(
                            &mut out,
                            text_start,
                            Token::Link { text: inner, url },
                            i,
                            end + 1,
                        );
                        i = end + 1;
                        text_start = i;
                        continue;
                    }
                }
                if let Some(x) = xref(&s[inner.0..inner.1]) {
                    push(&mut out, text_start, Token::XRef(x), i, close + 1);
                    i = close + 1;
                    text_start = i;
                    continue;
                }
                i = close + 1;
            }
            b'<' => {
                // `<scheme:...>`: an autolink.
                let end = b[i + 1..]
                    .iter()
                    .position(|&c| matches!(c, b'>' | b'<') || c.is_ascii_whitespace());
                if let Some(end) = end.map(|e| i + 1 + e)
                    && b[end] == b'>'
                    && is_autolink(&s[i + 1..end])
                {
                    push(
                        &mut out,
                        text_start,
                        Token::Link {
                            text: (i + 1, end),
                            url: (i + 1, end),
                        },
                        i,
                        end + 1,
                    );
                    i = end + 1;
                    text_start = i;
                    continue;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    if text_start < b.len() {
        out.push((Token::Text, text_start, b.len()));
    }
    out
}

/// An absolute URI, as CommonMark's autolinks take: a scheme of two to 32
/// letters, digits, `+`, `.` or `-`, then `:`.
fn is_autolink(s: &str) -> bool {
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    (2..=32).contains(&scheme.len())
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'-'))
        && !rest.is_empty()
        && !rest.contains(|c: char| c.is_ascii_control() || c == '<')
}

/// Reads a cross-reference's text, `name/major` then `.part`s: an
/// interface reference without a minor (ADR 0063, rule 10), then member
/// names. Anything else isn't one.
pub fn xref(s: &str) -> Option<XRef> {
    let (name, rest) = s.split_once('/')?;
    if !idl_rt::names::is_name(name.as_bytes()) {
        return None;
    }
    let mut parts = rest.split('.');
    let digits = parts.next()?;
    let (major, n) = idl_rt::names::number(digits.as_bytes())?;
    if n != digits.len() {
        return None;
    }
    let mut path = Vec::new();
    for p in parts {
        if !idl_rt::names::is_member_name(p.as_bytes()) || path.len() == 2 {
            return None;
        }
        path.push(p.to_string());
    }
    Some(XRef {
        interface: name.to_string(),
        major,
        path,
    })
}

/// A paragraph's or item's inline content. Line breaks become spaces.
fn inline(s: &str) -> Vec<Inline> {
    let mut out: Vec<Inline> = Vec::new();
    for (t, start, end) in tokens(s) {
        match t {
            Token::Text => {
                let text = s[start..end].replace('\n', " ");
                match out.last_mut() {
                    Some(Inline::Text(prev)) => prev.push_str(&text),
                    _ => out.push(Inline::Text(text)),
                }
            }
            Token::Code(a, b) => out.push(Inline::Code(s[a..b].replace('\n', " "))),
            Token::Link { text, url } => out.push(Inline::Link {
                text: s[text.0..text.1].replace('\n', " "),
                url: s[url.0..url.1].to_string(),
            }),
            Token::XRef(x) => out.push(Inline::XRef(x)),
        }
    }
    out
}

/// Every cross-reference in a comment, in order.
pub fn xrefs(doc: &Doc) -> Vec<&XRef> {
    let mut out = Vec::new();
    for b in &doc.blocks {
        let lists: Vec<&[Inline]> = match b {
            Block::Paragraph(p) => alloc::vec![p.as_slice()],
            Block::List { items, .. } => items.iter().map(Vec::as_slice).collect(),
            Block::Code { .. } => Vec::new(),
        };
        for l in lists {
            for i in l {
                if let Inline::XRef(x) = i {
                    out.push(x);
                }
            }
        }
    }
    out
}

/// The comment as rustdoc: each line as written, except that a
/// cross-reference becomes a code span, since rustdoc would read it as an
/// intra-doc link to a Rust path. Lines inside code spans and fenced code
/// are left alone.
pub fn rustdoc(lines: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(lines.len());
    let mut in_code = false;
    for raw in lines {
        let line = strip(raw);
        if fence(line).is_some() {
            in_code = if in_code {
                !fence(line).is_some_and(str::is_empty)
            } else {
                true
            };
            out.push(raw.clone());
            continue;
        }
        if in_code {
            out.push(raw.clone());
            continue;
        }
        let toks = tokens(raw);
        if !toks.iter().any(|(t, ..)| matches!(t, Token::XRef(_))) {
            out.push(raw.clone());
            continue;
        }
        let mut l = String::new();
        for (t, start, end) in toks {
            match t {
                Token::XRef(x) => {
                    l.push('`');
                    l.push_str(&x.to_string());
                    l.push('`');
                }
                _ => l.push_str(&raw[start..end]),
            }
        }
        out.push(l);
    }
    out
}

// ---- The model of a file ----------------------------------------------------

/// What a documented item is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    Interface,
    Const,
    Alias,
    Struct,
    Object,
    Union,
    Enum,
    Flags,
    Error,
    Method,
    /// A struct's, object's or error detail's field.
    Field,
    Param,
    Result,
    Arm,
    Value,
}

/// One documented item: where it is, what it is, and its comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Empty for the interface; a member, then a part of it.
    pub path: Vec<String>,
    pub kind: ItemKind,
    pub doc: Doc,
}

/// A file's doc model: the file's comment (`//!`), then every item in
/// declaration order, the interface first. Items without a comment are
/// listed too, with an empty one, so a renderer sees every member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocModel {
    pub interface: String,
    pub major: u16,
    pub file: Doc,
    pub items: Vec<Item>,
}

/// The parts of a member that a cross-reference can name, with their kind
/// and comment.
fn fields(fs: &[Field], k: ItemKind) -> Vec<(&str, ItemKind, &[String])> {
    fs.iter()
        .map(|f| (f.name.name.as_str(), k, f.docs.as_slice()))
        .collect()
}

fn parts(m: &Member) -> Vec<(&str, ItemKind, &[String])> {
    match &m.kind {
        MemberKind::Struct { fields: fs, .. } | MemberKind::Object { fields: fs, .. } => {
            fields(fs, ItemKind::Field)
        }
        MemberKind::Error {
            fields: Some(fs), ..
        } => fields(fs, ItemKind::Field),
        MemberKind::Union { arms, .. } => arms
            .iter()
            .filter_map(|a| match a {
                Arm::Arm { name, docs, .. } => {
                    Some((name.name.as_str(), ItemKind::Arm, docs.as_slice()))
                }
                Arm::Reserved { .. } => None,
            })
            .collect(),
        MemberKind::Enum { values, .. } => values
            .iter()
            .filter_map(|v| match v {
                Value::Value { name, docs, .. } => {
                    Some((name.name.as_str(), ItemKind::Value, docs.as_slice()))
                }
                Value::Reserved { .. } => None,
            })
            .collect(),
        MemberKind::Method(me) => {
            let mut out = fields(&me.params, ItemKind::Param);
            if let Some(r) = &me.results {
                match &r.kind {
                    ResultsKind::Fields(fs) => out.extend(fields(fs, ItemKind::Result)),
                    // `-> T`'s one result is `result` in JSON (ADR 0067,
                    // rule 8), so a reference names it so.
                    ResultsKind::Single(_) => out.push(("result", ItemKind::Result, &[])),
                    ResultsKind::None => {}
                }
            }
            out
        }
        _ => Vec::new(),
    }
}

fn member_kind(m: &Member) -> Option<ItemKind> {
    Some(match &m.kind {
        MemberKind::Const { .. } => ItemKind::Const,
        MemberKind::Alias { .. } => ItemKind::Alias,
        MemberKind::Struct { .. } => ItemKind::Struct,
        MemberKind::Object { .. } => ItemKind::Object,
        MemberKind::Union { .. } => ItemKind::Union,
        MemberKind::Enum { flags: false, .. } => ItemKind::Enum,
        MemberKind::Enum { flags: true, .. } => ItemKind::Flags,
        MemberKind::Error { .. } => ItemKind::Error,
        MemberKind::Method(_) => ItemKind::Method,
        MemberKind::Reserved { .. } => return None,
    })
}

/// The doc model of a checked file's interface.
pub fn model(c: &crate::Checked) -> DocModel {
    let unit = c.unit();
    let iface = &unit.file.interface;
    let mut items = alloc::vec![Item {
        path: Vec::new(),
        kind: ItemKind::Interface,
        doc: parse(&iface.docs),
    }];
    for m in &iface.members {
        let (Some(name), Some(kind)) = (m.name(), member_kind(m)) else {
            continue;
        };
        items.push(Item {
            path: alloc::vec![name.name.clone()],
            kind,
            doc: parse(&m.docs),
        });
        for (p, kind, docs) in parts(m) {
            items.push(Item {
                path: alloc::vec![name.name.clone(), p.to_string()],
                kind,
                doc: parse(docs),
            });
        }
    }
    DocModel {
        interface: unit.name.clone(),
        major: unit.major(),
        file: parse(&unit.file.docs),
        items,
    }
}

// ---- The checker's rule -----------------------------------------------------

/// Whether a path names something in a unit: a member, then one of its
/// parts.
fn resolves(unit: &Unit, path: &[String]) -> bool {
    let Some(first) = path.first() else {
        return true;
    };
    let Some(m) = unit
        .members()
        .iter()
        .find(|m| m.name().is_some_and(|n| &n.name == first))
    else {
        return false;
    };
    match path.get(1) {
        None => true,
        Some(p) => parts(m).iter().any(|(n, ..)| n == p),
    }
}

/// The checker's rule for doc comments: every cross-reference into the
/// unit's own interface, or into an interface its `use` lines import, must
/// resolve. A reference into an import resolves against the minor its
/// `use` line names, which is the import the compiler holds.
pub fn check(model: &Model, u: usize) -> Vec<Diagnostic> {
    let unit = model.unit(u);
    let mut diags = Vec::new();
    let mut check_doc = |docs: &[String], span: Span| {
        if docs.is_empty() {
            return;
        }
        let doc = parse(docs);
        for x in xrefs(&doc) {
            let target = if x.interface == unit.name && x.major == unit.major() {
                Some(unit)
            } else {
                unit.uses
                    .iter()
                    .filter(|&&i| i != NO_UNIT)
                    .map(|&i| model.unit(i))
                    .find(|i| i.name == x.interface && i.major() == x.major)
            };
            if let Some(t) = target
                && !resolves(t, &x.path)
            {
                diags.push(Diagnostic::new(
                    span,
                    Code::Doc,
                    format!(
                        "the cross-reference [{x}] names nothing in {}/{}",
                        t.name,
                        t.major()
                    ),
                ));
            }
        }
    };
    let iface = &unit.file.interface;
    check_doc(&unit.file.docs, iface.span);
    check_doc(&iface.docs, iface.span);
    for m in &iface.members {
        check_doc(&m.docs, m.span);
        let fields: &[Field] = match &m.kind {
            MemberKind::Struct { fields, .. } | MemberKind::Object { fields, .. } => fields,
            MemberKind::Error {
                fields: Some(fields),
                ..
            } => fields,
            MemberKind::Method(me) => {
                for f in &me.params {
                    check_doc(&f.docs, f.span);
                }
                match me.results.as_ref().map(|r| &r.kind) {
                    Some(ResultsKind::Fields(fs)) => fs,
                    _ => &[],
                }
            }
            MemberKind::Union { arms, .. } => {
                for a in arms {
                    if let Arm::Arm { docs, span, .. } = a {
                        check_doc(docs, *span);
                    }
                }
                &[]
            }
            MemberKind::Enum { values, .. } => {
                for v in values {
                    if let Value::Value { docs, span, .. } = v {
                        check_doc(docs, *span);
                    }
                }
                &[]
            }
            _ => &[],
        };
        for f in fields {
            check_doc(&f.docs, f.span);
        }
    }
    diags
}
