// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The ABNF text parser: RFC 5234 section 4, and RFC 7405's `%s` and `%i`.
//! Section 4's `rulelist` is ambiguous (RFC 5234 erratum 3076), but the
//! ambiguity doesn't change which files parse, and this parser reads it
//! one way only.
//!
//! It reads one file into the shared node arena. Rule names stay names
//! here; [`crate::grammar`] resolves them once every file is read. The
//! parser recurses only on groups and options, and refuses nesting deeper
//! than [`Limits::nesting`], so no input can overflow its stack.

use alloc::{string::String, vec, vec::Vec};

use crate::{GrammarErrorKind as Kind, Limits};

/// An index into the node arena.
pub(crate) type NodeId = u32;

/// One element of a grammar. Single-element alternations and
/// concatenations are collapsed into their element.
#[derive(Debug, Clone)]
pub(crate) enum Node {
    Alt(Vec<NodeId>),
    Cat(Vec<NodeId>),
    /// `n*m element`. An option `[ ]` is `0*1`, marked `option`: it is
    /// never a constraint's target (docs/design/call-language.md, "How
    /// constraints bind").
    Rep {
        min: u32,
        max: Option<u32>,
        node: NodeId,
        option: bool,
    },
    /// A rule name as written: the lowercase key, the file and the line.
    /// Loading replaces it with [`Node::Ref`].
    Name {
        key: String,
        file: u16,
        line: u32,
    },
    Ref(u32),
    /// A char-val, or a num-val concatenation. `ci` is true for a
    /// case-insensitive char-val, whose ASCII letters match either case.
    Lit {
        octets: Vec<u8>,
        ci: bool,
    },
    /// A num-val range, or one value.
    Range(u8, u8),
    /// A prose-val, `<...>`, whose text isn't a rule name. It matches
    /// nothing, as in abnf 2.9.1. A prose-val that is exactly a rule name,
    /// such as `<b>`, is read as that name ([`Node::Name`]).
    Prose,
}

/// A comment: its line, whether it starts at column 0, and its text from
/// the `;` to the end of the line.
#[derive(Debug, Clone)]
pub(crate) struct Comment {
    pub line: usize,
    pub column0: bool,
    pub text: String,
}

/// One rule as written: `name = ...` or `name =/ ...`.
#[derive(Debug)]
pub(crate) struct ParsedRule {
    pub name: String,
    pub line: usize,
    pub incremental: bool,
    pub body: NodeId,
    /// Every comment inside the rule's text: its own lines and their
    /// indented continuation lines. Constraints bind to the rule by these.
    pub comments: Vec<Comment>,
}

/// One file as written.
#[derive(Debug, Default)]
pub(crate) struct ParsedFile {
    pub rules: Vec<ParsedRule>,
    /// Comments outside every rule, with whether each came before the
    /// first rule (where `; uses:` lines go).
    pub loose: Vec<(Comment, bool)>,
    /// The lines of prose-vals, which a strict grammar may not hold.
    pub prose_vals: Vec<usize>,
}

/// A parse failure: the line and what went wrong.
pub(crate) type Error = (usize, Kind);

/// Parses `text` as one file, appending its nodes to `nodes`.
pub(crate) fn parse(
    text: &[u8],
    file: u16,
    nodes: &mut Vec<Node>,
    limits: &Limits,
) -> Result<ParsedFile, Error> {
    let src = normalize(text)?;
    let mut p = Parser {
        src: &src,
        pos: 0,
        line: 1,
        line_start: 0,
        comments: Vec::new(),
        nodes,
        limits,
        file,
        nesting: 0,
        prose_vals: Vec::new(),
    };
    p.rulelist()
}

/// Checks the octets (ASCII text: printable characters, tab and LF, and a
/// CR only before LF), turns CRLF into LF, and ends the text with LF.
fn normalize(text: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(text.len() + 1);
    let mut line = 1;
    let mut i = 0;
    while let Some(&b) = text.get(i) {
        match b {
            b'\r' if text.get(i + 1) == Some(&b'\n') => {}
            b'\n' => {
                line += 1;
                out.push(b);
            }
            b'\t' | 0x20..=0x7E => out.push(b),
            _ => return Err((line, Kind::NotAscii)),
        }
        i += 1;
    }
    if out.last().is_some_and(|&b| b != b'\n') {
        out.push(b'\n');
    }
    Ok(out)
}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
    line: usize,
    line_start: usize,
    /// Comments read since the last rule or loose line, in order.
    comments: Vec<Comment>,
    nodes: &'a mut Vec<Node>,
    limits: &'a Limits,
    file: u16,
    /// Groups and options open around the current element.
    nesting: usize,
    /// The lines of the prose-vals read so far.
    prose_vals: Vec<usize>,
}

/// A position to return to after a failed look-ahead.
#[derive(Clone, Copy)]
struct Mark {
    pos: usize,
    line: usize,
    line_start: usize,
    comments: usize,
}

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn peek_at(&self, ahead: usize) -> Option<u8> {
        self.src.get(self.pos + ahead).copied()
    }

    fn mark(&self) -> Mark {
        Mark {
            pos: self.pos,
            line: self.line,
            line_start: self.line_start,
            comments: self.comments.len(),
        }
    }

    fn reset(&mut self, m: Mark) {
        self.pos = m.pos;
        self.line = m.line;
        self.line_start = m.line_start;
        self.comments.truncate(m.comments);
    }

    fn err<T>(&self, kind: Kind) -> Result<T, Error> {
        Err((self.line, kind))
    }

    fn push(&mut self, node: Node) -> Result<NodeId, Error> {
        if self.nodes.len() >= self.limits.nodes {
            return self.err(Kind::TooLarge);
        }
        let id = NodeId::try_from(self.nodes.len()).map_err(|_| (self.line, Kind::TooLarge))?;
        self.nodes.push(node);
        Ok(id)
    }

    /// `c-nl = comment / CRLF`, with CRLF already read as LF.
    fn c_nl(&mut self) -> bool {
        match self.peek() {
            Some(b';') => {
                let start = self.pos;
                while self.peek().is_some_and(|b| b != b'\n') {
                    self.pos += 1;
                }
                // The text is ASCII, checked by `normalize`.
                let text = self.src[start..self.pos]
                    .iter()
                    .map(|&b| b as char)
                    .collect();
                self.comments.push(Comment {
                    line: self.line,
                    column0: start == self.line_start,
                    text,
                });
                self.newline();
                true
            }
            Some(b'\n') => {
                self.newline();
                true
            }
            _ => false,
        }
    }

    fn newline(&mut self) {
        // Called at an LF, which `normalize` guarantees ends every line.
        self.pos += 1;
        self.line += 1;
        self.line_start = self.pos;
    }

    /// `c-wsp = WSP / (c-nl WSP)`.
    fn c_wsp(&mut self) -> bool {
        if self.peek().is_some_and(is_wsp) {
            self.pos += 1;
            return true;
        }
        let m = self.mark();
        if self.c_nl() && self.peek().is_some_and(is_wsp) {
            self.pos += 1;
            return true;
        }
        self.reset(m);
        false
    }

    fn skip_c_wsp(&mut self) -> usize {
        let mut n = 0;
        while self.c_wsp() {
            n += 1;
        }
        n
    }

    /// `rulelist = 1*( rule / (*c-wsp c-nl) )`. An empty file is accepted,
    /// as abnf 2.9.1 accepts it.
    fn rulelist(&mut self) -> Result<ParsedFile, Error> {
        let mut out = ParsedFile::default();
        while self.pos < self.src.len() {
            if self.peek().is_some_and(|b| b.is_ascii_alphabetic()) {
                let rule = self.rule()?;
                out.rules.push(rule);
            } else {
                self.skip_c_wsp();
                if !self.c_nl() {
                    return self.err(Kind::Syntax);
                }
                let before_first = out.rules.is_empty();
                out.loose
                    .extend(self.comments.drain(..).map(|c| (c, before_first)));
            }
        }
        out.prose_vals = core::mem::take(&mut self.prose_vals);
        Ok(out)
    }

    /// `rule = rulename defined-as elements c-nl`.
    fn rule(&mut self) -> Result<ParsedRule, Error> {
        let line = self.line;
        let name = self.rulename();
        self.skip_c_wsp();
        let incremental = match (self.peek(), self.peek_at(1)) {
            (Some(b'='), Some(b'/')) => {
                self.pos += 2;
                true
            }
            (Some(b'='), _) => {
                self.pos += 1;
                false
            }
            _ => return self.err(Kind::Syntax),
        };
        self.skip_c_wsp();
        let body = self.alternation()?;
        self.skip_c_wsp();
        if !self.c_nl() {
            return self.err(Kind::Syntax);
        }
        Ok(ParsedRule {
            name,
            line,
            incremental,
            body,
            comments: core::mem::take(&mut self.comments),
        })
    }

    /// `rulename = ALPHA *(ALPHA / DIGIT / "-")`. The caller has seen ALPHA.
    fn rulename(&mut self) -> String {
        let start = self.pos;
        while self
            .peek()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            self.pos += 1;
        }
        self.src[start..self.pos]
            .iter()
            .map(|&b| b as char)
            .collect()
    }

    /// `alternation = concatenation *(*c-wsp "/" *c-wsp concatenation)`.
    fn alternation(&mut self) -> Result<NodeId, Error> {
        let mut alts = vec![self.concatenation()?];
        loop {
            let m = self.mark();
            self.skip_c_wsp();
            if self.peek() != Some(b'/') {
                self.reset(m);
                break;
            }
            self.pos += 1;
            self.skip_c_wsp();
            alts.push(self.concatenation()?);
        }
        if alts.len() == 1 {
            return Ok(alts[0]);
        }
        self.push(Node::Alt(alts))
    }

    /// `concatenation = repetition *(1*c-wsp repetition)`.
    fn concatenation(&mut self) -> Result<NodeId, Error> {
        let mut items = vec![self.repetition()?];
        loop {
            let m = self.mark();
            if self.skip_c_wsp() == 0 || !self.starts_element() {
                self.reset(m);
                break;
            }
            items.push(self.repetition()?);
        }
        if items.len() == 1 {
            return Ok(items[0]);
        }
        self.push(Node::Cat(items))
    }

    fn starts_element(&self) -> bool {
        self.peek().is_some_and(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'*' | b'(' | b'[' | b'"' | b'%' | b'<')
        })
    }

    /// A decimal repeat count, as a u32.
    fn count(&mut self) -> Result<Option<u32>, Error> {
        let start = self.pos;
        let mut n: u32 = 0;
        while let Some(d @ b'0'..=b'9') = self.peek() {
            n = n
                .checked_mul(10)
                .and_then(|n| n.checked_add(u32::from(d - b'0')))
                .ok_or((self.line, Kind::RepeatRange))?;
            self.pos += 1;
        }
        Ok((self.pos > start).then_some(n))
    }

    /// `repetition = [repeat] element`, where `repeat = 1*DIGIT /
    /// (*DIGIT "*" *DIGIT)`.
    fn repetition(&mut self) -> Result<NodeId, Error> {
        let lo = self.count()?;
        let repeat = if self.peek() == Some(b'*') {
            self.pos += 1;
            let hi = self.count()?;
            Some((lo.unwrap_or(0), hi))
        } else {
            lo.map(|n| (n, Some(n)))
        };
        let element = self.element()?;
        match repeat {
            None => Ok(element),
            Some((min, max)) => {
                if max.is_some_and(|max| min > max) {
                    return self.err(Kind::RepeatRange);
                }
                self.push(Node::Rep {
                    min,
                    max,
                    node: element,
                    option: false,
                })
            }
        }
    }

    /// `element = rulename / group / option / char-val / num-val /
    /// prose-val`.
    fn element(&mut self) -> Result<NodeId, Error> {
        match self.peek() {
            Some(b) if b.is_ascii_alphabetic() => {
                let line = u32::try_from(self.line).map_err(|_| (self.line, Kind::TooLarge))?;
                let key = self.rulename().to_ascii_lowercase();
                self.push(Node::Name {
                    key,
                    file: self.file,
                    line,
                })
            }
            Some(open @ (b'(' | b'[')) => self.group(open),
            Some(b'"') => self.char_val(true),
            Some(b'%') => match self.peek_at(1) {
                Some(b's' | b'S') if self.peek_at(2) == Some(b'"') => {
                    self.pos += 2;
                    self.char_val(false)
                }
                Some(b'i' | b'I') if self.peek_at(2) == Some(b'"') => {
                    self.pos += 2;
                    self.char_val(true)
                }
                _ => self.num_val(),
            },
            Some(b'<') => self.prose_val(),
            _ => self.err(Kind::Syntax),
        }
    }

    /// `group = "(" *c-wsp alternation *c-wsp ")"`, and `option`, the same
    /// with `[` and `]`.
    fn group(&mut self, open: u8) -> Result<NodeId, Error> {
        if self.nesting >= self.limits.nesting {
            return self.err(Kind::TooDeep);
        }
        self.nesting += 1;
        self.pos += 1;
        self.skip_c_wsp();
        let inner = self.alternation()?;
        self.skip_c_wsp();
        let close = if open == b'(' { b')' } else { b']' };
        if self.peek() != Some(close) {
            return self.err(Kind::Syntax);
        }
        self.pos += 1;
        self.nesting -= 1;
        if open == b'(' {
            return Ok(inner);
        }
        self.push(Node::Rep {
            min: 0,
            max: Some(1),
            node: inner,
            option: true,
        })
    }

    /// `char-val = DQUOTE *(%x20-21 / %x23-7E) DQUOTE`. `""` matches the
    /// empty string.
    fn char_val(&mut self, ci: bool) -> Result<NodeId, Error> {
        self.pos += 1;
        let start = self.pos;
        loop {
            match self.peek() {
                Some(b'"') => break,
                Some(0x20..=0x21 | 0x23..=0x7E) => self.pos += 1,
                _ => return self.err(Kind::Syntax),
            }
        }
        let octets = self.src[start..self.pos].to_vec();
        self.pos += 1;
        // Only ASCII letters have a case.
        let ci = ci && octets.iter().any(u8::is_ascii_alphabetic);
        self.push(Node::Lit { octets, ci })
    }

    /// One num-val digit string in `base`, as an octet (ADR 0062, rule 1).
    fn value(&mut self, base: u32) -> Result<u8, Error> {
        let start = self.pos;
        let mut n: u32 = 0;
        let mut too_big = false;
        while let Some(d) = self.peek().and_then(|b| (b as char).to_digit(base)) {
            match n.checked_mul(base).and_then(|n| n.checked_add(d)) {
                Some(v) => n = v,
                None => too_big = true,
            }
            self.pos += 1;
        }
        if self.pos == start {
            return self.err(Kind::Syntax);
        }
        if too_big {
            return self.err(Kind::OctetValue);
        }
        u8::try_from(n).map_err(|_| (self.line, Kind::OctetValue))
    }

    /// `num-val = "%" (bin-val / dec-val / hex-val)`, each a value, a
    /// `.`-separated concatenation, or a `-` range.
    fn num_val(&mut self) -> Result<NodeId, Error> {
        let base = match self.peek_at(1) {
            Some(b'b' | b'B') => 2,
            Some(b'd' | b'D') => 10,
            Some(b'x' | b'X') => 16,
            _ => return self.err(Kind::Syntax),
        };
        self.pos += 2;
        let first = self.value(base)?;
        match self.peek() {
            Some(b'-') => {
                self.pos += 1;
                let last = self.value(base)?;
                if first > last {
                    return self.err(Kind::EmptyRange);
                }
                self.push(Node::Range(first, last))
            }
            Some(b'.') => {
                let mut octets = vec![first];
                while self.peek() == Some(b'.') {
                    self.pos += 1;
                    octets.push(self.value(base)?);
                }
                self.push(Node::Lit { octets, ci: false })
            }
            _ => self.push(Node::Range(first, first)),
        }
    }

    /// `prose-val = "<" *(%x20-3D / %x3F-7E) ">"`. Text that is exactly a
    /// rulename, such as `<b>`, names that rule: RFC 5234 section 2.1 lets
    /// angle brackets enclose a rule name, and abnf 2.9.1 reads it so.
    /// Either kind is a prose-val, which a strict grammar may not hold.
    fn prose_val(&mut self) -> Result<NodeId, Error> {
        self.prose_vals.push(self.line);
        self.pos += 1;
        let start = self.pos;
        loop {
            match self.peek() {
                Some(b'>') => break,
                Some(0x20..=0x3D | 0x3F..=0x7E) => self.pos += 1,
                _ => return self.err(Kind::Syntax),
            }
        }
        let text: String = self.src[start..self.pos]
            .iter()
            .map(|&b| b as char)
            .collect();
        self.pos += 1;
        if crate::constraint::is_rulename(&text) {
            let line = u32::try_from(self.line).map_err(|_| (self.line, Kind::TooLarge))?;
            return self.push(Node::Name {
                key: text.to_ascii_lowercase(),
                file: self.file,
                line,
            });
        }
        self.push(Node::Prose)
    }
}
