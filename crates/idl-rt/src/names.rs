// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Names and references (ADR 0063; docs/design/call-language.md, "The
//! names grammar").
//!
//! `grammars/names.abnf` is the definition. Only three of its forms are
//! ever parsed (ADR 0063, rule 10): an [`InterfaceRef`], an [`ActionRef`] and
//! an [`ErrorRef`]. Each parser takes the whole input, allocates nothing,
//! and returns borrowed parts. A parser accepts exactly what the grammar
//! accepts with its constraints; `tests/names.rs` checks that against the
//! grammar's vectors. Each accepted reference renders back to the same
//! octets with [`core::fmt::Display`].

use core::fmt;

/// The longest label and the longest member name, in octets.
pub const MAX_LABEL: usize = 63;
/// The longest interface or type name, in octets.
pub const MAX_NAME: usize = 255;
/// The longest action reference: a 255-octet name, "/", a five-digit
/// major, "/@" and a 63-octet member name.
pub const MAX_ACTION_REF: usize = 326;

/// Cedar's reserved words, which no label or member name may be (ADR 0063,
/// rule 1). Every name is then a Cedar path, with no escaping.
pub const CEDAR_RESERVED: [&str; 9] = [
    "true", "false", "if", "then", "else", "in", "is", "like", "has",
];
/// Words Rust can't take as raw identifiers, which no label or member name
/// may be (ADR 0063, rules 1 and 4): a label is a generated module's name.
pub const RUST_RESERVED: [&str; 3] = ["self", "super", "crate"];

/// Why a reference doesn't parse: the offset of the first octet that
/// doesn't fit, or of the part that breaks a constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    pub at: usize,
}

/// `interface-ref`: a name, a major and an optional minor, such as
/// `aspis.catalog/1.2`. A missing minor means `.0` (ADR 0063, rule 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceRef<'a> {
    pub name: &'a str,
    pub major: u16,
    pub minor: Option<u16>,
}

impl InterfaceRef<'_> {
    /// The minor, with a missing one read as 0.
    pub fn minor_or_zero(&self) -> u16 {
        self.minor.unwrap_or(0)
    }
}

impl fmt::Display for InterfaceRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.name, self.major)?;
        if let Some(m) = self.minor {
            write!(f, ".{m}")?;
        }
        Ok(())
    }
}

/// What an action reference names in its major.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionTarget<'a> {
    /// `action-name`: one method.
    Method(&'a str),
    /// `group-name`: an action group, written `@group`.
    Group(&'a str),
    /// `all-methods`: `*`, every method of the major.
    All,
}

/// `action-ref`, such as `aspis.catalog/1/watch`. Every one is also an RFC
/// 6749 scope-token (ADR 0063, rule 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionRef<'a> {
    pub interface: &'a str,
    pub major: u16,
    pub target: ActionTarget<'a>,
}

impl fmt::Display for ActionRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/", self.interface, self.major)?;
        match self.target {
            ActionTarget::Method(m) => f.write_str(m),
            ActionTarget::Group(g) => write!(f, "@{g}"),
            ActionTarget::All => f.write_str("*"),
        }
    }
}

/// `error-ref`: an error by name, or, when its name isn't known, by the
/// interface's ID and the code (ADR 0063, rule 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorRef<'a> {
    /// `aspis.catalog/1!stream_expired`.
    Named {
        interface: &'a str,
        major: u16,
        error: &'a str,
    },
    /// `<id-text>/1!#17`. The ID is in the interim text form, 64 lowercase
    /// hex digits, until D34 (L01).
    Code {
        interface_id: &'a str,
        major: u16,
        code: u16,
    },
}

impl fmt::Display for ErrorRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ErrorRef::Named {
                interface,
                major,
                error,
            } => write!(f, "{interface}/{major}!{error}"),
            ErrorRef::Code {
                interface_id,
                major,
                code,
            } => write!(f, "{interface_id}/{major}!#{code}"),
        }
    }
}

fn is_lc_alpha(b: u8) -> bool {
    b.is_ascii_lowercase()
}

fn is_lchar(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
}

/// `label`: `lc-alpha *lchar / "_" ( lc-alpha / DIGIT ) *lchar`, at most 63
/// octets, and neither a Cedar reserved word nor `self`, `super` or
/// `crate`.
pub fn is_label(s: &[u8]) -> bool {
    let shape = match s {
        [first, rest @ ..] if is_lc_alpha(*first) => rest.iter().all(|&b| is_lchar(b)),
        [b'_', second, rest @ ..] if is_lc_alpha(*second) || second.is_ascii_digit() => {
            rest.iter().all(|&b| is_lchar(b))
        }
        _ => false,
    };
    shape
        && s.len() <= MAX_LABEL
        && !CEDAR_RESERVED
            .iter()
            .chain(RUST_RESERVED.iter())
            .any(|w| w.as_bytes() == s)
}

/// `name`: two or more labels joined by ".", at most 255 octets.
pub fn is_name(s: &[u8]) -> bool {
    s.len() <= MAX_NAME
        && s.split(|&b| b == b'.').count() >= 2
        && s.split(|&b| b == b'.').all(is_label)
}

/// `member-name`: lower snake_case with no "__" and no trailing "_", at
/// most 63 octets, and neither a Cedar reserved word nor `self`, `super`
/// or `crate` (ADR 0063, rule 4).
pub fn is_member_name(s: &[u8]) -> bool {
    let Some((&first, _)) = s.split_first() else {
        return false;
    };
    let shape = is_lc_alpha(first)
        && s.iter().all(|&b| is_lchar(b))
        && !s.windows(2).any(|w| w == b"__")
        && s.last() != Some(&b'_');
    shape
        && s.len() <= MAX_LABEL
        && !CEDAR_RESERVED
            .iter()
            .chain(RUST_RESERVED.iter())
            .any(|w| w.as_bytes() == s)
}

/// `number`: `"0" / %x31-39 *4DIGIT`, at most 65535. Returns the value and
/// the octets it took, or None.
pub fn number(s: &[u8]) -> Option<(u16, usize)> {
    let digits = s.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 || digits > 5 || (digits > 1 && s[0] == b'0') {
        return None;
    }
    let v = s[..digits]
        .iter()
        .fold(0u32, |v, &b| v * 10 + u32::from(b - b'0'));
    u16::try_from(v).ok().map(|v| (v, digits))
}

/// `id-text`: 64 lowercase hex digits (interim, until D34).
pub fn is_id_text(s: &[u8]) -> bool {
    s.len() == 64
        && s.iter()
            .all(|&b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn text(s: &[u8]) -> Result<&str, ParseError> {
    core::str::from_utf8(s).map_err(|e| ParseError {
        at: e.valid_up_to(),
    })
}

/// The name before the first "/", and the major after it. Returns the
/// name, the major and the offset after the major.
fn name_and_major(s: &[u8]) -> Result<(&str, u16, usize), ParseError> {
    let slash = s
        .iter()
        .position(|&b| b == b'/')
        .ok_or(ParseError { at: s.len() })?;
    if !is_name(&s[..slash]) {
        return Err(ParseError { at: 0 });
    }
    let (major, n) = number(&s[slash + 1..]).ok_or(ParseError { at: slash + 1 })?;
    Ok((text(&s[..slash])?, major, slash + 1 + n))
}

/// Parses an `interface-ref`, such as `aspis.catalog/1.2`.
pub fn parse_interface_ref(s: &[u8]) -> Result<InterfaceRef<'_>, ParseError> {
    let (name, major, at) = name_and_major(s)?;
    let minor = match &s[at..] {
        [] => None,
        [b'.', rest @ ..] => match number(rest) {
            Some((m, n)) if n == rest.len() => Some(m),
            _ => return Err(ParseError { at: at + 1 }),
        },
        _ => return Err(ParseError { at }),
    };
    Ok(InterfaceRef { name, major, minor })
}

/// Parses an `action-ref`: `interface/major/method`, `interface/major/@group`
/// or `interface/major/*`.
pub fn parse_action_ref(s: &[u8]) -> Result<ActionRef<'_>, ParseError> {
    let (interface, major, at) = name_and_major(s)?;
    let target = match &s[at..] {
        [b'/', b'*'] => ActionTarget::All,
        [b'/', b'@', rest @ ..] if is_member_name(rest) => ActionTarget::Group(text(rest)?),
        [b'/', rest @ ..] if is_member_name(rest) => ActionTarget::Method(text(rest)?),
        _ => return Err(ParseError { at }),
    };
    Ok(ActionRef {
        interface,
        major,
        target,
    })
}

/// Parses an `error-ref`: `interface/major!error`, or `id/major!#code`
/// with a code from 1 to 65535.
pub fn parse_error_ref(s: &[u8]) -> Result<ErrorRef<'_>, ParseError> {
    let slash = s
        .iter()
        .position(|&b| b == b'/')
        .ok_or(ParseError { at: s.len() })?;
    if is_id_text(&s[..slash]) {
        let (major, n) = number(&s[slash + 1..]).ok_or(ParseError { at: slash + 1 })?;
        let at = slash + 1 + n;
        return match &s[at..] {
            [b'!', b'#', rest @ ..] => match number(rest) {
                Some((code, n)) if n == rest.len() && code != 0 => Ok(ErrorRef::Code {
                    interface_id: text(&s[..slash])?,
                    major,
                    code,
                }),
                _ => Err(ParseError { at: at + 2 }),
            },
            _ => Err(ParseError { at }),
        };
    }
    let (interface, major, at) = name_and_major(s)?;
    match &s[at..] {
        [b'!', rest @ ..] if is_member_name(rest) => Ok(ErrorRef::Named {
            interface,
            major,
            error: text(rest)?,
        }),
        _ => Err(ParseError { at }),
    }
}
