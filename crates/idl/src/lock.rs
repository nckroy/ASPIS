// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The lock file beside an IDL file, `v<M>.idl.lock`: the SHA3-256 hash of
//! each published minor's canonical form (ADR 0067, rule 7;
//! docs/design/call-language.md, "The lock and the canonical form").
//! `grammars/idl-lock.abnf` is its grammar.
//!
//! - The entries are the minors 0 to p, in order, one each. A lock with no
//!   entries means nothing is published. A lock has at most 1,024 entries,
//!   since a major has at most that many minors ([`crate::MAX_MINOR`]).
//! - The file's version v is p (every minor published) or p + 1 (one minor
//!   in development). Anything else fails.
//! - Publishing a minor appends its hash; an entry is never rewritten.
//!   Changing a published hash is a hand edit, visible in review.

use alloc::{format, string::String, vec::Vec};

/// A parsed lock: the published minors' hashes, minor 0 first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lock {
    pub hashes: Vec<[u8; 32]>,
}

impl Lock {
    /// The newest published minor, or None when nothing is published.
    pub fn published(&self) -> Option<u16> {
        self.hashes
            .len()
            .checked_sub(1)
            .and_then(|p| u16::try_from(p).ok())
    }

    /// Whether `version`'s minor may be the file's version: p or p + 1.
    pub fn allows(&self, minor: u16) -> bool {
        usize::from(minor) == self.hashes.len() || usize::from(minor) + 1 == self.hashes.len()
    }
}

/// Reads a lock of major `major`. Errors carry the 1-based line.
pub fn parse(text: &[u8], major: u16) -> Result<Lock, (usize, String)> {
    let text = core::str::from_utf8(text).map_err(|_| (0, String::from("not UTF-8")))?;
    if !text.is_empty() && !text.ends_with('\n') {
        return Err((text.lines().count(), "no line feed at the end".into()));
    }
    let mut lock = Lock::default();
    // Split at LF only, so a CR stays in its line and is refused.
    for (n, line) in text
        .split_terminator('\n')
        .enumerate()
        .map(|(i, l)| (i + 1, l))
    {
        if line.contains('\r') {
            return Err((n, "a CR".into()));
        }
        if let Some(comment) = line.strip_prefix('#') {
            if !lock.hashes.is_empty() {
                return Err((n, "a comment after an entry".into()));
            }
            // `lock-char`: a tab, printable ASCII, or any other UTF-8
            // character, C1 controls included.
            if comment
                .chars()
                .any(|c| (c < ' ' && c != '\t') || c == '\x7f')
            {
                return Err((n, "a control character in a comment".into()));
            }
            continue;
        }
        let mut words = line.split(' ');
        let (Some(version), Some("sha3-256"), Some(hex), None) =
            (words.next(), words.next(), words.next(), words.next())
        else {
            return Err((
                n,
                "expected 'M.m sha3-256 <64 lowercase hex digits>'".into(),
            ));
        };
        if lock.hashes.len() > usize::from(crate::MAX_MINOR) {
            return Err((
                n,
                format!(
                    "more than {} entries: a major has at most {} minors, 0 to {}",
                    usize::from(crate::MAX_MINOR) + 1,
                    usize::from(crate::MAX_MINOR) + 1,
                    crate::MAX_MINOR
                ),
            ));
        }
        let expected = format!("{major}.{}", lock.hashes.len());
        if version != expected {
            return Err((
                n,
                format!(
                    "expected minor {expected}: the entries are minors 0, 1, 2 and on, in order"
                ),
            ));
        }
        lock.hashes
            .push(from_hex(hex).ok_or((n, String::from("a hash is 64 lowercase hex digits")))?);
    }
    Ok(lock)
}

fn from_hex(h: &str) -> Option<[u8; 32]> {
    let b = h.as_bytes();
    if b.len() != 64 || !b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks(2).enumerate() {
        let d = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
        out[i] = d(pair[0]) << 4 | d(pair[1]);
    }
    Some(out)
}

/// Lowercase hex.
pub fn hex(h: &[u8]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes a lock: the IDL file's SPDX lines, a title, then the entries.
pub fn render(spdx: &[String], name: &str, major: u16, lock: &Lock) -> String {
    let mut out = String::new();
    for l in spdx {
        out.push_str("# ");
        out.push_str(l);
        out.push('\n');
    }
    out.push_str(&format!(
        "# {name}/{major}: SHA3-256 of each published minor's canonical form (ADR 0067, rule 7).\n"
    ));
    for (m, h) in lock.hashes.iter().enumerate() {
        out.push_str(&format!("{major}.{m} sha3-256 {}\n", hex(h)));
    }
    out
}
