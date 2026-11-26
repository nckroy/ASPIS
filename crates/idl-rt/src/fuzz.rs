// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Entry functions for fuzz targets (ADR 0068, rules 4 and 5;
//! docs/design/call-language.md, "The gate for each target").
//!
//! C71's harness wraps each in a libFuzzer target; until then the crates'
//! replay tests run them over every vector and over mutations. Each takes
//! raw input, and panics only when a property breaks: that is the oracle.
//! They are plain functions, not behind `cfg(fuzzing)`, so the replay
//! tests run them under plain `cargo test`, and they need no fuzz
//! dependency.

use core::fmt::{self, Write as _};

use crate::{
    json::JsonWriter,
    names,
    rules::{Module, Op, Verdict},
};

/// The longest message [`decode`] takes. Longer input is ignored: one IPC
/// message is at most 960 octets, and the target's `max_len` is that plus
/// 1 KiB ("The gate for each target", item 1). RPC frames are C18's and
/// C29's targets.
pub const MAX_MESSAGE: usize = 16 << 10;

/// A message's JSON is at most this long. A control character takes six
/// octets in JSON, so 8 times the message is enough; the writer refuses
/// more rather than panicking anyway.
const MAX_JSON: usize = 8 * MAX_MESSAGE;

/// A generated module's decoders (ADR 0068, rule 4: "Every IDL-generated
/// decoder"). The first octet picks a rule, the second a minor (the
/// module's newest, or an earlier one), the third a capability count, 0 to
/// 3; the rest is the message.
///
/// Properties: the decoder never panics; a message it accepts re-encodes
/// to the same octets ("The gate for each target", item 2), and its JSON
/// renders. Agreement with the grammar is `idl::conformance::differential`.
pub fn decode(m: &Module, data: &[u8]) {
    let [r, minor, caps, input @ ..] = data else {
        return;
    };
    if m.rules.is_empty() || input.len() > MAX_MESSAGE {
        return;
    }
    let rule = m.rules[usize::from(*r) % m.rules.len()];
    let minor = (u32::from(*minor) % (u32::from(m.minor) + 1)) as u16;
    let caps = caps % 4;
    let mut out = [0u8; MAX_MESSAGE + 64];
    let verdict = (m.rule)(rule, minor, caps, input, Op::Encode(&mut out));
    match verdict {
        Verdict::Ok { len, .. } => assert!(
            out[..len] == *input,
            "{}/{} {rule} at minor {minor}: an accepted message re-encodes differently",
            m.name,
            m.major
        ),
        Verdict::Malformed | Verdict::FieldTooNew => return,
        Verdict::Encode(e) => panic!(
            "{}/{} {rule} at minor {minor}: an accepted message doesn't re-encode: {e:?}",
            m.name, m.major
        ),
        Verdict::NoRule => panic!(
            "{}/{}: RULES lists {rule}, which rule() lacks",
            m.name, m.major
        ),
    }
    let mut buf = [0u8; MAX_JSON];
    let mut j = JsonWriter::new(&mut buf);
    let again = (m.rule)(rule, minor, caps, input, Op::Json(&mut j));
    assert!(
        matches!(again, Verdict::Ok { .. }),
        "{}/{} {rule} at minor {minor}: decoded once, then {again:?}",
        m.name,
        m.major
    );
    let _ = j.finish();
}

/// A fixed buffer that `Display` writes into.
struct Buf {
    data: [u8; 1024],
    len: usize,
}

impl fmt::Write for Buf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        self.data
            .get_mut(self.len..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Renders a reference and checks it gives back the input.
fn renders_back(what: &str, r: &dyn fmt::Display, data: &[u8]) {
    let mut b = Buf {
        data: [0; 1024],
        len: 0,
    };
    assert!(
        write!(b, "{r}").is_ok(),
        "{what}: an accepted reference doesn't render into 1024 octets"
    );
    assert!(
        b.data[..b.len] == *data,
        "{what}: an accepted reference renders differently"
    );
}

/// The three reference parsers (ADR 0063, rule 10; "Trust-boundary
/// parsers"): `interface-ref`, `action-ref` and `error-ref`. A reference
/// any of them accepts renders back to the same octets. Agreement with
/// `grammars/names.abnf` is checked by idl-rt's `names` test against the
/// grammar's vectors and crates/abnf.
pub fn names(data: &[u8]) {
    if let Ok(r) = names::parse_interface_ref(data) {
        renders_back("interface-ref", &r, data);
    }
    if let Ok(r) = names::parse_action_ref(data) {
        renders_back("action-ref", &r, data);
    }
    if let Ok(r) = names::parse_error_ref(data) {
        renders_back("error-ref", &r, data);
    }
}
