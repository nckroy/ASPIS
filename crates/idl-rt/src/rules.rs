// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! A generated interface's codecs, by the rule names of its generated
//! grammars (docs/design/call-language.md, "Generated grammars"): what the
//! vector tests and the conformance runner drive.
//!
//! Each generated module has a `rule` function that decodes a message as
//! one rule, at one minor, and either re-encodes it or writes its JSON.
//! [`Module`] lists it with the interface's name, so a test can find the
//! module for a grammar file.

use crate::{
    json::JsonWriter,
    wire::{DecodeCx, DecodeError, EncodeError, Writer, decode_all},
};

/// What to do with a decoded message.
pub enum Op<'o, 'b> {
    /// Re-encode it into the buffer.
    Encode(&'o mut [u8]),
    /// Write its JSON.
    Json(&'o mut JsonWriter<'b>),
}

/// What a generated decoder made of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// It decoded. For [`Op::Encode`], `len` octets were written. In a
    /// strict read, `value_too_new` is the newest `since` minor of a known
    /// value newer than the minor: the message still matches the grammar.
    Ok {
        len: usize,
        value_too_new: Option<u16>,
    },
    Malformed,
    FieldTooNew,
    /// It decoded, and didn't re-encode.
    Encode(EncodeError),
    /// The module has no such rule.
    NoRule,
}

/// One generated interface module.
#[derive(Debug, Clone, Copy)]
pub struct Module {
    pub name: &'static str,
    pub major: u16,
    /// The newest minor the module knows.
    pub minor: u16,
    /// The rules [`Module::rule`] decodes, in the generated grammar's
    /// order.
    pub rules: &'static [&'static str],
    /// Decodes `input` as `rule` at a minor, with `caps` capabilities in
    /// the list, and applies the op.
    pub rule: fn(rule: &str, minor: u16, caps: u8, input: &[u8], op: Op<'_, '_>) -> Verdict,
}

/// The work of one rule: decode with `cx`, then encode or write JSON.
pub fn run<'a, T>(
    input: &'a [u8],
    mut cx: DecodeCx,
    op: Op<'_, '_>,
    decode: impl FnOnce(&mut crate::wire::Reader<'a>, &mut DecodeCx) -> Result<T, DecodeError>,
    encode: impl FnOnce(&T, &mut Writer<'_>) -> Result<(), EncodeError>,
    json: impl FnOnce(&T, &mut JsonWriter<'_>),
) -> Verdict {
    let v = match decode_all(input, &mut cx, decode) {
        Ok(v) => v,
        Err(DecodeError::Malformed) => return Verdict::Malformed,
        Err(DecodeError::FieldTooNew(_)) => return Verdict::FieldTooNew,
    };
    let value_too_new = cx.value_too_new();
    match op {
        Op::Encode(out) => {
            let mut w = Writer::new(out);
            match encode(&v, &mut w) {
                Ok(()) => Verdict::Ok {
                    len: w.len(),
                    value_too_new,
                },
                Err(e) => Verdict::Encode(e),
            }
        }
        Op::Json(j) => {
            json(&v, j);
            Verdict::Ok {
                len: j.len(),
                value_too_new,
            }
        }
    }
}
