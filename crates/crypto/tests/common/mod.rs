// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Helpers shared by aspis-crypto's tests: hex and base64, and reading the
//! vector files in `tests/data/` (their sources are in
//! `tests/data/README.md`). `src/kat.rs` includes it too.

#![allow(dead_code)]

// std's names in full, so `src/kat.rs` can include this file in the
// crate's unit tests, where the crate is `no_std`.
use std::{format, string::String, vec::Vec};

pub mod json;

pub use json::Value;

/// Decodes lowercase or uppercase hex. Panics on anything else.
pub fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Encodes lowercase hex.
pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Decodes base64 (RFC 4648, section 4), with or without padding.
pub fn base64(s: &str) -> Vec<u8> {
    let val = |c: u8| -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("not base64: {:?}", c as char),
        }
    };
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= val(c) << (18 - 6 * i);
        }
        let n = match chunk.len() {
            4 => 3,
            3 => 2,
            2 => 1,
            _ => panic!("truncated base64"),
        };
        out.extend_from_slice(&acc.to_be_bytes()[1..1 + n]);
    }
    out
}

/// Parses a vector file's text.
pub fn vectors(text: &str) -> Value {
    json::parse(text)
}

/// The hex field `key` of a test object, decoded.
pub fn field(test: &Value, key: &str) -> Vec<u8> {
    hex(test.get(key).as_str())
}

/// `N` octets from the hex field `key`. Panics on another length.
pub fn array<const N: usize>(test: &Value, key: &str) -> [u8; N] {
    field(test, key)
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("{key}: {} octets, not {N}", v.len()))
}
