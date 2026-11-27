// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! A minimal JSON reader for the vector files (RFC 8259), so the tests
//! need no dependency.
//!
//! It reads what the vector files hold: objects, arrays, strings with
//! escapes, integers, booleans and null. Numbers are kept as their text.
//! It panics on malformed input, which in a test is a failure. The file
//! names std's types in full, so `src/` can include it in its unit tests,
//! where the crate is `no_std`.

#![allow(dead_code)]

use std::{string::String, vec::Vec};

/// A JSON value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// A number, as written.
    Number(String),
    String(String),
    Array(Vec<Value>),
    /// An object's members, in order.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// The member `key` of an object. Panics if this isn't an object or
    /// the member is missing.
    pub fn get(&self, key: &str) -> &Value {
        self.try_get(key)
            .unwrap_or_else(|| panic!("no member {key:?}"))
    }

    /// The member `key` of an object, if it has one.
    pub fn try_get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => panic!("not an object, looking for {key:?}"),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Value::String(s) => s,
            v => panic!("not a string: {v:?}"),
        }
    }

    pub fn as_array(&self) -> &[Value] {
        match self {
            Value::Array(a) => a,
            v => panic!("not an array: {v:?}"),
        }
    }

    pub fn as_bool(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            v => panic!("not a boolean: {v:?}"),
        }
    }

    pub fn as_u64(&self) -> u64 {
        match self {
            Value::Number(n) => n.parse().unwrap_or_else(|_| panic!("not a u64: {n}")),
            v => panic!("not a number: {v:?}"),
        }
    }
}

/// Parses a whole document.
pub fn parse(text: &str) -> Value {
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
    };
    let v = p.value();
    p.ws();
    assert_eq!(p.i, p.s.len(), "trailing input at {}", p.i);
    v
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> u8 {
        *self
            .s
            .get(self.i)
            .unwrap_or_else(|| panic!("unexpected end"))
    }

    fn ws(&mut self) {
        while self.i < self.s.len() && matches!(self.s[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn expect(&mut self, lit: &[u8]) {
        assert!(
            self.s[self.i..].starts_with(lit),
            "expected {:?} at {}",
            core::str::from_utf8(lit).unwrap(),
            self.i
        );
        self.i += lit.len();
    }

    fn value(&mut self) -> Value {
        self.ws();
        match self.peek() {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Value::String(self.string()),
            b't' => {
                self.expect(b"true");
                Value::Bool(true)
            }
            b'f' => {
                self.expect(b"false");
                Value::Bool(false)
            }
            b'n' => {
                self.expect(b"null");
                Value::Null
            }
            b'-' | b'0'..=b'9' => self.number(),
            c => panic!("unexpected {:?} at {}", c as char, self.i),
        }
    }

    fn object(&mut self) -> Value {
        self.expect(b"{");
        let mut members = Vec::new();
        self.ws();
        if self.peek() == b'}' {
            self.i += 1;
            return Value::Object(members);
        }
        loop {
            self.ws();
            let k = self.string();
            self.ws();
            self.expect(b":");
            let v = self.value();
            members.push((k, v));
            self.ws();
            match self.peek() {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    return Value::Object(members);
                }
                c => panic!("unexpected {:?} in object at {}", c as char, self.i),
            }
        }
    }

    fn array(&mut self) -> Value {
        self.expect(b"[");
        let mut items = Vec::new();
        self.ws();
        if self.peek() == b']' {
            self.i += 1;
            return Value::Array(items);
        }
        loop {
            items.push(self.value());
            self.ws();
            match self.peek() {
                b',' => self.i += 1,
                b']' => {
                    self.i += 1;
                    return Value::Array(items);
                }
                c => panic!("unexpected {:?} in array at {}", c as char, self.i),
            }
        }
    }

    fn number(&mut self) -> Value {
        let start = self.i;
        while self.i < self.s.len()
            && matches!(
                self.s[self.i],
                b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'
            )
        {
            self.i += 1;
        }
        Value::Number(String::from(
            core::str::from_utf8(&self.s[start..self.i]).unwrap(),
        ))
    }

    fn hex4(&mut self) -> u32 {
        let h = core::str::from_utf8(&self.s[self.i..self.i + 4]).unwrap();
        self.i += 4;
        u32::from_str_radix(h, 16).unwrap_or_else(|_| panic!("bad \\u escape {h:?}"))
    }

    fn string(&mut self) -> String {
        self.expect(b"\"");
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.peek();
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek();
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let mut u = self.hex4();
                            if (0xD800..0xDC00).contains(&u) {
                                self.expect(b"\\u");
                                let lo = self.hex4();
                                assert!((0xDC00..0xE000).contains(&lo), "lone surrogate");
                                u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
                            }
                            char::from_u32(u).unwrap_or_else(|| panic!("bad \\u escape"))
                        }
                        _ => panic!("bad escape at {}", self.i),
                    };
                    let mut b = [0; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut b).as_bytes());
                }
                c if c < 0x20 => panic!("control character in string at {}", self.i),
                c => out.push(c),
            }
        }
        String::from_utf8(out).expect("UTF-8 string")
    }
}
