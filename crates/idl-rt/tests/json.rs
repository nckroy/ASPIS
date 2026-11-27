// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The JSON writer (ADR 0067, rule 8; docs/design/call-language.md, "The
//! JSON mapping"): escapes, the float layout, 64-bit integers, base64url,
//! UUIDs, embedded JSON, and what it writes against `grammars/json.abnf`.

use std::{fs, path::Path};

use abnf::{Grammar, LoadOptions};
use idl_rt::json::{JsonWriter, Overflow};

fn write(f: impl FnOnce(&mut JsonWriter<'_>)) -> String {
    let mut buf = [0u8; 4096];
    let mut w = JsonWriter::new(&mut buf);
    f(&mut w);
    String::from_utf8(w.finish().unwrap().to_vec()).unwrap()
}

fn grammar() -> Grammar {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../grammars");
    let text = fs::read(dir.join("json.abnf")).unwrap();
    let mut resolve = |n: &str| fs::read(dir.join(format!("{n}.abnf"))).ok();
    Grammar::load("json", &text, &mut resolve, &LoadOptions::default()).unwrap()
}

fn matches(g: &Grammar, rule: &str, text: &str) -> bool {
    g.matches_constrained(g.rule(rule).unwrap(), text.as_bytes(), &Default::default())
        .unwrap()
}

#[test]
fn strings_escape_as_rfc_8785() {
    let g = grammar();
    for (input, want) in [
        ("plain", r#""plain""#),
        ("a\"b\\c", r#""a\"b\\c""#),
        ("\u{8}\u{c}\n\r\t", r#""\b\f\n\r\t""#),
        ("\u{1}\u{1f}\u{b}", r#""\u0001\u001f\u000b""#),
        ("/é😀\u{7f}", "\"/é😀\u{7f}\""),
    ] {
        let got = write(|w| w.string(input));
        assert_eq!(got, want, "{input:?}");
        assert!(matches(&g, "json-string", &got), "{got}");
    }
}

#[test]
fn floats_lay_out_as_ecmascript() {
    let g = grammar();
    let f64_cases: &[(f64, &str)] = &[
        (0.0, "0"),
        (-0.0, "-0"),
        (1.5, "1.5"),
        (0.1, "0.1"),
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        // ECMAScript switches to exponent form above 21 digits.
        (123e18, "123000000000000000000"),
        (123e20, "1.23e+22"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (1.25e-7, "1.25e-7"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (-2.5e30, "-2.5e+30"),
        (f64::NAN, "\"NaN\""),
        (f64::INFINITY, "\"Infinity\""),
        (f64::NEG_INFINITY, "\"-Infinity\""),
    ];
    for &(v, want) in f64_cases {
        let got = write(|w| w.f64(v));
        assert_eq!(got, want, "{v:e}");
        assert!(matches(&g, "json-float", &got), "{got}");
    }
    for &(v, want) in &[
        (0.1f32, "0.1"),
        (16777216f32, "16777216"),
        (-0.0f32, "-0"),
        (3.4028235e38f32, "3.4028235e+38"),
        (1e-45f32, "1e-45"),
    ] {
        let got = write(|w| w.f32(v));
        assert_eq!(got, want);
        assert!(matches(&g, "json-float", &got), "{got}");
    }
}

#[test]
fn integers_bytes_ids_and_caps() {
    let g = grammar();
    assert_eq!(
        write(|w| w.u64_string(u64::MAX)),
        "\"18446744073709551615\""
    );
    assert_eq!(
        write(|w| w.i64_string(i64::MIN)),
        "\"-9223372036854775808\""
    );
    assert_eq!(write(|w| w.int(-128)), "-128");
    assert_eq!(write(|w| w.uint(0)), "0");
    assert!(matches(&g, "json-u64", &write(|w| w.u64_string(7))));
    assert!(matches(&g, "json-i64", &write(|w| w.i64_string(-7))));
    for (data, want) in [
        (&b""[..], "\"\""),
        (b"\x00", "\"AA\""),
        (b"\xff", "\"_w\""),
        (b"\x00\x01", "\"AAE\""),
        (b"\x00\x01\x02", "\"AAEC\""),
        (b"\xfb\xff\xbf", "\"-_-_\""),
    ] {
        let got = write(|w| w.bytes(data));
        assert_eq!(got, want);
        assert!(matches(&g, "json-bytes", &got), "{got}");
    }
    let uuid = [
        0xf8, 0x1d, 0x4f, 0xae, 0x7d, 0xec, 0x11, 0xd0, 0xa7, 0x65, 0x00, 0xa0, 0xc9, 0x1e, 0x6b,
        0xf6,
    ];
    let got = write(|w| w.uuid(&uuid));
    assert_eq!(got, "\"f81d4fae-7dec-11d0-a765-00a0c91e6bf6\"");
    assert!(matches(&g, "json-uuid", &got));
    let got = write(|w| w.id(&[0xab; 32]));
    assert!(matches(&g, "json-id", &got));
    assert_eq!(write(|w| w.cap(2)), r#"{"cap":2}"#);
}

#[test]
fn objects_and_arrays_place_commas() {
    let got = write(|w| {
        w.begin_object();
        w.key("a");
        w.uint(1);
        w.key("b");
        w.begin_array();
        w.null();
        w.bool(true);
        w.begin_object();
        w.end_object();
        w.end_array();
        w.tag_key(7);
        w.bytes(b"x");
        w.end_object();
    });
    assert_eq!(got, r#"{"a":1,"b":[null,true,{}],"@7":"eA"}"#);
    assert!(matches(&grammar(), "json-value", &got));
}

#[test]
fn embedded_json_is_checked() {
    let g = grammar();
    for (input, want) in [
        // Valid I-JSON: re-written compact, tokens unchanged.
        (
            r#" { "a" : [1, 2.50, "x y"], "b": null } "#,
            r#"{"a":[1,2.50,"x y"],"b":null}"#,
        ),
        ("\"\\u00e9\"", "\"\\u00e9\""),
        ("1E5", "1E5"),
        // Duplicate names, compared after unescaping: a string instead.
        (r#"{"a":1,"\u0061":2}"#, r#""{\"a\":1,\"\\u0061\":2}""#),
        // An unpaired surrogate: a string.
        (r#""\ud800""#, r#""\"\\ud800\"""#),
        // A noncharacter, escaped or as a pair of surrogate escapes: a
        // string, since I-JSON forbids it (RFC 7493, §2.1).
        (r#""\ufdd0""#, r#""\"\\ufdd0\"""#),
        (r#"{"a":"\uFFFF"}"#, r#""{\"a\":\"\\uFFFF\"}""#),
        (r#"["\udbff\udfff"]"#, r#""[\"\\udbff\\udfff\"]""#),
        // U+FFFD and U+10FFFD, beside them, embed.
        (r#""\ufffd\udbff\udffd""#, r#""\ufffd\udbff\udffd""#),
        // Not JSON at all.
        ("{a:1}", r#""{a:1}""#),
        ("[1,]", r#""[1,]""#),
        ("", r#""""#),
        // A bare null would read as redacted: a string. Nested, it embeds.
        ("null", r#""null""#),
        (" null ", r#"" null ""#),
        ("[null]", "[null]"),
    ] {
        let got = write(|w| w.embedded(input));
        assert_eq!(got, want, "{input}");
        assert!(matches(&g, "json-value", &got), "{got}");
    }
    // 64 members embed; 65 don't.
    let members = |n: usize| {
        let m: Vec<String> = (0..n).map(|i| format!("\"k{i}\":{i}")).collect();
        format!("{{{}}}", m.join(","))
    };
    assert_eq!(write(|w| w.embedded(&members(64))), members(64));
    assert!(write(|w| w.embedded(&members(65))).starts_with('"'));
    // 32 levels embed; 33 don't.
    let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    assert_eq!(write(|w| w.embedded(&deep(32))), deep(32));
    assert!(write(|w| w.embedded(&deep(33))).starts_with('"'));
}

/// The writer's output is I-JSON: a noncharacter, which no wire string
/// holds, is written as U+FFFD (RFC 7493, §2.1).
#[test]
fn strings_never_hold_a_noncharacter() {
    let g = grammar();
    for c in [
        '\u{FDD0}',
        '\u{FDEF}',
        '\u{FFFE}',
        '\u{FFFF}',
        '\u{1FFFE}',
        '\u{10FFFF}',
    ] {
        let got = write(|w| w.string(&format!("a{c}b")));
        assert_eq!(got, "\"a\u{FFFD}b\"", "{c:?}");
        assert!(matches(&g, "json-string", &got));
        assert!(!matches(&g, "json-string", &format!("\"a{c}b\"")), "{c:?}");
        // As embedded text, it is a string too.
        let got = write(|w| w.embedded(&format!("\"{c}\"")));
        assert_eq!(got, "\"\\\"\u{FFFD}\\\"\"", "{c:?}");
    }
    let got = write(|w| w.string("\u{FDCF}\u{FFFD}\u{10FFFD}"));
    assert_eq!(got, "\"\u{FDCF}\u{FFFD}\u{10FFFD}\"");
    assert!(matches(&g, "json-string", &got));
}

#[test]
fn overflow_is_reported() {
    let mut buf = [0u8; 4];
    let mut w = JsonWriter::new(&mut buf);
    w.string("too long");
    assert_eq!(w.finish(), Err(Overflow));
}

/// Checking an embedded value takes time linear in its length, however
/// many members its objects hold (ADR 0068: a parser of peer input).
#[test]
fn embedded_json_is_checked_in_linear_time() {
    // One object of many keys (about 4 MiB), and many objects of 64 keys
    // each, keys differing only in their last character.
    let wide = {
        let m: Vec<String> = (0..300_000).map(|i| format!("\"k{i}\":{i}")).collect();
        format!("{{{}}}", m.join(","))
    };
    let many = {
        let key = "k".repeat(50);
        let obj = |j: usize| {
            let m: Vec<String> = (0..64).map(|i| format!("\"{key}{i:02}\":{j}")).collect();
            format!("{{{}}}", m.join(","))
        };
        let objs: Vec<String> = (0..200).map(obj).collect();
        format!("[{}]", objs.join(","))
    };
    for text in [wide, many] {
        let mut buf = vec![0u8; 2 * text.len() + 16];
        let start = std::time::Instant::now();
        let mut w = JsonWriter::new(&mut buf);
        w.embedded(&text);
        w.finish().unwrap();
        let took = start.elapsed();
        assert!(
            took < std::time::Duration::from_secs(2),
            "{} octets took {took:?}",
            text.len()
        );
    }
}
