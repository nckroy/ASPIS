// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Runs the parser over `grammars/kernel-args.vectors`: it must accept every
//! "ok" line whole and reject every "err" line.

use std::path::Path;

/// Decodes a vector's command line: `\t`, `\\`, `\"` and `\xHH`.
fn decode(text: &str, lineno: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match bytes.next() {
            Some(b't') => out.push(b'\t'),
            Some(b'\\') => out.push(b'\\'),
            Some(b'"') => out.push(b'"'),
            Some(b'x') => {
                let hex = [bytes.next(), bytes.next()];
                let [Some(h), Some(l)] = hex else {
                    panic!("line {lineno}: short \\x escape");
                };
                let pair = [h, l];
                let s = std::str::from_utf8(&pair).expect("hex digits");
                out.push(
                    u8::from_str_radix(s, 16)
                        .unwrap_or_else(|_| panic!("line {lineno}: bad \\x escape {s:?}")),
                );
            }
            other => panic!("line {lineno}: bad escape {other:?}"),
        }
    }
    out
}

#[test]
fn vectors() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../grammars/kernel-args.vectors");
    let file = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let (mut oks, mut errs) = (0, 0);
    let mut failures = Vec::new();
    for (i, raw) in file.lines().enumerate() {
        let lineno = i + 1;
        if raw.is_empty() || raw.starts_with('#') {
            continue;
        }
        let (expect_ok, text) = match raw.split_once('\t') {
            Some(("ok", t)) => (true, t),
            Some(("err", t)) => (false, t),
            _ => panic!("line {lineno}: not \"ok<TAB>\" or \"err<TAB>\""),
        };
        let line = decode(text, lineno);
        let results: Vec<_> = kargs::parse(&line).collect();
        let errors = results.iter().filter(|r| r.is_err()).count();
        // An error, if any, is yielded once and last.
        assert!(errors <= 1, "line {lineno}: more than one error");
        if errors == 1 {
            assert!(results.last().is_some_and(Result::is_err), "line {lineno}");
        }
        let accepted = errors == 0;
        if expect_ok {
            oks += 1;
        } else {
            errs += 1;
        }
        if accepted != expect_ok {
            failures.push(format!(
                "line {lineno}: expected {raw:.60?}, got {results:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(oks + errs >= 40, "only {} vectors", oks + errs);
    println!("{oks} ok and {errs} err vectors pass");
}
