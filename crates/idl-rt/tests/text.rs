// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The canonical call and reply text (ADR 0063, rule 9), against
//! `grammars/names.abnf`'s `call-text` and `reply-text` through crates/abnf.

use std::{fs, path::Path};

use abnf::{Context, Grammar, LoadOptions};
use idl_rt::{
    error::{ErrorKey, Outcome},
    text::{ErrorName, Target, call_text, reply_error, reply_ok},
};

fn names() -> Grammar {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../grammars");
    let src = fs::read(dir.join("names.abnf")).unwrap();
    let mut shared = |n: &str| fs::read(dir.join(format!("{n}.abnf"))).ok();
    Grammar::load("names", &src, &mut shared, &LoadOptions::default()).unwrap()
}

fn matches(g: &Grammar, rule: &str, text: &[u8]) -> bool {
    let r = g.rule(rule).unwrap();
    g.matches_constrained(r, text, &Context::default())
        .unwrap_or(false)
}

#[test]
fn calls() {
    let g = names();
    let mut buf = [0u8; 256];
    // The note's example ("The canonical call text").
    let n = call_text(
        &mut buf,
        "aspis.kernel.eventcount/1/wait",
        Target::Kernel,
        Some(&mut |j| {
            j.begin_object();
            j.key("target");
            j.u64_string(42);
            j.end_object();
        }),
    )
    .unwrap();
    assert_eq!(
        &buf[..n],
        br#"aspis.kernel.eventcount/1/wait - {"target":"42"}"#
    );
    assert!(matches(&g, "call-text", &buf[..n]));
    let id = [0xAB; 32];
    let n = call_text(
        &mut buf,
        "aspis.catalog/1/list",
        Target::Object(&id),
        Some(&mut |j| {
            j.begin_object();
            j.end_object();
        }),
    )
    .unwrap();
    let want = format!("aspis.catalog/1/list {} {{}}", "ab".repeat(32));
    assert_eq!(&buf[..n], want.as_bytes());
    assert!(matches(&g, "call-text", &buf[..n]));
    // Without arguments, the default form.
    let n = call_text(&mut buf, "aspis.catalog/1/list", Target::Object(&id), None).unwrap();
    let want = format!("aspis.catalog/1/list {}", "ab".repeat(32));
    assert_eq!(&buf[..n], want.as_bytes());
    assert!(matches(&g, "call-text", &buf[..n]));
    // Too small a buffer.
    assert!(
        call_text(
            &mut buf[..10],
            "aspis.catalog/1/list",
            Target::Kernel,
            Some(&mut |_| {})
        )
        .is_err()
    );
}

#[test]
fn replies() {
    let g = names();
    let mut buf = [0u8; 256];
    let n = reply_ok(
        &mut buf,
        Some(&mut |j| {
            j.begin_object();
            j.key("result");
            j.u64_string(7);
            j.end_object();
        }),
    )
    .unwrap();
    assert_eq!(&buf[..n], br#"ok {"result":"7"}"#);
    assert!(matches(&g, "reply-text", &buf[..n]));
    let n = reply_ok(&mut buf, None).unwrap();
    assert_eq!(&buf[..n], b"ok");
    assert!(matches(&g, "reply-text", &buf[..n]));
    let key = ErrorKey {
        interface: [0x01; 32],
        major: 1,
        code: 24,
    };
    let n = reply_error(
        &mut buf,
        Outcome::Refused,
        &key,
        Some(ErrorName {
            interface: "aspis.catalog",
            error: "stream_expired",
        }),
    )
    .unwrap();
    assert_eq!(&buf[..n], b"refused aspis.catalog/1!stream_expired");
    assert!(matches(&g, "reply-text", &buf[..n]));
    let n = reply_error(&mut buf, Outcome::Indeterminate, &key, None).unwrap();
    let want = format!("indeterminate {}/1!#24", "01".repeat(32));
    assert_eq!(&buf[..n], want.as_bytes());
    assert!(matches(&g, "reply-text", &buf[..n]));
}
