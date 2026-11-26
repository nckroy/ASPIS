// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The name parsers against `grammars/names.abnf` (ADR 0063, rules 1 and
//! 10), and the "no escaping" property: every valid type name is a Cedar
//! `Path`, and every action reference an RFC 6749 `scope-token`
//! (docs/design/call-language.md, "Differential tests", per change).

use std::{fs, path::Path};

use abnf::{Context, Grammar, LoadOptions, vectors};
use idl_rt::names::{
    ActionTarget, ErrorRef, MAX_ACTION_REF, is_label, is_member_name, is_name, parse_action_ref,
    parse_error_ref, parse_interface_ref,
};

fn grammars() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../grammars")
}

fn load_names() -> Grammar {
    let dir = grammars();
    let text = fs::read(dir.join("names.abnf")).unwrap();
    let mut resolve = |n: &str| fs::read(dir.join(format!("{n}.abnf"))).ok();
    Grammar::load("names", &text, &mut resolve, &LoadOptions::default()).unwrap()
}

/// What our parsers say about a rule's input, for the rules they cover.
fn ours(rule: &str, s: &[u8]) -> Option<bool> {
    Some(match rule {
        "interface-ref" => {
            let r = parse_interface_ref(s);
            if let Ok(r) = r {
                assert_eq!(r.to_string().as_bytes(), s, "re-render");
            }
            r.is_ok()
        }
        "action-ref" | "scope-token" => {
            let r = parse_action_ref(s);
            if let Ok(r) = r {
                assert_eq!(r.to_string().as_bytes(), s, "re-render");
            }
            r.is_ok()
        }
        "action-name" => matches!(
            parse_action_ref(s),
            Ok(r) if matches!(r.target, ActionTarget::Method(_))
        ),
        "group-name" => matches!(
            parse_action_ref(s),
            Ok(r) if matches!(r.target, ActionTarget::Group(_))
        ),
        "all-methods" => matches!(parse_action_ref(s), Ok(r) if r.target == ActionTarget::All),
        "error-ref" => {
            let r = parse_error_ref(s);
            if let Ok(r) = r {
                assert_eq!(r.to_string().as_bytes(), s, "re-render");
            }
            r.is_ok()
        }
        "name" | "type-name" | "interface-name" => is_name(s),
        "label" => is_label(s),
        "member-name" => is_member_name(s),
        "major" | "minor" | "number" => {
            matches!(idl_rt::names::number(s), Some((_, n)) if n == s.len())
        }
        _ => return None,
    })
}

#[test]
fn parsers_agree_with_the_vectors() {
    let vf = vectors::parse(&fs::read(grammars().join("names.vectors")).unwrap()).unwrap();
    let mut checked = 0;
    for v in &vf.vectors {
        let Some(got) = ours(&v.rule, &v.octets) else {
            continue;
        };
        let want = v.tag == vectors::Tag::Ok;
        assert_eq!(
            got,
            want,
            "line {}: {} {:?}",
            v.line,
            v.rule,
            String::from_utf8_lossy(&v.octets)
        );
        checked += 1;
    }
    assert!(checked > 80, "only {checked} vectors reached the parsers");
}

/// A small deterministic generator, so a failure replays.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> usize {
        (self.next() % n) as usize
    }
}

/// Strings built mostly from the names alphabet, with a few octets from
/// outside it.
fn candidate(rng: &mut Rng) -> Vec<u8> {
    const ALPHABET: &[u8] = b"abcxyz019_._./@*!#-AZ ";
    let len = 1 + rng.below(24);
    (0..len)
        .map(|_| ALPHABET[rng.below(ALPHABET.len() as u64)])
        .collect()
}

/// The parsers against the grammar's constrained matcher, on generated
/// inputs.
#[test]
fn parsers_agree_with_the_grammar_on_generated_inputs() {
    let g = load_names();
    let cx = Context::default();
    let mut rng = Rng(0x6e61_6d65);
    for _ in 0..4000 {
        let s = candidate(&mut rng);
        for rule in [
            "interface-ref",
            "action-ref",
            "error-ref",
            "name",
            "member-name",
            "label",
        ] {
            let want = g
                .matches_constrained(g.rule(rule).unwrap(), &s, &cx)
                .unwrap();
            assert_eq!(
                ours(rule, &s),
                Some(want),
                "{rule} {:?}",
                String::from_utf8_lossy(&s)
            );
        }
    }
}

/// Cedar's `Path` (Cedar 4.7 grammar): `IDENT { '::' IDENT }`, where IDENT
/// is `['_' 'a'-'z' 'A'-'Z'] ['_' 'a'-'z' 'A'-'Z' '0'-'9']*` and not one of
/// Cedar's reserved words. Identifiers starting `__cedar` are reserved.
fn is_cedar_path(s: &str) -> bool {
    const RESERVED: [&str; 9] = [
        "true", "false", "if", "then", "else", "in", "is", "like", "has",
    ];
    s.split("::").all(|id| {
        let mut b = id.bytes();
        let first_ok = b
            .next()
            .is_some_and(|c| c == b'_' || c.is_ascii_alphabetic());
        first_ok
            && b.all(|c| c == b'_' || c.is_ascii_alphanumeric())
            && !RESERVED.contains(&id)
            && !id.starts_with("__cedar")
    })
}

/// RFC 6749, section 3.3: `scope-token = 1*( %x21 / %x23-5B / %x5D-7E )`.
fn is_scope_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c == 0x21 || (0x23..=0x5B).contains(&c) || (0x5D..=0x7E).contains(&c))
}

/// Dotted candidates built label by label, most of them valid names.
fn dotted(rng: &mut Rng) -> Vec<u8> {
    const ALPHABET: &[u8] = b"abiny019_";
    let labels = 1 + rng.below(4);
    let mut s = Vec::new();
    for i in 0..labels {
        if i > 0 {
            s.push(b'.');
        }
        let len = 1 + rng.below(8);
        s.extend((0..len).map(|_| ALPHABET[rng.below(ALPHABET.len() as u64)]));
    }
    s
}

#[test]
fn every_name_is_a_cedar_path_and_every_action_a_scope_token() {
    let mut rng = Rng(0x6365_6461);
    let mut names = 0;
    for _ in 0..20_000 {
        let s = dotted(&mut rng);
        if !is_name(&s) {
            continue;
        }
        names += 1;
        let name = std::str::from_utf8(&s).unwrap();
        assert!(is_cedar_path(&name.replace('.', "::")), "{name}");
        for action in [
            format!("{name}/1/watch"),
            format!("{name}/65535/@discover"),
            format!("{name}/0/*"),
        ] {
            assert!(parse_action_ref(action.as_bytes()).is_ok(), "{action}");
            assert!(is_scope_token(&action), "{action}");
        }
    }
    assert!(names > 50, "only {names} names generated");

    // The longest action reference fits the stated bound.
    let long = [&"a".repeat(63)[..]; 4].join(".");
    let action = format!("{long}/65535/@{}", "b".repeat(63));
    assert_eq!(action.len(), MAX_ACTION_REF);
    assert!(parse_action_ref(action.as_bytes()).is_ok());
    assert!(is_scope_token(&action));
}

#[test]
fn borrowed_parts() {
    let r = parse_interface_ref(b"aspis.catalog/1.2").unwrap();
    assert_eq!((r.name, r.major, r.minor), ("aspis.catalog", 1, Some(2)));
    assert_eq!(
        parse_interface_ref(b"aspis.catalog/1")
            .unwrap()
            .minor_or_zero(),
        0
    );
    let a = parse_action_ref(b"aspis.catalog/1/@discover").unwrap();
    assert_eq!(a.target, ActionTarget::Group("discover"));
    let id = "0123456789abcdef".repeat(4);
    let text = format!("{id}/1!#17");
    let e = parse_error_ref(text.as_bytes()).unwrap();
    assert!(matches!(
        e,
        ErrorRef::Code {
            major: 1,
            code: 17,
            ..
        }
    ));
    assert!(parse_error_ref(format!("{id}/1!#0").as_bytes()).is_err());
}
