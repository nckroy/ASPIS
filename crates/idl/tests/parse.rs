// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The parser on the note's examples and the repository's files, its
//! diagnostics, and its limits (ADR 0068, rule 5: bounded work, no
//! panics).

mod common;

use std::fs;

use idl::{
    Code, Limits,
    ast::{BaseType, MemberKind, ResultsKind},
    diag::line_col,
    parse::parse,
};

/// The IDL blocks under a heading of the call-language note.
fn note_example(heading: &str) -> String {
    let note = fs::read_to_string(common::repo().join("docs/design/call-language.md")).unwrap();
    let mut lines = note
        .lines()
        .skip_while(|l| *l != heading)
        .skip_while(|l| *l != "```")
        .skip(1);
    let mut out = String::new();
    for l in lines.by_ref() {
        if l == "```" {
            break;
        }
        out.push_str(l);
        out.push('\n');
    }
    out
}

#[test]
fn the_notes_examples_parse_and_check() {
    for heading in [
        "### Example: the eventcount interface",
        "### Example: the catalog across two minors",
    ] {
        let src = note_example(heading);
        assert!(src.starts_with("// SPDX"), "{heading}: {src}");
        let f =
            parse(src.as_bytes(), &Limits::default()).unwrap_or_else(|d| panic!("{heading}: {d}"));
        assert!(!f.interface.members.is_empty());
        common::check(src.as_bytes()).unwrap_or_else(|d| panic!("{heading}: {d:#?}"));
    }
}

#[test]
fn every_file_parses() {
    for p in common::idl_files() {
        let src = fs::read(&p).unwrap();
        parse(&src, &Limits::default()).unwrap_or_else(|d| panic!("{}: {d}", p.display()));
    }
}

#[test]
fn the_tree_keeps_what_the_source_says() {
    let src = fs::read(common::repo().join("interfaces/aspis/catalog/v1.idl")).unwrap();
    let f = parse(&src, &Limits::default()).unwrap();
    assert_eq!(f.interface.name.name, "catalog");
    assert!(f.docs[0].contains("The realm catalog"));
    let watch = f
        .interface
        .members
        .iter()
        .find_map(|m| match &m.kind {
            MemberKind::Method(m) if m.name.name == "watch" => Some(m),
            _ => None,
        })
        .unwrap();
    assert_eq!(watch.ordinal, 2);
    let r = watch.results.as_ref().unwrap();
    assert!(matches!(&r.kind, ResultsKind::Fields(f) if f.len() == 1));
    assert_eq!(r.stream.as_ref().unwrap().name.name, "change");
    assert_eq!(watch.errors[0].name, "query_too_broad");
    let register = f
        .interface
        .members
        .iter()
        .find_map(|m| match &m.kind {
            MemberKind::Method(m) if m.name.name == "register" => Some(m),
            _ => None,
        })
        .unwrap();
    assert!(
        matches!(&register.params[0].ty.base, BaseType::Cap(r, q) if r.name == "aspis.kernel.memory" && q.len() == 2)
    );
    assert!(register.params[3].ty.optional);
}

#[test]
fn diagnostics_carry_line_and_column() {
    let src = b"edition 2026;\n[id(a.b)]\ninterface b {\n    struct s { a: U8 }\n}\n";
    let d = parse(src, &Limits::default()).unwrap_err();
    assert_eq!(d.code, Code::Syntax);
    assert_eq!(line_col(src, d.span.start as usize), (4, 19));
    assert_eq!(d.line_col(src), (4, 19));
    // The checker's diagnostics point at the item.
    let src = b"edition 2026;\n[id(org.example.t), object_id(reserved(1)), version(1.0)]\ninterface t {\n  @1 m(x: nothing);\n}\n";
    let d = common::check(src).unwrap_err();
    assert_eq!(d[0].code, Code::Reference);
    assert_eq!(d[0].line_col(src), (4, 11));
}

fn wrap(body: &str) -> Vec<u8> {
    format!("edition 2026;\n[id(a.b)] interface b {{\n{body}\n}}\n").into_bytes()
}

#[test]
fn limits_give_errors_never_panics() {
    let limits = Limits::default();
    // Types nested 32 deep parse; 33 don't.
    let nest = |n: usize| {
        format!(
            "alias a = {}u8{};",
            "seq<".repeat(n - 1),
            ", 2>".repeat(n - 1)
        )
    };
    assert!(parse(&wrap(&nest(32)), &limits).is_ok());
    assert_eq!(
        parse(&wrap(&nest(33)), &limits).unwrap_err().code,
        Code::Limit
    );
    // Deep nesting far past the limit stops at the limit, without a deep
    // stack.
    assert_eq!(
        parse(&wrap(&nest(100_000)), &limits).unwrap_err().code,
        Code::Limit
    );
    // A 64-octet identifier is a syntax error; 63 is fine.
    assert!(parse(&wrap(&format!("struct {} {{}}", "a".repeat(63))), &limits).is_ok());
    assert_eq!(
        parse(&wrap(&format!("struct {} {{}}", "a".repeat(64))), &limits)
            .unwrap_err()
            .code,
        Code::Syntax
    );
    // An oversized source.
    let big = vec![b' '; limits.source + 1];
    assert_eq!(parse(&big, &limits).unwrap_err().code, Code::Limit);
    // Too many members, use lines and attributes.
    let small = Limits {
        members: 3,
        uses: 1,
        attrs: 2,
        ..Limits::default()
    };
    assert_eq!(
        parse(&wrap("@1 a();@2 b();@3 c();@4 d();"), &small)
            .unwrap_err()
            .code,
        Code::Limit
    );
    let uses = b"edition 2026;\nuse a.c/1.{x};\nuse a.d/1.{y};\n[id(a.b)] interface b {}";
    assert_eq!(parse(uses, &small).unwrap_err().code, Code::Limit);
    assert_eq!(
        parse(&wrap("[a, b, c] struct s {}"), &small)
            .unwrap_err()
            .code,
        Code::Limit
    );
}

#[test]
fn hostile_inputs_end_in_errors() {
    let limits = Limits::default();
    for src in [
        &b""[..],
        b"edition 2026;",
        b"edition 2026;\n[",
        b"edition 2026;\n[id(a.b)] interface b {",
        b"edition 2026;\n[id(a.b)] interface b { @1 m(",
        b"edition 2026;\n[id(a.b)] interface b { struct s { a: seq<",
        b"\xff\xfe",
        b"// \xc3",
        b"edition 2026;\n[id(a.b)] interface b {} //",
    ] {
        assert!(
            parse(src, &limits).is_err(),
            "{:?}",
            String::from_utf8_lossy(src)
        );
    }
}
