// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The checker's rules, one case or more each, table-driven
//! (docs/design/call-language.md, "The IDL"; the C07 plan's checker
//! list). Every negative case names the diagnostic code it must give.

mod common;

use idl::{Code, layout};

/// An interface `org.example.t`, version 1.1, around `body`.
fn iface(body: &str) -> String {
    format!(
        "edition 2026;\n[id(org.example.t), object_id(reserved(1)), version(1.1)]\ninterface t {{\n{body}\n}}\n"
    )
}

/// The same, with other header attributes.
fn iface_with(header: &str, body: &str) -> String {
    format!("edition 2026;\n[{header}]\ninterface t {{\n{body}\n}}\n")
}

fn codes(src: &str) -> Vec<Code> {
    match common::check(src.as_bytes()) {
        Ok(_) => Vec::new(),
        Err(d) => d.into_iter().map(|d| d.code).collect(),
    }
}

#[track_caller]
fn refused(src: &str, code: Code) {
    let got = codes(src);
    assert!(
        got.contains(&code),
        "expected {code:?}, got {got:?} for:\n{src}"
    );
}

#[track_caller]
fn accepted(src: &str) -> idl::Checked {
    match common::check(src.as_bytes()) {
        Ok(c) => c,
        Err(d) => panic!("refused:\n{src}\n{d:#?}"),
    }
}

#[test]
fn a_minimal_interface_passes() {
    accepted(&iface(""));
    accepted(&iface("@1 m(a: u8) -> u8;"));
}

#[test]
fn header() {
    let body = "";
    refused(
        &iface_with("object_id(reserved(1)), version(1.0)", body),
        Code::Header,
    );
    refused(
        &iface_with("id(org.example.t), object_id(reserved(1))", body),
        Code::Header,
    );
    refused(
        &iface_with("id(org.example.t), version(1.0)", body),
        Code::Header,
    );
    refused(
        &iface_with(
            "id(org.example.u), object_id(reserved(1)), version(1.0)",
            body,
        ),
        Code::Header,
    );
    refused(
        &iface_with("id(t), object_id(reserved(1)), version(1.0)", body),
        Code::Attribute,
    );
    refused(
        &iface_with(
            "id(org.example.t), object_id(reserved(-1)), version(1.0)",
            body,
        ),
        Code::Attribute,
    );
    refused(
        &iface("[type(org.example.thing)] object widget { a: u8 }"),
        Code::Header,
    );
    refused(&iface("object widget { a: u8 }"), Code::Header);
    // The interfaces the kernel calls are [local], never [kernel].
    let pager = |h: &str| {
        format!(
            "edition 2026;\n[id(aspis.kernel.pager), object_id(reserved(9)), version(1.0){h}]\ninterface pager {{}}\n"
        )
    };
    refused(&pager(", kernel"), Code::Header);
    refused(&pager(""), Code::Header);
    accepted(&pager(", local"));
}

#[test]
fn numbers() {
    refused(&iface("@65280 m();"), Code::Number);
    refused(&iface("@1 m();\n@1 n();"), Code::Number);
    refused(&iface("reserved @1;\n@1 m();"), Code::Number);
    refused(&iface("union u { @1 a: u8, @1 b: u16 }"), Code::Number);
    refused(&iface("union u { @1 a: u8, reserved @1 }"), Code::Number);
    refused(&iface("enum e: u8 { a = 256 }"), Code::Number);
    refused(&iface("enum e: u8 { a = -1 }"), Code::Number);
    refused(&iface("enum e: u8 { a = 1, reserved 1 }"), Code::Number);
    refused(&iface("flags f: u8 { a = 3 }"), Code::Number);
    refused(&iface("flags f: u8 { a = 0 }"), Code::Number);
    refused(&iface("error e = 0;"), Code::Number);
    refused(&iface("error e = 65536;"), Code::Number);
    refused(&iface("error e = 1;\nerror f = 1;"), Code::Number);
    refused(&iface("const c: u8 = 300;"), Code::Number);
    refused(&iface("const c: i8 = -129;"), Code::Number);
    refused(&iface("const c: u64 = 0x10000000000000000;"), Code::Number);
    refused(&iface("struct s { @2 a: u8 }"), Code::Number);
    accepted(&iface(
        "struct s { @1 a: u8, b: u8, @3 c: u8 }\n@65279 m();\nflags f: u64 { a = 0x8000000000000000 }",
    ));
}

#[test]
fn names() {
    refused(
        &iface("struct s { a: u8 }\nunion s { @1 a: u8 }"),
        Code::Duplicate,
    );
    refused(
        &iface("struct foo_1 { a: u8 }\nstruct foo1 { a: u8 }"),
        Code::Duplicate,
    );
    refused(&iface("error e_2 = 1;\nerror e2 = 2;"), Code::Duplicate);
    refused(&iface("struct s { a: u8, a: u16 }"), Code::Duplicate);
    refused(
        &iface("union u { @1 a_1: u8, @2 a1: u16 }"),
        Code::Duplicate,
    );
    refused(&iface("enum e: u8 { v_2 = 1, v2 = 2 }"), Code::Duplicate);
    refused(&iface("@1 m();\n@2 m();"), Code::Duplicate);
    refused(
        &iface("const c: u8 = 1;\nconst c: u8 = 2;"),
        Code::Duplicate,
    );
    refused(&iface("@1 m(a: u8, a: u8);"), Code::Duplicate);
    refused(
        "edition 2026;\nuse org.example.base/1.0.{point};\n[id(org.example.t), object_id(reserved(1)), version(1.0)]\ninterface t { struct point { a: u8 } }\n",
        Code::Duplicate,
    );
    // A struct, an error and a method may share a name: their Rust names
    // live apart.
    accepted(&iface(
        "struct thing { a: u8 }\nerror thing = 1;\n@1 thing();",
    ));
    // Helper words are ordinary member names.
    accepted(&iface(
        "struct s { tail: u8, opt: u8, unknown: u8, unknown_tag: u8 }\nunion u { @1 unknown: u8 }",
    ));
}

#[test]
fn attributes() {
    refused(&iface("[frozen] struct s { a: u8 }"), Code::Attribute);
    refused(&iface("[closed] error e = 1;"), Code::Attribute);
    refused(
        &iface("[closed, closed] struct s { a: u8 }"),
        Code::Attribute,
    );
    refused(&iface("[since(1)] struct s { a: u8 }"), Code::Attribute);
    refused(&iface("[closed(1)] struct s { a: u8 }"), Code::Attribute);
    refused(&iface("[retry(soon)] error e = 1;"), Code::Attribute);
    refused(&iface("[requires(read)] @1 m();"), Code::Attribute);
    refused(&iface("[static] @1 m();"), Code::Attribute);
    refused(&iface("[oneway] @1 m();"), Code::Attribute);
    refused(
        &iface_with(
            "id(org.example.t), object_id(reserved(1)), version(1.0), local",
            "[oneway] @1 m() -> u8;",
        ),
        Code::Attribute,
    );
    refused(
        &iface_with(
            "id(org.example.t), object_id(reserved(1)), version(1.0), local",
            "error e = 1;\n[oneway] @1 m() error(e);",
        ),
        Code::Attribute,
    );
    refused(&iface("[lossy] @1 m();"), Code::Attribute);
    refused(
        &iface("struct i { a: u8 }\n[lossy, coalescing] @1 m(after: u64?) -> stream<i>;"),
        Code::Attribute,
    );
    refused(
        &iface("struct s { [format(json)] a: u32 }"),
        Code::Attribute,
    );
    refused(
        &iface("struct s { [format(xml)] a: string<8> }"),
        Code::Attribute,
    );
    refused(&iface("struct s { [closed] a: u8 }"), Code::Attribute);
    refused(&iface("[group(g, g)] @1 m();"), Code::Attribute);
    refused(
        &iface_with(
            "id(org.example.t), object_id(reserved(1)), version(1.0), groups(g, g)",
            "[group(g)] @1 m();",
        ),
        Code::Attribute,
    );
    accepted(&iface_with(
        "id(org.example.t), object_id(reserved(1)), version(1.0), local",
        "[oneway] @1 m(a: u8);",
    ));
    accepted(&iface_with(
        "id(aspis.kernel.t), object_id(reserved(1)), version(1.0), kernel",
        "[requires(read, write), readonly] @1 m(s: slot<aspis.kernel.eventcount/1, read>);\n[static] @2 n();",
    ));
}

#[test]
fn since() {
    refused(&iface("[since(2.0)] struct s { a: u8 }"), Code::Since);
    refused(&iface("[since(1.2)] struct s { a: u8 }"), Code::Since);
    refused(&iface("[deprecated(1.2)] struct s { a: u8 }"), Code::Since);
    refused(
        &iface("struct s { a: u8, [since(1.1)] b: u8 }"),
        Code::Since,
    );
    refused(
        &iface("struct s { [since(1.1)] a: u8?, b: u8 }"),
        Code::Since,
    );
    refused(
        &iface("[closed] struct s { a: u8, [since(1.1)] b: u8? }"),
        Code::Since,
    );
    refused(
        &iface("[closed] enum e: u8 { a = 1, [since(1.1)] b = 2 }"),
        Code::Since,
    );
    refused(
        &iface("[closed] union u { @1 a: u8, [since(1.1)] @2 b: u8 }"),
        Code::Since,
    );
    refused(
        &iface("[since(1.1), deprecated(1.0)] struct s { a: u8 }"),
        Code::Since,
    );
    refused(
        &iface("[since(1.1)] struct s { [since(1.0)] a: u8 }"),
        Code::Since,
    );
    refused(
        &iface("[since(1.1)] struct s { a: u8 }\n@1 m(x: s);"),
        Code::Since,
    );
    refused(
        &iface("[since(1.1)] const n: u32 = 4;\nstruct s { a: string<n> }"),
        Code::Since,
    );
    refused(&iface("@1 m(a: u8, [since(1.1)] b: u8);"), Code::Since);
    // An error list may name a newer error: projection drops it.
    accepted(&iface("[since(1.1)] error e = 1;\n@1 m() error(e);"));
    accepted(&iface(
        "struct s { a: u8, [since(1.1)] b: u8? }\n[since(1.1)] enum e: u8 { a = 1 }\nenum f: u8 { a = 1, [since(1.1)] b = 2 }",
    ));
}

/// The plan critic's case: a struct new in 1.1 may have required fields and
/// a capability, since its fields aren't newer than it is.
#[test]
fn a_new_struct_takes_required_fields_and_a_capability() {
    let c = accepted(&iface(
        "[since(1.1)] struct later { a: u8, b: cap<org.example.base/1> }\n[since(1.1)] @1 m(x: later) -> later;",
    ));
    assert_eq!(c.layout.methods[0].request.caps, 1);
    assert_eq!(c.layout.methods[0].reply.unwrap().caps, 1);
    // But a field added to it later may hold none.
    refused(
        &iface_with(
            "id(org.example.t), object_id(reserved(1)), version(1.2)",
            "[since(1.1)] struct later { a: u8, [since(1.2)] b: cap<org.example.base/1>? }",
        ),
        Code::Capability,
    );
}

#[test]
fn types() {
    refused(&iface("struct s { a: nothing }"), Code::Reference);
    refused(
        &iface("[type(org.example.w)] object w { a: u8 }\nstruct s { a: w }"),
        Code::Reference,
    );
    refused(
        &iface("const c: u8 = 1;\nstruct s { a: c }"),
        Code::Reference,
    );
    refused(
        &iface("struct s { a: org.example.base/1.point }"),
        Code::Reference,
    );
    refused(&iface("struct s { a: s? }"), Code::Type);
    refused(
        &iface("struct s { a: seq<r, 2> }\nunion r { @1 x: s }"),
        Code::Type,
    );
    refused(&iface("alias a = b;\nalias b = a;"), Code::Type);
    refused(&iface("struct s { a: string<0> }"), Code::Type);
    refused(&iface("struct s { a: string<4294967296> }"), Code::Type);
    refused(&iface("struct s { a: array<u8, 65536> }"), Code::Type);
    refused(&iface("struct s { a: bytes<missing> }"), Code::Reference);
    refused(
        &iface("const n: i8 = -1;\nstruct s { a: bytes<n> }"),
        Code::Type,
    );
    refused(
        &iface("struct o { a: u8 }\n[closed] struct s { a: o }"),
        Code::Type,
    );
    refused(
        &iface("union o { @1 a: u8 }\n[closed] union s { @1 a: seq<o, 2> }"),
        Code::Type,
    );
    refused(&iface("alias a = u8?;"), Code::Type);
    refused(&iface("enum e: u64 { a = 1 }"), Code::Type);
    refused(&iface("[closed] union u {}"), Code::Type);
    refused(
        &iface("[type(org.example.w)] object w { a: f64 }"),
        Code::Type,
    );
    refused(
        &iface("[type(org.example.w)] object w { a: bytes<4> }"),
        Code::Type,
    );
    // Open enums and flags may sit in a closed type.
    accepted(&iface(
        "enum e: u8 { a = 1 }\nflags f: u16 { a = 1 }\n[closed] struct s { a: e, b: f, c: array<s2, 2> }\n[closed] struct s2 { x: u8 }",
    ));
}

#[test]
fn capabilities() {
    refused(
        &iface("struct s { a: seq<cap<org.example.base/1>, 2> }"),
        Code::Capability,
    );
    refused(
        &iface("struct c { x: cap<org.example.base/1> }\nstruct s { a: array<c, 2> }"),
        Code::Capability,
    );
    refused(
        &iface("error e = 1 { c: cap<org.example.base/1> };"),
        Code::Capability,
    );
    refused(
        &iface("struct s { a: u8, [since(1.1)] c: cap<org.example.base/1>? }"),
        Code::Capability,
    );
    refused(
        &iface("union u { @1 a: u8, [since(1.1)] @2 c: cap<org.example.base/1> }"),
        Code::Capability,
    );
    let cap = "cap<org.example.base/1>";
    refused(
        &iface(&format!("@1 m(a: {cap}, b: {cap}, c: {cap}, d: {cap}?);")),
        Code::Capability,
    );
    refused(
        &iface(&format!(
            "@1 m() -> (a: {cap}, b: {cap}, c: {cap}, d: {cap}?);"
        )),
        Code::Capability,
    );
    refused(
        &iface(&format!(
            "union u {{ @1 a: {cap}, @2 b: u8 }}\n@1 m(a: {cap}, b: {cap}, c: {cap}, d: u);"
        )),
        Code::Capability,
    );
    // A body that may spill carries at most 2.
    refused(
        &iface(&format!(
            "@1 m(a: {cap}, b: {cap}, c: {cap}, d: bytes<1024>);"
        )),
        Code::Capability,
    );
    accepted(&iface(&format!(
        "@1 m(a: {cap}, b: {cap}, d: bytes<1024>);"
    )));
    refused(
        &iface("@1 m(a: cap<org.example.base/1, read>);"),
        Code::Capability,
    );
    refused(
        &iface("@1 m(a: cap<aspis.kernel.eventcount/1, read, immutable>);"),
        Code::Capability,
    );
    refused(
        &iface("@1 m(a: cap<aspis.kernel.memory/1, read, read>);"),
        Code::Capability,
    );
    refused(
        &iface("@1 m(a: slot<aspis.kernel.eventcount/1, read>);"),
        Code::Capability,
    );
    refused(
        &iface(&format!(
            "struct i {{ c: {cap}? }}\n@1 m(after: u64?) -> stream<i>;"
        )),
        Code::Capability,
    );
    // A [kernel] interface skips the spill rule.
    accepted(&iface_with(
        "id(aspis.kernel.t), object_id(reserved(1)), version(1.0), kernel",
        "@1 m(a: cap<aspis.kernel.memory/1, read>, b: cap<aspis.kernel.memory/1, read>, c: cap<aspis.kernel.memory/1, read>, d: bytes<1024>);",
    ));
}

/// Capabilities to the interfaces the kernel calls are session
/// capabilities: no qualifiers, and they don't make a method local.
#[test]
fn the_interfaces_the_kernel_calls_are_sessions() {
    refused(
        &iface("@1 m(p: cap<aspis.kernel.pager/1, read>);"),
        Code::Capability,
    );
    let c = accepted(&iface(
        "@1 m(p: cap<aspis.kernel.pager/1>, f: cap<aspis.kernel.fault/1>?);",
    ));
    assert!(!c.layout.methods[0].local);
    let c = accepted(&iface("@1 m(e: cap<aspis.kernel.eventcount/1, read>);"));
    assert!(c.layout.methods[0].local && c.layout.methods[0].local_inferred);
    let c = accepted(&iface(
        "@1 m(e: cap<aspis.kernel.memory/1, read, immutable>);",
    ));
    assert!(!c.layout.methods[0].local);
}

#[test]
fn sizes() {
    refused(&iface("@1 m(a: bytes<4294967295>);"), Code::Size);
    refused(&iface("@1 m() -> bytes<4294967295>;"), Code::Size);
    refused(
        &iface("struct i { a: bytes<16777200> }\n@1 m(after: u64?) -> stream<i>;"),
        Code::Size,
    );
    // An error's detail is at most 708 octets: 4 for its tail count, then
    // a string's 4-octet length and 700 octets.
    accepted(&iface("error e = 1 { a: string<700> };"));
    refused(&iface("error e = 1 { a: string<701> };"), Code::Size);
}

/// A stream method's opening reply carries 12 more octets, which count for
/// spilling.
#[test]
fn an_opening_reply_counts_its_stream_id_and_start() {
    let cap = "cap<org.example.base/1>";
    // 4 (tail count) + 3 capabilities + 4 + 941 octets = 952: no spill.
    let reply = format!("(a: {cap}, b: {cap}, c: {cap}, d: bytes<941>)");
    let c = accepted(&iface(&format!("@1 m() -> {reply};")));
    assert_eq!(c.layout.methods[0].reply.unwrap().max, 952);
    // The same reply opening a stream: 964, so it may spill.
    refused(
        &iface(&format!(
            "struct i {{ a: u8 }}\n@1 m(after: u64?) -> {reply} stream<i>;"
        )),
        Code::Capability,
    );
    let c = accepted(&iface(
        "struct i { a: u8 }\n[lossy] @1 m(after: u64?) -> stream<i>;",
    ));
    let s = c.layout.methods[0].stream.unwrap();
    assert_eq!(
        (s.item_max, s.entry_max, s.kind),
        (5, 18, layout::StreamKind::Lossy)
    );
    assert_eq!(c.layout.methods[0].reply.unwrap().max, 16);
}

#[test]
fn streams() {
    refused(
        &iface("struct i { a: u8 }\n@1 m() -> stream<i>;"),
        Code::Stream,
    );
    refused(
        &iface("struct i { a: u8 }\n@1 m(after: u32?) -> stream<i>;"),
        Code::Stream,
    );
    refused(
        &iface("struct i { a: u8 }\n@1 m(after: u64) -> stream<i>;"),
        Code::Stream,
    );
    refused(
        &iface("union i { @1 a: u8 }\n@1 m(after: u64?) -> stream<i>;"),
        Code::Stream,
    );
    refused(
        &iface("@1 m(after: u64?) -> stream<nothing>;"),
        Code::Reference,
    );
}

#[test]
fn groups_and_error_lists() {
    let h = "id(org.example.t), object_id(reserved(1)), version(1.0), groups(read)";
    refused(&iface_with(h, "[group(write)] @1 m();"), Code::Group);
    refused(&iface_with(h, "@1 m();"), Code::Group);
    accepted(&iface_with(h, "[group(read)] @1 m();"));
    refused(&iface("@1 m() error(deadline_passed);"), Code::ErrorList);
    refused(&iface("error e = 1;\n@1 m() error(e, e);"), Code::ErrorList);
}

#[test]
fn imports() {
    let with_use = |u: &str, body: &str| {
        format!(
            "edition 2026;\nuse {u};\n[id(org.example.t), object_id(reserved(1)), version(1.0)]\ninterface t {{\n{body}\n}}\n"
        )
    };
    refused(&with_use("org.example.missing/1.{x}", ""), Code::Import);
    refused(&with_use("org.example.base/1.0.{extra}", ""), Code::Import);
    refused(&with_use("org.example.base/1.5.{point}", ""), Code::Import);
    refused(&with_use("org.example.base/2.{point}", ""), Code::Import);
    // An import at 1.1 sees 1.1's types.
    let c = accepted(&with_use(
        "org.example.base/1.1.{extra, point}",
        "@1 m(e: extra, p: point, q: org.example.base/1.point);",
    ));
    // point at 1.1: 4 + 4 + 4 (tail count) + 10 (z, a tail field).
    let req = c.layout.methods[0].request;
    assert_eq!(req.max, 4 + (1 + 1 + 4) + (8 + 4 + 10) * 2);
    // The same import at 1.0 doesn't have z.
    let c = accepted(&with_use("org.example.base/1.{point}", "@1 m(p: point);"));
    assert_eq!(c.layout.methods[0].request.max, 4 + 12);
}

#[test]
fn every_repository_file_passes() {
    for p in common::idl_files() {
        common::check_file(&p);
    }
}

#[test]
fn the_catalog_derives_what_the_note_says() {
    let c = common::check_file(&common::repo().join("interfaces/aspis/catalog/v1.idl"));
    let register = c
        .layout
        .methods
        .iter()
        .find(|m| m.name == "register")
        .unwrap();
    // "Its worst case is over 704 octets ... so the request may spill: at
    // most 2 capabilities, and it uses 1. It needs the grant right."
    assert!(register.request.may_spill && register.request.caps == 1);
    assert!(!register.local);
    assert!(c.layout.session_rights.grant && c.layout.session_rights.grant_reply);
    let watch = c.layout.methods.iter().find(|m| m.name == "watch").unwrap();
    assert_eq!(watch.stream.unwrap().kind, layout::StreamKind::Lossless);
    // change: 41-octet head, a 4-octet tail count, and publisher's 38.
    assert_eq!(watch.stream.unwrap().item_max, 41 + 4 + 38);
}

/// The whole front end, on mutations of every file: errors, never a panic
/// (ADR 0068, rule 5). Overflow checks are on in test builds.
#[test]
fn mutations_never_panic() {
    const OCTETS: &[u8] = b" \n@<>{}[](),.:;=?-_0123456789axz";
    const WORDS: &[&str] = &[
        "closed",
        "since(1.1)",
        "since(1.9)",
        "0xffffffffffffffffffff",
        "4294967295",
        "65535",
        "?",
        "u64",
        "cap<a.b/1>",
        "seq<u8, 99999999999>",
        "-1",
        "reserved",
        "stream<x>",
        "[oneway]",
        "error",
        "struct",
    ];
    let mut rng = common::Rng(0x0063_6865_636b);
    for p in common::idl_files() {
        let src = std::fs::read(&p).unwrap();
        for _ in 0..300 {
            let mut m = src.clone();
            let at = rng.below(m.len());
            match rng.below(3) {
                0 => m[at] = OCTETS[rng.below(OCTETS.len())],
                1 => {
                    let w = WORDS[rng.below(WORDS.len())].as_bytes();
                    m.splice(at..at, w.iter().copied());
                }
                _ => {
                    let end = (at + 1 + rng.below(40)).min(m.len());
                    m.drain(at..end);
                }
            }
            if let Ok(c) = common::check(&m) {
                // What passes projects and canonicalizes too.
                for minor in 0..=c.unit().version.minor {
                    let canon = idl::canon::canonical(&idl::project::project(c.file(), minor));
                    assert!(common::check(canon.as_bytes()).is_ok(), "{canon}");
                }
            }
        }
    }
}

/// A sequence's or an array's element encodes to at least one octet, so a
/// decoder's work follows the input's length, not a count the sender
/// picks.
#[test]
fn elements_take_at_least_one_octet() {
    for body in [
        "[closed] struct empty {}\n@1 take(xs: seq<empty, 4000000000>) -> u64;",
        "[closed] struct empty {}\n[closed] struct two { a: empty, b: empty }\nstruct s { xs: seq<two, 8> }",
        "[closed] struct empty {}\nalias many = array<empty, 4>;",
        "struct s { xs: seq<array<u8, 0>, 8> }",
    ] {
        refused(&iface(body), Code::Type);
    }
    // An optional empty element takes its presence octet; an open empty
    // struct takes its tail count.
    accepted(&iface(
        "[closed] struct empty {}\nstruct open_empty {}\nstruct s { a: seq<empty?, 8>, b: seq<open_empty, 8> }",
    ));
}

/// A chain of `n` structs, each the field of the next, ending in `u8`: the
/// last, `t{n-1}`, is `n` deep.
fn chain(n: usize, open: bool) -> String {
    let attr = if open { "" } else { "[closed] " };
    let mut body = format!("{attr}struct t0 {{ a: u8 }}\n");
    for i in 1..n {
        body += &format!("{attr}struct t{i} {{ a: t{} }}\n", i - 1);
    }
    body
}

/// Value depth is bounded through named types, not only within one type
/// expression ("Types", Limits): each value walker recurses once a level.
#[test]
fn values_nest_at_most_32_deep_through_named_types() {
    // 32 structs: t31 is 32 deep, and a method can't use it whole.
    accepted(&iface(&chain(32, true)));
    let c = accepted(&iface(&(chain(31, true) + "@1 m(a: t30) -> t30;")));
    assert_eq!(c.layout.methods.len(), 1);
    refused(&iface(&chain(33, true)), Code::Limit);
    refused(&iface(&(chain(32, true) + "@1 m(a: t31);")), Code::Limit);
    refused(
        &iface(&(chain(32, false) + "@1 m() -> (a: t31);")),
        Code::Limit,
    );
    // Through aliases and sequences too.
    let mut aliases = String::from("struct t0 { a: u8 }\n");
    for i in 1..40 {
        aliases += &format!("alias t{i} = t{};\n", i - 1);
    }
    refused(&iface(&aliases), Code::Limit);
    // u is 30 deep: its field `b: t28` is a level over t28's 29.
    let seqs = "alias s = seq<seq<seq<u8, 2>, 2>, 2>;\n".to_string()
        + &chain(29, true)
        + "struct u { a: s, b: t28 }\n";
    accepted(&iface(&(seqs.clone() + "union w { @1 a: seq<u, 2> }")));
    refused(
        &iface(&(seqs + "union w { @1 a: seq<seq<u, 2>, 2> }")),
        Code::Limit,
    );
    // An error's detail too.
    refused(
        &iface(&(chain(32, true) + "error e = 1 { a: t31 };")),
        Code::Limit,
    );
    // A chain far past the limit is refused without a deep stack.
    let long = std::thread::Builder::new()
        .stack_size(256 << 10)
        .spawn(|| codes(&iface(&chain(4000, false))))
        .unwrap()
        .join()
        .unwrap();
    assert!(long.contains(&Code::Limit), "{long:?}");
}

/// Every declared type is the top of its own rule, so its worst case is
/// bounded even when no method uses it.
#[test]
fn every_declared_type_fits_a_message() {
    // 2^20 × 16 octets: no message could hold it.
    refused(
        &iface("alias big = array<array<u8, 4096>, 4096>;\nalias huge = array<big, 2>;"),
        Code::Size,
    );
    accepted(&iface("alias big = array<array<u8, 4000>, 4000>;"));
    let mut doubling = String::from("[closed] struct t0 { a: u8, b: u8 }\n");
    for i in 1..26 {
        doubling += &format!("[closed] struct t{i} {{ a: t{}, b: t{} }}\n", i - 1, i - 1);
    }
    refused(&iface(&doubling), Code::Size);
}
