// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The doc model (docs/design/call-language.md, "Doc comments"; L32): its
//! blocks and inlines, the checker's rule for cross-references, the
//! rustdoc the Rust back end writes, and its robustness.

mod common;

use idl::{
    Code,
    doc::{self, Block, Inline, ItemKind, XRef},
};

fn lines(text: &str) -> Vec<String> {
    text.lines().map(|l| format!(" {l}")).collect()
}

fn xref(interface: &str, major: u16, path: &[&str]) -> Inline {
    Inline::XRef(XRef {
        interface: interface.into(),
        major,
        path: path.iter().map(|p| (*p).into()).collect(),
    })
}

#[test]
fn blocks() {
    let d = doc::parse(&lines(
        "First paragraph,\n\
         on two lines.\n\
         \n\
         - one\n\
         - two,\n\
         \x20 continued\n\
         \n\
         1. first\n\
         2. second\n\
         \n\
         ```rust\n\
         let x = [a.b/1];\n\
         \n\
         ```\n\
         Last.",
    ));
    assert_eq!(
        d.blocks,
        vec![
            Block::Paragraph(vec![Inline::Text("First paragraph, on two lines.".into())]),
            Block::List {
                ordered: false,
                items: vec![
                    vec![Inline::Text("one".into())],
                    vec![Inline::Text("two, continued".into())],
                ],
            },
            Block::List {
                ordered: true,
                items: vec![
                    vec![Inline::Text("first".into())],
                    vec![Inline::Text("second".into())],
                ],
            },
            Block::Code {
                info: "rust".into(),
                text: "let x = [a.b/1];\n\n".into(),
            },
            Block::Paragraph(vec![Inline::Text("Last.".into())]),
        ]
    );
}

#[test]
fn inlines() {
    let d = doc::parse(&lines(
        "See [aspis.catalog/1.watch], [aspis.catalog/1], `code [x.y/1]`, \
         [the note](https://example.org/a), <https://example.org/b>, \
         [sensitive], [x.y/01], [x.y/1.A] and [x.y/1.a.b.c].",
    ));
    let [Block::Paragraph(p)] = &d.blocks[..] else {
        panic!("{:?}", d.blocks)
    };
    assert_eq!(
        p,
        &vec![
            Inline::Text("See ".into()),
            xref("aspis.catalog", 1, &["watch"]),
            Inline::Text(", ".into()),
            xref("aspis.catalog", 1, &[]),
            Inline::Text(", ".into()),
            Inline::Code("code [x.y/1]".into()),
            Inline::Text(", ".into()),
            Inline::Link {
                text: "the note".into(),
                url: "https://example.org/a".into()
            },
            Inline::Text(", ".into()),
            Inline::Link {
                text: "https://example.org/b".into(),
                url: "https://example.org/b".into()
            },
            // Not cross-references: an attribute, a leading zero, an
            // uppercase member, a path three deep.
            Inline::Text(", [sensitive], [x.y/01], [x.y/1.A] and [x.y/1.a.b.c].".into()),
        ]
    );
}

#[test]
fn unrecognized_syntax_stays_text() {
    for text in [
        "an unclosed `code span",
        "[unclosed",
        "[a](no close",
        "<not a link>",
        "``` unclosed fence\ninside",
        "* \n-\n1.\n   \n",
        "[[x.y/1]]",
        "\u{1F600} [x.y/1.\u{e9}]",
    ] {
        // Never panics, and keeps every non-space character of the text.
        let d = doc::parse(&lines(text));
        let mut kept = String::new();
        for b in &d.blocks {
            match b {
                Block::Paragraph(p) => p.iter().for_each(|i| push(&mut kept, i)),
                Block::List { items, .. } => {
                    items.iter().flatten().for_each(|i| push(&mut kept, i))
                }
                Block::Code { info, text } => {
                    kept.push_str(info);
                    kept.push_str(text);
                }
            }
        }
        let squash = |s: &str| {
            s.chars()
                .filter(|c| !c.is_whitespace() && !"*-.1`".contains(*c))
                .collect::<String>()
        };
        assert_eq!(squash(&kept), squash(text), "{text:?}");
    }
}

fn push(out: &mut String, i: &Inline) {
    match i {
        Inline::Text(t) | Inline::Code(t) => out.push_str(t),
        Inline::Link { text, url } if text == url => out.push_str(&format!("<{url}>")),
        Inline::Link { text, url } => out.push_str(&format!("[{text}]({url})")),
        Inline::XRef(x) => out.push_str(&format!("[{x}]")),
    }
}

#[test]
fn the_model_of_a_fixture() {
    let c = common::check_file(
        &common::repo().join("crates/idl/tests/data/interfaces/org/example/kinds/v1.idl"),
    );
    let m = doc::model(&c);
    assert_eq!((m.interface.as_str(), m.major), ("org.example.kinds", 1));
    assert!(matches!(&m.file.blocks[..], [Block::Paragraph(_)]));
    assert_eq!(m.items[0].kind, ItemKind::Interface);
    let item = |path: &[&str]| {
        m.items
            .iter()
            .find(|i| i.path == path)
            .unwrap_or_else(|| panic!("{path:?}"))
    };
    assert_eq!(item(&["thing"]).kind, ItemKind::Struct);
    assert_eq!(item(&["thing", "key"]).kind, ItemKind::Field);
    assert_eq!(item(&["get"]).kind, ItemKind::Method);
    assert_eq!(item(&["get", "secret"]).kind, ItemKind::Param);
    assert_eq!(item(&["get", "result"]).kind, ItemKind::Result);
    assert_eq!(item(&["put", "at"]).kind, ItemKind::Result);
    assert_eq!(item(&["event", "moved"]).kind, ItemKind::Arm);
    assert_eq!(item(&["level", "top"]).kind, ItemKind::Value);
    assert_eq!(item(&["wide"]).kind, ItemKind::Flags);
    assert_eq!(item(&["gone", "why"]).kind, ItemKind::Field);
    let refs: Vec<String> = doc::xrefs(&item(&["thing"]).doc)
        .iter()
        .map(|x| x.to_string())
        .collect();
    assert_eq!(
        refs,
        [
            "org.example.kinds/1.get",
            "org.example.kinds/1.put.item",
            "org.example.base/1.point",
            "aspis.catalog/1.list",
        ]
    );
    // Every member of every file has an item, documented or not.
    for p in common::idl_files() {
        let c = common::check_file(&p);
        let m = doc::model(&c);
        let named = c
            .file()
            .interface
            .members
            .iter()
            .filter(|x| x.name().is_some())
            .count();
        assert!(m.items.iter().filter(|i| i.path.len() == 1).count() == named);
    }
}

/// A file with one doc comment.
fn with_doc(doc: &str) -> String {
    format!(
        "edition 2026;\n\
         use org.example.base/1.0.{{point}};\n\
         [id(org.example.d), object_id(reserved(9)), version(1.0)]\n\
         interface d {{\n\
         /// {doc}\n\
         struct s {{ a: u8, p: point }}\n\
         enum e: u8 {{ x = 1 }}\n\
         error bad = 1 {{ why: u8 }};\n\
         @1 m(a: u8) -> (b: u8);\n\
         @2 n() -> u8;\n\
         }}\n"
    )
}

#[test]
fn cross_references_into_known_interfaces_must_resolve() {
    for good in [
        "[org.example.d/1]",
        "[org.example.d/1.s]",
        "[org.example.d/1.s.a]",
        "[org.example.d/1.e.x]",
        "[org.example.d/1.bad.why]",
        "[org.example.d/1.m.a]",
        "[org.example.d/1.m.b]",
        "[org.example.d/1.n.result]",
        "[org.example.base/1.point.x]",
        "[org.example.base/1.ping]",
        // Not this interface's major, nor an import: not checked.
        "[org.example.d/2.nothing]",
        "[org.example.other/1.nothing]",
        "`[org.example.d/1.nothing]`, in code",
    ] {
        common::check(with_doc(good).as_bytes()).unwrap_or_else(|d| panic!("{good}: {d:#?}"));
    }
    for bad in [
        "[org.example.d/1.nothing]",
        "[org.example.d/1.s.b]",
        "[org.example.d/1.m.result]",
        "[org.example.d/1.e.y]",
        // The import is read at its use line's minor, 1.0, and z came in
        // 1.1.
        "[org.example.base/1.point.z]",
    ] {
        let d = common::check(with_doc(bad).as_bytes()).expect_err(bad);
        assert!(d.iter().all(|d| d.code == Code::Doc), "{bad}: {d:#?}");
    }
}

#[test]
fn rustdoc_writes_cross_references_as_code() {
    let src = lines(
        "Reads [aspis.catalog/1.watch], not [sensitive].\n\
         ```\n\
         [aspis.catalog/1.watch]\n\
         ```\n\
         `[x.y/1]` stays.",
    );
    let out = doc::rustdoc(&src);
    assert_eq!(
        out,
        [
            " Reads `aspis.catalog/1.watch`, not [sensitive].",
            " ```",
            " [aspis.catalog/1.watch]",
            " ```",
            " `[x.y/1]` stays.",
        ]
    );
    // A comment with no cross-reference is unchanged.
    let plain = lines("Plain.\n\n- a list");
    assert_eq!(doc::rustdoc(&plain), plain);
}

#[test]
fn work_is_bounded() {
    // Long runs of the characters the scanner looks at, and many lines.
    for unit in ["[", "`", "<", "[a.b/1", "](", "- ", "```\n"] {
        let text = unit.repeat(20_000);
        let d = doc::parse(&lines(&text));
        drop(d);
        doc::rustdoc(&lines(&text));
    }
    // Backtick runs of every length, none closed: a naive scan for each
    // run's closing run would be quadratic.
    let runs: String = (1..1500).map(|n| "`".repeat(n) + "a").collect();
    let t = std::time::Instant::now();
    doc::parse(&[runs]);
    assert!(t.elapsed().as_secs() < 5, "{:?}", t.elapsed());
}
