// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The compatibility check (ADR 0065, rule 13; docs/design/
//! call-language.md, "The compatibility check"): each change the note
//! allows passes, and each refused change fails with its named kind.

mod common;

use idl::{
    Limits,
    ast::File,
    compat::{Violation, step},
    parse::parse,
    project::project,
};

fn file(header: &str, body: &str) -> File {
    let src = format!(
        "edition 2026;\n[id(org.example.t), object_id(reserved(1)), {header}]\ninterface t {{\n{body}\n}}\n"
    );
    common::check(src.as_bytes()).unwrap_or_else(|d| panic!("{src}\n{d:#?}"));
    parse(src.as_bytes(), &Limits::default()).unwrap()
}

/// The step from a source's 1.0 to its 1.1, as idlc runs it.
fn within(body: &str) -> Vec<Violation> {
    let f = file("version(1.1), groups(a, b)", body);
    step(&project(&f, 0), &project(&f, 1))
}

/// The step between two sources: 1.0 and 1.1, as the catalog runs it.
fn between(prev: &str, next: &str) -> Vec<Violation> {
    step(&file("version(1.0)", prev), &file("version(1.1)", next))
}

#[test]
fn every_allowed_change_passes() {
    let body = "
        /// Docs may change freely.
        [group(a)] @1 m(x: u8, [since(1.1)] y: u16?) -> (r: u8, [since(1.1)] s: string<4>?) error(e, f);
        [since(1.1), group(a)] @2 added(q: s) -> u8;
        [since(1.1), group(b)] @3 in_a_new_group();
        error e = 1 { a: u8, [since(1.1)] b: u8? };
        [since(1.1)] error f = 2;
        struct s { a: u8, [since(1.1)] b: id? }
        union u { @1 a: u8, [since(1.1)] @2 b: s }
        enum e1: u8 { a = 1, [since(1.1)] b = 2 }
        flags f1: u16 { a = 1, [since(1.1)] b = 2 }
        [since(1.1)] const c: u32 = 4;
        [since(1.1)] alias al = string<c>;
        [since(1.1)] struct t2 { a: u8 }
        [deprecated(1.1)] struct old { a: u8 }
    ";
    assert_eq!(within(body), Vec::new());
    // A group that grows in a minor, and a header that gains a group.
    let v = step(
        &file("version(1.0), groups(a)", "[group(a)] @1 m();"),
        &file(
            "version(1.1), groups(a, b)",
            "[group(a)] @1 m();\n[since(1.1), group(a)] @2 n();\n[since(1.1), group(b)] @3 o();",
        ),
    );
    assert_eq!(v, Vec::new());
    // But a group may not be removed.
    let v = step(
        &file(
            "version(1.0), groups(a, b)",
            "[group(a)] @1 m();\n[group(b)] @2 n();",
        ),
        &file(
            "version(1.1), groups(a)",
            "[group(a)] @1 m();\n[group(a)] @2 n();",
        ),
    );
    assert!(v.iter().any(|v| v.kind == "removed"), "{v:?}");
}

#[track_caller]
fn refused(prev: &str, next: &str, kind: &str) {
    let v = between(prev, next);
    assert!(
        v.iter().any(|v| v.kind == kind),
        "expected {kind}, got {v:?}\n{prev}\n---\n{next}"
    );
}

#[test]
fn every_refused_change_fails() {
    // Removing, renaming and reordering.
    refused(
        "struct s { a: u8 }\nstruct t1 { a: u8 }",
        "struct t1 { a: u8 }",
        "removed",
    );
    refused(
        "struct s { a: u8 }\nstruct t1 { a: u8 }",
        "struct t1 { a: u8 }\nstruct s { a: u8 }",
        "reordered",
    );
    refused(
        "struct s { a: u8, b: u8 }",
        "struct s { a: u8, c: u8 }",
        "removed",
    );
    refused("@1 m();", "@1 n();", "removed");
    refused("reserved @2;\n@1 m();", "@1 m();\n@2 n();", "removed");
    // A head, a type, a bound or optionality.
    refused("struct s { a: u8 }", "struct s { a: u16 }", "changed");
    refused(
        "struct s { a: string<8> }",
        "struct s { a: string<9> }",
        "changed",
    );
    refused("struct s { a: u8? }", "struct s { a: u8 }", "changed");
    // New fields: optional, of this minor.
    refused(
        "struct s { a: u8 }",
        "struct s { a: u8, [since(1.1)] b: u8? }\nstruct x { a: u8, b: u8 }",
        "since",
    );
    refused(
        "@1 m(a: u8);",
        "@1 m(a: u8, [since(1.1)] b: u8?);\n@2 n();",
        "since",
    );
    // A closed type never changes.
    refused(
        "[closed] struct s { a: u8 }",
        "[closed] struct s { a: u8, b: u8 }",
        "closed",
    );
    refused(
        "[closed] enum e: u8 { a = 1 }",
        "[closed] enum e: u8 { a = 1, b = 2 }",
        "closed",
    );
    refused(
        "struct s { a: u8 }",
        "[closed] struct s { a: u8 }",
        "changed",
    );
    // Arms and values.
    refused(
        "union u { @1 a: u8, @2 b: u16 }",
        "union u { @1 a: u8 }",
        "changed",
    );
    refused(
        "union u { @1 a: u8 }",
        "union u { @1 a: u8, @2 b: u16 }",
        "since",
    );
    refused(
        "enum e: u8 { a = 1, b = 2 }",
        "enum e: u8 { a = 1, b = 3 }",
        "changed",
    );
    refused("enum e: u8 { a = 1 }", "enum e: u16 { a = 1 }", "changed");
    // New members need [since(1.1)].
    refused("@1 m();", "@1 m();\n@2 n();", "since");
    refused("", "struct s { a: u8 }", "since");
    // Methods: groups, attributes, numbers, results.
    refused("[idempotent] @1 m();", "@1 m();", "changed");
    refused("@1 m();", "[readonly] @1 m();", "changed");
    refused("@1 m();", "@2 m();", "changed");
    refused("@1 m() -> u8;", "@1 m() -> u16;", "changed");
    refused("@1 m() -> u8;", "@1 m();", "removed");
    refused("@1 m();", "@1 m() -> u8;", "required");
    refused(
        "@1 m(after: u64?) -> stream<s>;\nstruct s { a: u8 }",
        "@1 m(after: u64?);\nstruct s { a: u8 }",
        "changed",
    );
    refused(
        "@1 m(a: string<4>);",
        "@1 m([sensitive] a: string<4>);",
        "changed",
    );
    // Errors: code, outcome, and error lists.
    refused("error e = 1;", "error e = 2;", "changed");
    refused("error e = 1;", "[refused] error e = 1;", "changed");
    refused(
        "error e = 1;\n@1 m() error(e);",
        "error e = 1;\n@1 m();",
        "error-list",
    );
    refused(
        "error e = 1;\n@1 m();",
        "error e = 1;\n@1 m() error(e);",
        "error-list",
    );
}

#[test]
fn headers_and_use_lines() {
    let f0 = |h: &str| {
        parse(
            format!("edition 2026;\n{h}\ninterface t {{}}\n").as_bytes(),
            &Limits::default(),
        )
        .unwrap()
    };
    let prev = f0("[id(org.example.t), object_id(reserved(1)), version(1.0)]");
    let v = step(
        &prev,
        &f0("[id(org.example.t), object_id(reserved(1)), version(1.2)]"),
    );
    assert!(v.iter().any(|v| v.kind == "header"));
    let v = step(
        &prev,
        &f0("[id(org.example.t), object_id(reserved(2)), version(1.1)]"),
    );
    assert!(v.iter().any(|v| v.kind == "header"));
    let v = step(
        &prev,
        &f0("[id(org.example.t), object_id(reserved(1)), version(1.1), local]"),
    );
    assert!(v.iter().any(|v| v.kind == "header"));
    // `[kernel, local]` means `[kernel]`, which is how the canonical form
    // writes it: a stored canonical form beside the source steps cleanly.
    let src = "edition 2026;\n[id(org.example.t), object_id(reserved(1)), version(1.1), kernel, local]\ninterface t {\n@1 m();\n[since(1.1)] @2 n();\n}\n";
    let c = common::check(src.as_bytes()).unwrap();
    let stored = idl::canon::canonical(&project(c.file(), 0));
    assert!(!stored.contains("local"), "{stored}");
    let stored = parse(stored.as_bytes(), &Limits::default()).unwrap();
    assert_eq!(step(&stored, &project(c.file(), 1)), Vec::new());
    // Gaining or losing [kernel] still changes the header.
    let kernel = f0("[id(org.example.t), object_id(reserved(1)), version(1.1), kernel]");
    let v = step(&prev, &kernel);
    assert!(v.iter().any(|v| v.message.contains("kernel")), "{v:?}");
    let with_use = |u: &str, v: &str| {
        parse(
            format!("edition 2026;\n{u}[id(org.example.t), object_id(reserved(1)), version({v})]\ninterface t {{}}\n").as_bytes(),
            &Limits::default(),
        )
        .unwrap()
    };
    let one = "use org.example.base/1.{point};\n";
    assert_eq!(
        step(
            &with_use(one, "1.0"),
            &with_use(&format!("{one}use org.example.kinds/1.{{cell}};\n"), "1.1")
        ),
        Vec::new()
    );
    let v = step(
        &with_use(one, "1.0"),
        &with_use("use org.example.base/1.1.{point};\n", "1.1"),
    );
    assert!(v.iter().any(|v| v.kind == "use"), "{v:?}");
    // A name added to an existing line is an addition too.
    assert_eq!(
        step(
            &with_use(one, "1.0"),
            &with_use("use org.example.base/1.{point, pair};\n", "1.1"),
        ),
        Vec::new()
    );
    let v = step(
        &with_use(one, "1.0"),
        &with_use(
            "use org.example.base/1.1.{point};\nuse org.example.base/1.{pair};\n",
            "1.1",
        ),
    );
    assert!(v.iter().any(|v| v.kind == "use"), "{v:?}");
    let v = step(&with_use(one, "1.0"), &with_use("", "1.1"));
    assert!(v.iter().any(|v| v.kind == "use"), "{v:?}");
}

/// An import a later minor adds, as a new line or a new name on an
/// existing one, leaves the earlier minor's canonical form and hash as
/// they were: projection drops the imported names a minor doesn't use.
#[test]
fn a_later_minor_may_import_more() {
    let v1_0 = "edition 2026;
use org.example.base/1.0.{point};
[id(org.example.t), object_id(reserved(1)), version(1.0)]
interface t {
    struct s { p: point }
    @1 f(x: s);
}
";
    let c1_0 = common::check(v1_0.as_bytes()).unwrap();
    let published = idl::generate::minor_hash(&c1_0, 0);
    let grammars = |c: &idl::Checked| {
        let s = idl::schema::Schema::new(c, 0);
        (idl::abnf_gen::wire(&s, ""), idl::abnf_gen::text(&s, ""))
    };
    let published_grammars = grammars(&c1_0);
    assert!(published_grammars.0.contains("u1--t-point"));
    let source = |uses: &str| {
        let q = if uses.contains("pair") {
            ", q: pair?"
        } else {
            ""
        };
        format!(
            "edition 2026;
{uses}[id(org.example.t), object_id(reserved(1)), version(1.1)]
interface t {{
    struct s {{ p: point }}
    [since(1.1)] struct newer {{ e: extra{q} }}
    @1 f(x: s);
    [since(1.1)] @2 g(n: newer);
}}
"
        )
    };
    for uses in [
        "use org.example.base/1.0.{point};\nuse org.example.base/1.1.{extra};\n",
        "use org.example.base/1.0.{point, pair};\nuse org.example.base/1.1.{extra};\n",
        // A new line first: 1.0's grammar is still the published one, but
        // the step refuses it, so 1.1 keeps 1.0's u1.
        "use org.example.base/1.1.{extra};\nuse org.example.base/1.0.{point};\n",
    ] {
        let src = source(uses);
        let c = common::check(src.as_bytes()).unwrap_or_else(|d| panic!("{src}\n{d:#?}"));
        assert_eq!(idl::generate::minor_hash(&c, 0), published, "{src}");
        assert_eq!(grammars(&c), published_grammars, "{src}");
        let v = step(&project(c.file(), 0), &project(c.file(), 1));
        if uses.starts_with("use org.example.base/1.1") {
            assert_eq!(
                v.iter().map(|x| x.kind).collect::<Vec<_>>(),
                ["use"],
                "{src}"
            );
        } else {
            assert_eq!(v, Vec::new(), "{src}");
        }
        // The projection to 1.0 is itself a valid file, with its imports.
        let back = idl::canon::canonical(&project(c.file(), 0));
        common::check(back.as_bytes()).unwrap_or_else(|d| panic!("{back}\n{d:#?}"));
        assert!(!back.contains("extra"), "{back}");
    }
}

/// An unused import, added or removed, never renames a published
/// grammar's rules: imports are numbered by their places in the minor's
/// projected file, which the lock's hash covers.
#[test]
fn unused_imports_never_rename_rules() {
    let src = |extra: &str| {
        format!(
            "edition 2026;
{extra}use org.example.base/1.0.{{point}};
[id(org.example.t), object_id(reserved(1)), version(1.0)]
interface t {{
    struct s {{ p: point }}
    @1 f(x: s);
}}
"
        )
    };
    let wire = |text: String| {
        let c = common::check(text.as_bytes()).unwrap_or_else(|d| panic!("{text}\n{d:#?}"));
        idl::abnf_gen::wire(&idl::schema::Schema::new(&c, 0), "")
    };
    let plain = wire(src(""));
    assert!(plain.contains("u1--t-point"), "{plain}");
    assert_eq!(wire(src("use org.example.base/1.1.{extra};\n")), plain);
}

/// A `use` line the minor doesn't use takes no place in the numbering,
/// even when it names the unit a used line reaches through an import:
/// adding it last, or removing it, never renames `u1--u1--` rules. The
/// review's counterexample: `mid` imports `base/1.0`, and the new last
/// line names `base/1.0` too.
#[test]
fn an_unused_line_never_takes_a_transitive_unit() {
    const MID: &str = "edition 2026;
use org.example.base/1.0.{point};
[id(org.example.mid), object_id(reserved(7)), version(1.0)]
interface mid {
    struct m { p: point }
    @1 f(x: m);
}
";
    let check = |src: &str| {
        let mut roots = common::resolver();
        let mut r = |r: &idl_rt::names::InterfaceRef<'_>| {
            if r.name == "org.example.mid" {
                Some(MID.as_bytes().to_vec())
            } else {
                roots(r)
            }
        };
        idl::check(src.as_bytes(), &mut r, &Limits::default())
            .unwrap_or_else(|d| panic!("{src}\n{d:#?}"))
    };
    let grammars = |c: &idl::Checked| {
        let s = idl::schema::Schema::new(c, 0);
        (idl::abnf_gen::wire(&s, ""), idl::abnf_gen::text(&s, ""))
    };
    let published = check(
        "edition 2026;
use org.example.mid/1.0.{m};
[id(org.example.t), object_id(reserved(1)), version(1.0)]
interface t {
    struct s { q: m }
    @1 f(x: s);
}
",
    );
    let published_grammars = grammars(&published);
    assert!(
        published_grammars.0.contains("u1--r-m = u1--u1--r-point"),
        "{}",
        published_grammars.0
    );
    let source = |last: &str, extra: &str| {
        format!(
            "edition 2026;
use org.example.mid/1.0.{{m}};
{last}[id(org.example.t), object_id(reserved(1)), version(1.1)]
interface t {{
    struct s {{ q: m }}
    {extra}@1 f(x: s);
}}
"
        )
    };
    let later = "[since(1.1)] struct newer { e: pair }\n    [since(1.1)] @2 g(n: newer);\n    ";
    // Each case's last line, the members that use it, and how the Rust
    // binding re-exports `pair`, at the version.
    for (last, extra, pair) in [
        // A new last line, used by 1.1: the same unit as mid's import, and
        // another minor of it. At 1.1 the line has its own place.
        ("use org.example.base/1.0.{pair};\n", later, Some("u2")),
        ("use org.example.base/1.1.{pair};\n", later, Some("u2")),
        // A line no minor uses: the same unit, which mid's import reaches,
        // and another minor, which nothing reaches.
        ("use org.example.base/1.0.{pair};\n", "", Some("u1::u1")),
        ("use org.example.base/1.1.{pair};\n", "", None),
    ] {
        let src = source(last, extra);
        let c = check(&src);
        assert_eq!(
            idl::generate::minor_hash(&c, 0),
            idl::generate::minor_hash(&published, 0),
            "{src}"
        );
        assert_eq!(
            step(&project(c.file(), 0), &project(c.file(), 1)),
            Vec::new(),
            "{src}"
        );
        assert_eq!(grammars(&c), published_grammars, "{src}");
        let rust = idl::rust::generate(&c, idl::rust::Flavor::Crate, "v1", "v1.idl", &[]);
        assert!(rust.contains("pub use u1::M;"), "{rust}");
        match pair {
            Some(path) => assert!(rust.contains(&format!("pub use {path}::Pair;")), "{rust}"),
            None => assert!(!rust.contains("::Pair;"), "{rust}"),
        }
    }
}

/// A method with no results may gain a first optional one in a minor
/// (rule 2): its results are an open struct with no fields. The earlier
/// minor's canonical form is the one it had, and parses back.
#[test]
fn a_first_optional_result_may_come_in_a_minor() {
    for (before, after) in [
        ("@1 m();", "@1 m() -> ([since(1.1)] extra: u16?);"),
        (
            "@1 m(after: u64?) -> stream<s>;\nstruct s { a: u8 }",
            "@1 m(after: u64?) -> ([since(1.1)] x: u16?) stream<s>;\nstruct s { a: u8 }",
        ),
    ] {
        let src = |v: &str, body: &str| {
            format!(
                "edition 2026;\n[id(org.example.t), object_id(reserved(1)), version({v})]\ninterface t {{\n{body}\n}}\n"
            )
        };
        let old = common::check(src("1.0", before).as_bytes()).unwrap();
        let new = common::check(src("1.1", after).as_bytes()).unwrap();
        assert_eq!(
            idl::generate::minor_hash(&new, 0),
            idl::generate::minor_hash(&old, 0),
            "{after}"
        );
        let canon = idl::canon::canonical(&project(new.file(), 0));
        common::check(canon.as_bytes()).unwrap_or_else(|d| panic!("{canon}\n{d:#?}"));
        assert_eq!(
            step(&project(new.file(), 0), &project(new.file(), 1)),
            Vec::new(),
            "{after}"
        );
        assert_eq!(between(before, after), Vec::new(), "{after}");
        idl::fuzz::front_end(src("1.1", after).as_bytes());
    }
}

/// Every repository file's minors step cleanly.
#[test]
fn every_file_steps() {
    for p in common::idl_files() {
        let c = common::check_file(&p);
        for m in 1..=c.unit().version.minor {
            let v = step(&project(c.file(), m - 1), &project(c.file(), m));
            assert_eq!(
                v,
                Vec::new(),
                "{} {}.{m}",
                p.display(),
                c.unit().version.major
            );
        }
    }
}

/// Adding or removing `[nonzero]` on an existing field changes which
/// values are valid, so a later minor may do neither. A new field may
/// carry it.
#[test]
fn nonzero_never_changes_on_an_existing_field() {
    for (prev, next) in [
        ("struct s { a: u8 }", "struct s { [nonzero] a: u8 }"),
        ("struct s { [nonzero] a: u8 }", "struct s { a: u8 }"),
        (
            "struct s { a: u8, b: u32? }",
            "struct s { a: u8, [nonzero] b: u32? }",
        ),
        (
            "[closed] struct s { a: i16 }",
            "[closed] struct s { [nonzero] a: i16 }",
        ),
        (
            "error e = 1 { n: u32 };",
            "error e = 1 { [nonzero] n: u32 };",
        ),
        ("@1 m(a: u16);", "@1 m([nonzero] a: u16);"),
        ("@1 m() -> (r: u64);", "@1 m() -> ([nonzero] r: u64);"),
        (
            "@1 m([nonzero] a: u16) -> ([nonzero] r: u64);",
            "@1 m(a: u16) -> (r: u64);",
        ),
    ] {
        refused(prev, next, "changed");
    }
    assert_eq!(
        within(
            "struct s { [nonzero] a: u8, [since(1.1), nonzero] b: u16? }\n\
             [group(a)] @1 m([nonzero] a: u8, [since(1.1), nonzero] b: u32?);\n\
             [group(b)] @2 n();"
        ),
        Vec::new()
    );
}
