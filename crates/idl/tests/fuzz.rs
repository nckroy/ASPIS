// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Replays of crates/idl's fuzz entry functions (ADR 0068, rule 4: "seeds
//! include every vector line"; docs/design/call-language.md, "Per
//! change"): the front end over every `idl.vectors` line, every IDL file,
//! every canonical form and mutations of each; and the structured value
//! generator, whose every output must encode to a message its rule and
//! its generated grammar accept. Each runs under plain `cargo test`, with
//! no fuzz engine.

mod common;

use std::fs;

use abnf::{Context, Grammar, Kind, LoadOptions};
use common::Rng;
use idl::{fuzz, generate, schema::Schema, value, vectors::escape};

#[test]
fn the_front_end_over_every_vector_and_file() {
    let text = fs::read(common::repo().join("grammars/idl.vectors")).unwrap();
    let file = abnf::vectors::parse(&text).unwrap();
    for v in &file.vectors {
        fuzz::front_end(&v.octets);
    }
    let mut seeds = 0;
    for p in common::idl_files() {
        let src = fs::read(&p).unwrap();
        let mut r = common::resolver();
        fuzz::front_end_with(&src, &mut r);
        fuzz::front_end(&src);
        let c = common::check_file(&p);
        for m in 0..=c.unit().version.minor {
            let canon = generate::canonical(&c, m);
            fuzz::front_end_with(canon.as_bytes(), &mut r);
        }
        // Mutations: one octet deleted, inserted or replaced.
        let mut rng = Rng(src.len() as u64);
        for _ in 0..300 {
            let mut m = src.clone();
            let at = rng.below(m.len());
            match rng.below(3) {
                0 => {
                    m.remove(at);
                }
                1 => {
                    let set = b" {}();:,<>?@[]/.\n0azZ_";
                    m.insert(at, set[rng.below(set.len())]);
                }
                _ => m[at] = rng.next() as u8,
            }
            fuzz::front_end_with(&m, &mut r);
            seeds += 1;
        }
    }
    assert!(seeds > 1000, "{seeds}");
}

fn load(path: &std::path::Path) -> Option<Grammar> {
    let text = fs::read(path).ok()?;
    let mut shared =
        |name: &str| fs::read(common::repo().join(format!("grammars/{name}.abnf"))).ok();
    let opts = LoadOptions {
        kind: Kind::Strict,
        ..LoadOptions::default()
    };
    Some(Grammar::load("generated", &text, &mut shared, &opts).unwrap())
}

#[test]
fn generated_values_encode_to_valid_messages() {
    let mut made = 0;
    for p in common::idl_files() {
        let c = common::check_file(&p);
        let major = c.unit().major();
        for m in 0..=c.unit().version.minor {
            let s = Schema::new(&c, m);
            let g = load(&p.with_file_name(format!("v{major}.{m}.abnf")));
            let mut rng = Rng(u64::from(m) << 32 | p.as_os_str().len() as u64);
            for top in s.tops() {
                let rule = s.top_rule(top);
                for k in 0..48 {
                    // The empty input, then inputs of growing length.
                    let data: Vec<u8> = (0..k * 8).map(|_| rng.next() as u8).collect();
                    let v = fuzz::generate(&s, top, &data).expect("within the budget");
                    let enc = value::encode(&s, top, &v, true);
                    let at = || format!("{} {rule} at 1.{m}: {}", p.display(), escape(&enc.octets));
                    let d = value::decode(&s, top, &enc.octets, enc.caps)
                        .unwrap_or_else(|e| panic!("{}: {e:?}", at()));
                    let again = value::encode(&s, top, &d.value, false);
                    assert_eq!(again.octets, enc.octets, "{}", at());
                    if let Some(g) = &g {
                        let r = g.rule(&rule).unwrap();
                        let cx = Context {
                            caps: enc.caps,
                            unwrapped: 0,
                        };
                        assert_eq!(
                            g.matches_constrained(r, &enc.octets, &cx),
                            Ok(true),
                            "{}",
                            at()
                        );
                    }
                    made += 1;
                }
            }
        }
    }
    eprintln!("{made} generated values");
    assert!(made > 5000, "{made}");
}

#[test]
fn the_generator_is_deterministic_and_bounded() {
    let p = common::repo().join("crates/idl/tests/data/interfaces/org/example/kinds/v1.idl");
    let c = common::check_file(&p);
    let s = Schema::new(&c, 2);
    let data = vec![0xFFu8; 1 << 16];
    for top in s.tops() {
        let a = fuzz::generate(&s, top, &data).expect("within the budget");
        assert_eq!(Some(&a), fuzz::generate(&s, top, &data).as_ref());
        // All-ones input asks for the most of everything; the budget
        // keeps the message small.
        let enc = value::encode(&s, top, &a, true);
        assert!(enc.octets.len() < 64 << 10, "{}", s.top_rule(top));
    }
}

/// The front end visits a bounded number of minors, so its work doesn't
/// grow with the minor a file declares ("The gate for each target", items
/// 1 and 6).
#[test]
fn the_front_end_visits_a_bounded_number_of_minors() {
    let file = |version: &str, body: &str| {
        format!(
            "edition 2026;\n[id(org.example.y), object_id(reserved(0x0301)), version({version})]\ninterface y {{\n{body}}}\n"
        )
    };
    // The seed in grammars/idl.vectors: one method, version 1.1023, the
    // highest minor a file may declare.
    let src = file("1.1023", "    @1 m() -> (a: u8);\n");
    let c = common::check(src.as_bytes()).unwrap();
    assert_eq!(fuzz::minors(&c), [0, 1022, 1023]);
    let start = std::time::Instant::now();
    fuzz::front_end(src.as_bytes());
    assert!(start.elapsed().as_millis() < 2000, "{:?}", start.elapsed());
    // 1023 minors that each add a field: the lowest and highest few, each
    // with the minor before it.
    let mut body = String::from("    struct s {\n        a: u8,\n");
    for k in 1..=1023 {
        body += &format!("        [since(1.{k})] f{k}: u8?,\n");
    }
    body += "    }\n    @1 m(a: s);\n";
    let src = file("1.1023", &body);
    let c = common::check(src.as_bytes()).unwrap();
    let m = fuzz::minors(&c);
    assert_eq!(m, [0, 1, 2, 3, 4, 1019, 1020, 1021, 1022, 1023], "{m:?}");
    fuzz::front_end(src.as_bytes());
    // A file with few changes visits each, and the minor before it.
    let src = file(
        "1.9",
        "    @1 m();\n    [since(1.3)] @2 n();\n    [since(1.4), deprecated(1.7)] @3 o();\n",
    );
    let c = common::check(src.as_bytes()).unwrap();
    assert_eq!(fuzz::minors(&c), [0, 2, 3, 4, 6, 7, 8, 9]);
}

/// The generator makes at most `fuzz::MAX_VALUES` values for a message,
/// struct slots included. A fixed-size array, or a required field, takes
/// its full count whatever the input, so a type the checker accepts can
/// have a smallest value of millions: such a rule gets None, quickly.
#[test]
fn the_generator_has_a_hard_cap() {
    let mut body = String::from("    [closed] struct t0 { a: u8, b: u8 }\n");
    for i in 1..23 {
        body += &format!(
            "    [closed] struct t{i} {{ a: t{}, b: t{} }}\n",
            i - 1,
            i - 1
        );
    }
    body += "    alias big = array<array<u8, 4000>, 4000>;\n";
    let fields: Vec<String> = (0..4000).map(|i| format!("f{i}: u8")).collect();
    body += &format!("    struct row {{ {} }}\n", fields.join(", "));
    let rows: Vec<String> = (0..4000).map(|i| format!("r{i}: row")).collect();
    body += &format!("    struct rows {{ {} }}\n", rows.join(", "));
    body += "    @1 m(a: u8) -> u8;\n";
    let src = format!(
        "edition 2026;\n[id(org.example.y), object_id(reserved(0x0301)), version(1.0)]\ninterface y {{\n{body}}}\n"
    );
    let c = common::check(src.as_bytes()).unwrap();
    let s = Schema::new(&c, 0);
    let start = std::time::Instant::now();
    let data = vec![0xFFu8; 4096];
    let mut got = std::collections::BTreeMap::new();
    for top in s.tops() {
        got.insert(s.top_rule(top), fuzz::generate(&s, top, &data).is_some());
    }
    for rule in ["t-t22", "t-big", "t-rows"] {
        assert_eq!(got.get(rule), Some(&false), "{rule}");
    }
    for rule in ["t-t0", "t-t10", "t-row", "m-m--req"] {
        assert_eq!(got.get(rule), Some(&true), "{rule}");
    }
    assert!(start.elapsed().as_secs() < 10, "{:?}", start.elapsed());
}

/// A file within the source limit whose canonical form is over it: the
/// form writes out every tag (`@200 f199: u32`), so a dense file of
/// structs grows by about a third. The checker refuses it with
/// `Code::Limit`, so the front end never checks a form over the limit.
/// Found by C71's `idl-front-end` tests, when the front end panicked on
/// the form; `tests/check.rs` holds the rule at a small limit.
#[test]
fn a_canonical_form_over_the_source_limit_is_refused() {
    let limit = idl::Limits::default().source;
    let mut body = String::new();
    let mut k = 0;
    while body.len() + 2400 < limit - 200 {
        body += &format!("    struct s{k} {{ ");
        for f in 0..200 {
            body += &format!("f{f}: u32, ");
        }
        body += "}\n";
        k += 1;
    }
    let src = format!(
        "edition 2026;\n[id(org.example.y), object_id(reserved(0x0301)), version(1.0)]\ninterface y {{\n{body}}}\n"
    );
    assert!(src.len() <= limit, "{}", src.len());
    let d = idl::check(src.as_bytes(), &mut |_: &_| None, &idl::Limits::default()).unwrap_err();
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].code, idl::Code::Limit);
    assert!(d[0].message.contains("canonical form"), "{}", d[0]);
    fuzz::front_end(src.as_bytes());
}

/// The inputs of C71's coverage review of `idl-front-end`: a stream
/// method whose `after` or item is newer than it, a second `use` line
/// that names a type its interface lacks, and a closed enum with no
/// value. The checker refuses each; the front end never panics on them,
/// and keeps its properties on the files next to them that it accepts.
#[test]
fn the_coverage_reviews_inputs() {
    let file = |head: &str, version: &str, body: &str| {
        format!(
            "edition 2026;\n{head}[id(org.example.t), object_id(reserved(1)), version({version})]\ninterface t {{\n{body}\n}}\n"
        )
    };
    let cases = [
        (
            file(
                "",
                "1.1",
                "struct ev { a: u8 }\n@1 w([since(1.1)] after: u64?) -> stream<ev>;",
            ),
            false,
        ),
        (
            file(
                "",
                "1.1",
                "[since(1.1)] struct ev { a: u8 }\n@1 w(after: u64?) -> stream<ev>;",
            ),
            false,
        ),
        (
            file(
                "",
                "1.2",
                "[since(1.1)] struct ev { a: u8, [since(1.2)] b: u8? }\n[since(1.1)] @1 w([since(1.1)] after: u64?) -> stream<ev>;",
            ),
            true,
        ),
        (
            file(
                "use org.example.base/1.0.{point};\nuse org.example.base/1.0.{nosuch};\n",
                "1.0",
                "struct s { a: point }",
            ),
            false,
        ),
        (
            file(
                "use org.example.base/1.0.{point};\nuse org.example.base/1.{pair};\n",
                "1.1",
                "struct s { a: point, [since(1.1)] b: pair? }",
            ),
            true,
        ),
        (
            file(
                "",
                "1.0",
                "[closed] enum e: u8 { reserved 1 }\n@1 m(x: e) -> u8;",
            ),
            false,
        ),
        (
            file(
                "",
                "1.0",
                "[closed] flags f: u8 { reserved 1 }\n@1 m(x: f) -> f;",
            ),
            true,
        ),
    ];
    for (src, ok) in &cases {
        fuzz::front_end_with(src.as_bytes(), &mut common::resolver());
        let checked = common::check(src.as_bytes()).map(|_| ());
        assert_eq!(checked.is_ok(), *ok, "{src}\n{checked:?}");
    }
}
