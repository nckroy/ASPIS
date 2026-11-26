// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The dynamic value model (docs/design/call-language.md, "Rules for
//! readers", "Refusing what is too new", "The JSON mapping"): round trips
//! of every committed ok vector, rejection of every err and errc vector,
//! and the readings a strict and a tolerant decoder give at each minor.

mod common;

use std::{collections::BTreeMap, fs, path::Path};

use abnf::vectors::{self, Tag};
use idl::{
    Checked,
    model::TypeId,
    schema::{Mode, Schema, Top},
    value::{self, DecodeError, Fields, Value},
};
use idl_rt::json::JsonWriter;

fn tops(s: &Schema<'_>) -> BTreeMap<String, Top> {
    s.tops().into_iter().map(|t| (s.top_rule(t), t)).collect()
}

fn member(c: &Checked, name: &str) -> usize {
    c.unit()
        .members()
        .iter()
        .position(|m| m.name().is_some_and(|n| n.name == name))
        .unwrap()
}

fn type_id(c: &Checked, name: &str) -> TypeId {
    TypeId {
        unit: c.root,
        member: member(c, name),
    }
}

fn file(path: &str) -> Checked {
    common::check_file(&common::repo().join(path))
}

const KINDS: &str = "crates/idl/tests/data/interfaces/org/example/kinds/v1.idl";

/// Every ok vector of every generated wire grammar decodes and re-encodes
/// to its own octets; every err and errc vector is rejected.
#[test]
fn every_committed_vector() {
    let mut n = 0;
    for p in common::idl_files() {
        let c = common::check_file(&p);
        let dir = p.parent().unwrap();
        for m in 0..=c.unit().version.minor {
            let path = dir.join(format!("v{}.{m}.vectors", c.unit().major()));
            if !path.exists() {
                assert!(c.unit().is_kernel(), "{}", path.display());
                continue;
            }
            let s = Schema::new(&c, m);
            let tops = tops(&s);
            let vf = vectors::parse(&fs::read(&path).unwrap()).unwrap();
            for v in &vf.vectors {
                let top = tops[&v.rule];
                let got = value::decode(&s, top, &v.octets, v.caps);
                let at = format!("{}:{}", path.display(), v.line);
                match v.tag {
                    Tag::Ok => {
                        let d = got.unwrap_or_else(|e| panic!("{at}: {e:?}"));
                        let again = value::encode(&s, top, &d.value, false);
                        assert_eq!(again.octets, v.octets, "{at}");
                        assert_eq!(again.caps, v.caps, "{at}");
                    }
                    Tag::Err | Tag::Errc => assert!(got.is_err(), "{at}"),
                }
                n += 1;
            }
        }
    }
    assert!(n > 1000, "{n} vectors");
}

fn tail(fields: &[(u16, &[u8])]) -> Vec<u8> {
    let mut out = (fields.len() as u32).to_be_bytes().to_vec();
    for (tag, v) in fields {
        out.extend(tag.to_be_bytes());
        out.extend((v.len() as u32).to_be_bytes());
        out.extend(*v);
    }
    out
}

/// A request field newer than the minor is `field_too_new`, with its tags;
/// the same octets are fine at the minor that added it.
#[test]
fn a_newer_field_in_a_request() {
    let c = file("interfaces/aspis/catalog/v1.idl");
    let register = member(&c, "register");
    let mut msg = vec![0u8]; // definition: capability index 0
    msg.extend(5120u32.to_be_bytes());
    msg.extend(1u32.to_be_bytes());
    msg.push(b'p');
    msg.extend(tail(&[(4, &[1])]));
    let at_1_0 = Schema::new(&c, 0);
    assert_eq!(
        value::decode(&at_1_0, Top::Request(register), &msg, 1),
        Err(DecodeError::FieldTooNew(vec![4]))
    );
    let at_1_1 = Schema::new(&c, 1);
    let d = value::decode(&at_1_1, Top::Request(register), &msg, 1).unwrap();
    // The JSON the call text uses: the proof redacted, as in the note.
    let mut buf = [0u8; 256];
    let mut w = JsonWriter::new(&mut buf);
    value::to_json(&at_1_1, Top::Request(register), &d.value, &mut w);
    assert_eq!(
        std::str::from_utf8(w.finish().unwrap()).unwrap(),
        r#"{"definition":{"cap":0},"length":5120,"proof":null,"dry_run":true}"#
    );
    // A reply reads the same unknown field tolerantly, and keeps it.
    let rep = member(&c, "list");
    let mut msg = 7u64.to_be_bytes().to_vec();
    msg.extend(0u32.to_be_bytes());
    msg.extend(tail(&[(9, &[0xAA, 0xBB])]));
    let d = value::decode(&at_1_0, Top::Reply(rep), &msg, 0).unwrap();
    let Value::Struct(Fields { unknown, .. }) = &d.value else {
        panic!()
    };
    assert_eq!(unknown, &[(9, vec![0xAA, 0xBB])]);
    assert_eq!(
        value::encode(&at_1_0, Top::Reply(rep), &d.value, false).octets,
        msg
    );
}

/// A known arm newer than the minor is recorded as `value_too_new`, read as
/// raw octets (never with its type), and decoding goes on: a later
/// malformed part still makes the message malformed.
#[test]
fn value_too_new_is_recorded_and_decoding_goes_on() {
    let c = file(KINDS);
    let event = type_id(&c, "event");
    let at_1_0 = Schema::new(&c, 0);
    let at_1_1 = Schema::new(&c, 1);
    let strict = Top::Type(event, Mode::Strict);
    let tolerant = Top::Type(event, Mode::Tolerant);
    // Arm 5, moved, since 1.1: a pair, 4 octets.
    let moved = [0, 5, 0, 0, 0, 4, 0, 1, 0, 2];
    let d = value::decode(&at_1_0, strict, &moved, 0).unwrap();
    assert_eq!(d.value_too_new, Some(1));
    assert_eq!(d.value, Value::UnknownArm(5, vec![0, 1, 0, 2]));
    let d = value::decode(&at_1_0, tolerant, &moved, 0).unwrap();
    assert_eq!(d.value_too_new, None);
    let d = value::decode(&at_1_1, strict, &moved, 0).unwrap();
    assert_eq!(d.value_too_new, None);
    // The same arm with 3 octets: raw at 1.0, malformed where it is known.
    let short = [0, 5, 0, 0, 0, 3, 0, 1, 0];
    assert_eq!(
        value::decode(&at_1_0, strict, &short, 0)
            .unwrap()
            .value_too_new,
        Some(1)
    );
    assert_eq!(
        value::decode(&at_1_1, strict, &short, 0),
        Err(DecodeError::Malformed)
    );
    // put(item: thing, shape: shape, ev: event): the newer arm, then a
    // malformed tail. Malformed wins.
    let put = member(&c, "put");
    let mut msg = 1u64.to_be_bytes().to_vec(); // thing.key
    msg.extend(2u32.to_be_bytes()); // thing.count
    msg.extend(0u32.to_be_bytes()); // thing.tags
    msg.extend(0u32.to_be_bytes()); // thing's tail
    msg.extend([0, 1, 0, 0, 0, 7]); // shape: circle 7
    msg.extend(moved);
    let mut good = msg.clone();
    good.extend(0u32.to_be_bytes());
    let d = value::decode(&at_1_0, Top::Request(put), &good, 0).unwrap();
    assert_eq!(d.value_too_new, Some(1));
    let mut bad = msg;
    bad.extend(0x0001_0000u32.to_be_bytes()); // a tail count over 65,535
    assert_eq!(
        value::decode(&at_1_0, Top::Request(put), &bad, 0),
        Err(DecodeError::Malformed)
    );
}

/// An open union's tag 0 is malformed in both modes.
#[test]
fn an_open_unions_tag_0() {
    let c = file(KINDS);
    let s = Schema::new(&c, 2);
    let event = type_id(&c, "event");
    for mode in [Mode::Strict, Mode::Tolerant] {
        assert_eq!(
            value::decode(&s, Top::Type(event, mode), &[0, 0, 0, 0, 0, 0], 0),
            Err(DecodeError::Malformed)
        );
    }
}

/// Enum values and flag bits newer than the minor, in a strict read.
#[test]
fn newer_values_and_bits() {
    let c = file(KINDS);
    let level = type_id(&c, "level");
    let wide = type_id(&c, "wide");
    let at_1_0 = Schema::new(&c, 0);
    let strict = |id| Top::Type(id, Mode::Strict);
    // level.top = 4, since 1.1.
    let d = value::decode(&at_1_0, strict(level), &[0, 4], 0).unwrap();
    assert_eq!(d.value_too_new, Some(1));
    // An unknown value (5) is accepted and kept, with no refusal.
    let d = value::decode(&at_1_0, strict(level), &[0, 5], 0).unwrap();
    assert_eq!((d.value, d.value_too_new), (Value::Enum(5), None));
    // wide.mid = 1 << 32, since 1.1.
    let d = value::decode(&at_1_0, strict(wide), &(1u64 << 32).to_be_bytes(), 0).unwrap();
    assert_eq!(d.value_too_new, Some(1));
    // A closed flags type refuses an undeclared bit; a closed enum, an
    // undeclared value.
    let perms = type_id(&c, "perms");
    assert!(value::decode(&at_1_0, strict(perms), &[4], 0).is_err());
    assert!(value::decode(&at_1_0, strict(perms), &[11], 0).is_ok());
    let mode = type_id(&c, "mode");
    assert!(value::decode(&at_1_0, strict(mode), &[0, 0, 0, 2], 0).is_err());
}

/// Requests the kernel sends are read tolerantly: unknown tail fields are
/// kept, never refused (ADR 0063, rule 3).
#[test]
fn kernel_sent_requests_are_tolerant() {
    let c = common::check_file(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/interfaces/aspis/kernel/pager/v1.idl"),
    );
    let s = Schema::new(&c, 0);
    let page_request = member(&c, "page_request");
    assert_eq!(s.mode(Top::Request(page_request)), Mode::Tolerant);
    let mut msg = 4096u64.to_be_bytes().to_vec();
    msg.extend(4096u32.to_be_bytes());
    msg.extend(tail(&[(9, &[1, 2, 3])]));
    let d = value::decode(&s, Top::Request(page_request), &msg, 0).unwrap();
    assert_eq!(
        value::encode(&s, Top::Request(page_request), &d.value, false).octets,
        msg
    );
}

/// Capability indexes ascend in encoding order, each once, all below the
/// count, and every one below the count is named.
#[test]
fn capability_indexes() {
    let c = file(KINDS);
    let s = Schema::new(&c, 2);
    let give = member(&c, "give");
    // give(a: cap, b: cap?, c: cap): a, c in the head, b in the tail.
    let msg = |a: u8, c: u8, b: Option<u8>| {
        let mut m = vec![a, c];
        match b {
            Some(b) => m.extend(tail(&[(2, &[b])])),
            None => m.extend(0u32.to_be_bytes()),
        }
        m
    };
    let top = Top::Request(give);
    assert!(value::decode(&s, top, &msg(0, 1, None), 2).is_ok());
    assert!(value::decode(&s, top, &msg(0, 1, Some(2)), 3).is_ok());
    // Out of order, repeated, at or above the count, or one unnamed.
    assert!(value::decode(&s, top, &msg(1, 0, None), 2).is_err());
    assert!(value::decode(&s, top, &msg(0, 0, None), 2).is_err());
    assert!(value::decode(&s, top, &msg(0, 2, None), 2).is_err());
    assert!(value::decode(&s, top, &msg(0, 1, None), 3).is_err());
}

/// The JSON of a type with unknown members, sensitive fields and flags.
#[test]
fn json_of_unknowns_and_flags() {
    let c = file(KINDS);
    let s = Schema::new(&c, 0);
    let json = |top, v: &Value| {
        let mut buf = vec![0u8; 4096];
        let mut w = JsonWriter::new(&mut buf);
        value::to_json(&s, top, v, &mut w);
        String::from_utf8(w.finish().unwrap().to_vec()).unwrap()
    };
    let wide = Top::Type(type_id(&c, "wide"), Mode::Tolerant);
    // At 1.0, mid (1 << 32) is unknown, so it is among the unknown bits.
    assert_eq!(
        json(wide, &Value::Flags(1 | 1 << 63 | 1 << 32 | 2)),
        r#"["low","high","4294967298"]"#
    );
    let event = Top::Type(type_id(&c, "event"), Mode::Tolerant);
    assert_eq!(
        json(event, &Value::UnknownArm(9, vec![0xFF])),
        r#"{"@9":"_w"}"#
    );
    let note = Value::Arm(4, Box::new(Value::Text(r#"{ "a": [1] }"#.into())));
    assert_eq!(json(event, &note), r#"{"note":{"a":[1]}}"#);
    let level = Top::Type(type_id(&c, "level"), Mode::Tolerant);
    // top (4) is unknown at 1.0: its number.
    assert_eq!(json(level, &Value::Enum(4)), "4");
    assert_eq!(json(level, &Value::Enum(2)), r#""high""#);
}

/// A count near the bound, with little input after it, is refused at once:
/// every element takes at least one octet (the checker refuses an element
/// that takes none), so the work follows the input.
#[test]
fn a_huge_count_with_little_input_is_refused_quickly() {
    let c = common::check(
        b"edition 2026;
[id(org.example.t), object_id(reserved(1)), version(1.0)]
interface t {
    [closed] struct one { a: u8 }
    struct s { xs: seq<one, 16000000> }
}
",
    )
    .unwrap();
    let s = Schema::new(&c, 0);
    let ty = type_id(&c, "s");
    let start = std::time::Instant::now();
    for mode in [Mode::Strict, Mode::Tolerant] {
        // The count 16e6, the bound (a declared type fits a message),
        // then only eight octets.
        let data = [0x00, 0xF4, 0x24, 0x00, 1, 2, 3, 4, 0, 0, 0, 0];
        assert_eq!(
            value::decode(&s, Top::Type(ty, mode), &data, 0),
            Err(DecodeError::Malformed)
        );
    }
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
}

/// What a value allocates: itself and everything it holds, each of a
/// struct's slots included, whether its field is present or not.
fn count(v: &Value) -> usize {
    1 + match v {
        Value::List(l) => l.iter().map(count).sum(),
        Value::Opt(Some(b)) | Value::Arm(_, b) => count(b),
        Value::Struct(f) => {
            f.known.len() + f.unknown.len() + f.known.iter().flatten().map(count).sum::<usize>()
        }
        _ => 0,
    }
}

/// Each rule's samples, and what they allocate, in all.
fn sample_costs(body: &str) -> (BTreeMap<String, usize>, usize) {
    let src = format!(
        "edition 2026;\n[id(org.example.t), object_id(reserved(1)), version(1.0)]\ninterface t {{\n{body}}}\n"
    );
    let c = common::check(src.as_bytes()).unwrap();
    let s = Schema::new(&c, 0);
    let start = std::time::Instant::now();
    let samples = idl::vectors::samples(&s, &idl::vectors::Budget::default()).unwrap();
    assert!(start.elapsed().as_secs() < 30, "{:?}", start.elapsed());
    let mut per_rule: BTreeMap<String, usize> = BTreeMap::new();
    for x in &samples {
        *per_rule.entry(s.top_rule(x.top)).or_default() += count(&x.value);
    }
    for (rule, n) in &per_rule {
        assert!(*n <= idl::vectors::BUDGET, "{rule}: {n}");
    }
    let total = per_rule.values().sum();
    assert!(total <= idl::vectors::FILE_BUDGET, "{total}");
    (per_rule, total)
}

/// A struct of 4096 optional fields, all `u8?`.
fn wide(name: &str) -> String {
    let mut out = format!("struct {name} {{");
    for i in 0..4096 {
        out += &format!(" f{i}: u8?,");
    }
    out + " }\n"
}

/// The vector generator's samples stop at a budget for each rule, so a
/// type whose minimal value is huge, used by no method, costs a bounded
/// time and memory ("Generated grammars").
#[test]
fn samples_stay_within_a_budget() {
    let mut body = String::from("[closed] struct t0 { a: u8, b: u8 }\n");
    for i in 1..20 {
        body += &format!("[closed] struct t{i} {{ a: t{}, b: t{} }}\n", i - 1, i - 1);
    }
    body += "alias big = array<array<u8, 4000>, 4000>;\n@1 m(a: u8) -> u8;\n";
    let (per_rule, _) = sample_costs(&body);
    // Small types still get their samples; the method's rules are whole.
    for rule in ["t-t0", "t-t10", "m-m--req", "m-m--rep"] {
        assert!(per_rule.contains_key(rule), "{rule}: {per_rule:?}");
    }
    // The 2^19-value and 16 M-value minimal values get none.
    assert!(!per_rule.contains_key("t-t19") && !per_rule.contains_key("t-big"));
}

/// The budget charges what a sample allocates, a struct's absent fields
/// included. The review's counterexample: a struct of 4096 optional
/// fields costs one value when all are absent if only present values
/// count, so each of its 12,290 samples, a copy of 4096 slots, was free,
/// and two such structs held about 10 GB. Its rules still get samples.
#[test]
fn the_budget_charges_absent_fields() {
    for n in [1, 2] {
        let mut body: String = (0..n).map(|k| wide(&format!("w{k}"))).collect();
        body += "@1 m(a: u8) -> u8;\n";
        let (per_rule, _) = sample_costs(&body);
        assert!(per_rule.contains_key("t-w0"), "{per_rule:?}");
    }
    // The same struct as a method's parameters, and used by a method.
    let params: Vec<String> = (0..4096).map(|i| format!("p{i}: u8?")).collect();
    let body = format!(
        "{}@1 m({}) -> u8;\n@2 n(a: w0) -> u8;\n",
        wide("w0"),
        params.join(", ")
    );
    let (per_rule, _) = sample_costs(&body);
    assert!(per_rule.contains_key("m-m--req"), "{per_rule:?}");
}

/// The rules of a file share a budget too (`idl::vectors::FILE_BUDGET`),
/// so a small file of many rules, each near its own budget, holds a
/// bounded memory in all. Later rules get no samples once it is spent.
#[test]
fn a_minors_samples_share_a_budget() {
    let mut body = wide("w");
    for k in 0..1000 {
        body += &format!("struct h{k} {{ a: w, b: w, c: w }}\n");
    }
    body += "@1 m(a: u8) -> u8;\n";
    let (per_rule, total) = sample_costs(&body);
    assert!(per_rule.contains_key("m-m--req") && per_rule.contains_key("t-h0"));
    assert!(!per_rule.contains_key("t-h999"), "{total}");
}

/// The fastest of three runs of `f`.
fn fastest(mut f: impl FnMut()) -> std::time::Duration {
    (0..3)
        .map(|_| {
            let t = std::time::Instant::now();
            f();
            t.elapsed()
        })
        .min()
        .unwrap()
}

fn interface(body: &str) -> String {
    format!(
        "edition 2026;\n[id(org.example.t), object_id(reserved(1)), version(1.0)]\ninterface t {{\n{body}}}\n"
    )
}

/// Decoding an enum, a union or a struct costs a lookup per value, not a
/// scan of every declared member: the work is linear in the message
/// whatever the schema declares ("The gate for each target", item 6).
#[test]
fn decoding_cost_doesnt_grow_with_declared_members() {
    let schema = |values: usize| {
        let mut body = String::from("enum big: u16 {\n");
        for v in 1..=values {
            body += &format!("v{v} = {v},\n");
        }
        body += "}\nunion u {\n";
        for a in 1..=values {
            body += &format!("@{a} a{a}: u8,\n");
        }
        body += "}\n@1 m(a: seq<big, 1048576>, b: seq<u, 1048576>) -> u8;\n";
        common::check(interface(&body).as_bytes()).unwrap()
    };
    // 32,768 enum values 0x0001, then 32,768 arms tag 1, holding 0x07.
    let n = 32_768u32;
    let mut msg = n.to_be_bytes().to_vec();
    for _ in 0..n {
        msg.extend_from_slice(&[0, 1]);
    }
    msg.extend_from_slice(&n.to_be_bytes());
    for _ in 0..n {
        msg.extend_from_slice(&[0, 1, 0, 0, 0, 1, 7]);
    }
    msg.extend_from_slice(&[0, 0, 0, 0]);
    let time = |c: &Checked| {
        let s = Schema::new(c, 0);
        let top = Top::Request(member(c, "m"));
        value::decode(&s, top, &msg, 0).unwrap();
        fastest(|| {
            value::decode(&s, top, &msg, 0).unwrap();
        })
    };
    let (small, large) = (schema(1), schema(4000));
    let (a, b) = (time(&small), time(&large));
    // A scan per value made the large schema hundreds of times slower.
    assert!(
        b < a * 8 + std::time::Duration::from_millis(20),
        "{a:?} {b:?}"
    );
}

/// The strict forms are found in time linear in the types, whatever order
/// they are declared in. Values nest at most 32 deep, but a caller may
/// raise the limit, and the work must not depend on it.
#[test]
fn strict_forms_are_found_in_linear_time() {
    let limits = idl::Limits {
        nesting: 10_000,
        ..idl::Limits::default()
    };
    let chain = |reverse: bool| {
        let mut lines: Vec<String> = (1..4000)
            .map(|i| format!("alias t{i} = t{};\n", i - 1))
            .collect();
        if reverse {
            lines.reverse();
        }
        let src = interface(&(lines.concat() + "struct t0 { a: u8 }\n"));
        idl::check(
            src.as_bytes(),
            &mut |_: &idl_rt::names::InterfaceRef<'_>| None,
            &limits,
        )
        .unwrap()
    };
    let (fwd, rev) = (chain(false), chain(true));
    let a = fastest(|| {
        Schema::new(&fwd, 0);
    });
    let b = fastest(|| {
        Schema::new(&rev, 0);
    });
    let s = Schema::new(&rev, 0);
    assert!(s.has_strict(type_id(&rev, "t3999")));
    // One sweep a type made the reverse order thousands of times slower.
    assert!(
        b < a * 8 + std::time::Duration::from_millis(20),
        "{a:?} {b:?}"
    );
}
