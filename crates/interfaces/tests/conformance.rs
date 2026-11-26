// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The conformance runner, `idl::conformance::run`, over every interface
//! and fixture, at every minor, with every generated module that reads it
//! (ADR 0013, rule 3; ADR 0067, rule 9; ADR 0068, rules 4 and 6): the
//! generated decoders against the generated grammars, crates/idl's dynamic
//! codec and the text grammars, on every vector and on mutations of the ok
//! ones.
//!
//! Also the cases of "Rules for readers" that the vectors can't show
//! alone: a union arm newer than the minor is skipped as raw octets, never
//! read with its type, and a `value_too_new` doesn't hide a later
//! malformed part.

mod common;

use idl::{conformance, schema::Schema};
use idl_rt::{
    conformance::Subject,
    rules::{Module, Op, Verdict},
};

#[test]
fn every_module_conforms_at_every_minor() {
    let modules = common::modules();
    let (mut checks, mut unjudged, mut runs) = (0, 0, 0);
    let mut failures = Vec::new();
    for (name, path) in common::all_idl_files() {
        let c = common::check(&path);
        let (major, v) = (c.unit().major(), c.unit().version.minor);
        let mine: Vec<&Module> = modules
            .iter()
            .copied()
            .filter(|m| m.name == name && m.major == major)
            .collect();
        assert!(!mine.is_empty(), "no generated module for {name}/{major}");
        // One budget for each module's runs on the file, every minor.
        let budgets: Vec<_> = mine.iter().map(|_| conformance::budget()).collect();
        for m in 0..=v {
            let file = |ext: &str| path.with_file_name(format!("v{major}.{m}.{ext}"));
            let wire_g = common::grammar(&file("abnf"));
            let wire_v = common::vectors(&file("vectors"));
            assert_eq!(
                wire_g.is_none(),
                c.unit().is_kernel(),
                "{name}/{major}.{m}: a wire grammar exactly when not [kernel]"
            );
            let text = common::grammar(&file("text.abnf"))
                .unwrap_or_else(|| panic!("{name}/{major}.{m}: no text grammar"));
            let wire = wire_g.as_ref().zip(wire_v.as_ref());
            for (module, budget) in mine.iter().zip(&budgets).filter(|(x, _)| x.minor >= m) {
                let r = conformance::run(*module, &c, m, wire, &text, budget);
                runs += 1;
                checks += r.checks;
                unjudged += r.unjudged;
                failures.extend(r.failures);
            }
        }
    }
    eprintln!("{runs} runs, {checks} checks, {unjudged} unjudged");
    assert!(runs >= 10, "only {runs} runs");
    assert!(checks > 10_000, "only {checks} checks");
    // A budget that runs out is rare: it must not hide the differential.
    assert!(unjudged * 100 < checks, "{unjudged} of {checks} unjudged");
    assert!(
        failures.is_empty(),
        "{} failures, first ones:\n{}",
        failures.len(),
        failures
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// A subject that gets everything wrong, to show the runner notices.
struct Liar;

impl Subject for Liar {
    fn name(&self) -> &str {
        "aspis.catalog"
    }
    fn major(&self) -> u16 {
        1
    }
    fn minor(&self) -> u16 {
        1
    }
    fn run(&self, _: &str, _: u16, _: u8, _: &[u8], _: Op<'_, '_>) -> Verdict {
        Verdict::Ok {
            len: 0,
            value_too_new: None,
        }
    }
}

#[test]
fn the_runner_notices_a_wrong_subject() {
    let path = common::repo().join("interfaces/aspis/catalog/v1.idl");
    let c = common::check(&path);
    let g = common::grammar(&path.with_file_name("v1.1.abnf")).unwrap();
    let v = common::vectors(&path.with_file_name("v1.1.vectors")).unwrap();
    let t = common::grammar(&path.with_file_name("v1.1.text.abnf")).unwrap();
    let r = conformance::run(&Liar, &c, 1, Some((&g, &v)), &t, &conformance::budget());
    assert!(r.failures.len() > v.vectors.len() / 2, "{r:?}");
}

/// "Rules for readers" on the kinds fixture's open union `event`, whose
/// arm `moved` (@5, a closed `pair` of two u16s) came in 1.1.
#[test]
fn a_newer_arm_is_raw_octets_at_an_older_minor() {
    let path = common::repo().join("crates/idl/tests/data/interfaces/org/example/kinds/v1.idl");
    let c = common::check(&path);
    let kinds = common::modules()
        .into_iter()
        .find(|m| m.name == "org.example.kinds" && m.minor == 2)
        .unwrap();
    // Arm 5 with three octets: not a `pair`, which takes four.
    let bad_pair = [0x00, 0x05, 0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC];
    for (minor, rule, accepted) in [
        // At 1.0 the arm is unknown: its octets are never read as a pair,
        // so the message matches grammar 1.0, read either way.
        (0, "t-event", true),
        (0, "r-event", true),
        // At 1.1 the arm is known, and the octets aren't a pair.
        (1, "t-event", false),
        (1, "r-event", false),
    ] {
        let s = Schema::new(&c, minor);
        let g = common::grammar(&path.with_file_name(format!("v1.{minor}.abnf"))).unwrap();
        let j = conformance::judge(kinds, &s, Some(&g), rule, 0, &bad_pair)
            .unwrap_or_else(|e| panic!("{rule} at 1.{minor}: {e}"));
        assert_eq!(
            j,
            if accepted {
                conformance::Judged::Accepted
            } else {
                conformance::Judged::Refused
            },
            "{rule} at 1.{minor}"
        );
    }
}

/// A strict read at 1.0 of a request whose union arm is known to the
/// binding but newer than the minor: `value_too_new` is recorded, the
/// message still matches grammar 1.0, and a malformed part after it still
/// makes the message malformed.
#[test]
fn value_too_new_never_hides_a_later_malformed_part() {
    let path = common::repo().join("crates/idl/tests/data/interfaces/org/example/kinds/v1.idl");
    let c = common::check(&path);
    let kinds = common::modules()
        .into_iter()
        .find(|m| m.name == "org.example.kinds" && m.minor == 2)
        .unwrap();
    // A 1.1 request of `put` whose `ev` is the 1.1 arm `moved`.
    let v11 = common::vectors(&path.with_file_name("v1.1.vectors")).unwrap();
    let s0 = Schema::new(&c, 0);
    let g0 = common::grammar(&path.with_file_name("v1.0.abnf")).unwrap();
    let mut found = false;
    for v in v11
        .vectors
        .iter()
        .filter(|v| v.rule == "m-put--req" && v.tag == abnf::vectors::Tag::Ok)
    {
        let mut out = vec![0u8; v.octets.len() + 64];
        let verdict = kinds.run("m-put--req", 0, v.caps, &v.octets, Op::Encode(&mut out));
        let Verdict::Ok {
            value_too_new: Some(1),
            ..
        } = verdict
        else {
            continue;
        };
        found = true;
        // Grammar 1.0 accepts it: the arm is unknown there.
        assert_eq!(
            conformance::judge(kinds, &s0, Some(&g0), "m-put--req", v.caps, &v.octets),
            Ok(conformance::Judged::Accepted),
            "line {}",
            v.line
        );
        // A tail field with tag 0 after it is malformed, whatever came
        // before.
        let mut bad = v.octets.clone();
        bad.extend([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let mut out = vec![0u8; bad.len() + 64];
        assert_eq!(
            kinds.run("m-put--req", 0, v.caps, &bad, Op::Encode(&mut out)),
            Verdict::Malformed,
            "line {}",
            v.line
        );
        assert_eq!(
            conformance::judge(kinds, &s0, Some(&g0), "m-put--req", v.caps, &bad),
            Ok(conformance::Judged::Refused),
            "line {}",
            v.line
        );
    }
    assert!(found, "no 1.1 put request with the arm moved");
}
