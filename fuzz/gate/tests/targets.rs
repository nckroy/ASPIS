// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The target table agrees with the files: the bins, the target files,
//! the seed and regression directories, the embedded grammars, the
//! crates each target covers, and the product lock.

mod common;

use std::collections::BTreeSet;

use common::{committed, root, tracked};
use fuzz_gate::{
    PROBES, TARGETS, harness,
    idl_repo::{self, INTERFACES},
    idl_targets::{self, Class},
    repo,
};
use idl::{layout::Types, schema::Schema};
use idl_rt::rules::{Module, Op, Verdict};

#[test]
fn names_are_unique_and_plain() {
    let mut names = BTreeSet::new();
    for t in TARGETS {
        assert!(names.insert(t.name), "{} twice", t.name);
        assert!(
            harness::valid_name(t.name) && !t.name.contains('.'),
            "{}",
            t.name
        );
    }
    for p in PROBES {
        assert!(!names.contains(p), "{p} is a probe and a target");
    }
}

#[test]
fn bins_files_and_table_agree() {
    let manifest = std::fs::read_to_string(root().join("fuzz/Cargo.toml")).unwrap();
    let mut bins = BTreeSet::new();
    let mut in_bin = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_bin = line == "[[bin]]";
        } else if in_bin && let Some(v) = line.strip_prefix("name = ") {
            bins.insert(v.trim_matches('"').to_string());
        }
    }
    let files: BTreeSet<String> = tracked(&["fuzz/fuzz_targets"])
        .iter()
        .map(|p| {
            p.strip_prefix("fuzz/fuzz_targets/")
                .and_then(|f| f.strip_suffix(".rs"))
                .unwrap_or_else(|| panic!("{p} isn't a target file"))
                .to_string()
        })
        .collect();
    let table: BTreeSet<String> = TARGETS
        .iter()
        .map(|t| t.name)
        .chain(PROBES.iter().copied())
        .map(String::from)
        .collect();
    assert_eq!(bins, table, "fuzz/Cargo.toml's [[bin]]s and TARGETS");
    assert_eq!(files, table, "fuzz/fuzz_targets/ and TARGETS");
}

#[test]
fn committed_inputs_belong_to_targets() {
    for kind in ["seeds", "regressions"] {
        for p in tracked(&[&format!("fuzz/{kind}")]) {
            let rest = p.strip_prefix(&format!("fuzz/{kind}/")).unwrap();
            let (target, name) = rest
                .split_once('/')
                .unwrap_or_else(|| panic!("{p} isn't in a target's directory"));
            assert!(
                fuzz_gate::target(target).is_some(),
                "{p}: no target {target}"
            );
            assert!(
                harness::valid_name(name) && !name.contains('/'),
                "{p}: names are lowercase letters, digits, hyphens and dots"
            );
        }
    }
}

#[test]
fn every_seed_fits_max_len() {
    for t in TARGETS {
        for (name, bytes) in common::all_seeds(t) {
            assert!(
                bytes.len() <= t.max_len,
                "{}: {name} is {} octets, over max_len {}",
                t.name,
                bytes.len(),
                t.max_len
            );
        }
        for (name, _) in (t.seeds)() {
            assert!(harness::valid_name(&name), "{}: generated {name}", t.name);
        }
    }
}

#[test]
fn limits_are_sane() {
    for t in TARGETS {
        assert!(t.timeout_s >= 1, "{}", t.name);
        assert!(
            t.malloc_limit_mb >= 1 && t.malloc_limit_mb < t.rss_limit_mb,
            "{}",
            t.name
        );
        assert!(t.max_len >= 1024, "{}", t.name);
    }
}

#[test]
fn paths_exist_and_parsers_forbid_unsafe() {
    for t in TARGETS {
        for p in t.paths.iter().chain(t.extra_paths) {
            assert!(root().join(p).exists(), "{}: {p} doesn't exist", t.name);
            // A crate a target reaches parses input from across a trust
            // boundary (ADR 0068, rule 2). Only a crate's root counts, as
            // in `harness::coverage_dirs`: `crates/idl/tests/data/...`
            // is data.
            if let Some(name) = p.strip_prefix("crates/").filter(|c| !c.contains('/')) {
                let lib = std::fs::read_to_string(root().join(p).join("src/lib.rs")).unwrap();
                assert!(
                    lib.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]"),
                    "crates/{name} doesn't forbid unsafe code"
                );
            }
        }
    }
}

#[test]
fn every_grammar_is_embedded() {
    let tracked: BTreeSet<String> = tracked(&["grammars/*.abnf", "crates/abnf/tests/data/*.abnf"])
        .into_iter()
        .collect();
    let embedded: BTreeSet<String> = repo::GRAMMARS.iter().map(|g| g.path.to_string()).collect();
    assert_eq!(embedded, tracked);
    for g in repo::GRAMMARS {
        assert_eq!(
            std::fs::read(root().join(g.path)).unwrap(),
            g.text,
            "{}",
            g.path
        );
        assert_eq!(
            std::fs::read(root().join(g.vectors_path)).unwrap(),
            g.vectors,
            "{}",
            g.vectors_path
        );
    }
}

#[test]
fn the_product_lock_holds_no_fuzz_engine() {
    let lock = std::fs::read_to_string(root().join("Cargo.lock")).unwrap();
    assert_eq!(harness::engine_crates_in(&lock), Vec::<&str>::new());
}

/// The tracked files under an interface root: the IDL files, and the wire
/// grammars and vectors (the text ones aren't embedded).
fn interface_files(root: &str) -> [BTreeSet<String>; 3] {
    let of = |ext: &str| -> BTreeSet<String> {
        tracked(&[&format!("{root}/*{ext}")])
            .into_iter()
            .filter(|p| p.ends_with(ext) && !p.contains(".text."))
            .collect()
    };
    [of(".idl"), of(".abnf"), of(".vectors")]
}

#[test]
fn every_interface_is_embedded() {
    let mut want: [BTreeSet<String>; 3] = Default::default();
    for r in ["interfaces", "crates/idl/tests/data/interfaces"] {
        for (w, got) in want.iter_mut().zip(interface_files(r)) {
            w.extend(got);
        }
    }
    let mut have: [BTreeSet<String>; 3] = Default::default();
    for i in INTERFACES {
        have[0].insert(i.path.to_string());
        assert_eq!(
            std::fs::read(root().join(i.path)).unwrap(),
            i.idl,
            "{}",
            i.path
        );
        for w in i.wire {
            have[1].insert(w.abnf_path.to_string());
            have[2].insert(w.vectors_path.to_string());
            assert_eq!(std::fs::read(root().join(w.abnf_path)).unwrap(), w.abnf);
            assert_eq!(
                std::fs::read(root().join(w.vectors_path)).unwrap(),
                w.vectors
            );
        }
    }
    assert_eq!(have, want, "idl_repo::INTERFACES and the tracked files");
    // Each interface's wire minors are its minors, or none for a
    // `[kernel]` interface.
    for i in idl_repo::LOADED.iter() {
        let n = i.repo.wire.len();
        assert!(
            n == 0 || n == usize::from(i.version()) + 1,
            "{}: {n} wire minors, version 1.{}",
            i.repo.path,
            i.version()
        );
        assert_eq!(
            n == 0,
            i.checked
                .unit()
                .file
                .interface
                .attrs
                .iter()
                .any(|a| a.name.name == "kernel"),
            "{}",
            i.repo.path
        );
    }
}

#[test]
fn every_module_has_an_interface_and_a_frame() {
    let mut frames = BTreeSet::new();
    assert!(!idl_repo::MODULES.is_empty());
    for &m in idl_repo::MODULES.iter() {
        let i = idl_repo::interface_of(m)
            .unwrap_or_else(|| panic!("{}/{}: no embedded interface", m.name, m.major));
        assert!(m.minor <= i.version(), "{}/{}.{}", m.name, m.major, m.minor);
        let f = idl_repo::frame(m);
        assert!(f.len() <= idl_targets::FRAME_MAX, "{f}");
        assert!(frames.insert(f.clone()), "{f} twice");
        let mut input = f.clone().into_bytes();
        input.extend_from_slice(b"xyz");
        let (back, rest) = idl_targets::split_frame(&input).unwrap();
        assert!(std::ptr::eq(back, m), "{f} names another module");
        assert_eq!(rest, b"xyz");
        // Fewer than 256 rules, so the first octet reaches each.
        assert!(!m.rules.is_empty() && m.rules.len() < 256, "{f}");
    }
    assert!(idl_targets::split_frame(b"org.example.none/1.0\n...").is_none());
    assert!(idl_targets::split_frame(b"aspis.rpc/1.0").is_none());
}

/// What C07's entry passed to the module's `rule`, recorded by [`record`].
type Seen = Option<(String, u16, u8, Vec<u8>)>;

std::thread_local! {
    static SEEN: std::cell::RefCell<Seen> = const { std::cell::RefCell::new(None) };
}

/// A module's `rule` that records what it was asked to decode, and
/// refuses it, so `idl_rt::fuzz::decode` stops there.
fn record(rule: &str, minor: u16, caps: u8, input: &[u8], _: Op<'_, '_>) -> Verdict {
    SEEN.with(|s| *s.borrow_mut() = Some((rule.into(), minor, caps, input.to_vec())));
    Verdict::Malformed
}

/// Every ok vector a module reads, and every sample of a `[kernel]`
/// interface, framed as the seeds frame them: the rule, minor, count and
/// message that `idl_targets::pick` gives, and that C07's entry
/// (`idl_rt::fuzz::decode`, through a module that records them) passes
/// to the module, are the ones framed, and the module accepts them. A
/// drift between `pick` and idl-rt's own mapping would make the seeds
/// reach other rules than they name, and the gate's differential judge
/// other rules than C07's entry checks.
#[test]
fn decode_frames_pick_what_c07_picks() {
    let mut checked = 0;
    for &m in idl_repo::MODULES.iter() {
        let i = idl_repo::interface_of(m).unwrap();
        for minor in 0..=m.minor {
            let cases: Vec<(String, u8, Vec<u8>)> = match i.repo.wire.get(usize::from(minor)) {
                Some(w) => fuzz_gate::seeds::wire_vectors(w)
                    .into_iter()
                    .filter(|v| v.tag == abnf::vectors::Tag::Ok)
                    .map(|v| (v.rule, v.caps, v.octets))
                    .collect(),
                None => {
                    let s = Schema::new(&i.checked, minor);
                    idl::vectors::samples(&s, &idl::vectors::Budget::default())
                        .unwrap()
                        .into_iter()
                        .map(|x| (s.top_rule(x.top), x.caps, x.octets))
                        .collect()
                }
            };
            for (rule, caps, octets) in cases {
                let d = idl_targets::decode_input(m, &rule, minor, caps, &octets).unwrap();
                let (back, rest) = idl_targets::split_frame(&d).unwrap();
                let p = idl_targets::pick(back, rest).unwrap();
                assert_eq!(
                    (p.rule, p.minor, p.caps, p.msg),
                    (rule.as_str(), minor, caps, &octets[..])
                );
                let rec = Module {
                    rule: record,
                    ..*back
                };
                SEEN.with(|s| *s.borrow_mut() = None);
                idl_rt::fuzz::decode(&rec, rest);
                assert_eq!(
                    SEEN.with(|s| s.borrow_mut().take()),
                    Some((rule.clone(), minor, caps, octets.clone())),
                    "{}/{}.{}: C07's entry picks another rule, minor, count or message",
                    m.name,
                    m.major,
                    m.minor
                );
                let mut out = vec![0u8; octets.len() + 64];
                let v = (m.rule)(p.rule, p.minor, p.caps, p.msg, Op::Encode(&mut out));
                assert!(
                    matches!(v, Verdict::Ok { .. }),
                    "{}/{}.{} {rule}: {v:?}",
                    m.name,
                    m.major,
                    m.minor
                );
                checked += 1;
            }
        }
    }
    assert!(checked > 500, "{checked}");
}

/// Rules whose worst-case body doesn't fit idl-rt's 16 KiB cap with 1 KiB
/// to spare, so `idl-decode` can't reach their upper range: none. Their
/// frames are C18's and C29's targets.
const OUT_OF_REACH: &[&str] = &[];

#[test]
fn every_body_fits_the_decode_limit() {
    let cap = idl_rt::fuzz::MAX_MESSAGE as u64;
    let mut largest = (0, String::new());
    for i in idl_repo::LOADED.iter() {
        for minor in 0..=i.version() {
            let c = i.checked.project(minor);
            let mut bodies: Vec<(String, u64)> = Vec::new();
            for ml in &c.layout.methods {
                bodies.push((format!("{} request", ml.name), ml.request.max));
                if let Some(r) = ml.reply {
                    bodies.push((format!("{} reply", ml.name), r.max));
                }
                if let Some(st) = ml.stream {
                    bodies.push((format!("{} item", ml.name), st.item_max));
                }
            }
            for e in &c.layout.errors {
                bodies.push((format!("error {}", e.code), e.detail.max));
            }
            let s = Schema::new(&i.checked, minor);
            let mut types = Types::new(&i.checked.model);
            for t in s.tops() {
                if let idl::schema::Top::Type(id, _) = t {
                    bodies.push((s.top_rule(t), types.named(id).max));
                }
            }
            for (what, max) in bodies {
                let name = format!("{} 1.{minor} {what}", i.repo.name);
                if max > largest.0 {
                    largest = (max, name.clone());
                }
                assert!(
                    max + 1024 <= cap || OUT_OF_REACH.contains(&name.as_str()),
                    "{name}: a worst case of {max} octets doesn't fit idl-decode's {cap}"
                );
            }
        }
    }
    eprintln!(
        "the largest worst case: {} octets, {}",
        largest.0, largest.1
    );
}

#[test]
fn bound_seeds_reach_both_sides() {
    let seeds = idl_targets::bound_seeds();
    for (name, d) in &seeds {
        let (m, rest) = idl_targets::split_frame(d).unwrap();
        let want = if name.ends_with("-bound") {
            "ok"
        } else {
            "malformed"
        };
        match idl_targets::classify(m, rest) {
            Class::Read(_, _, v) => {
                assert_eq!(idl_targets::decode_kinds(d), [want], "{name}: {v:?}")
            }
            _ => panic!("{name}: not read"),
        }
    }
    let names: BTreeSet<&str> = seeds.iter().map(|(n, _)| n.as_str()).collect();
    for want in [
        "aspis.catalog-1.1-m-register--req-proof-bound",
        "aspis.catalog-1.1-m-register--req-proof-over",
        "aspis.catalog-1.1-m-list--rep-entries-bound",
        "aspis.catalog-1.1-m-list--rep-entries-over",
    ] {
        assert!(names.contains(want), "no seed {want}: {names:?}");
    }
}

/// The regression of C07's canonical-form panic: a file of the source
/// limit whose canonical form is about twice as long is refused with
/// `Code::Limit`, and one whose form fits checks, with the form within
/// 16 KiB of the limit, so the seed stays the target's costliest.
#[test]
fn canonical_seeds_reach_both_sides() {
    let limit = idl::Limits::default().source;
    let seeds = idl_targets::front_end_seeds();
    let seed = |name: &str| {
        &seeds
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("no seed {name}"))
            .1
    };
    let over = seed("canonical-over-source");
    assert_eq!(over.len(), limit);
    assert_eq!(idl_targets::front_end_kinds(over), ["limit"]);
    let at = seed("canonical-at-source");
    assert_eq!(at.len(), limit);
    assert_eq!(idl_targets::front_end_kinds(at), ["ok"]);
    let mut none = |_: &idl_rt::names::InterfaceRef<'_>| None;
    let c = idl::check(at, &mut none, &idl::Limits::default()).unwrap();
    let n = idl::generate::canonical(&c, 0).len();
    assert!(n <= limit && n > limit - 16384, "{n}");
}

/// `idl-generated` picks a top-level body at any reading minor; every
/// module has one at each, and the rule of each, so its early returns
/// never happen.
#[test]
fn every_module_has_tops_at_every_minor() {
    for &m in idl_repo::MODULES.iter() {
        let i = idl_repo::interface_of(m).unwrap();
        for minor in 0..=m.minor {
            let s = Schema::new(&i.checked, minor);
            let tops = s.tops();
            assert!(
                !tops.is_empty(),
                "{}/{}.{} at {minor}",
                m.name,
                m.major,
                m.minor
            );
            for t in tops {
                let rule = s.top_rule(t);
                assert!(
                    m.rules.contains(&rule.as_str()),
                    "{}/{}.{} at {minor}: no {rule}",
                    m.name,
                    m.major,
                    m.minor
                );
            }
        }
    }
}

#[test]
fn seed_names_are_valid_and_unique() {
    for t in TARGETS {
        let mut names = BTreeSet::new();
        for (name, _) in (t.seeds)() {
            assert!(harness::valid_name(&name), "{}: {name}", t.name);
            assert!(names.insert(name.clone()), "{}: {name} twice", t.name);
        }
    }
}

/// `idl-decode`'s hand-made seeds on `org.example.kinds` reach what they
/// were made for: the strict reader's too-new tags past 8, two values
/// too new in one message, and each `note` text embedded or written as a
/// string, which the wire takes either way.
#[test]
fn kinds_seeds_reach_their_verdicts() {
    let seeds = idl_targets::kinds_seeds();
    assert_eq!(
        seeds.len(),
        3 + idl_targets::NOTE_JSON.len() + 2,
        "{:?}",
        seeds.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
    for (name, d) in &seeds {
        let want = if name.contains("-too-new-") {
            "field-too-new"
        } else if name.ends_with("two-too-new") {
            "value-too-new"
        } else {
            "ok"
        };
        assert_eq!(idl_targets::decode_kinds(d), [want], "{name}");
        assert_ne!(
            idl_targets::decode_judged(d),
            Some(idl::conformance::Judged::Unjudged),
            "{name}"
        );
    }
}

/// The limit seeds added for the parser's per-list limits: the one at
/// each limit gets past the parser, and the one over is refused with
/// `Code::Limit` alone.
#[test]
fn list_limit_seeds_reach_both_sides() {
    let seeds = idl_targets::front_end_seeds();
    for what in ["imported-names", "errors", "items", "qualifiers"] {
        let seed = |side: &str| {
            let name = format!("limit-{what}-{side}");
            seeds
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap_or_else(|| panic!("no seed {name}"))
                .1
                .clone()
        };
        let at = idl_targets::front_end_kinds(&seed("at"));
        assert!(
            !at.contains(&"limit") && !at.contains(&"syntax"),
            "{what}: {at:?}"
        );
        assert_eq!(
            idl_targets::front_end_kinds(&seed("over")),
            ["limit"],
            "{what}"
        );
    }
}

/// Every comment seed is refused at its trailing comment, so each reaches
/// the parser's error return after trivia at its place; the source they
/// are cut from checks.
#[test]
fn comment_cut_seeds_end_in_a_bad_comment() {
    let seeds = idl_targets::comment_cut_seeds();
    assert!(seeds.len() > 100, "{}", seeds.len());
    let limits = idl::Limits::default();
    for (name, d) in &seeds {
        let msg = match idl::parse::parse_rule(idl::parse::Rule::IdlFile, d, &limits) {
            Err(e) => e.message,
            Ok(_) => panic!("{name}: parses"),
        };
        assert!(msg.contains("comment"), "{name}: {msg}");
    }
    assert_eq!(
        idl_targets::front_end_kinds(idl_targets::CUT_SOURCE.as_bytes()),
        ["ok"]
    );
}

/// The checker's refusals that the coverage review of the `idl-` targets'
/// campaign found missing. Replay guards only the two stream files, which
/// panic in the oracle without their rule; the other two are files the
/// checker accepted, so their verdicts are pinned here. Every file under
/// `fuzz/regressions/idl-front-end/` is listed, so a new one needs a row.
#[test]
fn front_end_regressions_keep_their_verdicts() {
    let want = [
        ("closed-enum-with-no-value", ["type"]),
        ("second-use-line-names-no-type", ["import"]),
        ("stream-after-newer-than-method", ["since"]),
        ("stream-item-newer-than-method", ["since"]),
    ];
    let files = committed("regressions", "idl-front-end");
    assert_eq!(
        files.len(),
        want.len(),
        "{:?}",
        files.iter().map(|(p, _)| p).collect::<Vec<_>>()
    );
    for (path, data) in &files {
        let name = path.rsplit('/').next().unwrap();
        let (_, kinds) = want
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("{path}: no verdict listed"));
        assert_eq!(idl_targets::front_end_kinds(data), kinds, "{path}");
    }
}
