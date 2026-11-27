// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Deterministic, linear work with depth limits ("The gate for each
//! target", item 6).
//!
//! - **Budgets.** On the repository's grammars, inputs built to 64 KiB
//!   match within a linear step budget, so the matcher's work on them is
//!   provably linear; on any other grammar the budget refuses superlinear
//!   work (L22). Every repository vector is judged within [`FUZZ_LIMITS`].
//! - **Scaling.** Each parser's time on 16n octets is at most 64 times its
//!   time on n: linear work gives about 16, quadratic about 256. The
//!   minimum of 7 timed batches keeps other load on the machine out of it.
//! - **Depth.** Nesting 64 loads and 65 doesn't; the matcher's depth limit
//!   ends a deep match with `Exhausted::Depth`, without overflowing the
//!   stack.

mod common;

use std::time::Instant;

use abnf::{Exhausted, Grammar, GrammarErrorKind, Kind, Limits, LoadOptions, constraint, vectors};
use fuzz_gate::{
    AGREEMENT_MAX, FUZZ_LIMITS,
    repo::{self, GRAMMARS},
    seeds,
};

/// Counts allocations, so the oracle test can show its peak.
#[global_allocator]
static ALLOC: fuzz_alloc::Bounded = fuzz_alloc::Bounded::unlimited();

/// The allocator's peak is process-wide, and the timings feel other load,
/// so this file's tests take turns: another test's allocations would
/// otherwise count against the oracle test's peak.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A step budget linear in the input: 10,000 steps, and 200 an octet.
fn linear_limits() -> Limits {
    Limits {
        steps_base: 10_000,
        steps_per_octet: 200,
        steps_max: u64::MAX,
        ..Limits::default()
    }
}

fn load_with(name: &str, limits: Limits) -> Grammar {
    let g = GRAMMARS.iter().find(|g| g.name == name).unwrap();
    let opts = LoadOptions {
        limits,
        kind: if name == "core" {
            Kind::Core
        } else {
            Kind::Auto
        },
    };
    Grammar::load(name, g.text, &mut repo::resolve, &opts).unwrap()
}

#[test]
fn repository_grammars_match_within_a_linear_budget() {
    let _turn = serial();
    common::on_big_stack(|| {
        let max = 64 << 10;
        let mut words = b"not word".to_vec();
        while words.len() + 2 <= max {
            words.extend_from_slice(b" w");
        }
        // core's `text`: a 4-octet big-endian length, then that many
        // characters, which its constraint holds it to.
        let n = max - 4;
        let mut text = (n as u32).to_be_bytes().to_vec();
        text.extend(vec![b'a'; n]);
        let cases: Vec<(&str, &str, Vec<u8>)> = vec![
            ("kernel-args", "kernel-args", seeds::kargs_line(max)),
            ("constraint", "constraint", words),
            ("core", "text", text),
        ];
        for (grammar, rule, input) in cases {
            let g = load_with(grammar, linear_limits());
            let r = g.rule(rule).unwrap();
            assert_eq!(
                g.matches(r, &input),
                Ok(true),
                "{grammar}/{rule}: {} octets within {} steps an octet",
                input.len(),
                linear_limits().steps_per_octet
            );
            // With its constraints too.
            assert_eq!(
                g.matches_constrained(r, &input, &abnf::Context::default()),
                Ok(true),
                "{grammar}/{rule}: {} octets within {} steps an octet",
                input.len(),
                linear_limits().steps_per_octet
            );
        }
    });
}

/// An IDL file of exactly `n` octets that `idl-file` in idl.abnf accepts:
/// one interface with structs of 64 fields, and its last line padded
/// with spaces before its `}`. The grammar is all these tests ask: at
/// 1 MiB the checker refuses the file with `Code::Limit`, since its
/// canonical form writes every field's position and is over the source
/// limit.
fn idl_file(n: usize) -> Vec<u8> {
    let head = "edition 2026;\n[id(org.example.y), object_id(reserved(0x0301)), version(1.0)]\ninterface y {\n";
    let mut f = head.as_bytes().to_vec();
    let mut k = 0;
    loop {
        let mut s = format!("    struct s{k} {{ ");
        for i in 0..64 {
            s += &format!("f{i}: u32, ");
        }
        s += "}\n";
        if f.len() + s.len() + 2 > n {
            break;
        }
        f.extend_from_slice(s.as_bytes());
        k += 1;
    }
    f.resize(n - 2, b' ');
    f.extend_from_slice(b"}\n");
    f
}

/// The agreement oracles' grammars give a verdict on inputs of
/// [`AGREEMENT_MAX`] octets, accepting and rejecting, within
/// [`ORACLE_LIMITS`](fuzz_gate::ORACLE_LIMITS) and within half the
/// targets' memory bound and timeout, so no input up to it is skipped
/// (`oracle::grammar_accepts` panics on one the matcher can't judge).
/// Inputs of 1 MiB, `abnf-constraint`'s longest, are judged here, beside
/// the fuzzer, since one takes longer than the target's timeout.
#[test]
fn the_oracles_judge_their_targets_longest_inputs() {
    let _turn = serial();
    common::on_big_stack(|| {
        let words = |n: usize, tail: &[u8]| {
            let mut w = b"not word".to_vec();
            while w.len() + 2 + tail.len() <= n {
                w.extend_from_slice(b" w");
            }
            w.extend_from_slice(tail);
            w
        };
        let comment = |n: usize| {
            let mut c = b"; constraint: ".to_vec();
            c.extend(words(n - 14, b""));
            c
        };
        let ints = |n: usize| {
            let mut t = b"not one of 1".to_vec();
            while t.len() + 3 <= n {
                t.extend_from_slice(b", 2");
            }
            t
        };
        let mut kargs_bad = seeds::kargs_line(kargs::MAX_LEN - 1);
        kargs_bad.push(b'"');
        // An IDL file of exactly `n` octets that the grammar accepts, and
        // one with a stray octet after its interface.
        let idl_bad = |n: usize| {
            let mut f = idl_file(n - 1);
            f.push(b'x');
            f
        };
        // The longest action reference, from `idl-names`' seeds, and
        // that target's longest input, which no rule takes.
        let action = fuzz_gate::idl_targets::names_seeds()
            .into_iter()
            .find(|(n, _)| n == "names-action-326")
            .unwrap()
            .1;
        let names_max = fuzz_gate::target("idl-names").unwrap().max_len;
        let constraint = fuzz_gate::target("abnf-constraint").unwrap();
        for (n, bounded) in [(AGREEMENT_MAX, true), (constraint.max_len, false)] {
            let mut cases: Vec<(&str, &str, Vec<u8>, bool)> = vec![
                ("constraint", "constraint", words(n, b""), true),
                ("constraint", "constraint", words(n, b"  "), false),
                ("constraint", "constraint", ints(n), true),
                ("constraint", "constraint", vec![b'w'; n], false),
                ("constraint", "constraint-comment", comment(n), true),
                ("constraint", "constraint-comment", ints(n), false),
                (
                    "kernel-args",
                    "kernel-args",
                    seeds::kargs_line(kargs::MAX_LEN),
                    true,
                ),
                ("kernel-args", "kernel-args", kargs_bad.clone(), false),
                // `idl-front-end`'s inputs reach 1 MiB, like
                // `abnf-constraint`'s, so they are judged here at both.
                ("idl", "idl-file", idl_file(n), true),
                ("idl", "idl-file", idl_bad(n), false),
            ];
            // `idl-names`' inputs are at most 1350 octets, under
            // AGREEMENT_MAX, so one size is enough.
            if bounded {
                cases.push(("names", "action-ref", action.clone(), true));
                let dotted = b"a.".repeat(names_max / 2);
                cases.push(("names", "action-ref", dotted.clone(), false));
                cases.push(("names", "name", dotted, false));
            }
            for (grammar, rule, input, want) in cases {
                let g = if bounded {
                    repo::oracle(grammar).unwrap()
                } else {
                    &load_with(
                        grammar,
                        Limits {
                            input_octets: n,
                            memory: 1 << 30,
                            ..fuzz_gate::ORACLE_LIMITS
                        },
                    )
                };
                fuzz_alloc::reset_peak();
                let base = fuzz_alloc::live();
                let t = Instant::now();
                let got =
                    g.matches_constrained(g.rule(rule).unwrap(), &input, &abnf::Context::default());
                let secs = t.elapsed().as_secs_f64();
                let peak = fuzz_alloc::peak().saturating_sub(base);
                eprintln!(
                    "{grammar}/{rule}: {} octets, {want}: {:.0} ms, peak {:.1} MiB",
                    input.len(),
                    secs * 1e3,
                    peak as f64 / f64::from(1u32 << 20)
                );
                assert_eq!(got, Ok(want), "{grammar}/{rule} on {} octets", input.len());
                if bounded {
                    let t = fuzz_gate::TARGETS
                        .iter()
                        .find(|t| t.grammar.is_some_and(|(g, _)| g == grammar))
                        .unwrap();
                    assert!(
                        peak < (t.malloc_limit_mb as usize) << 19,
                        "{grammar}/{rule}: {peak} bytes"
                    );
                    // Unoptimized test builds are slower than the fuzz
                    // build, so this is a generous check.
                    assert!(
                        secs < f64::from(t.timeout_s) / 2.0,
                        "{grammar}/{rule}: {secs} s"
                    );
                }
            }
        }
    });
}

#[test]
fn every_repository_vector_is_judged_within_the_fuzz_limits() {
    let _turn = serial();
    common::on_big_stack(|| {
        for g in GRAMMARS {
            let f = vectors::parse(g.vectors).unwrap();
            let r = vectors::check(repo::loaded(g.name).unwrap(), &f);
            assert_eq!(
                (r.disagree, r.unjudged),
                (0, 0),
                "{}: {:?}",
                g.vectors_path,
                r.results
                    .iter()
                    .filter(|(_, v)| *v != vectors::Verdict::Agrees)
                    .collect::<Vec<_>>()
            );
        }
    });
}

/// Every repository wire vector, read by every module of its interface
/// that knows its minor, is judged by `idl-decode`'s differential within
/// the limits the target matches with ([`WIRE_LIMITS`](fuzz_gate::WIRE_LIMITS)), and agrees: the
/// same claim as for the grammar vectors above.
#[test]
fn every_wire_vector_is_judged() {
    use fuzz_gate::{idl_repo, idl_targets};
    use idl::{conformance::Judged, schema::Schema};
    common::on_big_stack(|| {
        let mut judged = 0;
        for i in idl_repo::LOADED.iter() {
            for (minor, w) in i.repo.wire.iter().enumerate() {
                let minor = minor as u16;
                let s = Schema::new(&i.checked, minor);
                let g = i.wire_grammar(minor);
                let readers = idl_repo::MODULES.iter().copied().filter(|m| {
                    m.name == i.repo.name && m.major == i.repo.major && m.minor >= minor
                });
                for m in readers {
                    for v in seeds::wire_vectors(w) {
                        let j = idl_targets::differential_of(m, &s, g, &v.rule, v.caps, &v.octets);
                        assert_ne!(
                            j,
                            Judged::Unjudged,
                            "{}:{} read by {}/{}.{}",
                            w.vectors_path,
                            v.line,
                            m.name,
                            m.major,
                            m.minor
                        );
                        judged += 1;
                    }
                }
            }
        }
        eprintln!("{judged} wire vectors judged");
        assert!(judged > 500, "{judged}");
    });
}

/// The least time of 7 batches of `f`, in seconds.
fn best_of_7(mut f: impl FnMut()) -> f64 {
    (0..7)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64()
        })
        .fold(f64::INFINITY, f64::min)
}

/// Times `f` on `small` and on `large` (16 times as long), repeating the
/// small one so each batch runs at least a few milliseconds, and asserts
/// the per-call ratio is at most 64.
fn scales_linearly(what: &str, small: &[u8], large: &[u8], f: impl Fn(&[u8])) {
    assert!(large.len() >= 15 * small.len(), "{what}: the inputs");
    let reps = 16;
    let t_small = best_of_7(|| {
        for _ in 0..reps {
            f(std::hint::black_box(small));
        }
    }) / f64::from(reps);
    let t_large = best_of_7(|| f(std::hint::black_box(large)));
    let ratio = t_large / t_small.max(1e-9);
    eprintln!(
        "{what}: {} octets {:.3} ms, {} octets {:.3} ms, ratio {ratio:.1}",
        small.len(),
        t_small * 1e3,
        large.len(),
        t_large * 1e3
    );
    assert!(
        ratio <= 64.0,
        "{what}: 16 times the input took {ratio:.0} times as long"
    );
}

/// A long alternation of `n` octets, as the loader's limit seeds make.
fn alternation(n: usize) -> Vec<u8> {
    let mut t = b"a = \"x\"".to_vec();
    while t.len() + 6 < n {
        t.extend_from_slice(b" / \"x\"");
    }
    t.push(b'\n');
    t
}

/// About `n` octets of rules, each referring to the next. 256 KiB of
/// them stays under the loader's 16,384 rules.
fn many_rules(n: usize) -> Vec<u8> {
    let mut t = Vec::new();
    let mut i = 0;
    while t.len() + 64 < n {
        t.extend_from_slice(format!("r{i} = \"x\" / r{} \"y\"\n", i + 1).as_bytes());
        i += 1;
    }
    t.extend_from_slice(format!("r{i} = \"z\"\n").as_bytes());
    t
}

fn load(text: &[u8]) {
    let opts = LoadOptions {
        limits: FUZZ_LIMITS,
        kind: Kind::Auto,
    };
    Grammar::load("t", text, &mut repo::resolve, &opts).unwrap();
}

#[test]
fn parsers_scale_linearly() {
    let _turn = serial();
    common::on_big_stack(|| {
        let line = |n| seeds::kargs_line(n);
        scales_linearly("kargs::parse", &line(256), &line(4096), |l| {
            assert!(kargs::parse(l).all(|a| a.is_ok()));
        });
        let grub = |n: usize| {
            let mut g = b"BOOT_IMAGE=/x ".to_vec();
            while g.len() < n {
                g.extend_from_slice(b"\"a=b c\" d=e\\\\f ");
            }
            g
        };
        scales_linearly("kargs::from_grub", &grub(4096), &grub(65536), |l| {
            let mut out = vec![0u8; l.len() * 2 + 16];
            let mut word = vec![0u8; l.len() + 1];
            kargs::from_grub(l, &mut out, &mut word).unwrap();
        });
        scales_linearly(
            "Grammar::load, an alternation",
            &alternation(64 << 10),
            &alternation(1 << 20),
            load,
        );
        scales_linearly(
            "Grammar::load, many rules",
            &many_rules(16 << 10),
            &many_rules(256 << 10),
            load,
        );
        let words = |n: usize| {
            let mut w = b"not word".to_vec();
            while w.len() < n {
                w.extend_from_slice(b" w");
            }
            w
        };
        scales_linearly("constraint::parse", &words(4096), &words(65536), |t| {
            constraint::parse(std::str::from_utf8(t).unwrap()).unwrap();
        });
        let file = |n: usize| {
            let mut f = b"# rule: a\n".to_vec();
            while f.len() < n {
                f.extend_from_slice(b"ok\tabc\\x20\\t\nerr@b\t\\\"\n");
            }
            f
        };
        scales_linearly("vectors::parse", &file(64 << 10), &file(1 << 20), |t| {
            vectors::parse(t).unwrap();
        });
        // C07's targets, whole: the front end on a file of n members and
        // one of 16n, both within the agreement check's reach, so both
        // run the grammar oracle; then on files of structs either side of
        // it, 65 KiB and 1 MiB, on which only the front end runs. Their
        // fields write their positions, so each canonical form is shorter
        // than its file, and within the source limit.
        let file = |body: String| {
            format!(
                "edition 2026;\n[id(org.example.y), object_id(reserved(0x0301)), version(1.0)]\ninterface y {{\n{body}}}\n"
            )
            .into_bytes()
        };
        let members = |n: usize| file((1..=n).map(|k| format!("    @{k} m{k}();\n")).collect());
        let (small, large) = (members(200), members(3200));
        assert!(large.len() <= AGREEMENT_MAX, "{}", large.len());
        scales_linearly(
            "idl-front-end",
            &small,
            &large,
            fuzz_gate::idl_targets::front_end,
        );
        let structs = |n: usize| {
            let mut body = String::new();
            let mut k = 0;
            while body.len() + 3400 < n {
                body += &format!("    struct s{k} {{ ");
                for f in 0..200 {
                    body += &format!("@{} f{f}: u32, ", f + 1);
                }
                body += "}\n";
                k += 1;
            }
            file(body)
        };
        let (small, large) = (structs(AGREEMENT_MAX + 3400), structs(1 << 20));
        assert!(small.len() > AGREEMENT_MAX, "{}", small.len());
        assert_eq!(fuzz_gate::idl_targets::front_end_kinds(&large), ["ok"]);
        scales_linearly(
            "idl-front-end, past the agreement check",
            &small,
            &large,
            fuzz_gate::idl_targets::front_end,
        );
        // A decoder on a byte string 16 times longer: the catalog's
        // `proof`, at 512 octets and at its bound, 8192. Only the short
        // one is judged a third time with its grammar (`REJUDGE_MAX`),
        // which lowers the ratio by at most a third: quadratic work would
        // still give about 170.
        let (small, large) = proofs(512, 8192);
        scales_linearly("idl-decode", &small, &large, fuzz_gate::idl_targets::decode);
    });
}

/// `idl-decode` inputs of aspis.catalog/1.1's register request, with its
/// `proof` `small` and `large` octets long: built from its bound seed,
/// which `tests/targets.rs` holds to be there.
fn proofs(small: usize, large: usize) -> (Vec<u8>, Vec<u8>) {
    use fuzz_gate::{idl_repo, idl_targets};
    use idl::{schema::Schema, value::Value};
    let m = idl_repo::MODULES
        .iter()
        .copied()
        .find(|m| m.name == "aspis.catalog" && m.minor == 1)
        .unwrap();
    let i = idl_repo::interface_of(m).unwrap();
    let s = Schema::new(&i.checked, 1);
    let x = idl::vectors::samples(&s, &idl::vectors::Budget::default())
        .unwrap()
        .into_iter()
        .find(|x| s.top_rule(x.top) == "m-register--req")
        .unwrap();
    let w = idl_targets::widen(&s, x.top, &x.value)
        .into_iter()
        .find(|w| w.path == "proof")
        .unwrap();
    assert_eq!(w.bound, large as u64);
    // The widened value with its proof cut to `n` octets.
    fn cut(v: &Value, n: usize) -> Value {
        match v {
            Value::Bytes(b) if b.len() > n => Value::Bytes(b[..n].to_vec()),
            Value::Text(t) if t.len() > n => Value::Text(t[..n].to_string()),
            Value::Struct(f) => Value::Struct(idl::value::Fields {
                known: f
                    .known
                    .iter()
                    .map(|x| x.as_ref().map(|x| cut(x, n)))
                    .collect(),
                unknown: f.unknown.clone(),
            }),
            Value::Opt(Some(x)) => Value::Opt(Some(Box::new(cut(x, n)))),
            other => other.clone(),
        }
    }
    let input = |n: usize| {
        let enc = idl::value::encode(&s, x.top, &cut(&w.at, n), true);
        assert!(!enc.refused);
        idl_targets::decode_input(m, "m-register--req", 1, enc.caps, &enc.octets).unwrap()
    };
    (input(small), input(large))
}

/// The same on inputs that are rejected, with the error at the end, and
/// on inputs dense with escapes: a quadratic error or escape path would
/// pass every accepting case above.
#[test]
fn rejecting_and_escaping_scale_linearly() {
    let _turn = serial();
    common::on_big_stack(|| {
        // Quoted values made of `\\` and `\"` escapes.
        let escapes = |n: usize| {
            let mut l = Vec::new();
            while l.len() + 16 <= n {
                l.extend_from_slice(b"k=\"\\\\\\\"\\\\\\\"\" ");
            }
            l
        };
        scales_linearly(
            "kargs::parse, escapes",
            &escapes(256),
            &escapes(4096),
            |l| {
                assert!(kargs::parse(l).all(|a| a.is_ok()));
            },
        );
        // Valid arguments, then an unterminated quote at the very end.
        let bad_end = |n: usize| {
            let mut l = seeds::kargs_line(n - 3);
            l.extend_from_slice(b"k=\"");
            l
        };
        scales_linearly(
            "kargs::parse, error at the end",
            &bad_end(256),
            &bad_end(4096),
            |l| {
                assert!(kargs::parse(l).last().is_some_and(|a| a.is_err()));
            },
        );
        // GRUB's escapes, then a trailing backslash.
        let grub_bad = |n: usize| {
            let mut g = b"BOOT_IMAGE=/x ".to_vec();
            while g.len() < n {
                g.extend_from_slice(b"\\\\\\'\\\" ");
            }
            g.push(b'\\');
            g
        };
        scales_linearly(
            "kargs::from_grub, error at the end",
            &grub_bad(4096),
            &grub_bad(65536),
            |l| {
                let mut out = vec![0u8; l.len() * 2 + 16];
                let mut word = vec![0u8; l.len() + 1];
                assert!(kargs::from_grub(l, &mut out, &mut word).is_err());
            },
        );
        // A long `not one of` list, accepted, and one with a dangling
        // comma at the end.
        let list = |n: usize, tail: &str| {
            let mut t = b"not one of 1".to_vec();
            while t.len() + 3 + tail.len() < n {
                t.extend_from_slice(b", 2");
            }
            t.extend_from_slice(tail.as_bytes());
            String::from_utf8(t).unwrap()
        };
        scales_linearly(
            "constraint::parse, a long list",
            list(4096, "").as_bytes(),
            list(65536, "").as_bytes(),
            |t| {
                constraint::parse(std::str::from_utf8(t).unwrap()).unwrap();
            },
        );
        scales_linearly(
            "constraint::parse, error at the end",
            list(4096, ",").as_bytes(),
            list(65536, ",").as_bytes(),
            |t| {
                constraint::parse(std::str::from_utf8(t).unwrap()).unwrap_err();
            },
        );
        // Vector lines of `\xHH` escapes, then a malformed last line.
        let hex = |n: usize| {
            let mut f = b"# rule: a\n".to_vec();
            while f.len() < n {
                f.extend_from_slice(b"ok\t\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\n");
            }
            f.extend_from_slice(b"ok\t\\x4\n");
            f
        };
        scales_linearly(
            "vectors::parse, error at the end",
            &hex(64 << 10),
            &hex(1 << 20),
            |t| {
                vectors::parse(t).unwrap_err();
            },
        );
        // A long alternation with a syntax error at its end.
        let alt_bad = |n: usize| {
            let mut t = alternation(n - 2);
            t.pop();
            t.extend_from_slice(b" /\n");
            t
        };
        let opts = LoadOptions {
            limits: FUZZ_LIMITS,
            kind: Kind::Auto,
        };
        scales_linearly(
            "Grammar::load, error at the end",
            &alt_bad(64 << 10),
            &alt_bad(1 << 20),
            |t| {
                let e = Grammar::load("t", t, &mut repo::resolve, &opts).unwrap_err();
                assert_eq!(e.kind, GrammarErrorKind::Syntax);
            },
        );
        // `idl-names` on labels joined by dots with a bad octet at the
        // end, 84 and 1344 octets: every parser refuses them, and the
        // agreement check judges every rule.
        let dotted = |n: usize| {
            let mut d = b"a.".repeat(n / 2 - 1);
            d.extend_from_slice(b"a!");
            d
        };
        scales_linearly(
            "idl-names, error at the end",
            &dotted(84),
            &dotted(1344),
            |d| {
                assert_eq!(fuzz_gate::idl_targets::names_kinds(d), ["refused"]);
                fuzz_gate::idl_targets::names(d);
            },
        );
    });
}

#[test]
fn depth_is_limited() {
    let _turn = serial();
    common::on_big_stack(|| {
        let opts = LoadOptions {
            limits: FUZZ_LIMITS,
            kind: Kind::Auto,
        };
        let nest = |n: usize| format!("a = {}\"x\"{}\n", "(".repeat(n), ")".repeat(n));
        assert!(Grammar::load("t", nest(64).as_bytes(), &mut repo::resolve, &opts).is_ok());
        let e = Grammar::load("t", nest(65).as_bytes(), &mut repo::resolve, &opts).unwrap_err();
        assert_eq!(e.kind, GrammarErrorKind::TooDeep);
        // The matcher's own limit, at the fuzz limits' depth: 30,000
        // nested calls asked for, 768 allowed.
        let g = Grammar::load(
            "t",
            b"a = \"(\" a \")\" / \"x\"\n",
            &mut repo::resolve,
            &opts,
        )
        .unwrap();
        let mut deep = vec![b'('; 30_000];
        deep.push(b'x');
        deep.extend(vec![b')'; 30_000]);
        assert_eq!(
            g.matches(g.rule("a").unwrap(), &deep),
            Err(Exhausted::Depth)
        );
    });
}

/// `idl-decode` judges its longest inputs within the limits its wire
/// grammars match with ([`WIRE_LIMITS`](fuzz_gate::WIRE_LIMITS)), and
/// within half its timeout in this build: for each rule each module
/// reads, its longest seed padded to the target's longest input, a
/// message past idl-rt's 16 KiB cap, with `a` (a text octet, which a
/// string or an open tail takes) and with `0xff`. An input the grammar can't judge panics.
#[test]
fn idl_decode_judges_its_longest_inputs() {
    use fuzz_gate::idl_targets;
    common::on_big_stack(|| {
        let t = fuzz_gate::target("idl-decode").unwrap();
        let mut longest = std::collections::BTreeMap::new();
        for (_, bytes) in (t.seeds)() {
            let Some((m, rest)) = idl_targets::split_frame(&bytes) else {
                continue;
            };
            let Some(p) = idl_targets::pick(m, rest) else {
                continue;
            };
            let key = (m.name, m.major, m.minor, p.minor, p.rule);
            let e = longest.entry(key).or_insert_with(Vec::new);
            if bytes.len() > e.len() {
                *e = bytes.clone();
            }
        }
        let max = t.max_len;
        let mut judged = 0;
        let mut slowest = (0.0f64, String::new());
        for (key, bytes) in &longest {
            for pad in [b'a', 0xff] {
                let mut input = bytes.clone();
                input.resize(max, pad);
                let start = Instant::now();
                // None for a rule the reading minor lacks.
                let j = idl_targets::decode_judged(&input);
                let secs = start.elapsed().as_secs_f64();
                judged += usize::from(j.is_some());
                if secs > slowest.0 {
                    slowest = (secs, format!("{key:?} padded with {pad:#04x}"));
                }
            }
        }
        eprintln!(
            "idl-decode: {} rules padded to {max} octets, {judged} judged; slowest {} at {:.1} ms",
            longest.len(),
            slowest.1,
            slowest.0 * 1e3
        );
        assert!(judged > 500, "{judged}");
        assert!(
            slowest.0 < f64::from(t.timeout_s) / 2.0,
            "{}: {:.0} ms",
            slowest.1,
            slowest.0 * 1e3
        );
    });
}

/// Every message C07's generator makes is judged within the limits
/// `idl-generated` matches with ([`WIRE_LIMITS`](fuzz_gate::WIRE_LIMITS):
/// 8 M steps a match):
/// every seed, and 16 inputs of [`SplitMix64`](fuzz_gate::generate::SplitMix64)
/// octets for each top-level body of every module at every minor it
/// reads, of 0, 8, ..., 120 octets, as `crates/idl/tests/fuzz.rs` grows
/// them. Each must be accepted by the binding, the grammar and the
/// dynamic codec, and none may run out of the grammar's budget: C07's
/// own test asserts `matches_constrained == Ok(true)` on such values, and
/// this shows the target's limits keep that.
#[test]
fn generated_messages_are_judged() {
    use fuzz_gate::{generate::SplitMix64, idl_repo, idl_targets};
    use idl::{conformance::Judged, schema::Schema};
    common::on_big_stack(|| {
        let t = fuzz_gate::target("idl-generated").unwrap();
        let mut judged = 0;
        for (name, bytes) in (t.seeds)() {
            let j = idl_targets::generated_judged(&bytes);
            assert_ne!(j, Some(Judged::Unjudged), "{name}");
            judged += usize::from(j.is_some());
        }
        for &m in idl_repo::MODULES.iter() {
            let i = idl_repo::interface_of(m).unwrap();
            for minor in 0..=m.minor {
                let s = Schema::new(&i.checked, minor);
                for (k, top) in s.tops().into_iter().enumerate() {
                    let mut src = SplitMix64(u64::from(minor) << 16 | k as u64);
                    for n in 0..16 {
                        let choices: Vec<u8> =
                            (0..n).flat_map(|_| src.next_u64().to_le_bytes()).collect();
                        let j = idl_targets::generated_with(m, m, minor, top, &choices);
                        assert_eq!(
                            j,
                            Some(Judged::Accepted),
                            "{}/{}.{} at {minor}: {}",
                            m.name,
                            m.major,
                            m.minor,
                            s.top_rule(top)
                        );
                        judged += 1;
                    }
                }
            }
        }
        eprintln!("{judged} generated messages judged");
    });
}
