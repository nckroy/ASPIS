// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Each oracle catches a wrong subject. An oracle that passes everything
//! would make the gate's CPU-hours worthless, so each one is handed a
//! subject with a deliberate bug and must fail on an input that shows it
//! (and pass the real subject on the same input).

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};

use abnf::{
    constraint::Constraint,
    vectors::{self, Verdict},
};
use fuzz_gate::{generate::SplitMix64, idl_repo, idl_targets, oracle, repo};
use idl::{conformance::Judged, schema::Schema};
use idl_rt::{
    conformance::Subject,
    json::JsonWriter,
    rules::{Module, Op, Verdict as Decoded},
};

/// Held while the panic hook is swapped: the hook is global, and the
/// tests run on several threads.
static HOOK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Whether `f` panics, with the panic's message kept off the test output.
fn panics(f: impl FnOnce()) -> bool {
    let _held = HOOK.lock().unwrap_or_else(|e| e.into_inner());
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(f)).is_err();
    std::panic::set_hook(hook);
    r
}

#[test]
fn kargs_agreement_catches_a_lenient_parser() {
    common::on_big_stack(|| {
        // A parser that also takes a trailing tab, which the grammar
        // doesn't allow.
        let lenient = |l: &[u8]| {
            oracle::kargs_accepts(l) || l.strip_suffix(b"\t").is_some_and(oracle::kargs_accepts)
        };
        let line = b"console=uart\t";
        assert!(!panics(|| oracle::check_kargs_agreement(
            line,
            oracle::kargs_accepts
        )));
        assert!(panics(|| oracle::check_kargs_agreement(line, lenient)));
        // And one that refuses a value with an escaped quote.
        let strict = |l: &[u8]| oracle::kargs_accepts(l) && !l.contains(&b'\\');
        let line = br#"a="say \"hi\"""#;
        assert!(!panics(|| oracle::check_kargs_agreement(
            line,
            oracle::kargs_accepts
        )));
        assert!(panics(|| oracle::check_kargs_agreement(line, strict)));
    });
}

#[test]
fn constraint_agreement_catches_a_wrong_reader() {
    common::on_big_stack(|| {
        // A reader that takes "-0", which the grammar excludes.
        let lenient = |t: &str| oracle::constraint_accepts(t) || t == "not -0";
        let real = || {
            oracle::check_constraint_agreement(
                b"not -0",
                oracle::constraint_accepts,
                oracle::comment_accepts,
            )
        };
        assert!(!panics(real));
        assert!(panics(|| oracle::check_constraint_agreement(
            b"not -0",
            lenient,
            oracle::comment_accepts
        )));
        // A comment reader that needs no space after the marker.
        let lenient =
            |c: &str| oracle::comment_accepts(c) || oracle::comment_accepts(&c.replace(":", ": "));
        let c = b"; constraint:not 1";
        assert!(!panics(|| oracle::check_constraint_agreement(
            c,
            oracle::constraint_accepts,
            oracle::comment_accepts
        )));
        assert!(panics(|| oracle::check_constraint_agreement(
            c,
            oracle::constraint_accepts,
            lenient
        )));
    });
}

#[test]
fn constraint_round_trip_catches_a_lossy_encoder() {
    // An encoder that drops the last word of a word list.
    let lossy = |c: &Constraint| match c {
        Constraint::NotWord(w) if w.len() > 1 => format!("not word {}", w[..w.len() - 1].join(" ")),
        c => oracle::render_constraint(c),
    };
    let text = "not word a b c";
    assert!(!panics(|| oracle::check_constraint_round_trip(
        text,
        oracle::render_constraint
    )));
    assert!(panics(|| oracle::check_constraint_round_trip(text, lossy)));
    // Every vector line of grammars/constraint.vectors round-trips.
    for (_, line) in fuzz_gate::seeds::octets_of("constraint") {
        if let Ok(s) = std::str::from_utf8(&line) {
            oracle::check_constraint_round_trip(s, oracle::render_constraint);
        }
    }
}

#[test]
fn kargs_round_trip_catches_a_lossy_renderer() {
    // A renderer that forgets to escape a backslash in a quoted value.
    let lossy = |args: &[kargs::Arg<'_>]| {
        let out = oracle::render_kargs(args);
        String::from_utf8(out)
            .unwrap()
            .replace("\\\\", "\\")
            .into_bytes()
    };
    let line = br#"a="x y\\z""#;
    assert!(!panics(|| oracle::check_kargs_round_trip(
        line,
        oracle::render_kargs
    )));
    assert!(panics(|| oracle::check_kargs_round_trip(line, lossy)));
}

#[test]
fn grub_round_trip_catches_a_wrong_encoder() {
    // An encoder that forgets to escape `\` (GRUB escapes `\`, `'` and
    // `"`). Forgetting `'` alone would go unseen: the stub reads `'` as
    // itself, so `it's` and `it\'s` both convert to `it's`.
    let no_backslash = |words: &[Vec<u8>]| {
        let mut w: Vec<Vec<u8>> = words.to_vec();
        for x in &mut w {
            // Hide the backslashes from the real encoder, then put them
            // back unescaped.
            for b in x.iter_mut() {
                if *b == b'\\' {
                    *b = 0x01;
                }
            }
        }
        oracle::grub_encode(&w)
            .into_iter()
            .map(|b| if b == 0x01 { b'\\' } else { b })
            .collect()
    };
    let line = br#"a=b\c"#;
    assert!(!panics(|| oracle::check_grub_round_trip(
        line,
        oracle::grub_encode
    )));
    assert!(panics(|| oracle::check_grub_round_trip(line, no_backslash)));
    // And one that forgets to quote a word with a space.
    let no_quotes = |words: &[Vec<u8>]| {
        let mut out = b"BOOT_IMAGE=/x".to_vec();
        for w in words {
            out.push(b' ');
            out.extend_from_slice(w);
        }
        out
    };
    let line = br#"root.name="a b""#;
    assert!(!panics(|| oracle::check_grub_round_trip(
        line,
        oracle::grub_encode
    )));
    assert!(panics(|| oracle::check_grub_round_trip(line, no_quotes)));
}

#[test]
fn report_invariants_catch_a_miscount() {
    common::on_big_stack(|| {
        let g = repo::loaded("kernel-args").unwrap();
        let f = vectors::parse(b"# rule: kernel-args\nok\ta=b\nerr\tA\nok\tx\n").unwrap();
        let r = vectors::check(g, &f);
        assert!(!panics(|| oracle::check_report(&f, &r)));
        let mut off = r.clone();
        off.agree += 1;
        assert!(panics(|| oracle::check_report(&f, &off)));
        let mut off = r.clone();
        off.results[1].1 = Verdict::Disagrees {
            context_free: false,
            constrained: true,
        };
        off.agree -= 1;
        off.disagree += 1;
        assert!(panics(|| oracle::check_report(&f, &off)));
        let mut off = r;
        off.results.pop();
        assert!(panics(|| oracle::check_report(&f, &off)));
    });
}

#[test]
fn names_agreement_catches_a_lenient_parser() {
    common::on_big_stack(|| {
        // A parser that also takes uppercase letters in a label, which
        // the grammar doesn't allow.
        let lenient =
            |rule: &str, input: &[u8]| oracle::names_accepts(rule, &input.to_ascii_lowercase());
        let input = b"org.Example/1";
        assert!(!panics(|| oracle::check_names_agreement(
            input,
            oracle::names_accepts
        )));
        assert!(panics(|| oracle::check_names_agreement(input, lenient)));
    });
}

#[test]
fn idl_agreement_catches_a_wrong_parser() {
    common::on_big_stack(|| {
        // A parser that flips its verdict.
        let flipped = |f: &[u8]| oracle::idl_file_verdict(f).map(|v| !v);
        let file = idl_repo::INTERFACES[0].idl;
        assert!(!panics(|| oracle::check_idl_agreement(
            file,
            oracle::idl_file_verdict
        )));
        assert!(panics(|| oracle::check_idl_agreement(file, flipped)));
        let bad = b"edition 2026;\ninterface";
        assert!(!panics(|| oracle::check_idl_agreement(
            bad,
            oracle::idl_file_verdict
        )));
        assert!(panics(|| oracle::check_idl_agreement(bad, flipped)));
    });
}

/// A binding with a deliberate bug, around a real module.
struct Broken {
    inner: &'static Module,
    bug: Bug,
}

#[derive(Clone, Copy)]
enum Bug {
    /// Every message of the rule is malformed.
    Refuses(&'static str),
    /// Every message is malformed.
    RefusesAll,
    /// The re-encoding's first octet is flipped.
    Encodes,
    /// The JSON of a `point` has `x` and `y` swapped, while the
    /// re-encoding stays right: a decoder and encoder that share one bug.
    SwapsJson,
}

impl Subject for Broken {
    fn name(&self) -> &str {
        self.inner.name
    }

    fn major(&self) -> u16 {
        self.inner.major
    }

    fn minor(&self) -> u16 {
        self.inner.minor
    }

    fn run(&self, rule: &str, minor: u16, caps: u8, input: &[u8], op: Op<'_, '_>) -> Decoded {
        match (self.bug, op) {
            (Bug::Refuses(r), _) if r == rule => Decoded::Malformed,
            (Bug::RefusesAll, _) => Decoded::Malformed,
            (Bug::Encodes, Op::Encode(out)) => {
                let v = self.inner.run(rule, minor, caps, input, Op::Encode(out));
                if let Decoded::Ok { len, .. } = v
                    && len > 0
                {
                    out[0] ^= 1;
                }
                v
            }
            (Bug::SwapsJson, Op::Json(j)) if rule == "t-point" => {
                let mut buf = vec![0u8; 4096];
                let mut own = JsonWriter::new(&mut buf);
                let v = self.inner.run(rule, minor, caps, input, Op::Json(&mut own));
                let text = std::str::from_utf8(own.finish().unwrap()).unwrap();
                j.embedded(&swap_xy(text));
                v
            }
            (_, op) => self.inner.run(rule, minor, caps, input, op),
        }
    }
}

/// A point's JSON with its `x` and `y` values swapped.
fn swap_xy(json: &str) -> String {
    let span = |key: &str| {
        let start = json.find(key).unwrap() + key.len();
        let end = start + json[start..].find([',', '}']).unwrap();
        (start, end)
    };
    let (xs, xe) = span("\"x\":");
    let (ys, ye) = span("\"y\":");
    format!(
        "{}{}{}{}{}",
        &json[..xs],
        &json[ys..ye],
        &json[xe..ys],
        &json[xs..xe],
        &json[ye..]
    )
}

fn module(name: &str) -> &'static Module {
    idl_repo::MODULES
        .iter()
        .copied()
        .filter(|m| m.name == name)
        .max_by_key(|m| m.minor)
        .unwrap()
}

#[test]
fn differential_catches_a_wrong_decoder() {
    common::on_big_stack(|| {
        let m = module("aspis.rpc");
        let i = idl_repo::interface_of(m).unwrap();
        let s = Schema::new(&i.checked, 0);
        let g = i.wire_grammar(0);
        // An ok vector of aspis.rpc/1.0's `e-malformed`: an empty detail.
        let msg = [0u8; 4];
        assert_eq!(
            idl_targets::differential_of(m, &s, g, "e-malformed", 0, &msg),
            Judged::Accepted
        );
        for bug in [Bug::Refuses("e-malformed"), Bug::Encodes] {
            let broken = Broken { inner: m, bug };
            assert!(panics(|| {
                idl_targets::differential_of(&broken, &s, g, "e-malformed", 0, &msg);
            }));
        }
    });
}

#[test]
fn generated_catches_a_refusing_decoder() {
    common::on_big_stack(|| {
        let m = module("aspis.rpc");
        let i = idl_repo::interface_of(m).unwrap();
        let s = Schema::new(&i.checked, 0);
        let top = s.tops()[0];
        let refusing = Broken {
            inner: m,
            bug: Bug::RefusesAll,
        };
        assert_eq!(
            idl_targets::generated_with(m, m, 0, top, &[]),
            Some(Judged::Accepted)
        );
        assert!(panics(|| {
            idl_targets::generated_with(&refusing, m, 0, top, &[]);
        }));
    });
}

/// A decoder and encoder that share one bug (here, `x` and `y` read into
/// each other's place and written back from it) re-encode byte for byte
/// and agree with the grammar, so the differential passes them; only the
/// value check, the binding's JSON against the dynamic codec's, catches
/// them, on a vector and on a generated value.
#[test]
fn the_value_check_catches_a_shared_bug() {
    common::on_big_stack(|| {
        assert_eq!(
            swap_xy(r#"{"x":1,"y":-2,"z":3}"#),
            r#"{"x":-2,"y":1,"z":3}"#
        );
        let m = module("org.example.base");
        let swapped = Broken {
            inner: m,
            bug: Bug::SwapsJson,
        };
        let i = idl_repo::interface_of(m).unwrap();
        let s = Schema::new(&i.checked, m.minor);
        // A point with x 1 and y 0, and no tail.
        let msg = [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let g = i.wire_grammar(m.minor);
        assert_eq!(
            idl_targets::differential_of(&swapped, &s, g, "t-point", 0, &msg),
            Judged::Accepted
        );
        let rest = idl_targets::decode_input(m, "t-point", m.minor, 0, &msg).unwrap();
        let rest = &rest[idl_repo::frame(m).len()..];
        assert_eq!(idl_targets::decode_with(m, m, rest), Some(Judged::Accepted));
        assert!(panics(|| {
            idl_targets::decode_with(&swapped, m, rest);
        }));
        // Generated points: some has x and y apart.
        let top = idl_targets::top_of(&s, "t-point").unwrap();
        let mut caught = 0;
        for n in 1..16 {
            let mut src = SplitMix64(n);
            let choices: Vec<u8> = (0..4).flat_map(|_| src.next_u64().to_le_bytes()).collect();
            assert_eq!(
                idl_targets::generated_with(m, m, m.minor, top, &choices),
                Some(Judged::Accepted)
            );
            caught += usize::from(panics(|| {
                idl_targets::generated_with(&swapped, m, m.minor, top, &choices);
            }));
        }
        assert!(caught > 0, "no generated point had x and y apart");
    });
}

/// With its constraints, the reference matcher's work on a label or
/// member name is quadratic in its length, so a long run of name octets
/// runs it out of steps. The agreement checks leave such an input
/// unjudged, and only such an input.
#[test]
fn long_name_runs_are_left_unjudged() {
    common::on_big_stack(|| {
        assert_eq!(
            oracle::name_run_steps(b"ab_9.Cd/x"),
            4 * 4 / 2 * oracle::NAME_RUN_TRIES
        );
        let run = vec![b'a'; 1350];
        assert_eq!(
            oracle::names_grammar_accepts("names", "action-ref", &run),
            None
        );
        assert!(!panics(|| oracle::check_names_agreement(
            &run,
            oracle::names_accepts
        )));
        // A wrong parser is still caught on the rules the matcher judges.
        assert!(panics(|| oracle::check_names_agreement(&run, |_, _| true)));
        let file = format!(
            "edition 2026;\n[id(org.example.y)]\ninterface {} {{\n}}\n",
            "a".repeat(64 << 10)
        );
        assert_eq!(
            oracle::names_grammar_accepts("idl", "idl-file", file.as_bytes()),
            None
        );
        assert!(!panics(|| oracle::check_idl_agreement(
            file.as_bytes(),
            oracle::idl_file_verdict
        )));
        // Running out of steps is still a finding on an input whose name
        // runs don't explain it: the 64 hex digits of an `object_id`, or
        // of an interface ID's text, are a run of name octets too.
        for i in idl_repo::INTERFACES {
            assert!(!oracle::name_runs_explain_exhaustion(i.idl), "{}", i.path);
            assert!(panics(|| {
                oracle::names_verdict("idl", "idl-file", i.idl, Err(abnf::Exhausted::Steps));
            }));
            assert_eq!(
                oracle::names_verdict("idl", "idl-file", i.idl, Ok(true)),
                Some(true)
            );
        }
        let id_text = "0123456789abcdef".repeat(4);
        assert!(panics(|| {
            oracle::names_verdict(
                "names",
                "interface-ref",
                id_text.as_bytes(),
                Err(abnf::Exhausted::Steps),
            );
        }));
        // A long run explains it, but no other budget.
        assert!(oracle::name_runs_explain_exhaustion(&run));
        assert!(panics(|| {
            oracle::names_verdict("names", "action-ref", &run, Err(abnf::Exhausted::Memory));
        }));
        // A short run is judged.
        assert_eq!(
            oracle::names_grammar_accepts("names", "label", &[b'a'; 64]),
            Some(false)
        );
        assert_eq!(
            oracle::names_grammar_accepts("names", "label", &[b'a'; 63]),
            Some(true)
        );
    });
}
