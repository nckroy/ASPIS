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
use fuzz_gate::{oracle, repo};

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
