// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The budgets that bound every match (ADR 0027, rule 2; ADR 0062,
//! rule 8): adversarial grammars and inputs end with the exact
//! [`Exhausted`] they should, quickly and without overflowing the stack,
//! and valid inputs at the default limits still pass.

use std::time::{Duration, Instant};

use abnf::{Context, Exhausted, Grammar, GrammarErrorKind, Limits, LoadOptions};

fn grammar(text: &str, limits: Limits) -> Grammar {
    let core = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../grammars/core.abnf"
    ))
    .unwrap();
    let opts = LoadOptions {
        limits,
        ..LoadOptions::default()
    };
    Grammar::load("t", text.as_bytes(), &mut |_| Some(core.clone()), &opts).unwrap()
}

fn run(g: &Grammar, rule: &str, input: &[u8]) -> Result<bool, Exhausted> {
    g.matches(g.rule(rule).unwrap(), input)
}

/// With constraints on, which takes bigger frames and more state.
fn run_c(g: &Grammar, rule: &str, input: &[u8]) -> Result<bool, Exhausted> {
    g.matches_constrained(g.rule(rule).unwrap(), input, &Context::default())
}

/// Both readings agree.
fn both(g: &Grammar, rule: &str, input: &[u8]) -> Result<bool, Exhausted> {
    let cf = run(g, rule, input);
    assert_eq!(run_c(g, rule, input), cf);
    cf
}

/// Runs `f` on a thread with a 1 MiB stack, the smallest the default depth
/// is meant for, and fails on overflow (which would abort the process).
fn on_small_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap()
}

#[test]
fn depth() {
    on_small_stack(|| {
        let g = grammar("a = \"(\" a \")\" / \"x\"\n", Limits::default());
        let mut input = vec![b'('; 60_000];
        input.push(b'x');
        assert_eq!(both(&g, "a", &input), Err(Exhausted::Depth));
        // Shallow enough is fine.
        let ok = [&[b'('; 100][..], b"x", &[b')'; 100][..]].concat();
        assert_eq!(both(&g, "a", &ok), Ok(true));
        // A constrained rule takes the spanned path, with its checks.
        let g = grammar(
            "; uses: core\na = \"(\" a \")\" / u8\nb = a ; constraint: length at most 65536\n",
            Limits::default(),
        );
        assert_eq!(run_c(&g, "b", &input), Err(Exhausted::Depth));
    });
}

/// The deepest grammar nesting the default limits allow, 64 groups,
/// inside a recursive rule, still ends in `Depth` on a 1 MiB stack.
#[test]
fn depth_with_the_deepest_nesting() {
    on_small_stack(|| {
        let text = format!(
            "a = {}\"(\" a \")\" / \"x\" / \"y\" b{}\nb = \"z\"\n",
            "(".repeat(64),
            ")".repeat(64)
        );
        let g = grammar(&text, Limits::default());
        let mut input = vec![b'('; 10_000];
        input.push(b'x');
        assert_eq!(both(&g, "a", &input), Err(Exhausted::Depth));
        assert_eq!(both(&g, "a", b"((x))"), Ok(true));
    });
}

/// Repetitions nest a level each, as groups and calls do, so the deepest
/// nesting of repetitions inside a recursive rule also ends in `Depth` on
/// a 1 MiB stack: context-free, through a constrained rule, and through a
/// target.
#[test]
fn depth_with_nested_repetitions() {
    on_small_stack(|| {
        let nest = |n: usize, inner: &str| format!("{}{inner}{}", "1*1(".repeat(n), ")".repeat(n));
        let mut input = vec![b'('; 10_000];
        input.push(b'x');
        let cases = [
            (format!("a = {} / \"x\"\n", nest(64, "\"(\" a \")\"")), "a"),
            (
                format!(
                    "; uses: core\nb = a ; constraint: length at most 65536\n\
                     a = {} / \"x\"\n",
                    nest(64, "\"(\" b \")\"")
                ),
                "a",
            ),
            (
                format!(
                    "; uses: core\nb = *a ; constraint: remaining octets\n\
                     a = {} / \"x\"\n",
                    nest(63, "\"(\" b \")\"")
                ),
                "b",
            ),
            (
                format!(
                    "a = {} / \"x\"\n",
                    "[".repeat(64) + "\"(\" a \")\"" + &"]".repeat(64)
                ),
                "a",
            ),
        ];
        for (text, rule) in cases {
            let g = grammar(&text, Limits::default());
            assert_eq!(both(&g, rule, &input), Err(Exhausted::Depth), "{text}");
            // Shallow enough is fine. (A nested b can't run to the end of
            // the message, so the target case nests only context-free.)
            assert_eq!(run(&g, rule, b"((x))"), Ok(true), "{text}");
            assert_eq!(run_c(&g, rule, b"x"), Ok(true), "{text}");
        }
    });
}

/// Constraint work is charged as steps: reading a match's value, and
/// looking R up through the callers' frames. Work that grows faster than
/// the input runs out of steps quickly, and constraints written many times
/// over are checked once.
#[test]
fn constraint_work_is_charged() {
    let start = Instant::now();
    // Every prefix of a run of zeros is a match of d, read for its value.
    let g = grammar(
        "; uses: core\nx = *d \"!\"\nd = *DIGIT ; constraint: at most 5\n",
        Limits::default(),
    );
    assert_eq!(run_c(&g, "x", &vec![b'0'; 16_000]), Err(Exhausted::Steps));
    assert_eq!(run_c(&g, "x", b"00105!"), Ok(true));
    assert_eq!(run_c(&g, "x", b"6!"), Ok(false));

    // The same bound 20,000 times, inside 100 recursive calls, is one bound.
    let mut text = String::from(
        "; uses: core\ntop = u8 a\na = \"(\" a \")\" / c\nc = *( b \"y\" )\nb = *\"z\"\n",
    );
    text.push_str(&"  ; constraint: exactly u8 octets\n".repeat(20_000));
    let g = grammar(&text, Limits::default());
    let mut input = vec![1u8];
    input.extend([b'('; 100]);
    input.extend(b"zy".repeat(10_000));
    input.extend([b')'; 100]);
    assert_eq!(run_c(&g, "top", &input), Ok(true));

    // 2,000 distinct bounds, each looked up through 100 callers' frames,
    // run out of steps.
    let k = 2_000;
    let names: Vec<String> = (0..k).map(|i| format!("r{i}")).collect();
    let mut text = format!(
        "; uses: core\ntop = {} a\na = \"(\" a \")\" / c\nc = *( b \"y\" )\nb = *\"z\"\n",
        names.join(" ")
    );
    for n in &names {
        text.push_str(&format!("  ; constraint: exactly {n} octets\n"));
    }
    for n in &names {
        text.push_str(&format!("{n} = u8\n"));
    }
    let g = grammar(&text, Limits::default());
    let mut deep = vec![1u8; k];
    deep.extend(&input[1..]);
    assert_eq!(run_c(&g, "top", &deep), Err(Exhausted::Steps));
    assert!(start.elapsed() < Duration::from_secs(20));
}

/// Work that grows with the square of the input runs out of steps. Each of
/// n iterations starts a `*OCTET` that reads to the end.
#[test]
fn steps() {
    let limits = Limits {
        steps_base: 0,
        steps_per_octet: 100,
        memory: usize::MAX,
        input_octets: 1 << 20,
        ..Limits::default()
    };
    let g = grammar("s = *( OCTET / OCTET *OCTET \"!\" ) \"?\"\n", limits);
    let start = Instant::now();
    assert_eq!(run(&g, "s", &vec![b'a'; 50_000]), Err(Exhausted::Steps));
    assert!(start.elapsed() < Duration::from_secs(10));
}

/// A nullable element counted 2^32 - 1 times runs out of steps, rather than
/// looping.
#[test]
fn a_nullable_element_counted_many_times() {
    let g = grammar("x = 4294967295( *\"a\" )\n", Limits::default());
    assert_eq!(run(&g, "x", b""), Err(Exhausted::Steps));
    // With no lower count, the loop ends as soon as nothing new is reached.
    let g = grammar("x = *4294967295( *\"a\" ) \"b\"\n", Limits::default());
    assert_eq!(run(&g, "x", b"aaab"), Ok(true));
    // The count can come from a constraint, too.
    let g = grammar(
        "; uses: core\n\
         x = len32 *e ; constraint: exactly len32 e elements\n\
         e = *\"a\"\n",
        Limits::default(),
    );
    let start = Instant::now();
    assert_eq!(run_c(&g, "x", b"\xff\xff\xff\xff"), Err(Exhausted::Steps));
    assert!(start.elapsed() < Duration::from_secs(30));
    assert_eq!(run_c(&g, "x", b"\x00\x00\x00\x03aa"), Ok(true));
}

#[test]
fn memory() {
    let limits = Limits {
        memory: 1 << 20,
        steps_max: u64::MAX,
        input_octets: 1 << 20,
        ..Limits::default()
    };
    let g = grammar("s = *OCTET *OCTET *OCTET \"!\"\n", limits);
    assert_eq!(run(&g, "s", &vec![b'a'; 100_000]), Err(Exhausted::Memory));
}

#[test]
fn counts_that_cannot_fit() {
    let g = grammar("big = 4294967295OCTET\n", Limits::default());
    let start = Instant::now();
    assert_eq!(run(&g, "big", &[0; 10]), Ok(false));
    assert!(start.elapsed() < Duration::from_millis(100));
    let core = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../grammars/core.abnf"
    ))
    .unwrap();
    let e = Grammar::load(
        "t",
        b"big = 4294967296OCTET\n",
        &mut |_| Some(core.clone()),
        &LoadOptions::default(),
    )
    .unwrap_err();
    assert_eq!(e.kind, GrammarErrorKind::RepeatRange);
}

#[test]
fn input() {
    let limits = Limits {
        input_octets: 16,
        ..Limits::default()
    };
    let g = grammar("r = *OCTET\n", limits);
    assert_eq!(run(&g, "r", &[0; 16]), Ok(true));
    assert_eq!(run(&g, "r", &[0; 17]), Err(Exhausted::Input));
}

/// Backtracking that would be exponential in a naive matcher is linear in
/// sets of states.
#[test]
fn ambiguity_is_linear() {
    let g = grammar("a = *( \"a\" / \"aa\" ) \"b\"\n", Limits::default());
    let start = Instant::now();
    assert_eq!(run(&g, "a", &vec![b'a'; 10_000]), Ok(false));
    let mut yes = vec![b'a'; 10_000];
    yes.push(b'b');
    assert_eq!(run(&g, "a", &yes), Ok(true));
    // Nested repetitions are linear too.
    let g = grammar("s = *( *OCTET ) \"!\"\n", Limits::default());
    assert_eq!(run(&g, "s", &vec![b'a'; 50_000]), Ok(false));
    assert!(start.elapsed() < Duration::from_secs(5));
}

/// Valid inputs as long as the default input limit pass under the default
/// budgets, so a valid vector is never reported as exhausted.
#[test]
fn defaults_accept_the_largest_inputs() {
    let max = Limits::default().input_octets;
    let g = grammar("; uses: core\nbody = *OCTET\n", Limits::default());
    let start = Instant::now();

    let len = |n: usize| u32::try_from(n).unwrap().to_be_bytes();
    let octets = [&len(max - 4)[..], &vec![0xa5; max - 4]].concat();
    assert_eq!(both(&g, "octets", &octets), Ok(true));

    // U+1F600 is four octets.
    let text = [
        &len(max - 4)[..],
        &"\u{1f600}".repeat((max - 4) / 4).into_bytes(),
    ]
    .concat();
    assert_eq!(text.len(), max);
    assert_eq!(both(&g, "text", &text), Ok(true));

    assert_eq!(both(&g, "body", &vec![0; max]), Ok(true));
    // A tail of 10,000 empty fields, each with its tag in order.
    let mut tail = 10_000u32.to_be_bytes().to_vec();
    for t in 1..=10_000u16 {
        tail.extend(t.to_be_bytes());
        tail.extend([0; 4]);
    }
    assert!(tail.len() <= max);
    assert_eq!(both(&g, "tail", &tail), Ok(true));
    assert!(start.elapsed() < Duration::from_secs(10));
}

#[test]
fn deterministic() {
    let g = grammar("a = *( \"a\" / \"aa\" ) [\"b\"]\n", Limits::default());
    let input = vec![b'a'; 1_000];
    let first = run(&g, "a", &input);
    for _ in 0..3 {
        assert_eq!(run(&g, "a", &input), first);
    }
}
