// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Checks the parser against an independent reference: a backtracking
//! matcher that follows `grammars/kernel-args.abnf` rule by rule and tracks
//! every possible end position, as a generic ABNF matcher would.
//!
//! Every line up to six bytes over a small alphabet is checked exhaustively,
//! then longer pseudo-random lines. For each line the test checks that:
//!
//! - the parser accepts it exactly when the reference does;
//! - the arguments it yields are the line's own text, in order, separated by
//!   one or more spaces, with nothing but spaces before the first and after
//!   the last;
//! - an error is yielded once, last, and points where its kind says: at the
//!   first byte that no valid line could have there, or at the opening quote
//!   or the backslash.

use std::collections::BTreeSet;

use kargs::{Arg, ErrorKind, MAX_LEN, Value};

type Ends = BTreeSet<usize>;

fn byte(s: &[u8], i: usize, ok: impl Fn(u8) -> bool) -> Ends {
    s.get(i)
        .filter(|&&b| ok(b))
        .map(|_| i + 1)
        .into_iter()
        .collect()
}

/// `min*` repetitions of `f`, starting at every position in `from`.
fn rep(s: &[u8], from: &Ends, min: usize, f: &dyn Fn(&[u8], usize) -> Ends) -> Ends {
    let mut out = Ends::new();
    let mut frontier = from.clone();
    let mut seen = Ends::new();
    let mut count = 0;
    loop {
        if count >= min {
            out.extend(frontier.iter().copied());
        }
        let mut next = Ends::new();
        for &p in &frontier {
            for e in f(s, p) {
                // A repetition that consumes nothing adds nothing new.
                if e > p && (count < min || seen.insert(e)) {
                    next.insert(e);
                }
            }
        }
        if next.is_empty() {
            return out;
        }
        frontier = next;
        count += 1;
    }
}

fn then(s: &[u8], from: &Ends, f: &dyn Fn(&[u8], usize) -> Ends) -> Ends {
    from.iter().flat_map(|&p| f(s, p)).collect()
}

fn one(i: usize) -> Ends {
    [i].into_iter().collect()
}

fn sp(s: &[u8], i: usize) -> Ends {
    byte(s, i, |b| b == b' ')
}

fn lower(s: &[u8], i: usize) -> Ends {
    byte(s, i, |b| (0x61..=0x7A).contains(&b))
}

fn segment(s: &[u8], i: usize) -> Ends {
    let first = lower(s, i);
    rep(s, &first, 0, &|s, i| {
        byte(s, i, |b| {
            (0x61..=0x7A).contains(&b) || b.is_ascii_digit() || b == b'-'
        })
    })
}

fn key(s: &[u8], i: usize) -> Ends {
    let first = segment(s, i);
    rep(s, &first, 0, &|s, i| {
        then(s, &byte(s, i, |b| b == b'.'), &segment)
    })
}

fn bare(s: &[u8], i: usize) -> Ends {
    rep(s, &one(i), 1, &|s, i| {
        byte(s, i, |b| b == 0x21 || (0x23..=0x7E).contains(&b))
    })
}

fn quoted(s: &[u8], i: usize) -> Ends {
    let open = byte(s, i, |b| b == b'"');
    let body = rep(s, &open, 0, &|s, i| {
        let mut e = byte(s, i, |b| {
            (0x20..=0x21).contains(&b) || (0x23..=0x5B).contains(&b) || (0x5D..=0x7E).contains(&b)
        });
        let bs = byte(s, i, |b| b == b'\\');
        e.extend(then(s, &bs, &|s, i| {
            byte(s, i, |b| b == b'"' || b == b'\\')
        }));
        e
    });
    then(s, &body, &|s, i| byte(s, i, |b| b == b'"'))
}

fn value(s: &[u8], i: usize) -> Ends {
    let mut e = bare(s, i);
    e.extend(quoted(s, i));
    e
}

fn arg(s: &[u8], i: usize) -> Ends {
    let k = key(s, i);
    let mut e = k.clone();
    let eq = then(s, &k, &|s, i| byte(s, i, |b| b == b'='));
    e.extend(then(s, &eq, &value));
    e
}

/// `kernel-args = *SP [ arg *( 1*SP arg ) *SP ]`, plus the length limit.
fn reference(s: &[u8]) -> bool {
    if s.len() > MAX_LEN {
        return false;
    }
    let lead = rep(s, &one(0), 0, &sp);
    let mut ends = lead.clone();
    let first = then(s, &lead, &arg);
    let more = rep(s, &first, 0, &|s, i| {
        let gap = rep(s, &one(i), 1, &sp);
        then(s, &gap, &arg)
    });
    ends.extend(rep(s, &more, 0, &sp));
    ends.contains(&s.len())
}

/// Whether some valid line starts with `prefix`. These suffixes finish a
/// line from every live state of the grammar.
fn viable(prefix: &[u8]) -> bool {
    [&b""[..], b"a", b"\"", b"\"\""].iter().any(|suffix| {
        let mut line = prefix.to_vec();
        line.extend_from_slice(suffix);
        reference(&line)
    })
}

/// The argument's text as it appears in the line.
fn written(a: &Arg<'_>) -> String {
    match a.value {
        None => a.key.to_owned(),
        Some(Value::Bare(v)) => format!("{}={v}", a.key),
        Some(Value::Quoted(v)) => format!("{}=\"{v}\"", a.key),
    }
}

fn check(line: &[u8]) {
    let want = reference(line);
    let results: Vec<_> = kargs::parse(line).collect();
    let errors = results.iter().filter(|r| r.is_err()).count();
    assert!(errors <= 1, "{line:?}: {results:?}");
    assert_eq!(errors == 0, want, "{line:?}: {results:?}");

    // The arguments are the line's own bytes, in order, with spaces between.
    let base = line.as_ptr() as usize;
    let mut pos = 0;
    for (n, r) in results.iter().enumerate() {
        let Ok(a) = r else {
            assert_eq!(n + 1, results.len(), "{line:?}: error not last");
            break;
        };
        let start = a.key.as_ptr() as usize - base;
        let gap = &line[pos..start];
        assert!(gap.iter().all(|&b| b == b' '), "{line:?}: gap {gap:?}");
        assert!(
            n == 0 || !gap.is_empty(),
            "{line:?}: no space before arg {n}"
        );
        let text = written(a);
        let end = start + text.len();
        assert_eq!(&line[start..end], text.as_bytes(), "{line:?}");
        pos = end;
    }
    if want {
        assert!(line[pos..].iter().all(|&b| b == b' '), "{line:?}: tail");
        return;
    }

    let Some(Err(e)) = results.last() else {
        unreachable!()
    };
    assert!(e.offset <= line.len(), "{line:?}: {e:?}");
    match e.kind {
        ErrorKind::TooLong => assert!(line.len() > MAX_LEN),
        ErrorKind::UnterminatedQuote => assert_eq!(line[e.offset], b'"', "{line:?}"),
        ErrorKind::BadEscape => assert_eq!(line[e.offset], b'\\', "{line:?}"),
        kind => {
            // The error is at the first byte no valid line has there.
            assert!(viable(&line[..e.offset]), "{line:?}: {e:?}");
            if let Some(&b) = line.get(e.offset) {
                assert!(!viable(&line[..=e.offset]), "{line:?}: {e:?}");
                match kind {
                    ErrorKind::NotAscii => assert!(b >= 0x80, "{line:?}: {e:?}"),
                    ErrorKind::ControlChar => {
                        assert!(b < 0x20 || b == 0x7F, "{line:?}: {e:?}")
                    }
                    _ => assert!((0x20..0x7F).contains(&b), "{line:?}: {e:?}"),
                }
            } else {
                assert!(
                    matches!(kind, ErrorKind::BadKey | ErrorKind::EmptyValue),
                    "{line:?}: {e:?}"
                );
            }
        }
    }
}

#[test]
fn exhaustive_short_lines() {
    const ALPHABET: &[u8] = b"a1-.=\"\\ B\t\xc3";
    let mut line = Vec::new();
    let mut count = 0usize;
    for len in 0..=6u32 {
        for mut n in 0..ALPHABET.len().pow(len) {
            line.clear();
            for _ in 0..len {
                line.push(ALPHABET[n % ALPHABET.len()]);
                n /= ALPHABET.len();
            }
            check(&line);
            count += 1;
        }
    }
    assert!(count > 1_900_000);
}

#[test]
fn random_longer_lines() {
    // Biased towards bytes that matter to the grammar.
    const ALPHABET: &[u8] = b"az09-.=\"\\ !#~_ZA\t\x7f\x00\x80\xff";
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut line = Vec::new();
    for _ in 0..200_000 {
        line.clear();
        let len = (next() % 24) as usize;
        for _ in 0..len {
            line.push(ALPHABET[(next() % ALPHABET.len() as u64) as usize]);
        }
        check(&line);
    }
}

#[test]
fn length_limit_and_garbage_tails() {
    // Every byte value just past the limit gives TooLong, nothing else.
    for b in 0..=255u8 {
        let mut line = vec![b'a'; MAX_LEN];
        line.push(b);
        let r: Vec<_> = kargs::parse(&line).collect();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].unwrap_err().kind, ErrorKind::TooLong);
        assert_eq!(kargs::lookup(&line, "a").count, 0);
    }
    // A huge line is rejected without being read.
    let line = vec![0xffu8; 1 << 20];
    assert_eq!(kargs::parse(&line).count(), 1);
    // Many arguments up to the limit: every one is yielded.
    let line: Vec<u8> = b"a ".repeat(MAX_LEN / 2);
    assert_eq!(line.len(), MAX_LEN);
    let l = kargs::lookup(&line, "a");
    assert_eq!((l.count, l.value), (MAX_LEN / 2, Some(None)));
}

#[test]
fn unescape_round_trips_parsed_values() {
    // Every parsed quoted value unescapes into a buffer of raw().len() bytes,
    // and re-escaping gives back the raw text.
    let line = br#"a="" b="\\" c="\"" d="x\\\"y" e=" \\ \" " f=\\x"#;
    for r in kargs::parse(line) {
        let v = r.unwrap().value.unwrap();
        let mut buf = vec![0u8; v.raw().len()];
        let out = v.unescape(&mut buf).unwrap();
        let back: String = match v {
            Value::Quoted(_) => out
                .chars()
                .flat_map(|c| match c {
                    '"' | '\\' => vec!['\\', c],
                    c => vec![c],
                })
                .collect(),
            Value::Bare(_) => out.to_owned(),
        };
        assert_eq!(back, v.raw());
    }
}
