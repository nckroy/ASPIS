// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel-argument targets (ADR 0041, rule 5; C04 and C05):
//! `kargs-parse` for the parser, its values and `lookup`, and
//! `kargs-grub` for the stub's undoing of GRUB's rewriting.

use kargs::{Arg, Error, ErrorKind, GrubError, MAX_LEN, UnescapeError, Value};

use crate::{
    oracle::{self, stub_convert, unescaped},
    seeds,
};

kinds! {
    /// The kinds `kargs-parse` reaches: a line that parses whole, each
    /// [`ErrorKind`], and each [`UnescapeError`].
    pub const PARSE_KINDS = ["ok"];
    fn error_kind(k: ErrorKind) {
        ErrorKind::TooLong => "too-long",
        ErrorKind::NotAscii => "not-ascii",
        ErrorKind::ControlChar => "control-char",
        ErrorKind::BadKey => "bad-key",
        ErrorKind::EmptyValue => "empty-value",
        ErrorKind::QuoteInBare => "quote-in-bare",
        ErrorKind::UnterminatedQuote => "unterminated-quote",
        ErrorKind::BadEscape => "bad-escape",
        ErrorKind::MissingSpace => "missing-space",
    }
    fn unescape_kind(e: UnescapeError) {
        UnescapeError::BufferTooSmall => "unescape-buffer-too-small",
        UnescapeError::BadEscape => "unescape-bad-escape",
        UnescapeError::BadChar => "unescape-bad-char",
    }
}

/// The keys the kernel (`kernel/src/settings.rs`) and the stub look up.
const LOOKED_UP: &[&str] = &[
    "console",
    "console.cell",
    "log.size",
    "log.level",
    "initfs",
    "test.panic",
];

/// Where `part` starts in `line`, if it is a subslice of it.
fn offset_in(line: &[u8], part: &str) -> Option<usize> {
    let start = line.as_ptr() as usize;
    let at = part.as_ptr() as usize;
    (at >= start && at + part.len() <= start + line.len()).then(|| at - start)
}

/// What one run of the parser gives, and the unescape results it reaches.
struct Parsed<'a> {
    items: Vec<Result<Arg<'a>, Error>>,
    unescape: Vec<UnescapeError>,
}

fn run_parse(line: &[u8]) -> Parsed<'_> {
    let items: Vec<_> = kargs::parse(line).collect();
    let mut unescape = Vec::new();

    // The iterator is fused, and an error is yielded once, last.
    let mut it = kargs::parse(line);
    for _ in &items {
        it.next();
    }
    assert_eq!(it.next(), None, "the iterator yields nothing after the end");
    if let Some(i) = items.iter().position(Result::is_err) {
        assert_eq!(i, items.len() - 1, "an error is yielded last");
    }
    // A line over MAX_LEN gives TooLong first and nothing else.
    if line.len() > MAX_LEN {
        assert_eq!(
            items,
            [Err(Error {
                offset: MAX_LEN,
                kind: ErrorKind::TooLong
            })]
        );
    }

    // The arguments are the line's own text, in order, separated by one
    // or more spaces, with only spaces before the first and after the
    // last (as crates/kargs/tests/reference.rs checks).
    let mut end = 0usize;
    for item in &items {
        let Ok(arg) = item else { break };
        let at = offset_in(line, arg.key).expect("the key is part of the line");
        let gap = &line[end..at];
        assert!(
            gap.iter().all(|&b| b == b' '),
            "only spaces between arguments"
        );
        assert!(
            end == 0 || !gap.is_empty(),
            "arguments are separated by a space"
        );
        let mut arg_end = at + arg.key.len();
        if let Some(v) = arg.value {
            assert_eq!(line.get(arg_end), Some(&b'='));
            let raw_at = offset_in(line, v.raw()).expect("the value is part of the line");
            match v {
                Value::Bare(_) => assert_eq!(raw_at, arg_end + 1),
                Value::Quoted(_) => {
                    assert_eq!(raw_at, arg_end + 2);
                    assert_eq!(line.get(arg_end + 1), Some(&b'"'));
                    assert_eq!(line.get(raw_at + v.raw().len()), Some(&b'"'));
                }
            }
            arg_end = raw_at + v.raw().len() + usize::from(matches!(v, Value::Quoted(_)));
            // Unescaping into the raw text's length never fails; one byte
            // short of the result always does.
            let text = unescaped(&v);
            if !text.is_empty() {
                let mut short = vec![0u8; text.len() - 1];
                let e = v.unescape(&mut short).unwrap_err();
                assert_eq!(e, UnescapeError::BufferTooSmall);
                unescape.push(e);
                let _ = e.to_string();
            }
        }
        end = arg_end;
    }
    if items.last().is_none_or(Result::is_ok) {
        assert!(
            line[end..].iter().all(|&b| b == b' '),
            "only spaces at the end"
        );
    }
    if let Some(Err(e)) = items.last() {
        let _ = e.to_string();
        assert!(e.offset <= line.len().max(MAX_LEN));
    }

    // `lookup` gives the last occurrence before the first error, and how
    // many there were: for each key in the line, each of its prefixes
    // that ends before a `.`, the key with one more character, the keys
    // the kernel and the stub look up, and "".
    let ok: Vec<&Arg<'_>> = items.iter().map_while(|i| i.as_ref().ok()).collect();
    let check_lookup = |key: &str| {
        let found = kargs::lookup(line, key);
        let same: Vec<_> = ok.iter().filter(|a| a.key == key).collect();
        assert_eq!(found.count, same.len(), "lookup({key:?}) counts");
        assert_eq!(found.value, same.last().map(|a| a.value), "lookup({key:?})");
    };
    for arg in ok.iter().take(16) {
        check_lookup(arg.key);
        for (i, _) in arg.key.match_indices('.') {
            check_lookup(&arg.key[..i]);
        }
        check_lookup(&format!("{}.", arg.key));
        check_lookup(&format!("{}x", arg.key));
    }
    for key in LOOKED_UP {
        check_lookup(key);
    }
    assert_eq!(kargs::lookup(line, "").count, 0, "no key is empty");

    Parsed { items, unescape }
}

/// A [`Value`] built by hand from the line, which only an embedder can
/// make: unescaping it into the raw text's length never runs out of room,
/// and fails exactly when the text breaks its form.
fn hand_built(line: &[u8], out: &mut Vec<UnescapeError>) {
    let Ok(s) = core::str::from_utf8(line) else {
        return;
    };
    for v in [Value::Bare(s), Value::Quoted(s)] {
        let mut buf = vec![0u8; s.len()];
        match v.unescape(&mut buf) {
            Ok(text) => {
                assert!(text.len() <= s.len());
                if let Value::Bare(_) = v {
                    assert_eq!(text, s, "a bare value is copied as it is");
                }
            }
            Err(UnescapeError::BufferTooSmall) => {
                panic!("unescaping {v:?} ran out of a buffer as long as its raw text")
            }
            Err(e) => out.push(e),
        }
    }
}

/// `kargs-parse`: the parser, values and `lookup`, on any line.
pub fn parse(line: &[u8]) {
    let a = run_parse(line);
    // Deterministic: a second parse gives the same.
    assert_eq!(a.items, kargs::parse(line).collect::<Vec<_>>());
    let mut unescape = Vec::new();
    hand_built(line, &mut unescape);
    // Agreement with grammars/kernel-args.abnf, and the round trip through
    // the canonical form ("The gate for each target", items 2 and 3).
    oracle::check_kargs_agreement(line, oracle::kargs_accepts);
    oracle::check_kargs_round_trip(line, oracle::render_kargs);
}

/// The kinds a line reaches in `kargs-parse`.
pub fn parse_kinds(line: &[u8]) -> Vec<&'static str> {
    let a = run_parse(line);
    let mut kinds = Vec::new();
    match a.items.last() {
        Some(Err(e)) => kinds.push(error_kind(e.kind)),
        _ => kinds.push("ok"),
    }
    let mut unescape = a.unescape;
    hand_built(line, &mut unescape);
    kinds.extend(unescape.into_iter().map(unescape_kind));
    kinds
}

/// `kargs-parse`'s generated seeds: every vector line of
/// `grammars/kernel-args.vectors`, and the longest line and one octet
/// more.
pub fn parse_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = seeds::octets_of("kernel-args");
    out.push(("max-len".into(), seeds::kargs_line(MAX_LEN)));
    out.push(("over-max-len".into(), seeds::kargs_line(MAX_LEN + 1)));
    out
}

kinds! {
    /// The kinds `kargs-grub` reaches.
    pub const GRUB_KINDS = ["not-grub"];
    fn grub_kind(r: &Result<usize, GrubError>) {
        Ok(_) => "ok",
        Err(GrubError::TooLong) => "too-long",
        Err(GrubError::Unbalanced) => "unbalanced",
    }
}

/// Runs `kargs-grub`'s checks, and returns what the conversion gave with
/// the stub's buffers and with a 4-octet output buffer.
fn run_grub(line: &[u8]) -> [Result<usize, GrubError>; 2] {
    let grub = kargs::is_grub(line);
    assert_eq!(grub, kargs::is_grub(line));
    let (r, out) = stub_convert(line);
    // Deterministic, output included.
    assert_eq!(stub_convert(line), (r, out.clone()));
    // The stub passes only octets 0x20 to 0x7E, and with its buffers the
    // conversion never runs out of room.
    let printable = line.iter().all(|b| (0x20..0x7f).contains(b));
    if printable {
        assert_ne!(r, Err(GrubError::TooLong), "the stub's buffers suffice");
    }
    if let Ok(n) = r {
        assert!(n <= line.len() * 2 + 16);
        if printable {
            assert!(
                out.iter().all(|b| (0x20..0x7f).contains(b)),
                "ASCII in, ASCII out"
            );
        }
        // The kernel parses what the stub gives it.
        let _ = kargs::parse(&out).count();
    }
    // With a 4-octet output buffer, a longer result runs out of room.
    let mut small = [0u8; 4];
    let mut word = vec![0u8; line.len() + 1];
    let s = kargs::from_grub(line, &mut small, &mut word);
    match (r, s) {
        (Ok(n), s) if n <= 4 => assert_eq!(s, Ok(n)),
        (Ok(_), s) => assert_eq!(s, Err(GrubError::TooLong)),
        _ => {}
    }
    [r, s]
}

/// `kargs-grub`: `is_grub` and `from_grub`, on any line; and, when the
/// line parses as kernel arguments, the round trip through GRUB 2.14's
/// encoding and the stub's conversion.
pub fn grub(line: &[u8]) {
    let _ = run_grub(line);
    oracle::check_grub_round_trip(line, oracle::grub_encode);
}

/// The kinds a line reaches in `kargs-grub`.
pub fn grub_kinds(line: &[u8]) -> Vec<&'static str> {
    let mut kinds: Vec<_> = run_grub(line).iter().map(grub_kind).collect();
    if !kargs::is_grub(line) {
        kinds.push("not-grub");
    }
    kinds
}

/// `kargs-grub`'s generated seeds: every vector line of
/// `grammars/kernel-args.vectors` as it is, after GRUB's first word, and,
/// for each line that parses, as GRUB 2.14 encodes its words.
pub fn grub_seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for (name, octets) in seeds::octets_of("kernel-args") {
        let mut grub = b"BOOT_IMAGE=/aspis.efi ".to_vec();
        grub.extend_from_slice(&octets);
        out.push((format!("{name}-grub"), grub));
        if let Some(meaning) = oracle::kargs_meaning(&octets) {
            out.push((
                format!("{name}-encoded"),
                oracle::grub_encode(&oracle::grub_words(&meaning)),
            ));
        }
        out.push((name, octets));
    }
    out
}
