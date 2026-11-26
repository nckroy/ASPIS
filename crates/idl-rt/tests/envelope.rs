// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The error envelope's codec: its limits (768 octets, causes 3 deep), its
//! preserved tail, and round trips (docs/design/call-language.md, "The
//! error envelope").

use idl_rt::{
    envelope::{self, Fields, MAX_ENVELOPE},
    error::{Disposition, ErrorKey, Outcome},
    rpc::v1 as rpc,
    wire::{DecodeError, EncodeError, Writer},
};

const KEY: ErrorKey = ErrorKey {
    interface: [7; 32],
    major: 1,
    code: 3,
};

fn fields(cause: Option<&[u8]>) -> Fields<'_> {
    Fields {
        outcome: Outcome::Failed,
        disposition: Disposition::LATER,
        key: KEY,
        cause,
        retry_after: Some(5_000),
    }
}

/// Encodes an envelope whose detail is `n` octets of a bytes field's tail
/// encoding: an open struct with one tail field.
fn encode(f: &Fields<'_>, detail: &[u8]) -> Result<Vec<u8>, EncodeError> {
    let mut buf = vec![0u8; 4096];
    let mut w = Writer::new(&mut buf);
    envelope::encode(&mut w, f, &mut |w| w.put(detail))?;
    let n = w.len();
    buf.truncate(n);
    Ok(buf)
}

const EMPTY: [u8; 4] = [0, 0, 0, 0];

#[test]
fn round_trip() {
    let e = encode(&fields(None), &EMPTY).unwrap();
    // 46 octets fixed, the empty detail struct's 4, and retry_after's 14.
    assert_eq!(e.len(), 46 + EMPTY.len() + 14);
    let r = envelope::decode(&e).unwrap();
    assert_eq!(r.outcome, Outcome::Failed);
    assert_eq!(r.disposition, Disposition::LATER);
    assert_eq!(r.key, KEY);
    assert_eq!(r.detail, &EMPTY);
    assert_eq!(r.retry_after, Some(5_000));
    assert_eq!(r.cause, None);
    assert_eq!(r.octets, &e[..]);
    // With a cause.
    let outer = encode(&fields(Some(&e)), &EMPTY).unwrap();
    let r = envelope::decode(&outer).unwrap();
    assert_eq!(r.cause, Some(&e[..]));
}

/// How many envelopes a chain holds.
fn chain(e: &[u8]) -> usize {
    let r = envelope::decode(e).unwrap();
    1 + r.cause.map_or(0, chain)
}

/// Builds a chain of `n` envelopes by hand, outermost first, each with a
/// distinct code, without the encoder's truncation.
fn by_hand(n: u16) -> Vec<u8> {
    let mut e: Option<Vec<u8>> = None;
    for code in (1..=n).rev() {
        let mut b = Vec::new();
        b.extend_from_slice(&[2, 0]);
        b.extend_from_slice(&[7; 32]);
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&code.to_be_bytes());
        b.extend_from_slice(&4u32.to_be_bytes());
        b.extend_from_slice(&EMPTY);
        match &e {
            Some(c) => {
                b.extend_from_slice(&1u32.to_be_bytes());
                b.extend_from_slice(&7u16.to_be_bytes());
                b.extend_from_slice(&(c.len() as u32).to_be_bytes());
                b.extend_from_slice(c);
            }
            None => b.extend_from_slice(&0u32.to_be_bytes()),
        }
        e = Some(b);
    }
    e.unwrap()
}

#[test]
fn causes_nest_at_most_three_deep() {
    // A cause 3 deep decodes; 4 deep is malformed.
    assert!(envelope::decode(&by_hand(4)).is_ok());
    assert_eq!(envelope::decode(&by_hand(5)), Err(DecodeError::Malformed));
    // Each encode wraps the last; the chain stops growing at four
    // envelopes, and every one decodes.
    let mut e = encode(&fields(None), &EMPTY).unwrap();
    for depth in 1..=6 {
        e = encode(&fields(Some(&e)), &EMPTY).unwrap();
        assert!(envelope::decode(&e).is_ok(), "wrapping {depth} times");
        assert_eq!(chain(&e), (depth + 1).min(4));
    }
}

#[test]
fn forwarding_a_full_chain_drops_its_innermost_envelope() {
    // A valid chain of four, codes 1 to 4, outermost first.
    let full = by_hand(4);
    let e = encode(&fields(Some(&full)), &EMPTY).unwrap();
    let r = envelope::decode(&e).unwrap();
    let mut codes = vec![r.key.code];
    let mut c = r.cause;
    while let Some(o) = c {
        let r = envelope::decode(o).unwrap();
        codes.push(r.key.code);
        c = r.cause;
    }
    // The outer error, then the forwarded chain less code 4.
    assert_eq!(codes, [3, 1, 2, 3]);
    // A chain of three is kept whole, octet for octet.
    let three = by_hand(3);
    let e = encode(&fields(Some(&three)), &EMPTY).unwrap();
    assert_eq!(envelope::decode(&e).unwrap().cause, Some(&three[..]));
}

#[test]
fn a_truncated_cause_keeps_its_preserved_tail() {
    // Two envelopes, the outer with retry_after and a tail field 9.
    let inner = encode(&fields(None), &EMPTY).unwrap();
    let mut outer = encode(&fields(Some(&inner)), &EMPTY).unwrap();
    let count = u32::from_be_bytes(outer[46..50].try_into().unwrap());
    assert_eq!(count, 2);
    outer[46..50].copy_from_slice(&3u32.to_be_bytes());
    outer.extend_from_slice(&[0, 9, 0, 0, 0, 1, 0xEE]);
    assert!(envelope::decode(&outer).is_ok());
    // Wrap it twice more, so the chain must lose its innermost envelope.
    let mid = encode(&fields(Some(&outer)), &EMPTY).unwrap();
    let top = encode(&fields(Some(&mid)), &EMPTY).unwrap();
    assert_eq!(chain(&top), 4);
    let top = encode(&fields(Some(&top)), &EMPTY).unwrap();
    assert_eq!(chain(&top), 4);
    // Walk down to the old outer envelope: its fields survive, its own
    // cause is gone.
    let mut r = envelope::decode(&top).unwrap();
    for _ in 0..3 {
        r = envelope::decode(r.cause.unwrap()).unwrap();
    }
    assert_eq!(r.cause, None);
    assert_eq!(r.retry_after, Some(5_000));
    assert_eq!(r.unknown.iter().collect::<Vec<_>>(), [(9, &[0xEE][..])]);
}

#[test]
fn a_cause_that_isnt_an_envelope_is_refused() {
    for bad in [&[][..], &[1, 2, 3][..], &by_hand(5)[..]] {
        assert_eq!(
            encode(&fields(Some(bad)), &EMPTY),
            Err(EncodeError::Malformed)
        );
    }
}

#[test]
fn the_whole_envelope_is_at_most_768_octets() {
    // The largest detail the compiler allows, 708 octets, with
    // retry_after, fills it exactly.
    let detail = vec![0u8; 708];
    let e = encode(&fields(None), &detail).unwrap();
    assert_eq!(e.len(), MAX_ENVELOPE);
    assert!(envelope::decode(&e).is_ok());
    // One more octet is too large to encode, and to decode.
    let detail = vec![0u8; 709];
    assert_eq!(encode(&fields(None), &detail), Err(EncodeError::Bounds));
    let mut big = e.clone();
    big[38..42].copy_from_slice(&709u32.to_be_bytes());
    big.insert(42, 0);
    assert_eq!(envelope::decode(&big), Err(DecodeError::Malformed));
    // A cause that doesn't fit is dropped.
    let inner = encode(&fields(None), &[0u8; 300]).unwrap();
    let e = encode(&fields(Some(&inner)), &[0u8; 500]).unwrap();
    assert!(e.len() <= MAX_ENVELOPE);
    assert_eq!(envelope::decode(&e).unwrap().cause, None);
    // A chain that doesn't fit loses envelopes innermost first, and keeps
    // what fits.
    let two = encode(
        &fields(Some(&encode(&fields(None), &[0u8; 300]).unwrap())),
        &[0u8; 300],
    )
    .unwrap();
    assert_eq!(chain(&two), 2);
    let e = encode(&fields(Some(&two)), &[0u8; 100]).unwrap();
    assert!(e.len() <= MAX_ENVELOPE);
    assert_eq!(chain(&e), 2);
    let kept = envelope::decode(envelope::decode(&e).unwrap().cause.unwrap()).unwrap();
    assert_eq!(kept.detail.len(), 300);
    assert_eq!(kept.cause, None);
}

#[test]
fn a_later_minors_tail_fields_are_preserved() {
    let mut e = encode(
        &Fields {
            retry_after: None,
            ..fields(None)
        },
        &EMPTY,
    )
    .unwrap();
    // Replace the empty tail with one field, tag 9.
    e.truncate(e.len() - 4);
    e.extend_from_slice(&[0, 0, 0, 1, 0, 9, 0, 0, 0, 2, 0xAB, 0xCD]);
    let r = envelope::decode(&e).unwrap();
    assert_eq!(r.unknown.count(), 1);
    assert_eq!(
        r.unknown.iter().collect::<Vec<_>>(),
        [(9, &[0xAB, 0xCD][..])]
    );
}

#[test]
fn malformed_envelopes() {
    let good = encode(&fields(None), &EMPTY).unwrap();
    let mut cases = Vec::new();
    // Outcome 0 and 5.
    for o in [0, 5] {
        let mut b = good.clone();
        b[0] = o;
        cases.push(b);
    }
    // Code 0.
    let mut b = good.clone();
    b[36..38].copy_from_slice(&[0, 0]);
    cases.push(b);
    // A retry_after that isn't 8 octets.
    let mut b = good.clone();
    let n = b.len();
    b[n - 12..n - 8].copy_from_slice(&7u32.to_be_bytes());
    b.pop();
    cases.push(b);
    // A tail field at a required field's position.
    let mut b = good[..good.len() - 18].to_vec();
    b.extend_from_slice(&[0, 0, 0, 1, 0, 5, 0, 0, 0, 0]);
    cases.push(b);
    // Truncated, and one octet too many.
    cases.push(good[..good.len() - 1].to_vec());
    let mut b = good.clone();
    b.push(0);
    cases.push(b);
    for c in cases {
        assert_eq!(envelope::decode(&c), Err(DecodeError::Malformed), "{c:?}");
    }
}

#[test]
fn system_errors_round_trip_through_the_envelope() {
    let e = rpc::errors::Error::ResourceLimit(rpc::errors::detail::ResourceLimit {
        limit: rpc::types::LimitKind::SESSIONS,
        maximum: 64,
        unknown_: Default::default(),
    });
    let mut buf = [0u8; 768];
    let mut w = Writer::new(&mut buf);
    envelope::encode(
        &mut w,
        &Fields {
            outcome: e.outcome(),
            disposition: e.disposition(),
            key: e.key(),
            cause: None,
            retry_after: None,
        },
        &mut |w| e.encode_detail(w, &idl_rt::wire::EncodeCx::ANY),
    )
    .unwrap();
    let n = w.len();
    let raw = envelope::decode(&buf[..n]).unwrap();
    assert_eq!(raw.key.interface, rpc::ID);
    assert_eq!(raw.key.code, 20);
    assert_eq!(raw.outcome, Outcome::Refused);
    let mut cx = idl_rt::wire::DecodeCx::new(0, idl_rt::wire::Mode::Tolerant, 0);
    let back = rpc::errors::Error::decode(raw.key.code, raw.detail, &mut cx).unwrap();
    assert_eq!(back, e);
}
