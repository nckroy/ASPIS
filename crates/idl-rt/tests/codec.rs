// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The core codecs, tails and capability indexes (ADR 0062; ADR 0065,
//! rules 2 and 11; docs/design/call-language.md, "The struct encoding",
//! "Capability indexes").

use idl_rt::{
    cap::{CapRef, CapSink, Collect, Indexes, Positions, Rights},
    meta::{CapType, Identity, Kind},
    view::{Array, Elem, Seq, Str, Unknown},
    wire::{
        DecodeCx, DecodeError, EncodeCx, EncodeError, Mode, NAN32, NAN64, Reader, Tail, Writer,
        decode_all, exact, known,
    },
};

fn cx() -> DecodeCx {
    DecodeCx::new(0, Mode::Tolerant, 0)
}

#[test]
fn integers_at_their_extremes() {
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf);
    w.u8(u8::MAX).unwrap();
    w.u16(u16::MAX).unwrap();
    w.u32(u32::MAX).unwrap();
    w.u64(u64::MAX).unwrap();
    w.i8(i8::MIN).unwrap();
    w.i16(i16::MIN).unwrap();
    w.i32(i32::MIN).unwrap();
    w.i64(i64::MIN).unwrap();
    let n = w.len();
    assert_eq!(n, 30);
    let mut r = Reader::new(&buf[..n]);
    assert_eq!(r.u8().unwrap(), u8::MAX);
    assert_eq!(r.u16().unwrap(), u16::MAX);
    assert_eq!(r.u32().unwrap(), u32::MAX);
    assert_eq!(r.u64().unwrap(), u64::MAX);
    assert_eq!(r.i8().unwrap(), i8::MIN);
    assert_eq!(r.i16().unwrap(), i16::MIN);
    assert_eq!(r.i32().unwrap(), i32::MIN);
    assert_eq!(r.i64().unwrap(), i64::MIN);
    assert!(r.is_empty());
    // Big-endian: i16::MIN is 0x8000.
    assert_eq!(&buf[16..18], &[0x80, 0x00]);
    // Too short.
    assert_eq!(Reader::new(&[1, 2, 3]).u32(), Err(DecodeError::Malformed));
}

#[test]
fn booleans_are_strict() {
    assert_eq!(Reader::new(&[0]).bool(), Ok(false));
    assert_eq!(Reader::new(&[1]).bool(), Ok(true));
    assert_eq!(Reader::new(&[2]).bool(), Err(DecodeError::Malformed));
    assert_eq!(Reader::new(&[2]).presence(), Err(DecodeError::Malformed));
}

#[test]
fn only_the_canonical_nan() {
    assert!(Reader::new(&NAN32.to_be_bytes()).f32().unwrap().is_nan());
    assert!(Reader::new(&NAN64.to_be_bytes()).f64().unwrap().is_nan());
    assert_eq!(
        Reader::new(&0x7FC0_0001u32.to_be_bytes()).f32(),
        Err(DecodeError::Malformed)
    );
    assert_eq!(
        Reader::new(&0xFFF8_0000_0000_0000u64.to_be_bytes()).f64(),
        Err(DecodeError::Malformed)
    );
    // Every NaN is written as the canonical one; zeros keep their sign.
    let mut buf = [0u8; 16];
    let mut w = Writer::new(&mut buf);
    w.f32(f32::from_bits(0x7FC0_1234)).unwrap();
    w.f64(-0.0).unwrap();
    assert_eq!(&buf[..4], &NAN32.to_be_bytes());
    assert_eq!(&buf[4..12], &(-0.0f64).to_bits().to_be_bytes());
}

#[test]
fn strings_are_utf8_without_nul_within_their_bound() {
    let ok = [0, 0, 0, 4, 0xF0, 0x9F, 0x98, 0x80];
    assert_eq!(&*Reader::new(&ok).str(4).unwrap(), "\u{1F600}");
    // Over the bound.
    assert_eq!(Reader::new(&ok).str(3), Err(DecodeError::Malformed));
    // Overlong, a surrogate, U+0000.
    for bad in [
        &[0, 0, 0, 2, 0xC0, 0x80][..],
        &[0, 0, 0, 3, 0xED, 0xA0, 0x80],
        &[0, 0, 0, 1, 0],
    ] {
        assert_eq!(
            Reader::new(bad).str(16),
            Err(DecodeError::Malformed),
            "{bad:?}"
        );
    }
    let mut buf = [0u8; 16];
    assert_eq!(
        Writer::new(&mut buf).str("a\0", 8),
        Err(EncodeError::Bounds)
    );
    assert_eq!(
        Writer::new(&mut buf).str("abc", 2),
        Err(EncodeError::Bounds)
    );
    assert_eq!(
        Writer::new(&mut buf).bytes(&[1, 2, 3], 2),
        Err(EncodeError::Bounds)
    );
    assert_eq!(
        Writer::new(&mut buf[..5]).str("ab", 8),
        Err(EncodeError::Overflow)
    );
}

#[test]
fn a_measuring_writer_counts() {
    let mut w = Writer::measure();
    w.str("hello", 8).unwrap();
    let at = w.begin_len().unwrap();
    w.u64(1).unwrap();
    w.end_len(at).unwrap();
    assert_eq!(w.len(), 4 + 5 + 4 + 8);
    assert!(w.written().is_empty());
}

/// Writes a tail by hand: (tag, value) entries.
fn tail(entries: &[(u16, &[u8])]) -> Vec<u8> {
    let mut v = (entries.len() as u32).to_be_bytes().to_vec();
    for (t, x) in entries {
        v.extend_from_slice(&t.to_be_bytes());
        v.extend_from_slice(&(x.len() as u32).to_be_bytes());
        v.extend_from_slice(x);
    }
    v
}

/// Reads a tail whose known fields are positions 1 to `known`.
fn read_tail(b: &[u8], known: usize, mode: Mode) -> Result<(Vec<u16>, u32, Vec<u8>), DecodeError> {
    let mut cx = DecodeCx::new(0, mode, 0);
    decode_all(b, &mut cx, |r, cx| {
        let mut t = Tail::read(r, known)?;
        let mut tags = Vec::new();
        while let Some((tag, _)) = t.next(r, cx)? {
            tags.push(tag);
        }
        let u = t.finish(r);
        Ok((tags, u.count(), u.raw().to_vec()))
    })
}

#[test]
fn tails_ascend_and_preserve_what_is_unknown() {
    let b = tail(&[(2, &[1]), (3, &[2]), (5, &[3, 4])]);
    let (tags, n, raw) = read_tail(&b, 3, Mode::Tolerant).unwrap();
    assert_eq!(tags, [2, 3]);
    assert_eq!(n, 1);
    assert_eq!(raw, [0, 5, 0, 0, 0, 2, 3, 4]);
    // Out of order, repeated, and tag 0.
    for bad in [
        tail(&[(3, &[]), (2, &[])]),
        tail(&[(2, &[]), (2, &[])]),
        tail(&[(0, &[])]),
    ] {
        assert_eq!(
            read_tail(&bad, 3, Mode::Tolerant),
            Err(DecodeError::Malformed)
        );
    }
    // A count above the most tags there are.
    assert_eq!(
        read_tail(&0x1_0000u32.to_be_bytes(), 3, Mode::Tolerant),
        Err(DecodeError::Malformed)
    );
    // Truncated.
    assert_eq!(
        read_tail(&b[..b.len() - 1], 3, Mode::Tolerant),
        Err(DecodeError::Malformed)
    );
}

#[test]
fn a_strict_read_collects_field_too_new() {
    let b = tail(&[(2, &[1]), (4, &[]), (6, &[]), (7, &[])]);
    match read_tail(&b, 3, Mode::Strict) {
        Err(DecodeError::FieldTooNew(t)) => assert_eq!(t.as_slice(), [4, 6, 7]),
        other => panic!("{other:?}"),
    }
    // Past eight, tags are dropped.
    let many: Vec<(u16, &[u8])> = (2..14).map(|t| (t, &[][..])).collect();
    match read_tail(&tail(&many), 1, Mode::Strict) {
        Err(DecodeError::FieldTooNew(t)) => assert_eq!(t.as_slice(), [2, 3, 4, 5, 6, 7, 8, 9]),
        other => panic!("{other:?}"),
    }
    // A malformed part later wins.
    let mut bad = tail(&[(4, &[])]);
    bad.push(0);
    assert_eq!(
        read_tail(&bad, 3, Mode::Strict),
        Err(DecodeError::Malformed)
    );
}

#[test]
fn known_fields_are_a_prefix() {
    assert_eq!(known(&[0, 0, 1, 1, 2], 0), 2);
    assert_eq!(known(&[0, 0, 1, 1, 2], 1), 4);
    assert_eq!(known(&[0, 0, 1, 1, 2], 9), 5);
}

#[test]
fn a_tail_writer_orders_fields_and_unknowns() {
    let raw = tail(&[(9, &[7])]);
    let unknown = Unknown::wire(&raw[4..], 1);
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf);
    let mut t = w.tail().unwrap();
    let at = t.begin(&mut w, 2).unwrap();
    w.u8(5).unwrap();
    t.end(&mut w, at).unwrap();
    t.unknown(&mut w, &unknown).unwrap();
    t.finish(&mut w).unwrap();
    let n = w.len();
    assert_eq!(&buf[..n], &tail(&[(2, &[5]), (9, &[7])])[..]);
    // An unknown field that doesn't follow the known ones.
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf);
    let mut t = w.tail().unwrap();
    let at = t.begin(&mut w, 10).unwrap();
    t.end(&mut w, at).unwrap();
    assert_eq!(t.unknown(&mut w, &unknown), Err(EncodeError::Unknown));
}

#[test]
fn exact_reads_every_octet() {
    let mut c = cx();
    assert_eq!(exact(&[0, 1], &mut c, |r, _| r.u16()), Ok(1));
    assert_eq!(
        exact(&[0, 1, 2], &mut c, |r, _| r.u16()),
        Err(DecodeError::Malformed)
    );
    assert_eq!(
        decode_all(&[1, 2], &mut c, |r, _| r.u8()),
        Err(DecodeError::Malformed)
    );
}

const SESSION: CapType = CapType {
    interface: "org.example.base",
    major: 1,
    minor: 0,
    kernel_object: false,
    rights: Rights::NONE,
    immutable: false,
};

const MEMORY: CapType = CapType {
    interface: "aspis.kernel.memory",
    major: 1,
    minor: 0,
    kernel_object: true,
    rights: Rights::READ,
    immutable: true,
};

#[test]
fn capability_indexes_ascend_once_below_the_count() {
    let mut c = DecodeCx::new(0, Mode::Strict, 2);
    assert_eq!(c.cap(0, &SESSION), Ok(CapRef(0)));
    // Repeated, or skipping one.
    assert_eq!(c.clone().cap(0, &SESSION), Err(DecodeError::Malformed));
    assert_eq!(c.clone().cap(2, &SESSION), Err(DecodeError::Malformed));
    // Every capability named.
    assert_eq!(c.finish(), Err(DecodeError::Malformed));
    assert_eq!(c.cap(1, &MEMORY), Ok(CapRef(1)));
    assert_eq!(c.cap_type(1), Some(&MEMORY));
    assert_eq!(c.finish(), Ok(()));
    // An index not below the count.
    assert_eq!(
        DecodeCx::new(0, Mode::Strict, 1).cap(1, &SESSION),
        Err(DecodeError::Malformed)
    );
    // A count above the three a message carries names no fourth.
    let mut c = DecodeCx::new(0, Mode::Tolerant, 5);
    for i in 0..3 {
        assert_eq!(c.cap(i, &SESSION), Ok(CapRef(i)));
    }
    assert_eq!(c.cap(3, &SESSION), Err(DecodeError::Malformed));
}

#[test]
fn sinks_number_capabilities_in_encoding_order() {
    let mut i = Indexes::new();
    assert_eq!(i.put(&CapRef(0), &SESSION), Ok(0));
    assert_eq!(i.put(&CapRef(2), &SESSION), Err(EncodeError::Caps));
    let mut p = Positions::new();
    for n in 0..3 {
        assert_eq!(CapSink::<u32>::put(&mut p, &7, &SESSION), Ok(n));
    }
    assert_eq!(
        CapSink::<u32>::put(&mut p, &7, &SESSION),
        Err(EncodeError::Caps)
    );
    let caps = [10u32, 11, 12, 13];
    let mut c = Collect::new();
    for k in &caps[..3] {
        c.put(k, &MEMORY).unwrap();
    }
    assert_eq!(c.put(&caps[3], &MEMORY), Err(EncodeError::Caps));
    assert_eq!(c.iter().map(|(k, _)| *k).collect::<Vec<_>>(), [10, 11, 12]);
}

#[test]
fn a_received_capability_is_checked_for_kind_and_rights() {
    let rw = Rights::READ.union(Rights::WRITE);
    let mem = |rights, immutable| Identity {
        kind: Kind::Object("aspis.kernel.memory"),
        rights,
        immutable,
    };
    assert_eq!(MEMORY.check(Some(mem(rw, true))), Ok(()));
    assert_eq!(
        MEMORY.check(Some(mem(Rights::WRITE, true))),
        Err(Rights::READ)
    );
    // Not immutable, an endpoint, another kernel object, or nothing.
    assert_eq!(MEMORY.check(Some(mem(rw, false))), Err(Rights::READ));
    let ep = Identity {
        kind: Kind::Endpoint,
        rights: Rights::WRITE.union(Rights::GRANT_REPLY),
        immutable: false,
    };
    assert_eq!(MEMORY.check(Some(ep)), Err(Rights::READ));
    assert_eq!(
        MEMORY.check(Some(Identity {
            kind: Kind::Object("aspis.kernel.eventcount"),
            ..mem(rw, true)
        })),
        Err(Rights::READ)
    );
    assert_eq!(MEMORY.check(None), Err(Rights::READ));
    // A session capability: an endpoint with write and grant-reply.
    assert_eq!(SESSION.check(Some(ep)), Ok(()));
    assert_eq!(
        SESSION.check(Some(Identity {
            rights: Rights::WRITE,
            ..ep
        })),
        Err(Rights::GRANT_REPLY)
    );
    assert_eq!(
        SESSION.check(Some(mem(Rights(15), true))),
        Err(Rights::WRITE.union(Rights::GRANT_REPLY))
    );
}

#[test]
fn sequences_decode_lazily_and_read_back() {
    // seq<string<4>, 3> of "ab", "" and "cd".
    let b = [
        0, 0, 0, 3, 0, 0, 0, 2, b'a', b'b', 0, 0, 0, 0, 0, 0, 0, 2, b'c', b'd',
    ];
    let mut c = cx();
    let s = decode_all(&b, &mut c, |r, cx| {
        Seq::<Str<'_>>::decode(r, cx, 3, |r, _| r.str(4))
    })
    .unwrap();
    assert_eq!(s.len(), 3);
    let items: Vec<String> = s.iter().map(|x| x.to_string()).collect();
    assert_eq!(items, ["ab", "", "cd"]);
    assert_eq!(s, Seq::Slice(&["ab".into(), "".into(), "cd".into()]));
    // Over the count, or an element over its bound.
    assert!(
        decode_all(&b, &mut cx(), |r, cx| Seq::<Str<'_>>::decode(
            r,
            cx,
            2,
            |r, _| r.str(4)
        ))
        .is_err()
    );
    assert!(
        decode_all(&b, &mut cx(), |r, cx| Seq::<Str<'_>>::decode(
            r,
            cx,
            3,
            |r, _| r.str(1)
        ))
        .is_err()
    );
    // An array of two u16 arrays: no counts.
    let a = [0, 1, 0, 2, 0, 3, 0, 4];
    let v = decode_all(&a, &mut cx(), |r, cx| {
        Array::<Array<u16, 2>, 2>::decode(r, cx, |r, cx| Array::decode(r, cx, |r, _| r.u16()))
    })
    .unwrap();
    let flat: Vec<u16> = v
        .iter()
        .flat_map(|x| x.iter().collect::<Vec<_>>())
        .collect();
    assert_eq!(flat, [1, 2, 3, 4]);
    assert_eq!(
        Array::<u16, 2>::read(&mut Reader::new(&a), &mut cx())
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn encode_cx_refuses_only_when_it_checks() {
    assert_eq!(EncodeCx::ANY.field(5, &[3]), Ok(()));
    assert_eq!(EncodeCx::at(1).field(1, &[3]), Ok(()));
    assert_eq!(
        EncodeCx::at(1).field(2, &[3]),
        Err(EncodeError::FieldTooNew(&[3]))
    );
    assert_eq!(EncodeCx::at(0).value(1), Err(EncodeError::ValueTooNew(1)));
}

#[test]
fn value_too_new_is_recorded_only_in_strict_reads() {
    let mut s = DecodeCx::new(1, Mode::Strict, 0);
    s.value(1);
    assert_eq!(s.value_too_new(), None);
    s.value(3);
    s.value(2);
    assert_eq!(s.value_too_new(), Some(3));
    let mut t = DecodeCx::new(1, Mode::Tolerant, 0);
    t.value(3);
    assert_eq!(t.value_too_new(), None);
}
