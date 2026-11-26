// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Owned values under the `alloc` feature (docs/design/call-language.md,
//! "Back ends", row 4): a decoded value becomes the same type at
//! `'static`, outlives the message, and re-encodes to the same octets.

use aspis_interfaces::aspis::{catalog::v1 as catalog, rpc::v1 as rpc};
use idl_rt::{
    view::{Bytes, IntoOwned, Seq, Str, Unknown},
    wire::{DecodeCx, EncodeCx, Mode, Writer, decode_all},
};

fn encode(f: impl Fn(&mut Writer<'_>) -> Result<(), idl_rt::wire::EncodeError>) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let mut w = Writer::new(&mut buf);
    f(&mut w).unwrap();
    let n = w.len();
    buf.truncate(n);
    buf
}

#[test]
fn owned_values_outlive_their_message() {
    let ids = [[1u8; 32], [2; 32]];
    let rep = catalog::methods::list::Reply {
        at: 9,
        entries: Seq::Slice(&ids),
        next_page: Some(Bytes::Borrowed(b"page")),
        unknown_: Unknown::default(),
    };
    let octets = encode(|w| rep.encode(w, &EncodeCx::ANY));
    let owned: catalog::methods::list::Reply<'static> = {
        let copy = octets.clone();
        let mut cx = DecodeCx::new(1, Mode::Tolerant, 0);
        let v = decode_all(&copy, &mut cx, catalog::methods::list::Reply::decode).unwrap();
        v.into_owned()
    };
    assert_eq!(owned, rep);
    assert!(matches!(owned.entries, Seq::Owned(_)));
    assert_eq!(encode(|w| owned.encode(w, &EncodeCx::ANY)), octets);
}

#[test]
fn unknown_parts_stay_owned_and_in_order() {
    // A 1.1 change read by a 1.0 session keeps its publisher as unknown.
    let change = catalog::types::Change {
        seq: 1,
        kind: catalog::types::ChangeKind(200),
        entry: [5; 32],
        publisher: Some([6; 32]),
        unknown_: Unknown::default(),
    };
    let octets = encode(|w| change.encode(w, &EncodeCx::ANY));
    let owned = {
        let copy = octets.clone();
        let mut cx = DecodeCx::new(0, Mode::Tolerant, 0);
        decode_all(&copy, &mut cx, catalog::types::Change::decode)
            .unwrap()
            .into_owned()
    };
    assert_eq!(owned.publisher, None);
    assert_eq!(owned.unknown_.count(), 1);
    assert_eq!(owned.kind, catalog::types::ChangeKind(200));
    assert_eq!(encode(|w| owned.encode(w, &EncodeCx::ANY)), octets);
}

#[test]
fn unions_and_errors_too() {
    let sel = catalog::types::Selector::ByName(Str::Borrowed("name"));
    let octets = encode(|w| sel.encode(w, &EncodeCx::ANY));
    let owned = {
        let copy = octets.clone();
        let mut cx = DecodeCx::new(1, Mode::Tolerant, 0);
        decode_all(&copy, &mut cx, catalog::types::Selector::decode)
            .unwrap()
            .into_owned()
    };
    assert_eq!(owned, sel);
    let e = rpc::errors::Error::NoSuchMethod(rpc::errors::detail::NoSuchMethod {
        method: 3,
        session_minor: 0,
        since_minor: Some(1),
        unknown_: Unknown::default(),
    });
    let detail = encode(|w| e.encode_detail(w, &EncodeCx::ANY));
    let owned = {
        let copy = detail.clone();
        let mut cx = DecodeCx::new(0, Mode::Tolerant, 0);
        rpc::errors::Error::decode(6, &copy, &mut cx)
            .unwrap()
            .into_owned()
    };
    assert_eq!(owned, e);
}
