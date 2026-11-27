// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Generated stubs and dispatchers over an in-memory channel (docs/design/
//! call-language.md, "Back ends", "Refusing what is too new", "Capability
//! types", "Sessions, badges and proxies", "Errors in bindings and text").
//!
//! The channel encodes a request, hands its capabilities over as the
//! kernel would, runs the generated dispatcher, and returns its reply or
//! error envelope. Capabilities are numbers, with what the kernel's
//! identify operation would say of each.

use std::collections::BTreeMap;

use aspis_interfaces::aspis::catalog::v1 as catalog;
use idl_fixtures::{aspis::kernel::pager::v1 as pager, org::example::kinds::v1 as kinds};
use idl_rt::{
    cap::{CapArg, CapRef, Rights},
    channel::{
        CallOptions, CapOps, CapsOut, Channel, Ctx, Fail, Received, Request, Responder,
        SessionState,
    },
    envelope,
    error::{Disposition, ErrorKey, ErrorKind, LocalError, Outcome, RpcError},
    meta::{Identity, Kind},
    rpc::v1::{self as rpc, errors::detail as rpcd},
    view::{Bytes, Seq, Str, Unknown},
    wire::{EncodeCx, EncodeError, Opened, Writer},
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cap(u32);

fn session() -> Identity<'static> {
    Identity {
        kind: Kind::Endpoint,
        rights: Rights::WRITE.union(Rights::GRANT_REPLY),
        immutable: false,
    }
}

fn memory(rights: Rights, immutable: bool) -> Identity<'static> {
    Identity {
        kind: Kind::Object("aspis.kernel.memory"),
        rights,
        immutable,
    }
}

/// The capabilities there are, and what was done with them.
#[derive(Default)]
struct World {
    next: u32,
    ids: BTreeMap<u32, Identity<'static>>,
    dups: Vec<u32>,
    attenuated: Vec<u32>,
    closed: Vec<u32>,
    deleted: Vec<u32>,
}

impl World {
    fn make(&mut self, id: Identity<'static>) -> Cap {
        self.next += 1;
        self.ids.insert(self.next, id);
        Cap(self.next)
    }

    fn dup(&mut self, c: &Cap) -> Cap {
        let n = self.make(self.ids[&c.0]);
        self.dups.push(n.0);
        n
    }

    /// A copy with at most these rights: attenuating never adds one.
    fn attenuate(&mut self, c: &Cap, r: Rights) -> Cap {
        let mut id = self.ids[&c.0];
        id.rights = Rights(id.rights.0 & r.0);
        let n = self.make(id);
        self.attenuated.push(n.0);
        n
    }
}

impl CapOps for World {
    type Cap = Cap;
    fn dup(&mut self, cap: &Cap) -> Result<Cap, LocalError> {
        Ok(World::dup(self, cap))
    }
    fn attenuate(&mut self, cap: &Cap, rights: Rights) -> Result<Cap, LocalError> {
        Ok(World::attenuate(self, cap, rights))
    }
    fn close(&mut self, cap: Cap) {
        self.closed.push(cap.0);
    }
    fn delete(&mut self, cap: Cap) {
        self.deleted.push(cap.0);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Reply,
    Error,
}

/// A server's side of one call.
struct Resp<'w> {
    world: &'w mut World,
    received: Vec<Cap>,
    out: Vec<u8>,
    answer: Option<Answer>,
    caps: Vec<Cap>,
}

impl CapOps for Resp<'_> {
    type Cap = Cap;
    fn dup(&mut self, cap: &Cap) -> Result<Cap, LocalError> {
        Ok(self.world.dup(cap))
    }
    fn attenuate(&mut self, cap: &Cap, rights: Rights) -> Result<Cap, LocalError> {
        Ok(self.world.attenuate(cap, rights))
    }
    fn close(&mut self, cap: Cap) {
        self.world.closed.push(cap.0);
    }
    fn delete(&mut self, cap: Cap) {
        self.world.deleted.push(cap.0);
    }
}

impl Responder for Resp<'_> {
    fn identify(&mut self, index: u8) -> Option<Identity<'static>> {
        let c = self.received.get(usize::from(index))?;
        self.world.ids.get(&c.0).copied()
    }

    fn reply(
        &mut self,
        body: &mut dyn FnMut(&mut Writer<'_>) -> Result<(), EncodeError>,
        caps: CapsOut<Cap>,
    ) {
        assert!(self.answer.is_none(), "answered twice");
        let mut buf = vec![0u8; 1 << 16];
        let mut w = Writer::new(&mut buf);
        body(&mut w).unwrap();
        let n = w.len();
        self.out = buf[..n].to_vec();
        self.caps = caps.into_iter().map(|o| o.cap().clone()).collect();
        self.answer = Some(Answer::Reply);
    }

    fn error(
        &mut self,
        outcome: Outcome,
        disposition: Disposition,
        key: ErrorKey,
        detail: &mut dyn FnMut(&mut Writer<'_>) -> Result<(), EncodeError>,
    ) {
        assert!(self.answer.is_none(), "answered twice");
        let mut buf = [0u8; 768];
        let mut w = Writer::new(&mut buf);
        let f = envelope::Fields {
            outcome,
            disposition,
            key,
            cause: None,
            retry_after: None,
        };
        envelope::encode(&mut w, &f, detail).unwrap();
        let n = w.len();
        self.out = buf[..n].to_vec();
        self.answer = Some(Answer::Error);
    }
}

/// A server, by its generated dispatcher.
trait Serve {
    fn serve(&mut self, req: Request<'_, Cap>, resp: &mut Resp<'_>);
}

/// An in-memory session with a server.
struct Loop<S> {
    server: S,
    world: World,
    session: SessionState,
    reply: Vec<u8>,
    answer: Option<Answer>,
    reply_caps: u8,
    /// The next call fails in the channel, before delivery.
    fail: Option<LocalError>,
    /// The next call gets this error envelope, without reaching the server.
    canned: Option<Vec<u8>>,
    /// What each delivered call carried.
    sent: Vec<Vec<Cap>>,
    /// The badge each request comes with.
    badge: u64,
}

impl<S: Serve> Loop<S> {
    fn new(server: S, minor: u16) -> Self {
        Loop {
            server,
            world: World::default(),
            session: SessionState {
                minor,
                remote: false,
            },
            reply: Vec::new(),
            answer: None,
            reply_caps: 0,
            fail: None,
            canned: None,
            sent: Vec::new(),
            badge: 0,
        }
    }

    /// Delivers a request, as encoded, to the dispatcher.
    fn deliver(&mut self, method: u16, body: &[u8], caps: Vec<Cap>) {
        self.sent.push(caps.clone());
        let mut resp = Resp {
            world: &mut self.world,
            received: caps.clone(),
            out: Vec::new(),
            answer: None,
            caps: Vec::new(),
        };
        let req = Request {
            method,
            body,
            caps: &caps,
            session: self.session,
            badge: self.badge,
        };
        self.server.serve(req, &mut resp);
        self.reply = resp.out;
        self.answer = resp.answer;
        self.reply_caps = resp.caps.len() as u8;
    }

    /// The system error a raw request gets.
    fn refusal(&mut self, method: u16, body: &[u8], caps: Vec<Cap>) -> RpcError<'_> {
        self.deliver(method, body, caps);
        assert_eq!(self.answer, Some(Answer::Error));
        let raw = envelope::decode(&self.reply).unwrap();
        assert_eq!(raw.key.interface, rpc::ID);
        assert_eq!(raw.outcome, Outcome::Refused);
        let mut cx = idl_rt::wire::DecodeCx::new(0, idl_rt::wire::Mode::Tolerant, 0);
        rpc::errors::Error::decode(raw.key.code, raw.detail, &mut cx).unwrap()
    }
}

impl<S> CapOps for Loop<S> {
    type Cap = Cap;
    fn dup(&mut self, cap: &Cap) -> Result<Cap, LocalError> {
        Ok(self.world.dup(cap))
    }
    fn attenuate(&mut self, cap: &Cap, rights: Rights) -> Result<Cap, LocalError> {
        Ok(self.world.attenuate(cap, rights))
    }
    fn close(&mut self, cap: Cap) {
        self.world.closed.push(cap.0);
    }
    fn delete(&mut self, cap: Cap) {
        self.world.deleted.push(cap.0);
    }
}

fn encode_body(body: &mut dyn FnMut(&mut Writer<'_>) -> Result<(), EncodeError>) -> Vec<u8> {
    let mut buf = vec![0u8; 1 << 16];
    let mut w = Writer::new(&mut buf);
    body(&mut w).unwrap();
    let n = w.len();
    buf.truncate(n);
    buf
}

impl<S: Serve> Channel for Loop<S> {
    fn session_minor(&self) -> u16 {
        self.session.minor
    }

    fn call(
        &mut self,
        method: u16,
        _: &CallOptions,
        body: &mut dyn FnMut(&mut Writer<'_>) -> Result<(), EncodeError>,
        caps: CapsOut<Cap>,
    ) -> Result<(), LocalError> {
        let body = encode_body(body);
        // The receiver gets a copy of each; the channel deletes the
        // attenuated scratch copies once sent.
        let caps: Vec<Cap> = caps.into_iter().map(|o| o.cap().clone()).collect();
        if let Some(e) = self.fail.take() {
            return Err(e);
        }
        if let Some(env) = self.canned.take() {
            self.reply = env;
            self.answer = Some(Answer::Error);
            return Ok(());
        }
        self.deliver(method, &body, caps);
        assert!(self.answer.is_some(), "a two-way call got no answer");
        Ok(())
    }

    fn received(&self) -> Received<'_> {
        match self.answer {
            Some(Answer::Reply) => Received::Reply {
                body: &self.reply,
                caps: self.reply_caps,
            },
            _ => Received::Error(&self.reply),
        }
    }

    fn send(
        &mut self,
        method: u16,
        _: &CallOptions,
        body: &mut dyn FnMut(&mut Writer<'_>) -> Result<(), EncodeError>,
        caps: CapsOut<Cap>,
    ) -> Result<(), LocalError> {
        let body = encode_body(body);
        let caps: Vec<Cap> = caps.into_iter().map(|o| o.cap().clone()).collect();
        if let Some(e) = self.fail.take() {
            return Err(e);
        }
        self.deliver(method, &body, caps);
        assert_eq!(self.answer, None, "a one-way call was answered");
        Ok(())
    }
}

const OPTS: CallOptions = CallOptions {
    deadline: None,
    request_id: None,
};

fn u<'a>() -> Unknown<'a> {
    Unknown::default()
}

fn unreachable() -> LocalError {
    LocalError {
        outcome: Outcome::Unreachable,
        error: RpcError::Unreachable(rpcd::Unreachable {
            cause: rpc::types::UnreachableCause::CONNECTION_FAILED,
            unknown_: u(),
        }),
    }
}

fn indeterminate() -> LocalError {
    LocalError {
        outcome: Outcome::Indeterminate,
        error: RpcError::Indeterminate(rpcd::Indeterminate {
            cause: rpc::types::IndeterminateCause::CONNECTION_LOST,
            unknown_: u(),
        }),
    }
}

// ---- The catalog ------------------------------------------------------------

#[derive(Default)]
struct Catalog {
    ids: Vec<[u8; 32]>,
    calls: u32,
    registered: Vec<(Cap, u32, Option<bool>)>,
}

impl Serve for Catalog {
    fn serve(&mut self, req: Request<'_, Cap>, resp: &mut Resp<'_>) {
        catalog::dispatch(self, req, resp)
    }
}

impl catalog::Server for Catalog {
    type Cap = Cap;

    fn list<'a>(
        &'a mut self,
        _: &Ctx<'a, Cap>,
        req: catalog::methods::list::Request<'a>,
    ) -> Result<catalog::methods::list::Reply<'a>, Fail<'a, catalog::errors::Error<'a>>> {
        self.calls += 1;
        if let catalog::types::Selector::ByName(n) = &req.query.select {
            match &**n {
                "everything" => {
                    return Err(Fail::App(catalog::errors::Error::QueryTooBroad(
                        catalog::errors::detail::QueryTooBroad {
                            limit: 16,
                            unknown_: u(),
                        },
                    )));
                }
                "oops" => {
                    return Err(Fail::Rpc(RpcError::Internal(rpcd::Internal {
                        unknown_: u(),
                    })));
                }
                _ => {}
            }
        }
        Ok(catalog::methods::list::Reply {
            at: 7,
            entries: Seq::Slice(&self.ids),
            next_page: None,
            unknown_: u(),
        })
    }

    fn watch<'a>(
        &'a mut self,
        _: &Ctx<'a, Cap>,
        req: catalog::methods::watch::Request<'a>,
    ) -> Result<Opened<catalog::methods::watch::Reply<'a>>, Fail<'a, catalog::errors::Error<'a>>>
    {
        self.calls += 1;
        Ok(Opened {
            id: 9,
            start: req.after.unwrap_or(0) + 1,
            reply: catalog::methods::watch::Reply {
                at: 3,
                unknown_: u(),
            },
        })
    }

    fn register<'a>(
        &'a mut self,
        cx: &Ctx<'a, Cap>,
        req: catalog::methods::register::Request<'a>,
    ) -> Result<catalog::methods::register::Reply<'a>, Fail<'a, catalog::errors::Error<'a>>> {
        self.calls += 1;
        let c = cx.cap(req.definition).unwrap().clone();
        assert_eq!(&*req.proof, "signed");
        self.registered.push((c, req.length, req.dry_run));
        Ok(catalog::methods::register::Reply {
            result: 77,
            unknown_: u(),
        })
    }
}

fn query(name: &str) -> catalog::types::Query<'_> {
    catalog::types::Query {
        select: catalog::types::Selector::ByName(Str::Borrowed(name)),
        limit: None,
        unknown_: u(),
    }
}

fn list_req(name: &str) -> catalog::methods::list::Request<'_> {
    catalog::methods::list::Request {
        query: query(name),
        page: None,
        unknown_: u(),
    }
}

#[test]
fn a_call_and_its_reply() {
    let server = Catalog {
        ids: vec![[1; 32], [2; 32]],
        ..Catalog::default()
    };
    let mut c = catalog::Client {
        channel: Loop::new(server, 1),
    };
    let rep = c.list(&OPTS, list_req("x")).unwrap();
    assert_eq!(rep.at, 7);
    assert_eq!(rep.entries.iter().collect::<Vec<_>>(), [[1; 32], [2; 32]]);
    assert_eq!(rep.next_page, None);
}

#[test]
fn errors_decode_by_kind_and_keep_their_octets() {
    let mut c = catalog::Client {
        channel: Loop::new(Catalog::default(), 1),
    };
    // The interface's own.
    let e = c.list(&OPTS, list_req("everything")).unwrap_err();
    assert_eq!(e.outcome, Outcome::Failed);
    assert_eq!(e.disposition, Disposition::NONE);
    match &e.kind {
        ErrorKind::App(catalog::errors::Error::QueryTooBroad(d)) => assert_eq!(d.limit, 16),
        k => panic!("{k:?}"),
    }
    let raw = e.raw.as_ref().unwrap();
    assert_eq!(raw.key.interface, catalog::ID);
    assert_eq!(raw.key.code, 1);
    assert_eq!(envelope::decode(raw.octets).unwrap(), *raw);
    // A system error.
    let e = c.list(&OPTS, list_req("oops")).unwrap_err();
    assert!(matches!(e.kind, ErrorKind::Rpc(RpcError::Internal(_))));
    assert_eq!(e.outcome, Outcome::Failed);
    // Another interface's.
    let mut buf = [0u8; 768];
    let mut w = Writer::new(&mut buf);
    let key = ErrorKey {
        interface: [0x55; 32],
        major: 3,
        code: 17,
    };
    let f = envelope::Fields {
        outcome: Outcome::Refused,
        disposition: Disposition(9),
        key,
        cause: None,
        retry_after: Some(1),
    };
    envelope::encode(&mut w, &f, &mut |w| w.u32(0)).unwrap();
    let n = w.len();
    c.channel.canned = Some(buf[..n].to_vec());
    let e = c.list(&OPTS, list_req("x")).unwrap_err();
    match &e.kind {
        ErrorKind::Foreign(r) => {
            assert_eq!(r.key, key);
            assert_eq!(r.octets, &buf[..n]);
            assert_eq!(r.retry_after, Some(1));
        }
        k => panic!("{k:?}"),
    }
    // An unknown disposition is kept as it came.
    assert_eq!(e.disposition, Disposition(9));
}

#[test]
fn a_stream_opens_and_its_items_decode() {
    let mut c = catalog::Client {
        channel: Loop::new(Catalog::default(), 1),
    };
    let o = c
        .watch(
            &OPTS,
            catalog::methods::watch::Request {
                query: query("x"),
                after: Some(41),
                unknown_: u(),
            },
        )
        .unwrap();
    assert_eq!((o.id, o.start, o.reply.at), (9, 42, 3));
    // An item with 1.1's publisher, read by a 1.0 session and by a 1.1 one.
    let item = catalog::types::Change {
        seq: 5,
        kind: catalog::types::ChangeKind::WITHDRAWN,
        entry: [3; 32],
        publisher: Some([4; 32]),
        unknown_: u(),
    };
    let mut buf = [0u8; 256];
    let mut w = Writer::new(&mut buf);
    item.encode(&mut w, &EncodeCx::ANY).unwrap();
    let n = w.len();
    for minor in [0, 1] {
        let mut cx = idl_rt::wire::DecodeCx::new(minor, idl_rt::wire::Mode::Tolerant, 0);
        let got =
            idl_rt::wire::decode_all(&buf[..n], &mut cx, catalog::methods::watch::Item::decode)
                .unwrap();
        assert_eq!(got.publisher.is_some(), minor == 1);
        assert_eq!(got.unknown_.count(), u32::from(minor == 0));
        let mut again = [0u8; 256];
        let mut w = Writer::new(&mut again);
        got.encode(&mut w, &EncodeCx::ANY).unwrap();
        assert_eq!(w.written(), &buf[..n]);
    }
}

fn register_req<'a>(
    cap: CapArg<'a, Cap>,
    dry_run: Option<bool>,
) -> catalog::methods::register::Request<'a, CapArg<'a, Cap>> {
    catalog::methods::register::Request {
        definition: cap,
        length: 12,
        proof: Str::Borrowed("signed"),
        dry_run,
        unknown_: u(),
    }
}

#[test]
fn kernel_objects_are_attenuated_and_checked() {
    let mut c = catalog::Client {
        channel: Loop::new(Catalog::default(), 1),
    };
    let rw = Rights::READ.union(Rights::WRITE);
    let mem = c.channel.world.make(memory(rw, true));
    assert_eq!(
        c.register(&OPTS, register_req(CapArg::Share(&mem), Some(true)))
            .unwrap()
            .result,
        77
    );
    // The server got a copy with exactly the declared right.
    let (got, length, dry_run) = c.channel.server.registered[0].clone();
    assert_ne!(got, mem);
    assert_eq!(c.channel.world.ids[&got.0].rights, Rights::READ);
    assert_eq!((length, dry_run), (12, Some(true)));
    assert_eq!(c.channel.world.attenuated, [got.0]);
    assert!(c.channel.world.dups.is_empty());

    // A memory object that lacks read, or isn't immutable.
    for id in [memory(Rights::WRITE, true), memory(rw, false), session()] {
        let cap = c.channel.world.make(id);
        let e = c
            .register(&OPTS, register_req(CapArg::Move(cap), None))
            .unwrap_err();
        assert_eq!(e.outcome, Outcome::Refused);
        match e.kind {
            ErrorKind::Rpc(RpcError::CapabilityRights(d)) => {
                assert_eq!((d.position, d.missing), (0, Rights::READ.bits()));
            }
            k => panic!("{k:?}"),
        }
    }
    assert_eq!(c.channel.server.calls, 1);
}

// ---- The kinds fixture ------------------------------------------------------------

#[derive(Default)]
struct Kinds {
    calls: u32,
    held: Option<Cap>,
    gave: Vec<Vec<Cap>>,
}

impl Serve for Kinds {
    fn serve(&mut self, req: Request<'_, Cap>, resp: &mut Resp<'_>) {
        kinds::dispatch(self, req, resp)
    }
}

fn thing<'a>() -> kinds::types::Thing<'a> {
    kinds::types::Thing {
        key: 1,
        count: 2,
        tags: Seq::Slice(&[]),
        blob: None,
        nested: None,
        pt: None,
        secret: None,
        extra: None,
        more: None,
        unknown_: u(),
    }
}

fn point<'a>() -> kinds::types::Point<'a> {
    kinds::types::Point {
        x: 1,
        y: -1,
        unknown_: u(),
    }
}

type KFail<'a> = Fail<'a, kinds::errors::Error<'a>>;

impl kinds::Server for Kinds {
    type Cap = Cap;

    fn get<'a>(
        &'a mut self,
        _: &Ctx<'a, Cap>,
        _: kinds::methods::get::Request<'a>,
    ) -> Result<kinds::methods::get::Reply<'a>, KFail<'a>> {
        self.calls += 1;
        Ok(kinds::methods::get::Reply {
            result: thing(),
            unknown_: u(),
        })
    }

    fn put<'a>(
        &'a mut self,
        _: &Ctx<'a, Cap>,
        _: kinds::methods::put::Request<'a>,
    ) -> Result<kinds::methods::put::Reply<'a>, KFail<'a>> {
        self.calls += 1;
        Ok(kinds::methods::put::Reply {
            ok: true,
            at: Some(3),
            unknown_: u(),
        })
    }

    fn tail<'a>(
        &'a mut self,
        _: &Ctx<'a, Cap>,
        _: kinds::methods::tail::Request<'a>,
    ) -> Result<Opened<kinds::methods::tail::Reply<'a>>, KFail<'a>> {
        self.calls += 1;
        Ok(Opened {
            id: 1,
            start: 0,
            reply: kinds::methods::tail::Reply { unknown_: u() },
        })
    }

    fn give<'a>(
        &'a mut self,
        cx: &Ctx<'a, Cap>,
        _: kinds::methods::give::Request<'a>,
    ) -> Result<kinds::methods::give::Reply<'a>, KFail<'a>> {
        self.calls += 1;
        self.gave.push(cx.caps.to_vec());
        Ok(kinds::methods::give::Reply {
            result: cx.caps.len() as u8,
            unknown_: u(),
        })
    }

    fn big<'a>(
        &'a mut self,
        _: &Ctx<'a, Cap>,
        req: kinds::methods::big::Request<'a>,
    ) -> Result<kinds::methods::big::Reply<'a>, KFail<'a>> {
        self.calls += 1;
        Ok(kinds::methods::big::Reply {
            n: req.data.len() as u32,
            unknown_: u(),
        })
    }

    fn notify<'a>(
        &'a mut self,
        _: &Ctx<'a, Cap>,
        _: kinds::methods::notify::Request<'a>,
    ) -> Result<kinds::methods::notify::Reply<'a>, KFail<'a>> {
        self.calls += 1;
        Ok(kinds::methods::notify::Reply { unknown_: u() })
    }

    fn later_op<'a>(
        &'a mut self,
        _: &Ctx<'a, Cap>,
        req: kinds::methods::later_op::Request<'a>,
    ) -> Result<kinds::methods::later_op::Reply<'a, CapArg<'a, Cap>>, KFail<'a>> {
        self.calls += 1;
        Ok(kinds::methods::later_op::Reply {
            result: kinds::types::Later {
                a: req.x.a + 1,
                b: point(),
                r#type: 9,
                c: self.held.as_ref().map(CapArg::Share),
                unknown_: u(),
            },
            unknown_: u(),
        })
    }

    fn newest<'a>(
        &'a mut self,
        _: &Ctx<'a, Cap>,
        _: kinds::methods::newest::Request<'a>,
    ) -> Result<kinds::methods::newest::Reply<'a>, KFail<'a>> {
        self.calls += 1;
        Err(Fail::App(kinds::errors::Error::Busy(
            kinds::errors::detail::Busy { unknown_: u() },
        )))
    }

    /// Answers `total` 0, which no encoder writes, when asked for n = 1.
    fn count<'a>(
        &'a mut self,
        _: &Ctx<'a, Cap>,
        req: kinds::methods::count::Request<'a>,
    ) -> Result<kinds::methods::count::Reply<'a>, KFail<'a>> {
        self.calls += 1;
        let n = u32::from(req.n);
        Ok(kinds::methods::count::Reply {
            ids: kinds::types::Ids {
                first: u64::from(req.c.a),
                more: None,
                unknown_: u(),
            },
            total: Some(if n == 1 { 0 } else { n }),
            unknown_: u(),
        })
    }
}

fn give_req<'a>(
    a: CapArg<'a, Cap>,
    b: Option<CapArg<'a, Cap>>,
    c: CapArg<'a, Cap>,
) -> kinds::methods::give::Request<'a, CapArg<'a, Cap>> {
    kinds::methods::give::Request {
        a,
        b,
        c,
        unknown_: u(),
    }
}

#[test]
fn session_capabilities_are_moved_or_shared() {
    let mut c = kinds::Client {
        channel: Loop::new(Kinds::default(), 2),
    };
    let w = &mut c.channel.world;
    let (s1, s2) = (w.make(session()), w.make(session()));
    let mem = w.make(memory(Rights::READ, true));
    let n = c
        .give(
            &OPTS,
            give_req(
                CapArg::Move(s1.clone()),
                Some(CapArg::Share(&s2)),
                CapArg::Share(&mem),
            ),
        )
        .unwrap()
        .result;
    assert_eq!(n, 3);
    let world = &c.channel.world;
    // One dup, for the shared session; the memory object attenuated.
    assert_eq!(world.dups.len(), 1);
    assert_eq!(world.attenuated.len(), 1);
    // The list is in encoding order: the head's a and c, then the tail's b.
    let got = &c.channel.server.gave[0];
    assert_eq!(got[0], s1);
    assert_eq!(got[1].0, world.attenuated[0]);
    assert_eq!(got[2].0, world.dups[0]);
    // The optional one absent: two in the list.
    let n = c
        .give(
            &OPTS,
            give_req(CapArg::Move(s1.clone()), None, CapArg::Share(&mem)),
        )
        .unwrap()
        .result;
    assert_eq!(n, 2);
    assert!(c.channel.world.closed.is_empty());
}

#[test]
fn a_dupd_badge_is_closed_when_the_call_is_unreachable() {
    let mut c = kinds::Client {
        channel: Loop::new(Kinds::default(), 2),
    };
    let w = &mut c.channel.world;
    let (s1, s2) = (w.make(session()), w.make(session()));
    let mem = w.make(memory(Rights::READ, true));
    c.channel.fail = Some(unreachable());
    let e = c
        .give(
            &OPTS,
            give_req(
                CapArg::Move(s1.clone()),
                Some(CapArg::Share(&s2)),
                CapArg::Share(&mem),
            ),
        )
        .unwrap_err();
    assert_eq!(e.outcome, Outcome::Unreachable);
    assert_eq!(c.channel.world.closed, c.channel.world.dups);
    // Indeterminate: it may have arrived, so it is left to idle rundown.
    c.channel.fail = Some(indeterminate());
    let e = c
        .give(
            &OPTS,
            give_req(
                CapArg::Move(s1),
                Some(CapArg::Share(&s2)),
                CapArg::Share(&mem),
            ),
        )
        .unwrap_err();
    assert_eq!(e.outcome, Outcome::Indeterminate);
    assert_eq!(c.channel.world.dups.len(), 2);
    assert_eq!(c.channel.world.closed.len(), 1);
    assert_eq!(c.channel.server.calls, 0);
}

#[test]
fn a_reply_carries_capabilities() {
    let mut c = kinds::Client {
        channel: Loop::new(Kinds::default(), 1),
    };
    let held = c.channel.world.make(session());
    c.channel.server.held = Some(held);
    let x = kinds::types::Later {
        a: 4,
        b: point(),
        r#type: 0,
        c: None,
        unknown_: u(),
    };
    let rep = c
        .later_op(
            &OPTS,
            kinds::methods::later_op::Request { x, unknown_: u() },
        )
        .unwrap();
    assert_eq!(rep.result.a, 5);
    assert_eq!(rep.result.r#type, 9);
    assert_eq!(rep.result.c, Some(CapRef(0)));
    // The server shared its capability: a dup went in the reply.
    assert_eq!(c.channel.world.dups.len(), 1);
    assert_eq!(c.channel.reply_caps, 1);
}

#[test]
fn the_stub_refuses_what_is_too_new_without_sending() {
    // A method newer than the session.
    let mut c = kinds::Client {
        channel: Loop::new(Kinds::default(), 0),
    };
    let x = kinds::types::Later {
        a: 1,
        b: point(),
        r#type: 0,
        c: None,
        unknown_: u(),
    };
    let e = c
        .later_op(
            &OPTS,
            kinds::methods::later_op::Request { x, unknown_: u() },
        )
        .unwrap_err();
    assert_eq!(e.outcome, Outcome::Refused);
    assert!(e.raw.is_none());
    match e.kind {
        ErrorKind::Rpc(RpcError::NoSuchMethod(d)) => {
            assert_eq!((d.method, d.session_minor, d.since_minor), (8, 0, Some(1)));
        }
        k => panic!("{k:?}"),
    }
    // A union arm newer than the session.
    let put = kinds::methods::put::Request {
        item: thing(),
        shape: kinds::types::Shape::Circle(3),
        ev: kinds::types::Event::Moved(kinds::types::Pair { a: 1, b: 2 }),
        unknown_: u(),
    };
    let e = c.put(&OPTS, put.clone()).unwrap_err();
    match e.kind {
        ErrorKind::Rpc(RpcError::ValueTooNew(d)) => assert_eq!(d.since_minor, 1),
        k => panic!("{k:?}"),
    }
    // An enum value and a flag bit newer than the session.
    let tail = kinds::methods::tail::Request {
        after: None,
        lvl: Some(kinds::types::Level::TOP),
        unknown_: u(),
    };
    assert!(matches!(
        c.tail(&OPTS, tail).unwrap_err().kind,
        ErrorKind::Rpc(RpcError::ValueTooNew(_))
    ));
    // A field newer than the session.
    let get = kinds::methods::get::Request {
        key: 1,
        secret: None,
        unknown_: u(),
    };
    c.get(&OPTS, get).unwrap();
    let put11 = kinds::methods::put::Request {
        item: kinds::types::Thing {
            extra: Some(5),
            ..thing()
        },
        ev: kinds::types::Event::Deleted([0; 32]),
        ..put
    };
    match c.put(&OPTS, put11.clone()).unwrap_err().kind {
        ErrorKind::Rpc(RpcError::FieldTooNew(d)) => {
            assert_eq!(d.tags.iter().collect::<Vec<_>>(), [8]);
        }
        k => panic!("{k:?}"),
    }
    assert_eq!(c.channel.server.calls, 1);
    assert_eq!(c.channel.sent.len(), 1);
    // At 1.1 it goes.
    c.channel.session.minor = 1;
    assert!(c.put(&OPTS, put11).unwrap().ok);
}

/// A request encoded with no checks, as a client of a newer minor would.
fn raw_body(f: impl Fn(&mut Writer<'_>) -> Result<(), EncodeError>) -> Vec<u8> {
    encode_body(&mut |w| f(w))
}

#[test]
fn the_dispatcher_refuses_before_dispatch() {
    let mut l = Loop::new(Kinds::default(), 0);
    let ns = |since| rpcd::NoSuchMethod {
        method: 0,
        session_minor: 0,
        since_minor: since,
        unknown_: u(),
    };
    // An unknown method, and one newer than the session.
    match l.refusal(99, &[0, 0, 0, 0], vec![]) {
        RpcError::NoSuchMethod(d) => assert_eq!(
            d,
            rpcd::NoSuchMethod {
                method: 99,
                ..ns(None)
            }
        ),
        e => panic!("{e:?}"),
    }
    match l.refusal(8, &[0, 0, 0, 0], vec![]) {
        RpcError::NoSuchMethod(d) => assert_eq!(
            d,
            rpcd::NoSuchMethod {
                method: 8,
                ..ns(Some(1))
            }
        ),
        e => panic!("{e:?}"),
    }
    // A field newer than the session: thing's extra, tag 8.
    let item = kinds::types::Thing {
        extra: Some(5),
        ..thing()
    };
    let put = |item: kinds::types::Thing<'static>, ev| kinds::methods::put::Request {
        item,
        shape: kinds::types::Shape::Circle(3),
        ev,
        unknown_: u(),
    };
    let body = raw_body(|w| {
        put(item.clone(), kinds::types::Event::Deleted([0; 32])).encode(w, &EncodeCx::ANY)
    });
    match l.refusal(2, &body, vec![]) {
        RpcError::FieldTooNew(d) => assert_eq!(d.tags.iter().collect::<Vec<_>>(), [8]),
        e => panic!("{e:?}"),
    }
    // A union arm newer than the session.
    let moved = kinds::types::Event::Moved(kinds::types::Pair { a: 1, b: 2 });
    let body = raw_body(|w| put(thing(), moved.clone()).encode(w, &EncodeCx::ANY));
    match l.refusal(2, &body, vec![]) {
        RpcError::ValueTooNew(d) => assert_eq!(d.since_minor, 1),
        e => panic!("{e:?}"),
    }
    // A malformed body.
    assert!(matches!(
        l.refusal(1, &[1, 2, 3], vec![]),
        RpcError::Malformed(_)
    ));
    // A local method on a remote session.
    l.session.remote = true;
    assert!(matches!(l.refusal(6, &[], vec![]), RpcError::LocalOnly(_)));
    assert_eq!(l.server.calls, 0);
    // An open type's value that no minor declares isn't refused: it is the
    // implementation's to handle.
    l.session = SessionState {
        minor: 0,
        remote: false,
    };
    let unknown_arm = kinds::types::Event::Unknown_ {
        tag: 40,
        octets: Bytes::Borrowed(&[1, 2]),
    };
    let body = raw_body(|w| put(thing(), unknown_arm.clone()).encode(w, &EncodeCx::ANY));
    l.deliver(2, &body, vec![]);
    assert_eq!(l.answer, Some(Answer::Reply));
    assert_eq!(l.server.calls, 1);
}

#[test]
fn an_application_error_and_its_disposition() {
    let mut c = kinds::Client {
        channel: Loop::new(Kinds::default(), 2),
    };
    let req = kinds::methods::newest::Request {
        m: kinds::types::Mode::Auto,
        f: kinds::types::Perms::READ | kinds::types::Perms::EXEC,
        w: kinds::types::Wide::HIGH,
        unknown_: u(),
    };
    let e = c.newest(&OPTS, req).unwrap_err();
    assert_eq!(e.outcome, Outcome::Refused);
    assert_eq!(e.disposition, Disposition::LATER);
    assert!(matches!(e.app(), Some(kinds::errors::Error::Busy(_))));
}

/// A `[nonzero]` field is never 0 on the wire: the stub refuses to send
/// it, the dispatcher refuses a request that holds it, and a reply that
/// would hold it becomes `internal` (docs/design/call-language.md,
/// "Attributes").
#[test]
fn nonzero_fields_are_never_0() {
    let mut c = kinds::Client {
        channel: Loop::new(Kinds::default(), 2),
    };
    let req = |a: u32, b: Option<i16>, n: u16| kinds::methods::count::Request {
        c: kinds::types::Counts { a, b },
        n,
        unknown_: u(),
    };
    let r = c.count(&OPTS, req(7, Some(-1), 3)).unwrap();
    assert_eq!((r.ids.first, r.total), (7, Some(3)));
    // 0 in a parameter, in a closed struct's field and in its optional
    // field: refused without sending.
    for bad in [req(7, None, 0), req(0, None, 3), req(7, Some(0), 3)] {
        let e = c.count(&OPTS, bad).unwrap_err();
        assert_eq!(e.outcome, Outcome::Refused);
        assert!(e.raw.is_none());
        assert!(
            matches!(e.kind, ErrorKind::Rpc(RpcError::Malformed(_))),
            "{:?}",
            e.kind
        );
    }
    assert_eq!(c.channel.server.calls, 1);
    // A reply that would hold 0: the method ran, and failed.
    let e = c.count(&OPTS, req(7, None, 1)).unwrap_err();
    assert_eq!(e.outcome, Outcome::Failed);
    assert!(
        matches!(e.kind, ErrorKind::Rpc(RpcError::Internal(_))),
        "{:?}",
        e.kind
    );
    assert_eq!(c.channel.server.calls, 2);
    // A request that holds 0, as no stub sends it: counts { a: 1, b: None
    // }, then n = 0, then an empty tail.
    let mut l = Loop::new(Kinds::default(), 2);
    let body = [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
    assert!(matches!(
        l.refusal(10, &body, vec![]),
        RpcError::Malformed(_)
    ));
    let body = [0, 0, 0, 1, 0, 0, 3, 0, 0, 0, 0];
    l.deliver(10, &body, vec![]);
    assert_eq!(l.answer, Some(Answer::Reply));
    assert_eq!(l.server.calls, 1);
}

// ---- An interface the kernel calls -------------------------------------------------

#[derive(Default)]
struct Pager {
    requests: Vec<(u64, u32, Option<pager::types::Access>, u32)>,
    /// Each unknown request's badge and method.
    unknown: Vec<(u64, u16)>,
}

impl Serve for Pager {
    fn serve(&mut self, req: Request<'_, Cap>, resp: &mut Resp<'_>) {
        pager::dispatch(self, req, resp)
    }
}

impl pager::Server for Pager {
    type Cap = Cap;

    fn page_request<'a>(
        &'a mut self,
        _: &Ctx<'a, Cap>,
        req: pager::methods::page_request::Request<'a>,
    ) {
        self.requests
            .push((req.offset, req.length, req.access, req.unknown_.count()));
    }

    fn query<'a>(
        &'a mut self,
        _: &Ctx<'a, Cap>,
        req: pager::methods::query::Request<'a>,
    ) -> Result<pager::methods::query::Reply<'a>, Fail<'a, pager::errors::Error<'a>>> {
        Ok(pager::methods::query::Reply {
            result: req.key * 2,
            unknown_: u(),
        })
    }

    fn unknown_(&mut self, cx: &Ctx<'_, Cap>, method: u16, _: &[u8]) {
        self.unknown.push((cx.badge, method));
    }
}

#[test]
fn the_kernels_requests_are_never_refused() {
    let mut c = pager::Client {
        channel: Loop::new(Pager::default(), 0),
    };
    // One-way: delivered, never answered.
    c.page_request(
        &OPTS,
        pager::methods::page_request::Request {
            offset: 4096,
            length: 8192,
            access: Some(pager::types::Access::WRITE),
            unknown_: u(),
        },
    )
    .unwrap();
    assert_eq!(
        c.channel.server.requests,
        [(4096, 8192, Some(pager::types::Access::WRITE), 0)]
    );
    // An enum value no minor declares, and a later minor's field (tag 7):
    // read tolerantly, and handed on.
    let body = raw_body(|w| {
        w.u64(0)?;
        w.u32(1)?;
        // The tail: two fields.
        w.u32(2)?;
        w.u16(3)?;
        w.octets(&[9])?;
        w.u16(7)?;
        w.octets(&[1, 2])
    });
    c.channel.deliver(1, &body, vec![]);
    assert_eq!(c.channel.answer, None);
    assert_eq!(
        c.channel.server.requests[1],
        (0, 1, Some(pager::types::Access(9)), 1)
    );
    // An unknown method, and one that doesn't decode: handed on with the
    // badge, which names the faulting thread or memory object.
    c.channel.badge = 0x7ead;
    c.channel.deliver(40, &[], vec![]);
    c.channel.deliver(2, &[1], vec![]);
    assert_eq!(c.channel.server.unknown, [(0x7ead, 40), (0x7ead, 2)]);
    assert_eq!(c.channel.answer, None);
    // A two-way call is answered as usual.
    let rep = c
        .query(
            &OPTS,
            pager::methods::query::Request {
                key: 21,
                unknown_: u(),
            },
        )
        .unwrap();
    assert_eq!(rep.result, 42);
}

#[test]
fn metadata_records_locality_rights_and_capabilities() {
    let m = &kinds::META;
    assert!(m.session_rights.contains(Rights::GRANT));
    let give = m.method(4).unwrap();
    assert_eq!(give.request.caps, 3);
    assert!(!give.local);
    let big = m.method(5).unwrap();
    assert!(big.request.may_spill);
    assert_eq!(big.request.caps, 2);
    let notify = m.method(6).unwrap();
    assert!(notify.local);
    let tail = m.method(3).unwrap();
    assert_eq!(tail.stream.unwrap().kind, idl_rt::meta::StreamKind::Lossy);
    assert_eq!(m.method(8).unwrap().since, 1);
    assert!(pager::META.kernel_called);
    // register carries a capability, so sessions need grant.
    assert!(catalog::META.session_rights.contains(Rights::GRANT));
    assert!(!pager::META.session_rights.contains(Rights::GRANT));
}

#[test]
fn member_names_never_collide_with_generated_items() {
    // A field `unknown` beside the preserved `unknown_`; an arm `unknown`
    // beside `Unknown_`; errors `unknown` and `error` beside `Unknown_`
    // and the enum `Error`.
    let odd = kinds::types::Odd {
        unknown: 1,
        unknown_tag: Some(2),
        tail: None,
        unknown_: u(),
    };
    let mut buf = [0u8; 64];
    let mut w = Writer::new(&mut buf);
    odd.encode(&mut w, &EncodeCx::ANY).unwrap();
    let n = w.len();
    let mut cx = idl_rt::wire::DecodeCx::new(2, idl_rt::wire::Mode::Strict, 0);
    let back = idl_rt::wire::decode_all(&buf[..n], &mut cx, kinds::types::Odd::decode).unwrap();
    assert_eq!(back, odd);
    let arms = [
        kinds::types::Event::Unknown(3),
        kinds::types::Event::Unknown_ {
            tag: 9,
            octets: Bytes::Borrowed(&[1]),
        },
    ];
    assert_ne!(arms[0], arms[1]);
    let errors = [
        kinds::errors::Error::Unknown(kinds::errors::detail::Unknown { unknown_: u() }),
        kinds::errors::Error::Error(kinds::errors::detail::Error {
            unknown: Some(1),
            unknown_: u(),
        }),
        kinds::errors::Error::Unknown_ {
            code: 40,
            detail: Bytes::Borrowed(&[]),
        },
    ];
    let codes: Vec<u16> = errors.iter().map(|e| e.code()).collect();
    assert_eq!(codes, [4, 5, 40]);
    assert_eq!(errors[1].name(), Some("error"));
}
