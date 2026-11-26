// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The seams between generated stubs and dispatchers and the runtime that
//! moves messages: kernel IPC (C18), network proxies (C29), and in-memory
//! loopbacks in tests (docs/design/call-language.md, "Back ends").
//!
//! A [`Channel`] is a client's session. It owns buffers, headers, request
//! IDs, deadlines and spilling, so a stub never sizes a buffer. A
//! [`Responder`] is a server's side of one call. Both do the capability
//! operations of [`CapOps`].
//!
//! The helpers here are what every generated stub and dispatcher shares:
//!
//! - [`call`] and [`send`]: a stub refuses, without sending, a method
//!   newer than the session's minor (`no_such_method`), a set field newer
//!   than it (`field_too_new`), and a set enum value, flag bit or union
//!   arm newer than it (`value_too_new`), all with outcome refused ("Refusing
//!   what is too new"). It attenuates each kernel object capability to its
//!   declared rights, sends a moved session capability as it is, and dups
//!   a shared one first. When a call that carried a dup'd badge comes back
//!   unreachable, the stub closes that badge; an indeterminate one is left
//!   to idle rundown ("Sessions, badges and proxies").
//! - [`accept`]: a dispatcher's checks before dispatch: `no_such_method`,
//!   `local_only` on a remote session, then the request decoded strictly
//!   (`malformed`, `field_too_new`, `value_too_new`), then each received
//!   capability's kind and rights (`capability_rights`). Interfaces the
//!   kernel calls make none of these refusals.
//! - [`reply`] and [`fail`]: a dispatcher's answer.

// A `CallError` is returned by value: the crate has no allocator to box
// it in, and it keeps the error envelope's fields for the caller.
#![allow(clippy::result_large_err)]

use crate::{
    cap::{CapArg, CapRef, CapSink, Collect, MAX_CAPS, Positions, Rights},
    envelope,
    error::{AppError, CallError, Disposition, ErrorKey, ErrorKind, LocalError, Outcome, RpcError},
    meta::{Identity, MethodInfo},
    rpc::v1::{self as rpc, errors::detail},
    view::{Seq, Unknown},
    wire::{DecodeCx, DecodeError, EncodeCx, EncodeError, Mode, Reader, Tags, Writer, decode_all},
};

/// Per-call options, which generated code passes through untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CallOptions {
    /// An absolute deadline, in the node's virtual count (ADR 0051,
    /// rule 5).
    pub deadline: Option<u64>,
    /// The request ID, for retries and the reply cache (L04).
    pub request_id: Option<[u8; 16]>,
}

/// A capability on its way out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outgoing<C> {
    /// A session capability the caller gave up: its badge is now the
    /// receiver's.
    Moved(C),
    /// A new badge the stub made with `session_dup`, for a shared session
    /// capability.
    Dup(C),
    /// A kernel object capability's copy with exactly the declared rights,
    /// in a scratch slot that the channel deletes once it is sent.
    Attenuated(C),
}

impl<C> Outgoing<C> {
    pub fn cap(&self) -> &C {
        match self {
            Outgoing::Moved(c) | Outgoing::Dup(c) | Outgoing::Attenuated(c) => c,
        }
    }
}

/// A message's outgoing capabilities, in list order.
#[derive(Debug)]
pub struct CapsOut<C> {
    items: [Option<Outgoing<C>>; MAX_CAPS as usize],
    len: u8,
}

impl<C> Default for CapsOut<C> {
    fn default() -> Self {
        CapsOut {
            items: [None, None, None],
            len: 0,
        }
    }
}

impl<C> CapsOut<C> {
    pub fn len(&self) -> u8 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &Outgoing<C>> {
        self.items.iter().flatten()
    }

    fn push(&mut self, o: Outgoing<C>) {
        if let Some(slot) = self.items.get_mut(usize::from(self.len)) {
            *slot = Some(o);
            self.len += 1;
        }
    }
}

impl<C> IntoIterator for CapsOut<C> {
    type Item = Outgoing<C>;
    type IntoIter = core::iter::Flatten<core::array::IntoIter<Option<Outgoing<C>>, 3>>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter().flatten()
    }
}

/// The capability operations a stub or a dispatcher needs.
pub trait CapOps {
    /// A capability address in the caller's capability space. Which
    /// badges the binding owns is the runtime's to track.
    type Cap: Clone + 'static;
    /// `session_dup`: another badge of the same session.
    fn dup(&mut self, cap: &Self::Cap) -> Result<Self::Cap, LocalError>;
    /// A copy with exactly these rights, in a scratch slot.
    fn attenuate(&mut self, cap: &Self::Cap, rights: Rights) -> Result<Self::Cap, LocalError>;
    /// `session_close`: releases a badge the binding owns.
    fn close(&mut self, cap: Self::Cap);
    /// Deletes a scratch copy that was never sent.
    fn delete(&mut self, cap: Self::Cap);
}

/// What came back for a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received<'a> {
    /// A reply body (or a stream's opening reply), with the capabilities
    /// in its list.
    Reply { body: &'a [u8], caps: u8 },
    /// An error envelope.
    Error(&'a [u8]),
}

/// A client's session with one object, at the minor its bind fixed.
pub trait Channel: CapOps {
    /// The session's minor, fixed at bind (ADR 0014, rule 4).
    fn session_minor(&self) -> u16;
    /// Makes a call. `body` writes the request body; it may be called
    /// more than once. The channel takes the outgoing capabilities, and
    /// deletes attenuated copies once sent. An error is the channel's own:
    /// a kernel result as an `aspis.rpc` error ("Kernel results").
    fn call(
        &mut self,
        method: u16,
        opts: &CallOptions,
        body: &mut dyn FnMut(&mut Writer<'_>) -> Result<(), EncodeError>,
        caps: CapsOut<Self::Cap>,
    ) -> Result<(), LocalError>;
    /// What came back for the last call.
    fn received(&self) -> Received<'_>;
    /// Sends a one-way request ([local] interfaces only).
    fn send(
        &mut self,
        method: u16,
        opts: &CallOptions,
        body: &mut dyn FnMut(&mut Writer<'_>) -> Result<(), EncodeError>,
        caps: CapsOut<Self::Cap>,
    ) -> Result<(), LocalError>;
}

/// How a stub reads an interface's own errors.
pub struct Errors<'r, E> {
    pub interface: &'static [u8; 32],
    pub major: u16,
    /// Decodes an error's detail struct, by code.
    pub decode: fn(u16, &'r [u8], &mut DecodeCx) -> Result<E, DecodeError>,
}

/// Encodes a message body with its capabilities: called once to collect
/// them, and again to write it.
pub type Encode<'e, 'q, 'c, C> = &'e dyn Fn(
    &mut Writer<'_>,
    &EncodeCx,
    &mut dyn CapSink<'q, CapArg<'c, C>>,
) -> Result<(), EncodeError>;

fn malformed() -> RpcError<'static> {
    RpcError::Malformed(detail::Malformed {
        unknown_: Unknown::default(),
    })
}

/// What a stub refuses for an encoding error.
fn encode_refusal(e: EncodeError) -> RpcError<'static> {
    match e {
        EncodeError::FieldTooNew(tags) => RpcError::FieldTooNew(detail::FieldTooNew {
            tags: Seq::Slice(tags),
            unknown_: Unknown::default(),
        }),
        EncodeError::ValueTooNew(since) => RpcError::ValueTooNew(detail::ValueTooNew {
            since_minor: since,
            unknown_: Unknown::default(),
        }),
        // A value out of its bounds: the server would refuse it.
        _ => malformed(),
    }
}

/// Releases outgoing capabilities that were never sent.
fn release<O: CapOps + ?Sized>(ops: &mut O, caps: CapsOut<O::Cap>) {
    for o in caps {
        match o {
            Outgoing::Moved(_) => {}
            Outgoing::Dup(c) => ops.close(c),
            Outgoing::Attenuated(c) => ops.delete(c),
        }
    }
}

/// Collects a body's capabilities, in encoding order, and converts each:
/// attenuated for a kernel object, moved or dup'd for a session.
fn outgoing<'q, 'c, O: CapOps + ?Sized>(
    ops: &mut O,
    cx: &EncodeCx,
    encode: Encode<'_, 'q, 'c, O::Cap>,
) -> Result<CapsOut<O::Cap>, (Outcome, RpcError<'static>)> {
    let mut col = Collect::new();
    encode(&mut Writer::measure(), cx, &mut col)
        .map_err(|e| (Outcome::Refused, encode_refusal(e)))?;
    let mut out = CapsOut::default();
    for (arg, ty) in col.iter() {
        let made = if ty.kernel_object {
            ops.attenuate(arg.cap(), ty.rights)
                .map(Outgoing::Attenuated)
        } else {
            match arg {
                CapArg::Move(c) => Ok(Outgoing::Moved(c.clone())),
                CapArg::Share(c) => ops.dup(c).map(Outgoing::Dup),
            }
        };
        match made {
            Ok(o) => out.push(o),
            Err(e) => {
                release(ops, out);
                return Err((e.outcome, e.error));
            }
        }
    }
    Ok(out)
}

/// The stub's side of a call, up to sending: the method's `since`, the
/// request's own checks, and its capabilities. Returns them, the dup'd
/// badges to close if the call comes back unreachable, and the minor.
#[allow(clippy::type_complexity)]
fn prepare<'q, 'c, C: Channel>(
    chan: &mut C,
    m: &MethodInfo,
    encode: Encode<'_, 'q, 'c, C::Cap>,
) -> Result<(CapsOut<C::Cap>, [Option<C::Cap>; 3], u16), (Outcome, RpcError<'static>)> {
    let minor = chan.session_minor();
    if m.since > minor {
        return Err((
            Outcome::Refused,
            RpcError::NoSuchMethod(detail::NoSuchMethod {
                method: m.number,
                session_minor: minor,
                since_minor: Some(m.since),
                unknown_: Unknown::default(),
            }),
        ));
    }
    let caps = outgoing(chan, &EncodeCx::at(minor), encode)?;
    let mut dups: [Option<C::Cap>; 3] = [None, None, None];
    for (d, o) in dups.iter_mut().zip(caps.iter()) {
        if let Outgoing::Dup(c) = o {
            *d = Some(c.clone());
        }
    }
    Ok((caps, dups, minor))
}

/// Makes a two-way call: `decode` reads the reply body (a stream method's
/// opening reply included) at the session's minor, tolerantly.
pub fn call<'r, 'q, 'c, C: Channel, T, E>(
    chan: &'r mut C,
    m: &MethodInfo,
    opts: &CallOptions,
    encode: Encode<'_, 'q, 'c, C::Cap>,
    decode: impl FnOnce(&mut Reader<'r>, &mut DecodeCx) -> Result<T, DecodeError>,
    errors: &Errors<'r, E>,
) -> Result<T, CallError<'r, E>> {
    let (caps, dups, minor) = prepare(chan, m, encode).map_err(|(o, e)| CallError::local(o, e))?;
    let cx = EncodeCx::at(minor);
    let sent = chan.call(
        m.number,
        opts,
        &mut |w| encode(w, &cx, &mut Positions::new()),
        caps,
    );
    let unreachable = match &sent {
        Err(e) => e.outcome == Outcome::Unreachable,
        Ok(()) => matches!(
            chan.received(),
            Received::Error(env) if env.first() == Some(&(Outcome::Unreachable as u8))
        ),
    };
    if unreachable {
        for d in dups.into_iter().flatten() {
            chan.close(d);
        }
    }
    if let Err(e) = sent {
        return Err(CallError::local(e.outcome, e.error));
    }
    let chan: &'r C = chan;
    match chan.received() {
        Received::Reply { body, caps } => {
            // A reply the client can't read: the method may have run,
            // and no usable answer came. More capabilities than a message
            // carries is a reply no decoder reads.
            if caps > MAX_CAPS {
                return Err(CallError::local(Outcome::Indeterminate, malformed()));
            }
            let mut cx = DecodeCx::new(minor, Mode::Tolerant, caps);
            decode_all(body, &mut cx, decode)
                .map_err(|_| CallError::local(Outcome::Indeterminate, malformed()))
        }
        Received::Error(env) => Err(error_of(env, minor, errors)),
    }
}

/// Sends a one-way request.
pub fn send<'r, 'q, 'c, C: Channel, E>(
    chan: &mut C,
    m: &MethodInfo,
    opts: &CallOptions,
    encode: Encode<'_, 'q, 'c, C::Cap>,
) -> Result<(), CallError<'r, E>> {
    let (caps, dups, minor) = prepare(chan, m, encode).map_err(|(o, e)| CallError::local(o, e))?;
    let cx = EncodeCx::at(minor);
    let sent = chan.send(
        m.number,
        opts,
        &mut |w| encode(w, &cx, &mut Positions::new()),
        caps,
    );
    if let Err(e) = sent {
        if e.outcome == Outcome::Unreachable {
            for d in dups.into_iter().flatten() {
                chan.close(d);
            }
        }
        return Err(CallError::local(e.outcome, e.error));
    }
    Ok(())
}

/// Reads an error envelope as the interface's own error, a system error,
/// or a foreign one.
fn error_of<'r, E>(env: &'r [u8], minor: u16, errors: &Errors<'r, E>) -> CallError<'r, E> {
    let raw = match envelope::decode(env) {
        Ok(r) => r,
        Err(_) => return CallError::local(Outcome::Indeterminate, malformed()),
    };
    let key = raw.key;
    let kind = if key.interface == *errors.interface && key.major == errors.major {
        let mut cx = DecodeCx::new(minor, Mode::Tolerant, 0);
        match (errors.decode)(key.code, raw.detail, &mut cx) {
            Ok(e) => ErrorKind::App(e),
            Err(_) => ErrorKind::Foreign(raw.clone()),
        }
    } else if key.interface == rpc::ID && key.major == rpc::MAJOR {
        // aspis.rpc's minor is its own; read at the newest this runtime
        // knows.
        let mut cx = DecodeCx::new(rpc::MINOR, Mode::Tolerant, 0);
        match RpcError::decode(key.code, raw.detail, &mut cx) {
            Ok(e) => ErrorKind::Rpc(e),
            Err(_) => ErrorKind::Foreign(raw.clone()),
        }
    } else {
        ErrorKind::Foreign(raw.clone())
    };
    CallError {
        outcome: raw.outcome,
        disposition: raw.disposition,
        kind,
        raw: Some(raw),
    }
}

// ---- Servers ---------------------------------------------------------------

/// What a session's bind fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionState {
    pub minor: u16,
    /// The bind came through a network server.
    pub remote: bool,
}

/// One request, as a dispatcher receives it.
#[derive(Debug)]
pub struct Request<'a, C> {
    pub method: u16,
    pub body: &'a [u8],
    /// The capabilities received, in list order.
    pub caps: &'a [C],
    pub session: SessionState,
    /// The badge the request came with, which the runtime reads from the
    /// IPC receive: the session locally, or the faulting thread or memory
    /// object in a message the kernel sends ("Messages the kernel sends").
    /// A runtime with none, such as a proxy's, passes 0.
    pub badge: u64,
}

/// What a server's method sees besides its parameters.
#[derive(Debug)]
pub struct Ctx<'a, C> {
    pub session: SessionState,
    pub caps: &'a [C],
    /// The request's badge, as [`Request::badge`].
    pub badge: u64,
}

impl<'a, C> Ctx<'a, C> {
    /// The received capability a parameter names.
    pub fn cap(&self, r: CapRef) -> Option<&'a C> {
        self.caps.get(usize::from(r.0))
    }
}

/// What a dispatcher refuses before dispatch: nothing ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NoSuchMethod {
        method: u16,
        session_minor: u16,
        since_minor: Option<u16>,
    },
    FieldTooNew(Tags),
    ValueTooNew {
        since: u16,
    },
    LocalOnly,
    CapabilityRights {
        position: u8,
        missing: Rights,
    },
    Malformed,
}

impl Refusal {
    /// The refusal as an `aspis.rpc` error.
    pub fn error(&self) -> RpcError<'_> {
        let u = Unknown::default;
        match self {
            Refusal::NoSuchMethod {
                method,
                session_minor,
                since_minor,
            } => RpcError::NoSuchMethod(detail::NoSuchMethod {
                method: *method,
                session_minor: *session_minor,
                since_minor: *since_minor,
                unknown_: u(),
            }),
            Refusal::FieldTooNew(tags) => RpcError::FieldTooNew(detail::FieldTooNew {
                tags: Seq::Slice(tags.as_slice()),
                unknown_: u(),
            }),
            Refusal::ValueTooNew { since } => RpcError::ValueTooNew(detail::ValueTooNew {
                since_minor: *since,
                unknown_: u(),
            }),
            Refusal::LocalOnly => RpcError::LocalOnly(detail::LocalOnly { unknown_: u() }),
            Refusal::CapabilityRights { position, missing } => {
                RpcError::CapabilityRights(detail::CapabilityRights {
                    position: *position,
                    missing: missing.bits(),
                    unknown_: u(),
                })
            }
            Refusal::Malformed => malformed(),
        }
    }
}

/// A server's side of one call.
pub trait Responder: CapOps {
    /// The kernel's identify operation on a received capability (L41).
    fn identify(&mut self, index: u8) -> Option<Identity<'static>>;
    /// Sends the reply body (a stream method's opening reply included).
    fn reply(
        &mut self,
        body: &mut dyn FnMut(&mut Writer<'_>) -> Result<(), EncodeError>,
        caps: CapsOut<Self::Cap>,
    );
    /// Sends an error envelope with this detail.
    fn error(
        &mut self,
        outcome: Outcome,
        disposition: Disposition,
        key: ErrorKey,
        detail: &mut dyn FnMut(&mut Writer<'_>) -> Result<(), EncodeError>,
    );
    /// Sends a refusal, as its `aspis.rpc` error.
    fn refuse(&mut self, r: &Refusal) {
        let e = r.error();
        self.error(Outcome::Refused, e.disposition(), e.key(), &mut |w| {
            e.encode_detail(w, &EncodeCx::ANY)
        });
    }
}

/// A server method's error.
#[derive(Debug, Clone, PartialEq)]
pub enum Fail<'a, E> {
    /// The interface's own.
    App(E),
    /// A system error, such as `internal` or `no_memory`.
    Rpc(RpcError<'a>),
}

/// A dispatcher's checks before dispatch, and the request decoded.
pub fn accept<'a, C, R: Responder + ?Sized, T>(
    req: &Request<'a, C>,
    resp: &mut R,
    m: &MethodInfo,
    kernel_called: bool,
    decode: impl FnOnce(&mut Reader<'a>, &mut DecodeCx) -> Result<T, DecodeError>,
) -> Result<T, Refusal> {
    let s = req.session;
    if !kernel_called {
        if m.since > s.minor {
            return Err(Refusal::NoSuchMethod {
                method: m.number,
                session_minor: s.minor,
                since_minor: Some(m.since),
            });
        }
        if m.local && s.remote {
            return Err(Refusal::LocalOnly);
        }
    }
    let caps = u8::try_from(req.caps.len())
        .ok()
        .filter(|&n| n <= MAX_CAPS)
        .ok_or(Refusal::Malformed)?;
    let mode = if kernel_called {
        Mode::Tolerant
    } else {
        Mode::Strict
    };
    let mut cx = DecodeCx::new(s.minor, mode, caps);
    let v = decode_all(req.body, &mut cx, decode).map_err(|e| match e {
        DecodeError::Malformed => Refusal::Malformed,
        DecodeError::FieldTooNew(t) => Refusal::FieldTooNew(t),
    })?;
    if kernel_called {
        return Ok(v);
    }
    if let Some(since) = cx.value_too_new() {
        return Err(Refusal::ValueTooNew { since });
    }
    for i in 0..caps {
        if let Some(ty) = cx.cap_type(i)
            && let Err(missing) = ty.check(resp.identify(i))
        {
            return Err(Refusal::CapabilityRights {
                position: i,
                missing,
            });
        }
    }
    Ok(v)
}

/// Sends a reply with its capabilities. A reply that won't encode, or
/// whose capabilities can't be sent, becomes a failed error: the method
/// ran.
pub fn reply<'q, 'c, R: Responder + ?Sized>(resp: &mut R, encode: Encode<'_, 'q, 'c, R::Cap>) {
    match outgoing(resp, &EncodeCx::ANY, encode) {
        Ok(caps) => resp.reply(
            &mut |w| encode(w, &EncodeCx::ANY, &mut Positions::new()),
            caps,
        ),
        Err((_, e)) => {
            let e = match e {
                RpcError::Malformed(_) | RpcError::FieldTooNew(_) | RpcError::ValueTooNew(_) => {
                    RpcError::Internal(detail::Internal {
                        unknown_: Unknown::default(),
                    })
                }
                e => e,
            };
            fail::<R, RpcError<'_>>(resp, Fail::Rpc(e));
        }
    }
}

/// Sends a server method's error. A system error keeps its outcome only
/// when it is refused or failed: a server sends nothing else ("Outcomes").
pub fn fail<R: Responder + ?Sized, E: AppError>(resp: &mut R, f: Fail<'_, E>) {
    match f {
        Fail::App(e) => send_error(resp, &e),
        Fail::Rpc(e) => send_error(resp, &e),
    }
}

fn send_error<R: Responder + ?Sized, E: AppError>(resp: &mut R, e: &E) {
    let outcome = match e.outcome() {
        Outcome::Refused => Outcome::Refused,
        _ => Outcome::Failed,
    };
    resp.error(outcome, e.disposition(), e.key(), &mut |w| {
        e.encode_detail(w, &EncodeCx::ANY)
    });
}
