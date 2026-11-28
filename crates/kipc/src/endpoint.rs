// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Synchronous endpoints (ADR 0054; kernel specification, "Endpoint
//! operations and messages" and "IPC deadlines and cancellation"), with
//! seL4's send, send without blocking, call, receive, and reply and
//! receive. `specs/IpcEndpoint.tla` models this module, and the host tests
//! check traces of it against the spec's steps.
//!
//! **The queue.** An endpoint queues senders or receivers, never both, as
//! in seL4. They are served in priority order, first come first served
//! within a priority (ADR 0054, rule 1): the queue is an intrusive
//! red-black tree linked through the waiting threads, keyed by priority,
//! highest first, then by the endpoint's arrival number (K25). A thread
//! whose priority changes while queued leaves and rejoins as a new arrival,
//! as seL4's `reorderEP` does ([`requeue`]). Queued senders are also in a
//! second tree keyed by badge, then arrival, so canceling a badge's sends
//! takes them out one per unit (K23; [`cancel_badged`]).
//!
//! **Donation.** Every wait is a `ksched::donation` state, and donation
//! stays the one implementation of scheduling contexts and reply objects:
//! a call delivered to a receiver is donation's `call` or `deliver`, which
//! donates the caller's context to a passive server. This module keeps the
//! queues around those transitions and tells the kernel what to copy
//! ([`crate::store::Transfer`]); it never touches a context.
//!
//! **Checks first.** Each operation checks its rights and its arguments
//! before it changes anything; a refusal returns its status with nothing
//! changed (K30). A call needs the write right and grant or grant-reply; a
//! receive the read right; reply and receive checks its endpoint, its
//! reply object and its reply's info word before it replies, so "no
//! caller" is the one result that can follow the reply, and it doesn't stop
//! the receive.
//!
//! **Faults** travel as calls the kernel makes on the faulting thread's
//! behalf (kernel specification, "Fault delivery"): queued as
//! [`Role::Fault`], delivered by donation's `deliver`, donating for a fault
//! on the fault endpoint and not for a timeout or context-withdrawn fault.

use crate::eventcount;
use crate::msg::{Info, Status};
use crate::store::{EpRec, IpcRec, IpcStore, Role, Transfer};
use crate::{Ep, NIL, Outcome, Rights};
use kcap::preempt::{Budget, Pending, Preempted};
use ksched::donation::{self, Error, RState, Reply, Res, TState, Tcb};
use ksched::tree::{self, Links, TreeStore};

/// An endpoint capability, as the kernel looked it up: the endpoint, its
/// badge and its rights.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpCap {
    pub ep: Ep,
    pub badge: u64,
    pub rights: Rights,
}

/// A donation refusal as a status.
fn status(e: Error) -> Status {
    match e {
        Error::Busy => Status::Busy,
        Error::NoCaller => Status::NoCaller,
        Error::NotHolder => Status::NotHolder,
        _ => Status::InvalidArgument,
    }
}

// ---------------------------------------------------------------------------
// The queue and the badge tree.

struct Queue<'a, S>(&'a mut S);

impl<S: IpcStore> TreeStore for Queue<'_, S> {
    type Key = (u8, u64, u64);

    fn key(&self, n: u64) -> Self::Key {
        let r = self.0.ipc(Tcb(n));
        (u8::MAX - r.prio, r.arrival, n)
    }

    fn links(&self, n: u64) -> Links {
        self.0.ipc(Tcb(n)).links
    }

    fn set_links(&mut self, n: u64, l: Links) {
        let mut r = self.0.ipc(Tcb(n));
        r.links = l;
        self.0.set_ipc(Tcb(n), r);
    }
}

struct Badges<'a, S>(&'a mut S);

impl<S: IpcStore> TreeStore for Badges<'_, S> {
    type Key = (u64, u64, u64);

    fn key(&self, n: u64) -> Self::Key {
        let r = self.0.ipc(Tcb(n));
        (r.badge, r.arrival, n)
    }

    fn links(&self, n: u64) -> Links {
        self.0.ipc(Tcb(n)).blinks
    }

    fn set_links(&mut self, n: u64, l: Links) {
        let mut r = self.0.ipc(Tcb(n));
        r.blinks = l;
        self.0.set_ipc(Tcb(n), r);
    }
}

/// Puts `t` into both of `e`'s trees, as `rec` describes it, as a new
/// arrival with its priority now.
fn insert<S: IpcStore>(s: &mut S, e: Ep, t: Tcb, mut rec: IpcRec) {
    let mut ep = s.ep(e);
    rec.ep = Some(e);
    rec.arrival = ep.next;
    rec.prio = s.priority(t);
    rec.links = Links::default();
    rec.blinks = Links::default();
    s.set_ipc(t, rec);
    ep.next = ep.next.saturating_add(1);
    ep.recv = rec.role == Role::Recv;
    tree::insert(&mut Queue(s), &mut ep.root, t.0);
    if rec.role != Role::Recv {
        tree::insert(&mut Badges(s), &mut ep.broot, t.0);
    }
    s.set_ep(e, ep);
}

/// Queues `t` on `e` for `role`.
fn enqueue<S: IpcStore>(s: &mut S, e: Ep, t: Tcb, role: Role, info: u64, badge: u64, grant: bool) {
    let rec = IpcRec {
        role,
        info,
        badge,
        grant,
        ..IpcRec::default()
    };
    insert(s, e, t, rec);
}

/// Takes `t` out of its endpoint's trees, if it is queued, and returns its
/// record as it was. Its wait isn't ended: the caller ends it.
pub fn leave<S: IpcStore>(s: &mut S, t: Tcb) -> IpcRec {
    let rec = s.ipc(t);
    let Some(e) = rec.ep else {
        return rec;
    };
    let mut ep = s.ep(e);
    tree::remove(&mut Queue(s), &mut ep.root, t.0);
    if rec.role != Role::Recv {
        tree::remove(&mut Badges(s), &mut ep.broot, t.0);
    }
    s.set_ep(e, ep);
    let mut now = s.ipc(t);
    now.ep = None;
    now.links = Links::default();
    now.blinks = Links::default();
    s.set_ipc(t, now);
    rec
}

/// The first thread of `e`'s queue, or None.
fn head<S: IpcStore>(s: &mut S, e: Ep) -> Option<Tcb> {
    let root = s.ep(e).root;
    let n = tree::first(&Queue(s), root);
    (n != NIL).then_some(Tcb(n))
}

/// The first receiver queued on `e`, if receivers are queued.
fn receiver<S: IpcStore>(s: &mut S, e: Ep) -> Option<Tcb> {
    if s.ep(e).recv { head(s, e) } else { None }
}

/// The first sender queued on `e`, if senders are queued.
fn sender<S: IpcStore>(s: &mut S, e: Ep) -> Option<Tcb> {
    if s.ep(e).recv { None } else { head(s, e) }
}

/// The threads queued on `e`, in the order they are served. O(n): for
/// tests and checks.
pub fn queued<S: IpcStore>(s: &mut S, e: Ep, out: &mut [Tcb]) -> usize {
    let root = s.ep(e).root;
    let mut n = tree::first(&Queue(s), root);
    let mut k = 0;
    while n != NIL && k < out.len() {
        if let Some(slot) = out.get_mut(k) {
            *slot = Tcb(n);
        }
        k += 1;
        n = tree::next(&Queue(s), n);
    }
    k
}

/// Takes `t` out of every queue and tree its wait has it in: an endpoint's
/// queue and badge tree, its own eventcount node, a wait set's entries
/// (K17). It does nothing for a thread in none of them. The kernel's
/// donation store calls it as `cancel_other`.
pub fn cancel_wait<S: IpcStore>(s: &mut S, t: Tcb) {
    leave(s, t);
    eventcount::unlink_waits(s, t);
}

// ---------------------------------------------------------------------------
// Delivery.

/// Delivers queued sender `x`'s message, call or fault to `v`, which waits
/// in `Recv`; `x` has left the queue.
fn deliver_queued<S: IpcStore>(s: &mut S, e: Ep, x: Tcb, rec: IpcRec, v: Tcb) {
    match rec.role {
        Role::Send => {
            let _ = donation::deliver_send(s, x, v);
            s.transfer(
                x,
                v,
                Transfer::Message {
                    ep: e,
                    info: rec.info,
                    badge: rec.badge,
                    grant: rec.grant,
                },
            );
        }
        Role::Call => {
            let _ = donation::deliver(s, x, v);
            s.transfer(
                x,
                v,
                Transfer::Message {
                    ep: e,
                    info: rec.info,
                    badge: rec.badge,
                    grant: rec.grant,
                },
            );
        }
        Role::Fault => {
            let _ = donation::deliver(s, x, v);
            s.transfer(x, v, Transfer::Fault { badge: rec.badge });
        }
        Role::Recv => {}
    }
}

/// Takes the first receiver off `e`'s queue, out of its bound eventcount's
/// tree too, and returns it.
fn take_receiver<S: IpcStore>(s: &mut S, e: Ep) -> Option<Tcb> {
    let v = receiver(s, e)?;
    cancel_wait(s, v);
    Some(v)
}

// ---------------------------------------------------------------------------
// The operations. The kernel runs each for a thread that runs ("Runs" in
// the specs), with the capability it looked up.

/// `Send(t)` and `NBSend(t)`: `t` sends a message with info word `info` on
/// `cap`, which needs the write right. A waiting receiver gets it at once.
/// Otherwise a blocking send queues `t`, and a send without blocking drops
/// the message (ADR 0054, rule 2).
pub fn send<S: IpcStore>(
    s: &mut S,
    t: Tcb,
    cap: EpCap,
    info: u64,
    block: bool,
) -> Result<Outcome, Status> {
    if !cap.rights.contains(Rights::WRITE) {
        return Err(Status::MissingRight);
    }
    Info::for_send(info)?;
    let grant = cap.rights.contains(Rights::GRANT);
    if let Some(v) = take_receiver(s, cap.ep) {
        // A passive receiver is left ready with no context, as in seL4.
        let _ = donation::wake(s, v, Res::Replied);
        s.transfer(
            t,
            v,
            Transfer::Message {
                ep: cap.ep,
                info,
                badge: cap.badge,
                grant,
            },
        );
        return Ok(Outcome::Done);
    }
    if !block {
        return Ok(Outcome::Done);
    }
    enqueue(s, cap.ep, t, Role::Send, info, cap.badge, grant);
    donation::send_wait(s, t);
    Ok(Outcome::Blocked)
}

/// The checks of [`call`], which change nothing: the write right and grant
/// or grant-reply, the info word, and a context. The kernel runs them
/// before it looks at a call's deadline, so a refused call reports its
/// error even when its deadline has passed (K19: a passed deadline times
/// out only a call that would block).
pub fn call_check<S: IpcStore>(s: &S, t: Tcb, cap: EpCap, info: u64) -> Result<(), Status> {
    if !cap.rights.contains(Rights::WRITE)
        || !(cap.rights.contains(Rights::GRANT) || cap.rights.contains(Rights::GRANT_REPLY))
    {
        return Err(Status::MissingRight);
    }
    Info::for_send(info)?;
    if s.thread(t).sc.is_none() {
        // A running thread holds a context; this is no running thread.
        return Err(Status::InvalidArgument);
    }
    Ok(())
}

/// `Call(t)`: `t` calls on `cap`, which needs the write right and grant or
/// grant-reply (seL4 lets such a call through and leaves the caller
/// inactive; ASPIS refuses it). Delivered at once to a waiting receiver,
/// donating `t`'s context to a passive one; otherwise `t` waits queued.
/// Either way `t` blocks until the reply, a cancel, its deadline or a
/// destruction.
pub fn call<S: IpcStore>(s: &mut S, t: Tcb, cap: EpCap, info: u64) -> Result<Outcome, Status> {
    call_check(s, t, cap, info)?;
    let grant = cap.rights.contains(Rights::GRANT);
    if let Some(v) = take_receiver(s, cap.ep) {
        let _ = donation::call(s, t, v);
        s.transfer(
            t,
            v,
            Transfer::Message {
                ep: cap.ep,
                info,
                badge: cap.badge,
                grant,
            },
        );
        return Ok(Outcome::Blocked);
    }
    enqueue(s, cap.ep, t, Role::Call, info, cap.badge, grant);
    donation::send_wait(s, t);
    Ok(Outcome::Blocked)
}

/// `Fault(t)`: `t` raised a fault, and has a fault endpoint `e`, whose copy
/// in its thread carries `badge` (ADR 0056, rule 1). It waits, sending the
/// fault: delivered at once to a waiting receiver, as a call that donates;
/// otherwise queued.
pub fn fault<S: IpcStore>(s: &mut S, t: Tcb, e: Ep, badge: u64) {
    donation::fault_wait(s, t);
    send_fault(s, t, e, badge);
}

/// Sends `t`'s fault, already in donation's `Fault` state, on `e`: the
/// timeout endpoint's half of the donation store's `send_fault`, and
/// [`fault`]'s.
pub fn send_fault<S: IpcStore>(s: &mut S, t: Tcb, e: Ep, badge: u64) {
    if let Some(v) = take_receiver(s, e) {
        let _ = donation::deliver(s, t, v);
        s.transfer(t, v, Transfer::Fault { badge });
        return;
    }
    enqueue(s, e, t, Role::Fault, 0, badge, false);
}

/// The receive that follows the checks and donation's `recv`: `t` waits in
/// `Recv(r)`. A bound eventcount's advance comes first; then a queued
/// sender; otherwise `t` waits queued, and links its bound eventcount.
fn recv_rest<S: IpcStore>(s: &mut S, t: Tcb, e: Ep) -> Outcome {
    if eventcount::recv_report(s, t) {
        return Outcome::Done;
    }
    if let Some(x) = sender(s, e) {
        let rec = leave(s, x);
        deliver_queued(s, e, x, rec, t);
        return Outcome::Done;
    }
    enqueue(s, e, t, Role::Recv, 0, 0, false);
    eventcount::recv_link(s, t);
    Outcome::Blocked
}

/// `Recv(t, r)`: `t` receives on `cap`, which needs the read right, with
/// reply object `r`, which must be free. It gets its bound eventcount's
/// advance, a queued message, call or fault, or waits.
pub fn recv<S: IpcStore>(s: &mut S, t: Tcb, cap: EpCap, r: Reply) -> Result<Outcome, Status> {
    if !cap.rights.contains(Rights::READ) {
        return Err(Status::MissingRight);
    }
    donation::recv(s, t, r).map_err(status)?;
    Ok(recv_rest(s, t, cap.ep))
}

/// The caller `r` would answer, and whether it waits on a fault, whose
/// reply carries nothing.
fn answering<S: IpcStore>(s: &S, r: Reply) -> Option<(Tcb, bool)> {
    let c = s.reply(r).caller?;
    Some((c, s.thread(c).fault.is_some()))
}

/// `Reply(t, r)`: `t` replies on `r` with info word `info`; `grant` is the
/// reply capability's grant right. Only the thread that holds a donated
/// call's context answers it (donation's rule). A delivered fault's reply
/// carries nothing: the thread resumes.
pub fn reply<S: IpcStore>(
    s: &mut S,
    t: Tcb,
    r: Reply,
    info: u64,
    grant: bool,
) -> Result<(), Status> {
    Info::for_send(info)?;
    let to = answering(s, r);
    donation::reply(s, t, r).map_err(status)?;
    if let Some((c, false)) = to {
        s.transfer(t, c, Transfer::Reply { info, grant });
    }
    Ok(())
}

/// `ReplyRecv(t, r)`: a reply on `r`, then a receive on `cap` with `r`, as
/// a server's loop does. Everything is checked before the reply. A reply
/// with no caller doesn't stop the receive; "not the holder" and a reply
/// object in use refuse it, with nothing changed.
pub fn reply_recv<S: IpcStore>(
    s: &mut S,
    t: Tcb,
    cap: EpCap,
    r: Reply,
    info: u64,
    grant: bool,
) -> Result<Outcome, Status> {
    if !cap.rights.contains(Rights::READ) {
        return Err(Status::MissingRight);
    }
    Info::for_send(info)?;
    if donation::may_reply(s, t, r) == Err(Error::NotHolder) {
        return Err(Status::NotHolder);
    }
    if matches!(s.reply(r).state, RState::Recv) {
        return Err(Status::Busy);
    }
    let to = answering(s, r);
    match donation::reply_recv(s, t, r) {
        Ok(()) => {
            if let Some((c, false)) = to {
                s.transfer(t, c, Transfer::Reply { info, grant });
            }
        }
        Err(Error::NoCaller) => {}
        Err(e) => return Err(status(e)),
    }
    Ok(recv_rest(s, t, cap.ep))
}

/// `SetPrio`: `t`'s priority changed. If it is queued, it leaves both of
/// its trees and rejoins them as a new arrival (K25).
pub fn requeue<S: IpcStore>(s: &mut S, t: Tcb) {
    let rec = s.ipc(t);
    let Some(e) = rec.ep else {
        return;
    };
    leave(s, t);
    insert(s, e, t, rec);
}

// ---------------------------------------------------------------------------
// Canceling a badge's sends (ADR 0049, rule 5).

/// The checks of canceling the sends queued under `cap`'s badge: the
/// manager invokes it on the badged copy it is releasing, which needs all
/// four rights, as seL4's `cancelBadgedSends` needs (K23). An unbadged
/// capability is refused.
pub fn cancel_badged_check(cap: EpCap) -> Result<(), Status> {
    if !cap.rights.contains(Rights::ALL) {
        return Err(Status::MissingRight);
    }
    if cap.badge == 0 {
        return Err(Status::InvalidArgument);
    }
    Ok(())
}

/// The first sender queued on `e` under `badge`, or None: a lower-bound
/// search of the badge tree. O(log n).
fn first_badged<S: IpcStore>(s: &mut S, e: Ep, badge: u64) -> Option<Tcb> {
    let b = Badges(s);
    let mut n = b.0.ep(e).broot;
    let mut lb = NIL;
    while n != NIL {
        if b.key(n) >= (badge, 0, 0) {
            lb = n;
            n = b.links(n).left;
        } else {
            n = b.links(n).right;
        }
    }
    (lb != NIL && b.key(lb).0 == badge).then_some(Tcb(lb))
}

/// `CancelBadgedStep`, repeated: takes every sender queued on `e` under
/// `badge` out, one per unit of `budget`, first come first. A send or a
/// call ends with no result and restarts at its `SVC`, as in seL4, so it
/// makes its call again and finds its capability revoked. A queued fault is
/// withdrawn with no result, with its PC untouched, so the thread goes on
/// as its fault's kind allows: a faulting instruction is re-executed, and
/// faults again if its cause remains; after a timeout fault the thread goes
/// on where its budget ran out, once it has a refill; after a
/// context-withdrawn fault it stays without a context until something gives
/// it one (kernel specification, "Fault delivery"; K50). Its progress is the
/// badge tree itself, so a restart after [`Preempted`] finds the next.
pub fn cancel_badged<S: IpcStore, P: Pending>(
    s: &mut S,
    e: Ep,
    badge: u64,
    budget: &mut Budget<P>,
) -> Result<(), Preempted> {
    while let Some(x) = first_badged(s, e, badge) {
        let rec = leave(s, x);
        let _ = donation::wake(s, x, Res::None);
        if rec.role != Role::Fault {
            s.restart(x);
        }
        budget.tick(1)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Destruction (K30).

/// One step of an endpoint's queue zombie: releases its first queued
/// thread. A sender, a caller or a receiver ends "object destroyed",
/// undelivered. Returns true when none is left.
///
/// The `Role::Fault` branch is defensive, and the kernel never reaches it:
/// a fault is queued only through the faulting thread's own copy of the
/// endpoint, in its slot 3 or 4, which is itself a capability to it, so the
/// endpoint can't become a zombie while the copy exists; and deleting the
/// copy runs its unbind step first, which withdraws the fault with K50's
/// outcome. Should one be found, it is withdrawn with no result.
pub fn drain<S: IpcStore>(s: &mut S, e: Ep) -> bool {
    let Some(x) = head(s, e) else {
        return true;
    };
    let rec = leave(s, x);
    if rec.role == Role::Recv {
        eventcount::unlink_waits(s, x);
    }
    let res = if rec.role == Role::Fault {
        Res::None
    } else {
        Res::Destroyed
    };
    let _ = donation::wake(s, x, res);
    head(s, e).is_none()
}

/// `e` is finished: its queue is empty.
pub fn finish<S: IpcStore>(s: &mut S, e: Ep) {
    s.set_ep(e, EpRec::default());
}

// ---------------------------------------------------------------------------
// Invariants, for the host tests and the kernel's test builds.

/// The invariant that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    /// A queue or badge tree is malformed.
    Tree,
    /// A queued thread's record names another endpoint, or its role
    /// disagrees with its donation state or the queue's kind.
    Queued,
    /// A sender is in one of its endpoint's trees but not the other.
    Badges,
    /// A thread waits on an endpoint but isn't queued, or is queued but
    /// doesn't wait.
    Waiting,
}

/// Checks the endpoint invariants over the objects given. O(n log n): for
/// tests.
pub fn check<S: IpcStore>(s: &mut S, eps: &[Ep], threads: &[Tcb]) -> Result<(), Violation> {
    for &e in eps {
        let ep = s.ep(e);
        let Ok(nq) = tree::check(&Queue(s), ep.root, usize::MAX) else {
            return Err(Violation::Tree);
        };
        let Ok(nb) = tree::check(&Badges(s), ep.broot, usize::MAX) else {
            return Err(Violation::Tree);
        };
        let mut senders = 0;
        let mut n = tree::first(&Queue(s), ep.root);
        while n != NIL {
            let rec = s.ipc(Tcb(n));
            let st = s.thread(Tcb(n)).state;
            let ok = rec.ep == Some(e)
                && (rec.role == Role::Recv) == ep.recv
                && match rec.role {
                    Role::Recv => matches!(st, TState::Recv(_)),
                    Role::Send | Role::Call => st == TState::Send,
                    Role::Fault => matches!(st, TState::Fault(_)),
                };
            if !ok {
                return Err(Violation::Queued);
            }
            if rec.role != Role::Recv {
                senders += 1;
            }
            n = tree::next(&Queue(s), n);
        }
        if senders != nb || (ep.recv && nb != 0) || nq < nb {
            return Err(Violation::Badges);
        }
    }
    for &t in threads {
        let queued = s.ipc(t).ep.is_some();
        let waits = matches!(
            s.thread(t).state,
            TState::Send | TState::Fault(_) | TState::Recv(_)
        );
        if queued != waits {
            return Err(Violation::Waiting);
        }
    }
    Ok(())
}
