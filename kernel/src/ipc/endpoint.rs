// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Endpoint operations on the kernel's objects (ADR 0054; kernel
//! specification, "Endpoint operations and messages" and "IPC deadlines and
//! cancellation"): `kipc::endpoint`'s protocol, the one implementation,
//! which `specs/IpcEndpoint.tla` models, run over [`KStore`].
//!
//! Each operation here takes its capabilities already looked up, and its
//! thread, which runs, or in a test stays suspended while the test drives
//! it. It writes the thread's x0 itself when the operation returns at once,
//! with "ok" or the error that refused it; a wait's end writes it otherwise
//! (`crate::sched::donation`). [`super::syscall`] looks the capabilities up
//! from the caller's addresses.
//!
//! **Deadlines** (ADR 0064, rule 5; K19). An operation that blocks gets its
//! deadline, a value of the virtual count, or none for 0. A deadline that
//! has already passed times out only an operation that would block: a call
//! always would, so it is refused "timed out" before anything is delivered;
//! a send or a receive that finds its partner waiting completes, and one
//! that blocks times out at once, leaving its queue.

use crate::sched::donation::{self, KStore};
use crate::sched::object::Tcb;
use crate::sched::run;
use kcap::cap::Cap;
use kcap::preempt::{Budget, Pending, Preempted};
use kcap::rights::Rights;
use kipc::endpoint::{self as ep, EpCap};
use kipc::msg::{Status, regs};
use kipc::{Ep, Outcome};
use ksched::donation::{Reply, Tcb as DTcb};

/// What an operation did: it returned at once, it blocked, or it was
/// refused with a status, nothing changed.
pub type Ret = Result<Outcome, Status>;

fn d(t: Tcb) -> DTcb {
    DTcb(t.0)
}

/// The endpoint a capability names, with its badge and rights.
pub fn ep_cap(c: &Cap) -> Result<EpCap, Status> {
    match *c {
        Cap::Endpoint {
            ptr, rights, badge, ..
        } => Ok(EpCap {
            ep: Ep(ptr),
            badge,
            rights,
        }),
        Cap::Null => Err(Status::InvalidCapability),
        _ => Err(Status::WrongKind),
    }
}

/// The reply object a capability names, and whether it has the grant
/// right, so the reply may carry capabilities (ADR 0049, rule 6).
pub fn reply_cap(c: &Cap) -> Result<(Reply, bool), Status> {
    match *c {
        Cap::Reply { ptr, rights } => Ok((Reply(ptr), rights.contains(Rights::GRANT))),
        Cap::Null => Err(Status::InvalidCapability),
        _ => Err(Status::WrongKind),
    }
}

/// Writes x0: the status of an operation that returns at once.
pub fn set_status(t: Tcb, s: Status) {
    t.with(|b| b.ctx.x[regs::STATUS] = s.word(false));
}

/// Whether `deadline` has passed: 0 is none.
fn passed(deadline: u64) -> bool {
    deadline != 0 && deadline <= crate::timer::now()
}

/// Ends an operation (module docs): a refusal or a return writes x0; a
/// wait gets its deadline, or times out at once if it has passed.
pub(super) fn conclude(t: Tcb, r: Ret, deadline: u64) -> Ret {
    match r {
        Err(s) => set_status(t, s),
        Ok(Outcome::Done) => set_status(t, Status::Ok),
        Ok(Outcome::Blocked) if deadline == 0 => {}
        Ok(Outcome::Blocked) if passed(deadline) => {
            let _ = donation::deadline(t);
        }
        Ok(Outcome::Blocked) => run::deadline_insert(t, deadline),
    }
    r
}

/// Send, and send without blocking (`block` false), with the info word in
/// x1 and the words in x2 to x5 (ADR 0054, rule 2).
pub fn send(t: Tcb, cap: EpCap, info: u64, block: bool, deadline: u64) -> Ret {
    let r = ep::send(&mut KStore::begin(), d(t), cap, info, block);
    conclude(t, r, if block { deadline } else { 0 })
}

/// Call: the caller blocks until the reply, a cancel, its deadline or a
/// destruction ends it.
pub fn call(t: Tcb, cap: EpCap, info: u64, deadline: u64) -> Ret {
    // A call always blocks, so a passed deadline times it out before it is
    // delivered; a refused call reports its error first (K19).
    let mut store = KStore::begin();
    if let Err(s) = ep::call_check(&store, d(t), cap, info) {
        return conclude(t, Err(s), 0);
    }
    if passed(deadline) {
        return conclude(t, Err(Status::TimedOut), 0);
    }
    let r = ep::call(&mut store, d(t), cap, info);
    conclude(t, r, deadline)
}

/// Receive with reply object `reply`, which must be free.
pub fn recv(t: Tcb, cap: EpCap, reply: Reply, deadline: u64) -> Ret {
    let r = ep::recv(&mut KStore::begin(), d(t), cap, reply);
    conclude(t, r, deadline)
}

/// Reply on `reply`, with the reply capability's grant right, the info word
/// in x1 and the words in x2 to x5. Only the thread that holds a donated
/// call's context answers it.
pub fn reply(t: Tcb, reply: Reply, grant: bool, info: u64) -> Result<(), Status> {
    let r = ep::reply(&mut KStore::begin(), d(t), reply, info, grant);
    set_status(t, r.err().unwrap_or(Status::Ok));
    r
}

/// Reply and receive: everything is checked before the reply; a reply with
/// no caller doesn't stop the receive.
pub fn reply_recv(t: Tcb, cap: EpCap, reply: Reply, grant: bool, info: u64, deadline: u64) -> Ret {
    let r = ep::reply_recv(&mut KStore::begin(), d(t), cap, reply, info, grant);
    conclude(t, r, deadline)
}

/// Cancels the sends queued under the badge of `cap`, the badged copy being
/// released, which needs all four rights (ADR 0049, rule 5; K23). One
/// sender per unit of `budget`; a preempted call is made again, and finds
/// the next in the badge tree. A canceled send restarts at its `SVC`; a
/// queued fault is withdrawn with no result, and the thread goes on as its
/// fault's kind allows (kernel specification, "Fault delivery").
pub fn cancel_badged<P: Pending>(
    cap: EpCap,
    budget: &mut Budget<P>,
) -> Result<Result<(), Status>, Preempted> {
    if let Err(e) = ep::cancel_badged_check(cap) {
        return Ok(Err(e));
    }
    ep::cancel_badged(&mut KStore::begin(), cap.ep, cap.badge, budget)?;
    Ok(Ok(()))
}

/// `t`'s priority changed: if it is queued on an endpoint, it rejoins its
/// trees as a new arrival (K25).
pub fn requeue(t: Tcb) {
    ep::requeue(&mut KStore, d(t));
}

/// One step of an endpoint's queue zombie: releases its first queued thread
/// (K30). True when none is left.
pub fn drain(e: u64) -> bool {
    ep::drain(&mut KStore::begin(), Ep(e))
}

/// The endpoint at `e` is finished: its queue is empty.
pub fn finish(e: u64) {
    ep::finish(&mut KStore, Ep(e));
}

/// The threads queued on the endpoint at `e`, in the order they are
/// served, into `out`; returns how many there are (test builds).
#[cfg(aspis_test_build)]
pub fn queued(e: u64, out: &mut [Tcb]) -> usize {
    let mut ts = [DTcb(0); 512];
    let n = ep::queued(&mut KStore, Ep(e), &mut ts);
    for (o, t) in out.iter_mut().zip(&ts[..n.min(512)]) {
        *o = Tcb(t.0);
    }
    n
}

/// Checks the endpoint invariants over the objects given (test builds).
#[cfg(aspis_test_build)]
pub fn check(eps: &[u64], threads: &[Tcb]) -> Result<(), ep::Violation> {
    const MAX: usize = 512;
    assert!(eps.len() <= MAX && threads.len() <= MAX);
    let mut es = [Ep(0); MAX];
    let mut ts = [DTcb(0); MAX];
    for (i, &e) in eps.iter().enumerate() {
        es[i] = Ep(e);
    }
    for (i, &t) in threads.iter().enumerate() {
        ts[i] = d(t);
    }
    ep::check(&mut KStore, &es[..eps.len()], &ts[..threads.len()])
}
