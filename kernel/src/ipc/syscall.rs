// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The IPC system calls, decoded (kernel specification K28): the surface
//! the test trap calls now (`crate::testing::trap`), and C17's entry table
//! later, with the same decoded arguments.
//!
//! Capabilities are named by their address in the calling thread's
//! capability space, from its root CNode in slot 1, as C17's calls name
//! them. A name that doesn't resolve refuses the call with
//! "invalid capability"; a capability of another kind, "wrong kind".
//!
//! The registers are K28's ([`kipc::msg::regs`]): x0 the capability, x1
//! the info word, x2 to x5 the message's first four words, x6 the reply
//! object, x7 the deadline. The eventcount and wait-set calls keep x0 for
//! the capability and x7 for the deadline, and take their other arguments
//! in x1 to x3; a count or a mask comes back in x1. Each function writes x0 when the call returns
//! at once; a call that blocks gets its status when its wait ends. A call
//! with a long part ([`cancel_badged_sends`], [`set_ipc_buffer`],
//! [`ws_remove`], [`unbind_eventcount`]) returns
//! [`Preempted`] at a preemption point, having made progress, and is made
//! again from its `SVC` (`crate::sched::entry::restart`), finding the
//! progress it recorded in its objects.

use super::buffer;
use super::endpoint::{self, Ret, set_status};
use super::eventcount::{self, ec_cap};
use super::waitset::{self, ws_cap};
use crate::cap::DirectSlots;
use crate::sched::object::Tcb;
use kcap::SlotRef;
use kcap::cap::Cap;
use kcap::preempt::{Budget, Pending, Preempted};
use kcap::rights::Rights;
use kipc::msg::{Status, regs};

/// The decoded arguments of an endpoint call (module docs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Args {
    /// The endpoint capability's address.
    pub cap: u64,
    /// The info word.
    pub info: u64,
    /// The reply object capability's address.
    pub reply: u64,
    /// The deadline, a value of the virtual count, 0 for none.
    pub deadline: u64,
}

impl Args {
    /// The arguments in `t`'s saved registers.
    pub fn of(t: Tcb) -> Args {
        t.with(|b| Args {
            cap: b.ctx.x[regs::CAP],
            info: b.ctx.x[regs::INFO],
            reply: b.ctx.x[regs::REPLY],
            deadline: b.ctx.x[regs::DEADLINE],
        })
    }
}

/// The capability at `addr` in `t`'s capability space, with its slot.
pub fn lookup(t: Tcb, addr: u64) -> Result<(SlotRef, Cap), Status> {
    kcap::lookup::lookup_cap(&DirectSlots, t.slot_cap(1), addr)
        .map_err(|_| Status::InvalidCapability)
}

/// Refuses a call with a long part, with status `s`.
fn refuse(t: Tcb, s: Status) -> Result<(), Preempted> {
    set_status(t, s);
    Ok(())
}

/// Runs `f`, refusing the call with its status if it fails.
fn refusing(t: Tcb, f: impl FnOnce() -> Ret) -> Ret {
    let r = f();
    if let Err(s) = r {
        set_status(t, s);
    }
    r
}

/// Send (`block`) or send without blocking.
pub fn send(t: Tcb, a: &Args, block: bool) -> Ret {
    refusing(t, || {
        let cap = endpoint::ep_cap(&lookup(t, a.cap)?.1)?;
        endpoint::send(t, cap, a.info, block, a.deadline)
    })
}

/// Call.
pub fn call(t: Tcb, a: &Args) -> Ret {
    refusing(t, || {
        let cap = endpoint::ep_cap(&lookup(t, a.cap)?.1)?;
        endpoint::call(t, cap, a.info, a.deadline)
    })
}

/// Receive, with the reply object at `a.reply`.
pub fn recv(t: Tcb, a: &Args) -> Ret {
    refusing(t, || {
        let cap = endpoint::ep_cap(&lookup(t, a.cap)?.1)?;
        let (r, _) = endpoint::reply_cap(&lookup(t, a.reply)?.1)?;
        endpoint::recv(t, cap, r, a.deadline)
    })
}

/// Reply on the reply object at `a.reply`.
pub fn reply(t: Tcb, a: &Args) -> Result<(), Status> {
    let r = lookup(t, a.reply).and_then(|(_, c)| endpoint::reply_cap(&c));
    match r {
        Ok((r, grant)) => endpoint::reply(t, r, grant, a.info),
        Err(s) => {
            set_status(t, s);
            Err(s)
        }
    }
}

/// Reply and receive. The lookups come before the reply, as every other
/// check does.
pub fn reply_recv(t: Tcb, a: &Args) -> Ret {
    refusing(t, || {
        let cap = endpoint::ep_cap(&lookup(t, a.cap)?.1)?;
        let (r, grant) = endpoint::reply_cap(&lookup(t, a.reply)?.1)?;
        endpoint::reply_recv(t, cap, r, grant, a.info, a.deadline)
    })
}

/// Cancels the sends queued under the badge of the endpoint capability at
/// `a.cap`, the badged copy being released (ADR 0049, rule 5).
pub fn cancel_badged_sends<P: Pending>(
    t: Tcb,
    a: &Args,
    budget: &mut Budget<P>,
) -> Result<(), Preempted> {
    let cap = match lookup(t, a.cap).and_then(|(_, c)| endpoint::ep_cap(&c)) {
        Ok(c) => c,
        Err(s) => return refuse(t, s),
    };
    let s = endpoint::cancel_badged(cap, budget)?;
    set_status(t, s.err().unwrap_or(Status::Ok));
    Ok(())
}

/// Registers the page at `va` of the thread at `thread` as its IPC buffer,
/// backed by the frame at `frame`; `va` 0 unregisters it (K29). The thread
/// capability needs the write right.
pub fn set_ipc_buffer<P: Pending>(
    t: Tcb,
    thread: u64,
    frame: u64,
    va: u64,
    budget: &mut Budget<P>,
) -> Result<(), Preempted> {
    let target = match written_thread(t, thread) {
        Ok(x) => x,
        Err(s) => return refuse(t, s),
    };
    let slot = if va == 0 {
        None
    } else {
        match lookup(t, frame) {
            Ok((s, _)) => Some(s),
            Err(s) => return refuse(t, s),
        }
    };
    let s = buffer::set(target, slot, va, budget)?;
    set_status(t, s.err().unwrap_or(Status::Ok));
    Ok(())
}

// ---------------------------------------------------------------------------
// Eventcounts and wait sets (ADR 0053).

/// Advances the eventcount at `cap`; the count goes into x1. Its wakes
/// past a preemption point go to the work list, so it is never made again
/// (K31).
pub fn ec_advance<P: Pending>(t: Tcb, cap: u64, budget: &mut Budget<P>) {
    match lookup(t, cap).and_then(|(_, c)| ec_cap(&c)) {
        Ok((e, rights)) => {
            let _ = eventcount::advance(t, e, rights, budget);
        }
        Err(s) => set_status(t, s),
    }
}

/// Reads the eventcount at `cap` into x1.
pub fn ec_read(t: Tcb, cap: u64) {
    match lookup(t, cap).and_then(|(_, c)| ec_cap(&c)) {
        Ok((e, rights)) => {
            let _ = eventcount::read(t, e, rights);
        }
        Err(s) => set_status(t, s),
    }
}

/// Waits until the eventcount at `cap` reaches `target`, or `deadline`; the
/// count goes into x1.
pub fn ec_wait(t: Tcb, cap: u64, target: u64, deadline: u64) -> Ret {
    refusing(t, || {
        let (e, rights) = ec_cap(&lookup(t, cap)?.1)?;
        eventcount::wait(t, e, rights, target, deadline)
    })
}

/// Entry `i` of the wait set at `ws` waits for the eventcount at `ec` to
/// reach `target`.
pub fn ws_add(t: Tcb, ws: u64, i: u64, ec: u64, target: u64) {
    let r = (|| {
        let (w, rights) = ws_cap(&lookup(t, ws)?.1)?;
        let (src, _) = lookup(t, ec)?;
        waitset::add(w, rights, i, src, target)
    })();
    set_status(t, r.err().unwrap_or(Status::Ok));
}

/// Removes entry `i` of the wait set at `ws`, deleting its copy under
/// `budget`.
pub fn ws_remove<P: Pending>(
    t: Tcb,
    ws: u64,
    i: u64,
    budget: &mut Budget<P>,
) -> Result<(), Preempted> {
    let (w, rights) = match lookup(t, ws).and_then(|(_, c)| ws_cap(&c)) {
        Ok(x) => x,
        Err(s) => return refuse(t, s),
    };
    let s = waitset::remove(w, rights, i, budget)?;
    set_status(t, s.err().unwrap_or(Status::Ok));
    Ok(())
}

/// Waits on the wait set at `ws`, or until `deadline`; the mask goes into
/// x1.
pub fn ws_wait(t: Tcb, ws: u64, deadline: u64) -> Ret {
    refusing(t, || {
        let (w, rights) = ws_cap(&lookup(t, ws)?.1)?;
        waitset::wait(t, w, rights, deadline)
    })
}

/// The thread a thread capability at `thread` names, with the write right.
fn written_thread(t: Tcb, thread: u64) -> Result<Tcb, Status> {
    match lookup(t, thread)? {
        (_, Cap::Thread { ptr, rights }) if rights.contains(Rights::WRITE) => Ok(Tcb(ptr)),
        (_, Cap::Thread { .. }) => Err(Status::MissingRight),
        _ => Err(Status::WrongKind),
    }
}

/// Cancels the wait of the thread at `thread` (ADR 0054, rule 6; kernel
/// specification, "IPC deadlines and cancellation"). The thread capability
/// needs the write right. Canceling the caller's own caller only takes the
/// caller's context away: it is still ready, and sees the status when it
/// next runs.
pub fn cancel(t: Tcb, thread: u64) {
    let r = written_thread(t, thread).and_then(|target| {
        crate::sched::donation::cancel(target).map_err(|_| Status::InvalidArgument)
    });
    set_status(t, r.err().unwrap_or(Status::Ok));
}

/// Binds the eventcount at `ec` to the thread at `thread` (ADR 0053, rule
/// 5). The thread capability needs the write right.
pub fn bind_eventcount(t: Tcb, thread: u64, ec: u64) {
    let r = written_thread(t, thread).and_then(|target| {
        let (src, _) = lookup(t, ec)?;
        eventcount::bind(target, src)
    });
    set_status(t, r.err().unwrap_or(Status::Ok));
}

/// Unbinds the thread at `thread`'s eventcount, deleting its copy under
/// `budget`.
pub fn unbind_eventcount<P: Pending>(
    t: Tcb,
    thread: u64,
    budget: &mut Budget<P>,
) -> Result<(), Preempted> {
    let target = match written_thread(t, thread) {
        Ok(x) => x,
        Err(s) => return refuse(t, s),
    };
    eventcount::unbind(target, budget)?;
    set_status(t, Status::Ok);
    Ok(())
}
