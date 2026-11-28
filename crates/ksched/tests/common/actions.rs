// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Random donation runs: the actions the TLA+ spec enables in a state,
//! with the spec's preconditions, picked at random and applied through
//! ksched::donation.

use super::Lcg;
use super::store::{Host, c, project, r, t};
use ksched::donation::{self, RState, Res, TState};

/// One of the spec's actions, with its parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Recv(usize, usize),
    Call(usize, usize),
    Reply(usize, usize),
    ReplyRecv(usize, usize),
    Cancel(usize),
    Deadline(usize),
    Wait(usize),
    BudgetOut(usize),
    FaultReplied(usize),
    Suspend(usize),
    Resume(usize),
    SetTep(usize, bool),
    BindSc(usize, usize),
    UnbindSc(usize),
    WalkStep(usize),
    DestroyThread(usize),
    DestroyReply(usize),
    DestroySc(usize),
    // C14's, with endpoint queues (`Flags::queue`).
    SendWait(usize),
    FaultWait(usize),
    DeliverCall(usize, usize),
    DeliverSend(usize, usize),
    Wake(usize, Res),
}

/// The results a wake may carry: the spec's `WakeResults`.
pub const WAKE_RESULTS: [Res; 3] = [Res::Replied, Res::Destroyed, Res::None];

/// The spec's constants that switch actions on.
#[derive(Clone, Copy, Debug)]
pub struct Flags {
    pub destroy: bool,
    pub set_tep: bool,
    pub suspend: bool,
    /// The refinement model: no interference with pending walks.
    pub refine: bool,
    /// Whether walk steps are among the choices (false: drained at once).
    pub walks: bool,
    /// The spec's `WithQueue`: queued sends and faults, their delivery and
    /// wakes (C14). Without it, a fault is replied to in one step.
    pub queue: bool,
}

/// The spec's `ReplyApplies`.
fn reply_applies(h: &Host, ti: usize, ri: usize) -> bool {
    let rec = h.replies[ri];
    match (rec.state, rec.sc) {
        (RState::Pending, Some(sc)) => {
            let cr = h.scs[sc.0 as usize];
            cr.holder == Some(t(ti)) && cr.top == Some(r(ri))
        }
        (RState::Pending, None) => true,
        (RState::Invalid, _) => true,
        _ => false,
    }
}

/// The spec's `OnWalk(t)` and `ReplyOnWalk(r)`, from the projection.
fn on_walk(h: &mut Host) -> (Vec<bool>, Vec<bool>) {
    let a = project(h);
    let mut th = vec![false; h.nt() + 1];
    let mut rp = vec![false; h.nr() + 1];
    for w in &a.walks {
        for &q in w {
            rp[q] = true;
            th[a.rserver[q - 1]] = true;
            th[a.rcaller[q - 1]] = true;
        }
    }
    th[0] = false;
    (th, rp)
}

/// Every action enabled in `h`.
pub fn enabled(h: &mut Host, f: Flags) -> Vec<Op> {
    let (nt, nr, ns) = (h.nt(), h.nr(), h.ns());
    let (tw, rw) = if f.refine {
        on_walk(h)
    } else {
        (vec![false; nt + 1], vec![false; nr + 1])
    };
    let mut ops = vec![];
    for ti in 1..=nt {
        let tr = h.threads[ti];
        let alive = h.talive[ti];
        let runs = h.runs(ti);
        for ri in 1..=nr {
            if !h.ralive[ri] || !runs {
                continue;
            }
            let free = matches!(h.replies[ri].state, RState::Idle | RState::Invalid);
            if free {
                ops.push(Op::Recv(ti, ri));
            }
            if reply_applies(h, ti, ri) {
                ops.push(Op::Reply(ti, ri));
            }
            if free || reply_applies(h, ti, ri) {
                ops.push(Op::ReplyRecv(ti, ri));
            }
        }
        if runs {
            for vi in 1..=nt {
                if vi != ti && h.talive[vi] && matches!(h.threads[vi].state, TState::Recv(_)) {
                    ops.push(Op::Call(ti, vi));
                }
            }
            ops.push(Op::Wait(ti));
            if tr.tep {
                ops.push(Op::BudgetOut(ti));
            }
            if f.queue {
                ops.push(Op::SendWait(ti));
                ops.push(Op::FaultWait(ti));
            }
        }
        if !alive {
            continue;
        }
        let free = !tw[ti];
        if tr.state != TState::Ready && free {
            ops.push(Op::Cancel(ti));
        }
        if matches!(
            tr.state,
            TState::Call(_) | TState::Recv(_) | TState::Other | TState::Send
        ) && tr.fault.is_none()
            && free
        {
            ops.push(Op::Deadline(ti));
        }
        if matches!(tr.state, TState::Fault(_)) && !f.queue {
            ops.push(Op::FaultReplied(ti));
        }
        if f.queue && free {
            let queued = matches!(tr.state, TState::Send | TState::Fault(_));
            for vi in 1..=nt {
                let receiving = vi != ti
                    && h.talive[vi]
                    && !tw[vi]
                    && matches!(h.threads[vi].state, TState::Recv(_));
                if queued && receiving {
                    ops.push(Op::DeliverCall(ti, vi));
                }
                if tr.state == TState::Send && receiving {
                    ops.push(Op::DeliverSend(ti, vi));
                }
            }
            if matches!(
                tr.state,
                TState::Other | TState::Send | TState::Fault(_) | TState::Recv(_)
            ) {
                for x in WAKE_RESULTS {
                    ops.push(Op::Wake(ti, x));
                }
            }
        }
        if f.suspend {
            ops.push(if tr.suspended {
                Op::Resume(ti)
            } else {
                Op::Suspend(ti)
            });
        }
        if f.set_tep && free {
            ops.push(Op::SetTep(ti, !tr.tep));
        }
        if f.destroy && free {
            ops.push(Op::DestroyThread(ti));
        }
        for ci in 1..=ns {
            let cr = h.scs[ci];
            if h.scalive[ci]
                && cr.home.is_none()
                && cr.holder.is_none()
                && tr.home.is_none()
                && tr.sc.is_none()
                && tr.serving.is_none()
            {
                ops.push(Op::BindSc(ci, ti));
            }
        }
    }
    for ci in 1..=ns {
        if h.scalive[ci] && h.scs[ci].home.is_some() {
            ops.push(Op::UnbindSc(ci));
        }
        if f.destroy && h.scalive[ci] {
            ops.push(Op::DestroySc(ci));
        }
    }
    if f.destroy {
        for ri in 1..=nr {
            if h.ralive[ri] && !rw[ri] {
                ops.push(Op::DestroyReply(ri));
            }
        }
    }
    if f.walks {
        for q in h.work.clone() {
            ops.push(Op::WalkStep(q.0 as usize));
        }
    }
    ops
}

/// Applies `op`.
pub fn apply(h: &mut Host, op: Op) {
    match op {
        Op::Recv(a, b) => drop(donation::recv(h, t(a), r(b))),
        Op::Call(a, b) => drop(donation::call(h, t(a), t(b))),
        Op::Reply(a, b) => drop(donation::reply(h, t(a), r(b))),
        Op::ReplyRecv(a, b) => drop(donation::reply_recv(h, t(a), r(b))),
        Op::Cancel(a) => drop(donation::cancel(h, t(a))),
        Op::Deadline(a) => drop(donation::deadline(h, t(a))),
        Op::Wait(a) => donation::wait_other(h, t(a)),
        Op::BudgetOut(a) => drop(donation::budget_out(h, t(a))),
        Op::FaultReplied(a) => drop(donation::fault_replied(h, t(a))),
        Op::Suspend(a) => donation::set_suspended(h, t(a), true),
        Op::Resume(a) => donation::set_suspended(h, t(a), false),
        Op::SetTep(a, b) => donation::set_tep(h, t(a), b),
        Op::BindSc(a, b) => drop(donation::bind_sc(h, c(a), t(b))),
        Op::UnbindSc(a) => drop(donation::unbind_sc(h, c(a))),
        Op::WalkStep(q) => drop(donation::walk_step(h, r(q))),
        Op::DestroyThread(a) => h.destroy_thread(a),
        Op::DestroyReply(a) => h.destroy_reply(a),
        Op::DestroySc(a) => h.destroy_sc(a),
        Op::SendWait(a) => donation::send_wait(h, t(a)),
        Op::FaultWait(a) => donation::fault_wait(h, t(a)),
        Op::DeliverCall(a, b) => drop(donation::deliver(h, t(a), t(b))),
        Op::DeliverSend(a, b) => drop(donation::deliver_send(h, t(a), t(b))),
        Op::Wake(a, x) => drop(donation::wake(h, t(a), x)),
    }
}

/// Picks an enabled action at random. Calls are favored so chains grow,
/// and destruction is rare so runs last.
pub fn pick(h: &mut Host, rng: &mut Lcg, f: Flags) -> Option<Op> {
    let mut ops = enabled(h, f);
    let destroys = |o: &Op| {
        matches!(
            o,
            Op::DestroyThread(_) | Op::DestroyReply(_) | Op::DestroySc(_)
        )
    };
    if !rng.chance(4) && ops.iter().any(|o| !destroys(o)) {
        ops.retain(|o| !destroys(o));
    }
    if ops.is_empty() {
        return None;
    }
    let calls: Vec<Op> = ops
        .iter()
        .copied()
        .filter(|o| matches!(o, Op::Call(..) | Op::DeliverCall(..)))
        .collect();

    if !calls.is_empty() && rng.chance(35) {
        return Some(calls[rng.below(calls.len() as u64) as usize]);
    }
    Some(ops[rng.below(ops.len() as u64) as usize])
}
