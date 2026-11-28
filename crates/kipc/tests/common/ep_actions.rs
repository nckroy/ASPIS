// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The actions of `specs/IpcEndpoint.tla`, with its preconditions, applied
//! through kipc's endpoint module; and the projection of a store onto the
//! spec's state record.
//!
//! The universe is one endpoint, `nt` threads each running on its own
//! context, `nr` reply objects, and badges: thread t's capability carries
//! badge `1 + (t - 1) % nb`.

use super::store::{Host, Shape, badged, cap, ep, r, t};
use super::{Lcg, tla_bool, tla_str, tup};
use kcap::preempt::{Always, Budget};
use kipc::Rights;
use kipc::endpoint;
use kipc::msg::Info;
use kipc::store::Role;
use ksched::donation::{self, RState, Res, TState};
use std::collections::BTreeSet;

/// One of the spec's actions, with its parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Send(usize),
    NBSend(usize),
    Call(usize),
    Fault(usize),
    Recv(usize, usize),
    Reply(usize, usize),
    ReplyRecv(usize, usize),
    Cancel(usize),
    Deadline(usize),
    SetPrio(usize, u8),
    RevokeBadge(u64),
    CancelBadged(u64),
    DestroyEp,
    DrainStep,
    DestroyReply(usize),
}

/// The spec's constants.
#[derive(Clone, Debug)]
pub struct Consts {
    pub nt: usize,
    pub nr: usize,
    pub prios: Vec<u8>,
    pub nb: u64,
    pub with_prio: bool,
    pub with_badge: bool,
    pub with_destroy: bool,
}

/// A store and the spec's state that the capability layer keeps: whether
/// the endpoint is live, the released badges, the reply objects alive.
pub struct World {
    pub h: Host,
    pub k: Consts,
    pub ep: &'static str,
    pub revoked: BTreeSet<u64>,
    pub ralive: Vec<bool>,
    /// Messages sent, for labels.
    pub sent: u64,
}

impl World {
    /// The spec's `InitState`.
    pub fn init(k: Consts) -> World {
        let mut h = Host::new(Shape {
            threads: k.nt,
            replies: k.nr,
            eps: 1,
            ecs: 0,
            sets: 0,
            entries: 0,
        });
        let low = *k.prios.iter().min().expect("priorities");
        for p in h.prio.iter_mut() {
            *p = low;
        }
        World {
            h,
            ralive: vec![true; k.nr + 1],
            k,
            ep: "live",
            revoked: BTreeSet::new(),
            sent: 0,
        }
    }

    pub fn badge(&self, i: usize) -> u64 {
        1 + (i as u64 - 1) % self.k.nb
    }

    fn can_send(&self, i: usize) -> bool {
        self.ep == "live" && !self.revoked.contains(&self.badge(i))
    }

    /// Every action enabled now, or whose refusal changes nothing.
    pub fn enabled(&self) -> Vec<Op> {
        let mut ops = vec![];
        let live = self.ep == "live";
        for i in 1..=self.k.nt {
            let st = self.h.threads[i].state;
            if self.h.runs(i) {
                if self.can_send(i) {
                    ops.extend([Op::Send(i), Op::NBSend(i), Op::Call(i), Op::Fault(i)]);
                }
                for j in 1..=self.k.nr {
                    if !self.ralive[j] {
                        continue;
                    }
                    ops.push(Op::Reply(i, j));
                    if live {
                        ops.extend([Op::Recv(i, j), Op::ReplyRecv(i, j)]);
                    }
                }
            }
            if st != TState::Ready {
                ops.push(Op::Cancel(i));
            }
            let fault = matches!(st, TState::Fault(_)) || self.h.threads[i].fault.is_some();
            if st != TState::Ready && !fault {
                ops.push(Op::Deadline(i));
            }
            if self.k.with_prio {
                for &p in &self.k.prios {
                    if p != self.h.prio[i] {
                        ops.push(Op::SetPrio(i, p));
                    }
                }
            }
        }
        if self.k.with_badge {
            for b in 1..=self.k.nb {
                if self.revoked.contains(&b) {
                    if live {
                        ops.push(Op::CancelBadged(b));
                    }
                } else {
                    ops.push(Op::RevokeBadge(b));
                }
            }
        }
        if self.k.with_destroy {
            if live {
                ops.push(Op::DestroyEp);
            }
            for j in 1..=self.k.nr {
                if self.ralive[j] {
                    ops.push(Op::DestroyReply(j));
                }
            }
        }
        if self.ep == "draining" {
            ops.push(Op::DrainStep);
        }
        ops
    }

    fn info(&mut self) -> u64 {
        self.sent += 1;
        Info {
            label: self.sent,
            len: 8,
            caps: 0,
            unwrapped: 0,
            advance: false,
        }
        .encode()
    }

    /// Applies `op` through kipc and donation.
    pub fn apply(&mut self, op: Op) {
        let all = Rights::ALL;
        match op {
            Op::Send(i) | Op::NBSend(i) => {
                let info = self.info();
                let c = badged(1, self.badge(i), all);
                let block = matches!(op, Op::Send(_));
                endpoint::send(&mut self.h, t(i), c, info, block).expect("send");
            }
            Op::Call(i) => {
                let info = self.info();
                let c = badged(1, self.badge(i), all);
                endpoint::call(&mut self.h, t(i), c, info).expect("call");
            }
            Op::Fault(i) => {
                let b = self.badge(i);
                endpoint::fault(&mut self.h, t(i), ep(1), b);
            }
            Op::Recv(i, j) => {
                let _ = endpoint::recv(&mut self.h, t(i), cap(1), r(j));
            }
            Op::Reply(i, j) => {
                let info = self.info();
                let _ = endpoint::reply(&mut self.h, t(i), r(j), info, false);
            }
            Op::ReplyRecv(i, j) => {
                let info = self.info();
                let _ = endpoint::reply_recv(&mut self.h, t(i), cap(1), r(j), info, false);
            }
            Op::Cancel(i) => {
                let _ = donation::cancel(&mut self.h, t(i));
            }
            Op::Deadline(i) => {
                let _ = donation::deadline(&mut self.h, t(i));
            }
            Op::SetPrio(i, p) => {
                self.h.prio[i] = p;
                endpoint::requeue(&mut self.h, t(i));
            }
            Op::RevokeBadge(b) => {
                self.revoked.insert(b);
            }
            Op::CancelBadged(b) => {
                // One unit: every check finds an interrupt pending.
                let mut budget = Budget::with_threshold(Always, 1);
                let _ = endpoint::cancel_badged(&mut self.h, ep(1), b, &mut budget);
            }
            Op::DestroyEp => self.ep = "draining",
            Op::DrainStep => {
                if endpoint::drain(&mut self.h, ep(1)) {
                    endpoint::finish(&mut self.h, ep(1));
                    self.ep = "gone";
                }
            }
            Op::DestroyReply(j) => {
                donation::destroy_reply(&mut self.h, r(j));
                self.ralive[j] = false;
            }
        }
    }

    /// Picks an enabled action at random: deliveries and receives are
    /// favored, so queues fill and drain; destruction is rare, so runs
    /// last.
    pub fn pick(&self, rng: &mut Lcg) -> Option<Op> {
        let mut ops = self.enabled();
        let rare = |o: &Op| matches!(o, Op::DestroyEp | Op::DestroyReply(_) | Op::RevokeBadge(_));
        if !rng.chance(5) && ops.iter().any(|o| !rare(o)) {
            ops.retain(|o| !rare(o));
        }
        if ops.is_empty() {
            return None;
        }
        Some(ops[rng.below(ops.len() as u64) as usize])
    }

    /// The state as the spec's record.
    pub fn project(&mut self) -> String {
        let nt = self.k.nt;
        let nr = self.k.nr;
        let mut ts = vec![];
        let mut wr = vec![];
        let mut res = vec![];
        let mut flt = vec![];
        for i in 1..=nt {
            let tr = self.h.threads[i];
            let (s, w) = match tr.state {
                TState::Ready => ("ready", 0),
                TState::Recv(q) => ("recv", q.0 as usize),
                TState::Call(q) => ("call", q.0 as usize),
                TState::Send => match self.h.ipcs[i].role {
                    Role::Call => ("callq", 0),
                    _ => ("sendq", 0),
                },
                TState::Fault(_) => ("faultq", 0),
                TState::Other => ("other", 0),
            };
            ts.push(s);
            wr.push(w);
            res.push(res_name(tr.result));
            flt.push(tr.fault.is_some());
        }
        let mut rst = vec![];
        let mut rcaller = vec![];
        for j in 1..=nr {
            let rec = self.h.replies[j];
            rst.push(match rec.state {
                RState::Idle => "idle",
                RState::Recv => "recv",
                RState::Pending => "pending",
                RState::Invalid => "invalid",
            });
            rcaller.push(rec.caller.map_or(0, |x| x.0 as usize));
        }
        let q = self.h.queue(1);
        let num = |x: &usize| x.to_string();
        let prio: Vec<usize> = (1..=nt).map(|i| self.h.prio[i] as usize).collect();
        let revoked: Vec<String> = self.revoked.iter().map(|b| b.to_string()).collect();
        format!(
            "[ts |-> {}, prio |-> {}, q |-> {}, wr |-> {}, rst |-> {}, rcaller |-> {}, \
             res |-> {}, dbit |-> {}, flt |-> {}, rw |-> {}, ep |-> \"{}\", revoked |-> {{{}}}, \
             ralive |-> {}]",
            tup(&ts, tla_str),
            tup(&prio, num),
            tup(&q, num),
            tup(&wr, num),
            tup(&rst, tla_str),
            tup(&rcaller, num),
            tup(&res, tla_str),
            tup(&self.h.dbit[1..=nt], tla_bool),
            tup(&flt, tla_bool),
            tup(&self.h.rw[1..=nt], tla_bool),
            self.ep,
            revoked.join(", "),
            tup(&self.ralive[1..=nr], tla_bool),
        )
    }
}

/// A result as the specs name it.
pub fn res_name(x: Res) -> &'static str {
    match x {
        Res::None => "none",
        Res::Replied => "replied",
        Res::Canceled => "canceled",
        Res::TimedOut => "timedout",
        Res::Destroyed => "destroyed",
    }
}
