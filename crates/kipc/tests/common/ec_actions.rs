// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The actions of `specs/Eventcount.tla`, with its preconditions, applied
//! through kipc's eventcount and endpoint modules; and the projection of a
//! store onto the spec's state record.
//!
//! The universe is `nt` threads, each on its own context, `ne`
//! eventcounts, `nw` wait sets of `ni` entries, and, for bound receives,
//! one endpoint and a hidden thread, `nt + 1`, that sends to it without
//! blocking. Thread t receives with reply object t. The counts start at
//! `u64::MAX - max`, so the spec's `Max` is the count's real maximum; the
//! projection subtracts that base from counts, targets and last-seen
//! values.

use super::store::{Host, Shape, c, cap, ec, r, t, ws};
use super::{Chance, Lcg, tla_bool, tla_str, tup};
use kcap::preempt::Budget;
use kipc::Rights;
use kipc::store::Value;
use kipc::{endpoint, eventcount};
use ksched::donation::{self, TState};

/// One of the spec's actions, with its parameters. Entries are numbered
/// from 1, as in the spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Wait(usize, usize, u64),
    Advance(usize),
    IrqAdvance(usize),
    BatchUnit(usize),
    WsAdd(usize, usize, usize, u64),
    WsRemove(usize, usize),
    WsWait(usize, usize),
    DestroyWs(usize),
    Bind(usize, usize),
    Unbind(usize),
    Recv(usize),
    PassiveRecv(usize),
    MsgArrive,
    LoseCtx(usize),
    GainCtx(usize),
    Cancel(usize),
    Deadline(usize),
    DestroyEc(usize),
    DrainStep(usize),
}

/// The spec's constants.
#[derive(Clone, Copy, Debug)]
pub struct Consts {
    pub nt: usize,
    pub ne: usize,
    pub nw: usize,
    pub ni: usize,
    pub max: u64,
    pub with_sets: bool,
    pub with_bound: bool,
    pub with_destroy: bool,
    /// Where waits and wait-set entries draw their targets: `None` for
    /// every target 1..=max; `Some(w)` for the eventcount's count up to `w`
    /// past it, within 1..=max, so waiters gather just ahead of the count
    /// and an advance reaches several at once, however far the count is
    /// from its maximum.
    pub window: Option<u64>,
}

pub struct World {
    pub h: Host,
    pub k: Consts,
    pub base: u64,
    pub ecst: Vec<&'static str>,
    /// A finished eventcount's record is clear; the spec keeps its count.
    pub final_count: Vec<u64>,
    pub wsalive: Vec<bool>,
    /// The advance's preemption points.
    pub rng: Lcg,
}

impl World {
    /// The spec's `InitState`.
    pub fn init(k: Consts, seed: u64) -> World {
        let mut h = Host::new(Shape {
            threads: k.nt + 1,
            replies: k.nt + 1,
            eps: 1,
            ecs: k.ne,
            sets: k.nw,
            entries: k.ni,
        });
        let base = u64::MAX - k.max;
        for e in h.ecs.iter_mut().skip(1) {
            e.count = base;
        }
        World {
            h,
            k,
            base,
            ecst: vec!["live"; k.ne + 1],
            final_count: vec![0; k.ne + 1],
            wsalive: vec![true; k.nw + 1],
            rng: Lcg(seed ^ 0x5eed),
        }
    }

    fn named(&self, e: usize) -> bool {
        (1..=self.k.nt).any(|i| self.h.tecs[i].bound == Some(ec(e)))
            || self.h.entries.iter().flatten().any(|x| *x == Some(ec(e)))
    }

    /// Every action enabled now, or whose refusal changes nothing.
    pub fn enabled(&self) -> Vec<Op> {
        let k = self.k;
        let mut ops = vec![];
        for i in 1..=k.nt {
            let tr = self.h.threads[i];
            let runs = self.h.runs(i);
            if tr.state != TState::Ready {
                ops.extend([Op::Cancel(i), Op::Deadline(i)]);
            }
            for e in 1..=k.ne {
                if self.ecst[e] != "live" {
                    continue;
                }
                if runs {
                    for g in self.targets(e) {
                        ops.push(Op::Wait(i, e, g));
                    }
                }
                if k.with_bound && self.h.tecs[i].bound.is_none() {
                    ops.push(Op::Bind(i, e));
                }
            }
            if k.with_sets && runs {
                for w in 1..=k.nw {
                    if self.wsalive[w] {
                        ops.push(Op::WsWait(i, w));
                    }
                }
            }
            if k.with_bound {
                if runs {
                    ops.extend([Op::Recv(i), Op::PassiveRecv(i)]);
                }
                if self.h.tecs[i].bound.is_some() {
                    ops.push(Op::Unbind(i));
                }
                ops.push(if tr.sc.is_some() {
                    Op::LoseCtx(i)
                } else {
                    Op::GainCtx(i)
                });
            }
        }
        if k.with_bound && (1..=k.nt).any(|i| matches!(self.h.threads[i].state, TState::Recv(_))) {
            ops.push(Op::MsgArrive);
        }
        for e in 1..=k.ne {
            match self.ecst[e] {
                "live" => {
                    ops.extend([Op::Advance(e), Op::IrqAdvance(e)]);
                    if k.with_destroy && !self.named(e) {
                        ops.push(Op::DestroyEc(e));
                    }
                }
                "draining" => ops.push(Op::DrainStep(e)),
                _ => {}
            }
            if self.h.ecs[e].pending {
                ops.push(Op::BatchUnit(e));
            }
        }
        if k.with_sets {
            for w in 1..=k.nw {
                if !self.wsalive[w] {
                    continue;
                }
                if k.with_destroy {
                    ops.push(Op::DestroyWs(w));
                }
                for i in 1..=k.ni {
                    if self.h.entries[w][i - 1].is_some() {
                        ops.push(Op::WsRemove(w, i));
                        continue;
                    }
                    for e in 1..=k.ne {
                        if self.ecst[e] == "live" {
                            for g in self.targets(e) {
                                ops.push(Op::WsAdd(w, i, e, g));
                            }
                        }
                    }
                }
            }
        }
        ops
    }

    /// Applies `op` through kipc and donation.
    pub fn apply(&mut self, op: Op) {
        let all = Rights::ALL;
        let h = &mut self.h;
        let base = self.base;
        match op {
            Op::Wait(i, e, g) => {
                let _ = eventcount::wait(h, t(i), ec(e), all, base + g);
            }
            Op::Advance(e) => {
                let seed = self.rng.next();
                let mut budget = Budget::with_threshold(Chance(Lcg(seed), 40), 1);
                let _ = eventcount::advance(h, ec(e), all, &mut budget);
            }
            Op::IrqAdvance(e) => {
                let _ = eventcount::advance_irq(h, ec(e));
            }
            Op::BatchUnit(e) => {
                if eventcount::work_unit(h, ec(e)) {
                    h.work.retain(|&x| x != ec(e));
                    h.work.push(ec(e));
                }
            }
            Op::WsAdd(w, i, e, g) => {
                let _ = eventcount::ws_add(h, ws(w), all, i - 1, ec(e), all, base + g);
            }
            Op::WsRemove(w, i) => {
                eventcount::ws_remove_check(h, ws(w), all, i - 1).expect("remove");
                h.remove_entry(w, i - 1);
            }
            Op::WsWait(i, w) => {
                let _ = eventcount::ws_wait(h, t(i), ws(w), all);
            }
            Op::DestroyWs(w) => {
                h.destroy_set(w);
                self.wsalive[w] = false;
            }
            Op::Bind(i, e) => {
                let _ = eventcount::bind(h, t(i), ec(e), all);
            }
            Op::Unbind(i) => eventcount::unbind(h, t(i)),
            Op::Recv(i) => {
                let _ = endpoint::recv(h, t(i), cap(1), r(i));
            }
            Op::PassiveRecv(i) => {
                // A passive server's loop: its reply gives the donated
                // context back, then it receives without one. Here the
                // thread's own context goes first, and the reply object
                // has no caller, which doesn't stop the receive.
                donation::unbind_sc(h, c(i)).expect("unbind");
                endpoint::reply_recv(h, t(i), cap(1), r(i), 0, false).expect("reply and receive");
            }
            Op::MsgArrive => {
                let sender = t(self.k.nt + 1);
                endpoint::send(h, sender, cap(1), 0, false).expect("send");
            }
            Op::LoseCtx(i) => donation::unbind_sc(h, c(i)).expect("unbind"),
            Op::GainCtx(i) => {
                donation::bind_sc(h, c(i), t(i)).expect("bind");
                eventcount::context_bound(h, t(i));
            }
            Op::Cancel(i) => {
                let _ = donation::cancel(h, t(i));
            }
            Op::Deadline(i) => {
                let _ = donation::deadline(h, t(i));
            }
            Op::DestroyEc(e) => self.ecst[e] = "draining",
            Op::DrainStep(e) => {
                if eventcount::drain(h, ec(e)) {
                    self.final_count[e] = h.ecs[e].count;
                    eventcount::finish(h, ec(e));
                    self.ecst[e] = "gone";
                }
            }
        }
    }

    /// The targets, relative to the base, that a wait or an entry on `e`
    /// may take now ([`Consts::window`]).
    fn targets(&self, e: usize) -> core::ops::RangeInclusive<u64> {
        let k = self.k;
        match k.window {
            None => 1..=k.max,
            Some(w) => {
                let now = self.h.ecs[e].count - self.base;
                now.max(1)..=(now + w).min(k.max)
            }
        }
    }

    /// Picks an enabled action at random; destruction is rare, so runs
    /// last.
    pub fn pick(&self, rng: &mut Lcg) -> Option<Op> {
        self.pick_with(rng, 0)
    }

    /// [`Self::pick`], choosing an advance, when one is enabled, with
    /// `advance` percent chance, so a run can drive its counts to their
    /// maximum.
    pub fn pick_with(&self, rng: &mut Lcg, advance: u64) -> Option<Op> {
        let mut ops = self.enabled();
        let is_advance = |o: &Op| matches!(o, Op::Advance(_) | Op::IrqAdvance(_));
        if advance > 0 && rng.chance(advance) && ops.iter().any(is_advance) {
            ops.retain(is_advance);
        }
        let rare = |o: &Op| matches!(o, Op::DestroyEc(_) | Op::DestroyWs(_));
        if !rng.chance(4) && ops.iter().any(|o| !rare(o)) {
            ops.retain(|o| !rare(o));
        }
        if ops.is_empty() {
            return None;
        }
        Some(ops[rng.below(ops.len() as u64) as usize])
    }

    /// How many nodes are linked on eventcount `e` with a target its count
    /// has reached: waiters an advance has reached and not yet woken.
    pub fn reached_linked(&self, e: usize) -> usize {
        let count = self.h.ecs[e].count;
        self.h
            .nodes
            .iter()
            .filter(|n| n.ec == e as u64 && n.target != 0 && n.target <= count)
            .count()
    }

    /// Whether eventcount `e` is live at its maximum.
    pub fn at_max(&self, e: usize) -> bool {
        self.ecst[e] == "live" && self.h.ecs[e].count == u64::MAX
    }

    fn rel(&self, v: u64) -> u64 {
        if v == 0 { 0 } else { v - self.base }
    }

    /// The store node of the spec's node `n`.
    fn node_of(&self, n: usize) -> u64 {
        let nt = self.k.nt;
        if n <= nt {
            n as u64
        } else {
            let k = n - nt - 1;
            use kipc::store::IpcStore;
            self.h.entry_node(ws(k / self.k.ni + 1), k % self.k.ni)
        }
    }

    /// The state as the spec's record.
    pub fn project(&mut self) -> String {
        let k = self.k;
        let num = |x: &u64| x.to_string();
        let count: Vec<u64> = (1..=k.ne)
            .map(|e| match self.ecst[e] {
                "gone" => self.final_count[e] - self.base,
                _ => self.h.ecs[e].count - self.base,
            })
            .collect();
        let pending: Vec<bool> = (1..=k.ne).map(|e| self.h.ecs[e].pending).collect();
        let mut ts = vec![];
        let mut ctx = vec![];
        let mut res = vec![];
        let mut got = vec![];
        let mut bound = vec![];
        let mut last = vec![];
        let rp: Vec<bool> = (1..=k.nt).map(|i| self.h.rp[i]).collect();
        for i in 1..=k.nt {
            let tr = self.h.threads[i];
            let te = self.h.tecs[i];
            ts.push(match tr.state {
                TState::Ready => "ready",
                TState::Recv(_) => "recv",
                TState::Other if te.set.is_some() => "wswait",
                TState::Other => "wait",
                _ => "other",
            });
            ctx.push(tr.sc.is_some());
            res.push(super::ep_actions::res_name(tr.result));
            got.push(match self.h.got[i] {
                None => 0,
                Some(Value::Count(v) | Value::Advance(v)) => v - self.base,
                Some(Value::Mask(m)) => m,
            });
            bound.push(te.bound.map_or(0, |e| e.0));
            last.push(if te.bound.is_some() {
                te.last - self.base
            } else {
                0
            });
        }
        let nodes = k.nt + k.nw * k.ni;
        let mut lk = vec![];
        let mut tgt = vec![];
        for n in 1..=nodes {
            let node = self.h.nodes[self.node_of(n) as usize];
            lk.push(node.ec);
            tgt.push(self.rel(node.target));
        }
        let mut ent = vec![];
        let mut waiter = vec![];
        for w in 1..=k.nw {
            let row: Vec<u64> = self.h.entries[w]
                .iter()
                .map(|x| x.map_or(0, |e| e.0))
                .collect();
            ent.push(tup(&row, num));
            waiter.push(self.h.wss[w].waiter.map_or(0, |x| x.0));
        }
        format!(
            "[count |-> {}, pending |-> {}, ecst |-> {}, ts |-> {}, ctx |-> {}, res |-> {}, \
             got |-> {}, lk |-> {}, tgt |-> {}, bound |-> {}, last |-> {}, rp |-> {}, \
             ent |-> {}, waiter |-> {}, wsalive |-> {}]",
            tup(&count, num),
            tup(&pending, tla_bool),
            tup(&self.ecst[1..], tla_str),
            tup(&ts, tla_str),
            tup(&ctx, tla_bool),
            tup(&res, tla_str),
            tup(&got, num),
            tup(&lk, num),
            tup(&tgt, num),
            tup(&bound, num),
            tup(&last, num),
            tup(&rp, tla_bool),
            tup(&ent, |x| x.clone()),
            tup(&waiter, num),
            tup(&self.wsalive[1..], tla_bool),
        )
    }

    /// Every invariant over the store, and that no projected thread is in
    /// a state the spec doesn't name.
    pub fn check(&mut self) {
        self.h.check();
    }
}
