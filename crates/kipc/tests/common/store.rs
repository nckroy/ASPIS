// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! An IPC store in vectors: donation's records, and kipc's. It records the
//! effects the kernel would carry out (messages copied, values written,
//! restarts), and the delivered bit as the kernel computes it.

use kipc::store::{EcRec, EpRec, IpcRec, IpcStore, Node, Owner, ThreadEc, Transfer, Value, WsRec};
use kipc::{Ec, Ep, Rights, Ws, endpoint, eventcount};
use ksched::donation::{
    self, FaultKind, Reply, ReplyRec, Res, Sc, ScRec, Step, Store, TState, Tcb, ThreadRec, WalkNode,
};

pub fn t(i: usize) -> Tcb {
    Tcb(i as u64)
}
pub fn r(i: usize) -> Reply {
    Reply(i as u64)
}
pub fn c(i: usize) -> Sc {
    Sc(i as u64)
}
pub fn ep(i: usize) -> Ep {
    Ep(i as u64)
}
pub fn ec(i: usize) -> Ec {
    Ec(i as u64)
}
pub fn ws(i: usize) -> Ws {
    Ws(i as u64)
}

/// An endpoint capability with every right and no badge.
pub fn cap(e: usize) -> endpoint::EpCap {
    endpoint::EpCap {
        ep: ep(e),
        badge: 0,
        rights: Rights::ALL,
    }
}

/// An endpoint capability with `badge` and `rights`.
pub fn badged(e: usize, badge: u64, rights: Rights) -> endpoint::EpCap {
    endpoint::EpCap {
        ep: ep(e),
        badge,
        rights,
    }
}

/// The sizes of a universe. Objects are numbered from 1; thread i starts
/// running on its own home context i.
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    pub threads: usize,
    pub replies: usize,
    pub eps: usize,
    pub ecs: usize,
    pub sets: usize,
    /// Entries per wait set.
    pub entries: usize,
}

pub struct Host {
    // Donation's records.
    pub threads: Vec<ThreadRec>,
    pub replies: Vec<ReplyRec>,
    pub walk_nodes: Vec<WalkNode>,
    pub scs: Vec<ScRec>,
    pub walk_root: u64,
    pub seq: u64,
    pub walks: Vec<Reply>,
    // kipc's records.
    pub eps: Vec<EpRec>,
    pub ipcs: Vec<IpcRec>,
    pub prio: Vec<u8>,
    pub ecs: Vec<EcRec>,
    pub nodes: Vec<Node>,
    pub tecs: Vec<ThreadEc>,
    pub wss: Vec<WsRec>,
    pub entries: Vec<Vec<Option<Ec>>>,
    pub ni: usize,
    /// The work list of eventcounts, in order: every core's, as one.
    pub work: Vec<Ec>,
    /// The core the operations run on, as the kernel's `this_core()`.
    pub core: usize,
    /// The core whose work list holds each eventcount, as the kernel
    /// records it in the eventcount's word (K24).
    pub queued_on: Vec<Option<usize>>,
    /// Each thread's timeout endpoint, if it has one.
    pub tep: Vec<Option<Ep>>,
    // The effects, as the kernel would carry them out.
    pub transfers: Vec<(Tcb, Tcb, Transfer)>,
    pub restarts: Vec<Tcb>,
    pub got: Vec<Option<Value>>,
    /// Flips at each report of a bound eventcount's advance to the thread,
    /// as `specs/Eventcount.tla`'s `rp` does.
    pub rp: Vec<bool>,
    pub dbit: Vec<bool>,
    pub rw: Vec<bool>,
    pub faults: Vec<(Tcb, FaultKind, u64)>,
    pub steps: Vec<Step>,
}

impl Host {
    pub fn new(sh: Shape) -> Host {
        let nt = sh.threads;
        let mut h = Host {
            threads: vec![ThreadRec::default(); nt + 1],
            replies: vec![ReplyRec::default(); sh.replies + 1],
            walk_nodes: vec![WalkNode::default(); sh.replies + 1],
            scs: vec![ScRec::default(); nt + 1],
            walk_root: 0,
            seq: 0,
            walks: Vec::new(),
            eps: vec![EpRec::default(); sh.eps + 1],
            ipcs: vec![IpcRec::default(); nt + 1],
            prio: vec![1; nt + 1],
            ecs: vec![EcRec::default(); sh.ecs + 1],
            nodes: vec![Node::default(); nt + sh.sets * sh.entries + 1],
            tecs: vec![ThreadEc::default(); nt + 1],
            wss: vec![
                WsRec {
                    waiter: None,
                    entries: sh.entries as u8,
                };
                sh.sets + 1
            ],
            entries: vec![vec![None; sh.entries]; sh.sets + 1],
            ni: sh.entries,
            work: Vec::new(),
            core: 0,
            queued_on: vec![None; sh.ecs + 1],
            tep: vec![None; nt + 1],
            transfers: Vec::new(),
            restarts: Vec::new(),
            got: vec![None; nt + 1],
            rp: vec![false; nt + 1],
            dbit: vec![false; nt + 1],
            rw: vec![false; nt + 1],
            faults: Vec::new(),
            steps: Vec::new(),
        };
        for i in 1..=nt {
            h.scs[i] = ScRec {
                holder: Some(t(i)),
                home: Some(t(i)),
                top: None,
                badge: 0x100 + i as u64,
            };
            h.threads[i].sc = Some(c(i));
            h.threads[i].home = Some(c(i));
        }
        h
    }

    pub fn nt(&self) -> usize {
        self.threads.len() - 1
    }
    pub fn all_threads(&self) -> Vec<Tcb> {
        (1..self.threads.len()).map(t).collect()
    }
    pub fn all_replies(&self) -> Vec<Reply> {
        (1..self.replies.len()).map(r).collect()
    }
    pub fn all_scs(&self) -> Vec<Sc> {
        (1..self.scs.len()).map(c).collect()
    }
    pub fn all_eps(&self) -> Vec<Ep> {
        (1..self.eps.len()).map(ep).collect()
    }
    pub fn all_ecs(&self) -> Vec<Ec> {
        (1..self.ecs.len()).map(ec).collect()
    }
    pub fn all_sets(&self) -> Vec<Ws> {
        (1..self.wss.len()).map(ws).collect()
    }

    /// Every invariant: donation's, the endpoints' and the eventcounts'.
    pub fn check(&mut self) {
        let (ts, rs, cs) = (self.all_threads(), self.all_replies(), self.all_scs());
        if let Err(v) = donation::check(self, &ts, &rs, &cs) {
            panic!(
                "donation invariant {v:?} broken after {:?}",
                self.steps.last()
            );
        }
        let eps = self.all_eps();
        if let Err(v) = endpoint::check(self, &eps, &ts) {
            panic!(
                "endpoint invariant {v:?} broken after {:?}",
                self.steps.last()
            );
        }
        let (es, ws) = (self.all_ecs(), self.all_sets());
        if let Err(v) = eventcount::check(self, &es, &ws, &ts) {
            panic!(
                "eventcount invariant {v:?} broken after {:?}",
                self.steps.last()
            );
        }
        for e in &self.work {
            assert!(self.ecs[e.0 as usize].listed, "{e:?} on the list unmarked");
        }
        for (i, rec) in self.ecs.iter().enumerate().skip(1) {
            let on = self.work.iter().filter(|e| e.0 as usize == i).count();
            assert_eq!(
                on,
                usize::from(rec.listed),
                "eventcount {i} listed {on} times"
            );
            assert_eq!(
                self.queued_on[i].is_some(),
                rec.listed,
                "eventcount {i}'s core disagrees with its mark"
            );
        }
    }

    /// The spec's `Runs(t)`.
    pub fn runs(&self, i: usize) -> bool {
        let tr = self.threads[i];
        tr.state == TState::Ready && !tr.suspended && tr.sc.is_some()
    }

    /// The threads queued on endpoint `e`, in order.
    pub fn queue(&mut self, e: usize) -> Vec<usize> {
        let mut out = [Tcb(0); 64];
        let n = endpoint::queued(self, ep(e), &mut out);
        out[..n].iter().map(|x| x.0 as usize).collect()
    }

    /// Runs the eventcounts' work list until it is empty, each unit taking
    /// the first item and moving it to the back if work remains. Returns
    /// the units run.
    pub fn run_work(&mut self) -> usize {
        let mut n = 0;
        while let Some(&e) = self.work.first() {
            if eventcount::work_unit(self, e) {
                self.work.retain(|&x| x != e);
                self.work.push(e);
            }
            n += 1;
            assert!(n < 1_000_000, "the work list doesn't end");
        }
        n
    }

    /// A message's transfers to `to`, in order.
    pub fn received(&self, to: usize) -> Vec<(usize, Transfer)> {
        self.transfers
            .iter()
            .filter(|(_, b, _)| b.0 as usize == to)
            .map(|(a, _, x)| (a.0 as usize, *x))
            .collect()
    }

    /// Removes entry `i` of set `w`, as the kernel's deletion of its slot
    /// does: the unbind step, then the slot is clear.
    pub fn remove_entry(&mut self, w: usize, i: usize) {
        if self.entries[w][i].is_some() {
            eventcount::unbind_entry(self, ws(w), i);
            self.entries[w][i] = None;
        }
    }

    /// Destroys wait set `w`, as its zombie does: zombify, then each
    /// entry's slot.
    pub fn destroy_set(&mut self, w: usize) -> u32 {
        let units = eventcount::ws_zombify(self, ws(w));
        for i in 0..self.ni {
            self.remove_entry(w, i);
        }
        units
    }

    /// Destroys eventcount `e`, as its queue zombie does: drain steps,
    /// then the finish. Returns the steps.
    pub fn destroy_ec(&mut self, e: usize) -> usize {
        let mut n = 1;
        while !eventcount::drain(self, ec(e)) {
            n += 1;
        }
        eventcount::finish(self, ec(e));
        n
    }

    /// Destroys endpoint `e` likewise.
    pub fn destroy_ep(&mut self, e: usize) -> usize {
        let mut n = 1;
        while !endpoint::drain(self, ep(e)) {
            n += 1;
        }
        endpoint::finish(self, ep(e));
        n
    }
}

impl Store for Host {
    fn thread(&self, x: Tcb) -> ThreadRec {
        self.threads[x.0 as usize]
    }
    fn set_thread(&mut self, x: Tcb, rec: ThreadRec) {
        let i = x.0 as usize;
        let old = self.threads[i];
        // The kernel's set_thread: a wait that ends writes the status, with
        // the delivered bit for a delivered call that ended without its
        // reply.
        if old.state != TState::Ready && rec.state == TState::Ready {
            self.dbit[i] = matches!(old.state, TState::Call(_))
                && matches!(rec.result, Res::Canceled | Res::TimedOut | Res::Destroyed);
            self.rw[i] = false;
        }
        self.threads[i] = rec;
    }
    fn reply(&self, x: Reply) -> ReplyRec {
        self.replies[x.0 as usize]
    }
    fn set_reply(&mut self, x: Reply, rec: ReplyRec) {
        self.replies[x.0 as usize] = rec;
    }
    fn sc(&self, x: Sc) -> ScRec {
        self.scs[x.0 as usize]
    }
    fn set_sc(&mut self, x: Sc, rec: ScRec) {
        self.scs[x.0 as usize] = rec;
    }
    fn walk_node(&self, x: Reply) -> WalkNode {
        self.walk_nodes[x.0 as usize]
    }
    fn set_walk_node(&mut self, x: Reply, n: WalkNode) {
        self.walk_nodes[x.0 as usize] = n;
    }
    fn walk_root(&self) -> u64 {
        self.walk_root
    }
    fn set_walk_root(&mut self, root: u64) {
        self.walk_root = root;
    }
    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }
    fn cancel_other(&mut self, x: Tcb) {
        kipc::cancel_wait(self, x);
    }
    fn withdraw_fault(&mut self, x: Tcb, _kind: FaultKind) {
        endpoint::leave(self, x);
    }
    fn send_fault(&mut self, x: Tcb, kind: FaultKind, badge: u64) {
        self.faults.push((x, kind, badge));
        if let Some(e) = self.tep[x.0 as usize] {
            endpoint::send_fault(self, x, e, badge);
        }
    }
    fn wait_cost(&self, x: Tcb) -> u32 {
        kipc::wait_cost(self, x)
    }
    fn changed(&mut self, _t: Tcb) {}
    fn walk_queued(&mut self, cursor: Reply) {
        self.walks.push(cursor);
    }
    fn walk_moved(&mut self, from: Reply, to: Reply) {
        let i = self.walks.iter().position(|&q| q == from).expect("moved");
        self.walks[i] = to;
    }
    fn walk_ended(&mut self, cursor: Reply) {
        let i = self.walks.iter().position(|&q| q == cursor).expect("ended");
        self.walks.remove(i);
    }
    fn observe(&mut self, step: Step) {
        self.steps.push(step);
    }
}

impl IpcStore for Host {
    fn ep(&self, e: Ep) -> EpRec {
        self.eps[e.0 as usize]
    }
    fn set_ep(&mut self, e: Ep, rec: EpRec) {
        self.eps[e.0 as usize] = rec;
    }
    fn ipc(&self, x: Tcb) -> IpcRec {
        self.ipcs[x.0 as usize]
    }
    fn set_ipc(&mut self, x: Tcb, rec: IpcRec) {
        self.ipcs[x.0 as usize] = rec;
    }
    fn priority(&self, x: Tcb) -> u8 {
        self.prio[x.0 as usize]
    }
    fn ec(&self, e: Ec) -> EcRec {
        self.ecs[e.0 as usize]
    }
    fn set_ec(&mut self, e: Ec, rec: EcRec) {
        self.ecs[e.0 as usize] = rec;
    }
    fn node(&self, n: u64) -> Node {
        self.nodes[n as usize]
    }
    fn set_node(&mut self, n: u64, node: Node) {
        self.nodes[n as usize] = node;
    }
    fn owner(&self, n: u64) -> Owner {
        let n = n as usize;
        let nt = self.nt();
        if n <= nt {
            Owner::Thread(t(n))
        } else {
            let k = n - nt - 1;
            Owner::Entry(ws(k / self.ni + 1), k % self.ni)
        }
    }
    fn thread_node(&self, x: Tcb) -> u64 {
        x.0
    }
    fn entry_node(&self, w: Ws, i: usize) -> u64 {
        (self.nt() + (w.0 as usize - 1) * self.ni + i + 1) as u64
    }
    fn thread_ec(&self, x: Tcb) -> ThreadEc {
        self.tecs[x.0 as usize]
    }
    fn set_thread_ec(&mut self, x: Tcb, rec: ThreadEc) {
        self.tecs[x.0 as usize] = rec;
    }
    fn ws(&self, w: Ws) -> WsRec {
        self.wss[w.0 as usize]
    }
    fn set_ws(&mut self, w: Ws, rec: WsRec) {
        self.wss[w.0 as usize] = rec;
    }
    fn entry(&self, w: Ws, i: usize) -> Option<Ec> {
        self.entries[w.0 as usize].get(i).copied().flatten()
    }
    fn bind_entry(&mut self, w: Ws, i: usize, e: Ec) {
        assert!(self.entries[w.0 as usize][i].is_none(), "entry bound twice");
        self.entries[w.0 as usize][i] = Some(e);
    }
    fn queue_work(&mut self, e: Ec) {
        assert!(!self.work.contains(&e), "{e:?} queued twice");
        assert_eq!(self.queued_on[e.0 as usize], None, "{e:?} on two lists");
        self.work.push(e);
        self.queued_on[e.0 as usize] = Some(self.core);
    }
    fn unqueue_work(&mut self, e: Ec) {
        let i = self.work.iter().position(|&x| x == e).expect("unqueued");
        self.work.remove(i);
        self.queued_on[e.0 as usize] = None;
    }
    fn transfer(&mut self, from: Tcb, to: Tcb, what: Transfer) {
        self.transfers.push((from, to, what));
    }
    fn woke(&mut self, x: Tcb, v: Value) {
        if matches!(v, Value::Advance(_)) {
            self.rp[x.0 as usize] ^= true;
        }
        self.got[x.0 as usize] = Some(v);
    }
    fn restart(&mut self, x: Tcb) {
        self.restarts.push(x);
        self.rw[x.0 as usize] = true;
    }
}
