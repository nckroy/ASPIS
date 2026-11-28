// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! A donation store in vectors, set up as the TLA+ spec's `Init`, and its
//! projection onto the spec's state record.

use ksched::donation::{
    self, FaultKind, RState, Reply, ReplyRec, Res, Sc, ScRec, Step, Store, TState, Tcb, ThreadRec,
    WalkNode,
};
use std::collections::BTreeSet;
use std::fmt::Write;

/// Objects are numbered from 1, as in the spec: thread i is `Tcb(i)`.
pub struct Host {
    pub threads: Vec<ThreadRec>,
    pub replies: Vec<ReplyRec>,
    pub nodes: Vec<WalkNode>,
    pub scs: Vec<ScRec>,
    pub talive: Vec<bool>,
    pub ralive: Vec<bool>,
    pub scalive: Vec<bool>,
    pub root: u64,
    pub seq: u64,
    /// The work list: walk cursors, in order.
    pub work: Vec<Reply>,
    /// Faults sent: (thread, kind, badge).
    pub faults: Vec<(Tcb, FaultKind, u64)>,
    pub withdrawn: Vec<(Tcb, FaultKind)>,
    /// Every thread the protocol asked the kernel to take out of what it
    /// keeps for its wait (`cancel_other`), in order.
    pub other_canceled: Vec<Tcb>,
    /// What ending each thread's wait costs, as the kernel would say (C14);
    /// 1 unless a test sets it.
    pub wait_costs: Vec<u32>,
    pub steps: Vec<Step>,
}

pub fn t(i: usize) -> Tcb {
    Tcb(i as u64)
}
pub fn r(i: usize) -> Reply {
    Reply(i as u64)
}
pub fn c(i: usize) -> Sc {
    Sc(i as u64)
}

impl Host {
    /// The spec's `InitState` for `nt` threads, `nr` replies and `ns`
    /// contexts, with timeout endpoints on `tep`. Context i has badge
    /// 0x100 + i.
    pub fn init(nt: usize, nr: usize, ns: usize, tep: &[usize]) -> Host {
        let mut h = Host {
            threads: vec![ThreadRec::default(); nt + 1],
            replies: vec![ReplyRec::default(); nr + 1],
            nodes: vec![WalkNode::default(); nr + 1],
            scs: vec![ScRec::default(); ns + 1],
            talive: vec![true; nt + 1],
            ralive: vec![true; nr + 1],
            scalive: vec![true; ns + 1],
            root: 0,
            seq: 0,
            work: Vec::new(),
            faults: Vec::new(),
            withdrawn: Vec::new(),
            other_canceled: Vec::new(),
            wait_costs: vec![1; nt + 1],
            steps: Vec::new(),
        };
        for i in 1..=ns {
            h.scs[i] = ScRec {
                holder: Some(t(i)),
                home: Some(t(i)),
                top: None,
                badge: 0x100 + i as u64,
            };
            h.threads[i].sc = Some(c(i));
            h.threads[i].home = Some(c(i));
        }
        for i in ns + 1..=nt {
            let k = i - ns;
            if k <= nr {
                h.threads[i].state = TState::Recv(r(k));
                h.replies[k] = ReplyRec {
                    state: RState::Recv,
                    server: Some(t(i)),
                    ..ReplyRec::default()
                };
            }
        }
        for &i in tep {
            h.threads[i].tep = true;
        }
        h
    }

    pub fn nt(&self) -> usize {
        self.threads.len() - 1
    }
    pub fn nr(&self) -> usize {
        self.replies.len() - 1
    }
    pub fn ns(&self) -> usize {
        self.scs.len() - 1
    }

    pub fn all_threads(&self) -> Vec<Tcb> {
        (1..=self.nt()).filter(|&i| self.talive[i]).map(t).collect()
    }
    pub fn all_replies(&self) -> Vec<Reply> {
        (1..=self.nr()).filter(|&i| self.ralive[i]).map(r).collect()
    }
    pub fn all_scs(&self) -> Vec<Sc> {
        (1..=self.ns())
            .filter(|&i| self.scalive[i])
            .map(c)
            .collect()
    }

    /// The spec's invariants, in ksched's form.
    pub fn check(&mut self) {
        let (ts, rs, cs) = (self.all_threads(), self.all_replies(), self.all_scs());
        if let Err(v) = donation::check(self, &ts, &rs, &cs) {
            panic!("invariant {v:?} broken after {:?}", self.steps.last());
        }
    }

    /// The spec's `Runs(t)`.
    pub fn runs(&self, i: usize) -> bool {
        let tr = self.threads[i];
        self.talive[i] && tr.state == TState::Ready && !tr.suspended && tr.sc.is_some()
    }

    /// Drains every pending walk, oldest first.
    pub fn drain(&mut self) {
        while let Some(&q) = self.work.first() {
            donation::walk_step(self, q);
        }
    }

    pub fn destroy_thread(&mut self, i: usize) {
        donation::destroy_thread(self, t(i));
        self.talive[i] = false;
    }
    pub fn destroy_reply(&mut self, i: usize) {
        donation::destroy_reply(self, r(i));
        self.ralive[i] = false;
    }
    pub fn destroy_sc(&mut self, i: usize) {
        donation::destroy_sc(self, c(i));
        self.scalive[i] = false;
    }
}

impl Store for Host {
    fn thread(&self, x: Tcb) -> ThreadRec {
        self.threads[x.0 as usize]
    }
    fn set_thread(&mut self, x: Tcb, rec: ThreadRec) {
        self.threads[x.0 as usize] = rec;
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
        self.nodes[x.0 as usize]
    }
    fn set_walk_node(&mut self, x: Reply, n: WalkNode) {
        self.nodes[x.0 as usize] = n;
    }
    fn walk_root(&self) -> u64 {
        self.root
    }
    fn set_walk_root(&mut self, root: u64) {
        self.root = root;
    }
    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }
    fn cancel_other(&mut self, x: Tcb) {
        self.other_canceled.push(x);
    }

    fn withdraw_fault(&mut self, x: Tcb, kind: FaultKind) {
        self.withdrawn.push((x, kind));
    }
    fn send_fault(&mut self, x: Tcb, kind: FaultKind, badge: u64) {
        self.faults.push((x, kind, badge));
    }
    fn wait_cost(&self, x: Tcb) -> u32 {
        self.wait_costs[x.0 as usize]
    }
    fn changed(&mut self, _t: Tcb) {}

    fn walk_queued(&mut self, cursor: Reply) {
        assert!(!self.work.contains(&cursor), "walk queued twice");
        self.work.push(cursor);
    }
    fn walk_moved(&mut self, from: Reply, to: Reply) {
        let i = self.work.iter().position(|&q| q == from).expect("moved");
        self.work[i] = to;
    }
    fn walk_ended(&mut self, cursor: Reply) {
        let i = self.work.iter().position(|&q| q == cursor).expect("ended");
        self.work.remove(i);
    }
    fn observe(&mut self, step: Step) {
        self.steps.push(step);
    }
}

/// The spec's state record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Abs {
    pub holder: Vec<usize>,
    pub home: Vec<usize>,
    pub stack: Vec<Vec<usize>>,
    pub rst: Vec<&'static str>,
    pub rcaller: Vec<usize>,
    pub rserver: Vec<usize>,
    pub rsc: Vec<usize>,
    pub ts: Vec<&'static str>,
    pub wr: Vec<usize>,
    pub fk: Vec<&'static str>,
    pub flt: Vec<&'static str>,
    pub res: Vec<&'static str>,
    pub serving: Vec<usize>,
    pub tep: Vec<bool>,
    pub susp: Vec<bool>,
    pub walks: BTreeSet<Vec<usize>>,
    pub talive: Vec<bool>,
    pub ralive: Vec<bool>,
    pub scalive: Vec<bool>,
}

fn tn(x: Option<Tcb>) -> usize {
    x.map_or(0, |v| v.0 as usize)
}
fn rn(x: Option<Reply>) -> usize {
    x.map_or(0, |v| v.0 as usize)
}
fn cn(x: Option<Sc>) -> usize {
    x.map_or(0, |v| v.0 as usize)
}

/// Projects a store onto the spec's state.
pub fn project(h: &mut Host) -> Abs {
    let (nt, nr, ns) = (h.nt(), h.nr(), h.ns());
    let mut a = Abs {
        holder: vec![],
        home: vec![],
        stack: vec![],
        rst: vec![],
        rcaller: vec![],
        rserver: vec![],
        rsc: vec![],
        ts: vec![],
        wr: vec![],
        fk: vec![],
        flt: vec![],
        res: vec![],
        serving: vec![],
        tep: vec![],
        susp: vec![],
        walks: BTreeSet::new(),
        talive: vec![],
        ralive: vec![],
        scalive: vec![],
    };
    for i in 1..=ns {
        let sc = h.scs[i];
        a.holder.push(tn(sc.holder));
        a.home.push(tn(sc.home));
        let mut k = vec![];
        let mut cur = sc.top;
        while let Some(q) = cur {
            k.push(q.0 as usize);
            cur = h.replies[q.0 as usize].prev;
            assert!(k.len() <= nr, "a cycle in context {i}'s stack");
        }
        k.reverse();
        a.stack.push(k);
        a.scalive.push(h.scalive[i]);
    }
    for i in 1..=nr {
        let rec = h.replies[i];
        let st = match rec.state {
            RState::Idle => "idle",
            RState::Recv => "recv",
            RState::Pending => {
                if rec.sc.is_some() && donation::is_stale(h, r(i)) {
                    "stale"
                } else {
                    "pending"
                }
            }
            RState::Invalid => "invalid",
        };
        a.rst.push(st);
        a.rcaller.push(tn(rec.caller));
        a.rserver.push(tn(rec.server));
        a.rsc.push(cn(rec.sc));
        a.ralive.push(h.ralive[i]);
    }
    for i in 1..=nt {
        let tr = h.threads[i];
        let (ts, wr, fk) = match tr.state {
            TState::Ready => ("ready", 0, "none"),
            TState::Recv(q) => ("recv", q.0 as usize, "none"),
            TState::Call(q) => ("call", q.0 as usize, "none"),
            TState::Send => ("send", 0, "none"),
            TState::Fault(k) => ("fault", 0, fault_name(k)),
            TState::Other => ("other", 0, "none"),
        };
        a.ts.push(ts);
        a.wr.push(wr);
        a.fk.push(fk);
        a.flt.push(tr.fault.map_or("none", fault_name));
        a.res.push(res_name(tr.result));
        a.serving.push(rn(tr.serving));
        a.tep.push(tr.tep);
        a.susp.push(tr.suspended);
        a.talive.push(h.talive[i]);
    }
    for &cur in &h.work {
        let mut w = vec![];
        let mut q = Some(cur);
        while let Some(x) = q {
            w.push(x.0 as usize);
            q = h.replies[x.0 as usize].next;
            assert!(w.len() <= nr, "a cycle in a walk");
        }
        a.walks.insert(w);
    }
    a
}

/// A fault kind as the spec names it.
pub fn fault_name(k: FaultKind) -> &'static str {
    match k {
        FaultKind::Timeout => "timeout",
        FaultKind::Withdrawn => "withdrawn",
        FaultKind::Endpoint => "endpoint",
    }
}

/// A result as the spec names it.
pub fn res_name(r: Res) -> &'static str {
    match r {
        Res::None => "none",
        Res::Replied => "replied",
        Res::Canceled => "canceled",
        Res::TimedOut => "timedout",
        Res::Destroyed => "destroyed",
    }
}

fn fun<T>(xs: &[T], f: impl Fn(&T) -> String) -> String {
    let body: Vec<String> = xs.iter().map(f).collect();
    format!("<<{}>>", body.join(", "))
}

impl Abs {
    /// The state as a TLA+ record. A function on 1..n is written as a
    /// tuple, which TLA+ treats as the same value.
    pub fn to_tla(&self) -> String {
        let num = |x: &usize| x.to_string();
        let st = |x: &&str| format!("\"{x}\"");
        let b = |x: &bool| if *x { "TRUE".into() } else { "FALSE".into() };
        let mut o = String::new();
        let walks: Vec<String> = self.walks.iter().map(|w| fun(w, num)).collect();
        write!(
            o,
            "[holder |-> {}, home |-> {}, stack |-> {}, rst |-> {}, rcaller |-> {}, \
             rserver |-> {}, rsc |-> {}, ts |-> {}, wr |-> {}, fk |-> {}, flt |-> {}, \
             res |-> {}, serving |-> {}, tep |-> {}, susp |-> {}, walks |-> {{{}}}, \
             talive |-> {}, ralive |-> {}, scalive |-> {}]",
            fun(&self.holder, num),
            fun(&self.home, num),
            fun(&self.stack, |k| fun(k, num)),
            fun(&self.rst, st),
            fun(&self.rcaller, num),
            fun(&self.rserver, num),
            fun(&self.rsc, num),
            fun(&self.ts, st),
            fun(&self.wr, num),
            fun(&self.fk, st),
            fun(&self.flt, st),
            fun(&self.res, st),
            fun(&self.serving, num),
            fun(&self.tep, b),
            fun(&self.susp, b),
            walks.join(", "),
            fun(&self.talive, b),
            fun(&self.ralive, b),
            fun(&self.scalive, b),
        )
        .unwrap();
        o
    }
}
