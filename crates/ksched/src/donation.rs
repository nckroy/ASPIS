// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Scheduling-context donation along chains of calls, and taking a context
//! back (ADR 0051, rule 3; kernel specification, "Passive servers and taking
//! a context back"; K17).
//!
//! This is the one implementation of the protocol: the kernel runs it over
//! its objects through [`Store`], and the host tests run it over a store in
//! vectors, so both execute the same transitions. `specs/SchedDonation.tla`
//! models it, and each public function here names the TLA+ action it is.
//! The host tests write traces of its states that TLC checks against the
//! spec's steps.
//!
//! **Donation.** A call to a passive server waiting to receive donates the
//! caller's context, as in seL4 MCS. The server's reply object records the
//! donation and joins the context's stack of donating replies, oldest first,
//! so the replies lead from the context's home thread through each server
//! to the thread that holds the context. The reply returns the context to
//! the caller.
//!
//! **Taking a context back** when a delivered call is canceled, or its
//! deadline passes (the cut, O(log w) for w pending walks):
//! 1. the segment of the stack from the caller's reply `r` to its top is
//!    detached, and `r` loses its caller;
//! 2. the holder, the top server, loses the context, and its own wait is
//!    canceled (K17);
//! 3. the caller holds the context again, and its call ends "canceled" or
//!    "timed out";
//! 4. the segment becomes a walk, queued on the core that took it back.
//!
//! **The walk** then goes one reply at a time, from `r` up ([`walk_step`],
//! one unit of a batch): at each reply, its server's onward call ends
//! "canceled" (K17); then, if the server is still without a context and has
//! a timeout endpoint, it gets a context-withdrawn fault, which donates
//! nothing; then the reply becomes invalid, so the server's later reply
//! fails with "no caller". So the faults go out S1 first.
//!
//! **Which replies are stale.** Every donating push takes a sequence number
//! from one kernel-wide counter that never wraps. Each pending walk is a
//! node of one kernel-wide interval tree, keyed by its context and its
//! cursor's sequence number, with the interval up to the segment's top, and
//! augmented with the largest end below each node. A donating reply is live
//! iff it is pending and no interval of its context holds its number: a
//! logarithmic query (ADR 0052, rule 2). The context is only compared,
//! never read, so a walk outlives a destroyed context, and a new context at
//! the same address can't be confused with it, since its numbers are later.
//!
//! **Queued sends and faults** (C14). A send or call that finds no receiver
//! waits queued on the endpoint ([`TState::Send`]); a fault raised with a
//! fault endpoint, and a timeout or context-withdrawn fault, waits queued
//! on its endpoint ([`TState::Fault`]). A receive delivers either
//! ([`deliver`], [`deliver_send`]): a queued call, or a fault on the fault
//! endpoint, donates as a call does; a timeout or context-withdrawn fault
//! is delivered as a plain call, donating nothing (ADR 0051, rule 1; ADR
//! 0054, rule 6). A delivered fault is a call on the handler's reply object
//! whose caller has [`ThreadRec::fault`] set: a reply, a cancel, or the
//! destruction of its reply object or of the server it donated to, ends it
//! with no result, so the thread resumes and re-executes (or, for a timeout
//! fault, goes on); a canceled or destroyed one leaves its reply object
//! invalid, so the handler's reply fails with "no caller" (K50), or, while
//! the take-back's walk of a donated one is still to pass it, with "not the
//! holder", since the handler has lost the context. The kernel's
//! IPC (crate `kipc`) keeps the endpoint's queue around these transitions;
//! this module never sees a queue.
//!
//! **Destroyed objects** (K30). A call ends "object destroyed" when its
//! reply object is destroyed, or the server it donated to; so does a
//! receive whose reply object is destroyed. The runtime then reports the
//! call as indeterminate.
//!
//! **What the kernel supplies** through [`Store`]: each object's donation
//! fields, the walk tree's links, the sequence counter, and the effects
//! this module can't do itself: ending a wait it doesn't model (an
//! endpoint's queue, an eventcount's tree, a test sleep, C15's page wait),
//! queuing and withdrawing faults on endpoints, requeuing threads, keeping
//! walks on a core's work list, and the cost of ending a wait.

use crate::NIL;
use crate::tree::{self, Links, TreeStore};

/// A thread, by its object's physical address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tcb(pub u64);
/// A reply object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reply(pub u64);
/// A scheduling context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sc(pub u64);

/// The faults a thread sends: on its timeout endpoint, the two this
/// protocol raises; on its fault endpoint, every other (C14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// The budget ran out (ADR 0051, rule 1).
    Timeout,
    /// The context was taken back (ADR 0056, rule 3).
    Withdrawn,
    /// A fault on the fault endpoint (ADR 0056, rule 1): delivered as a
    /// call, which donates.
    Endpoint,
}

/// A thread's state, as far as donation sees it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TState {
    /// Running or ready, or stranded without a context.
    #[default]
    Ready,
    /// Waiting to receive, with this reply object.
    Recv(Reply),
    /// Waiting for the reply to its call: a call delivered, or a fault
    /// delivered ([`ThreadRec::fault`]).
    Call(Reply),
    /// A send or call queued on an endpoint, not yet delivered (C14).
    Send,
    /// A fault queued on its endpoint, not yet delivered (C14): on the
    /// fault endpoint, or the timeout endpoint.
    Fault(FaultKind),
    /// A wait the kernel keeps: a test sleep, and from C14 and C15, the
    /// waits on eventcounts, wait sets, pages and memory.
    Other,
}

/// How a thread's last wait ended, held until it runs (K20). `None` writes
/// no result: a restart, or a fault's resume.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Res {
    #[default]
    None,
    Replied,
    Canceled,
    TimedOut,
    /// The wait's object was destroyed (K30): its reply object, the server
    /// its call donated to, or from C14, its endpoint, eventcount or wait
    /// set.
    Destroyed,
}

/// How a cancel, a deadline or a destruction ends a wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Canceled,
    TimedOut,
    Destroyed,
}

impl End {
    fn res(self) -> Res {
        match self {
            End::Canceled => Res::Canceled,
            End::TimedOut => Res::TimedOut,
            End::Destroyed => Res::Destroyed,
        }
    }
}

/// A thread's donation fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ThreadRec {
    pub state: TState,
    /// The context it holds: its home one, or one donated to it.
    pub sc: Option<Sc>,
    /// The context bound to it (thread slot 5).
    pub home: Option<Sc>,
    /// The donating reply it serves.
    pub serving: Option<Reply>,
    pub result: Res,
    /// Whether it has a timeout endpoint (thread slot 4).
    pub tep: bool,
    pub suspended: bool,
    /// The fault whose delivered call it waits in, if its [`TState::Call`]
    /// is a fault's (C14).
    pub fault: Option<FaultKind>,
}

/// A reply object's state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RState {
    #[default]
    Idle,
    /// Given to a thread waiting to receive.
    Recv,
    /// A call is delivered: live, or stale while a walk has it.
    Pending,
    /// The call it answered is gone: a reply on it fails with "no caller".
    Invalid,
}

/// A reply object's fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplyRec {
    pub state: RState,
    pub caller: Option<Tcb>,
    /// The receiver while waiting; the server of a donated call.
    pub server: Option<Tcb>,
    /// The context it donated.
    pub sc: Option<Sc>,
    /// Its sequence number, from the push.
    pub seq: u64,
    /// The stack's or the walk's neighbors, older and newer.
    pub prev: Option<Reply>,
    pub next: Option<Reply>,
    /// A walk cursor's badge: the context's, copied at the cut.
    pub badge: u64,
}

/// A reply's node in the walk tree: its interval's end, and the largest end
/// in its subtree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WalkNode {
    pub links: Links,
    pub hi: u64,
    pub max_hi: u64,
}

/// A scheduling context's donation fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScRec {
    pub holder: Option<Tcb>,
    pub home: Option<Tcb>,
    /// The newest donating reply on its stack.
    pub top: Option<Reply>,
    /// The badge that its faults report.
    pub badge: u64,
}

/// One transition, for an observer: the TLA+ action it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Recv(Tcb, Reply),
    Call(Tcb, Tcb),
    Reply(Tcb, Reply),
    ReplyRecv(Tcb, Reply),
    Cancel(Tcb),
    Deadline(Tcb),
    Wait(Tcb),
    BudgetOut(Tcb),
    FaultReplied(Tcb),
    Suspend(Tcb),
    Resume(Tcb),
    SetTep(Tcb, bool),
    BindSc(Sc, Tcb),
    UnbindSc(Sc),
    WalkStep(Reply),
    DestroyThread(Tcb),
    DestroyReply(Reply),
    DestroySc(Sc),
    SendWait(Tcb),
    FaultWait(Tcb),
    DeliverCall(Tcb, Tcb),
    DeliverSend(Tcb, Tcb),
    Wake(Tcb, Res),
}

/// The memory and effects the protocol runs on (module docs).
pub trait Store {
    fn thread(&self, t: Tcb) -> ThreadRec;
    fn set_thread(&mut self, t: Tcb, rec: ThreadRec);
    fn reply(&self, r: Reply) -> ReplyRec;
    fn set_reply(&mut self, r: Reply, rec: ReplyRec);
    fn sc(&self, c: Sc) -> ScRec;
    fn set_sc(&mut self, c: Sc, rec: ScRec);
    fn walk_node(&self, r: Reply) -> WalkNode;
    fn set_walk_node(&mut self, r: Reply, n: WalkNode);
    /// The walk tree's root, or [`NIL`].
    fn walk_root(&self) -> u64;
    fn set_walk_root(&mut self, root: u64);
    /// The next sequence number: one more than the last, never reused.
    fn next_seq(&mut self) -> u64;

    /// Takes `t` out of what the kernel keeps for its wait, before the wait
    /// ends: for [`TState::Other`], its eventcount's or wait set's trees,
    /// its test sleep, from C15 its page wait; for [`TState::Send`] and
    /// [`TState::Recv`], the endpoint's queue and a bound eventcount's tree
    /// (C14). It does nothing for a thread that is in none of them, so a
    /// wait the kernel has already taken out ends the same way.
    fn cancel_other(&mut self, t: Tcb);
    /// Withdraws `t`'s queued fault from its endpoint's queue (K50). It
    /// never sees a delivered fault: that is a call, and ends as one. It
    /// does nothing if the kernel has already taken the fault out.
    fn withdraw_fault(&mut self, t: Tcb, kind: FaultKind);
    /// `t` now sends `kind` on its timeout endpoint, carrying `badge`.
    fn send_fault(&mut self, t: Tcb, kind: FaultKind, badge: u64);
    /// The units of work that ending `t`'s wait takes, as the kernel counts
    /// them for its preemption points and batches (K23, K24): 1, or for a
    /// wait on a wait set, the nodes it unlinks (C14).
    fn wait_cost(&self, _t: Tcb) -> u32 {
        1
    }

    /// `t`'s state, result or context changed: the kernel requeues it, and
    /// drops its deadline if it no longer waits.
    fn changed(&mut self, t: Tcb);
    /// A new walk at `cursor`: the kernel queues it on this core's work
    /// list.
    fn walk_queued(&mut self, cursor: Reply);
    /// A walk's cursor moves from `from` to `to`, in its place on the list.
    fn walk_moved(&mut self, from: Reply, to: Reply);
    /// A walk ended at `cursor`: it leaves the list.
    fn walk_ended(&mut self, cursor: Reply);
    /// Every transition, after it is done: the tests' observer.
    fn observe(&mut self, _step: Step) {}
}

/// Why an operation changed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The thread isn't waiting to receive.
    NotReceiving,
    /// The thread isn't in a wait this ends.
    NotWaiting,
    /// The reply object is in use.
    Busy,
    /// The call has no caller any more (or never had one).
    NoCaller,
    /// The replier doesn't hold the donated context (module docs).
    NotHolder,
    /// The context is already bound, or the thread has or serves one.
    Bound,
    /// The context isn't bound.
    NotBound,
    /// The caller holds no context.
    NoContext,
}

// ---------------------------------------------------------------------------
// The walk tree.

/// The walk tree's view of the store.
struct Walks<'a, S: Store>(&'a mut S);

impl<S: Store> TreeStore for Walks<'_, S> {
    type Key = (u64, u64, u64);
    const AUGMENTED: bool = true;

    fn key(&self, n: u64) -> Self::Key {
        let r = self.0.reply(Reply(n));
        (r.sc.map_or(0, |c| c.0), r.seq, n)
    }

    fn links(&self, n: u64) -> Links {
        self.0.walk_node(Reply(n)).links
    }

    fn set_links(&mut self, n: u64, l: Links) {
        let mut w = self.0.walk_node(Reply(n));
        w.links = l;
        self.0.set_walk_node(Reply(n), w);
    }

    fn update(&mut self, n: u64) {
        let mut w = self.0.walk_node(Reply(n));
        let mut m = w.hi;
        for c in [w.links.left, w.links.right] {
            if c != NIL {
                m = m.max(self.0.walk_node(Reply(c)).max_hi);
            }
        }
        w.max_hi = m;
        self.0.set_walk_node(Reply(n), w);
    }
}

fn walk_insert<S: Store>(s: &mut S, r: Reply, hi: u64) {
    s.set_walk_node(
        r,
        WalkNode {
            links: Links::default(),
            hi,
            max_hi: hi,
        },
    );
    let mut root = s.walk_root();
    tree::insert(&mut Walks(s), &mut root, r.0);
    s.set_walk_root(root);
}

fn walk_remove<S: Store>(s: &mut S, r: Reply) {
    let mut root = s.walk_root();
    tree::remove(&mut Walks(s), &mut root, r.0);
    s.set_walk_root(root);
    s.set_walk_node(r, WalkNode::default());
}

/// Whether some pending walk of context `c` covers sequence number `x`: the
/// largest interval end among the walks of `c` that start at or below `x`
/// reaches `x`. O(log w).
fn stabbed<S: Store>(s: &mut S, c: Sc, x: u64) -> bool {
    let lo = (c.0, 0u64, 0u64);
    let hi = (c.0, x, u64::MAX);
    let w = Walks(s);
    // Find the top node inside [lo, hi].
    let mut n = w.0.walk_root();
    while n != NIL {
        let k = w.key(n);
        if k < lo {
            n = w.links(n).right;
        } else if k > hi {
            n = w.links(n).left;
        } else {
            break;
        }
    }
    if n == NIL {
        return false;
    }
    let mut best = w.0.walk_node(Reply(n)).hi;
    // Its left side: nodes at or above lo.
    let mut m = w.links(n).left;
    while m != NIL {
        if w.key(m) >= lo {
            best = best.max(w.0.walk_node(Reply(m)).hi);
            let r = w.links(m).right;
            if r != NIL {
                best = best.max(w.0.walk_node(Reply(r)).max_hi);
            }
            m = w.links(m).left;
        } else {
            m = w.links(m).right;
        }
    }
    // Its right side: nodes at or below hi.
    let mut m = w.links(n).right;
    while m != NIL {
        if w.key(m) <= hi {
            best = best.max(w.0.walk_node(Reply(m)).hi);
            let l = w.links(m).left;
            if l != NIL {
                best = best.max(w.0.walk_node(Reply(l)).max_hi);
            }
            m = w.links(m).right;
        } else {
            m = w.links(m).left;
        }
    }
    best >= x
}

/// The walk whose segment holds a stale donating reply of context `c` at
/// sequence number `x`: its cursor. O(log w).
///
/// A context's walks cover intervals of sequence numbers that nest or are
/// disjoint: a cut detaches everything above it, and later calls take
/// higher numbers. A reply was on its context's stack, unbroken, from its
/// call to the cut that made it stale, so no walk nested inside its own
/// covers it. Its walk is therefore the innermost one that covers `x`: of
/// the walks of `c` that start at or below `x` and reach it, the one that
/// starts highest. The search finds the deepest node on the search path for
/// `x` that is, or has a left subtree with, such a walk, then the highest
/// such walk below it.
fn covering<S: Store>(s: &mut S, c: Sc, x: u64) -> Option<Reply> {
    let lo = (c.0, 0u64, 0u64);
    let hi = (c.0, x, u64::MAX);
    let w = Walks(s);
    let reaches = |n: u64| w.0.walk_node(Reply(n)).hi >= x;
    let sub_reaches = |n: u64| n != NIL && w.0.walk_node(Reply(n)).max_hi >= x;
    let mut n = w.0.walk_root();
    let mut best = NIL;
    while n != NIL {
        let k = w.key(n);
        if k > hi {
            n = w.links(n).left;
            continue;
        }
        if k >= lo && (reaches(n) || sub_reaches(w.links(n).left)) {
            best = n;
        }
        n = w.links(n).right;
    }
    if best == NIL {
        return None;
    }
    if reaches(best) {
        return Some(Reply(best));
    }
    // The highest walk below `best` that reaches `x`: it is of `c` only if
    // it starts at or above `lo`, and every walk left of it is lower still.
    let mut m = w.links(best).left;
    while m != NIL {
        let l = w.links(m);
        if sub_reaches(l.right) {
            m = l.right;
        } else if reaches(m) {
            return (w.key(m) >= lo).then_some(Reply(m));
        } else {
            m = l.left;
        }
    }
    None
}

/// Whether `r` is a live donating reply: pending, and on its context's
/// stack.
pub fn is_live<S: Store>(s: &mut S, r: Reply) -> bool {
    let rec = s.reply(r);
    match (rec.state, rec.sc) {
        (RState::Pending, Some(c)) => !stabbed(s, c, rec.seq),
        _ => false,
    }
}

/// Whether `r` is a stale donating reply: on a pending walk.
pub fn is_stale<S: Store>(s: &mut S, r: Reply) -> bool {
    let rec = s.reply(r);
    match (rec.state, rec.sc) {
        (RState::Pending, Some(c)) => stabbed(s, c, rec.seq),
        _ => false,
    }
}

/// Whether `r` is a walk's cursor.
pub fn is_cursor<S: Store>(s: &S, r: Reply) -> bool {
    s.walk_node(r).hi != 0
}

// ---------------------------------------------------------------------------
// Small effects, as the spec's operators.

/// The spec's `EndWait`, on a record: the wait ends with `res`, unless it
/// is a delivered fault's call, which ends with no result, so the thread
/// resumes (C14).
fn ended(tr: &mut ThreadRec, res: Res) {
    tr.state = TState::Ready;
    tr.result = if tr.fault.is_some() { Res::None } else { res };
    tr.fault = None;
}

/// The spec's `EndWait`.
fn end_wait<S: Store>(s: &mut S, t: Tcb, res: Res) {
    let mut tr = s.thread(t);
    ended(&mut tr, res);
    s.set_thread(t, tr);
}

fn set_idle<S: Store>(s: &mut S, r: Reply) {
    s.set_reply(r, ReplyRec::default());
}

/// The spec's `CancelHolderWait`: the holder losing its context at a cut.
fn cancel_holder_wait<S: Store>(s: &mut S, t: Tcb) {
    match s.thread(t).state {
        TState::Ready => {}
        TState::Recv(q) => {
            s.cancel_other(t);
            let mut qr = s.reply(q);
            qr.state = RState::Idle;
            qr.server = None;
            s.set_reply(q, qr);
            end_wait(s, t, Res::Canceled);
        }
        TState::Call(q) => {
            let mut qr = s.reply(q);
            qr.state = RState::Invalid;
            qr.caller = None;
            s.set_reply(q, qr);
            end_wait(s, t, Res::Canceled);
        }
        TState::Fault(k) => {
            s.withdraw_fault(t, k);
            end_wait(s, t, Res::None);
        }
        TState::Send | TState::Other => {
            s.cancel_other(t);
            end_wait(s, t, Res::Canceled);
        }
    }
}

/// The spec's `TakeBackStart`: the cut at the live donating reply `r`.
fn take_back<S: Store>(s: &mut S, r: Reply, end: End) {
    let rec = s.reply(r);
    let (Some(c), Some(caller)) = (rec.sc, rec.caller) else {
        return;
    };
    let mut cr = s.sc(c);
    let Some(top) = cr.top else {
        return;
    };
    let hi = s.reply(top).seq;
    // 1. Detach the segment r..top.
    cr.top = rec.prev;
    if let Some(p) = rec.prev {
        let mut pr = s.reply(p);
        pr.next = None;
        s.set_reply(p, pr);
    }
    let holder = cr.holder;
    cr.holder = None;
    s.set_sc(c, cr);
    // 2. The holder loses the context; its own wait ends (K17).
    if let Some(h) = holder {
        let mut hr = s.thread(h);
        hr.sc = None;
        s.set_thread(h, hr);
        cancel_holder_wait(s, h);
        s.changed(h);
    }
    // 4. The segment becomes a walk at r, which loses its caller.
    let mut rec = s.reply(r);
    rec.caller = None;
    rec.prev = None;
    rec.badge = cr.badge;
    s.set_reply(r, rec);
    walk_insert(s, r, hi);
    s.walk_queued(r);
    // 3. The caller holds its context again.
    let mut cr = s.sc(c);
    cr.holder = Some(caller);
    s.set_sc(c, cr);
    let mut t = s.thread(caller);
    t.sc = Some(c);
    ended(&mut t, end.res());
    s.set_thread(caller, t);
    s.changed(caller);
}

/// The spec's `StepServer`: the server of walk reply `q`, whose next reply
/// on the walk is `next`.
fn step_server<S: Store>(s: &mut S, q: Reply, next: Option<Reply>, badge: u64) {
    let Some(srv) = s.reply(q).server else {
        return;
    };
    if let (Some(n), TState::Call(w)) = (next, s.thread(srv).state)
        && w == n
    {
        end_wait(s, srv, Res::Canceled);
        let mut nr = s.reply(n);
        nr.caller = None;
        s.set_reply(n, nr);
    }
    let mut t = s.thread(srv);
    let stranded = t.state == TState::Ready && t.sc.is_none();
    t.serving = None;
    if stranded && t.tep {
        t.state = TState::Fault(FaultKind::Withdrawn);
        s.set_thread(srv, t);
        s.send_fault(srv, FaultKind::Withdrawn, badge);
    } else {
        s.set_thread(srv, t);
    }
    s.changed(srv);
}

/// The spec's `WalkStepEffect` at cursor `q`.
fn step<S: Store>(s: &mut S, q: Reply) {
    let rec = s.reply(q);
    let hi = s.walk_node(q).hi;
    step_server(s, q, rec.next, rec.badge);
    walk_remove(s, q);
    match rec.next {
        Some(n) => {
            let mut nr = s.reply(n);
            nr.prev = None;
            nr.badge = rec.badge;
            s.set_reply(n, nr);
            walk_insert(s, n, hi);
            s.walk_moved(q, n);
        }
        None => s.walk_ended(q),
    }
    s.set_reply(
        q,
        ReplyRec {
            state: RState::Invalid,
            ..ReplyRec::default()
        },
    );
}

/// The spec's `EndAnyWait`: ends `t`'s wait, taking back a donated
/// context.
fn end_any_wait<S: Store>(s: &mut S, t: Tcb, end: End) {
    match s.thread(t).state {
        TState::Ready => {}
        TState::Call(q) => {
            if is_live(s, q) {
                take_back(s, q, end);
            } else if is_stale(s, q) {
                let mut qr = s.reply(q);
                qr.caller = None;
                s.set_reply(q, qr);
                end_wait(s, t, end.res());
            } else {
                let mut qr = s.reply(q);
                qr.state = RState::Invalid;
                qr.caller = None;
                s.set_reply(q, qr);
                end_wait(s, t, end.res());
            }
        }
        TState::Recv(q) => {
            s.cancel_other(t);
            let mut qr = s.reply(q);
            qr.state = RState::Idle;
            qr.server = None;
            s.set_reply(q, qr);
            end_wait(s, t, end.res());
        }
        TState::Fault(k) => {
            s.withdraw_fault(t, k);
            end_wait(s, t, Res::None);
        }
        TState::Send | TState::Other => {
            s.cancel_other(t);
            end_wait(s, t, end.res());
        }
    }
    s.changed(t);
}

/// Whether `t` may reply on `r`, and if not, why: the check of `reply`,
/// which changes nothing, for an operation that must check before it acts
/// (C14's reply and receive).
pub fn may_reply<S: Store>(s: &mut S, t: Tcb, r: Reply) -> Result<(), Error> {
    let rec = s.reply(r);
    match rec.state {
        RState::Pending => match rec.sc {
            None => Ok(()),
            Some(c) => {
                let cr = s.sc(c);
                if cr.holder == Some(t) && cr.top == Some(r) {
                    Ok(())
                } else if s.thread(t).sc == Some(c) && !is_live(s, r) {
                    // The replier holds the context, and r is stale: on a
                    // walk, its caller gone.
                    Err(Error::NoCaller)
                } else {
                    // Not the holder, or the holder replying below the top
                    // of its context's stack.
                    Err(Error::NotHolder)
                }
            }
        },
        RState::Invalid => Ok(()),
        RState::Idle | RState::Recv => Err(Error::NoCaller),
    }
}

/// The spec's `ReplyEffect`, once `may_reply` allowed it.
fn reply_effect<S: Store>(s: &mut S, t: Tcb, r: Reply) -> Result<(), Error> {
    let rec = s.reply(r);
    match (rec.state, rec.caller) {
        (RState::Pending, Some(caller)) => {
            if let Some(c) = rec.sc {
                // Pop: the context returns to the caller.
                let mut cr = s.sc(c);
                cr.top = rec.prev;
                cr.holder = Some(caller);
                s.set_sc(c, cr);
                if let Some(p) = rec.prev {
                    let mut pr = s.reply(p);
                    pr.next = None;
                    s.set_reply(p, pr);
                }
                let mut tr = s.thread(t);
                tr.sc = None;
                tr.serving = None;
                s.set_thread(t, tr);
                let mut cl = s.thread(caller);
                cl.sc = Some(c);
                s.set_thread(caller, cl);
                s.changed(t);
            }
            end_wait(s, caller, Res::Replied);
            s.changed(caller);
            set_idle(s, r);
            Ok(())
        }
        _ => {
            set_idle(s, r);
            Err(Error::NoCaller)
        }
    }
}

fn recv_effect<S: Store>(s: &mut S, t: Tcb, r: Reply) {
    s.set_reply(
        r,
        ReplyRec {
            state: RState::Recv,
            server: Some(t),
            ..ReplyRec::default()
        },
    );
    let mut tr = s.thread(t);
    tr.state = TState::Recv(r);
    tr.result = Res::None;
    s.set_thread(t, tr);
    s.changed(t);
}

// ---------------------------------------------------------------------------
// The operations. The kernel checks, before each, what the spec's action
// requires of a running thread: that it is ready, not suspended and holds
// a context ("Runs").

/// `Recv(t, r)`: `t` waits to receive with reply object `r` (C14's
/// endpoint queue comes around it).
pub fn recv<S: Store>(s: &mut S, t: Tcb, r: Reply) -> Result<(), Error> {
    if !matches!(s.reply(r).state, RState::Idle | RState::Invalid) {
        return Err(Error::Busy);
    }
    recv_effect(s, t, r);
    s.observe(Step::Recv(t, r));
    Ok(())
}

/// How a call was delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivered {
    /// The server had no context: the caller's is donated.
    Donated(Sc),
    /// The server runs on its own context.
    Plain,
}

/// `Call(cl, v)`: `cl`, running, calls `v`, which waits to receive. C14's
/// endpoint picks `v` and carries the message.
pub fn call<S: Store>(s: &mut S, cl: Tcb, v: Tcb) -> Result<Delivered, Error> {
    let TState::Recv(r) = s.thread(v).state else {
        return Err(Error::NotReceiving);
    };
    if s.thread(cl).sc.is_none() {
        return Err(Error::NoContext);
    }
    let out = call_effect(s, cl, v, r, true, None);
    s.observe(Step::Call(cl, v));
    Ok(out)
}

/// The spec's `CallEffect` and `DeliverEffect`: `cl`'s call, or its fault
/// `fault`, is delivered to `v`, which receives with `r`. It donates `cl`'s
/// context if `may_donate`, `cl` holds one and `v` holds none.
fn call_effect<S: Store>(
    s: &mut S,
    cl: Tcb,
    v: Tcb,
    r: Reply,
    may_donate: bool,
    fault: Option<FaultKind>,
) -> Delivered {
    let mut ct = s.thread(cl);
    ct.state = TState::Call(r);
    ct.result = Res::None;
    ct.fault = fault;
    let mut vt = s.thread(v);
    vt.state = TState::Ready;
    vt.result = Res::None;
    let mut rec = ReplyRec {
        state: RState::Pending,
        caller: Some(cl),
        ..ReplyRec::default()
    };
    let donated = match ct.sc {
        Some(c) if may_donate && vt.sc.is_none() => Some(c),
        _ => None,
    };
    let out = if let Some(c) = donated {
        let seq = s.next_seq();
        let mut cr = s.sc(c);
        rec.server = Some(v);
        rec.sc = Some(c);
        rec.seq = seq;
        rec.prev = cr.top;
        if let Some(p) = cr.top {
            let mut pr = s.reply(p);
            pr.next = Some(r);
            s.set_reply(p, pr);
        }
        cr.top = Some(r);
        cr.holder = Some(v);
        s.set_sc(c, cr);
        ct.sc = None;
        vt.sc = Some(c);
        vt.serving = Some(r);
        Delivered::Donated(c)
    } else {
        Delivered::Plain
    };
    s.set_reply(r, rec);
    s.set_thread(cl, ct);
    s.set_thread(v, vt);
    s.changed(cl);
    s.changed(v);
    out
}

/// `DeliverCall(cl, v)`: a receive by `v` delivers `cl`'s queued call or
/// queued fault (C14). `cl` waits in the call on `v`'s reply object, as if
/// it had called `v` now. A call, or a fault on the fault endpoint, donates
/// `cl`'s context if it holds one and `v` holds none; a timeout or
/// context-withdrawn fault donates nothing (ADR 0051, rule 1). A delivered
/// fault records its kind in [`ThreadRec::fault`]. The kernel's IPC has
/// taken `cl` out of the endpoint's queue and carries the message.
pub fn deliver<S: Store>(s: &mut S, cl: Tcb, v: Tcb) -> Result<Delivered, Error> {
    let (may_donate, fault) = match s.thread(cl).state {
        TState::Send => (true, None),
        TState::Fault(k) => (k == FaultKind::Endpoint, Some(k)),
        _ => return Err(Error::NotWaiting),
    };
    let TState::Recv(r) = s.thread(v).state else {
        return Err(Error::NotReceiving);
    };
    let out = call_effect(s, cl, v, r, may_donate, fault);
    s.observe(Step::DeliverCall(cl, v));
    Ok(out)
}

/// `DeliverSend(t, v)`: a receive by `v` delivers `t`'s queued plain send
/// (C14). Both waits end; `v`'s reply object goes back to idle, unused, as
/// seL4's `reply_unlink` leaves it. The kernel's IPC has taken `t` out of
/// the endpoint's queue and carries the message.
pub fn deliver_send<S: Store>(s: &mut S, t: Tcb, v: Tcb) -> Result<(), Error> {
    if s.thread(t).state != TState::Send {
        return Err(Error::NotWaiting);
    }
    let TState::Recv(r) = s.thread(v).state else {
        return Err(Error::NotReceiving);
    };
    end_wait(s, t, Res::Replied);
    set_idle(s, r);
    end_wait(s, v, Res::Replied);
    s.changed(t);
    s.changed(v);
    s.observe(Step::DeliverSend(t, v));
    Ok(())
}

/// `SendWait(t)`: `t`, running, sends or calls on an endpoint with no
/// receiver waiting, and waits queued (C14). Whether it is a call is the
/// kernel's IPC's to keep: it chooses [`deliver`] or [`deliver_send`].
pub fn send_wait<S: Store>(s: &mut S, t: Tcb) {
    let mut tr = s.thread(t);
    tr.state = TState::Send;
    tr.result = Res::None;
    s.set_thread(t, tr);
    s.changed(t);
    s.observe(Step::SendWait(t));
}

/// `FaultWait(t)`: `t`, running, raised a fault and has a fault endpoint:
/// it waits, sending the fault, queued on that endpoint (ADR 0056, rule 1;
/// C14). The kernel writes the fault record and queues it. The timeout and
/// context-withdrawn faults are [`budget_out`]'s and the walk's.
pub fn fault_wait<S: Store>(s: &mut S, t: Tcb) {
    let mut tr = s.thread(t);
    tr.state = TState::Fault(FaultKind::Endpoint);
    s.set_thread(t, tr);
    s.changed(t);
    s.observe(Step::FaultWait(t));
}

/// `Wake(t, res)`: the kernel ends `t`'s wait on an endpoint, an eventcount
/// or a wait set, which it has already taken `t` out of (C14): a send or
/// receive whose message came, or whose endpoint was destroyed; an
/// eventcount wait whose target was reached; a sender whose badge was
/// released, with no result, so it restarts its call. A queued fault is
/// withdrawn, and ends with no result, so the thread goes on as its
/// fault's kind allows (it re-executes a faulting instruction). A
/// receive's reply object goes back to idle. A call can't be woken: it ends
/// by its reply, a cancel or a destruction.
pub fn wake<S: Store>(s: &mut S, t: Tcb, res: Res) -> Result<(), Error> {
    match s.thread(t).state {
        TState::Ready | TState::Call(_) => return Err(Error::NotWaiting),
        TState::Fault(k) => {
            s.withdraw_fault(t, k);
            end_wait(s, t, Res::None);
        }
        TState::Recv(r) => {
            set_idle(s, r);
            end_wait(s, t, res);
        }
        TState::Send | TState::Other => end_wait(s, t, res),
    }
    s.changed(t);
    s.observe(Step::Wake(t, res));
    Ok(())
}

/// `Reply(t, r)`: `t`, running, replies on `r`. A donating call can be
/// answered only by the thread that holds its context, at the top of the
/// context's stack.
pub fn reply<S: Store>(s: &mut S, t: Tcb, r: Reply) -> Result<(), Error> {
    may_reply(s, t, r)?;
    let out = reply_effect(s, t, r);
    s.observe(Step::Reply(t, r));
    out
}

/// `ReplyRecv(t, r)`: a reply on `r`, if there is one to make, then a
/// receive with `r`, as a passive server's loop does. The reply's result is
/// returned; the receive happens if `r` is then free.
pub fn reply_recv<S: Store>(s: &mut S, t: Tcb, r: Reply) -> Result<(), Error> {
    let replied = match may_reply(s, t, r) {
        Ok(()) => reply_effect(s, t, r),
        Err(e) => Err(e),
    };
    if !matches!(s.reply(r).state, RState::Idle | RState::Invalid) {
        return Err(Error::Busy);
    }
    recv_effect(s, t, r);
    s.observe(Step::ReplyRecv(t, r));
    replied
}

/// `Cancel(t)`: ends `t`'s wait with "canceled", taking back the context of
/// a donated call at once (ADR 0051, rule 3). A fault send is withdrawn,
/// and the thread goes on as its fault's kind allows: a faulting
/// instruction faults again when it re-executes, if its cause remains.
pub fn cancel<S: Store>(s: &mut S, t: Tcb) -> Result<(), Error> {
    if s.thread(t).state == TState::Ready {
        return Err(Error::NotWaiting);
    }
    end_any_wait(s, t, End::Canceled);
    s.observe(Step::Cancel(t));
    Ok(())
}

/// `Deadline(t)`: `t`'s deadline passed: as a cancel, with "timed out".
/// Faults have no deadline, queued or delivered.
pub fn deadline<S: Store>(s: &mut S, t: Tcb) -> Result<(), Error> {
    let tr = s.thread(t);
    if matches!(tr.state, TState::Ready | TState::Fault(_)) || tr.fault.is_some() {
        return Err(Error::NotWaiting);
    }
    end_any_wait(s, t, End::TimedOut);
    s.observe(Step::Deadline(t));
    Ok(())
}

/// The units ending `t`'s wait takes, for a batch that must know a unit's
/// cost before it runs it (K24): its own wait's, and for a live donated
/// call, whose end is a take-back, the holder's wait's too, since the cut
/// cancels it (K17). C14's wait-set waits cost more than one.
pub fn end_cost<S: Store>(s: &mut S, t: Tcb) -> u32 {
    let mut cost = s.wait_cost(t);
    if let TState::Call(q) = s.thread(t).state
        && is_live(s, q)
        && let Some(c) = s.reply(q).sc
        && let Some(h) = s.sc(c).holder
    {
        cost = cost.saturating_add(s.wait_cost(h));
    }
    cost
}

/// The units the walk step at cursor `q` takes: one, and the cost of the
/// server's onward call it ends, if any.
pub fn step_cost<S: Store>(s: &mut S, q: Reply) -> u32 {
    let rec = s.reply(q);
    match (rec.server, rec.next) {
        (Some(srv), Some(n)) if s.thread(srv).state == TState::Call(n) => {
            1u32.saturating_add(s.wait_cost(srv))
        }
        _ => 1,
    }
}

/// The holder whose wait a take-back at `r` would end: `r`'s context's
/// holder, if `r` is a live donating reply.
fn cut_holder<S: Store>(s: &mut S, r: Reply) -> Option<Tcb> {
    if !is_live(s, r) {
        return None;
    }
    let c = s.reply(r).sc?;
    s.sc(c).holder
}

/// The units destroying thread `t` takes ([`destroy_thread`]), for the
/// deletion step that makes its zombie (K23): the wait of the holder that
/// the take-back of the call it serves ends, and its own wait's end, as
/// [`end_cost`] counts it, each counted once. At least 1. Call it before
/// [`destroy_thread`]; nothing may change between the two.
pub fn destroy_cost<S: Store>(s: &mut S, t: Tcb) -> u32 {
    let tr = s.thread(t);
    let mut cost = 0u32;
    let cut = tr.serving.and_then(|q| cut_holder(s, q));
    if let Some(h) = cut {
        cost = cost.saturating_add(s.wait_cost(h));
    }
    // The cut ended `t`'s wait if `t` held the context.
    if tr.state != TState::Ready && cut != Some(t) {
        cost = cost.saturating_add(s.wait_cost(t));
        if let TState::Call(q) = tr.state
            && let Some(h) = cut_holder(s, q)
            && Some(h) != cut
        {
            cost = cost.saturating_add(s.wait_cost(h));
        }
    }
    cost.max(1)
}

/// The units destroying reply object `r` takes ([`destroy_reply`]), for
/// the deletion step that finishes it (K23): a live reply's take-back ends
/// its context's holder's wait, a donating reply's walk step ends its
/// server's onward call ([`step_cost`]), and a receive with it ends. At
/// least 1. Call it before [`destroy_reply`].
pub fn destroy_reply_cost<S: Store>(s: &mut S, r: Reply) -> u32 {
    let rec = s.reply(r);
    let cost = match rec.state {
        RState::Pending if rec.sc.is_some() => {
            let cut = cut_holder(s, r).map_or(0, |h| s.wait_cost(h));
            cut.saturating_add(step_cost(s, r))
        }
        RState::Recv => rec.server.map_or(0, |v| s.wait_cost(v)),
        _ => 0,
    };
    cost.max(1)
}

/// The units unbinding context `c` takes ([`unbind_sc`], or the unbind of
/// [`destroy_sc`]), for the deletion step that runs it (K23): a donated
/// context is taken back first, which ends its holder's wait. At least 1.
pub fn unbind_cost<S: Store>(s: &mut S, c: Sc) -> u32 {
    let cr = s.sc(c);
    let cost = match (cr.home, cr.top) {
        (Some(h), Some(_)) => match s.thread(h).state {
            TState::Call(r1) => cut_holder(s, r1).map_or(0, |x| s.wait_cost(x)),
            _ => 0,
        },
        _ => 0,
    };
    cost.max(1)
}

/// `WalkStep`: one unit of the walk whose cursor is `q`. Returns the next
/// cursor, or None when the walk ends.
pub fn walk_step<S: Store>(s: &mut S, q: Reply) -> Option<Reply> {
    let next = s.reply(q).next;
    step(s, q);
    s.observe(Step::WalkStep(q));
    next
}

/// `Wait(t)`: `t`, running, starts a wait the kernel keeps
/// ([`TState::Other`]).
pub fn wait_other<S: Store>(s: &mut S, t: Tcb) {
    let mut tr = s.thread(t);
    tr.state = TState::Other;
    tr.result = Res::None;
    s.set_thread(t, tr);
    s.changed(t);
    s.observe(Step::Wait(t));
}

/// `BudgetOut(t)`: `t`'s budget ran out and it has a timeout endpoint: it
/// sends a timeout fault with its context's badge, donating nothing (ADR
/// 0051, rule 1). Returns false, changing nothing, without an endpoint: the
/// kernel then queues it for its refill.
pub fn budget_out<S: Store>(s: &mut S, t: Tcb) -> bool {
    let mut tr = s.thread(t);
    if !tr.tep {
        return false;
    }
    let badge = tr.sc.map_or(0, |c| s.sc(c).badge);
    tr.state = TState::Fault(FaultKind::Timeout);
    s.set_thread(t, tr);
    s.send_fault(t, FaultKind::Timeout, badge);
    s.changed(t);
    s.observe(Step::BudgetOut(t));
    true
}

/// `FaultReplied(t)`: the handler replied to `t`'s fault: it resumes. The
/// delivery and the reply as one step, for a model without endpoint queues
/// (the spec with `WithQueue` false) and C12's tests. With queues, a fault
/// is delivered ([`deliver`]) and replied to as a call ([`reply`]).
pub fn fault_replied<S: Store>(s: &mut S, t: Tcb) -> Result<(), Error> {
    if !matches!(s.thread(t).state, TState::Fault(_)) {
        return Err(Error::NotWaiting);
    }
    end_wait(s, t, Res::None);
    s.changed(t);
    s.observe(Step::FaultReplied(t));
    Ok(())
}

/// `Suspend(t)` and `Resume(t)`: the flag only; the wait stays (ADR 0061,
/// rule 3).
pub fn set_suspended<S: Store>(s: &mut S, t: Tcb, on: bool) {
    let mut tr = s.thread(t);
    if tr.suspended == on {
        return;
    }
    tr.suspended = on;
    s.set_thread(t, tr);
    s.changed(t);
    s.observe(if on {
        Step::Suspend(t)
    } else {
        Step::Resume(t)
    });
}

/// `SetTep(t, b)`: setting or removing `t`'s timeout endpoint (K08). A
/// fault queued on the endpoint it loses is withdrawn (K50): a timeout
/// fault becomes a wait for the refill, a context-withdrawn fault a silent
/// strand. A fault queued on the fault endpoint ([`FaultKind::Endpoint`])
/// isn't the timeout endpoint's, and stays.
pub fn set_tep<S: Store>(s: &mut S, t: Tcb, on: bool) {
    let mut tr = s.thread(t);
    if tr.tep == on {
        return;
    }
    tr.tep = on;
    s.set_thread(t, tr);
    if let (false, TState::Fault(k @ (FaultKind::Timeout | FaultKind::Withdrawn))) = (on, tr.state)
    {
        s.withdraw_fault(t, k);
        end_wait(s, t, Res::None);
    }
    s.changed(t);
    s.observe(Step::SetTep(t, on));
}

/// `BindSC(c, t)`: binds context `c` to `t` as its home. Refused if either
/// is bound, if `t` holds a context, or if `t` serves a donated call.
pub fn bind_sc<S: Store>(s: &mut S, c: Sc, t: Tcb) -> Result<(), Error> {
    let cr = s.sc(c);
    let tr = s.thread(t);
    if cr.home.is_some()
        || cr.holder.is_some()
        || tr.home.is_some()
        || tr.sc.is_some()
        || tr.serving.is_some()
    {
        return Err(Error::Bound);
    }
    s.set_sc(
        c,
        ScRec {
            home: Some(t),
            holder: Some(t),
            ..cr
        },
    );
    s.set_thread(
        t,
        ThreadRec {
            home: Some(c),
            sc: Some(c),
            ..tr
        },
    );
    s.changed(t);
    s.observe(Step::BindSc(c, t));
    Ok(())
}

/// The spec's `UnbindEffect`: a donated context is taken back first.
fn unbind<S: Store>(s: &mut S, c: Sc) -> Result<(), Error> {
    let cr = s.sc(c);
    let Some(h) = cr.home else {
        return Err(Error::NotBound);
    };
    if cr.top.is_some() {
        // The home thread is the caller at the stack's bottom.
        if let TState::Call(r1) = s.thread(h).state {
            take_back(s, r1, End::Canceled);
        }
    }
    let cr = s.sc(c);
    s.set_sc(
        c,
        ScRec {
            home: None,
            holder: None,
            ..cr
        },
    );
    let mut ht = s.thread(h);
    ht.home = None;
    ht.sc = None;
    s.set_thread(h, ht);
    s.changed(h);
    Ok(())
}

/// `UnbindSC(c)`: unbinds `c` from its home thread, which can't run until
/// it gets a context again.
pub fn unbind_sc<S: Store>(s: &mut S, c: Sc) -> Result<(), Error> {
    unbind(s, c)?;
    s.observe(Step::UnbindSc(c));
    Ok(())
}

/// `DestroyThread(t)`: the donated call it serves is taken back for its
/// caller, whose call ends "object destroyed" (K30), its own wait ends, and
/// its home context is unbound. The kernel calls this when the thread's
/// object becomes a zombie, then forgets it.
pub fn destroy_thread<S: Store>(s: &mut S, t: Tcb) {
    if let Some(q) = s.thread(t).serving {
        if is_live(s, q) {
            take_back(s, q, End::Destroyed);
        }
        let mut qr = s.reply(q);
        qr.server = None;
        s.set_reply(q, qr);
        let mut tr = s.thread(t);
        tr.serving = None;
        s.set_thread(t, tr);
    }
    if s.thread(t).state != TState::Ready {
        end_any_wait(s, t, End::Canceled);
    }
    if let Some(c) = s.thread(t).home {
        let cr = s.sc(c);
        s.set_sc(
            c,
            ScRec {
                home: None,
                holder: None,
                ..cr
            },
        );
    }
    s.set_thread(t, ThreadRec::default());
    s.changed(t);
    s.observe(Step::DestroyThread(t));
}

/// `DestroyReply(r)`. A live donating reply is a cut at `r`, and `r`'s
/// own step follows at once. A stale one takes its step at once, and its
/// caller's wait on it ends. A call waiting on `r`, and a receive with it,
/// end "object destroyed" (K30). The kernel calls this from the reply
/// object's finish.
pub fn destroy_reply<S: Store>(s: &mut S, r: Reply) {
    let rec = s.reply(r);
    match rec.state {
        RState::Pending if rec.sc.is_some() && is_live(s, r) => {
            take_back(s, r, End::Destroyed);
            step(s, r);
        }
        RState::Pending if rec.sc.is_some() => {
            if let Some(cl) = rec.caller {
                end_wait(s, cl, Res::Destroyed);
                s.changed(cl);
            }
            if is_cursor(s, r) {
                step(s, r);
            } else {
                // Its step now, with the badge its walk's cursor took at
                // the cut, then out of its segment.
                let badge = rec
                    .sc
                    .and_then(|c| covering(s, c, rec.seq))
                    .map_or(0, |q| s.reply(q).badge);
                step_server(s, r, rec.next, badge);
                if let Some(p) = rec.prev {
                    let mut pr = s.reply(p);
                    pr.next = rec.next;
                    s.set_reply(p, pr);
                }
                if let Some(n) = rec.next {
                    let mut nr = s.reply(n);
                    nr.prev = rec.prev;
                    s.set_reply(n, nr);
                }
            }
        }
        RState::Pending => {
            if let Some(cl) = rec.caller {
                end_wait(s, cl, Res::Destroyed);
                s.changed(cl);
            }
        }
        RState::Recv => {
            if let Some(v) = rec.server {
                // Out of the endpoint's queue first (C14).
                s.cancel_other(v);
                end_wait(s, v, Res::Destroyed);
                s.changed(v);
            }
        }

        RState::Idle | RState::Invalid => {}
    }
    set_idle(s, r);
    s.observe(Step::DestroyReply(r));
}

/// `DestroySC(c)`: unbound first, and taken back first if donated. Its
/// pending walks carry on without it.
pub fn destroy_sc<S: Store>(s: &mut S, c: Sc) {
    if s.sc(c).home.is_some() {
        let _ = unbind(s, c);
    }
    s.set_sc(c, ScRec::default());
    s.observe(Step::DestroySc(c));
}

// ---------------------------------------------------------------------------
// Invariants, for the host tests and the kernel's test builds.

/// The invariant that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    /// A context's holder and the thread's context disagree.
    Holder,
    /// A thread holds a context that names another holder.
    OneContext,
    /// A holder is blocked in a donating call.
    HolderBlocked,
    /// A context's stack is malformed.
    Chain,
    /// A pending donating reply is neither live nor on a walk.
    Lost,
    /// A reply's caller isn't waiting on it.
    Caller,
    /// A served reply doesn't name its server.
    Serving,
    /// The walk tree is malformed.
    WalkTree,
    /// A stale reply's segment doesn't end at the walk the tree finds for
    /// it.
    Segment,
    /// A thread records a delivered fault, but isn't waiting in a call.
    Fault,
}

/// Checks the spec's invariants over the objects given. O(n log n): for
/// tests.
pub fn check<S: Store>(
    s: &mut S,
    threads: &[Tcb],
    replies: &[Reply],
    scs: &[Sc],
) -> Result<(), Violation> {
    let limit = replies.len() + 1;
    for &c in scs {
        let cr = s.sc(c);
        if let Some(h) = cr.holder {
            let ht = s.thread(h);
            if ht.sc != Some(c) || cr.home.is_none() {
                return Err(Violation::Holder);
            }
            if let TState::Call(q) = ht.state
                && is_live(s, q)
            {
                return Err(Violation::HolderBlocked);
            }
        } else if cr.home.is_some() {
            return Err(Violation::Holder);
        }
        // Walk the stack down from its top.
        let mut cur = cr.top;
        let mut expect_server = cr.holder;
        let mut n = 0;
        let mut bottom_caller = None;
        while let Some(q) = cur {
            n += 1;
            if n > limit {
                return Err(Violation::Chain);
            }
            let qr = s.reply(q);
            if qr.state != RState::Pending || qr.sc != Some(c) || !is_live(s, q) {
                return Err(Violation::Chain);
            }
            if qr.server != expect_server || qr.server.is_none() {
                return Err(Violation::Chain);
            }
            if let Some(p) = qr.prev
                && s.reply(p).next != Some(q)
            {
                return Err(Violation::Chain);
            }
            expect_server = qr.caller;
            bottom_caller = qr.caller;
            cur = qr.prev;
        }
        if cr.top.is_some() && bottom_caller != cr.home {
            return Err(Violation::Chain);
        }
        if cr.top.is_none() && cr.holder != cr.home {
            return Err(Violation::Chain);
        }
    }
    for &t in threads {
        let tr = s.thread(t);
        if tr.fault.is_some() && !matches!(tr.state, TState::Call(_)) {
            return Err(Violation::Fault);
        }
        if let Some(c) = tr.sc
            && s.sc(c).holder != Some(t)
        {
            return Err(Violation::OneContext);
        }
        if let Some(q) = tr.serving {
            let qr = s.reply(q);
            if qr.server != Some(t) || qr.state != RState::Pending || qr.sc.is_none() {
                return Err(Violation::Serving);
            }
        }
    }
    for &r in replies {
        let rec = s.reply(r);
        if let Some(cl) = rec.caller
            && s.thread(cl).state != TState::Call(r)
        {
            return Err(Violation::Caller);
        }
        if rec.state == RState::Pending && rec.sc.is_some() {
            if let Some(v) = rec.server
                && s.thread(v).serving != Some(r)
            {
                return Err(Violation::Serving);
            }
            if is_live(s, r) {
                // Live: its context's stack must reach it.
                let Some(c) = rec.sc else {
                    return Err(Violation::Lost);
                };
                let mut cur = s.sc(c).top;
                let mut found = false;
                let mut n = 0;
                while let Some(q) = cur {
                    n += 1;
                    if q == r {
                        found = true;
                        break;
                    }
                    if n > limit {
                        break;
                    }
                    cur = s.reply(q).prev;
                }
                if !found {
                    return Err(Violation::Lost);
                }
            } else if let Some(c) = rec.sc {
                // Stale: its segment, down from it, ends at the cursor of
                // the walk that covers it.
                let mut q = r;
                let mut n = 0;
                while let Some(p) = s.reply(q).prev {
                    n += 1;
                    if n > limit {
                        return Err(Violation::Segment);
                    }
                    q = p;
                }
                if !is_cursor(s, q) || covering(s, c, rec.seq) != Some(q) {
                    return Err(Violation::Segment);
                }
            }
        }
    }
    let root = s.walk_root();
    if tree::check(&Walks(s), root, limit).is_err() {
        return Err(Violation::WalkTree);
    }
    Ok(())
}
