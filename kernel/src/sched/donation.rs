// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Scheduling-context donation and taking a context back, on the kernel's
//! objects (ADR 0051, rule 3; ADR 0056, rule 3; kernel specification,
//! "Passive servers and taking a context back"; K17).
//!
//! The protocol is `ksched::donation`'s, the one implementation, which
//! `specs/SchedDonation.tla` models and the host tests check (ADR 0068,
//! rule 10). This module gives it a [`Store`] over the direct map
//! ([`KStore`]): each thread's, reply object's and context's donation
//! fields, the kernel-wide walk tree and sequence counter, and the effects
//! the protocol leaves to the kernel: ending a wait it doesn't model,
//! queuing and withdrawing faults (C14's seam), putting a thread where it
//! belongs, and keeping each walk on its core's work list.
//!
//! **The seams C14 uses.** [`recv`], [`call`], [`reply`], [`reply_recv`]
//! and [`cancel`] are the scheduling side of C14's receive, call, reply and
//! cancel: C14 adds the endpoint's queue, the message and the capability
//! transfer around them. Until then the test trap and the in-QEMU tests
//! call them, with one message word standing in for the message.
//!
//! **Charging.** Each operation that may move a context first charges the
//! running thread's time to its context ([`run::commit_current`]), so the
//! time used before the move counts against the context that was used. A
//! holder that runs on another core is stalled there first, which charges
//! its time there (`crate::smp::remote`).
//!
//! **Mapping waits.** A thread's kernel wait ([`Wait`]) is the protocol's
//! state: a receive and a call are `Recv` and `Call` on the reply object in
//! [`super::object::SchedState::waiting_reply`]; a timeout or
//! context-withdrawn fault send is `Fault`; a fault send on the fault
//! endpoint and a test sleep are `Other`, the waits the kernel keeps itself.
//! C14's endpoint and eventcount waits, C15's page wait and C16's memory
//! request join `Other`, each with its own cancel in [`KStore::cancel_other`]
//! (K17).

use super::fault::{self, Kind};
use super::object::{Ended, FaultRecord, ReplyObj, Rp, Sc, Tcb, Wait, flag, reply_word};
use super::percore::this_core;
use super::run;
use core::sync::atomic::{AtomicU64, Ordering};
use kcap::cap::Binding;
use ksched::donation::{
    self as d, Delivered, Error, FaultKind, RState, ReplyRec, Res, ScRec, Step, Store, TState,
    ThreadRec, WalkNode,
};
use ksched::tree::Links;
use ksched::worklist::{Tagged, WLinks, WorkStore};

/// The walk tree's root, a reply object's address, or 0. Kernel-wide, under
/// the kernel lock, as every walk's nodes are, whichever core's work list
/// holds it.
static WALK_ROOT: AtomicU64 = AtomicU64::new(0);
/// The last sequence number given to a donating call. It never wraps: at
/// one call a nanosecond it would take five centuries.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// The steps taken, by kind, for the tests (test builds).
#[cfg(aspis_test_build)]
pub static STEPS: [AtomicU64; 18] = [const { AtomicU64::new(0) }; 18];

fn nz(v: u64) -> Option<u64> {
    (v != 0).then_some(v)
}

fn res_of(v: u8) -> Res {
    match v {
        1 => Res::Replied,
        2 => Res::Canceled,
        3 => Res::TimedOut,
        _ => Res::None,
    }
}

const fn res_num(r: Res) -> u8 {
    match r {
        Res::None => 0,
        Res::Replied => 1,
        Res::Canceled => 2,
        Res::TimedOut => 3,
    }
}

/// What a system call's x0 says when its wait ends.
const fn ended(r: Res) -> Ended {
    match r {
        Res::None | Res::Replied => Ended::Done,
        Res::Canceled => Ended::Canceled,
        Res::TimedOut => Ended::TimedOut,
    }
}

fn rstate(v: u64) -> RState {
    match v & reply_word::STATE {
        1 => RState::Recv,
        2 => RState::Pending,
        3 => RState::Invalid,
        _ => RState::Idle,
    }
}

const fn rstate_num(s: RState) -> u64 {
    match s {
        RState::Idle => 0,
        RState::Recv => 1,
        RState::Pending => 2,
        RState::Invalid => 3,
    }
}

const fn fault_kind(k: FaultKind) -> (Wait, Kind) {
    match k {
        FaultKind::Timeout => (Wait::TimeoutSend, Kind::Timeout),
        FaultKind::Withdrawn => (Wait::WithdrawnSend, Kind::Withdrawn),
    }
}

/// The store over the kernel's objects (module docs).
pub struct KStore;

impl KStore {
    /// A store for an operation that may move a context: the running
    /// thread's time is charged first (module docs).
    pub fn begin() -> KStore {
        run::commit_current(crate::timer::now());
        KStore
    }
}

impl Store for KStore {
    fn thread(&self, t: d::Tcb) -> ThreadRec {
        let t = Tcb(t.0);
        let s = t.state();
        let state = match Wait::from_u8(s.wait) {
            Wait::None => TState::Ready,
            Wait::Receive => TState::Recv(d::Reply(s.waiting_reply)),
            Wait::Call => TState::Call(d::Reply(s.waiting_reply)),
            Wait::TimeoutSend => TState::Fault(FaultKind::Timeout),
            Wait::WithdrawnSend => TState::Fault(FaultKind::Withdrawn),
            Wait::FaultSend | Wait::TestSleep => TState::Other,
        };
        ThreadRec {
            state,
            sc: nz(s.sc).map(d::Sc),
            home: nz(s.home).map(d::Sc),
            serving: nz(s.serving_reply).map(d::Reply),
            result: res_of(s.result),
            tep: fault::has_endpoint(t, Binding::TimeoutEndpoint),
            suspended: s.flags & flag::RESUMED == 0,
        }
    }

    /// Writes the record back. Whether the thread has a timeout endpoint is
    /// its slot 4's, which only the endpoint's binding changes, so `tep` is
    /// read, never written. A wait that ends writes its result into a
    /// system call's x0 at once (K20), and lets a ready head refill count
    /// from now, as seL4's `refill_unblock_check`.
    fn set_thread(&mut self, t: d::Tcb, rec: ThreadRec) {
        let t = Tcb(t.0);
        let old = Wait::from_u8(t.with(|b| b.s.wait));
        let wait = match rec.state {
            TState::Ready => Wait::None,
            TState::Recv(_) => Wait::Receive,
            TState::Call(_) => Wait::Call,
            TState::Fault(k) => fault_kind(k).0,
            TState::Other => match old {
                Wait::FaultSend | Wait::TestSleep => old,
                w => panic!(
                    "thread {:#x} starts a wait the kernel keeps from {w:?}; the kernel sets it first",
                    t.0
                ),
            },
        };
        let waiting = match rec.state {
            TState::Recv(r) | TState::Call(r) => r.0,
            _ => 0,
        };
        t.with(|b| {
            let s = &mut b.s;
            s.wait = wait as u8;
            s.waiting_reply = waiting;
            s.sc = rec.sc.map_or(0, |c| c.0);
            s.home = rec.home.map_or(0, |c| c.0);
            s.serving_reply = rec.serving.map_or(0, |r| r.0);
            s.result = res_num(rec.result);
            // A dead thread is never resumed again.
            if rec.suspended || s.flags & flag::DEAD != 0 {
                s.flags &= !flag::RESUMED;
            } else {
                s.flags |= flag::RESUMED;
            }
            if old.is_call() && wait == Wait::None && rec.result != Res::None {
                b.ctx.x[0] = ended(rec.result) as u64;
            }
        });
        if old != Wait::None
            && wait == Wait::None
            && let Some(c) = rec.sc.map(|c| Sc(c.0))
            && c.is_configured()
        {
            let now = crate::timer::now();
            c.refills(|r| r.unblock(now));
        }
    }

    fn reply(&self, r: d::Reply) -> ReplyRec {
        let o = Rp(r.0).get();
        ReplyRec {
            state: rstate(o.word),
            caller: nz(o.caller).map(d::Tcb),
            server: nz(o.server).map(d::Tcb),
            sc: nz(o.sc).map(d::Sc),
            seq: o.seq,
            prev: nz(o.prev).map(d::Reply),
            next: nz(o.next).map(d::Reply),
            badge: o.badge,
        }
    }

    /// Writes the record back, keeping the work-list bits of word 0.
    fn set_reply(&mut self, r: d::Reply, rec: ReplyRec) {
        Rp(r.0).with(|o| {
            o.word = (o.word & !reply_word::STATE) | rstate_num(rec.state);
            o.caller = rec.caller.map_or(0, |t| t.0);
            o.server = rec.server.map_or(0, |t| t.0);
            o.sc = rec.sc.map_or(0, |c| c.0);
            o.seq = rec.seq;
            o.prev = rec.prev.map_or(0, |q| q.0);
            o.next = rec.next.map_or(0, |q| q.0);
            o.badge = rec.badge;
        });
    }

    fn sc(&self, c: d::Sc) -> ScRec {
        let h = Sc(c.0).header();
        ScRec {
            holder: nz(h.holder).map(d::Tcb),
            home: nz(h.home).map(d::Tcb),
            top: nz(h.top).map(d::Reply),
            badge: h.badge,
        }
    }

    fn set_sc(&mut self, c: d::Sc, rec: ScRec) {
        Sc(c.0).with(|h| {
            h.holder = rec.holder.map_or(0, |t| t.0);
            h.home = rec.home.map_or(0, |t| t.0);
            h.top = rec.top.map_or(0, |r| r.0);
            h.badge = rec.badge;
        });
    }

    fn walk_node(&self, r: d::Reply) -> WalkNode {
        let o = Rp(r.0).get();
        WalkNode {
            links: Links {
                left: o.left,
                right: o.right,
                parent: o.parent & !1,
                red: o.parent & 1 != 0,
            },
            hi: o.hi,
            max_hi: o.max_hi,
        }
    }

    fn set_walk_node(&mut self, r: d::Reply, n: WalkNode) {
        Rp(r.0).with(|o| {
            o.left = n.links.left;
            o.right = n.links.right;
            o.parent = n.links.parent | n.links.red as u64;
            o.hi = n.hi;
            o.max_hi = n.max_hi;
        });
    }

    fn walk_root(&self) -> u64 {
        WALK_ROOT.load(Ordering::Relaxed)
    }

    fn set_walk_root(&mut self, root: u64) {
        WALK_ROOT.store(root, Ordering::Relaxed);
    }

    fn next_seq(&mut self) -> u64 {
        SEQ.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Ends a wait the kernel keeps (K17): a test sleep needs nothing more,
    /// since its deadline leaves its tree when the wait ends; a fault send
    /// on the fault endpoint is withdrawn from it (K50), and the thread
    /// raises the fault again when it re-executes. C14's endpoint and
    /// eventcount waits, C15's page wait and C16's memory request add their
    /// cancels here.
    fn cancel_other(&mut self, t: d::Tcb) {
        let t = Tcb(t.0);
        if t.wait() == Wait::FaultSend {
            let ep = t.slot_cap(Binding::FaultEndpoint.thread_slot());
            fault::seam::withdraw_fault(&ep, t);
        }
    }

    fn withdraw_fault(&mut self, t: d::Tcb, _kind: FaultKind) {
        let t = Tcb(t.0);
        let ep = t.slot_cap(Binding::TimeoutEndpoint.thread_slot());
        fault::seam::withdraw_fault(&ep, t);
    }

    /// A timeout fault carries the badge and the counts its context has
    /// used; a context-withdrawn fault, the withdrawn context's badge
    /// (kernel specification, "Fault delivery").
    fn send_fault(&mut self, t: d::Tcb, kind: FaultKind, badge: u64) {
        let t = Tcb(t.0);
        let (_, k) = fault_kind(kind);
        let used = match (kind, t.sc()) {
            (FaultKind::Timeout, Some(c)) => c.with(|h| h.consumed),
            _ => 0,
        };
        let pc = t.with(|b| b.ctx.pc);
        t.update(|s| {
            s.fault = FaultRecord {
                kind: k as u64,
                esr: 0,
                pc,
                addr: badge,
                extra: used,
            }
        });
        let ep = t.slot_cap(Binding::TimeoutEndpoint.thread_slot());
        fault::seam::queue_fault(&ep, t);
    }

    /// A deadline belongs to a system call's wait: when that wait ends,
    /// whether the thread is then ready or sending a fault, as a walk
    /// leaves a stranded server, its deadline leaves its tree.
    fn changed(&mut self, t: d::Tcb) {
        let t = Tcb(t.0);
        if !t.wait().is_call() {
            run::deadline_remove(t);
        }
        run::place(t);
    }

    /// A walk goes on the work list of the core that starts it (K24).
    fn walk_queued(&mut self, cursor: d::Reply) {
        let c = this_core();
        let core = c.index as u64;
        c.work.push_back(&mut Replies, walk_item(cursor.0));
        Rp(cursor.0).with(|o| {
            o.word = (o.word & !reply_word::CORE) | core << reply_word::CORE_SHIFT;
        });
    }

    fn walk_moved(&mut self, from: d::Reply, to: d::Reply) {
        let core = list_core(from.0);
        super::percore::core(core)
            .work
            .replace(&mut Replies, walk_item(from.0), walk_item(to.0));
        Rp(to.0).with(|o| {
            o.word = (o.word & !reply_word::CORE) | (core as u64) << reply_word::CORE_SHIFT;
        });
    }

    fn walk_ended(&mut self, cursor: d::Reply) {
        let core = list_core(cursor.0);
        super::percore::core(core)
            .work
            .remove(&mut Replies, walk_item(cursor.0));
    }

    fn observe(&mut self, _step: Step) {
        #[cfg(aspis_test_build)]
        STEPS[step_index(_step)].fetch_add(1, Ordering::Relaxed);
    }
}

/// The index of a step's kind in [`STEPS`].
#[cfg(aspis_test_build)]
pub const fn step_index(s: Step) -> usize {
    match s {
        Step::Recv(..) => 0,
        Step::Call(..) => 1,
        Step::Reply(..) => 2,
        Step::ReplyRecv(..) => 3,
        Step::Cancel(..) => 4,
        Step::Deadline(..) => 5,
        Step::Wait(..) => 6,
        Step::BudgetOut(..) => 7,
        Step::FaultReplied(..) => 8,
        Step::Suspend(..) => 9,
        Step::Resume(..) => 10,
        Step::SetTep(..) => 11,
        Step::BindSc(..) => 12,
        Step::UnbindSc(..) => 13,
        Step::WalkStep(..) => 14,
        Step::DestroyThread(..) => 15,
        Step::DestroyReply(..) => 16,
        Step::DestroySc(..) => 17,
    }
}

/// How many steps of `s`'s kind were taken (test builds).
#[cfg(aspis_test_build)]
pub fn steps(s: Step) -> u64 {
    STEPS[step_index(s)].load(Ordering::Relaxed)
}

/// A walk's cursor, as a work-list item.
fn walk_item(r: u64) -> Tagged {
    match Tagged::new(r, Tagged::WALK) {
        Some(t) => t,
        None => panic!("reply object {r:#x} isn't aligned"),
    }
}

/// The core whose work list holds the walk at `r`.
fn list_core(r: u64) -> usize {
    let w = Rp(r).with(|o| o.word);
    assert!(
        w & reply_word::QUEUED != 0,
        "reply object {r:#x} isn't on a work list"
    );
    ((w & reply_word::CORE) >> reply_word::CORE_SHIFT) as usize
}

/// The reply objects' work-list links.
pub struct Replies;

impl WorkStore for Replies {
    fn wlinks(&self, item: Tagged) -> WLinks {
        let o: ReplyObj = Rp(item.addr()).get();
        WLinks {
            next: o.wnext,
            prev: o.wprev,
            queued: o.word & reply_word::QUEUED != 0,
        }
    }

    fn set_wlinks(&mut self, item: Tagged, l: WLinks) {
        Rp(item.addr()).with(|o| {
            o.wnext = l.next;
            o.wprev = l.prev;
            if l.queued {
                o.word |= reply_word::QUEUED;
            } else {
                o.word &= !reply_word::QUEUED;
            }
        });
    }
}

// ---------------------------------------------------------------------------
// The seams (module docs). Each runs one of the protocol's operations; a
// `ksched::donation::Error` changes nothing.

fn t(x: Tcb) -> d::Tcb {
    d::Tcb(x.0)
}

fn r(x: Rp) -> d::Reply {
    d::Reply(x.0)
}

/// `thread` waits to receive a call, with reply object `reply`.
pub fn recv(thread: Tcb, reply: Rp) -> Result<(), Error> {
    d::recv(&mut KStore::begin(), t(thread), r(reply))
}

/// `caller`, which holds a context, calls `server`, which waits to
/// receive. A passive server gets the caller's context (ADR 0051, rule 3).
/// The server's receive ends with x0 = 0 and x1 = `msg`, the stand-in for
/// C14's message.
pub fn call(caller: Tcb, server: Tcb, msg: u64) -> Result<Delivered, Error> {
    let out = d::call(&mut KStore::begin(), t(caller), t(server))?;
    server.with(|b| {
        b.ctx.x[0] = Ended::Done as u64;
        b.ctx.x[1] = msg;
    });
    Ok(out)
}

/// `thread` replies on `reply`: the caller's call ends with x0 = 0 and x1
/// = `msg`, and a donated context goes back to it.
pub fn reply(thread: Tcb, reply: Rp, msg: u64) -> Result<(), Error> {
    let caller = Rp(reply.0).with(|o| o.caller);
    d::reply(&mut KStore::begin(), t(thread), r(reply))?;
    if caller != 0 {
        Tcb(caller).with(|b| b.ctx.x[1] = msg);
    }
    Ok(())
}

/// A passive server's loop: a reply on `reply`, if there is a call to
/// answer, then a receive with it. The reply's result is returned; the
/// receive happens if the reply object is then free.
pub fn reply_recv(thread: Tcb, reply: Rp, msg: u64) -> Result<(), Error> {
    let caller = Rp(reply.0).with(|o| o.caller);
    let out = d::reply_recv(&mut KStore::begin(), t(thread), r(reply));
    if out.is_ok() && caller != 0 {
        Tcb(caller).with(|b| b.ctx.x[1] = msg);
    }
    out
}

/// Stalls the thread that holds context `c`, if it runs on another core,
/// before the context is taken from it (kernel specification, "Cross-core
/// signals and TLB maintenance"): its time there is charged first.
fn stall_holder(c: u64) {
    if c != 0 {
        let h = Sc(c).header().holder;
        if h != 0 {
            crate::smp::remote::stall(Tcb(h));
        }
    }
}

/// Stalls the holder of the context `thread` lent in the call it waits in,
/// if any: a take-back moves that context.
fn stall_for_call(thread: Tcb) {
    let r = thread.state().waiting_reply;
    if r != 0 && thread.wait() == Wait::Call {
        stall_holder(Rp(r).get().sc);
    }
}

/// Ends `thread`'s wait with "canceled": a delivered donating call's
/// context comes back at once, and the walk follows in batches (ADR 0051,
/// rule 3).
pub fn cancel(thread: Tcb) -> Result<(), Error> {
    stall_for_call(thread);
    d::cancel(&mut KStore::begin(), t(thread))
}

/// `thread`'s deadline passed, inside a batch: as a cancel, "timed out".
pub fn deadline(thread: Tcb) -> Result<(), Error> {
    stall_for_call(thread);
    d::deadline(&mut KStore, t(thread))
}

/// One step of the walk at the front of this core's work list, inside a
/// batch. False if the list is empty.
pub fn walk_step() -> bool {
    let Some(item) = this_core().work.front() else {
        return false;
    };
    match item.tag() {
        Tagged::WALK => {
            d::walk_step(&mut KStore, d::Reply(item.addr()));
        }
        tag => panic!("work-list item {:#x} has tag {tag}", item.addr()),
    }
    true
}

/// `thread`, running, starts a wait the kernel keeps, which the kernel has
/// set already ([`KStore::cancel_other`]).
pub fn wait_other(thread: Tcb) {
    d::wait_other(&mut KStore, t(thread));
}

/// `thread`'s budget ran out: with a timeout endpoint it sends a timeout
/// fault, donating nothing (ADR 0051, rule 1). False, changing nothing,
/// without one.
pub fn budget_out(thread: Tcb) -> bool {
    d::budget_out(&mut KStore, t(thread))
}

/// The handler replied to `thread`'s timeout or context-withdrawn fault.
pub fn fault_replied(thread: Tcb) -> Result<(), Error> {
    d::fault_replied(&mut KStore, t(thread))
}

/// Suspends or resumes `thread`: the flag only; its wait stays (ADR 0061,
/// rule 3).
pub fn set_suspended(thread: Tcb, on: bool) {
    d::set_suspended(&mut KStore::begin(), t(thread), on);
}

/// `thread`'s timeout endpoint is being removed (K08): a fault queued on it
/// is withdrawn (K50).
pub fn timeout_endpoint_removed(thread: Tcb) {
    d::set_tep(&mut KStore, t(thread), false);
}

/// Binds `c` to `thread` as its home context. Refused while either is
/// bound, the thread holds a context, or it serves a donated call.
pub fn bind(c: Sc, thread: Tcb) -> Result<(), Error> {
    d::bind_sc(&mut KStore::begin(), d::Sc(c.0), t(thread))
}

/// Unbinds `c` from its home thread, taking a donated context back first.
pub fn unbind(c: Sc) -> Result<(), Error> {
    stall_holder(c.0);
    d::unbind_sc(&mut KStore::begin(), d::Sc(c.0))
}

/// `thread`'s object becomes a zombie: the donated call it serves
/// goes back to its caller, its own wait ends, and its home context is
/// unbound.
pub fn destroy_thread(thread: Tcb) {
    stall_for_call(thread);
    stall_holder(thread.state().home);
    d::destroy_thread(&mut KStore::begin(), t(thread));
}

/// The reply object's last capability is gone.
pub fn destroy_reply(reply: Rp) {
    if reply.get().word & reply_word::STATE == rstate_num(RState::Pending) {
        stall_holder(reply.get().sc);
    }
    d::destroy_reply(&mut KStore::begin(), r(reply));
}

/// The context's last capability is gone. Its pending walks go on without
/// it: they only compare its address.
pub fn destroy_sc(c: Sc) {
    stall_holder(c.0);
    d::destroy_sc(&mut KStore::begin(), d::Sc(c.0));
}

/// Whether the walk tree is empty: no take-back is still being walked.
pub fn no_walks() -> bool {
    WALK_ROOT.load(Ordering::Relaxed) == 0
}

/// Checks the protocol's invariants over the objects given (test builds;
/// kernel specification, "Model checking").
#[cfg(aspis_test_build)]
pub fn check(threads: &[Tcb], replies: &[Rp], scs: &[Sc]) -> Result<(), d::Violation> {
    // At most 512 of each, on the stack: for tests.
    const MAX: usize = 512;
    assert!(threads.len() <= MAX && replies.len() <= MAX && scs.len() <= MAX);
    let mut ts = [d::Tcb(0); MAX];
    let mut rs = [d::Reply(0); MAX];
    let mut cs = [d::Sc(0); MAX];
    for (i, x) in threads.iter().enumerate() {
        ts[i] = t(*x);
    }
    for (i, x) in replies.iter().enumerate() {
        rs[i] = r(*x);
    }
    for (i, x) in scs.iter().enumerate() {
        cs[i] = d::Sc(x.0);
    }
    d::check(
        &mut KStore,
        &ts[..threads.len()],
        &rs[..replies.len()],
        &cs[..scs.len()],
    )
}

/// Whether `reply` is a live donating reply, on its context's stack.
#[cfg(aspis_test_build)]
pub fn is_live(reply: Rp) -> bool {
    d::is_live(&mut KStore, r(reply))
}

/// The protocol's view of `reply` (test builds).
#[cfg(aspis_test_build)]
pub fn reply_rec(reply: Rp) -> ReplyRec {
    KStore.reply(r(reply))
}

/// The protocol's view of `c` (test builds).
#[cfg(aspis_test_build)]
pub fn sc_rec(c: Sc) -> ScRec {
    KStore.sc(d::Sc(c.0))
}
