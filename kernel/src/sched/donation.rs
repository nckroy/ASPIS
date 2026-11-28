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
//! **IPC.** C14's endpoints and eventcounts (`crate::ipc`) run `kipc`,
//! which runs this protocol over the same store: [`KStore`] is `kipc`'s
//! store too (`crate::ipc::store`), so a send, call, receive, reply,
//! delivery or wake is one of the protocol's steps, with the endpoint's
//! queue, the message and the capability transfer around it. The store's
//! effects reach back into `crate::ipc`: ending a wait takes the thread out
//! of its endpoint's queue and its eventcounts' trees, and a timeout or
//! context-withdrawn fault is sent on the timeout endpoint as a call.
//!
//! **Charging.** Each operation that may move a context first charges the
//! running thread's time to its context ([`run::commit_current`]), so the
//! time used before the move counts against the context that was used. A
//! holder that runs on another core is stalled there first, which charges
//! its time there (`crate::smp::remote`).
//!
//! **Mapping waits.** A thread's kernel wait ([`Wait`]) is the protocol's
//! state: a receive and a call are `Recv` and `Call` on the reply object in
//! [`super::object::SchedState::waiting_reply`]; a delivered fault is a
//! `Call` with [`flag::FAULT_DELIVERED`] set, its kind in the fault record;
//! a send or call queued on an endpoint is `Send` (C14); a fault queued on
//! the fault endpoint, and a timeout or context-withdrawn fault, is
//! `Fault`; a test sleep and C14's eventcount and wait-set waits are
//! `Other`, the waits the kernel keeps itself. C15's page wait and C16's
//! memory request join `Other`, each with its own cancel in
//! [`KStore::cancel_other`] (K17).

use super::fault::{self, Kind};
use super::object::{FaultRecord, ReplyObj, Rp, Sc, Tcb, Wait, flag, reply_word};
use super::percore::this_core;
use super::run;
use crate::ipc::store::WorkItems;
use core::sync::atomic::{AtomicU64, Ordering};
use kcap::cap::Binding;
use kipc::msg::Status;
use ksched::donation::{
    self as d, Error, FaultKind, RState, ReplyRec, Res, ScRec, Step, Store, TState, ThreadRec,
    WalkNode,
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
pub static STEPS: [AtomicU64; 23] = [const { AtomicU64::new(0) }; 23];

fn nz(v: u64) -> Option<u64> {
    (v != 0).then_some(v)
}

fn res_of(v: u8) -> Res {
    match v {
        1 => Res::Replied,
        2 => Res::Canceled,
        3 => Res::TimedOut,
        4 => Res::Destroyed,
        _ => Res::None,
    }
}

const fn res_num(r: Res) -> u8 {
    match r {
        Res::None => 0,
        Res::Replied => 1,
        Res::Canceled => 2,
        Res::TimedOut => 3,
        Res::Destroyed => 4,
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

/// The wait of a thread whose fault of kind `k` is queued.
const fn queued_wait(k: FaultKind) -> Wait {
    match k {
        FaultKind::Timeout => Wait::TimeoutSend,
        FaultKind::Withdrawn => Wait::WithdrawnSend,
        FaultKind::Endpoint => Wait::FaultSend,
    }
}

/// The kind of a delivered fault, from its record: a timeout or
/// context-withdrawn fault is the protocol's; every other is one sent on
/// the fault endpoint.
fn delivered_kind(t: Tcb) -> FaultKind {
    match Kind::from_record(t.with(|b| b.s.fault.kind)) {
        Some(Kind::Timeout) => FaultKind::Timeout,
        Some(Kind::Withdrawn) => FaultKind::Withdrawn,
        _ => FaultKind::Endpoint,
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
        let wait = Wait::from_u8(s.wait);
        let state = match wait {
            Wait::None => TState::Ready,
            Wait::Receive => TState::Recv(d::Reply(s.waiting_reply)),
            Wait::Call => TState::Call(d::Reply(s.waiting_reply)),
            Wait::Send => TState::Send,
            Wait::FaultSend => TState::Fault(FaultKind::Endpoint),
            Wait::TimeoutSend => TState::Fault(FaultKind::Timeout),
            Wait::WithdrawnSend => TState::Fault(FaultKind::Withdrawn),
            Wait::TestSleep | Wait::Eventcount | Wait::Set => TState::Other,
        };
        let delivered = wait == Wait::Call && s.flags & flag::FAULT_DELIVERED != 0;
        ThreadRec {
            state,
            sc: nz(s.sc).map(d::Sc),
            home: nz(s.home).map(d::Sc),
            serving: nz(s.serving_reply).map(d::Reply),
            result: res_of(s.result),
            tep: fault::has_endpoint(t, Binding::TimeoutEndpoint),
            suspended: s.flags & flag::RESUMED == 0,
            fault: delivered.then(|| delivered_kind(t)),
        }
    }

    /// Writes the record back. Whether the thread has a timeout endpoint is
    /// its slot 4's, which only the endpoint's binding changes, so `tep` is
    /// read, never written; a delivered fault's kind is its fault record's,
    /// so only the flag that says it was delivered is written. A wait that
    /// ends writes its result into a system call's x0 at once (K20), unless
    /// it ends with no result (a restart, or a fault's resume), and lets a
    /// ready head refill count from now, as seL4's `refill_unblock_check`.
    fn set_thread(&mut self, t: d::Tcb, rec: ThreadRec) {
        let t = Tcb(t.0);
        let old = Wait::from_u8(t.with(|b| b.s.wait));
        let wait = match rec.state {
            TState::Ready => Wait::None,
            TState::Recv(_) => Wait::Receive,
            TState::Call(_) => Wait::Call,
            TState::Send => Wait::Send,
            TState::Fault(k) => queued_wait(k),
            TState::Other => match old {
                Wait::TestSleep | Wait::Eventcount | Wait::Set => old,
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
            if rec.fault.is_some() {
                s.flags |= flag::FAULT_DELIVERED;
            } else {
                s.flags &= !flag::FAULT_DELIVERED;
            }
            // A call that had been delivered says so when it ends canceled,
            // timed out or "object destroyed" (K30); a queued one doesn't.
            if old.is_call() && wait == Wait::None && rec.result != Res::None {
                b.ctx.x[0] = Status::of_res(rec.result).word(old == Wait::Call);
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

    /// Takes the thread out of what the kernel keeps for its wait (K17): a
    /// send, a receive, an eventcount or a wait-set wait leaves its
    /// endpoint's queue or its eventcounts' trees (C14's IPC); a test sleep
    /// needs nothing more, since its deadline leaves its tree when the wait
    /// ends. C15's page wait and C16's memory request add their cancels
    /// here.
    fn cancel_other(&mut self, t: d::Tcb) {
        let t = Tcb(t.0);
        match t.wait() {
            Wait::Send | Wait::Receive | Wait::Eventcount | Wait::Set => crate::ipc::cancel_wait(t),
            _ => {}
        }
    }

    /// A queued fault leaves its endpoint's queue (K50): the fault
    /// endpoint's, or the timeout endpoint's. The thread goes on as its
    /// fault's kind allows: a faulting instruction re-executes, and faults
    /// again if its cause remains.
    fn withdraw_fault(&mut self, t: d::Tcb, _kind: FaultKind) {
        crate::ipc::fault::withdraw(Tcb(t.0));
    }

    fn wait_cost(&self, t: d::Tcb) -> u32 {
        crate::ipc::wait_cost(Tcb(t.0))
    }

    /// A timeout fault carries the badge and the counts its context has
    /// used; a context-withdrawn fault, the withdrawn context's badge
    /// (kernel specification, "Fault delivery").
    fn send_fault(&mut self, t: d::Tcb, kind: FaultKind, badge: u64) {
        let t = Tcb(t.0);
        let k = match kind {
            FaultKind::Timeout => Kind::Timeout,
            FaultKind::Withdrawn => Kind::Withdrawn,
            // A fault on the fault endpoint is the kernel's to raise, with
            // its record ([`fault::raise`]), never the protocol's.
            FaultKind::Endpoint => return,
        };
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
        crate::ipc::fault::send_timeout(t);
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
        c.work.push_back(&mut WorkItems, walk_item(cursor.0));
        Rp(cursor.0).with(|o| {
            o.word = (o.word & !reply_word::CORE) | core << reply_word::CORE_SHIFT;
        });
    }

    fn walk_moved(&mut self, from: d::Reply, to: d::Reply) {
        let core = list_core(from.0);
        super::percore::core(core)
            .work
            .replace(&mut WorkItems, walk_item(from.0), walk_item(to.0));
        Rp(to.0).with(|o| {
            o.word = (o.word & !reply_word::CORE) | (core as u64) << reply_word::CORE_SHIFT;
        });
    }

    fn walk_ended(&mut self, cursor: d::Reply) {
        let core = list_core(cursor.0);
        super::percore::core(core)
            .work
            .remove(&mut WorkItems, walk_item(cursor.0));
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
        Step::SendWait(..) => 18,
        Step::FaultWait(..) => 19,
        Step::DeliverCall(..) => 20,
        Step::DeliverSend(..) => 21,
        Step::Wake(..) => 22,
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

/// The reply objects' work-list links: a walk's cursor's. A list holds
/// eventcounts too, so lists are run through `crate::ipc::store::WorkItems`,
/// which passes a reply object's links here.
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

/// The units ending `thread`'s wait takes, for the batch's deadline units
/// (K24): its own wait's, and the holder's for a donated call's take-back.
pub fn end_cost(thread: Tcb) -> u32 {
    d::end_cost(&mut KStore, t(thread))
}

/// The units the next unit of this core's work list costs (K24): a walk's
/// step, one and the server's onward call it ends, or an eventcount's wake,
/// one or the nodes of a wait set. 0 if the list is empty.
pub fn work_cost() -> u32 {
    let Some(item) = this_core().work.front() else {
        return 0;
    };
    match item.tag() {
        Tagged::WALK => d::step_cost(&mut KStore, d::Reply(item.addr())),
        Tagged::EVENTCOUNT => crate::ipc::eventcount::unit_cost(item.addr()),
        tag => panic!("work-list item {:#x} has tag {tag}", item.addr()),
    }
}

/// One unit of this core's work list, inside a batch: a step of a walk, or
/// one wake of an eventcount's (K24). The list's first item moves to its
/// back first, so its walks and eventcounts share the units in turn, each
/// in its own order; an item whose work is done leaves the list in its
/// unit, wherever it is. False if the list is empty.
pub fn work_unit() -> bool {
    let Some(item) = this_core().work.front() else {
        return false;
    };
    // The cost the batch took was this item's: rotating keeps it the one
    // that runs.
    let list = &mut this_core().work;
    list.remove(&mut WorkItems, item);
    list.push_back(&mut WorkItems, item);
    match item.tag() {
        Tagged::WALK => {
            this_core().stats.walk_steps += 1;
            d::walk_step(&mut KStore, d::Reply(item.addr()));
        }
        Tagged::EVENTCOUNT => {
            this_core().stats.ec_units += 1;
            crate::ipc::eventcount::work_unit(item.addr());
        }
        tag => panic!("work-list item {:#x} has tag {tag}", item.addr()),
    }
    true
}

/// Ends `thread`'s wait on an endpoint, which the kernel has taken it out
/// of, with `res`: the protocol's `Wake`. A queued fault ends with no
/// result, so the thread goes on as its fault's kind allows.
pub fn wake(thread: Tcb, res: Res) -> Result<(), Error> {
    d::wake(&mut KStore, t(thread), res)
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

/// The units unbinding `c` takes (K23): a donated context's take-back
/// ends its holder's wait.
pub fn unbind_cost(c: Sc) -> u32 {
    d::unbind_cost(&mut KStore, d::Sc(c.0))
}

/// `thread`'s object becomes a zombie: the donated call it serves
/// goes back to its caller, its own wait ends, and its home context is
/// unbound. Returns the units it took (K23).
pub fn destroy_thread(thread: Tcb) -> u32 {
    stall_for_call(thread);
    stall_holder(thread.state().home);
    let units = d::destroy_cost(&mut KStore, t(thread));
    d::destroy_thread(&mut KStore::begin(), t(thread));
    units
}

/// The reply object's last capability is gone. Returns the units it took
/// (K23).
pub fn destroy_reply(reply: Rp) -> u32 {
    if reply.get().word & reply_word::STATE == rstate_num(RState::Pending) {
        stall_holder(reply.get().sc);
    }
    let units = d::destroy_reply_cost(&mut KStore, r(reply));
    d::destroy_reply(&mut KStore::begin(), r(reply));
    units
}

/// The context's last capability is gone. Its pending walks go on without
/// it: they only compare its address. Returns the units it took (K23).
pub fn destroy_sc(c: Sc) -> u32 {
    stall_holder(c.0);
    let units = d::unbind_cost(&mut KStore, d::Sc(c.0));
    d::destroy_sc(&mut KStore::begin(), d::Sc(c.0));
    units
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
