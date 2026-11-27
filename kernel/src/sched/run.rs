// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The scheduler's core: run queues, the release and deadline trees,
//! charging, where a thread belongs, the exit path and the tickless timer
//! (ADR 0051, rules 1, 2 and 5; ADR 0052, rules 2 and 3; kernel
//! specification, "Scheduling contexts and budgets", "Priorities and bands",
//! "The timer and deadlines" and "Ordered kernel queues").
//!
//! **Where a thread belongs.** A thread is *eligible* when it is resumed,
//! not dead, not waiting, has a root CNode and an address space, and holds
//! a configured scheduling context. An eligible thread whose context has a
//! sufficient refill now is in its context's core's run queue, or running
//! there; one whose context has none waits with its context in the core's
//! release tree. [`place`] puts a thread where it belongs after any change.
//! The running thread is in no queue, as in seL4. Deleting a copy in slot 1
//! or 2 isn't such a change, as they are plain copies with no unbind step,
//! so the choice of thread checks a queued thread again before it runs it.
//!
//! **Charging**, as seL4 MCS commits time: the running thread's time since
//! its dispatch is charged to its context when it stops running, and when
//! its budget ends, which the timer is programmed for. A preempted thread
//! keeps its turn at the front of its queue; one whose head refill ran out
//! goes as `endTimeslice` says ([`end_timeslice`]), even when its next
//! refill is ready ([`Stop::BudgetEnd`]). An operation that may move
//! a context away from the running thread charges it first
//! ([`commit_current`]), as seL4's `commitTime`. Kernel time on a thread's
//! behalf is charged to it, as in seL4, except a batch's, which is charged
//! to no context (kernel specification, "Scheduling contexts and budgets"): one job's mass deadlines must not
//! spend another job's budget (ADR 0058, rule 8).
//!
//! **The exit path** ([`exit`]) runs at the end of every kernel entry from
//! EL0, and from the idle loop, with the kernel lock held: the budget check; one batch of interrupt
//! work, at most [`ksched::BATCH_UNITS`] units, drawn in turn from the
//! core's release tree, deadline tree and work list of walks
//! (`ksched::batch`), the rest left for the next exit with the compare
//! value at most 100 µs ahead (K24); the budget check again, since the
//! batch's commit can use the budget up; the choice of thread; the timer;
//! then the return to EL0, or idle, each of which releases the lock. The
//! core doesn't idle while batch work is left: with nothing to run, it
//! gives the lock up and takes it again between batches, so the lock is
//! held one batch at a time (ADR 0052, rule 2).
//!
//! **Other cores.** Each core runs threads from its own run queues, and
//! keeps its own release and deadline trees and work list. A thread made
//! ready on another core, above what runs there, and an entry in another
//! core's trees, mark that core to get SGI 1 when the lock is released.

use super::object::{Sc, Tcb, Wait, flag, sc_flag};
use super::percore::{self, this_core};
use crate::mm::space::AddressSpace;
use crate::timer;
use kcap::cap::Cap;
use ksched::batch::Sources;
use ksched::refill::Charged;
use ksched::runq::{QLinks, QueueStore};
use ksched::time::{self, Clock, Wakeups};
use ksched::tree::{self, Links, TreeStore};

/// The least amount of a refill worth dispatching a thread for: 5 µs, half
/// the shortest budget (seL4's `MIN_BUDGET` is twice its kernel's
/// worst-case execution time).
pub const MIN_DISPATCH_US: u64 = 5;

/// The `SPSR_EL1` a thread returns to EL0 with: EL0t, FIQs masked (the
/// kernel never uses them), IRQs, SErrors and debug exceptions unmasked
/// (K77, K70). Only the bits EL0 owns come from the thread.
pub const SPSR_EL0: u64 = 1 << 6;
/// The condition flags, N, Z, C and V: all a register write may set.
pub const SPSR_NZCV: u64 = 0xf000_0000;
/// The PSTATE bits EL0 owns that the hardware saved at the entry, kept on
/// the return: the condition flags, DIT (bit 24), SSBS (bit 12) and BTYPE
/// (bits 11:10), so a thread that set DIT, or was interrupted between a
/// branch and its landing pad, keeps it.
pub const SPSR_FROM_EL0: u64 = SPSR_NZCV | 1 << 24 | 1 << 12 | 0b11 << 10;

/// The virtual counter's frequency, as a [`Clock`].
pub fn clock() -> Clock {
    match Clock::new(timer::frequency()) {
        Some(c) => c,
        None => panic!("CNTFRQ_EL0 is 0"),
    }
}

/// Threads' run-queue links.
pub struct Threads;

impl QueueStore for Threads {
    fn qlinks(&self, t: u64) -> QLinks {
        Tcb(t).with(|b| b.s.q)
    }
    fn set_qlinks(&mut self, t: u64, l: QLinks) {
        Tcb(t).update(|s| s.q = l);
    }
}

/// The deadline tree's nodes: threads, keyed by (deadline, address).
pub struct Deadlines;

impl TreeStore for Deadlines {
    type Key = (u64, u64);
    fn key(&self, n: u64) -> (u64, u64) {
        (Tcb(n).with(|b| b.s.deadline), n)
    }
    fn links(&self, n: u64) -> Links {
        Tcb(n).with(|b| b.s.dl)
    }
    fn set_links(&mut self, n: u64, l: Links) {
        Tcb(n).update(|s| s.dl = l);
    }
}

/// The release tree's nodes: contexts, keyed by (release time, address).
pub struct Releases;

impl TreeStore for Releases {
    type Key = (u64, u64);
    fn key(&self, n: u64) -> (u64, u64) {
        (Sc(n).with(|h| h.release), n)
    }
    fn links(&self, n: u64) -> Links {
        Sc(n).with(|h| h.rl)
    }
    fn set_links(&mut self, n: u64, l: Links) {
        Sc(n).with(|h| h.rl = l);
    }
}

/// Whether the thread has a root CNode and an address space: its slots 1
/// and 2. They are plain copies, not bindings, so the kernel checks them
/// here, each time it decides where the thread belongs.
fn has_spaces(t: Tcb) -> bool {
    matches!(t.slot_cap(1), Cap::CNode { .. }) && matches!(t.slot_cap(2), Cap::AddressSpace { .. })
}

/// Whether the thread may run once its context has budget (module docs).
pub fn eligible(t: Tcb) -> bool {
    let s = t.state();
    s.flags & flag::RESUMED != 0
        && s.flags & flag::DEAD == 0
        && Wait::from_u8(s.wait) == Wait::None
        && s.sc != 0
        && Sc(s.sc).is_configured()
        && has_spaces(t)
}

/// The core whose queues the thread uses (K18): the core of the context it
/// runs on; else, while it lent its own away in a call, its own context's;
/// else the core it last ran on, as for a passive server waiting to
/// receive.
fn core_of(t: Tcb) -> usize {
    match (t.sc(), t.home()) {
        (Some(sc), _) if sc.is_configured() => sc.with(|h| h.core) as usize,
        (_, Some(h)) if h.is_configured() => h.with(|h| h.core) as usize,
        _ => t.with(|b| b.s.core) as usize,
    }
}

/// Puts `t` at the back of its priority's queue, if it isn't queued.
pub fn enqueue_back(t: Tcb) {
    enqueue(t, false);
}

/// Puts `t` at the front, as a preempted thread keeps its turn.
pub fn enqueue_front(t: Tcb) {
    enqueue(t, true);
}

fn enqueue(t: Tcb, front: bool) {
    if t.has(flag::QUEUED) {
        return;
    }
    let core = core_of(t);
    let me = percore::index();
    let c = percore::core(core);
    let p = t.priority();
    if front {
        c.runq.push_front(&mut Threads, p, t.0);
    } else {
        c.runq.push_back(&mut Threads, p, t.0);
    }
    // Another core reschedules if the thread outranks what runs there, or
    // it idles: SGI 1 at the lock's release (kernel specification,
    // "Cross-core signals and TLB maintenance").
    if core != me && (c.current == 0 || p > Tcb(c.current).priority()) {
        crate::smp::lock::mark_resched(core);
    }
    t.update(|s| {
        s.flags |= flag::QUEUED;
        s.core = core as u8;
    });
}

/// Takes `t` out of its run queue, if it is queued.
pub fn dequeue(t: Tcb) {
    if !t.has(flag::QUEUED) {
        return;
    }
    let (p, core) = t.with(|b| (b.s.priority, b.s.core));
    percore::core(core as usize)
        .runq
        .remove(&mut Threads, p, t.0);
    t.set(flag::QUEUED, false);
}

/// Puts `sc` in its core's release tree, keyed by its head refill's time,
/// but never at or before `now`, so a release is never due the moment it
/// is made.
pub fn release_insert(sc: Sc, now: u64) {
    release_remove(sc);
    let at = sc.refills(|r| r.head().time).max(now.saturating_add(1));
    let core = sc.with(|h| {
        h.release = at;
        h.flags |= sc_flag::RELEASE;
        h.core
    });
    let c = percore::core(core as usize);
    tree::insert(&mut Releases, &mut c.release_root, sc.0);
    // That core programs its timer for it (K24).
    crate::smp::lock::mark_resched(core as usize);
}

/// Takes `sc` out of its core's release tree, if it is there.
pub fn release_remove(sc: Sc) {
    let (inside, core) = sc.with(|h| (h.flags & sc_flag::RELEASE != 0, h.core));
    if !inside {
        return;
    }
    let c = percore::core(core as usize);
    tree::remove(&mut Releases, &mut c.release_root, sc.0);
    sc.with(|h| h.flags &= !sc_flag::RELEASE);
}

/// Queues `t`'s deadline in its core's deadline tree. The deadline stays in
/// that core's tree until the wait ends (K18).
pub fn deadline_insert(t: Tcb, deadline: u64) {
    deadline_remove(t);
    let core = core_of(t);
    t.update(|s| {
        s.deadline = deadline;
        s.flags |= flag::DEADLINE;
        s.core = core as u8;
    });
    let c = percore::core(core);
    tree::insert(&mut Deadlines, &mut c.deadline_root, t.0);
    crate::smp::lock::mark_resched(core);
}

/// Takes `t`'s deadline out of its tree, if it has one.
pub fn deadline_remove(t: Tcb) {
    if !t.has(flag::DEADLINE) {
        return;
    }
    let core = t.with(|b| b.s.core);
    let c = percore::core(core as usize);
    tree::remove(&mut Deadlines, &mut c.deadline_root, t.0);
    t.update(|s| {
        s.flags &= !flag::DEADLINE;
        s.deadline = 0;
    });
}

/// Puts `t` where it belongs after a change to its state, its context, its
/// slots or its priority (module docs).
pub fn place(t: Tcb) {
    let c = this_core();
    if c.current == t.0 {
        if !eligible(t) {
            stop_current(Stop::Blocked);
        }
        return;
    }
    // Running on another core: a change that matters there stalls it first
    // (`crate::smp::remote::stall`); anything else that core sees at its
    // next exit, which SGI 1 brings on.
    if let Some(k) = crate::smp::remote::running_elsewhere(t) {
        crate::smp::lock::mark_resched(k);
        return;
    }
    if !eligible(t) {
        dequeue(t);
        return;
    }
    let Some(sc) = t.sc() else { return };
    let now = timer::now();
    if sc.refills(|r| r.sufficient(now)) {
        release_remove(sc);
        enqueue_back(t);
    } else {
        dequeue(t);
        release_insert(sc, now);
    }
}

/// Why the running thread stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// A higher-priority thread runs, or the kernel stopped it to change
    /// it: it keeps its turn at the front of its queue.
    Preempted,
    /// Its head refill ran out, or a system call found less than the
    /// minimum left: its time slice ends, as seL4 17.0.0's
    /// `endTimeslice(true)`, whether or not its next refill is ready
    /// ([`end_timeslice`]).
    BudgetEnd,
    /// It yields: the rest of its head refill is charged, as seL4 MCS's
    /// yield, so it goes to the back of its queue or waits for its release.
    /// A yield never raises a timeout fault (seL4's `endTimeslice(false)`).
    Yield,
    /// It blocked, was suspended, lost its context or died.
    Blocked,
}

/// Stops the running thread: charges its time since dispatch to its
/// context, and puts it where it belongs.
pub fn stop_current(how: Stop) {
    let c = this_core();
    if c.current == 0 {
        return;
    }
    let t = Tcb(c.current);
    let now = timer::now();
    let start = c.dispatch;
    // Inside a batch, the time since the batch began is no context's.
    let used = if c.in_batch {
        0
    } else {
        now.saturating_sub(start)
    };
    c.current = 0;
    c.dispatch = now;
    if c.exhausted != 0 && t.sc().is_some_and(|sc| sc.0 == c.exhausted) {
        // A commit found the budget gone: the time since that commit is
        // charged too, and the slice ends now. The budget was gone before
        // a yield, so a timeout fault may be raised, as seL4's
        // `checkBudgetRestart` does before the call runs.
        c.exhausted = 0;
        let Some(sc) = t.sc() else { return };
        if used > 0 && sc.is_configured() {
            sc.with(|h| h.consumed = h.consumed.saturating_add(used));
            sc.refills(|r| r.charge(start, used, now));
        }
        if eligible(t) {
            end_timeslice(t, sc, true);
        }
        return;
    }
    let Some(sc) = t.sc().filter(|sc| sc.is_configured()) else {
        return;
    };
    sc.with(|h| h.consumed = h.consumed.saturating_add(used));
    let usage = match how {
        Stop::Yield => sc.refills(|r| r.head().amount).max(used),
        _ => used,
    };
    let charged = sc.refills(|r| r.charge(start, usage, now));
    if !eligible(t) {
        return;
    }
    match (charged, how) {
        (_, Stop::BudgetEnd) => end_timeslice(t, sc, true),
        (Charged::Exhausted, Stop::Yield) => end_timeslice(t, sc, false),
        (Charged::Exhausted, _) => end_timeslice(t, sc, true),
        (Charged::Ready, Stop::Preempted) => enqueue_front(t),
        (Charged::Ready, _) => {
            // Yield: the head was used up, but the next refill is ready.
            if sc.refills(|r| r.sufficient(now)) {
                enqueue_back(t);
            } else {
                release_insert(sc, now);
            }
        }
    }
}

/// Charges the running thread's time since its dispatch to its context, and
/// restarts its dispatch at `now`, so it goes on running (seL4 MCS's
/// `commitTime`). If that used the budget up, the exit path ends its time
/// slice ([`PerCore::exhausted`](super::percore::PerCore::exhausted)).
/// Nothing is charged inside a batch.
pub fn commit_current(now: u64) {
    let c = this_core();
    if c.current == 0 || c.in_batch {
        return;
    }
    let t = Tcb(c.current);
    let start = c.dispatch;
    c.dispatch = now;
    let Some(sc) = t.sc().filter(|sc| sc.is_configured()) else {
        return;
    };
    let used = now.saturating_sub(start);
    sc.with(|h| h.consumed = h.consumed.saturating_add(used));
    if sc.refills(|r| r.charge(start, used, now)) == Charged::Exhausted {
        this_core().exhausted = sc.0;
    }
}

/// Whether the running thread `t`'s budget still holds at `now`, with at
/// least the minimum left: a system call goes ahead only then, and is made
/// again after the refill otherwise (seL4's `checkBudgetRestart`).
pub fn budget_holds(t: Tcb, now: u64) -> bool {
    let c = this_core();
    if c.current != t.0 {
        return false;
    }
    let (dispatch, exhausted) = (c.dispatch, c.exhausted);
    match t.sc().filter(|sc| sc.is_configured() && sc.0 != exhausted) {
        Some(sc) => sc.refills(|r| {
            r.ready(dispatch) && r.budget_end(dispatch).saturating_sub(now) >= r.st.min_budget
        }),
        None => false,
    }
}

/// `t`'s time slice ended (seL4 17.0.0's `endTimeslice`): round-robin
/// goes to the back of its queue with its budget refilled whole; when
/// `can_fault`, a thread with a timeout endpoint sends a timeout fault,
/// which donates nothing, and waits for its handler's reply; any other goes
/// to the back of its queue if a sufficient refill is ready, else waits for
/// its context's next refill (ADR 0051, rule 1). A yield passes false.
fn end_timeslice(t: Tcb, sc: Sc, can_fault: bool) {
    let now = timer::now();
    this_core().stats.exhausted += 1;
    if sc.refills(|r| r.is_round_robin()) {
        enqueue_back(t);
        return;
    }
    if can_fault && super::donation::budget_out(t) {
        this_core().stats.timeouts += 1;
        return;
    }
    if sc.refills(|r| r.sufficient(now)) {
        enqueue_back(t);
    } else {
        release_insert(sc, now);
    }
}

/// Makes `t` the running thread.
fn dispatch(t: Tcb, now: u64) {
    let c = this_core();
    c.current = t.0;
    c.dispatch = now;
    c.exhausted = 0;
    c.stats.switches += 1;
    let index = c.index as u8;
    t.update(|s| s.core = index);
}

/// Picks the thread to run: the running one, unless a higher priority is
/// ready, else the first of the highest priority (ADR 0051, rule 2).
///
/// A queued thread is checked again here: deleting the copy in its slot 1
/// or 2, a plain copy with no unbind step, doesn't move it, so a queued
/// thread may have stopped being eligible since it was placed. Such a
/// thread leaves its queue unrun, and the next one is taken; a new copy in
/// either slot places it again ([`super::thread::configure_space`]).
fn choose(now: u64) {
    let p = loop {
        let c = this_core();
        let Some((p, t)) = c.runq.next_to_run() else {
            return;
        };
        if eligible(Tcb(t)) {
            break p;
        }
        c.runq.remove(&mut Threads, p, t);
        Tcb(t).set(flag::QUEUED, false);
    };
    let c = this_core();
    if c.current != 0 {
        if p <= Tcb(c.current).priority() {
            return;
        }
        stop_current(Stop::Preempted);
    }
    // The eligible head found above is still first: the stopped thread
    // went back at its own, lower priority.
    let c = this_core();
    if let Some((p, t)) = c.runq.next_to_run() {
        c.runq.remove(&mut Threads, p, t);
        Tcb(t).set(flag::QUEUED, false);
        dispatch(Tcb(t), now);
    }
}

/// The sources of a core's batch (K24): the release tree, the deadline
/// tree and the work list, in that order.
struct Work {
    now: u64,
}

const RELEASES: usize = 0;
const DEADLINES: usize = 1;
const WALKS: usize = 2;

impl Work {
    fn first_release(&self) -> Option<Sc> {
        let n = tree::first(&Releases, this_core().release_root);
        (n != 0 && Sc(n).with(|h| h.release) <= self.now).then_some(Sc(n))
    }

    fn first_deadline(&self) -> Option<Tcb> {
        let n = tree::first(&Deadlines, this_core().deadline_root);
        (n != 0 && Tcb(n).with(|b| b.s.deadline) <= self.now).then_some(Tcb(n))
    }
}

impl Sources for Work {
    fn count(&self) -> usize {
        3
    }

    fn has_work(&mut self, i: usize) -> bool {
        match i {
            RELEASES => self.first_release().is_some(),
            DEADLINES => self.first_deadline().is_some(),
            WALKS => !this_core().work.is_empty(),
            _ => false,
        }
    }

    fn unit(&mut self, i: usize) {
        match i {
            RELEASES => {
                let Some(sc) = self.first_release() else {
                    return;
                };
                this_core().stats.releases += 1;
                release_remove(sc);
                let holder = sc.with(|h| h.holder);
                if holder != 0 {
                    place(Tcb(holder));
                }
            }
            DEADLINES => {
                let Some(t) = self.first_deadline() else {
                    return;
                };
                this_core().stats.expiries += 1;
                // Ending the wait drops its deadline; the tree is left in
                // order whatever happens, so the batch always progresses.
                let _ = super::donation::deadline(t);
                deadline_remove(t);
            }
            WALKS => {
                this_core().stats.walk_steps += 1;
                super::donation::walk_step();
            }
            _ => {}
        }
    }
}

/// Runs one batch of interrupt work at `now` (module docs). Its time is
/// charged to no context: the running thread's time is committed before
/// it, and its dispatch restarted after it.
fn batch(now: u64) {
    let has = {
        let mut w = Work { now };
        (0..3).any(|i| w.has_work(i))
    };
    if !has {
        return;
    }
    commit_current(now);
    this_core().in_batch = true;
    let mut b = this_core().batcher;
    let ran = b.run(&mut Work { now }, ksched::BATCH_UNITS);
    let after = timer::now();
    let c = this_core();
    c.batcher = b;
    c.in_batch = false;
    if c.current != 0 {
        c.dispatch = after;
    }
    c.stats.batch_counts += after.saturating_sub(now);
    c.batch_pending = ran.more;
    if ran.units > 0 {
        c.stats.batches += 1;
        c.stats.batch_max = c.stats.batch_max.max(ran.units as u64);
        for (i, n) in ran.per_source.iter().take(3).enumerate() {
            if *n > 0 {
                c.stats.batches_of[i] += 1;
            }
        }
    }
}

/// Programs the compare value for the earliest of the running thread's
/// budget end, the next release, the earliest deadline, and the batch gap
/// while work is left (tickless, as seL4 MCS; [`time::compare_value`]).
/// A running context whose head isn't ready, or that a commit found
/// exhausted, ends its slice at once: the exit path never leaves it so,
/// and this keeps it from running on a refill that hasn't come.
fn program_timer(now: u64) {
    let c = this_core();
    let exhausted = c.exhausted;
    let budget_end = match c.current {
        0 => None,
        t => Tcb(t).sc().map(|sc| {
            if sc.0 == exhausted {
                now
            } else {
                sc.refills(|r| {
                    if r.ready(c.dispatch) {
                        r.budget_end(c.dispatch)
                    } else {
                        now
                    }
                })
            }
        }),
    };
    let release = match tree::first(&Releases, c.release_root) {
        0 => None,
        n => Some(Sc(n).with(|h| h.release)),
    };
    let deadline = match tree::first(&Deadlines, c.deadline_root) {
        0 => None,
        n => Some(Tcb(n).with(|b| b.s.deadline)),
    };
    let w = Wakeups {
        budget_end,
        release,
        deadline,
        batch_pending: c.batch_pending,
    };
    #[allow(unused_mut)]
    let mut v = time::compare_value(clock(), now, w);
    #[cfg(aspis_test_build)]
    if let Some(d) = crate::testing::driver::deadline() {
        v = v.min(d);
    }
    // Written each time: the timer disarms itself when it fires, and the
    // tests program it directly, so a cached value could be stale.
    if v == time::NEVER {
        timer::disarm();
    } else {
        timer::set_deadline(v);
    }
    c.cval = v;
}

/// The timer fired (`timer::hooks::deadline_reached`, inside `irq::handle`,
/// before the end of interrupt): only a flag; the work is on the exit path
/// after it (K24).
pub fn timer_fired() {
    if percore::tpidr() == 0 {
        return;
    }
    this_core().timer_fired = true;
}

/// The end of every kernel entry from EL0, and the idle loop (module docs).
pub fn exit() -> ! {
    loop {
        let now = timer::now();
        // Each step takes this core's data afresh: no reference to it is
        // held across a call that takes it again.
        let (current, dispatch) = {
            let c = this_core();
            c.timer_fired = false;
            c.batch_pending = false;
            (c.current, c.dispatch)
        };
        if current != 0 {
            let t = Tcb(current);
            let exhausted = this_core().exhausted;
            if !eligible(t) {
                stop_current(Stop::Blocked);
            } else if let Some(sc) = t.sc()
                && (sc.0 == exhausted
                    || sc.refills(|r| !r.ready(dispatch) || now >= r.budget_end(dispatch)))
            {
                stop_current(Stop::BudgetEnd);
            }
        }
        batch(now);
        // The batch's commit may have used the budget up (a head left below
        // the minimum merges into a refill not yet ready): the slice ends
        // here, not on the next entry.
        {
            let c = this_core();
            if c.current != 0
                && c.exhausted != 0
                && Tcb(c.current).sc().is_some_and(|sc| sc.0 == c.exhausted)
            {
                stop_current(Stop::BudgetEnd);
            }
        }
        if this_core().batch_pending {
            this_core().stats.batches_left += 1;
        }
        #[cfg(aspis_test_build)]
        crate::testing::driver::check(now);
        choose(now);
        program_timer(now);
        let current = this_core().current;
        if current != 0 {
            return_to_user(Tcb(current));
        }
        if this_core().batch_pending {
            // Work is left and nothing runs: the next batch now, not idle
            // (K24). But the lock is given up between batches, as `idle`
            // does without its `WFI`, so the lock is held for one batch at
            // a time: other cores take it in FIFO order, remote calls and
            // the panic stop are served in the spin, and pending
            // interrupts are taken (ADR 0052, rule 2).
            this_core().stats.batch_yields += 1;
            crate::smp::lock::unlock();
            crate::smp::lock::lock();
            while crate::irq::pending() {
                crate::irq::handle();
            }
            continue;
        }
        idle();
    }
}

/// Waits for an interrupt with IRQs masked, then handles every pending
/// one: no thread object, and no IRQ taken at EL1 (kernel specification,
/// "The kernel's interrupt controller"). The
/// kernel lock is released around the `WFI`, and taken again before
/// anything else, so a remote call or the panic stop that woke the core is
/// served in the lock's spin.
fn idle() {
    let c = this_core();
    c.stats.idles += 1;
    if c.batch_pending || !c.work.is_empty() {
        c.stats.idle_with_work += 1;
    }
    crate::smp::lock::unlock();
    // SAFETY: waiting for an interrupt; WFI wakes on a pending one even
    // while PSTATE.I masks it.
    unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)) };
    crate::smp::lock::lock();
    while crate::irq::pending() {
        crate::irq::handle();
    }
}

unsafe extern "C" {
    /// Restores the user context at `ctx` (a thread's saved context, in the
    /// direct map) and returns to EL0 (`crate::exceptions`).
    fn aspis_user_restore(ctx: u64) -> !;
    /// Switches to the stack at `top` and runs [`exit`].
    fn aspis_enter_scheduler(top: u64) -> !;
}

core::arch::global_asm!(
    ".section .text.aspis_enter_scheduler, \"ax\"",
    ".global aspis_enter_scheduler",
    "aspis_enter_scheduler:",
    "    mov sp, x0",
    "    mov x29, #0",
    "    mov x30, #0",
    "    b aspis_scheduler_main",
);

#[unsafe(no_mangle)]
extern "C" fn aspis_scheduler_main() -> ! {
    exit()
}

/// Leaves `kernel_main` for good: the boot core's scheduler, on its entry
/// stack, as every core runs its own. Called with the kernel lock held.
pub fn enter() -> ! {
    // SAFETY: the boot core's entry stack, in its per-core slot, which
    // nothing uses while it runs on the boot stack; the boot stack is never
    // returned to.
    unsafe { aspis_enter_scheduler(percore::tpidr()) }
}

/// Returns to `t` at EL0: activates its address space if it isn't active,
/// forces its `SPSR_EL1` to [`SPSR_EL0`] with the bits EL0 owns
/// ([`SPSR_FROM_EL0`]), and restores its registers.
///
/// `t` is eligible: [`exit`] stops a running thread that isn't, and
/// [`choose`] runs no queued thread that isn't. A thread without an address
/// space would run in whatever space the core last loaded, another
/// thread's, so that is a kernel bug, and the kernel panics rather than
/// return to EL0.
fn return_to_user(t: Tcb) -> ! {
    let Cap::AddressSpace { base, .. } = t.slot_cap(2) else {
        panic!("thread {:#x} would run without an address space", t.0);
    };
    let space = AddressSpace::from_object(base);
    if !space.is_active() {
        space.activate();
    }
    t.with(|b| b.ctx.spsr = (b.ctx.spsr & SPSR_FROM_EL0) | SPSR_EL0);
    let ctx = t.context_va();
    // The last thing under the lock. Another core that changes `t` from now
    // on stalls it first, which waits for this core to take the remote
    // call's SGI: right after `ERET`, at EL0, with `t`'s registers saved
    // again (`crate::smp::remote`). So the restore below reads a live
    // object.
    crate::smp::lock::unlock();
    // SAFETY: `t` is eligible (above), so its object is a live thread whose
    // saved context is in the direct map; its address space, the one in its
    // slot 2, is active; the vectors save into this context on the next
    // entry from EL0.
    unsafe { aspis_user_restore(ctx) }
}
