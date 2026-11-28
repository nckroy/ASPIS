// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! In-QEMU tests of eventcounts, wait sets and bound eventcounts (C14; ADR
//! 0053; ADR 0047, rules 4 and 6; ADR 0052, rule 2; K08, K17, K23, K24,
//! K30, K31, K32, K33).
//!
//! As [`super::tests`] does, most drive the operations on threads that stay
//! suspended ([`super::testkit`]), so hundreds of waiters are made in the
//! kernel and every step is checked as it happens; a few run at EL0
//! through the test trap: the advance and the deletions with every
//! preemption point finding an interrupt pending, the trap's calls, and
//! wakes and work lists across cores. Each checks the eventcount and donation invariants
//! after the steps that change them, and ends with the scheduler's
//! baseline check (`crate::sched::testkit::finish`), which also finds every
//! core's work list empty. The tests count and order; none measures time.

use super::endpoint;
use super::eventcount::{self, advance_for_interrupt, count, is_clear, pending, set_count};
use super::store::{entry_slot, times_on_list};
use super::syscall;
use super::testkit::{
    caller_thread, check, check_ec, copy_with, ec_obj, endpoint_obj, epc, idle_thread, info, many,
    on_this_core, others, queued_at, reply_obj, scratch, set_words, status, tcb, ws_obj, wsc, x,
};
use super::waitset::{self, waiter};
use crate::cap;
use crate::sched::object::{Tcb, Wait, flag};
use crate::sched::percore::{self, this_core};
use crate::sched::testkit::{self, Spec, User, control, ms, space, spawn_in};
use crate::sched::{context, thread};
use crate::testing::driver::run_until;
use crate::testing::report;
use crate::testing::trap::{
    BIND_EC, DELETE, EC_ADVANCE, EC_READ, EC_WAIT, FORCE_PREEMPT, UNBIND_EC, WS_ADD, WS_REMOVE,
    WS_WAIT,
};
use crate::testing::user::Program;
use core::sync::atomic::{AtomicU64, Ordering};
use kcap::cap::{Binding, Cap};
use kcap::preempt::{Always, Budget};
use kcap::rights::Rights;
use kipc::Outcome::{Blocked, Done};
use kipc::msg::{Info, Status};
use kmem::untyped::ObjectType;

const OK: (Status, bool) = (Status::Ok, false);
const ALL: Rights = Rights::ALL;

/// Every entry of a wait set of 60 entries, as a mask.
const ALL_60: u64 = (1 << 60) - 1;

/// The threads a test's condition watches; 0 for none.
static W: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

fn watch(ts: &[Tcb]) {
    for (i, w) in W.iter().enumerate() {
        w.store(ts.get(i).map_or(0, |t| t.0), Ordering::Relaxed);
    }
}

fn watched() -> impl Iterator<Item = Tcb> {
    W.iter()
        .map(|w| w.load(Ordering::Relaxed))
        .filter(|&t| t != 0)
        .map(Tcb)
}

fn all_done() -> bool {
    watched().all(|t| t.has(flag::DONE))
}

fn all_ready() -> bool {
    watched().all(|t| t.wait() == Wait::None)
}

fn all_waiting() -> bool {
    watched().all(|t| matches!(t.wait(), Wait::Eventcount | Wait::Set))
}

fn work_done() -> bool {
    this_core().work.is_empty()
}

fn done_and_drained() -> bool {
    all_done() && work_done()
}

/// The eventcount operations' result and x1: a count or a mask.
fn got(t: Tcb) -> (Status, bool, u64) {
    let (s, d) = status(t);
    (s, d, x(t, 1))
}

const fn ok(v: u64) -> (Status, bool, u64) {
    (Status::Ok, false, v)
}

/// A value no eventcount operation returns in x1, written there before a
/// call that K28 says leaves x1 as the caller passed it: one refused, or a
/// wait that ends canceled, timed out or destroyed.
const KEPT: u64 = 0xdead_beef;

/// Writes [`KEPT`] into `t`'s x1.
fn keep(t: Tcb) {
    t.with(|b| b.ctx.x[1] = KEPT);
}

/// A wait that ended `s`, with x1 as the caller passed it ([`keep`]).
const fn kept(s: Status) -> (Status, bool, u64) {
    (s, false, KEPT)
}

/// An advance by thread `a`, with every right and a budget that never
/// finds an interrupt pending.
fn adv(a: Tcb, e: kipc::Ec) -> Result<u64, Status> {
    eventcount::advance(a, e, ALL, &mut cap::budget())
}

/// What an EL0 thread reported.
fn reports(u: &User) -> impl Iterator<Item = u64> {
    report::values_of(u.tcb.0)
}

/// An EL0 thread making trap call `num` with `args` in x0 to x3 and
/// `deadline` in x7, which reports its x0 and x1, then ends
/// ([`Program::TrapValueReport`]).
fn trap_call(num: u64, args: [u64; 4], deadline: u64) -> Spec {
    let mut spec = Spec::of(Program::TrapValueReport);
    spec.args.copy_from_slice(&args[..3]);
    spec.more = [args[3], 0, num, 0, deadline];
    spec
}

/// Destroys an EL0 thread that has ended, and its context, whose share
/// goes back to its core.
fn reap(u: User) {
    cap::delete(u.thread);
    cap::delete(u.context);
}

// ---------------------------------------------------------------------------
// Eventcounts.

crate::kernel_test!(ec_advance_read_wait, {
    // ADR 0053, rules 1 to 3: an advance adds one and wakes exactly the
    // waiters whose targets it reaches, giving each the count; a wait whose
    // target is reached returns at once; the rights; and the maximum, where
    // an advance fails and the count stays.
    let mut sc = scratch(20);
    let (es, e) = ec_obj(&mut sc);
    let (eps, _) = endpoint_obj(&mut sc);
    let (_, a) = idle_thread(&mut sc, 10);
    let (_, w1) = idle_thread(&mut sc, 10);
    let (_, w2) = idle_thread(&mut sc, 10);
    let (_, w3) = idle_thread(&mut sc, 10);
    assert_eq!(eventcount::read(a, e, ALL), Ok(0));
    assert_eq!(got(a), ok(0));
    assert_eq!(eventcount::wait(w1, e, ALL, 0, 0), Ok(Done));
    assert_eq!((w1.wait(), got(w1)), (Wait::None, ok(0)));
    for (t, g) in [(w1, 1), (w2, 2), (w3, 2)] {
        assert_eq!(eventcount::wait(t, e, ALL, g, 0), Ok(Blocked));
        assert_eq!(t.wait(), Wait::Eventcount);
    }
    check_ec(&[es], &[], &[a, w1, w2, w3]);
    assert_eq!(adv(a, e), Ok(1));
    assert_eq!(got(a), ok(1));
    assert_eq!((w1.wait(), got(w1)), (Wait::None, ok(1)));
    assert_eq!((w2.wait(), w3.wait()), (Wait::Eventcount, Wait::Eventcount));
    check_ec(&[es], &[], &[a, w1, w2, w3]);
    assert_eq!(adv(a, e), Ok(2));
    for t in [w2, w3] {
        assert_eq!((t.wait(), got(t)), (Wait::None, ok(2)));
    }
    // A target already reached returns at once, with the count.
    assert_eq!(eventcount::wait(w1, e, ALL, 2, 0), Ok(Done));
    assert_eq!((w1.wait(), got(w1)), (Wait::None, ok(2)));
    // The rights, through the trap's lookups: the write right advances,
    // the read right reads and waits.
    let ro = copy_with(&mut sc, es, Rights::READ);
    let wo = copy_with(&mut sc, es, Rights::WRITE);
    // K28: a refused call leaves x1 as the caller passed it.
    keep(a);
    super::syscall::ec_advance(a, sc.addr_of(ro), &mut cap::budget());
    assert_eq!((got(a), count(e)), (kept(Status::MissingRight), 2));
    super::syscall::ec_advance(a, sc.addr_of(wo), &mut cap::budget());
    assert_eq!(got(a), ok(3));
    keep(a);
    super::syscall::ec_read(a, sc.addr_of(wo));
    assert_eq!(got(a), kept(Status::MissingRight));
    keep(w1);
    assert_eq!(
        super::syscall::ec_wait(w1, sc.addr_of(wo), 9, 0),
        Err(Status::MissingRight)
    );
    assert_eq!((w1.wait(), x(w1, 1)), (Wait::None, KEPT));
    super::syscall::ec_read(a, sc.addr_of(eps));
    assert_eq!(got(a), kept(Status::WrongKind));
    super::syscall::ec_read(a, sc.addr(127));
    assert_eq!(got(a), kept(Status::InvalidCapability));
    // The maximum (ADR 0053, rule 3).
    let (ms_, m) = ec_obj(&mut sc);
    set_count(m, u64::MAX - 1);
    assert_eq!(adv(a, m), Ok(u64::MAX));
    keep(a);
    assert_eq!(adv(a, m), Err(Status::CountAtMaximum));
    assert_eq!((got(a), count(m)), (kept(Status::CountAtMaximum), u64::MAX));
    assert_eq!(advance_for_interrupt(m), Err(Status::CountAtMaximum));
    assert_eq!(eventcount::wait(w1, m, ALL, u64::MAX, 0), Ok(Done));
    assert_eq!(got(w1), ok(u64::MAX));
    check_ec(&[es, ms_], &[], &[a, w1, w2, w3]);
    testkit::finish(sc);
});

crate::kernel_test!(ec_deadline_and_cancel, {
    // ADR 0047, rule 6; ADR 0053, rule 2: an eventcount wait and a wait-set
    // wait each end at their deadline, "timed out", or when canceled,
    // "canceled", and leave every tree. A deadline already passed times out
    // a wait that would block at once (K19).
    let mut sc = scratch(20);
    let (es, e) = ec_obj(&mut sc);
    let (wss, w) = ws_obj(&mut sc, 7);
    assert_eq!(waitset::add(w, ALL, 0, es, 5), Ok(()));
    let (_, a) = idle_thread(&mut sc, 10);
    let (t1s, t1) = idle_thread(&mut sc, 10);
    let (_, t2) = idle_thread(&mut sc, 10);
    let (_, t3) = idle_thread(&mut sc, 10);
    let (t4s, t4) = idle_thread(&mut sc, 10);
    let threads = [a, t1, t2, t3, t4];
    // K28: each wait that ends so leaves x1 as the caller passed it.
    for t in threads {
        keep(t);
    }
    assert_eq!(eventcount::wait(t1, e, ALL, 1, 1), Ok(Blocked));
    assert_eq!((t1.wait(), got(t1)), (Wait::None, kept(Status::TimedOut)));
    assert_eq!(waitset::wait(t1, w, ALL, 1), Ok(Blocked));
    assert_eq!((t1.wait(), got(t1)), (Wait::None, kept(Status::TimedOut)));
    // A deadline 20 ms ahead.
    let at = crate::timer::now() + ms(20);
    assert_eq!(eventcount::wait(t2, e, ALL, 1, at), Ok(Blocked));
    assert_eq!(waitset::wait(t3, w, ALL, at), Ok(Blocked));
    check_ec(&[es], &[wss], &threads);
    watch(&[t2, t3]);
    assert!(run_until(all_ready, ms(2_000)), "the deadlines didn't pass");
    for t in [t2, t3] {
        assert_eq!(got(t), kept(Status::TimedOut));
    }
    assert_eq!(waiter(w), None);
    check_ec(&[es], &[wss], &threads);
    // Canceled.
    assert_eq!(eventcount::wait(t1, e, ALL, 1, 0), Ok(Blocked));
    thread::cancel(t1s).unwrap();
    assert_eq!((t1.wait(), got(t1)), (Wait::None, kept(Status::Canceled)));
    assert_eq!(waitset::wait(t4, w, ALL, 0), Ok(Blocked));
    thread::cancel(t4s).unwrap();
    assert_eq!((t4.wait(), got(t4)), (Wait::None, kept(Status::Canceled)));
    assert_eq!(waiter(w), None);
    check_ec(&[es], &[wss], &threads);
    // Nothing is left in the tree to wake.
    assert_eq!(adv(a, e), Ok(1));
    assert!(threads.iter().all(|t| t.wait() == Wait::None));
    assert_eq!(pending(e), (false, None));
    check_ec(&[es], &[wss], &threads);
    testkit::finish(sc);
});

crate::kernel_test!(ec_many_waiters_preempted, {
    // K31, K24; ADR 0052, rule 2: an advance made at EL0 on an eventcount
    // with 300 waiters, with every preemption point finding an interrupt
    // pending, wakes waiters until its first check, returns the count, and
    // leaves the rest to its core's work list, one wake a unit. Then 100
    // wait-set waiters of 60 entries each: each wake unlinks 60 nodes and
    // costs 60 units, so a batch holds one. Each count goes up by exactly
    // one, and the advance is never made again.
    const N: u64 = 300;
    const M: u64 = 100;
    let mut sc = scratch(22);
    let s = space(&mut sc);
    let (es, e) = ec_obj(&mut sc);
    let ts = many(&mut sc, ObjectType::Thread, N);
    for i in 0..N {
        let t = tcb(ts.offset(i));
        on_this_core(t);
        assert_eq!(eventcount::wait(t, e, ALL, 1, 0), Ok(Blocked));
    }
    let st = this_core().stats;
    FORCE_PREEMPT.store(true, Ordering::Relaxed);
    let spec = trap_call(EC_ADVANCE, [sc.addr_of(es), 0, 0, 0], 0);
    let u = spawn_in(&mut sc, s, spec);
    watch(&[u.tcb]);
    let ended = run_until(done_and_drained, ms(10_000));
    FORCE_PREEMPT.store(false, Ordering::Relaxed);
    assert!(ended, "the advance's wakes didn't end");
    assert!(reports(&u).eq([Status::Ok as u64, 1]));
    assert_eq!(count(e), 1);
    for i in 0..N {
        let t = tcb(ts.offset(i));
        assert_eq!((t.wait(), got(t)), (Wait::None, ok(1)), "waiter {i}");
    }
    let now = this_core().stats;
    let inline = u64::from(kcap::UNITS_PER_CHECK);
    assert_eq!(now.ec_units - st.ec_units, N - inline);
    assert_eq!(now.restarts, st.restarts, "the advance was made again");
    assert!(now.batch_max <= u64::from(ksched::BATCH_UNITS));
    reap(u);
    // Wait-set waiters, each on 60 entries of one eventcount.
    let (es2, e2) = ec_obj(&mut sc);
    let sets = many(&mut sc, ObjectType::WaitSet(12), M);
    let wts = many(&mut sc, ObjectType::Thread, M);
    for i in 0..M {
        let w = wsc(sets.offset(i));
        for j in 0..60 {
            assert_eq!(waitset::add(w, ALL, j, es2, 1), Ok(()));
        }
        let t = tcb(wts.offset(i));
        on_this_core(t);
        assert_eq!(waitset::wait(t, w, ALL, 0), Ok(Blocked));
    }
    check_ec(&[es2], &[sets.offset(0), sets.offset(M - 1)], &[]);
    let st = this_core().stats;
    FORCE_PREEMPT.store(true, Ordering::Relaxed);
    let spec = trap_call(EC_ADVANCE, [sc.addr_of(es2), 0, 0, 0], 0);
    let u = spawn_in(&mut sc, s, spec);
    watch(&[u.tcb]);
    let ended = run_until(done_and_drained, ms(10_000));
    FORCE_PREEMPT.store(false, Ordering::Relaxed);
    assert!(ended, "the wait-set waiters' wakes didn't end");
    assert!(reports(&u).eq([Status::Ok as u64, 1]));
    assert_eq!(count(e2), 1);
    for i in 0..M {
        let t = tcb(wts.offset(i));
        assert_eq!((t.wait(), got(t)), (Wait::None, ok(ALL_60)), "waiter {i}");
    }
    let now = this_core().stats;
    // The advance's own wakes: 60 units each, until a check.
    let inline = u64::from(kcap::UNITS_PER_CHECK.div_ceil(60));
    assert_eq!(now.ec_units - st.ec_units, M - inline);
    assert!(
        now.batches - st.batches >= M - inline,
        "two wakes shared a batch"
    );
    assert!(now.batch_max <= u64::from(ksched::BATCH_UNITS));
    assert_eq!(now.restarts, st.restarts, "the advance was made again");
    check_ec(&[es, es2], &[sets.offset(0), sets.offset(M - 1)], &[]);
    reap(u);
    testkit::finish(sc);
});

crate::kernel_test!(ec_interrupt_advance, {
    // K24 (C13b's seam): an advance for an interrupt adds one at once and
    // leaves every wake to this core's work list; the mark clears only once
    // no reached waiter is left. A second advance while it is pending finds
    // it on the list already, so one mark covers both.
    let mut sc = scratch(20);
    let (es, e) = ec_obj(&mut sc);
    let mut ts = [Tcb(0); 6];
    for (i, t) in ts.iter_mut().enumerate() {
        *t = idle_thread(&mut sc, 10).1;
        let target = if i < 5 { 1 } else { 3 };
        assert_eq!(eventcount::wait(*t, e, ALL, target, 0), Ok(Blocked));
    }
    let me = this_core().index;
    let units = this_core().stats.ec_units;
    assert_eq!(advance_for_interrupt(e), Ok(1));
    assert_eq!(pending(e), (true, Some(me)));
    assert!(ts.iter().all(|t| t.wait() == Wait::Eventcount));
    check_ec(&[es], &[], &ts);
    assert!(run_until(work_done, ms(2_000)), "the wakes didn't run");
    for t in &ts[..5] {
        assert_eq!((t.wait(), got(*t)), (Wait::None, ok(1)));
    }
    assert_eq!(ts[5].wait(), Wait::Eventcount);
    assert_eq!(pending(e), (false, None));
    assert_eq!(this_core().stats.ec_units - units, 5);
    // Two advances: the second finds the first's mark.
    let units = this_core().stats.ec_units;
    assert_eq!(advance_for_interrupt(e), Ok(2));
    assert_eq!(
        pending(e),
        (false, None),
        "nothing reached, nothing pending"
    );
    assert_eq!(advance_for_interrupt(e), Ok(3));
    assert_eq!(pending(e), (true, Some(me)));
    assert_eq!(advance_for_interrupt(e), Ok(4));
    assert_eq!(pending(e), (true, Some(me)));
    check_ec(&[es], &[], &ts);
    assert!(run_until(work_done, ms(2_000)), "the wake didn't run");
    assert_eq!((ts[5].wait(), got(ts[5])), (Wait::None, ok(4)));
    assert_eq!(this_core().stats.ec_units - units, 1);
    check_ec(&[es], &[], &ts);
    testkit::finish(sc);
});

crate::kernel_test!(ec_destroy_while_pending, {
    // K24, K30; ADR 0052, rule 2: an eventcount with a wake pending on this
    // core's work list, and 300 waiters, half of them reached, is destroyed
    // by a delete made at EL0 with every preemption point finding an
    // interrupt pending. Its queue zombie releases a waiter a step: the
    // reached ones get the count, the others "object destroyed". Its finish
    // takes it off the work list, so nothing points into its memory.
    const N: u64 = 300;
    let mut sc = scratch(21);
    let s = space(&mut sc);
    let (es, e) = ec_obj(&mut sc);
    let ts = many(&mut sc, ObjectType::Thread, N);
    for i in 0..N {
        let t = tcb(ts.offset(i));
        on_this_core(t);
        let target = if i % 2 == 0 { 1 } else { 5 };
        keep(t);
        assert_eq!(eventcount::wait(t, e, ALL, target, 0), Ok(Blocked));
    }
    assert_eq!(advance_for_interrupt(e), Ok(1));
    assert_eq!(pending(e), (true, Some(this_core().index)));
    let restarts = this_core().stats.restarts;
    let mut spec = Spec::of(Program::TrapReport);
    spec.args[0] = sc.addr_of(es);
    spec.more[0] = DELETE;
    FORCE_PREEMPT.store(true, Ordering::Relaxed);
    let u = spawn_in(&mut sc, s, spec);
    watch(&[u.tcb]);
    let ended = run_until(done_and_drained, ms(10_000));
    FORCE_PREEMPT.store(false, Ordering::Relaxed);
    assert!(ended, "the delete didn't end");
    assert!(this_core().stats.restarts > restarts, "never restarted");
    assert!(reports(&u).eq([Status::Ok as u64]));
    assert!(cap::cap(es).is_null());
    for i in 0..N {
        let t = tcb(ts.offset(i));
        let want = if i % 2 == 0 {
            ok(1)
        } else {
            kept(Status::ObjectDestroyed)
        };
        assert_eq!((t.wait(), got(t)), (Wait::None, want), "waiter {i}");
    }
    assert!(work_done() && is_clear(e));
    testkit::finish(sc);
});

crate::kernel_test!(ec_delete_last_copy_restarts, {
    // ADR 0052, rule 2; K23: removing a wait-set entry whose copy is the
    // last capability to an eventcount with 300 waiters, and unbinding a
    // thread's eventcount whose copy is the last, each made at EL0, delete
    // the copy under the caller's budget: made again at every preemption
    // point, each ends, and every waiter ends "object destroyed".
    const N: u64 = 300;
    for unbind in [false, true] {
        let mut sc = scratch(21);
        let s = space(&mut sc);
        let (es, e) = ec_obj(&mut sc);
        let (wss, w) = ws_obj(&mut sc, 7);
        let (xs, xt) = idle_thread(&mut sc, 10);
        if unbind {
            assert_eq!(eventcount::bind(xt, es), Ok(()));
        } else {
            assert_eq!(waitset::add(w, ALL, 0, es, u64::MAX), Ok(()));
        }
        let ts = many(&mut sc, ObjectType::Thread, N);
        for i in 0..N {
            let t = tcb(ts.offset(i));
            on_this_core(t);
            assert_eq!(eventcount::wait(t, e, ALL, 1, 0), Ok(Blocked));
        }
        // The binding's copy is now the last capability to the eventcount.
        cap::delete(es);
        let restarts = this_core().stats.restarts;
        let mut spec = Spec::of(Program::TrapReport);
        if unbind {
            spec.args[0] = sc.addr_of(xs);
            spec.more[0] = UNBIND_EC;
        } else {
            spec.args[0] = sc.addr_of(wss);
            spec.more[0] = WS_REMOVE;
        }
        FORCE_PREEMPT.store(true, Ordering::Relaxed);
        let u = spawn_in(&mut sc, s, spec);
        watch(&[u.tcb]);
        let ended = run_until(all_done, ms(10_000));
        FORCE_PREEMPT.store(false, Ordering::Relaxed);
        assert!(ended, "the deletion didn't end");
        assert!(this_core().stats.restarts > restarts, "never restarted");
        assert!(reports(&u).eq([Status::Ok as u64]));
        assert!(xt.slot_cap(6).is_null());
        assert!(cap::cap(entry_slot(w, 0)).is_null());
        for i in 0..N {
            let t = tcb(ts.offset(i));
            assert_eq!(
                (t.wait(), status(t)),
                (Wait::None, (Status::ObjectDestroyed, false)),
                "waiter {i}"
            );
        }
        assert!(is_clear(e));
        check_ec(&[], &[wss], &[xt]);
        testkit::finish(sc);
    }
});

// ---------------------------------------------------------------------------
// Wait sets.

crate::kernel_test!(ec_preempted_removal_leaves_its_zombie, {
    // Kernel specification, "An operation that deletes a capability deletes
    // it first": with every preemption point finding an interrupt pending, a
    // removal or an unbind is preempted only while its slot holds the
    // deletion's zombie, never once the slot is empty. So no `WsAdd` or
    // `BIND_EC` can fill the slot between a preempted call and its restart,
    // for a restart to delete. The checks in the loops show it, and the
    // count of preemptions; once both calls end, the slots are empty and
    // take a new entry and binding.
    const N: u64 = 20;
    let always = || Budget::with_threshold(Always, 1);
    for last in [false, true] {
        let mut sc = scratch(20);
        let (es, e) = ec_obj(&mut sc);
        let (es2, _) = ec_obj(&mut sc);
        let (wss, w) = ws_obj(&mut sc, 7);
        let (_, xt) = idle_thread(&mut sc, 10);
        assert_eq!(waitset::add(w, ALL, 0, es, u64::MAX), Ok(()));
        assert_eq!(eventcount::bind(xt, es), Ok(()));
        let mut ts = [Tcb(0); N as usize];
        if last {
            // The binding's and the entry's copies are the last two: the
            // second deletion drains N waiters, one a unit.
            for t in ts.iter_mut() {
                *t = idle_thread(&mut sc, 10).1;
                assert_eq!(eventcount::wait(*t, e, ALL, 1, 0), Ok(Blocked));
            }
            cap::delete(es);
        }
        // Remove the entry, then unbind, each made again until it ends.
        let mut preempted = 0;
        loop {
            match waitset::remove(w, ALL, 0, &mut always()) {
                Ok(r) => {
                    assert_eq!(r, Ok(()));
                    break;
                }
                Err(_) => {
                    preempted += 1;
                    assert!(!cap::cap(entry_slot(w, 0)).is_null(), "entry empty");
                }
            }
        }
        loop {
            match eventcount::unbind(xt, &mut always()) {
                Ok(()) => break,
                Err(_) => {
                    preempted += 1;
                    assert!(!xt.slot_cap(6).is_null(), "slot 6 empty");
                }
            }
        }
        // Only the last capability's deletion is preempted, after every
        // unit but the one that empties the slot: its zombify, and N drain
        // steps, the last of which finishes the eventcount.
        assert_eq!(preempted, if last { N } else { 0 });
        // Both slots end empty, and take a new entry and binding.
        assert!(cap::cap(entry_slot(w, 0)).is_null() && xt.slot_cap(6).is_null());
        assert_eq!(waitset::add(w, ALL, 0, es2, 1), Ok(()));
        assert_eq!(eventcount::bind(xt, es2), Ok(()));
        assert!(!cap::cap(entry_slot(w, 0)).is_null());
        assert!(!xt.slot_cap(6).is_null());
        let waited = if last { ts.len() } else { 0 };
        for t in &ts[..waited] {
            assert_eq!(
                (t.wait(), status(*t)),
                (Wait::None, (Status::ObjectDestroyed, false))
            );
        }
        check_ec(&[es2], &[wss], &[xt]);
        testkit::finish(sc);
    }
});

crate::kernel_test!(ws_sizes_masks_and_rights, {
    // K33: the six sizes; ADR 0053, rule 4: a wait returns the mask of the
    // entries whose targets are reached, at once if one is, and an empty
    // mask for a set with no entries; one wait at a time; entries in range
    // and free; K32: the write right adds and removes, the read right
    // waits, and an entry needs the read right on its eventcount.
    let mut sc = scratch(20);
    for (bits, n) in [(7, 1), (8, 3), (9, 7), (10, 15), (11, 31), (12, 60)] {
        let (_, w) = ws_obj(&mut sc, bits);
        assert_eq!(waitset::entries(w), n, "a set of 2^{bits} bytes");
    }
    let (e1s, e1) = ec_obj(&mut sc);
    let (e2s, e2) = ec_obj(&mut sc);
    let (wss, w) = ws_obj(&mut sc, 8);
    let (_, a) = idle_thread(&mut sc, 10);
    let (_, t) = idle_thread(&mut sc, 10);
    let (_, t2) = idle_thread(&mut sc, 10);
    let threads = [a, t, t2];
    // No entries: an empty mask at once.
    assert_eq!(waitset::wait(t, w, ALL, 0), Ok(Done));
    assert_eq!(got(t), ok(0));
    for (i, src, target) in [(0, e1s, 1), (1, e2s, 1), (2, e1s, 3)] {
        assert_eq!(waitset::add(w, ALL, i, src, target), Ok(()));
    }
    assert!(matches!(
        cap::cap(entry_slot(w, 0)),
        Cap::Eventcount {
            binding: Some(Binding::WaitSetEntry),
            ..
        }
    ));
    // Out of range, and in use.
    assert_eq!(
        waitset::add(w, ALL, 3, e1s, 1),
        Err(Status::InvalidArgument)
    );
    assert_eq!(
        waitset::add(w, ALL, u64::MAX, e1s, 1),
        Err(Status::InvalidArgument)
    );
    assert_eq!(waitset::add(w, ALL, 0, e2s, 1), Err(Status::Busy));
    // The rights (K32).
    let ewo = copy_with(&mut sc, e1s, Rights::WRITE);
    assert_eq!(
        waitset::add(w, Rights::READ, 0, e1s, 1),
        Err(Status::MissingRight)
    );
    assert_eq!(waitset::add(w, ALL, 0, ewo, 1), Err(Status::MissingRight));
    assert_eq!(
        waitset::remove(w, Rights::READ, 0, &mut cap::budget()),
        Ok(Err(Status::MissingRight))
    );
    assert_eq!(
        waitset::wait(t, w, Rights::WRITE, 0),
        Err(Status::MissingRight)
    );
    let wro = copy_with(&mut sc, wss, Rights::READ);
    super::syscall::ws_add(a, sc.addr_of(wro), 0, sc.addr_of(e2s), 1);
    assert_eq!(status(a), (Status::MissingRight, false));
    // One wait at a time.
    assert_eq!(waitset::wait(t, w, ALL, 0), Ok(Blocked));
    assert_eq!((t.wait(), waiter(w)), (Wait::Set, Some(t)));
    assert_eq!(waitset::wait(t2, w, ALL, 0), Err(Status::Busy));
    assert_eq!(t2.wait(), Wait::None);
    check_ec(&[e1s, e2s], &[wss], &threads);
    // The mask names the entries reached: entry 0 only.
    assert_eq!(adv(a, e1), Ok(1));
    assert_eq!((t.wait(), got(t)), (Wait::None, ok(0b001)));
    assert_eq!(waiter(w), None);
    check_ec(&[e1s, e2s], &[wss], &threads);
    // Reached: at once.
    assert_eq!(waitset::wait(t, w, ALL, 0), Ok(Done));
    assert_eq!(got(t), ok(0b001));
    assert_eq!(adv(a, e2), Ok(1));
    assert_eq!(waitset::wait(t, w, ALL, 0), Ok(Done));
    assert_eq!(got(t), ok(0b011));
    // Sixty entries, all linked, and woken together.
    let (bigs, big) = ws_obj(&mut sc, 12);
    for j in 0..60 {
        assert_eq!(waitset::add(big, ALL, j, e2s, 2), Ok(()));
    }
    assert_eq!(waitset::wait(t, big, ALL, 0), Ok(Blocked));
    check_ec(&[e1s, e2s], &[wss, bigs], &threads);
    assert_eq!(adv(a, e2), Ok(2));
    assert_eq!((t.wait(), got(t)), (Wait::None, ok(ALL_60)));
    check_ec(&[e1s, e2s], &[wss, bigs], &threads);
    testkit::finish(sc);
});

crate::kernel_test!(ws_change_during_wait_k08, {
    // K08: removing an entry during a wait, or revoking its copy, leaves the
    // wait on the other entries; adding a reached entry during a wait ends
    // it; removing the last linked entry ends it with an empty mask. An
    // empty entry's removal does nothing.
    let mut sc = scratch(20);
    let (e1s, e1) = ec_obj(&mut sc);
    let (e2s, _) = ec_obj(&mut sc);
    let (e3s, _) = ec_obj(&mut sc);
    // Entry 1's copy descends from a copy the test revokes.
    let c2 = copy_with(&mut sc, e2s, ALL);
    let (wss, w) = ws_obj(&mut sc, 8);
    for (i, src) in [(0, e1s), (1, c2), (2, e3s)] {
        assert_eq!(waitset::add(w, ALL, i, src, 5), Ok(()));
    }
    let (_, t) = idle_thread(&mut sc, 10);
    let (_, a) = idle_thread(&mut sc, 10);
    let ecs = [e1s, e2s, e3s];
    assert_eq!(waitset::wait(t, w, ALL, 0), Ok(Blocked));
    assert_eq!(waitset::remove(w, ALL, 0, &mut cap::budget()), Ok(Ok(())));
    assert_eq!(t.wait(), Wait::Set);
    check_ec(&ecs, &[wss], &[t, a]);
    assert_eq!(waitset::remove(w, ALL, 0, &mut cap::budget()), Ok(Ok(())));
    cap::revoke(c2);
    assert!(cap::cap(entry_slot(w, 1)).is_null());
    assert_eq!(t.wait(), Wait::Set);
    check_ec(&ecs, &[wss], &[t, a]);
    // Added, and reached: the wait ends with that entry's bit.
    assert_eq!(adv(a, e1), Ok(1));
    assert_eq!(waitset::add(w, ALL, 0, e1s, 1), Ok(()));
    assert_eq!((t.wait(), got(t)), (Wait::None, ok(0b001)));
    check_ec(&ecs, &[wss], &[t, a]);
    // The last linked entry removed: an empty mask.
    assert_eq!(waitset::remove(w, ALL, 0, &mut cap::budget()), Ok(Ok(())));
    assert_eq!(waitset::wait(t, w, ALL, 0), Ok(Blocked));
    assert_eq!(waitset::remove(w, ALL, 2, &mut cap::budget()), Ok(Ok(())));
    assert_eq!((t.wait(), got(t)), (Wait::None, ok(0)));
    assert_eq!(waiter(w), None);
    check_ec(&ecs, &[wss], &[t, a]);
    testkit::finish(sc);
});

crate::kernel_test!(ws_destroy_during_wait, {
    // K30: destroying a wait set ends its wait "object destroyed", and its
    // entries leave their eventcounts' trees.
    let mut sc = scratch(20);
    let (es, e) = ec_obj(&mut sc);
    let (wss, w) = ws_obj(&mut sc, 9);
    for i in 0..7 {
        assert_eq!(waitset::add(w, ALL, i, es, 1), Ok(()));
    }
    let (_, t) = idle_thread(&mut sc, 10);
    let (_, a) = idle_thread(&mut sc, 10);
    keep(t);
    assert_eq!(waitset::wait(t, w, ALL, 0), Ok(Blocked));
    cap::delete(wss);
    assert_eq!(
        (t.wait(), got(t)),
        (Wait::None, kept(Status::ObjectDestroyed))
    );
    check_ec(&[es], &[], &[t, a]);
    assert_eq!(adv(a, e), Ok(1));
    assert_eq!(pending(e), (false, None));
    check_ec(&[es], &[], &[t, a]);
    testkit::finish(sc);
});

crate::kernel_test!(ws_waiter_destroyed_counts_its_nodes, {
    // K23: deleting the last capability to a thread that waits on a wait
    // set of 60 entries unlinks 60 nodes, and the deletion step that makes
    // its zombie counts them, not one.
    let mut sc = scratch(20);
    let (es, _) = ec_obj(&mut sc);
    let (wss, w) = ws_obj(&mut sc, 12);
    for i in 0..60 {
        assert_eq!(waitset::add(w, ALL, i, es, 1), Ok(()));
    }
    let (ts, t) = idle_thread(&mut sc, 10);
    let (_, a) = idle_thread(&mut sc, 10);
    assert_eq!(waitset::wait(t, w, ALL, 0), Ok(Blocked));
    check_ec(&[es], &[wss], &[t, a]);
    let units = kcap::delete::delete_unit(&mut cap::DirectSlots, &mut cap::KernelHooks, ts);
    assert_eq!(units, 60);
    assert!(cap::cap(ts).is_zombie());
    assert_eq!(waiter(w), None);
    check_ec(&[es], &[wss], &[a]);
    cap::delete(ts);
    testkit::finish(sc);
});

// ---------------------------------------------------------------------------
// Bound eventcounts.

crate::kernel_test!(ec_bind_needs_the_threads_write_right, {
    // ADR 0053, rule 5: binding an eventcount to a thread, and unbinding
    // it, need the write right on the thread capability. Without it the
    // call is refused, and slot 6 stays as it was.
    let mut sc = scratch(20);
    let (es, _) = ec_obj(&mut sc);
    let (_, m) = idle_thread(&mut sc, 10);
    let (ts, t) = idle_thread(&mut sc, 10);
    let weak = copy_with(&mut sc, ts, Rights::READ);
    let (wa, ta, ea) = (sc.addr_of(weak), sc.addr_of(ts), sc.addr_of(es));
    let s6 = Binding::BoundEventcount.thread_slot();
    syscall::bind_eventcount(m, wa, ea);
    assert_eq!(status(m), (Status::MissingRight, false));
    assert!(t.slot_cap(s6).is_null());
    syscall::bind_eventcount(m, ta, ea);
    assert_eq!(status(m), OK);
    let bound = t.slot_cap(s6);
    assert!(bound.same_object(&cap::cap(es)));
    syscall::unbind_eventcount(m, wa, &mut cap::budget()).unwrap();
    assert_eq!(status(m), (Status::MissingRight, false));
    assert_eq!(t.slot_cap(s6), bound);
    syscall::unbind_eventcount(m, ta, &mut cap::budget()).unwrap();
    assert_eq!(status(m), OK);
    assert!(t.slot_cap(s6).is_null());
    testkit::finish(sc);
});

/// The info word of a receive that reports its bound eventcount's advance.
fn advance_info() -> u64 {
    Info::advance().encode()
}

crate::kernel_test!(ec_bound_receive, {
    // ADR 0053, rule 5: a receive by a thread bound to an eventcount, which
    // holds a context, reports an advance it hasn't seen before any message,
    // at once or when it comes, with the count in x6, and last-seen moves to
    // it: none is missed or reported twice. A bound receive is canceled and
    // times out as any. Revoking the binding's eventcount leaves the receive
    // on the endpoint alone. At the count's maximum nothing is linked.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (es, e) = ec_obj(&mut sc);
    let (eps, _) = endpoint_obj(&mut sc);
    let (rs, rt) = caller_thread(&mut sc, s, 10, 0);
    let (_, r) = reply_obj(&mut sc);
    let (_, st) = idle_thread(&mut sc, 10);
    let (_, a) = idle_thread(&mut sc, 10);
    let threads = [rt, st, a];
    let c = copy_with(&mut sc, es, Rights::READ);
    let wo = copy_with(&mut sc, es, Rights::WRITE);
    assert_eq!(eventcount::bind(rt, wo), Err(Status::MissingRight));
    assert_eq!(eventcount::bind(rt, c), Ok(()));
    assert!(matches!(
        rt.slot_cap(6),
        Cap::Eventcount {
            binding: Some(Binding::BoundEventcount),
            ..
        }
    ));
    assert_eq!(eventcount::bind(rt, es), Err(Status::Busy));
    // An advance comes before a queued message.
    assert_eq!(adv(a, e), Ok(1));
    set_words(st, [7, 0, 0, 0]);
    assert_eq!(
        endpoint::send(st, epc(eps), info(0, 8, 0), true, 0),
        Ok(Blocked)
    );
    assert_eq!(endpoint::recv(rt, epc(eps), r, 0), Ok(Done));
    assert_eq!((status(rt), x(rt, 1), x(rt, 6)), (OK, advance_info(), 1));
    assert_eq!(st.wait(), Wait::Send);
    assert_eq!(endpoint::recv(rt, epc(eps), r, 0), Ok(Done));
    assert_eq!((x(rt, 2), st.wait()), (7, Wait::None));
    // A blocked receive woken by an advance.
    assert_eq!(endpoint::recv(rt, epc(eps), r, 0), Ok(Blocked));
    check_ec(&[es], &[], &threads);
    assert_eq!(adv(a, e), Ok(2));
    assert_eq!(
        (rt.wait(), status(rt), x(rt, 1), x(rt, 6)),
        (Wait::None, OK, advance_info(), 2)
    );
    // Two advances between receives: reported once, with the count.
    assert_eq!(adv(a, e), Ok(3));
    assert_eq!(adv(a, e), Ok(4));
    assert_eq!(endpoint::recv(rt, epc(eps), r, 0), Ok(Done));
    assert_eq!(x(rt, 6), 4);
    assert_eq!(endpoint::recv(rt, epc(eps), r, 0), Ok(Blocked));
    check_ec(&[es], &[], &threads);
    // Canceled, and timed out.
    thread::cancel(rs).unwrap();
    assert_eq!(status(rt), (Status::Canceled, false));
    check_ec(&[es], &[], &threads);
    let at = crate::timer::now() + ms(10);
    assert_eq!(endpoint::recv(rt, epc(eps), r, at), Ok(Blocked));
    watch(&[rt]);
    assert!(run_until(all_ready, ms(2_000)), "the deadline didn't pass");
    assert_eq!(status(rt), (Status::TimedOut, false));
    check_ec(&[es], &[], &threads);
    // Revoked: the receive goes on, on the endpoint alone.
    assert_eq!(endpoint::recv(rt, epc(eps), r, 0), Ok(Blocked));
    cap::revoke(es);
    assert!(rt.slot_cap(6).is_null());
    assert_eq!(rt.wait(), Wait::Receive);
    check_ec(&[es], &[], &threads);
    assert_eq!(adv(a, e), Ok(5));
    assert_eq!(rt.wait(), Wait::Receive);
    set_words(st, [8, 0, 0, 0]);
    assert_eq!(
        endpoint::send(st, epc(eps), info(0, 8, 0), true, 0),
        Ok(Done)
    );
    assert_eq!(
        (rt.wait(), x(rt, 2), x(rt, 1)),
        (Wait::None, 8, info(0, 8, 0))
    );
    // Nothing bound: nothing to unbind.
    assert_eq!(eventcount::unbind(rt, &mut cap::budget()), Ok(()));
    assert_eq!(eventcount::bind(rt, es), Ok(()));
    assert_eq!(eventcount::unbind(rt, &mut cap::budget()), Ok(()));
    assert!(rt.slot_cap(6).is_null());
    // At the maximum: nothing linked, nothing reported.
    set_count(e, u64::MAX);
    assert_eq!(eventcount::bind(rt, es), Ok(()));
    assert_eq!(endpoint::recv(rt, epc(eps), r, 0), Ok(Blocked));
    check_ec(&[es], &[], &threads);
    thread::cancel(rs).unwrap();
    check_ec(&[es], &[], &threads);
    check(&[eps], &threads, &[r]);
    testkit::finish(sc);
});

crate::kernel_test!(ec_bound_passive_server, {
    // ADR 0053, rule 5; ADR 0051, rule 3: a passive server bound to an
    // eventcount neither hears nor is woken by it while it holds no
    // context, so it keeps serving calls on its callers' contexts; the
    // advance stays unseen, and is reported once it is given a context of
    // its own. A context bound to a receiving thread with nothing to report
    // links its node instead.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (es, e) = ec_obj(&mut sc);
    let (eps, _) = endpoint_obj(&mut sc);
    let (ps, p) = idle_thread(&mut sc, 10);
    let (_, r) = reply_obj(&mut sc);
    let (_, c) = caller_thread(&mut sc, s, 10, 0);
    let (_, a) = idle_thread(&mut sc, 10);
    let threads = [p, c, a];
    assert_eq!(eventcount::bind(p, es), Ok(()));
    assert_eq!(endpoint::recv(p, epc(eps), r, 0), Ok(Blocked));
    assert_eq!(adv(a, e), Ok(1));
    assert_eq!(p.wait(), Wait::Receive, "a passive server was woken");
    check_ec(&[es], &[], &threads);
    // A call: the server runs on the caller's context, and answers with
    // reply and receive, passive again; the advance stays unseen.
    let own = c.sc();
    assert_eq!(endpoint::call(c, epc(eps), info(0, 0, 0), 0), Ok(Blocked));
    assert_eq!((p.wait(), p.sc()), (Wait::None, own));
    assert_eq!(
        endpoint::reply_recv(p, epc(eps), r, false, info(0, 0, 0), 0),
        Ok(Blocked)
    );
    assert_eq!((c.wait(), status(c), c.sc()), (Wait::None, OK, own));
    assert_eq!((p.wait(), p.sc()), (Wait::Receive, None));
    check_ec(&[es], &[], &threads);
    // A context of its own: the advance is reported at once.
    let ctx = sc.make(ObjectType::SchedContext(8));
    context::configure(control(), ctx, 50, 1_000, 0, 0).unwrap();
    thread::bind_context(ps, ctx).unwrap();
    assert_eq!(
        (p.wait(), status(p), x(p, 1), x(p, 6)),
        (Wait::None, OK, advance_info(), 1)
    );
    // Another passive receiver given a context with nothing to report: its
    // node is linked, and the next advance wakes it.
    let (qs, q) = idle_thread(&mut sc, 10);
    let (_, rq) = reply_obj(&mut sc);
    assert_eq!(eventcount::bind(q, es), Ok(()));
    assert_eq!(endpoint::recv(q, epc(eps), rq, 0), Ok(Blocked));
    let ctx2 = sc.make(ObjectType::SchedContext(8));
    context::configure(control(), ctx2, 50, 1_000, 0, 0).unwrap();
    thread::bind_context(qs, ctx2).unwrap();
    assert_eq!(q.wait(), Wait::Receive);
    check_ec(&[es], &[], &[p, c, a, q]);
    assert_eq!(adv(a, e), Ok(2));
    assert_eq!(
        (q.wait(), x(q, 1), x(q, 6)),
        (Wait::None, advance_info(), 2)
    );
    check_ec(&[es], &[], &[p, c, a, q]);
    testkit::finish(sc);
});

crate::kernel_test!(ec_stranded_k17, {
    // K17: C → S1, and S1 then waits on an eventcount, or, in a second
    // chain, on a wait set. Canceling C cancels S1's wait, undelivered,
    // which leaves every tree, and its walk step then sends S1 its
    // context-withdrawn fault.
    for on_set in [false, true] {
        let mut sc = scratch(20);
        let s = space(&mut sc);
        let (e, _) = endpoint_obj(&mut sc);
        let (tep, _) = endpoint_obj(&mut sc);
        let (es, ec) = ec_obj(&mut sc);
        let (wss, w) = ws_obj(&mut sc, 7);
        assert_eq!(waitset::add(w, ALL, 0, es, 1), Ok(()));
        let (cs, c) = caller_thread(&mut sc, s, 10, 0x17);
        let (s1s, s1) = idle_thread(&mut sc, 10);
        thread::set_endpoint(s1s, Binding::TimeoutEndpoint, Some(tep)).unwrap();
        let (_, r) = reply_obj(&mut sc);
        assert_eq!(endpoint::recv(s1, epc(e), r, 0), Ok(Blocked));
        assert_eq!(endpoint::call(c, epc(e), info(0, 0, 0), 0), Ok(Blocked));
        if on_set {
            assert_eq!(waitset::wait(s1, w, ALL, 0), Ok(Blocked));
            assert_eq!(s1.wait(), Wait::Set);
        } else {
            assert_eq!(eventcount::wait(s1, ec, ALL, 1, 0), Ok(Blocked));
            assert_eq!(s1.wait(), Wait::Eventcount);
        }
        thread::cancel(cs).unwrap();
        assert_eq!(status(c), (Status::Canceled, true));
        assert_eq!(status(s1), (Status::Canceled, false));
        assert_eq!(waiter(w), None);
        check_ec(&[es], &[wss], &[c, s1]);
        assert!(run_until(work_done, ms(2_000)));
        assert_eq!(s1.wait(), Wait::WithdrawnSend);
        assert_eq!(queued_at(tep, 0), Some(s1));
        check(&[e, tep], &[c, s1], &[r]);
        testkit::finish(sc);
    }
});

// ---------------------------------------------------------------------------
// The trap's calls, and across cores.

crate::kernel_test!(ec_trap_calls, {
    // The test trap's eventcount and wait-set calls (14 to 21) from EL0,
    // with K28's registers: WS_ADD, WS_WAIT, EC_WAIT, EC_ADVANCE, EC_READ,
    // BIND_EC and a wait's deadline.
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (es, e) = ec_obj(&mut sc);
    let (wss, w) = ws_obj(&mut sc, 7);
    let (_, a) = idle_thread(&mut sc, 10);
    let (xs, xt) = idle_thread(&mut sc, 10);
    let (ea, wa) = (sc.addr_of(es), sc.addr_of(wss));
    let run = |sc: &mut crate::cap::testkit::Scratch, spec: Spec| -> [u64; 2] {
        let u = spawn_in(sc, s, spec);
        watch(&[u.tcb]);
        assert!(run_until(all_done, ms(2_000)), "{spec:?} didn't end");
        let mut v = [u64::MAX; 2];
        for (o, r) in v.iter_mut().zip(reports(&u)) {
            *o = r;
        }
        reap(u);
        v
    };
    assert_eq!(run(&mut sc, trap_call(WS_ADD, [wa, 0, ea, 1], 0)), [0, 0]);
    // A wait set's wait, woken by an advance from the kernel.
    let u = spawn_in(&mut sc, s, trap_call(WS_WAIT, [wa, 0, 0, 0], 0));
    watch(&[u.tcb]);
    assert!(run_until(all_waiting, ms(2_000)));
    assert_eq!(adv(a, e), Ok(1));
    assert!(run_until(all_done, ms(2_000)));
    assert!(reports(&u).eq([Status::Ok as u64, 0b1]));
    reap(u);
    // An eventcount's wait, woken by advances from EL0.
    let u = spawn_in(&mut sc, s, trap_call(EC_WAIT, [ea, 3, 0, 0], 0));
    watch(&[u.tcb]);
    assert!(run_until(all_waiting, ms(2_000)));
    assert_eq!(
        run(&mut sc, trap_call(EC_ADVANCE, [ea, 0, 0, 0], 0)),
        [0, 2]
    );
    assert_eq!(u.tcb.wait(), Wait::Eventcount);
    assert_eq!(
        run(&mut sc, trap_call(EC_ADVANCE, [ea, 0, 0, 0], 0)),
        [0, 3]
    );
    watch(&[u.tcb]);
    assert!(run_until(all_done, ms(2_000)));
    assert!(reports(&u).eq([Status::Ok as u64, 3]));
    reap(u);
    assert_eq!(run(&mut sc, trap_call(EC_READ, [ea, 0, 0, 0], 0)), [0, 3]);
    // A wait's deadline: "timed out", x1 as it was.
    let at = crate::timer::now() + ms(10);
    assert_eq!(
        run(&mut sc, trap_call(EC_WAIT, [ea, 9, 0, 0], at)),
        [Status::TimedOut as u64, 9]
    );
    // Binding a thread's eventcount.
    let xa = sc.addr_of(xs);
    assert_eq!(run(&mut sc, trap_call(BIND_EC, [xa, ea, 0, 0], 0)), [0, ea]);
    assert!(matches!(xt.slot_cap(6), Cap::Eventcount { .. }));
    assert_eq!(
        run(&mut sc, trap_call(BIND_EC, [xa, ea, 0, 0], 0))[0],
        Status::Busy as u64
    );
    assert_eq!(waiter(w), None);
    check_ec(&[es], &[wss], &[a, xt]);
    testkit::finish(sc);
});

crate::kernel_smp_test!(ec_cross_core_wake, {
    // K24: one advance for an interrupt on this core wakes waiters on every
    // core, through this core's work list alone. Then an advance made at
    // EL0 on another core wakes waiters on the others at once, and leaves
    // no work on any list.
    let Some(cores) = others(1) else { return };
    let me = this_core().index;
    let on: [Option<usize>; 4] = {
        let mut on = [None; 4];
        on[0] = Some(me);
        for (o, k) in on[1..].iter_mut().zip(cores.clone()) {
            *o = Some(k);
        }
        on
    };
    let n = on.iter().flatten().count();
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let (es, e) = ec_obj(&mut sc);
    let ea = sc.addr_of(es);
    let units = |k: usize| percore::core(k).stats.ec_units;
    for round in 1..=2u64 {
        let mut us = [None; 4];
        let mut ts = [Tcb(0); 4];
        for (i, k) in on.iter().enumerate() {
            let Some(k) = *k else { continue };
            let u = spawn_in(&mut sc, s, trap_call(EC_WAIT, [ea, round, 0, 0], 0).on(k));
            ts[i] = u.tcb;
            us[i] = Some(u);
        }
        watch(&ts[..n]);
        assert!(run_until(all_waiting, ms(5_000)), "the waiters didn't wait");
        let before: [u64; 4] = core::array::from_fn(|i| on[i].map_or(0, units));
        if round == 1 {
            assert_eq!(advance_for_interrupt(e), Ok(1));
        } else {
            let k = on[1].unwrap();
            let u = spawn_in(&mut sc, s, trap_call(EC_ADVANCE, [ea, 0, 0, 0], 0).on(k));
            watch(&[u.tcb]);
            assert!(run_until(all_done, ms(5_000)), "the advance didn't end");
            assert!(reports(&u).eq([Status::Ok as u64, 2]));
            reap(u);
        }
        watch(&ts[..n]);
        assert!(run_until(all_done, ms(5_000)), "the waiters weren't woken");
        for u in us.iter().flatten() {
            assert!(reports(u).eq([Status::Ok as u64, round]));
        }
        for (i, k) in on.iter().enumerate() {
            let Some(k) = *k else { continue };
            let want = if round == 1 && k == me { n as u64 } else { 0 };
            assert_eq!(units(k) - before[i], want, "core {k}'s units");
        }
        for u in us.into_iter().flatten() {
            reap(u);
        }
    }
    testkit::finish(sc);
});

/// Whether every online core's work list is empty.
fn all_lists_empty() -> bool {
    (0..kirq::MAX_CORES)
        .filter(|&c| crate::smp::is_online(c))
        .all(|c| percore::core(c).work.is_empty())
}

fn all_done_and_lists_empty() -> bool {
    all_done() && all_lists_empty()
}

crate::kernel_smp_test!(ec_work_list_across_cores, {
    // K24: an eventcount stays on the work list of the core that first
    // queued it, once. A later advance on another core that stops at a
    // preemption point only sets the mark, and queues nothing on its own
    // list; that core's batches wake the rest. Destroying an eventcount
    // listed on another core takes it off that core's list. A wait set's
    // waiter on one core is woken by another core's batch. The test body
    // holds the kernel lock, so the other core runs none of its work until
    // `run_until` lets the lock go.
    const N: usize = 8;
    let Some(mut cores) = others(1) else { return };
    let me = this_core().index;
    let k = cores.next().unwrap();
    let j = cores.next().unwrap_or(me);
    let mut sc = scratch(20);
    let s = space(&mut sc);
    let units = |c: usize| percore::core(c).stats.ec_units;
    // 1. Listed on k, advanced here.
    let (es, e) = ec_obj(&mut sc);
    let (_, a) = idle_thread(&mut sc, 10);
    let slots = many(&mut sc, ObjectType::Thread, N as u64);
    let ts: [Tcb; N] = core::array::from_fn(|i| tcb(slots.offset(i as u64)));
    for &t in &ts {
        on_this_core(t);
        assert_eq!(eventcount::wait(t, e, ALL, 1, 0), Ok(Blocked));
    }
    crate::smp::remote::advance_on(k, e);
    assert_eq!(count(e), 1);
    assert_eq!(pending(e), (true, Some(k)));
    assert_eq!(times_on_list(k, e), 1);
    assert!(work_done(), "this core's list holds work");
    assert!(ts.iter().all(|t| t.wait() == Wait::Eventcount));
    let before = (units(me), units(k));
    // An advance whose first preemption point finds an interrupt pending:
    // one wake inline, then only the mark.
    let r = eventcount::advance(a, e, ALL, &mut Budget::with_threshold(Always, 1));
    assert_eq!(r, Ok(2));
    assert_eq!(pending(e), (true, Some(k)), "the mark moved");
    assert_eq!(times_on_list(k, e), 1, "listed twice on core {k}");
    assert_eq!(times_on_list(me, e), 0, "listed on this core too");
    assert!(work_done(), "this core's list holds work");
    assert_eq!(ts.iter().filter(|t| t.wait() == Wait::None).count(), 1);
    check_ec(&[es], &[], &ts);
    assert!(
        run_until(all_lists_empty, ms(2_000)),
        "k's batches didn't run"
    );
    for (i, &t) in ts.iter().enumerate() {
        assert_eq!((t.wait(), got(t)), (Wait::None, ok(2)), "waiter {i}");
    }
    assert_eq!(pending(e), (false, None));
    assert_eq!(units(me) - before.0, 0, "this core ran the wakes");
    assert_eq!(units(k) - before.1, N as u64 - 1, "core {k}'s units");
    check_ec(&[es], &[], &ts);
    // 2. Listed on k, destroyed here: its finish takes it off k's list,
    // and every waiter is released, the reached ones with the count.
    let (es2, e2) = ec_obj(&mut sc);
    let slots2 = many(&mut sc, ObjectType::Thread, N as u64);
    let ts2: [Tcb; N] = core::array::from_fn(|i| tcb(slots2.offset(i as u64)));
    for (i, &t) in ts2.iter().enumerate() {
        on_this_core(t);
        let target = if i % 2 == 0 { 1 } else { 5 };
        keep(t);
        assert_eq!(eventcount::wait(t, e2, ALL, target, 0), Ok(Blocked));
    }
    crate::smp::remote::advance_on(k, e2);
    assert_eq!(pending(e2), (true, Some(k)));
    assert_eq!(times_on_list(k, e2), 1);
    cap::delete(es2);
    assert!(cap::cap(es2).is_null());
    assert!(percore::core(k).work.is_empty(), "left on core {k}'s list");
    assert!(is_clear(e2));
    for (i, &t) in ts2.iter().enumerate() {
        let want = if i % 2 == 0 {
            ok(1)
        } else {
            kept(Status::ObjectDestroyed)
        };
        assert_eq!((t.wait(), got(t)), (Wait::None, want), "waiter {i}");
    }
    // 3. A wait set's waiter, at EL0 on core j, woken by core k's batch.
    let (es3, e3) = ec_obj(&mut sc);
    let (wss, w) = ws_obj(&mut sc, 7);
    assert_eq!(waitset::add(w, ALL, 0, es3, 1), Ok(()));
    let wa = sc.addr_of(wss);
    let u = spawn_in(&mut sc, s, trap_call(WS_WAIT, [wa, 0, 0, 0], 0).on(j));
    watch(&[u.tcb]);
    assert!(run_until(all_waiting, ms(2_000)), "the waiter didn't wait");
    assert_eq!(waiter(w), Some(u.tcb));
    let before = units(k);
    crate::smp::remote::advance_on(k, e3);
    assert_eq!(pending(e3), (true, Some(k)));
    assert!(
        run_until(all_done_and_lists_empty, ms(2_000)),
        "the waiter wasn't woken"
    );
    assert!(reports(&u).eq([Status::Ok as u64, 0b1]));
    assert!(units(k) > before, "core {k}'s batch didn't wake it");
    assert_eq!(waiter(w), None);
    check_ec(&[es, es3], &[wss], &ts);
    reap(u);
    testkit::finish(sc);
});
