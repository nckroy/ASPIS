// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! In-QEMU tests of donation, taking a context back, deadlines, batches,
//! the restart, SError and PSCI (C12's stage 3; ADR 0036, rule 5; ADR
//! 0051, rules 1, 3 and 5; ADR 0052, rule 2; ADR 0056, rule 3; ADR 0061,
//! rule 3; K08, K17, K21, K24, K50, K77; kernel specification, "Passive servers and taking a context back").
//!
//! Most drive the protocol through the kernel's seams
//! ([`super::donation`]) on threads that stay suspended, so nothing runs
//! but the batches, and set up many waits at once without running each
//! thread at EL0. Two run at EL0, through the test trap: a passive
//! server on its caller's budget, and a revoke restarted at every
//! preemption point. After each step that changes donation state, a test
//! checks `ksched::donation`'s invariants on the kernel's objects (the C12
//! plan, §4.8). Each ends with [`testkit::finish`]'s baseline check.

use super::donation::{self, is_live, reply_rec, sc_rec};
use super::fault::{Kind, seam};
use super::object::{Ended, Rp, Sc, Tcb, Wait, flag};
use super::percore::this_core;
use super::testkit::{
    self, Spec, User, control, endpoint, first_thread, make_room, ms, space, spawn_in,
};
use super::{boot, context, run, thread};
use crate::cap::testkit::Scratch;
use crate::cap::{self, DirectSlots, boot as cboot};
use crate::testing::driver::run_until;
use crate::testing::report;
use crate::testing::trap::{FORCE_PREEMPT, LAST_DAIF};
use crate::testing::user::Program;
use core::sync::atomic::{AtomicU64, Ordering};
use kcap::SlotRef;
use kcap::cap::{Binding, Cap};
use kcap::mdb;
use kmem::untyped::ObjectType;
use ksched::donation::{Delivered, Error as DErr, Step};

/// The thread a test's condition watches.
static W: AtomicU64 = AtomicU64::new(0);

fn watch(t: Tcb) {
    W.store(t.0, Ordering::Relaxed);
}

fn w() -> Tcb {
    Tcb(W.load(Ordering::Relaxed))
}

fn walks_done() -> bool {
    this_core().work.is_empty()
}

fn w_done() -> bool {
    w().has(flag::DONE)
}

fn w_ready() -> bool {
    w().wait() == Wait::None
}

fn w_receiving() -> bool {
    w().wait() == Wait::Receive
}

fn w_timeout_fault() -> bool {
    w().wait() == Wait::TimeoutSend
}

fn no_deadlines() -> bool {
    this_core().deadline_root == 0
}

fn no_releases() -> bool {
    this_core().release_root == 0
}

/// A scratch space with room made on the boot core, and empty logs.
fn scratch() -> Scratch {
    make_room();
    report::clear();
    seam::clear_sent();
    Scratch::new(20)
}

fn tcb(s: SlotRef) -> Tcb {
    match Tcb::of(&cap::cap(s)) {
        Some(t) => t,
        None => panic!("slot {:#x} holds no thread", s.0),
    }
}

fn sc_of(s: SlotRef) -> Sc {
    match cap::cap(s) {
        Cap::SchedContext { ptr, .. } => Sc(ptr),
        c => panic!("slot {:#x} holds {c:x?}, not a context", s.0),
    }
}

fn x(t: Tcb, i: usize) -> u64 {
    t.with(|b| b.ctx.x[i])
}

/// A thread with root CNode and address space `s`, at priority 10, with
/// no context: a passive server. It stays suspended, so it never runs:
/// the test drives it through the kernel's seams.
fn passive(sc: &mut Scratch, s: SlotRef, tep: Option<SlotRef>) -> (SlotRef, Tcb) {
    let t = sc.make(ObjectType::Thread);
    thread::configure_space(t, cboot::root_slot(cboot::ROOT_SELF), s).unwrap();
    thread::set_priority(t, first_thread(), 10).unwrap();
    if let Some(ep) = tep {
        thread::set_endpoint(t, Binding::TimeoutEndpoint, Some(ep)).unwrap();
    }
    (t, tcb(t))
}

fn reply_obj(sc: &mut Scratch) -> (SlotRef, Rp) {
    let r = sc.make(ObjectType::Reply);
    match Rp::of(&cap::cap(r)) {
        Some(p) => (r, p),
        None => panic!("no reply object"),
    }
}

/// A caller with its own context, 200 µs in 1 ms with `badge`, suspended.
fn caller(sc: &mut Scratch, s: SlotRef, badge: u64) -> User {
    let mut spec = Spec::of(Program::Spin);
    spec.badge = badge;
    let u = spawn_in(sc, s, spec);
    thread::suspend(u.thread).unwrap();
    u
}

/// A chain C → S1 → … → Sn of passive servers, each waiting with its own
/// reply object, then called in turn.
struct Chain {
    c: User,
    ctx: Sc,
    st: [SlotRef; 4],
    s: [Tcb; 4],
    rs: [SlotRef; 4],
    r: [Rp; 4],
    n: usize,
}

impl Chain {
    /// Checks the protocol's invariants over the chain's objects, leaving
    /// out the threads and replies a test destroyed.
    fn check(&self, gone_t: &[Tcb], gone_r: &[Rp]) {
        let mut ts = [Tcb(0); 5];
        let mut nt = 0;
        for t in core::iter::once(self.c.tcb).chain(self.s[..self.n].iter().copied()) {
            if !gone_t.contains(&t) {
                ts[nt] = t;
                nt += 1;
            }
        }
        let mut rs = [Rp(0); 4];
        let mut nr = 0;
        for &r in &self.r[..self.n] {
            if !gone_r.contains(&r) {
                rs[nr] = r;
                nr += 1;
            }
        }
        if let Err(v) = donation::check(&ts[..nt], &rs[..nr], &[self.ctx]) {
            panic!("donation invariant broken: {v:?}");
        }
    }

    fn holder(&self) -> Option<u64> {
        sc_rec(self.ctx).holder.map(|t| t.0)
    }

    fn top(&self) -> Option<u64> {
        sc_rec(self.ctx).top.map(|r| r.0)
    }
}

fn chain(sc: &mut Scratch, n: usize, tep: bool, badge: u64) -> Chain {
    assert!(n <= 4);
    let s = space(sc);
    let ep = endpoint(sc);
    let c = caller(sc, s, badge);
    let ctx = sc_of(c.context);
    let mut ch = Chain {
        c,
        ctx,
        st: [SlotRef(0); 4],
        s: [Tcb(0); 4],
        rs: [SlotRef(0); 4],
        r: [Rp(0); 4],
        n,
    };
    for i in 0..n {
        let (st, t) = passive(sc, s, tep.then_some(ep));
        let (rs, r) = reply_obj(sc);
        donation::recv(t, r).unwrap();
        (ch.st[i], ch.s[i], ch.rs[i], ch.r[i]) = (st, t, rs, r);
    }
    let mut from = ch.c.tcb;
    for i in 0..n {
        match donation::call(from, ch.s[i], 100 + i as u64) {
            Ok(Delivered::Donated(d)) if d.0 == ctx.0 => {}
            r => panic!("call {i} of the chain: {r:?}"),
        }
        ch.check(&[], &[]);
        from = ch.s[i];
    }
    ch
}

crate::kernel_test!(donation_moves_the_context_along_a_chain, {
    let mut sc = scratch();
    let ch = chain(&mut sc, 2, false, 0xb0d6e);
    let (c, s1, s2) = (ch.c.tcb, ch.s[0], ch.s[1]);
    // The context is with S2, at the top of a stack r2 over r1, and keeps
    // its badge.
    assert_eq!(ch.holder(), Some(s2.0));
    assert_eq!(ch.top(), Some(ch.r[1].0));
    assert_eq!(reply_rec(ch.r[1]).prev.map(|r| r.0), Some(ch.r[0].0));
    assert_eq!(sc_rec(ch.ctx).badge, 0xb0d6e);
    assert_eq!(
        (c.wait(), s1.wait(), s2.wait()),
        (Wait::Call, Wait::Call, Wait::None)
    );
    assert!(c.sc().is_none() && s1.sc().is_none() && s2.sc() == Some(ch.ctx));
    // The server's receive ended with the caller's word.
    assert_eq!((x(s2, 0), x(s2, 1)), (Ended::Done as u64, 101));
    // Only the holder answers, at the top; anyone else changes nothing.
    assert_eq!(donation::reply(s1, ch.r[0], 0), Err(DErr::NotHolder));
    ch.check(&[], &[]);
    // The replies return it step by step.
    donation::reply(s2, ch.r[1], 7).unwrap();
    assert_eq!(ch.holder(), Some(s1.0));
    assert_eq!(s1.wait(), Wait::None);
    assert_eq!((x(s1, 0), x(s1, 1)), (Ended::Done as u64, 7));
    ch.check(&[], &[]);
    donation::reply(s1, ch.r[0], 8).unwrap();
    assert_eq!(ch.holder(), Some(c.0));
    assert_eq!(ch.top(), None);
    assert_eq!(
        (c.wait(), x(c, 0), x(c, 1)),
        (Wait::None, Ended::Done as u64, 8)
    );
    assert_eq!(c.sc(), Some(ch.ctx));
    ch.check(&[], &[]);
    testkit::finish(sc);
});

crate::kernel_test!(take_back_on_cancel, {
    // One hop: C → S1. The cancel gives C its context back at once; the
    // walk then sends S1 its context-withdrawn fault.
    let mut sc = scratch();
    let ch = chain(&mut sc, 1, true, 0x0ce);
    thread::cancel(ch.c.thread).unwrap();
    assert_eq!(ch.holder(), Some(ch.c.tcb.0));
    assert_eq!(
        (ch.c.tcb.wait(), x(ch.c.tcb, 0)),
        (Wait::None, Ended::Canceled as u64)
    );
    assert!(!this_core().work.is_empty(), "no walk was queued");
    ch.check(&[], &[]);
    assert!(run_until(walks_done, ms(2_000)), "the walk didn't end");
    assert_eq!(ch.s[0].wait(), Wait::WithdrawnSend);
    let f = ch.s[0].state().fault;
    assert_eq!((f.kind, f.addr), (Kind::Withdrawn as u64, 0x0ce));
    ch.check(&[], &[]);
    testkit::finish(sc);
    // Two hops: S1's fault first, then S2's; S1's onward call ended
    // "canceled"; S1's later reply fails with "no caller".
    let mut sc = scratch();
    let ch = chain(&mut sc, 2, true, 0x0ce2);
    thread::cancel(ch.c.thread).unwrap();
    assert_eq!(ch.holder(), Some(ch.c.tcb.0));
    assert!(!is_live(ch.r[0]) && !is_live(ch.r[1]));
    assert!(ch.s[1].sc().is_none(), "the holder kept the context");
    ch.check(&[], &[]);
    assert!(run_until(walks_done, ms(2_000)), "the walk didn't end");
    assert_eq!(seam::sent_count(), 2);
    assert_eq!(seam::sent(0), Some(ch.s[0]));
    assert_eq!(seam::sent(1), Some(ch.s[1]));
    assert_eq!(x(ch.s[0], 0), Ended::Canceled as u64);
    for s in &ch.s[..2] {
        assert_eq!(s.wait(), Wait::WithdrawnSend);
        assert_eq!(s.state().fault.addr, 0x0ce2);
    }
    assert_eq!(donation::reply(ch.s[0], ch.r[0], 0), Err(DErr::NoCaller));
    ch.check(&[], &[]);
    testkit::finish(sc);
});

crate::kernel_test!(take_back_on_deadline, {
    // C's call has a deadline: when it passes, C has its context back with
    // "timed out", inside the batch that ends the wait (ADR 0051, rule 3).
    let mut sc = scratch();
    let ch = chain(&mut sc, 1, true, 0xd1);
    let expiries = this_core().stats.expiries;
    run::deadline_insert(ch.c.tcb, crate::timer::now() + ms(20));
    watch(ch.c.tcb);
    assert!(
        run_until(w_ready, ms(2_000)),
        "the deadline didn't end the call"
    );
    assert_eq!(x(ch.c.tcb, 0), Ended::TimedOut as u64);
    assert_eq!(ch.holder(), Some(ch.c.tcb.0));
    assert_eq!(this_core().stats.expiries - expiries, 1);
    assert!(run_until(walks_done, ms(2_000)));
    assert_eq!(ch.s[0].wait(), Wait::WithdrawnSend);
    assert_eq!(ch.s[0].state().fault.addr, 0xd1);
    ch.check(&[], &[]);
    testkit::finish(sc);
});

crate::kernel_test!(take_back_cancels_stranded_waits, {
    // K17: the holder's own wait, here a sleep, is canceled at the cut;
    // each server below has its onward call canceled, then its fault.
    let mut sc = scratch();
    let ch = chain(&mut sc, 2, true, 0x17);
    let s2 = ch.s[1];
    s2.update(|s| s.wait = Wait::TestSleep as u8);
    donation::wait_other(s2);
    thread::cancel(ch.c.thread).unwrap();
    assert_eq!((s2.wait(), x(s2, 0)), (Wait::None, Ended::Canceled as u64));
    assert!(run_until(walks_done, ms(2_000)));
    assert_eq!(x(ch.s[0], 0), Ended::Canceled as u64);
    assert_eq!(ch.s[0].wait(), Wait::WithdrawnSend);
    // The fault doesn't touch x0: the server sees "canceled" when its
    // handler resumes it (K20).
    assert_eq!(
        (s2.wait(), x(s2, 0)),
        (Wait::WithdrawnSend, Ended::Canceled as u64)
    );
    ch.check(&[], &[]);
    testkit::finish(sc);
});

crate::kernel_test!(stranded_server_without_timeout_endpoint_gets_no_fault, {
    let mut sc = scratch();
    let ch = chain(&mut sc, 1, false, 1);
    thread::cancel(ch.c.thread).unwrap();
    assert!(run_until(walks_done, ms(2_000)));
    let s1 = ch.s[0];
    assert_eq!(s1.wait(), Wait::None);
    assert!(s1.sc().is_none() && !s1.has(flag::QUEUED));
    assert_eq!(seam::sent_count(), 0);
    ch.check(&[], &[]);
    testkit::finish(sc);
});

crate::kernel_test!(removing_the_timeout_endpoint_while_donated, {
    // K08: allowed while the server runs on a donated context; a later
    // take-back strands it silently.
    let mut sc = scratch();
    let ch = chain(&mut sc, 1, true, 1);
    thread::set_endpoint(ch.st[0], Binding::TimeoutEndpoint, None).unwrap();
    assert_eq!(ch.holder(), Some(ch.s[0].0));
    thread::cancel(ch.c.thread).unwrap();
    assert!(run_until(walks_done, ms(2_000)));
    assert_eq!(ch.s[0].wait(), Wait::None);
    assert_eq!(seam::sent_count(), 0);
    ch.check(&[], &[]);
    testkit::finish(sc);
});

crate::kernel_test!(queued_fault_withdrawn_when_its_endpoint_is_unset, {
    // K50: a context-withdrawn fault still queued is withdrawn with its
    // endpoint, and the server is stranded silently.
    let mut sc = scratch();
    let ch = chain(&mut sc, 1, true, 1);
    thread::cancel(ch.c.thread).unwrap();
    assert!(run_until(walks_done, ms(2_000)));
    assert_eq!(ch.s[0].wait(), Wait::WithdrawnSend);
    thread::set_endpoint(ch.st[0], Binding::TimeoutEndpoint, None).unwrap();
    assert_eq!(ch.s[0].wait(), Wait::None);
    assert!(ch.s[0].sc().is_none());
    ch.check(&[], &[]);
    testkit::finish(sc);
});

crate::kernel_test!(unbinding_a_donated_context_takes_it_back, {
    let mut sc = scratch();
    let ch = chain(&mut sc, 1, true, 0x0b);
    // A thread that serves a donated call can't be bound a context.
    let other = sc.make(ObjectType::SchedContext(8));
    context::configure(control(), other, 100, 10_000, 0, 0).unwrap();
    assert_eq!(
        thread::bind_context(ch.st[0], other),
        Err(super::Error::Busy)
    );
    thread::unbind_context(ch.c.thread).unwrap();
    let c = ch.c.tcb;
    assert_eq!((c.wait(), x(c, 0)), (Wait::None, Ended::Canceled as u64));
    assert!(c.sc().is_none() && c.home().is_none());
    assert_eq!((sc_rec(ch.ctx).holder, sc_rec(ch.ctx).home), (None, None));
    assert!(run_until(walks_done, ms(2_000)));
    assert_eq!(ch.s[0].wait(), Wait::WithdrawnSend);
    // Its walk step has passed: now it may be lent a context.
    thread::bind_context(ch.st[0], other).unwrap();
    thread::unbind_context(ch.st[0]).unwrap();
    thread::bind_context(ch.c.thread, ch.c.context).unwrap();
    ch.check(&[], &[]);
    testkit::finish(sc);
});

crate::kernel_test!(destroying_a_reply_or_server_mid_walk, {
    // Destroying a server that serves a live donated call gives the
    // context back to its caller, whose call ends "canceled"; the rest of
    // the chain stands, and the caller can still reply.
    let mut sc = scratch();
    let ch = chain(&mut sc, 2, true, 2);
    cap::delete(ch.st[1]);
    let s1 = ch.s[0];
    assert_eq!(ch.holder(), Some(s1.0));
    assert_eq!((s1.wait(), x(s1, 0)), (Wait::None, Ended::Canceled as u64));
    assert!(is_live(ch.r[0]));
    assert!(run_until(walks_done, ms(2_000)));
    ch.check(&[ch.s[1]], &[]);
    donation::reply(s1, ch.r[0], 5).unwrap();
    assert_eq!((ch.holder(), x(ch.c.tcb, 1)), (Some(ch.c.tcb.0), 5));
    ch.check(&[ch.s[1]], &[]);
    testkit::finish(sc);
    // With a walk pending over C → S1 → S2 → S3, destroying the stale
    // r2 takes its step at once (S2's onward call canceled, then its
    // fault), and destroying S3, which serves the stale r3, leaves the walk
    // to skip it.
    let mut sc = scratch();
    let ch = chain(&mut sc, 3, true, 3);
    thread::cancel(ch.c.thread).unwrap();
    cap::delete(ch.rs[1]);
    assert_eq!(ch.s[1].wait(), Wait::WithdrawnSend);
    assert_eq!(x(ch.s[1], 0), Ended::Canceled as u64);
    assert_eq!(x(ch.s[0], 0), Ended::Canceled as u64);
    cap::delete(ch.st[2]);
    ch.check(&[ch.s[2]], &[ch.r[1]]);
    assert!(run_until(walks_done, ms(2_000)));
    assert_eq!(seam::sent_count(), 2);
    assert_eq!(
        (seam::sent(0), seam::sent(1)),
        (Some(ch.s[1]), Some(ch.s[0]))
    );
    assert_eq!(ch.s[0].wait(), Wait::WithdrawnSend);
    ch.check(&[ch.s[2]], &[ch.r[1]]);
    testkit::finish(sc);
});

crate::kernel_test!(mid_chain_cancel_and_two_take_backs, {
    // Canceling S1's onward call gives S1 the context back and leaves
    // C's call to S1 live, so S1's reply still reaches C.
    let mut sc = scratch();
    let ch = chain(&mut sc, 2, true, 4);
    let s1 = ch.s[0];
    thread::cancel_thread(s1).unwrap();
    assert_eq!(ch.holder(), Some(s1.0));
    assert_eq!(x(s1, 0), Ended::Canceled as u64);
    assert!(is_live(ch.r[0]) && !is_live(ch.r[1]));
    ch.check(&[], &[]);
    donation::reply(s1, ch.r[0], 9).unwrap();
    assert_eq!((ch.holder(), x(ch.c.tcb, 1)), (Some(ch.c.tcb.0), 9));
    assert!(run_until(walks_done, ms(2_000)));
    assert_eq!(seam::sent(0), Some(ch.s[1]));
    ch.check(&[], &[]);
    testkit::finish(sc);
    // Two take-backs on one context while the first walk is pending:
    // each stranded server is faulted exactly once.
    let mut sc = scratch();
    let ch = chain(&mut sc, 3, true, 5);
    thread::cancel_thread(ch.s[1]).unwrap();
    thread::cancel(ch.c.thread).unwrap();
    assert_eq!(ch.holder(), Some(ch.c.tcb.0));
    ch.check(&[], &[]);
    assert!(run_until(walks_done, ms(2_000)));
    assert_eq!(seam::sent_count(), 3);
    assert_eq!(seam::sent(0), Some(ch.s[2]));
    assert_eq!(seam::sent(1), Some(ch.s[0]));
    assert_eq!(seam::sent(2), Some(ch.s[1]));
    ch.check(&[], &[]);
    testkit::finish(sc);
});

crate::kernel_test!(suspend_keeps_a_donated_call, {
    // ADR 0061, rule 3 and K20: suspending a caller blocked in a donating
    // call keeps the server on the donated context and sends no fault; the
    // reply is held in the caller's registers until it resumes. Suspending
    // the server takes nothing back.
    let mut sc = scratch();
    let ch = chain(&mut sc, 1, true, 6);
    let (c, s1) = (ch.c.tcb, ch.s[0]);
    thread::resume(ch.st[0]).unwrap();
    thread::suspend(ch.st[0]).unwrap();
    assert_eq!(ch.holder(), Some(s1.0));
    assert_eq!(c.wait(), Wait::Call);
    assert_eq!(seam::sent_count(), 0);
    donation::reply(s1, ch.r[0], 3).unwrap();
    assert_eq!(
        (c.wait(), x(c, 0), x(c, 1)),
        (Wait::None, Ended::Done as u64, 3)
    );
    assert!(
        !c.has(flag::RESUMED),
        "the reply resumed a suspended caller"
    );
    assert_eq!(ch.holder(), Some(c.0));
    ch.check(&[], &[]);
    testkit::finish(sc);
});

/// `n` objects of type `ty` in a CNode of radix 9 made in the scratch
/// space, and the CNode's first slot.
fn many(sc: &mut Scratch, ty: ObjectType, n: u64) -> SlotRef {
    let cn = sc.make(ObjectType::CNode(9));
    // One retype makes at most `RETYPE_FAN_OUT` objects, as seL4's limit.
    let mut first = 0;
    while first < n {
        let k = (n - first).min(kcap::RETYPE_FAN_OUT);
        cap::retype(sc.ram, ty, cn, first, k)
            .unwrap_or_else(|e| panic!("can't make {n} {ty:?}: {e:?}"));
        first += k;
    }
    match cap::cap(cn) {
        Cap::CNode { ptr, .. } => SlotRef(ptr),
        c => panic!("{c:x?}"),
    }
}

crate::kernel_test!(long_chain_take_back_runs_in_batches, {
    // 250 passive servers: the walk takes 250 units, so at least three
    // batches of at most 100; every server is faulted, S1 first (ADR 0052,
    // rule 2; K24).
    const N: usize = 250;
    let mut sc = scratch();
    let s = space(&mut sc);
    let ep = endpoint(&mut sc);
    let c = caller(&mut sc, s, 0x250);
    let ts = many(&mut sc, ObjectType::Thread, N as u64);
    let rs = many(&mut sc, ObjectType::Reply, N as u64);
    let mut threads = [Tcb(0); N + 1];
    let mut replies = [Rp(0); N];
    threads[N] = c.tcb;
    for i in 0..N {
        let t = ts.offset(i as u64);
        thread::configure_space(t, cboot::root_slot(cboot::ROOT_SELF), s).unwrap();
        thread::set_endpoint(t, Binding::TimeoutEndpoint, Some(ep)).unwrap();
        threads[i] = tcb(t);
        replies[i] = Rp::of(&cap::cap(rs.offset(i as u64))).unwrap();
        donation::recv(threads[i], replies[i]).unwrap();
    }
    let mut from = c.tcb;
    for (i, &t) in threads[..N].iter().enumerate() {
        donation::call(from, t, i as u64).unwrap();
        from = t;
    }
    let ctx = sc_of(c.context);
    donation::check(&threads, &replies, &[ctx]).unwrap();
    let st = this_core().stats;
    let steps = donation::steps(Step::WalkStep(ksched::donation::Reply(0)));
    thread::cancel(c.thread).unwrap();
    assert_eq!(sc_rec(ctx).holder.map(|t| t.0), Some(c.tcb.0));
    assert!(run_until(walks_done, ms(5_000)), "the walk didn't end");
    let now = this_core().stats;
    assert_eq!(now.walk_steps - st.walk_steps, N as u64);
    assert_eq!(
        donation::steps(Step::WalkStep(ksched::donation::Reply(0))) - steps,
        N as u64
    );
    assert!(now.batches_of[2] - st.batches_of[2] >= N.div_ceil(100) as u64);
    assert!(now.batch_max <= ksched::BATCH_UNITS as u64);
    assert_eq!(seam::sent_count(), N);
    for (i, t) in threads[..64].iter().enumerate() {
        assert_eq!(seam::sent(i), Some(*t), "fault {i} out of order");
    }
    for t in &threads[..N] {
        assert_eq!(t.wait(), Wait::WithdrawnSend);
        assert_eq!(t.state().fault.addr, 0x250);
    }
    donation::check(&threads, &replies, &[ctx]).unwrap();
    testkit::finish(sc);
});

crate::kernel_test!(many_deadlines_expire_in_batches, {
    // 300 sleeps with one deadline, a second ahead, set up at once:
    // at least three batches of at most 100, every wait timed out.
    const N: u64 = 300;
    let mut sc = scratch();
    let ts = many(&mut sc, ObjectType::Thread, N);
    let core = this_core().index as u8;
    let deadline = crate::timer::now() + ms(1_000);
    for i in 0..N {
        let t = tcb(ts.offset(i));
        t.update(|s| {
            s.core = core;
            s.wait = Wait::TestSleep as u8;
        });
        run::deadline_insert(t, deadline);
    }
    let st = this_core().stats;
    assert!(
        run_until(no_deadlines, ms(5_000)),
        "the deadlines didn't pass"
    );
    let now = this_core().stats;
    assert_eq!(now.expiries - st.expiries, N);
    assert!(now.batches_of[1] - st.batches_of[1] >= N.div_ceil(100));
    assert!(now.batch_max <= ksched::BATCH_UNITS as u64);
    assert!(
        now.batches_left > st.batches_left,
        "no batch left work over"
    );
    // Nothing became runnable, so the core ran batch after batch, and gave
    // the lock up between them (ADR 0052, rule 2).
    assert!(
        now.batch_yields - st.batch_yields >= N.div_ceil(100) - 1,
        "the lock wasn't given up between batches"
    );
    for i in 0..N {
        let t = tcb(ts.offset(i));
        assert_eq!((t.wait(), x(t, 0)), (Wait::None, Ended::TimedOut as u64));
    }
    testkit::finish(sc);
});

crate::kernel_test!(many_refills_release_in_batches, {
    // 300 contexts whose refills come due at one count: released in at
    // least three batches of at most 100.
    const N: u64 = 300;
    let mut sc = scratch();
    let cs = many(&mut sc, ObjectType::SchedContext(8), N);
    for i in 0..N {
        context::configure(control(), cs.offset(i), 10, 1_000_000, 0, 0).unwrap();
    }
    let start = crate::timer::now();
    for i in 0..N {
        let c = sc_of(cs.offset(i));
        c.refills(|r| {
            let b = r.st.budget;
            r.charge(start, b, start)
        });
        run::release_insert(c, start);
    }
    let st = this_core().stats;
    assert!(
        run_until(no_releases, ms(5_000)),
        "the refills weren't released"
    );
    let now = this_core().stats;
    assert_eq!(now.releases - st.releases, N);
    assert!(now.batches_of[0] - st.batches_of[0] >= N.div_ceil(100));
    assert!(now.batch_max <= ksched::BATCH_UNITS as u64);
    testkit::finish(sc);
});

crate::kernel_test!(server_runs_on_the_callers_budget_at_el0, {
    // At EL0, through the trap: a server receives, is made passive, and
    // serves a call on the caller's context, which is charged.
    let mut sc = scratch();
    let s = space(&mut sc);
    let (r_slot, _) = reply_obj(&mut sc);
    let mut spec = Spec::of(Program::Serve);
    spec.args = [sc.addr_of(r_slot), 20_000, 0];
    let srv = spawn_in(&mut sc, s, spec);
    watch(srv.tcb);
    assert!(
        run_until(w_receiving, ms(2_000)),
        "the server didn't receive"
    );
    let own = sc_of(srv.context);
    thread::unbind_context(srv.thread).unwrap();
    let own_used = own.header().consumed;
    let mut spec = Spec::of(Program::CallReport);
    spec.args = [sc.addr_of(srv.thread), 0, 41];
    spec.badge = 0xca11;
    let cl = spawn_in(&mut sc, s, spec);
    let ctx = sc_of(cl.context);
    watch(cl.tcb);
    assert!(run_until(w_done, ms(5_000)), "the caller didn't end");
    assert!(report::values_of(srv.tcb.0).eq([41]));
    assert!(report::values_of(cl.tcb.0).eq([Ended::Done as u64, 42]));
    assert!(ctx.header().consumed > 0);
    assert_eq!(
        own.header().consumed,
        own_used,
        "the server's own context was charged"
    );
    assert_eq!(srv.tcb.wait(), Wait::Receive);
    assert!(srv.tcb.sc().is_none());
    // A budget that runs out mid-request: the timeout fault comes from the
    // server, with the caller's badge, and donates nothing. Canceling the
    // call then takes the context back, and the server gets its
    // context-withdrawn fault.
    let (r2, _) = reply_obj(&mut sc);
    let ep = endpoint(&mut sc);
    let mut spec = Spec::of(Program::Serve);
    spec.args = [sc.addr_of(r2), u64::MAX, 0];
    let srv2 = spawn_in(&mut sc, s, spec);
    watch(srv2.tcb);
    assert!(run_until(w_receiving, ms(2_000)));
    thread::set_endpoint(srv2.thread, Binding::TimeoutEndpoint, Some(ep)).unwrap();
    thread::unbind_context(srv2.thread).unwrap();
    let mut spec = Spec::of(Program::CallReport);
    spec.args = [sc.addr_of(srv2.thread), 0, 5];
    spec.budget_us = 200;
    spec.period_us = 10_000;
    spec.badge = 0xfeed;
    let cl2 = spawn_in(&mut sc, s, spec);
    watch(srv2.tcb);
    assert!(run_until(w_timeout_fault, ms(5_000)), "no timeout fault");
    let f = srv2.tcb.state().fault;
    assert_eq!((f.kind, f.addr), (Kind::Timeout as u64, 0xfeed));
    assert_eq!(srv2.tcb.sc(), Some(sc_of(cl2.context)));
    assert_eq!(cl2.tcb.wait(), Wait::Call);
    thread::cancel(cl2.thread).unwrap();
    watch(cl2.tcb);
    assert!(
        run_until(w_done, ms(5_000)),
        "the canceled caller didn't end"
    );
    assert_eq!(
        report::values_of(cl2.tcb.0).next(),
        Some(Ended::Canceled as u64)
    );
    assert!(run_until(walks_done, ms(2_000)));
    let f = srv2.tcb.state().fault;
    assert_eq!(srv2.tcb.wait(), Wait::WithdrawnSend);
    assert_eq!((f.kind, f.addr), (Kind::Withdrawn as u64, 0xfeed));
    testkit::finish(sc);
});

crate::kernel_test!(preempted_revoke_restarts_from_el0, {
    // A revoke of 200 copies, with an interrupt "pending" at every
    // preemption point: the system call is made again each time, and ends
    // as an unpreempted revoke does.
    const N: u64 = 200;
    let mut sc = scratch();
    let s = space(&mut sc);
    let ep = endpoint(&mut sc);
    let cn = sc.make(ObjectType::CNode(8));
    let first = match cap::cap(cn) {
        Cap::CNode { ptr, .. } => SlotRef(ptr),
        c => panic!("{c:x?}"),
    };
    for i in 0..N {
        cap::copy(ep, first.offset(i)).unwrap();
    }
    let restarts = this_core().stats.restarts;
    let mut spec = Spec::of(Program::RevokeReport);
    spec.args[0] = sc.addr_of(ep);
    FORCE_PREEMPT.store(true, Ordering::Relaxed);
    let u = spawn_in(&mut sc, s, spec);
    watch(u.tcb);
    let ended = run_until(w_done, ms(10_000));
    FORCE_PREEMPT.store(false, Ordering::Relaxed);
    assert!(ended, "the revoke didn't end");
    assert!(
        this_core().stats.restarts > restarts,
        "the revoke was never restarted"
    );
    assert!(report::values_of(u.tcb.0).eq([Ended::Done as u64]));
    assert!(!mdb::has_children(&DirectSlots, ep));
    for i in 0..N {
        assert!(cap::cap(first.offset(i)).is_null(), "copy {i} survived");
    }
    testkit::finish(sc);
});

crate::kernel_test!(serror_unmasked_in_kernel_and_at_el0, {
    // K77: DAIF.A is clear in the kernel, in a trap's handler once the
    // entry is on the entry stack, and in a thread's saved SPSR.
    assert_eq!(
        boot::daif() & boot::DAIF_A,
        0,
        "SError is masked in the kernel"
    );
    let mut sc = scratch();
    let s = space(&mut sc);
    let u = spawn_in(&mut sc, s, Spec::of(Program::ReportEnd));
    watch(u.tcb);
    assert!(run_until(w_done, ms(2_000)));
    assert_eq!(
        LAST_DAIF.load(Ordering::Relaxed) & boot::DAIF_A,
        0,
        "SError masked in a trap"
    );
    assert_eq!(
        u.tcb.with(|b| b.ctx.spsr) & boot::DAIF_A,
        0,
        "SError masked at EL0"
    );
    testkit::finish(sc);
});

crate::kernel_test!(psci_found_with_its_conduit_and_version, {
    // K21: QEMU's virt machine has PSCI 0.2 or later, through HVC, or SMC
    // when EL2 is emulated.
    let Some(p) = crate::smp::psci() else {
        panic!("no PSCI found");
    };
    assert!(p.version.0 > 0 || p.version.1 >= 2, "PSCI {:?}", p.version);
    let v = crate::smp::psci::call(p.conduit, ksched::smp::psci::VERSION, 0, 0, 0);
    assert_eq!(ksched::smp::psci::version(v), p.version);
});
