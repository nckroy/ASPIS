// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! In-QEMU tests of threads and scheduling on the boot core (C12's stage 2;
//! ADR 0036, rule 5; ADR 0051, rules 1, 2 and 5; ADR 0056, rule 1; ADR
//! 0061, rule 3; K13, K15, K19, K20, K70). Each runs EL0 threads through
//! the driver, asserts from the threads' state and the report log, not
//! from elapsed time, and leaves the scheduler as it
//! found it ([`testkit::finish`]).

use super::context::{self, configure};
use super::fault::{self, Kind};
use super::object::{Ended, Sc, Tcb, Wait, capacity, flag};
use super::percore::this_core;
use super::testkit::{
    self, Spec, UNMAPPED_VA, control, endpoint, first_context, first_thread, make_room, ms, run_ms,
    spawn,
};
use super::{Error, boot, thread};
use crate::cap::testkit::Scratch;
use crate::cap::{self, DirectSlots, boot as cboot};
use crate::testing::driver::run_until;
use crate::testing::report;
use crate::testing::user::Program;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kcap::cap::{Binding, Cap};
use kcap::{mdb, ops};
use kmem::untyped::ObjectType;
use ksched::share::Refused;
use ksched::time::Invalid;

/// The threads a test's conditions watch, and a report count.
static T1: AtomicU64 = AtomicU64::new(0);
static T2: AtomicU64 = AtomicU64::new(0);
static N: AtomicUsize = AtomicUsize::new(0);

fn watch(a: Tcb, b: Option<Tcb>) {
    T1.store(a.0, Ordering::Relaxed);
    T2.store(b.map_or(0, |t| t.0), Ordering::Relaxed);
}

fn t1() -> Tcb {
    Tcb(T1.load(Ordering::Relaxed))
}

fn t2() -> Tcb {
    Tcb(T2.load(Ordering::Relaxed))
}

fn done1() -> bool {
    t1().has(flag::DONE)
}

fn done12() -> bool {
    t1().has(flag::DONE) && t2().has(flag::DONE)
}

fn waiting1() -> bool {
    t1().wait() != Wait::None
}

fn suspended1() -> bool {
    !t1().has(flag::RESUMED)
}

fn reports_n() -> bool {
    report::count() >= N.load(Ordering::Relaxed)
}

fn reports_of_1_n() -> bool {
    report::count_of(t1().0) >= N.load(Ordering::Relaxed)
}

/// A scratch space with room made on the boot core.
fn scratch() -> Scratch {
    make_room();
    report::clear();
    Scratch::new(20)
}

/// The exception class of a fault record's syndrome.
fn ec(t: Tcb) -> u64 {
    t.state().fault.esr >> 26
}

crate::kernel_test!(first_thread_is_suspended_at_priority_255, {
    // The first thread is the authority for every priority.
    let t = Tcb(boot::first_thread());
    assert!(matches!(cap::cap(first_thread()), Cap::Thread { .. }));
    let s = t.state();
    assert_eq!((s.priority, s.mcp), (255, 255));
    assert!(!t.has(flag::RESUMED), "the first thread isn't suspended");
    // Its context is bound in its slot 5, from root slot 5: one page.
    let Cap::SchedContext { ptr, bits: 12, .. } = cap::cap(first_context()) else {
        panic!("root slot 5 holds {:x?}", cap::cap(first_context()));
    };
    assert_eq!(s.sc, ptr);
    assert_eq!(t.slot_cap(5).binding(), Some(Binding::Context));
    assert_eq!(Sc(ptr).header().home, t.0);
    assert!(Sc(ptr).is_configured());
    // No root CNode, address space or endpoints: C17 and C19 set them.
    for i in [1, 2, 3, 4] {
        assert!(t.slot_cap(i).is_null(), "first thread slot {i}");
    }
    assert!(cap::cap(cboot::root_slot(3)).is_null());
    assert_eq!(capacity(12), 244);
    assert_eq!(capacity(8), 4);
});

crate::kernel_test!(scheduling_control_in_boot_space, {
    // Root slot 4 is the scheduling-control CNode; slot n holds core n's
    // control, for each online core: only the boot core in the tests'
    // first phase, before the other cores start.
    let me = this_core().index;
    let Cap::CNode { radix: 7, .. } = cap::cap(cboot::root_slot(cboot::SCHED_CONTROL)) else {
        panic!("root slot 4");
    };
    assert_eq!(cap::cap(control()), Cap::SchedControl { core: me as u8 });
    for i in 0..cboot::SLOTS as usize {
        if i != me {
            assert!(
                cap::cap(boot::control_slot(i)).is_null(),
                "control slot {i}"
            );
        }
    }
    // As in seL4, control copies: a copy is a child, which configures as
    // the original does, and revoking reaches it. It moves too.
    let mut sc = scratch();
    let (a, b, m) = (sc.take(), sc.take(), sc.take());
    cap::copy(control(), a).unwrap();
    cap::copy(a, b).unwrap();
    cap::move_cap(b, m).unwrap();
    let c = sc.make(ObjectType::SchedContext(8));
    configure(m, c, 100, 1_000, 0, 0).unwrap();
    cap::revoke(a);
    assert!(cap::cap(m).is_null(), "revoking a copy left its child");
    cap::delete(a);
    assert_eq!(cap::cap(control()), Cap::SchedControl { core: me as u8 });
    testkit::finish(sc);
});

crate::kernel_test!(el0_thread_runs_and_reports, {
    let mut sc = scratch();
    let mut spec = Spec::of(Program::ReportEnd);
    spec.args[0] = 0x1234_5678;
    let u = spawn(&mut sc, spec);
    watch(u.tcb, None);
    assert!(run_until(done1, ms(2_000)), "the thread didn't end");
    assert!(report::values_of(u.tcb.0).eq([0x1234_5678]));
    assert!(!u.tcb.has(flag::RESUMED), "END didn't suspend it");
    assert!(this_core().stats.entries > 0);
    testkit::finish(sc);
});

crate::kernel_test!(registers_and_tpidr_el0_round_trip, {
    // Two threads write their own TPIDR_EL0 and are preempted while they
    // spin; each reads back its own, and the registers the test wrote.
    let mut sc = scratch();
    let mut users = [None; 2];
    for (i, v) in [0xdead_beef_0000u64, 0xcafe_f00d_0000]
        .into_iter()
        .enumerate()
    {
        let mut spec = Spec::of(Program::Tpidr);
        spec.args = [v, 3_000_000, 0];
        spec.budget_us = 100;
        let u = spawn(&mut sc, spec);
        let mut r = thread::read_registers(u.thread).unwrap();
        r.x[19] = 0x1919 + i as u64;
        r.x[30] = 0x3030 + i as u64;
        // Every SPSR bit but the condition flags is the kernel's.
        r.spsr = u64::MAX;
        thread::write_registers(u.thread, &r).unwrap();
        let back = thread::read_registers(u.thread).unwrap();
        assert_eq!(back.spsr, 0xf000_0000);
        assert_eq!((back.x[19], back.x[30], back.pc), (r.x[19], r.x[30], r.pc));
        users[i] = Some((u, v));
    }
    let (a, va) = users[0].unwrap();
    let (b, vb) = users[1].unwrap();
    watch(a.tcb, Some(b.tcb));
    assert!(run_until(done12, ms(5_000)), "the threads didn't end");
    assert!(report::values_of(a.tcb.0).eq([va, 0x1919, 0x3030]));
    assert!(report::values_of(b.tcb.0).eq([vb, 0x191a, 0x3031]));
    // A read right alone reads, and can't write.
    let ro = sc.take();
    cap::mint(
        a.thread,
        ro,
        kcap::rights::Rights::READ,
        ops::MintData::None,
    )
    .unwrap();
    assert!(thread::read_registers(ro).is_ok());
    let r = thread::read_registers(ro).unwrap();
    assert_eq!(thread::write_registers(ro, &r), Err(Error::MissingRight));
    assert_eq!(thread::suspend(ro), Err(Error::MissingRight));
    testkit::finish(sc);
});

crate::kernel_test!(fp_simd_state_survives_preemption, {
    let mut sc = scratch();
    let mut spec = Spec::of(Program::Fp);
    spec.budget_us = 100;
    spec.args = [0x1000, 20, 20_000];
    let a = spawn(&mut sc, spec);
    spec.args[0] = 0x2000;
    let b = spawn(&mut sc, spec);
    let switches = this_core().stats.switches;
    watch(a.tcb, Some(b.tcb));
    assert!(run_until(done12, ms(10_000)), "the threads didn't end");
    assert!(
        report::values_of(a.tcb.0).eq([1]),
        "thread A's registers changed"
    );
    assert!(
        report::values_of(b.tcb.0).eq([1]),
        "thread B's registers changed"
    );
    assert!(
        this_core().stats.switches - switches > 2,
        "the threads never took turns"
    );
    testkit::finish(sc);
});

crate::kernel_test!(timer_preempts_el0_in_priority_order, {
    // A low-priority spinner runs while a higher one sleeps. When the
    // higher one's deadline passes, the timer preempts the spinner and the
    // higher one runs (ADR 0051, rules 2 and 5).
    let mut sc = scratch();
    let mut low = Spec::of(Program::SpinReport);
    low.priority = 5;
    low.args = [1, 200_000, 0];
    let lo = spawn(&mut sc, low);
    let deadline = crate::timer::now() + ms(30);
    let mut high = Spec::of(Program::SleepReport);
    high.priority = 20;
    high.args[0] = deadline;
    let hi = spawn(&mut sc, high);
    watch(hi.tcb, None);
    assert!(run_until(done1, ms(5_000)), "the sleeper didn't end");
    // It timed out, at or after its deadline, and the spinner ran first.
    let h = report::all()
        .find(|r| r.thread == hi.tcb.0)
        .expect("the sleeper never reported");
    assert_eq!(h.value, Ended::TimedOut as u64);
    assert!(h.at >= deadline);
    assert!(
        report::all().any(|r| r.thread == lo.tcb.0 && r.at < h.at),
        "the spinner didn't run while the sleeper slept"
    );
    testkit::finish(sc);
});

/// A copy of the first reports in the log, that a test can index: at most
/// 256, 8 KiB of the boot stack.
mod heapless_reports {
    use crate::testing::report::{self, Report};

    const CAPACITY: usize = 256;

    pub struct Reports {
        r: [Report; CAPACITY],
        n: usize,
    }

    impl core::ops::Deref for Reports {
        type Target = [Report];
        fn deref(&self) -> &[Report] {
            &self.r[..self.n]
        }
    }

    pub fn collect() -> Reports {
        let mut out = Reports {
            r: [Report::default(); CAPACITY],
            n: 0,
        };
        for r in report::all().take(CAPACITY) {
            out.r[out.n] = r;
            out.n += 1;
        }
        out
    }
}

crate::kernel_test!(equal_priorities_take_turns, {
    // With yield: the two threads alternate.
    let mut sc = scratch();
    let mut spec = Spec::of(Program::YieldReport);
    spec.budget_us = 400;
    spec.args[0] = 1;
    let a = spawn(&mut sc, spec);
    spec.args[0] = 2;
    let b = spawn(&mut sc, spec);
    N.store(20, Ordering::Relaxed);
    assert!(run_until(reports_n, ms(5_000)), "too few reports");
    let r = heapless_reports::collect();
    for w in r[..20].windows(2) {
        assert_ne!(w[0].thread, w[1].thread, "a yield didn't pass the turn");
    }
    testkit::finish(sc);
    // With budgets that run out: both spinners run, in turns.
    let mut sc = scratch();
    let mut spec = Spec::of(Program::SpinReport);
    spec.budget_us = 300;
    spec.args = [1, 100_000, 0];
    let a2 = spawn(&mut sc, spec);
    spec.args[0] = 2;
    let b2 = spawn(&mut sc, spec);
    let exhausted = this_core().stats.exhausted;
    run_ms(40);
    let r = heapless_reports::collect();
    let turns = r.windows(2).filter(|w| w[0].thread != w[1].thread).count();
    assert!(report::count_of(a2.tcb.0) > 0 && report::count_of(b2.tcb.0) > 0);
    assert!(turns >= 2, "the spinners didn't take turns");
    assert!(this_core().stats.exhausted > exhausted);
    let _ = (a, b);
    testkit::finish(sc);
});

crate::kernel_test!(round_robin_context_raises_no_timeout_fault, {
    // A round-robin context needs a whole core (K13), so the test lends the
    // first thread's: 5 ms round-robin again, bound to a test thread with
    // a timeout endpoint. Its budget runs out many times, and it is
    // refilled whole each time, with no timeout fault.
    let mut sc = Scratch::new(20);
    report::clear();
    thread::unbind_context(first_thread()).unwrap();
    configure(control(), first_context(), 5_000, 5_000, 0, 0).unwrap();
    let s = testkit::space(&mut sc);
    let t = sc.make(ObjectType::Thread);
    thread::configure_space(t, cboot::root_slot(cboot::ROOT_SELF), s).unwrap();
    thread::set_priority(t, first_thread(), 10).unwrap();
    let ep = endpoint(&mut sc);
    thread::set_endpoint(t, Binding::TimeoutEndpoint, Some(ep)).unwrap();
    thread::bind_context(t, first_context()).unwrap();
    let mut regs = super::object::UserContext {
        pc: testkit::CODE_VA + Program::SpinReport.offset(),
        ..Default::default()
    };
    regs.x[..2].copy_from_slice(&[7, 100_000]);
    thread::write_registers(t, &regs).unwrap();
    thread::resume(t).unwrap();
    let tcb = Tcb::of(&cap::cap(t)).unwrap();
    let (ex, to) = (this_core().stats.exhausted, this_core().stats.timeouts);
    run_ms(40);
    assert!(
        this_core().stats.exhausted - ex >= 2,
        "the budget never ran out"
    );
    assert_eq!(
        this_core().stats.timeouts,
        to,
        "a round-robin context raised a timeout fault"
    );
    assert_eq!(tcb.wait(), Wait::None);
    assert!(report::count_of(tcb.0) > 0);
    // Give the context back.
    thread::unbind_context(t).unwrap();
    thread::bind_context(first_thread(), first_context()).unwrap();
    make_room();
    testkit::finish(sc);
});

crate::kernel_test!(budget_exhaustion_waits_for_refill, {
    // No timeout endpoint: the thread waits for its context's next refill,
    // over and over; the refills stay well formed, and their sum is the
    // budget.
    let mut sc = scratch();
    let mut spec = Spec::of(Program::Spin);
    spec.budget_us = 500;
    spec.period_us = 5_000;
    let u = spawn(&mut sc, spec);
    let c = Sc(cap::cap(u.context).object().unwrap().0);
    let (ex, rel, to) = (
        this_core().stats.exhausted,
        this_core().stats.releases,
        this_core().stats.timeouts,
    );
    run_ms(40);
    assert!(
        this_core().stats.exhausted - ex >= 2,
        "the budget never ran out"
    );
    assert!(
        this_core().stats.releases - rel >= 1,
        "no refill was released"
    );
    assert_eq!(this_core().stats.timeouts, to);
    assert_eq!(u.tcb.wait(), Wait::None);
    let budget = run_counts(500);
    c.refills(|r| {
        assert!(r.check(), "the refills are malformed");
        assert_eq!(r.sum(), budget);
    });
    assert!(c.header().consumed > 0);
    testkit::finish(sc);
});

/// A budget in counts, as configure rounds it.
fn run_counts(us: u64) -> u64 {
    super::run::clock().budget(us)
}

crate::kernel_test!(budget_exhaustion_sends_timeout_fault_with_badge, {
    let mut sc = scratch();
    let mut spec = Spec::of(Program::Spin);
    spec.budget_us = 500;
    spec.period_us = 5_000;
    spec.badge = 0xbad6e;
    let u = spawn(&mut sc, spec);
    let ep = endpoint(&mut sc);
    thread::set_endpoint(u.thread, Binding::TimeoutEndpoint, Some(ep)).unwrap();
    watch(u.tcb, None);
    assert!(run_until(waiting1, ms(5_000)), "no timeout fault");
    assert_eq!(u.tcb.wait(), Wait::TimeoutSend);
    let f = u.tcb.state().fault;
    assert_eq!(f.kind, Kind::Timeout as u64);
    assert_eq!(f.addr, 0xbad6e, "the fault doesn't carry the badge");
    assert!(f.extra > 0, "the fault doesn't carry the time used");
    // It waits for its handler's reply, not for its refill: it donated
    // nothing, and its context stays its own.
    run_ms(20);
    assert_eq!(u.tcb.wait(), Wait::TimeoutSend);
    assert!(!u.tcb.has(flag::QUEUED));
    assert!(u.tcb.sc().is_some());
    // The reply resumes it.
    assert!(fault::reply(u.tcb));
    assert_eq!(u.tcb.wait(), Wait::None);
    // Removing the endpoint while a timeout fault is queued withdraws it,
    // and the thread waits for its refill instead (K50).
    assert!(run_until(waiting1, ms(5_000)), "no second timeout fault");
    thread::set_endpoint(u.thread, Binding::TimeoutEndpoint, None).unwrap();
    assert_eq!(u.tcb.wait(), Wait::None);
    assert!(u.tcb.has(flag::RESUMED));
    testkit::finish(sc);
});

crate::kernel_test!(head_refill_end_ends_the_slice, {
    // A sporadic context whose head refill runs out while its next refill
    // is already ready: the time slice ends, as seL4 17.0.0's
    // `endTimeslice(true)`, so a thread with a timeout endpoint gets its
    // fault then, the ready refill unused, and doesn't run on (ADR 0051,
    // rule 1). The ready refill is large, so an interrupt taken late, as
    // under a loaded host, can't use it up and hide the difference.
    let mut sc = scratch();
    let mut spec = Spec::of(Program::Spin);
    spec.budget_us = 20_000;
    spec.period_us = 1_000_000;
    spec.extra_refills = 2;
    let u = spawn(&mut sc, spec);
    let ep = endpoint(&mut sc);
    thread::set_endpoint(u.thread, Binding::TimeoutEndpoint, Some(ep)).unwrap();
    let c = Sc(cap::cap(u.context).object().unwrap().0);
    let clock = super::run::clock();
    let now = crate::timer::now();
    let head = run_counts(300);
    let rest = run_counts(20_000) - head;
    c.refills(|r| {
        // Two refills, both ready: a head of 300 µs, and the rest.
        r.st.head = 0;
        r.st.count = 2;
        r.ring[0] = ksched::refill::Refill {
            time: now.saturating_sub(clock.counts_ceil(1_000)),
            amount: head,
        };
        r.ring[1] = ksched::refill::Refill {
            time: now.saturating_sub(clock.counts_ceil(500)),
            amount: rest,
        };
        assert!(r.check());
    });
    let to = this_core().stats.timeouts;
    watch(u.tcb, None);
    assert!(run_until(waiting1, ms(5_000)), "no timeout fault");
    assert_eq!(u.tcb.wait(), Wait::TimeoutSend);
    assert_eq!(this_core().stats.timeouts, to + 1);
    let now = crate::timer::now();
    c.refills(|r| {
        assert!(r.check(), "the refills are malformed");
        assert!(
            r.sufficient(now),
            "the fault came only once the ready refill was used too"
        );
    });
    assert!(
        c.header().consumed < run_counts(10_000),
        "the thread ran on past its head refill: {} counts used, of {head}",
        c.header().consumed
    );
    // Its handler lends it budget: reconfiguring a context whose thread
    // waits gives the whole new budget from now, as seL4's `refill_new`.
    configure(control(), u.context, 20_000, 1_000_000, 2, 0).unwrap();
    let now = crate::timer::now();
    c.refills(|r| {
        assert!(r.check());
        assert_eq!(r.count(), 1, "the old refills were kept");
        assert!(r.ready(now));
        assert_eq!(r.head().amount, run_counts(20_000));
    });
    testkit::finish(sc);
});

crate::kernel_test!(yield_raises_no_timeout_fault, {
    // A sporadic thread with a timeout endpoint yields with no other refill
    // ready: it waits for its refill, as seL4's `endTimeslice(false)`, and
    // runs again after it, with no timeout fault.
    let mut sc = scratch();
    let mut spec = Spec::of(Program::YieldReport);
    spec.budget_us = 500;
    spec.period_us = 5_000;
    spec.args[0] = 3;
    let u = spawn(&mut sc, spec);
    let ep = endpoint(&mut sc);
    thread::set_endpoint(u.thread, Binding::TimeoutEndpoint, Some(ep)).unwrap();
    let to = this_core().stats.timeouts;
    run_ms(20);
    assert_eq!(
        this_core().stats.timeouts,
        to,
        "a yield raised a timeout fault"
    );
    assert_eq!(u.tcb.wait(), Wait::None);
    assert!(
        report::count_of(u.tcb.0) >= 2,
        "the thread didn't run again after its refill"
    );
    testkit::finish(sc);
});

crate::kernel_test!(refills_over_several_periods, {
    // Five periods of 4 ms, with two extra refills: the refills stay at
    // most four, ordered, and sum to the budget; the exact window
    // property is ksched's host test.
    let mut sc = scratch();
    let mut spec = Spec::of(Program::SpinReport);
    spec.budget_us = 1_000;
    spec.period_us = 4_000;
    spec.extra_refills = 2;
    spec.args = [1, 100_000, 0];
    let u = spawn(&mut sc, spec);
    let c = Sc(cap::cap(u.context).object().unwrap().0);
    let rel = this_core().stats.releases;
    for _ in 0..5 {
        run_ms(5);
        c.refills(|r| {
            assert!(r.check(), "the refills are malformed");
            assert!(r.count() <= 4, "{} refills, of 4", r.count());
            assert_eq!(r.sum(), run_counts(1_000));
        });
    }
    assert!(this_core().stats.releases - rel >= 2);
    assert!(report::count_of(u.tcb.0) > 0);
    testkit::finish(sc);
});

crate::kernel_test!(mcp_refuses_priority_above_authority, {
    let mut sc = scratch();
    let a = spawn(&mut sc, Spec::of(Program::Spin));
    let b = spawn(&mut sc, Spec::of(Program::Spin));
    thread::suspend(a.thread).unwrap();
    thread::suspend(b.thread).unwrap();
    // A retyped thread's MCP is 0: it can set nothing above 0.
    assert_eq!(
        thread::set_priority(b.thread, a.thread, 1),
        Err(Error::Priority)
    );
    thread::set_mcp(a.thread, first_thread(), 50).unwrap();
    assert_eq!(
        thread::set_priority(b.thread, a.thread, 51),
        Err(Error::Priority)
    );
    assert_eq!(
        thread::set_mcp(b.thread, a.thread, 51),
        Err(Error::Priority)
    );
    thread::set_priority(b.thread, a.thread, 50).unwrap();
    thread::set_mcp(b.thread, a.thread, 50).unwrap();
    assert_eq!((b.tcb.priority(), b.tcb.state().mcp), (50, 50));
    // The first thread's MCP is 255.
    thread::set_priority(b.thread, first_thread(), 255).unwrap();
    assert_eq!(b.tcb.priority(), 255);
    testkit::finish(sc);
});

crate::kernel_test!(share_check_refuses_past_share, {
    // K13: exact. With the first thread's tenth, nine tenths fit exactly;
    // the smallest context more is refused; a delete frees it.
    let mut sc = scratch();
    let me = this_core().index;
    let cs: [_; 3] = core::array::from_fn(|_| sc.make(ObjectType::SchedContext(8)));
    for &c in &cs {
        configure(control(), c, 300, 1_000, 0, 0).unwrap();
    }
    assert_eq!(context::used(me).fraction(), (1, 1));
    let x = sc.make(ObjectType::SchedContext(8));
    assert_eq!(
        configure(control(), x, 10, 3_600_000_000, 0, 0),
        Err(Error::Share(Refused::PastShare))
    );
    // Reconfiguring within the share is admitted; past it, refused, with
    // nothing changed.
    configure(control(), cs[0], 250, 1_000, 0, 0).unwrap();
    assert_eq!(
        configure(control(), cs[1], 400, 1_000, 0, 0),
        Err(Error::Share(Refused::PastShare))
    );
    assert_eq!(
        Sc(cap::cap(cs[1]).object().unwrap().0).header().budget_us,
        300
    );
    cap::delete(cs[2]);
    configure(control(), x, 10, 3_600_000_000, 0, 0).unwrap();
    testkit::finish(sc);
});

crate::kernel_test!(configure_rejects_bad_parameters, {
    let mut sc = scratch();
    let c = sc.make(ObjectType::SchedContext(8));
    let bad = |b, p, e| configure(control(), c, b, p, e, 0);
    assert_eq!(
        bad(9, 1_000, 0),
        Err(Error::Limits(Invalid::BudgetTooShort))
    );
    assert_eq!(
        bad(1_001, 1_000, 0),
        Err(Error::Limits(Invalid::BudgetPastPeriod))
    );
    assert_eq!(
        bad(10, 3_600_000_001, 0),
        Err(Error::Limits(Invalid::PeriodTooLong))
    );
    // 2^8 bytes hold four refills: two plus two extra, not three (K15).
    assert_eq!(bad(100, 1_000, 3), Err(Error::TooManyRefills));
    assert_eq!(bad(100, 1_000, u32::MAX), Err(Error::TooManyRefills));
    assert!(!Sc(cap::cap(c).object().unwrap().0).is_configured());
    bad(100, 1_000, 2).unwrap();
    // The wrong kinds, and a core that isn't online.
    assert_eq!(configure(c, c, 100, 1_000, 0, 0), Err(Error::WrongKind));
    assert_eq!(
        configure(control(), control(), 100, 1_000, 0, 0),
        Err(Error::WrongKind)
    );
    let off = sc.take();
    let core = (this_core().index + 1) as u8;
    mdb::insert_root(&mut DirectSlots, off, Cap::SchedControl { core });
    assert_eq!(configure(off, c, 100, 1_000, 0, 0), Err(Error::CoreOffline));
    cap::delete(off);
    testkit::finish(sc);
});

crate::kernel_test!(suspend_and_resume_running_and_ready_threads, {
    let mut sc = scratch();
    let mut spec = Spec::of(Program::SpinReport);
    spec.args = [1, 100_000, 0];
    let a = spawn(&mut sc, spec);
    spec.args[0] = 2;
    let b = spawn(&mut sc, spec);
    run_ms(10);
    thread::suspend(a.thread).unwrap();
    assert!(!a.tcb.has(flag::QUEUED));
    let (na, nb) = (report::count_of(a.tcb.0), report::count_of(b.tcb.0));
    run_ms(10);
    assert_eq!(report::count_of(a.tcb.0), na, "a suspended thread ran");
    assert!(report::count_of(b.tcb.0) > nb);
    thread::resume(a.thread).unwrap();
    watch(a.tcb, None);
    N.store(na + 1, Ordering::Relaxed);
    assert!(
        run_until(reports_of_1_n, ms(5_000)),
        "the resumed thread didn't run"
    );
    // Suspending twice, or resuming a resumed thread, changes nothing.
    thread::suspend(b.thread).unwrap();
    thread::suspend(b.thread).unwrap();
    thread::resume(a.thread).unwrap();
    assert!(!b.tcb.has(flag::RESUMED) && a.tcb.has(flag::RESUMED));
    testkit::finish(sc);
});

crate::kernel_test!(suspend_keeps_a_wait, {
    // ADR 0061, rule 3 and K20: a suspended thread's wait stays, its
    // deadline keeps running, and the result is held in its registers
    // until it resumes.
    let mut sc = scratch();
    let mut spec = Spec::of(Program::SleepReport);
    spec.args[0] = crate::timer::now() + ms(15);
    let u = spawn(&mut sc, spec);
    watch(u.tcb, None);
    assert!(run_until(waiting1, ms(2_000)), "it never slept");
    thread::suspend(u.thread).unwrap();
    assert_eq!(u.tcb.wait(), Wait::TestSleep, "suspend ended the wait");
    run_ms(30);
    assert_eq!(u.tcb.wait(), Wait::None, "the deadline didn't keep running");
    assert_eq!(
        thread::read_registers(u.thread).unwrap().x[0],
        Ended::TimedOut as u64
    );
    assert_eq!(report::count_of(u.tcb.0), 0, "a suspended thread ran");
    thread::resume(u.thread).unwrap();
    assert!(run_until(done1, ms(2_000)), "it didn't end once resumed");
    assert!(report::values_of(u.tcb.0).eq([Ended::TimedOut as u64]));
    // A cancel ends a sleep with "canceled"; a deadline already passed
    // returns "timed out" at once (K19).
    let mut spec = Spec::of(Program::SleepReport);
    spec.args[0] = 0;
    let v = spawn(&mut sc, spec);
    watch(v.tcb, None);
    assert!(run_until(waiting1, ms(2_000)));
    thread::cancel(v.thread).unwrap();
    assert_eq!(thread::cancel(v.thread), Err(Error::NotWaiting));
    assert!(run_until(done1, ms(2_000)));
    assert!(report::values_of(v.tcb.0).eq([Ended::Canceled as u64]));
    let mut spec = Spec::of(Program::SleepReport);
    spec.args[0] = 1;
    let w = spawn(&mut sc, spec);
    watch(w.tcb, None);
    assert!(run_until(done1, ms(2_000)));
    assert!(report::values_of(w.tcb.0).eq([Ended::TimedOut as u64]));
    testkit::finish(sc);
});

crate::kernel_test!(unknown_svc_faults_or_suspends, {
    // Without a fault endpoint: suspended, and logged.
    let mut sc = scratch();
    let u = spawn(&mut sc, Spec::of(Program::SvcUnknown));
    watch(u.tcb, None);
    assert!(
        run_until(suspended1, ms(2_000)),
        "the thread wasn't suspended"
    );
    let f = u.tcb.state().fault;
    assert_eq!((f.kind, f.addr), (Kind::UnknownSyscall as u64, 1));
    assert_eq!(u.tcb.wait(), Wait::None);
    // With one: it waits sending the fault; the reply resumes it after the
    // call.
    let v = spawn(&mut sc, Spec::of(Program::SvcUnknown));
    let ep = endpoint(&mut sc);
    thread::set_endpoint(v.thread, Binding::FaultEndpoint, Some(ep)).unwrap();
    watch(v.tcb, None);
    assert!(run_until(waiting1, ms(2_000)), "no fault");
    assert_eq!(v.tcb.wait(), Wait::FaultSend);
    assert_eq!(v.tcb.state().fault.kind, Kind::UnknownSyscall as u64);
    assert!(fault::reply(v.tcb));
    assert!(run_until(done1, ms(2_000)));
    assert!(report::values_of(v.tcb.0).eq([0x51]));
    // An endpoint without the write right, or without grant and
    // grant-reply, is refused as a fault endpoint (seL4's
    // `validFaultHandler`).
    let ro = sc.take();
    cap::mint(
        ep,
        ro,
        kcap::rights::Rights::READ.union(kcap::rights::Rights::GRANT),
        ops::MintData::None,
    )
    .unwrap();
    assert_eq!(
        thread::set_endpoint(v.thread, Binding::FaultEndpoint, Some(ro)),
        Err(Error::MissingRight)
    );
    testkit::finish(sc);
});

crate::kernel_test!(user_abort_is_an_unmapped_fault, {
    let mut sc = scratch();
    let mut spec = Spec::of(Program::Load);
    spec.args[0] = UNMAPPED_VA;
    let u = spawn(&mut sc, spec);
    let ep = endpoint(&mut sc);
    thread::set_endpoint(u.thread, Binding::FaultEndpoint, Some(ep)).unwrap();
    watch(u.tcb, None);
    assert!(run_until(waiting1, ms(2_000)), "no fault");
    let f = u.tcb.state().fault;
    assert_eq!(f.kind, Kind::Unmapped as u64);
    assert_eq!(f.addr, UNMAPPED_VA);
    assert_eq!(ec(u.tcb), 0x24, "not a data abort from EL0");
    assert_eq!(f.pc, testkit::CODE_VA + Program::Load.offset());
    // Withdrawing the endpoint with the fault queued suspends the thread
    // and logs the fault (K50).
    thread::set_endpoint(u.thread, Binding::FaultEndpoint, None).unwrap();
    assert_eq!(u.tcb.wait(), Wait::None);
    assert!(!u.tcb.has(flag::RESUMED));
    testkit::finish(sc);
});

crate::kernel_test!(el0_reads_virtual_count_only, {
    // K19: EL0 reads CNTVCT_EL0 and CNTFRQ_EL0 directly; CNTPCT_EL0 traps,
    // a user exception.
    let mut sc = scratch();
    let u = spawn(&mut sc, Spec::of(Program::Counts));
    let ep = endpoint(&mut sc);
    thread::set_endpoint(u.thread, Binding::FaultEndpoint, Some(ep)).unwrap();
    let before = crate::timer::now();
    watch(u.tcb, None);
    assert!(run_until(waiting1, ms(2_000)), "no fault");
    let after = crate::timer::now();
    let r = heapless_reports::collect();
    let mine: [u64; 2] = [r[0].value, r[1].value];
    assert!(
        (before..=after).contains(&mine[0]),
        "CNTVCT_EL0 read {:#x}",
        mine[0]
    );
    assert_eq!(mine[1], crate::timer::frequency());
    assert_eq!(report::count_of(u.tcb.0), 2);
    assert_eq!(u.tcb.state().fault.kind, Kind::UserException as u64);
    assert_eq!(ec(u.tcb), 0x18, "not a trapped system register");
    testkit::finish(sc);
});

crate::kernel_test!(brk_is_a_debug_fault_and_mdscr_is_clear, {
    // K70: no thread has hardware debug state; MDSCR_EL1, and
    // PMUSERENR_EL0 where there is a PMU, are 0.
    let (mdscr, pmu) = boot::debug_controls();
    assert_eq!(mdscr, 0);
    assert!(pmu.is_none_or(|p| p == 0));
    let mut sc = scratch();
    let u = spawn(&mut sc, Spec::of(Program::Brk));
    let ep = endpoint(&mut sc);
    thread::set_endpoint(u.thread, Binding::FaultEndpoint, Some(ep)).unwrap();
    watch(u.tcb, None);
    assert!(run_until(waiting1, ms(2_000)), "no fault");
    assert_eq!(u.tcb.state().fault.kind, Kind::Debug as u64);
    assert_eq!(ec(u.tcb), 0x3c);
    testkit::finish(sc);
});

crate::kernel_test!(destroying_a_running_thread, {
    // The thread stops before its slots are cleared: it leaves its
    // queue, its context is unbound but stays configured, and it never
    // runs again.
    let mut sc = scratch();
    let mut spec = Spec::of(Program::SpinReport);
    spec.args = [1, 100_000, 0];
    let u = spawn(&mut sc, spec);
    run_ms(5);
    assert!(report::count_of(u.tcb.0) > 0);
    let c = Sc(cap::cap(u.context).object().unwrap().0);
    let used = context::used(this_core().index);
    cap::delete(u.thread);
    assert!(cap::cap(u.thread).is_null());
    assert!(this_core().runq.is_empty());
    assert_eq!((c.header().home, c.header().holder), (0, 0));
    assert!(c.is_configured());
    assert_eq!(context::used(this_core().index), used);
    let n = report::count();
    run_ms(5);
    assert_eq!(report::count(), n, "a destroyed thread ran");
    testkit::finish(sc);
});
