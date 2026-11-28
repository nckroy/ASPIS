// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! In-QEMU tests with every core up (C12's stage 4, the tests' second
//! phase; ADR 0036, rule 5; ADR 0047, rule 3; ADR 0051, rules 2 to 4; ADR
//! 0052, rules 1 to 4; ADR 0061, rule 3; K18, K20, K77; kernel specification,
//! "Cross-core signals and TLB maintenance"). They run after `smp::start_secondaries`, on a72-v2
//! (GICv2) and max-v3 (GICv3) per change and through the nightly matrix.
//!
//! The boot core runs each body, holding the kernel lock; the other cores
//! wait for it in their lock's spin, serving remote calls, until the body
//! runs threads through the driver, which releases the lock while threads
//! run and the boot core idles. Each test asserts order from the report
//! log, the lock's take log and the per-core counters, never from elapsed
//! time, and leaves every core as it found it
//! ([`testkit::finish`]). With one core they print "(one core: skipped)"
//! and pass.

use crate::cap::testkit::Scratch;
use crate::cap::{self, DirectSlots, map, unmap};
use crate::mm::phys::{DirectMem, Window};
use crate::sched::object::{Ended, Sc, Tcb, Wait, flag};
use crate::sched::percore::{self, ENTERING_SVC, this_core};
use crate::sched::testkit::{
    self, Spec, control_of, make_room, ms, run_ms, space, spawn, spawn_in,
};
use crate::sched::{Error, context, fault, thread};
use crate::testing::driver::run_until;
use crate::testing::report;
use crate::testing::user::{Program, blob};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use kcap::cap::Cap;
use kcap::mdb;
use kirq::MAX_CORES;
use kmem::desc::UserPerm;
use kmem::untyped::ObjectType;

use super::lock::order;
use super::remote;

/// Where a test maps its data page.
const DATA_VA: u64 = 0xc0_0000;

/// The threads a test's conditions watch, and a count.
static W: [AtomicU64; MAX_CORES] = [const { AtomicU64::new(0) }; MAX_CORES];
static N: AtomicUsize = AtomicUsize::new(0);

fn watch(i: usize, t: Tcb) {
    W[i].store(t.0, Ordering::Relaxed);
}

fn w(i: usize) -> Tcb {
    Tcb(W[i].load(Ordering::Relaxed))
}

fn set_n(n: usize) {
    N.store(n, Ordering::Relaxed);
}

fn n() -> usize {
    N.load(Ordering::Relaxed)
}

/// Every watched thread, up to the first unset, reported at least N times.
fn each_reported_n() -> bool {
    (0..MAX_CORES)
        .map(w)
        .take_while(|t| t.0 != 0)
        .all(|t| report::count_of(t.0) >= n())
}

fn w0_reported_n() -> bool {
    report::count_of(w(0).0) >= n()
}

/// The first watched thread reported N times and runs now on its core.
/// Read under the kernel lock, which the test body keeps once this holds,
/// so it still runs there when the body goes on: its core can't change its
/// running thread without the lock.
fn w0_reported_n_and_running() -> bool {
    let t = w(0);
    let k = t.state().core as usize;
    w0_reported_n() && percore::core(k).current == t.0
}

fn w0_done() -> bool {
    w(0).has(flag::DONE)
}

fn w0_waiting() -> bool {
    w(0).wait() != Wait::None
}

fn w0_not_waiting() -> bool {
    w(0).wait() == Wait::None
}

fn w0_suspended() -> bool {
    !w(0).has(flag::RESUMED)
}

fn w0_receiving() -> bool {
    w(0).wait() == Wait::Receive
}

fn takes_n() -> bool {
    order::takes().count() >= n()
}

/// The online cores other than this one; None, after the skip line, if
/// fewer than `need` other cores are online.
fn others(need: usize) -> Option<impl Iterator<Item = usize> + Clone> {
    let me = this_core().index;
    let it = (0..MAX_CORES).filter(move |&k| k != me && crate::smp::is_online(k));
    if it.clone().count() < need {
        crate::uart::write(if need == 1 {
            "  (one core: skipped)\n"
        } else {
            "  (too few cores: skipped)\n"
        });
        return None;
    }
    Some(it)
}

/// A scratch space, room made on the boot core, the report log and the
/// watch list cleared.
fn scratch() -> Scratch {
    make_room();
    report::clear();
    for x in &W {
        x.store(0, Ordering::Relaxed);
    }
    Scratch::new(20)
}

/// Whether the values `t` reported, as the log kept them, count up by one
/// each, with no gap or repeat, and how many there are. The log keeps only
/// its first [`report::CAPACITY`] reports, so the tests clear it where they
/// count again.
fn counts_in_order(t: Tcb) -> (bool, usize) {
    let mut prev: Option<u64> = None;
    let mut n = 0;
    let ok = report::values_of(t.0).all(|v| {
        n += 1;
        let good = prev.is_none_or(|p| v == p + 1);
        prev = Some(v);
        good
    });
    (ok, n)
}

/// How many remote calls core `k` served. The SGI that brought each is
/// counted only when the core next handles its interrupts, after the lock.
fn served(k: usize) -> u64 {
    percore::core(k).stats.served
}

/// The context a capability in `slot` names.
fn sc_of(slot: kcap::SlotRef) -> Sc {
    match cap::cap(slot) {
        Cap::SchedContext { ptr, .. } => Sc(ptr),
        c => panic!("{c:x?}"),
    }
}

/// A thread's saved PC.
fn pc(t: Tcb) -> u64 {
    t.with(|b| b.ctx.pc)
}

crate::kernel_smp_test!(secondaries_come_online_through_psci, {
    // ADR 0052, rule 1: every core the device tree names is online, each
    // with its own data, vectors and stack, its SGIs and timer PPI enabled
    // at its own interface, EL0 kept out of the timers (K19), self-hosted
    // debug off (K70), and SError unmasked once its stack was set (K77).
    let irq = crate::irq::get().unwrap();
    if crate::smp::psci().is_some() {
        assert_eq!(crate::smp::online_count(), irq.cores().len());
    }
    let vectors = {
        let v: u64;
        // SAFETY: reading VBAR_EL1 has no side effects.
        unsafe {
            core::arch::asm!("mrs {}, vbar_el1", out(reg) v, options(nomem, nostack, preserves_flags))
        };
        v
    };
    let me = this_core().index;
    let boot_sctlr = remote::probe_core(me).sctlr;
    for k in (0..MAX_CORES).filter(|&k| crate::smp::is_online(k)) {
        let p = remote::probe_core(k);
        assert!(p.done, "core {k} didn't serve the probe");
        assert_eq!(p.tpidr, percore::data_va(k), "core {k}'s TPIDR_EL1");
        assert_eq!(percore::core(k).index, k);
        assert_eq!(p.vbar, vectors, "core {k}'s vectors");
        assert_eq!(
            p.daif & crate::sched::boot::DAIF_A,
            0,
            "core {k} masks SError"
        );
        assert_ne!(
            p.daif & 1 << 7,
            0,
            "core {k} runs the kernel with IRQs unmasked"
        );
        assert_eq!(p.cntkctl, crate::timer::CNTKCTL, "core {k}'s CNTKCTL_EL1");
        assert_eq!(p.mdscr, 0, "core {k}'s MDSCR_EL1");
        assert!(p.timer_ppi_enabled, "core {k}'s timer PPI");
        assert!(p.sgis_enabled, "core {k}'s SGIs");
        assert_eq!(p.sctlr, boot_sctlr, "core {k}'s SCTLR_EL1");
        // Each online core has its scheduling control.
        assert_eq!(cap::cap(control_of(k)), Cap::SchedControl { core: k as u8 });
    }
    // A core that isn't online has none.
    for k in irq.cores().len()..MAX_CORES {
        assert!(cap::cap(control_of(k)).is_null());
        assert!(!crate::smp::is_online(k));
    }
    if others(1).is_none() {
        return;
    }
});

crate::kernel_smp_test!(virtual_count_has_no_offset_on_every_core, {
    // ADR 0051, rule 4: every core reads the same virtual count, whatever
    // EL it was started at: the EL2 entry zeroes CNTVOFF_EL2, as the stub
    // does on the boot core. A count another core reads lies between two
    // this core reads around it.
    let Some(cores) = others(1) else { return };
    for k in cores {
        let before = crate::timer::now();
        let p = remote::probe_core(k);
        let after = crate::timer::now();
        assert!(
            (before..=after).contains(&p.count),
            "core {k}'s count {} isn't between {before} and {after}",
            p.count
        );
    }
});

crate::kernel_smp_test!(each_core_runs_its_own_threads_from_its_own_queue, {
    // ADR 0052, rule 3: a thread runs on its context's core, from that
    // core's run queue, and every core runs at once.
    let Some(cores) = others(1) else { return };
    let mut sc = scratch();
    let s = space(&mut sc);
    let me = this_core().index;
    let mut on = [usize::MAX; MAX_CORES];
    for (i, k) in core::iter::once(me).chain(cores).enumerate() {
        let mut spec = Spec::of(Program::CountReport).on(k);
        spec.args = [0, 20_000, 0];
        let u = spawn_in(&mut sc, s, spec);
        watch(i, u.tcb);
        on[i] = k;
    }
    set_n(5);
    assert!(
        run_until(each_reported_n, ms(5_000)),
        "a core's thread didn't run"
    );
    for (i, &k) in on.iter().enumerate().take_while(|(_, k)| **k != usize::MAX) {
        assert!(
            report::all()
                .filter(|r| r.thread == w(i).0)
                .all(|r| r.core == k),
            "a thread of core {k} ran elsewhere"
        );
        assert!(counts_in_order(w(i)).0);
    }
    testkit::finish(sc);
});

crate::kernel_smp_test!(reschedule_sgi_wakes_a_remote_core, {
    // A thread made ready on an idle core sends it SGI 1 when the lock is
    // released, and it runs there (kernel specification, "Cross-core
    // signals and TLB maintenance").
    let Some(mut cores) = others(1) else { return };
    let k = cores.next().unwrap();
    let mut sc = scratch();
    let before = crate::irq::stats_of(k).reschedule;
    let mut spec = Spec::of(Program::ReportEnd).on(k);
    spec.args = [0x5e1, 0, 0];
    let u = spawn(&mut sc, spec);
    watch(0, u.tcb);
    assert!(
        run_until(w0_done, ms(2_000)),
        "the thread didn't run on core {k}"
    );
    assert!(
        crate::irq::stats_of(k).reschedule > before,
        "core {k} got no SGI 1"
    );
    assert_eq!(
        report::all().next().map(|r| (r.core, r.value)),
        Some((k, 0x5e1))
    );
    testkit::finish(sc);
});

crate::kernel_smp_test!(remote_call_stalls_a_thread_on_another_core, {
    // Suspending a thread that runs on another core stalls it there first,
    // with a remote call that core serves while it spins for the lock this
    // core holds; its time there is charged. Its reports stop, and
    // start again on resume, none lost or repeated.
    let Some(mut cores) = others(1) else { return };
    let k = cores.next().unwrap();
    let mut sc = scratch();
    let mut spec = Spec::of(Program::CountReport).on(k);
    spec.args = [0, 100_000, 0];
    spec.budget_us = 900;
    let u = spawn(&mut sc, spec);
    watch(0, u.tcb);
    set_n(3);
    assert!(run_until(w0_reported_n_and_running, ms(2_000)));
    let calls = served(k);
    let used = sc_of(u.context).header().consumed;
    thread::suspend(u.thread).unwrap();
    assert!(served(k) > calls, "no remote call reached core {k}");
    assert_ne!(
        percore::core(k).current,
        u.tcb.0,
        "the thread still runs on core {k}"
    );
    assert!(sc_of(u.context).header().consumed >= used);
    let (ok, kept) = counts_in_order(u.tcb);
    assert!(
        ok && kept < report::CAPACITY,
        "a report was lost or repeated"
    );
    let last = report::values_of(u.tcb.0).last();
    report::clear();
    run_ms(20);
    assert_eq!(report::count_of(u.tcb.0), 0, "a suspended thread reported");
    thread::resume(u.thread).unwrap();
    set_n(3);
    assert!(
        run_until(w0_reported_n, ms(2_000)),
        "the thread didn't resume"
    );
    assert!(counts_in_order(u.tcb).0, "a report was lost or repeated");
    assert_eq!(
        report::values_of(u.tcb.0).next(),
        last.map(|v| v + 1),
        "a report was lost or repeated across the stall"
    );
    testkit::finish(sc);
});

crate::kernel_smp_test!(a_thread_stalled_in_a_trap_makes_its_call_again, {
    // A thread stalled while its core waits for the lock on its entry
    // is no longer current there when the lock comes; the entry is dropped,
    // and its system call, whose PC went back to the SVC, runs once when it
    // next runs.
    let Some(mut cores) = others(1) else { return };
    let k = cores.next().unwrap();
    let mut sc = scratch();
    let mut spec = Spec::of(Program::CountReport).on(k);
    spec.args = [0, 5_000, 0];
    spec.budget_us = 900;
    let u = spawn(&mut sc, spec);
    watch(0, u.tcb);
    // This core holds the lock once the thread runs on its core: the
    // thread's next REPORT waits for it. An interrupt may enter first, its
    // budget's end; then try again.
    let mut trapped = false;
    for _ in 0..20 {
        report::clear();
        set_n(1);
        assert!(run_until(w0_reported_n_and_running, ms(2_000)));
        assert!(
            crate::irq::spin_until(|| percore::entering(k) != 0, ms(2_000)),
            "core {k} didn't enter"
        );
        if percore::entering(k) == ENTERING_SVC {
            trapped = true;
            break;
        }
    }
    assert!(trapped, "core {k} never entered from its thread's trap");
    thread::suspend(u.thread).unwrap();
    // The PC is on the SVC again.
    let at = (pc(u.tcb) - testkit::CODE_VA) as usize;
    let word = u32::from_le_bytes(blob()[at..at + 4].try_into().unwrap());
    assert_eq!(word, 0xd400_0001 | (crate::testing::trap::IMM as u32) << 5);
    assert!(counts_in_order(u.tcb).0);
    // The stalled REPORT carries the count in x19, one past the last made.
    let last = Some(report::last());
    let stalled = u.tcb.with(|b| b.ctx.x[19]);
    assert_eq!(
        last.map(|v| v + 1),
        Some(stalled),
        "the stalled call was made"
    );
    report::clear();
    run_ms(10);
    assert_eq!(
        report::count_of(u.tcb.0),
        0,
        "the stalled report was made anyway"
    );
    thread::resume(u.thread).unwrap();
    set_n(3);
    assert!(run_until(w0_reported_n, ms(2_000)));
    assert!(counts_in_order(u.tcb).0);
    // The count the stalled REPORT carried comes next: made once.
    assert_eq!(
        report::values_of(u.tcb.0).next(),
        last.map(|v| v + 1),
        "the stalled call was lost or made twice"
    );
    testkit::finish(sc);
});

crate::kernel_smp_test!(cross_core_suspend_keeps_a_wait, {
    // ADR 0061, rule 3 and K20 across cores: a thread suspended while it
    // sleeps on another core keeps its wait; its deadline, in that core's
    // tree (K18), passes while it is suspended, and it sees "timed out"
    // when resumed.
    let Some(mut cores) = others(1) else { return };
    let k = cores.next().unwrap();
    let mut sc = scratch();
    let mut spec = Spec::of(Program::SleepReport).on(k);
    spec.args = [crate::timer::now() + ms(200), 0, 0];
    let u = spawn(&mut sc, spec);
    watch(0, u.tcb);
    assert!(run_until(w0_waiting, ms(2_000)));
    assert_eq!(u.tcb.state().core as usize, k);
    assert_ne!(
        percore::core(k).deadline_root,
        0,
        "the deadline isn't on core {k}"
    );
    thread::suspend(u.thread).unwrap();
    assert_eq!(u.tcb.wait(), Wait::TestSleep, "suspending ended the wait");
    assert!(
        run_until(w0_not_waiting, ms(2_000)),
        "the deadline didn't pass"
    );
    run_ms(10);
    assert_eq!(report::count_of(u.tcb.0), 0, "a suspended thread ran");
    thread::resume(u.thread).unwrap();
    assert!(run_until(w0_done, ms(2_000)));
    assert!(report::values_of(u.tcb.0).eq([Ended::TimedOut as u64]));
    testkit::finish(sc);
});

crate::kernel_smp_test!(kernel_lock_is_fifo, {
    // ADR 0052, rule 2: cores take the lock in the order they asked for
    // it. In a CLH lock each core waits on its predecessor's node, so in
    // the order of takes each take's predecessor is the node the take
    // before it held. Every core contends: each runs a thread that traps
    // to report and to yield, without end.
    let Some(cores) = others(1) else { return };
    let mut sc = scratch();
    let s = space(&mut sc);
    let me = this_core().index;
    for (i, k) in core::iter::once(me).chain(cores).enumerate() {
        let mut spec = Spec::of(Program::YieldReport).on(k);
        spec.args = [i as u64, 0, 0];
        watch(i, spawn_in(&mut sc, s, spec).tcb);
    }
    order::start();
    set_n(1000);
    let enough = run_until(takes_n, ms(10_000));
    order::stop();
    assert!(enough, "fewer than 1000 takes of the lock");
    let mut by = [0usize; MAX_CORES];
    let mut prev: Option<order::Take> = None;
    for (i, t) in order::takes().enumerate() {
        by[t.core] += 1;
        if let Some(p) = prev {
            assert_eq!(
                t.predecessor,
                p.node,
                "take {i} didn't follow take {}",
                i - 1
            );
        }
        prev = Some(t);
    }
    assert!(
        by.iter().filter(|&&n| n > 0).count() >= 2,
        "only one core took the lock"
    );
    testkit::finish(sc);
});

/// The core whose deadline tree a test watches.
static K: AtomicUsize = AtomicUsize::new(0);

fn core_k_has_no_deadlines() -> bool {
    percore::core(K.load(Ordering::Relaxed)).deadline_root == 0
}

crate::kernel_smp_test!(an_idle_core_lets_the_lock_go_between_batches, {
    // ADR 0052, rule 2 and K24: 300 deadlines pass at one tick on an idle
    // core, in three batches or more. Between batches that core gives the
    // lock up, as its idle loop does without the WFI, so the lock is held
    // one batch at a time: this core, whose thread traps to report over and
    // over, takes it between two of that core's takes, in FIFO order.
    const N: u64 = 300;
    let Some(mut cores) = others(1) else { return };
    let Some(k) = cores.next() else { return };
    K.store(k, Ordering::Relaxed);
    let mut sc = scratch();
    let cn = sc.make(ObjectType::CNode(9));
    let mut first = 0;
    while first < N {
        let m = (N - first).min(kcap::RETYPE_FAN_OUT);
        cap::retype(sc.ram, ObjectType::Thread, cn, first, m)
            .unwrap_or_else(|e| panic!("can't make {N} threads: {e:?}"));
        first += m;
    }
    let base = match cap::cap(cn) {
        Cap::CNode { ptr, .. } => kcap::SlotRef(ptr),
        c => panic!("{c:x?}"),
    };
    let thread_at = |i: u64| match Tcb::of(&cap::cap(base.offset(i))) {
        Some(t) => t,
        None => panic!("slot {i} holds no thread"),
    };
    let mut spec = Spec::of(Program::SpinReport);
    spec.args = [1, 2_000, 0];
    spec.budget_us = 800;
    let spinner = spawn(&mut sc, spec);
    // The record starts before the deadlines are queued, so it holds all of
    // core k's takes whenever they pass, however long setting up takes.
    let st = percore::core(k).stats;
    order::start();
    let deadline = crate::timer::now() + ms(10);
    for i in 0..N {
        let t = thread_at(i);
        t.update(|s| {
            s.core = k as u8;
            s.wait = Wait::TestSleep as u8;
        });
        crate::sched::run::deadline_insert(t, deadline);
    }
    let done = run_until(core_k_has_no_deadlines, ms(5_000));
    order::stop();
    assert!(done, "core {k}'s deadlines didn't pass");
    let now = percore::core(k).stats;
    assert!(
        now.batch_yields - st.batch_yields >= 2,
        "core {k} didn't give the lock up between its batches: {} yields, {} expiries, {} batches, {} left over, {} idles",
        now.batch_yields - st.batch_yields,
        now.expiries - st.expiries,
        now.batches - st.batches,
        now.batches_left - st.batches_left,
        now.idles - st.idles
    );
    // Core k's first take is at the SGI, to program its timer, and may run
    // a batch too if the deadline has passed by then: it isn't counted, so
    // the check is of takes between two later batches.
    let (mut k_takes, mut other, mut between) = (0, false, false);
    for t in order::takes() {
        if t.core == k {
            if k_takes >= 2 {
                between |= other;
            }
            k_takes += 1;
            other = false;
        } else if k_takes > 0 {
            other = true;
        }
    }
    assert!(
        between,
        "no other core took the lock between core {k}'s batches ({} takes recorded)",
        order::takes().count()
    );
    assert!(report::count_of(spinner.tcb.0) > 0);
    for i in 0..N {
        let t = thread_at(i);
        assert_eq!(t.wait(), Wait::None, "sleep {i} didn't end");
    }
    testkit::finish(sc);
});

crate::kernel_smp_test!(configuring_a_context_moves_its_thread_to_another_core, {
    // K18: reconfiguring a context onto another core moves it, and
    // the thread on it, there: O(1) and a stall. Its bandwidth moves from
    // one core's share to the other's (K13).
    let Some(mut cores) = others(2) else { return };
    let (a, b) = (cores.next().unwrap(), cores.next().unwrap());
    let mut sc = scratch();
    let mut spec = Spec::of(Program::CountReport).on(a);
    spec.args = [0, 100_000, 0];
    let u = spawn(&mut sc, spec);
    watch(0, u.tcb);
    set_n(3);
    assert!(run_until(w0_reported_n, ms(2_000)));
    context::configure(
        control_of(b),
        u.context,
        spec.budget_us,
        spec.period_us,
        0,
        0,
    )
    .unwrap();
    assert_eq!(
        context::used(a).fraction(),
        ksched::share::Used::EMPTY.fraction()
    );
    assert_ne!(
        context::used(b).fraction(),
        ksched::share::Used::EMPTY.fraction()
    );
    report::clear();
    set_n(3);
    assert!(
        run_until(w0_reported_n, ms(2_000)),
        "the thread didn't run on core {b}"
    );
    assert!(
        report::all().all(|r| r.core == b),
        "the thread ran on core {a} after its context moved"
    );
    assert!(counts_in_order(u.tcb).0);
    testkit::finish(sc);
});

crate::kernel_smp_test!(changing_a_priority_on_another_core_stalls_it, {
    // ADR 0051, rule 2: a priority change to a thread running on
    // another core stalls it there, with its time charged, and that core
    // then runs the highest-priority ready thread.
    let Some(mut cores) = others(1) else { return };
    let k = cores.next().unwrap();
    let mut sc = scratch();
    let s = space(&mut sc);
    let mut hi = Spec::of(Program::CountReport).on(k);
    hi.args = [0, 100_000, 0];
    hi.priority = 20;
    hi.budget_us = 400;
    let a = spawn_in(&mut sc, s, hi);
    let mut lo = hi;
    lo.priority = 10;
    let b = spawn_in(&mut sc, s, lo);
    watch(0, a.tcb);
    set_n(3);
    assert!(run_until(w0_reported_n_and_running, ms(2_000)));
    let calls = served(k);
    thread::set_priority(a.thread, testkit::first_thread(), 5).unwrap();
    assert_eq!(a.tcb.priority(), 5);
    assert!(served(k) > calls, "no stall reached core {k}");
    assert_ne!(percore::core(k).current, a.tcb.0);
    watch(0, b.tcb);
    report::clear();
    set_n(3);
    assert!(
        run_until(w0_reported_n, ms(2_000)),
        "the other thread didn't run"
    );
    assert!(counts_in_order(a.tcb).0 && counts_in_order(b.tcb).0);
    testkit::finish(sc);
});

crate::kernel_smp_test!(donation_runs_the_server_on_the_callers_core, {
    // ADR 0051, rule 3: a passive server runs on its caller's context, so
    // on the caller's core, wherever it last ran.
    let Some(mut cores) = others(1) else { return };
    let k = cores.next().unwrap();
    let mut sc = scratch();
    let s = space(&mut sc);
    let r = sc.make(ObjectType::Reply);
    let ep = sc.make(ObjectType::Endpoint);
    let mut spec = Spec::of(Program::Serve);
    spec.args = [sc.addr_of(ep), 1_000, sc.addr_of(r)];
    let srv = spawn_in(&mut sc, s, spec);
    watch(0, srv.tcb);
    assert!(
        run_until(w0_receiving, ms(2_000)),
        "the server didn't receive"
    );
    thread::unbind_context(srv.thread).unwrap();
    let mut spec = Spec::of(Program::CallReport).on(k);
    spec.args = [sc.addr_of(ep), 0, 41];
    let cl = spawn_in(&mut sc, s, spec);
    watch(0, cl.tcb);
    assert!(run_until(w0_done, ms(5_000)), "the call didn't end");
    assert!(report::values_of(srv.tcb.0).eq([41]));
    assert!(report::values_of(cl.tcb.0).eq([Ended::Done as u64, 42]));
    assert!(
        report::all().all(|r| r.core == k),
        "the server didn't run on its caller's core"
    );
    testkit::finish(sc);
});

crate::kernel_smp_test!(taking_a_context_back_from_another_core, {
    // A cancel takes a donated context back from a server that runs on
    // another core: the server is stalled there first (ADR 0051, rule 3),
    // and the caller's call ends "canceled".
    let Some(mut cores) = others(1) else { return };
    let k = cores.next().unwrap();
    let mut sc = scratch();
    let s = space(&mut sc);
    let r = sc.make(ObjectType::Reply);
    let ep = sc.make(ObjectType::Endpoint);
    let mut spec = Spec::of(Program::Serve);
    spec.args = [sc.addr_of(ep), u64::MAX, sc.addr_of(r)];
    let srv = spawn_in(&mut sc, s, spec);
    watch(0, srv.tcb);
    assert!(run_until(w0_receiving, ms(2_000)));
    thread::unbind_context(srv.thread).unwrap();
    let mut spec = Spec::of(Program::CallReport).on(k);
    spec.args = [sc.addr_of(ep), 0, 7];
    spec.budget_us = 900;
    let cl = spawn_in(&mut sc, s, spec);
    watch(0, srv.tcb);
    set_n(1);
    assert!(
        run_until(w0_reported_n_and_running, ms(2_000)),
        "the server didn't take the call"
    );
    let calls = served(k);
    thread::cancel(cl.thread).unwrap();
    assert!(served(k) > calls, "the server wasn't stalled");
    assert!(srv.tcb.sc().is_none(), "the server kept the context");
    watch(0, cl.tcb);
    assert!(run_until(w0_done, ms(2_000)));
    // The call had been delivered, and says so (K30).
    assert_eq!(
        report::values_of(cl.tcb.0).next(),
        Some(kipc::msg::Status::Canceled.word(true))
    );
    assert!(
        (0..MAX_CORES)
            .filter(|&c| crate::smp::is_online(c))
            .all(|c| percore::core(c).current != srv.tcb.0)
    );
    testkit::finish(sc);
});

/// A data page holding `value`, mapped read-write at [`DATA_VA`] in `s`.
fn data_page(sc: &mut Scratch, s: kcap::SlotRef, value: u64) {
    let f = sc.make(ObjectType::Frame4K);
    let Some((pa, _)) = cap::cap(f).object() else {
        panic!("no data frame")
    };
    // SAFETY: a RAM frame the test just retyped, in the direct map, which
    // nothing else uses yet.
    unsafe { (DirectMem.va(pa) as *mut u64).write_volatile(value) };
    let rw = UserPerm {
        write: true,
        exec: false,
    };
    map(f, s, DATA_VA, rw, sc.ram).unwrap_or_else(|e| panic!("can't map the data: {e:?}"));
}

crate::kernel_smp_test!(unmap_reaches_other_cores_without_an_ipi, {
    // ADR 0052, rule 4: an unmap's broadcast TLBI reaches a core that runs
    // a thread in the space, with no interrupt sent to it. The thread's
    // next load faults there.
    let Some(mut cores) = others(1) else { return };
    let k = cores.next().unwrap();
    let mut sc = scratch();
    let s = space(&mut sc);
    data_page(&mut sc, s, 0x5eed);
    let mut spec = Spec::of(Program::LoadLoop).on(k);
    spec.args = [DATA_VA, 500, 0];
    let u = spawn_in(&mut sc, s, spec);
    watch(0, u.tcb);
    set_n(3);
    assert!(run_until(w0_reported_n, ms(2_000)));
    assert!(report::values_of(u.tcb.0).all(|v| v == 0x5eed));
    let before = crate::irq::stats_of(k);
    let calls = served(k);
    assert_eq!(unmap(s, DATA_VA, 4096), Ok(1));
    assert!(
        run_until(w0_suspended, ms(2_000)),
        "the thread didn't fault"
    );
    let f = u.tcb.state().fault;
    assert_eq!((f.kind, f.addr), (fault::Kind::Unmapped as u64, DATA_VA));
    let after = crate::irq::stats_of(k);
    assert_eq!(
        after.remote_call, before.remote_call,
        "the unmap sent a remote call"
    );
    assert_eq!(
        served(k),
        calls,
        "core {k} served a remote call for the unmap"
    );
    testkit::finish(sc);
});

crate::kernel_smp_test!(destroying_a_space_drops_it_on_every_core, {
    // An address space destroyed while another core's TTBR0_EL1 holds it
    // is deactivated there first, by a remote call, and the thread that
    // ran in it there stops (`crate::mm::space`).
    let Some(mut cores) = others(1) else { return };
    let k = cores.next().unwrap();
    let mut sc = scratch();
    let s = space(&mut sc);
    let mut spec = Spec::of(Program::CountReport).on(k);
    spec.args = [0, 100_000, 0];
    spec.budget_us = 900;
    let u = spawn_in(&mut sc, s, spec);
    watch(0, u.tcb);
    set_n(3);
    assert!(run_until(w0_reported_n, ms(2_000)));
    let calls = served(k);
    // The thread's copy goes with the revoke, the space with the delete.
    cap::revoke(s);
    cap::delete(s);
    assert!(served(k) > calls, "no remote call reached core {k}");
    assert_eq!(
        remote::probe_core(k).ttbr0 & 0xffff_ffff_f000,
        crate::mm::phys::kernel_pa(crate::entry::zero_table())
    );
    assert_ne!(percore::core(k).current, u.tcb.0);
    let n0 = report::count_of(u.tcb.0);
    run_ms(10);
    assert_eq!(
        report::count_of(u.tcb.0),
        n0,
        "a thread ran without its space"
    );
    testkit::finish(sc);
});

crate::kernel_smp_test!(log_records_carry_their_core, {
    // ADR 0042, rule 2: each record names the core that wrote it.
    let me = this_core().index;
    crate::klog!(Info, "smp", "a record from core {me}");
    for k in (0..MAX_CORES).filter(|&k| k != me && crate::smp::is_online(k)) {
        remote::log_from(k);
    }
    let mut seen = 0u64;
    crate::log::for_each(|r| {
        for k in 0..MAX_CORES {
            let mut want = crate::log::Line::new();
            let _ = core::fmt::write(&mut want, format_args!("a record from core {k}"));
            if r.text == want.as_str() {
                assert_eq!(
                    r.cpu as usize, k,
                    "a record of core {k} names core {}",
                    r.cpu
                );
                seen |= 1 << k;
            }
        }
    });
    assert_eq!(seen, crate::smp::start::online_mask());
});

crate::kernel_smp_test!(configure_refuses_a_core_that_is_offline, {
    // A context can't be configured onto a core that isn't online,
    // whose deadlines no timer would ever end.
    let n = crate::irq::get().unwrap().cores().len();
    if n == MAX_CORES {
        crate::uart::write("  (every core is in the device tree: skipped)\n");
        return;
    }
    let mut sc = scratch();
    let ctl = sc.take();
    mdb::insert_root(&mut DirectSlots, ctl, Cap::SchedControl { core: n as u8 });
    let c = sc.make(ObjectType::SchedContext(8));
    assert_eq!(
        context::configure(ctl, c, 100, 1_000, 0, 0),
        Err(Error::CoreOffline)
    );
    cap::delete(ctl);
    testkit::finish(sc);
});

crate::kernel_smp_test!(asid_rollover_with_spaces_on_several_cores, {
    // Kernel specification, "ASIDs": a rollover keeps the number each core
    // runs, so threads in two spaces on two cores go on reading their own
    // pages through it, and a TLB flush in between changes nothing they see.
    let Some(mut cores) = others(1) else { return };
    let k = cores.next().unwrap();
    let me = this_core().index;
    let mut sc = scratch();
    let mut users = [None; 2];
    for (i, (core, value)) in [(me, 0xa1u64), (k, 0xb2)].into_iter().enumerate() {
        let s = space(&mut sc);
        data_page(&mut sc, s, value);
        let mut spec = Spec::of(Program::LoadLoop).on(core);
        spec.args = [DATA_VA, 100_000, 0];
        let u = spawn_in(&mut sc, s, spec);
        watch(i, u.tcb);
        users[i] = Some((u, value));
    }
    set_n(3);
    assert!(run_until(each_reported_n, ms(2_000)));
    crate::mm::space::force_rollover();
    report::clear();
    assert!(
        run_until(each_reported_n, ms(2_000)),
        "a thread stopped after the rollover"
    );
    for (u, value) in users.into_iter().flatten() {
        assert!(
            report::values_of(u.tcb.0).all(|v| v == value),
            "a thread read another space's page after the rollover"
        );
    }
    testkit::finish(sc);
});
