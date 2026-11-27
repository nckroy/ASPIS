// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Scheduling contexts and scheduling control (ADR 0051, rule 1; ADR 0058,
//! rule 8; kernel specification, "Scheduling contexts and budgets", K13,
//! K14 and K15).
//!
//! [`configure`] is seL4's `SchedControl_ConfigureFlags` with no flags,
//! through one core's scheduling-control capability: a budget and a period
//! in microseconds, the number of extra refills, and the badge that timeout
//! and context-withdrawn faults report. It binds the context to that core.
//! It checks, in this order, before it changes anything:
//!
//! 1. the core is online;
//! 2. 10 µs ≤ budget ≤ period ≤ one hour ([`ksched::time::check_limits`]);
//! 3. the refills fit the context: two plus the extra, or one for
//!    round-robin, within the capacity its size gives (K15);
//! 4. the share check: the context's job's contexts on that core stay within
//!    the job's share of it (K13).
//!
//! **The share stand-in.** Until C16 makes jobs, every context belongs to
//! the root job, whose share is the whole of each core, and the sums live
//! here, one per core. C16 moves them into job objects.

use super::Error;
use super::object::{Sc, capacity, sc_flag};
use super::percore::this_core;
use super::run::{self, MIN_DISPATCH_US, Stop};
use crate::cap;
use crate::mm::BootCell;
use kcap::SlotRef;
use kcap::cap::Cap;
use kirq::MAX_CORES;
use ksched::refill::{Invalid, MIN_REFILLS};
use ksched::share::{Share, Used};
use ksched::time;

/// The root job's bandwidth on each core: the stand-in for C16's jobs.
static ROOT_USED: BootCell<[Used; MAX_CORES]> = BootCell::new([Used::EMPTY; MAX_CORES]);

/// The root job's share of each core: the whole core.
pub const ROOT_SHARE: Share = Share::WHOLE;

fn with_used<R>(f: impl FnOnce(&mut [Used; MAX_CORES]) -> R) -> R {
    // SAFETY: under the kernel lock; the reference lives only for `f`,
    // which doesn't call this again.
    f(unsafe { ROOT_USED.get_mut() })
}

/// The root job's bandwidth on `core`, for the tests.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub fn used(core: usize) -> Used {
    with_used(|u| u[core])
}

/// Whether core `core` is online: the boot core, and each core PSCI
/// brought up.
pub fn is_online(core: usize) -> bool {
    crate::smp::is_online(core)
}

/// Configures the scheduling context in `sc` through the scheduling-control
/// capability in `control` (module docs).
pub fn configure(
    control: SlotRef,
    sc: SlotRef,
    budget_us: u64,
    period_us: u64,
    extra_refills: u32,
    badge: u64,
) -> Result<(), Error> {
    let core = match cap::cap(control) {
        Cap::SchedControl { core } => core as usize,
        Cap::Null => return Err(Error::Cap(kcap::ops::Error::Empty)),
        _ => return Err(Error::WrongKind),
    };
    let (c, bits) = match cap::cap(sc) {
        Cap::SchedContext { ptr, bits, .. } => (Sc(ptr), bits),
        Cap::Null => return Err(Error::Cap(kcap::ops::Error::Empty)),
        _ => return Err(Error::WrongKind),
    };
    if core >= MAX_CORES || !is_online(core) {
        return Err(Error::CoreOffline);
    }
    time::check_limits(budget_us, period_us).map_err(Error::Limits)?;
    let round_robin = budget_us == period_us;
    let max = if round_robin {
        1
    } else {
        MIN_REFILLS
            .checked_add(extra_refills)
            .ok_or(Error::TooManyRefills)?
    };
    if max > capacity(bits) {
        return Err(Error::TooManyRefills);
    }
    // The share check, before anything changes (ADR 0058, rule 8).
    let old = c.with(|h| {
        (h.flags & sc_flag::CONFIGURED != 0).then_some((h.core as usize, h.budget_us, h.period_us))
    });
    with_used(|used| -> Result<(), Error> {
        match old {
            Some((oc, ob, op)) if oc == core => {
                used[core] = used[core]
                    .reconfigure(ROOT_SHARE, (ob, op), (budget_us, period_us))
                    .map_err(Error::Share)?;
            }
            Some((oc, ob, op)) => {
                used[core] = used[core]
                    .admit(ROOT_SHARE, budget_us, period_us)
                    .map_err(Error::Share)?;
                used[oc] = used[oc].release(ob, op);
            }
            None => {
                used[core] = used[core]
                    .admit(ROOT_SHARE, budget_us, period_us)
                    .map_err(Error::Share)?;
            }
        }
        Ok(())
    })?;
    // The thread on the context stops, with its time charged, and is put
    // back where it belongs afterwards.
    let holder = c.with(|h| h.holder);
    let t = super::object::Tcb(holder);
    if holder != 0 {
        // On another core it is stalled there first, with its time charged
        // (kernel specification, "Cross-core signals and TLB maintenance").
        crate::smp::remote::stall(t);
        if this_core().current == holder {
            run::stop_current(Stop::Preempted);
        }
        run::dequeue(t);
    }
    run::release_remove(c);
    let clock = run::clock();
    let budget = clock.budget(budget_us);
    let period = if round_robin {
        budget
    } else {
        clock.period(period_us, budget)
    };
    let min = clock.counts_ceil(MIN_DISPATCH_US);
    let now = crate::timer::now();
    // As seL4 17.0.0's `invokeSchedControl_ConfigureFlags`: a context in
    // use, on the same core with a runnable thread on it, keeps its head
    // refill (`refill_update`); any other gets its whole new budget from
    // now (`refill_new`), as an exhausted thread blocked in its timeout
    // fault does when its handler lends it budget (ADR 0051, rule 3).
    let in_use = holder != 0 && old.is_some_and(|(oc, _, _)| oc == core) && run::eligible(t);
    let r = c.with_refills(bits, |r| {
        if in_use {
            r.reconfigure(budget, period, max, min, now)
        } else {
            r.configure(budget, period, max, min, now)
        }
    });
    match r {
        Ok(()) => {}
        // Checked above: the budget is at least one count and at most the
        // period, and the refills fit.
        Err(Invalid::TooManyRefills) | Err(Invalid::Budget) => {
            panic!("configure's checks passed, but the refills refused {r:?}")
        }
    }
    c.with(|h| {
        h.budget_us = budget_us;
        h.period_us = period_us;
        h.badge = badge;
        h.core = core as u8;
        h.bits = bits;
        h.flags |= sc_flag::CONFIGURED;
    });
    if holder != 0 {
        run::place(t);
    }
    Ok(())
}

/// The context's last capability is gone (`kcap`'s finish hook): it leaves
/// its release tree and its bandwidth is released (K13). No thread holds
/// it: a thread's binding is itself a capability to it, deleted first, and
/// its unbind took a donated context back. Walks of its take-backs that are
/// still pending go on without it (`super::donation`).
pub fn finish(ptr: u64) {
    let c = Sc(ptr);
    super::donation::destroy_sc(c);
    run::release_remove(c);
    let h = c.header();
    assert!(
        h.home == 0,
        "a scheduling context was destroyed while bound to {:#x}",
        h.home
    );
    if h.flags & sc_flag::CONFIGURED != 0 {
        with_used(|u| u[h.core as usize] = u[h.core as usize].release(h.budget_us, h.period_us));
    }
    c.with(|h| h.flags = 0);
}
