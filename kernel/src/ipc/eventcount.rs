// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Eventcounts and threads bound to one, on the kernel's objects (ADR
//! 0053; kernel specification, "Eventcount operations" and "Threads bound
//! to an eventcount"): `kipc::eventcount`'s protocol, the one
//! implementation, which `specs/Eventcount.tla` models, run over
//! [`KStore`]. Wait sets are [`super::waitset`]'s.
//!
//! Each operation takes its capabilities already looked up
//! ([`super::syscall`] looks them up from the caller's addresses) and writes
//! the caller's x0 when it returns at once, with "ok" or the error that
//! refused it; a wait's end writes it otherwise. A count goes into x1 (K28).
//!
//! **An advance** from a system call wakes the reached waiters itself,
//! ticking the caller's budget with each wake's cost, and leaves the rest
//! to its core's work list when a preemption point finds an interrupt
//! pending: it returns once the count has changed, and is never restarted,
//! so it adds one exactly once (K31). An advance for an interrupt (C13b's
//! seam, [`advance_for_interrupt`]) only adds one and queues the
//! eventcount. Either way the work list's units ([`work_unit`]) wake the
//! rest, in the core's batches, each unit costing the nodes it unlinks
//! ([`unit_cost`]; K24).
//!
//! **A bound eventcount** is a copy in thread slot 6, a binding with the
//! bound-eventcount role (ADR 0053, rule 5; K07). Binding refuses a thread
//! whose slot 6 holds anything, so it never deletes; unbinding deletes the
//! copy with the caller's budget, and is made again at a preemption point,
//! as every operation that deletes a capability is (K23). The copy's unbind
//! step ([`super::unbind_bound`]) takes the thread's node out of the
//! eventcount's tree, and a receive in progress goes on, on the endpoint
//! alone. A receive reports an advance only while its thread holds a
//! context: a context bound to a receiving thread links its node, or
//! reports an advance it hasn't seen ([`context_bound`]).

use super::endpoint::{Ret, conclude, set_status};
#[cfg(aspis_test_build)]
use super::object::{self, ec_word};
use crate::cap::{self, DirectSlots};
use crate::sched::donation::KStore;
use crate::sched::object::{Tcb, Wait};
use kcap::SlotRef;
use kcap::cap::{Binding, Cap};
use kcap::ops;
use kcap::preempt::{Budget, Pending, Preempted};
use kcap::rights::Rights;
use kipc::eventcount as ec;
use kipc::msg::{Status, regs};
use kipc::{Ec, Outcome};
use ksched::donation::Tcb as DTcb;

fn d(t: Tcb) -> DTcb {
    DTcb(t.0)
}

/// The eventcount a capability names, with its rights.
pub fn ec_cap(c: &Cap) -> Result<(Ec, Rights), Status> {
    match *c {
        Cap::Eventcount { ptr, rights, .. } => Ok((Ec(ptr), rights)),
        Cap::Null => Err(Status::InvalidCapability),
        _ => Err(Status::WrongKind),
    }
}

/// Writes x1: a count, or a wait set's mask.
fn set_value(t: Tcb, v: u64) {
    t.with(|b| b.ctx.x[regs::INFO] = v);
}

/// Ends an operation that returns at once: x0 the status, and on success
/// x1 the count.
fn returns(t: Tcb, r: Result<u64, Status>) -> Result<u64, Status> {
    match r {
        Ok(count) => {
            set_status(t, Status::Ok);
            set_value(t, count);
        }
        Err(s) => set_status(t, s),
    }
    r
}

/// `Advance`: adds one to `e`, which needs the write right, and wakes its
/// reached waiters, the rest in batches once `budget` finds an interrupt
/// pending (module docs; K31). At 2^64 - 1 it fails "count at maximum",
/// the count unchanged (ADR 0053, rule 3). Returns the new count, in x1.
pub fn advance<P: Pending>(
    t: Tcb,
    e: Ec,
    rights: Rights,
    budget: &mut Budget<P>,
) -> Result<u64, Status> {
    let r = ec::advance(&mut KStore::begin(), e, rights, budget);
    returns(t, r)
}

/// An advance for an interrupt, under the kernel lock (C13b's seam; K24):
/// adds one at once and leaves every wake to this core's work list, unless
/// the eventcount is on a list already. C13b's handler objects call it when
/// their interrupt fires; until then only the tests do.
#[cfg_attr(not(aspis_test_build), allow(dead_code))]
pub fn advance_for_interrupt(e: Ec) -> Result<u64, Status> {
    ec::advance_irq(&mut KStore, e)
}

/// `Read`: `e`'s count, in x1. Needs the read right.
pub fn read(t: Tcb, e: Ec, rights: Rights) -> Result<u64, Status> {
    let r = ec::read(&KStore, e, rights);
    returns(t, r)
}

/// `Wait`: `t` waits until `e`'s count reaches `target`, or `deadline`, 0
/// for none. Needs the read right. A target already reached returns at once
/// with the count in x1, so no wake-up is lost between a read and a wait;
/// a passed deadline then times out only a wait that would block (K19).
pub fn wait(t: Tcb, e: Ec, rights: Rights, target: u64, deadline: u64) -> Ret {
    // The running thread's time is charged first; then the kernel names
    // the wait, before the protocol starts it.
    let mut store = KStore::begin();
    t.update(|s| s.wait = Wait::Eventcount as u8);
    let r = ec::wait(&mut store, d(t), e, rights, target);
    if !matches!(r, Ok(Outcome::Blocked)) {
        t.update(|s| s.wait = Wait::None as u8);
    }
    conclude(t, r, deadline)
}

/// The units the next work-list unit of the eventcount at `e` costs: its
/// first reached waiter's wake, one or the nodes of a wait set, or one to
/// clear its mark (K24).
pub fn unit_cost(e: u64) -> u32 {
    ec::unit_cost(&mut KStore, Ec(e))
}

/// One work-list unit of the eventcount at `e`, inside a batch: wakes its
/// first reached waiter, or, with none left, clears its mark and takes it
/// off its list. Returns whether work remains.
pub fn work_unit(e: u64) -> bool {
    ec::work_unit(&mut KStore, Ec(e))
}

// ---------------------------------------------------------------------------
// Bound eventcounts.

/// Binds the eventcount whose capability is in `src` to thread `t`, whose
/// capability's write right was checked (ADR 0053, rule 5): a copy in slot
/// 6, a binding, and last-seen the count now. The eventcount needs the read
/// right. Refused "busy" while slot 6 holds anything, a binding or the
/// zombie of one being deleted, so binding never deletes.
pub fn bind(t: Tcb, src: SlotRef) -> Result<(), Status> {
    let (e, rights) = ec_cap(&cap::cap(src))?;
    if !rights.contains(Rights::READ) {
        return Err(Status::MissingRight);
    }
    let slot = t.slot(Binding::BoundEventcount.thread_slot());
    if !cap::cap(slot).is_null() {
        return Err(Status::Busy);
    }
    // Stalled after the checks that read only the slots, so a bind refused
    // there leaves the target's run on another core alone.
    crate::smp::remote::stall(t);
    // The copy first: it is the one step that can fail, and changes
    // nothing when it does.
    if let Err(err) = ops::bind_copy(&mut DirectSlots, src, slot, Binding::BoundEventcount) {
        return Err(match err {
            ops::Error::Empty => Status::InvalidCapability,
            ops::Error::WrongKind => Status::WrongKind,
            _ => Status::InvalidArgument,
        });
    }
    match ec::bind(&mut KStore, d(t), e, rights) {
        Ok(()) => Ok(()),
        // The checks above are the protocol's, so it can't refuse.
        Err(s) => panic!(
            "binding eventcount {:#x} failed after its checks: {s:?}",
            e.0
        ),
    }
}

/// Unbinds thread `t`'s eventcount: deletes its copy in slot 6 with
/// `budget`, whose unbind step does the rest (module docs). A preempted
/// call leaves the copy's zombie in slot 6, never an empty slot
/// ([`kcap::delete::delete`]), so a call made again finds the deletion
/// further on, and no `BIND_EC` can fill the slot in between. A thread
/// with nothing bound is nothing to do. Deleting the last capability to an eventcount drains its
/// waiters, one a unit (K30).
pub fn unbind<P: Pending>(t: Tcb, budget: &mut Budget<P>) -> Result<(), Preempted> {
    crate::smp::remote::stall(t);
    let slot = t.slot(Binding::BoundEventcount.thread_slot());
    if !cap::cap(slot).is_null() {
        cap::delete_with(slot, budget)?;
    }
    Ok(())
}

/// A context was bound to thread `t` (`crate::sched::thread::bind_context`):
/// if it receives with a bound eventcount, an advance it hasn't seen is
/// reported now, or its node is linked, as a receive made with a context
/// does (ADR 0053, rule 5).
pub fn context_bound(t: Tcb) {
    ec::context_bound(&mut KStore, d(t));
}

// ---------------------------------------------------------------------------
// Test builds.

/// Sets the eventcount at `e`'s count, for the tests of its maximum, which
/// no number of advances in a test could reach (test builds).
#[cfg(aspis_test_build)]
pub fn set_count(e: Ec, v: u64) {
    object::set(e.0, ec_word::COUNT, v);
}

/// The eventcount at `e`'s count.
#[cfg(aspis_test_build)]
pub fn count(e: Ec) -> u64 {
    object::get(e.0, ec_word::COUNT)
}

/// Whether the eventcount at `e` has a wake pending, and the core whose
/// work list holds it, if any (test builds).
#[cfg(aspis_test_build)]
pub fn pending(e: Ec) -> (bool, Option<usize>) {
    let w = object::get(e.0, ec_word::WORD);
    let core =
        (w & ec_word::QUEUED != 0).then_some(((w & ec_word::CORE) >> ec_word::CORE_SHIFT) as usize);
    (w & ec_word::PENDING != 0, core)
}

/// Whether every word of the eventcount at `e` is zero, as retype left it
/// and its finish leaves it (test builds).
#[cfg(aspis_test_build)]
pub fn is_clear(e: Ec) -> bool {
    (0..8).all(|i| object::get(e.0, i * 8) == 0)
}

/// Checks the eventcount invariants over the eventcounts, wait sets (by
/// `kipc`'s names) and threads given (test builds).
#[cfg(aspis_test_build)]
pub fn check(ecs: &[Ec], sets: &[kipc::Ws], threads: &[Tcb]) -> Result<(), ec::Violation> {
    const MAX: usize = 512;
    assert!(threads.len() <= MAX);
    let mut ts = [DTcb(0); MAX];
    for (i, &t) in threads.iter().enumerate() {
        ts[i] = d(t);
    }
    ec::check(&mut KStore, ecs, sets, &ts[..threads.len()])
}
