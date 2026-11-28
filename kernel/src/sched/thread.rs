// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The operations on a thread through its capability (ADR 0047, rule 2;
//! ADR 0051, rules 1 and 2; ADR 0061, rule 3; kernel specification,
//! "Threads and scheduling", "Kernel bindings that hold capabilities" and
//! "Rights by object type").
//!
//! These are kernel functions over capabilities, as C11's capability
//! operations are: C17's system calls decode invocations into them, and
//! until then the in-QEMU tests call them. The read right reads a thread's
//! registers; the write right does everything else.
//!
//! - [`configure_space`]: the root CNode and address space, slots 1 and 2.
//! - [`set_endpoint`]: the fault and timeout endpoints, slots 3 and 4, each
//!   a binding, needing an endpoint with write and grant or grant-reply, as
//!   seL4's `validFaultHandler`.
//! - [`set_priority`] and [`set_mcp`], checked against an authority
//!   thread's maximum controlled priority, as seL4's `checkPrio`.
//! - [`bind_context`] and [`unbind_context`]: slot 5.
//! - [`suspend`] and [`resume`], which leave a wait in place (ADR 0061,
//!   rule 3).
//! - [`read_registers`] and [`write_registers`], `TPIDR_EL0` included.
//! - [`cancel`]: ends the thread's wait with "canceled", taking a donated
//!   call's context back at once (ADR 0051, rule 3).
//!
//! The IPC bindings are `crate::ipc`'s (C14): a bound eventcount in slot 6
//! (`crate::ipc::eventcount::bind`) and the IPC buffer in slot 7
//! (`crate::ipc::buffer::set`).
//!
//! Binding, unbinding, suspending, canceling and destroying go through
//! `ksched::donation` ([`super::donation`]), so a thread's context and its
//! donated calls stay as the protocol keeps them.
//!
//! Each operation stalls a thread that runs on another core first, with a
//! remote call, and so does destroying one (kernel specification,
//! "Cross-core signals and TLB maintenance").

use super::Error;
use super::donation;
use super::object::{Sc, Tcb, UserContext, Wait, flag};
use super::run::{self, SPSR_EL0, SPSR_NZCV, Stop};
use crate::cap::{self, DirectSlots};
use kcap::SlotRef;
use kcap::cap::{Binding, Cap};
use kcap::ops;
use kcap::preempt::{Budget, Pending};
use kcap::rights::Rights;
use ksched::prio;

/// The thread a capability in `slot` names, if the capability has `right`.
pub fn thread_of(slot: SlotRef, right: Rights) -> Result<Tcb, Error> {
    match cap::cap(slot) {
        Cap::Thread { ptr, rights } if rights.contains(right) => Ok(Tcb(ptr)),
        Cap::Thread { .. } => Err(Error::MissingRight),
        Cap::Null => Err(Error::Cap(ops::Error::Empty)),
        _ => Err(Error::WrongKind),
    }
}

/// The thread a capability in `slot` names, with `right`, stalled if it
/// runs on another core, so the change that follows doesn't race its run
/// there, and its registers in its object are its own (kernel
/// specification, "Cross-core signals and TLB maintenance").
fn stalled(slot: SlotRef, right: Rights) -> Result<Tcb, Error> {
    let t = thread_of(slot, right)?;
    crate::smp::remote::stall(t);
    Ok(t)
}

/// Deletes the capability in the thread's slot `i`, if any, under
/// `budget`: [`Error::Preempted`] at a preemption point, with the
/// deletion's progress recorded in its zombies and queues. Every operation
/// that replaces a slot deletes first, after its checks and before any
/// other change, so made again it finds the slot empty, or the deletion
/// further on, and its restart is idempotent (kernel specification, "The
/// kernel lock and long operations"; ADR 0052, rule 2): deleting the last
/// capability to an endpoint with a long queue takes a step per waiter.
///
/// A deletion never reports a preemption once its slot is empty
/// ([`kcap::delete::delete`]), so [`Error::Preempted`] always leaves the
/// slot holding the deletion's zombie, which a restart resumes
/// ([`deleting`]).
fn clear<P: Pending>(t: Tcb, i: u64, budget: &mut Budget<P>) -> Result<(), Error> {
    let dst = t.slot(i);
    if cap::cap(dst).is_null() {
        return Ok(());
    }
    cap::delete_with(dst, budget).map_err(|_| Error::Preempted)
}

/// Puts a copy of the capability in `src`, a child of it, into the
/// thread's empty slot `i`, as a binding in `role` if it has one.
fn put(t: Tcb, i: u64, src: SlotRef, role: Option<Binding>) -> Result<(), Error> {
    let dst = t.slot(i);
    match role {
        Some(r) => ops::bind_copy(&mut DirectSlots, src, dst, r).map(|_| ()),
        None => ops::copy(&mut DirectSlots, src, dst),
    }
    .map_err(Error::Cap)
}

/// Refuses `src` before anything changes when [`put`] couldn't copy it:
/// the copy is a child of `src`, one level deeper, and a slot at the
/// deepest level has no room for one. The other refusals of `put` are
/// ruled out by the checks before [`clear`], and by [`source`] when the
/// deletion emptied the source.
fn deep_enough(src: SlotRef) -> Result<(), Error> {
    if kcap::slot::read(&DirectSlots, src).depth == kcap::slot::MAX_DEPTH {
        return Err(Error::Cap(ops::Error::TooDeep));
    }
    Ok(())
}

/// Checks `src` as a source for [`put`]: a capability that `kind` accepts,
/// not at the deepest level ([`deep_enough`]). `Ok(false)` for an empty
/// slot, which the caller refuses before it deletes anything, and skips
/// after: clearing a thread's root CNode may destroy the CNode that holds
/// `src`, which empties it. The copy is then skipped, as seL4's
/// `checkCapAt` skips it, and the thread's slot stays empty (kernel
/// specification, "The kernel lock and long operations"). A completed
/// deletion only empties slots, so a source it touched is empty, never
/// another capability. Only an object with slots cascades so: endpoints,
/// eventcounts and frames don't.
fn source(src: SlotRef, kind: fn(&Cap) -> bool) -> Result<bool, Error> {
    match cap::cap(src) {
        Cap::Null => Ok(false),
        c if kind(&c) => deep_enough(src).map(|()| true),
        _ => Err(Error::WrongKind),
    }
}

/// Whether the thread's slot `i` holds a zombie: a deletion of it that a
/// preemption point stopped, which the next operation on the slot resumes.
fn deleting(t: Tcb, i: u64) -> bool {
    matches!(t.slot_cap(i), Cap::Zombie { .. })
}

/// Runs `f` with fresh budgets until it isn't preempted: a kernel-internal
/// caller's loop, where a system call would restart from its `SVC`. Each
/// call makes progress before it checks, so the loop ends.
fn to_end(f: impl FnMut(&mut Budget<cap::IrqPending>) -> Result<(), Error>) -> Result<(), Error> {
    to_end_under(cap::budget, f)
}

/// [`to_end`], with each call's budget from `budget`.
fn to_end_under<P: Pending>(
    mut budget: impl FnMut() -> Budget<P>,
    mut f: impl FnMut(&mut Budget<P>) -> Result<(), Error>,
) -> Result<(), Error> {
    loop {
        match f(&mut budget()) {
            Err(Error::Preempted) => continue,
            r => return r,
        }
    }
}

/// Sets the thread's root CNode and address space to copies of the
/// capabilities in `cnode` and `space` (seL4's `TCB_SetSpace`, without the
/// fault endpoint). The thread can't run until both are set. Deleting the
/// old ones runs under `budget` ([`clear`]).
///
/// A first attempt checks the sources before anything is deleted, so every
/// refusal comes before any change. `restart` says that this call is the
/// same call made again after a preemption point stopped it: the kernel's
/// own callers set it on every call but the first ([`configure_space`]).
/// C17's system call is to set it when the call is made again from its
/// `SVC`. How it learns that is still open (kernel specification K23):
/// [`super::entry::restart`] only moves the PC back, so a call made again
/// looks like a fresh one, and a mark kept for it mustn't outlive a write
/// of the thread's registers, a cancel or any other entry. A restart
/// that finds slot 1 or 2 holding its deletion's zombie resumes the
/// deletion first, since the deletion may already have emptied a source
/// inside the old root, and checks each source only after it, an empty one
/// skipped ([`source`]). A zombie that another operation left in slot 1 or
/// 2, such as a revocation's stopped at a preemption point, doesn't make a
/// first attempt a restart: its checks run first, and its deletion then
/// finishes that zombie, as any operation may.
///
/// A restart ends as the run without preemption does while the thread's
/// capability in `thread` lies outside what the old root reaches. When the
/// deletion takes that capability out of its slot without destroying the
/// thread, a copy that isn't the last, a restart can no longer name the
/// thread through it, and fails with the lookup's error, as seL4's
/// re-decode does; the zombie stays in slot 1 for the thread's next
/// configuration to resume.
///
/// Deleting the old root may destroy the thread itself, when that root was
/// the last capability to the CNode that holds the thread's last capability.
/// The thread is then stopped for good, and nothing is copied into it, as
/// seL4's `invokeTCB_ThreadControl` checks `sameObjectAs(tCap, slot->cap)`
/// before it inserts: a copy in a dead thread's slot would stay linked while
/// its memory is reset. A preemption point after the thread is stopped ends
/// the call with `Ok`, as the run without preemption ends, but leaves the
/// rest of the deletion undone, since no restart could name the thread,
/// whose capability the deletion has made a zombie, and nothing else
/// resumes it. What is left no lookup can name: the old root, if it isn't
/// finished yet, and the thread, which hold each other's last capabilities,
/// perhaps through other CNodes, and every object that only their slots not
/// yet cleared reach, such as the thread's old address space in slot 2,
/// whose ASID stays allocated. Once the deletion has handed the thread's
/// zombie over into slot 1, the old root is finished, and only the thread
/// is left, holding its own zombie there. Those objects stay, and threads
/// waiting on them stay blocked, until revoking their untyped memory
/// finishes them, as it finishes a revoke's cycle (`kcap::delete::revoke`);
/// the run without preemption destroys them. Only a thread that replaces
/// its own root, held nowhere else, meets this. Whether to finish what is
/// left as work with no caller is still open, for C17 (kernel
/// specification K23).
pub fn configure_space_with<P: Pending>(
    thread: SlotRef,
    cnode: SlotRef,
    space: SlotRef,
    restart: bool,
    budget: &mut Budget<P>,
) -> Result<(), Error> {
    let is_cnode: fn(&Cap) -> bool = |c| matches!(c, Cap::CNode { .. });
    let is_space: fn(&Cap) -> bool = |c| matches!(c, Cap::AddressSpace { .. });
    let t = stalled(thread, Rights::WRITE)?;
    if !(restart && (deleting(t, 1) || deleting(t, 2))) {
        // Nothing of this call's to resume: every refusal comes before
        // anything changes.
        match (cap::cap(cnode), cap::cap(space)) {
            (Cap::CNode { .. }, Cap::AddressSpace { .. }) => {}
            (Cap::Null, _) | (_, Cap::Null) => return Err(Error::Cap(ops::Error::Empty)),
            _ => return Err(Error::WrongKind),
        }
        deep_enough(cnode)?;
        deep_enough(space)?;
    }
    let cleared = clear(t, 1, budget).and_then(|()| clear(t, 2, budget));
    if t.has(flag::DEAD) {
        // Its old root held its last capability: it was stopped, perhaps
        // just before a preemption point, which then ends the call too.
        return Ok(());
    }
    cleared?;
    if source(cnode, is_cnode)? {
        put(t, 1, cnode, None)?;
    }
    if source(space, is_space)? {
        put(t, 2, space, None)?;
    }
    run::place(t);
    Ok(())
}

/// [`configure_space_with`], run to the end.
pub fn configure_space(thread: SlotRef, cnode: SlotRef, space: SlotRef) -> Result<(), Error> {
    configure_space_under(thread, cnode, space, cap::budget)
}

/// [`configure_space`], with each call's budget from `budget`: the kernel's
/// own restart loop, a first attempt and then restarts, which the tests
/// drive with budgets that find an interrupt pending at every check.
pub(crate) fn configure_space_under<P: Pending>(
    thread: SlotRef,
    cnode: SlotRef,
    space: SlotRef,
    budget: impl FnMut() -> Budget<P>,
) -> Result<(), Error> {
    let mut restart = false;
    to_end_under(budget, |b| {
        let r = configure_space_with(thread, cnode, space, restart, b);
        restart = true;
        r
    })
}

/// Sets the thread's fault or timeout endpoint (`role`) to a copy of the
/// endpoint capability in `ep`, or unsets it with `None` (kernel
/// specification, "Fault delivery"). The endpoint needs the write right and
/// grant or grant-reply. Unsetting withdraws a fault queued there (K50).
/// Deleting the old copy runs under `budget` ([`clear`]).
pub fn set_endpoint_with<P: Pending>(
    thread: SlotRef,
    role: Binding,
    ep: Option<SlotRef>,
    budget: &mut Budget<P>,
) -> Result<(), Error> {
    let t = stalled(thread, Rights::WRITE)?;
    if !matches!(role, Binding::FaultEndpoint | Binding::TimeoutEndpoint) {
        return Err(Error::WrongKind);
    }
    if let Some(e) = ep {
        match cap::cap(e) {
            Cap::Endpoint { rights, .. }
                if rights.contains(Rights::WRITE)
                    && (rights.contains(Rights::GRANT) || rights.contains(Rights::GRANT_REPLY)) => {
            }
            Cap::Endpoint { .. } => return Err(Error::MissingRight),
            Cap::Null => return Err(Error::Cap(ops::Error::Empty)),
            _ => return Err(Error::WrongKind),
        }
        deep_enough(e)?;
    }
    clear(t, role.thread_slot(), budget)?;
    match ep {
        Some(e) => put(t, role.thread_slot(), e, Some(role)),
        None => Ok(()),
    }
}

/// [`set_endpoint_with`], run to the end.
pub fn set_endpoint(thread: SlotRef, role: Binding, ep: Option<SlotRef>) -> Result<(), Error> {
    to_end(|b| set_endpoint_with(thread, role, ep, b))
}

/// The maximum controlled priority of the thread in `auth`, any thread
/// capability, as seL4 takes it.
fn authority(auth: SlotRef) -> Result<u8, Error> {
    let a = thread_of(auth, Rights::NONE)?;
    Ok(a.with(|b| b.s.mcp))
}

/// Sets the thread's priority to `p`, which may not exceed the maximum
/// controlled priority of the thread in `auth` (ADR 0051, rule 2).
pub fn set_priority(thread: SlotRef, auth: SlotRef, p: u8) -> Result<(), Error> {
    let t = stalled(thread, Rights::WRITE)?;
    if !prio::may_set(authority(auth)?, p) {
        return Err(Error::Priority);
    }
    // Out of the queue at its old priority, then back in at its new one;
    // queued on an endpoint, it rejoins as a new arrival (K25).
    run::dequeue(t);
    t.update(|s| s.priority = p);
    crate::ipc::endpoint::requeue(t);
    run::place(t);
    Ok(())
}

/// Sets the thread's maximum controlled priority to `m`, which may not
/// exceed the authority's.
pub fn set_mcp(thread: SlotRef, auth: SlotRef, m: u8) -> Result<(), Error> {
    let t = stalled(thread, Rights::WRITE)?;
    if !prio::may_set(authority(auth)?, m) {
        return Err(Error::Priority);
    }
    t.update(|s| s.mcp = m);
    Ok(())
}

/// Binds the scheduling context in `sc` to the thread, as its own: a copy
/// in slot 5, a binding (ADR 0049, rule 4). Refused if the thread has one,
/// holds a donated one, or serves a donated call, or if the context is
/// bound to another (kernel specification, "Passive servers and taking a
/// context back"): a stranded server is given a context only after its
/// walk step has passed.
pub fn bind_context(thread: SlotRef, sc: SlotRef) -> Result<(), Error> {
    let t = stalled(thread, Rights::WRITE)?;
    let c = match cap::cap(sc) {
        Cap::SchedContext { ptr, .. } => Sc(ptr),
        Cap::Null => return Err(Error::Cap(ops::Error::Empty)),
        _ => return Err(Error::WrongKind),
    };
    if !t.slot_cap(5).is_null() {
        return Err(Error::Busy);
    }
    donation::bind(c, t).map_err(|_| Error::Busy)?;
    if let Err(e) = ops::bind_copy(&mut DirectSlots, sc, t.slot(5), Binding::Context) {
        // Nothing is bound after all, and the release entry the bind's
        // placing may have made goes too.
        let _ = donation::unbind(c);
        run::release_remove(c);
        return Err(Error::Cap(e));
    }
    // A thread receiving with a bound eventcount hears it now that it holds
    // a context: an advance it hasn't seen is reported, or its node linked
    // (ADR 0053, rule 5; C14).
    crate::ipc::eventcount::context_bound(t);
    run::place(t);
    Ok(())
}

/// Unbinds the thread's own scheduling context: deletes its copy in slot
/// 5, whose unbind step ([`unbind_context_step`]) does the rest. The thread
/// can't run until it gets a context again.
pub fn unbind_context(thread: SlotRef) -> Result<(), Error> {
    let t = stalled(thread, Rights::WRITE)?;
    if t.slot_cap(5).is_null() {
        return Err(Error::NotBound);
    }
    cap::delete(t.slot(5));
    Ok(())
}

/// Suspends the thread: it stops being scheduled, and any wait it is in
/// stays in place, its deadline running (ADR 0061, rule 3; K20).
pub fn suspend(thread: SlotRef) -> Result<(), Error> {
    let t = stalled(thread, Rights::WRITE)?;
    donation::set_suspended(t, true);
    Ok(())
}

/// Resumes the thread. If its wait ended while it was suspended, it sees the
/// result now.
pub fn resume(thread: SlotRef) -> Result<(), Error> {
    let t = stalled(thread, Rights::WRITE)?;
    if t.has(flag::RESUMED) || t.has(flag::DEAD) {
        return Ok(());
    }
    donation::set_suspended(t, false);
    if t.wait() == Wait::None
        && let Some(sc) = t.sc()
        && sc.is_configured()
    {
        let now = crate::timer::now();
        sc.refills(|r| r.unblock(now));
    }
    run::place(t);
    Ok(())
}

/// The thread's registers, `TPIDR_EL0` included; of `SPSR_EL1`, only the
/// condition flags.
pub fn read_registers(thread: SlotRef) -> Result<UserContext, Error> {
    let t = stalled(thread, Rights::READ)?;
    let mut ctx = t.with(|b| b.ctx);
    ctx.spsr &= SPSR_NZCV;
    Ok(ctx)
}

/// Writes the thread's registers, `TPIDR_EL0` included. Of `SPSR_EL1`, only
/// the condition flags are taken: the rest is always EL0t with FIQs masked.
pub fn write_registers(thread: SlotRef, regs: &UserContext) -> Result<(), Error> {
    let t = stalled(thread, Rights::WRITE)?;
    t.with(|b| {
        b.ctx = *regs;
        b.ctx.spsr = (regs.spsr & SPSR_NZCV) | SPSR_EL0;
    });
    Ok(())
}

/// Ends the thread's wait with "canceled" (ADR 0054, rule 6). A delivered
/// donating call's context comes back at once, and the servers it leaves
/// stranded are walked in batches (ADR 0051, rule 3; K17). A fault send is
/// withdrawn, and the thread goes on as its fault's kind allows: a faulting
/// instruction faults again when it re-executes, if its cause remains;
/// after a timeout fault the thread goes on where its budget ran out, once
/// it has a refill; after a context-withdrawn fault it stays without a
/// context until something gives it one (kernel specification, "Fault
/// delivery"; K50).
pub fn cancel(thread: SlotRef) -> Result<(), Error> {
    let t = stalled(thread, Rights::WRITE)?;
    cancel_thread(t)
}

/// [`cancel`], on the thread itself.
pub fn cancel_thread(t: Tcb) -> Result<(), Error> {
    match donation::cancel(t) {
        Ok(()) => Ok(()),
        Err(_) => Err(Error::NotWaiting),
    }
}

/// The thread's object is about to become a zombie (`kcap`'s zombify
/// hook): it never runs again. It is marked dead, so its slots' unbind
/// steps log nothing while the zombie clears them, perhaps across
/// preemptions (kernel specification, "Derivation and revocation",
/// zombies). The donated call it serves goes back
/// to its caller, its own wait ends, a context it lent away in a call comes
/// back first, and its home context is unbound. It leaves its run
/// queue and its deadline tree. Returns the units it took: those of the
/// waits it ends, a take-back's included (K23), at least 1.
pub fn zombify(t: Tcb) -> u32 {
    crate::smp::remote::stall(t);
    t.update(|s| s.flags = (s.flags | flag::DEAD) & !flag::RESUMED);
    if super::percore::this_core().current == t.0 {
        run::stop_current(Stop::Blocked);
    }
    let units = donation::destroy_thread(t);
    run::dequeue(t);
    run::deadline_remove(t);
    units
}

/// The thread's copy of its scheduling context, `cap`, is being removed
/// from slot 5 (its unbind step): if the context is out on a donated call,
/// it is taken back first, as a cancel of the thread's call (kernel
/// specification, "Kernel bindings that hold capabilities"); then the
/// thread loses it, and can't run until it gets a context again. The
/// context leaves its release tree, since no thread waits on it.
///
/// A thread being destroyed was unbound at its zombify hook already, and
/// its zombie may clear slot 5 only after preemptions, by which time
/// another thread may have bound the context. Then the context, and its
/// release entry, are that thread's, and stay as they are.
///
/// Returns the units it took: the take-back's, which ends its holder's
/// wait (K23), at least 1.
pub fn unbind_context_step(t: Tcb, cap: &Cap) -> u32 {
    let Cap::SchedContext { ptr, .. } = *cap else {
        return 1;
    };
    let c = Sc(ptr);
    let mut units = 1;
    if c.with(|h| h.home) == t.0 {
        // Its time is charged before it goes, and a donated context comes
        // back first.
        units = donation::unbind_cost(c);
        let _ = donation::unbind(c);
    }
    if c.with(|h| h.home == 0 && h.holder == 0) {
        run::release_remove(c);
    }
    run::place(t);
    units
}
