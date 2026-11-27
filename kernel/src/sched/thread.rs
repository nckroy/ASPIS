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

/// Replaces the capability in the thread's slot `i` with a copy of the one
/// in `src`, a child of it, or empties the slot. Deleting the old one runs
/// to the end; C17's system call restarts it instead (kernel specification,
/// "The kernel lock and long operations").
fn replace(t: Tcb, i: u64, src: Option<SlotRef>, role: Option<Binding>) -> Result<(), Error> {
    let dst = t.slot(i);
    if !cap::cap(dst).is_null() {
        cap::delete(dst);
    }
    if let Some(src) = src {
        match role {
            Some(r) => ops::bind_copy(&mut DirectSlots, src, dst, r).map(|_| ()),
            None => ops::copy(&mut DirectSlots, src, dst),
        }
        .map_err(Error::Cap)?;
    }
    Ok(())
}

/// Sets the thread's root CNode and address space to copies of the
/// capabilities in `cnode` and `space` (seL4's `TCB_SetSpace`, without the
/// fault endpoint). The thread can't run until both are set.
pub fn configure_space(thread: SlotRef, cnode: SlotRef, space: SlotRef) -> Result<(), Error> {
    let t = stalled(thread, Rights::WRITE)?;
    match (cap::cap(cnode), cap::cap(space)) {
        (Cap::CNode { .. }, Cap::AddressSpace { .. }) => {}
        (Cap::Null, _) | (_, Cap::Null) => return Err(Error::Cap(ops::Error::Empty)),
        _ => return Err(Error::WrongKind),
    }
    replace(t, 1, Some(cnode), None)?;
    replace(t, 2, Some(space), None)?;
    run::place(t);
    Ok(())
}

/// Sets the thread's fault or timeout endpoint (`role`) to a copy of the
/// endpoint capability in `ep`, or unsets it with `None` (kernel
/// specification, "Fault delivery"). The endpoint needs the write right and
/// grant or grant-reply. Unsetting withdraws a fault queued there (K50).
pub fn set_endpoint(thread: SlotRef, role: Binding, ep: Option<SlotRef>) -> Result<(), Error> {
    let t = stalled(thread, Rights::WRITE)?;
    if role == Binding::Context {
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
    }
    replace(t, role.thread_slot(), ep, Some(role))
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
    // Out of the queue at its old priority, then back in at its new one.
    run::dequeue(t);
    t.update(|s| s.priority = p);
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
/// bound to another (kernel specification, "Passive servers and taking a context back"): a stranded server is given a context only after
/// its walk step has passed.
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
/// withdrawn: the thread raises the fault again when it re-executes the
/// instruction.
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
/// queue and its deadline tree.
pub fn zombify(t: Tcb) {
    crate::smp::remote::stall(t);
    t.update(|s| s.flags = (s.flags | flag::DEAD) & !flag::RESUMED);
    if super::percore::this_core().current == t.0 {
        run::stop_current(Stop::Blocked);
    }
    donation::destroy_thread(t);
    run::dequeue(t);
    run::deadline_remove(t);
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
pub fn unbind_context_step(t: Tcb, cap: &Cap) {
    let Cap::SchedContext { ptr, .. } = *cap else {
        return;
    };
    let c = Sc(ptr);
    if c.with(|h| h.home) == t.0 {
        // Its time is charged before it goes, and a donated context comes
        // back first.
        let _ = donation::unbind(c);
    }
    if c.with(|h| h.home == 0 && h.holder == 0) {
        run::release_remove(c);
    }
    run::place(t);
}
