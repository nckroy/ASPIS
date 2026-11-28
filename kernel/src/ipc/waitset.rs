// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Wait sets on the kernel's objects (ADR 0053, rule 4; kernel
//! specification, "Wait sets"; K08, K32, K33): `kipc::eventcount`'s
//! protocol, run over [`KStore`].
//!
//! A wait set of `2^k` bytes holds 1, 3, 7, 15, 31 or 60 entries, chosen
//! when it is made (K33; layout in [`super::object`]). Entry i is a copy of
//! an eventcount capability in the set's slot i + 1, a binding with the
//! wait-set-entry role, and a node that waits for a target. The write right
//! adds and removes entries; the read right waits (K32).
//!
//! - **Add** refuses an entry whose slot holds anything, a copy or the
//!   zombie of one being deleted, so it never deletes.
//! - **Remove** deletes the entry's copy with the caller's budget, and is
//!   made again at a preemption point (K23): deleting the last capability
//!   to an eventcount drains its waiters, one a unit. The copy's unbind
//!   step ([`super::unbind_entry`]) takes the entry's node out of its tree;
//!   during a wait, the wait goes on on the other entries, and removing the
//!   last linked one ends it with an empty mask (K08). A revocation that
//!   deletes the copy does the same.
//! - **Wait** returns at once with the mask of entries whose targets are
//!   reached, or an empty mask for a set with no entries; otherwise it links
//!   every present entry's node, at most 60 links, and blocks until one is
//!   reached, its deadline passes, or it is canceled. One wait at a time.
//!
//! Waking a set's waiter unlinks every node of the set and returns the
//! mask, as many units as it unlinks (K23, K24). Destroying the set ends
//! its wait "object destroyed" at its zombify ([`super::zombify`]; K30).

use super::endpoint::{Ret, conclude};
use super::eventcount::ec_cap;
use super::object;
use super::store::{PRESENTED, entry_slot};
use crate::cap::{self, DirectSlots};
use crate::sched::donation::KStore;
use crate::sched::object::{Tcb, Wait};
use core::sync::atomic::Ordering;
use kcap::SlotRef;
use kcap::cap::Cap;
use kcap::preempt::{Budget, Pending, Preempted};
use kcap::rights::Rights;
use kipc::eventcount as ec;
use kipc::msg::Status;
use kipc::store::IpcStore;
use kipc::{Outcome, Ws};
use ksched::donation::Tcb as DTcb;

/// The wait set a capability names, by `kipc`'s name for it, with its
/// rights. Its header is written the first time a capability reaches it
/// ([`object::init_set`]).
pub fn ws_cap(c: &Cap) -> Result<(Ws, Rights), Status> {
    match *c {
        Cap::WaitSet { ptr, bits, rights } => {
            object::init_set(ptr, bits);
            Ok((Ws(object::ws_name(ptr, bits)), rights))
        }
        Cap::Null => Err(Status::InvalidCapability),
        _ => Err(Status::WrongKind),
    }
}

/// How many entries the wait set `w` holds.
pub fn entries(w: Ws) -> usize {
    usize::from(IpcStore::ws(&KStore, w).entries)
}

/// An entry index from a register, which may hold any value: past every
/// set's entries if it doesn't fit.
fn index(i: u64) -> usize {
    usize::try_from(i).unwrap_or(usize::MAX)
}

/// `WsAdd`: entry `i` of `w` waits for the eventcount whose capability is
/// in `src` to reach `target` (module docs). The set needs the write right,
/// the eventcount the read right (ADR 0053, rule 4; K32).
pub fn add(w: Ws, rights: Rights, i: u64, src: SlotRef, target: u64) -> Result<(), Status> {
    let (e, erights) = ec_cap(&cap::cap(src))?;
    if !rights.contains(Rights::WRITE) || !erights.contains(Rights::READ) {
        return Err(Status::MissingRight);
    }
    let i = index(i);
    if i >= entries(w) {
        return Err(Status::InvalidArgument);
    }
    // A slot with a zombie in it, its copy being deleted, isn't free.
    if !cap::cap(entry_slot(w, i)).is_null() {
        return Err(Status::Busy);
    }
    // The copy is a child of `src`, one level deeper, as every copy is.
    if kcap::slot::read(&DirectSlots, src).depth == kcap::slot::MAX_DEPTH {
        return Err(Status::InvalidArgument);
    }
    PRESENTED.store(src.0, Ordering::Relaxed);
    let r = ec::ws_add(&mut KStore::begin(), w, rights, i, e, erights, target);
    PRESENTED.store(0, Ordering::Relaxed);
    r
}

/// `WsRemove`: removes entry `i` of `w`, which needs the write right, by
/// deleting its copy with `budget` (module docs). A preempted call leaves
/// the copy's zombie in the entry, never an empty entry
/// ([`kcap::delete::delete`]), so a call made again resumes that deletion,
/// and no `WsAdd` can fill the entry in between. An empty entry is nothing
/// to do.
pub fn remove<P: Pending>(
    w: Ws,
    rights: Rights,
    i: u64,
    budget: &mut Budget<P>,
) -> Result<Result<(), Status>, Preempted> {
    let i = index(i);
    if let Err(s) = ec::ws_remove_check(&KStore, w, rights, i) {
        return Ok(Err(s));
    }
    let slot = entry_slot(w, i);
    if !cap::cap(slot).is_null() {
        cap::delete_with(slot, budget)?;
    }
    Ok(Ok(()))
}

/// `WsWait`: `t` waits on `w`, which needs the read right, until an entry
/// reaches its target, or `deadline`, 0 for none (module docs). The mask
/// goes into x1.
pub fn wait(t: Tcb, w: Ws, rights: Rights, deadline: u64) -> Ret {
    // The running thread's time is charged first; then the kernel names
    // the wait, before the protocol starts it.
    let mut store = KStore::begin();
    t.update(|s| s.wait = Wait::Set as u8);
    let r = ec::ws_wait(&mut store, DTcb(t.0), w, rights);
    if !matches!(r, Ok(Outcome::Blocked)) {
        t.update(|s| s.wait = Wait::None as u8);
    }
    conclude(t, r, deadline)
}

/// The thread waiting on `w`, if any (test builds).
#[cfg(aspis_test_build)]
pub fn waiter(w: Ws) -> Option<Tcb> {
    IpcStore::ws(&KStore, w).waiter.map(|t| Tcb(t.0))
}
