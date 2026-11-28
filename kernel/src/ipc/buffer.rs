// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! IPC buffers: registration, and its undoing (ADR 0054, rule 3; ADR 0048,
//! rule 5; kernel specification, "IPC buffers"; K29).
//!
//! A thread's IPC buffer is one page of its address space, which the kernel
//! reaches only through the direct map, at the physical address it found
//! when the buffer was registered. Registration presents the capability
//! that backs the page, with the write right, and the thread keeps a copy
//! of it in slot 7, a binding with the IPC-buffer role, as seL4's
//! `tcbBuffer` holds a frame capability. That copy pins the page: the
//! frame's memory can't be retyped while it exists, since it descends from
//! the memory's capability, and destroying the memory, or ending its job,
//! revokes the copy first, which unregisters the buffer
//! ([`unbind`]). So the kernel never writes to a freed frame, and needs no
//! list of the threads that use an object's pages.
//!
//! **Until C15** the capability is a frame's ([`Backing::Frame`]): the walk
//! must find the page mapped writable at EL0 at the address, inside that
//! frame, in RAM. From C15 it is a memory object's
//! ([`Backing::MemoryObject`]), and registration also pins the page in the
//! object's page tracking, so eviction, decommit and reclaim skip it.
//! **Until C16** every buffer is the root job's, so the job check passes
//! ([`job_ok`]).

use crate::cap::{self, DirectSlots};
use crate::mm::space::AddressSpace;
use crate::sched::object::Tcb;
use kcap::SlotRef;
use kcap::cap::{Binding, Cap};
use kcap::ops;
use kcap::preempt::{Budget, Pending, Preempted};
use kcap::rights::Rights;
use kipc::msg::Status;
use kmem::PAGE_SIZE;
use kmem::user::{Access, UserError};

/// The kind of capability that backs a buffer's page (module docs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backing {
    /// A frame, until C15.
    Frame { base: u64, bytes: u64 },
    // C15: MemoryObject, whose registration pins the page in the object's
    // page tracking.
}

/// The C16 stand-in: whether the buffer's memory and the thread are the
/// same job's. Until C16 everything is the root job's.
const fn job_ok() -> bool {
    true
}

/// The page that registering `va` in `t`'s address space, backed by
/// `backing`, would pin: every check, before anything changes.
fn check(t: Tcb, backing: Backing, va: u64) -> Result<u64, Status> {
    if !va.is_multiple_of(PAGE_SIZE) {
        return Err(Status::InvalidArgument);
    }
    let Cap::AddressSpace { base, .. } = t.slot_cap(2) else {
        return Err(Status::NotMapped);
    };
    let pa = match AddressSpace::from_object(base).translate(va, Access::Write) {
        Ok(pa) => pa,
        Err(UserError::NotResident) => return Err(Status::NotMapped),
        Err(UserError::NoRight) => return Err(Status::MissingRight),
        Err(UserError::NotRam) => return Err(Status::NotRam),
        Err(UserError::NotUserAddress) => return Err(Status::InvalidArgument),
    };
    let Backing::Frame { base, bytes } = backing;
    if pa < base || pa - base >= bytes {
        return Err(Status::InvalidArgument);
    }
    if !crate::mm::direct_map_covers(pa, PAGE_SIZE, true) {
        return Err(Status::NotRam);
    }
    if !job_ok() {
        return Err(Status::InvalidArgument);
    }
    Ok(pa)
}

/// The buffer's backing, from the capability presented: a frame of RAM
/// with the write right.
fn backing(c: &Cap) -> Result<Backing, Status> {
    match *c {
        Cap::Frame { device: true, .. } => Err(Status::NotRam),
        Cap::Frame {
            base, size, rights, ..
        } if rights.contains(Rights::WRITE) => Ok(Backing::Frame {
            base,
            bytes: size.bytes(),
        }),
        Cap::Frame { .. } => Err(Status::MissingRight),
        Cap::Null => Err(Status::InvalidCapability),
        _ => Err(Status::WrongKind),
    }
}

/// Refuses a source whose copy couldn't be made: the copy in slot 7 is a
/// child of `f`, one level deeper, and a slot at the deepest level has no
/// room for one. Checked before the old copy is deleted, so a refusal
/// changes nothing, as `super::waitset::add` does.
fn deep_enough(f: SlotRef) -> Result<(), Status> {
    if kcap::slot::read(&DirectSlots, f).depth == kcap::slot::MAX_DEPTH {
        return Err(Status::InvalidArgument);
    }
    Ok(())
}

/// Registers the page at `va` of thread `t`'s address space as its IPC
/// buffer, backed by the capability in `frame`; `None` unregisters it (K29).
/// The thread capability's write right was checked. Every check comes
/// first; then the old buffer's copy in slot 7 is deleted, under `budget`.
/// In C14 that deletion is one unit, which empties the slot: a frame has no
/// slots and no queue, so [`kcap::delete::delete`] never reports a
/// preemption for it, and the call is never made again. It still takes the
/// budget, and the trap still restarts it at a preemption, as every
/// operation that deletes a capability does (kernel specification, "The
/// kernel lock and long operations"). Then the new copy is bound and the
/// page recorded.
pub fn set<P: Pending>(
    t: Tcb,
    frame: Option<SlotRef>,
    va: u64,
    budget: &mut Budget<P>,
) -> Result<Result<(), Status>, Preempted> {
    let new = match frame {
        None => None,
        Some(f) => match backing(&cap::cap(f))
            .and_then(|b| check(t, b, va))
            .and_then(|pa| deep_enough(f).map(|()| pa))
        {
            Ok(pa) => Some((f, pa)),
            Err(e) => return Ok(Err(e)),
        },
    };
    crate::smp::remote::stall(t);
    let slot = t.slot(Binding::IpcBuffer.thread_slot());
    if !cap::cap(slot).is_null() {
        cap::delete_with(slot, budget)?;
    }
    let Some((f, pa)) = new else {
        return Ok(Ok(()));
    };
    if let Err(e) = ops::bind_copy(&mut DirectSlots, f, slot, Binding::IpcBuffer) {
        return Ok(Err(match e {
            ops::Error::Empty => Status::InvalidCapability,
            ops::Error::WrongKind => Status::WrongKind,
            _ => Status::InvalidArgument,
        }));
    }
    super::object::with_ipc(t, |s| {
        s.buf_va = va;
        s.buf_pa = pa;
    });
    Ok(Ok(()))
}

/// Thread `t`'s copy in slot 7 is being deleted (its unbind step): the
/// buffer is unregistered, and messages to and from the thread are cut to
/// their register words, with no capabilities, until another is registered.
pub fn unbind(t: Tcb) {
    super::object::with_ipc(t, |s| {
        s.buf_va = 0;
        s.buf_pa = 0;
    });
}
