// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel's capability layer (ADR 0049; kernel specification,
//! "Capabilities"): the capability system of the `kcap` crate, run on real
//! memory.
//!
//! `kcap` holds the logic, tested on the host. This module gives it what it
//! needs from the kernel:
//!
//! - [`DirectSlots`]: slot memory, through the direct map;
//! - [`KernelHooks`]: what deleting a binding or the last capability to an
//!   object does to the hardware: unmapping a frame, releasing an ASID;
//! - [`NoIrq`]: the pending-interrupt check at preemption points.
//!
//! and the kernel-internal operations on top: lookup, copy, mint, mutate,
//! move, delete, revoke, retype, reset, identify, transfer, and Map and
//! Unmap of frames through capabilities. The boot capability space is in
//! [`boot`].
//!
//! C11 has no threads, so no system call reaches these yet, and lookups
//! start at the boot root CNode. C12 and C14 decode invocations, look the
//! capabilities up from the calling thread's root CNode, and call these.
//! C12 and C13a replace [`NoIrq`] with the interrupt controller's check and
//! restart a preempted call.
//!
//! Kernel objects carry no IDs (ADR 0050, rule 1): nothing here stores one.
//!
//! # Seams for later chunks
//!
//! Each later chunk plugs into this layer at a named place. The rules they
//! must keep are in the kernel specification, "Derivation and revocation"
//! and "Kernel bindings that hold capabilities".
//!
//! - **C12, threads:** a [`Pending`] that asks the GIC, and the restart of a
//!   system call stopped with [`Preempted`] or [`Error::Preempted`]. The
//!   thread is a new zombie kind in `kcap::cap::ZombieKind`, with a slot
//!   array whose slot 0 is its park slot and whose other slots bind its root
//!   CNode, address space, fault and timeout endpoints and bound
//!   eventcount; [`KernelHooks::finish`] gains its finish. Lookups start from
//!   the calling thread's root CNode instead of [`boot::root`]. An address
//!   space's finish deactivates it on every core, not only this one. Control
//!   capabilities are kinds that can't be derived. K50 is settled there.
//! - **C13a:** the interrupt-pending source behind [`Pending`].
//! - **C13b:** the interrupt handler kind, with one binding slot, and the
//!   interrupt control capability, which can't be derived. K40: the finish
//!   of a handler, and what a revoke reports when an ITS table refuses it.
//! - **C14:** the endpoint's real layout and size (K25), and its finish,
//!   which releases queued threads. `cancel_badged_sends`, called between
//!   the revoke and the delete that release a badge. Reply capabilities,
//!   eventcounts and wait sets (K32). The IPC path calls [`transfer`] with
//!   the addresses in the sender's IPC buffer and the receiver's slots.
//! - **C15:** memory objects replace frame mapping ([`map`], [`unmap`] and
//!   the frame binding in [`KernelHooks::unbind`]), and mapping records
//!   replace the address space's binding slots (K02). Listing (K42). Boot
//!   memory objects get root slots 2 to 15.
//! - **C16:** a [`TableSource`](crate::mm::space::TableSource) that takes
//!   tables from the job's pieces instead of [`UntypedTables`]; the job
//!   kinds; ending a job by revoking its pieces; taking an empty piece back
//!   with [`reset_with`].
//! - **C17:** the capability-table copy, as a library operation built on
//!   [`copy`] (K09); the ABI numbers for kinds and errors (K28, K30);
//!   publishing identify (K75).
//! - **C19:** the root server receives the root CNode's capability, from
//!   root slot [`boot::ROOT_SELF`], and the layout of root slots 2 to 15.

pub mod boot;
#[cfg(aspis_test_build)]
pub mod testkit;
#[cfg(aspis_test_build)]
mod tests;

use crate::mm::arch;
use crate::mm::phys::{DirectMem, Window};
use crate::mm::space::{AddressSpace, Frame, UntypedTables};
#[cfg(aspis_test_build)]
use core::sync::atomic::{AtomicU64, Ordering};
use kcap::SlotRef;
use kcap::cap::{Cap, Kind, Mapping, SlotArray, ZombieKind};
use kcap::delete::{self, Hooks};
use kcap::lookup::{self, LookupError};
use kcap::mdb;
use kcap::ops::{self, Error, Guard, MintData};
use kcap::preempt::{Budget, Pending, Preempted};
use kcap::rights::Rights;
use kcap::slot::{self, Mem};
use kcap::transfer::{self, Send, Transferred};
use kmem::desc::UserPerm;
use kmem::table::MapError;
use kmem::untyped::{ADDRESS_SPACE_BITS, ObjectType};
use kmem::{PAGE_SIZE, align_up};

/// Capability slots, read and written through the direct map.
///
/// Every object that has slots (a CNode, an address space's record) is made
/// from RAM, and the boot CNodes are pages of usable RAM, so every slot is
/// in the direct map, read-write. Each word moves with a single volatile
/// access. C12: the kernel lock serializes every access; until then one CPU
/// runs, with exceptions masked.
pub struct DirectSlots;

impl DirectSlots {
    fn words(slot: SlotRef) -> *mut u64 {
        assert!(
            slot.0.is_multiple_of(kcap::SLOT_SIZE),
            "capability slot {:#x} is misaligned",
            slot.0
        );
        DirectMem.va(slot.0) as *mut u64
    }
}

impl Mem for DirectSlots {
    fn read(&self, slot: SlotRef) -> [u64; 4] {
        let p = Self::words(slot);
        // SAFETY: a slot of a CNode or an address-space record, 32 bytes of
        // RAM aligned to 32 in the direct map, which only the kernel writes,
        // under the kernel lock.
        core::array::from_fn(|i| unsafe { core::ptr::read_volatile(p.add(i)) })
    }

    fn write(&mut self, slot: SlotRef, words: [u64; 4]) {
        let p = Self::words(slot);
        for (i, w) in words.into_iter().enumerate() {
            // SAFETY: as for `read`.
            unsafe { core::ptr::write_volatile(p.add(i), w) };
        }
    }

    fn clear(&mut self, pa: u64, len: u64) {
        // kcap clears only RAM pieces: device memory is never written, and
        // isn't in the direct map. The range ends where the watermark did,
        // perhaps partway through a page. Everything above the watermark is
        // free, so already zero, and the piece ends on a page, so the
        // clear rounds up to whole pages, which `DC ZVA` clears fastest.
        let len = align_up(len, PAGE_SIZE).unwrap_or(len);
        let va = DirectMem.va(pa);
        // SAFETY: RAM of an untyped piece below its watermark, or free above
        // it, in the direct map, read-write. kcap clears only a piece
        // nothing derives from, so nothing uses it (ADR 0048, rule 1).
        unsafe { arch::zero(va, len) };
        // The zeroes reach every table walker before the memory is retyped
        // into a translation table again.
        arch::dsb_ishst();
    }

    fn corrupt(&self, slot: SlotRef) -> ! {
        panic!(
            "capability slot {:#x} is corrupt: {:x?}",
            slot.0,
            self.read(slot)
        )
    }
}

/// How many objects deletion has finished, and how many bindings it has
/// removed, for the tests.
#[cfg(aspis_test_build)]
pub static FINISHED: AtomicU64 = AtomicU64::new(0);
#[cfg(aspis_test_build)]
pub static UNBOUND: AtomicU64 = AtomicU64::new(0);

/// What deleting a binding, or the last capability to an object, does to
/// the hardware (kernel specification, "Derivation and revocation" and
/// "Kernel bindings that hold capabilities").
pub struct KernelHooks;

impl Hooks for KernelHooks {
    fn finish(&mut self, cap: &Cap) {
        #[cfg(aspis_test_build)]
        FINISHED.fetch_add(1, Ordering::Relaxed);
        // An address space: every binding slot of its record is clear, so no
        // mapping is left. Deactivate it and release its ASID.
        //
        // Nothing else needs work. A CNode's slots are clear. A frame is
        // unmapped everywhere, since each of its mappings held a copy of it.
        // Untyped memory goes back at its parent's next reset. An endpoint
        // has nothing to release until C14 queues threads on it.
        if let Cap::Zombie {
            kind: ZombieKind::AddressSpace,
            ptr,
            ..
        } = *cap
        {
            AddressSpace::from_object(ptr).finish();
        }
    }

    fn unbind(&mut self, slot: SlotRef, cap: &Cap) {
        #[cfg(aspis_test_build)]
        UNBOUND.fetch_add(1, Ordering::Relaxed);
        // C11's only binding: a frame's mapping, in a binding slot of an
        // address space's record. The binding depends only on the
        // capability's own encoding, and binding slots never move, so the
        // space is the object that holds the slot: its address rounded down
        // to the space's 8 KiB.
        let Cap::Frame {
            size,
            mapping: Some(m),
            ..
        } = *cap
        else {
            panic!("unbind of {cap:x?}, which isn't a binding");
        };
        let space = AddressSpace::from_object(slot.0 & !((1 << ADDRESS_SPACE_BITS) - 1));
        // One leaf, since Map needs the address aligned to the frame's
        // size; the unmap invalidates it in the TLB under the space's ASID.
        match space.unmap(m.va, size.bytes()) {
            Ok(1) => {}
            r => panic!(
                "the binding at {:#x} for {:#x} unmapped {r:?}, not one leaf",
                slot.0, m.va
            ),
        }
    }
}

/// The pending-interrupt check at preemption points: never pending. C11
/// has no interrupt controller driver, and runs with interrupts masked, so
/// every long operation runs to the end. C13a replaces it with the GIC's
/// check, and C12 restarts the preempted system call.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoIrq;

impl Pending for NoIrq {
    fn pending(&mut self) -> bool {
        false
    }
}

/// A budget that checks for a pending interrupt every
/// [`kcap::UNITS_PER_CHECK`] units (kernel specification K22).
pub fn budget() -> Budget<NoIrq> {
    Budget::new(NoIrq)
}

/// The capability in a slot.
pub fn cap(slot: SlotRef) -> Cap {
    slot::cap(&DirectSlots, slot)
}

/// The slot that `addr` names at exactly `depth` bits from the boot root
/// CNode, for a CNode operation. C12: from the calling thread's root.
pub fn lookup_slot(addr: u64, depth: u32) -> Result<SlotRef, LookupError> {
    lookup::lookup_slot(&DirectSlots, boot::root(), addr, depth)
}

/// The capability that `addr` names from the boot root CNode, for an
/// invocation, with its slot. C12: from the calling thread's root.
pub fn lookup_cap(addr: u64) -> Result<(SlotRef, Cap), LookupError> {
    lookup::lookup_cap(&DirectSlots, boot::root(), addr)
}

/// Copies the capability in `src` into the empty slot `dst`, as its child.
pub fn copy(src: SlotRef, dst: SlotRef) -> Result<(), Error> {
    ops::copy(&mut DirectSlots, src, dst)
}

/// Copies with rights dropped to `rights`, and a badge or a guard set.
pub fn mint(src: SlotRef, dst: SlotRef, rights: Rights, data: MintData) -> Result<(), Error> {
    ops::mint(&mut DirectSlots, src, dst, rights, data)
}

/// Moves a CNode capability with a new guard.
pub fn mutate(src: SlotRef, dst: SlotRef, guard: Guard) -> Result<(), Error> {
    ops::mutate(&mut DirectSlots, src, dst, guard)
}

/// Moves a capability, keeping its place in the tree.
pub fn move_cap(src: SlotRef, dst: SlotRef) -> Result<(), Error> {
    ops::move_cap(&mut DirectSlots, src, dst)
}

/// The kind and rights of the capability in a slot (ADR 0047, rule 3): no
/// badge, no ID.
pub fn identify(slot: SlotRef) -> (Kind, Rights) {
    ops::identify(&cap(slot))
}

/// Makes `count` objects of type `ty` from the untyped capability in `ut`,
/// into slots `first` onward of the CNode whose capability is in `dest`.
/// Under `budget`; on [`Error::Preempted`], call again to go on.
pub fn retype_with<P: Pending>(
    ut: SlotRef,
    ty: ObjectType,
    dest: SlotRef,
    first: u64,
    count: u64,
    budget: &mut Budget<P>,
) -> Result<(), Error> {
    let dest = cap(dest);
    ops::retype(&mut DirectSlots, ut, ty, &dest, first, count, budget)
}

/// [`retype_with`], run to the end.
pub fn retype(
    ut: SlotRef,
    ty: ObjectType,
    dest: SlotRef,
    first: u64,
    count: u64,
) -> Result<(), Error> {
    retype_with(ut, ty, dest, first, count, &mut budget())
}

/// Resets the piece of the untyped capability in `ut`, which nothing may
/// derive from (`kcap::ops::reset`). Under `budget`.
pub fn reset_with<P: Pending>(ut: SlotRef, budget: &mut Budget<P>) -> Result<(), Error> {
    ops::reset(&mut DirectSlots, ut, budget)
}

/// Deletes the capability in `slot`, with everything only it reaches. On
/// [`Preempted`], call again with the same slot to go on.
pub fn delete_with<P: Pending>(slot: SlotRef, budget: &mut Budget<P>) -> Result<(), Preempted> {
    delete::delete(&mut DirectSlots, &mut KernelHooks, slot, budget)
}

/// Deletes every descendant of the capability in `slot`. On [`Preempted`],
/// call again with the same slot to go on.
pub fn revoke_with<P: Pending>(slot: SlotRef, budget: &mut Budget<P>) -> Result<(), Preempted> {
    delete::revoke(&mut DirectSlots, &mut KernelHooks, slot, budget)
}

/// [`delete_with`], run to the end: [`NoIrq`] never preempts.
pub fn delete(slot: SlotRef) {
    while delete_with(slot, &mut budget()).is_err() {}
}

/// [`revoke_with`], run to the end: [`NoIrq`] never preempts.
pub fn revoke(slot: SlotRef) {
    while revoke_with(slot, &mut budget()).is_err() {}
}

/// Transfers up to three capabilities from the sender's space into the
/// receive slots (ADR 0049, rule 6). C14 calls it from the IPC path; until
/// then only the tests do.
pub fn transfer(send: &Send<'_>, recv: &[SlotRef]) -> Transferred {
    transfer::transfer(&mut DirectSlots, send, recv)
}

/// Why Map or Unmap through capabilities failed. Nothing was changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapFailure {
    /// A capability was missing, of the wrong kind, without a right the
    /// call needs, or the mapping itself was refused (`kcap::ops::Error`).
    Cap(Error),
    /// The tables refused it: the range is occupied, or there was no memory
    /// for a table.
    Table(MapError),
    /// An unmap's range isn't whole pages, or leaves the lower half.
    Misaligned,
    /// An unmap's range would cut a mapping in two.
    CutsMapping,
}

/// Maps the frame capability in `frame` into the address space whose
/// capability is in `space`, at `va` with `perm`, taking any page tables it
/// needs from the untyped capability in `tables` (kernel specification,
/// "Mapping and unmapping"; C11, until C15's memory objects):
///
/// 1. `tables` must be RAM untyped memory whose piece contains the space,
///    so the tables come from the memory of whoever made it (ADR 0048,
///    rule 1);
/// 2. `kcap::ops::bind_mapping` checks the rights (read on the frame, write
///    on the frame for a writable mapping, write on the space), that `va`
///    is aligned to the frame's size, and W^X, and keeps a copy of the
///    frame capability in a binding slot of the space's record, as the
///    frame capability's child (ADR 0049, rule 4);
/// 3. the encoder writes the one leaf. If it can't, the binding is unlinked
///    again, with no hook, since nothing was mapped.
///
/// Deleting the binding, directly, by [`unmap`], by revoking the frame or
/// its untyped memory, or by destroying the space, unmaps it
/// ([`KernelHooks`]). Only [`unmap`] and a revoke reach capabilities derived
/// from the binding; a plain delete leaves them under the frame capability.
pub fn map(
    frame: SlotRef,
    space: SlotRef,
    va: u64,
    perm: UserPerm,
    tables: SlotRef,
) -> Result<(), MapFailure> {
    let mem = &mut DirectSlots;
    let base = match slot::cap(mem, space) {
        Cap::AddressSpace { base, .. } => base,
        Cap::Null => return Err(MapFailure::Cap(Error::Empty)),
        _ => return Err(MapFailure::Cap(Error::WrongKind)),
    };
    // Checked first, so that a wrong piece changes nothing, whether or not
    // this mapping needs a new table.
    match slot::cap(mem, tables) {
        Cap::Untyped {
            base: ub,
            bits,
            device: false,
            ..
        } if base >= ub && base - ub < 1 << bits => {}
        Cap::Untyped { .. } => return Err(MapFailure::Cap(Error::BadRegion)),
        Cap::Null => return Err(MapFailure::Cap(Error::Empty)),
        _ => return Err(MapFailure::Cap(Error::WrongKind)),
    }
    let mapping = Mapping {
        va,
        write: perm.write,
        exec: perm.exec,
    };
    let (binding, copy) = ops::bind_mapping(mem, frame, space, mapping).map_err(MapFailure::Cap)?;
    let Cap::Frame {
        base: pa,
        size,
        device,
        ..
    } = copy
    else {
        panic!("a frame's binding isn't a frame: {copy:x?}");
    };
    let r = AddressSpace::from_object(base).map(
        va,
        Frame::new(pa, size.bytes(), device),
        perm,
        &mut UntypedTables {
            slot: tables,
            space: base,
        },
    );
    if let Err(e) = r {
        // Nothing is mapped: `map` maps nothing over an occupied range, and
        // unmaps what it made before it ran out of tables.
        mdb::unlink(mem, binding);
        return Err(MapFailure::Table(e));
    }
    Ok(())
}

/// Unmaps every frame mapped through capabilities inside `[va, va + len)`
/// of the address space whose capability is in `space`, which needs the
/// write right, and returns how many there were. It revokes each binding,
/// so every capability derived from it goes with the mapping (kernel
/// specification K42), then deletes it; the binding's unbind step clears
/// the leaf and invalidates the TLB. A range that would cut a mapping in two
/// is refused before anything changes.
pub fn unmap(space: SlotRef, va: u64, len: u64) -> Result<u64, MapFailure> {
    let base = match cap(space) {
        Cap::AddressSpace { base, rights } if rights.contains(Rights::WRITE) => base,
        Cap::AddressSpace { .. } => return Err(MapFailure::Cap(Error::MissingRight)),
        Cap::Null => return Err(MapFailure::Cap(Error::Empty)),
        _ => return Err(MapFailure::Cap(Error::WrongKind)),
    };
    let end = va
        .checked_add(len)
        .filter(|&e| (va | len) & (PAGE_SIZE - 1) == 0 && e <= kmem::layout::USER_TOP)
        .ok_or(MapFailure::Misaligned)?;
    let array = SlotArray::of_address_space(base);
    // The binding slots whose mapping lies in the range; any that only
    // overlaps it refuses the whole call.
    let inside = |i: u64| -> Result<bool, MapFailure> {
        let Cap::Frame {
            size,
            mapping: Some(m),
            ..
        } = cap(array.slot(i))
        else {
            return Ok(false);
        };
        let (s, e) = (m.va, m.va + size.bytes());
        match (s < end && va < e, va <= s && e <= end) {
            (false, _) => Ok(false),
            (true, true) => Ok(true),
            (true, false) => Err(MapFailure::CutsMapping),
        }
    };
    let mut n = 0;
    for i in 1..array.count {
        if inside(i)? {
            n += 1;
        }
    }
    for i in 1..array.count {
        if inside(i)? {
            revoke(array.slot(i));
            delete(array.slot(i));
        }
    }
    Ok(n)
}
