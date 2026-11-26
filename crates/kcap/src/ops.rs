// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The capability operations C11 provides to the kernel: copy, mint,
//! mutate, move, retype through untyped capabilities, the kernel's frame
//! bindings and identify (ADR 0049; kernel specification, "Capability
//! spaces and lookup", "Derivation and revocation", "Kernel bindings that
//! hold capabilities").
//!
//! C11 has no threads, so no system call reaches these yet. C12 and C14
//! decode invocations and call them with slots found by [`crate::lookup`].
//! Each checks everything before it changes anything, except where it says
//! otherwise.

use kmem::untyped::{ObjectType, RetypeError, Untyped};

use crate::cap::{Cap, FrameSize, Kind, Mapping, SlotArray, guard_ok};
use crate::derive::{DeriveError, derive};
use crate::mdb::{self, InsertError};
use crate::preempt::{Budget, Pending, Preempted};
use crate::rights::Rights;
use crate::slot::{self, Mem};
use crate::{RETYPE_FAN_OUT, SlotRef};

/// Why an operation failed. Unless it is [`Error::Preempted`], nothing was
/// changed. Names are internal until K30.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The source slot is empty.
    Empty,
    /// The destination slot isn't empty.
    DestNotEmpty,
    /// The source and the destination are the same slot.
    SameSlot,
    /// The capability can't be derived (a zombie, or untyped memory with
    /// children), or moved (a zombie or a binding).
    NotDerivable,
    /// The capability would sit deeper than the tree allows.
    TooDeep,
    /// Data that the capability's kind doesn't take, or out of range: a
    /// badge on anything but an unbadged endpoint, a badge of 0, a guard
    /// that doesn't fit.
    InvalidData,
    /// The capability is of the wrong kind for the operation.
    WrongKind,
    /// Retype can't make that type through a capability (a page table).
    BadType,
    /// Destination slots outside the CNode, or more than the fan-out limit.
    BadRange,
    /// A right the operation needs is missing.
    MissingRight,
    /// A virtual address out of range, or not aligned to the frame's size,
    /// or a mapping both writable and executable.
    BadMapping,
    /// The address space has no free binding slot.
    NoBindingSlot,
    /// The untyped memory isn't where the operation needs it.
    BadRegion,
    /// Something still derives from the untyped capability, so its piece
    /// can't be reset.
    InUse,
    /// The untyped memory refused the retype.
    Retype(RetypeError),
    /// Stopped at a preemption point, with progress recorded. Call again.
    Preempted,
}

impl From<DeriveError> for Error {
    fn from(e: DeriveError) -> Error {
        match e {
            DeriveError::Empty => Error::Empty,
            DeriveError::NotDerivable => Error::NotDerivable,
        }
    }
}

impl From<InsertError> for Error {
    fn from(e: InsertError) -> Error {
        match e {
            InsertError::TooDeep => Error::TooDeep,
        }
    }
}

impl From<RetypeError> for Error {
    fn from(e: RetypeError) -> Error {
        Error::Retype(e)
    }
}

impl From<Preempted> for Error {
    fn from(_: Preempted) -> Error {
        Error::Preempted
    }
}

/// The data a mint may change, as seL4's `updateCapData`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MintData {
    /// Nothing but the rights.
    None,
    /// A badge for a copy of an unbadged endpoint. A badge is set once
    /// (ADR 0049, rule 3), and 0 means unbadged, so it must not be 0.
    Badge(u64),
    /// A CNode's guard.
    Guard(Guard),
}

/// A CNode capability's guard: `size` bits of `value`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guard {
    pub size: u8,
    pub value: u64,
}

fn check_dest<M: Mem>(mem: &M, src: SlotRef, dst: SlotRef) -> Result<(), Error> {
    if src == dst {
        return Err(Error::SameSlot);
    }
    if !slot::is_empty(mem, dst) {
        return Err(Error::DestNotEmpty);
    }
    Ok(())
}

fn check_depth<M: Mem>(mem: &M, parent: SlotRef) -> Result<(), Error> {
    if slot::read(mem, parent).depth == slot::MAX_DEPTH {
        return Err(Error::TooDeep);
    }
    Ok(())
}

/// Inserts a derived capability as a child of the one in `src`. A copy of
/// untyped memory marks its source full, as seL4's `setUntypedCapAsFull`, so
/// two capabilities to one piece never hand out the same memory.
pub(crate) fn insert_derived<M: Mem>(
    mem: &mut M,
    src: SlotRef,
    dst: SlotRef,
    new: Cap,
) -> Result<(), Error> {
    mdb::insert_child(mem, src, dst, new)?;
    let source = slot::cap(mem, src);
    if let Cap::Untyped {
        base, bits, device, ..
    } = source
        && source.same_object(&new)
    {
        slot::set_cap(
            mem,
            src,
            Cap::Untyped {
                base,
                bits,
                device,
                watermark: 1 << bits,
            },
        );
    }
    Ok(())
}

/// Copies the capability in `src` into the empty slot `dst`, with every
/// right it has, as a child of it.
pub fn copy<M: Mem>(mem: &mut M, src: SlotRef, dst: SlotRef) -> Result<(), Error> {
    mint(mem, src, dst, Rights::ALL, MintData::None)
}

/// Copies the capability in `src` into the empty slot `dst`, as a child of
/// it, with its rights masked by `rights` (ADR 0049, rule 2: a copy may drop
/// rights, never add them) and `data` applied.
pub fn mint<M: Mem>(
    mem: &mut M,
    src: SlotRef,
    dst: SlotRef,
    rights: Rights,
    data: MintData,
) -> Result<(), Error> {
    check_dest(mem, src, dst)?;
    let cap = slot::cap(mem, src);
    let new = derive(&cap, mdb::has_children(mem, src))?.masked(rights);
    let new = match (data, new) {
        (MintData::None, c) => c,
        (
            MintData::Badge(b),
            Cap::Endpoint {
                ptr,
                rights,
                badge: 0,
            },
        ) if b != 0 => Cap::Endpoint {
            ptr,
            rights,
            badge: b,
        },
        (MintData::Guard(g), c) => with_guard(c, g)?,
        _ => return Err(Error::InvalidData),
    };
    check_depth(mem, src)?;
    insert_derived(mem, src, dst, new)
}

fn with_guard(cap: Cap, g: Guard) -> Result<Cap, Error> {
    match cap {
        Cap::CNode { ptr, radix, .. } if guard_ok(radix, g.size, g.value) => Ok(Cap::CNode {
            ptr,
            radix,
            guard_size: g.size,
            guard: g.value,
        }),
        _ => Err(Error::InvalidData),
    }
}

/// Moves the CNode capability in `src` into the empty slot `dst`, with a new
/// guard, keeping its place in the tree. As in seL4, mutate changes only
/// data that preserving a capability allows: a CNode's guard. A badge is set
/// only by [`mint`].
pub fn mutate<M: Mem>(mem: &mut M, src: SlotRef, dst: SlotRef, guard: Guard) -> Result<(), Error> {
    check_dest(mem, src, dst)?;
    let new = match slot::cap(mem, src) {
        Cap::Null => return Err(Error::Empty),
        c @ Cap::CNode { .. } => with_guard(c, guard)?,
        _ => return Err(Error::InvalidData),
    };
    mdb::move_slot(mem, src, dst);
    slot::set_cap(mem, dst, new);
    Ok(())
}

/// Moves the capability in `src` into the empty slot `dst`, keeping its
/// place in the tree. A zombie and a binding never move (module docs of
/// [`crate::delete`]).
pub fn move_cap<M: Mem>(mem: &mut M, src: SlotRef, dst: SlotRef) -> Result<(), Error> {
    check_dest(mem, src, dst)?;
    let cap = slot::cap(mem, src);
    if cap.is_null() {
        return Err(Error::Empty);
    }
    if cap.is_zombie() || cap.is_binding() {
        return Err(Error::NotDerivable);
    }
    mdb::move_slot(mem, src, dst);
    Ok(())
}

/// The kind and rights of a capability, for identify (ADR 0047, rule 3). An
/// empty slot and a zombie are [`Kind::Null`]; untyped and CNode
/// capabilities carry no rights. It reports no badge and no ID (ADR 0050,
/// rule 1).
pub const fn identify(cap: &Cap) -> (Kind, Rights) {
    (cap.kind(), cap.rights())
}

/// The capability retype gives an object of type `ty` at `pa`: every right,
/// no badge, no guard, an empty watermark.
fn new_cap(ty: ObjectType, pa: u64, device: bool) -> Option<Cap> {
    let frame = |size| Cap::Frame {
        base: pa,
        size,
        device,
        rights: Rights::ALL,
        mapping: None,
    };
    Some(match ty {
        ObjectType::Untyped(bits) => Cap::Untyped {
            base: pa,
            bits,
            device,
            watermark: 0,
        },
        ObjectType::Frame4K => frame(FrameSize::Small),
        ObjectType::Frame2M => frame(FrameSize::Large),
        ObjectType::Frame1G => frame(FrameSize::Huge),
        ObjectType::AddressSpace => Cap::AddressSpace {
            base: pa,
            rights: Rights::ALL,
        },
        ObjectType::CNode(radix) => Cap::CNode {
            ptr: pa,
            radix,
            guard_size: 0,
            guard: 0,
        },
        ObjectType::Endpoint => Cap::Endpoint {
            ptr: pa,
            rights: Rights::ALL,
            badge: 0,
        },
        ObjectType::PageTable => return None,
    })
}

fn untyped_of<M: Mem>(mem: &M, s: SlotRef) -> Result<Untyped, Error> {
    match slot::cap(mem, s) {
        Cap::Untyped {
            base,
            bits,
            device,
            watermark,
        } => match Untyped::from_parts(base, bits, device, watermark) {
            Some(u) => Ok(u),
            None => mem.corrupt(s),
        },
        Cap::Null => Err(Error::Empty),
        _ => Err(Error::WrongKind),
    }
}

fn store_watermark<M: Mem>(mem: &mut M, s: SlotRef, u: &Untyped) {
    slot::set_cap(
        mem,
        s,
        Cap::Untyped {
            base: u.base(),
            bits: u.bits(),
            device: u.is_device(),
            watermark: u.watermark(),
        },
    );
}

/// The chunk a reset clears between preemption checks: 64 KiB, which counts
/// as 16 units.
pub const RESET_CHUNK: u64 = 64 * 1024;

/// Makes `count` objects of type `ty` from the untyped capability in `ut`,
/// and puts their capabilities in slots `first` to `first + count - 1` of
/// the CNode `dest`, each a child of `ut`: seL4's `Untyped_Retype`.
///
/// If nothing derives from `ut`, the piece is reset first and objects are
/// made from its start, as seL4 does. The reset clears from the top down in
/// [`RESET_CHUNK`]s and writes the lowered watermark back into the
/// capability after each, so a preempted retype resumes the reset where it
/// stopped ([`Error::Preempted`]). Otherwise objects are made from the
/// watermark. Everything is checked before the reset, so no other error
/// leaves a change behind.
pub fn retype<M: Mem, P: Pending>(
    mem: &mut M,
    ut: SlotRef,
    ty: ObjectType,
    dest: &Cap,
    first: u64,
    count: u64,
    budget: &mut Budget<P>,
) -> Result<(), Error> {
    let mut u = untyped_of(mem, ut)?;
    if matches!(ty, ObjectType::PageTable) {
        return Err(Error::BadType);
    }
    let Cap::CNode { ptr, radix, .. } = *dest else {
        return Err(Error::WrongKind);
    };
    if count == 0 {
        return Err(Error::Retype(RetypeError::ZeroCount));
    }
    let end = first.checked_add(count).ok_or(Error::BadRange)?;
    if count > RETYPE_FAN_OUT || end > 1 << radix {
        return Err(Error::BadRange);
    }
    let slots = (first..end).map(|i| SlotRef(ptr).offset(i));
    for s in slots.clone() {
        if s == ut || !slot::is_empty(mem, s) {
            return Err(Error::DestNotEmpty);
        }
    }
    check_depth(mem, ut)?;
    let reset = !mdb::has_children(mem, ut);
    // Check that the objects fit, as they will after any reset.
    let mut trial = if reset {
        Untyped::new(u.base(), u.bits(), u.is_device()).ok_or(Error::BadRegion)?
    } else {
        u
    };
    trial.retype(ty, count)?;
    if reset {
        u = reset_piece(mem, ut, u, budget)?;
    }
    let base = u.retype(ty, count)?;
    store_watermark(mem, ut, &u);
    let size = 1u64 << ty.size_bits();
    for (i, s) in slots.enumerate() {
        let Some(cap) = new_cap(ty, base + i as u64 * size, u.is_device()) else {
            return Err(Error::BadType);
        };
        insert_derived(mem, ut, s, cap)?;
    }
    Ok(())
}

/// Clears what was retyped from the piece `u`, whose capability is in `ut`,
/// from the top down in [`RESET_CHUNK`]s, writing the lowered watermark back
/// into the capability after each, as seL4's `resetUntypedCap` does.
fn reset_piece<M: Mem, P: Pending>(
    mem: &mut M,
    ut: SlotRef,
    mut u: Untyped,
    budget: &mut Budget<P>,
) -> Result<Untyped, Error> {
    u.begin_reset();
    store_watermark(mem, ut, &u);
    while let Some((pa, len)) = u.reset_step(RESET_CHUNK) {
        mem.clear(pa, len);
        store_watermark(mem, ut, &u);
        budget.tick(len.div_ceil(kmem::PAGE_SIZE) as u32)?;
    }
    Ok(u)
}

/// Resets the piece of the untyped capability in `ut` without making
/// anything: its used part is cleared and its watermark drops to 0, as the
/// reset at the start of [`retype`] does. It is refused with
/// [`Error::InUse`] while anything derives from `ut`.
///
/// seL4 has no such call: there a reset happens only inside a retype. This
/// one is kernel-internal, and no system call reaches it. The kernel's
/// tests use it to leave a piece as the boot left it, free and zero; C16
/// may use it when the memory server takes an empty piece back. On
/// [`Error::Preempted`], call again to go on.
pub fn reset<M: Mem, P: Pending>(
    mem: &mut M,
    ut: SlotRef,
    budget: &mut Budget<P>,
) -> Result<(), Error> {
    let u = untyped_of(mem, ut)?;
    if mdb::has_children(mem, ut) {
        return Err(Error::InUse);
    }
    reset_piece(mem, ut, u, budget).map(|_| ())
}

/// Takes a zeroed 4 KiB page for a translation table from the watermark of
/// the untyped capability in `ut`, with no capability of its own: C11's
/// `TableSource` (kernel specification, "Mapping and unmapping").
///
/// The piece must contain `inside`, the address space the table is for,
/// so the address space descends from it: the piece can't then be reset
/// while the address space lives, and once the address space is destroyed
/// nothing reaches the table. So tables come from the memory of whoever made
/// the address space (ADR 0048, rule 1). C16 takes them from the job's
/// pieces instead.
pub fn take_page<M: Mem>(mem: &mut M, ut: SlotRef, inside: u64) -> Result<u64, Error> {
    let mut u = untyped_of(mem, ut)?;
    if u.is_device() || inside < u.base() || inside - u.base() >= u.size() {
        return Err(Error::BadRegion);
    }
    if !mdb::has_children(mem, ut) {
        return Err(Error::BadRegion);
    }
    let pa = u.retype(ObjectType::PageTable, 1)?;
    store_watermark(mem, ut, &u);
    Ok(pa)
}

/// The first free binding slot of the address space at `base`: record slots
/// 1 to 126. Slot 0 is the park slot.
pub fn free_binding_slot<M: Mem>(mem: &M, base: u64) -> Option<SlotRef> {
    let array = SlotArray::of_address_space(base);
    (1..array.count)
        .map(|i| array.slot(i))
        .find(|&s| slot::is_empty(mem, s))
}

/// Records a frame mapping as a binding (ADR 0049, rule 4): a copy of the
/// frame capability in `frame`, with the mapping, in a free binding slot of
/// the address space in `space`, as a child of the frame capability. Returns
/// the binding's slot and capability. The kernel then writes the page-table
/// entry; if that fails, it unlinks the binding with [`mdb::unlink`], which
/// runs no hook.
///
/// The frame needs the read right for any mapping and the write right for a
/// writable one; the address space needs the write right. The virtual
/// address must be aligned to the frame's size, as seL4 requires, so every
/// mapping is one leaf, and a mapping is never both writable and executable
/// (ADR 0048, rule 6).
pub fn bind_mapping<M: Mem>(
    mem: &mut M,
    frame: SlotRef,
    space: SlotRef,
    mapping: Mapping,
) -> Result<(SlotRef, Cap), Error> {
    let Cap::AddressSpace { base, rights } = slot::cap(mem, space) else {
        return Err(Error::WrongKind);
    };
    if !rights.contains(Rights::WRITE) {
        return Err(Error::MissingRight);
    }
    let fc = slot::cap(mem, frame);
    let Cap::Frame { rights: fr, .. } = fc else {
        return Err(Error::WrongKind);
    };
    if !fr.contains(Rights::READ) || (mapping.write && !fr.contains(Rights::WRITE)) {
        return Err(Error::MissingRight);
    }
    let derived = derive(&fc, false)?;
    let Cap::Frame {
        base: fb,
        size,
        device,
        rights: dr,
        ..
    } = derived
    else {
        return Err(Error::WrongKind);
    };
    if (mapping.write && mapping.exec) || (device && mapping.exec) {
        return Err(Error::BadMapping);
    }
    let binding = Cap::Frame {
        base: fb,
        size,
        device,
        rights: dr,
        mapping: Some(mapping),
    };
    if !binding.is_valid() {
        return Err(Error::BadMapping);
    }
    let dst = free_binding_slot(mem, base).ok_or(Error::NoBindingSlot)?;
    check_depth(mem, frame)?;
    insert_derived(mem, frame, dst, binding)?;
    Ok((dst, binding))
}
