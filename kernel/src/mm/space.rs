// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! User address spaces: lower-half tables made from untyped memory, an ASID
//! for each, and the TLB maintenance that keeps them right (ADR 0048,
//! rules 1, 3, 4 and 6; ADR 0052, rule 4; kernel specification,
//! "Address-space layout" and "Cross-core signals and TLB maintenance").
//!
//! An address space is an 8 KiB object retyped from untyped memory: its
//! level-0 table, then a 4 KiB kernel record that holds its ASID word. Its
//! other tables are retyped, one page each, from the memory a
//! [`TableSource`] supplies, so the kernel makes none from memory of its
//! own (ADR 0048, rule 1).
//!
//! Every leaf comes from [`kmem::desc::user_leaf`], so every user mapping is
//! PXN and non-global, nothing is writable and executable, and the memory
//! type follows the frame: RAM is normal write-back, device memory is
//! Device-nGnRE and never executable (rule 6).
//!
//! C11: capabilities name address spaces and frames ([`crate::cap`]).
//! [`AddressSpace`] and [`Frame`] are the kernel's internal views of them,
//! built from a decoded capability; a mapping made through capabilities
//! keeps a copy of the frame capability in the space's record, and deleting
//! that copy unmaps it. C12: the kernel lock guards the ASID allocator, and
//! the current core's index replaces [`CORE`]. C15: memory objects make
//! mapping records, and map their pages through these functions. C16: a
//! job's pieces implement [`TableSource`].

use super::phys::{DirectMem, Window};
use super::{BootCell, arch};
use crate::cap::DirectSlots;
#[cfg(aspis_test_build)]
use core::sync::atomic::AtomicU64;
use core::sync::atomic::{AtomicBool, Ordering};
use kmem::PAGE_SIZE;
use kmem::asid::{AsidAllocator, asid_of};
use kmem::desc::{self, Half, LeafError, UserPerm};
use kmem::table::{FrameSource, MapError, Tables, UnmapError};
use kmem::user::{Access, UserError};

/// The core the kernel runs on. C12: each core's own index.
const CORE: usize = 0;

/// The node's ASID allocator (kernel specification, "Address-space
/// layout", "ASIDs"). [`init`] sets its width at boot.
static ASIDS: BootCell<AsidAllocator> = BootCell::new(AsidAllocator::new(16));

/// Set once [`init`] has run.
static INIT_DONE: AtomicBool = AtomicBool::new(false);

/// Sets the ASID width, from `ID_AA64MMFR0_EL1.ASIDBits`, by `mm::init`,
/// before any address space exists. It runs once: a second call would
/// restart the generations, so an old ASID word would look current again
/// while TLB entries under its number remain. So it panics instead.
pub fn init(asid_bits: u8) {
    assert!(
        !INIT_DONE.swap(true, Ordering::Relaxed),
        "the ASID allocator is set up twice"
    );
    with_asids(|a| a.init(asid_bits));
}

/// Runs `f` on the allocator. The `&mut` can't escape `f`, and nothing
/// that `f` is given can reach the allocator again. C12: under the kernel
/// lock.
fn with_asids<R>(f: impl FnOnce(&mut AsidAllocator) -> R) -> R {
    // SAFETY: one CPU, exceptions masked, and every use of the allocator
    // goes through this function, whose callers pass closures that don't
    // call it again.
    f(unsafe { ASIDS.get_mut() })
}

/// A frame: RAM or device memory, of 4 KiB, 2 MiB or 1 GiB, that a user
/// address space can map: the kernel's view of a frame capability.
///
/// C15: memory objects own their frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pa: u64,
    size: u64,
    /// Device memory: mapped Device-nGnRE, never executable, and "not RAM"
    /// to the kernel's walk.
    device: bool,
}

impl Frame {
    /// The frame of `size` bytes at `pa`, as a frame capability names it.
    pub const fn new(pa: u64, size: u64, device: bool) -> Frame {
        Frame { pa, size, device }
    }
}

/// Where an address space's page tables come from: the memory of the job
/// responsible for it (ADR 0048, rule 1).
///
/// C11 takes them from an untyped capability that the caller of Map
/// presents ([`UntypedTables`]). C16 takes them from the address space's
/// job, through the job's index of pieces.
pub trait TableSource {
    /// The physical address of a new, zeroed, 4 KiB translation table, or
    /// `None` if there is no memory.
    fn page_table(&mut self) -> Option<u64>;
}

/// Page tables from the watermark of the untyped capability in a slot,
/// whose piece must contain the address space they are for (kernel
/// specification, "Mapping and unmapping"; `kcap::ops::take_page`). The
/// address space then descends from that capability, so the piece can't be
/// reset while the space lives, and once the space is destroyed nothing
/// reaches its tables.
pub struct UntypedTables {
    /// The untyped capability's slot.
    pub slot: kcap::SlotRef,
    /// The address space the tables are for, by its object's address.
    pub space: u64,
}

impl TableSource for UntypedTables {
    fn page_table(&mut self) -> Option<u64> {
        // Free untyped memory is zero, and its zeroes were made visible to
        // the walkers when it was cleared, at boot or at its last reset.
        kcap::ops::take_page(&mut DirectSlots, self.slot, self.space).ok()
    }
}

/// A [`TableSource`] as `kmem`'s table code wants it.
struct Source<'a, S: TableSource>(&'a mut S);

impl<S: TableSource> FrameSource for Source<'_, S> {
    fn table(&mut self) -> Option<u64> {
        self.0.page_table()
    }
}

/// A user address space, named by the physical address of its object: the
/// level-0 table, then the kernel record. It is the kernel's view of an
/// address-space capability ([`crate::cap`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressSpace(u64);

/// The ASID word's offset in the object: the first word of the kernel
/// record, after the level-0 table.
const ASID_WORD: u64 = PAGE_SIZE;

impl AddressSpace {
    /// The address space whose object is at `pa`, as its capability names
    /// it. Retype made it from zeroed memory: its tables are empty, and it
    /// has no ASID until it is first activated.
    pub const fn from_object(pa: u64) -> AddressSpace {
        AddressSpace(pa)
    }

    /// The physical address of its level-0 table.
    pub fn root(&self) -> u64 {
        self.0
    }

    /// Its tables, read and written through the direct map.
    pub fn tables(&self) -> Tables<'static, DirectMem> {
        Tables::new(&DirectMem, self.0, Half::User)
    }

    fn word_va(&self) -> u64 {
        DirectMem.va(self.0 + ASID_WORD)
    }

    /// Its ASID word: generation and ASID, or 0 if it never had one.
    pub fn asid_word(&self) -> u64 {
        // SAFETY: the kernel record of an address space object, normal RAM
        // in the direct map, which only the kernel writes.
        unsafe { core::ptr::read_volatile(self.word_va() as *const u64) }
    }

    fn set_asid_word(&self, word: u64) {
        // SAFETY: as for `asid_word`.
        unsafe { core::ptr::write_volatile(self.word_va() as *mut u64, word) }
    }

    /// Maps `frame` at user address `va` with `perm` (ADR 0048, rules 3
    /// and 6). Blocks are used where `va` and the frame are aligned. New
    /// tables come from `src`.
    ///
    /// This is the one encoder every user mapping goes through. Map through
    /// capabilities ([`crate::cap::map`]) calls it with a virtual address
    /// aligned to the frame's size, so every such mapping is one leaf; only
    /// the kernel's own tests call it with others.
    ///
    /// A mapping that is writable and executable, or executable device
    /// memory, is refused, and so is a range that is partly mapped already:
    /// nothing is changed. If `src` runs out, what was mapped is unmapped
    /// again before the error returns.
    ///
    /// An executable mapping first makes the frame's instructions coherent
    /// with what data stores wrote there ([`sync_icache`]): it may hold
    /// another job's old code, cleared since by data stores, or code the
    /// kernel wrote. The descriptors are stored, then `DSB ISHST` makes
    /// them visible to every walker, and `ISB` makes this core's later
    /// instructions use them (kernel specification, "Cross-core signals and
    /// TLB maintenance").
    pub fn map(
        &self,
        va: u64,
        frame: Frame,
        perm: UserPerm,
        src: &mut impl TableSource,
    ) -> Result<(), MapError> {
        if perm.exec && !perm.write && !frame.device {
            // Before any descriptor is stored, so no core can fetch from
            // the frame before its instructions are coherent. Writable and
            // executable mappings, and executable device memory, are
            // refused below.
            sync_icache(frame);
        }
        let mut leaf = |pa: u64, level: u8| -> Result<u64, LeafError> {
            desc::user_leaf(pa, level, perm, frame.device)
        };
        let r = self
            .tables()
            .map(va, frame.pa, frame.size, &mut leaf, &mut Source(src));
        arch::dsb_ishst();
        arch::isb();
        if r == Err(MapError::NoMemory) {
            // Leaves made before the source ran out are mapped; remove
            // them. The range holds only this frame's leaves, since `map`
            // checked it was free.
            let _ = self.unmap(va, frame.size);
        }
        r
    }

    /// Unmaps every leaf in `[va, va + len)`, and returns how many there
    /// were. A range that would cut a block is refused, unchanged.
    ///
    /// Each leaf is cleared, then `DSB ISHST`, then `TLBI VAE1IS` with the
    /// space's ASID and the leaf's address; at the end `DSB ISH` and `ISB`
    /// (ADR 0052, rule 4). The ASID is the number in the space's word,
    /// whatever its generation: a space that ran on another core across a
    /// rollover may still have entries under it (kernel specification,
    /// "Address-space layout", "ASIDs"). A space that never had an ASID has
    /// no TLB entries.
    ///
    /// The tables left empty stay: they are objects of their own, and go
    /// with the address space.
    pub fn unmap(&self, va: u64, len: u64) -> Result<u64, UnmapError> {
        let asid = asid_of(self.asid_word());
        let mut on_leaf = |leaf_va: u64, _level: u8| {
            arch::dsb_ishst();
            if let Some(asid) = asid {
                arch::tlbi_vae1is(asid, leaf_va);
            }
        };
        let n = self.tables().unmap(va, len, &mut on_leaf)?;
        arch::dsb_ish();
        arch::isb();
        Ok(n)
    }

    /// Translates user address `va` in software for `access`, as the kernel
    /// does before it reaches user memory (ADR 0048, rule 5).
    pub fn translate(&self, va: u64, access: Access) -> Result<u64, UserError> {
        kmem::user::translate(&DirectMem, self.0, va, access)
    }

    /// Makes this the active address space on this core: gives it an ASID,
    /// rolling the generation over if none is free, and points `TTBR0_EL1`
    /// at it (kernel specification, "Address-space layout", "ASIDs").
    pub fn activate(&self) {
        let mut word = self.asid_word();
        let a = with_asids(|a| a.activate(CORE, self.0, &mut word));
        self.set_asid_word(word);
        if a.flush_all {
            // A new generation: no TLB may keep an entry under a number
            // that is now free.
            arch::flush_all();
        }
        // SAFETY: an address space's level-0 table, whose stores `map` made
        // visible with `DSB ISHST`.
        unsafe { arch::set_ttbr0(self.0, a.asid) };
    }

    /// Whether this is the active address space on this core.
    pub fn is_active(&self) -> bool {
        arch::ttbr0() & 0x0000_ffff_ffff_f000 == self.0
    }

    /// Destroys the address space, when deleting its last capability has
    /// cleared every binding slot of its record (kernel specification,
    /// "Derivation and revocation"): deactivates it if this core runs it,
    /// and releases its ASID. Its memory goes back with its untyped piece's
    /// next reset.
    ///
    /// C12: every core that runs it deactivates it first.
    pub fn finish(self) {
        if self.is_active() {
            deactivate();
        }
        self.release();
    }

    /// Releases the address space's ASID, when the space is destroyed
    /// (kernel specification, "Address-space layout", "ASIDs"): `TLBI
    /// ASIDE1IS` with its number, whatever its generation, then `DSB ISH`
    /// and `ISB`. It must be active on no core.
    fn release(self) {
        assert!(!self.is_active(), "releasing the active address space");
        let word = self.asid_word();
        if let Some(asid) = with_asids(|a| a.release(self.0, word)) {
            arch::tlbi_aside1is(asid);
            arch::dsb_ish();
            arch::isb();
        }
        self.set_asid_word(0);
    }
}

/// How many times [`sync_icache`] has run, for the test that checks an
/// executable mapping runs it.
#[cfg(aspis_test_build)]
pub static ICACHE_SYNCS: AtomicU64 = AtomicU64::new(0);

/// Makes `frame`'s instructions coherent with the data stores that wrote
/// it, through the direct map, before it is mapped executable.
fn sync_icache(frame: Frame) {
    #[cfg(aspis_test_build)]
    ICACHE_SYNCS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: a RAM frame, which the direct map covers as normal memory.
    unsafe { arch::sync_icache(DirectMem.va(frame.pa), frame.size) };
}

/// Leaves this core with no user address space: `TTBR0_EL1` holds the
/// empty table with ASID 0, which no walk can make a TLB entry from.
pub fn deactivate() {
    with_asids(|a| a.deactivate(CORE));
    let empty = super::phys::kernel_pa(crate::entry::zero_table());
    // SAFETY: the empty table, with the reserved ASID 0.
    unsafe { arch::set_ttbr0(empty, 0) };
}

/// Starts a new ASID generation at once, and invalidates every TLB entry:
/// a test hook, since a real rollover needs 255 or 65,535 address spaces.
#[cfg(aspis_test_build)]
pub fn force_rollover() {
    with_asids(|a| a.rollover());
    arch::flush_all();
}

/// Whether `word` is of the current ASID generation, for tests.
#[cfg(aspis_test_build)]
pub fn is_current(word: u64) -> bool {
    with_asids(|a| a.is_current(word))
}
