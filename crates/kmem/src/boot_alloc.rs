// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The boot allocator: the kernel's only page source before untyped memory
//! exists (ADR 0048, rule 1; kernel specification, "Boot memory").
//!
//! It hands out single pages of usable RAM, top-down from the highest
//! usable range, for what the kernel keeps for itself: its page tables now,
//! and later chunks' boot objects, other cores' stacks and LPI tables. Once
//! the boot objects are made the kernel seals it, and from then on every
//! request fails: after boot, the kernel never allocates memory that no job
//! supplied. What it never handed out becomes untyped memory.
//!
//! The kernel zeroes each page it takes; this module only does the
//! bookkeeping.

use crate::PAGE_SIZE;
use crate::memmap::{CLASS_RANGES, ClassSet};
use crate::ranges::{Full, RangeSet};

/// The most separate runs of pages the allocator can hand out. Pages are
/// taken top-down, so they coalesce into one run per usable range used.
pub const TAKEN_RANGES: usize = 64;

/// Why a page couldn't be had.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocError {
    /// The allocator is sealed (ADR 0048, rule 1). The kernel panics if
    /// this happens: it is a kernel bug.
    Sealed,
    /// No free page lies in the range asked for.
    Exhausted,
}

/// The boot allocator.
#[derive(Clone, Debug)]
pub struct BootAlloc {
    /// Usable RAM not yet taken.
    free: ClassSet,
    /// The pages handed out.
    taken: RangeSet<TAKEN_RANGES>,
    sealed: bool,
}

impl Default for BootAlloc {
    fn default() -> Self {
        Self::new()
    }
}

impl BootAlloc {
    /// An allocator with nothing to give. The kernel keeps one in a static
    /// and calls [`BootAlloc::start`].
    pub const fn new() -> Self {
        Self {
            free: RangeSet::new(),
            taken: RangeSet::new(),
            sealed: false,
        }
    }

    /// Starts over with every page of `usable`, which must be page-aligned.
    pub fn start(&mut self, usable: &ClassSet) -> Result<(), Full> {
        self.free.copy_from(usable)?;
        self.taken.clear();
        self.sealed = false;
        Ok(())
    }

    /// Takes the highest free page, within `[limit.0, limit.1)` if a limit is
    /// given. The kernel gives none: it reaches any page through its boot
    /// window before the switch to its own tables, and through the direct
    /// map after it.
    pub fn alloc(&mut self, limit: Option<(u64, u64)>) -> Result<u64, AllocError> {
        if self.sealed {
            return Err(AllocError::Sealed);
        }
        let (lo, hi) = limit.unwrap_or((0, u64::MAX));
        let page = self
            .free
            .iter()
            .rev()
            .map(|(s, e)| (s.max(lo), e.min(hi)))
            .find(|&(s, e)| e >= s.saturating_add(PAGE_SIZE))
            .map(|(_, e)| e - PAGE_SIZE)
            .ok_or(AllocError::Exhausted)?;
        // Taking a page from the middle of a range can split it.
        self.free
            .remove(page, page + PAGE_SIZE)
            .map_err(|Full| AllocError::Exhausted)?;
        if self.taken.insert(page, page + PAGE_SIZE).is_err() {
            // Put it back, so the two sets stay exact.
            let _ = self.free.insert(page, page + PAGE_SIZE);
            return Err(AllocError::Exhausted);
        }
        Ok(page)
    }

    /// Seals the allocator: every later request fails.
    pub fn seal(&mut self) {
        self.sealed = true;
    }

    pub const fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// The pages handed out.
    pub fn taken(&self) -> &RangeSet<TAKEN_RANGES> {
        &self.taken
    }

    /// The usable pages never handed out: after the seal, the RAM that
    /// becomes untyped memory.
    pub fn free(&self) -> &RangeSet<CLASS_RANGES> {
        &self.free
    }
}
