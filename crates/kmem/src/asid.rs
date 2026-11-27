// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! ASIDs by generation rollover, as Linux on arm64 gives them out
//! (`arch/arm64/mm/context.c`), so that no job can exhaust them however many
//! address spaces it makes (ADR 0048, rule 4; kernel specification,
//! "Address-space layout", which settles K01).
//!
//! Each address space keeps an ASID word: its generation in the high bits
//! and its ASID in the low 16. A word of 0 means it has never had one.
//!
//! - Activating a space whose word is of the current generation uses it.
//! - Otherwise the space keeps its old number if that is reserved for this
//!   same space, or free; else it takes the next free number.
//! - When none is free, the generation rolls over: every number is freed
//!   except 0 and the numbers active on each core, the current core's
//!   included, which are reserved for the spaces running there. The caller
//!   then invalidates every TLB entry (`TLBI VMALLE1IS`).
//!
//! A space that runs on another core across a rollover keeps its number
//! there, and its own word is moved to the new generation when it is next
//! activated anywhere. So one address space never has two live ASIDs, and
//! a number is never given to a second space while a core still runs the
//! first under it.
//!
//! Its word may still be of an old generation while it runs, so the kernel
//! invalidates by the word's number whatever its generation, as Linux does.
//! An invalidation that also hits another space's entries costs only a
//! refill.
//!
//! All of this runs under the kernel lock (C12).

/// The most cores the allocator tracks: the kernel's core bound, which the
/// kernel checks equals `kirq::MAX_CORES` (C12). Unused cores' records stay
/// empty.
pub const MAX_CORES: usize = 8;

/// ASID 0 is never given out: it tags "no user address space", the empty
/// table `TTBR0_EL1` holds when no space is active.
pub const RESERVED_ASID: u16 = 0;

const ASID_MASK: u64 = 0xffff;
const GEN_SHIFT: u32 = 16;

/// The ASID a word holds, or `None` for a space that has never had one and
/// so can have no TLB entries.
pub const fn asid_of(word: u64) -> Option<u16> {
    if word == 0 {
        None
    } else {
        Some((word & ASID_MASK) as u16)
    }
}

const fn generation_of(word: u64) -> u64 {
    word >> GEN_SHIFT
}

/// What a core is running, or was running at the last rollover: the
/// address space's identity (the physical address of its record) and its
/// ASID word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    space: u64,
    word: u64,
}

const EMPTY: Slot = Slot { space: 0, word: 0 };

/// The result of an activation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Activation {
    /// The ASID to write into `TTBR0_EL1`.
    pub asid: u16,
    /// The generation rolled over: the caller must invalidate every TLB
    /// entry (`TLBI VMALLE1IS; DSB ISH; ISB`) before it writes `TTBR0_EL1`.
    pub flush_all: bool,
}

/// The node's ASID allocator.
#[derive(Clone, Debug)]
pub struct AsidAllocator {
    /// 8 or 16.
    bits: u8,
    /// The current generation, from 1.
    generation: u64,
    /// One bit per ASID: used in this generation.
    used: [u64; 1024],
    /// Where the search for a free number starts.
    next: u32,
    active: [Slot; MAX_CORES],
    reserved: [Slot; MAX_CORES],
}

impl AsidAllocator {
    /// An allocator for `bits`-bit ASIDs: 16 when
    /// `ID_AA64MMFR0_EL1.ASIDBits` is `0b0010`, else 8.
    pub const fn new(bits: u8) -> Self {
        let mut used = [0; 1024];
        used[0] = 1 << RESERVED_ASID;
        Self {
            bits: if bits >= 16 { 16 } else { 8 },
            generation: 1,
            used,
            next: 1,
            active: [EMPTY; MAX_CORES],
            reserved: [EMPTY; MAX_CORES],
        }
    }

    /// Starts the allocator afresh, in place, for `bits`-bit ASIDs, as
    /// [`AsidAllocator::new`] would make it. The kernel keeps the allocator
    /// in a static and calls this once at boot, when it has read the width,
    /// so the 8 KiB bitmap is never built on the stack. No address space may
    /// have been activated yet: a word from before would look current.
    pub fn init(&mut self, bits: u8) {
        self.bits = if bits >= 16 { 16 } else { 8 };
        self.generation = 1;
        self.used.fill(0);
        self.mark(RESERVED_ASID);
        self.next = 1;
        self.active = [EMPTY; MAX_CORES];
        self.reserved = [EMPTY; MAX_CORES];
    }

    /// The ASID width in bits.
    pub const fn bits(&self) -> u8 {
        self.bits
    }

    /// The current generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether `word` is of the current generation.
    pub const fn is_current(&self, word: u64) -> bool {
        word != 0 && generation_of(word) == self.generation
    }

    const fn limit(&self) -> u32 {
        1 << self.bits
    }

    fn is_used(&self, asid: u16) -> bool {
        self.used[asid as usize / 64] & (1 << (asid % 64)) != 0
    }

    fn mark(&mut self, asid: u16) {
        self.used[asid as usize / 64] |= 1 << (asid % 64);
    }

    fn unmark(&mut self, asid: u16) {
        self.used[asid as usize / 64] &= !(1 << (asid % 64));
    }

    const fn word(&self, asid: u16) -> u64 {
        self.generation << GEN_SHIFT | asid as u64
    }

    /// Makes `space` the active address space on `core`, and returns the
    /// ASID it runs under. `word` is the space's ASID word, which this
    /// updates. `space` identifies the space: the physical address of its
    /// record, never 0.
    pub fn activate(&mut self, core: usize, space: u64, word: &mut u64) -> Activation {
        let core = core.min(MAX_CORES - 1);
        if self.is_current(*word) {
            self.active[core] = Slot { space, word: *word };
            return Activation {
                asid: (*word & ASID_MASK) as u16,
                flush_all: false,
            };
        }
        let mut flush_all = false;
        let asid = match self.reuse(space, *word) {
            Some(asid) => asid,
            None => match self.find_free() {
                Some(asid) => asid,
                None => {
                    self.rollover();
                    flush_all = true;
                    // The space may have been active somewhere, and so now
                    // reserved; otherwise its old number may now be free.
                    match self.reuse(space, *word).or_else(|| self.find_free()) {
                        Some(asid) => asid,
                        // At most MAX_CORES numbers are reserved after a
                        // rollover, far fewer than 255.
                        None => RESERVED_ASID,
                    }
                }
            },
        };
        self.mark(asid);
        let new = self.word(asid);
        *word = new;
        // Every slot that names this space now holds its new word.
        for slot in self.active.iter_mut().chain(self.reserved.iter_mut()) {
            if slot.space == space {
                slot.word = new;
            }
        }
        self.active[core] = Slot { space, word: new };
        Activation { asid, flush_all }
    }

    /// The number a space with an old-generation `word` may keep: the one
    /// reserved for it at the last rollover (Linux's
    /// `check_update_reserved_asid`), or its old number if no one uses it.
    fn reuse(&mut self, space: u64, word: u64) -> Option<u16> {
        let asid = asid_of(word)?;
        if self
            .reserved
            .iter()
            .any(|r| r.space == space && r.word == word)
        {
            // Marked used at the rollover.
            return Some(asid);
        }
        if asid != RESERVED_ASID && (asid as u32) < self.limit() && !self.is_used(asid) {
            return Some(asid);
        }
        None
    }

    fn find_free(&mut self) -> Option<u16> {
        let limit = self.limit();
        for i in 0..limit {
            let a = (self.next + i) % limit;
            if a != RESERVED_ASID as u32 && !self.is_used(a as u16) {
                self.next = (a + 1) % limit;
                return Some(a as u16);
            }
        }
        None
    }

    /// Starts a new generation. Every number is freed except 0 and each
    /// core's active number, which is reserved for the space running there.
    /// The caller must invalidate every TLB entry before any core's
    /// `TTBR0_EL1` is written again. Activation calls this when it runs out;
    /// tests call it to force a rollover.
    pub fn rollover(&mut self) {
        self.generation += 1;
        self.used.fill(0);
        self.mark(RESERVED_ASID);
        for core in 0..MAX_CORES {
            let slot = self.active[core];
            self.reserved[core] = slot;
            if let Some(asid) = asid_of(slot.word) {
                self.mark(asid);
            }
        }
        self.next = 1;
    }

    /// The address space `core`'s `TTBR0_EL1` holds, by its level-0 table,
    /// or 0 for none: what it runs, or ran last and keeps while it idles.
    /// The kernel deactivates it there before the space is destroyed (C12).
    pub const fn active_space(&self, core: usize) -> u64 {
        if core < MAX_CORES {
            self.active[core].space
        } else {
            0
        }
    }

    /// Records that `core` runs no user address space: `TTBR0_EL1` holds the
    /// empty table and ASID 0.
    pub fn deactivate(&mut self, core: usize) {
        self.active[core.min(MAX_CORES - 1)] = EMPTY;
    }

    /// Releases a space's ASID when the space is destroyed. It must be
    /// active on no core. Returns the number to invalidate
    /// (`TLBI ASIDE1IS`), if the space ever had one: whatever its
    /// generation, since a space that ran across a rollover may still have
    /// entries under its old word's number. The number is freed only if it
    /// belongs to the current generation.
    pub fn release(&mut self, space: u64, word: u64) -> Option<u16> {
        let asid = asid_of(word)?;
        for slot in self.reserved.iter_mut() {
            if slot.space == space {
                *slot = EMPTY;
            }
        }
        if self.is_current(word) {
            self.unmark(asid);
        }
        Some(asid)
    }
}
