// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Building, walking and unmapping translation tables, four levels with the
//! 4 KiB granule (ADR 0048, rule 3).
//!
//! Level 0 covers VA bits 47:39 in either half, so the same code serves the
//! kernel's tables and a user address space's. The caller says which half
//! the tables belong to, for the hierarchical execute-never bits and the
//! range check.
//!
//! These functions only read and write descriptors. Barriers and TLB
//! maintenance are the kernel's (kernel specification, "Cross-core signals
//! and TLB maintenance"), and so is break-before-make: [`map`] never replaces
//! a valid entry.

use crate::desc::{self, Entry, Half, Leaf, LeafError};
use crate::layout::{UPPER_HALF_BASE, USER_TOP};
use crate::{BLOCK_1G, BLOCK_2M, ENTRIES, PAGE_SIZE};

/// Physical memory holding translation tables, as the kernel reaches it:
/// through the boot window before the switch, and the direct map after.
pub trait PhysMem {
    /// Reads descriptor `i` of the table at physical address `table`.
    fn read(&self, table: u64, i: usize) -> u64;
    /// Writes descriptor `i` of the table at `table`. The kernel's writes
    /// are single 64-bit stores, so the walker never sees a torn descriptor.
    fn write(&self, table: u64, i: usize, v: u64);
}

/// Where [`map`] gets the frames for new tables.
pub trait FrameSource {
    /// The physical address of a zeroed page, or `None` if there is no
    /// memory. The zeroes must be visible to the table walker before the
    /// page is returned: the kernel issues `DSB ISHST` after clearing it.
    fn table(&mut self) -> Option<u64>;
}

/// Why [`map`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapError {
    /// An address or the length isn't a multiple of the page size.
    Misaligned,
    /// Part of the range is already mapped. Nothing was changed.
    Occupied,
    /// The frame source ran out. Leaves made before it ran out stay mapped;
    /// the caller unmaps the whole range, which skips the holes.
    NoMemory,
    /// The mapping would be writable and executable (ADR 0048, rule 6).
    WriteExecute,
    /// Device memory can't be executable.
    DeviceExecute,
    /// The range leaves its half, or the physical range is above 2^48.
    OutOfRange,
}

impl From<LeafError> for MapError {
    fn from(e: LeafError) -> Self {
        match e {
            LeafError::WriteExecute => MapError::WriteExecute,
            LeafError::DeviceExecute => MapError::DeviceExecute,
            LeafError::BadLevel | LeafError::Misaligned => MapError::Misaligned,
        }
    }
}

/// Why [`unmap`] failed. In every case nothing was changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmapError {
    Misaligned,
    /// The range would cut a block mapping in two.
    CutsBlock,
    OutOfRange,
}

/// What a walk found at a virtual address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Walk {
    /// No translation: the entry at `level` is invalid.
    Invalid { level: u8 },
    /// A leaf maps the address. `va` is the leaf's first virtual address,
    /// and the leaf's PXN and UXN include the tables' hierarchical bits.
    Leaf { leaf: Leaf, va: u64 },
}

impl Walk {
    /// The physical address `va` translates to, if it is mapped.
    pub const fn pa(&self, va: u64) -> Option<u64> {
        match self {
            Walk::Leaf { leaf, .. } => Some(leaf.pa + (va & (leaf.size() - 1))),
            Walk::Invalid { .. } => None,
        }
    }
}

/// The table index of `va` at `level`.
const fn index(va: u64, level: u8) -> usize {
    ((va >> (39 - 9 * level as u32)) & (ENTRIES as u64 - 1)) as usize
}

/// Checks that `[va, va + len)` lies within `half`.
fn in_half(half: Half, va: u64, len: u64) -> bool {
    let Some(end) = va.checked_add(len) else {
        // Only the kernel's half reaches the top of the address space.
        return half == Half::Kernel && va >= UPPER_HALF_BASE && va.wrapping_add(len) == 0;
    };
    match half {
        Half::User => end <= USER_TOP,
        Half::Kernel => va >= UPPER_HALF_BASE,
    }
}

/// The largest leaf level whose size both addresses are aligned to and the
/// remaining length covers.
fn pick_level(va: u64, pa: u64, left: u64) -> u8 {
    for (level, size) in [(1, BLOCK_1G), (2, BLOCK_2M)] {
        if (va | pa) & (size - 1) == 0 && left >= size {
            return level;
        }
    }
    3
}

/// One set of translation tables: the level-0 table at `root`, reached
/// through `mem`, in `half` of the address space.
#[derive(Clone, Copy, Debug)]
pub struct Tables<'a, M: PhysMem> {
    pub mem: &'a M,
    pub root: u64,
    pub half: Half,
}

impl<'a, M: PhysMem> Tables<'a, M> {
    pub const fn new(mem: &'a M, root: u64, half: Half) -> Self {
        Self { mem, root, half }
    }

    /// The first virtual address of the half.
    pub const fn half_base(&self) -> u64 {
        match self.half {
            Half::Kernel => UPPER_HALF_BASE,
            Half::User => 0,
        }
    }

    /// Maps `[va, va + len)` to `[pa, pa + len)`,
    /// with 1 GiB blocks, then 2 MiB blocks, then 4 KiB pages, wherever both
    /// addresses are aligned and the length covers the size (ADR 0048, rule 3).
    ///
    /// `leaf(pa, level)` encodes each leaf, normally through
    /// [`desc::kernel_leaf`] or [`desc::user_leaf`], so the W^X check is theirs.
    /// New tables come from `src`.
    ///
    /// The whole range is checked before anything is written: an occupied entry
    /// or a refused leaf changes nothing. Only [`MapError::NoMemory`] can leave
    /// part of the range mapped.
    pub fn map(
        &self,
        va: u64,
        pa: u64,
        len: u64,
        leaf: &mut impl FnMut(u64, u8) -> Result<u64, LeafError>,
        src: &mut impl FrameSource,
    ) -> Result<(), MapError> {
        let (mem, root, half) = (self.mem, self.root, self.half);
        if (va | pa | len) & (PAGE_SIZE - 1) != 0 {
            return Err(MapError::Misaligned);
        }
        if !in_half(half, va, len) || pa.checked_add(len).is_none_or(|end| end > 1 << 48) {
            return Err(MapError::OutOfRange);
        }

        // First pass: every leaf can be encoded, and nothing is in the way.
        let mut off = 0;
        while off < len {
            let (v, p) = (va.wrapping_add(off), pa + off);
            let level = pick_level(v, p, len - off);
            leaf(p, level)?;
            if !free_at(mem, root, v, level) {
                return Err(MapError::Occupied);
            }
            off += desc::level_size(level);
        }

        // Second pass: write the leaves, making tables as needed.
        let mut off = 0;
        while off < len {
            let (v, p) = (va.wrapping_add(off), pa + off);
            let level = pick_level(v, p, len - off);
            let d = leaf(p, level)?;
            let table = table_for(mem, root, half, v, level, src)?;
            mem.write(table, index(v, level), d);
            off += desc::level_size(level);
        }
        Ok(())
    }

    /// Walks the tables for `va`: see [`walk`].
    pub fn walk(&self, va: u64) -> Walk {
        walk(self.mem, self.root, va)
    }

    /// Calls `f(va, leaf)` for every leaf, in address order. Each leaf's PXN
    /// and UXN include the tables' hierarchical bits.
    pub fn for_each_leaf(&self, f: &mut impl FnMut(u64, &Leaf)) {
        visit(self.mem, self.root, 0, self.half_base(), false, false, f);
    }

    /// Removes every leaf in `[va, va + len)` from the tables, and
    /// returns how many it removed. Holes are skipped. `on_leaf(va, level)` is
    /// called after each leaf's descriptor is cleared, so the kernel can issue
    /// its TLB invalidation (kernel specification, "Cross-core signals and TLB
    /// maintenance").
    ///
    /// A range that would cut a block in two is refused before anything is
    /// changed. Tables left empty stay in place: they are objects of their own,
    /// made from untyped memory, and go when the address space does.
    pub fn unmap(
        &self,
        va: u64,
        len: u64,
        on_leaf: &mut impl FnMut(u64, u8),
    ) -> Result<u64, UnmapError> {
        let (mem, root, half) = (self.mem, self.root, self.half);
        if (va | len) & (PAGE_SIZE - 1) != 0 {
            return Err(UnmapError::Misaligned);
        }
        if !in_half(half, va, len) {
            return Err(UnmapError::OutOfRange);
        }
        // Offsets from `va` avoid overflow at the top of the kernel's half.
        let cuts = |leaf_va: u64, size: u64| {
            leaf_va < va || (leaf_va.wrapping_sub(va)).wrapping_add(size) > len
        };

        // First pass: refuse a range that cuts a block.
        let mut off = 0;
        while off < len {
            let v = va.wrapping_add(off);
            match step(mem, root, v) {
                Step::Hole(size) => off += size - (v & (size - 1)),
                Step::Leaf { va: lv, size, .. } => {
                    if cuts(lv, size) {
                        return Err(UnmapError::CutsBlock);
                    }
                    off += size;
                }
            }
        }

        // Second pass: clear the leaves.
        let mut count = 0;
        let mut off = 0;
        while off < len {
            let v = va.wrapping_add(off);
            match step(mem, root, v) {
                Step::Hole(size) => off += size - (v & (size - 1)),
                Step::Leaf {
                    va: lv,
                    size,
                    table,
                    level,
                } => {
                    mem.write(table, index(lv, level), 0);
                    on_leaf(lv, level);
                    count += 1;
                    off += size;
                }
            }
        }
        Ok(count)
    }
}

/// Whether a leaf at `level` for `va` would replace nothing: the path down
/// holds only tables or ends in an invalid entry, and the slot is empty.
fn free_at(mem: &impl PhysMem, root: u64, va: u64, level: u8) -> bool {
    let mut table = root;
    for l in 0..level {
        match desc::decode(mem.read(table, index(va, l)), l) {
            Entry::Table { pa, .. } => table = pa,
            Entry::Invalid => return true,
            Entry::Leaf(_) => return false,
        }
    }
    matches!(
        desc::decode(mem.read(table, index(va, level)), level),
        Entry::Invalid
    ) && mem.read(table, index(va, level)) == 0
}

/// The table at `level` that holds `va`'s entry, making the tables above it
/// as needed.
fn table_for(
    mem: &impl PhysMem,
    root: u64,
    half: Half,
    va: u64,
    level: u8,
    src: &mut impl FrameSource,
) -> Result<u64, MapError> {
    let mut table = root;
    for l in 0..level {
        let i = index(va, l);
        table = match desc::decode(mem.read(table, i), l) {
            Entry::Table { pa, .. } => pa,
            Entry::Invalid => {
                let new = src.table().ok_or(MapError::NoMemory)?;
                mem.write(table, i, desc::table_desc(new, half));
                new
            }
            // The first pass found the path clear.
            Entry::Leaf(_) => return Err(MapError::Occupied),
        };
    }
    Ok(table)
}

/// Walks the tables under `root` for `va`, in software. Only bits 47:12 of
/// `va` select entries; the caller checks which half `va` is in.
pub fn walk(mem: &impl PhysMem, root: u64, va: u64) -> Walk {
    let mut table = root;
    let (mut pxn, mut uxn) = (false, false);
    for level in 0..=3 {
        match desc::decode(mem.read(table, index(va, level)), level) {
            Entry::Invalid => return Walk::Invalid { level },
            Entry::Table { pa, pxn: p, uxn: u } => {
                table = pa;
                pxn |= p;
                uxn |= u;
            }
            Entry::Leaf(mut leaf) => {
                leaf.pxn |= pxn;
                leaf.uxn |= uxn;
                let base = va & !(leaf.size() - 1);
                return Walk::Leaf { leaf, va: base };
            }
        }
    }
    // Level 3 never holds a table.
    Walk::Invalid { level: 3 }
}

fn visit(
    mem: &impl PhysMem,
    table: u64,
    level: u8,
    base: u64,
    pxn: bool,
    uxn: bool,
    f: &mut impl FnMut(u64, &Leaf),
) {
    let span = desc::level_size(level);
    for i in 0..ENTRIES {
        let va = base + i as u64 * span;
        match desc::decode(mem.read(table, i), level) {
            Entry::Invalid => {}
            Entry::Table { pa, pxn: p, uxn: u } => {
                visit(mem, pa, level + 1, va, pxn | p, uxn | u, f)
            }
            Entry::Leaf(mut leaf) => {
                leaf.pxn |= pxn;
                leaf.uxn |= uxn;
                f(va, &leaf);
            }
        }
    }
}

enum Step {
    /// Nothing is mapped in the aligned span of this size around the address.
    Hole(u64),
    Leaf {
        va: u64,
        size: u64,
        table: u64,
        level: u8,
    },
}

fn step(mem: &impl PhysMem, root: u64, va: u64) -> Step {
    let mut table = root;
    for level in 0..=3u8 {
        match desc::decode(mem.read(table, index(va, level)), level) {
            Entry::Invalid => {
                return Step::Hole(desc::level_size(level));
            }
            Entry::Table { pa, .. } => table = pa,
            Entry::Leaf(leaf) => {
                let size = leaf.size();
                return Step::Leaf {
                    va: va & !(size - 1),
                    size,
                    table,
                    level,
                };
            }
        }
    }
    Step::Hole(PAGE_SIZE)
}
