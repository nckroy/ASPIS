// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Translation-table descriptors for the 4 KiB granule, without LPA2 (Arm ARM
//! D8.3), and the W^X rule (ADR 0048, rule 6).
//!
//! The encoders here are the only way the kernel makes a leaf, so W^X is
//! enforced in one place:
//!
//! - kernel leaves are always UXN, and PXN unless they are text, which is
//!   read-only;
//! - user leaves are always PXN and non-global, and executable only when
//!   read-only;
//! - nothing is both writable and executable at any exception level.
//!
//! The kernel sets the access flag in every leaf, and uses no hardware
//! access-flag or dirty-bit management (`TCR_EL1.HA` and `HD` stay 0).

use crate::PAGE_SHIFT;

/// `MAIR_EL1` attribute index of Device-nGnRE memory, as M1 set it.
pub const MAIR_DEVICE: u8 = 0;
/// `MAIR_EL1` attribute index of normal write-back memory.
pub const MAIR_NORMAL: u8 = 1;
/// `MAIR_EL1` attribute index of normal non-cacheable memory.
pub const MAIR_NC: u8 = 2;

const VALID: u64 = 1 << 0;
/// Bit 1: a table at levels 0 to 2, a page at level 3; clear for a block.
const TYPE_BIT: u64 = 1 << 1;
const ATTR_SHIFT: u32 = 2;
/// AP[1]: EL0 has access.
const AP_EL0: u64 = 1 << 6;
/// AP[2]: read-only.
const AP_RO: u64 = 1 << 7;
/// SH = 0b11, inner shareable.
const SH_INNER: u64 = 0b11 << 8;
/// The access flag.
const AF: u64 = 1 << 10;
/// Not global: the entry is tagged with the ASID.
const NG: u64 = 1 << 11;
/// Privileged execute-never.
const PXN: u64 = 1 << 53;
/// Unprivileged execute-never.
const UXN: u64 = 1 << 54;
/// In a table descriptor: no privileged execution anywhere below it.
const PXN_TABLE: u64 = 1 << 59;
/// In a table descriptor: no unprivileged execution anywhere below it.
const UXN_TABLE: u64 = 1 << 60;
/// The output address, bits 47:12.
const OA_MASK: u64 = 0x0000_ffff_ffff_f000;

/// Software bit 55: the mapping is of memory that isn't RAM in the direct
/// map, so the kernel must never reach it on a user's behalf (ADR 0048,
/// rule 5). It marks every user mapping of device memory, and every kernel
/// mapping in the device window.
pub const DEVICE_BIT: u64 = 1 << 55;

/// The memory type of a kernel mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemType {
    /// Normal memory, write-back, inner shareable: RAM.
    Normal,
    /// Device-nGnRE: MMIO.
    Device,
    /// Normal non-cacheable: the boot framebuffer.
    NonCacheable,
}

impl MemType {
    /// The `MAIR_EL1` attribute index.
    pub const fn attr_index(self) -> u8 {
        match self {
            MemType::Normal => MAIR_NORMAL,
            MemType::Device => MAIR_DEVICE,
            MemType::NonCacheable => MAIR_NC,
        }
    }
}

/// The permissions of a kernel mapping. Every kernel mapping is readable at
/// EL1, and none is accessible at EL0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelPerm {
    pub write: bool,
    pub exec: bool,
}

/// The permissions of a user mapping. Every user mapping is readable: an
/// execute-only mapping would need FEAT_EPAN, which C10 doesn't use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserPerm {
    pub write: bool,
    pub exec: bool,
}

/// Why a leaf can't be made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafError {
    /// The level isn't 1, 2 or 3. Level 0 has no blocks with this granule.
    BadLevel,
    /// The physical address isn't aligned to the leaf's size, or is at or
    /// above 2^48.
    Misaligned,
    /// The mapping would be both writable and executable (ADR 0048, rule 6).
    WriteExecute,
    /// Device memory is never executable.
    DeviceExecute,
}

/// The span in bytes of one entry at `level`: 512 GiB, 1 GiB, 2 MiB or
/// 4 KiB. At levels 1 to 3 it is a leaf's size.
pub const fn level_size(level: u8) -> u64 {
    1 << (PAGE_SHIFT + 9 * (3 - level as u32))
}

/// Which half a table belongs to, for the hierarchical execute-never bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Half {
    /// The kernel's half (`TTBR1_EL1`): tables carry UXNTable.
    Kernel,
    /// A user address space (`TTBR0_EL1`): tables carry PXNTable.
    User,
}

/// A table descriptor for the table at `pa`. As a backstop for W^X, tables
/// in the kernel's half forbid execution at EL0 below them, and user tables
/// forbid execution at EL1 below them. `TCR_EL1.HPD0` and `HPD1` are clear,
/// so the hardware honors these bits.
pub const fn table_desc(pa: u64, half: Half) -> u64 {
    let xn = match half {
        Half::Kernel => UXN_TABLE,
        Half::User => PXN_TABLE,
    };
    (pa & OA_MASK) | xn | TYPE_BIT | VALID
}

fn leaf_base(pa: u64, level: u8) -> Result<u64, LeafError> {
    if !(1..=3).contains(&level) {
        return Err(LeafError::BadLevel);
    }
    if pa & (level_size(level) - 1) != 0 || pa & !OA_MASK != 0 {
        return Err(LeafError::Misaligned);
    }
    // A page at level 3 sets the type bit; a block at levels 1 and 2 doesn't.
    let ty = if level == 3 { TYPE_BIT } else { 0 };
    Ok(pa | ty | VALID | AF | SH_INNER)
}

/// A leaf of the kernel's half: global, always UXN (ADR 0048, rule 6).
///
/// Text is read-only and executable at EL1. Everything else is PXN. Memory
/// that isn't normal write-back RAM is outside the direct map and carries
/// [`DEVICE_BIT`].
pub fn kernel_leaf(pa: u64, level: u8, mem: MemType, perm: KernelPerm) -> Result<u64, LeafError> {
    let mut d = leaf_base(pa, level)?;
    if perm.write && perm.exec {
        return Err(LeafError::WriteExecute);
    }
    if perm.exec && mem != MemType::Normal {
        return Err(LeafError::DeviceExecute);
    }
    d |= (mem.attr_index() as u64) << ATTR_SHIFT;
    d |= UXN;
    if !perm.exec {
        d |= PXN;
    }
    if !perm.write {
        d |= AP_RO;
    }
    if mem != MemType::Normal {
        d |= DEVICE_BIT;
    }
    Ok(d)
}

/// A leaf of a user address space: non-global, always PXN (ADR 0048,
/// rule 6).
///
/// The memory type follows the frame's kind, never the caller's choice:
/// RAM is normal write-back and inner shareable, so it matches the direct
/// map's attributes; device memory is Device-nGnRE, never executable, and
/// carries [`DEVICE_BIT`], so the kernel's walk reports it as "not RAM"
/// (ADR 0048, rule 5).
///
/// C15: device memory objects may later choose normal non-cacheable or
/// write-combining memory for framebuffer-like devices.
pub fn user_leaf(pa: u64, level: u8, perm: UserPerm, device: bool) -> Result<u64, LeafError> {
    let mut d = leaf_base(pa, level)?;
    if perm.write && perm.exec {
        return Err(LeafError::WriteExecute);
    }
    if perm.exec && device {
        return Err(LeafError::DeviceExecute);
    }
    let attr = if device { MAIR_DEVICE } else { MAIR_NORMAL };
    d |= (attr as u64) << ATTR_SHIFT;
    d |= NG | PXN | AP_EL0;
    if !perm.exec {
        d |= UXN;
    }
    if !perm.write {
        d |= AP_RO;
    }
    if device {
        d |= DEVICE_BIT;
    }
    Ok(d)
}

/// A decoded leaf: a page or a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leaf {
    /// The output address: the base of the page or block.
    pub pa: u64,
    /// 1, 2 or 3.
    pub level: u8,
    pub attr_index: u8,
    pub el1_write: bool,
    pub el0_read: bool,
    pub el0_write: bool,
    /// Privileged execute-never, including any PXNTable above the leaf when
    /// it came from a walk.
    pub pxn: bool,
    /// Unprivileged execute-never, including any UXNTable above the leaf
    /// when it came from a walk.
    pub uxn: bool,
    pub global: bool,
    pub access_flag: bool,
    pub device_bit: bool,
}

impl Leaf {
    /// The leaf's size in bytes.
    pub const fn size(&self) -> u64 {
        level_size(self.level)
    }
}

/// One descriptor, decoded according to its level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// Faults. This includes `0b01` at level 0 and at level 3, which are
    /// invalid or reserved with this granule, so the walker treats them as
    /// faults too.
    Invalid,
    /// A table descriptor: the next table's address, and its hierarchical
    /// execute-never bits.
    Table { pa: u64, pxn: bool, uxn: bool },
    /// A page or block.
    Leaf(Leaf),
}

/// Decodes descriptor `d` found at `level` (0 to 3).
pub fn decode(d: u64, level: u8) -> Entry {
    if d & VALID == 0 || level > 3 {
        return Entry::Invalid;
    }
    let table_bit = d & TYPE_BIT != 0;
    match (level, table_bit) {
        (0..=2, true) => Entry::Table {
            pa: d & OA_MASK,
            pxn: d & PXN_TABLE != 0,
            uxn: d & UXN_TABLE != 0,
        },
        (1 | 2, false) | (3, true) => {
            let size = level_size(level);
            Entry::Leaf(Leaf {
                pa: d & OA_MASK & !(size - 1),
                level,
                attr_index: ((d >> ATTR_SHIFT) & 0b111) as u8,
                el1_write: d & AP_RO == 0,
                el0_read: d & AP_EL0 != 0,
                el0_write: d & AP_EL0 != 0 && d & AP_RO == 0,
                pxn: d & PXN != 0,
                uxn: d & UXN != 0,
                global: d & NG == 0,
                access_flag: d & AF != 0,
                device_bit: d & DEVICE_BIT != 0,
            })
        }
        // A block at level 0, or `0b01` at level 3: invalid.
        _ => Entry::Invalid,
    }
}

/// Whether `leaf` breaks W^X: writable at either exception level and
/// executable at either (ADR 0048, rule 6).
pub const fn violates_wx(leaf: &Leaf) -> bool {
    (leaf.el1_write || leaf.el0_write) && (!leaf.pxn || !leaf.uxn)
}
