// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The capability kinds and their encoding in two words, bit-packed as seL4
//! packs its `cap_t` (kernel specification, "Capability spaces and lookup").
//!
//! Word 0 bits 0 to 4 hold a tag, and a tag of 0 is the null capability, so
//! an empty slot is all zero. The tags are the kernel's own: the numbers the
//! ABI reports for each kind are C17's (kernel specification K28 and K30).
//!
//! | Kind | Word 0 | Word 1 |
//! |---|---|---|
//! | Untyped | tag, device (5), size bits (6-11), base (12-47, in place) | watermark |
//! | CNode | tag, radix (5-10), guard size (11-16), pointer >> 6 (17-58) | guard |
//! | Frame | tag, device (5), size code (6-7), rights (8-11), base >> 12 (16-51) | 0, or a binding's mapping: VA, with bit 0 set, write in bit 1, execute in bit 2 |
//! | Address space | tag, rights (5-8), base (13-47, in place) | 0 |
//! | Endpoint | tag, rights (5-8), pointer >> 6 (9-50) | badge, 0 if unbadged |
//! | Zombie | tag, zombie kind (5-7), radix (8-13), pointer >> 6 (14-55) | slots still to clear |
//!
//! Physical and virtual addresses are below 2^48. Every other bit is zero,
//! and [`Cap::decode`] refuses words that don't re-encode to themselves, so
//! a corrupt slot is caught rather than misread. No encoding holds an ID
//! (ADR 0050, rule 1).

use kmem::untyped::{ADDRESS_SPACE_BITS, ENDPOINT_BITS, MAX_BITS, MAX_RADIX, MIN_BITS, MIN_RADIX};
use kmem::{BLOCK_1G, BLOCK_2M, PAGE_SIZE};

use crate::rights::Rights;
use crate::{SLOT_BITS, SLOT_SIZE};

const TAG_NULL: u64 = 0;
const TAG_UNTYPED: u64 = 1;
const TAG_CNODE: u64 = 2;
const TAG_FRAME: u64 = 3;
const TAG_ADDRESS_SPACE: u64 = 4;
const TAG_ENDPOINT: u64 = 5;
const TAG_ZOMBIE: u64 = 6;

/// Addresses are below 2^48.
const ADDR_MASK: u64 = (1 << 48) - 1;
/// Where an address space's record starts, past its level-0 table.
pub const RECORD_OFFSET: u64 = 4096;
/// The record's header: the ASID word, then three words kept for C15 and
/// C16.
pub const RECORD_HEADER: u64 = 32;
/// Slots in an address space's record: the park slot, then the binding
/// slots.
pub const RECORD_SLOTS: u64 = (RECORD_OFFSET - RECORD_HEADER) / SLOT_SIZE;

/// The largest guard: seL4 on 64-bit keeps the guard size in six bits.
pub const MAX_GUARD_BITS: u8 = 63;

const fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1 << bits) - 1
    }
}

/// A frame's size: 4 KiB, 2 MiB or 1 GiB, as AArch64 maps them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameSize {
    Small,
    Large,
    Huge,
}

impl FrameSize {
    /// The size in bytes.
    pub const fn bytes(self) -> u64 {
        match self {
            FrameSize::Small => PAGE_SIZE,
            FrameSize::Large => BLOCK_2M,
            FrameSize::Huge => BLOCK_1G,
        }
    }

    const fn code(self) -> u64 {
        match self {
            FrameSize::Small => 0,
            FrameSize::Large => 1,
            FrameSize::Huge => 2,
        }
    }

    const fn from_code(code: u64) -> Option<FrameSize> {
        match code {
            0 => Some(FrameSize::Small),
            1 => Some(FrameSize::Large),
            2 => Some(FrameSize::Huge),
            _ => None,
        }
    }
}

/// A frame binding's mapping (C11; C15's mapping records replace it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Mapping {
    /// The virtual address, aligned to the frame's size.
    pub va: u64,
    pub write: bool,
    pub exec: bool,
}

/// Which object a zombie is finishing: the kinds that have slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ZombieKind {
    /// A CNode of `2^radix` slots.
    CNode { radix: u8 },
    /// An address space: its record's slots.
    AddressSpace,
}

/// The kind of object a capability names, as identify reports it (ADR 0047,
/// rule 3). An empty slot and a zombie are both [`Kind::Null`]: a zombie is
/// a deletion in progress, and names nothing a holder can use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Null,
    Untyped,
    CNode,
    Frame,
    AddressSpace,
    Endpoint,
}

/// A capability, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cap {
    /// No capability.
    Null,
    /// Untyped memory: a piece of `2^bits` bytes at `base`, with its
    /// watermark, as seL4 keeps it in the capability (ADR 0048, rule 1).
    Untyped {
        base: u64,
        bits: u8,
        device: bool,
        watermark: u64,
    },
    /// A CNode of `2^radix` slots at `ptr`, with the guard that lookup
    /// consumes before its index (ADR 0049, rule 1).
    CNode {
        ptr: u64,
        radix: u8,
        guard_size: u8,
        guard: u64,
    },
    /// A frame. `mapping` is set only on a binding: the copy that a mapping
    /// keeps in an address space's record (ADR 0049, rule 4).
    Frame {
        base: u64,
        size: FrameSize,
        device: bool,
        rights: Rights,
        mapping: Option<Mapping>,
    },
    /// An address space: its level-0 table, then its record.
    AddressSpace { base: u64, rights: Rights },
    /// An endpoint, with its badge (0 is unbadged; ADR 0049, rule 3). Its
    /// operations are C14's.
    Endpoint {
        ptr: u64,
        rights: Rights,
        badge: u64,
    },
    /// An object whose last capability is being deleted: slots `[0, n)` of
    /// its slot array are still to clear (kernel specification, "Derivation
    /// and revocation").
    Zombie { kind: ZombieKind, ptr: u64, n: u64 },
}

impl Cap {
    /// The two words of the capability. The fields must be in range, as
    /// every constructor in this crate makes them; [`Cap::is_valid`] says
    /// whether they are.
    pub const fn encode(&self) -> [u64; 2] {
        match *self {
            Cap::Null => [TAG_NULL, 0],
            Cap::Untyped {
                base,
                bits,
                device,
                watermark,
            } => [
                TAG_UNTYPED
                    | (device as u64) << 5
                    | (bits as u64 & 63) << 6
                    | (base & ADDR_MASK & !mask(12)),
                watermark,
            ],
            Cap::CNode {
                ptr,
                radix,
                guard_size,
                guard,
            } => [
                TAG_CNODE
                    | (radix as u64 & 63) << 5
                    | (guard_size as u64 & 63) << 11
                    | ((ptr & ADDR_MASK) >> 6) << 17,
                guard,
            ],
            Cap::Frame {
                base,
                size,
                device,
                rights,
                mapping,
            } => {
                let w1 = match mapping {
                    None => 0,
                    Some(m) => {
                        (m.va & ADDR_MASK & !mask(12))
                            | (m.write as u64) << 1
                            | (m.exec as u64) << 2
                            | 1
                    }
                };
                [
                    TAG_FRAME
                        | (device as u64) << 5
                        | size.code() << 6
                        | (rights.bits() as u64) << 8
                        | ((base & ADDR_MASK) >> 12) << 16,
                    w1,
                ]
            }
            Cap::AddressSpace { base, rights } => [
                TAG_ADDRESS_SPACE
                    | (rights.bits() as u64) << 5
                    | (base & ADDR_MASK & !mask(ADDRESS_SPACE_BITS as u32)),
                0,
            ],
            Cap::Endpoint { ptr, rights, badge } => [
                TAG_ENDPOINT | (rights.bits() as u64) << 5 | ((ptr & ADDR_MASK) >> 6) << 9,
                badge,
            ],
            Cap::Zombie { kind, ptr, n } => {
                let (code, radix) = match kind {
                    ZombieKind::CNode { radix } => (0, radix),
                    ZombieKind::AddressSpace => (1, 0),
                };
                [
                    TAG_ZOMBIE
                        | code << 5
                        | (radix as u64 & 63) << 8
                        | ((ptr & ADDR_MASK) >> 6) << 14,
                    n,
                ]
            }
        }
    }

    /// The capability in two words, or `None` if they hold no valid
    /// capability: an unknown tag, a field out of range, or a stray bit.
    pub fn decode(w: [u64; 2]) -> Option<Cap> {
        let [w0, w1] = w;
        let cap = match w0 & 31 {
            TAG_NULL => Cap::Null,
            TAG_UNTYPED => Cap::Untyped {
                base: w0 & ADDR_MASK & !mask(12),
                bits: ((w0 >> 6) & 63) as u8,
                device: w0 & 1 << 5 != 0,
                watermark: w1,
            },
            TAG_CNODE => Cap::CNode {
                ptr: ((w0 >> 17) & mask(42)) << 6,
                radix: ((w0 >> 5) & 63) as u8,
                guard_size: ((w0 >> 11) & 63) as u8,
                guard: w1,
            },
            TAG_FRAME => Cap::Frame {
                base: ((w0 >> 16) & mask(36)) << 12,
                size: FrameSize::from_code((w0 >> 6) & 3)?,
                device: w0 & 1 << 5 != 0,
                rights: Rights::from_bits((w0 >> 8) as u8),
                mapping: if w1 & 1 == 0 {
                    None
                } else {
                    Some(Mapping {
                        va: w1 & ADDR_MASK & !mask(12),
                        write: w1 & 2 != 0,
                        exec: w1 & 4 != 0,
                    })
                },
            },
            TAG_ADDRESS_SPACE => Cap::AddressSpace {
                base: w0 & ADDR_MASK & !mask(ADDRESS_SPACE_BITS as u32),
                rights: Rights::from_bits((w0 >> 5) as u8),
            },
            TAG_ENDPOINT => Cap::Endpoint {
                ptr: ((w0 >> 9) & mask(42)) << 6,
                rights: Rights::from_bits((w0 >> 5) as u8),
                badge: w1,
            },
            TAG_ZOMBIE => Cap::Zombie {
                kind: match (w0 >> 5) & 7 {
                    0 => ZombieKind::CNode {
                        radix: ((w0 >> 8) & 63) as u8,
                    },
                    1 => ZombieKind::AddressSpace,
                    _ => return None,
                },
                ptr: ((w0 >> 14) & mask(42)) << 6,
                n: w1,
            },
            _ => return None,
        };
        // Every bit must belong to a field, and every field be in range.
        (cap.encode() == w && cap.is_valid()).then_some(cap)
    }

    /// Whether every field is in range and every address aligned.
    pub fn is_valid(&self) -> bool {
        let aligned = |a: u64, bits: u32| a & mask(bits) == 0 && a <= ADDR_MASK;
        match *self {
            Cap::Null => true,
            Cap::Untyped {
                base,
                bits,
                watermark,
                ..
            } => {
                (MIN_BITS..=MAX_BITS).contains(&bits)
                    && aligned(base, bits as u32)
                    && watermark <= 1 << bits
            }
            Cap::CNode {
                ptr,
                radix,
                guard_size,
                guard,
            } => {
                (MIN_RADIX..=MAX_RADIX).contains(&radix)
                    && aligned(ptr, radix as u32 + SLOT_BITS)
                    && guard_ok(radix, guard_size, guard)
            }
            Cap::Frame {
                base,
                size,
                mapping,
                ..
            } => {
                aligned(base, size.bytes().trailing_zeros())
                    && match mapping {
                        None => true,
                        Some(m) => {
                            aligned(m.va, size.bytes().trailing_zeros())
                                && m.va + size.bytes() <= 1 << 48
                                && !(m.write && m.exec)
                        }
                    }
            }
            Cap::AddressSpace { base, .. } => aligned(base, ADDRESS_SPACE_BITS as u32),
            Cap::Endpoint { ptr, .. } => aligned(ptr, ENDPOINT_BITS as u32),
            Cap::Zombie { kind, ptr, n } => match kind {
                ZombieKind::CNode { radix } => {
                    (MIN_RADIX..=MAX_RADIX).contains(&radix)
                        && aligned(ptr, radix as u32 + SLOT_BITS)
                        && n <= 1 << radix
                }
                ZombieKind::AddressSpace => {
                    aligned(ptr, ADDRESS_SPACE_BITS as u32) && n <= RECORD_SLOTS
                }
            },
        }
    }

    /// The kind identify reports.
    pub const fn kind(&self) -> Kind {
        match self {
            Cap::Null | Cap::Zombie { .. } => Kind::Null,
            Cap::Untyped { .. } => Kind::Untyped,
            Cap::CNode { .. } => Kind::CNode,
            Cap::Frame { .. } => Kind::Frame,
            Cap::AddressSpace { .. } => Kind::AddressSpace,
            Cap::Endpoint { .. } => Kind::Endpoint,
        }
    }

    /// The capability's rights. Untyped and CNode capabilities carry none,
    /// as in seL4, and nor does a zombie.
    pub const fn rights(&self) -> Rights {
        match *self {
            Cap::Frame { rights, .. }
            | Cap::AddressSpace { rights, .. }
            | Cap::Endpoint { rights, .. } => rights,
            _ => Rights::NONE,
        }
    }

    /// The same capability with its rights masked by `mask`. Kinds without
    /// rights are unchanged.
    pub const fn masked(self, mask: Rights) -> Cap {
        match self {
            Cap::Frame {
                base,
                size,
                device,
                rights,
                mapping,
            } => Cap::Frame {
                base,
                size,
                device,
                rights: rights.mask(mask),
                mapping,
            },
            Cap::AddressSpace { base, rights } => Cap::AddressSpace {
                base,
                rights: rights.mask(mask),
            },
            Cap::Endpoint { ptr, rights, badge } => Cap::Endpoint {
                ptr,
                rights: rights.mask(mask),
                badge,
            },
            other => other,
        }
    }

    pub const fn is_null(&self) -> bool {
        matches!(self, Cap::Null)
    }

    pub const fn is_zombie(&self) -> bool {
        matches!(self, Cap::Zombie { .. })
    }

    /// Whether the capability is a binding the kernel keeps: C11's only one
    /// is a frame mapped in an address space. Deleting it, or making it a
    /// zombie, runs its unbind hook first.
    pub const fn is_binding(&self) -> bool {
        matches!(
            self,
            Cap::Frame {
                mapping: Some(_),
                ..
            }
        )
    }

    /// The memory the object occupies, `(base, size)`. A zombie's object
    /// still occupies its memory. `None` for the null capability.
    pub const fn object(&self) -> Option<(u64, u64)> {
        match *self {
            Cap::Null => None,
            Cap::Untyped { base, bits, .. } => Some((base, 1 << bits)),
            Cap::CNode { ptr, radix, .. } => Some((ptr, 1 << (radix as u32 + SLOT_BITS))),
            Cap::Frame { base, size, .. } => Some((base, size.bytes())),
            Cap::AddressSpace { base, .. } => Some((base, 1 << ADDRESS_SPACE_BITS)),
            Cap::Endpoint { ptr, .. } => Some((ptr, 1 << ENDPOINT_BITS)),
            Cap::Zombie { kind, ptr, .. } => Some((
                ptr,
                match kind {
                    ZombieKind::CNode { radix } => 1 << (radix as u32 + SLOT_BITS),
                    ZombieKind::AddressSpace => 1 << ADDRESS_SPACE_BITS,
                },
            )),
        }
    }

    /// Whether both capabilities name the same object, as seL4's
    /// `sameObjectAs`: the same kind at the same place and size, whatever
    /// their rights, badges, guards or mappings. A zombie is never the same
    /// object as anything: it is always the last capability to its object.
    pub fn same_object(&self, other: &Cap) -> bool {
        let same_kind = matches!(
            (self, other),
            (Cap::Untyped { .. }, Cap::Untyped { .. })
                | (Cap::CNode { .. }, Cap::CNode { .. })
                | (Cap::Frame { .. }, Cap::Frame { .. })
                | (Cap::AddressSpace { .. }, Cap::AddressSpace { .. })
                | (Cap::Endpoint { .. }, Cap::Endpoint { .. })
        );
        same_kind && self.object() == other.object()
    }

    /// Whether the object has slots of its own, and so becomes a zombie
    /// when its last capability is deleted.
    pub const fn has_slots(&self) -> bool {
        matches!(self, Cap::CNode { .. } | Cap::AddressSpace { .. })
    }

    /// The zombie that finishes this capability's object, with every slot
    /// still to clear, if the object has slots.
    pub const fn zombie(&self) -> Option<Cap> {
        match *self {
            Cap::CNode { ptr, radix, .. } => Some(Cap::Zombie {
                kind: ZombieKind::CNode { radix },
                ptr,
                n: 1 << radix,
            }),
            Cap::AddressSpace { base, .. } => Some(Cap::Zombie {
                kind: ZombieKind::AddressSpace,
                ptr: base,
                n: RECORD_SLOTS,
            }),
            _ => None,
        }
    }
}

/// Whether a guard fits a CNode: a size of 0 to 63 bits, as seL4 on 64-bit
/// keeps it in six bits; the guard within that size; and the guard and the
/// radix together no more than 64 bits, so that one level never consumes
/// more than an address holds.
pub const fn guard_ok(radix: u8, guard_size: u8, guard: u64) -> bool {
    guard_size <= MAX_GUARD_BITS
        && guard_size as u32 + radix as u32 <= 64
        && guard & !mask(guard_size as u32) == 0
}

/// The slot array of an object with slots: where its slots start, and how
/// many there are. A CNode's array is the CNode. An address space's is its
/// record's slots: slot 0 is the park slot, and slots 1 to 126 are the
/// binding slots its mappings use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotArray {
    pub base: u64,
    pub count: u64,
}

impl SlotArray {
    /// The array of a zombie's object.
    pub const fn of(kind: ZombieKind, ptr: u64) -> SlotArray {
        match kind {
            ZombieKind::CNode { radix } => SlotArray {
                base: ptr,
                count: 1 << radix,
            },
            ZombieKind::AddressSpace => SlotArray {
                base: ptr + RECORD_OFFSET + RECORD_HEADER,
                count: RECORD_SLOTS,
            },
        }
    }

    /// The array of an address space at `base`.
    pub const fn of_address_space(base: u64) -> SlotArray {
        SlotArray::of(ZombieKind::AddressSpace, base)
    }

    /// Slot `i`.
    pub const fn slot(&self, i: u64) -> crate::SlotRef {
        crate::SlotRef(self.base + (i << SLOT_BITS))
    }

    /// The park slot, slot 0: where deletion keeps a waiting zombie. It
    /// never holds a binding.
    pub const fn park(&self) -> crate::SlotRef {
        self.slot(0)
    }

    /// Whether `slot` is one of this array's.
    pub const fn contains(&self, slot: crate::SlotRef) -> bool {
        slot.0 >= self.base && slot.0 - self.base < self.count << SLOT_BITS
    }
}
