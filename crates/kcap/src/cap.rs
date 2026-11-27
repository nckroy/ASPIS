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
//! | Endpoint | tag, rights (5-8), pointer >> 6 (9-50), binding (51-52) | badge, 0 if unbadged |
//! | Zombie | tag, zombie kind (5-7), radix (8-13), pointer >> 6 (14-55) | slots still to clear |
//! | Thread | tag, rights (5-8), pointer >> 11 (9-45) | 0 |
//! | Scheduling context | tag, size bits (5-8), binding (9-10), pointer >> 8 (11-50) | 0 |
//! | Scheduling control | tag, core (5-12) | 0 |
//! | Reply object | tag, rights (5-8), pointer >> 7 (9-49) | 0 |
//!
//! **Bindings** (C12). A copy that a thread keeps of an endpoint or a
//! scheduling context presented to it records its role in its own encoding
//! ([`Binding`]), as a frame's binding records its mapping, so its unbind
//! step depends only on the capability, never on the slot's index (kernel
//! specification, "Derivation and revocation", "What moves"). The thread is
//! the object that holds the slot: its address rounded down to the thread's
//! 2 KiB. A thread's root CNode and address space are plain copies: the
//! kernel checks for them whenever it picks the thread to run, so they need
//! no unbind step. C13b and C14 add the eventcount's roles.
//!
//! Physical and virtual addresses are below 2^48. Every other bit is zero,
//! and [`Cap::decode`] refuses words that don't re-encode to themselves, so
//! a corrupt slot is caught rather than misread. No encoding holds an ID
//! (ADR 0050, rule 1).

use kmem::untyped::{
    ADDRESS_SPACE_BITS, ENDPOINT_BITS, MAX_BITS, MAX_RADIX, MAX_SCHED_CONTEXT_BITS, MIN_BITS,
    MIN_RADIX, MIN_SCHED_CONTEXT_BITS, REPLY_BITS, THREAD_BITS,
};
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
const TAG_THREAD: u64 = 7;
const TAG_SCHED_CONTEXT: u64 = 8;
const TAG_SCHED_CONTROL: u64 = 9;
const TAG_REPLY: u64 = 10;

/// Slots in a thread: slot 0 is the park slot; slots 1 to 7 hold its root
/// CNode, address space, fault endpoint, timeout endpoint, scheduling
/// context, bound eventcount (C14) and IPC buffer (C14, K29) (kernel
/// specification K07).
pub const THREAD_SLOTS: u64 = 8;

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

/// The role of a copy that a thread keeps (module docs). Each role fits one
/// kind: the endpoints' roles an endpoint, the context's a scheduling
/// context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Binding {
    /// The thread's fault endpoint, in thread slot 3.
    FaultEndpoint,
    /// The thread's timeout endpoint, in thread slot 4.
    TimeoutEndpoint,
    /// The thread's scheduling context, in thread slot 5.
    Context,
}

impl Binding {
    const fn code(b: Option<Binding>) -> u64 {
        match b {
            None => 0,
            Some(Binding::FaultEndpoint) => 1,
            Some(Binding::TimeoutEndpoint) => 2,
            Some(Binding::Context) => 3,
        }
    }

    const fn from_code(code: u64) -> Option<Binding> {
        match code {
            1 => Some(Binding::FaultEndpoint),
            2 => Some(Binding::TimeoutEndpoint),
            3 => Some(Binding::Context),
            _ => None,
        }
    }

    /// The thread slot that holds a copy in this role.
    pub const fn thread_slot(self) -> u64 {
        match self {
            Binding::FaultEndpoint => 3,
            Binding::TimeoutEndpoint => 4,
            Binding::Context => 5,
        }
    }

    const fn fits_endpoint(b: Option<Binding>) -> bool {
        matches!(
            b,
            None | Some(Binding::FaultEndpoint | Binding::TimeoutEndpoint)
        )
    }

    const fn fits_context(b: Option<Binding>) -> bool {
        matches!(b, None | Some(Binding::Context))
    }
}

/// Which object a zombie is finishing: the kinds that have slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ZombieKind {
    /// A CNode of `2^radix` slots.
    CNode { radix: u8 },
    /// An address space: its record's slots.
    AddressSpace,
    /// A thread: its eight slots (C12).
    Thread,
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
    Thread,
    SchedContext,
    SchedControl,
    Reply,
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
    /// operations are C14's. `binding` is set only on a thread's copy of
    /// its fault or timeout endpoint (C12).
    Endpoint {
        ptr: u64,
        rights: Rights,
        badge: u64,
        binding: Option<Binding>,
    },
    /// An object whose last capability is being deleted: slots `[0, n)` of
    /// its slot array are still to clear (kernel specification, "Derivation
    /// and revocation").
    Zombie { kind: ZombieKind, ptr: u64, n: u64 },
    /// A thread (C12; ADR 0051). The read right reads its state and
    /// registers; the write right does everything else (kernel
    /// specification, "Rights by object type").
    Thread { ptr: u64, rights: Rights },
    /// A scheduling context of `2^bits` bytes (C12; ADR 0051, rule 1). It
    /// carries no rights, as in seL4, and its badge lives in the object.
    /// `binding` is set only on the copy its thread keeps.
    SchedContext {
        ptr: u64,
        bits: u8,
        binding: Option<Binding>,
    },
    /// The scheduling control of core `core` (C12): it configures
    /// scheduling contexts for that core, as seL4's `SchedControl`. It names
    /// no memory, and copies like any capability, as in seL4 17.0.0's
    /// `deriveCap`.
    SchedControl { core: u8 },
    /// A reply object (C12; seL4 MCS). The grant right lets a reply carry
    /// capabilities (C14).
    Reply { ptr: u64, rights: Rights },
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
            Cap::Endpoint {
                ptr,
                rights,
                badge,
                binding,
            } => [
                TAG_ENDPOINT
                    | (rights.bits() as u64) << 5
                    | ((ptr & ADDR_MASK) >> 6) << 9
                    | Binding::code(binding) << 51,
                badge,
            ],
            Cap::Thread { ptr, rights } => [
                TAG_THREAD | (rights.bits() as u64) << 5 | ((ptr & ADDR_MASK) >> 11) << 9,
                0,
            ],
            Cap::SchedContext { ptr, bits, binding } => [
                TAG_SCHED_CONTEXT
                    | (bits as u64 & 15) << 5
                    | Binding::code(binding) << 9
                    | ((ptr & ADDR_MASK) >> 8) << 11,
                0,
            ],
            Cap::SchedControl { core } => [TAG_SCHED_CONTROL | (core as u64) << 5, 0],
            Cap::Reply { ptr, rights } => [
                TAG_REPLY | (rights.bits() as u64) << 5 | ((ptr & ADDR_MASK) >> 7) << 9,
                0,
            ],
            Cap::Zombie { kind, ptr, n } => {
                let (code, radix) = match kind {
                    ZombieKind::CNode { radix } => (0, radix),
                    ZombieKind::AddressSpace => (1, 0),
                    ZombieKind::Thread => (2, 0),
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
                binding: Binding::from_code((w0 >> 51) & 3),
            },
            TAG_THREAD => Cap::Thread {
                ptr: ((w0 >> 9) & mask(37)) << 11,
                rights: Rights::from_bits((w0 >> 5) as u8),
            },
            TAG_SCHED_CONTEXT => Cap::SchedContext {
                ptr: ((w0 >> 11) & mask(40)) << 8,
                bits: ((w0 >> 5) & 15) as u8,
                binding: Binding::from_code((w0 >> 9) & 3),
            },
            TAG_SCHED_CONTROL => Cap::SchedControl {
                core: (w0 >> 5) as u8,
            },
            TAG_REPLY => Cap::Reply {
                ptr: ((w0 >> 9) & mask(41)) << 7,
                rights: Rights::from_bits((w0 >> 5) as u8),
            },
            TAG_ZOMBIE => Cap::Zombie {
                kind: match (w0 >> 5) & 7 {
                    0 => ZombieKind::CNode {
                        radix: ((w0 >> 8) & 63) as u8,
                    },
                    1 => ZombieKind::AddressSpace,
                    2 => ZombieKind::Thread,
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
            Cap::Endpoint { ptr, binding, .. } => {
                aligned(ptr, ENDPOINT_BITS as u32) && Binding::fits_endpoint(binding)
            }
            Cap::Thread { ptr, .. } => aligned(ptr, THREAD_BITS as u32),
            Cap::SchedContext { ptr, bits, binding } => {
                (MIN_SCHED_CONTEXT_BITS..=MAX_SCHED_CONTEXT_BITS).contains(&bits)
                    && aligned(ptr, bits as u32)
                    && Binding::fits_context(binding)
            }
            Cap::SchedControl { .. } => true,
            Cap::Reply { ptr, .. } => aligned(ptr, REPLY_BITS as u32),
            Cap::Zombie { kind, ptr, n } => match kind {
                ZombieKind::CNode { radix } => {
                    (MIN_RADIX..=MAX_RADIX).contains(&radix)
                        && aligned(ptr, radix as u32 + SLOT_BITS)
                        && n <= 1 << radix
                }
                ZombieKind::AddressSpace => {
                    aligned(ptr, ADDRESS_SPACE_BITS as u32) && n <= RECORD_SLOTS
                }
                ZombieKind::Thread => aligned(ptr, THREAD_BITS as u32) && n <= THREAD_SLOTS,
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
            Cap::Thread { .. } => Kind::Thread,
            Cap::SchedContext { .. } => Kind::SchedContext,
            Cap::SchedControl { .. } => Kind::SchedControl,
            Cap::Reply { .. } => Kind::Reply,
        }
    }

    /// The capability's rights. Untyped, CNode, scheduling-context and
    /// scheduling-control capabilities carry none, as in seL4, and nor does
    /// a zombie.
    pub const fn rights(&self) -> Rights {
        match *self {
            Cap::Frame { rights, .. }
            | Cap::AddressSpace { rights, .. }
            | Cap::Endpoint { rights, .. }
            | Cap::Thread { rights, .. }
            | Cap::Reply { rights, .. } => rights,
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
            Cap::Endpoint {
                ptr,
                rights,
                badge,
                binding,
            } => Cap::Endpoint {
                ptr,
                rights: rights.mask(mask),
                badge,
                binding,
            },
            Cap::Thread { ptr, rights } => Cap::Thread {
                ptr,
                rights: rights.mask(mask),
            },
            Cap::Reply { ptr, rights } => Cap::Reply {
                ptr,
                rights: rights.mask(mask),
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

    /// Whether the capability is a binding the kernel keeps: a frame mapped
    /// in an address space (C11), or a thread's copy of its fault endpoint,
    /// timeout endpoint or scheduling context (C12). Deleting it, or making
    /// it a zombie, runs its unbind hook first.
    pub const fn is_binding(&self) -> bool {
        matches!(
            self,
            Cap::Frame {
                mapping: Some(_),
                ..
            } | Cap::Endpoint {
                binding: Some(_),
                ..
            } | Cap::SchedContext {
                binding: Some(_),
                ..
            }
        )
    }

    /// The role of a thread's copy (module docs), if it is one.
    pub const fn binding(&self) -> Option<Binding> {
        match *self {
            Cap::Endpoint { binding, .. } | Cap::SchedContext { binding, .. } => binding,
            _ => None,
        }
    }

    /// The same capability as a thread's copy in role `role`, or `None` if
    /// the role doesn't fit its kind. Only an endpoint takes the endpoints'
    /// roles, and only a scheduling context the context's.
    pub const fn with_binding(self, role: Binding) -> Option<Cap> {
        match (self, role) {
            (
                Cap::Endpoint {
                    ptr, rights, badge, ..
                },
                Binding::FaultEndpoint | Binding::TimeoutEndpoint,
            ) => Some(Cap::Endpoint {
                ptr,
                rights,
                badge,
                binding: Some(role),
            }),
            (Cap::SchedContext { ptr, bits, .. }, Binding::Context) => Some(Cap::SchedContext {
                ptr,
                bits,
                binding: Some(role),
            }),
            _ => None,
        }
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
            Cap::Thread { ptr, .. } => Some((ptr, 1 << THREAD_BITS)),
            Cap::SchedContext { ptr, bits, .. } => Some((ptr, 1 << bits)),
            // Scheduling control names a core, not memory.
            Cap::SchedControl { .. } => None,
            Cap::Reply { ptr, .. } => Some((ptr, 1 << REPLY_BITS)),
            Cap::Zombie { kind, ptr, .. } => Some((
                ptr,
                match kind {
                    ZombieKind::CNode { radix } => 1 << (radix as u32 + SLOT_BITS),
                    ZombieKind::AddressSpace => 1 << ADDRESS_SPACE_BITS,
                    ZombieKind::Thread => 1 << THREAD_BITS,
                },
            )),
        }
    }

    /// Whether both capabilities name the same object, as seL4's
    /// `sameObjectAs`: the same kind at the same place and size, whatever
    /// their rights, badges, guards or mappings. A zombie is never the same
    /// object as anything: it is always the last capability to its object.
    /// Two scheduling-control capabilities are the same object when they
    /// name the same core.
    pub fn same_object(&self, other: &Cap) -> bool {
        if let (Cap::SchedControl { core: a }, Cap::SchedControl { core: b }) = (self, other) {
            return a == b;
        }
        let same_kind = matches!(
            (self, other),
            (Cap::Untyped { .. }, Cap::Untyped { .. })
                | (Cap::CNode { .. }, Cap::CNode { .. })
                | (Cap::Frame { .. }, Cap::Frame { .. })
                | (Cap::AddressSpace { .. }, Cap::AddressSpace { .. })
                | (Cap::Endpoint { .. }, Cap::Endpoint { .. })
                | (Cap::Thread { .. }, Cap::Thread { .. })
                | (Cap::SchedContext { .. }, Cap::SchedContext { .. })
                | (Cap::Reply { .. }, Cap::Reply { .. })
        );
        same_kind && self.object() == other.object()
    }

    /// Whether the object has slots of its own, and so becomes a zombie
    /// when its last capability is deleted.
    pub const fn has_slots(&self) -> bool {
        matches!(
            self,
            Cap::CNode { .. } | Cap::AddressSpace { .. } | Cap::Thread { .. }
        )
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
            Cap::Thread { ptr, .. } => Some(Cap::Zombie {
                kind: ZombieKind::Thread,
                ptr,
                n: THREAD_SLOTS,
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
/// binding slots its mappings use. A thread's is its first eight slots, of
/// which slot 0 is the park slot ([`THREAD_SLOTS`]).
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
            ZombieKind::Thread => SlotArray {
                base: ptr,
                count: THREAD_SLOTS,
            },
        }
    }

    /// The array of a thread at `ptr`.
    pub const fn of_thread(ptr: u64) -> SlotArray {
        SlotArray::of(ZombieKind::Thread, ptr)
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
