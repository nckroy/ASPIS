// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! seL4's guarded lookup (ADR 0049, rule 1; kernel specification,
//! "Capability spaces and lookup").
//!
//! A capability address is a 64-bit word, read from its high end. Lookup
//! starts at a root CNode capability. At each CNode it consumes the guard
//! that the CNode capability carries, then `radix` bits of index, as seL4's
//! `resolveAddressBits` does. Each level consumes at least one bit, since a
//! radix is at least 1, so lookup takes at most 64 levels, even through a
//! CNode that holds a capability to itself.
//!
//! There are two modes, as in seL4:
//!
//! - a **slot lookup** names a slot for a CNode operation, with an explicit
//!   depth that must be used up exactly ([`lookup_slot`]);
//! - a **capability lookup** names a capability to invoke, with depth 64,
//!   and stops at the first capability that isn't a CNode ([`lookup_cap`]).
//!
//! The error names are internal until K30 settles the ABI's.

use crate::SlotRef;
use crate::cap::Cap;
use crate::slot::{self, Mem};

/// Why a lookup failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupError {
    /// The root isn't a CNode capability.
    InvalidRoot,
    /// A depth outside 1 to 64.
    BadDepth,
    /// The address's bits don't match a CNode's guard, or the guard is
    /// longer than the bits left.
    GuardMismatch { bits_left: u32 },
    /// The bits ran out partway through a level, or a slot lookup ended at a
    /// capability that isn't a CNode with bits still to resolve.
    DepthMismatch { bits_left: u32 },
    /// A capability lookup found an empty slot.
    MissingCapability,
}

const fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1 << bits) - 1
    }
}

/// The `bits` bits of `addr` that end `below` bits from its low end, when
/// `below + bits <= 64`. Every shift is checked, so a shift of 64 is zero.
fn field(addr: u64, below: u32, bits: u32) -> u64 {
    addr.checked_shr(below).unwrap_or(0) & mask(bits)
}

/// Resolves the low `depth` bits of `addr` from `root`: the slot reached,
/// and how many bits are left when it stopped at a capability that isn't a
/// CNode.
pub fn resolve<M: Mem>(
    mem: &M,
    root: Cap,
    addr: u64,
    depth: u32,
) -> Result<(SlotRef, u32), LookupError> {
    let mut node = root;
    let mut bits = depth;
    loop {
        let Cap::CNode {
            ptr,
            radix,
            guard_size,
            guard,
        } = node
        else {
            return Err(LookupError::InvalidRoot);
        };
        let (radix, guard_size) = (radix as u32, guard_size as u32);
        let level = radix + guard_size;
        // The guard first, then the index, as seL4.
        if guard_size > bits || field(addr, bits - guard_size, guard_size) != guard {
            return Err(LookupError::GuardMismatch { bits_left: bits });
        }
        if level > bits {
            return Err(LookupError::DepthMismatch { bits_left: bits });
        }
        let index = field(addr, bits - level, radix);
        let s = SlotRef(ptr).offset(index);
        bits -= level;
        if bits == 0 {
            return Ok((s, 0));
        }
        let next = slot::cap(mem, s);
        if !matches!(next, Cap::CNode { .. }) {
            return Ok((s, bits));
        }
        node = next;
    }
}

/// The slot that `addr` names at exactly `depth` bits, for a CNode
/// operation, as seL4's `lookupSlotForCNodeOp`.
pub fn lookup_slot<M: Mem>(
    mem: &M,
    root: Cap,
    addr: u64,
    depth: u32,
) -> Result<SlotRef, LookupError> {
    if !(1..=64).contains(&depth) {
        return Err(LookupError::BadDepth);
    }
    match resolve(mem, root, addr, depth)? {
        (s, 0) => Ok(s),
        (_, bits_left) => Err(LookupError::DepthMismatch { bits_left }),
    }
}

/// The capability that `addr` names, for an invocation: lookup with depth
/// 64, stopping at the first capability that isn't a CNode, as seL4's
/// `lookupCapAndSlot`.
pub fn lookup_cap<M: Mem>(mem: &M, root: Cap, addr: u64) -> Result<(SlotRef, Cap), LookupError> {
    let (s, _) = resolve(mem, root, addr, 64)?;
    match slot::cap(mem, s) {
        Cap::Null => Err(LookupError::MissingCapability),
        cap => Ok((s, cap)),
    }
}
