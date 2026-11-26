// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel's capability system (ADR 0049), kept apart from the kernel so
//! that it can be tested on the host.
//!
//! The mechanism is in `docs/design/kernel-specification.md`, sections
//! "Capability spaces and lookup", "Rights by object type", "Derivation and
//! revocation", "Kernel bindings that hold capabilities", "Sessions and
//! badges", "The kernel lock and long operations" and "Capability transfer".
//! It follows seL4 17.0.0 (ADR 0047, rules 1 and 2), with the departures the
//! specification lists under "How far the kernel follows seL4".
//!
//! Nothing here touches hardware. The kernel supplies slot memory through
//! [`slot::Mem`], the work that deleting an object needs through
//! [`delete::Hooks`], and the pending-interrupt check through
//! [`preempt::Pending`]. The crate is `no_std`, has no `unsafe`, allocates
//! nothing, and never panics on its input: a slot that holds no valid
//! capability is reported to [`slot::Mem::corrupt`], which the kernel treats
//! as a bug.
//!
//! - [`rights`]: read, write, grant and grant-reply (ADR 0049, rule 2).
//! - [`cap`]: the capability kinds and their two-word encoding.
//! - [`slot`]: slots, and the memory that holds them.
//! - [`mdb`]: the derivation tree (ADR 0049, rule 4).
//! - [`lookup`]: seL4's guarded lookup (ADR 0049, rule 1).
//! - [`derive`]: what a copy may be.
//! - [`preempt`]: units of work and preemption points (ADR 0052, rule 2).
//! - [`ops`]: copy, mint, mutate, move, retype, bindings and identify.
//! - [`delete`]: complete, preemptible delete and revoke.
//! - [`transfer`]: up to three capabilities per message (ADR 0049, rule 6).
//!
//! Kernel objects carry no IDs (ADR 0050, rule 1): no capability, slot or
//! object here holds one.

#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable
)]

pub mod cap;
pub mod delete;
pub mod derive;
pub mod lookup;
pub mod mdb;
pub mod ops;
pub mod preempt;
pub mod rights;
pub mod slot;
pub mod transfer;

/// The physical address of a capability slot: 32 bytes, aligned to 32.
///
/// Every object that has slots is made from RAM, so the kernel reaches every
/// slot through its direct map.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotRef(pub u64);

impl SlotRef {
    /// The slot `index` slots past this one.
    pub const fn offset(self, index: u64) -> SlotRef {
        SlotRef(self.0 + (index << SLOT_BITS))
    }
}

/// log2 of a slot's size: 32 bytes, four words, as seL4's `cte_t` on AArch64.
pub const SLOT_BITS: u32 = kmem::untyped::SLOT_BITS as u32;
/// A slot's size in bytes.
pub const SLOT_SIZE: u64 = 1 << SLOT_BITS;
/// Units of work between checks for a pending interrupt: seL4's default,
/// `CONFIG_MAX_NUM_WORK_UNITS_PER_PREEMPTION` (kernel specification K22).
pub const UNITS_PER_CHECK: u32 = 100;
/// The most objects one retype makes: seL4's default
/// `CONFIG_RETYPE_FAN_OUT_LIMIT`.
pub const RETYPE_FAN_OUT: u64 = 256;
