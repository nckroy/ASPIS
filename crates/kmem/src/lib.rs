// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The pure parts of the kernel's memory management (ADR 0048), kept apart
//! from the kernel so that they can be tested on the host.
//!
//! The mechanism is in `docs/design/kernel-specification.md`, sections "Boot
//! memory", "Untyped memory and kernel records", "Address-space layout",
//! "Access to user memory" and "Cross-core signals and TLB maintenance".
//!
//! Nothing here touches hardware. The kernel supplies physical memory through
//! [`table::PhysMem`] and [`user::Bytes`], page-table frames through
//! [`table::FrameSource`], and issues every barrier and TLB maintenance
//! instruction itself. The crate is `no_std`, allocates nothing, and never
//! panics on its input.
//!
//! - [`layout`]: the virtual layout of the kernel's half.
//! - [`desc`]: translation-table descriptors, and W^X (ADR 0048, rule 6).
//! - [`table`]: building, walking and unmapping translation tables.
//! - [`ranges`]: sets of physical address ranges.
//! - [`memmap`]: dividing the boot memory map (ADR 0048, rule 1).
//! - [`boot_alloc`]: the boot-time page source, sealed after boot.
//! - [`untyped`]: untyped memory and retype, as in seL4.
//! - [`asid`]: ASIDs by generation rollover (ADR 0048, rule 4).
//! - [`user`]: reaching user memory by a software walk (ADR 0048, rule 5).

#![no_std]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable
)]

pub mod asid;
pub mod boot_alloc;
pub mod desc;
pub mod layout;
pub mod memmap;
pub mod ranges;
pub mod table;
pub mod untyped;
pub mod user;

/// log2 of the page size: the granule is 4 KiB everywhere (ADR 0048, rule 3).
pub const PAGE_SHIFT: u32 = 12;
/// The page size, 4 KiB.
pub const PAGE_SIZE: u64 = 1 << PAGE_SHIFT;
/// The size of a level-2 block mapping, 2 MiB.
pub const BLOCK_2M: u64 = 1 << 21;
/// The size of a level-1 block mapping, 1 GiB.
pub const BLOCK_1G: u64 = 1 << 30;
/// Descriptors in one translation table.
pub const ENTRIES: usize = 512;

/// Rounds `x` down to a multiple of `align`, a power of two.
pub const fn align_down(x: u64, align: u64) -> u64 {
    x & !(align - 1)
}

/// Rounds `x` up to a multiple of `align`, a power of two, or `None` if that
/// overflows.
pub const fn align_up(x: u64, align: u64) -> Option<u64> {
    match x.checked_add(align - 1) {
        Some(v) => Some(v & !(align - 1)),
        None => None,
    }
}
