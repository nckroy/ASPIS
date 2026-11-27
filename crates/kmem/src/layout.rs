// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The virtual layout (ADR 0048, rule 4; kernel specification, "Address-space
//! layout").
//!
//! Both halves are 48 bits with 4 KiB granules. The lower half, below
//! [`USER_TOP`], belongs to user space. The kernel's half starts at
//! [`UPPER_HALF_BASE`]:
//!
//! | VA | Holds |
//! |---|---|
//! | [`DIRECT_MAP_BASE`] + PA | The direct map, for PA below [`DIRECT_MAP_PA_LIMIT`] |
//! | [`KERNEL_BASE`] | The kernel image, at most [`KERNEL_MAX_SIZE`] |
//! | [`DEVICE_WINDOW_BASE`] | The device window, [`DEVICE_WINDOW_SIZE`] |
//! | [`PERCORE_WINDOW_BASE`] | The per-core window: a [`PERCORE_SLOT`] for each core |

/// The first address of the kernel's half (`TTBR1_EL1`, T1SZ = 16).
pub const UPPER_HALF_BASE: u64 = 0xffff_0000_0000_0000;

/// The end of the lower half (`TTBR0_EL1`, T0SZ = 16), which is user space's.
pub const USER_TOP: u64 = 1 << 48;

/// The base of the direct map: physical address `pa` is at
/// `DIRECT_MAP_BASE + pa`. It takes the first half of the kernel's half, L0
/// indices 0 to 255.
pub const DIRECT_MAP_BASE: u64 = UPPER_HALF_BASE;

/// The direct map reaches physical addresses below this, 128 TiB. RAM above
/// it isn't used.
pub const DIRECT_MAP_PA_LIMIT: u64 = 1 << 47;

/// The kernel image's base, which C05 fixed and `kernel/link.ld` links at.
pub const KERNEL_BASE: u64 = 0xffff_8000_0000_0000;

/// The most the kernel image may take, as `kernel/link.ld` asserts.
pub const KERNEL_MAX_SIZE: u64 = 32 << 20;

/// The device window: the UART, the boot framebuffer and, from C13a, the
/// interrupt controller's frames. It is never part of the direct map.
pub const DEVICE_WINDOW_BASE: u64 = KERNEL_BASE + (1 << 30);

/// The device window's size, 1 GiB.
pub const DEVICE_WINDOW_SIZE: u64 = 1 << 30;

/// The per-core window (C12), right above the device window: core `i`'s
/// slot starts at `PERCORE_WINDOW_BASE + i * PERCORE_SLOT`. Each slot holds
/// the core's entry stack, above an unmapped guard, and its scheduler data
/// at the stack's top; the rest of the slot stays unmapped.
pub const PERCORE_WINDOW_BASE: u64 = DEVICE_WINDOW_BASE + DEVICE_WINDOW_SIZE;

/// Each core's slot in the per-core window, 256 KiB.
pub const PERCORE_SLOT: u64 = 256 << 10;

/// The physical address size the processor reports, from
/// `ID_AA64MMFR0_EL1.PARange`, capped at 48 bits: the kernel doesn't use
/// 52-bit addresses. An encoding this crate doesn't know is newer and so
/// larger, so it is taken as 48.
pub const fn pa_bits(parange: u8) -> u8 {
    match parange {
        0 => 32,
        1 => 36,
        2 => 40,
        3 => 42,
        4 => 44,
        _ => 48,
    }
}

/// The direct-map address of physical address `pa`, if the direct map can
/// reach it. Whether it does map `pa` depends on the memory map.
pub const fn direct_va(pa: u64) -> Option<u64> {
    if pa < DIRECT_MAP_PA_LIMIT {
        Some(DIRECT_MAP_BASE + pa)
    } else {
        None
    }
}

/// The physical address behind direct-map address `va`.
pub const fn direct_pa(va: u64) -> Option<u64> {
    if va >= DIRECT_MAP_BASE && va - DIRECT_MAP_BASE < DIRECT_MAP_PA_LIMIT {
        Some(va - DIRECT_MAP_BASE)
    } else {
        None
    }
}
