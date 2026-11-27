// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Priorities and maximum controlled priorities (ADR 0051, rule 2; kernel
//! specification, "Priorities and bands").
//!
//! Priorities run from 0 to 255, and 255 is the highest, so a `u8` holds
//! every one. As in seL4, setting a thread's priority or its maximum
//! controlled priority (MCP) names an authority thread, and the value can't
//! exceed the authority's MCP.

/// The number of priorities.
pub const LEVELS: usize = 256;

/// Whether an authority with MCP `auth_mcp` may set a priority, or an MCP,
/// to `value`: seL4's `checkPrio`.
pub const fn may_set(auth_mcp: u8, value: u8) -> bool {
    value <= auth_mcp
}

/// The default bands (K16). A convention for the root server's boot
/// manifest and the process manager: the kernel doesn't enforce it. ADR
/// 0051, rule 2 fixes their order; these ranges are the kernel
/// specification's. A shared server called from a higher band runs at that
/// band's priority (ADR 0051, rule 3), which the convention allows.
pub mod band {
    use core::ops::RangeInclusive;

    /// Interrupt-handling threads in drivers.
    pub const DRIVER_INTERRUPTS: RangeInclusive<u8> = 192..=255;
    /// Pagers and the display path.
    pub const PAGERS_AND_DISPLAY: RangeInclusive<u8> = 128..=191;
    /// System servers.
    pub const SYSTEM_SERVERS: RangeInclusive<u8> = 64..=127;
    /// Applications.
    pub const APPLICATIONS: RangeInclusive<u8> = 0..=63;
}
