// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel's interrupt-controller and timer logic, kept apart from the
//! kernel so that it can be tested on the host.
//!
//! The mechanism is in `docs/design/kernel-specification.md`, sections
//! "The kernel's interrupt controller", "The timer and deadlines" and
//! "Cross-core signals and TLB maintenance". It serves ADR 0007's two GIC
//! versions (GICv2, the Pi 4's GIC-400, and GICv3), ADR 0052, rule 4's
//! software-generated interrupts, and ADR 0055's interrupt objects, which
//! build on it in C13b.
//!
//! Nothing here touches hardware. The kernel does the MMIO and the system
//! register accesses; this crate gives it register offsets and bits, the
//! layout of the device tree's GIC node, the redistributor walk (with the
//! register reads passed in), the encodings of the SGI registers, the
//! classification of an acknowledged interrupt, and the virtual timer's
//! interrupt. The crate is `no_std`, has
//! no `unsafe`, allocates nothing, and never panics on its input.
//!
//! - [`intid`]: interrupt IDs and their ranges.
//! - [`affinity`]: a core's MPIDR affinity, in each register's form.
//! - [`regs`]: register offsets and bits of the GICv2 and GICv3.
//! - [`dt`]: decoding the device tree's GIC specifiers and cpu nodes.
//! - [`layout`]: which `reg` entry of the GIC node is which frame.
//! - [`redist`]: finding a core's GICv3 redistributor.
//! - [`sgi`]: the kernel's SGIs (K26) and how each GIC sends them.
//! - [`dispatch`]: what the kernel does with an acknowledged interrupt.
//! - [`timer`]: the virtual timer's interrupt and compare value.

#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreachable
)]

pub mod affinity;
pub mod dispatch;
pub mod dt;
pub mod intid;
pub mod layout;
pub mod redist;
pub mod regs;
pub mod sgi;
pub mod timer;

/// The most cores the kernel's core table holds. It covers QEMU's test
/// matrix (1, 4 and 8 cores, ADR 0036, rule 4) and the Pi 4's 4. C12 keeps
/// it as the kernel's core bound: the per-core window, the ASID allocator
/// and `ksched`'s lock are sized by it, and the kernel checks they agree.
pub const MAX_CORES: usize = 8;

/// The one priority the kernel gives every interrupt it enables: Linux's
/// `GICD_INT_DEF_PRI`. The kernel never nests interrupts, so none needs a
/// priority above another (kernel specification, "The kernel's interrupt
/// controller").
pub const PRIORITY: u8 = 0xa0;

/// The priority mask: interrupts of a higher priority (a lower value) than
/// this are signaled. Linux's `DEFAULT_PMR_VALUE`.
pub const PRIORITY_MASK: u8 = 0xf0;
