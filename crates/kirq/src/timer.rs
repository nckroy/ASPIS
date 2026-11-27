// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The EL1 virtual timer's pure parts (ADR 0051, rules 4 and 5; kernel
//! specification, "The timer and deadlines"): the compare value that arms
//! nothing, how the device tree names the timer's interrupt, and what a
//! `CNTV_CTL_EL0` value says.
//!
//! The kernel's clock is the virtual count itself, in counts of
//! `CNTFRQ_EL0`. The kernel holds no nanoseconds or microseconds: the
//! kernel interface library converts nanoseconds (C17, K19), and C12 owns
//! the arithmetic for its budgets and periods.

use crate::dt::{DtError, gic_specifier};
use crate::intid::Intid;
use crate::regs::cntv_ctl;

/// The value `CNTV_CVAL_EL0` holds when nothing is armed: no count the
/// clock reaches in the life of a node (at 1 GHz, `u64::MAX` counts is over
/// 500 years). It is a compare-register value, not an encoding of "no
/// deadline": the call header's is 0 (ADR 0064, rule 5), and how the
/// kernel interface encodes it is still open (K19).
pub const CVAL_DISARMED: u64 = u64::MAX;

/// The device-tree timer nodes the kernel reads, by `compatible` (the Linux
/// binding `arm,arch_timer.yaml`).
pub const COMPATIBLE: &[&str] = &["arm,armv8-timer", "arm,armv7-timer"];

/// The index of the virtual timer's entry in the timer node's `interrupts`:
/// the binding lists the secure physical, non-secure physical, virtual and
/// hypervisor physical timers, in that order.
pub const VIRTUAL_INDEX: usize = 2;

/// Why the timer node's interrupt can't be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerError {
    /// The `interrupts` property, or the GIC's `#interrupt-cells`, can't be
    /// decoded.
    Dt(DtError),
    /// The virtual timer's entry isn't a private peripheral interrupt.
    NotPpi(Intid),
}

impl core::fmt::Display for TimerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Dt(e) => write!(f, "its interrupts can't be read: {e:?}"),
            Self::NotPpi(i) => write!(
                f,
                "its virtual timer is INTID {}, not a private peripheral interrupt",
                i.0
            ),
        }
    }
}

/// The virtual timer's INTID, from the timer node's raw `interrupts` and
/// its GIC parent's `#interrupt-cells`. The flags cell isn't used: a PPI's
/// trigger is implementation defined, and the Pi 4's device tree says
/// level-low, which a GIC can't express.
pub fn virtual_intid(interrupts: &[u8], interrupt_cells: u32) -> Result<Intid, TimerError> {
    let s = gic_specifier(interrupts, interrupt_cells, VIRTUAL_INDEX).map_err(TimerError::Dt)?;
    if !s.intid.is_ppi() {
        return Err(TimerError::NotPpi(s.intid));
    }
    Ok(s.intid)
}

/// Whether a `CNTV_CTL_EL0` value says the timer asserts its interrupt:
/// enabled, its interrupt not masked, and its condition met (the count has
/// reached the compare value).
pub const fn asserts(ctl: u64) -> bool {
    ctl & (cntv_ctl::ENABLE | cntv_ctl::IMASK | cntv_ctl::ISTATUS)
        == cntv_ctl::ENABLE | cntv_ctl::ISTATUS
}
