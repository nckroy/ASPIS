// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! What the kernel does with an interrupt it acknowledged (kernel
//! specification, "The kernel's interrupt controller"). It takes one
//! interrupt per entry, as seL4's `getActiveIRQ` does.

use crate::intid::Intid;
use crate::sgi::Sgi;

/// The action for one acknowledged interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// INTIDs 1020 to 1023: nothing was acknowledged, so there is no end of
    /// interrupt to write.
    Spurious,
    /// SGI 0.
    RemoteCall,
    /// SGI 1.
    Reschedule,
    /// SGI 2: another core panicked.
    Stop,
    /// The virtual timer's PPI.
    Timer,
    /// Any other interrupt below the distributor's lines: the kernel has no
    /// use or handler for it, so it is disabled and logged, as seL4 masks
    /// an interrupt with no bound notification. C13b gives SPIs handlers.
    Unclaimed(Intid),
    /// An INTID at or above the distributor's lines that isn't special: an
    /// extended PPI or SPI (GICv3.1), or an LPI. The kernel disables these
    /// at setup and enables none, so one arriving is firmware's or the
    /// hardware's doing. The per-line register arrays don't cover it, so it
    /// is counted, logged once and ended, and no enable register is
    /// written for it.
    Extended(Intid),
}

/// The action for `intid`, given the virtual timer's INTID, if the kernel
/// has armed the timer, and the distributor's lines ([`crate::regs::lines`]).
pub fn classify(intid: Intid, timer: Option<Intid>, lines: u32) -> Action {
    if intid.is_special() {
        return Action::Spurious;
    }
    if intid.0 >= lines {
        return Action::Extended(intid);
    }
    if Some(intid) == timer {
        return Action::Timer;
    }
    match Sgi::from_intid(intid) {
        Some(Sgi::RemoteCall) => Action::RemoteCall,
        Some(Sgi::Reschedule) => Action::Reschedule,
        Some(Sgi::Stop) => Action::Stop,
        None => Action::Unclaimed(intid),
    }
}
