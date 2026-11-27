// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The kernel's software-generated interrupts (ADR 0052, rule 4; kernel
//! specification, "Cross-core signals and TLB maintenance", K26) and the
//! register values that send them.
//!
//! The numbers are seL4 17.0.0's, plus one: SGI 0 for remote calls and SGI
//! 1 for rescheduling (`irq_remote_call_ipi` and `irq_reschedule_ipi`), and
//! SGI 2 for the panic stop, the next free number, which is also Linux's
//! `IPI_CPU_STOP`. All three are in the range Arm recommends for the
//! non-secure world, 0 to 7. SGIs 3 to 15 are never sent.

use crate::affinity::Affinity;
use crate::intid::Intid;
use crate::regs::gicd;

/// An SGI the kernel uses. No other code names a raw SGI number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Sgi {
    /// Run a request from another core, such as stopping a thread there
    /// before its state changes (seL4's `remoteTCBStall`).
    RemoteCall = 0,
    /// Pick the next thread to run.
    Reschedule = 1,
    /// Stop: another core panicked.
    Stop = 2,
}

impl Sgi {
    /// Every SGI the kernel uses.
    pub const ALL: [Sgi; 3] = [Sgi::RemoteCall, Sgi::Reschedule, Sgi::Stop];

    /// The bits of SGIs 0 to 15 that the kernel enables: one per [`Sgi`].
    pub const ENABLED_MASK: u32 = 0b111;

    pub const fn intid(self) -> Intid {
        Intid(self as u32)
    }

    /// The SGI with INTID `intid`, if the kernel uses it.
    pub const fn from_intid(intid: Intid) -> Option<Sgi> {
        match intid.0 {
            0 => Some(Sgi::RemoteCall),
            1 => Some(Sgi::Reschedule),
            2 => Some(Sgi::Stop),
            _ => None,
        }
    }
}

/// Why an SGI can't be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SgiError {
    /// A GICv2 target list with no core in it.
    EmptyList,
    /// A GICv3 target whose Aff0 is 16 or more, on a CPU interface without
    /// `ICC_CTLR_EL1.RSS`, which can't reach it.
    NeedsRss,
    /// A GICv2 core mask with more than one bit set: an `ITARGETSR0` value
    /// no single core reads.
    BadMask,
}

/// Whom a GICv2 SGI goes to (`GICD_SGIR.TargetListFilter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V2Target {
    /// The cores whose CPU-interface bits are set (filter 0).
    List(u8),
    /// Every core but the sender (filter 1).
    AllButSelf,
    /// The sender alone (filter 2).
    SelfOnly,
}

/// The `GICD_SGIR` value that sends `sgi` to `target`: `TargetListFilter`
/// in 25:24, `CPUTargetList` in 23:16, and the INTID in 3:0. `NSATT` (bit
/// 15) stays 0; only a secure write can set it.
pub const fn gicd_sgir(sgi: Sgi, target: V2Target) -> Result<u32, SgiError> {
    let (filter, list) = match target {
        V2Target::List(0) => return Err(SgiError::EmptyList),
        V2Target::List(mask) => (0, mask as u32),
        V2Target::AllButSelf => (1, 0),
        V2Target::SelfOnly => (2, 0),
    };
    Ok(filter << gicd::SGIR_FILTER_SHIFT | list << gicd::SGIR_TARGETS_SHIFT | sgi as u32)
}

/// Whom a GICv3 SGI goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V3Target {
    /// The core with this affinity.
    Core(Affinity),
    /// Every core but the sender (`IRM` = 1).
    AllButSelf,
}

/// `ICC_SGI1R_EL1.IRM`, bit 40.
pub const SGI1R_IRM: u64 = 1 << 40;

/// The `ICC_SGI1R_EL1` value that sends `sgi` to `target` as a Group 1
/// interrupt: Aff3 in 55:48, `RS` in 47:44, `IRM` in 40, Aff2 in 39:32,
/// the INTID in 27:24, Aff1 in 23:16 and the target list in 15:0. A core
/// is bit Aff0 mod 16 of the list, in range `RS` = Aff0 / 16, which needs
/// `rss` (`ICC_CTLR_EL1.RSS`) when Aff0 is 16 or more.
pub const fn icc_sgi1r(sgi: Sgi, target: V3Target, rss: bool) -> Result<u64, SgiError> {
    let intid = (sgi as u64) << 24;
    match target {
        V3Target::AllButSelf => Ok(SGI1R_IRM | intid),
        V3Target::Core(a) => {
            if a.aff0 >= 16 && !rss {
                return Err(SgiError::NeedsRss);
            }
            Ok((a.aff3 as u64) << 48
                | ((a.aff0 / 16) as u64) << 44
                | (a.aff2 as u64) << 32
                | intid
                | (a.aff1 as u64) << 16
                | 1 << (a.aff0 % 16))
        }
    }
}

/// This core's GICv2 CPU-interface mask, from its `GICD_ITARGETSR0` (bits
/// 7:0 are SGI 0's targets, which read as the reading core's own bit).
/// `None` means the GIC is uniprocessor: `ITARGETSR` reads as zero there,
/// and the kernel sends SGIs to itself with [`V2Target::SelfOnly`].
pub const fn v2_cpu_mask(itargetsr0: u32) -> Result<Option<u8>, SgiError> {
    let mask = itargetsr0 as u8;
    match mask.count_ones() {
        0 => Ok(None),
        1 => Ok(Some(mask)),
        _ => Err(SgiError::BadMask),
    }
}
