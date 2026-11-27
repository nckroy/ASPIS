// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Calls to the firmware's PSCI (Arm DEN 0022, PSCI 1.3; SMC Calling
//! Convention, Arm DEN 0028). The function IDs and the decoding of their
//! results are `ksched::smp::psci`'s, tested on the host.

use core::arch::asm;
use ksched::smp::psci::Conduit;

/// Calls PSCI function `fid` with arguments `a1` to `a3` through `conduit`,
/// and returns x0. The SMC Calling Convention from 1.1 keeps x4 to x17;
/// 1.0 may not, so the call takes them all as clobbered.
pub fn call(conduit: Conduit, fid: u32, a1: u64, a2: u64, a3: u64) -> u64 {
    let mut x0 = fid as u64;
    match conduit {
        // SAFETY: an SMCCC call to the hypervisor's PSCI: it returns to the
        // next instruction with x0 set, and touches no kernel memory.
        Conduit::Hvc => unsafe {
            asm!(
                "hvc #0",
                inout("x0") x0,
                inout("x1") a1 => _,
                inout("x2") a2 => _,
                inout("x3") a3 => _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _,
                out("x8") _, out("x9") _, out("x10") _, out("x11") _,
                out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                options(nostack),
            )
        },
        // SAFETY: as above, to the secure monitor's PSCI.
        Conduit::Smc => unsafe {
            asm!(
                "smc #0",
                inout("x0") x0,
                inout("x1") a1 => _,
                inout("x2") a2 => _,
                inout("x3") a3 => _,
                out("x4") _, out("x5") _, out("x6") _, out("x7") _,
                out("x8") _, out("x9") _, out("x10") _, out("x11") _,
                out("x12") _, out("x13") _, out("x14") _, out("x15") _,
                out("x16") _, out("x17") _,
                options(nostack),
            )
        },
    }
    x0
}
