// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The other cores (ADR 0052; kernel specification, "SMP").
//!
//! - [`init`] finds the firmware's PSCI, which starts the other cores (ADR
//!   0052, rule 1) and, from C72, resets and powers off the machine (ADR
//!   0039, rule 3). Without a usable PSCI the kernel goes on with the boot
//!   core alone (K21).
//! - [`start`] brings the other cores up through `CPU_ON`.
//! - [`lock`] is the kernel lock, with the coalesced reschedule SGIs at its
//!   release.
//! - [`remote`] holds remote calls and the panic stop's flag.

pub mod lock;
pub mod psci;
pub mod remote;
pub mod start;
#[cfg(aspis_test_build)]
mod tests;

pub use start::{is_online, online_count, start_secondaries};

use crate::mm::BootCell;
use ksched::smp::psci::{Absent, Conduit};

/// The firmware's PSCI, as [`init`] found it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Psci {
    pub conduit: Conduit,
    /// `PSCI_VERSION`: major and minor.
    pub version: (u16, u16),
}

static PSCI: BootCell<Option<Psci>> = BootCell::new(None);

/// The firmware's PSCI, if it has a usable one: the bring-up of the other
/// cores uses it, and C72's reset and power-off will.
pub fn psci() -> Option<Psci> {
    // SAFETY: written once by `init`, on the boot core, before anything
    // reads it.
    unsafe { *PSCI.get() }
}

/// Finds the firmware's PSCI in the device tree, and logs what it found
/// (K21). Runs once, on the boot core, after the scheduler's setup.
pub fn init(fdt: Option<&fdt::Fdt<'_>>) {
    match find(fdt) {
        Ok(p) => {
            // SAFETY: once, at boot, before any reader.
            unsafe { *PSCI.get_mut() = Some(p) };
            crate::klog!(
                Info,
                "smp",
                "PSCI {}.{} through {}",
                p.version.0,
                p.version.1,
                match p.conduit {
                    Conduit::Hvc => "HVC",
                    Conduit::Smc => "SMC",
                }
            );
        }
        Err(why) => crate::klog!(
            Warning,
            "smp",
            "no usable PSCI ({}): the other cores stay off, and a reset or power-off halts instead",
            match why {
                Absent::NoNode => "no psci node",
                Absent::Method => "its method is neither hvc nor smc",
                Absent::Compatible => "PSCI 0.1 isn't supported",
                Absent::Version => "PSCI_VERSION is below 0.2",
            }
        ),
    }
}

/// The `psci` node's conduit, then `PSCI_VERSION` through it (K21).
fn find(fdt: Option<&fdt::Fdt<'_>>) -> Result<Psci, Absent> {
    let node = fdt
        .and_then(|f| f.find_compatible(&["arm,psci-1.0", "arm,psci-0.2", "arm,psci"]))
        .ok_or(Absent::NoNode)?;
    let method = node.property("method").map(|p| p.value);
    let compatible = node.property("compatible").map(|p| p.value);
    let conduit = ksched::smp::psci::conduit(method, compatible)?;
    let v = psci::call(conduit, ksched::smp::psci::VERSION, 0, 0, 0);
    if !ksched::smp::psci::version_ok(v) {
        return Err(Absent::Version);
    }
    Ok(Psci {
        conduit,
        version: ksched::smp::psci::version(v),
    })
}
