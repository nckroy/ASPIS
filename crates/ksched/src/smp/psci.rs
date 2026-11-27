// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! PSCI: finding it, its function IDs and its return codes (ADR 0052,
//! rule 1; kernel specification, "Starting secondary cores"; K21).
//!
//! The Power State Coordination Interface is Arm DEN 0022. ASPIS uses only
//! functions PSCI 0.2 already defines, with the SMC64 IDs where both exist;
//! the kernel specification cites the document's newest issue (stage 3). The parsing here works on the raw bytes of
//! device-tree properties, as kirq's does, so it is tested on the host.
//!
//! **No PSCI** (K21) means any of: no `psci` node; a `method` that isn't
//! `hvc` or `smc`; a `compatible` list without `arm,psci-0.2` or
//! `arm,psci-1.0` (PSCI 0.1's own function IDs aren't supported); or a
//! `PSCI_VERSION` below 0.2. Then the secondary cores stay off.

/// `PSCI_VERSION`.
pub const VERSION: u32 = 0x8400_0000;
/// `CPU_OFF` (C72).
pub const CPU_OFF: u32 = 0x8400_0002;
/// `CPU_ON`, SMC64.
pub const CPU_ON: u32 = 0xC400_0003;
/// `AFFINITY_INFO`, SMC64.
pub const AFFINITY_INFO: u32 = 0xC400_0004;
/// `SYSTEM_OFF`.
pub const SYSTEM_OFF: u32 = 0x8400_0008;
/// `SYSTEM_RESET`.
pub const SYSTEM_RESET: u32 = 0x8400_0009;

/// How the kernel calls the firmware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conduit {
    /// `hvc #0`: a hypervisor, as on QEMU without EL2 firmware.
    Hvc,
    /// `smc #0`: the secure monitor, as TF-A on the Pi 4.
    Smc,
}

/// Why the kernel finds no usable PSCI (K21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Absent {
    /// No `psci` node.
    NoNode,
    /// A `method` that isn't `hvc` or `smc`.
    Method,
    /// No `arm,psci-0.2` or `arm,psci-1.0` in `compatible`.
    Compatible,
    /// `PSCI_VERSION` below 0.2.
    Version,
}

/// A PSCI return code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Success,
    NotSupported,
    InvalidParameters,
    Denied,
    AlreadyOn,
    OnPending,
    InternalFailure,
    NotPresent,
    Disabled,
    InvalidAddress,
    /// A code the specification doesn't define.
    Unknown(i32),
}

impl Status {
    /// Decodes the low 32 bits of `x0` after a call.
    pub const fn decode(x0: u64) -> Status {
        match x0 as u32 as i32 {
            0 => Status::Success,
            -1 => Status::NotSupported,
            -2 => Status::InvalidParameters,
            -3 => Status::Denied,
            -4 => Status::AlreadyOn,
            -5 => Status::OnPending,
            -6 => Status::InternalFailure,
            -7 => Status::NotPresent,
            -8 => Status::Disabled,
            -9 => Status::InvalidAddress,
            c => Status::Unknown(c),
        }
    }
}

/// The NUL-terminated strings of a device-tree string list.
pub fn strings(prop: &[u8]) -> impl Iterator<Item = &[u8]> {
    prop.split(|&b| b == 0).filter(|s| !s.is_empty())
}

/// Whether a string list holds `want`.
pub fn has_string(prop: &[u8], want: &[u8]) -> bool {
    strings(prop).any(|s| s == want)
}

/// The conduit, from the `psci` node's `method` and `compatible`. The node
/// is absent when both are None.
pub fn conduit(method: Option<&[u8]>, compatible: Option<&[u8]>) -> Result<Conduit, Absent> {
    let (Some(method), Some(compatible)) = (method, compatible) else {
        return Err(Absent::NoNode);
    };
    if !(has_string(compatible, b"arm,psci-0.2") || has_string(compatible, b"arm,psci-1.0")) {
        return Err(Absent::Compatible);
    }
    match strings(method).next() {
        Some(b"hvc") => Ok(Conduit::Hvc),
        Some(b"smc") => Ok(Conduit::Smc),
        _ => Err(Absent::Method),
    }
}

/// `PSCI_VERSION`'s result: (major, minor).
pub const fn version(x0: u64) -> (u16, u16) {
    let v = x0 as u32;
    ((v >> 16) as u16, v as u16)
}

/// Whether a version is 0.2 or later. A version's bit 31 is zero: a
/// negative result, such as `NOT_SUPPORTED` from firmware without PSCI, is
/// an error code, not a version (DEN 0022, `PSCI_VERSION`).
pub const fn version_ok(x0: u64) -> bool {
    if (x0 as u32 as i32) < 0 {
        return false;
    }
    let (major, minor) = version(x0);
    major > 0 || minor >= 2
}

/// Whether a `cpu` node's `enable-method` is `psci`. A core without it is
/// left off, and the kernel logs that.
pub fn enabled_by_psci(enable_method: Option<&[u8]>) -> bool {
    enable_method.is_some_and(|m| has_string(m, b"psci"))
}
