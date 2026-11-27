// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Finding PSCI from device-tree properties (K21), and its codes.

use ksched::smp::psci::{self, Absent, Conduit, Status};

#[test]
fn qemu_virt_node() {
    // QEMU's own property: three strings.
    let compatible = b"arm,psci-1.0\0arm,psci-0.2\0arm,psci\0";
    assert_eq!(
        psci::conduit(Some(b"hvc\0"), Some(compatible)),
        Ok(Conduit::Hvc)
    );
    assert_eq!(
        psci::conduit(Some(b"smc\0"), Some(compatible)),
        Ok(Conduit::Smc)
    );
}

#[test]
fn pi4_node() {
    // The Pi 4's TF-A device tree: PSCI 1.0 alone, through the monitor.
    assert_eq!(
        psci::conduit(Some(b"smc\0"), Some(b"arm,psci-1.0\0")),
        Ok(Conduit::Smc)
    );
}

#[test]
fn no_psci() {
    assert_eq!(psci::conduit(None, None), Err(Absent::NoNode));
    assert_eq!(
        psci::conduit(Some(b"hvc\0"), Some(b"arm,psci\0")),
        Err(Absent::Compatible)
    );
    assert_eq!(
        psci::conduit(Some(b"spin\0"), Some(b"arm,psci-0.2\0")),
        Err(Absent::Method)
    );
    // A string that only starts like one isn't it.
    assert_eq!(
        psci::conduit(Some(b"hvc\0"), Some(b"arm,psci-0.20\0")),
        Err(Absent::Compatible)
    );
}

#[test]
fn versions_and_codes() {
    assert!(psci::version_ok(0x0001_0000));
    assert!(psci::version_ok(0x0000_0002));
    assert!(!psci::version_ok(0x0000_0001));
    // NOT_SUPPORTED, as a 32-bit and as a 64-bit result: an error code.
    assert!(!psci::version_ok(0xffff_ffff));
    assert!(!psci::version_ok((-1i64) as u64));
    assert!(!psci::version_ok(0x8001_0000));
    assert_eq!(psci::version(0x0001_0003), (1, 3));
    assert_eq!(Status::decode(0), Status::Success);
    assert_eq!(Status::decode(0xFFFF_FFFC), Status::AlreadyOn);
    assert_eq!(Status::decode(u64::MAX - 1), Status::InvalidParameters);
    assert_eq!(Status::decode(0xFFFF_FFF7), Status::InvalidAddress);
    assert_eq!(Status::decode(0xFFFF_FFF0), Status::Unknown(-16));
    assert_eq!(psci::CPU_ON, 0xC400_0003);
}

#[test]
fn enable_method() {
    assert!(psci::enabled_by_psci(Some(b"psci\0")));
    assert!(!psci::enabled_by_psci(Some(b"spin-table\0")));
    assert!(!psci::enabled_by_psci(None));
}
