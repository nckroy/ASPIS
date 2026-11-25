<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0043. QEMU configurations turn ACPI off, so the firmware passes the device tree

- **Status:** Proposed. Would amend [0036](0036-qemu-configuration-and-test-builds.md) (rule 2).
- **Date:** 2026-11-25

## Context

[0007](0007-initial-hardware-targets.md), rule 3 puts the device tree first and ACPI later. The kernel finds its devices, starting with the PL011 UART, in the device tree that the boot stub passes on ([0041](0041-boot-abi.md), rule 3).

The first boot of M1's kernel on QEMU (2026-11-25) printed nothing after the stub handed over. The kernel ran to its idle loop, but it had no UART to write to: its boot information held no device tree.

- EDK2's ArmVirtQemu firmware installs either the ACPI tables or the device tree in the UEFI configuration table, never both.
- QEMU's `virt` machine has ACPI on by default, so the firmware installed ACPI and withheld the device tree.
- With `-machine virt,acpi=off`, the firmware installs the device tree, and the kernel found the UART and booted to first light.

[0036](0036-qemu-configuration-and-test-builds.md), rule 2 lists the machine options without saying anything about ACPI.

The Raspberry Pi 4's community firmware has the same choice. It defaults to ACPI only, and offers a device tree mode ([0007](0007-initial-hardware-targets.md); [build plan](../design/build-plan.md#mh-hardware-and-hardening)).

## Decision

1. **Every QEMU configuration sets `acpi=off`.** This amends [0036](0036-qemu-configuration-and-test-builds.md), rule 2, whose first item becomes `-machine virt,iommu=smmuv3,acpi=off` and a selected GIC version.
2. **The device tree is the only hardware description on QEMU** until a decision adds ACPI support (C65). A configuration that tests ACPI then turns ACPI on, and so gets no device tree.

## Consequences

- **The kernel finds its devices on QEMU.** The device tree reaches the kernel through the stub, as [0041](0041-boot-abi.md), rule 3 expects.
- **ACPI paths aren't exercised on QEMU yet.** C65 adds ACPI, and with it a configuration that runs with ACPI on.
- **The Pi 4 needs the same setting.** Its firmware must be set to pass a device tree before ASPIS can find its devices there (C63).
- **A missing device tree shows only on screen.** Until it can read ACPI, a kernel that gets no device tree has no UART. It still draws its console, which reports "device tree: no", so a headless node with this fault is silent.

## References

- [QEMU `virt`](https://www.qemu.org/docs/master/system/arm/virt.html) (the `acpi` machine option)
- [EDK2 ArmVirtPkg](https://github.com/tianocore/edk2/tree/master/ArmVirtPkg) (`PlatformHasAcpiDtDxe` installs one or the other)
- [pftf/RPi4](https://github.com/pftf/RPi4) (system table mode)
- [0036. QEMU configuration, the test framework and test builds](0036-qemu-configuration-and-test-builds.md)
