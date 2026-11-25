<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0039. No UEFI runtime services after boot

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

[0006](0006-uefi-boot-image.md), rule 4 has the boot stub exit boot services before it enters the kernel. It says nothing about runtime services, such as `ResetSystem`, `GetTime`, `SetVariable` and `SetVirtualAddressMap`, which firmware keeps available after that ([design backlog, D07](../design/design-backlog.md#m1-first-light)). Using them means mapping the firmware's runtime regions and running firmware code with kernel privilege. Linux, for example, keeps them in a private address space and switches to it for each call.

Facts checked on 2026-11-25:

- **EBBR 2.4** (March 2026) lets firmware return `EFI_UNSUPPORTED` for runtime `SetVariable` and `GetTime`, declared in `EFI_RT_PROPERTIES_TABLE`. Where `ResetSystem` isn't available, it says the OS should fall back to PSCI.
- **QEMU `virt`** implements PSCI `SYSTEM_OFF` and `SYSTEM_RESET`, and has a PL031 real-time clock.
- **The Raspberry Pi 4's firmware (pftf/RPi4)**:
  - It provides PSCI through Trusted Firmware-A. `SYSTEM_OFF` can't cut the board's power; it halts it.
  - It has no real-time clock.
  - Variables written from the operating system aren't persisted.

The project owner decided on 2026-11-25 that ASPIS doesn't use runtime services. The rules below spell that decision out.

## Decision

1. **ASPIS calls no UEFI runtime service.** After `ExitBootServices`, no firmware code runs at ASPIS's request. The stub doesn't call `SetVirtualAddressMap`, and the kernel doesn't map the runtime regions.
2. **The runtime regions stay reserved.** The boot information reports them as firmware-reserved memory ([0041](0041-boot-abi.md)), so nothing reuses them.
3. **Reset and power-off go through PSCI**, using `SYSTEM_RESET` and `SYSTEM_OFF`. The rest of power management is D56's.
4. **Time doesn't come from firmware.** On QEMU, a driver reads the PL031. The Pi 4 has no clock to read. Either way, time a node relies on is authenticated time ([0015](0015-jwt-tokens-and-oidc-identity.md), rule 7).
5. **Boot selection doesn't use UEFI variables.** Choosing a slot and falling back after a failed boot ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 6) use files on the ESP, which GRUB and the stub can read. D146 decides the details.

## Consequences

- **Firmware code never runs with kernel privilege after boot.** This is a smaller trusted base, and it suits a microkernel.
- **There's one mechanism on every target.** Reset, power-off and boot selection work the same on QEMU, the Pi 4 and servers. ASPIS doesn't depend on whether a firmware's variable store persists.
- **Some features are lost:**
  - ASPIS can't set `BootNext` or `BootOrder` from a running node, or read firmware variables such as crash logs. Zircon, for example, writes a crash log into a UEFI variable.
  - Capsule updates of the firmware itself would need runtime services. If ASPIS ever updates firmware, that needs a new decision.
- **Pi 4 power-off only halts the board.** Its firmware has no way to cut power.

## References

- [EBBR 2.4.0, chapter 2](https://github.com/ARM-software/ebbr/blob/v2.4.0/source/chapter2-uefi.rst)
- [Linux arm64 EFI runtime support](https://github.com/torvalds/linux/blob/master/drivers/firmware/efi/arm-runtime.c)
- [Zircon's UEFI runtime use](https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/zircon/kernel/platform/efi.rs)
- [Raspberry Pi 4 EDK2 platform readme](https://github.com/tianocore/edk2-platforms/blob/master/Platform/RaspberryPi/RPi4/Readme.md); [TF-A for the Pi 4](https://github.com/tianocore/edk2-non-osi/blob/master/Platform/RaspberryPi/RPi4/TrustedFirmware/Readme.md)
- [QEMU PSCI](https://gitlab.com/qemu-project/qemu/-/blob/v11.1.3/target/arm/tcg/psci.c)
