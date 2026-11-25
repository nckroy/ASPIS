<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0036. QEMU configuration, the test framework and test builds

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

[0007](0007-initial-hardware-targets.md), rule 1 makes QEMU `virt` with EDK2 the development and CI platform. The accepted records fix a few of its parts:

- an SMMUv3 for DMA isolation ([0007](0007-initial-hardware-targets.md), rule 1);
- `ramfb` for an early display ([0009](0009-text-as-graphics-console.md), rule 2);
- a virtio-rng device in every configuration ([0021](0021-entropy-before-keys.md), rule 12).

They leave open the CPU, the core counts, the memory, the GIC matrix and the test framework. They also leave open how test builds carry a seed hook that production builds can't contain ([0021](0021-entropy-before-keys.md), Consequences; [design backlog, D03](../design/design-backlog.md#m1-first-light)).

Facts checked on 2026-11-25:

- **QEMU.** The current stable release is 11.1.3 (28 October 2026). It bundles ArmVirtQemu EDK2 as `edk2-aarch64-code.fd`, built with `EFI_RNG_PROTOCOL` (from virtio-rng and from `RNDR`) and with TPM 2.0 support.
- **CPU limits.** `gic-version=2` allows at most 8 CPUs, and `gic-version=3` allows far more.
- **The `max` CPU** under TCG has FEAT_RNG (`RNDR`), pointer authentication, BTI and MTE (with `mte=on`). `cortex-a72`, the Raspberry Pi 4's core, also runs with a GICv3.
- **The SMMUv3** that `iommu=smmuv3` creates covers only devices in the PCIe topology, so virtio-mmio devices bypass it.
- **`ramfb`.** EDK2's driver gives a linear framebuffer in XRGB8888, at 800×600 by default, with 640×480 and 1024×768 also offered.
- **Ending a run.** Under TCG, a guest can end QEMU with an exit status through semihosting `SYS_EXIT`. PSCI `SYSTEM_OFF` ends it with status 0.
- **Firmware levels.** With `virtualization=off`, EDK2 enters the boot stub at EL1. With `virtualization=on`, it enters at EL2.
- **ACPI or the device tree.** EDK2's ArmVirtQemu firmware installs either the ACPI tables or the device tree in the UEFI configuration table, never both. `virt` has ACPI on by default, so the firmware withholds the device tree unless the machine sets `acpi=off`. M1's first boot (2026-11-25) found this: the kernel got no device tree, and so no UART ([0043](0043-qemu-boots-with-acpi-off.md)).
- **Test harnesses.** Rust's `custom_test_frameworks` is unstable.

The project owner decided on 2026-11-25: two configurations on every change and the full matrix nightly. The rules below spell that decision out.

## Decision

1. **The platform is pinned.** CI uses QEMU 11.1.3 with the EDK2 build it bundles, and GRUB 2.14 arm64-efi built from source. Moving to a newer version is a commit of its own.
2. **Every configuration is `virt` with these devices:**
   - `-machine virt,iommu=smmuv3,acpi=off` and a selected GIC version;
   - `ramfb`, the PL011 UART and the PL031 real-time clock;
   - `virtio-rng-pci`, `virtio-blk-pci` and `virtio-net-pci`, all on PCIe so that the SMMUv3 covers them. ASPIS uses no virtio-mmio devices.

   With ACPI off, the firmware passes the device tree, which is the only hardware description on QEMU until a decision adds ACPI support (C65). A configuration that tests ACPI then turns ACPI on, and so gets no device tree.
3. **Every change runs two configurations**, each with 4 cores and 1 GiB:
   - `cortex-a72` with a GICv2, which is close to the Raspberry Pi 4;
   - `max` with a GICv3, which exercises `RNDR` and newer features.
4. **The full matrix runs nightly:**
   - `cortex-a72` and `max`, each with a GICv2 and a GICv3;
   - 1, 4 and 8 cores;
   - 1 GiB and 3 GiB of memory, 3 GiB being the Pi 4 firmware's default limit;
   - one configuration with `virtualization=on`, so that the stub's path from EL2 to EL1 ([0006](0006-uefi-boot-image.md), rule 4) is tested.
5. **There are two kinds of test.**
   - **Host tests.** Code that doesn't depend on the hardware lives in `no_std` crates that also build for the host, and runs under `cargo test`. This covers parsers, formats, allocators and data structures.
   - **In-QEMU tests.** A test build of the kernel, or of a server, collects its tests through a linker section, which works on stable Rust. It runs them, reports each result on the UART in a line format the harness reads, and ends QEMU through semihosting with an exit status. A host-side runner starts QEMU, applies a timeout and collects the results.
6. **Test builds are a separate build configuration.**
   - A test build is compiled with `--cfg aspis_test_build`, set only by the test runner's build, in a separate target directory. It is never a Cargo feature, because features unify across a workspace and could leak into a production build.
   - Only test builds contain test-only code: the test runner, semihosting, the seed hook, and the switch that waives the initial image's digest check ([0040](0040-the-stub-checks-the-initial-image.md)).
7. **The seed hook.** In a test build, the entropy service accepts a fixed seed from a kernel argument, and credits it, so that a test run can be replayed. A production build doesn't recognize that argument.
8. **CI shows that a production build holds no test code.**
   - Every test-only module carries a marker in a section of its own. The production `aspis.efi`, the kernel payload and every program in `initfs.img` are checked for that section and for semihosting instructions, and a hit fails the build.
   - Production images are only ever built by the reproducible release build ([0038](0038-reproducible-builds-and-provenance.md)), so anyone can rebuild them and check that they match.

## Consequences

- **The Pi 4's GICv2 is tested on every change.** Breakage that only the Pi 4 would see shows up before merging, not a day later.
- **DMA isolation can be developed from M2.** All devices sit behind the SMMUv3 from the start.
- **The kernel finds its devices on QEMU.** The device tree reaches the kernel through the stub, as [0041](0041-boot-abi.md), rule 3 expects. ACPI paths aren't exercised on QEMU until C65 adds ACPI, and with it a configuration that runs with ACPI on.
- **The Pi 4 needs the same setting.** Its firmware defaults to ACPI only, and must be set to pass a device tree before ASPIS can find its devices there (C63).
- **A missing device tree shows only on screen.** Until it can read ACPI, a kernel that gets no device tree has no UART. It still draws its console, which reports "device tree: no", so a headless node with this fault is silent.
- **Semihosting works only under TCG**, so in-QEMU tests don't run under KVM or on hardware. Hardware tests (C63) report over the UART instead.
- **A test seed never reaches a real node.** A production build can't accept one, and CI checks for test code.
- **The nightly matrix is large**: 24 combinations, plus the EL2 run. Its cost is CI time, not developer time.

## References

- [QEMU `virt`](https://www.qemu.org/docs/master/system/arm/virt.html); [QEMU Arm CPU features](https://gitlab.com/qemu-project/qemu/-/blob/v11.1.3/docs/system/arm/emulation.rst); [QEMU semihosting](https://gitlab.com/qemu-project/qemu/-/blob/v11.1.3/semihosting/arm-compat-semi.c); [QEMU PSCI](https://gitlab.com/qemu-project/qemu/-/blob/v11.1.3/target/arm/tcg/psci.c)
- [EDK2 `QemuRamfbDxe`](https://github.com/tianocore/edk2/blob/master/OvmfPkg/QemuRamfbDxe/QemuRamfb.c); [ArmVirtQemu firmware volume](https://github.com/tianocore/edk2/blob/master/ArmVirtPkg/ArmVirtQemuFvMain.fdf.inc); [EDK2 ArmVirtPkg](https://github.com/tianocore/edk2/tree/master/ArmVirtPkg) (`PlatformHasAcpiDtDxe` installs ACPI or the device tree)
- [pftf/RPi4](https://github.com/pftf/RPi4) (system table mode)
- [0007. Initial hardware targets](0007-initial-hardware-targets.md); [0021. Entropy](0021-entropy-before-keys.md); [0043. QEMU configurations turn ACPI off](0043-qemu-boots-with-acpi-off.md)
