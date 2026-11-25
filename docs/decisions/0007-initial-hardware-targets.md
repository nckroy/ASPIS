<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->

# 0007. Initial hardware targets: QEMU `virt`, then Raspberry Pi 4

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

ASPIS needs a development platform that is easy to automate and to run as several nodes, and real hardware cheap enough for a multi-node cluster. Booting through GRUB requires UEFI ([0006](0006-uefi-boot-image.md)).

## Decision

1. **QEMU `virt` with EDK2 firmware** is the primary development and CI platform. It provides a selectable GICv2 or GICv3, a PL011 UART, virtio devices and a device tree. An SMMUv3 (`iommu=smmuv3`) lets us develop DMA isolation for user-space drivers. Multi-node tests run several instances on a virtual network.
2. **Raspberry Pi 4** (BCM2711, four Cortex-A72 cores) is the first real hardware. It boots UEFI through the community EDK2 firmware (pftf/RPi4) or U-Boot's UEFI layer, and is cheap enough for a multi-node cluster.
3. **Device tree first; ACPI later**, for SBSA/SBBR servers such as Ampere and AWS Graviton.

## Consequences

The Pi 4 brings three constraints:

- **Interrupts:** its interrupt controller is a GIC-400 (GICv2) plus a Broadcom second-level controller. The kernel needs GICv2 support alongside GICv3 for servers.
- **No crypto instructions:** it lacks the ARMv8 AES and SHA instructions, so they run in software. This is why ChaCha20-Poly1305 is the default AEAD ([0003](0003-hybrid-post-quantum-cryptography.md)).
- **Probably no IOMMU:** no source we found shows one on the BCM2711; confirm against the datasheet. If there is none, DMA-capable drivers on the Pi 4 run without hardware DMA isolation. Isolation is developed and tested on QEMU with SMMUv3.

Alternatives considered:

- **Raspberry Pi 5:** has crypto instructions and IOMMUs, but its UEFI port (worproject/rpi5-uefi) appears unmaintained since its v0.3 release in March 2024.
- **RK3588 boards:** have an EDK2 port and are a candidate second board.

## References

- [QEMU `virt` machine](https://www.qemu.org/docs/master/system/arm/virt.html)
- [pftf/RPi4 UEFI firmware](https://github.com/pftf/RPi4); [Fedora CoreOS on the Raspberry Pi 4](https://docs.fedoraproject.org/en-US/fedora-coreos/provisioning-raspberry-pi4/)
- BCM2711 GIC-400: [NuttX BCM2711 platform docs](https://nuttx.apache.org/docs/12.10.0/platforms/arm64/bcm2711/index.html); [Linux `bcm2711.dtsi`](https://android-kvm.googlesource.com/linux/+/b7db41c9e03b5189bc94993bd50e4506ac9e34c1/arch/arm/boot/dts/bcm2711.dtsi)
- BCM2711 without ARMv8 crypto instructions: [Pi 4 vs Le Potato comparison](https://hacklido.com/d/544/1); [Geekbench BCM2711 entry](https://browser.geekbench.com/v5/cpu/9974578)
- [Raspberry Pi 5 IOMMU driver work (Phoronix)](https://www.phoronix.com/news/Raspberry-Pi-5-IOMMU-Driver)
- [worproject/rpi5-uefi](https://github.com/worproject/rpi5-uefi)
- [edk2-rk35xx](https://github.com/edk2-porting/edk2-rk35xx)
