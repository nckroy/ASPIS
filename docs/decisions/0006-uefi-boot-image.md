<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0006. Boot: a UEFI PE32+ image loaded by GRUB

- **Status:** Accepted. Amended by [0035](0035-toolchain-image-linkage-and-esp-layout.md) (rule 3).
- **Date:** 2026-11-24

## Context

The founding requirement is that ASPIS boots with GRUB on ARM64. GRUB builds its multiboot and multiboot2 loaders only for x86 and MIPS. On arm64, GRUB's `linux` command:

- requires a PE/COFF EFI image;
- starts it with UEFI `LoadImage` and `StartImage`;
- passes the command line as UTF-16 load options;
- serves the initrd through `EFI_LOAD_FILE2_PROTOCOL` (`LINUX_EFI_INITRD_MEDIA_GUID`) if the image's PE major image version is 1 or higher.

GRUB's `chainloader` loads any EFI image. ([Research §4.1](../research/aegis-domain-os.md#41-grub-on-arm64).)

## Decision

1. **Boot artifact.** ASPIS boots from an AArch64 UEFI PE32+ executable containing a Rust boot stub and the kernel. Its PE major image version is 1 or higher, so GRUB's `linux` command serves the initrd through `LoadFile2`.
2. **Initial image.** The initrd carries the initial user-space image: the root server and the core servers needed to bring up storage and networking.
3. **GRUB entry:**

   ```
   menuentry "ASPIS" {
       linux  /aspis/aspis.efi <kernel arguments>
       initrd /aspis/initfs.img
   }
   ```

   `chainloader /aspis/aspis.efi` and direct firmware boot are also supported. In those cases the stub loads the initial image from the EFI system partition itself.
4. **The boot stub** reads the command line and collects the UEFI memory map, the device tree and/or ACPI tables, the initrd, the framebuffer (GOP) and, where available, a seed from `EFI_RNG_PROTOCOL`. It then exits boot services and enters the kernel at EL1, first configuring and leaving EL2 if the firmware handed over at EL2.
5. **Development** uses QEMU `virt` with EDK2 firmware and GRUB arm64-efi.

## Consequences

- One image boots under GRUB, from the firmware boot manager, or on U-Boot boards that implement UEFI.
- ASPIS depends on UEFI. Boards without UEFI firmware need U-Boot's UEFI layer.
- The PE header and load-option handling need care, and future GRUB releases could change the loader's requirements.
- Secure Boot needs a signed image (through shim or our own key). GRUB 2.14's shim loader protocol and TPM 2.0 support feed into the measured-boot design.

## References

- [Research notes §4.1](../research/aegis-domain-os.md#41-grub-on-arm64)
