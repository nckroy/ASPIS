<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0040. The stub checks the initial image against a digest in `aspis.efi`

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Secure Boot verifies a signed `aspis.efi` ([0006](0006-uefi-boot-image.md), Consequences), but GRUB serves `initfs.img` separately, through `LoadFile2`, and under `chainloader` or direct boot the stub reads it from the ESP. Either way, the signature on `aspis.efi` doesn't cover the initial image, which holds the root server and every server that starts before storage ([0037](0037-initial-image-format-and-contents.md)). See [design backlog, D08](../design/design-backlog.md#m1-first-light).

Facts checked on 2026-11-25:

- **Linux's EFI stub** measures the initrd into TPM PCR 9.
- **GRUB 2.14**, with its `tpm` module, measures every file it reads into PCR 9, and commands and the kernel command line into PCR 8.
- **QEMU's bundled EDK2** provides `EFI_TCG2_PROTOCOL` with an emulated TPM.

There are three options:

- **Pin the image's hash inside the signed `aspis.efi`.** This couples the two images.
- **Sign `initfs.img` separately.** This puts composite signature verification into the stub.
- **Only measure it into a TPM.** This enforces nothing at boot, and nothing at all without a TPM.

The project owner decided on 2026-11-25: a pinned digest, and a measurement into PCR 9 where a TPM exists. The rules below spell that decision out.

## Decision

1. **`aspis.efi` carries the initial image's digest.** The build computes the SHA-512 of `initfs.img` and places it in the stub's `.initfs` section before `aspis.efi` is signed ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 3). So the signature covers the digest.
2. **The stub refuses an image that doesn't match.**
   - The stub computes the SHA-512 of the whole image it received, however it got it.
   - On a mismatch it doesn't enter the kernel. It reports the failure on the GOP console and the UART, and returns an error to its caller, so GRUB or the firmware can try another entry.
   - Only a test build may waive the check ([0036](0036-qemu-configuration-and-test-builds.md), rule 6), for example to boot a freshly rebuilt image during development. A production build has no way to waive it.
3. **Where a TPM exists, the stub also measures the image.** If the firmware offers `EFI_TCG2_PROTOCOL`, the stub extends PCR 9 with the image, as Linux's stub does. This is for attestation (C64). It doesn't replace rule 2.
4. **The kernel learns the result.** The boot information carries the image's digest and whether it was checked or waived ([0041](0041-boot-abi.md)), so the node can report what it booted.
5. **The root server checks each entry** against its own digest in the image's table before using it ([0037](0037-initial-image-format-and-contents.md), rule 7).

## Consequences

- **Secure Boot covers the whole boot path.** A signed `aspis.efi` admits only the initial image it was built with.
- **The two images are released and updated together**, as a slot ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 6). Changing a server in the initial image means a new `aspis.efi`.
- **The stub needs SHA-512 and nothing else.** It verifies no signature.
- **A node with a TPM can attest** to which initial image it booted, using C69's release hashes as the known-good values.

## References

- [Linux EFI stub: initrd measurement](https://github.com/torvalds/linux/blob/master/drivers/firmware/efi/libstub/efi-stub-helper.c)
- [GRUB manual: Measured Boot](https://www.gnu.org/software/grub/manual/grub/html_node/Measured-Boot.html)
- [QEMU TPM](https://www.qemu.org/docs/master/specs/tpm.html)
- [Key flows §1: boot to the entropy gate](../design/key-flows.md#1-boot-to-the-entropy-gate)
