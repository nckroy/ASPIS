<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0037. The initial image: an ASPIS format, carrying everything that starts before storage

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

[0006](0006-uefi-boot-image.md), rule 2 has the initial image, `initfs.img`, carry the root server and the core servers that bring up storage and networking. Boot also needs:

- the entropy service and the RNG drivers ([0021](0021-entropy-before-keys.md), rule 1 and Consequences);
- `bootfb` ([0009](0009-text-as-graphics-console.md), rule 4);
- the key service ([node view §2](../design/node-components.md#2-boot-time-core)).

No record names the image's format ([design backlog, D04](../design/design-backlog.md#m1-first-light)).

The common formats are cpio, as Linux's initramfs uses, and tar.

- cpio's `newc` variant aligns file data to 4 bytes, and ustar to 512 bytes. So an executable's pages can't be mapped from the image in place; they must be copied first.
- Neither format carries a hash for each file, or says which entry is the manifest.

The project owner decided on 2026-11-25: a format of ASPIS's own. The rules below spell that decision out.

## Decision

1. **`initfs.img` uses an ASPIS format.**
   - **Header:** the magic `ASPISIMG`, a major and minor format version, the alignment, the number of entries, the offset of the entry table, and the index of the boot manifest's entry.
   - **Entry table:** one entry for each file, giving its name, kind, flags, offset, length and SHA-512 digest.
   - **Contents:** each file starts at an offset that is a multiple of the alignment. The alignment is a power of two, at least 4 KiB. The builder uses 64 KiB, which suits any translation granule, until the kernel specification fixes the page size.
   - Integers are little-endian. The image is an in-memory structure for the node that boots it, not a message, so the byte order of messages ([0062](0062-core-rules-big-endian-fixed-width.md), rule 2) doesn't apply.
2. **An ABNF grammar defines the format**, with test vectors, and CI checks it like every other grammar ([0013](0013-abnf-for-protocols-and-calls.md), rule 6). The root server's parser is a fuzzing target (C71).
3. **There are three kinds of entry:** an executable, which is a static ELF64 AArch64 program; data; and the boot manifest. The manifest's format is the root server's decision (D40).
4. **Executables are mapped in place.** Because each file is aligned, the root server can map an executable's segments straight from the image's memory without copying them. How the image's memory becomes a memory object is decided with the kernel specification.
5. **The image carries everything the root server starts before storage is up**, as the boot manifest lists. [0006](0006-uefi-boot-image.md), rule 2's list is read as a minimum, not as the whole. For the first targets, the image holds:
   - the root server and the boot manifest;
   - the entropy service and the RNG drivers;
   - the memory server, which the root server starts right after the entropy service ([0058](0058-jobs-and-budgets.md), rule 4);
   - `bootfb`;
   - the key service;
   - the drivers that the storage and network servers need, starting with the PCIe and SMMUv3 drivers and the virtio-blk and virtio-net drivers;
   - the storage servers and the network server.
6. **The image holds no secrets** ([0021](0021-entropy-before-keys.md), rule 11): no keys, no credited seed and no node configuration that would make two nodes' images differ. Every node of a release boots the same bytes.
7. **Each entry's digest is checked before it is used.** The stub checks the whole image against the digest in `aspis.efi` ([0040](0040-the-stub-checks-the-initial-image.md)). The root server also checks each entry's own digest before it starts or reads the entry, so that a fault in the image is reported against the file it hit.

## Consequences

- **Executables start without a copy**, and their pages are shared with the image.
- **The format is small, and it is ASPIS's own.** It needs a builder (C02) and a parser in the root server, both tested against the grammar. No existing tool reads it, so the builder also lists and extracts images for debugging.
- **The alignment wastes some space.** An image of about fifteen files, each padded to 64 KiB, is at most about 1 MiB larger.
- **The root server's design (D40) inherits the boot manifest**, and the kernel specification inherits how the image becomes memory objects.

## References

- [Linux: ramfs, rootfs and initramfs](https://docs.kernel.org/filesystems/ramfs-rootfs-initramfs.html) (the `newc` cpio format)
- [0006. Boot: a UEFI PE32+ image loaded by GRUB](0006-uefi-boot-image.md); [0013. ABNF](0013-abnf-for-protocols-and-calls.md); [0021. Entropy](0021-entropy-before-keys.md)
- [Node view §2: the boot-time core](../design/node-components.md#2-boot-time-core)
