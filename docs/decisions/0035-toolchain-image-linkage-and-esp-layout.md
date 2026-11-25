<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0035. Toolchain, image linkage and the ESP layout

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

[0006](0006-uefi-boot-image.md) fixes the boot artifact: one AArch64 PE32+ image, `aspis.efi`, holding a Rust boot stub and the kernel, with PE major image version 1 or higher, so that GRUB's `linux` command serves the initial image through `LoadFile2`. It doesn't say how the image is built, or how the EFI system partition makes room for the two boot entries that updates with rollback will need ([design backlog, D02 and D146](../design/design-backlog.md#m1-first-light)).

Facts checked on 2026-11-25:

- **Rust.** The current stable is 1.100.0 (12 November 2026). `aarch64-unknown-uefi` and `aarch64-unknown-none` are both Tier 2 targets, and stable ships `core` and `alloc` for both.
- **No part of `build-std` is stable**, and no date is set. Since Rust 1.95, a custom target specification also needs `-Zunstable-options`, so a target of ASPIS's own is nightly-only in practice.
- **The linker.** `aarch64-unknown-uefi` links with LLD in its `link` flavor. `/version:1.0` sets the PE major and minor image versions. `/Brepro` writes a hash of the output as the timestamp, and LLD otherwise honors `SOURCE_DATE_EPOCH`.
- **Two linkages are in use.** Linux's arm64 `Image` builds its EFI stub into the kernel, so they are one link. systemd's unified kernel images and Linux's `EFI_ZBOOT` instead carry the kernel as a payload inside a separate EFI program.
- **GRUB 2.14** (14 January 2026) is the current release. Its `linux` command serves the initrd through `LoadFile2` when the image's PE major image version is at least 1.

The project owner decided on 2026-11-25: the kernel travels as a payload, the toolchain is stable Rust, and the ESP gets two slots now. The rules below spell that decision out.

Building M1 on 2026-11-25 showed three more facts, which rules 2 and 3 cover ([0045](0045-linking-the-kernel-and-stub-on-stable-rust.md)):

- **`-C relocation-model=pie` isn't enough.** For `aarch64-unknown-none`, rustc links statically and produces an ordinary executable even with that flag. The linker needs `-pie` and `--no-dynamic-linker` too.
- **The prebuilt `core` isn't position-independent.** Rust ships `core` for this target compiled without PIC, so some of its read-only data holds absolute pointers. A position-independent kernel then needs dynamic relocations in read-only sections, which the linker refuses unless given `-z notext`. Rebuilding `core` as PIC would take `build-std`, which is nightly-only.
- **The stub's debug record depends on build paths.** Even with debug information turned off in Cargo, lld-link writes a CodeView record naming a PDB, whose GUID it derives from the PDB's contents, which include absolute paths. So two builds of the same commit in different directories gave different `aspis.efi` files. `/DEBUG:NONE` removes the record.

## Decision

1. **The toolchain is pinned stable Rust.**
   - `rust-toolchain.toml` pins Rust 1.100.0, with the `aarch64-unknown-uefi` and `aarch64-unknown-none` targets. Moving to a newer release is a commit of its own, which must keep the build reproducible ([0038](0038-reproducible-builds-and-provenance.md)).
   - No nightly feature is used. If a later chunk needs one, that is a decision for that chunk.
2. **The stub and the kernel are built separately.**
   - The boot stub is built for `aarch64-unknown-uefi`.
   - The kernel is built for `aarch64-unknown-none` as a static, position-independent ELF, linked in the upper half of the address space with a linker script of its own. C05 fixes the exact base.
   - The kernel links as a static PIE with text relocations allowed. Its build passes `-pie`, `--no-dynamic-linker` and `-z notext` to the linker. The result is an ELF of type `ET_DYN` whose relocations are all `R_AARCH64_RELATIVE`, which the stub applies before the kernel runs.
3. **The kernel is a payload inside the stub.**
   - `aspis.efi` is the stub, with the kernel's ELF in a `.kernel` section and the initial image's digest in an `.initfs` section ([0040](0040-the-stub-checks-the-initial-image.md)).
   - The stub loads the kernel's segments at a physical address aligned to 2 MiB, zeroes its uninitialized data and applies its relocations for the chosen virtual base. The kernel never relocates itself.
   - Read-only protection starts after relocation. Some relocations land in the kernel's read-only data. The stub applies them while nothing is write-protected: the MMU is on under UEFI's identity map, and the kernel isn't running yet. The kernel maps its text and read-only data read-only only after that, when it builds its own page tables (C10, and W^X in C78).
   - The build links the stub with `/version:1.0`, `/Brepro` and `/DEBUG:NONE`, so the image's major version is 1, its timestamp is deterministic, and no PDB or debug record is produced. So `aspis.efi` doesn't depend on where it was built. Debugging the stub uses symbols from a separate build when it needs them.
   - The build order is: the kernel, then `initfs.img`, then the stub that embeds both, then signing.
4. **The stub may move the kernel.** Because the kernel is position-independent and the stub relocates it, the stub can choose its virtual base. Until C78, the base is fixed. Whether the stub randomizes it, using the firmware's seed for its own purpose as [0021](0021-entropy-before-keys.md), rule 3 allows, is decided with C78.
5. **User-space programs are `no_std` until there is a std port.**
   - Servers and test programs are built for `aarch64-unknown-none`, with ASPIS's runtime crate and linker script.
   - A Rust standard library for ASPIS needs a custom target, and so nightly, until `build-std` is stable. Whether and when to port it is decided when the POSIX personality or applications need it.
6. **The EFI system partition has two slots.**

   | Path | Contents |
   |---|---|
   | `/EFI/BOOT/BOOTAA64.EFI` | GRUB arm64-efi, built to read `/aspis/grub.cfg` |
   | `/aspis/grub.cfg` | The menu entries |
   | `/aspis/a/aspis.efi`, `/aspis/a/initfs.img` | Slot `a` |
   | `/aspis/b/aspis.efi`, `/aspis/b/initfs.img` | Slot `b`, empty until updates exist (C79) |

   The entry for slot `a` is:

   ```
   menuentry "ASPIS" {
       linux  /aspis/a/aspis.efi <kernel arguments>
       initrd /aspis/a/initfs.img
   }
   ```

   `chainloader` and direct firmware boot still work. In those cases the stub loads the initial image from its own directory ([0041](0041-boot-abi.md), rule 6), so each slot is self-contained. How a slot is chosen, and how a failed boot falls back, are decided in D146. The Raspberry Pi 4's firmware files can share the same partition, at its root.

## Consequences

- **Stable Rust only.** Upgrades are predictable, and nothing in M1 depends on an unstable feature. The cost comes later: a std port needs either nightly or a stable `build-std`.
- **The kernel keeps its own target and linker script.** The stub does the PE work, and the kernel never deals with PE relocation.
- **The stub has more to do.** It parses an ELF, places it and applies relocations, which is about what a small loader does. In return, the stub can place the kernel anywhere, which C78's hardening needs.
- **The stub's loader must handle every relocation.** It applies every entry of the `DT_RELA` table, including those in read-only segments. It refuses any relocation type other than `R_AARCH64_RELATIVE`, and an image that has any other kind of relocation table: `DT_REL`, `DT_RELR` or PLT relocations (`DT_JMPREL`).
- **`aspis.efi` is reproducible across directories.** Two builds of the same commit, in different directories, give identical images. CI checks this ([0038](0038-reproducible-builds-and-provenance.md), rule 1).
- **If `build-std` becomes stable,** a PIC `core` would let the kernel link with `-z text`. That would be a change under rule 1.
- **`aspis.efi` and `initfs.img` are released as a pair**, because the stub embeds the initial image's digest. Updates (C79) replace both together, one slot at a time.
- **The two-slot layout costs nothing in M1.** Slot `b` stays empty until C79 needs it.

## References

- [Rust 1.100.0 release announcement](https://blog.rust-lang.org/2026/11/12/Rust-1.100.0/); [Rust platform support](https://doc.rust-lang.org/nightly/rustc/platform-support.html); [`aarch64-unknown-uefi`](https://doc.rust-lang.org/nightly/rustc/platform-support/unknown-uefi.html); [`aarch64-unknown-none`](https://doc.rust-lang.org/nightly/rustc/platform-support/aarch64-unknown-none.html)
- [Cargo unstable features: `build-std`](https://doc.rust-lang.org/cargo/reference/unstable.html); [Rust project goal: build-std (2026)](https://goals.rust-lang.org/2026/build-std.html); [rust-lang/rust#151534: custom targets need `-Zunstable-options`](https://github.com/rust-lang/rust/pull/151534)
- [LLD COFF driver](https://github.com/llvm/llvm-project/blob/main/lld/COFF/Driver.cpp) (`/version`, `/Brepro`, `/DEBUG:NONE`)
- [Linux arm64 booting](https://docs.kernel.org/arch/arm64/booting.html); [UAPI Group: Unified Kernel Image](https://uapi-group.org/specifications/specs/unified_kernel_image/)
- [GRUB 2.14 `linux` loader for EFI](https://cgit.git.savannah.gnu.org/cgit/grub.git/tree/grub-core/loader/efi/linux.c?h=grub-2.14)
- [0006. Boot: a UEFI PE32+ image loaded by GRUB](0006-uefi-boot-image.md); [0045. Linking the kernel and the stub on stable Rust](0045-linking-the-kernel-and-stub-on-stable-rust.md)
