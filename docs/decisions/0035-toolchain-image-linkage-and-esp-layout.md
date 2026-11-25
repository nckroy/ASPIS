<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0035. Toolchain, image linkage and the ESP layout

- **Status:** Accepted. Amends [0006](0006-uefi-boot-image.md) (rule 3).
- **Date:** 2026-11-25

## Context

[0006](0006-uefi-boot-image.md) fixes the boot artifact: one AArch64 PE32+ image, `aspis.efi`, holding a Rust boot stub and the kernel, with PE major image version 1 or higher, so that GRUB's `linux` command serves the initial image through `LoadFile2`. It doesn't say how the image is built, and the GRUB entry in its rule 3 names fixed paths with no room for the two boot entries that updates with rollback will need ([design backlog, D02 and D146](../design/design-backlog.md#m1-first-light)).

Facts checked on 2026-11-25:

- **Rust.** The current stable is 1.100.0 (12 November 2026). `aarch64-unknown-uefi` and `aarch64-unknown-none` are both Tier 2 targets, and stable ships `core` and `alloc` for both.
- **No part of `build-std` is stable**, and no date is set. Since Rust 1.95, a custom target specification also needs `-Zunstable-options`, so a target of ASPIS's own is nightly-only in practice.
- **The linker.** `aarch64-unknown-uefi` links with LLD in its `link` flavor. `/version:1.0` sets the PE major and minor image versions. `/Brepro` writes a hash of the output as the timestamp, and LLD otherwise honors `SOURCE_DATE_EPOCH`.
- **Two linkages are in use.** Linux's arm64 `Image` builds its EFI stub into the kernel, so they are one link. systemd's unified kernel images and Linux's `EFI_ZBOOT` instead carry the kernel as a payload inside a separate EFI program.
- **GRUB 2.14** (14 January 2026) is the current release. Its `linux` command serves the initrd through `LoadFile2` when the image's PE major image version is at least 1.

The project owner decided on 2026-11-25: the kernel travels as a payload, the toolchain is stable Rust, and the ESP gets two slots now. The rules below spell that decision out.

## Decision

1. **The toolchain is pinned stable Rust.**
   - `rust-toolchain.toml` pins Rust 1.100.0, with the `aarch64-unknown-uefi` and `aarch64-unknown-none` targets. Moving to a newer release is a commit of its own, which must keep the build reproducible ([0038](0038-reproducible-builds-and-provenance.md)).
   - No nightly feature is used. If a later chunk needs one, that is a decision for that chunk.
2. **The stub and the kernel are built separately.**
   - The boot stub is built for `aarch64-unknown-uefi`.
   - The kernel is built for `aarch64-unknown-none` as a static, position-independent ELF, linked in the upper half of the address space with a linker script of its own. C05 fixes the exact base.
3. **The kernel is a payload inside the stub.**
   - `aspis.efi` is the stub, with the kernel's ELF in a `.kernel` section and the initial image's digest in an `.initfs` section ([0040](0040-the-stub-checks-the-initial-image.md)).
   - The stub loads the kernel's segments at a physical address aligned to 2 MiB, zeroes its uninitialized data and applies its relocations for the chosen virtual base. The kernel never relocates itself.
   - The build links the stub with `/version:1.0` and `/Brepro`, so the image's major version is 1 and its timestamp is deterministic.
   - The build order is: the kernel, then `initfs.img`, then the stub that embeds both, then signing.
4. **The stub may move the kernel.** Because the kernel is position-independent and the stub relocates it, the stub can choose its virtual base. Until C78, the base is fixed. Whether the stub randomizes it, using the firmware's seed for its own purpose as [0021](0021-entropy-before-keys.md), rule 3 allows, is decided with C78.
5. **User-space programs are `no_std` until there is a std port.**
   - Servers and test programs are built for `aarch64-unknown-none`, with ASPIS's runtime crate and linker script.
   - A Rust standard library for ASPIS needs a custom target, and so nightly, until `build-std` is stable. Whether and when to port it is decided when the POSIX personality or applications need it.
6. **The EFI system partition has two slots.** This amends [0006](0006-uefi-boot-image.md), rule 3, whose paths become slot `a`'s.

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
- **`aspis.efi` and `initfs.img` are released as a pair**, because the stub embeds the initial image's digest. Updates (C79) replace both together, one slot at a time.
- **The two-slot layout costs nothing in M1.** Slot `b` stays empty until C79 needs it.

## References

- [Rust 1.100.0 release announcement](https://blog.rust-lang.org/2026/11/12/Rust-1.100.0/); [Rust platform support](https://doc.rust-lang.org/nightly/rustc/platform-support.html); [`aarch64-unknown-uefi`](https://doc.rust-lang.org/nightly/rustc/platform-support/unknown-uefi.html); [`aarch64-unknown-none`](https://doc.rust-lang.org/nightly/rustc/platform-support/aarch64-unknown-none.html)
- [Cargo unstable features: `build-std`](https://doc.rust-lang.org/cargo/reference/unstable.html); [Rust project goal: build-std (2026)](https://goals.rust-lang.org/2026/build-std.html); [rust-lang/rust#151534: custom targets need `-Zunstable-options`](https://github.com/rust-lang/rust/pull/151534)
- [LLD COFF driver](https://github.com/llvm/llvm-project/blob/main/lld/COFF/Driver.cpp) (`/version`, `/Brepro`)
- [Linux arm64 booting](https://docs.kernel.org/arch/arm64/booting.html); [UAPI Group: Unified Kernel Image](https://uapi-group.org/specifications/specs/unified_kernel_image/)
- [GRUB 2.14 `linux` loader for EFI](https://cgit.git.savannah.gnu.org/cgit/grub.git/tree/grub-core/loader/efi/linux.c?h=grub-2.14)
- [0006. Boot: a UEFI PE32+ image loaded by GRUB](0006-uefi-boot-image.md)
