<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0045. Linking the kernel and the stub on stable Rust

- **Status:** Superseded by [0035](0035-toolchain-image-linkage-and-esp-layout.md)
- **Date:** 2026-11-25

## Context

[0035](0035-toolchain-image-linkage-and-esp-layout.md) builds the kernel for `aarch64-unknown-none` as a static, position-independent ELF (rule 2), carried in the stub, which relocates it (rule 3), on pinned stable Rust with no nightly features (rule 1). Rule 3 has the stub linked with `/version:1.0` and `/Brepro`. Building M1 on 2026-11-25 showed three things those rules don't cover:

- **`-C relocation-model=pie` isn't enough.** For `aarch64-unknown-none`, rustc links statically and produces an ordinary executable even with that flag. The linker needs `-pie` and `--no-dynamic-linker` too.
- **The prebuilt `core` isn't position-independent.** Rust ships `core` for this target compiled without PIC, so some of its read-only data holds absolute pointers. A position-independent kernel then needs dynamic relocations in read-only sections, which the linker refuses unless given `-z notext`. Rebuilding `core` as PIC would take `build-std`, which is nightly-only, and rule 1 rules that out.
- **The stub's debug record depends on build paths.** Even with debug information turned off in Cargo, lld-link writes a CodeView record naming a PDB, whose GUID it derives from the PDB's contents, which include absolute paths. So two builds of the same commit in different directories gave different `aspis.efi` files, against [0038](0038-reproducible-builds-and-provenance.md), rule 1. `/DEBUG:NONE` removes the record.

## Decision

1. **The kernel links as a static PIE with text relocations allowed.** The kernel's build passes `-pie`, `--no-dynamic-linker` and `-z notext` to the linker. The result is an ELF of type `ET_DYN` whose relocations are all `R_AARCH64_RELATIVE`, which the stub applies before the kernel runs. This amends [0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 2.
2. **Read-only protection starts after relocation.** Some relocations land in the kernel's read-only data. The stub applies them while nothing is write-protected: the MMU is on under UEFI's identity map, and the kernel isn't running yet. The kernel maps its text and read-only data read-only only after that, when it builds its own page tables (C10, and W^X in C78).
3. **The stub links with `/DEBUG:NONE` as well.** No PDB and no debug record are produced, so `aspis.efi` doesn't depend on where it was built. This amends [0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 3. Debugging the stub uses symbols from a separate build when it needs them.

## Consequences

- **M1 builds on stable Rust.** The kernel needs no nightly feature, as [0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 1 requires.
- **The stub's loader must handle every relocation.** It applies every entry of the `DT_RELA` table, including those in read-only segments. It refuses any relocation type other than `R_AARCH64_RELATIVE`, and an image that has any other kind of relocation table: `DT_REL`, `DT_RELR` or PLT relocations (`DT_JMPREL`).
- **`aspis.efi` is reproducible across directories.** Two builds of the same commit, in different directories, give identical images. CI checks this ([0038](0038-reproducible-builds-and-provenance.md), rule 1).
- **If `build-std` becomes stable,** a PIC `core` would let the kernel link with `-z text`. That would be a change under [0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 1.

## References

- [Rust platform support: `aarch64-unknown-none`](https://doc.rust-lang.org/nightly/rustc/platform-support/aarch64-unknown-none.html)
- [Cargo unstable features: `build-std`](https://doc.rust-lang.org/cargo/reference/unstable.html)
- [LLD COFF driver](https://github.com/llvm/llvm-project/blob/main/lld/COFF/Driver.cpp) (`/DEBUG:NONE`, `/Brepro`)
- [0035. Toolchain, image linkage and the ESP layout](0035-toolchain-image-linkage-and-esp-layout.md); [0038. Reproducible builds](0038-reproducible-builds-and-provenance.md)
