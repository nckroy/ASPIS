<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0041. The boot ABI: entry state, boot information and kernel arguments

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

[0006](0006-uefi-boot-image.md), rule 4 lists what the boot stub collects: the command line, the UEFI memory map, the device tree and/or ACPI tables, the initial image, the framebuffer and, where available, a seed from `EFI_RNG_PROTOCOL`. The stub then exits boot services and enters the kernel at EL1. No record says how the stub hands these to the kernel, what state the processor is in at entry, or what the kernel arguments look like. Every text format needs an ABNF grammar ([0013](0013-abnf-for-protocols-and-calls.md), rule 2). See [design backlog, D09](../design/design-backlog.md#m1-first-light).

Other records constrain the hand-off:

- **Layout.** The stub carries the kernel as an ELF payload, places it and relocates it ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rules 2–4).
- **The initial image.** The stub checks it against a digest ([0040](0040-the-stub-checks-the-initial-image.md)), and GRUB serves it through `LoadFile2` or the stub reads it from the ESP ([0006](0006-uefi-boot-image.md), rule 3).
- **The seed.** The kernel hands the seed on and keeps no copy ([0021](0021-entropy-before-keys.md), rule 1). The stub uses it only for what it does itself (rule 3).
- **Firmware.** ASPIS uses no UEFI runtime services ([0039](0039-no-uefi-runtime-services.md)).
- **The console.** The framebuffer's description goes to the kernel ([0009](0009-text-as-graphics-console.md), rule 2).

Precedents: Linux's arm64 boot protocol enters the kernel with the MMU off and the device tree's address in `x0`. Multiboot2 and Limine pass tagged records that a kernel can skip if it doesn't know them.

GRUB's arm64 `linux` command doesn't pass a menu entry's arguments as written. GRUB 2.14's `grub_create_loader_cmdline` builds the load options from the entry's words, after GRUB's own parser has removed their quoting. M1's first boot through GRUB (2026-11-25) showed the result ([0044](0044-stub-undoes-grubs-command-line.md)):

- **It puts `BOOT_IMAGE=<path of the image>` first,** as GRUB does for Linux. `BOOT_IMAGE` isn't a lowercase key, so the grammar in rule 5 would reject the line at its first byte.
- **It puts a backslash before every `\`, `'` and `"`** in a word, so a backslash in a value arrives doubled.
- **It wraps a word that contains a space in double quotes,** around the whole word. A menu entry's `root.name="a b"` reaches the stub as `"root.name=a b"`, and a key can't start with a quote.

Claude proposed this record, and the project owner accepted it on 2026-11-25.

## Decision

1. **The kernel is entered in a fixed state:**
   - at EL1, using SP_EL1, with the stub having configured and left EL2 if the firmware entered it there ([0006](0006-uefi-boot-image.md), rule 4);
   - with the MMU and data cache off, and the kernel image and the boot information cleaned to the point of coherency;
   - with all exceptions masked;
   - with `x0` holding the boot information's physical address, and `x1` to `x3` zero;
   - at the kernel's entry point, at its physical load address, relocated for the virtual base the stub chose ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 3).

   The kernel turns on the MMU itself (C05).
2. **The boot information is a header followed by tagged records.**
   - **The header** holds the magic `ASPISBI\0`, a major and minor version, its own length, the total length and the number of records.
   - **Each record** has a 32-bit type and a 32-bit length, then its payload, padded to 8 bytes.
   - **Unknown records are skipped.** A type with its top bit set is critical: a kernel that doesn't know it refuses to boot, and says why on the UART.
   - **Versions.** A new record is a minor version. Changing a record's meaning is a major version.
   - Integers are little-endian: this is an in-memory structure between two programs on one processor, not a message ([0013](0013-abnf-for-protocols-and-calls.md), rule 4).
3. **The records** are:

   | Record | Contents |
   |---|---|
   | Command line | The kernel arguments, converted from UTF-16 to ASCII (rule 5) |
   | Memory map | Each range with an ASPIS type (usable, firmware-reserved, ACPI reclaimable, ACPI non-volatile, MMIO, kernel image, initial image, boot information, framebuffer, seed) and the original UEFI type and attributes. UEFI runtime regions are firmware-reserved ([0039](0039-no-uefi-runtime-services.md), rule 2) |
   | Device tree | The physical address and size of the device tree blob, copied into reserved memory |
   | ACPI | The physical address of the ACPI 2.0 RSDP |
   | Framebuffer | Base, size, width, height, stride and pixel format of the linear GOP framebuffer ([0009](0009-text-as-graphics-console.md), rule 2), if there is one |
   | Initial image | Its physical address and size, its SHA-512 digest, and whether the digest was checked or waived ([0040](0040-the-stub-checks-the-initial-image.md), rule 4) |
   | Seed | The physical address and length of a page holding the seed, and its source. Absent if the firmware offered none |
   | Kernel placement | The physical base, the virtual base and the slide |
   | Stub | The stub's version, how it was started (GRUB `linux`, `chainloader` or direct), whether it was entered at EL2, and the firmware vendor and revision |
   | TPM event log | Reserved for measured boot (C64) |

   Only the memory map and the kernel placement are required. The kernel prefers the device tree to ACPI when it has both ([0007](0007-initial-hardware-targets.md), rule 3).
4. **The seed is passed on, never kept.**
   - The stub fills the seed's page with bytes from `EFI_RNG_PROTOCOL` that it hasn't used for its own purposes, and erases every other copy.
   - The kernel never reads the page. It hands the page on as D42 decides, and keeps no copy ([0021](0021-entropy-before-keys.md), rule 1).
5. **Kernel arguments are ASCII words separated by spaces**, with this grammar:

   ```abnf
   kernel-args = *SP [ arg *( 1*SP arg ) *SP ]
   arg         = key [ "=" value ]
   key         = segment *( "." segment )
   segment     = lower *( lower / DIGIT / "-" )
   lower       = %x61-7A
   value       = bare / quoted
   bare        = 1*bare-char
   bare-char   = %x21 / %x23-7E                ; printable, not SP or DQUOTE
   quoted      = DQUOTE *( q-char / escape ) DQUOTE
   q-char      = %x20-21 / %x23-5B / %x5D-7E   ; not DQUOTE or "\"
   escape      = "\" ( DQUOTE / "\" )
   ```

   - **Length and errors.** The command line is at most 4096 bytes. The stub rejects characters outside ASCII and passes the rest. If the kernel finds an error, it reports the error and uses only the arguments before it.
   - **The stub undoes GRUB's rewriting.** `BOOT_IMAGE` tells the kernel nothing it needs, since the stub already reports how it was started (rule 3).
     - A leading `BOOT_IMAGE=` word, after any spaces, marks GRUB's form, and the stub treats the line as GRUB's.
     - The stub then recovers GRUB's words: a backslash takes the next byte literally, and double quotes group a word that holds spaces. It drops the `BOOT_IMAGE=` word, and writes each remaining word again, separated by one space. A `key=value` word whose value is empty, or holds a space or a double quote, becomes `key="value"`, with `\"` and `\\` escapes, as `quoted` allows. Any other word is written as it is.
     - A line GRUB couldn't have written passes no arguments. An unclosed double quote, or a backslash at the very end, means the line isn't GRUB's form after all. The stub reports it and passes an empty command line.
     - Lines without the marker are passed as they are, apart from the ASCII conversion.
   - **Repeated keys.** If a key appears more than once, the last one counts, and the kernel logs the repeat.
   - **The first keys are:**
     - `console` (`fb`, `uart` or `fb,uart`), and `console.cell` (`16`, `24` or `32`; [0034](0034-noto-fonts-under-ofl.md), rule 4);
     - `log.size` and `log.level` ([0042](0042-log-ring-and-panic-path.md));
     - `initfs`, an ESP path that only the stub reads (rule 6).
   - **Other keys.** Keys under `root.` are passed to the root server without being read. In test builds, keys under `test.` are reserved ([0036](0036-qemu-configuration-and-test-builds.md), rule 7). Any other key is logged and ignored.
   - **The grammar file.** The grammar, each key's value rules and test vectors live in a grammar file that CI checks ([0013](0013-abnf-for-protocols-and-calls.md), rule 6). The parser is a fuzzing target (C71).
6. **The stub finds the initial image in this order:**
   1. through `LoadFile2`, if GRUB offers the `LINUX_EFI_INITRD_MEDIA_GUID` device path;
   2. at the ESP path in the `initfs` argument;
   3. as `initfs.img` in the directory that holds `aspis.efi`, from the stub's own loaded-image device path.

   So each slot on the ESP is self-contained ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 6). If no image is found, the stub doesn't enter the kernel.

## Consequences

- **The kernel's first code is simple.** It starts in a known state, with one pointer, and doesn't need to know which loader started it.
- **The format can grow.** Measured boot, ACPI-first platforms and new firmware facts add records without breaking older kernels, and a record no kernel may ignore can say so.
- **The seed travels in a page of its own**, which D42 can hand on as a memory object without anyone reading it.
- **Arguments in a GRUB menu entry reach the kernel as written there,** quoted values included. M1's tests use this: `test.panic` and a quoted `root.` value come in through GRUB.
- **The conversion is shared code.** It lives in the `kargs` crate, beside the grammar's parser, and its host tests check that every converted line parses.
- **The image's path isn't recorded.** The boot information says how the stub was started, but not the path GRUB loaded it from. If a later decision needs the path, for example to report which ESP slot booted ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 6), it adds a record.
- **Other loaders may add words of their own.** Each one found gets the same treatment, by a change to rule 5.
- **Kernel arguments are small and strict.** Values with spaces need quotes, and non-ASCII text isn't accepted, so the arguments can't carry anything for people to read. ABNF here describes a machine-read format, which suits [0031](0031-abnf-is-not-a-command-language.md).

## References

- [Linux arm64 booting](https://docs.kernel.org/arch/arm64/booting.html)
- [Multiboot2 specification](https://www.gnu.org/software/grub/manual/multiboot2/multiboot.html); [Limine boot protocol](https://github.com/limine-bootloader/limine-protocol)
- [GRUB 2.14 `linux` loader for EFI](https://cgit.git.savannah.gnu.org/cgit/grub.git/tree/grub-core/loader/efi/linux.c?h=grub-2.14) (`BOOT_IMAGE=` before the arguments) and [`grub_create_loader_cmdline`](https://cgit.git.savannah.gnu.org/cgit/grub.git/tree/grub-core/lib/cmdline.c?h=grub-2.14) (escaping and quoting)
- [RFC 5234: ABNF](https://www.rfc-editor.org/rfc/rfc5234)
- [Key flows §1: boot to the entropy gate](../design/key-flows.md#1-boot-to-the-entropy-gate)
- [0044. The stub undoes GRUB's rewriting of the command line](0044-stub-undoes-grubs-command-line.md)
