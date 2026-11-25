<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0044. The stub undoes GRUB's rewriting of the command line

- **Status:** Accepted. Amends [0041](0041-boot-abi.md) (rule 5).
- **Date:** 2026-11-25

## Context

[0041](0041-boot-abi.md), rule 5 gives the kernel arguments a grammar. Keys are lowercase, and if the kernel finds an error, it uses only the arguments before it. The stub converts the UEFI load options from UTF-16 to ASCII and passes them on.

GRUB's arm64 `linux` command doesn't pass the menu entry's arguments as written. GRUB 2.14's `grub_create_loader_cmdline` builds the load options from the entry's words, after GRUB's own parser has removed their quoting:

- **It puts `BOOT_IMAGE=<path of the image>` first,** as GRUB does for Linux. M1's first boot through GRUB (2026-11-25) showed it.
- **It puts a backslash before every `\`, `'` and `"`** in a word.
- **It wraps a word that contains a space in double quotes,** around the whole word.

Each of these breaks the grammar:

- `BOOT_IMAGE` isn't a lowercase key, so the grammar rejects the line at its first byte, and the kernel would ignore every argument.
- A menu entry's `root.name="a b"` reaches the stub as `"root.name=a b"`, and a key can't start with a quote.
- A backslash in a value arrives doubled.

`BOOT_IMAGE` tells the kernel nothing it needs. The stub already reports how it was started ([0041](0041-boot-abi.md), rule 3).

## Decision

1. **A leading `BOOT_IMAGE=` word marks GRUB's form.** If the converted load options begin with `BOOT_IMAGE=`, after any spaces, the stub treats the line as GRUB's.
2. **The stub recovers GRUB's words and writes them in the grammar's form.** It reads the line as GRUB wrote it: a backslash takes the next byte literally, and double quotes group a word that holds spaces. It then drops the `BOOT_IMAGE=` word. Each remaining word is written again, separated by one space:
   - A `key=value` word whose value is empty, or holds a space or a double quote, becomes `key="value"`, with `\"` and `\\` escapes, as rule 5's `quoted` allows.
   - Any other word is written as it is.
3. **A line GRUB couldn't have written passes no arguments.** An unclosed double quote, or a backslash at the very end, means the line isn't GRUB's form after all. The stub reports it and passes an empty command line.
4. **Lines without the marker are passed as they are**, apart from the ASCII conversion rule 5 already describes.

Rules 1 to 4 amend [0041](0041-boot-abi.md), rule 5, which says only that the stub converts the load options and rejects characters outside ASCII.

## Consequences

- **Arguments in a GRUB menu entry reach the kernel as written there,** quoted values included. M1's tests use this: `test.panic` and a quoted `root.` value come in through GRUB.
- **The conversion is shared code.** It lives in the `kargs` crate, beside the grammar's parser, and its host tests check that every converted line parses.
- **The image's path isn't recorded.** The boot information says how the stub was started, but not the path GRUB loaded it from. If a later decision needs the path, for example to report which ESP slot booted ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 6), it adds a record.
- **Other loaders may add words of their own.** Each one found gets the same treatment, by amendment.

## References

- [GRUB 2.14 `linux` loader for EFI](https://cgit.git.savannah.gnu.org/cgit/grub.git/tree/grub-core/loader/efi/linux.c?h=grub-2.14) (`BOOT_IMAGE=` before the arguments) and [`grub_create_loader_cmdline`](https://cgit.git.savannah.gnu.org/cgit/grub.git/tree/grub-core/lib/cmdline.c?h=grub-2.14) (escaping and quoting)
- [0041. The boot ABI](0041-boot-abi.md)
