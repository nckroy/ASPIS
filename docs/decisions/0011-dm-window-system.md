<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0011. dm: the window system, built on Display SVG

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

The brief names the windowing system `dm`, after Apollo's Display Manager, and builds it on Display SVG ([0010](0010-svg-core-primitive.md)).

Apollo's DM ([research §2.9](../research/aegis-domain-os.md#29-user-environment)):

- integrated window management;
- kept pad transcripts from process birth;
- had a built-in editor and allowed editing everywhere;
- was the system console (root could log in only on a DM pad);
- let pads hold GPR graphics.

Its pads were not terminals.

## Decision

1. **dm is a privileged Display SVG client.** It runs in user space. It:
   - owns the screen's root document;
   - places windows and routes focus;
   - grants capabilities to create surfaces;
   - draws window decorations as SVG, themed with CSS.
2. **Windows** are SVG surfaces composed into the root document.
3. **Pads replace character terminals.**
   - A program's standard streams connect to a pad, which renders them as SVG text and keeps a transcript from process birth.
   - Programs can also write SVG fragments to a pad, so text and graphics mix in one transcript, as Apollo pads mixed text and GPR graphics.
   - As on Apollo, pads are not terminals. Programs that need a terminal get one from a terminal-emulator pad mode provided by the POSIX layer.
4. **Universal editing.** All on-screen text is real text, so dm offers selection, copy and search in every window, and editing wherever the window's owner allows it.
5. **dm is the console.** When dm starts, it adopts the console surface from [0009](0009-text-as-graphics-console.md). Login happens in a dm pad.
6. **Detailed design is design-session work:** the command language, key bindings, pad types and window policies.

## Consequences

- The core has no terminal emulation. Terminal compatibility lives in the POSIX layer.
- dm decides input routing and who may draw, which makes it security-critical.
- dm can only be built once the native SVG layer and Display SVG exist.

## References

- [Research notes §2.9](../research/aegis-domain-os.md#29-user-environment)
