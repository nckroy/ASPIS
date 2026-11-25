<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0009. Console: text as graphics from the first kernel message

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

The brief: once the preboot environment is done, a graphics driver takes the system into a text-as-graphics mode that supports both text and graphics natively.

- ARM64 UEFI systems have no character-mode display; the firmware provides graphics through GOP. After `ExitBootServices`, a GOP framebuffer stays usable only if it is linear ([research §4.3](../research/aegis-domain-os.md#43-firmware-framebuffers-after-boot)).
- On QEMU aarch64, EDK2's virtio-gpu GOP is blit-only, with no linear framebuffer. The `ramfb` device provides one.
- Apollo's Display Manager was the console itself, and its pads could hold graphics as well as text ([research §2.9](../research/aegis-domain-os.md#29-user-environment)).
- Drivers and complex code belong in user space ([0002](0002-capability-security-model.md), [0004](0004-network-transparency-and-failure.md)).

## Decision

1. **No character mode.** From its first message, the kernel console is text drawn as graphics on a framebuffer.
2. **Boot framebuffer.** The boot stub ([0006](0006-uefi-boot-image.md)) picks a GOP mode with a linear framebuffer. It passes the framebuffer's base, size, dimensions, stride and pixel format to the kernel, and reserves the region in the memory map. On QEMU, ASPIS runs with `ramfb` for this. If no linear framebuffer exists, the console uses the serial UART until a display driver starts.
3. **Kernel early console.** The kernel draws text, filled rectangles and bitmaps, such as a logo, into the boot framebuffer.
   - Glyphs come from atlases rasterized at build time from the same OpenType font family the SVG layer uses, at a few sizes chosen by framebuffer resolution. The console therefore looks the same before and after the handoff.
   - The kernel contains no font rasterizer and no SVG code.
   - Output also goes to the serial UART and to a log ring buffer.
4. **Handoff.** The root server starts the display driver in user space and gives it a capability to the framebuffer memory.
   - The first driver, `bootfb`, simply adopts the boot framebuffer. Hardware drivers add mode setting and page flipping: virtio-gpu on QEMU first, then the Pi 4's display pipeline.
   - When Display SVG ([0010](0010-svg-core-primitive.md)) claims the display, it imports the console's text as its first text surface, so nothing on screen jumps or flickers. From then on the kernel stops drawing.
5. **Panic path.** On a kernel panic, the kernel draws the report on the boot framebuffer if that is still the active scan-out, and always on the serial UART.

## Consequences

- Text and graphics share one surface from the first kernel message, as on Apollo workstations.
- The kernel carries a small amount of drawing code and a few glyph atlases. That is the only graphics code in the kernel.
- Until a hardware display driver exists, the resolution is whatever the firmware set.
- On QEMU, `ramfb` is required for an early display, and virtio-gpu needs ASPIS's own driver.
- A panic after a hardware driver has changed modes may reach only the serial port.

## References

- [Research notes §2.9, §4.3](../research/aegis-domain-os.md)
