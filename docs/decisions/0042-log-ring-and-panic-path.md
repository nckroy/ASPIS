<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0042. The kernel log ring and the panic path

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

[0009](0009-text-as-graphics-console.md) sends the kernel's console output to the framebuffer, the serial UART and a log ring buffer (rule 3). Display SVG imports the console's text when it claims the display (rule 4). On a panic, the kernel draws the report on the boot framebuffer only if that is still the active scan-out, and always on the UART (rule 5).

None of the records give the ring's format, say who may read it, or say how the kernel knows at a panic whether the framebuffer is still scanned out. See [design backlog, D10](../design/design-backlog.md#m1-first-light).

Other records constrain the answer:

- The kernel uses no clock-derived names and no randomness ([0001](0001-object-identifiers.md); [0021](0021-entropy-before-keys.md), rule 3).
- Authority comes from capabilities ([0002](0002-capability-security-model.md)).
- Supervision will want persistent panic records (C73).

Linux's printk ring offers a precedent. Its records have sequence numbers, so a reader can tell when it has fallen behind.

Claude proposed this record, and the project owner accepted it on 2026-11-25.

## Decision

1. **The log ring is a fixed-size ring of variable-length records**, in kernel memory. Its size is a power of two, 256 KiB by default, set by the `log.size` argument ([0041](0041-boot-abi.md), rule 5).
2. **Each record holds:**
   - a 64-bit sequence number, counting from zero at boot;
   - the generic timer's count at the time of writing, which is not a wall-clock time;
   - a level: panic, error, warning, notice, info or debug;
   - the CPU that wrote it;
   - a short ASCII source tag naming the kernel subsystem;
   - up to 1024 bytes of UTF-8 text.
3. **Writing never blocks.**
   - Only the kernel writes. A writer reserves space atomically, so CPUs don't wait for each other, and the oldest records are overwritten.
   - A reader that falls behind sees a gap in the sequence numbers and learns how many records it lost.
4. **Where output goes.**
   - The ring keeps every level.
   - The UART and the framebuffer show records at or above the `log.level` argument, which is `info` by default.
5. **Reading needs a capability.**
   - The ring is a kernel object with a read-only interface: read from a sequence number, and wait for new records.
   - The kernel gives the capability only to the root server. The root server passes it on: to the server that collects system logs (C74), to Display SVG to import the console's text (D55), and to debuggers.
   - The interface is written in the IDL with the other kernel interfaces (M2). Until then, M1 writes the ring and the UART only.
6. **The kernel tracks the boot framebuffer's state:**

   | State | Who draws | Panic drawn on it |
   |---|---|---|
   | Kernel | The kernel draws its console | Yes |
   | Adopted | Display SVG has claimed the display, and the kernel has stopped drawing ([0009](0009-text-as-graphics-console.md), rule 4); `bootfb` scans out the same memory | Yes |
   | Retired | A hardware display driver has changed the scan-out | No |

   - **Moves are calls.** Each move from one state to the next is a call on the boot framebuffer's kernel object, made by whoever holds its capability.
   - **A display driver must retire the boot framebuffer before it changes the scan-out.** Until then, the panic path may still draw on it.
   - **The states only go forward.** Once a framebuffer is retired, no panic is drawn on it again, so a panic can never write into memory that is no longer a framebuffer.
7. **A panic always reaches the UART.** It reaches the framebuffer too, unless that is retired, and it is recorded in the ring. The panic path takes no locks that a normal writer holds, and it writes even if a record is half written. Keeping panic records across a reboot is C73's.

## Consequences

- **Readers never stall the kernel.** A slow log reader loses records and knows how many it lost. It never delays a CPU.
- **The log is private by default.** Kernel messages can reveal memory layout. Only holders of the ring's capability can read them, and the root server decides who those are.
- **Display SVG's import has a source.** It reads the console's text from the ring by sequence number (D55).
- **A display driver's contract is fixed.** Before a hardware display driver takes over scan-out, it must retire the boot framebuffer. After that, panics go to the UART only, as [0009](0009-text-as-graphics-console.md)'s Consequences expect.
- **Timestamps are counter ticks.** Turning them into wall-clock time is a reader's job, once the node has authenticated time.

## References

- [Linux printk ring buffer](https://github.com/torvalds/linux/blob/master/kernel/printk/printk_ringbuffer.c)
- [0009. Console: text as graphics](0009-text-as-graphics-console.md); [0002. Capabilities](0002-capability-security-model.md)
