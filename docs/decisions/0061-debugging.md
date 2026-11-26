<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0061. Debugging: the kernel, user threads and crash dumps

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

No record covers debugging. [0014](0014-versioned-object-apis.md) names debuggers among the users of introspection (Consequences), and the POSIX personality needs to suspend a thread and read or write its registers ([POSIX note §5](../design/posix-compatibility.md#5-what-the-kernel-must-provide)). Nothing says what authority a debugger needs. A panic reaches the UART and, while it is still scanned out, the boot framebuffer ([0009](0009-text-as-graphics-console.md), rule 5; [0042](0042-log-ring-and-panic-path.md), rule 7). Keeping panic records across a reboot is C73's.

The [design backlog, D31](../design/design-backlog.md#m2-kernel-objects) asks for the kernel debugging workflow, the interface through which a debugger reads and writes a user thread's registers and memory and the authority it needs, symbolized panics, and crash dumps. M2 is done when "Kernel panics are symbolized, a debugger can stop a user thread and read its registers and memory through a capability" ([build plan](../design/build-plan.md#m2-kernel-objects)).

seL4 lets a holder of a thread's capability suspend and resume it and read and write its registers, and, where its hardware debug API is configured, set breakpoints and watchpoints, reported as debug faults. seL4's suspend cancels the thread's current wait.

An app's build is mapped read-only and is immutable, so its code can't change at run time ([0025](0025-twelve-factor-app-contract.md), rule 6). A software breakpoint is a write to code, so it must not reach the build object. A process holds untyped memory of its job, not its job's capability, which stays with the job's manager ([0058](0058-jobs-and-budgets.md), rule 9; [0060](0060-processes-native-spawn-and-elf.md), rule 2).

Builds are reproducible bit for bit ([0038](0038-reproducible-builds-and-provenance.md), rule 1), so anything the build adds for symbolizing must be deterministic too. The kernel is a static PIE whose relocations the stub applies ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 2), and its linker script discards ELF notes, so it has no GNU build-ID note.

The mechanism behind this record is in the [kernel specification](../design/kernel-specification.md) ([0047](0047-the-kernel-follows-sel4.md), rule 5), which also lists what is still open.

Claude drafted this record on 2026-11-25.

## Decision

1. **The kernel is debugged through QEMU's gdbstub.** `cargo xtask run` gains an option that starts QEMU waiting for a debugger, and prints how to attach one with the kernel's ELF. On the Pi 4, a UART debug stub comes with C63.
2. **Panics are symbolized in the kernel.**
   - **The build makes a table of the kernel's function symbols** from the linked kernel, by offset from the kernel's start, so the table doesn't depend on where the stub places the kernel. The kernel's linked image doesn't change.
   - **The kernel's build ID is a digest of its ELF**, computed by the build.
   - **The stub carries the table** in a section of its own, beside `.kernel` ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 3), and at boot places it right after the kernel's image, inside the range the memory map types as kernel image ([0041](0041-boot-abi.md), rule 3). So the table needs no memory-map type of its own, and the kernel never hands it out as usable memory ([0048](0048-kernel-memory-and-address-spaces.md), rule 1). This adds a section to the stub and a build step after linking the kernel. It extends [0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 3 without changing it, since that rule's list of sections isn't exhaustive. This widens what the kernel-image range holds, but not what a kernel does with it, so it is no change of the memory map's meaning under [0041](0041-boot-abi.md), rule 2, and needs no major version.
   - **A new, non-critical boot-information record** gives the table's place and the build ID. It is a minor version ([0041](0041-boot-abi.md), rule 2), so a kernel that doesn't know it still boots.
   - **A panic prints each frame as symbol and offset, and the build ID.** Without the record, it prints offsets from the kernel's start.
   - **The table and the digest are deterministic**, so the build stays reproducible ([0038](0038-reproducible-builds-and-provenance.md), rule 1).
   - **Every release keeps the kernel's unstripped ELF** beside the image, with its SBOM ([0038](0038-reproducible-builds-and-provenance.md), rule 2). A host tool, `cargo xtask symbolize`, turns a panic's addresses into file and line.

   The table's format, the hash and the record are in the [kernel specification](../design/kernel-specification.md#the-panic-symbol-table).
3. **A debugger works through capabilities**, and the kernel checks nothing else.
   - **The thread's capability with read** lets it read the thread's state and registers, `TPIDR_EL0` among them ([0047](0047-the-kernel-follows-sel4.md), rule 2). **With write**, it may also suspend and resume the thread, write its registers, single-step it, set hardware breakpoints and watchpoints, which change no memory, and make itself the thread's fault handler ([0056](0056-faults-and-page-fetch-deadlines.md), rule 1).
   - **The address space's capability with read** lets it read resident memory, and list the mappings as descriptions without capabilities. **With write**, it may also write resident memory, and listing yields each mapping's memory-object capability with the mapping's rights ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 3).
   - **A debugger's access never waits and never faults the kernel.** It fails at once with "not resident" rather than wait for a pager ([0048](0048-kernel-memory-and-address-spaces.md), rule 5), and with "not RAM" at an address mapped to a device memory object, so the kernel never touches MMIO for a debugger.
   - **A write needs a mapping with the write right.** The one exception is the private clone of rule 4, mapped read-only and executable, for which the debugger also presents the clone's capability with the write right. A holder of that could map the clone writable anyway, so the exception adds no authority. So a write never reaches an immutable object ([0025](0025-twelve-factor-app-contract.md), rule 6), nor an object the process maps read-only, such as a shared file.
   - **A write never spends another job's memory.** A write to a page shared copy-on-write gives the written object its own frame, from its own job, or fails with "no memory" ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 4; [0058](0058-jobs-and-budgets.md), rule 6).
   - **A write is seen as a write.** It marks the page dirty, so the pager's write-back sees it ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 8), and a target never runs stale code after a write to an executable page.
   - **Suspending a thread doesn't cancel its wait.** A thread blocked in a call stays blocked, its donated scheduling context keeps serving the call, and a reply is held until it resumes. A wait for a page, for memory or on a word stays attached. Only an explicit cancel ends a wait ([0054](0054-ipc-endpoints.md), rule 6). This departs from seL4: with ASPIS's take-back of a canceled caller's context ([0047](0047-the-kernel-follows-sel4.md), rule 3), a debugger's stop would otherwise give a passive server a context-withdrawn fault, and re-issue a call the server had already received.

   The [kernel specification](../design/kernel-specification.md#debugger-access-to-threads-and-memory) gives the operations.
4. **Policy decides who gets those capabilities.**
   - **The manager holds them.** The process manager holds each native process's address-space capability, its main thread's capability and, as the job's manager, its job's capability ([0060](0060-processes-native-spawn-and-elf.md), rules 2 and 7). It hands a debugger copies, the thread's with read and write and the address space's with read, only when a Cedar decision allows the debug action on that process ([0018](0018-cedar-policy-language.md), rule 1; [0019](0019-authzen-decision-protocol.md), rule 1). Through the job, it finds every thread of the process, including those the runtime made ([0058](0058-jobs-and-budgets.md), rule 9).
   - **Processes can't debug each other around the policy.** No process holds its job's capability, so two processes that share a job, such as a POSIX session's, can't reach each other's threads through it.
   - **Writing memory needs the debug action with write**, and only then does the manager hand over the address space's capability with write. A realm's policy refuses that by default for production app instances. This reads [0025](0025-twelve-factor-app-contract.md), rule 6 as protecting the build object: the build never changes, and a debug session that policy allows may change one instance's code only in its private clone.
   - **Software breakpoints go into a private clone.** Under that same decision, the manager replaces the process's code mapping with a clone of that range of the immutable object, made in the process's job and mapped read-only and executable, with the process's threads stopped while it does ([kernel specification](../design/kernel-specification.md#software-breakpoints-in-a-private-clone)). Cloning an immutable object needs only the read right ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 4). The build object never changes, and no other process sees a breakpoint.
   - **The kernel interface library takes hardware breakpoints only.** Its code mapping can't be removed or moved ([0059](0059-the-kernel-interface-library.md), rule 3), so it can't be replaced by a clone.
   - **The POSIX process server does the same for `ptrace`.**
   - **Detaching undoes the session.** The manager revokes the debugger's copies, restores the fault handler, and maps the immutable object in place of any clone.
   - **One gap stays open.** Revoking the debugger's copies doesn't reach memory-object capabilities it got by listing mappings with the write right, because they derive from each mapping's own copy of its memory-object capability, not from the debugger's copy ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 3; [kernel specification K42](../design/kernel-specification.md#k42-capabilities-yielded-by-listing)). Until a record closes this, a decision that allows writing memory also grants access to the process's mapped objects that outlasts the session, and policy should allow it only where that is acceptable.
5. **Crash dumps of user processes are ELF core files.** When a process dies of a fault and policy asks for a dump, its fault handler writes one, with the registers of every thread of the process, found through its job (rule 4), and the resident memory, as an object owned by the process's owner and readable as policy allows. Writing dumps needs storage, so it starts in M3.
6. **The kernel writes no crash dump.** A kernel panic leaves its report on the UART, on the framebuffer if allowed, and in the log ring ([0042](0042-log-ring-and-panic-path.md), rule 7). Keeping that across a reboot is C73's.

## Consequences

- **Debugging needs no special kernel mode.** A debugger is an ordinary process holding capabilities, which policy granted and can revoke.
- **Panics are readable without the host.** The symbol table costs some image size and kernel memory. File and line need the host tool and the release's ELF.
- **Breakpoints never change shared code.** A software breakpoint goes into a private clone of the debugged process's code, and only when policy allows writing. By default, production app instances get hardware breakpoints and watchpoints only, and so does the kernel interface library's code everywhere.
- **A debugger can write only what the process could**, through its writable mappings or into the private clone.
- **Stopping a thread disturbs nothing else.** A suspended caller keeps its call, and its server keeps its context (rule 3).
- **Existing tools work.** GDB and LLDB read ELF core files, and attach to QEMU's gdbstub.
- **D31 is settled.** The table's format, the hash, the debugger operations and the steps of a debug session are mechanism, which the kernel specification settles with C70.

## References

- [QEMU: GDB usage](https://www.qemu.org/docs/master/system/gdb.html)
- [seL4 reference manual, 17.0.0: thread control and the hardware debug API](https://docs.sel4.systems/releases/sel4/17.0.0)
- seL4 17.0.0 source: [`src/kernel/thread.c`](https://github.com/seL4/seL4/blob/17.0.0/src/kernel/thread.c) (`suspend`, which cancels the thread's IPC)
- [0042. Log ring and panic path](0042-log-ring-and-panic-path.md); [0035. Toolchain, image linkage and ESP layout](0035-toolchain-image-linkage-and-esp-layout.md), rules 2 and 3; [0038. Reproducible builds](0038-reproducible-builds-and-provenance.md); [0041. Boot ABI](0041-boot-abi.md); [0025. Twelve-factor app contract](0025-twelve-factor-app-contract.md), rule 6
- [0057. Memory objects and pagers](0057-memory-objects-and-the-pager-protocol.md); [0058. Jobs and budgets](0058-jobs-and-budgets.md); [0059. The kernel interface library](0059-the-kernel-interface-library.md); [0060. Processes and spawn](0060-processes-native-spawn-and-elf.md)
- [Kernel specification](../design/kernel-specification.md)
