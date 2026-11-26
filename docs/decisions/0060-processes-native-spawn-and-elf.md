<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0060. Processes, native spawn and the executable format

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Native process creation is spawn-only, and `fork` lives in the POSIX personality ([POSIX note §4.2](../design/posix-compatibility.md#42-process-creation); [0012](0012-posix-compatibility-layer.md), rule 4). The environment block arrives at spawn ([0025](0025-twelve-factor-app-contract.md), rule 4). The initial image's programs are static ELF64 AArch64 programs, mapped in place ([0037](0037-initial-image-format-and-contents.md), rules 3 and 4), and user-space programs are `no_std` until there is a `std` port ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 5). The executable format for other programs, and where the dynamic linker lives, are open ([POSIX note §8](../design/posix-compatibility.md#8-open-questions)).

The [design backlog, D30](../design/design-backlog.md#m2-kernel-objects) asks what a process is at kernel level, for the native spawn interface, how programs are loaded, what initial capabilities a process gets, how the environment block is delivered, and for the executable format and where the dynamic linker lives.

seL4 has no process object. A process is a convention: an address space, a capability space and threads that a parent sets up. An object belongs to the job whose untyped memory it is made from, as in seL4. A process holds untyped memory of its job, not its job's capability, which stays with the job's manager ([0058](0058-jobs-and-budgets.md), rules 1 and 9).

The steps of spawn and the startup block's layout are in the [kernel specification](../design/kernel-specification.md) ([0047](0047-the-kernel-follows-sel4.md), rule 5), which also lists what is still open.

Claude drafted this record on 2026-11-25.

## Decision

1. **The kernel has no process object.** A process is an address space, a capability space and one or more threads, in one job, with the kernel interface library mapped ([0059](0059-the-kernel-interface-library.md), rule 3). The server that creates it names it and answers its base interface ([0050](0050-ids-for-kernel-objects.md), rule 3).
2. **Native spawn is a call on the process manager**, a user-space server. Until the process manager runs, the root server spawns with the same code.
   - Spawn takes the executable, as a capability to an immutable memory object; the job to run in, given as untyped memory that belongs to that job; the initial capabilities, each with a name; and the environment block ([0025](0025-twelve-factor-app-contract.md), rule 4).
   - **Spawn is a builder session.** The named initial capabilities can outnumber one message's three, so a spawn begins, adds up to three named capabilities per call, and then starts the process ([0066](0066-capability-parameters-and-server-streams.md), rule 3).
   - **The spawner manages the job it spawns into.** It holds that job's capability, and refuses memory of a job it doesn't manage, so it can always reach every thread of a process it started (rule 7). The caller needs no capability to the job, and the process never gets one.
   - Spawn returns the process's ID, absent for a process that isn't named yet ([0050](0050-ids-for-kernel-objects.md), rule 6), and a capability to the main thread. The [kernel specification](../design/kernel-specification.md#native-spawn-and-program-loading) lists what is open about these.
3. **The spawner loads the program, in the job given to spawn.**
   - Everything it makes for the process comes from that job's memory: address space, capability space, main thread and memory objects. So they count against that job, and end with it ([0058](0058-jobs-and-budgets.md), rules 5 and 10).
   - **Read-only segments are mapped in place** from the executable's memory object. **Writable segments are clones of it**, made in the job. The executable is immutable, so cloning it needs only the read right, and the clone may belong to any job ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 4).
   - **The program's own code doesn't run until everything is in place.**
4. **A process starts with what spawn gives it, and nothing else.**
   - Its initial capabilities are the ones named in spawn, and what its runtime needs to make its own threads (rule 7), which the [kernel specification](../design/kernel-specification.md#native-spawn-and-program-loading) lists as open.
   - **A startup block delivers them**: a read-only, versioned page the spawner fills, which carries the initial capabilities, the environment block and what the runtime needs to start, such as the kernel interface library's address ([0059](0059-the-kernel-interface-library.md), rule 5). Its fields are in the [kernel specification](../design/kernel-specification.md#the-startup-block).
   - The main thread starts at the ELF entry point, with the startup block's address in `x0`. The runtime crate, `aspis-rt` ([0059](0059-the-kernel-interface-library.md), rule 8), sets its `TPIDR_EL0` from the block.
5. **Executables are static ELF64 AArch64 programs, position-independent**, so the spawner can place them where it chooses. This applies to native programs and to POSIX programs.
6. **Dynamic linking is still open.** Whether ASPIS has shared libraries, where the dynamic linker lives and how an executable names it are decided in a later record, written with the POSIX personality (M6). One option is a user-space linker inside the process, named by the executable's `PT_INTERP` header, as on Linux and Fuchsia. The question is tracked as [design backlog, D162](../design/design-backlog.md#m6-a-console-you-can-log-in-to); [kernel specification K73](../design/kernel-specification.md#k73-dynamic-linking).
7. **Threads after the first are the process's own business.**
   - The runtime makes them through the kernel interface library, from untyped memory of its own job. Each one's IPC buffer is a page of a memory object in that job or an ancestor's ([0054](0054-ipc-endpoints.md), rule 3).
   - It sets each new thread's `TPIDR_EL0` through the thread's capability with the write right, as seL4 sets a thread's TLS base ([0047](0047-the-kernel-follows-sel4.md), rule 2).
   - They carry no ID unless presented ([0050](0050-ids-for-kernel-objects.md), rule 4).
   - **The job's manager reaches them through the job.** As the manager of the process's job (rule 2), the process manager lists the job's threads with their address spaces, and picks those whose address space is the process's ([0058](0058-jobs-and-budgets.md), rule 9). So it reaches every thread of the process, for debugging and crash dumps ([0061](0061-debugging.md), rules 4 and 5).
   - **Processes that share a job can't reach each other through it**, because no process holds its job's capability.

## Consequences

- **Spawn is the only way to start a native program**, and it hands over only the capabilities it names. A process has no ambient authority.
- **A process's memory is its job's.** The spawner pays nothing for it, and ending the job destroys it ([0058](0058-jobs-and-budgets.md), rule 10).
- **Executables share pages.** Read-only segments are mapped from the executable's memory object, so every instance shares them, charged once, to the job that object belongs to ([0058](0058-jobs-and-budgets.md), rule 11). Each process pays only for its page tables and mapping records. An executable mapped in place from the initial image is part of a boot object, charged to no job ([0058](0058-jobs-and-budgets.md), rule 1).
- **A program can't make the cache that holds its executable fail.** Touching the executable's pages charges the cache's job, and when that job can't get more memory, its pager evicts clean pages before any fault fails ([0058](0058-jobs-and-budgets.md), rules 6 and 7).
- **The kernel never parses ELF.** A malformed executable is the process manager's problem, and its ELF parser is a fuzzing target (C71).
- **Position-independent executables leave room for address-space randomization** (C78).
- **D30 is settled except for dynamic linking**, which rule 6 leaves to a later record ([design backlog, D162](../design/design-backlog.md#m6-a-console-you-can-log-in-to); [kernel specification K73](../design/kernel-specification.md#k73-dynamic-linking)). The capabilities a runtime needs and the startup block's layout are mechanism, which the kernel specification settles with C17.

## References

- [ELF for the Arm 64-bit Architecture (AArch64)](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst)
- [Fuchsia process creation: processargs](https://fuchsia.dev/fuchsia-src/concepts/process/program_loading)
- [seL4 reference manual, 17.0.0: thread control and the TLS base](https://docs.sel4.systems/releases/sel4/17.0.0)
- [POSIX note](../design/posix-compatibility.md); [0025. Twelve-factor app contract](0025-twelve-factor-app-contract.md), rule 4; [0037. Initial image](0037-initial-image-format-and-contents.md); [0057. Memory objects and pagers](0057-memory-objects-and-the-pager-protocol.md); [0058. Jobs and budgets](0058-jobs-and-budgets.md); [0066. Capability parameters](0066-capability-parameters-and-server-streams.md), rule 3
- [Kernel specification](../design/kernel-specification.md)
