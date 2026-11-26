<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0059. The kernel interface library

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Programs reach system calls only through a kernel interface library mapped into every process, as with Fuchsia's vDSO. The library exposes versioned interfaces for kernel objects, and the raw system-call ABI can change underneath it ([0014](0014-versioned-object-apis.md), rule 6). A major version stays available for a declared support period after its successor ships ([0014](0014-versioned-object-apis.md), rule 7).

As accepted, [0013](0013-abnf-for-protocols-and-calls.md), rule 2 said ABNF describes "every RPC and IPC call: the message header, each method's request and reply, and error replies", generated from the IDL. Rule 3 made the generated grammar "normative for the wire format", and had conformance tests check real messages against it. A raw ABI that changes underneath the library has no stable grammar. The [design backlog](../design/design-backlog.md#conflicts-between-accepted-adrs) lists this as a conflict between accepted records that D29 settles, and names one option: define the library's interfaces in the IDL, and treat the raw ABI as no IPC call, unpublished. Since the two rules conflict, the project owner chose on 2026-11-25 to edit 0013 rather than read it narrowly. This record was proposed with that edit, in the same pull request, and the edit is kept narrow. 0013's rule 2 now exempts only the private ABI, and its rule 3 says what the generated grammar means for the `[kernel]` interfaces, which have no wire form (rule 7).

The kernel also sends messages of its own to user-space servers: fault messages to fault handlers, page requests to pagers and memory requests to the memory server ([0056](0056-faults-and-page-fetch-deadlines.md); [0057](0057-memory-objects-and-the-pager-protocol.md); [0058](0058-jobs-and-budgets.md)). Those servers parse them as they parse any other IPC message.

The [design backlog, D29](../design/design-backlog.md#m2-kernel-objects) also asks for the library's name, packaging and mapping; whether the kernel accepts calls only from it; how long its versions are supported; and how early servers, relibc and Rust's standard library use it.

Fuchsia's kernel accepts system calls only from its vDSO's code. Its documentation says this mitigates programs bypassing the vDSO only "somewhat". Its vDSO has no writable segment and needs no dynamic relocations, so one copy serves every process.

User-space programs are `no_std` until there is a `std` port ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 5), and the initial image's programs are static ELF ([0037](0037-initial-image-format-and-contents.md), rule 3), so they have no dynamic linker to bind them to a shared library by symbol.

Claude drafted this record on 2026-11-25, with the project owner's choices: to edit 0013, and the names `aspis-kernel-interface` and `aspis-rt`.

## Decision

1. **The kernel's interfaces are written in the IDL**, under the reserved ASPIS authority ([0014](0014-versioned-object-apis.md), rule 2): one interface for each kind of kernel object, including the log ring and the boot framebuffer ([0042](0042-log-ring-and-panic-path.md), rules 5 and 6).
   - Their generated ABNF describes the calls' canonical text form ([0013](0013-abnf-for-protocols-and-calls.md), rule 5). They have no wire form of their own, because the only way to make the calls is the private ABI (rule 2). [0013](0013-abnf-for-protocols-and-calls.md), rule 3 says so (rule 7).
   - An interface may include operations that the library builds from several system calls, such as copying a capability table ([0049](0049-capability-spaces-rights-and-revocation.md)).
   - Each is a `[kernel]` interface named `aspis.kernel.<object>`, such as `aspis.kernel.eventcount` ([0063](0063-names-and-the-canonical-call-text.md), rule 3). The pager capability's is `aspis.kernel.pager_object`, so no name collides with the interfaces the kernel calls (rule 2). D35 assigns their IDs under the reserved authority.
   - The kernel knows no object's ID ([0050](0050-ids-for-kernel-objects.md), rule 1), and a `[kernel]` call names its object only by capability, so the target in a call's canonical text is `-` ([0063](0063-names-and-the-canonical-call-text.md), rule 9).
   - Their failures are typed errors of their own interfaces, such as `aspis.kernel.eventcount/1!overflow`, declared in their IDL. The raw status numbers stay private (rule 2; [0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rule 8).
   - The log ring's read is a lossy server stream ([0066](0066-capability-parameters-and-server-streams.md), rule 6).
2. **The raw system-call ABI is private.**
   - The instruction, the call numbers and the use of registers belong to the kernel and the library, which are built together. The raw ABI isn't published, has no grammar and may change in any release.
   - Messages the kernel itself sends to user-space servers aren't part of it. Fault messages, page requests and memory requests are IPC messages. They are defined in the IDL, with generated grammars, as every other IPC message is ([0013](0013-abnf-for-protocols-and-calls.md), rules 2 and 3).
   - The interfaces the kernel calls, `aspis.kernel.fault`, `aspis.kernel.pager` and `aspis.kernel.memory_request`, are implemented by user-space servers. They are `[local]` interfaces, not `[kernel]` ones, so they keep wire grammars, and no network server carries them ([0064](0064-the-call-header-and-wire-encoding.md), rule 9).
3. **The library ships inside the kernel, and every address space maps the same copy.**
   - Its name is the kernel interface library. It is built from the crate `aspis-kernel-interface`.
   - The build embeds it in the kernel's image, so `aspis.efi` always carries a kernel and a library that match. The kernel never executes it.
   - It has no writable segment and needs no dynamic relocations, so one read-only copy serves every address space, wherever it is mapped.
   - At boot the kernel makes it an immutable memory object and gives it to the root server. Like the kernel's other boot objects, it belongs to no job and is never destroyed ([0048](0048-kernel-memory-and-address-spaces.md); [0058](0058-jobs-and-budgets.md)).
   - Whoever creates an address space maps the library into it. The kernel itself records where the library's code is mapped, and doesn't take the creator's word for it. An address space has at most one executable mapping of the library's code, and that mapping can't be removed or moved while the address space exists.
   - So a debugger can't put a software breakpoint in the library's code, which would need a private clone mapped in its place. Only hardware breakpoints work there ([0061](0061-debugging.md)).
   - The [kernel specification](../design/kernel-specification.md#the-kernel-interface-library) gives the library's packaging, how it is mapped and how the kernel recognizes it.
4. **The kernel accepts system calls only from the library.**
   - A system call from outside the library's code mapping (rule 3) becomes an unknown-system-call fault ([0056](0056-faults-and-page-fetch-deadlines.md)).
   - This stops programs from embedding the raw trap instruction, and so from coming to depend on the raw ABI. It is a stability measure, not a security boundary. A program could still set the registers itself and jump to the library's trap instruction, and would gain no authority by it, since every call is checked against the capabilities it names.
   - Whether the kernel also checks that each call comes from the place in the library that makes that call, as Fuchsia's does, is still open. It is a question for the [kernel specification](../design/kernel-specification.md#open-questions).
5. **Programs reach the library through an entry table, not by symbol.** The library starts with a table of the interfaces and major versions it supports. A program's runtime finds the library's address in its startup block ([0060](0060-processes-native-spawn-and-elf.md)), looks up the versions it was built for, and calls through them. The table holds no absolute address, so it works wherever the library is mapped, and a static program needs no dynamic linker. The [kernel specification](../design/kernel-specification.md#the-kernel-interface-library) gives the table's layout.
6. **Each major version is supported for the period the API policy sets** ([0014](0014-versioned-object-apis.md), rule 7). The library carries every major version still in its period. The period itself is set with the API policy, and is still open ([design backlog, D115](../design/design-backlog.md#m7-workloads-and-discovery); [kernel specification K61](../design/kernel-specification.md#k61-support-period-of-the-librarys-major-versions)).
7. **Only the private ABI goes without a wire grammar.** Every other IPC message, the kernel's own messages to servers included (rule 2), keeps a generated grammar that is normative for its wire format ([0013](0013-abnf-for-protocols-and-calls.md), rules 2 and 3).
   - The private system-call ABI is the one exception to [0013](0013-abnf-for-protocols-and-calls.md), rule 2.
   - For the `[kernel]` interfaces, the generated grammar defines the canonical text form of their calls, and conformance tests check text renderings of their calls against it ([0013](0013-abnf-for-protocols-and-calls.md), rule 3).
8. **Everything above the library goes through the runtime crate.** ASPIS's `no_std` runtime crate, `aspis-rt`, wraps the entry table in Rust. Early servers use it directly. relibc's ASPIS backend and any later `std` port are built on it, so that only one piece of code knows the entry table.

## Consequences

- **The raw ABI can change freely.** Only the library, which is built with the kernel, needs to know it.
- **0013 and 0014 agree.** Every kernel interface has IDL, and ABNF for its canonical text form. Every IPC message, the kernel's fault messages and requests included, has a wire grammar. The one thing without a grammar is private to a pair of components that ship together. The [design backlog](../design/design-backlog.md#conflicts-between-accepted-adrs)'s conflict between the two is settled by the edits to 0013's rules 2 and 3 that rule 7 relies on.
- **The check is cheap, and guards stability, not authority.** It keeps honest programs off the raw ABI. It doesn't stop a determined one, and doesn't need to.
- **Old programs keep working** for as long as their major versions are in their support period, whatever happens to the raw ABI.
- **C17 depends on the IDL compiler (C07)**, because the library's interfaces and `aspis-rt`'s wrappers are generated from the IDL.
- **This record settles D29**, except for two things. Its name, packaging and mapping are rule 3's. Its interfaces are in the IDL under the reserved authority (rule 1). The kernel accepts calls only from it (rule 4). Early servers, relibc and `std` use it through `aspis-rt` (rule 8). Still open: the support period, which the API policy sets (rule 6; [design backlog, D115](../design/design-backlog.md#m7-workloads-and-discovery); [kernel specification K61](../design/kernel-specification.md#k61-support-period-of-the-librarys-major-versions)), and whether the kernel checks each call's place in the library, which the kernel specification settles with C17 (rule 4).

## References

- [Fuchsia vDSO](https://fuchsia.dev/fuchsia-src/concepts/kernel/vdso)
- [0013. ABNF for protocols and calls](0013-abnf-for-protocols-and-calls.md), rules 2, 3 and 5; [0014. Versioned object APIs](0014-versioned-object-apis.md), rules 2, 6 and 7
- [0042. The kernel log ring and the panic path](0042-log-ring-and-panic-path.md), rules 5 and 6
- [0048. Kernel memory](0048-kernel-memory-and-address-spaces.md); [0049. Capability spaces](0049-capability-spaces-rights-and-revocation.md); [0056. Typed faults](0056-faults-and-page-fetch-deadlines.md); [0057. Memory objects and the pager protocol](0057-memory-objects-and-the-pager-protocol.md); [0058. Jobs and budgets](0058-jobs-and-budgets.md)
- [0060. Processes](0060-processes-native-spawn-and-elf.md); [0061. Debugging](0061-debugging.md)
- [0063. Names and the canonical call text](0063-names-and-the-canonical-call-text.md); [0064. The call header](0064-the-call-header-and-wire-encoding.md); [0065. Typed errors](0065-typed-errors-and-minor-versions-on-the-wire.md); [0066. Capability parameters and server streams](0066-capability-parameters-and-server-streams.md)
- [The kernel specification](../design/kernel-specification.md)
