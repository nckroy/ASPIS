<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# The kernel specification

*2026-11-25, updated 2026-11-26. The kernel specification: the mechanism behind the M2 kernel records, and every mechanism question still open. It follows ADRs 0047 to 0061, and records what C10 and C11 settled.*

This note is the kernel specification that [0047](../decisions/0047-the-kernel-follows-sel4.md), rule 5 names. The records say what is decided, what is guaranteed, and why. This note says how the kernel does it: each object's operations and their arguments, the order of steps inside the kernel, and the queue and allocation strategies.

- **seL4 fills the gaps.** Where this note says nothing, the kernel does what the reference manual of seL4 17.0.0 with MCS says ([0047](../decisions/0047-the-kernel-follows-sel4.md), rule 1). ASPIS follows seL4's design, not its code, and copies no seL4 source.
- **The records win.** Every mechanism here must keep the guarantees of the records, listed in [Invariants the prototype checks](#invariants-the-prototype-checks). If a section here and a record disagree, the record is right and the section is wrong.
- **It changes with the prototype.** The mechanism is settled alongside a prototype of chunks C10 to C16, or of C17 for the kernel interface library and C70 for debugging. This note may change with the prototype without an edit to the records, as long as every guarantee still holds. A change that would break one is an edit to the record that gives the guarantee, proposed in the pull request that needs it ([0047](../decisions/0047-the-kernel-follows-sel4.md), rule 5).
- **Open questions are numbered.** Each is listed once, as K01, K02, …, under [Open questions](#open-questions) at the end, and the sections link to them. The [design backlog](design-backlog.md#m2-kernel-objects) carries them as D150 to D160, grouped, under M2. D161, under [M3](design-backlog.md#m3-node-user-space-and-the-entropy-gate), carries K12, and D162, under [M6](design-backlog.md#m6-a-console-you-can-log-in-to), carries K73. K10 and K61 belong to D95 and D115.
- **The records are accepted.** The project owner accepted ADRs 0047 to 0061 on 2026-11-25, with the call-language records 0062 to 0068 that this note cites for message layouts ([call-language specification](call-language.md)).

The sections follow the order in which the kernel is built: memory and address spaces, capabilities, threads and scheduling, SMP, IPC, eventcounts, interrupts, memory objects and paging, faults, jobs and memory reclaim, the kernel interface library, processes and spawn, debugging, and the boot hand-off.

## The model

### How far the kernel follows seL4

The kernel follows seL4 17.0.0 with MCS enabled ([0047](../decisions/0047-the-kernel-follows-sel4.md), rule 1).

It adopts these seL4 mechanisms unchanged, except where a later section says otherwise ([0047](../decisions/0047-the-kernel-follows-sel4.md), rule 2):

- untyped memory and retype;
- thread control blocks, with `TPIDR_EL0` saved and restored as seL4 saves its TLS base;
- CNodes, rights, badges and the capability derivation tree;
- MCS scheduling contexts, passive servers and donation;
- SMP under one kernel lock;
- synchronous endpoints with call and reply, the per-thread IPC buffer and 120 message words;
- interrupt handler capabilities;
- a fault endpoint and a timeout endpoint per thread.

The departures of [0047](../decisions/0047-the-kernel-follows-sel4.md), rule 3 change seL4's mechanism as follows.

- **Eventcounts replace notifications.** The kernel has no notification object. Where seL4 binds a notification to a thread, ASPIS binds an eventcount ([0053](../decisions/0053-eventcounts.md), rule 5). Where seL4 delivers an interrupt to a notification, ASPIS advances an eventcount ([0055](../decisions/0055-interrupt-objects.md), rule 2).
- **Memory objects are kernel objects.** seL4 sends every page fault to the faulting thread's fault endpoint, and leaves paging to user space. In ASPIS, a fault on a missing page of a mapped memory object goes to the object's pager as a page request ([0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 6). Faults that aren't about a missing page, such as an access with no mapping or without the needed right, still go to the thread's fault endpoint ([0056](../decisions/0056-faults-and-page-fetch-deadlines.md), rule 1).
  - To do this, the kernel keeps records that no capability names: a record for each mapping, linked to its memory object so that a page can be unmapped everywhere; each object's page tracking (its page index, pending marks and dirty state); and a share count for each frame that copy-on-write clones share.
  - seL4 makes no object that lacks a capability. These records are made from the memory of the job responsible: the address space's job for page tables and mapping records, and the memory object's job for its page tracking ([0048](../decisions/0048-kernel-memory-and-address-spaces.md); [0058](../decisions/0058-jobs-and-budgets.md)). How they are allocated inside that memory is open ([K02](#k02-small-kernel-records)).
- **Jobs are kernel objects.** seL4 has none. Each piece of untyped memory belongs to a job, and an object belongs to the job whose untyped memory it is made from. The job's capability gives the job memory, makes child jobs, lists, stops, resumes and ends the job's threads, and sets its limits. A process holds untyped memory of its job, not the job's capability, which stays with the job's manager ([0058](../decisions/0058-jobs-and-budgets.md), rule 9; [Job capabilities](#job-capabilities)).
- **Every blocking operation takes a deadline and can be canceled.** seL4's endpoint operations take no timeout, and MCS reports only budget exhaustion as a timeout fault. ASPIS adds an optional deadline argument to every blocking call, and a cancel operation on the thread's capability ([0054](../decisions/0054-ipc-endpoints.md), rules 5 and 6; [0053](../decisions/0053-eventcounts.md), rule 7; [0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 5).
- **Canceling a call takes the caller's scheduling context back.** In seL4 17.0.0, `cancelIPC` in `src/object/endpoint.c` calls `reply_remove_tcb` for a caller blocked on a reply, and the donated scheduling context stays with the server. In ASPIS the kernel invalidates the reply object, returns the context to the caller from wherever it has been donated along a chain of calls, and sends each passive server left without a context a context-withdrawn fault on its timeout endpoint. The steps are in [Passive servers and taking a context back](#passive-servers-and-taking-a-context-back).
- **Suspending a thread doesn't cancel its wait.** seL4's `suspend` cancels the thread's IPC. ASPIS leaves the wait in place ([0061](../decisions/0061-debugging.md), rule 3; [Suspending a thread](#suspending-a-thread)).
- **Up to three capabilities transfer in a message.** seL4's receiver names one receive slot in its IPC buffer, by a CNode, an index and a depth, and `transferCaps` in `src/kernel/thread.c` moves at most one capability into it. In ASPIS the receiver names up to three receive slots, and up to three capabilities move, each into its own slot, as a child of the sender's capability. The rest of transfer follows seL4, unwrapping included ([0054](../decisions/0054-ipc-endpoints.md), rule 7; [Capability transfer](#capability-transfer)).
- **Every copy is a child of the capability it came from.** seL4's mapping database marks a new capability revocable only when it is untyped memory, a newly badged endpoint copy or made by retype (`isCapRevocable`), and a plain copy becomes its source's sibling, so revoking a plain copy deletes nothing. ASPIS records each slot's depth in the tree instead, and inserts every copy, badged copy, transfer, binding and retype one level below the capability it came from, as [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 4 requires. When a capability that has children is deleted, its children stay under its parent, behind a barrier that keeps them out of any sibling's run. So revoking any capability reaches exactly what was derived from it, and the revocable and first-badged marks are gone ([Derivation and revocation](#derivation-and-revocation)).
- **Deleting an object finishes the objects that only it reached.** seL4's `reduceZombie` (in `src/object/cnode.c`) moves the zombie of a nested object, such as a CNode whose last capability was in the CNode being deleted, into that object's own first slot, and leaves it there with its slots uncleared until a revocation of its untyped memory reaches it. [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 4 says that when the last capability to an object is deleted, the object is destroyed, so ASPIS clears the nested object in the same deletion: waiting zombies are kept on a stack threaded through park slots, with bounded work per step and no recursion ([Derivation and revocation](#derivation-and-revocation)). Only objects that hold each other's last capabilities and that no lookup can name still wait for their untyped memory's revocation, as in seL4.
- **Fault replies carry no register values.** seL4's fault replies may set some of the faulting thread's registers. In ASPIS the reply only resumes the thread, and the kernel reads none of its contents. A handler that changes registers does so through the thread's capability before it replies ([0061](../decisions/0061-debugging.md), rule 3; [0064](../decisions/0064-the-call-header-and-wire-encoding.md), rule 9; [Fault delivery](#fault-delivery)).
- **A capability's kind and rights can be read.** seL4 reports a capability's type only through a call in debug builds. ASPIS adds identify, which any build offers ([Capability spaces and lookup](#capability-spaces-and-lookup); [0066](../decisions/0066-capability-parameters-and-server-streams.md), rules 1 and 4).
- **Message lengths are in octets.** seL4's message info gives a message's length in words. ASPIS's gives octets, from 0 to 960, so every message has an exact end ([0054](../decisions/0054-ipc-endpoints.md), rule 3; [0064](../decisions/0064-the-call-header-and-wire-encoding.md), rule 2; [Endpoint operations and messages](#endpoint-operations-and-messages)).
- **System calls come only from the kernel interface library.** seL4 accepts a system call from any address. ASPIS accepts one only from the library's code mapping ([The kernel interface library](#the-kernel-interface-library)).
- **The log ring and the boot framebuffer are kernel objects** ([0042](../decisions/0042-log-ring-and-panic-path.md), rules 5 and 6). seL4 has neither.

### Invariants the prototype checks

[0047](../decisions/0047-the-kernel-follows-sel4.md), rule 6 lists the guarantees that every mechanism in this note must keep. The prototype of C10 to C16 checks each one with tests.

| Invariant | Decided in | What the prototype shows |
|---|---|---|
| The kernel never waits for anything outside itself | [0047](../decisions/0047-the-kernel-follows-sel4.md), rule 4 | A pager, server or memory server that never answers delays only the threads waiting on it. Other threads' system calls on every core complete, and no kernel lock is held while a thread waits |
| The kernel never dereferences a user address, and never takes a page fault in kernel mode | [0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 5 | Every system call that names user memory reaches it through the direct map after a software walk, and fails with "not resident" rather than fault. The kernel treats a synchronous abort taken at EL1 as a panic, and tests run with PAN on where the CPU has it |
| After boot, the kernel never allocates memory that no job supplied | [0047](../decisions/0047-the-kernel-follows-sel4.md), rule 2; [0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 1 | The kernel has no heap. Each object, page table and kernel record is charged to a job, and a job's accounting returns to zero when the job ends |
| No mapping is both writable and executable | [0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 6 | A request for a writable and executable mapping is refused, and a walk of every page table, kernel and user, finds no entry that is both |
| Every blocking call takes a deadline and can be canceled | [0047](../decisions/0047-the-kernel-follows-sel4.md), rule 3 | Every blocking operation in the kernel's interfaces has a deadline argument. A test blocks a thread in each one, then cancels it, and lets another's deadline pass |
| Reservations are never taken away; memory is reclaimed before it is refused; there is no out-of-memory killer | [0058](../decisions/0058-jobs-and-budgets.md), rules 3, 6 and 7 | Under memory pressure, a job within its reservation keeps working, and a job that can't borrow gets a typed memory fault, never a kill |
| A writer never spends another job's memory; a reader can't make another job's faults fail while that job has clean pages to evict | [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 4; [0058](../decisions/0058-jobs-and-budgets.md), rule 6 | A write to a shared copy-on-write page is charged to the writer's object's job only. A reader that touches many pages of a cache job causes evictions in that job, not failed faults, both when the job is at its limit and when it is below its limit on a node whose pool is used up |
| Raw capabilities never leave a node | [0002](../decisions/0002-capability-security-model.md), rule 5 | The kernel has no network code. This is checked in the network server, not in the kernel |

## Memory and address spaces

### Boot memory

This section gives the mechanism behind [0048](../decisions/0048-kernel-memory-and-address-spaces.md), rules 1 and 2.

At boot the kernel reads the boot information's memory map ([0041](../decisions/0041-boot-abi.md), rule 3) and keeps these ranges for itself:

- its image, which the memory map types as kernel image, except the pages of the kernel interface library that the image carries;
- the panic symbol table, which the stub places right after the kernel image, inside the same range ([The panic symbol table](#the-panic-symbol-table));
- one stack per core;
- its own page tables for the upper half;
- the log ring ([0042](../decisions/0042-log-ring-and-panic-path.md), rule 1);
- per-interrupt state for every SPI, and for every LPI the kernel will use ([Interrupt handlers](#interrupt-handlers));
- on a GICv3, the redistributors' LPI property and pending tables, sized for a number of LPIs fixed at boot ([MSI and the GICv3 ITS](#msi-and-the-gicv3-its));
- the memory for its boot objects, which [What the root server receives](#what-the-root-server-receives) lists.

Everything else in usable RAM goes to the root server as untyped memory, in the root job. Boot objects belong to no job, count against no reservation or limit, and are never destroyed. Page tables and mapping records made later for the root server's address space come from the root job ([0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 1).

**How the kernel divides the memory map (C10).**

- **Rounding.** Usable ranges are rounded inward to whole pages, and every other type outward.
- **Precedence.** Where ranges overlap, the more restrictive type wins, in this order:
  1. firmware-reserved, ACPI reclaimable, ACPI non-volatile, unusable, and any type the kernel doesn't know;
  2. the seed;
  3. the framebuffer;
  4. the kernel image, the initial image and the boot information;
  5. MMIO;
  6. usable.
- **Kept ranges are kept whole.** The kernel image, initial image and boot information ranges are kept with their slack pages. So the panic symbol table, inside the kernel image's range, is kept with the image. The stub's alignment slack, up to 2 MiB, is kept too.
- **ACPI memory is left alone.** ACPI reclaimable memory is neither in the direct map nor untyped memory. Whether it is given out once the tables are read is C65's choice.
- **RAM beyond the direct map's reach** isn't used. That is usable RAM at or above 2^47 ([Address-space layout](#address-space-layout)). The boot log says how much there was.
- **The boot allocator** is the kernel's only page source before untyped memory exists.
  - It hands out single pages of usable RAM, top-down from the highest usable range. The kernel zeroes each page it takes.
  - Before the switch to the kernel's own tables, the kernel reaches each page it takes through the boot window ([Address-space layout](#address-space-layout), "Bootstrap tables and the switch"), so the allocator may take any usable page.
  - It serves the kernel's own page tables, and later chunks' boot objects, other cores' stacks and the LPI tables.
  - Once the boot objects are made, the kernel seals it. A request after that is a kernel bug, and panics ([0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 1).
- **Untyped memory** is the usable RAM below 2^47 that the boot allocator never handed out. The kernel splits it into naturally aligned power-of-two pieces, from 4 KiB to 2^47 bytes, the largest that fit first, and zeroes it once ([Untyped memory and kernel records](#untyped-memory-and-kernel-records)).
- **Device untyped memory** follows seL4: everything up to the processor's physical address size that no memory-map range other than MMIO covers.
  - The size comes from `ID_AA64MMFR0_EL1.PARange`, at most 48 bits. Every range is rounded outward here, so a page that holds any RAM is never device memory.
  - It leaves out the devices the kernel drives ([0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 1): the PL011's `reg`, and every `reg` of the interrupt controller's node (`arm,cortex-a15-gic`, `arm,gic-400` or `arm,gic-v3`) and of its children (`arm,gic-v2m-frame`, `arm,gic-v3-its`).
  - The kernel doesn't translate addresses through a bus's `ranges` yet. So it reads a `reg` as a physical address only where that is certain: the UART's node and the interrupt controller's node must be children of `/`, and the interrupt controller's children need its `ranges` to be empty, as QEMU `virt`'s is.
  - The kernel stops at boot, rather than give a frame of its own devices away, when it can't name them for certain: with no device tree, with no interrupt controller it knows, with one of these nodes elsewhere in the tree, or with a `reg` it can't read. C65 reads the same devices from ACPI's MADT and SPCR. The Pi 4's devices sit under `/soc`, whose `ranges` translate them, so booting it (MH) needs the translation first.
  - It is never zeroed, and never in the direct map.
- **The boot capability space** holds up to 2048 pieces, RAM and device together, as untyped capabilities ([What the root server receives](#what-the-root-server-receives)). A piece beyond that panics in a test build. In production it goes unused, with a warning in the boot log.
- **The boot core's stack and the log ring** are in the kernel image's `.bss`. The stack has a page-aligned section of its own, with an unmapped guard page below it, so an overflow takes a translation fault, which panics and names the overflow, rather than corrupting `.bss`. The exception entry's own frames then land below the guard page, in the bootstrap tables, which nothing uses after the switch. The empty table that `TTBR0_EL1` holds when no user address space is active is live, so it isn't among them: it is read-only data in the image, which the kernel's tables map read-only.

### Untyped memory and kernel records

This section gives the mechanism behind [0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 1, and [0058](../decisions/0058-jobs-and-budgets.md), rules 1, 3 and 4.

- **Retype.** Every object made after boot is made by retyping untyped memory, as in seL4. The object belongs to the job of the piece it came from. No call that makes an object names a job, and none needs a job's capability, except making a child job ([Job capabilities](#job-capabilities)).
- **Where objects go in a piece.** As in seL4, a piece has a watermark: below it, memory has been retyped; above it, memory is free. A retype aligns the watermark up to the object's size, then places the objects one after another. Device untyped memory makes only frames and smaller device untyped pieces, so the kernel never keeps its own records in MMIO.
- **Retype through capabilities (C11).** Retype takes an untyped capability, an object type with its size, and a run of empty slots in one CNode, as seL4's `Untyped_Retype` does. It makes at most 256 objects, seL4's default fan-out limit, and inserts each new capability as a child of the untyped capability. The watermark lives in the untyped capability, as in seL4. Copying an untyped capability marks the source full, as seL4's `setUntypedCapAsFull` does, so two capabilities to one piece never hand out the same memory, and an untyped capability with children can't be copied. Page tables get no capability ([Address-space layout](#address-space-layout)).
- **Pieces.** A job holds its memory as pieces of untyped memory. Reserved memory is carved from the parent's reservation. Borrowed memory is lent from the pool in page-sized pieces, or in larger pieces for large objects, so that a piece the job empties can be returned whole. Which objects come from which size is open ([K04](#k04-piece-sizes)).
- **The index of a job's pieces.** The kernel keeps, for each job, an index of the pieces it holds, so that it can find free memory on a fault, when no caller names any. Where the index's own memory comes from is open ([K03](#k03-the-index-of-a-jobs-pieces)).
- **Small records.** A fault can need records that have no capability of their own: mapping records, nodes of an object's page index, pending marks and per-frame share counts. They come from the job responsible ([0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 2). seL4's untyped memory is a watermark allocator, so small records freed inside a piece can't be reused until the piece is empty. How the kernel keeps them is open ([K02](#k02-small-kernel-records)).
- **Which piece a fault uses.** Whether the kernel takes a fault's memory from reserved pieces before borrowed ones is open ([K05](#k05-which-pieces-a-fault-uses-first)).
- **Untyped capabilities a process holds.** A job's manager gives the job memory through the job's capability, and may pass untyped capabilities for those pieces to the job's processes, which make objects from them. How that relates to the pieces the kernel uses for faults is open ([K06](#k06-untyped-capabilities-and-fault-memory)).
- **Taking a piece back.** The memory server takes an empty piece back in one kernel operation. Under the kernel lock, the kernel checks that nothing has been made from the piece, and removes it from the job and its index in the same step. It fails if anything has been made from it. So taking back can't race with a retype or a fault.
- **Clearing.** Free untyped memory is always zero, so a retype never needs to clear.
  - The kernel zeroes RAM untyped memory once at boot.
  - A reset clears the used part from the top down, in 64 KiB chunks, and records its progress in the watermark, as seL4's `resetUntypedCap` does. So a reset is a long operation that resumes where it stopped ([The kernel lock and long operations](#the-kernel-lock-and-long-operations)).
  - As in seL4, a piece is reset only when nothing derives from its capability, which the derivation tree shows: a retype through an untyped capability with no children resets the piece first, then makes objects from its start. The kernel writes the lowered watermark back into the capability after each chunk, so a preempted retype resumes the reset where it stopped. A retype through a capability that has children makes objects from the watermark.
  - Device untyped memory is never cleared: a reset only lowers its watermark to zero.
  - The kernel can also reset a piece that nothing derives from without making anything. seL4 has no such call, and no system call reaches it: the kernel's tests use it to leave a piece free and zero, and C16 may use it when the memory server takes an empty piece back (C11).
- **Cost.** This note will give, for each object type, its size in bytes, so that a size ([0058](../decisions/0058-jobs-and-budgets.md), rule 12) can leave room for kernel bookkeeping. Several sizes wait on open questions ([K07](#k07-where-binding-copies-live-and-object-sizes)). C10's and C11's objects:

  | Object | Size |
  |---|---|
  | Untyped memory | 2^n bytes, from 4 KiB to 2^47 |
  | Frame | 4 KiB, 2 MiB or 1 GiB |
  | Page table, at any level | 4 KiB |
  | Address space | 8 KiB: its level-0 table, then a 4 KiB kernel record. The record is a 32-byte header, whose first word is the ASID word and whose other three are kept for C15 and C16, then 127 capability slots. Slot 0 is the park slot that deletion uses, and slots 1 to 126 hold the copies its mappings keep, until C15's mapping records replace them ([Kernel bindings that hold capabilities](#kernel-bindings-that-hold-capabilities)). The level-0 table needs all 512 entries for a 48-bit lower half, so the record can't live inside it |
  | CNode | 2^(n+5) bytes: 2^n slots of 32 bytes, n from 1 to 42 |
  | Endpoint | 64 bytes, provisional until C14 settles its layout ([K25](#k25-ordered-queue-structures)) |

### Address-space layout

This section gives the mechanism behind [0048](../decisions/0048-kernel-memory-and-address-spaces.md), rules 3, 4 and 6.

- **Granule.** 4 KiB pages, with 2 MiB and 1 GiB block mappings where a range is aligned and has one set of attributes. Addresses are 48 bits in each half.
- **Lower half (`TTBR0`).** Each address space has its own translation tables and an ASID. The ASID width is 16 bits where `ID_AA64MMFR0_EL1.ASIDBits` says the processor supports it, and 8 bits otherwise. No job can exhaust the ASIDs ([0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 4), because they are given out by generation rollover, below, which settles [K01](#k01-asid-allocation).
- **Upper half (`TTBR1`).** It starts at `0xffff_0000_0000_0000`. It holds the kernel's image, at the base `0xffff_8000_0000_0000` that C05 chose, the stacks, the interrupt controller's frames and the UART, the boot framebuffer until it is retired ([0042](../decisions/0042-log-ring-and-panic-path.md), rule 6), and the direct map. The generic timer is reached through system registers and needs no mapping.

  | Virtual address | Holds |
  |---|---|
  | `0xffff_0000_0000_0000` + PA | The direct map, for physical addresses below 2^47 |
  | `0xffff_8000_0000_0000` | The kernel's image, at most 32 MiB. The boot core's stack and the log ring are in its `.bss` |
  | `0xffff_8000_4000_0000` | The device window, 1 GiB: the UART, then the boot framebuffer, and from C13a the interrupt controller's frames. Addresses are handed out in order, and each mapping keeps its physical address's offset within 2 MiB, so blocks can be used |

  Where the other cores' stacks are mapped is C12's.
- **The direct map.** It covers usable RAM and the ranges that hold the boot objects. It is never executable. The kernel image's range is mapped read-only. It leaves out the UEFI runtime regions and other firmware-reserved memory ([0039](../decisions/0039-no-uefi-runtime-services.md), rules 1 and 2), the seed's page, the framebuffer and all MMIO.
- **Attributes.** Kernel text is read-only and executable at EL1. Kernel read-only data is read-only. Everything else in the upper half is read-write and never executable. Every kernel mapping is UXN, and every user mapping is PXN. The kernel refuses a user mapping that is both writable and executable. PAN is set where the processor implements it (Armv8.1 and later).
- **Memory types.** `MAIR_EL1` stays as M1 set it: attribute 0 is Device-nGnRE, 1 is normal write-back, 2 is normal non-cacheable.
  - The image, the direct map and every translation table are normal write-back memory, inner shareable.
  - The UART is Device-nGnRE.
  - The boot framebuffer is normal non-cacheable, so scan-out needs no cache maintenance. It isn't in the direct map, so it has no alias with other attributes. Its cacheability changes at the switch, since the firmware had it write-back. So the kernel cleans and invalidates its range by address (`DC CIVAC`, then `DSB SY`) after the switch and before the console first draws.
  - The memory type of a user mapping follows the frame, never the caller: RAM is normal write-back and inner shareable, as the direct map has it, and device memory is Device-nGnRE. Whether device memory objects may choose non-cacheable or write-combining memory is C15's.
  - The kernel sets the access flag in every leaf. `TCR_EL1.HA` and `HD` stay 0, so there is no hardware access-flag or dirty-bit management.
- **Descriptors.**
  - Kernel mappings are global and always UXN. Text is read-only at EL1 (AP = `10`) and executable. Everything else is PXN: read-only data is AP = `10`, data and `.bss` AP = `00`.
  - User mappings are non-global, always PXN, and open to EL0 (AP[1] = 1). Read-write is AP = `01` and UXN. Read-only is AP = `11` and UXN. Read-execute is AP = `11` without UXN. Write with execute is refused, and so is execute on device memory, which is always UXN.
  - As a backstop for W^X, table descriptors carry UXNTable in the upper half and PXNTable in user tables. `TCR_EL1.HPD0` and `HPD1` stay 0, so the hardware honors them.
  - Software bit 55 marks every user mapping of device memory, and every mapping in the device window. The walk in [Access to user memory](#access-to-user-memory) reads it.
  - With the 4 KiB granule, the encoding `0b01` is a block at levels 1 and 2 only. At level 0 it is invalid and at level 3 reserved, and the kernel's own walks treat both as invalid. The kernel makes no leaf at level 0.
- **Registers.**
  - `TCR_EL1` is as M1 set it, plus `AS` = 1 where `ID_AA64MMFR0_EL1.ASIDBits` is `0b0010` (16-bit ASIDs), and `A1` = 0, so the ASID is the one in `TTBR0_EL1`. `EPD0` stays 0. With no user address space active, `TTBR0_EL1` holds an empty table and ASID 0, as Linux's `reserved_pg_dir` does, so no walk can make a lower-half TLB entry. The kernel writes `TCR_EL1` only at boot.
  - `SCTLR_EL1` adds `WXN`, so the hardware treats any writable mapping as execute-never.
  - Where `ID_AA64MMFR1_EL1.PAN` isn't 0, the kernel clears `SPAN`, so every exception taken to EL1 sets PAN, and sets `PSTATE.PAN` at boot. It never clears PAN. The Pi 4's Cortex-A72 has no PAN, and `SPAN` stays 1 there. [0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 5 makes the kernel safe without it, and whether to emulate it is C78's (rule 6).
- **ASIDs.** They are given out by generation rollover, as Linux on arm64 does (`arch/arm64/mm/context.c`). So any number of address spaces share the ASIDs, and no job can exhaust them, whatever user space does. This settles [K01](#k01-asid-allocation).
  - ASID 0 is never given out. It tags "no user address space".
  - Each address space keeps an ASID word in its kernel record: a generation, and its ASID. A word of 0 means it has never had one.
  - The allocator keeps the current generation, a bitmap of the numbers used in it, and for each core the space it runs and the space it ran at the last rollover, each with its word. It tracks 8 cores until C12 sizes this from the device tree.
  - **Activating** an address space on a core:
    1. If its word is of the current generation, it uses that number.
    2. Otherwise it keeps its old number if that was reserved for this same space at the last rollover, as Linux's `check_update_reserved_asid` does, or if no one uses it in this generation. Else it takes the next free number.
    3. If none is free, the generation rolls over. Every number is freed except 0 and the number each core is running, the current core's included, which stay reserved for the spaces running there. Then `TLBI VMALLE1IS`, `DSB ISH` and `ISB`.
    4. The kernel writes `TTBR0_EL1` with the space's level-0 table and its ASID in bits 63:48, then issues `ISB`.
  - **Deactivating** writes `TTBR0_EL1` with the empty table and ASID 0, then issues `ISB`.
  - A space that runs on another core across a rollover keeps its number there, and its word moves to the new generation when it is next activated anywhere. So one address space never has two live ASIDs, and no number is given to a second space while a core still runs the first under it. Until then its word may be of an old generation while it runs, so TLB maintenance uses the word's number whatever its generation ([Cross-core signals and TLB maintenance](#cross-core-signals-and-tlb-maintenance)).
  - **Releasing** a destroyed address space, which no core may be running: `TLBI ASIDE1IS` with its number, whatever its generation, then `DSB ISH`. The number is freed if its generation is current.
  - All of this runs under the kernel lock. QEMU flushes its whole TLB whenever `TTBR0_EL1` changes ASID, so it can't show a stale translation after a rollover. The rollover is checked by host tests of the allocator instead, against a model of which spaces can have TLB entries under which number. Invalidation after an unmap is checked in QEMU, which keeps a translation until a `TLBI` drops it: a test reads a page with an unprivileged load (`LDTR`), remaps the address to another frame, and reads it again. The test alone does this; the kernel never dereferences a user address ([0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 5).
- **Mapping and unmapping.** Every user mapping is made through one encoder, so the rules above hold for all of them.
  - A user address space is an object of its own, made by retype: its level-0 table, then its kernel record ([Untyped memory and kernel records](#untyped-memory-and-kernel-records)). Each further table is a page retyped from the memory of the address space's job when a mapping first needs it ([0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 1). Until C16, Map takes them from an untyped capability the caller presents, whose piece must contain the address space itself (C11). The address space then descends from that capability, so the piece can't be reset while the space lives, and once the space is destroyed nothing reaches its tables. The tables come from the piece's watermark and get no capability. With jobs, C16 takes them from the job's pieces.
  - The kernel's one encoder maps a frame with blocks where the virtual address and the frame are aligned to the block's size, and with pages otherwise. Only Map through a capability reaches it from outside the kernel, and that always gives an aligned address, so the page fallback serves the kernel's own tests.
  - Map through a frame capability (C11, until C15's memory objects) needs the virtual address aligned to the frame's size, as seL4 requires, so every such mapping is one leaf and removing it clears one entry. It needs the read right on the frame for any mapping, the write right on the frame for a writable one, and the write right on the address space. Map keeps a copy of the frame capability as the mapping's binding ([Kernel bindings that hold capabilities](#kernel-bindings-that-hold-capabilities)). Deleting that copy, directly or by revoking the frame, its untyped memory or the address space's, unmaps the range and invalidates the TLB under the space's ASID. Unmapping a range revokes and then deletes the bindings inside it, so the copies derived from them go too, and refuses a range that cuts a mapping.
  - A mapping never replaces a valid entry. A request that would, or that is writable and executable, or executable device memory, is refused before any entry is written. If the job runs out of memory for a table partway, what was mapped is unmapped again before the call fails.
  - An unmap that would cut a block in two is refused. Tables that an unmap leaves empty stay until the address space goes, since each is an object of its own.
- **Relocation first.** The kernel builds these tables only after the stub has applied its relocations, so read-only protection starts after relocation ([0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), rule 3).
- **Bootstrap tables and the switch.** M1's early tables in `entry.rs` become bootstrap tables, which run the kernel only until the switch.
  - **They map the kernel's image and nothing else**, so even before the switch the kernel never maps the UEFI runtime regions or other firmware-reserved memory ([0039](../decisions/0039-no-uefi-runtime-services.md), rule 1), or the seed's page ([0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 2). The identity map in `TTBR0_EL1` covers only the image's first 2 MiB, which hold its text, wherever the stub put it. The high map covers the image from its first page to its last, with 2 MiB blocks where a whole block lies inside it and pages at its end.
  - **They are W^X too**, so the invariant holds from the first instruction with the MMU on. The identity map and the high map share one level-3 table for the kernel's first 2 MiB, with text read-only and executable and the rest read-write and PXN. The rest of the image is read-write and PXN. `kernel/link.ld` asserts that text fits in 2 MiB, and that the image fits in 32 MiB.
  - **The boot window.** Right above the image's 32 MiB, `_start` links four empty level-3 tables into `TTBR1_EL1`: 8 MiB of page slots, as Linux's early fixmap has. Before the switch the kernel maps there, one page at a time, exactly what it must reach: the boot information and the device tree read-only, the UART as device memory, and each page of its new tables read-write. Slots are used once and never reused, so no entry changes from one valid descriptor to another, and no TLB maintenance is needed before the switch. The pages of the tables may be anywhere in usable RAM. A memory map that needs more than 1024 pages of tables, or a window too small for the boot information and the device tree, stops the boot.
  - **The kernel builds its own tables** after relocation, with pages from the boot allocator, written through the boot window.
  - **A trampoline replaces `TTBR1_EL1`.** It runs from the identity map, as Linux's `idmap_cpu_replace_ttbr1` does. It points `TTBR1_EL1` at an empty table, invalidates every TLB entry, then points it at the new tables. So no TLB ever holds entries from both sets (break-before-make), and a change of block size or attributes can't conflict.
  - **The kernel moves to upper-half addresses.** It finds the new addresses of the boot information, the device tree and the framebuffer while the boot window still maps the boot information. The boot window goes with the bootstrap tables at the switch, so the console moves to the UART's address in the device window as soon as the trampoline returns, before anything can print.
  - **Then it retires the identity map.** `TTBR0_EL1` gets the empty table and ASID 0, `SCTLR_EL1` gets `WXN`, and PAN is set where there is PAN. Every TLB entry is invalidated.
  - From then on the lower half belongs to user space, and nothing reads a physical pointer.
- **TLB maintenance** is in [Cross-core signals and TLB maintenance](#cross-core-signals-and-tlb-maintenance).

### Access to user memory

This section gives the mechanism behind [0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 5. The kernel reaches user memory only through its direct map, after a walk of the address space's tables in software. So it never dereferences a user address, and never takes a page fault.

**Reading.** For a word wait ([Word waits](#word-waits)) or a debugger's read ([Debugger access to threads and memory](#debugger-access-to-threads-and-memory)), the kernel:

1. walks the address space's tables in software, holding no lock but the kernel lock;
2. fails at once with "not resident" if the walk finds no frame mapped there;
3. fails at once with "not RAM" if the address is mapped to a device memory object, so it never reads MMIO;
4. otherwise reaches the frame through the direct map.

The caller of a call that failed with "not resident" touches the page in user mode, which faults to the pager under the mapping's fetch timeout ([Waiting for a page](#waiting-for-a-page)), and retries. A debugger can't touch a page in another address space ([K69](#k69-a-debugger-read-of-a-page-that-isnt-resident)).

**Writing.** Before any write the kernel makes to user memory, such as a received message in an IPC buffer or a debugger's write:

1. The write must go through a mapping with the write right, or, for a debugger, into a memory object for which it presents a capability with the write right, as it does for the private clone that holds software breakpoints ([Software breakpoints in a private clone](#software-breakpoints-in-a-private-clone)). Anything else is refused.
2. If the page is shared copy-on-write, the written object takes a frame of its own from its own job, and the page is copied into it. If that job has no free memory, the call fails at once with "no memory". No memory request is sent.
3. The kernel writes through the direct map, and marks the page dirty in its object's page tracking, as a user write would. So Query and Clean see the write.

**The walk (C10).**

- The kernel walks the address space's tables through its direct map, level by level, with the 4 KiB granule's encodings: an encoding the hardware treats as a fault is "not resident" too ([Address-space layout](#address-space-layout)).
- An address at or above 2^48 isn't in the lower half, and is refused.
- An invalid entry at any level is "not resident".
- A leaf with the device bit is "not RAM".
- As defense in depth, the kernel then checks the frame against its direct map. A read needs the frame in the direct map. A write needs it in the direct map's read-write part. A frame the direct map doesn't cover is "not RAM". A write to a frame the direct map holds read-only, such as a boot object's, is refused, never attempted, so a wrong mapping can't make the kernel fault.
- A write needs a mapping writable at EL0, which is step 1 of Writing.
- A span is checked page by page before any byte moves, so a call moves all of its bytes or none.
- The bytes move with volatile accesses through the direct map, aligned words as words and the rest as bytes. User memory is shared with threads outside the kernel's own memory model: a thread on another core may write the frame meanwhile, and the copy then holds some mix of old and new bytes, never a fault.
- Marking pages dirty and breaking copy-on-write come with memory objects (C15). The names of these results are internal until [K30](#k30-results-and-error-names) settles them.

**IPC buffers** are pinned when they are registered, so the kernel can always write a received message ([IPC buffers](#ipc-buffers)). Eviction, decommit and reclaim skip a pinned frame ([0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 8).

## Capabilities

### Capability spaces and lookup

This section gives the mechanism behind [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 1.

- **CNodes.** A CNode is an array of 2^n slots, made by retyping untyped memory. As in seL4 on AArch64, a slot is 32 bytes and n runs from 1 to 42, so a CNode is 64 bytes to 2^47 bytes, the largest piece (C11).
- **A slot** holds one capability and the links that place it in the derivation tree ([Derivation and revocation](#derivation-and-revocation)). It is four words, as seL4's `cte_t` is: two for the capability; then the previous slot in the tree's list with the slot's depth in the tree; then the next slot. All four words zero is an empty slot, so a CNode made from free memory, which is zero, starts empty. A capability records the object's type, its physical address, its rights and, where the type has one, its badge, bit-packed as seL4 packs `cap_t`. The bit layout is the kernel's own; the numbers the ABI reports for each kind are C17's ([K28](#k28-message-and-buffer-layout); [K30](#k30-results-and-error-names)).
- **Lookup.** A capability address is a 64-bit word and a depth. Lookup starts at the thread's root CNode. At each CNode it consumes the guard bits that the CNode capability carries, then n bits of index, until the depth is used up. This is seL4's guarded lookup. A failed lookup is a capability fault on a fault path ([Fault delivery](#fault-delivery)), and an error result for a system call.
  - A guard is 0 to 63 bits, as seL4 on 64-bit keeps its size in six bits, and a CNode capability's guard and radix together are at most 64 bits. Mint and mutate check both (C11).
  - Lookup has seL4's two modes. A CNode operation names a slot with an explicit depth, from 1 to 64, which must be used up exactly. An invocation names a capability with depth 64, and lookup stops at the first capability that isn't a CNode.
  - Each level consumes at least one bit, so a lookup ends after at most 64 levels, even through a CNode that holds its own capability.
- **A thread's root CNode** is held in a slot of the thread, as seL4's `tcbCTable` is, so revoking it also reaches the thread's binding ([Kernel bindings that hold capabilities](#kernel-bindings-that-hold-capabilities)).
- **Receive slots.** A receiver names up to three empty slots for the capabilities a message carries, in its IPC buffer, as seL4 names its one receive slot there ([Capability transfer](#capability-transfer)).
- **Identify.** A thread can ask for the kind of object a capability in its own space names, and the capability's rights. Generated stubs use it to check the rights a call received, and the network server to decide how to translate a capability between nodes ([0047](../decisions/0047-the-kernel-follows-sel4.md), rule 3; [0066](../decisions/0066-capability-parameters-and-server-streams.md), rules 1 and 4). It reports the kind and the rights only, never a badge or an ID ([0050](../decisions/0050-ids-for-kernel-objects.md), rule 1). An empty slot and a zombie both report the null kind. Untyped and CNode capabilities carry no rights, as in seL4, so identify reports none for them (C11). Whether it is a published method of the capability-space interface or internal to `aspis-rt` is open ([K75](#k75-the-identify-operation)).

### Rights by object type

[0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 2 fixes four rights, and their meaning on the object types other records rely on. A copy may drop rights, never add them. This table collects what each right allows, and says where it comes from. Where a cell says "seL4", the right means what it means for the matching seL4 object.

| Object | Read | Write | Grant, grant-reply | Source |
|---|---|---|---|---|
| Endpoint | Receive | Send | Grant: send capabilities. Grant or grant-reply: call | seL4; [0054](../decisions/0054-ipc-endpoints.md), rule 7 |
| Reply object | — | — (replying needs no right beyond holding the reply capability, as in seL4 MCS) | Grant: the reply may carry capabilities | seL4 MCS; [0054](../decisions/0054-ipc-endpoints.md), rule 7 |
| Eventcount | Read, wait, add to a wait set, bind to a thread | Advance, bind an interrupt handler | — | [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 2; [0053](../decisions/0053-eventcounts.md), rules 2, 4, 5 and 8 |
| Wait set | Open ([K32](#k32-rights-on-wait-sets)) | Open ([K32](#k32-rights-on-wait-sets)) | — | [0053](../decisions/0053-eventcounts.md), rule 4 |
| Thread | Read state and registers | Suspend, resume, write registers, debug, cancel a wait, set fault and timeout endpoints, register the IPC buffer, bind an eventcount | — | [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 2 |
| Address space | Read resident memory; list mappings as descriptions | Map, unmap, write resident memory through writable mappings, list mappings with capabilities | — | [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 2; [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 3 |
| Memory object | Map readable or executable; clone an immutable or pager-backed object | Map writable; make a snapshot clone of an anonymous object; make a clone of a clone; decommit a range of an anonymous object, any clone included | — | [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 2; [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rules 3, 4 and 8 |
| Job | Open ([K53](#k53-rights-on-a-jobs-capability)) | Open ([K53](#k53-rights-on-a-jobs-capability)) | — | [0058](../decisions/0058-jobs-and-budgets.md), rule 9 |
| Frame (C11, until C15's memory objects) | Map readable or executable | Map writable | — | seL4 |
| CNode, untyped memory, scheduling context, scheduling control, interrupt control and handler | seL4 | seL4 | seL4 | [0047](../decisions/0047-the-kernel-follows-sel4.md), rule 1 |

Untyped and CNode capabilities carry no rights, as in seL4: a copy of one keeps none, and identify reports none. A capability that listing yields for a mapping carries the read right, and the write right only if the mapping is writable. Execute is an attribute of a mapping, never a right. Making an object needs no job capability: the object belongs to the job whose untyped memory it is made from. The one exception is a child job, made through its parent's capability ([Job capabilities](#job-capabilities)).

### Derivation and revocation

This section gives the mechanism behind [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 4.

- **The derivation tree.** As in seL4's mapping database, the slots are linked in a list, in a depth-first order of the tree. Unlike seL4's, each slot records its depth in the tree, and a copy, a badged copy, a transfer, a binding and a retype each insert the new capability right after the one it came from, one level deeper, as its child ([How far the kernel follows seL4](#how-far-the-kernel-follows-sel4)). C11 settled this.
  - A capability b descends from a when b lies in the run of slots right after a, each deeper than a, with no barrier at a's depth or shallower (below), and related to it: inside a's range when a is untyped memory; otherwise naming the same object, and carrying a's badge when a is a badged endpoint.
  - A derivation more than 65,535 levels deep is refused.
  - Deleting a capability that has children leaves the children in place, at their depth, and records a *barrier* on the slot after it: the deleted capability's depth. A slot's barrier is the shallowest depth among the capabilities deleted between it and the slot before it, while it lay in their runs; it is kept in the slot's fourth word, beside the next link. A run stops at a slot whose barrier is at the run's own depth or shallower. So the children stay in the run of every ancestor that remains, and join no other capability's run: revoking a capability deletes exactly its descendants, never a sibling's or a sibling's copies, even when they name the same object. A delete does O(1) work, since no depth is lowered (C11).
  - The cost is depth. A capability keeps the depth it was made at after its ancestors go, so a chain of copies, each made from the last and the last then deleted, deepens by one per link.
  - Every capability to one object is contiguous in the list: an object's first capability is inserted after its untyped memory, each copy after its source, and a removal keeps the rest together. So a capability is the last to its object when neither neighbor names the same object, as seL4's `isFinalCapability` checks.
- **What can't be derived.** As in seL4, an untyped capability that has children can't be copied, a zombie can't, and the control capabilities (interrupt control, scheduling control and the like) can't be copied at all. A copy of a mapping's frame copy is the frame without its mapping, as seL4's `deriveCap` clears a frame capability's mapping, and a child of the mapping's copy: revoking the mapping's copy, or anything it derives from, reaches it, and Unmap revokes the mapping's copy before it deletes it. A copy keeps its source's badge. Mint may badge only an unbadged endpoint, and mutate changes only a CNode's guard, as seL4's `updateCapData` does.
- **Revoke** deletes every descendant of a capability, in the tree's list order, most recently derived first, as seL4's `cteRevoke` does, and leaves the capability itself. It keeps no state of its own: each unit of work takes the first descendant afresh and takes one unit of deleting it. If the capability itself lies in an object that a descendant names, the revocation deletes it partway and stops, as seL4's does, and its remaining descendants stay under its parent.
- **Delete** removes one slot. If the capability is a binding, its unbind step runs first, whether or not it is the last capability to its object ([Kernel bindings that hold capabilities](#kernel-bindings-that-hold-capabilities)). When it removes the last capability to an object, the object is destroyed, and each type's destruction step runs: an endpoint's queued threads are released, an eventcount's waiters are woken, a thread's bindings are dropped, and so on. What the waiters return is open ([K30](#k30-results-and-error-names)).
- **Zombies.** When the last capability to an object with slots (a CNode or an address space; from C12 to C14 also a thread, a wait set and an interrupt handler) is deleted, it becomes a zombie in place and keeps its place in the tree, so the object's untyped memory can't be reset until the object is finished. Zombie(o, n) means that slots 0 to n − 1 of o's slot array are still to clear; slots n and up are empty, but for the zombie's own slot if it lies there. A CNode's slot array is the CNode; an address space's is its record's 127 slots. Slot 0 of each array is its *park slot*, which never holds a binding. A deletion runs from the slot S it started at. One step at a slot s that holds Zombie(o, n), with e the end slot o[n − 1] and o's park slot o[0]:
  1. If n is 0, o's destruction step runs and s is emptied.
  2. If e is s itself, or empty, n drops by 1.
  3. If e holds a capability that isn't the last to its object, or is the last to an object without slots, e is deleted in place, as Delete says, and n drops by 1.
  4. If e holds the last capability to an object p with slots, its unbind step runs if it is a binding, and e becomes Zombie(p) in place.
  5. If e holds Zombie(p, m):
     - if m is 0, the kernel takes one step at e instead, in place, which finishes p there;
     - else, if s lies among o's own slots, the kernel takes one step at e instead, in place;
     - else, if n is 1, s is S, and S doesn't lie among p's slots, the kernel takes one step at e instead, in place (a delegated step, which delegates no further);
     - else, if n is 1, o is finished, s is emptied, and Zombie(p) moves into s (a hand-over). At S this happens only when S lies among p's slots: a cycle that the deletion entered;
     - else, if p's park slot is s or S, o's park slot and e swap contents;
     - else o's park slot takes Zombie(p), p's park slot takes what o's held, and e takes what p's held.
- **Why deletion ends, and is complete.**
  - Each object becomes a zombie at most once.
  - The zombies that rule 5 sets aside wait on a stack: o's park slot, then the park slot of each zombie on it. A zombie joins the stack only from e, which is never the park slot of a zombie already on it, so it joins at most once. It leaves only by a hand-over, which finishes the object above it.
  - A zombie whose n is 0 has swept every slot, its park slot included, so nothing may be moved into its slots: rule 5 finishes it where it is before any swap, deferral or hand-over.
  - Every other step deletes a capability or lowers some n. So a deletion takes O(slots + objects) steps, each with bounded work: no recursion beyond one step at e, which never recurses further, and no memory of its own.
  - When o's park slot is all that is left, S keeps Zombie(o) and the delegated steps clear the stack in o's park slot: a hand-over there finishes the object on top and brings up the one below, and a delegated step never moves S's contents, since a park slot that is S takes a swap instead of a deferral. So S keeps Zombie(o), with its place in the tree, until o and every object that only it reached are finished. Only a cycle that S lies in, objects holding each other's last capabilities with S among their slots, hands over into S, and S is then emptied when the cycle is finished whole. This departs from seL4's `reduceZombie` ([How far the kernel follows seL4](#how-far-the-kernel-follows-sel4)).
  - Another deletion may adopt S's zombie: when S lies in an object that another deletion clears, that deletion's step at S defers or hands over S's zombie, which it then finishes. So a delete returns once its slot is empty, and the object it made a zombie is finished by it, or by the deletion that adopted it. C12 must not take a completed delete to mean that the object's destruction step has run.
- **What moves.** Only zombies and the contents of park slots move, each with its place in the tree, as seL4's `cteSwap` moves them. Since a park slot never holds a binding, a binding never moves, and its unbind step may find its object from the binding slot's address. A binding's unbind step runs when its capability is deleted, or first made a zombie, and depends only on the capability, never on the slot's index. C12, C13b and C14 keep this rule for the bindings they add.
- **Any operation may step any zombie.** Each zombie needs only its own object. A revocation that reaches a waiting zombie through the tree steps it where it is, and the deletion it waits in stays consistent. A revocation keeps no state between units, and a descendant it made a zombie keeps its place among the revoked capability's descendants until its object and every object only it reached are finished, so a restarted revocation does exactly what an unpreempted one does. The one exception is a cycle that the descendant's slot lies in: the hand-over gives the slot the nested zombie, with its place among its own untyped memory's descendants, and the revocation goes on without it. What is left of the cycle can be named by no lookup, and is an unreachable cycle, as below.
- **Unreachable cycles.** Objects that hold each other's last capabilities, and that nothing else reaches, can't be named by any lookup. As in seL4, they stay until a revocation of their untyped memory reaches them and finishes them. Their memory is never reused before then, since their capabilities keep their place in the tree.
- **Boot objects are never destroyed** ([0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 2; [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 4). The kernel keeps the original capability to each boot object in a kernel page that no capability names, so no lookup reaches it, as a root of the tree. What the root server holds are copies, its children. A delete or a revocation through them never removes the last capability, so no boot object's destruction step runs. C11's boot objects are the boot CNodes ([The boot capability space](#what-the-root-server-receives)); later chunks keep their boot objects' originals the same way.
- **Preemption.** Revoke and delete are long operations. One step of a deletion is one unit of work ([The kernel lock and long operations](#the-kernel-lock-and-long-operations)). At each preemption point the kernel leaves its progress in the tree itself and in its zombies: the descendants already deleted are gone, and each zombie records the slots still to clear. So a restarted revoke continues with the descendants left, and a restarted delete with whatever its slot holds, until the slot is empty, as in seL4.
- **Memory reuse.** A destroyed object's memory can be retyped again once every object made from its untyped piece is gone. seL4's untyped memory is a watermark allocator, which is why jobs hold memory in page-sized pieces ([0058](../decisions/0058-jobs-and-budgets.md), rule 4).
- **The ITS exception.** A deletion of the ITS command queue, device table or collection table fails while the ITS uses them, whether it is direct or part of a revocation ([0055](../decisions/0055-interrupt-objects.md), rule 4). These tables are made from the root job's memory, and the root job never ends, so ending any other job never meets them. A device's interrupt translation table isn't an exception: deleting it first unmaps the device in the ITS ([MSI and the GICv3 ITS](#msi-and-the-gicv3-its)). How a revocation reports a table it couldn't delete is open ([K40](#k40-a-revocation-that-meets-an-its-table)).

### Kernel bindings that hold capabilities

[0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 4 says that every lasting reference the kernel keeps from a presented capability holds a copy of that capability, as a child of it. Revoking or deleting the copy removes the binding. seL4 keeps a thread's references this way, in slots of the thread object (`tcbCTable`, `tcbVTable`, `tcbBuffer`, `tcbFaultHandler` and `tcbTimeoutHandler` in 17.0.0's `include/object/structures.h`).

| Binding | Where the copy lives | What removing it does |
|---|---|---|
| A thread's root CNode and address space | Slots of the thread | As in seL4: the thread can't run until new ones are set |
| A thread's fault endpoint | A slot of the thread | The thread has no fault endpoint. Its next fault suspends it and is logged ([Fault delivery](#fault-delivery)). A fault already in flight is open ([K50](#k50-a-fault-in-flight-when-its-endpoint-is-unset)) |
| A thread's timeout endpoint | A slot of the thread | The thread gets no timeout or context-withdrawn faults. A passive server that holds a donated context is open ([K08](#k08-removing-a-binding-in-use)) |
| A thread's bound eventcount | A slot of the thread | The eventcount is unbound, and the thread's receives no longer report its advances |
| A wait-set entry's eventcount | A slot of the wait set, one per entry | The entry leaves the set. A wait in progress is open ([K08](#k08-removing-a-binding-in-use)) |
| An interrupt handler's eventcount | A slot of the handler, as seL4 keeps a handler's notification | Interrupts on that handler advance nothing until a new eventcount is bound |
| A mapping's memory object | The mapping record ([Memory objects and mappings](#memory-objects-and-mappings)) | The range is unmapped, as revoking an seL4 frame capability unmaps the frame. Capabilities that listing yielded for the mapping are its descendants, and go with it when it is unmapped or revoked ([K42](#k42-capabilities-yielded-by-listing)) |
| A thread's IPC buffer | Open ([K29](#k29-ipc-buffer-registration-and-capabilities)) | Open ([K29](#k29-ipc-buffer-registration-and-capabilities)) |
| A frame's mapping (C11, until C15's memory objects and mapping records) | A binding slot of the address space's record, slots 1 to 126 | The range is unmapped, and the TLB invalidated under the space's ASID. An address space holds at most 126 such mappings until C15 |

**The mechanism (C11).** When the kernel keeps a lasting reference from a presented capability, it derives a copy, as Copy does, and inserts it as the presented capability's child, in a slot of the binding object. The binding's state is that slot, so deleting or revoking the copy removes the binding. Where hardware state mirrors a binding, as page-table entries mirror a mapping, the copy's own encoding marks it as a binding, and its unbind step undoes that state when the copy is deleted or first made a zombie ([Derivation and revocation](#derivation-and-revocation)).

Each object's size includes its slots, with slot 0 of its slot array kept as the park slot, and each mapping record's size includes its slot. C11 settled the address space's record ([Untyped memory and kernel records](#untyped-memory-and-kernel-records)). The thread's, wait set's and handler's sizes are open ([K07](#k07-where-binding-copies-live-and-object-sizes); [K02](#k02-small-kernel-records)).

### Sessions and badges

This section gives the mechanism behind [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rules 3 and 5.

- A badge is 64 bits. Badge 0 means unbadged, as in seL4.
- At bind, the manager makes a badged copy of its endpoint capability and keeps it. The client's copy is derived from it.
- A session may have several badges. `session_dup` makes another in the same way, and the manager's table maps each badge to its session ([0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 5; [0066](../decisions/0066-capability-parameters-and-server-streams.md), rule 5).
- To release a badge, on `session_close` or because its session ends, the manager:
  1. revokes the copy it kept, which deletes every copy made from it, wherever it was passed, and every binding made from them;
  2. cancels the sends still queued on the endpoint under that badge, as seL4's `CancelBadgedSends` does, which is preemptible;
  3. deletes the copy it kept.
- Only after step 3 may the badge be reused, so no message from the old session is delivered under a new one. Ending a session takes these steps for each of its badges.
- In the derivation tree, a badged copy is a child of the unbadged capability it was minted from, and the copies made from it carry its badge. A badged capability's descendants must carry its badge, so revoking a kept copy reaches exactly its badge's copies, even after another kept copy was deleted without a revoke (C11). Step 2 is C14's: C11's capability layer leaves a place for it between the revoke and the delete.
- A scheduling context's badge is set when the context is configured, and timeout and context-withdrawn faults report it ([Scheduling contexts and budgets](#scheduling-contexts-and-budgets)).

### Copying a capability table

This section gives the mechanism behind [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 7. The copy is an operation of the kernel interface library, built from several system calls ([0059](../decisions/0059-the-kernel-interface-library.md), rule 1).

- The library walks the source capability space. It makes CNodes of the same shape in the target, from untyped memory the caller supplies, and copies each slot as a child of the original.
- So revoking an original also reaches its copy.
- A capability that can't be derived ([Derivation and revocation](#derivation-and-revocation)) is skipped or refused. Which of the two, and what else `fork` leaves behind, such as binding credentials, is D95's ([K10](#k10-what-fork-copies)).
- The source space can change during the copy. Whether the copy is defined only for a stopped source is open ([K09](#k09-the-capability-table-copy-under-change)).
- If copying slot by slot proves too slow, a batch call can be added to the private system-call ABI ([0059](../decisions/0059-the-kernel-interface-library.md), rule 2) without changing the library's interface.

### Kernel objects and IDs

The kernel stores, checks and returns no ID ([0050](../decisions/0050-ids-for-kernel-objects.md), rule 1). A user-space server that presents a kernel object as an object mints its ID and answers its base interface ([0050](../decisions/0050-ids-for-kernel-objects.md), rule 2).

- **The server keeps the link.** It keeps a table from each ID it minted to the capability it holds for that object. A server that hands out badged capabilities, as a manager does at bind, can also key its table by badge, since the badge arrives with each message ([Sessions and badges](#sessions-and-badges)).
- **A process learns its own ID at spawn.** The spawner writes the ID into the startup block, or a mark that the process has none yet ([The startup block](#the-startup-block)). How a process named later learns its ID is open ([K67](#k67-a-process-named-after-it-starts)).
- **Threads without IDs are reached through the job.** The process's manager holds the job's capability, lists the threads in the job and its descendants with each thread's address space, and gets capabilities to them ([Job capabilities](#job-capabilities)).
- **A kernel object without an ID** is inspected through its capability and its kernel interface ([0059](../decisions/0059-the-kernel-interface-library.md), rule 1).
- **Two capabilities to one object.** seL4 has no operation that tells whether two capabilities name the same object, and ASPIS adds none, which settles [K11](#k11-telling-whether-two-capabilities-name-the-same-object). A server presents only objects it made or received through its own sessions, and keys its table by its own slot or by badge. A new operation would be a departure from seL4 that [0047](../decisions/0047-the-kernel-follows-sel4.md), rule 3 doesn't list.
- **Objects made after the entropy gate but before storage** can't take a sequence number from a durably recorded block. How they are named is a decision, not mechanism ([K12](#k12-naming-objects-made-after-the-entropy-gate-but-before-storage)).

## Threads and scheduling

### Scheduling contexts and budgets

This section gives the mechanism behind [0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 1, and [0058](../decisions/0058-jobs-and-budgets.md), rule 8.

- **Making a context.** A scheduling context is made by retyping untyped memory. It belongs to the job whose untyped memory it is made from, and counts against that job ([0058](../decisions/0058-jobs-and-budgets.md), rule 5). Making one needs no job capability.
- **Configuring a context.** A scheduling context is configured through the scheduling-control capability of one core, as with seL4's `seL4_SchedControl_ConfigureFlags`. Configuring sets:
  - the budget and the period, in microseconds;
  - the core the context is bound to;
  - the 64-bit badge that timeout and context-withdrawn faults report ([0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 3; [Fault delivery](#fault-delivery));
  - the number of extra refills, as in seL4.
- **The share check.** The kernel refuses a configuration that would take the job's contexts on that core past the job's remaining share of that core ([0058](../decisions/0058-jobs-and-budgets.md), rule 8). The job is the context's own job, so the check needs no job capability from the caller. The arithmetic of the check is open ([K13](#k13-the-share-check)).
- **Who holds scheduling control.** At boot the root server holds one scheduling-control capability for each core. Who else may hold copies, and whether a runtime can configure contexts within its own job's share without one, is open ([K14](#k14-who-configures-scheduling-contexts)).
- **Refills.** A context is refilled as a sporadic server, as in seL4 MCS. The size of a context, and so the most refills it can hold, is open ([K15](#k15-the-size-of-a-scheduling-context)).
- **Binding.** A thread runs only while a context is bound to it, or donated to it ([Passive servers and taking a context back](#passive-servers-and-taking-a-context-back)). It runs on the core of that context ([0052](../decisions/0052-smp-bring-up-and-the-kernel-lock.md), rule 3).
- **When a budget runs out**, the kernel acts as seL4 17.0.0's `endTimeslice` does:
  - A round-robin context, whose budget equals its period, raises no timeout fault. Its thread goes to the back of its priority's run queue with a fresh budget.
  - For any other context, if the thread running on it has a timeout endpoint, the kernel sends a timeout fault there. The fault carries the context's badge and the time used. The thread then waits for its handler's reply, not for its refill.
  - Otherwise the thread waits for the context's next refill.
- **Timeout faults donate no context.** The kernel sends timeout faults, and context-withdrawn faults, without donating a scheduling context, as seL4's `handleTimeout` does (`sendFaultIPC(tptr, cap, false)` in 17.0.0's `src/kernel/faulthandler.c`). So the handler on a timeout endpoint always runs on its own context ([0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 3).

### Priorities and bands

This section gives the mechanism behind [0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 2.

- Priorities run from 0 to 255, and 255 is the highest. Each core keeps a run queue for each priority, and the highest-priority runnable thread on the core runs.
- Threads of equal priority take turns, as in seL4 MCS: a thread goes to the back of its queue when its budget runs out, or when it yields.
- Each thread has a maximum controlled priority, as in seL4. Setting a thread's priority, or its maximum controlled priority, names an authority thread, and the value can't exceed that thread's maximum controlled priority.
- The kernel holds no policy. The root server's boot manifest assigns priorities, and the process manager assigns them to the processes it starts.
- **Default bands.** [0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 2 fixes their order, from highest to lowest:
  1. interrupt-handling threads in drivers;
  2. pagers and the display path;
  3. system servers;
  4. applications.

  The range of priorities in each band is open ([K16](#k16-priority-bands)).
- **A shared server's priority.** A shared server runs at a priority at least as high as any caller's ([0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 3). The kernel doesn't check this. Whoever starts the server sets it. How that party learns the highest priority among a server's callers is open ([K16](#k16-priority-bands)).
- **Passive exceptions.** [0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 3 makes the PDP, the entropy service and the network server's client-call threads passive unless a later record says why one can't be. None does.

### Passive servers and taking a context back

This section gives the mechanism behind [0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 3, and [0054](../decisions/0054-ipc-endpoints.md), rule 6.

- **Donation.** A call to a passive server's thread, waiting to receive on an endpoint, donates the caller's scheduling context with the message, as in seL4 MCS. The reply object records the donation. The reply returns the context to the caller.
- **A chain of calls.** A passive server that calls another passive server while it runs on a donated context passes that context on. The reply objects form a chain from the caller C, through each server S1, S2, …, to the thread that now holds the context, as seL4 MCS's call stack does.
- **Callers wait in priority order** on the endpoint ([0054](../decisions/0054-ipc-endpoints.md), rule 1). How the queue is kept is in [Ordered kernel queues](#ordered-kernel-queues).
- **Taking the context back.** When a delivered call is canceled, or its deadline passes, the kernel:
  1. invalidates the caller's reply object, so the server's later reply fails with "no caller";
  2. follows the chain of reply objects from the caller to the thread that holds the context, unbinds the context there, and binds it to the caller again;
  3. ends the caller's call with "canceled" or "timed out";
  4. sends each passive server along the chain that was left without a context, from S1 to the end, a context-withdrawn fault on its timeout endpoint, carrying the withdrawn context's badge ([Fault delivery](#fault-delivery)). These faults donate no context.

  What happens to the wait each stranded server is in, and in what order the faults go out, is open ([K17](#k17-stranded-servers-waits)).
- **A long chain.** Following a long chain is a long operation, which keeps its progress in the reply objects. When a deadline starts it, it comes from the timer interrupt, with no calling thread to restart, so it runs in bounded batches ([The kernel lock and long operations](#the-kernel-lock-and-long-operations)).
- **A passive server with no timeout endpoint.** The kernel doesn't check that a passive server has one ([0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 3). A server without one that loses its context gets no fault. It doesn't run again until something gives it a context. The caller still gets its context back at once.
- **A budget that runs out mid-request.** The server thread runs on the caller's context, so the timeout fault comes from the server thread, to the server's timeout endpoint, with the caller's context's badge ([Scheduling contexts and budgets](#scheduling-contexts-and-budgets)). The handler can end the request with an error, or lend the server a budget to finish it.

### The timer and deadlines

This section gives the mechanism behind [0051](../decisions/0051-scheduling-timers-and-deadlines.md), rules 4 and 5.

- **The timer.** The kernel uses the EL1 virtual timer: the count `CNTVCT_EL0`, the compare value `CNTV_CVAL_EL0` and the control `CNTV_CTL_EL0`. The counter's frequency is `CNTFRQ_EL0`. Its interrupt is the private peripheral interrupt that the device tree's timer node, or the ACPI GTDT, gives for the virtual timer. On QEMU `virt` and on the Pi 4 that is PPI 11, INTID 27.
- **The stub at EL2.** When the stub is entered at EL2, before it drops to EL1, it writes zero to `CNTVOFF_EL2`, and sets the `CNTHCTL_EL2` controls that let EL1 read the physical counter. Those controls' bit positions depend on `HCR_EL2.E2H`, so the stub clears E2H first. M1's stub does both (`boot/stub/src/handoff.rs`), and the kernel test `virtual_count_has_no_offset` checks, in a test build booted at EL2, that the virtual count falls between two reads of the physical count.
- **Tickless.** As in seL4 MCS, the kernel has no periodic tick. Each core programs its compare value for the earliest of: the end of the running context's budget, the next refill on that core's release queue, and the earliest deadline on that core.
- **Deadlines.** A deadline is an absolute 64-bit value of the virtual count. Every blocking call takes one, optionally ([0054](../decisions/0054-ipc-endpoints.md), rule 5). A thread with a deadline is queued on one core's deadline queue ([Ordered kernel queues](#ordered-kernel-queues)). Which core's is open ([K18](#k18-which-core-keeps-a-deadline)).
- **Expiry.** When the timer fires, the kernel ends every wait whose deadline has passed with "timed out". A call whose deadline passes after delivery ends as a canceled call does ([Passive servers and taking a context back](#passive-servers-and-taking-a-context-back)), with the result "timed out". Many deadlines can pass at one tick. Ending them is work started from an interrupt, so it runs in bounded batches ([The kernel lock and long operations](#the-kernel-lock-and-long-operations)).
- **Conversion.** The kernel interface library converts nanoseconds to counts, using `CNTFRQ_EL0`. A deadline in a message between nodes is a duration, encoded as the nanoseconds remaining ([0064](../decisions/0064-the-call-header-and-wire-encoding.md), rule 12).
- **Edge cases** are open: a deadline already passed when a call starts, the rounding of a conversion, and how "no deadline" is encoded ([K19](#k19-deadline-edge-cases)).

### Suspending a thread

This section gives the mechanism behind [0061](../decisions/0061-debugging.md), rule 3, which departs from seL4: seL4's `suspend` cancels the thread's IPC, and ASPIS's doesn't. Suspend and resume need the thread's capability with the write right ([0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 2).

Suspend marks the thread suspended, apart from whatever it is blocked on.

- A thread blocked in a call stays queued or delivered. Its donated scheduling context keeps serving the call. A reply that arrives is held, and the thread sees it when it resumes.
- A wait for a page, for memory or on a word stays attached. If the page arrives, the thread is made ready to repeat its access, but doesn't run until it resumes.
- A thread suspended while running or ready simply stops being scheduled.
- Only an explicit cancel ends a wait ([IPC deadlines and cancellation](#ipc-deadlines-and-cancellation)).
- A thread running on another core is first stopped there with a remote call, then marked suspended ([Cross-core signals and TLB maintenance](#cross-core-signals-and-tlb-maintenance)).

Stopping a job suspends every thread in the job and its descendants this way, and resuming the job resumes them ([Job capabilities](#job-capabilities)). Whether a suspended thread's deadlines keep running, and how a held reply is kept, are open ([K20](#k20-deadlines-and-replies-of-a-suspended-thread)).

## SMP

### Starting secondary cores

This section gives the mechanism behind [0052](../decisions/0052-smp-bring-up-and-the-kernel-lock.md), rule 1.

- **The conduit.** On a device-tree platform, the `psci` node's `method` property, `hvc` or `smc`, names the conduit. On an ACPI platform, the FADT's Arm boot architecture flags do: `PSCI_COMPLIANT` and `PSCI_USE_HVC` (C65).
- **The cores.** The device tree's `cpu` nodes, or the ACPI MADT's GICC entries, give each core's MPIDR affinity. A core whose `enable-method` isn't `psci` is left off, and the kernel logs that ([0042](../decisions/0042-log-ring-and-panic-path.md), rule 1). The core the stub ran on is the boot core.
- **Starting a core.** The kernel calls `CPU_ON` with the core's affinity, the physical address of its secondary entry point, and a context ID that tells the new core its per-core data. The new core enters at EL1 with its MMU off.
- **Reset and power-off** use PSCI `SYSTEM_RESET` and `SYSTEM_OFF` ([0039](../decisions/0039-no-uefi-runtime-services.md), rule 3). What the kernel does when firmware has no PSCI is open ([K21](#k21-firmware-without-psci)).

### The kernel lock and long operations

This section gives the mechanism behind [0052](../decisions/0052-smp-bring-up-and-the-kernel-lock.md), rule 2.

- **The lock.** As in seL4, the lock is a CLH queue lock, so cores take it in the order they ask. Every system call, fault and interrupt from user mode takes it on entry and releases it on exit. The kernel runs with interrupts masked.
- **Spinning serves requests.** A core waiting for the lock serves cross-core requests while it spins, as seL4's `clh_lock_acquire` does ([Cross-core signals and TLB maintenance](#cross-core-signals-and-tlb-maintenance)).
- **Preemption points.** At a preemption point the kernel checks the interrupt controller for a pending interrupt, every so many units of work, as seL4's `preemptionPoint` does. If one is pending, the operation records its progress in the objects it works on, the kernel handles the interrupt, and the system call restarts from the start when the thread runs again, picking up the recorded progress.
  - The kernel checks every 100 units of work, seL4's default `CONFIG_MAX_NUM_WORK_UNITS_PER_PREEMPTION`, which settles [K22](#k22-preemption-granularity). A unit is one step of a deletion, one unlink, one copy, or 4 KiB of memory cleared, so a 64 KiB chunk of a reset counts 16.
  - Work always comes before the check, so every call makes progress.
  - C11 has no interrupt controller driver and no threads, so its kernel finds nothing pending and runs every operation to the end. C12 and C13a add the check and the restart. C11's tests stand in for both: they run revoke, delete and the clearing of untyped memory with a check that finds an interrupt pending after every unit, or at random, restart each until it ends, and check that it ends as a run without preemption does, nested objects from other untyped memory included.
- **Long operations.** These have preemption points:

  | Operation | Record | How it keeps progress |
  |---|---|---|
  | Revoking a capability | [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 4 | In the tree: the descendants already deleted are gone, as seL4's `cteRevoke` |
  | Deleting an object | [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 4 | In the zombies and the park slots ([Derivation and revocation](#derivation-and-revocation)) |
  | Canceling the sends queued under a badge | [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 5 | As seL4's `cancelBadgedSends` |
  | Clearing untyped memory before it is retyped again | [0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 1 | In the untyped capability's watermark, as seL4's `resetUntypedCap` |
  | Ending a job | [0058](../decisions/0058-jobs-and-budgets.md), rule 10 | Open |
  | Stopping or resuming a job | [0058](../decisions/0058-jobs-and-budgets.md), rule 9 | Open |
  | Listing a job's threads | [0058](../decisions/0058-jobs-and-budgets.md), rule 9 | Open ([K41](#k41-listing-in-pages)) |
  | Listing an address space's mappings | [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 3 | Open ([K41](#k41-listing-in-pages)) |
  | Unmapping a large range | [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 3 | Open |
  | Cloning a range, which write-protects every resident shared page in every mapping of the original | [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 4 | Open |
  | Breaking copy-on-write on a page mapped in many address spaces | [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 4 | Open |
  | Destroying an original with its clones | [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 4 | Open |
  | Evicting a range | [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 8 | Open |
  | Cleaning a range, which write-protects it everywhere | [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 8 | Open |
  | Decommitting a range | [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 8 | Open |
  | Waking many waiters on an eventcount or a word | [0053](../decisions/0053-eventcounts.md), rules 2 and 6 | Open ([K31](#k31-restarting-an-advance) for an advance) |
  | Waking the word waiters of a destroyed memory object | [0053](../decisions/0053-eventcounts.md), rule 6 | Open |
  | Taking a context back along a chain of calls | [0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 3 | In the reply objects |
  | Ending the waits whose deadlines passed at one tick | [0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 5 | Open |

  "Open" means the operation must keep its progress in its objects, but how is still to be settled ([K23](#k23-how-each-long-operation-keeps-its-progress)).
- **Work started from an interrupt.** Some long operations have no calling thread to restart: an advance made for an interrupt ([Interrupt handlers](#interrupt-handlers)), the waits whose deadlines passed at a tick, and a take-back after a deadline passed. Each records its progress in the objects it works on. The kernel runs one bounded batch of it before it leaves the interrupt, and another batch at each later exit from the kernel on that core. The core doesn't go idle while any of it is left. An eventcount with a wake still pending records that itself, so it is queued for more work at most once. The batch size, and where a core keeps its list of pending work, are open ([K24](#k24-batches-of-interrupt-work)).
- **The log ring and the panic path** take no lock ([0042](../decisions/0042-log-ring-and-panic-path.md), rules 3 and 7).

### Ordered kernel queues

This section gives the mechanism behind the bound on ordered queues in [0052](../decisions/0052-smp-bring-up-and-the-kernel-lock.md), rule 2. The kernel keeps these queues in order:

| Queue | Order | seL4 17.0.0 |
|---|---|---|
| Each core's run queues | Priority, then arrival | Constant time: a list for each priority and a two-level bitmap |
| Each core's release queue | Time of next refill | Linear insert (`tcbReleaseEnqueue`) |
| Each endpoint's queue of senders or receivers | Priority, then arrival | Linear insert (`find_tcb_with_higher_prio`) |
| Each core's deadline queue | Deadline | None in seL4 |
| Each eventcount's waiters | Target value | None in seL4 |
| The waiters on words in user memory | Memory object and offset, then arrival | None in seL4 |

[0052](../decisions/0052-smp-bring-up-and-the-kernel-lock.md), rule 2 requires that each inserts and removes in bounded or logarithmic time, and that an advance or a wake visits only the waiters it wakes. The run queues meet this as seL4 builds them. The others don't, in seL4's form, so ASPIS departs from seL4's code here, though not from its design. In seL4 the slow inserts run under the kernel lock with interrupts masked, so a job with many threads could slow every other insert on its core. Which structures ASPIS uses is open ([K25](#k25-ordered-queue-structures)). Where the word-wait queues live is open too ([K34](#k34-where-word-wait-queues-live)).

A thread can sit on several queues at once: an endpoint queue and the deadline queue, or up to 60 eventcount queues through a wait set ([Wait sets](#wait-sets)). Each needs its own link in the thread's or the wait set's memory, since the kernel has no heap ([0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 1). Those links set part of the size of a thread and of a wait set.

### Cross-core signals and TLB maintenance

This section gives the mechanism behind [0052](../decisions/0052-smp-bring-up-and-the-kernel-lock.md), rule 4.

- **Software-generated interrupts** are the kernel's alone. It uses them:
  - to make another core reschedule, when a thread is woken there, or a thread running there is suspended, or its priority changes;
  - for remote calls, such as stopping a thread that runs on another core before the kernel changes its state, as seL4's `remoteTCBStall` does;
  - to stop every core at a panic.

  Which SGI numbers the kernel uses is open ([K26](#k26-sgi-numbers)).
- **A stop at a panic** reaches a core spinning for the lock, which serves it, and a core in user mode at once. A core in the kernel, with interrupts masked, sees it at its next preemption point or exit. Whether a stop should reach such a core sooner is open ([K27](#k27-stopping-a-core-that-has-interrupts-masked)).
- **TLB maintenance** uses the broadcast inner-shareable `TLBI` instructions by ASID and address, such as `TLBI VAE1IS` and `TLBI ASIDE1IS`, then `DSB ISH`, then `ISB` on the issuing core. They reach every core in the inner-shareable domain and complete before the `DSB` does, so no core needs an interrupt to flush its TLB. ASIDs are given out as [Address-space layout](#address-space-layout) says. The sequences:
  - **A new user mapping:** store the descriptor, then `DSB ISHST` and `ISB`. The `DSB` makes the entry visible to every walker, and the `ISB` makes the issuing core's later instructions use it.
  - **A new executable user mapping** first makes the frame's instructions coherent with what data stores wrote there, before the descriptor is stored. The frame may hold another job's old code, cleared since by data stores when its untyped memory was reset, or code the kernel wrote. Through the direct map, the kernel cleans each data-cache line to the point of unification (`DC CVAU`) unless `CTR_EL0.IDC` is set, then `DSB ISH`; invalidates each instruction-cache line (`IC IVAU`), or all of them (`IC IALLUIS`) for a range over 64 KiB, unless `CTR_EL0.DIC` is set; then `DSB ISH` and `ISB`. The Pi 4's Cortex-A72 sets neither bit. Its instruction cache is physically indexed, so maintenance through the direct map reaches every alias.
  - **A new table** is zeroed, and the zeroes are made visible with `DSB ISHST`, before the table is linked.
  - **Unmapping a user page or block:** store 0, `DSB ISHST`, `TLBI VAE1IS` with the address space's ASID and the address, `DSB ISH`, then `ISB`. The ASID is the number in the space's ASID word, whatever its generation, as Linux does: a space that runs on another core across a rollover keeps an old-generation word until it is next activated. A space that has never had an ASID has no TLB entries, and needs no invalidation.
  - **Changing a kernel mapping after boot:** `TLBI VAALE1IS` for a last-level entry, and `TLBI VAAE1IS` for a table entry, since `VAALE1IS` keeps cached walks. C10 changes none.
  - **A rollover, and the switch to the kernel's own tables:** `TLBI VMALLE1IS`.
  - Tables are written through cacheable mappings and walked cacheably (`TCR_EL1` IRGN and ORGN are write-back), so tables need no cache maintenance beyond the barriers. An executable user mapping does, as above.

## IPC

### Endpoint operations and messages

This section gives the mechanism behind [0054](../decisions/0054-ipc-endpoints.md), rules 1 to 4. It follows seL4 MCS where the records are silent.

- **Operations.**
  - Send: an endpoint, a message and an optional deadline.
  - Send without blocking: an endpoint and a message. It drops the message if no receiver waits.
  - Call: an endpoint, a message and an optional deadline. It returns the reply.
  - Receive: an endpoint, a reply object and an optional deadline. It returns the sender's badge and the message, or a bound eventcount's advance ([Threads bound to an eventcount](#threads-bound-to-an-eventcount)).
  - Reply and receive: a reply object and a reply message, then an endpoint and an optional deadline for the receive.
- **The message info word** gives the message's length **in octets**, from 0 to 960, the number of capabilities and the mask of capabilities unwrapped to badges. seL4's gives the length in words; ASPIS gives octets, so every message has an exact end ([0064](../decisions/0064-the-call-header-and-wire-encoding.md), rule 2). The call header ASPIS publishes lives in the message's words, never in the info word's label.
- **Where the words travel.** A message is an octet string in memory order. Its first four words, octets 0 to 31, travel in registers, as seL4 on AArch64 passes four. The sending library loads each with a big-endian read of its eight octets, and the receiving library stores each back the same way, into the first 32 octets of its IPC buffer's message area. Words 4 and up are plain octets in the IPC buffer, which the kernel copies a word at a time without swapping or reading them ([0064](../decisions/0064-the-call-header-and-wire-encoding.md), rule 2; [Octets and words](call-language.md#octets-and-words)). The call numbers belong to the private ABI ([0059](../decisions/0059-the-kernel-interface-library.md), rule 2). The rest of the layout is open ([K28](#k28-message-and-buffer-layout)).
- **Queues.** An endpoint's waiting senders, or its waiting receivers, are queued in priority order, first come first served within a priority ([0054](../decisions/0054-ipc-endpoints.md), rule 1). A thread blocked in a call that donated a scheduling context waits on the reply object, not on the endpoint. How insertion stays bounded is in [Ordered kernel queues](#ordered-kernel-queues).
- **Kernel-sent messages.** A fault, a page request or a memory request travels on the faulting thread's behalf: the thread is queued on the handler's, pager's or memory server's endpoint as a sender, so the kernel never buffers a message itself. These messages aren't part of the private ABI. They are IPC messages defined in the IDL, each with a generated grammar ([0059](../decisions/0059-the-kernel-interface-library.md), rule 2): requests on the common call header, with deadline 0 and an all-zero request ID, of the `[local]` interfaces `aspis.kernel.fault/1`, `aspis.kernel.pager/1` and `aspis.kernel.memory_request/1` ([0064](../decisions/0064-the-call-header-and-wire-encoding.md), rule 9; [Messages the kernel sends](call-language.md#messages-the-kernel-sends)). Page and memory requests are one-way. The kernel reads no reply to a fault, only the fact that one came. How a server that speaks an older major of these interfaces is served is open ([K76](#k76-older-majors-of-the-interfaces-the-kernel-calls)). Their fields are in [Fault delivery](#fault-delivery), [The pager protocol](#the-pager-protocol) and [Memory requests and reclaim](#memory-requests-and-reclaim).

### IPC buffers

This section gives the mechanism behind [0054](../decisions/0054-ipc-endpoints.md), rule 3, and [0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 5.

- **Registering** takes the thread's capability with the write right, and an address in the thread's address space. Under the kernel lock, the kernel:
  1. walks the address space's tables in software, to find the mapping and its memory object;
  2. checks that the mapping is writable, and that the object is RAM, not a device memory object;
  3. checks that the object belongs to the thread's job or to an ancestor of it;
  4. fails with "not resident" unless the page is resident;
  5. if the page's frame is shared copy-on-write, gives the object a frame of its own, from the object's job, and copies the page into it; if that job has no free memory, the call fails with "no memory", and no memory request is sent;
  6. pins the frame, records the buffer in the thread, and records the thread in the object's list of threads whose buffers are pages of it.
- **The root server's first thread** uses the buffer the kernel gave it at boot, since it belongs to no job ([What the root server receives](#what-the-root-server-receives)).
- **A pinned frame is never shared.** A clone made later copies the page into the clone at once, charged to the clone's job, and the clone call fails with "no memory" if that job has none free ([Copy-on-write clones](#copy-on-write-clones)).
- **Eviction, decommit and reclaim skip a pinned frame** until the buffer is unregistered or the thread is destroyed ([0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 8).
- **Unregistering** happens by an explicit call, when the thread is destroyed, and before the buffer's memory object is destroyed or its job ends. In the last case the kernel walks the object's list and unregisters every thread's buffer in it, so the kernel never writes to a freed or retyped frame.
- **The pin stays charged** to the buffer's memory object's job ([0058](../decisions/0058-jobs-and-budgets.md), rule 5).
- **Dirty marking.** When the kernel writes a received message into a buffer through its direct map, it marks the page dirty in its object's page tracking, so Query and Clean see the write ([Access to user memory](#access-to-user-memory)).
- **A capability for the buffer.** Whether the thread holds a copy of a capability to the buffer's memory object, as seL4's `tcbBuffer` holds a frame capability, is open ([K29](#k29-ipc-buffer-registration-and-capabilities)).
- **Layout.** Like seL4's, the buffer holds the message's octets beyond the register words, the addresses of the capabilities to send, the badges of unwrapped capabilities, and the receive slots. ASPIS needs three receive-slot entries where seL4 has one. The first 32 octets of the message area are left for the register words, as in seL4. The rest of the layout is open ([K28](#k28-message-and-buffer-layout)).

### Capability transfer

This section gives the mechanism behind [0054](../decisions/0054-ipc-endpoints.md), rule 7, and [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 6. Only the number of receive slots departs from seL4. The rest follows seL4's `transferCaps` ([0047](../decisions/0047-the-kernel-follows-sel4.md), rules 1 and 3).

- **The sender** names up to three capability addresses in its IPC buffer. A thread with no IPC buffer neither sends nor receives capabilities, as in seL4.
- **The receiver** names up to three empty receive slots in its IPC buffer.
- **Without the grant right** on the endpoint capability used to send, no capability is transferred or unwrapped, as in seL4. A reply carries capabilities only if the reply capability has the grant right.
- **Lookup.** The kernel looks up every named capability when the message is delivered. If any of them doesn't resolve, the message is delivered with no capabilities, as in seL4's `doNormalTransfer`.
- **Transfer in order.** For each capability, in the order named:
  - If it is an endpoint capability to the endpoint the message travels through, the kernel writes its badge into the receiver's buffer and sets its bit in the unwrapped mask. It fills no slot ([0054](../decisions/0054-ipc-endpoints.md), rule 7).
  - Otherwise, if the receiver has a named receive slot left, and that slot is empty, the kernel derives the capability, as seL4's `deriveCap` does, and inserts it in that slot as a child of the sender's.
  - If no slot is left, the slot isn't empty, or the capability can't be derived, transfer stops there, as in seL4.
- **The receiver is told** how many capabilities were processed, and which of them were unwrapped, in the message info word.
- **C11** provides transfer as a step inside the kernel, tested on its own: without the grant right it reports nothing, no count, no unwrapped bits and no badges. C14 calls it from the IPC path.
- **Positions.** The receiver sees the capabilities in the order the sender named them. An unwrapped capability fills no receive slot, but keeps its position in that list, and the unwrapped mask shows it, so the IDL's capability indexes don't shift ([0066](../decisions/0066-capability-parameters-and-server-streams.md), rule 2).

### IPC deadlines and cancellation

This section gives the mechanism behind [0054](../decisions/0054-ipc-endpoints.md), rules 5 and 6.

- **Deadlines.** Each blocking operation takes an optional deadline, an absolute value of the virtual count ([The timer and deadlines](#the-timer-and-deadlines)). When the timer passes it, the kernel ends the wait with "timed out". If the wait was a call already delivered, the kernel ends it as a canceled call, and the result is "timed out".
- **Cancel** takes the thread's capability with the write right, and ends the thread's current wait with "canceled".
- **A delivered bit.** A call's "timed out" and "canceled" results say whether the message had been delivered, so the caller's runtime can report the call as unreachable or indeterminate ([0054](../decisions/0054-ipc-endpoints.md), rules 5 and 6; [0065](../decisions/0065-typed-errors-and-minor-versions-on-the-wire.md), rule 8).
- **Before delivery.** The kernel takes the thread off the endpoint's queue. The server never sees the message.
- **After delivery.** The kernel invalidates the reply object, and the caller returns at once. A later reply through that reply object fails with "no caller".
- **Taking a context back.** If the call donated the caller's scheduling context, the kernel takes it back along the chain of calls, as [Passive servers and taking a context back](#passive-servers-and-taking-a-context-back) says. What happens to each stranded server's own wait is open ([K17](#k17-stranded-servers-waits)).
- **Page waits.** A thread waiting for a page isn't in a system call. Canceling it detaches it from the page's request, and it takes a page-deadline fault at once, marked canceled ([Waiting for a page](#waiting-for-a-page)).
- **Memory waits.** Canceling a thread that waits on a memory request detaches it, and it takes a memory fault at once, marked canceled ([0058](../decisions/0058-jobs-and-budgets.md), rule 6). How the request is withdrawn is open ([K51](#k51-memory-waits-on-the-fault-path)).
- **Suspending a thread** doesn't end its wait ([Suspending a thread](#suspending-a-thread)).
- **A cancel message** tells a server running on its own context to stop work. The caller's library sends it after a call returns "canceled" or "timed out" following delivery, with the non-blocking send. The kernel neither sends nor reads it ([0064](../decisions/0064-the-call-header-and-wire-encoding.md), rule 7).

## Eventcounts

### Eventcount operations

This section gives the mechanism behind [0053](../decisions/0053-eventcounts.md), rules 1 to 3 and 8.

- **The object** holds the 64-bit count, the queue of threads waiting on it with their targets, and a mark that a batched wake is still pending.
- **Advance** needs the write right. It adds one to the count. At 2^64 − 1 it fails, and the count stays at its maximum. It then wakes every waiter whose target is at or below the count. Each woken wait returns the count.
- **Read** needs the read right, and returns the count.
- **Wait** needs the read right, and takes a target and an optional deadline. If the count has already reached the target, it returns at once. Otherwise the thread joins the eventcount's queue until an advance reaches its target, its deadline passes, or it is canceled ([0053](../decisions/0053-eventcounts.md), rule 7).
- **Waking is bounded.** The waiters are kept ordered by target, so an advance visits only the waiters it wakes ([Ordered kernel queues](#ordered-kernel-queues)).
- **An advance from a system call** that wakes many waiters reaches preemption points. The count has already changed, so a restart must not add one again. How the kernel ensures that is open ([K31](#k31-restarting-an-advance)).
- **An advance for an interrupt** has no calling thread to restart. The count advances at once, and the kernel wakes the waiters in bounded batches, as [The kernel lock and long operations](#the-kernel-lock-and-long-operations) says. The eventcount marks a wake pending until the last batch.
- **Destroying an eventcount** wakes its waiters. What they return is open ([K30](#k30-results-and-error-names)).

### Wait sets

This section gives the mechanism behind [0053](../decisions/0053-eventcounts.md), rule 4.

- **The object** holds up to 60 entries. Each entry has:
  - a slot with a copy of the eventcount's capability ([Kernel bindings that hold capabilities](#kernel-bindings-that-hold-capabilities));
  - the target;
  - the queue link that puts the waiting thread on that eventcount's queue, since the kernel has no heap.
- **Add** takes the wait set, an entry index, an eventcount capability with the read right and a target. **Remove** takes the wait set and an entry index. Which rights on the wait set these need is open ([K32](#k32-rights-on-wait-sets)).
- **Wait** takes the wait set's capability and an optional deadline, and nothing else, so no list has to fit in the message words. The kernel links the thread onto each entry's eventcount queue. When any entry's eventcount reaches its target, the kernel unlinks the thread from every queue and returns a 64-bit mask of the entries that have reached their targets. If any entry already has, the wait returns at once.
- **One wait at a time.** A wait on a set that is already serving a wait fails at once.
- **Cost.** Linking and unlinking touch at most 60 queues, which bounds the work of one wait.
- The object's size, and whether wait sets come in more than one size, are open ([K33](#k33-wait-set-size)). What happens when an entry is removed during a wait is open ([K08](#k08-removing-a-binding-in-use)).

### Threads bound to an eventcount

This section gives the mechanism behind [0053](../decisions/0053-eventcounts.md), rule 5.

- The thread holds the bound eventcount's capability in a slot, and the value of that eventcount it last saw.
- Binding sets the last-seen value to the count at that moment. Each receive that reports an advance sets it to the count the receive returns.
- While the thread is blocked in a receive on an endpoint, it also waits on the bound eventcount, with a target one above its last-seen value.
- When the receive starts, if the count is already above the last-seen value, the receive reports the advance at once, even if a message is also queued. The message stays queued for the next receive. This matches seL4's order for a bound notification.
- Only a receive on an endpoint, including the receive half of reply and receive, is affected. Eventcount waits, set waits and word waits are unchanged. A direct read of or wait on the bound eventcount doesn't change the last-seen value.
- A thread unbinds by an explicit call, or when the slot's copy is revoked or deleted.

### Word waits

This section gives the mechanism behind [0053](../decisions/0053-eventcounts.md), rule 6.

- **Wait** takes the word's address, its size (32 or 64 bits), the expected value and an optional deadline. The steps are:
  1. Check that the address is aligned to the size.
  2. Walk the calling thread's address space's tables in software, to find the mapping, its memory object and the word's offset in it.
  3. Refuse a word in a device memory object at once, so the kernel never reads MMIO.
  4. If the page isn't resident, fail at once with "not resident" ([Access to user memory](#access-to-user-memory)).
  5. Read the word through the direct map. If it differs from the expected value, return at once.
  6. Otherwise queue the thread under the key (memory object, offset), with its deadline.
- Steps 2 to 6 run under the kernel lock, so a wake can't slip between the read and the queueing.
- **Wake** takes the word's address and a count. It resolves the key from the mapping alone, so it doesn't need the page to be resident. It wakes up to that many waiters on the key, and returns how many it woke. Waking many is a long operation with preemption points.
- **The key is the mapping's own object.** A clone is a separate object from its original, so a word in a private mapping is private to that mapping. A shared object's word is shared by every process that maps it on the node.
- **The page can move.** Eviction, supply, copy-on-write and decommit change the frame, not the key, so waiters stay queued.
- **Destroying the memory object** wakes every thread waiting on a word in it. What they return is open ([K30](#k30-results-and-error-names)).
- Where the queues for each key live is open ([K34](#k34-where-word-wait-queues-live)). The error names are open ([K30](#k30-results-and-error-names)).

## Interrupts

### Interrupt handlers

This section gives the mechanism behind [0055](../decisions/0055-interrupt-objects.md), rules 1 to 3. Where it says nothing, the kernel does what seL4 17.0.0 does with IRQ control and IRQ handler capabilities.

- **Interrupt control.** The root server holds the interrupt control capability from boot. From it, a holder makes a handler capability for one shared peripheral interrupt (INTID 32 to 1019), naming its trigger mode, level or edge, and the core it targets, as with seL4's `seL4_IRQControl_GetTriggerCore`. Making a second handler for an interrupt that has one fails. Whether a handler's target core can change later is open ([K36](#k36-interrupt-targets)). MSI handlers are made as in [MSI and the GICv3 ITS](#msi-and-the-gicv3-its).
- **Reserved interrupts.** The kernel makes no handler for a software-generated interrupt, for the virtual timer's interrupt, or for an SPI that a GICv2m frame reserves for MSIs.
- **Per-interrupt state** is kept in kernel memory taken at boot, as seL4's interrupt state table is: for every SPI, and for every LPI the kernel will use.
- **Binding.** A handler is bound to an eventcount through a capability to it with the write right ([0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 2). As in seL4, the handler keeps a copy of that capability in a slot, as a child of the one presented, so revoking the driver's capability unbinds the handler ([Kernel bindings that hold capabilities](#kernel-bindings-that-hold-capabilities)). Binding again replaces the eventcount. Clearing the handler unbinds it.
- **When the interrupt fires**, the kernel acknowledges it at the GIC, masks it if it is level-triggered, and advances the bound eventcount by one. The waking runs in bounded batches ([The kernel lock and long operations](#the-kernel-lock-and-long-operations)). An interrupt with no bound eventcount is masked and logged, as seL4 does.
- **Acknowledging** through the handler unmasks a level-triggered interrupt. An edge-triggered interrupt and an MSI are never masked, so acknowledging one does nothing, and each edge or message advances the count.
- **Deleting the last handler capability** unbinds the eventcount, masks the interrupt, and frees it for a new handler, as seL4's `deletingIRQHandler` does.

### MSI and the GICv3 ITS

This section gives the mechanism behind [0055](../decisions/0055-interrupt-objects.md), rules 4 and 5.

- **Asking for MSIs.** A holder of the interrupt control capability asks for a number of MSIs for one device. The kernel picks free vectors and returns a handler capability for each, with the doorbell address and the data the device must write for it. One handler serves each MSI or MSI-X vector. The PCIe driver (C20) programs the device. How a request names the device, and what authority it needs over that device, is open ([K35](#k35-naming-a-device-for-msi)).
- **With a GICv2 and GICv2m.** The frame's `MSI_TYPER` register gives the SPIs it reserves for MSIs. The doorbell is the frame's `MSI_SETSPI_NS` register, and the data is the SPI's number. Each such SPI is then handled as in [Interrupt handlers](#interrupt-handlers), with edge triggering.
- **With a GICv3 and the ITS.** The doorbell is the ITS's `GITS_TRANSLATER` register. The data is the event ID. The device's ID reaches the ITS with the write. It comes from the PCIe requester ID, as the device tree's `msi-map` or ACPI's IORT describes. The kernel maps each event to an LPI and a collection with `MAPTI`.
- **The redistributors' LPI tables.** The LPI property table holds a byte for each LPI. Each redistributor's pending table holds a bit for each interrupt ID up to the highest LPI. The kernel takes both from its own memory at boot ([Boot memory](#boot-memory)), sized for a number of LPIs fixed at boot, and they last until the node stops. How that number is chosen is open ([K37](#k37-the-number-of-lpis)).
- **The ITS's shared tables.** The command queue (`GITS_CBASER`), the device table and the collection table (`GITS_BASER<n>`) are kernel objects. Before the first MSI through the ITS, the root server supplies untyped memory for them from the root job's memory. They belong to the root job ([0058](../decisions/0058-jobs-and-budgets.md), rule 5). The kernel then enables the ITS and maps one collection to each core's redistributor with `MAPC`. The tables' sizes, and whether they are flat or two-level, are open ([K38](#k38-its-table-sizes)).
- **A device's interrupt translation table.** A request for MSIs for a new device supplies untyped memory for that device's table, sized for its number of events, as `GITS_TYPER` gives the entry size. The table belongs to the job whose untyped memory it is made from. The kernel maps the device to it with `MAPD`.
- **Commands.** The kernel writes commands to the queue, advances `GITS_CWRITER`, and polls `GITS_CREADR` until the ITS has processed a `SYNC` that follows them. This is a wait on hardware under the kernel lock. Its bound, and what the kernel does if the ITS stalls, are open ([K39](#k39-waiting-for-the-its)).
- **Deleting a device's table.** Whether the table is deleted directly, or because the memory it was made from is revoked or its job ends, the kernel first unmaps the device with `MAPD` (valid bit clear) followed by `SYNC`, and waits for the ITS to finish. Only then does it free the table and the device's LPIs. The device's handler capabilities then stop working.
- **The shared tables can't be deleted.** The ITS reads its command queue and its device and collection tables for as long as it is enabled, and they can't be replaced while it runs. A deletion of one, directly or through a revocation, fails while the ITS uses it. This is an exception to a revocation that deletes every descendant. How a revocation that meets such a table reports it is open ([K40](#k40-a-revocation-that-meets-an-its-table)).
- **Controllers beyond the GIC.** The kernel keeps every GIC frame it drives out of device untyped memory. The Pi 4's second-level controller and the BCM2711 PCIe root complex's MSI controller are user-space drivers' (C63, C20).

## Memory objects and paging

### Memory objects and mappings

This section gives the mechanism behind [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rules 1 to 3.

- **Making a memory object.** The caller supplies untyped memory of the job the object will belong to, the object's size in pages and its kind. A pager-backed object also takes an endpoint capability, normally badged; a default fetch timeout, which must be finite; and whether it is immutable. The pager receives a pager capability to the object.
- **The page index.** Each memory object keeps an index from page offset to its state: absent, pending (with the frame allocated for the request), resident (with its frame), or shared with clones. Index nodes come from the object's job.
- **Allocation.** An anonymous object or a clone takes a zero-filled frame from its job on first touch, and a frame of its own when a write needs one. A pager-backed object's frame is allocated from its job before the page request is sent ([Waiting for a page](#waiting-for-a-page)).
- **Mapping.** Map takes a capability to the memory object with the rights asked for, the address space's capability with the write right, an address, a range of the object, the rights (read, write, execute), and a fetch timeout.
  - A mapping may not be both writable and executable. Mapping executable needs the read right.
  - If no fetch timeout is given, the mapping takes the default set on the pager-backed object its pages come from, or for a clone, on the object at the root of its chain of clones. A mapping whose pages come from no pager must name one ([0056](../decisions/0056-faults-and-page-fetch-deadlines.md), rule 4).
  - Page tables and mapping records come from the address space's job, or, for the root server's address space, from the root job. If that job has no free memory, Map fails at once with "no memory".
  - The mapping record keeps a copy of the memory-object capability presented, as a child of it, with the rights the mapping needs ([0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 4). Revoking or deleting that copy unmaps the range. Unmap deletes the copy.
  - A Map of the kernel interface library's object is checked further ([The kernel interface library](#the-kernel-interface-library)).
- **Mapping records.** The kernel records each mapping against its memory object, so that it can unmap a page in every address space that maps it, on Evict, Clean, decommit, a copy-on-write break, or destruction.
- **Listing mappings.** With the address space's capability with the read right, listing returns, for each mapping, its range, its rights, its fetch timeout, its offset in the object, and the object's badge if it is pager-backed. With the write right, it can also return a capability to a listed mapping's memory object, with the read right, and with the write right if the mapping is writable. That capability is derived from the mapping's own copy, so revoking the object's capability, or unmapping, reaches it ([0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 3). How a list longer than one message is returned is open ([K41](#k41-listing-in-pages)). Revoking the address-space capability used to list doesn't reach the capabilities a listing yields ([K42](#k42-capabilities-yielded-by-listing)).

### Copy-on-write clones

This section gives the mechanism behind [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 4.

- **The call.** Cloning takes a capability to the original, a range of it, and untyped memory of the job the clone will belong to. The clone is a new anonymous object.
  - If the original is anonymous, the call needs the write right on it, and the clone's job must be the original's job or a descendant of it. This makes a snapshot clone of the pages the original holds.
  - If the original is pager-backed or immutable, the call needs only the read right, and the clone's job may be any job.
  - A clone is anonymous, so cloning a clone needs the write right on it, and the new clone's job must be that clone's job or a descendant of it, because the new clone shares the frames the cloned clone holds ([0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 4; [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 2).
- **Snapshot pages.** For each resident page the anonymous original holds in the range, the kernel shares the frame between the original and the clone, counts the sharing in the frame's share count, and write-protects the page in every mapping of either side. A write on either side gives the writer's object a new frame from the writer's object's job, copies the page into it, and drops the writer's share of the old frame. The old frame stays charged to the job that made it until no object shares it.
- **Read-through pages.** Pages the clone hasn't written, and that the cloned object doesn't hold itself, read through to the pager-backed root original. A fault on such a page in the clone is resolved through the root original's page index. If the page is resident there, the clone maps that frame read-only. If not, the fault becomes a page request to the root original's pager, charged to the root original's job. A write copies the page into the clone, from the clone's job. Evicting the page from the root original unmaps it in every clone that reads it through.
- **Immutable originals.** An immutable object's pages never change, so a clone of one shares its frames, and a write copies the page into the clone, from the clone's job.
- **Clones of clones.** A clone of a clone shares the frames the cloned clone holds, as snapshot pages, and reads through to a pager-backed root original for pages neither holds. Pages neither holds of an immutable root share the root's frames.
- **Pinned pages.** A page pinned as an IPC buffer is copied into the clone at once, charged to the clone's job. If that job has no free memory, the clone call fails with "no memory".
- **Destroying an original.** Destroying an anonymous original destroys its snapshot clones and removes their mappings. What a read-through clone sees when its pager-backed original is destroyed is open ([K46](#k46-a-read-through-clone-whose-original-is-destroyed)).
- **Structure.** Whether shared pages live in a hidden node apart from both sides, as Fuchsia's snapshot clones do, or in chains of shadow objects, as Mach's do, and how chain length is bounded, is open ([K47](#k47-the-structure-of-shared-pages)).
- **Long operations.** Cloning a large range, a copy-on-write break on a page mapped in many address spaces, and destroying an original with many clones have preemption points ([The kernel lock and long operations](#the-kernel-lock-and-long-operations)).

### The pager protocol

This section gives the mechanism behind [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rules 5 to 8. The faulting thread's side of a page request is in [Waiting for a page](#waiting-for-a-page).

**Page requests.** When a thread touches a missing page of a pager-backed object, the kernel allocates the frame from the object's job, marks the page pending in the object's page index with the frame, and queues the thread on the pager's endpoint as a sender of the page request. The kernel never buffers the message. The request donates no scheduling context.

The page request is an IPC message defined in the IDL ([0059](../decisions/0059-the-kernel-interface-library.md), rule 2): a one-way request of `aspis.kernel.pager/1` on the common call header ([0064](../decisions/0064-the-call-header-and-wire-encoding.md), rule 9). The pager answers with Supply or Fail, never with a reply. It carries:

- the object's badge;
- the page's offset;
- a suggested length;
- the kind of access: read, write or execute;
- a reference to the frame the kernel allocated.

There is one request per page. One thread carries it until the pager receives it. Whether a higher-priority thread that joins a request becomes its carrier is open ([K44](#k44-priority-of-a-page-request)).

**Filling the frame.** The pager fills the pending frame through its pager capability. Which way it does so is open ([K43](#k43-how-a-pager-fills-a-frame)), but either way it needs no memory of its own per page, and no writable mapping of the page outlasts Supply or Fail.

**Pager operations.** Each takes the pager capability, an offset and a length.

- **Supply** installs the filled pages in the object and clears their pending marks. It maps nothing and needs no memory. Waiting threads resume and repeat the access. Each maps the page on its own fault, from its own address space's job. A page supplied after every waiter has gone is kept.
- **Fail** takes an error key: the interface ID, major and code of a typed error, 36 octets ([0065](../decisions/0065-typed-errors-and-minor-versions-on-the-wire.md), rules 1 and 2). It clears the pending marks in the range and frees their frames. Every waiting thread gets a page-unavailable fault with that key. The full error stays with the pager. Where the kernel keeps the key until every waiting thread's fault is delivered, and how a handler asks the pager for the full error, are open ([K74](#k74-keeping-a-fails-error-key)).
- **Read-ahead** asks the kernel to allocate frames for further pages, from the object's job, and mark them pending, so the pager can fill and supply them. Pages for which the job has no free memory are skipped, and no memory request is sent.
- **Query** reports which pages in the range are dirty. Whether it also reports which pages were accessed, for a pager's LRU, is open ([K48](#k48-telling-a-pager-which-pages-are-least-recently-used)).
- **Clean** write-protects the range in every mapping and clears its dirty state, so the pager can write the pages back and see later writes.
- **Evict** unmaps the range everywhere, including in clones that read it through, and frees its frames to the free memory of the object's job. It skips pinned frames. Threads waiting on a word in an evicted page keep waiting, because word waiters are keyed by memory object and offset. What Evict does to a pending page is open ([K45](#k45-evicting-or-decommitting-a-pending-page)).

Evicting, cleaning or unmapping a large range is a long operation, with preemption points ([The kernel lock and long operations](#the-kernel-lock-and-long-operations)).

### Decommit

This section gives the mechanism behind [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 8.

- **The call.** Decommit takes a capability to an anonymous memory object, a clone included, with the write right, and a range.
- **What it does.** It unmaps the range in every mapping of the object, and drops the object's pages in it. A frame the object owns alone returns to the free memory of the object's job. A frame shared with another clone loses only this object's share, and stays charged to the job that made it until no object shares it.
- **The next touch.** A page of an anonymous object, or a page a snapshot clone held, reads as zeros on its next touch. A page of a clone of a pager-backed object reads through to the root original again.
- **Pinned frames** are skipped ([0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 8). A pending page is open ([K45](#k45-evicting-or-decommitting-a-pending-page)).
- **Word waiters** on a decommitted page stay queued, since the key doesn't change ([Word waits](#word-waits)).
- **Long ranges.** Decommitting a large range is a long operation, with preemption points.
- **Use.** Runtimes and allocators decommit pages they don't need when the memory-pressure eventcount advances ([Memory requests and reclaim](#memory-requests-and-reclaim), step 3 of reclaim). A piece that empties can then be taken back by the memory server.

## Faults

### Fault delivery

This section gives the mechanism behind [0056](../decisions/0056-faults-and-page-fetch-deadlines.md), rules 1 to 3.

**Setting the endpoints.** A thread's fault endpoint and timeout endpoint are set through the thread's capability with the write right.

- The thread keeps its own copy of each endpoint capability presented, in a slot of the thread, as seL4 17.0.0 does with `tcbFaultHandler` and `tcbTimeoutHandler`. Each copy is a child of the capability presented ([Kernel bindings that hold capabilities](#kernel-bindings-that-hold-capabilities)). Revoking or deleting the capability presented deletes the copy, and that unsets the endpoint.
- Setting an endpoint again replaces the copy. Passing no capability unsets it.

**Sending a fault.**

- The kernel sends a fault as a call on the faulting thread's behalf. The thread is queued as a sender on the endpoint, as a faulting thread is in seL4, so the kernel never buffers the message itself.
- The message carries the badge of the thread's copy of the endpoint capability, which tells the handler which thread faulted.
- A fault sent to the fault endpoint donates the thread's scheduling context, as in seL4. A fault sent to the timeout endpoint, a timeout fault or a context-withdrawn fault, donates none, so the handler on a timeout endpoint runs on its own scheduling context.
- The handler's reply resumes the thread. The kernel reads none of its contents. A handler that changes the thread's registers does so through the thread's capability before it replies ([0061](../decisions/0061-debugging.md), rule 3). This departs from seL4, whose fault replies may set registers ([0047](../decisions/0047-the-kernel-follows-sel4.md), rule 3).
- If the thread has no fault endpoint, the kernel suspends the thread and logs the fault ([0042](../decisions/0042-log-ring-and-panic-path.md), rule 1). A thread with no timeout endpoint gets no timeout or context-withdrawn faults. A fault in flight when its endpoint is unset is open ([K50](#k50-a-fault-in-flight-when-its-endpoint-is-unset)).

**The fault message.** Every fault message names its kind, as its method number, and carries the program counter and the exception syndrome. Whether the syndrome is raw or decoded is open ([K49](#k49-the-syndrome-in-a-fault-message)). Each kind then adds these fields:

| Kind | Fields |
|---|---|
| Capability | The capability address, and what failed: no capability there, the wrong type, or a missing right |
| Unmapped | The address, and the access: read, write or execute |
| Page unavailable | The address, the object's badge, and the pager's error key ([The pager protocol](#the-pager-protocol)) |
| Page deadline | The address, the object's badge, and whether the fetch timeout passed or the wait was canceled |
| Memory | The address, what the memory was for (a frame, or kernel memory for the fault), and why it couldn't be had: the limit with nothing to evict, a refusal, a timeout or a cancel |
| User exception | The syndrome's exception class and its details |
| Unknown system call | The call's number |
| Timeout | The scheduling context's badge, and the time used |
| Context withdrawn | The withdrawn scheduling context's badge |
| Debug | The kind of debug event (breakpoint, watchpoint or single step), and the address |

Each kind is a method of the `[local]` interface `aspis.kernel.fault/1`, on the common call header, and each has a generated grammar ([0059](../decisions/0059-the-kernel-interface-library.md), rule 2; [0064](../decisions/0064-the-call-header-and-wire-encoding.md), rule 9). A handler that doesn't know a kind treats it as fatal: its generated dispatcher hands the unknown method to the handler, which doesn't reply, so the thread stays stopped ([Messages the kernel sends](call-language.md#messages-the-kernel-sends)).

### Waiting for a page

This section gives the steps behind [0056](../decisions/0056-faults-and-page-fetch-deadlines.md), rule 4, and [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rules 6 and 7. The rules for charging memory are [0058](../decisions/0058-jobs-and-budgets.md), rule 6.

**At the fault.** When a thread faults on a page of a pager-backed object that isn't resident:

1. The kernel arms the thread's fetch timeout, from the faulting thread's own mapping. The timeout covers every step below, the wait for memory included ([0056](../decisions/0056-faults-and-page-fetch-deadlines.md), rule 4).
2. If the page is pending, the thread joins the outstanding request, and waits on the page.
3. Otherwise, the kernel takes a frame for the page from the memory object's job. If that job has no free memory, the kernel sends a memory request on the thread's behalf, and the thread waits for memory ([Memory requests and reclaim](#memory-requests-and-reclaim)). A refusal becomes a memory fault.
4. With the frame in hand, the kernel marks the page pending in the object's page index, and sends a page request that names the frame to the pager's endpoint ([The pager protocol](#the-pager-protocol)). The thread is queued on that endpoint as a sender, carrying the request.

A fault on an anonymous object's missing page takes a zero-filled frame from the object's job, and waits for memory only as in step 3.

**When the page arrives.** Supply installs the page and clears its pending mark. Each waiting thread resumes and repeats the access. Its own mapping of the page, with its page tables and mapping records, is made then, from its address space's job, as on any fault. If that job has no free memory, that thread alone waits for memory or takes a memory fault.

**When the fetch timeout passes.** The kernel first detaches the thread, then sends the fault to the thread's fault endpoint.

- A thread waiting for memory takes a memory fault, marked timed out. A memory request the memory server hasn't received is withdrawn ([K51](#k51-memory-waits-on-the-fault-path)).
- A thread waiting on the page takes a page-deadline fault.
- If the pager hasn't received the request, and this thread was carrying it, the request passes to the next thread waiting on the page. If none is waiting, the request is dropped, the pending mark cleared and the frame freed.
- If the pager has received the request, it stays outstanding for the other waiters, until Supply, Fail or Evict covers the page.

**When the wait is canceled.** Canceling the thread ([IPC deadlines and cancellation](#ipc-deadlines-and-cancellation)) detaches it in the same way, and the thread takes its fault at once, marked canceled: a memory fault if it was waiting for memory, a page-deadline fault if it was waiting on the page.

**Afterward.** A page supplied after every waiter has gone is kept. A thread that faults again on a page whose request is still outstanding joins that request, and no second request is sent. A request dropped before the pager received it is gone, and the next fault sends a new one.

The fetch timeout's unit and range are open ([K52](#k52-the-fetch-timeouts-representation)).

## Jobs and memory reclaim

### Job capabilities

This section gives the mechanism behind [0058](../decisions/0058-jobs-and-budgets.md), rules 1, 3, 4 and 9.

- **Who holds them.** A job's capability is held by its manager, which made the job: the root server for the jobs it spawns into before the process manager runs, the process manager for the native processes it spawns, or the POSIX process server for POSIX processes ([0061](../decisions/0061-debugging.md), rule 4). The memory server holds a capability to each job it lends to, which lets it give and take back memory only. A process doesn't hold its own job's capability. It holds untyped memory of its job ([Untyped memory and kernel records](#untyped-memory-and-kernel-records)).
- **Operations:**
  - make a child job, from the job's memory, with a reservation carved from the job's reservation, a limit no more than the job's, and a CPU share carved from the job's;
  - give the job a piece of untyped memory, which the kernel records as the job's and indexes, and which yields an untyped capability for the piece. The kernel refuses a piece that would take the job, or any ancestor, past its limit ([0058](../decisions/0058-jobs-and-budgets.md), rule 4);
  - take back an empty piece the job holds above its reservation ([Untyped memory and kernel records](#untyped-memory-and-kernel-records));
  - set the job's limit and its memory endpoint;
  - stop every thread in the job and its descendants, and resume them;
  - list those threads, each with its address space, and get a capability to a listed thread or address space;
  - end the job ([Ending a job](#ending-a-job)).
- **Rights.** Which rights each operation needs, and how the memory server's capability is limited to giving and taking back memory, is open ([K53](#k53-rights-on-a-jobs-capability)).
- **Listing.** How a list of threads longer than one message is returned is open ([K41](#k41-listing-in-pages)).
- **Stopping.** Stopping a job suspends each of its threads, and its descendants' threads, as [Suspending a thread](#suspending-a-thread) says. Stopping doesn't cancel a thread's current wait ([0061](../decisions/0061-debugging.md), rule 3). Stopping and resuming are long operations, with preemption points.

### Memory requests and reclaim

This section gives the mechanism behind [0058](../decisions/0058-jobs-and-budgets.md), rules 6 and 7.

**Memory requests.** When a fault needs memory and the job responsible has none free:

1. The kernel sends a memory request to the job's memory endpoint, on the faulting thread's behalf, as it sends a page request: the thread is queued as a sender, and no scheduling context is donated. The request is a one-way request of `aspis.kernel.memory_request/1` on the common call header ([0064](../decisions/0064-the-call-header-and-wire-encoding.md), rule 9).
2. The request carries the job's badge, the amount needed, what it is for (a page frame, a page-table page, or a kernel record), and whether the job, or an ancestor, is at its limit. How the request says which job is at its limit is open ([K54](#k54-reclaim-at-a-limit)).
3. The memory server answers through its capability to the job, not with a reply, with one of: memory lent, and the kernel adds the pieces to the job, and the thread repeats its access; memory freed within the job, and the thread repeats its access; or a refusal, and the thread gets a memory fault.

A memory fault says whether the refusal came with the job or an ancestor at its limit, and whether the thread's wait timed out or was canceled ([Fault delivery](#fault-delivery)). The mapping's fetch timeout bounds the wait, and a cancel ends it at once ([Waiting for a page](#waiting-for-a-page)). How a memory request is withdrawn, and whether it passes between threads, is open ([K51](#k51-memory-waits-on-the-fault-path)).

**A runtime's request.** An explicit call that needs memory, such as making an object, never sends a memory request. It fails at once with "no memory". The runtime then calls `aspis.memory/1` on the job's memory endpoint, which its startup block carries ([The startup block](#the-startup-block)). The memory server lends as it does for a fault and then replies, or refuses with a typed error ([0058](../decisions/0058-jobs-and-budgets.md), rule 6). The interface's methods and errors are C83's.

**Reclaim below a limit.** The memory server frees memory in the order [0058](../decisions/0058-jobs-and-budgets.md), rule 7 gives, stopping as soon as it has enough:

1. it takes back empty pieces that jobs hold above their reservations, each with the single take-back operation ([Untyped memory and kernel records](#untyped-memory-and-kernel-records));
2. it asks pagers to evict clean pages held in borrowed memory, skipping pinned frames;
3. it advances the node's memory-pressure eventcount, so runtimes and allocators decommit what they don't need ([Decommit](#decommit)), waits a short time, and takes back the pieces that emptied;
4. it asks pagers to write back and evict dirty pages held in borrowed memory.

How the memory server and pagers tell pages in borrowed pieces from pages in reserved ones is open ([K56](#k56-targeting-borrowed-memory)). The memory server asks pagers with a deadline ([0054](../decisions/0054-ipc-endpoints.md), rule 5).

**When the memory server can't lend.** When the job responsible, or an ancestor, is at its limit, or the reclaim steps above found too little, the memory server lends nothing more. It has the pagers of the job's own objects evict clean pages of the job, least recently used first, wherever those pages sit, reserved or borrowed, and answers "memory freed" once a page is free. It refuses only if nothing can be evicted ([0058](../decisions/0058-jobs-and-budgets.md), rule 6). When an ancestor's limit is the one reached, the memory server first reclaims within that ancestor's subtree, from memory above reservations, and lends what it frees within the limit. Open: how the memory server finds the pagers of a job's objects ([K54](#k54-reclaim-at-a-limit)); which jobs in a subtree it evicts from first ([K55](#k55-reclaim-under-an-ancestors-limit)); how a pager knows its least recently used pages ([K48](#k48-telling-a-pager-which-pages-are-least-recently-used)); and whether it also writes back dirty pages ([K57](#k57-dirty-pages-at-a-limit)).

### Ending a job

This section gives the mechanism behind [0058](../decisions/0058-jobs-and-budgets.md), rule 10.

Ending a job takes these steps, with preemption points between them and within each ([The kernel lock and long operations](#the-kernel-lock-and-long-operations)):

1. Stop every thread in the job and its descendants.
2. Unregister every IPC buffer that is a page of a memory object of the job or a descendant ([IPC buffers](#ipc-buffers)).
3. Revoke every piece of untyped memory the job and each descendant hold, reserved and borrowed, deepest descendants first. That destroys every object made from them, including the snapshot clones of their anonymous objects. A device's interrupt translation table is destroyed only after the kernel has unmapped the device in the ITS ([MSI and the GICv3 ITS](#msi-and-the-gicv3-its)). The ITS's shared tables belong to the root job, which never ends, so ending a job never meets them.
4. Return borrowed pieces to the pool, and the reservation and CPU share of the job to its parent.

What happens to read-through clones of the job's pager-backed objects, which may belong to other jobs, is open ([K46](#k46-a-read-through-clone-whose-original-is-destroyed)).

## The kernel interface library

The library's decisions are in [0059](../decisions/0059-the-kernel-interface-library.md). This section gives the mechanism. It is settled with C17.

**Packaging.**

- The crate `aspis-kernel-interface` is built for EL0 and linked on its own, as a position-independent object. The build checks that the result has no writable loadable segment and no dynamic relocations, and fails if it has either.
- The build embeds the linked library in the kernel's image as page-aligned data. The stub's relocation of the kernel ([0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), rule 2) never touches it, and the kernel never executes it.
- At boot the kernel makes those pages the library's resident immutable memory object, and gives the root server a capability to it ([What the root server receives](#what-the-root-server-receives)). The object is a boot object: it belongs to no job and is never destroyed.

**Mapping.**

- Whoever creates an address space maps the library's memory object into it with the ordinary Map operation: the library's read-only data read-only, and its code read-only and executable. Where it is mapped is open ([K60](#k60-where-the-library-is-mapped)).
- The kernel recognizes the library's memory object, which it made at boot. A Map of that object that asks for execute must cover exactly the library's code segment, at its own offset and size, or it is refused.
- The kernel records the code mapping's range in the address space. An address space has at most one such mapping. While the address space exists, the kernel refuses to unmap, remap or move that range.
- A software breakpoint in the library would need a private clone mapped in its place, which this forbids. Debuggers use hardware breakpoints there ([Debugger access to threads and memory](#debugger-access-to-threads-and-memory)).

**The call check.**

- On a system call, the kernel takes the address of the trapping instruction, which is `ELR_EL1` less 4, and compares it with the address space's recorded code range. A call from outside the range becomes an unknown-system-call fault carrying the call's number ([Fault delivery](#fault-delivery)).
- The check costs one range comparison per call. Whether the kernel also checks each call's place is open ([K58](#k58-whether-the-call-check-also-checks-the-calls-place)).
- An address space with no library mapping can make no system call. Its threads can only fault.

**The entry table.**

- The library starts with an entry table. It lists each interface the library supports, by interface ID and major version, with the offset from the library's base of that version's table of functions.
- Each function table holds offsets from the library's base too. No table holds an absolute address, so the library needs no relocation wherever it is mapped.
- A program's runtime reads the library's address from its startup block ([The startup block](#the-startup-block)), looks up the interface versions it was built for, and calls through their function tables.
- The library carries every major version still in its support period ([0059](../decisions/0059-the-kernel-interface-library.md), rule 6). The period is D115's ([K61](#k61-support-period-of-the-librarys-major-versions)).
- The table's field widths and other details are open ([K59](#k59-the-entry-tables-details)).

**The runtime crate.** `aspis-rt` wraps the entry table in Rust. Early servers use it directly, and relibc's ASPIS backend and any later `std` port are built on it ([0059](../decisions/0059-the-kernel-interface-library.md), rule 8).

**Operations built from several calls.** An interface may include operations that the library builds from several system calls. The first is the capability-table copy ([Copying a capability table](#copying-a-capability-table)).

**The kernel's own messages.** Fault messages, page requests and memory requests aren't part of the private ABI. They are requests of three `[local]` interfaces with wire grammars, which user-space servers implement ([Endpoint operations and messages](#endpoint-operations-and-messages); [0059](../decisions/0059-the-kernel-interface-library.md), rule 2).

**Names and errors.** The library's interfaces are `[kernel]` interfaces named `aspis.kernel.<object>`, such as `aspis.kernel.eventcount` ([0059](../decisions/0059-the-kernel-interface-library.md), rule 1; [Kernel interface names](call-language.md#kernel-interface-names)). Their calls render in canonical text with the target `-`. Their failures are typed errors of their own interfaces; the raw status numbers stay private ([0065](../decisions/0065-typed-errors-and-minor-versions-on-the-wire.md), rule 8).

## Processes and spawn

### Native spawn and program loading

This section gives the mechanism behind [0060](../decisions/0060-processes-native-spawn-and-elf.md), rules 2 and 3.

**Arguments.** Spawn, a call on the process manager, takes:

- the executable: a capability to an immutable memory object, with the read right;
- the job to run in: untyped memory that belongs to that job, of a job the spawner manages;
- the initial capabilities, each with a name;
- the environment block ([0025](../decisions/0025-twelve-factor-app-contract.md), rule 4).

The initial capabilities can outnumber one message's three, so spawn is a builder session: a call opens it, each `add` call carries up to three named capabilities, and a last call starts the process ([0060](../decisions/0060-processes-native-spawn-and-elf.md), rule 2; [0066](../decisions/0066-capability-parameters-and-server-streams.md), rule 3).

It returns the process's ID, or a mark that it has none, and a capability to the main thread. These are open:

- how the spawner checks that the untyped memory belongs to a job it manages, and how a caller gets a job to spawn a child into ([K62](#k62-how-a-spawner-knows-the-job));
- which rights the main-thread capability carries ([K63](#k63-rights-of-the-main-thread-capability));
- what the process gets beyond the initial capabilities named in spawn, so that its runtime can make its own threads ([K64](#k64-what-a-runtime-needs-to-make-its-own-threads));
- how a process spawned before it can be named learns its ID later ([K67](#k67-a-process-named-after-it-starts)).

**Loading.** The spawner does these steps, making every object from the job's untyped memory:

1. It checks the ELF headers: ELF64, little-endian, `EM_AARCH64`, type `ET_DYN`, and program headers inside the file. It refuses a segment that is both writable and executable, since the kernel would refuse the mapping ([0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 6), and a `PT_INTERP` header while dynamic linking is open ([0060](../decisions/0060-processes-native-spawn-and-elf.md), rule 6; [K73](#k73-dynamic-linking)).
2. It makes the address space, the capability space and the main thread.
3. It chooses a load base, and maps each `PT_LOAD` segment:
   - a read-only segment, in place from the executable's memory object;
   - a writable segment, as a clone of that range of the executable's memory object, made in the job ([Copy-on-write clones](#copy-on-write-clones)). How the tail of the segment's last page is zeroed is open ([K66](#k66-the-tail-of-a-writable-segment)).
4. It makes an anonymous memory object for the zero-filled part of each writable segment beyond its file data, and maps it after the clone.
5. It makes the main thread's stack, as an anonymous memory object, and the main thread's IPC buffer, which it touches and registers ([IPC buffers](#ipc-buffers)).
6. It maps the kernel interface library ([The kernel interface library](#the-kernel-interface-library)).
7. It fills the startup block, and maps it read-only.
8. It installs the initial capabilities, and the job's memory endpoint, in the new capability space.
9. It sets the main thread's fault endpoint to itself, its program counter to the entry point, its stack pointer, and `x0` to the startup block's address.
10. It starts the main thread.

The program's own code runs only after the last step.

### The startup block

This section gives what [0060](../decisions/0060-processes-native-spawn-and-elf.md), rule 4 calls the startup block. It is a read-only page the spawner fills. It holds:

- the block's version;
- the kernel interface library's address ([0059](../decisions/0059-the-kernel-interface-library.md), rule 5);
- each initial capability's name and slot;
- the environment block's address and length;
- the slot of the job's memory endpoint, a capability badged for the job, on which the runtime asks for more memory ([0058](../decisions/0058-jobs-and-budgets.md), rule 6);
- the process's ID, or a mark that it has none;
- the main thread's stack, and its thread-pointer area.

The runtime crate, `aspis-rt`, reads the block, and sets the main thread's `TPIDR_EL0` from it. The block's layout is open ([K65](#k65-the-startup-blocks-layout)).

## Debugging

### The panic symbol table

This section gives the mechanism behind [0061](../decisions/0061-debugging.md), rule 2.

**The table.** After the kernel is linked, the build reads the kernel's ELF and writes a table of its function symbols.

- Each entry holds a 32-bit offset from the kernel's start, and the symbol's name.
- Entries are sorted by offset, so the kernel finds a frame's symbol by binary search.
- Offsets need no relocations, so the table doesn't depend on where the stub places the kernel.
- The build writes the table in a fixed order from the pinned build's output, so it is reproducible ([0038](../decisions/0038-reproducible-builds-and-provenance.md), rule 1).

**The build ID** is a digest of the kernel's ELF, computed by the build. Which hash, and the table's exact format, are open ([K68](#k68-the-symbol-tables-format-and-the-build-ids-hash)).

**Carrying it.** The stub carries the table in a section of its own, beside `.kernel` ([0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), rule 3). At boot it copies the table right after the kernel's image, inside the range that the memory map types as kernel image ([0041](../decisions/0041-boot-abi.md), rule 3). A new, non-critical boot-information record gives the table's address and size, and carries the build ID. The kernel's direct map covers the kernel image's range read-only ([Address-space layout](#address-space-layout)), so the panic path reads the table there.

**At a panic,** the kernel prints each frame of the backtrace as symbol and offset, and the build ID. Without the record, it prints offsets from the kernel's start. The host tool `cargo xtask symbolize` turns those into file and line, from the release's unstripped ELF.

### Debugger access to threads and memory

This section gives the operations behind [0061](../decisions/0061-debugging.md), rule 3.

**On a thread's capability.**

- With read: read the thread's state, its general registers, stack pointer, program counter, `PSTATE`, `TPIDR_EL0`, and floating-point and SIMD registers.
- With write, also:
  - write those registers;
  - suspend and resume the thread ([Suspending a thread](#suspending-a-thread));
  - single-step it, through `MDSCR_EL1.SS` and the saved `SPSR_EL1.SS`, so it takes a debug fault after one instruction;
  - set and clear hardware breakpoints and watchpoints, which the kernel saves and restores with the thread's registers; how many, and how they are switched, is open ([K70](#k70-hardware-debug-state));
  - set the thread's fault endpoint ([Fault delivery](#fault-delivery)).

**On an address space's capability.**

- With read: read memory at a virtual address; list the mappings as descriptions ([Memory objects and mappings](#memory-objects-and-mappings)).
- With write, also: write memory at a virtual address; list the mappings with their memory-object capabilities.

**Reading and writing memory.** For each page the access covers, the kernel follows [Access to user memory](#access-to-user-memory):

1. it walks the address space's tables in software, and fails with "not resident" if the page isn't mapped resident;
2. it fails with "not RAM" if the mapping's memory object is a device memory object, so it never touches MMIO;
3. for a write, it checks that the mapping has the write right, or that the debugger presented a capability, with the write right, to the memory object mapped there, which is how the private clone is written;
4. for a write to a page shared copy-on-write, it gives the written object a frame of its own from that object's job, or fails with "no memory";
5. it copies through its direct map, and for a write marks the page dirty in its memory object;
6. after a write to a page mapped executable, it cleans the data cache to the point of unification and invalidates the instruction cache for that range.

A read of a page that isn't resident fails, and a debugger can't touch the page itself ([K69](#k69-a-debugger-read-of-a-page-that-isnt-resident)).

### Software breakpoints in a private clone

This section gives the steps behind [0061](../decisions/0061-debugging.md), rule 4. When a Cedar decision allows the debug action with write, the manager:

1. suspends every thread of the process, or stops the process's job when the process has a job of its own ([Job capabilities](#job-capabilities));
2. makes a clone of the code mapping's range of the immutable object, in the process's job ([Copy-on-write clones](#copy-on-write-clones));
3. unmaps the code mapping, and maps the clone in its place, read-only and executable, with the same fetch timeout;
4. resumes the threads;
5. hands the debugger the clone's capability with the write right.

When the debugger detaches, the manager revokes the debugger's copies, restores each thread's fault endpoint, suspends the threads again, maps the immutable object in place of the clone, destroys the clone, and resumes the threads.

Whether the clone covers the whole code mapping is open ([K71](#k71-the-private-clones-extent)). Revoking the debugger's copies doesn't reach memory-object capabilities it got by listing mappings with write ([K42](#k42-capabilities-yielded-by-listing)).

### User crash dumps

This section gives the mechanism behind [0061](../decisions/0061-debugging.md), rule 5. A crash dump is an ELF core file. The fault handler finds every thread of the process through its job, and writes each thread's registers as notes, and the process's resident memory as loadable segments. It writes the dump as an object owned by the process's owner. Writing dumps needs storage and a Cedar decision, so it starts in M4, when the node's PDP runs. Before then, only test builds write dumps, from their own test code. The dump's contents are open ([K72](#k72-crash-dump-contents)).

## Boot hand-off

### What the root server receives

This section gives the mechanism behind [0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 2, and the item that [0037](../decisions/0037-initial-image-format-and-contents.md), rule 4 left to the kernel specification: how the initial image's memory becomes a memory object.

The kernel makes these boot objects from memory it kept for itself ([Boot memory](#boot-memory)):

- the initial image, the device tree and the boot information, each a resident immutable memory object;
- the kernel interface library's resident immutable memory object ([The kernel interface library](#the-kernel-interface-library));
- the framebuffer's device memory object, beside the framebuffer's kernel object ([0042](../decisions/0042-log-ring-and-panic-path.md), rule 6);
- the seed's frame, which the kernel never maps ([0041](../decisions/0041-boot-abi.md), rule 4);
- the root job;
- the root server's first thread, its IPC buffer, its capability space, its address space, and the page tables the kernel builds to start it;
- the control capabilities: interrupt control, and one scheduling-control capability for each core.

The root server receives capabilities to all of them, and:

- the rest of usable RAM, as untyped memory capabilities in the root job;
- the MMIO ranges, as device untyped capabilities, except every frame of the interrupt controller (the GICv2 distributor, CPU interface and GICv2m frame; or the GICv3 distributor, redistributors and ITS) and the UART.

Boot objects belong to no job, count against no reservation or limit, and are never destroyed ([0058](../decisions/0058-jobs-and-budgets.md), rule 1).

**The boot capability space (C11).** The kernel builds it in `mm::seal`, before it seals the boot allocator, in pages it takes from that allocator. Its CNodes are boot objects: they are never destroyed, and no untyped capability covers their memory ([Derivation and revocation](#derivation-and-revocation), "Boot objects are never destroyed").

- **The originals page** is one more page of 128 slots that no capability names. It holds the original capability to each boot CNode, each a root of the tree: the root CNode's in slot 0 and the untyped CNodes' in slots 1 to 16. The root CNode holds a copy of each, as its child, so deleting or revoking through the root CNode never destroys a boot CNode.

- **The root CNode** is one page: radix 7, 128 slots. Its capability carries a 50-bit guard of zeros, so a 64-bit capability address is a root index shifted left by 7, then an index in the CNode found there. A root slot itself is named at depth 57.
- **Root slots:**

  | Slots | Hold |
  |---|---|
  | 0 | Nothing |
  | 1 | A copy of the root CNode's capability |
  | 2 to 15 | Kept for later boot capabilities: the first thread and its address space (C12), interrupt control (C13), the boot memory objects (C15) and the root job (C16) |
  | 16 to 31 | Copies of the untyped CNodes' capabilities |
  | 32 to 127 | Free for the root server |

- **The untyped CNodes** are 16 one-page CNodes of radix 7, so they hold 2048 untyped capabilities, the most the kernel makes ([Boot memory](#boot-memory)). The kernel takes a fixed 16 pages for them before it divides the rest of RAM into pieces, since taking pages can split the free set into more pieces: a fixed count is what always fits.
- **Each piece gets one untyped capability**, RAM pieces first, then device pieces, each in address order, from slot 0 of the first untyped CNode on. Each is a root of the derivation tree, with no parent, and a watermark of 0. Free RAM untyped memory is zero.
- The boot log reports the number of untyped capabilities. C19 fixes what the root server receives in root slots 2 to 15, and how it learns the layout.

## Open questions

These mechanism questions are open, except those marked settled. Each is settled alongside the prototype of chunks C10 to C16, or of C17 or C70 where it says so, and this note records the answer. A settled question keeps its number, and says where its answer is. A question whose answer would change a guarantee of the records needs an edit to that record instead ([0047](../decisions/0047-the-kernel-follows-sel4.md), rule 5). K12, K61 and K73 are decisions rather than mechanism. K10 and K61 belong to existing backlog entries, D95 and D115. The [design backlog](design-backlog.md#m2-kernel-objects) carries the rest as D150 to D160 under M2, D161 under [M3](design-backlog.md#m3-node-user-space-and-the-entropy-gate) for K12, and D162 under [M6](design-backlog.md#m6-a-console-you-can-log-in-to) for K73. "The third review" means the third review of the M2 records.

### K01. ASID allocation

How does the kernel allocate ASIDs so that no job can exhaust them ([0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 4)?

- **Settled with C10:** generation rollover, as Linux on arm64 does; see [Address-space layout](#address-space-layout).
- **From:** [Address-space layout](#address-space-layout); the third review. **Backlog:** D150.

### K02. Small kernel records

How does the kernel keep the small, capability-less records it makes on faults (mapping records, page-index nodes, pending marks and frame share counts) in a job's memory? They are small and short-lived, and untyped memory is a watermark allocator, so a job's free memory would fragment.

- **Options:** per-job slab pages, each a page-sized piece retyped into fixed-size records with a free list, returned to the job when empty, which [0047](../decisions/0047-the-kernel-follows-sel4.md), rule 3 would list as a departure from seL4; records reserved inside the object they describe, sized when it is made; or a fixed allowance per address space and memory object, set at creation.
- **Blocks:** C15, C16. C10 makes no small records: its page tables and address spaces are whole pages.
- **From:** [How far the kernel follows seL4](#how-far-the-kernel-follows-sel4); [Untyped memory and kernel records](#untyped-memory-and-kernel-records); [0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 1; the third review. **Backlog:** D150.

### K03. The index of a job's pieces

Where does the memory for the kernel's per-job index of pieces come from?

- **Options:** slots made from the job's own memory, supplied with the call that gives memory; a header inside each piece; or a fixed-size index in the job object, which caps the number of pieces.
- **Blocks:** C16.
- **From:** [Untyped memory and kernel records](#untyped-memory-and-kernel-records); [0058](../decisions/0058-jobs-and-budgets.md), rule 3; the third review. **Backlog:** D150.

### K04. Piece sizes

Which objects come from page-sized pieces, which from larger ones, and how large are those?

- **Options:** page-sized only, with objects larger than a page (CNodes, runs of page tables) made from a run of contiguous pieces; or a few fixed sizes, such as 4 KiB, 64 KiB and 2 MiB.
- **Blocks:** C16.
- **From:** [0058](../decisions/0058-jobs-and-budgets.md), rule 4. **Backlog:** D150.

### K05. Which pieces a fault uses first

Does the kernel take a fault's memory from a job's reserved pieces before its borrowed ones?

- **Options:** reserved first, so a job borrows only when its reservation is full; borrowed first, so reserved memory stays free for explicit calls; or the fullest piece first, to keep pieces emptiable.
- **Blocks:** C16.
- **From:** [0058](../decisions/0058-jobs-and-budgets.md), rule 6; the third review. **Backlog:** D150.

### K06. Untyped capabilities and fault memory

When a job's manager passes an untyped capability for one of the job's pieces to a process, may the kernel still take fault memory from that piece? What does the process see when the memory server takes an empty piece back?

- **Options:** pieces are either kept for faults or handed out, never both; pieces are shared, and the kernel takes fault memory from any piece's free space; taking a piece back revokes the process's capability to it, and the runtime treats that as "no memory".
- **Blocks:** C16, C17.
- **From:** [0058](../decisions/0058-jobs-and-budgets.md), rules 1 and 3; the project owner's decision that a process holds its job's memory, not its job's capability. **Backlog:** D150.

### K07. Where binding copies live, and object sizes

Which slots do the thread, the wait set and the interrupt handler carry for the capability copies their bindings hold ([Kernel bindings that hold capabilities](#kernel-bindings-that-hold-capabilities)), and so what is each object's size in bytes?

- **Options:** seL4's thread layout, with the fault and timeout endpoints as slots of the thread, plus a slot for the bound eventcount; one slot per wait-set entry; one slot in the handler. Queue links ([Ordered kernel queues](#ordered-kernel-queues)) add to the same sizes.
- **Settled in part with C11:** the mechanism, a derived copy in a slot of the binding object with slot 0 of its slot array kept as the park slot, and the address space's record; see [Kernel bindings that hold capabilities](#kernel-bindings-that-hold-capabilities). The thread's, wait set's and handler's slots and sizes stay open.
- **Blocks:** C12, C13b, C14.
- **From:** [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 4; the third review. **Backlog:** D151.

### K08. Removing a binding in use

What happens when a wait-set entry is removed, or its copy revoked, during a wait on the set? And when a passive server's timeout endpoint is removed while it runs on a donated context ([0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 3)?

- **Options:** for a wait set, the wait continues on the other entries, or returns with an empty mask. For a timeout endpoint, it can't be removed while the thread holds a donated context; or its removal is allowed, and the server's next withdrawal suspends it.
- **Blocks:** C12, C14.
- **From:** [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 4; [0053](../decisions/0053-eventcounts.md), rule 4. **Backlog:** D151.

### K09. The capability-table copy under change

The library copies a capability space slot by slot, so the source can change during the copy. Is the copy defined only against a stopped process, as `fork` uses it, or must it tolerate changes? Is a batch call needed?

- **Options:** define it for a stopped source only; or tolerate concurrent change. A batch call in the private ABI waits for measurements.
- C11 needed no answer: the copy is built on Copy, which C11 provides.
- **Blocks:** C17.
- **From:** [Copying a capability table](#copying-a-capability-table); [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 7; [0059](../decisions/0059-the-kernel-interface-library.md), rule 1; the third review. **Backlog:** D159.

### K10. What fork copies

Does the capability-table copy skip or refuse capabilities that can't be derived, and how do binding credentials stay with the parent ([0025](../decisions/0025-twelve-factor-app-contract.md), rule 5; [0012](../decisions/0012-posix-compatibility-layer.md), rule 4)?

- **Options:** skip; or refuse. Either fork leaves credential capabilities behind unless they are passed, or 0025 rule 5 gives way.
- **Blocks:** the POSIX process server, not C10 to C16.
- **From:** [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 7; the third review. **Backlog:** D95, which already asks it. No new entry.

### K11. Telling whether two capabilities name the same object

A server that presents kernel objects it didn't make may receive a second capability to an object it already named. Does the kernel offer a way to tell, so that a server doesn't mint two IDs for one object?

- **Settled with C11:** no such operation, as in seL4; see [Kernel objects and IDs](#kernel-objects-and-ids).
- **From:** [Kernel objects and IDs](#kernel-objects-and-ids); [0050](../decisions/0050-ids-for-kernel-objects.md), Consequences. **Backlog:** D152.

### K12. Naming objects made after the entropy gate but before storage

Objects made after the entropy gate but before storage runs can't take a sequence number from a durably recorded block ([0001](../decisions/0001-object-identifiers.md), rule 4). How are they named? This is a decision, not mechanism.

- **Options:** none named.
- **Blocks:** C19 and naming in M3, not the prototype.
- **From:** [0050](../decisions/0050-ids-for-kernel-objects.md), rule 6. **Backlog:** D161.

### K13. The share check

How does the kernel check a scheduling context against its job's share of a core when the context is configured ([0058](../decisions/0058-jobs-and-budgets.md), rule 8)?

- **Options:** the sum of budget over period for the job's contexts on that core must not pass the job's own; a fixed set of share slots per job; integer arithmetic in microseconds, or in counts.
- **Blocks:** C12, C16.
- **From:** [Scheduling contexts and budgets](#scheduling-contexts-and-budgets); [0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 1. **Backlog:** D153.

### K14. Who configures scheduling contexts

The root server holds the scheduling-control capabilities, and a process holds untyped memory of its job, not the job's capability. Can a runtime configure contexts for its own threads, within its job's share, without a scheduling-control capability, or must it ask the process manager?

- **Options:** the process manager holds copies of scheduling control and configures every context; or a per-job scheduling-control capability, which the kernel checks against the job's share.
- **Blocks:** C12, C16, C17.
- **From:** [Scheduling contexts and budgets](#scheduling-contexts-and-budgets); [0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 1; [0058](../decisions/0058-jobs-and-budgets.md), rule 9. **Backlog:** D153.

### K15. The size of a scheduling context

How many refills does a context hold, and so what is its size?

- **Options:** as in seL4, sized by the extra refills chosen when it is configured; or a fixed refill count.
- **Blocks:** C12.
- **From:** [Scheduling contexts and budgets](#scheduling-contexts-and-budgets). **Backlog:** D151.

### K16. Priority bands

What is the numeric range of each default band ([0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 2)? How does whoever starts a shared server learn the highest priority among its callers, so that the server's priority is at least as high?

- **Options:** fixed ranges in this note; or ranges set in the boot manifest.
- **Blocks:** C12, C19.
- **From:** [Priorities and bands](#priorities-and-bands). **Backlog:** D153.

### K17. Stranded servers' waits

Along a chain of calls C to S1 to S2, S1 may itself be waiting when C's context is taken back: on its call to S2, on a page, on a memory request or on an eventcount. A thread blocked in one wait can't also be sending a fault. What happens to each stranded server's wait, what does the server see when its handler resumes it, and in what order do the context-withdrawn faults go out?

- **Options:** before sending the faults, the kernel cancels each stranded server's own wait, working down the chain: its call to the next server ends as a canceled call, a page wait detaches as in [Waiting for a page](#waiting-for-a-page), and a memory request is withdrawn; the interrupted operation returns "canceled" when the handler resumes the server. Or the waits stay attached, and the handler decides.
- **Blocks:** C12, C14, C15.
- **From:** [Passive servers and taking a context back](#passive-servers-and-taking-a-context-back); [0054](../decisions/0054-ipc-endpoints.md), rule 6; [0056](../decisions/0056-faults-and-page-fetch-deadlines.md), rule 3; the third review. **Backlog:** D154.

### K18. Which core keeps a deadline

A wait's deadline is kept in one core's deadline queue. For a thread with a scheduling context, the natural core is that context's. A passive server waiting to receive has none. Which core keeps its deadline?

- **Options:** the core of the thread's scheduling context, else the core it last ran on; the core of the endpoint's last caller; or one node-wide queue under the lock.
- **Blocks:** C12.
- **From:** [The timer and deadlines](#the-timer-and-deadlines); [0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 5. **Backlog:** D154.

### K19. Deadline edge cases

What does a blocking call do with a deadline that has already passed when it starts? Does the library round a nanosecond conversion up, so that a deadline is never early? How does the kernel interface encode "no deadline"?

- **Options:** return "timed out" at once only if the call would block, or always; round up; a reserved value, or a flag.
- **Blocks:** C12, C17.
- **From:** [The timer and deadlines](#the-timer-and-deadlines); [0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 5. **Backlog:** D154.

### K20. Deadlines and replies of a suspended thread

While a thread is suspended ([Suspending a thread](#suspending-a-thread)), does its fetch timeout or its call's deadline keep running, and if one passes, when does the thread see the result? How is a reply held for a suspended caller?

- **Options:** deadlines keep running, and their result is held until the thread resumes; or deadlines pause while it is suspended.
- **Blocks:** C12, C14, C15, C70.
- **From:** [0061](../decisions/0061-debugging.md), rule 3; the third review. **Backlog:** D154.

### K21. Firmware without PSCI

What does the kernel do when asked to reboot or power off and the firmware has no PSCI? [0052](../decisions/0052-smp-bring-up-and-the-kernel-lock.md), rule 1 already rules out spin tables for starting cores.

- **Options:** halt with a log record; or rely on a watchdog driver.
- **Blocks:** C12.
- **From:** [Starting secondary cores](#starting-secondary-cores). **Backlog:** D153.

### K22. Preemption granularity

How many units of work does the kernel do between checks for a pending interrupt?

- **Settled with C11:** seL4's default, 100 units between checks; see [The kernel lock and long operations](#the-kernel-lock-and-long-operations).
- **From:** [The kernel lock and long operations](#the-kernel-lock-and-long-operations); [0052](../decisions/0052-smp-bring-up-and-the-kernel-lock.md), rule 2. **Backlog:** D155.

### K23. How each long operation keeps its progress

For each long operation marked "Open" in [The kernel lock and long operations](#the-kernel-lock-and-long-operations), where is its progress recorded, and how does a restart resume it? Which memory operations need preemption points at all?

- **Options:** to be settled with the prototype, operation by operation. Listings are [K41](#k41-listing-in-pages).
- **Settled in part with C11:** revoke and delete keep their progress in the tree and its zombies, and revoke keeps no state of its own ([Derivation and revocation](#derivation-and-revocation)), and clearing untyped memory keeps it in the untyped capability's watermark, as seL4's `resetUntypedCap` does ([Untyped memory and kernel records](#untyped-memory-and-kernel-records)). The other operations stay open.
- **Blocks:** C12, C14, C15, C16.
- **From:** [0052](../decisions/0052-smp-bring-up-and-the-kernel-lock.md), rule 2; [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rules 4 and 8; [0058](../decisions/0058-jobs-and-budgets.md), rules 9 and 10; the third review; the project owner's decision to add decommit. **Backlog:** D155.

### K24. Batches of interrupt work

Work started from an interrupt runs in bounded batches: interrupt advances, deadline expiries at one tick, and a take-back after a deadline passes. How large is one batch, and where does each core keep its list of pending work, needing no memory beyond the objects themselves?

- **Options:** a fixed batch size, or a time-bounded batch, tuned per platform; an intrusive list per core, linked through the objects with pending work.
- **Blocks:** C12, C13b, C14.
- **From:** [The kernel lock and long operations](#the-kernel-lock-and-long-operations); [0052](../decisions/0052-smp-bring-up-and-the-kernel-lock.md), rule 2; [0053](../decisions/0053-eventcounts.md), rules 2 and 8; the third review. **Backlog:** D155.

### K25. Ordered-queue structures

Which structures meet [0052](../decisions/0052-smp-bring-up-and-the-kernel-lock.md), rule 2's bound for the endpoint, release, deadline, eventcount-target and word-waiter queues ([Ordered kernel queues](#ordered-kernel-queues))?

- **Options:** for endpoint queues, an intrusive balanced tree keyed by priority and arrival, or a list for each priority with a bitmap, which costs a 256-entry table in every endpoint; for the release and deadline queues, an intrusive balanced tree, a pairing heap or a timer wheel; for eventcount waiters, an intrusive tree keyed by target, linked through the thread and the wait-set entries; for word waiters, a tree in each memory object keyed by offset. Each choice sets part of a thread's, an endpoint's, a wait set's and a memory object's size.
- **Blocks:** C12, C14, C15.
- **From:** [0053](../decisions/0053-eventcounts.md), rule 2; [0054](../decisions/0054-ipc-endpoints.md), rule 1; the third review. **Backlog:** D155.

### K26. SGI numbers

Which software-generated interrupts does the kernel use for rescheduling, remote calls and the panic stop?

- **Options:** follow seL4's assignment; or any fixed set from the non-secure range.
- **Blocks:** C13a.
- **From:** [Cross-core signals and TLB maintenance](#cross-core-signals-and-tlb-maintenance); [0052](../decisions/0052-smp-bring-up-and-the-kernel-lock.md), rule 4. **Backlog:** D153.

### K27. Stopping a core that has interrupts masked

Should the panic stop use GICv3 interrupt priorities as a pseudo-NMI, so that it reaches a core running in the kernel before its next preemption point? A GICv2 has no such means.

- **Options:** a pseudo-NMI on GICv3, and nothing on GICv2; or rely on preemption points and exits only.
- **Blocks:** C13a.
- **From:** [Cross-core signals and TLB maintenance](#cross-core-signals-and-tlb-maintenance); [0052](../decisions/0052-smp-bring-up-and-the-kernel-lock.md), rule 4. **Backlog:** D153.

### K28. Message and buffer layout

What is the message info word's exact layout, and what is the IPC buffer's layout with three receive-slot entries? Does the library write the four register words into the first 32 octets of the buffer's message area, or keep a separate 32-octet header area beside a view of the buffer? All are part of the private ABI ([0059](../decisions/0059-the-kernel-interface-library.md), rule 2). Already decided: four words travel in registers, the length is in octets from 0 to 960, and the decoder sees one octet string ([0064](../decisions/0064-the-call-header-and-wire-encoding.md), rule 2; [Endpoint operations and messages](#endpoint-operations-and-messages)).

- **Options:** seL4's AArch64 layout, with its message info word giving octets, and its buffer extended to three receive slots; the register words in the buffer, or beside it.
- **Blocks:** C14, C17.
- **From:** [Endpoint operations and messages](#endpoint-operations-and-messages); [IPC buffers](#ipc-buffers); [0054](../decisions/0054-ipc-endpoints.md), rules 3 and 7; [0064](../decisions/0064-the-call-header-and-wire-encoding.md), rule 2. **Backlog:** D156.

### K29. IPC buffer registration and capabilities

Registration names an address, so no capability to the buffer's memory object is presented. Should the thread hold a copy of one, as seL4's `tcbBuffer` holds a frame capability?

- **Options:** registration also presents the memory object's capability, the thread keeps a copy, and revoking it unregisters the buffer; or the thread holds none, and only destroying the object or ending its job unregisters it.
- **Blocks:** C12, C14.
- **From:** [IPC buffers](#ipc-buffers); [0054](../decisions/0054-ipc-endpoints.md), rule 3; [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 4. **Backlog:** D151.

### K30. Results and error names

What does a waiter return when its eventcount, its word's memory object or its endpoint is destroyed? What are the names of the errors "not resident", "not RAM", "misaligned", "no mapping", "count at maximum", "no memory" and "no caller"?

- **Options:** one "object destroyed" result for every wait; or seL4's restart, which makes the thread find a missing capability.
- **Blocks:** C14, C15.
- **From:** [0053](../decisions/0053-eventcounts.md), rules 3 and 6; [0054](../decisions/0054-ipc-endpoints.md), rule 6; the third review. **Backlog:** D156.

### K31. Restarting an advance

A system-call advance that stops at a preemption point has already changed the count, so a restart that re-executes the call would add one twice. How does a restart avoid that?

- **Options:** the call returns once the count has changed, and the remaining wakes continue as an interrupt advance's batches do; or the eventcount records the pending wake, and a restarted call finishes it without adding again.
- **Blocks:** C14.
- **From:** [Eventcount operations](#eventcount-operations); [0053](../decisions/0053-eventcounts.md), rule 2. **Backlog:** D155.

### K32. Rights on wait sets

Which rights on a wait set allow adding and removing entries, and which allow waiting?

- **Options:** write to change entries and read to wait; or write for both.
- C11 needed no answer: it makes no wait sets.
- **Blocks:** C14.
- **From:** [Rights by object type](#rights-by-object-type); [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 2; [0053](../decisions/0053-eventcounts.md), rule 4. **Backlog:** D152.

### K33. Wait-set size

Does every wait set hold 60 entries, or can it be made smaller, and what does each size cost in bytes?

- **Options:** one size of 60 entries; or a number of entries up to 60, chosen when the wait set is made.
- **Blocks:** C14, C16.
- **From:** [Wait sets](#wait-sets); [0053](../decisions/0053-eventcounts.md), rule 4. **Backlog:** D151.

### K34. Where word-wait queues live

The kernel has no heap. Where do the queues keyed by memory object and offset live?

- **Options:** in the memory object's page tracking, charged to its job; or a fixed-size hash table the kernel takes at boot, with the queue links in each waiting thread.
- **Blocks:** C15.
- **From:** [Word waits](#word-waits); [0053](../decisions/0053-eventcounts.md), rule 6. **Backlog:** D155.

### K35. Naming a device for MSI

How does an MSI request name the device, and is holding the interrupt control capability enough to claim any device's MSIs?

- **Options:** by its ITS device ID; by its PCIe requester ID; or by a capability to the device's PCIe function.
- **Blocks:** C13b, C20.
- **From:** [MSI and the GICv3 ITS](#msi-and-the-gicv3-its); [0055](../decisions/0055-interrupt-objects.md), rule 4. **Backlog:** D157.

### K36. Interrupt targets

Which core does an SPI or an LPI target when its handler is made, and can a holder move it later?

- **Options:** name the core when the handler is made, as seL4's `GetTriggerCore` does; and allow retargeting through the handler, or not.
- **Blocks:** C13b.
- **From:** [Interrupt handlers](#interrupt-handlers); [0055](../decisions/0055-interrupt-objects.md), rules 1 and 4. **Backlog:** D157.

### K37. The number of LPIs

How does the kernel choose the number of LPIs at boot?

- **Options:** a fixed default; a kernel argument ([0041](../decisions/0041-boot-abi.md), rule 5); or a number derived from the PCIe devices the device tree or ACPI describes. Each is bounded by `GICD_TYPER.IDbits`.
- **Blocks:** C13b.
- **From:** [MSI and the GICv3 ITS](#msi-and-the-gicv3-its); [0055](../decisions/0055-interrupt-objects.md), rule 4. **Backlog:** D157.

### K38. ITS table sizes

What are the sizes of the command queue and of the device and collection tables, and is the device table flat or two-level (`GITS_BASER<n>.Indirect`)?

- **Options:** flat, or two-level. A collection table may be unneeded where `GITS_TYPER.HCC` covers every core.
- **Blocks:** C13b.
- **From:** [MSI and the GICv3 ITS](#msi-and-the-gicv3-its); [0055](../decisions/0055-interrupt-objects.md), rule 4. **Backlog:** D157.

### K39. Waiting for the ITS

The kernel polls `GITS_CREADR` under the lock. What bounds that wait, and what does the kernel do if the ITS stalls or reports a command error?

- **Options:** panic; log and fail the operation; or disable MSIs.
- **Blocks:** C13b.
- **From:** [MSI and the GICv3 ITS](#msi-and-the-gicv3-its); [0055](../decisions/0055-interrupt-objects.md), rule 4. **Backlog:** D157.

### K40. A revocation that meets an ITS table

A revocation that reaches the ITS's command queue, device table or collection table must leave it in place ([0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 4; [0055](../decisions/0055-interrupt-objects.md), rule 4). How does it report that?

- **Options:** the revocation deletes everything else, leaves those slots as children, and returns a result that names them; it refuses before it deletes anything; the memory that holds them can't be revoked at all once the ITS is enabled; or the kernel takes them over from the root job when it enables the ITS.
- C11 needed no answer: an object's destruction step, which C11's deletion runs, is where C13b adds the refusal ([Derivation and revocation](#derivation-and-revocation)).
- **Blocks:** C13b.
- **From:** [Derivation and revocation](#derivation-and-revocation); [MSI and the GICv3 ITS](#msi-and-the-gicv3-its); the third review. **Backlog:** D157.

### K41. Listing in pages

Listing an address space's mappings, or a job's threads, may yield more than one message holds: 120 words and three capabilities. How are long lists returned, and how is listing bounded?

- **Options:** each call takes a cursor (an address for mappings, an opaque position for threads) and returns what fits in one message, with the next cursor; a capability is fetched for one listed entry per call, into the receiver's slots; results may change between calls unless the process or job is stopped. Or a long operation with preemption points that fills a memory object the caller supplies.
- **Blocks:** C15, C16.
- **From:** [Memory objects and mappings](#memory-objects-and-mappings); [Job capabilities](#job-capabilities); [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 3; [0058](../decisions/0058-jobs-and-budgets.md), rule 9; the third review. **Backlog:** D155.

### K42. Capabilities yielded by listing

A memory-object capability got by listing mappings with the write right derives from the mapping's own copy of its memory-object capability ([0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 3), so revoking the object's capability, or the mapping's copy, reaches it, and Unmap, which revokes the mapping's copy before it deletes it, does too. It doesn't derive from the address-space capability used to list, so revoking a debugger's copy of that doesn't reach it ([0061](../decisions/0061-debugging.md), rule 4). Should it?

- **Options:** record each listed capability as a child of the address-space capability used to list, instead of the mapping's copy, which departs from seL4's tree, where children are copies of the same object or made from untyped memory, and changes [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 3; or keep the gap, and let policy allow writing memory only where the lasting access is acceptable. 0061 rule 4 says a record closes the gap, so the first option needs one.
- C11 needed no answer. In C11's tree a copy of a mapping's copy is that copy's child, so revoking the mapping's copy, or anything it derives from, reaches it, as [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 3 says. Deleting the mapping's copy alone doesn't: the copy stays under the object's capability. So C11's Unmap revokes each binding before it deletes it ([Derivation and revocation](#derivation-and-revocation)). Whether destroying an address space should also revoke its mappings' copies, rather than only delete them, is C15's to settle with the mapping records.
- **Blocks:** C15, C70.
- **From:** [Memory objects and mappings](#memory-objects-and-mappings); [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rules 2 and 4. **Backlog:** D152.

### K43. How a pager fills a frame

How does the pager fill the pending frame, without needing memory per page and without a writable mapping outlasting Supply?

- **Options:** a copy-in call, in which the kernel copies from a resident page of the pager's own into the pending frame; or the pager maps pending frames into a window it set up and paid for in advance, allowed even for a pending page of an immutable object, and Supply or Fail removes that mapping.
- **Blocks:** C15.
- **From:** [The pager protocol](#the-pager-protocol); [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 6; the third review. **Backlog:** D158.

### K44. Priority of a page request

A page request is queued on the pager's endpoint at its carrier's priority. A higher-priority thread that joins the same page waits behind the pager's other requests. Should the request be requeued?

- **Options:** when a higher-priority thread joins a request the pager hasn't received, it becomes the carrier, and the request is requeued at its priority; or pagers serve requests in their own order, and the pager's priority band bounds the inversion ([0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 2).
- **Blocks:** C15.
- **From:** [The pager protocol](#the-pager-protocol); [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 6; [0054](../decisions/0054-ipc-endpoints.md), rule 1; the third review. **Backlog:** D158.

### K45. Evicting or decommitting a pending page

What do Evict and decommit do to a pending page, and to the threads waiting on it?

- **Options:** free the frame, clear the mark, and resume the waiting threads to fault again, which sends a new request; or skip pending pages.
- **Blocks:** C15.
- **From:** [The pager protocol](#the-pager-protocol); [Decommit](#decommit); [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 8; the third review. **Backlog:** D158.

### K46. A read-through clone whose original is destroyed

A clone of a pager-backed object may belong to any job. When the original is destroyed, by its pager or by the end of its job, what happens to the clone?

- **Options:** the clone is destroyed too, and its mappings removed; or the clone keeps the pages it has written, and an access to any other page gets a page-unavailable fault.
- **Blocks:** C15.
- **From:** [Copy-on-write clones](#copy-on-write-clones); [Ending a job](#ending-a-job); [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 4; [0058](../decisions/0058-jobs-and-budgets.md), rule 10; the project owner's decision on POSIX private mappings. **Backlog:** D158.

### K47. The structure of shared pages

How are pages shared between snapshot clones represented, and how is the length of a chain of clones bounded?

- **Options:** a hidden node apart from both sides, as Fuchsia's snapshot clones keep; or chains of shadow objects, as Mach's.
- **Blocks:** C15.
- **From:** [Copy-on-write clones](#copy-on-write-clones); [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 4. **Backlog:** D158.

### K48. Telling a pager which pages are least recently used

When the memory server can't lend to a job, pagers evict the job's least recently used clean pages ([0058](../decisions/0058-jobs-and-budgets.md), rule 6). How does a pager know which those are?

- **Options:** Query reports and clears the hardware access flag of each page; the kernel keeps an LRU order per object; or the pager approximates by the order of its own page requests.
- **Blocks:** C15, C16.
- **From:** [The pager protocol](#the-pager-protocol); the project owner's decision on readers and cache limits. **Backlog:** D158.

### K49. The syndrome in a fault message

Does a fault message carry the raw `ESR_EL1` and `FAR_EL1` values, or decoded fields?

- **Options:** the raw values, as seL4's VM faults do; decoded fields only; or both.
- **Blocks:** C15.
- **From:** [Fault delivery](#fault-delivery); [0056](../decisions/0056-faults-and-page-fetch-deadlines.md), rule 3. **Backlog:** D156.

### K50. A fault in flight when its endpoint is unset

If the capability that set a thread's fault endpoint is revoked while the thread's fault is queued or delivered, what happens to the thread?

- **Options:** the fault is withdrawn, the thread is suspended and the fault logged, as for a thread with no fault endpoint; or a delivered fault stands until it is replied to.
- C11 needed no answer: a binding's state is its slot, and its unbind step leaves room for either option ([Kernel bindings that hold capabilities](#kernel-bindings-that-hold-capabilities)).
- **Blocks:** C12, C15.
- **From:** [Fault delivery](#fault-delivery); [0056](../decisions/0056-faults-and-page-fetch-deadlines.md), rule 1; the third review. **Backlog:** D151.

### K51. Memory waits on the fault path

The records decide that the mapping's fetch timeout bounds a fault's whole wait, the wait for memory included ([0056](../decisions/0056-faults-and-page-fetch-deadlines.md), rule 4), and that a canceled memory wait takes a memory fault at once ([0058](../decisions/0058-jobs-and-budgets.md), rule 6). Still open: how a memory request is withdrawn when its thread times out or is canceled; whether a memory request carried by one thread passes to another, as a page request does; and whether the fetch timeout is armed afresh when a thread repeats its access after Supply and then waits for memory for its own mapping.

- **Options:** withdraw the request if the memory server hasn't received it, else let it complete; or pass it on like a page request.
- **Blocks:** C14, C15, C16.
- **From:** [Waiting for a page](#waiting-for-a-page); [Memory requests and reclaim](#memory-requests-and-reclaim); the third review. **Backlog:** D154.

### K52. The fetch timeout's representation

What unit and range does a fetch timeout have, and is zero allowed?

- **Options:** a duration in the virtual count's units ([0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 5), with a maximum this note sets; zero meaning "fail at once unless resident".
- **Blocks:** C15.
- **From:** [Waiting for a page](#waiting-for-a-page); [0056](../decisions/0056-faults-and-page-fetch-deadlines.md), rule 4. **Backlog:** D154.

### K53. Rights on a job's capability

Which rights does each job operation need, and how is the memory server's capability limited to giving and taking back memory?

- **Options:** read to list, write to stop, resume and end, and a separate derived capability for memory; or a separate memory-account object per job, which the memory server holds instead of a job capability.
- **Blocks:** C16.
- **From:** [Job capabilities](#job-capabilities); [0058](../decisions/0058-jobs-and-budgets.md), rule 9; the third review, as resolved by the project owner's decision that processes don't hold their job's capability. **Backlog:** D152.

### K54. Reclaim at a limit

How does the memory server learn that a job, or which ancestor, is at its limit, and how does it find the pagers of the objects in that job? Its answers to a memory request (lend, free, refuse) are operations on the job's capability, not a reply; only a runtime's `aspis.memory/1` call gets a reply ([0058](../decisions/0058-jobs-and-budgets.md), rule 6).

- **Options:** the memory request names the job at its limit; pagers register the jobs they keep for their objects with the memory server; or a cache job's memory endpoint is its own pager's, which evicts directly.
- **Blocks:** C16.
- **From:** [Memory requests and reclaim](#memory-requests-and-reclaim); [0058](../decisions/0058-jobs-and-budgets.md), rule 6; the project owner's decision on readers and cache limits. **Backlog:** D158.

### K55. Reclaim under an ancestor's limit

When an ancestor's limit is reached, the memory server reclaims in that ancestor's subtree and lends within the limit. Which jobs' pages does it evict first?

- **Options:** the faulting job's own pages first, then its siblings' borrowed pages; or least recently used across the subtree.
- **Blocks:** C16.
- **From:** [Memory requests and reclaim](#memory-requests-and-reclaim); [0058](../decisions/0058-jobs-and-budgets.md), rule 6. **Backlog:** D158.

### K56. Targeting borrowed memory

Reclaim evicts pages held in borrowed memory, but user space can't tell which frames sit in borrowed pieces. How is that targeted?

- **Options:** Query also reports which resident pages sit in borrowed pieces; Evict takes a "borrowed only" flag; or the memory server asks a pager for a number of pages, and the kernel picks them from borrowed pieces.
- **Blocks:** C16.
- **From:** [Memory requests and reclaim](#memory-requests-and-reclaim); [0058](../decisions/0058-jobs-and-budgets.md), rule 7; the third review. **Backlog:** D158.

### K57. Dirty pages at a limit

When the memory server can't lend to a job, does it also have the job's pagers write back and evict dirty pages before it refuses?

- **Options:** clean pages only, so the fault never waits for a write-back; or dirty pages too, under the memory server's deadline.
- **Blocks:** C16.
- **From:** [Memory requests and reclaim](#memory-requests-and-reclaim); [0058](../decisions/0058-jobs-and-budgets.md), rule 6. **Backlog:** D158.

### K58. Whether the call check also checks the call's place

Besides checking that a system call comes from the library's code range, does the kernel check that each call comes from the place in the library that makes it, as Fuchsia's kernel does for its vDSO?

- **Options:** the range check only; or also a check of each call's place, from a table the build generates.
- **Blocks:** C17.
- **From:** [The kernel interface library](#the-kernel-interface-library); [0059](../decisions/0059-the-kernel-interface-library.md), rule 4. **Backlog:** D156.

### K59. The entry table's details

What are the width of each field, the table's own version, and how a runtime learns that an interface or version is missing? Do entries report the highest minor version of each major, so that a runtime can check the minimum minor it needs?

- **Options:** none named.
- **Blocks:** C17.
- **From:** [The kernel interface library](#the-kernel-interface-library); [0059](../decisions/0059-the-kernel-interface-library.md), rule 5. **Backlog:** D156.

### K60. Where the library is mapped

Does the address space's creator choose the library's address, or is it fixed in every address space?

- **Options:** the creator chooses any page-aligned address; or a fixed address. Whether its placement is randomized is C78's (D145).
- **Blocks:** C17, C78.
- **From:** [The kernel interface library](#the-kernel-interface-library); [0059](../decisions/0059-the-kernel-interface-library.md), rule 3. **Backlog:** D156.

### K61. Support period of the library's major versions

How long is each major version of the kernel's interfaces supported? This is a decision, not mechanism.

- **Options:** set with the API policy ([0014](../decisions/0014-versioned-object-apis.md), rule 7).
- **Blocks:** C17's release policy, not the prototype.
- **From:** [0059](../decisions/0059-the-kernel-interface-library.md), rule 6. **Backlog:** D115, which already asks it, the kernel interface library included. No new entry.

### K62. How a spawner knows the job

How does the spawner check that the untyped memory given to spawn belongs to a job it manages, and how does a caller get a job to spawn a child into?

- **Options:** a kernel operation on a job's capability that says whether an untyped capability is that job's; the caller names the job by a handle the process manager issued, beside the untyped memory; or the process manager makes a child job on request and returns its untyped memory.
- **Blocks:** C16, C17.
- **From:** [Native spawn and program loading](#native-spawn-and-program-loading); [0060](../decisions/0060-processes-native-spawn-and-elf.md), rule 2. **Backlog:** D159.

### K63. Rights of the main-thread capability

With the write right, spawn's caller could suspend the child and write its registers without a Cedar decision ([0061](../decisions/0061-debugging.md), rule 4). Which rights does the capability spawn returns carry?

- **Options:** no write right; no thread capability, and instead an eventcount advanced when the process ends; or the write right, accepting that a parent may debug its children.
- **Blocks:** C17, C70.
- **From:** [Native spawn and program loading](#native-spawn-and-program-loading); [0060](../decisions/0060-processes-native-spawn-and-elf.md), rule 2. **Backlog:** D152.

### K64. What a runtime needs to make its own threads

Which capabilities does a process get beyond those named in spawn: untyped memory of its job and how much, its own capability space and address space, and a scheduling context or a way to get one? Who provides the main thread's scheduling context?

- **Options:** spawn gives the process its address space and capability space with the write right, a share of the untyped memory given to spawn, and a scheduling context configured within the job's share; or the process asks the process manager for each thread. Depends on [K14](#k14-who-configures-scheduling-contexts).
- **Blocks:** C17.
- **From:** [Native spawn and program loading](#native-spawn-and-program-loading); [0060](../decisions/0060-processes-native-spawn-and-elf.md), rules 4 and 7. **Backlog:** D159.

### K65. The startup block's layout

What are the startup block's field order and widths, its byte order, its version scheme, and where it is mapped? What are the main stack's size and guard, and the thread-pointer area's layout for `PT_TLS` (AArch64 uses TLS variant 1)?

- **Options:** little-endian like the boot information, since it is an in-memory structure ([0041](../decisions/0041-boot-abi.md), rule 2); tagged records like the boot information; or a fixed header.
- **Blocks:** C17.
- **From:** [The startup block](#the-startup-block); [0060](../decisions/0060-processes-native-spawn-and-elf.md), rule 4. **Backlog:** D159.

### K66. The tail of a writable segment

When a writable segment's file data ends partway through a page, the rest of that page must read as zero, but the clone shows the executable's bytes there. How is it zeroed? What segment alignment does the spawner require, given 4 KiB pages ([0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 3) and the initial image's 64 KiB alignment ([0037](../decisions/0037-initial-image-format-and-contents.md), rule 1)?

- **Options:** the spawner writes zeros into the clone's page, which gives it a frame of its own; or the build pads writable segments so their file data ends on a page boundary.
- **Blocks:** C17.
- **From:** [Native spawn and program loading](#native-spawn-and-program-loading); [0060](../decisions/0060-processes-native-spawn-and-elf.md), rule 3. **Backlog:** D159.

### K67. A process named after it starts

A process spawned before it can be named has no ID in its startup block ([0050](../decisions/0050-ids-for-kernel-objects.md), rule 6). How does it learn its ID once it has one?

- **Options:** it asks the process manager; or the manager writes it into a page the process can read, and advances an eventcount.
- **Blocks:** C17.
- **From:** [Kernel objects and IDs](#kernel-objects-and-ids); [0060](../decisions/0060-processes-native-spawn-and-elf.md), rule 4. **Backlog:** D159.

### K68. The symbol table's format and the build ID's hash

Which hash names the build? Are names stored mangled or demangled, and with what length limit? Are local symbols included? What are the stub section's name and the boot-information record's type number?

- **Options:** SHA-512, as the initial image's digest uses ([0041](../decisions/0041-boot-abi.md), rule 3); SHA-256; or BLAKE3. Mangled or demangled names.
- **Blocks:** C70.
- **From:** [The panic symbol table](#the-panic-symbol-table); [0061](../decisions/0061-debugging.md), rule 2. **Backlog:** D160.

### K69. A debugger read of a page that isn't resident

The kernel fails such a read with "not resident", and the caller is meant to touch the page and retry ([0048](../decisions/0048-kernel-memory-and-address-spaces.md), rule 5). A debugger can't touch a page in the target's address space.

- **Options:** the manager maps the object itself, using the memory-object capability that listing with write yields, and touches the page; a kernel operation that sends the page request for an address in another address space, and lets the caller wait with a deadline; or debuggers and crash dumps show such pages as absent.
- **Blocks:** C70.
- **From:** [Debugger access to threads and memory](#debugger-access-to-threads-and-memory); [0061](../decisions/0061-debugging.md), rule 3. **Backlog:** D160.

### K70. Hardware debug state

How many hardware breakpoints and watchpoints does a thread get, when the processor's count in `ID_AA64DFR0_EL1` varies? Are debug registers switched eagerly or lazily? How does a single step that enters the kernel resume correctly?

- **Options:** none named yet.
- **Blocks:** C12, C70.
- **From:** [Debugger access to threads and memory](#debugger-access-to-threads-and-memory); [0061](../decisions/0061-debugging.md), rule 3. **Backlog:** D160.

### K71. The private clone's extent

Does the breakpoint clone cover the whole code mapping, or only the pages that hold breakpoints? How is a code mapping made of 2 MiB blocks split?

- **Options:** the whole mapping; or only the pages touched.
- **Blocks:** C70.
- **From:** [Software breakpoints in a private clone](#software-breakpoints-in-a-private-clone); [0061](../decisions/0061-debugging.md), rule 4. **Backlog:** D160.

### K72. Crash dump contents

Which notes does a dump carry (`NT_PRSTATUS`, `NT_FPREGSET`, `NT_ARM_TLS` and others)? Are pages that aren't resident fetched or left out? How large may a dump be?

- **Options:** none named yet beyond those notes.
- **Blocks:** C70, in M4.
- **From:** [User crash dumps](#user-crash-dumps); [0061](../decisions/0061-debugging.md), rule 5. **Backlog:** D160.

### K73. Dynamic linking

Does ASPIS have shared libraries? If so, where does the dynamic linker live, and how does an executable name it? This is a decision, not mechanism.

- **Options:** a user-space linker in the process, named by the executable's `PT_INTERP` header, as on Linux and Fuchsia.
- **Blocks:** C47 (M6), not the prototype.
- **From:** [Native spawn and program loading](#native-spawn-and-program-loading); [0060](../decisions/0060-processes-native-spawn-and-elf.md), rule 6. **Backlog:** D162.

### K74. Keeping a Fail's error key

Fail gives an error key of 36 octets for a range, and every thread waiting on a page in it gets a page-unavailable fault with that key. Where does the kernel keep the key until each of those faults is delivered? And by which call does a handler fetch the full error from the pager?

- **Options:** in the pending-page record, charged to the object's job, as the [call-language specification](call-language.md#l43-keeping-a-fails-error-key) suggests. The full error comes by an ordinary call on the pager, which C15 and C17 define.
- **Blocks:** C15, C17.
- **From:** [The pager protocol](#the-pager-protocol); [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 7; [0065](../decisions/0065-typed-errors-and-minor-versions-on-the-wire.md), rule 1. **Backlog:** D158.

### K75. The identify operation

Is identify, which reads a capability's kind and rights, a published method of the capability-space interface, `aspis.kernel.cspace`, or internal to `aspis-rt`?

- **Options:** a published method of `aspis.kernel.cspace`, which the [call-language specification](call-language.md#l41-the-identify-operation) assumes meanwhile; or an operation internal to `aspis-rt`, which the network server and generated stubs both use.
- C11 needed no answer: the kernel operation exists either way ([Capability spaces and lookup](#capability-spaces-and-lookup)).
- **Blocks:** C17.
- **From:** [Capability spaces and lookup](#capability-spaces-and-lookup); [0047](../decisions/0047-the-kernel-follows-sel4.md), rule 3; [0066](../decisions/0066-capability-parameters-and-server-streams.md), rules 1 and 4. **Backlog:** D152.

### K76. Older majors of the interfaces the kernel calls

How is a fault handler, pager or memory server served when it speaks an older major of `aspis.kernel.fault`, `aspis.kernel.pager` or `aspis.kernel.memory_request`? No bind fixes the version of a message the kernel sends.

- **Options:** major 1 only, read tolerantly, as the [call-language specification](call-language.md#l21-older-majors-of-the-interfaces-the-kernel-calls) assumes meanwhile, until a second major exists.
- **Blocks:** C15, C17.
- **From:** [Endpoint operations and messages](#endpoint-operations-and-messages); [0064](../decisions/0064-the-call-header-and-wire-encoding.md), rule 9. **Backlog:** D156.
