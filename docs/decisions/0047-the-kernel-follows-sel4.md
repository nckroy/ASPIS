<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0047. The kernel follows seL4's design, with ASPIS's own objects where the records need them

- **Status:** Accepted
- **Date:** 2026-11-25, updated 2026-11-26

## Context

[0002](0002-capability-security-model.md), rule 1 makes seL4 the reference model for the kernel's capabilities, but no record says how far the rest of the kernel follows it. The [design backlog, D13](../design/design-backlog.md#m2-kernel-objects) asks which of seL4's mechanisms the kernel adopts, and how it meets what other records need:

- the POSIX personality's needs ([POSIX note §5](../design/posix-compatibility.md#5-what-the-kernel-must-provide)): copy-on-write clones, a capability-table copy, cancelable waits, thread suspend and register access, fault delivery, waits on sets of eventcounts and on words in user memory, and a thread-pointer register;
- jobs and budgets, and immutable and job-scoped memory objects ([0025](0025-twelve-factor-app-contract.md), rule 12);
- memory objects whose page faults go to user-space pagers ([0005](0005-single-level-store.md), rule 2);
- typed faults with deadlines ([0004](0004-network-transparency-and-failure.md), rule 4);
- eventcounts as kernel objects ([0002](0002-capability-security-model.md), rule 1; [0025](0025-twelve-factor-app-contract.md), rule 5; [0028](0028-discovery-and-realm-catalog.md), rule 6).

D13 also carries one item from [0037](0037-initial-image-format-and-contents.md), rule 4: how the initial image's memory becomes a memory object.

seL4 provides most of this. Its untyped memory, capability spaces, synchronous endpoints and MCS scheduling contexts are a small, well-studied set of mechanisms, and [0025](0025-twelve-factor-app-contract.md) notes that untyped memory and scheduling contexts already give most of what jobs and budgets need (Consequences). seL4 has no memory objects with pagers, no jobs and no eventcounts, and it delivers every page fault to the faulting thread's handler, not to an object's pager.

ASPIS is written in Rust ([founding requirements](README.md#founding-requirements)), so it can follow seL4's design but can't inherit its proofs. The current seL4 release is 17.0.0, of 30 October 2026.

The project owner chose seL4 as the model throughout on 2026-11-25. Claude drafted this record from that choice. After three rounds of review, the project owner also decided that these records hold decisions and invariants only, and that the mechanism moves to a design note, the kernel specification, to be settled alongside a prototype (rule 5).

## Decision

1. **The kernel follows seL4's design.** Where a record leaves the kernel's design open, the kernel does what seL4 does, unless a record or this rule's list says otherwise. The reference is seL4 17.0.0 with MCS enabled. ASPIS follows the design, not the code: it copies no seL4 source and claims none of seL4's proofs.
2. **ASPIS adopts these mechanisms from seL4:**
   - untyped memory and retyping. Every object made after boot is made from untyped memory that a job holds, and belongs to that job, as an seL4 object belongs to the untyped memory it was made from. So the kernel allocates no memory of its own after boot ([0048](0048-kernel-memory-and-address-spaces.md); [0058](0058-jobs-and-budgets.md));
   - thread control blocks. The kernel saves and restores each thread's registers, the thread pointer `TPIDR_EL0` included, and a holder of the thread's capability reads and writes them, as seL4 does with its TLS base ([0061](0061-debugging.md));
   - capability spaces built from CNodes, with seL4's rights, badges and capability derivation tree ([0049](0049-capability-spaces-rights-and-revocation.md));
   - MCS scheduling contexts, passive servers and scheduling-context donation ([0051](0051-scheduling-timers-and-deadlines.md));
   - SMP under one kernel lock ([0052](0052-smp-bring-up-and-the-kernel-lock.md));
   - synchronous endpoints with call and reply, a per-thread IPC buffer and seL4's limit of 120 words per message ([0054](0054-ipc-endpoints.md));
   - interrupt handler capabilities ([0055](0055-interrupt-objects.md));
   - a fault endpoint per thread, and an optional, separate timeout endpoint, as in seL4 MCS ([0056](0056-faults-and-page-fetch-deadlines.md); [0051](0051-scheduling-timers-and-deadlines.md)). Every passive server's threads must have a timeout endpoint (rule 3). That is a duty on the server's author, which the kernel doesn't check ([0051](0051-scheduling-timers-and-deadlines.md), rule 3).
3. **ASPIS departs from seL4 where accepted records, or the project owner, require it.** The [kernel specification](../design/kernel-specification.md#how-far-the-kernel-follows-sel4) says what each departure changes in seL4's mechanism.
   - **Eventcounts replace notifications** as the asynchronous primitive ([0053](0053-eventcounts.md)). The project owner chose them.
   - **Memory objects are kernel objects.** A memory object's page faults go to its pager, not to the faulting thread's handler ([0005](0005-single-level-store.md), rule 2; [0057](0057-memory-objects-and-the-pager-protocol.md)). To do this, the kernel keeps records that no capability names, such as mapping records and each object's page tracking. They are made from the memory of the job responsible, like every other object (rule 2).
   - **Jobs are kernel objects**, with a memory reservation, a memory limit and a CPU share ([0025](0025-twelve-factor-app-contract.md), rule 12; [0058](0058-jobs-and-budgets.md)). An object belongs to the job whose untyped memory it is made from (rule 2). The job's capability controls the job: it gives the job memory and makes child jobs, lists, stops, resumes and ends the job's threads, and sets its limits. It stays with the job's manager, such as the process manager. A process holds untyped memory of its job, not its job's capability.
   - **Every blocking operation takes a deadline and can be canceled** ([0004](0004-network-transparency-and-failure.md), rule 3; [POSIX note §5](../design/posix-compatibility.md#5-what-the-kernel-must-provide)).
   - **Canceling a call to a passive server takes the caller's scheduling context back.** In seL4 MCS the donated context stays with the server. In ASPIS the caller gets its context back, wherever it has been donated along a chain of calls: at once when the call is canceled, and, when its deadline passes after delivery, within the bounded batches of [0052](0052-smp-bring-up-and-the-kernel-lock.md), rule 2. The call returns "canceled" or "timed out" ([0054](0054-ipc-endpoints.md), rule 6; [0051](0051-scheduling-timers-and-deadlines.md), rule 3). A passive server left without a context is told through its timeout endpoint (rule 2).
   - **Suspending a thread doesn't cancel its wait.** seL4's suspend cancels the thread's IPC. In ASPIS a suspended thread keeps its call, its donated scheduling context and any page, memory or word wait; only an explicit cancel ends a wait. So a debugger's stop, or a job being stopped, gives no passive server a context-withdrawn fault ([0061](0061-debugging.md), rule 3).
   - **A message carries up to three capabilities.** seL4 transfers at most one, into a single receive slot. In ASPIS the receiver names up to three receive slots ([0054](0054-ipc-endpoints.md); [0049](0049-capability-spaces-rights-and-revocation.md)). Only the number changes; the rest of capability transfer follows seL4 (rule 1). The project owner chose this on 2026-11-25.
   - **Every copy is a child of the capability it came from.** In seL4 only an original, an untyped capability or a newly badged copy can revoke: a plain copy becomes its source's sibling, so revoking it deletes nothing. In ASPIS every copy, badged copy, transfer and binding is recorded as a child of its source, so revoking any capability reaches everything derived from it ([0049](0049-capability-spaces-rights-and-revocation.md), rule 4).
   - **Deleting an object finishes the objects that only it reached.** In seL4, when a deletion meets the last capability to a nested object, such as a CNode held only in the CNode being deleted, it parks that object's zombie in the object's own first slot and leaves it, uncleared, until its untyped memory is revoked. In ASPIS the same deletion clears and destroys the nested object, as [0049](0049-capability-spaces-rights-and-revocation.md), rule 4 requires: when the last capability to an object is deleted, the object is destroyed. Only objects that hold each other's last capabilities, and that no lookup can name, still wait for their untyped memory's revocation, as in seL4.
   - **Fault replies carry no register values.** In seL4 a fault handler's reply may set some of the faulting thread's registers. In ASPIS the reply only resumes the thread. A handler changes registers through the thread's capability before it replies ([0061](0061-debugging.md), rule 3), so the kernel reads no message contents ([0054](0054-ipc-endpoints.md), rule 4; [0064](0064-the-call-header-and-wire-encoding.md), rule 9).
   - **A capability's kind and rights can be read.** A holder can ask the kernel the kind and rights of a capability in its own space (identify). seL4 reports a capability's type only through a call in debug builds. The network server needs identify to translate capabilities between nodes, and generated stubs need it to check the rights a call received ([0066](0066-capability-parameters-and-server-streams.md), rules 1 and 4).
   - **Message lengths are in octets.** seL4's message info gives a length in words. ASPIS's kernel reports octets, 0 to 960, so every message has an exact end ([0054](0054-ipc-endpoints.md), rule 3; [0064](0064-the-call-header-and-wire-encoding.md), rule 2).
   - **System calls come only from the kernel interface library** ([0014](0014-versioned-object-apis.md), rule 6; [0059](0059-the-kernel-interface-library.md)).
   - **The log ring and the boot framebuffer are kernel objects** ([0042](0042-log-ring-and-panic-path.md), rules 5 and 6).
4. **The kernel never waits for anything outside itself.** No system call waits for a pager, a server or the network, and no kernel lock is held across such a wait. A thread may block; the kernel doesn't. This keeps a slow or hostile pager, server or remote node from stalling the kernel or any other thread's system call.
5. **The kernel specification is a design note, and holds the mechanism.**
   - These records state what is decided and what is guaranteed, and why. The [kernel specification](../design/kernel-specification.md), `docs/design/kernel-specification.md`, gives the mechanism: the objects' operations and their arguments, message and record layouts, the order of steps inside the kernel, queue and allocation strategies, and preemption points.
   - It also lists every mechanism question that is still open, under [Open questions](../design/kernel-specification.md#open-questions). They are settled alongside a prototype of chunks C10 to C16, and the specification records each answer.
   - Where the specification says nothing, the kernel follows seL4's reference manual (rule 1).
   - The specification may change with the prototype without an edit to these records, as long as every guarantee of these records still holds (rule 6). A change that would break one is an edit to the record that gives the guarantee, proposed in the pull request that needs it.
6. **The kernel keeps these invariants.** Each is decided in the record cited. Any mechanism the kernel specification gives must keep all of them, and the prototype tests them ([kernel specification](../design/kernel-specification.md#invariants-the-prototype-checks)).
   - The kernel never waits for anything outside itself (rule 4).
   - The kernel never dereferences a user address, and never takes a page fault in kernel mode ([0048](0048-kernel-memory-and-address-spaces.md)).
   - After boot, the kernel never allocates memory that no job supplied (rule 2; [0048](0048-kernel-memory-and-address-spaces.md)).
   - No mapping is both writable and executable ([0048](0048-kernel-memory-and-address-spaces.md)).
   - Every blocking call takes a deadline and can be canceled (rule 3).
   - A job's reservation is never taken away while the job runs, and memory is reclaimed before it is refused. A job that still can't get memory gets a typed fault. There is no out-of-memory killer, in the kernel or out of it ([0058](0058-jobs-and-budgets.md)).
   - A writer never spends another job's memory ([0057](0057-memory-objects-and-the-pager-protocol.md)). A reader that touches another job's pages can't make that job's faults fail while the job has clean pages it can evict ([0058](0058-jobs-and-budgets.md)).
   - Raw capabilities never leave a node ([0002](0002-capability-security-model.md), rule 5).

## Consequences

- **The kernel stays small.** It has no heap, no policy, no IDs and no network code. Its new objects (eventcounts and their wait sets, memory objects, jobs, the log ring and the framebuffer) are each small, and each meets a need in the Context or an accepted record. The GICv3 ITS's tables are kernel objects too, because the kernel keeps MSI routing to itself ([0055](0055-interrupt-objects.md)).
- **Developers can learn from seL4's documentation**, which covers most of the kernel's model. ASPIS's departures are listed in one place (rule 3).
- **Nothing is verified.** seL4's proofs cover its C code in particular configurations, so they say nothing about a Rust kernel. ASPIS's assurance comes from testing, fuzzing (C71), model checking of its concurrent protocols' designs ([0068](0068-the-fuzzing-and-differential-testing-gate.md), rule 10) and Rust's memory safety, and it should say so plainly. The invariants of rule 6 are what the tests check first.
- **This record settles D13.** Each need in the Context has a record that meets it:
  - copy-on-write clones: [0057](0057-memory-objects-and-the-pager-protocol.md);
  - a capability-table copy: [0049](0049-capability-spaces-rights-and-revocation.md), made by the kernel interface library ([0059](0059-the-kernel-interface-library.md));
  - cancelable waits: [0054](0054-ipc-endpoints.md) and [0053](0053-eventcounts.md);
  - thread suspend and register access: [0061](0061-debugging.md);
  - fault delivery: [0056](0056-faults-and-page-fetch-deadlines.md);
  - waits on sets of eventcounts and on words in user memory: [0053](0053-eventcounts.md);
  - a thread-pointer register: rule 2 above, and [0060](0060-processes-native-spawn-and-elf.md);
  - jobs and budgets: [0058](0058-jobs-and-budgets.md) and [0051](0051-scheduling-timers-and-deadlines.md);
  - immutable and job-scoped memory objects: [0057](0057-memory-objects-and-the-pager-protocol.md) and [0058](0058-jobs-and-budgets.md);
  - page faults that go to user-space pagers: [0057](0057-memory-objects-and-the-pager-protocol.md);
  - typed faults with deadlines: [0056](0056-faults-and-page-fetch-deadlines.md);
  - eventcounts as kernel objects: [0053](0053-eventcounts.md);
  - the initial image as a memory object: [0048](0048-kernel-memory-and-address-spaces.md) makes it a resident immutable memory object at boot.

  What these records leave to the mechanism is named in the kernel specification's [Open questions](../design/kernel-specification.md#open-questions).
- **Memory objects add work seL4 leaves to user space.** The kernel tracks which mappings come from which memory object, so that it can send a fault to the object's pager, unmap an evicted page everywhere, and list an address space's mappings (rule 3).
- **A slow or hostile passive server can't keep a caller's scheduling context.** Canceling the call takes the context back at once, and its deadline takes it back within the kernel's bounded batches (rule 3). seL4 MCS gives no such bound.
- **The records stay short.** Each states a choice or a guarantee and its reason. The mechanism can change with the prototype without an edit to any record, as long as the invariants hold (rules 5 and 6).

## References

- [seL4 17.0.0 release](https://github.com/seL4/seL4/releases/tag/17.0.0) and [documentation](https://docs.sel4.systems/releases/sel4/17.0.0)
- [seL4 FAQ: multicore](https://docs.sel4.systems/projects/sel4/frequently-asked-questions)
- seL4 17.0.0 source: [`src/object/endpoint.c`](https://github.com/seL4/seL4/blob/17.0.0/src/object/endpoint.c) (`cancelIPC`, which calls `reply_remove_tcb` for a caller waiting on a reply) and [`src/kernel/thread.c`](https://github.com/seL4/seL4/blob/17.0.0/src/kernel/thread.c) (`transferCaps`, which fills one receive slot and unwraps capabilities to the sending endpoint)
- [0002. Capabilities](0002-capability-security-model.md); [0005. Single-level store](0005-single-level-store.md); [0025. Twelve-factor app contract](0025-twelve-factor-app-contract.md)
- [0064. The call header and the wire encoding](0064-the-call-header-and-wire-encoding.md); [0066. Capability parameters and server streams](0066-capability-parameters-and-server-streams.md)
- [POSIX note §5](../design/posix-compatibility.md#5-what-the-kernel-must-provide); [Inside the kernel §3](../design/kernel-components.md#3-open)
- [The kernel specification](../design/kernel-specification.md)
