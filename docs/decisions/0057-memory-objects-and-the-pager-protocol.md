<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0057. Memory objects and the pager protocol

- **Status:** Proposed
- **Date:** 2026-11-25

## Context

Mapping is ASPIS's main way to reach data ([0005](0005-single-level-store.md), rule 1). The kernel forwards a page fault on a mapped object to that object's pager over IPC, and the pager supplies the page from local storage or from a remote node ([0005](0005-single-level-store.md), rule 2). Its Consequences call the pager protocol early, critical work. Other records need memory objects of several kinds:

- immutable memory objects shared across processes, and anonymous ones that end with their job ([0025](0025-twelve-factor-app-contract.md), rule 12);
- scratch areas, which are anonymous memory objects ([0025](0025-twelve-factor-app-contract.md), rule 6);
- copy-on-write clones for the POSIX personality's `fork` ([0012](0012-posix-compatibility-layer.md), rule 4);
- executables mapped in place from the initial image ([0037](0037-initial-image-format-and-contents.md), rule 4).

The POSIX personality targets POSIX.1-2024 ([0012](0012-posix-compatibility-layer.md), rule 2). POSIX lets a process map a file it opened read-only with `PROT_WRITE` and `MAP_PRIVATE`, and dynamic linkers map data segments that way. So a private copy of a file's pages can't need the right to write the file, nor belong to the file's owner.

The [design backlog, D23](../design/design-backlog.md#m2-kernel-objects) asks for the messages between the kernel and pagers, page supply, write-back and eviction, copy-on-write and remote pages. Its options are Mach's external pagers, seL4's user-level paging and Fuchsia's VMOs and pagers.

seL4 has frames, not memory objects, and sends a VM fault to the faulting thread's handler. [0047](0047-the-kernel-follows-sel4.md), rule 3 makes memory objects kernel objects instead, because [0005](0005-single-level-store.md), rule 2 sends faults to the object's pager. Fuchsia's VMOs and pagers are the closest model. Mach's shadow objects hold a copy's written pages and read the rest through the original; Fuchsia's snapshot clones copy a shared page for whichever side writes it.

[0047](0047-the-kernel-follows-sel4.md), rule 4 adds that the kernel never waits for anything outside itself, so a page request must never hold up the kernel.

This record states what is decided and what is guaranteed. The messages, operations and their order are in the [kernel specification](../design/kernel-specification.md) ([0047](0047-the-kernel-follows-sel4.md), rule 5), which also lists what is still open.

Claude drafted this record from the project owner's choices of 2026-11-25.

## Decision

1. **A memory object is a kernel object holding a range of pages.**
   - **It belongs to the job whose untyped memory it is made from** ([0058](0058-jobs-and-budgets.md), rule 1). Its pages and the kernel's records for it come from that job, and it ends with that job ([0058](0058-jobs-and-budgets.md), rules 5 and 10).
   - **The kernel's boot objects belong to no job.** The initial image, the device tree, the boot information, the kernel interface library and the framebuffer's device memory object count against no reservation or limit, and are never destroyed ([0048](0048-kernel-memory-and-address-spaces.md), rule 2).
   - **There are three kinds:**

     | Kind | Pages come from | Used for |
     |---|---|---|
     | Anonymous | Zero-filled frames, allocated from its job's memory on first touch (rule 2) | Scratch areas, stacks, heaps, and copy-on-write clones (rule 4) |
     | Pager-backed | Frames from its job's memory, which the kernel allocates and the pager fills on request (rules 5 to 7) | Files, persistent objects, remote objects, build caches |
     | Device | A range of device memory, mapped uncached | MMIO for drivers. Its pages count against no budget; only the object and its records come from its job |

   - **Immutability is a property, not a kind.** An immutable object's contents never change after it is made, and it can't be mapped writable. It can be shared across jobs. Executables, build images and the initial image are immutable. A pager-backed object may be immutable, such as a build cache's, and its pager may evict its pages and supply them again, since they never change.
2. **Pages a memory object allocates come from its job.**
   - An anonymous object, and a clone (rule 4), set nothing aside when they are made. Each frame comes from the object's job when the page is first touched, or when a write needs a page of its own. So a large, sparse stack or heap costs only the pages it uses.
   - A pager-backed object's frames come from its job too. The kernel allocates each one before it asks the pager to fill it (rule 6). So the pages a reader touches are charged to the object's job, not the reader's ([0058](0058-jobs-and-budgets.md), rule 11).
   - The kernel memory a fault needs comes from the job responsible for it: page tables and mapping records from the address space's job, and the object's page index from the object's job.
   - When the job has no free memory, the kernel asks for more without waiting ([0058](0058-jobs-and-budgets.md), rule 6).
3. **Mapping puts a range of a memory object into an address space**, at an address, with rights and a fetch timeout, which is always finite ([0056](0056-faults-and-page-fetch-deadlines.md), rule 4).
   - It needs a capability to the memory object with the rights asked for, and the address space's capability with the write right. Mapping executable needs the read right, as in seL4, where execute is an attribute of the mapping, not a right. No mapping is both writable and executable ([0048](0048-kernel-memory-and-address-spaces.md), rule 6).
   - Map names no job. Its page tables and mapping records come from the address space's job, or, for the root server's address space, which belongs to no job, from the root job ([0048](0048-kernel-memory-and-address-spaces.md), rule 1). Map fails at once with "no memory" if that job has none free.
   - **A mapping holds a copy of the memory-object capability it was made from** ([0049](0049-capability-spaces-rights-and-revocation.md), rule 4). So revoking that capability, or any it derives from, unmaps the range, and a manager that revokes a client's memory object also takes it out of the client's address space.
   - The kernel records each mapping against its object, so that it can unmap a page everywhere.
   - **Mappings can be listed.** With the read right on the address space, listing yields descriptions only. With the write right, it also yields, for each mapping, a capability to its memory object with the read right, and with the write right if the mapping is writable. Each such capability is derived from the mapping's own copy, so revoking the object's capability reaches it too. Revoking the address-space capability used to list doesn't ([kernel specification K42](../design/kernel-specification.md#k42-capabilities-yielded-by-listing)). The POSIX process server uses these for `fork` (Consequences). What a description holds, and how a long list is returned, is in the [kernel specification](../design/kernel-specification.md#memory-objects-and-mappings).
4. **A clone is copy-on-write.** Cloning a range of a memory object makes a new anonymous object, which belongs to the job whose untyped memory it is made from. The clone holds the pages written into it. What else it holds, and what cloning needs, depends on what it clones:
   - **A clone of an anonymous object is a snapshot** of the pages that object holds. Neither side sees the other's later writes. Cloning one needs the write right on it, and the clone must belong to its job or a descendant of that job. The reason: a shared page stays charged to the job that made it, and a write on either side leaves the old frame with the other, so the original's writers keep frames for the clone. Only a holder who could write the original may cause that, and only inside the subtree its limit covers ([0058](0058-jobs-and-budgets.md), rule 4).
   - **A clone of a pager-backed object reads through to it** for pages the clone hasn't written. Cloning one needs only the read right, and the clone may belong to any job.
     - Until the clone writes a page, it sees the original's page as it is now, including newer contents from the pager, as Linux's `MAP_PRIVATE` file mappings do. A write copies the page into the clone, charged to the clone's job, so the original's job never pays for the clone.
   - **A clone of an immutable object** needs only the read right, and may belong to any job, because the shared pages never change on the original's side.
   - **A clone of a clone follows its root original** for pages neither clone has written: if the root is pager-backed, they read through to it. The pages the cloned clone has written are shared as a snapshot, so cloning any clone needs the write right on it, and the new clone must belong to its job or a descendant (the snapshot rule above).
   - **No writer ever spends another job's memory.** A write copies only into the writer's own object, charged to its own job.
   - A page pinned as a thread's IPC buffer is never shared. Cloning copies it into the clone at once, charged to the clone's job, and fails with "no memory" if that job can't pay ([0048](0048-kernel-memory-and-address-spaces.md), rule 5).
   - **Destroying an anonymous original destroys its snapshot clones**, and their mappings are removed. They belong to its job or a descendant, so ending its job ends them anyway. What happens to a read-through clone, which may belong to any job, when its pager-backed original is destroyed is open in the [kernel specification](../design/kernel-specification.md#copy-on-write-clones).
5. **A pager creates the objects it backs.** It gives an endpoint capability, normally badged so that it knows the object; a default fetch timeout, which is finite; whether the object is immutable; and untyped memory of the job the object will belong to. That job may be one the pager keeps for the objects it backs, apart from the job it runs in ([0058](0058-jobs-and-budgets.md), rules 7 and 11). The pager receives a pager capability to the object, which it uses to answer page requests, and to write back and evict pages (rules 7 and 8).
6. **The kernel asks for pages without waiting.**
   - **The frame comes first.** When a thread touches a missing page, the kernel takes a frame for it from the object's job, asking for memory if the job has none ([0058](0058-jobs-and-budgets.md), rule 6). Then it sends a page request to the pager's endpoint. The faulting thread waits; the kernel doesn't.
   - **The kernel buffers no page request.** A request is an IPC message defined in the IDL ([0059](0059-the-kernel-interface-library.md), rule 2): a one-way request of the `[local]` interface `aspis.kernel.pager/1`, on the common call header ([0064](0064-the-call-header-and-wire-encoding.md), rule 9). It travels on a faulting thread's behalf, so the kernel keeps no copy of it in memory of its own. Its fields, how it is carried, and how threads that touch a page already requested share its request, are in the [kernel specification](../design/kernel-specification.md#the-pager-protocol) and its [steps of a page wait](../design/kernel-specification.md#waiting-for-a-page).
   - **A page request donates no scheduling context.** The pager runs on its own, and answers with Supply or Fail (rule 7), not with a reply. Pagers aren't passive servers ([0051](0051-scheduling-timers-and-deadlines.md), rules 2 and 3).
   - **Every page wait ends.** A thread stops waiting when its fetch timeout passes ([0056](0056-faults-and-page-fetch-deadlines.md), rule 4), or at once when it is canceled ([0054](0054-ipc-endpoints.md), rule 6), and takes a page-deadline fault, marked canceled if it was ([0056](0056-faults-and-page-fetch-deadlines.md), rule 3). Other threads waiting on the page keep waiting.
   - **Filling a page costs the pager no memory.** The pager fills the frame the kernel allocated, through its pager capability. It needs no memory of its own for each page, and no writable mapping of the page outlasts Supply. Which way it fills the frame is open in the [kernel specification](../design/kernel-specification.md#the-pager-protocol).
7. **The pager answers by supplying or by failing.**
   - **Supply** installs filled pages in the object and clears their pending marks. It maps nothing and needs no memory, so it never fails because of a waiting thread's job.
   - **Waiting threads resume and repeat the access.** Each maps the page on its own fault, from its own address space's job (rule 2), so a shortage there affects that thread alone.
   - **Fail** reports an error for a range, as an error key: the interface ID, major and code of a typed error, 36 octets ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rules 1 and 2). Every waiting thread gets a page-unavailable fault with that key ([0056](0056-faults-and-page-fetch-deadlines.md), rule 3). The full error, with its detail, stays with the pager, and a handler that wants it asks the pager. Where the kernel keeps the key until every fault is delivered is open in the [kernel specification](../design/kernel-specification.md#the-pager-protocol).
   - **Read-ahead sends no memory request.** A pager may fill and supply pages no thread has asked for yet, in frames the kernel takes from the object's job. If that job has no free memory, the kernel skips those pages, and asks for none ([kernel specification](../design/kernel-specification.md#the-pager-protocol)).
   - **So pagers never need memory for the pages they supply.** Every frame comes from the object's job, and the kernel allocates it before the pager is asked. Pagers run within their reservations ([0058](0058-jobs-and-budgets.md), rule 7).
8. **Pages leave an object only when user space asks.** The kernel never evicts on its own.
   - **The pager decides write-back and eviction**, through its pager capability. The [kernel specification](../design/kernel-specification.md#the-pager-protocol) lists the operations. Evicting unmaps the pages everywhere, including in clones that read them through, and returns their frames to the object's job, where the memory server can take them back ([0058](0058-jobs-and-budgets.md), rule 7).
   - **A holder of anonymous memory can give pages back.** With the write right on an anonymous object, a clone included, a holder can decommit a range, as `madvise(MADV_DONTNEED)` does. That drops the object's pages in the range and returns their frames to its job. The next touch reads zeros, or, in a clone of a pager-backed object, reads through again. A frame still shared with another clone leaves only this object's side. Runtimes decommit when the memory-pressure eventcount advances ([0058](0058-jobs-and-budgets.md), rule 7).
   - **Pinned frames stay.** Eviction and decommit skip frames pinned as IPC buffers ([0048](0048-kernel-memory-and-address-spaces.md), rule 5). Destroying a memory object, or ending its job, first unregisters the IPC buffer of every thread whose buffer is a page of it ([0054](0054-ipc-endpoints.md), rule 3).
   - Word waiters are found by memory object and offset, so eviction loses none of them ([0053](0053-eventcounts.md), rule 6).
   - The operations, and how long ones stay preemptible ([0052](0052-smp-bring-up-and-the-kernel-lock.md), rule 2), are in the [kernel specification](../design/kernel-specification.md#the-pager-protocol) and its [decommit section](../design/kernel-specification.md#decommit).
9. **The kernel knows nothing of where pages come from.** A pager for a remote object fetches through the network server. Coherence between nodes uses leases or tokens ([0005](0005-single-level-store.md), rule 4), whose protocol is still open, and which a later record decides.

## Consequences

- **[0037](0037-initial-image-format-and-contents.md), rule 4 is answered.** The initial image is a resident immutable memory object that the kernel makes at boot ([0048](0048-kernel-memory-and-address-spaces.md), rule 2), and the root server maps executables from it. It belongs to no job (rule 1).
- **Memory pressure is user space's problem.** Pagers evict and runtimes decommit, on their own or when the memory server asks ([0058](0058-jobs-and-budgets.md), rule 7). The kernel's memory never grows with page traffic.
- **Immutable pages can be evicted.** A build cache can hold more builds than its reservation, and lose none of them under pressure, because its pager can fetch an evicted page again ([0058](0058-jobs-and-budgets.md), rule 11). The kernel can't check that a pager supplies the same contents again, so trusting an immutable pager-backed object means trusting its pager.
- **Pagers pay for their own work, not for the pages.** A fetch runs on the pager's scheduling context, and the frames come from the objects' jobs.
- **POSIX private mappings of files work.** A process that opened a file read-only can map it writable and private: the mapping is a clone of the file's object, in the process's own job, which reads through and pays only for the pages it writes (rule 4). A clone of a pager-backed object isn't a snapshot. POSIX and Linux's `mmap(2)` leave unspecified whether a private mapping sees later changes to the file.
- **`fork` has what it needs.** The POSIX process server lists the parent's mappings through the address space's capability with the write right (rule 3). It clones the parent's private writable objects in the child's job, which is the parent's job or a descendant of it, as rule 4 requires for snapshot clones. It then maps them, and the parent's shared objects, into the child's address space ([0012](0012-posix-compatibility-layer.md), rule 4). Destroying an anonymous original destroys its clones, so the process server keeps an exited parent's anonymous objects while its children live, and decommits the pages no child shares.
- **A clone's limit covers only what it writes.** Pages a snapshot clone shares with its original count against the job that made them, which pays for them until every object that shares them lets go. A child job's limit therefore doesn't bound how much of its parent's memory its clones keep alive; its parent's limit does ([0058](0058-jobs-and-budgets.md), rule 4).
- **The kernel does more bookkeeping than seL4.** It tracks mappings by object, pending requests by page, and clones by original. This is the main cost of [0005](0005-single-level-store.md)'s design, and it comes from the jobs' memory.
- **DMA isn't settled here.** How drivers get memory with known physical addresses for devices, behind the SMMU, is decided with the driver model (C20).
- **D23 is settled, except for mechanism.** The messages are page requests, Supply and Fail (rules 6 and 7); write-back and eviction are the pager's (rule 8); copy-on-write is rule 4; remote pages go through the network server (rule 9). The [kernel specification](../design/kernel-specification.md#the-pager-protocol) gives the message fields and the operations. Open there, to be settled with the prototype of C10 to C16: how the pager fills a frame, whether a request is requeued when a higher-priority thread joins it, what Evict and decommit do to a pending page, what a read-through clone sees when its original is destroyed, how shared pages and chains of clones are structured, and how a pager learns which pages were used least recently.

## References

- [Fuchsia: VMOs](https://fuchsia.dev/fuchsia-src/reference/kernel_objects/vm_object), [pagers](https://fuchsia.dev/fuchsia-src/reference/kernel_objects/pager) and [`zx_vmo_create_child`](https://fuchsia.dev/fuchsia-src/reference/syscalls/vmo_create_child): snapshot clones
- Rashid et al., "Machine-independent virtual memory management for paged uniprocessor and multiprocessor architectures", ASPLOS 1987, [doi:10.1145/36206.36181](https://doi.org/10.1145/36206.36181): Mach's external pagers and shadow objects
- [seL4 reference manual, 17.0.0: virtual memory](https://docs.sel4.systems/releases/sel4/17.0.0)
- [POSIX.1-2024, `mmap`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/mmap.html): `MAP_PRIVATE`, and `EACCES` only for `MAP_SHARED` with `PROT_WRITE`
- [Linux `mmap(2)`](https://man7.org/linux/man-pages/man2/mmap.2.html) and [`madvise(2)`](https://man7.org/linux/man-pages/man2/madvise.2.html): `MAP_PRIVATE` and `MADV_DONTNEED`
- [Kernel specification](../design/kernel-specification.md): memory objects and mappings, copy-on-write clones, the pager protocol, and decommit
- [0005. Single-level store](0005-single-level-store.md); [0012. POSIX compatibility layer](0012-posix-compatibility-layer.md); [0025. Twelve-factor app contract](0025-twelve-factor-app-contract.md)
- [0064. The call header and the wire encoding](0064-the-call-header-and-wire-encoding.md); [0065. Typed errors](0065-typed-errors-and-minor-versions-on-the-wire.md)
