<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0058. Jobs, memory reservations and limits, and CPU shares

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Jobs can be stopped as a unit, each has a memory budget and a CPU budget, and anonymous memory objects end with their job ([0025](0025-twelve-factor-app-contract.md), rule 12). Scratch areas are anonymous memory objects ([0025](0025-twelve-factor-app-contract.md), rule 6). A deploy's formation gives each process type a size ([0026](0026-realm-as-cloud-provider.md), rule 5), but nothing defines one. The [design backlog, D24](../design/design-backlog.md#m2-kernel-objects) asks for the budgets' units, how budgets nest, whether a scratch area counts, and who pays for immutable build pages that many instances map.

seL4 has no jobs, but its untyped memory and MCS scheduling contexts give most of what they need ([0025](0025-twelve-factor-app-contract.md), Consequences): revoking an untyped capability destroys every object made from it, and a scheduling context caps its threads' CPU time. [0048](0048-kernel-memory-and-address-spaces.md) and [0051](0051-scheduling-timers-and-deadlines.md) adopt both.

A first draft made a job's memory budget simply the untyped memory it held. That is a fixed partition: memory a job holds but doesn't use is idle. And seL4's untyped memory is a watermark allocator, so freed space returns only once everything made from its region is gone, and a long-running job would lose capacity unless memory is handed out in page-sized pieces.

Kubernetes separates a container's memory request, which is guaranteed and used to place it, from its limit, which caps it, so a node can promise more in limits than it has. Linux overcommits more freely and kills a process when memory runs out, which the project owner didn't want.

On 2026-11-25 the project owner chose a reservation plus a limit, and asked that the node try to free memory before it refuses a job more. The owner also chose that a process holds its job's memory, not its job's capability, and that a reader can't make a cache's faults fail by touching its pages.

This record states what is decided and what is guaranteed. The mechanism is in the [kernel specification](../design/kernel-specification.md) ([0047](0047-the-kernel-follows-sel4.md), rule 5), which also lists what is still open.

Claude drafted this record from those choices.

## Decision

1. **A job is a kernel object.** Jobs nest: every job but the root has one parent. At boot the root server holds the root job, with all the node's memory and CPU.
   - **The kernel's boot objects belong to no job.** They are what the kernel makes at boot from memory it kept for itself, the initial image and the root job among them ([0048](0048-kernel-memory-and-address-spaces.md), rule 2). They count against no reservation or limit, and are never destroyed.
   - **Every other object belongs to the job whose untyped memory it is made from**, as in seL4. Making an object needs untyped memory of the job, not the job's capability. The one exception is a child job, which is made through its parent's capability, because it carves the parent's reservation, limit and CPU share (rule 9).
2. **A job has a memory reservation and a memory limit**, in bytes, in whole 4 KiB pages. The reservation is never more than the limit.
3. **The reservation is guaranteed.**
   - It is untyped memory the job holds itself, carved from its parent's reservation. So a node's reservations never add up to more than its RAM.
   - Giving a job memory is an operation on the job's capability (rule 9). The kernel records each piece as the job's.
   - **Nothing takes memory within a job's reservation away from it while the job runs.**
4. **Above its reservation, a job borrows from the node's pool, up to its limit.**
   - **The pool** is the root job's memory that no child's reservation holds and the root server doesn't use. A user-space memory server holds it on the root job's behalf, and it doesn't count against the memory server's own job. The root server starts the memory server from the initial image ([0037](0037-initial-image-format-and-contents.md), rule 5), second, right after the entropy service ([0021](0021-entropy-before-keys.md), rule 1) and before any driver. Until then the root server plays its role.
   - **Borrowed memory is lent in page-sized pieces**, or larger ones for large objects, so that every piece a job empties can be returned whole ([K04](../design/kernel-specification.md#k04-piece-sizes)).
   - **Limits nest.** A child's limit, which its parent sets, is never more than the parent's. Borrowed memory counts against the job's limit and every ancestor's, so a parent's limit caps its whole subtree. The kernel refuses to add memory to a job beyond any of those limits.
   - **Limits may add up to more than the node's RAM.** That is the only overcommit: borrowing can fail; a reservation can't.
5. **Everything made from a job's memory belongs to it, and counts against it**: threads, scheduling contexts, capability spaces, address spaces, page tables, endpoints, eventcounts and wait sets, memory objects, the ITS's command queue and tables ([0055](0055-interrupt-objects.md), rule 4), the kernel's records for them, and the pages its memory objects allocate ([0057](0057-memory-objects-and-the-pager-protocol.md), rules 1 and 2). Scratch areas count too ([0025](0025-twelve-factor-app-contract.md), rule 6).
   - Map's page tables and mapping records come from the address space's job, or the root job's for the root server ([0048](0048-kernel-memory-and-address-spaces.md), rule 1; [0057](0057-memory-objects-and-the-pager-protocol.md), rule 3).
   - The pages of an anonymous object, a clone or a pager-backed object are charged to its job when touched or written, whichever job's thread touched them ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 2).
   - A page pinned as an IPC buffer stays charged to its memory object's job, the thread's or an ancestor's ([0048](0048-kernel-memory-and-address-spaces.md), rule 5).
   - **A server that makes objects for another job makes them from that job's memory**, so they are charged to it and end with it: a spawned process's objects ([0060](0060-processes-native-spawn-and-elf.md), rule 3), or `fork`'s snapshot clones, in the child's job ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 4).
   - **A writer never spends another job's memory**: a write copies only into the writer's own object ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 4).
6. **When a job runs out, the kernel asks; it doesn't wait.**
   - Each job has a memory endpoint, normally the memory server's, badged for the job.
   - **An explicit call that needs memory**, such as making an object, fails at once with "no memory". The runtime then asks for more and retries, with a two-way call of the `[local]` interface `aspis.memory/1` on the job's memory endpoint, which the startup block carries ([0060](0060-processes-native-spawn-and-elf.md), rule 4). The memory server lends and replies, or refuses with a typed error ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rule 1). The interface's methods and errors are C83's.
   - **A fault takes memory from the job responsible**: the object's job for a page, and the address space's job for page tables and mapping records ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 2). If that job has none free, the kernel sends a memory request to its memory endpoint on the thread's behalf, as it sends a page request ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 6). The thread waits; the kernel doesn't.
   - **A memory request is one-way**, of the `[local]` interface `aspis.kernel.memory_request/1` on the common call header ([0064](0064-the-call-header-and-wire-encoding.md), rule 9). It donates no scheduling context: the memory server runs on its own. The memory server answers through the job's capability ([Memory requests and reclaim](../design/kernel-specification.md#memory-requests-and-reclaim)).
   - **Below its limit,** the memory server lends, freeing memory first if it must (rule 7). At an ancestor's limit, it first reclaims within that ancestor's subtree, above reservations, and lends what it frees within the limit.
   - **If it can't lend,** it has the pagers of the job's own objects evict that job's clean pages, least recently used first, so the fault is served from the job's own memory. It refuses only if nothing can be evicted. Evicting a job's own pages for its own fault takes nothing from its reservation (rule 3). So a reader that touches a cache's pages can't make the cache's faults fail while the cache has clean pages to evict.
   - A refusal becomes a memory fault ([0056](0056-faults-and-page-fetch-deadlines.md), rule 3).
   - **A memory wait ends.** A cancel ([0054](0054-ipc-endpoints.md), rule 6) gives the thread a memory fault at once, marked canceled. The mapping's fetch timeout bounds the memory wait too ([0056](0056-faults-and-page-fetch-deadlines.md), rule 4). How a request is withdrawn on a timeout or cancel, and whether it passes to another waiting thread, is open ([kernel specification K51](../design/kernel-specification.md#k51-memory-waits-on-the-fault-path)).
7. **The memory server frees memory before it refuses**, in this order, stopping as soon as it has enough:
   1. it takes back empty pieces that jobs hold above their reservations;
   2. it asks pagers to evict clean pages held in borrowed memory;
   3. it advances the node's memory-pressure eventcount, so runtimes and allocators decommit what they don't need ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 8), and waits a short time;
   4. it asks pagers to write back and evict dirty pages held in borrowed memory.

   If that doesn't free enough within a bound its policy sets, it has the job's own clean pages evicted (rule 6). **It never takes memory within a reservation from the job that holds it, and it never kills a job.** Stopping, killing or moving an instance under pressure is user-space policy; on a realm, the realm's scheduler decides.

   - **Reclaim never waits on itself.** The servers on the reclaim path (pagers, the storage and network servers, and the memory server) never borrow: their limits equal their reservations. The objects a pager backs may belong to a job that borrows, such as a cache's (rule 11).
   - The memory server asks pagers with a deadline ([0054](0054-ipc-endpoints.md), rule 5), so a silent pager delays reclaim only until then.
   - Reclaim acts only by taking back empty pieces, and through eviction and decommit, which skip frames pinned as IPC buffers ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 8). It takes a piece back without racing the job ([Untyped memory and kernel records](../design/kernel-specification.md#untyped-memory-and-kernel-records)). How it targets borrowed memory is open ([K56](../design/kernel-specification.md#k56-targeting-borrowed-memory)).
8. **A job's CPU budget is a share of each core**: a budget and a period, in microseconds, for each core it may use. A child's share is carved from its parent's. Scheduling contexts for a job's threads can be configured only within the job's remaining share ([0051](0051-scheduling-timers-and-deadlines.md), rule 1). CPU isn't overcommitted.
9. **A job's capability stays with its manager.**
   - A process doesn't hold its own job's capability. It holds untyped memory of its job (rule 1), which is all it needs to make objects.
   - The manager that made the job, such as the process manager or the root server, holds its capability. The memory server holds one to each job it lends to, which gives and takes back memory and nothing else. Which rights make that so is open ([kernel specification K53](../design/kernel-specification.md#k53-rights-on-a-jobs-capability)).
   - **With the job's capability, a manager can:** give the job memory and set its limits; make a child job, carving its reservation, limit and CPU share from this job's (rules 3, 4 and 8); stop and resume every thread in the job and its descendants, without canceling their waits ([0061](0061-debugging.md), rule 3); list those threads, each with its address space, and get capabilities to them; and end the job (rule 10). So a process's manager reaches every thread of the process, including those its runtime made ([0060](0060-processes-native-spawn-and-elf.md), rule 7; [0061](0061-debugging.md), rule 4), and no process reaches another's threads through a job they share. The [kernel specification](../design/kernel-specification.md#job-capabilities) gives each operation.
10. **Ending a job destroys everything it made.** The kernel revokes every piece the job and its descendants hold, reserved and borrowed. That destroys every object made from them, anonymous memory objects and scratch areas included ([0025](0025-twelve-factor-app-contract.md), rules 6 and 12), and the snapshot clones of their anonymous objects ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 4). Borrowed memory returns to the pool; the reservation and CPU share return to the parent. It is a long operation with preemption points ([0052](0052-smp-bring-up-and-the-kernel-lock.md), rule 2), whose steps are in the [kernel specification](../design/kernel-specification.md#ending-a-job). What happens to read-through clones of the job's pager-backed objects, which may belong to other jobs, is open ([K46](../design/kernel-specification.md#k46-a-read-through-clone-whose-original-is-destroyed)).
11. **Shared immutable pages are charged to the job they belong to.**
    - An immutable memory object's frames belong to its job ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 1). For builds and files cached on the node, that is normally a job the caching server keeps for its cache, apart from the job it runs in (rule 7). The caching server is those objects' pager.
    - A job that maps such an object pays only for its own page tables and mapping records. Instances of one release share one copy, charged once.
    - Executables mapped in place from the initial image, a boot object (rule 1), are charged to no job.
    - The cache's pages above its reservation are borrowed, and among the first evicted under pressure (rule 7). Its pager supplies them again on the next fault. When it can't get more memory, the cache evicts its own least recently used clean pages (rule 6).
12. **A size is a CPU share, a memory reservation and a memory limit.** The realm's named sizes ([0026](0026-realm-as-cloud-provider.md), rule 5) map onto these units. The names and their values are decided with C54.

## Consequences

- **Reservations are guarantees.** A job keeps its reservation whatever other jobs do, so apps can be sized predictably, and the realm's scheduler places instances by their reservations.
- **Idle memory is shared.** The pool serves whichever jobs need it, and caches files until they do.
- **A parent caps its subtree.** A job can't escape its limit by making children. But a child's limit bounds only what its objects allocate and write: pages its snapshot clones share with a parent's objects stay charged to the parent until every clone that shares them lets go ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 4). A policy that sandboxes a forked child by its limit must count that.
- **Running out is a fault, not a kill.** A job that can't get more memory gets a typed memory fault, which its runtime or fault handler can act on. No out-of-memory killer exists, in the kernel or out of it, unless a policy chooses to stop a job.
- **Reclaim can't deadlock.** The kernel takes each frame from the object's job, and asks for memory itself, before it asks the pager ([0057](0057-memory-objects-and-the-pager-protocol.md), rules 6 and 7). So no pager waits on the memory server while the memory server waits on it.
- **Killing a job is complete.** It reclaims everything the job and its descendants made, wherever their capabilities went, including what other servers made in them.
- **Processes can't control their own job.** Only managers hold job capabilities (rule 9), so stopping, listing and debugging a job's threads stay with the job's manager and the policy it applies ([0061](0061-debugging.md), rule 4).
- **The memory server is a new node server**, C83 in M3. It holds the pool, answers memory requests, and drives reclaim.
- **Sizes must cover kernel bookkeeping**, since page tables, mapping records and capability spaces come out of the job's memory. Servers on the reclaim path can't borrow, so their reservations must cover their peak.
- **D24 is settled.** Units: bytes in whole pages, and a budget and period in microseconds per core (rules 2 and 8). Nesting: rules 3, 4 and 8. Scratch areas count (rule 5). Shared immutable build pages are charged to the cache's job (rule 11). Open in the kernel specification, to be settled with the prototype of C10 to C16: how the memory server learns which job is at its limit and finds its pagers (K54), how a memory request is withdrawn or passed on (K51), which pieces a fault takes first (K05), and the rights on a job's capability (K53).

## References

- [seL4 reference manual, 17.0.0: untyped memory and scheduling contexts](https://docs.sel4.systems/releases/sel4/17.0.0)
- [Kubernetes: resource management for pods and containers](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/): requests and limits
- [Zircon jobs](https://fuchsia.dev/fuchsia-src/reference/kernel_objects/job), for the nesting of jobs
- [Kernel specification](../design/kernel-specification.md): job capabilities, memory requests and reclaim, and ending a job
- [0025. Twelve-factor app contract](0025-twelve-factor-app-contract.md); [0026. Realm as cloud provider](0026-realm-as-cloud-provider.md); [0057. Memory objects and pagers](0057-memory-objects-and-the-pager-protocol.md); [0064. The call header and the wire encoding](0064-the-call-header-and-wire-encoding.md)
