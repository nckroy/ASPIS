<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0053. Eventcounts

- **Status:** Proposed
- **Date:** 2026-11-25

## Context

Eventcounts are kernel objects ([0002](0002-capability-security-model.md), rule 1). One signals each rotation of a process's credentials ([0025](0025-twelve-factor-app-contract.md), rule 5), and local catalog watchers are woken through them ([0028](0028-discovery-and-realm-catalog.md), rule 6). The POSIX personality builds `poll` on a wait over many eventcounts, and futex-style locks on a wait on a word in user memory ([POSIX note §4.15](../design/posix-compatibility.md#415-threads), [§5](../design/posix-compatibility.md#5-what-the-kernel-must-provide)). The research notes propose 64-bit eventcounts as the asynchronous primitive, after AEGIS's `ec2_$` calls ([research notes §5](../research/aegis-domain-os.md#5-implications-for-aspis)). The [design backlog, D19](../design/design-backlog.md#m2-kernel-objects) asks how an eventcount is advanced, read and awaited, its width, how it relates to a word in user memory, and what limits a wait on a set.

[0047](0047-the-kernel-follows-sel4.md) follows seL4, whose asynchronous primitive is the notification: a word of bits that signals set and a receive clears. On 2026-11-25 the project owner weighed the two and chose eventcounts, for three reasons:

- **Several observers.** Reading or waiting on an eventcount doesn't consume it. A notification's bits are cleared by the first receiver, so only one waiter sees each signal.
- **A count, not a flag.** An eventcount records how many events occurred, which matches the catalog's 64-bit sequence numbers ([0028](0028-discovery-and-realm-catalog.md), rule 6) and tells a watcher how many changes it missed. Notifications merge repeated signals into one bit.
- **No registration.** A wait on a set of eventcounts doesn't need to tell their owners. With notifications, each `poll` would first have to hand every session server a badged capability, and take it back afterwards.

The discussion also found what notifications do better, and borrowed it: a notification can be bound to a thread so that one receive waits for either a message or a signal.

The project owner also asked whether a wait on a word in user memory gives a remote node a way into the kernel. In a single-level store, the word's page may be missing, and fetching it may mean a remote node. If the kernel waited for that page, a hostile or partitioned node could stall a system call and the locks it holds. [0048](0048-kernel-memory-and-address-spaces.md), rule 5 closes that, and rule 6 below applies it.

A page can also move to another frame while threads wait on a word in it: a pager may evict it and supply it again later, and a copy-on-write write gives it a new frame ([0057](0057-memory-objects-and-the-pager-protocol.md), rules 4 and 8). Waiters keyed by physical frame would then miss their wakes. Linux keys shared futexes by object and offset for the same reason.

Claude drafted this record from that discussion.

## Decision

1. **An eventcount is a 64-bit unsigned count in kernel memory.** It starts at zero. It is made by retyping untyped memory, and belongs to the job that memory belongs to ([0058](0058-jobs-and-budgets.md), rule 1).
2. **There are three operations: advance, read and wait.**
   - **Advance** adds one to the count and wakes every waiter whose target the count has reached. It needs the write right ([0049](0049-capability-spaces-rights-and-revocation.md), rule 2).
   - **Read** returns the count. **Wait** blocks until the count reaches a target value, then returns the count. Both need the read right.
   - Reading and waiting never change the count, so any number of threads can observe one eventcount.
   - **An advance never holds the kernel lock for unbounded time**, however many threads wait. The count changes at once. Waking many waiters is a long operation with preemption points, and an advance made for an interrupt, which has no calling thread to restart, wakes its waiters in bounded batches ([0052](0052-smp-bring-up-and-the-kernel-lock.md), rule 2). The [kernel specification](../design/kernel-specification.md#eventcount-operations) gives the mechanism.
3. **The count never wraps.** An advance that would pass 2^64 − 1 fails, and the count stays at its maximum. At a billion advances a second, reaching it would take about 584 years.
4. **A thread can wait on a set of up to 60 eventcounts** at once, each with its own target.
   - The set is a wait-set object, because the kernel has no heap to hold a list of waits ([0048](0048-kernel-memory-and-address-spaces.md), rule 1). It belongs to the job whose untyped memory it is made from, normally the waiting thread's.
   - Entries are added and removed by separate calls. Adding one needs the read right on its eventcount, and the entry holds a copy of that capability, so revoking it removes the entry ([0049](0049-capability-spaces-rights-and-revocation.md), rule 4).
   - The wait names only the wait set and an optional deadline (rule 7). A wait set serves one wait at a time.
   - The wait returns when any entry's eventcount reaches its target, with a 64-bit mask of the entries that have.
   - The [kernel specification](../design/kernel-specification.md#wait-sets) gives the object's size and layout.
5. **An eventcount can be bound to a thread**, so that a server can wait for requests and events in one call.
   - Binding needs the write right on the thread and the read right on the eventcount ([0049](0049-capability-spaces-rights-and-revocation.md), rule 2). A thread has at most one bound eventcount, and the binding holds a copy of the eventcount's capability ([0049](0049-capability-spaces-rights-and-revocation.md), rule 4).
   - While it is bound, the thread's receive on an endpoint, including the receive half of reply and receive ([0054](0054-ipc-endpoints.md), rule 2), also returns when the count has passed the value the thread last saw. It says which happened, and for an advance it returns the count. So no advance is missed between receives.
   - If an advance and a message are both pending, the receive reports the advance first, as seL4 reports a bound notification's signal first. The message stays queued for the next receive.
   - The [kernel specification](../design/kernel-specification.md#threads-bound-to-an-eventcount) says how the last-seen value is kept.
6. **A thread can also wait on a word in user memory**, for futex-style locks.
   - **Wait** takes the word's address, the value the caller expects and an optional deadline. If the word still holds that value, the thread sleeps until it is woken. Otherwise the call returns at once. **Wake** takes the address and how many waiters to wake. Words are 32 or 64 bits, aligned to their size.
   - **Waiters are keyed by memory object and offset**, not by physical frame: the object of the mapping that holds the word ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 3). So processes that share an object on one node can share a lock, and eviction and copy-on-write don't lose a wake. A clone is its own object, so a lock word in a private mapping is private to that mapping's process, as a futex in a private mapping is on Linux.
   - **The kernel never dereferences the address, and never waits for the page** ([0048](0048-kernel-memory-and-address-spaces.md), rule 5). If the page isn't resident, the call fails at once. The caller touches the page in user mode, which faults to its pager under a deadline, and retries. A word in a device memory object can't be waited on, and the call fails at once, so the kernel never reads MMIO.
   - When a memory object is destroyed, the threads waiting on words in it are woken.
   - A word in a page shared between nodes doesn't work as a lock, because a wake on one node can't reach a waiter on another. Locks across nodes use leases or tokens ([0005](0005-single-level-store.md), rule 4), whose protocol is still open.
   - The [kernel specification](../design/kernel-specification.md#word-waits) gives the mechanism and the errors.
7. **Every wait takes an optional deadline and can be canceled** ([0051](0051-scheduling-timers-and-deadlines.md), rule 5; [0054](0054-ipc-endpoints.md), rules 5 and 6). It returns "timed out" or "canceled".
8. **Interrupts advance eventcounts.** An interrupt handler capability is bound to an eventcount, and each interrupt advances it by one, so a driver knows how many interrupts fired ([0055](0055-interrupt-objects.md), rule 2). Binding a handler needs the write right on the eventcount, because the kernel then advances it ([0049](0049-capability-spaces-rights-and-revocation.md), rule 2).
9. **Eventcounts are local to a node.** A remote watcher receives a stream over RPC instead ([0028](0028-discovery-and-realm-catalog.md), rule 6). A local program waits for a stream's items on the stream's readiness eventcount, which it gets with `stream_ready`: from the server for a local stream, and from the network server for a remote one, which advances its own eventcount for each item it buffers ([0066](0066-capability-parameters-and-server-streams.md), rules 8 and 9). So a local program treats both kinds of watch alike.

## Consequences

- **The kernel has one asynchronous primitive.** Interrupts, `poll`, credential rotation, catalog watches and session readiness all use eventcounts, and there are no notifications.
- **A wait never misses an event.** A waiter reads the count and waits for the next value, so an advance between the read and the wait isn't lost.
- **Waiting on a set costs work and memory in proportion to its size**, through a wait set its job pays for. The limit of 60 bounds it. `poll` on more descriptors than that needs more than one wait, which libc can arrange.
- **A widely watched eventcount can't stall the kernel.** Anyone who can read it can add waiters, but an advance that wakes many of them is preemptible, or wakes them in bounded batches (rule 2).
- **Revoking an eventcount's capability reaches every wait set and thread it was added to** (rules 4 and 5), so a manager that ends a session also ends its client's waits on that session's eventcounts.
- **An eventcount isn't a lock.** An advance wakes every waiter whose target is reached. Locks use the word wait, whose wake wakes only as many as asked.
- **Remote pages can't stall the kernel through a lock word.** The cost is that a lock word must be resident when a thread starts to wait on it.
- **D19 is settled.** Advance, read and wait are rules 2 and 7, the width rules 1 and 3, the relation to words in user memory rule 6, and the limit on sets rule 4. The [kernel specification](../design/kernel-specification.md#open-questions) lists the mechanism questions still open. D13's eventcount sets and words are rules 4 and 6.

## References

- Reed and Kanodia, "Synchronization with eventcounts and sequencers", Communications of the ACM 22(2), 1979, [doi:10.1145/359060.359076](https://doi.org/10.1145/359060.359076)
- [Research notes §2.5](../research/aegis-domain-os.md#25-processes-synchronization-and-errors): AEGIS's `ec2_$` calls
- [seL4 reference manual, 17.0.0: notifications and bound notifications](https://docs.sel4.systems/releases/sel4/17.0.0), the option not taken
- [Linux `futex(2)`](https://man7.org/linux/man-pages/man2/futex.2.html)
- [0049. Capability spaces and rights](0049-capability-spaces-rights-and-revocation.md); [0054. IPC endpoints](0054-ipc-endpoints.md); [0057. Memory objects](0057-memory-objects-and-the-pager-protocol.md); [0058. Jobs and budgets](0058-jobs-and-budgets.md); [0066. Capability parameters and server streams](0066-capability-parameters-and-server-streams.md)
- [Kernel specification](../design/kernel-specification.md)
