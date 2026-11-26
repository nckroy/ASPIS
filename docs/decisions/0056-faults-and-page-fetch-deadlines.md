<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0056. Typed faults, and the deadline for fetching a page

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

If a page can't be fetched by its deadline, the kernel delivers a typed fault to the faulting thread's fault handler, instead of blocking forever ([0004](0004-network-transparency-and-failure.md), rule 4). Every operation that may cross the network carries a deadline ([0004](0004-network-transparency-and-failure.md), rule 3). But the kernel knows nothing about the network (rule 5 there), so it can only enforce a deadline it is given. The POSIX personality needs faults delivered to a user-level handler ([POSIX note §5](../design/posix-compatibility.md#5-what-the-kernel-must-provide)), and its "hard" subtrees wait indefinitely but can be interrupted by signals ([0012](0012-posix-compatibility-layer.md), rule 7). The [design backlog, D22](../design/design-backlog.md#m2-kernel-objects) asks for the kinds of typed fault and their message, how a thread's fault handler is set, and who sets the deadline for fetching a page: the mapping, or the pager.

In seL4, each thread names a fault endpoint. A fault is sent there as if the thread had made a call, and the handler's reply resumes the thread, possibly with new registers. Under MCS, a thread may also name a timeout endpoint for its timeout faults, which donate no scheduling context.

In ASPIS, a fault on a page that comes from a pager goes first to that pager, not to the thread's handler ([0005](0005-single-level-store.md), rule 2; [0057](0057-memory-objects-and-the-pager-protocol.md), rule 6). That is a page of a pager-backed object, or a page that a clone hasn't written and still reads through such an object ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 4). The thread's handler hears of it only if the pager fails or is too slow.

The mechanism behind this record is in the [kernel specification](../design/kernel-specification.md) ([0047](0047-the-kernel-follows-sel4.md), rule 5), which also lists what is still open.

Claude drafted this record from the project owner's choices of 2026-11-25.

## Decision

1. **Each thread has a fault endpoint, and may have a timeout endpoint**, as in seL4 MCS. Both are set through the thread's capability with the write right.
   - A fault goes to the fault endpoint as a call on the thread's behalf, badged so the handler knows which thread faulted. The thread waits for the reply.
   - Timeout and context-withdrawn faults (rule 3) go to the timeout endpoint instead ([0051](0051-scheduling-timers-and-deadlines.md), rule 1). As in seL4, they donate no scheduling context, so the handler on a timeout endpoint runs on its own.
   - A thread without a timeout endpoint gets neither kind. Every passive server must have one, a duty on its author that the kernel doesn't check ([0051](0051-scheduling-timers-and-deadlines.md), rule 3).
   - The thread keeps its own copy of each endpoint capability, as seL4 does, so revoking the capability presented unsets the endpoint ([0049](0049-capability-spaces-rights-and-revocation.md), rule 4; [kernel specification](../design/kernel-specification.md#fault-delivery)).
2. **The handler's reply decides what happens.** The handler's reply resumes the thread. A handler that changes the thread's registers does so through the thread's capability ([0061](0061-debugging.md), rule 3) before it replies, because the kernel reads no reply contents ([0047](0047-the-kernel-follows-sel4.md), rule 3). Or it may not reply, and act on the thread through its capability: suspend it, have the job's manager end its job, or hand it to a debugger. A handler that doesn't know a fault's kind doesn't reply, so the thread stays stopped ([0064](0064-the-call-header-and-wire-encoding.md), rule 9). A thread with no fault endpoint is suspended, and the kernel logs the fault ([0042](0042-log-ring-and-panic-path.md), rule 1).
3. **Faults are typed.** Every fault message names its kind, as its method number, and carries the program counter and the exception syndrome. Each kind adds what its handler needs. The kinds are:

   | Kind | When |
   |---|---|
   | Capability | A capability address didn't resolve, or lacked a right |
   | Unmapped | An access hit no mapping, or a mapping without the needed right |
   | Page unavailable | The pager reported that it can't supply a page ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 7) |
   | Page deadline | The page wasn't supplied before the mapping's fetch timeout passed, or the wait for it was canceled (rule 4). The fault says which |
   | Memory | Memory the fault needed couldn't be had: the paying job couldn't get more and had nothing left to evict, the memory server refused, or the wait for memory timed out or was canceled ([0058](0058-jobs-and-budgets.md), rules 6 and 7). The fault says which |
   | User exception | An instruction faulted: undefined, misaligned, floating point, and the rest |
   | Unknown system call | A call the kernel doesn't know, or one made from outside the kernel interface library ([0059](0059-the-kernel-interface-library.md), rule 4) |
   | Timeout | A scheduling context's budget ran out ([0051](0051-scheduling-timers-and-deadlines.md), rule 1) |
   | Context withdrawn | The kernel took a caller's scheduling context back from a passive server, because the call was canceled or its deadline passed ([0054](0054-ipc-endpoints.md), rule 6) |
   | Debug | A breakpoint, a watchpoint or a single step ([0061](0061-debugging.md), rule 3) |

   - Fault messages are IPC messages, defined in the IDL with generated grammars ([0013](0013-abnf-for-protocols-and-calls.md), rule 2; [0059](0059-the-kernel-interface-library.md), rule 2). They are requests of the `[local]` interface `aspis.kernel.fault/1`, one method per kind, on the common call header ([0064](0064-the-call-header-and-wire-encoding.md), rule 9). The [kernel specification](../design/kernel-specification.md#fault-delivery) lists each kind's fields.
   - A page-unavailable fault carries the pager's error key: the interface ID, major and code of a typed error, 36 octets ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rules 1 and 2). The full error stays with the pager.
   - New kinds are added as the kernel grows. A handler that doesn't know a kind treats it as fatal, and doesn't reply (rule 2).
   - A context-withdrawn fault leaves the server with no scheduling context. Its handler may give it one to clean up with, or reset it.
4. **The mapping sets the fetch timeout.**
   - **Every mapping carries a fetch timeout**, always finite, so no fault waits without limit ([0004](0004-network-transparency-and-failure.md), rules 3 and 4).
   - **The mapper chooses it.** If the mapper doesn't, the mapping takes the default that the pager set on the pager-backed object its pages come from, or for a clone, on the object at the root of its chain of clones ([0057](0057-memory-objects-and-the-pager-protocol.md), rules 4 and 5). A mapping whose pages come from no pager, such as an anonymous object's, has no default, so its mapper must name one.
   - **It bounds the thread's whole wait on a fault**: for any memory the fault needs (the page's frame, page tables and mapping records), then for the pager.
   - **It ends only that thread's wait.** Other threads waiting on the page keep waiting, and a page that arrives late is kept.
   - **A wait on a fault can be canceled**, by a holder of the thread's capability with the write right, as any wait ([0054](0054-ipc-endpoints.md), rule 6). The thread takes its fault at once, marked canceled.
   - **A page request donates no scheduling context**, so the pager runs on its own ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 6).

   The [kernel specification](../design/kernel-specification.md#waiting-for-a-page) gives the steps of a page wait.
5. **The kernel doesn't retry, and doesn't decide whether a failure is fatal.** It reports the fault and leaves the decision to the handler. The POSIX personality maps fault kinds to signals; native runtimes may map them to typed errors.

## Consequences

- **Remote failure reaches programs as a typed fault, at a time they chose**, as [0004](0004-network-transparency-and-failure.md), rule 4 requires, while the kernel still knows nothing of the network.
- **The program decides how long to wait.** An interactive program sets a short fetch timeout; a batch job may set a long one. The pager knows the backing store, and sets the default.
- **POSIX "hard" subtrees need no unbounded wait.** The POSIX process server, as the fault handler, resumes the thread after each page-deadline fault, and the thread waits for the page again ([0012](0012-posix-compatibility-layer.md), rule 7). To deliver a signal, it cancels the wait, so a signal never waits for a fetch timeout.
- **A fetch timeout isn't the end of the page.** A pager that has received a request keeps fetching, so a handler can resume the thread and expect success.
- **A reader can't make a cache's faults fail.** Touching a pager-backed object's pages charges the object's job, such as a file or build cache. When that job can't get more memory, its own pagers evict its clean pages first, and a memory fault comes only if nothing can be evicted ([0058](0058-jobs-and-budgets.md), rules 6, 7 and 11).
- **Fault handlers are ordinary servers**: the process manager for native processes, the POSIX process server for POSIX ones, and a debugger while it is attached.
- **D22 is settled.** The fields of each message and the steps of a page wait are mechanism, which the kernel specification settles with the prototype of C15.

## References

- [seL4 reference manual, 17.0.0: fault handlers, fault types and timeout faults](https://docs.sel4.systems/releases/sel4/17.0.0)
- [seL4 `faults.h`](https://github.com/seL4/seL4/blob/master/libsel4/include/sel4/faults.h)
- [0004. Network transparency](0004-network-transparency-and-failure.md), rules 3 to 5; [0005. Single-level store](0005-single-level-store.md); [0012. POSIX compatibility layer](0012-posix-compatibility-layer.md), rule 7
- [0049. Capability spaces](0049-capability-spaces-rights-and-revocation.md); [0051. Scheduling](0051-scheduling-timers-and-deadlines.md); [0054. IPC endpoints](0054-ipc-endpoints.md); [0057. Memory objects and pagers](0057-memory-objects-and-the-pager-protocol.md); [0058. Jobs and budgets](0058-jobs-and-budgets.md)
- [0061. Debugging](0061-debugging.md); [0064. The call header and the wire encoding](0064-the-call-header-and-wire-encoding.md); [0065. Typed errors](0065-typed-errors-and-minor-versions-on-the-wire.md)
- [Kernel specification](../design/kernel-specification.md)
