<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0051. Scheduling, the timer and deadlines

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Jobs have CPU budgets ([0025](0025-twelve-factor-app-contract.md), rule 12), and every operation that may cross the network carries a deadline ([0004](0004-network-transparency-and-failure.md), rule 3). `CLOCK_MONOTONIC` comes from the ARM generic timer ([POSIX note §4.18](../design/posix-compatibility.md#418-time)). No record covers the scheduler, priorities or timers.

The [design backlog, D17](../design/design-backlog.md#m2-kernel-objects) asks for the scheduler; priorities for drivers, interrupt handling and the display; how priority inversion is avoided when many clients call shared servers, such as the PDP, the entropy service, the network server and pagers; how a job's CPU budget applies; which ARM timer the kernel uses, including under a hypervisor; and how the kernel represents a deadline, and where wall time lives.

[0047](0047-the-kernel-follows-sel4.md) adopts seL4's MCS scheduling. There a thread runs only while it holds a scheduling context: a budget of CPU time per period, refilled as a sporadic server. A passive server has no context of its own, and runs on the one its caller donates with each call. Canceling a caller that waits for a passive server's reply leaves the donated context with the server for good (`reply_remove_tcb`).

The generic timer has an EL1 physical timer and an EL1 virtual timer. The virtual timer counts the physical count minus an offset that EL2 sets. Under a hypervisor such as KVM, a guest uses the virtual timer. On bare metal, with the offset set to zero, it counts the same as the physical one.

This record gives the decisions and what they guarantee. The mechanism is in the [kernel specification](../design/kernel-specification.md) ([0047](0047-the-kernel-follows-sel4.md), rule 5), which also lists what is still open.

Claude drafted this record from the project owner's choice of seL4 as the model, on 2026-11-25.

## Decision

1. **Scheduling follows seL4's MCS model.**
   - A thread runs only with a scheduling context, which holds a budget and a period, both in microseconds, and is bound to one core. The kernel enforces the budget.
   - A scheduling context is made from untyped memory, and belongs to the job whose memory it is made from ([0058](0058-jobs-and-budgets.md), rule 5). The kernel configures it only within that job's CPU share ([0058](0058-jobs-and-budgets.md), rule 8). So a job's CPU budget applies through its scheduling contexts.
   - Configuring a context also sets its 64-bit badge, as in seL4 MCS. Timeout and context-withdrawn faults report it ([0056](0056-faults-and-page-fetch-deadlines.md), rule 3).
   - A thread has a fault endpoint and, separately, an optional timeout endpoint, as in seL4 MCS ([0056](0056-faults-and-page-fetch-deadlines.md), rule 1). The handler on a thread's timeout endpoint may differ from its fault handler.
   - When a budget runs out, the kernel does what seL4 MCS does: the thread waits for its refill, or, if it has a timeout endpoint, the kernel sends a timeout fault there ([0056](0056-faults-and-page-fetch-deadlines.md), rule 3). The [kernel specification](../design/kernel-specification.md#scheduling-contexts-and-budgets) gives the cases.
2. **Priorities are fixed, from 0 to 255.**
   - The highest-priority runnable thread on a core runs. Threads of equal priority take turns.
   - Each thread has a maximum controlled priority, as in seL4, so a thread can't give another a priority above its own limit.
   - The kernel sets no policy. The root server's boot manifest assigns priorities. The default bands are, from highest to lowest:
     1. interrupt-handling threads in drivers;
     2. pagers and the display path;
     3. system servers;
     4. applications.

     Their numeric ranges are open ([kernel specification](../design/kernel-specification.md#priorities-and-bands)).
3. **Shared servers are passive where they can be.**
   - A passive server runs on its caller's scheduling context, so a busy server can't starve its callers, and each caller pays for its own requests.
   - A shared server runs at a priority at least as high as any of its callers. Callers wait in priority order, so a high-priority caller isn't queued behind a low-priority one.
   - The PDP and the entropy service are written as passive servers, and so are the network server's threads that serve client calls, unless a later record says why one can't be. A passive server answers every call without waiting for an event. Stream pulls return at once, and clients wait on the stream's eventcount ([0066](0066-capability-parameters-and-server-streams.md), rule 8).
   - Work with no caller present, such as the network server's receive path, runs on threads with their own scheduling contexts.
   - **Pagers and the memory server aren't passive.** Page requests and memory requests donate no scheduling context ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 6; [0058](0058-jobs-and-budgets.md), rule 6), so pagers and the memory server run on their own contexts. Pagers sit in band 2 (rule 2).
   - **Every passive server's threads have a timeout endpoint** (rule 1). Its handler acts when a caller's budget runs out mid-request, so callers queued behind it don't wait for that caller's refill, and when a caller's context is taken back (below). This is a duty on the server's author, which the kernel doesn't check. A server that breaks it harms only itself and the callers queued behind it.
   - **The handler on a timeout endpoint runs on its own scheduling context**, since timeout and context-withdrawn faults donate none, as in seL4.
   - **Canceling a call takes the caller's context back.** If a delivered call to a passive server is canceled, or its deadline passes, the kernel takes the caller's scheduling context back from wherever it has been donated along a chain of calls, and the call returns "canceled" or "timed out" ([0054](0054-ipc-endpoints.md), rules 5 and 6). It takes the context back at once on a cancel, and, when a deadline passes, within the bounded batches of [0052](0052-smp-bring-up-and-the-kernel-lock.md), rule 2. Each passive server left without a context gets a context-withdrawn fault on its timeout endpoint ([0056](0056-faults-and-page-fetch-deadlines.md), rule 3). This departs from seL4 MCS ([0047](0047-the-kernel-follows-sel4.md), rule 3). So a caller's own deadline bounds every call it makes to a passive server, whatever the server is doing ([kernel specification](../design/kernel-specification.md#passive-servers-and-taking-a-context-back)).
4. **The kernel uses the EL1 virtual timer on every platform.** Its count, `CNTVCT_EL0`, is the kernel's clock, and its interrupt preempts threads and ends waits. When the stub is entered at EL2, it sets the virtual offset to zero and lets EL1 read the physical counter, before it drops to EL1 ([0041](0041-boot-abi.md), rule 1). Under a hypervisor, the host sets the offset, and the kernel doesn't need to know ([kernel specification](../design/kernel-specification.md#the-timer-and-deadlines)).
5. **A deadline is a value of the virtual count.**
   - Every blocking call takes an optional deadline: an absolute 64-bit value of the count, after which the call returns "timed out" ([0054](0054-ipc-endpoints.md), rule 5).
   - The count starts near zero at boot, never goes back and doesn't wrap in any lifetime a node will have.
   - The kernel interface library converts nanoseconds to counts, so programs never see the counter's frequency.
   - A deadline in a message between nodes is a duration, never a count, since each node's count is its own. It is encoded as the nanoseconds remaining ([0064](0064-the-call-header-and-wire-encoding.md), rule 12).
6. **Wall time lives in user space.** The kernel knows no date or time of day. A user-space time service supplies wall time, once the node has authenticated time. Log records ([0042](0042-log-ring-and-panic-path.md), rule 2) and deadlines use the count.

## Consequences

- **D17 is settled.** Every item it asked for is decided here, except two details the kernel specification lists as open: the numeric range of each priority band, and how a job's share is checked when a context is configured ([kernel specification](../design/kernel-specification.md#scheduling-contexts-and-budgets)).
- **Budgets are enforced by the kernel.** A job can't use more CPU than its share, and a server's work is charged to the caller that asked for it.
- **Priority inversion through shared servers is bounded** by the servers' priorities, their callers' budgets and the handlers on their timeout endpoints.
- **Passive servers bear the cost of prompt cancellation.** One can lose its context mid-request, and the handler on its timeout endpoint cleans up.
- **Page fetching is charged to the pager**, whose own budget bounds the fetching it does for all its clients.
- **The stub gains two register writes**, the virtual offset and the timer access controls at EL2. C04's follow-up work adds them, before C13a starts the timer.
- **One timer path serves bare metal, QEMU and cloud VMs**, which C81 needs.

## References

- [seL4 reference manual, 17.0.0: MCS scheduling contexts, passive servers and timeout faults](https://docs.sel4.systems/releases/sel4/17.0.0)
- seL4 17.0.0 source: [`src/object/reply.c`](https://github.com/seL4/seL4/blob/17.0.0/src/object/reply.c), where `reply_remove_tcb` unlinks a canceled caller's reply object and leaves the donated context with the server; [`src/kernel/thread.c`](https://github.com/seL4/seL4/blob/17.0.0/src/kernel/thread.c) and [`src/kernel/faulthandler.c`](https://github.com/seL4/seL4/blob/17.0.0/src/kernel/faulthandler.c), where `endTimeslice` and `handleTimeout` send timeout faults without donating a context
- Lyons, McLeod, Almatary, Heiser, "Scheduling-context capabilities: a principled, light-weight operating-system mechanism for managing time", EuroSys 2018, [doi:10.1145/3190508.3190539](https://doi.org/10.1145/3190508.3190539)
- [Arm Architecture Reference Manual for A-profile (DDI 0487), issue M.d](https://developer.arm.com/documentation/ddi0487/latest): the generic timer
- [Kernel specification](../design/kernel-specification.md): scheduling contexts, priorities, passive servers, the timer and deadlines
- [0025. Twelve-factor app contract](0025-twelve-factor-app-contract.md), rule 12; [0004. Network transparency](0004-network-transparency-and-failure.md), rule 3
- [0064. The call header and the wire encoding](0064-the-call-header-and-wire-encoding.md), rule 12; [0066. Capability parameters and server streams](0066-capability-parameters-and-server-streams.md), rule 8
