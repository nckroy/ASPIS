<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0054. IPC: synchronous endpoints with deadlines and cancellation

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

[0002](0002-capability-security-model.md), rule 1 says only that capabilities pass over IPC, and [0005](0005-single-level-store.md), rule 2 that page faults reach pagers over it. Every operation that may cross the network carries a deadline ([0004](0004-network-transparency-and-failure.md), rule 3), and the POSIX personality needs to cancel a blocked wait ([POSIX note §5](../design/posix-compatibility.md#5-what-the-kernel-must-provide)). The [design backlog, D20](../design/design-backlog.md#m2-kernel-objects) asks whether messaging is synchronous or asynchronous, for message sizes and buffers, how capabilities travel, call and reply, and timeouts and cancellation. Its options are seL4's synchronous endpoints, Zircon's channels, and synchronous endpoints with eventcounts as the asynchronous primitive.

[0047](0047-the-kernel-follows-sel4.md) adopts seL4's endpoints, and [0053](0053-eventcounts.md) makes eventcounts the asynchronous primitive.

In seL4, an endpoint has no buffer. A sender waits until a receiver takes its message, and the kernel copies the message directly from one thread to the other. A call sends a message and waits for the reply. Under MCS, the receiver gets a reply object for each call, through which it answers exactly once. A message has up to 120 words, in message registers and the IPC buffer. It may name up to three extra capabilities, but the receiver has a single receive slot, so at most one capability is transferred. An extra capability that names the endpoint the message travels through is unwrapped to its badge instead. seL4 has no timeouts on IPC.

Under MCS, a call to a passive server donates the caller's scheduling context to the server, and the server's reply gives it back. In seL4 17.0.0, canceling a caller that waits for a reply only unlinks it from the reply object (`reply_remove_tcb`). The donated context stays with the server for good, and nothing returns it to the caller. A thread with no scheduling context can't run, so the canceled caller can't return. seL4 also sends timeout faults without donating a context (`handleTimeout` in `faulthandler.c`), so the handler on a timeout endpoint runs on its own.

Claude drafted this record from the project owner's choice of seL4 as the model, on 2026-11-25.

## Decision

1. **Endpoints are synchronous**, as in seL4. An endpoint holds no messages. A sender waits for a receiver, and the kernel copies the message from one thread to the other. Waiting senders and receivers are queued in priority order ([0051](0051-scheduling-timers-and-deadlines.md), rule 3).
2. **There are seL4's operations:** send; send without blocking, which drops the message if no receiver is waiting; call, which sends and waits for the reply; receive; and reply and receive, in one call.
   - A call gives the receiver a reply object, through which it replies once.
   - A call to a passive server carries the caller's scheduling context with it ([0051](0051-scheduling-timers-and-deadlines.md), rule 3).
   - Page requests and memory requests, which the kernel sends on a faulting thread's behalf, donate no scheduling context. Pagers and the memory server run on their own ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 6; [0058](0058-jobs-and-budgets.md), rule 6).
   - The [kernel specification](../design/kernel-specification.md#endpoint-operations-and-messages) gives each operation's arguments and results.
3. **A message has up to 120 64-bit words**, as in seL4, **and up to three capabilities** (rule 7).
   - The first four words travel in registers, and the rest in the sender's and receiver's IPC buffers. The kernel reports a message's length in octets, from 0 to 960, so every message has an exact end ([0064](0064-the-call-header-and-wire-encoding.md), rule 2). Data that doesn't fit is passed through a shared memory object. How a call is laid out in a message, and when its body spills to shared memory, is [0064](0064-the-call-header-and-wire-encoding.md)'s (rules 2, 5 and 11).
   - **Each thread has one IPC buffer**: a page of RAM, in a memory object mapped writable in the thread's address space, which a holder of the thread's capability with the write right registers ([0049](0049-capability-spaces-rights-and-revocation.md), rule 2). A thread with no registered buffer sends and receives only the words that travel in registers, as in seL4.
   - **The buffer can't outlive the thread.** Its memory object must belong to the thread's own job or to an ancestor of it.
   - **The kernel reaches the buffer without faulting** ([0048](0048-kernel-memory-and-address-spaces.md), rule 5). Registering pins the page: it must be resident, its frame is the buffer object's own and never shared copy-on-write, and neither eviction, decommit nor reclaim takes it while it is registered ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 8).
   - **The pinned frame stays charged to its memory object's job**, which is the thread's job or an ancestor's ([0058](0058-jobs-and-budgets.md), rule 5).
   - **The kernel never writes to a freed frame.** Destroying the buffer's memory object, or ending the job it belongs to, first unregisters the buffer of every thread that uses it ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 8).
   - **The kernel's writes count as writes.** A message the kernel writes into a buffer marks the page dirty, as a user write would, so the pager writes it back ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 8).
   - The [kernel specification](../design/kernel-specification.md#ipc-buffers) gives the registration steps and their errors.
4. **The kernel doesn't read message contents.** It copies the words and moves the capabilities. A message is an octet string whose integers are big-endian, encoded as the IDL says ([0062](0062-core-rules-big-endian-fixed-width.md), rule 2; [0064](0064-the-call-header-and-wire-encoding.md), rule 2). Messages the kernel itself sends to user-space servers, such as faults, page requests and memory requests, are IPC messages too, defined in the IDL with generated grammars ([0059](0059-the-kernel-interface-library.md), rule 2). They use the common call header, in `[local]` interfaces ([0064](0064-the-call-header-and-wire-encoding.md), rule 9). Page and memory requests are one-way: no reply comes. The kernel reads no reply to a fault: a handler that changes a thread's registers does so through the thread's capability before it replies.
5. **Every blocking operation takes an optional deadline**, a value of the virtual count ([0051](0051-scheduling-timers-and-deadlines.md), rule 5).
   - If the deadline passes first, the operation returns "timed out".
   - If it passes after a call was delivered, the call ends as a canceled call does (rule 6), and returns "timed out" instead of "canceled".
   - A call's "timed out" result says whether the message had been delivered, so the caller's runtime can report the call as unreachable or indeterminate ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rule 8).
   - This covers send, call, receive and every eventcount wait ([0053](0053-eventcounts.md), rule 7).
6. **A blocked thread can be canceled.**
   - A holder of the thread's capability with the write right can cancel the thread's current wait ([0049](0049-capability-spaces-rights-and-revocation.md), rule 2). The wait returns "canceled". The POSIX personality uses this for signals and thread cancellation.
   - **Before delivery,** canceling a call takes the message out of the endpoint's queue, and the server never sees it.
   - **After delivery,** the kernel invalidates the reply object, and the caller's call returns "canceled" at once. The server's reply then fails, and the server stops work it doesn't need to finish.
   - A call's "canceled" result says whether the message had been delivered, as "timed out" does (rule 5).
   - **If the call donated the caller's scheduling context,** the kernel takes the context back from wherever it has been donated along a chain of calls, and gives it to the caller. It does so at once on a cancel, and, when a deadline passes (rule 5), within the bounded batches of [0052](0052-smp-bring-up-and-the-kernel-lock.md), rule 2. This departs from seL4, where the context stays with the server ([0047](0047-the-kernel-follows-sel4.md), rule 3).
   - **Each passive server left without a scheduling context** gets a "context withdrawn" fault on its timeout endpoint ([0056](0056-faults-and-page-fetch-deadlines.md), rules 1 and 3). The handler on that endpoint may give the server a scheduling context to clean up, or reset it. That is why a passive server must have a timeout endpoint ([0051](0051-scheduling-timers-and-deadlines.md), rule 3).
   - **The handler on a timeout endpoint runs on its own scheduling context.** Timeout faults and context-withdrawn faults donate none, as seL4's timeout faults don't, so that handler can't be a passive server.
   - **A thread waiting for a page** isn't in a system call. Canceling it detaches it from the page's request, and it takes a page-deadline fault at once, marked canceled ([0056](0056-faults-and-page-fetch-deadlines.md), rules 3 and 4; [0057](0057-memory-objects-and-the-pager-protocol.md), rule 6). So a POSIX signal doesn't wait for the fetch timeout.
   - The [kernel specification](../design/kernel-specification.md#ipc-deadlines-and-cancellation) says how the kernel takes a context back along a chain, and lists what is still open there, including a thread that waits on a memory request.
   - A server that runs on its own scheduling context learns of a cancel before it replies through [0064](0064-the-call-header-and-wire-encoding.md)'s cancel message (rule 7), which the caller's library sends. It is advisory; the invalidated reply object is the guarantee.
7. **Up to three capabilities transfer in a message.**
   - Capability transfer needs the grant right on the endpoint capability used to send. A call needs the grant or grant-reply right on the caller's endpoint capability. A reply may carry capabilities only if the receiver's reply capability has the grant right, as in seL4 MCS.
   - The receiver names up to three receive slots in its capability space, and each transferred capability goes into one of them, as a child of the sender's capability ([0049](0049-capability-spaces-rights-and-revocation.md), rules 4 and 6). If the receiver names fewer slots than the message carries capabilities, the rest aren't transferred, and the receiver is told how many were, as in seL4.
   - **A capability that names the endpoint the message travels through is unwrapped**, as in seL4: the receiver gets its badge, and it fills no slot ([0047](0047-the-kernel-follows-sel4.md), rule 1). It keeps its position in the message's capability list, so the IDL's capability indexes don't shift ([0066](0066-capability-parameters-and-server-streams.md), rule 2).
   - The IDL holds each message to these three, and a call that needs more uses a builder session ([0066](0066-capability-parameters-and-server-streams.md), rule 3).
   - This departs from seL4, which has a single receive slot and so transfers at most one capability per message ([0047](0047-the-kernel-follows-sel4.md), rule 3). The project owner chose three on 2026-11-25.
   - The [kernel specification](../design/kernel-specification.md#capability-transfer) gives the order of transfer and what stops it.
8. **There is no asynchronous message queue in the kernel.** Asynchronous work uses eventcounts, with data in shared memory: for example, a ring of requests in a memory object, and an eventcount that is advanced when the ring has entries.

## Consequences

- **IPC is fast and bounded.** No message is buffered in the kernel, so a flood of sends can't exhaust kernel memory; senders just wait.
- **A slow or hostile server can't hold a client forever.** Every call can carry a deadline, and every wait can be canceled. When either ends a call to a passive server, the kernel takes the caller's scheduling context back, whether the server is running, blocked on another server or waiting for a page: at once on a cancel, and within bounded batches when a deadline passes (rule 6). A call with no deadline waits as long as the server takes, unless it is canceled.
- **IPC buffers stay where the kernel can reach them.** A registered buffer is pinned, and unregistered before its memory can go, so the kernel never meets a missing, shared or freed buffer page.
- **Passive servers must expect to lose a context.** A server whose caller is canceled loses the caller's scheduling context mid-request, and the handler on its timeout endpoint, running on a context of its own, cleans up ([0051](0051-scheduling-timers-and-deadlines.md), rule 3).
- **Large transfers use shared memory**, as in seL4 and Mach, which suits a system built on mapping ([0005](0005-single-level-store.md), rule 1).
- **The network server sees the same model.** A proxy endpoint behaves like a local one, and a call's deadline bounds the remote work.
- **D20 is settled.** Messaging is synchronous (rules 1 and 8); message size and buffers are rule 3; capability transfer is rule 7; call and reply are rule 2; timeouts and cancellation are rules 5 and 6. The cancel message to a server is [0064](0064-the-call-header-and-wire-encoding.md)'s (rule 7), and the mechanism questions still open are in the [kernel specification](../design/kernel-specification.md#open-questions). D13's cancelable waits are rule 6.

## References

- [seL4 reference manual, 17.0.0: endpoints, IPC buffer, reply objects, scheduling-context donation](https://docs.sel4.systems/releases/sel4/17.0.0)
- [seL4 `constants.h`](https://github.com/seL4/seL4/blob/master/libsel4/include/sel4/constants.h): `seL4_MsgMaxLength = 120`, `seL4_MsgMaxExtraCaps` = 3
- seL4 17.0.0 source: [`src/kernel/thread.c`](https://github.com/seL4/seL4/blob/17.0.0/src/kernel/thread.c), where `transferCaps` fills the single receive slot and unwraps capabilities to the endpoint the message travels through; [`src/object/endpoint.c`](https://github.com/seL4/seL4/blob/17.0.0/src/object/endpoint.c) and [`src/object/reply.c`](https://github.com/seL4/seL4/blob/17.0.0/src/object/reply.c), where canceling a caller that waits for a reply calls `reply_remove_tcb`, which leaves the donated context with the server; [`src/kernel/faulthandler.c`](https://github.com/seL4/seL4/blob/17.0.0/src/kernel/faulthandler.c), where `handleTimeout` sends a timeout fault without donating a context
- [Zircon channels](https://fuchsia.dev/fuchsia-src/reference/kernel_objects/channel), the option not taken
- [0062. Core rules](0062-core-rules-big-endian-fixed-width.md); [0064. The call header and the wire encoding](0064-the-call-header-and-wire-encoding.md); [0065. Typed errors](0065-typed-errors-and-minor-versions-on-the-wire.md); [0066. Capability parameters](0066-capability-parameters-and-server-streams.md)
- [0004. Network transparency](0004-network-transparency-and-failure.md); [0049. Capability spaces and rights](0049-capability-spaces-rights-and-revocation.md); [0051. Scheduling](0051-scheduling-timers-and-deadlines.md); [0053. Eventcounts](0053-eventcounts.md); [0056. Typed faults](0056-faults-and-page-fetch-deadlines.md); [0057. Memory objects](0057-memory-objects-and-the-pager-protocol.md); [0058. Jobs and budgets](0058-jobs-and-budgets.md)
- [Kernel specification](../design/kernel-specification.md)
