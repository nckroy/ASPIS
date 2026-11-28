<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# TLA+ specs

*2026-11-26, updated 2026-11-27. The TLA+ specs of the kernel's concurrent protocols ([0068](../docs/decisions/0068-the-fuzzing-and-differential-testing-gate.md), rule 10), checked with TLC v1.7.4 as the [call-language specification](../docs/design/call-language.md#model-checking) says. Their properties are the [kernel specification](../docs/design/kernel-specification.md#model-checking)'s.*

Each spec comes with the chunk whose protocol it models. C12's is scheduling-context donation, which C14 extends with queued sends and faults. C14's are IPC endpoints and eventcounts. C15's, of the pager protocol, is still to be written.

## Running them

`cargo xtask tlc` runs every per-change model below, then trace validation, within one budget of 10 minutes. `cargo xtask tlc --nightly` adds the six nightly models and longer traces, all within one budget of 60 minutes, which xtask enforces by stopping the run and failing it; it runs in `nightly.yml`, never in a build workflow. Four of the nightly models haven't been timed in their current form: `SchedDonation.nightly.cfg` and `SchedDonationQueue.nightly.cfg` never, `EventcountBound.nightly.cfg` not since `rp` and `PassiveRecv` were added, and `IpcEndpoint.nightly.cfg` not since the action properties `OneCallEndsPerStep` and `QueuedEndsOnce` were added, which leave its states as they were. So whether all six fit the budget is still to be measured.

- xtask fetches `tla2tools.jar` into `build/tla/` and checks its pinned SHA-256 first.
- It copies the specs into `build/tla/run/` and runs TLC there, so TLC's state files never land in `specs/`.
- TLC gets at most min(4, cores / 2) workers, at low priority (`nice -n 10`).
- It needs a JRE, 11 or later. CI uses the runner's Java 21, with no setup action: the Temurin 21 the image preinstalls, else Ubuntu's `openjdk-21-jre-headless`.

CI's `tlc` job runs it when a change touches `specs/`, `crates/ksched/`, `crates/kipc/`, `crates/kcap/`, `crates/kmem/`, `xtask/`, `.github/workflows/`, `.github/actions/`, `rust-toolchain.toml`, `Cargo.toml` or `Cargo.lock`: the specs, the code whose traces it validates, or what defines the job.

## Scheduling-context donation (C12)

The protocol is in the kernel specification's [Passive servers and taking a context back](../docs/design/kernel-specification.md#passive-servers-and-taking-a-context-back). `crates/ksched`'s `donation` module is its one implementation, which the kernel runs over its objects.

| File | What it is |
|---|---|
| `SchedDonationCore.tla` | The state, one record `s`, and every action but the take-back's walk |
| `SchedDonationAtOnce.tla` | Take-back as one atomic step, walk included. Safety only |
| `SchedDonation.tla` | Take-back in bounded batches: the cut at once, then one walk step at a time, interleaved with everything else. The invariants, the properties, and the refinement `AO!Spec` |
| `SchedDonationTrace.tla` | Trace validation: the Rust's states must start at `Init` and move only by `Next` |
| `SchedDonation*.cfg` | The models below |

The objects are numbers: threads `1..NT`, reply objects `1..NR`, contexts `1..NS`, and `Nil` is 0. Context i starts bound to thread i. The other threads start as passive servers, each receiving on its own reply object.

### C14's extension: queued sends and faults

C14 extends the spec, behind the constant `WithQueue`, with what donation sees of an endpoint's queue. The queue itself, its order and its badges are C14's own spec's.

- **A queued send or call** (`SendWait`, state `"send"`) is delivered to any receiver as a call (`DeliverCall`), which donates as a call does, or as a send (`DeliverSend`), which ends both waits and leaves the receiver's reply object idle.
- **A queued fault** on the fault endpoint (`FaultWait`, fault kind `"endpoint"`) is delivered as a donating call; a timeout or context-withdrawn fault is delivered as a plain call. A delivered fault is a call whose caller has `flt` set. However it ends, by a reply, a cancel, a cut or a destruction, it ends with no result, and its reply object is left invalid if it didn't end by a reply. So the thread goes on as its fault's kind allows, which the spec doesn't model: it re-executes a faulting instruction, or goes on where its budget ran out once it has a refill, or stays without a context. A late reply from the handler fails with "no caller" (K50). With `WithQueue`, `FaultReplied` is off: a fault is delivered, then replied to.
- **The kernel's wakes** (`Wake`) end a send, a receive, a queued fault or a kept wait with "replied", "destroyed" or no result: a message or count came, the object was destroyed, or the sender restarts.
- **"Destroyed"** (K30): destroying a call's reply object, or the server its call donated to, ends the call "destroyed", not "canceled", in every model; so does destroying a receiver's reply object.

The C12 models set `WithQueue = FALSE` and explore the states they did, but for the destruction models, where "destroyed" now tells apart states that "canceled" merged.

### What each property checks

| Kernel specification bullet | Operator in `SchedDonation.tla` |
|---|---|
| Each context is bound to at most one thread, and a thread runs only on a context bound to it | `OneContextPerThread`, `HolderIsWhereTheContextIs`; every action that runs a thread requires `Runs` |
| Along a chain, the reply objects lead from the caller to the thread that holds the context; no context is lost or duplicated | `ChainWellFormed`, `RepliesAccountedFor`, `ServingWellFormed` |
| A canceled or timed-out caller gets its context back at once; a server's later reply fails with "no caller" and never reaches the caller | `ContextBackAtOnce`, `ReplyReachesOnlyItsCaller` |
| Each passive server left without a context gets one context-withdrawn fault, if it has a timeout endpoint | `StrandedGetWithdrawn` (at least one, written apart from the step that sends it), `WithdrawnOnlyByItsStep` (at most one), `OwedAreStranded` |
| A long chain followed in bounded batches ends in the same state as one followed at once | `Refinement` (`AO!Spec`, under `RunAll`), and `WalksEnd` |
| Suspend keeps the wait (ADR 0061, rule 3) | `SuspendOnlyFlags` |
| C14: a delivered fault ends with no result, however it ends, and is a call while it lasts | `FaultResumesSilently`, `WaitsWellFormed`; `ContextBackAtOnce` takes "destroyed" and a fault's empty result |

Two readings that the spec makes precise:

- **The walk decides when it reaches a server.** Whether a stranded server gets its fault depends on whether it has a timeout endpoint, and is still without a context, at that step.
- **The refinement holds where nothing interferes.** "Ends in the same state" is checked in the `Refine` model, where Cancel, Deadline and the destroys aren't enabled on a pending walk's objects. Those actions would be decided differently had the walk already passed. That model leaves SetTep and suspend out entirely: with SetTep it took over 6 minutes. The full interleaving is checked with the invariants, in the other models.

### The models and their times

Measured on 2026-11-27 on an Apple M-series machine, under `nice`, with 2 workers, as CI's runners give `cargo xtask tlc`.

| Model | Constants | What it adds | Distinct states | Time |
|---|---|---|---|---|
| `SchedDonation.cfg` | 3 threads, 2 replies, 1 context | Full interleaving: invariants, action properties, `WalksEnd` | 17,704 | 2 s |
| `SchedDonationTwo.cfg` | 3, 2, 2 contexts, two timeout endpoints | Non-donating calls, their replies and cancels, and two contexts at once | 152,300 | 16 s |
| `SchedDonationRefine.cfg` | 3, 2, 1, destruction | The refinement | 68,103 | 31 s |
| `SchedDonationDestroy.cfg` | 3, 2, 1, destruction | Destruction in full interleaving | 134,676 | 6 s |
| `SchedDonationSuspend.cfg` | 3, 2, 1 | Suspend, and setting and removing timeout endpoints | 1,880,416 | 69 s |
| `SchedDonationQueue.cfg` | 3, 2, 1, `WithQueue` | C14's queued sends and faults, their delivery and wakes: invariants, action properties, `FaultResumesSilently`, `WalksEnd` | 167,236 | 17 s |
| `SchedDonationTrace.cfg` | 4, 3, 2, every action, `WithQueue` | 100 traces of 80 steps from the Rust | 8,088 | 3 s |
| `SchedDonation.nightly.cfg` | 4, 3, 1, every action but `WithQueue` | Chains of three, nightly only | not measured here | at most 60 min, with the other five nightly models |
| `SchedDonationQueue.nightly.cfg` | 3, 2, 1, destruction, `SetTep`, `WithQueue` | Queued sends and faults with destruction and timeout endpoints set and removed, nightly only | not measured yet | to measure by hand once before nightly CI relies on it |
| `SchedDonationRefine.nightly.cfg` | 3, 2, 1, `WithQueue` | The refinement with queued sends and faults, nightly only | 162,316 | 71 s |

The donation models take about two and a half minutes on 2 workers, and a minute and a half on 4. With C14's models below, the whole per-change run takes about three and a quarter minutes on 2 workers, and 134 seconds on 4. Chains of two cover a cut in the middle of a chain, and two take-backs on one context while a walk is pending. If a model outgrows the budget, shrink its constants first, then move an action into a model of its own, as Suspend and SetTep are, and as `WithQueue` is: with it, the refinement model took 71 seconds without destruction, so it runs nightly.

A chain of three on one context, with every action but those two, took 5 minutes and 1.8 million distinct states with liveness. That is why it runs nightly.

## IPC endpoints (C14)

The protocol is in the kernel specification's [Endpoint operations and messages](../docs/design/kernel-specification.md#endpoint-operations-and-messages) and [IPC deadlines and cancellation](../docs/design/kernel-specification.md#ipc-deadlines-and-cancellation). `crates/kipc`'s `endpoint` module is its one implementation, which the kernel runs over its objects. It runs donation through `ksched::donation`, so this spec leaves contexts out: every thread runs on its own, and no call donates. `SchedDonation.tla`'s queue extension checks what donation sees of the queue.

| File | What it is |
|---|---|
| `IpcEndpoint.tla` | One endpoint: send, send without blocking, call, faults sent as calls, receive, reply, and reply and receive; cancels and deadlines; priority changes while queued; releasing a badge and canceling its sends; destroying the endpoint and reply objects. The invariants and the properties |
| `IpcEndpointTrace.tla` | Trace validation, as `SchedDonationTrace.tla`'s |
| `IpcEndpoint*.cfg` | The models below |

The state is one record `s`. Threads `1..NT` each send with a capability whose badge is `1 + (t - 1) % NB`. The queue `q` is the sequence of its threads in the order they are served. A thread joins it after every queued thread whose priority is at least its own: the Rust's tree order by priority, then arrival, without arrival numbers, so the state stays finite. `dbit` is the delivered bit a wait's end writes (K30), and `rw` whether a send was restarted at its `SVC` when its badge was released.

### What each property checks

| Kernel specification bullet, and the plan's additions | Operator in `IpcEndpoint.tla` |
|---|---|
| A call ends exactly once: with its reply, "canceled", "timed out", "object destroyed" or an error. A reply object answers at most one call | `CallEndsOnce` (a delivered call's end), `QueuedEndsOnce` (a queued call or send ends undelivered, or restarts at its `SVC`; a queued send ends "replied" only in a step a receive could have made, on the live endpoint with another running thread's result "replied", since the state doesn't record which action ran), `OneCallEndsPerStep` (no step, a reply's included, ends two delivered calls), `ReplyAnswersOne` (each pending reply object names its one caller, which waits on it) |
| Waiting senders and receivers are served in priority order, first come first served within a priority | `PriorityOrder` (every delivery takes the queue's head), `QueueWellFormed` (the queue is ordered by priority). First come first served within a priority is `Insert`'s definition, a thread joining after its equals, which no invariant checks, since the state keeps no arrival order: trace validation (`IpcEndpointTrace.cfg`) checks the Rust's order against it |
| A call's result says whether it was delivered; one ended before delivery was never seen | `CallEndsOnce` (the bit is set exactly for a delivered call that ended without its reply), `NeverSeenIfEndedFirst` |
| A fault ends with no result, and is never restarted at its `SVC` | `FaultSilent` |
| A released badge's sends: none joins again, and every queued one is canceled in the end | `NoJoinUnderRevoked`, `BadgeCancelEnds` |
| A destroyed endpoint releases every queued thread, one per step, and is gone in the end | `DrainedWhenGone`, `DrainEnds` |

### The models and their times

Measured as the donation models are.

| Model | Constants | What it adds | Distinct states | Time |
|---|---|---|---|---|
| `IpcEndpoint.cfg` | 3 threads, 2 reply objects, priorities 1 and 2, 1 badge | Every operation, with priorities that change while queued: invariants and action properties | 318,768 | 12 s |
| `IpcEndpointDestroy.cfg` | 3, 1, one priority, 2 badges, badges and destruction | Badges released and their sends canceled; the endpoint and its reply objects destroyed | 355,039 | 8 s |
| `IpcEndpointLife.cfg` | 2, 1, one priority, 2 badges, badges and destruction | Liveness: `DrainEnds`, `BadgeCancelEnds` | 9,817 | 1 s |
| `IpcEndpointTrace.cfg` | 4, 3, priorities 1 and 2, 2 badges, every action | 100 traces of 80 steps from the Rust | 8,100 | 2 s |
| `IpcEndpoint.nightly.cfg` | 3, 2, priorities 1 and 2, 2 badges, every action | Everything at once, nightly only | 7,781,240 | 5 min |

The nightly model was run once by hand at those constants, before `OneCallEndsPerStep` and `QueuedEndsOnce` were added: they add no states, but its time is still to be measured again.

## Eventcounts (C14)

The protocol is in the kernel specification's [Eventcount operations](../docs/design/kernel-specification.md#eventcount-operations), [Wait sets](../docs/design/kernel-specification.md#wait-sets) and [Threads bound to an eventcount](../docs/design/kernel-specification.md#threads-bound-to-an-eventcount). `crates/kipc`'s `eventcount` module is its one implementation.

| File | What it is |
|---|---|
| `Eventcount.tla` | Eventcounts with waits, advances from system calls and interrupts, and the work list's units; wait sets, with entries added and removed during waits; bound eventcounts, with receivers that lose and regain their contexts; cancels, deadlines and destruction. The invariants and the properties |
| `EventcountTrace.tla` | Trace validation, as `SchedDonationTrace.tla`'s |
| `Eventcount*.cfg` | The models below |

Waiters are nodes: thread t's is node t, and entry i of wait set w is node `NT + (w - 1) * NI + i`. A node is linked into an eventcount's waiters with a target, and the tree's order is by target, then node. `Max` stands for 2^64 - 1. A system call's advance is one step: the kernel holds its lock throughout, so nothing interleaves with it. How many reached waiters it wakes before its preemption point finds an interrupt pending is chosen, and the rest are left pending, as the Rust does (K31). `pending` is the mark that puts an eventcount on a work list, exactly once. `rp` flips at each report of a bound eventcount's advance to a thread, so a report is a visible step even when it would leave the rest of the state as it was; the trace's projection flips it at each advance the Rust reports. `PassiveRecv` is a receive made without a context, as a passive server's reply and receive makes it after its reply gives the donated context back. The trace's counts start `Max` below 2^64 - 1. Its waits and entries take targets from the count to two past it, so waiters gather just ahead of the count and an advance reaches several at once, and every fourth trace favors advances, so it reaches the Rust's real maximum. The `eventcount_traces` test counts the states with a pending eventcount and two or more reached waiters, the advances that reach two or more, and the traces that reach the maximum, and fails if a change to the harness loses them.

### What each property checks

| Kernel specification bullet, and the plan's additions | Operator in `Eventcount.tla` |
|---|---|
| An eventcount's count never decreases | `CountNeverDecreases` |
| An advance wakes every waiter whose target is at or below the count, and no other | `WakesOnlyReached` (no other), `NoLostWakeup` and `ReachedWoken` (every one: a reached waiter has a wake pending until it is woken) |
| A wait whose target is already reached returns at once, so no wake-up is lost between reading the count and waiting | `WaitReachedReturnsAtOnce`, `NoLostWakeup` |
| A system-call advance that reaches a preemption point adds one exactly once and is never restarted; its remaining wakes go to the work list (K31) | Not by TLC: the spec takes a system call's advance as one step by construction, so two advances would be two valid steps. `CountNeverDecreases` checks only that a step adds at most one. The guarantee is checked by `crates/kipc`'s host test `advance_preempted_queues_rest_once` and the in-QEMU test `ec_many_waiters_preempted` (count 1, no restart) |
| A wake batched for an interrupt reaches every waiter whose target the advance reached before the eventcount's pending mark clears | `NoLostWakeup`, `ReachedWoken`; `BatchUnit` clears the mark only with no reached waiter left |
| Revoking an eventcount capability, or deleting a wait-set entry's copy, removes that entry; a removal during a wait leaves the wait on the others, and the last one ends it with an empty mask (K08) | `EntriesWellFormed`, `WakesOnlyReached` (an empty mask only when an entry was removed in that step), `WsRemove` |
| One wait per wait set | `WsWait`'s guard, `s.waiter[w] = Nil`, checked by `WaitsWellFormed` (a thread is in `"wswait"` exactly when some set's waiter is it, so a second wait that took a set over would leave the first thread unaccounted for). `EntriesWellFormed` adds that a thread waits on at most one set, which only the trace model, with two sets, exercises |
| A bound eventcount's advance is reported once, never spuriously, and a receiver without a context is never woken by one | `NoSpuriousReport` (each report tells a count past last-seen, so none is repeated or made up, and last-seen moves only at a report, to the count it reports), `LastSeenBelowCount`, `PassiveNotWoken` (nothing is reported to a receiver without a context, and a receive made without one neither reports nor links), `WaitsWellFormed` (a receiver with a context is linked with target last-seen + 1) |
| A destroyed eventcount leaves its work list and keeps no waiter | `GoneClean` |

### The models and their times

| Model | Constants | What it adds | Distinct states | Time |
|---|---|---|---|---|
| `Eventcount.cfg` | 3 threads, 1 eventcount, maximum 2, destruction | Direct waits, both advances, the work list, cancels, deadlines and destruction, with liveness | 14,052 | 4 s |
| `EventcountSets.cfg` | 2, 2, one wait set of 2 entries, maximum 1, destruction | Wait sets: invariants and action properties | 119,614 | 6 s |
| `EventcountSetsLife.cfg` | 2, 1, one wait set of 2 entries, maximum 1, destruction | Liveness over wait sets: `ReachedWoken` with entry nodes | 4,715 | 2 s |
| `EventcountBound.cfg` | 2, 1, maximum 2, destruction | Bound eventcounts and passive receivers, with liveness | 95,223 | 8 s |
| `EventcountTrace.cfg` | 4, 2, two wait sets of 2 entries, maximum 12, every action | 100 traces of 80 steps from the Rust | 8,100 | 5 s |
| `EventcountSets.nightly.cfg` | 2, 2, one wait set of 2 entries, maximum 2, destruction | Wait sets up to a larger maximum, nightly only | 1,217,445 | 55 s |
| `EventcountBound.nightly.cfg` | 2, 2 eventcounts, maximum 2, destruction | Bound eventcounts over two eventcounts, nightly only | 2,726,164 before `rp` and `PassiveRecv`, which took the per-change model from 48,996 states to 95,223; not measured since | 71 s then |

Wait sets and bound eventcounts are checked in separate models: together, even at a maximum of 1, the state space passed 2 million states in two minutes. Liveness over the wait-set model's two eventcounts took three minutes, so `EventcountSetsLife.cfg` checks it over one eventcount. Trace validation checks steps and invariants only, never liveness. The nightly models were run once by hand at those constants, without liveness; `EventcountBound.nightly.cfg`'s run was of the spec before `rp` and `PassiveRecv`.

## Trace validation

The `donation_traces` test of `crates/ksched` runs seeded operations through `ksched::donation`, projects each state onto the spec's record, and, with `KSCHED_TRACE_OUT` set, writes them as the module `SchedDonationTraces`. TLC then checks that each trace starts at `InitState` and that each step is one of `Next`'s, or changes nothing. `Next` comes first in `TraceNext`, and the trace's state is compared with the state it makes: in the other order TLC v1.7.4 compares the trace's tuples with functions the spec built with `EXCEPT`, and can find an equal pair unequal, which C14's eventcount traces met. Deadlock checking stays on, so a step the spec doesn't allow stops the run. TLC reports a model with no initial state as no error, so an `ASSUME` checks that there are traces and that each starts at `InitState`, and `cargo xtask tlc` checks that TLC started every trace. This follows Cirstea and others, "Validating Traces of Distributed Programs Against TLA+ Specifications" (arXiv 2404.16075).

C14's traces are checked the same way. The `endpoint_traces` and `eventcount_traces` tests of `crates/kipc` run seeded operations through `kipc`'s modules, over a store that also runs `ksched::donation`, and, with `KIPC_TRACE_OUT_EP` and `KIPC_TRACE_OUT_EC` set, write the modules `IpcEndpointTraces` and `EventcountTraces`, which `IpcEndpointTrace.tla` and `EventcountTrace.tla` check. `KIPC_TRACES` and `KIPC_TRACE_STEPS` set their number and length. The state the capability layer keeps, such as whether an endpoint is draining or a badge was released, is recorded by the test as the kernel's capability operations would leave it.
