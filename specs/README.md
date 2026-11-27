<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# TLA+ specs

*2026-11-26. The TLA+ specs of the kernel's concurrent protocols ([0068](../docs/decisions/0068-the-fuzzing-and-differential-testing-gate.md), rule 10), checked with TLC v1.7.4 as the [call-language specification](../docs/design/call-language.md#model-checking) says. Their properties are the [kernel specification](../docs/design/kernel-specification.md#model-checking)'s.*

Each spec comes with the chunk whose protocol it models. C12's is scheduling-context donation. C14's (IPC and eventcounts) and C15's (the pager protocol) are still to be written.

## Running them

`cargo xtask tlc` runs every per-change model below, then trace validation, within one budget of 10 minutes. `cargo xtask tlc --nightly` adds the nightly model and longer traces, within 60 minutes; it runs in `nightly.yml`, never in a build workflow.

- xtask fetches `tla2tools.jar` into `build/tla/` and checks its pinned SHA-256 first.
- It copies the specs into `build/tla/run/` and runs TLC there, so TLC's state files never land in `specs/`.
- TLC gets at most min(4, cores / 2) workers, at low priority (`nice -n 10`).
- It needs a JRE, 11 or later. CI uses the Temurin 21 that GitHub's runner image preinstalls.

CI's `tlc` job runs it when a change touches `specs/`, `crates/ksched/`, `xtask/`, `.github/workflows/`, `.github/actions/`, `rust-toolchain.toml`, `Cargo.toml` or `Cargo.lock`: the specs, the code whose traces it validates, or what defines the job.

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

### What each property checks

| Kernel specification bullet | Operator in `SchedDonation.tla` |
|---|---|
| Each context is bound to at most one thread, and a thread runs only on a context bound to it | `OneContextPerThread`, `HolderIsWhereTheContextIs`; every action that runs a thread requires `Runs` |
| Along a chain, the reply objects lead from the caller to the thread that holds the context; no context is lost or duplicated | `ChainWellFormed`, `RepliesAccountedFor`, `ServingWellFormed` |
| A canceled or timed-out caller gets its context back at once; a server's later reply fails with "no caller" and never reaches the caller | `ContextBackAtOnce`, `ReplyReachesOnlyItsCaller` |
| Each passive server left without a context gets one context-withdrawn fault, if it has a timeout endpoint | `StrandedGetWithdrawn` (at least one, written apart from the step that sends it), `WithdrawnOnlyByItsStep` (at most one), `OwedAreStranded` |
| A long chain followed in bounded batches ends in the same state as one followed at once | `Refinement` (`AO!Spec`, under `RunAll`), and `WalksEnd` |
| Suspend keeps the wait (ADR 0061, rule 3) | `SuspendOnlyFlags` |

Two readings that the spec makes precise:

- **The walk decides when it reaches a server.** Whether a stranded server gets its fault depends on whether it has a timeout endpoint, and is still without a context, at that step.
- **The refinement holds where nothing interferes.** "Ends in the same state" is checked in the `Refine` model, where Cancel, Deadline and the destroys aren't enabled on a pending walk's objects. Those actions would be decided differently had the walk already passed. That model leaves SetTep and suspend out entirely: with SetTep it took over 6 minutes. The full interleaving is checked with the invariants, in the other models.

### The models and their times

Measured on 2026-11-26 on an Apple M-series machine, 4 workers, under `nice`.

| Model | Constants | What it adds | Distinct states | Time |
|---|---|---|---|---|
| `SchedDonation.cfg` | 3 threads, 2 replies, 1 context | Full interleaving: invariants, action properties, `WalksEnd` | 17,704 | 2 s |
| `SchedDonationTwo.cfg` | 3, 2, 2 contexts, two timeout endpoints | Non-donating calls, their replies and cancels, and two contexts at once | 152,300 | 14 s, 2 workers |
| `SchedDonationRefine.cfg` | 3, 2, 1, destruction | The refinement | 52,576 | 16 s |
| `SchedDonationDestroy.cfg` | 3, 2, 1, destruction | Destruction in full interleaving | 102,460 | 3 s |
| `SchedDonationSuspend.cfg` | 3, 2, 1 | Suspend, and setting and removing timeout endpoints | 1,880,416 | 40 s |
| `SchedDonationTrace.cfg` | 4, 3, 2, every action | 100 traces of 80 steps from the Rust | 8,100 | 2 s |
| `SchedDonation.nightly.cfg` | 4, 3, 1, every action | Chains of three, nightly only | not measured here | at most 60 min |

The per-change total is about a minute. Chains of two cover a cut in the middle of a chain, and two take-backs on one context while a walk is pending. If a model outgrows the budget, shrink its constants first, then move an action into a model of its own, as Suspend and SetTep are.

A chain of three on one context, with every action but those two, took 5 minutes and 1.8 million distinct states with liveness. That is why it runs nightly.

### Trace validation

The `donation_traces` test of `crates/ksched` runs seeded operations through `ksched::donation`, projects each state onto the spec's record, and, with `KSCHED_TRACE_OUT` set, writes them as the module `SchedDonationTraces`. TLC then checks that each trace starts at `InitState` and that each step is one of `Next`'s, or changes nothing. Deadlock checking stays on, so a step the spec doesn't allow stops the run. TLC reports a model with no initial state as no error, so an `ASSUME` checks that there are traces and that each starts at `InitState`, and `cargo xtask tlc` checks that TLC started every trace. This follows Cirstea and others, "Validating Traces of Distributed Programs Against TLA+ Specifications" (arXiv 2404.16075).
