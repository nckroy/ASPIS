<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0068. The fuzzing and differential-testing gate

- **Status:** Accepted
- **Date:** 2026-11-25, updated 2026-11-26

## Context

D32 asks which parsers must be fuzzed before their chunk counts as done, how the PDP is tested against Cedar, whether leases and catalog sequence numbers are model-checked, and how partitions are injected ([design backlog, D32](../design/design-backlog.md#m2-kernel-objects); [build plan](../design/build-plan.md), C71).

- Hostile input reaches every manager's JSON parsing and every decoder ([0015](0015-jwt-tokens-and-oidc-identity.md), Consequences; [0010](0010-svg-core-primitive.md), rule 11), but grammars are checked only against test vectors ([0013](0013-abnf-for-protocols-and-calls.md), rule 6).
- The initial image's parser and the kernel arguments' are already named targets ([0037](0037-initial-image-format-and-contents.md), rule 2; [0041](0041-boot-abi.md), rule 5).
- The kernel's assurance comes from testing, fuzzing, model checking of its concurrent protocols' designs (rule 10) and Rust's memory safety, not proofs ([0047](0047-the-kernel-follows-sel4.md), Consequences).

The project owner decided disclosure on 2026-11-25: public CI until ASPIS's first release; after it, short-lived crash artifacts, a private advisory, and long campaigns on a private fork or runner. The owner also accepted a default that Claude proposed: from then on, public nightly logs give only a crash count and crash artifacts are encrypted. The other choices here, such as fuzzing on stable Rust only and TLA+ with TLC, are defaults that Claude proposes in this record. Claude drafted it from the owner's decisions.

On 2026-11-26 the project owner extended rule 10 from leases and catalog sequence numbers to the kernel's concurrent protocols. C11's preemptible revoke and delete needed a redesign of its derivation tree during review before its model-based tests passed, and the protocols of C12, C14 and C15 interleave more than C11's do.

Checked on 2026-11-25: cargo-fuzz with `--sanitizer none` needs no nightly feature, and Rust's sanitizers aren't stable. No accepted record was edited with this one. The [call-language specification](../design/call-language.md#the-fuzzing-gate) gives the tables, limits and properties behind each rule.

## Decision

1. **A parser at a trust boundary isn't done until it passes the gate.** Its input comes from another principal, the network, removable media, the boot command line, or a publisher through the catalog. Its chunk brings its targets, and its pull request records the pass. Boot-information records and the device tree are trusted on the boot path; their targets are optional.
2. **Engine and toolchain.** cargo-fuzz and libFuzzer, with `--sanitizer none`, on the pinned stable toolchain only ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 1).
   - With no sanitizers, **every crate that parses input from across a trust boundary is `#![forbid(unsafe_code)]`**, every IDL-generated interface crate included. The `unsafe` glue to the kernel interface library lives in `aspis-rt`, and parses nothing ([0059](0059-the-kernel-interface-library.md), rule 8).
   - The oracle is panics, overflow checks and debug assertions. Fuzz-only hooks sit behind `cfg(fuzzing)`, never a Cargo feature ([0036](0036-qemu-configuration-and-test-builds.md), rule 6).
   - If libFuzzer fails on the pinned toolchain, afl.rs takes its place, and the gate is unchanged.
   - A tool that only runs in CI, and is never linked into ASPIS code or shipped, is outside [0008](0008-mpl-2.0-license.md), rule 4. That covers libFuzzer's NCSA license and the JRE that runs TLC.
3. **Layout.** `fuzz/` is a separate Cargo workspace, so fuzz dependencies never enter the product lock file, the images or the SBOM ([0038](0038-reproducible-builds-and-provenance.md)). Targets, seeds and minimized regressions are committed; every vector line is also a seed; the growing corpus is never committed or in iCloud.
4. **Which parsers.** The specification lists each trust-boundary parser and its chunk, every IDL-generated decoder included ([Trust-boundary parsers](../design/call-language.md#trust-boundary-parsers)). A later parser that meets rule 1 joins with its chunk. For a third-party parser, the chunk fuzzes ASPIS's wrapper, and the crate itself unless it is fuzzed upstream.
5. **The gate for each target** ([details](../design/call-language.md#the-gate-for-each-target)):
   - no panic or abort, within time and memory bounds, on inputs up to the format's limit plus 1 KiB;
   - round trips both ways where an encoder exists, since ASPIS encodings are canonical;
   - the decoder accepts exactly what its grammar and constraints accept, where a grammar exists;
   - seeds include every vector line, and every error kind is reached;
   - at least 1 CPU-hour of cumulative fuzzing with no open finding, and a coverage report reviewed in the chunk's pull request;
   - every parse is deterministic and linear, with a depth limit on any recursion.
6. **Differential tests** compare decoders with their grammars, the two ABNF checkers, names with Cedar's parser and RFC 6749's `scope-token`, messages across both network servers' translation, old minors with new, the JSON encoder with a reference parser, and the PDP with Cedar ([details](../design/call-language.md#differential-tests)).
7. **Per change**, CI builds every target, replays seeds, regressions and the cached corpus, and fuzzes each target whose crates changed, within a fixed time box. `cargo xtask test` replays seeds and regressions without libFuzzer. Later chunks add PDP cases, TLC and a partition smoke test ([details](../design/call-language.md#per-change)).
8. **Nightly**, every target runs for a fixed time on a merged, cached corpus, beside the differentials, TLC, the kernel-call fuzzer and the partition campaign. Each job has a time limit ([Nightly](../design/call-language.md#nightly)).
9. **The PDP is tested against Cedar's own engine** (C32), on generated realms written into a real authorization tree with a signed root. ASPIS's PDP and the pinned `cedar-policy` authorizer, given the same model without the tree, must agree on each decision and its determining policies; errors deny; and a root older than the bound never allows ([0016](0016-authorization-sparse-merkle-tree.md), rule 7). Every generated schema fragment validates in Cedar ([details](../design/call-language.md#the-pdp-against-cedar)).
10. **Concurrent protocols are model-checked**, in TLA+ with TLC, from specs in `specs/`. Each spec comes with the chunk whose protocol it models, and TLC passes it, with CI-sized constants, in that chunk's pull request:
    - scheduling-context donation along chains of calls, and taking a canceled or timed-out caller's context back ([0051](0051-scheduling-timers-and-deadlines.md), rule 3; [0054](0054-ipc-endpoints.md), rule 6), with C12;
    - IPC calls, replies and cancels, and eventcount advances and waits ([0054](0054-ipc-endpoints.md); [0053](0053-eventcounts.md)), with C14;
    - the pager protocol, with fetch deadlines, eviction and decommit ([0057](0057-memory-objects-and-the-pager-protocol.md), rules 5 to 8; [0056](0056-faults-and-page-fetch-deadlines.md)), with C15;
    - leases ([0028](0028-discovery-and-realm-catalog.md), rule 5), with C40 and C50;
    - catalog sequence numbers and list-then-watch (ADR 0028, rule 6), with C51.

    The specifications give the properties: the [kernel specification](../design/kernel-specification.md#model-checking) for the kernel's protocols, and the [call-language specification](../design/call-language.md#model-checking) for the rest. The reply cache, export reference counting, and C11's preemptible delete and revoke are recommended, not required.
11. **The kernel-call fuzzer** runs nightly once the kernel interfaces' IDL (C07) and the interface library (C17) exist, in a test build on QEMU. It generates call sequences from the kernel interfaces' IDL, through the interface library ([0059](0059-the-kernel-interface-library.md), rule 4). The kernel never panics; every call returns a result or a typed error; [0047](0047-the-kernel-follows-sel4.md), rule 6's invariants hold after every call; faults are [0056](0056-faults-and-page-fetch-deadlines.md)'s typed faults. It doesn't block per-change CI.
12. **Partitions are injected** from C40, by an unprivileged host-side switch between QEMU nodes, on a seeded schedule of partitions, loss, delay, reordering, pauses and crashes. From each operation's logged outcome, host checkers verify that no request ran twice; that every success ran and every unreachable didn't ([0004](0004-network-transparency-and-failure.md), rule 3); that new binds fail closed once the root is stale ([0016](0016-authorization-sparse-merkle-tree.md), rule 7); and that revocation ends every session and proxy derived from it ([0066](0066-capability-parameters-and-server-streams.md), rule 5).
13. **Triage and disclosure** (the owner's decision).
    - A fix commits the finding's minimized input as a regression, replayed on every change. A finding that doesn't reproduce is itself a bug.
    - Until ASPIS's first release, fuzzing runs in public CI, and findings are fixed in the open.
    - From the first release, findings go into a private security advisory ([SECURITY.md](../../SECURITY.md)), and long campaigns run on a private fork or runner. The public nightly's log names only the target and its crash count. The crash input and backtrace are encrypted to the triagers' keys, and kept only briefly ([Triage and disclosure](../design/call-language.md#triage-and-disclosure)).

## Consequences

- **D32 is settled**: rules 1, 4 and 5 say which parsers, rule 9 how the PDP is tested, rule 10 which protocols are model-checked, and rule 12 how partitions are injected.
- **A parser's chunk costs more**: targets, an hour of fuzzing and a review.
- **Fuzzing can't find memory errors in `unsafe` code**, so parsers have none. The kernel's and `aspis-rt`'s rely on the kernel-call fuzzer and the test build's invariants.
- **Cedar's engine is trusted.** The differential aims at ASPIS's integration around it, where ASPIS adds risk.
- **A kernel chunk with a concurrent protocol costs more too**: a TLA+ spec of its design, checked before the chunk is done. TLC checks the model, not the Rust, so the chunk's tests check, on the runs they make, that the code takes only the spec's steps.
- **CI gains a JVM**, for the model-checking jobs only.
- **After the first release**, a crash's existence and target are public until it is fixed. Running the nightly fuzz shards privately would close that, at the cost of public results.
- **libFuzzer works on the pinned toolchain.** C71 fuzzed every target with it on aarch64 macOS, and built, ran and replayed it on aarch64 Linux ([L35](../design/call-language.md#l35-fuzzing-on-stable-rust)), so afl.rs isn't used.
- **Still open, in the specification:** coverage thresholds ([L36](../design/call-language.md#l36-coverage-thresholds)), the TLA+ specs ([L37](../design/call-language.md#l37-the-tla-specs)), clock-skew injection ([L38](../design/call-language.md#l38-clock-skew-injection)), third-party parsers ([L39](../design/call-language.md#l39-third-party-parsers)), and kernel coverage, Kani and OSS-Fuzz ([L40](../design/call-language.md#l40-kernel-coverage-kani-and-oss-fuzz)).

## References

- [The call language: the fuzzing gate](../design/call-language.md#the-fuzzing-gate)
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz); [libFuzzer](https://llvm.org/docs/LibFuzzer.html); [afl.rs](https://github.com/rust-fuzz/afl.rs); [rust-lang/rust#123617](https://github.com/rust-lang/rust/issues/123617) (stabilizing sanitizers)
- [TLA+ tools releases](https://github.com/tlaplus/tlaplus/releases) (v1.7.4; v1.8.0 is still a prerelease, last built 2026-11-26)
- [Cedar](https://github.com/cedar-policy/cedar); [cedar-spec](https://github.com/cedar-policy/cedar-spec) (Cedar's own differential testing)
- [age](https://github.com/FiloSottile/age)
- [RFC 6749, The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749), §3.3
