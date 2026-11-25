<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0004. Network transparency: scope and failure semantics

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

The founding requirement is that all resources are API calls that work transparently on local or remote resources. AEGIS made remote objects look local, but a remote failure then surfaced as a page fault in the middle of a memory access ([research §3.2](../research/aegis-domain-os.md#32-other-weaknesses)). Waldo et al. argue that latency, memory access, partial failure and concurrency stop remote objects from ever being indistinguishable from local ones.

## Decision

1. **Scope.** The architecture assumes many realms federated across the internet: IPv6 over UDP, NAT traversal, and realms as trust and administrative domains, like DCE cells. The first implementation and test environment is a single realm on one LAN.
2. **One API.** Naming and invocation are identical for local and remote objects: an ID resolves to a capability wherever the object lives.
3. **Failure is visible.** Every operation that may cross the network carries a deadline. Outcomes distinguish success, an application error, *unreachable* (the request was never delivered) and *indeterminate* (the request may have run). Requests carry IDs, so a server executes each request at most once and can replay its reply.
4. **Remote mapped objects** ([0005](0005-single-level-store.md)). If a page can't be fetched by its deadline, the kernel delivers a typed fault to the faulting thread's fault handler instead of blocking forever.
5. **Mechanism.** Each node runs a user-space network server that holds proxy endpoints for remote objects. The kernel knows nothing about the network. The authority in an object ID is the first location hint, and a location service tracks objects that move.

## Consequences

- Programs use one API but must handle distributed outcomes, so the IDL and its libraries must make that easy.
- Federation shapes identity, naming and trust from the start, even though early testing is LAN-only.
- Multi-node tests can run as several QEMU instances on a virtual network.

## References

- [Research notes §3.2](../research/aegis-domain-os.md#32-other-weaknesses)
- [Waldo, Wyant, Wollrath, Kendall, "A Note on Distributed Computing" (1994)](https://waldo.scholars.harvard.edu/publications/note-distributed-computing)
