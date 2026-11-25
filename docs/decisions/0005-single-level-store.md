<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0005. Single-level store as the primary I/O model

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

AEGIS's defining feature was the single-level store: objects were mapped into address spaces, a global address was a UID plus an offset, and streams were layered on top of mapping ([research §2.2](../research/aegis-domain-os.md#22-single-level-store)). Microkernels achieve the same with user-space pagers: Mach's external pagers, seL4's user-level paging, Fuchsia's VMOs and pagers.

## Decision

1. **Mapping is the primary way to access data.** A process maps an object, through a capability, into an address space. A global address is an object ID plus a byte offset.
2. **Pagers run in user space.** The kernel forwards a page fault on a mapped object to that object's pager over IPC. The pager supplies the page from local storage, or from a remote node through the network server.
3. **Streams and messages remain** for devices, pipes and RPC. Byte-stream read/write APIs are library code over mapping where that fits, as AEGIS layered streams on mapping.
4. **Coherence** for shared remote objects uses leases or tokens with explicit semantics, not AEGIS's mandatory implicit locks. The protocol is a design-session item.
5. **Failure** behavior follows [0004](0004-network-transparency-and-failure.md).

## Consequences

- The virtual-memory subsystem and the pager protocol are early, critical work.
- Files, persistent data structures and remote objects share one access path.
- Remote failure has to be handleable at fault time.

## References

- [Research notes §2.2](../research/aegis-domain-os.md#22-single-level-store)
