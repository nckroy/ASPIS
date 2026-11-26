<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0002. Capabilities in the kernel; object IDs are names

- **Status:** Accepted
- **Date:** 2026-11-24, updated 2026-11-25

## Context

AEGIS checked access control lists against three-part principals such as `user.none.none` ([research §2.6](../research/aegis-domain-os.md#26-protection-and-identity)). A microkernel needs an authority model that is small, fast and analysable, that avoids ambient authority (the root of confused-deputy bugs), and that supports delegation. ASPIS also needs authority that works across nodes.

## Decision

1. **The kernel uses capabilities only.** Every kernel operation goes through a capability: an unforgeable handle in the calling process's capability space that names a kernel object (address space, thread, endpoint, eventcount, memory object, interrupt, …) together with a set of rights. Capabilities can be copied with fewer rights, passed over IPC and revoked. seL4 is the reference model.
2. **IDs grant nothing.** Holding or guessing an object ID ([0001](0001-object-identifiers.md)) gives no access.
3. **Binding to an object.** A process asks the object's manager to bind it to an ID ([0014](0014-versioned-object-apis.md), rule 4). The manager is the object's type manager, or the name service for directories. The manager checks policy (the object's ACL and the caller's authenticated principal) and returns a capability to an endpoint or memory object.
   - Permissions live in the realm's authorization tree ([0016](0016-authorization-sparse-merkle-tree.md), rule 1). An object's ACL is the set of grants under that object's branch.
   - Managers read permissions from the tree rather than storing them privately.
4. **Principals** (people, groups, services and nodes) are objects with IDs and post-quantum keys, kept in the realm registry. ACL entries name principals by ID.
5. **Across nodes, raw capabilities never travel.** The network server ([0004](0004-network-transparency-and-failure.md)) gives the local process a capability to a proxy endpoint and authenticates to the remote node with the node's key. Authority that a party will exercise under its own binding is delegated across nodes with JWTs ([0015](0015-jwt-tokens-and-oidc-identity.md)); a capability passed as a call parameter crosses as a proxy that routes back through the exporting node ([0066](0066-capability-parameters-and-server-streams.md), rule 4).

## Consequences

- The kernel contains no ACL parsing, no principal database and no policy.
- Least privilege and delegation follow from the capability rules.
- Developers have two layers to understand, capabilities and ACLs, so the documentation must explain both clearly.
- Revocation and cross-node delegation need careful design.

## References

- [Research notes §2.6](../research/aegis-domain-os.md#26-protection-and-identity)
- [seL4](https://sel4.systems/)
