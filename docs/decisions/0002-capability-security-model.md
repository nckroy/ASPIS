<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->

# 0002. Capabilities in the kernel; object IDs are names

- **Status:** Accepted. Amended by [0015](0015-jwt-tokens-and-oidc-identity.md) (rule 5) and [0016](0016-authorization-sparse-merkle-tree.md) (rule 3).
- **Date:** 2026-11-24

## Context

AEGIS checked access control lists against three-part principals such as `user.none.none` ([research §2.6](../research/aegis-domain-os.md#26-protection-and-identity)). A microkernel needs an authority model that is small, fast and analysable, that avoids ambient authority (the root of confused-deputy bugs), and that supports delegation. ASPIS also needs authority that works across nodes.

## Decision

1. **The kernel uses capabilities only.** Every kernel operation goes through a capability: an unforgeable handle in the calling process's capability space that names a kernel object (address space, thread, endpoint, eventcount, memory object, interrupt, …) together with a set of rights. Capabilities can be copied with fewer rights, passed over IPC and revoked. seL4 is the reference model.
2. **IDs grant nothing.** Holding or guessing an object ID ([0001](0001-object-identifiers.md)) gives no access.
3. **Opening an object.** A process asks the object's manager to open an ID: its type manager, or the name service for directories. The manager checks policy (the object's ACL and the caller's authenticated principal) and returns a capability to an endpoint or memory object.
4. **Principals** (people, groups, services and nodes) are objects with IDs and post-quantum keys, kept in the realm registry. ACL entries name principals by ID.
5. **Across nodes, raw capabilities never travel.** The network server ([0004](0004-network-transparency-and-failure.md)) gives the local process a capability to a proxy endpoint and authenticates to the remote node with the node's key. How authority is delegated across nodes (signed tokens or similar) is a design-session item.

## Consequences

- The kernel contains no ACL parsing, no principal database and no policy.
- Least privilege and delegation follow from the capability rules.
- Developers have two layers to understand, capabilities and ACLs, so the documentation must explain both clearly.
- Revocation and cross-node delegation need careful design.

## References

- [Research notes §2.6](../research/aegis-domain-os.md#26-protection-and-identity)
- [seL4](https://sel4.systems/)
