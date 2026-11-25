<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0016. Authorization store: a sparse Merkle tree, revoked by branch

- **Status:** Accepted. Amends [0002](0002-capability-security-model.md), rule 3. Amended by [0018](0018-cedar-policy-language.md) (rule 1) and [0019](0019-authzen-decision-protocol.md) (rule 6).
- **Date:** 2026-11-24

## Context

The brief: permissions (authorization) across the network-transparent environment are stored in a sparse Merkle tree, and revoking permissions means marking the relevant branch of the tree as revoked.

A sparse Merkle tree is a Merkle tree over a key space too large to store, here 2^256 leaves, almost all of them empty.

- Empty subtrees have predictable hashes, so the tree is cheap to keep.
- A single root hash commits to the whole map.
- Anyone holding a signed root can check short proofs that a key is present or absent.

Prior art:

- Laurie and Kasper proposed this structure for certificate revocation ("Revocation Transparency", 2012).
- Google's Trillian verifiable map is the same structure.
- A 2026 IETF draft builds on it for revocation lists.
- Dahlberg, Pulls and Peeters (2016) showed that proofs can be produced in roughly constant time with a modest cache.

The [authorization tree design note](../design/authorization-tree.md) covers this in detail.

## Decision

1. **Permissions live in the tree.** Each realm keeps every grant of access to an object in an authorization tree: a sparse Merkle tree with 256-bit keys, hashed with SHA3-256.
   - An object's ACL is the set of grants under that object's branch.
   - Managers read permissions from the tree rather than storing them privately. This amends rule 3 of [0002](0002-capability-security-model.md).
2. **Branches are revocation units.** Keys are laid out so that things revoked together share a prefix. The strawman, to be refined in the design session, has two trees:
   - a **grant tree**, keyed by object and then by delegation path. One branch holds every grant on an object, and each grant's branch holds everything delegated from it.
   - a **principal tree**, keyed by principal ID. Each principal is a leaf. Principal IDs begin with the authority that minted them ([0001](0001-object-identifiers.md)), so a single branch holds every principal a given node or service minted.
3. **Revoking marks a branch.**
   - Revocation replaces the subtree at a prefix with a revoked marker whose hash commits to the prefix and the epoch.
   - A proof for any key under that prefix ends at the marker, so revocation is cheap to prove.
   - Revocation is permanent: restoring access means issuing new grants under new keys.
   - The realm's audit log records what each marker removed.
4. **Signed roots, ordered by epoch.**
   - The realm's authorization service applies changes in batches.
   - Each batch produces a new root, numbered with a 64-bit unsigned epoch and signed with the realm's key ([0003](0003-hybrid-post-quantum-cryptography.md)).
   - Epochs, not clocks, order the tree's history.
5. **Every node keeps a replica.**
   - Nodes hold the realm's tree, or the branches they need, and follow the signed roots.
   - A manager checks grants against its replica when a client binds ([0014](0014-versioned-object-apis.md)).
   - A client may also attach a proof and a signed root to its token.
6. **Revocation reaches live sessions.**
   - Access tokens ([0015](0015-jwt-tokens-and-oidc-identity.md)) name the grant keys they rely on.
   - When a new root revokes a branch, managers end the sessions and revoke the kernel capabilities derived from grants under it.
7. **Partitions fail closed.** If a node's newest signed root is older than a policy bound, its managers refuse any new bind they can't confirm. Existing sessions last no longer than their tokens.
8. **One tree per realm.** Each realm keeps its own trees. A grant from another realm is checked against that realm's signed roots, which are trusted through OpenID Federation ([0015](0015-jwt-tokens-and-oidc-identity.md)).

## Consequences

- **Revocation is cheap and provable.** It is one cheap operation, anyone holding the new root can verify it, and it reaches every node with the next root. That removes bearer tokens' weakness of staying valid until they expire.
- **New critical infrastructure.** The authorization service and root distribution must be replicated. Subtrees can be sharded by prefix if one writer isn't enough.
- **Key layout sets limits.** It caps delegation depth and fan-out, so wide sharing goes through groups.
- **Safety over availability during a partition.** New binds wait until a fresh root arrives.
- **POSIX mode bits** ([0012](0012-posix-compatibility-layer.md)) become a view of the object's grant branch.

## References

- [Authorization tree design note](../design/authorization-tree.md)
