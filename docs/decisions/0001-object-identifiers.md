<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0001. Object identifiers: 256 bits, self-certifying, no clock

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

ASPIS names every object a program can touch with an identifier: files, directories, processes, threads, endpoints, types, principals and nodes. The founding requirement is an identifier with an indexable, deterministic part and a part that is guaranteed to be globally unique.

AEGIS used 64-bit UIDs built from the top 32 bits of the system clock, a 4-bit counter and a 20-bit node ID ([research §2.1](../research/aegis-domain-os.md#21-objects-and-uids)). The clock's high word was declared as 31 bits, so it overflowed at 14:59:13 UTC on 2 November 1997. The workaround of setting clocks back risked duplicate UIDs and file-system corruption ([§3.1](../research/aegis-domain-os.md#31-the-2-november-1997-clock-rollover)). Node IDs came from hardware serial numbers, and nothing proved them.

Without coordination, uniqueness can only be probabilistic. A hard guarantee needs either a coordinating allocator, or an identifier bound to a key plus a registry that rejects duplicates.

## Decision

An ASPIS object ID is 32 bytes, big-endian, and every field is unsigned:

| Bytes | Field | Bits | Contents |
|---|---|---|---|
| 0–15 | authority | 128 | UUID of the node that minted the ID |
| 16–23 | sequence | 64 | That node's monotonic counter |
| 24 | version | 8 | ID format version; this record defines version 1 |
| 25–26 | class | 16 | Object class: file, directory, process, thread, endpoint, type, principal, node, realm, … |
| 27–31 | random | 40 | CSPRNG output chosen when the ID is minted |

The authority is the globally unique part. The sequence is the indexable, deterministic part.

1. **No field holds time.** Creation time is an ordinary attribute of the object.
2. **Comparison is bytewise.** IDs compare as 32-byte strings, which matches numeric order. No field is ever interpreted as signed.
3. **Authority.** A node's UUID is an RFC 9562 UUIDv8 whose 122 free bits are a truncated SHA3-256 hash over a domain-separated encoding of the node's genesis public key: the hybrid key bundle defined in [0003](0003-hybrid-post-quantum-cryptography.md). The genesis key only certifies operational keys, so operational keys rotate without changing the node's UUID. SHA-3 adds no new primitive, because ML-KEM and ML-DSA are already built on Keccak.
4. **Sequence.** Numbers are reserved in blocks. The node durably records the end of a block before issuing any number from it, and after a crash it resumes at the next block: gaps are allowed, reuse never is. Sequence numbers below 2^16 are reserved for well-known objects such as the node object and the node's root directory. A node that exhausts 2^64 mints a new genesis key and so a new authority; the counter never wraps.
5. **Random.** The 40 random bits keep IDs distinct if a node restored from a snapshot or a cloned disk reissues sequence numbers. A node that detects a restore or clone takes a new authority.
6. **Hard uniqueness.** The realm registry refuses to enroll an authority it already knows, so authorities are unique within a federation.
7. **Well-known system objects**, such as built-in types and interfaces, use a reserved ASPIS authority, so their IDs are identical on every node.
8. **IDs are names, not permissions.** See [0002](0002-capability-security-model.md).

The text form, the class registry and the exact hash encoding belong in the ID format specification that the design session produces.

## Consequences

- Clock resets, clock rollover and per-tick generation limits can no longer threaten identity.
- IDs sort cleanly and cluster by the node that minted them, so B-tree indexes fill sequentially.
- The authority doubles as the first hint for where an object lives; a location service tracks objects that have moved.
- The version byte lets the format change later.
- A reference costs 32 bytes instead of 16. The full ID isn't an RFC 9562 UUID, although its authority is one.
- An ID reveals which node minted it, in what order, and its class. That is acceptable only because IDs grant nothing.
- An object's class is fixed for its lifetime.

## References

- [Research notes §2.1, §3.1](../research/aegis-domain-os.md)
- [RFC 9562, Universally Unique IDentifiers](https://www.rfc-editor.org/rfc/rfc9562)
