<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0003. Hybrid post-quantum cryptography

- **Status:** Accepted
- **Date:** 2026-11-24, updated 2026-11-27

## Context

The founding requirement is that RPC between nodes be secured with modern, lattice-based, quantum-resistant cryptography. ML-KEM (FIPS 203) and ML-DSA (FIPS 204) are the lattice standards, final since August 2024 ([research §4.2](../research/aegis-domain-os.md#42-post-quantum-cryptography)). They are young compared with elliptic-curve cryptography, and the Rust implementations are all pre-1.0. A hybrid construction stays secure as long as either of its halves does.

## Decision

1. **Key establishment:** X25519 + ML-KEM-768. Both shared secrets feed the key derivation, so a session stays secret if either half holds.
2. **Signatures and identity keys:** Ed25519 + ML-DSA-65 as a composite. A signature is valid only if both halves verify. A node's genesis key ([0001](0001-object-identifiers.md)) is such a composite.
3. **Hashing and key derivation:** the SHA-3 family (SHA3-256, SHAKE256), for constructs ASPIS defines. Standard protocols keep the hashes they specify: TLS 1.3's key schedule uses SHA-256 or SHA-384, and RFC 10073 pre-hashes with SHA-512 ([0020](0020-realm-certificate-authority.md)).
4. **Bulk encryption:** ChaCha20-Poly1305 by default, because the first board ([0007](0007-initial-hardware-targets.md)) lacks the ARMv8 AES instructions, and ChaCha20 is fast and constant-time in software. AES-256-GCM can be negotiated where hardware AES exists. Every key that protects secrets is 256 bits. Standard protocols keep the ciphers they mandate for keys derived from public values, as rule 3 lets them keep their hashes. QUIC v1 protects its Initial packets and its Retry integrity tag with AES-128-GCM, and the header of an Initial packet with AES-128 (RFC 9001, sections 5.2, 5.4 and 5.8). Those keys come from the connection ID or from the RFC itself, so they guard against corruption, not eavesdropping. Every other packet uses the negotiated suite.
5. **Crypto agility:** every handshake, key record and signature carries algorithm identifiers. Suites can then be added (ML-KEM-1024 and ML-DSA-87 for CNSA 2.0 deployments; FN-DSA or HQC once standardized) or retired (the classical half, once confidence in the lattice schemes is established).
6. **No cryptography in the kernel.** It runs in user-space servers: the network server and a key service.
7. **Libraries:** set by [0069](0069-cryptography-libraries.md). RustCrypto and dalek supply the primitives, wrapped by one crate, `aspis-crypto`. Cryspen's libcrux checks them, as the fuzz workspace's differential oracle.

## Consequences

- Handshakes are large. An ML-DSA-65 signature (3,309 bytes) exceeds the 1,280-byte IPv6 minimum MTU on its own, so handshakes must fragment. RPC authenticates with TLS 1.3 and composite certificates ([0020](0020-realm-certificate-authority.md), rule 3), so its handshakes carry signatures. Authenticating with key exchange instead (TLS AuthKEM) can be added through crypto agility if it is standardized.
- Each identity has two key pairs, and a handshake costs more computation than a classical one.
- Security survives a break of either the classical or the lattice half.

## References

- [Research notes §4.2](../research/aegis-domain-os.md#42-post-quantum-cryptography)
- [FIPS 203, ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204, ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [0069](0069-cryptography-libraries.md), the libraries
