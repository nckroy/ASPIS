<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0021. Entropy: no key before the generator is seeded

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

The tenet: where in the OS's initialization lifecycle the first certificates are minted decides how much entropy is available when they are, so sufficient entropy, with blocking until there is enough, is a core concern.

Accepted decisions constrain how this works:

- a node mints its permanent genesis key, and so its UUID, at first boot ([0001](0001-object-identifiers.md));
- cryptography runs in user-space servers, never in the kernel ([0003](0003-hybrid-post-quantum-cryptography.md), rule 6);
- the boot stub already collects a seed from `EFI_RNG_PROTOCOL` where the firmware offers one ([0006](0006-uefi-boot-image.md), rule 4);
- the first targets are QEMU `virt` and the Raspberry Pi 4 ([0007](0007-initial-hardware-targets.md));
- a realm's first certificates are minted when the realm is created, and a node's first certificate when it first enrolls ([0020](0020-realm-certificate-authority.md)).

Facts this decision relies on (details and sources in the [design note](../design/entropy-and-first-keys.md)):

- **Seeding.** NIST SP 800-90C (final, September 2025) requires at least 3*s*/2 bits of min-entropy to instantiate a DRBG at security strength *s*, and at least *s* bits to reseed one.
- **Classes of RBG.** SP 800-90C distinguishes an RBG2(P) construction, seeded from a physical source, from an RBG2(NP), seeded from a non-physical source such as jitter.
- **Strength.** FIPS 203 and FIPS 204 require an approved RBG of at least 192-bit strength for ML-KEM-768 and for ML-DSA-65 key generation.
- **The risk is real.** In 2012, keys that headless devices generated at first boot, before their generators had enough entropy, exposed the private keys of 0.50% of TLS hosts.
- **Sources on the first targets.**
  - QEMU offers virtio-rng and, under TCG, `RNDR`.
  - The Pi 4 has a hardware generator in its SoC, but its Cortex-A72 cores have no FEAT_RNG.
  - On both, EDK2 can provide a seed through `EFI_RNG_PROTOCOL`.

## Decision

1. **Each node has one generator, in user space.**
   - An entropy service, which the root server starts first, holds the node's root DRBG at a security strength of 256 bits. That is above the 192 bits that FIPS 203 and 204 require for [0003](0003-hybrid-post-quantum-cryptography.md)'s parameter sets.
   - The service is the only source of randomness for ASPIS code.
   - The kernel holds no generator. It hands the stub's seed to the entropy service and keeps no copy.
2. **Nothing is served until the generator is seeded.**
   - The service answers no request until its DRBG has been instantiated with at least 384 bits (3*s*/2) of credited min-entropy.
   - Until then requests wait. No request gets weaker output instead.
   - Once the gate opens, the service never blocks again. Each reseed adds at least 256 bits.
3. **Nothing needs randomness before the gate.**
   - The boot stub uses the firmware's seed only for what it does itself.
   - The kernel uses no randomness.
   - Objects that exist before the gate are the node's well-known objects, named from [0001](0001-object-identifiers.md)'s reserved sequence range.
4. **Only justified estimates are credited.**
   - **Hardware generators that ASPIS drivers read** (virtio-rng, the Pi 4's SoC generator, and `RNDRRS` where the CPU has FEAT_RNG) are physical sources. Each is credited at its estimated rate once SP 800-90B health tests pass on its output.
   - **The firmware's seed** is credited only up to a limit set for each platform. ASPIS can't test it, so it never counts as the physical source that rule 5 requires.
   - **CPU timing jitter** is a non-physical source. It is credited only at a rate measured on that platform.
   - **A persisted seed, and entropy an operator supplies,** are mixed in but never credited.
5. **Long-lived keys need a physical source and prediction resistance.**
   - This covers genesis keys ([0001](0001-object-identifiers.md)), CA keys ([0020](0020-realm-certificate-authority.md)), federation keys ([0017](0017-openid-federation-membership.md)) and the tree-signing key ([0016](0016-authorization-sparse-merkle-tree.md)).
   - They are generated only when a physical source has contributed to the DRBG's state, as SP 800-90C's RBG2(P) requires, and immediately after a reseed with fresh entropy.
   - If no physical source is healthy, the request waits, and the node reports what it is waiting for.
6. **Creating a realm is a ceremony.**
   - Creating a realm mints its CA root and intermediates, its federation keys and its tree-signing key. It is never an automatic step of a node's first boot.
   - It is an explicit ceremony, on a node that meets rule 5.
   - The ceremony may mix in entropy from outside, for example from an HSM, but never credits it.
7. **Each process gets a child generator.**
   - A process that needs randomness gets its own child DRBG, instantiated from the root with 384 bits of seed material. This is SP 800-90C's RBGC tree.
   - Requests for prediction resistance go to the root.
8. **The DRBG is HMAC_DRBG with SHA-512** (SP 800-90A Rev. 1).
   - CTR_DRBG is ruled out because the Pi 4 has no AES instructions.
   - When SP 800-90A Rev. 2 is final, ASPIS moves to its SHAKE-based DRBG, using the agility of [0003](0003-hybrid-post-quantum-cryptography.md) rule 5.
9. **The root DRBG reseeds** periodically. It also reseeds before giving any further output after:
   - a detected restore or clone ([0001](0001-object-identifiers.md), rule 5);
   - a resume from suspend;
   - a change of VM generation, where the hypervisor reports one.
10. **The POSIX interfaces wait at the gate too.** `getrandom`, `getentropy`, `/dev/random` and `/dev/urandom` all block until the gate opens, and never after ([0012](0012-posix-compatibility-layer.md)).
11. **Images carry no secrets.** A boot or disk image never contains a genesis key, a CA key or a credited seed. Every node mints its own keys after the gate.
12. **Each platform gets a physical source.**
    - QEMU configurations always attach a virtio-rng device.
    - The Pi 4 gets a user-space driver for its SoC generator.

## Consequences

- **A first boot can wait.**
  - A node with no credited source never opens its gate.
  - A QEMU guest without virtio-rng waits on jitter alone, slowly.
  - This failure is intended: a node that can't get entropy mints no keys.
- **Boot order is fixed.** The entropy service and the RNG drivers start before the key service, the network server and anything that mints IDs.
- **The Pi 4 needs a driver before it can enroll.** Its SoC generator's noise source isn't publicly documented, so its credit rate starts conservatively.
- **Cloned SD cards are safe**, because images hold no keys and persisted seeds are never credited.
- **Time is the other first-boot gate.** The Pi 4 has no battery-backed clock, so enrollment also waits for authenticated time ([0015](0015-jwt-tokens-and-oidc-identity.md), rule 7; [0020](0020-realm-certificate-authority.md)).
- **[0001](0001-object-identifiers.md) needs one more answer:** what fills the random field of IDs that exist before the gate.
- **Reproducible tests** need a seed hook in test builds that production builds can't contain.

## References

- [Entropy and the first keys: design note](../design/entropy-and-first-keys.md)
- [NIST SP 800-90C](https://csrc.nist.gov/pubs/sp/800/90/c/final), [SP 800-90A Rev. 1](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final), [SP 800-90B](https://csrc.nist.gov/pubs/sp/800/90/b/final)
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [Heninger et al., "Mining Your Ps and Qs" (2012)](https://factorable.net/)
