<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0069. The cryptography libraries: RustCrypto and dalek

- **Status:** Proposed
- **Date:** 2026-11-26

## Context

[0003](0003-hybrid-post-quantum-cryptography.md) fixes the algorithms. Key exchange is X25519 with ML-KEM-768 (rule 1). Signatures are a composite of Ed25519 and ML-DSA-65 (rule 2). ASPIS's own hashes are SHA-3 (rule 3), and bulk encryption is ChaCha20-Poly1305, or AES-256-GCM where hardware AES exists (rule 4). Rule 4 also admits the ciphers a standard protocol mandates for keys derived from public values: QUIC v1's AES-128-GCM for Initial packets and the Retry tag, and AES-128 header protection for Initial packets (RFC 9001, sections 5.2, 5.4 and 5.8). [0020](0020-realm-certificate-authority.md) makes the composite `id-MLDSA65-Ed25519-SHA512` of RFC 10073 (rule 2), and TLS 1.3's key schedule keeps SHA-256 or SHA-384 (rule 3). 0003, rule 7 left the libraries to the design session. The [design backlog's D33](../design/design-backlog.md#m3-node-user-space-and-the-entropy-gate) asks for them, judged on `no_std` fit and on license ([0008](0008-mpl-2.0-license.md), rule 4). C08 wraps them ([build plan](../design/build-plan.md)).

Two families supply every primitive. This survey is of 2026-11-26:

- **RustCrypto, with dalek for Curve25519.**
  - The crates are `ml-kem` 0.3, `ml-dsa` 0.1, `sha2` 0.11, `sha3` 0.12, `shake` 0.1 (SHAKE256, which left `sha3` at 0.12), `hmac` 0.13, `hkdf` 0.13, `chacha20poly1305` 0.11 and `aes-gcm` 0.11, with `x25519-dalek` 3.0, `ed25519-dalek` 3.0 and `curve25519-dalek` 5.0. The AEAD crates are built on `chacha20` 0.10 and `aes` 0.9, which also give the raw ChaCha20 function and the AES block cipher.
  - They build `no_std` for `aarch64-unknown-none` on the pinned toolchain ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 1), with 45 third-party crates in the tree, counting build dependencies. Licenses are MIT OR Apache-2.0, and BSD-3-Clause for dalek.
  - RustSec lists one advisory against the crates named here since 2025: a timing leak in `ml-dsa`'s decomposition, fixed before 0.1.0 (RUSTSEC-2025-0144). It lists three in 2026 against crates they depend on: `cmov` (RUSTSEC-2026-0003, ARM32 only), `keccak` (RUSTSEC-2026-0012, an opt-in ARMv8 assembly backend) and `ctutils` (RUSTSEC-2026-0385, masks and comparisons that weren't constant-time). The pinned versions have every fix.
  - They share the `digest`, `signature`, `kem` and `aead` traits with RustCrypto's DER, X.509 and PKCS crates. `rustls-rustcrypto`, still a pre-release, builds a rustls crypto provider on them.
  - None of them is formally verified.
- **Cryspen's libcrux.**
  - Its ML-KEM is formally verified with hax and F*. Its SHA-2, HMAC, HKDF, ChaCha20-Poly1305, X25519 and Ed25519 are translated from HACL*.
  - Every crate is at 0.0.x and licensed Apache-2.0 only. They build `no_std` for the same target.
  - RustSec lists about twenty advisories against its crates in 2026, and one in December 2025. Two affect only aarch64, ASPIS's one architecture: wrong results from an unverified NEON fallback (RUSTSEC-2025-0133, December 2025), and wrong results from its constant-time select and swap (RUSTSEC-2026-0212). A third, against its AES-GCM, is a tag check that wasn't constant-time (RUSTSEC-2026-0211).

No crate in either family implements RFC 10073's composite.

Claude drafted this record from the project owner's choice of 2026-11-26.

## Decision

1. **RustCrypto and dalek supply every primitive.**
   - The workspace pins one version of each crate: `sha2`, `sha3`, `shake`, `hmac`, `hkdf`, `chacha20poly1305`, `aes-gcm`, `chacha20`, `aes`, `ml-kem`, `ml-dsa`, `x25519-dalek`, `ed25519-dalek` and `curve25519-dalek`, with `zeroize` and `subtle` for rule 5.
   - Each is built with its default features off. None may pull in `std`, `getrandom` or any other source of randomness.
   - A new primitive comes from the same families unless a record says otherwise.
2. **One crate wraps them.**
   - `crates/crypto` (`aspis-crypto`) is `#![no_std]` with an `alloc` feature and `#![forbid(unsafe_code)]`. It is the only ASPIS crate that depends on the primitive crates, except that the boot stub and `crates/initfs` take SHA-512 from the workspace's `sha2` pin for the initial image's digests ([0037](0037-initial-image-format-and-contents.md)), and xtask takes SHA-256 from it to check the TLC jar's checksum. The IDL compiler takes SHA3-256 from it.
   - A third-party protocol stack that takes a crypto provider, as rustls does, gets one built on `aspis-crypto`. The stack itself is D65's.
   - **QUIC's fixed ciphers.** `aspis-crypto` also wraps AES-128-GCM, and RFC 9001's header-protection masks: AES-128 and AES-256 in ECB mode, and the raw ChaCha20 function (section 5.4). C29's QUIC needs them, and this rule leaves it nowhere else to get them. AES-128-GCM and the AES-128 mask are documented for [0003](0003-hybrid-post-quantum-cryptography.md), rule 4's use alone: QUIC v1's Initial packets and Retry tag, whose keys come from public values.
   - No cryptography runs in the kernel ([0003](0003-hybrid-post-quantum-cryptography.md), rule 6). The kernel doesn't depend on `aspis-crypto`.
3. **Randomness is an input.** Nothing in `aspis-crypto` draws randomness of its own. The entropy service supplies it ([0021](0021-entropy-before-keys.md), rule 1), and the caller passes it in as bytes.
   - **Key generation** takes a seed: 64 bytes (*d* ‖ *z*) for ML-KEM-768, 32 bytes (ξ) for ML-DSA-65, and 32 bytes each for Ed25519 and X25519.
   - **Encapsulation** takes its 32 random bytes (*m*). **ML-DSA signing** is hedged with 32 random bytes from the caller.
   - **Deterministic signing** exists for known-answer tests only. The composite refuses an all-zero hedge, which would select it.
4. **ASPIS implements the composite.** `id-MLDSA65-Ed25519-SHA512` (OID 1.3.6.1.5.5.7.6.48) follows RFC 10073, sections 2 to 4:
   - **The message representative** is M′ = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(M). The label is `COMPSIG-MLDSA65-Ed25519-SHA512`, and ctx is at most 255 bytes.
   - **Signing.** ML-DSA-65 signs M′ with the label as its context. Ed25519 signs M′ as pure Ed25519.
   - **Sizes.** The public key is the ML-DSA key followed by the Ed25519 key, 1,984 bytes. The private key is the ML-DSA seed followed by the Ed25519 seed, 64 bytes. A signature is 3,373 bytes.
   - **Verification** succeeds only if both halves verify.
   - **The components stay inside the composite.** The crate gives out no component key or component signature on its own ([0020](0020-realm-certificate-authority.md), rule 2).
   - **Standalone verifiers.** The crate also verifies standalone Ed25519 and ML-DSA-65 signatures, for outside certificates (C28) and tokens (C37). They refuse messages that start with the Prefix (RFC 10073, section 9.4), so a composite's half doesn't verify alone. The cost, which the RFC notes, is that a legitimate message that starts with that string can't be verified.
5. **Inputs from outside are checked where they are decoded.**
   - Every public key, ciphertext and signature is checked for its exact length.
   - An ML-KEM encapsulation key gets FIPS 203's modulus check.
   - Ed25519 verification refuses non-canonical encodings and small-order keys.
   - X25519 refuses an all-zero shared secret (RFC 7748, section 6.1).
   - Secret keys and shared secrets are zeroized when dropped, and compared in constant time.
   - That clearing covers `aspis-crypto`'s secret types and its own copies. It doesn't reach the libraries' internal stack temporaries, such as ML-DSA's per-signature randomness or HMAC's padded key block. A server that holds long-term keys, such as C21's entropy service or C25's key service, relies on its process isolation for those.
6. **Algorithms have identifiers.**
   - `aspis-crypto` names each algorithm with an enumeration. Each value maps to its OID where one exists, to its TLS codepoint where one exists (`X25519MLKEM768` is 0x11EC), and to its JOSE name where one exists. A JOSE name is an `alg` or an `enc`, and a name from the other registry is refused.
   - An unknown identifier is refused, never replaced by a default.
   - The composite's private-use TLS codepoint is D65's, and its JOSE identifier is C37's.
   - How ASPIS's own records carry an identifier is decided by the chunks that define them, such as C25's key records and C27's signed roots ([0003](0003-hybrid-post-quantum-cryptography.md), rule 5).
   - AES-128-GCM and the header-protection masks have no identifier. QUIC v1 fixes them by its version, so nothing negotiates or records them, and no TLS codepoint may select AES-128-GCM.
7. **Known-answer tests come from the standards.**
   - The vectors are FIPS 180-4's and FIPS 202's examples, and those of RFC 4231 (HMAC), RFC 5869 (HKDF), RFC 7748 (X25519), RFC 8032 (Ed25519) and RFC 8439 (ChaCha20-Poly1305).
   - AES-256-GCM and AES-128-GCM use the test cases of the GCM specification. ML-KEM-768 and ML-DSA-65 use NIST's ACVP vectors, and the composite uses RFC 10073, Appendix E.
   - QUIC's packet protection and header-protection masks use RFC 9001, Appendix A, and the AES masks also FIPS 197's examples (as updated in 2023).
   - Each vector file keeps its source's notice ([0033](0033-contributions-docs-license-and-notice-years.md), rule 3).
8. **libcrux is the differential oracle.**
   - The fuzz workspace compares `aspis-crypto` with libcrux on the same seeds and inputs, for every primitive libcrux has. libcrux has no public raw ChaCha20 function, so `aspis-crypto`'s own tests check the ChaCha20 header-protection mask against RFC 8439's block function.
   - libcrux stays out of the product lock file, the images and the SBOM ([0068](0068-the-fuzzing-and-differential-testing-gate.md), rule 3).
   - The decoders of rule 5 are trust-boundary parsers, fuzzed through `aspis-crypto`'s entry points ([0068](0068-the-fuzzing-and-differential-testing-gate.md), rule 4).

## Consequences

- **D33 is settled for the primitives.** Which crates supply DER, JOSE, JSON, TLS, QUIC and TOML stays with the chunks that use them ([call-language L39](../design/call-language.md#l39-third-party-parsers)). The TLS and QUIC stack stays with D65.
- **The ML crates are young.** `ml-kem` is at 0.3 and `ml-dsa` at 0.1, so their interfaces may change. `aspis-crypto` keeps any change in one place, and every bump reruns the vectors and the differential tests.
- **Nothing in the product is formally verified.** Two things limit the risk: the hybrid holds while either half does ([0003](0003-hybrid-post-quantum-cryptography.md)), and libcrux's verified ML-KEM checks RustCrypto's on every fuzz run.
- **Later chunks call `aspis-crypto`, not the traits.** RustCrypto's DER, X.509 and PKCS crates take the same `digest` and `signature` traits as its primitives, but `aspis-crypto` exposes none of them: its types are its own, with their own methods. C28 and C37 may use the format crates to parse and encode, and call `aspis-crypto` for every cryptographic operation. If one of them needs a trait, such as `signature::Verifier`, `aspis-crypto` implements it on its own types; no other crate depends on the primitive crates (rule 2). A rustls provider, if D65 picks rustls, implements rustls's own traits on `aspis-crypto`, so it needs no second implementation.
- **Speed on the Pi 4 is unmeasured.** C29 measures the cost of a handshake.

## References

- [0003](0003-hybrid-post-quantum-cryptography.md), [0008](0008-mpl-2.0-license.md), [0020](0020-realm-certificate-authority.md), [0021](0021-entropy-before-keys.md), [0037](0037-initial-image-format-and-contents.md), [0068](0068-the-fuzzing-and-differential-testing-gate.md)
- [RFC 10073, Composite ML-DSA for use in X.509](https://www.rfc-editor.org/rfc/rfc10073)
- [RFC 9001, Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [FIPS 203, ML-KEM](https://csrc.nist.gov/pubs/fips/203/final); [FIPS 204, ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [RustCrypto](https://github.com/RustCrypto); [dalek-cryptography](https://github.com/dalek-cryptography); [libcrux](https://github.com/cryspen/libcrux)
- [RustSec advisory database](https://rustsec.org/)
