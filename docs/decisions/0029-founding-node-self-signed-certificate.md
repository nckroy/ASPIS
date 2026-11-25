<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0029. The founding node's initial certificate is self-signed

- **Status:** Accepted. Amends [0020](0020-realm-certificate-authority.md) (rules 4 and 6).
- **Date:** 2026-11-24

## Context

A realm is created in a ceremony on its founding node ([0021](0021-entropy-before-keys.md), rule 6). The ceremony mints the root, the intermediates, the federation keys and the tree-signing key ([0020](0020-realm-certificate-authority.md), rule 1). The founding node also needs a certificate of its own, because RPC's secure channel needs a node certificate at each end ([0020](0020-realm-certificate-authority.md), rule 3).

The normal path can't produce that first certificate:

- The RPC CA certifies a node only after the registry has enrolled it ([0020](0020-realm-certificate-authority.md), rule 4).
- Issuing is an authorized call: the CA asks its node's decision point first ([0020](0020-realm-certificate-authority.md), rule 6). During the ceremony no decision point runs yet. Until one starts, authority comes only from the capabilities the root server hands out ([0018](0018-cedar-policy-language.md), rule 5).
- The root signs only intermediate certificates, cross-certificates and its CRL ([0020](0020-realm-certificate-authority.md), rule 1), so it can't certify the node either.

The [key flows](../design/key-flows.md#3-realm-creation-ceremony) listed this as open. Nicole decided it on 2026-11-24: the founding node generates its initial certificate as self-signed, signed with the node's genesis key. Rules 3 to 6 below spell that decision out. Claude proposed them, and the project owner accepted them on 2026-11-25.

## Decision

1. **The founding node generates its initial certificate itself.** No CA issues it.
2. **The node's genesis key signs it.**
   - The certified key is the founding node's operational TLS key, never the genesis key itself, so the certificate is the genesis key's certification of the operational key, in X.509 form ([0001](0001-object-identifiers.md), rule 3; [0020](0020-realm-certificate-authority.md), rule 4).
   - "Self-signed" means signed by the node itself. In RFC 5280's terms the certificate is self-issued: the node is both its issuer and its subject, and the signature is the genesis key's, not the certified key's.
   - Otherwise it follows the X.509-SVID profile: one URI subjectAltName, `spiffe://<realm-domain>/<object-id-text>` ([0020](0020-realm-certificate-authority.md), rule 5; [0022](0022-spiffe-and-wimse-workload-identity.md), rule 2); `id-MLDSA65-Ed25519-SHA512`, which the composite genesis key already uses ([0003](0003-hybrid-post-quantum-cryptography.md), rule 2; [0020](0020-realm-certificate-authority.md), rule 2); and a life of seven days at most ([0020](0020-realm-certificate-authority.md), rule 7).
3. **The ceremony records it in the authorization tree's genesis state.** The first signed root commits to it, as to every certificate in force ([0020](0020-realm-certificate-authority.md), rule 7). It is the only certificate in force that no CA issued.
4. **Only the founding node uses it.** Every node trusts one anchor, its own realm's root ([0020](0020-realm-certificate-authority.md), rule 10), and a certificate signed with a node's genesis key doesn't chain to that root. So no other node, and no other realm, ever accepts the initial certificate.
5. **The founding node replaces it by renewal.**
   - Once the founding node's decision point runs, the node renews with the RPC CA. It authenticates with its current certificate, the initial one, and uses a new operational key, which its genesis key certifies in turn ([0020](0020-realm-certificate-authority.md), rule 6; [0001](0001-object-identifiers.md), rule 3). The CA asks its decision point as for any issuance.
   - The renewal is recorded in the tree. The initial certificate is then revoked in the tree and never renewed.
   - The founding node has its RPC CA certificate before any other node enrolls.
6. **Everything else is unchanged.** Every other node enrolls as [0020](0020-realm-certificate-authority.md) rule 4 describes. Every later certificate of the founding node, and every certificate a CA issues, follows rules 4 to 7 of 0020.

## Consequences

- **The initial certificate can be checked without a CA.** Its signature verifies with the node's genesis public key, and the node's UUID is a hash of that key ([0001](0001-object-identifiers.md), rule 3). A verifier that holds the genesis public key, such as the registry, which enrolls nodes by it ([0020](0020-realm-certificate-authority.md), rule 4), can check both.
- **The genesis key's role is unchanged.** It still certifies only operational keys ([0001](0001-object-identifiers.md), rule 3); this certificate is one such certification.
- **0020 rule 6 holds for every certificate a CA issues.** The ceremony needs no exception to the decision-point check, and no decision point before genesis.
- **The root's role is unchanged.** It still signs only intermediates, cross-certificates and its CRL ([0020](0020-realm-certificate-authority.md), rule 1).
- **There is a short bootstrap window.** Until its first renewal, the founding node holds a certificate that no CA issued. The window is bounded by the certificate's seven-day life and by the requirement to renew before another node enrolls. The tree records the certificate throughout, so it is auditable.
- **The genesis tree state grows.** It must record the initial certificate and the founding node's principal with its genesis public key. It must also hold the policies that let the founding node renew, enroll the next node and run the realm's services. Designing that state is part of the ceremony's design.
- **Amends [0020](0020-realm-certificate-authority.md), once accepted.**
  - Rule 4: the founding node's initial certificate is signed with its own genesis key and not issued by the RPC CA.
  - Rule 6: no CA issues that certificate, so no decision point is asked; its replacement is an ordinary renewal.

## References

- [Key flows: the realm-creation ceremony](../design/key-flows.md#3-realm-creation-ceremony)
- [RFC 5280, Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280) (self-issued and self-signed certificates)
