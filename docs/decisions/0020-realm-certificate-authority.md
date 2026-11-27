<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0020. The realm as its own certificate authority, with hybrid post-quantum certificates

- **Status:** Accepted
- **Date:** 2026-11-24, updated 2026-11-26

## Context

The decision: the realm is its own certificate authority (CA) for RPC and HTTPS across the realm. Its intermediate CAs are exposed as certificate signing requests (CSRs), which other PKIs can import or cross-sign. The certificates are hybrid post-quantum TLS certificates.

Accepted decisions constrain how this works:

- signatures are composite ML-DSA-65 + Ed25519, and key establishment is X25519 + ML-KEM-768 ([0003](0003-hybrid-post-quantum-cryptography.md));
- a node's UUID is the hash of its genesis key, and that key only certifies operational keys ([0001](0001-object-identifiers.md));
- RPC runs over IPv6 and UDP, and realms federate across the internet ([0004](0004-network-transparency-and-failure.md));
- inside ASPIS, revocation is the authorization tree ([0016](0016-authorization-sparse-merkle-tree.md); [0017](0017-openid-federation-membership.md), rule 11);
- the realm already serves HTTPS endpoints for federation, for its provider and for its decision point ([0017](0017-openid-federation-membership.md), rule 9; [0019](0019-authzen-decision-protocol.md)).

Facts this decision relies on (details and sources in the [design note](../design/realm-certificate-authority.md)):

- **Composite certificates are standardized.** RFC 10073 (Proposed Standard, November 2026) defines composite ML-DSA for X.509.
  - It includes `id-MLDSA65-Ed25519-SHA512`, OID 1.3.6.1.5.5.7.6.48.
  - Composite keys drop into PKCS #10 requests unchanged.
  - A composite's component keys must never be used on their own.
- **Hybrid key exchange is standardized.** RFC 10024 (Proposed Standard, August 2026) defines `X25519MLKEM768` for TLS 1.3. TLS 1.3 itself is now RFC 9846 (July 2026), which obsoletes RFC 8446.
- **Composite signatures in TLS have no codepoint yet.** `draft-ietf-tls-composite-mldsa-00` (October 2026) names `mldsa65_ed25519_sha512`, but its codepoint is still TBD.
- **The public Web PKI won't carry these certificates.** Chrome has no immediate plan to admit post-quantum X.509 certificates to its root store. Its post-quantum route is Merkle Tree Certificates, with a root store that accepts only those planned for Q3 2027.
- **Workload identity in certificates.** The WIMSE drafts put exactly one workload identifier in a URI subjectAltName. The identifier's authority is its trust domain, a DNS name.
- **Size.** A composite ML-DSA-65 + Ed25519 key is 1,984 bytes and a signature 3,373 bytes. A certificate is therefore about 6 KB, and each side that authenticates in a handshake sends about 15 KB.

## Decision

1. **Each realm runs its own CA hierarchy.**
   - **An offline root.** It signs only intermediate certificates, cross-certificates and its CRL, in a ceremony. Its key is used for nothing else, and is distinct from the realm's tree-signing and federation keys.
   - **One intermediate per purpose**, each with its own key:
     - the **RPC CA** certifies nodes and workloads, named by URI;
     - the **HTTPS CA** certifies servers in the realm's DNS domain, named by DNS name.
   - The root limits each intermediate to the realm's names, with path length 0. More intermediates can be added the same way.
2. **Every certificate is hybrid.**
   - Every certificate, CSR and CRL the realm issues uses `id-MLDSA65-Ed25519-SHA512` (RFC 10073). That matches [0003](0003-hybrid-post-quantum-cryptography.md) rule 2 and the JOSE composite in [0015](0015-jwt-tokens-and-oidc-identity.md).
   - TLS signatures use `mldsa65_ed25519_sha512` from `draft-ietf-tls-composite-mldsa`. Until IANA assigns its codepoint, ASPIS uses a private-use value and pins the draft revision.
   - Inside the realm, key exchange is `X25519MLKEM768` (RFC 10024) and nothing else.
   - The components of a composite key are never used on their own.
3. **TLS 1.3 secures RPC and HTTPS.**
   - **RPC.** RPC's secure channel is TLS 1.3 (RFC 9846) over QUIC (RFC 9000, RFC 9001), which fits [0004](0004-network-transparency-and-failure.md)'s IPv6 and UDP transport. It has its own ALPN identifier.
   - **Mutual authentication.** Both network servers present node certificates.
   - **HTTPS** inside the realm uses the same TLS stack.
   - **Cipher suites** follow [0003](0003-hybrid-post-quantum-cryptography.md) rule 4: `TLS_CHACHA20_POLY1305_SHA256` by default, and `TLS_AES_256_GCM_SHA384` where hardware AES exists. QUIC's Initial packets and Retry tags use AES-128-GCM, and an Initial packet's header protection uses AES-128, as RFC 9001 requires and [0003](0003-hybrid-post-quantum-cryptography.md) rule 4 admits.
   - **Hashes.** TLS 1.3's key schedule keeps SHA-256 or SHA-384, and RFC 10073 pre-hashes with SHA-512. [0003](0003-hybrid-post-quantum-cryptography.md), rule 3 admits the hashes a standard protocol specifies.
   - **Certificates replace no token.** Certificates authenticate nodes and servers. Principals still authenticate with tokens when they bind ([0015](0015-jwt-tokens-and-oidc-identity.md)).
4. **What the realm certifies.**
   - **Nodes.** The registry enrolls a node once it proves that it holds its genesis key ([0001](0001-object-identifiers.md)). The RPC CA then certifies an operational TLS key that the genesis key has certified, and never the genesis key itself.
   - **The founding node** is the one exception. The RPC CA doesn't issue its initial certificate: the node signs that certificate with its own genesis key, during the realm-creation ceremony ([0029](0029-founding-node-self-signed-certificate.md)).
   - **Workloads** that need mutual TLS with parties outside ASPIS, such as RFC 8705 client authentication, get an RPC CA certificate for a key they hold.
   - **Servers.** Each HTTPS endpoint in the realm's domain gets an HTTPS CA certificate.
   - Certificates for people are out of scope.
5. **Every name can be constrained.**
   - **Node and workload certificates** carry exactly one URI subjectAltName. It is the principal's identity URI, `spiffe://<realm-domain>/<object-id-text>`, which is both a SPIFFE ID and a WIMSE workload identifier ([0022](0022-spiffe-and-wimse-workload-identity.md), rule 2). Its trust domain is the realm's DNS name, and its path is the principal's object ID in the ABNF text form ([0013](0013-abnf-for-protocols-and-calls.md)).
   - **Server certificates** carry DNS names in the realm's domain.
   - Every name therefore falls under the realm's domain, so the realm and any cross-signer can confine an intermediate with RFC 5280 name constraints. A URI without a host can't be constrained that way, so `urn:` forms aren't used.
6. **Issuing a certificate is an authorized call.**
   - Each CA is an object with a versioned interface ([0014](0014-versioned-object-apis.md)), and enrollment and renewal are calls on it.
   - The CA asks its node's decision point ([0019](0019-authzen-decision-protocol.md)) whether the caller may obtain a certificate for the names it requests. The rules are Cedar policies in the authorization tree ([0018](0018-cedar-policy-language.md)).
   - Renewal authenticates with the current certificate and uses a new key.
   - No CA issues the founding node's initial certificate, so no decision point is asked for it. Its replacement is an ordinary renewal ([0029](0029-founding-node-self-signed-certificate.md)).
7. **Short lives, with revocation through the tree.**
   - End-entity certificates live for seven days at most. They renew automatically and carry no revocation pointers.
   - The CA records every certificate it issues in the authorization tree, under a branch for the issuing CA ([0016](0016-authorization-sparse-merkle-tree.md)). The signed root then commits to every certificate in force, which is the realm's equivalent of Certificate Transparency.
   - **Inside ASPIS the tree is authoritative.**
     - During the handshake, a peer checks the certificate's principal and serial number against its replica.
     - A peer from another realm is checked against that realm's signed roots (0016, rule 8).
     - When a new root revokes a certificate, the connections that use it close.
     - Revoking a principal's branch or a CA's branch revokes every certificate under it.
   - **Outside ASPIS:**
     - the root publishes a CRL, generated from the tree, covering intermediates and cross-certificates;
     - end-entity certificates rely on expiry;
     - there is no OCSP.
8. **Intermediates are published as CSRs.**
   - For each intermediate, the realm publishes a PKCS #10 request (RFC 2986), signed with the intermediate's composite key.
   - An `extensionRequest` attribute (RFC 2985) proposes the constraints a signer should apply:
     - CA, with path length 0;
     - `keyCertSign` and `cRLSign`;
     - name constraints that permit only the realm's domain;
     - the realm's certificate policy OID.
   - The realm publishes the CSRs over HTTPS, under its entity identifier, and in its ASPIS-native federation metadata, which the realm's federation key signs.
   - A CSR proves that the requester holds the key, not who owns it. The federation statement or the importer's own vetting supplies that.
   - The realm publishes a certificate policy in RFC 3647's framework, so that a signer can map its own policies onto the realm's.
   - The same CSR serves import (another PKI makes the intermediate its subordinate) and cross-signing (a peer certifies it).
9. **Every path is discoverable.**
   - The realm publishes every CA certificate issued for an intermediate: its root's, and each import or cross-certificate. The intermediate's AIA `caIssuers` URL serves them as one certs-only CMS bundle, so path builders find every path (RFC 4158).
   - A TLS endpoint sends the chain that leads to an anchor its peer trusts. It chooses that chain from the peer's trust anchors (`draft-ietf-tls-trust-anchor-ids`), from the peer's realm, or by configuration.
   - Re-keying an intermediate produces a new CSR, and signers certify the new key. Intermediates overlap their successors, so no path lapses.
10. **ASPIS realms cross-certify one another.**
    - Suppose realm A's policy accepts realm B for RPC through an ASPIS-native federation ([0017](0017-openid-federation-membership.md)). A's root then issues a cross-certificate for B's RPC CA, from the CSR in B's federation metadata. The cross-certificate is limited to B's trust domain, with path length 0.
    - Every node trusts one anchor, its own realm's root. It validates nodes from other realms through these cross-certificates.
    - When A stops trusting B, A revokes the cross-certificate. If A stops trusting B because it leaves a topology, the revocation happens in the same epoch as the branches that 0017 rule 5 revokes.
11. **Classical certificates only at the edge.**
    - Some endpoints must be reachable by clients that can only verify classical signatures: the login page that 0017 rule 10's browser opens, external relying parties, and external enforcement points. These endpoints also hold a Web PKI certificate from a public CA, obtained with ACME (RFC 8555).
    - App routes ([0026](0026-realm-as-cloud-provider.md), rule 6) are edge endpoints too. A public route in the realm's domain also holds a Web PKI certificate, obtained with ACME.
    - A custom domain outside the realm's domain holds Web PKI certificates only, because the HTTPS CA's name constraints confine it to the realm's domain (rules 1 and 5).
    - The endpoint picks the chain from the client's signature algorithms and trust anchors.
    - ASPIS clients never accept a Web PKI certificate for a name in the realm's domain. Such names validate only through the realm's root or a cross-certified path.
    - When public post-quantum certificates arrive (Merkle Tree Certificates), the edge adopts them.

## Consequences

- **Handshakes are large.**
  - Each side that authenticates sends about 15 KB, roughly seven times a classical chain.
  - Under QUIC's amplification limit, a new client's first connection costs an extra round trip.
  - Long-lived connections, address-validation tokens and session resumption spread that cost between nodes.
- **One TLS stack serves RPC and HTTPS.** It must support RFC 10024, RFC 10073 and the composite TLS draft. Choosing it is D65's ([design backlog](../design/design-backlog.md#m4-a-founding-node-with-an-identity)). Its cryptography comes from `aspis-crypto`, as proposed in [0069](0069-cryptography-libraries.md), rule 2: a stack that takes a crypto provider, as rustls does, gets one built on `aspis-crypto`.
- **Interoperability is limited.**
  - A PKI can import or cross-sign an intermediate only if it can process RFC 10073 keys, and its relying parties must verify composite signatures.
  - A path through a classical cross-signer is only as strong as that signer's classical signature. That matches the classical trust at the edge in [0017](0017-openid-federation-membership.md).
- **Each partner gets a narrow grant of trust.** A signer certifies one intermediate within the realm's names. It doesn't trust the realm's root, or anyone the root cross-certifies.
- **The CA is critical infrastructure**, alongside the provider, the authorization service and the decision points.
  - Intermediate keys need hardware protection where the board has it.
  - The root needs an offline ceremony.
- **Clocks matter more.** Certificate validity depends on time, as token validity does ([0015](0015-jwt-tokens-and-oidc-identity.md), rule 7). Authenticated time synchronization must not depend on a certificate that a node can't validate before its clock is set.
- **Partners must re-certify.** Re-keying an intermediate means every signer certifies the new key, so rotation needs coordination.
- **Public endpoints serve two chains**, a hybrid one and a Web PKI one, until public post-quantum certificates exist.

## References

- [The realm's certificate authority: design note](../design/realm-certificate-authority.md)
- [RFC 10073, Composite ML-DSA for use in X.509](https://www.rfc-editor.org/info/rfc10073)
- [RFC 10024, PQ/T hybrid key agreement for TLS 1.3](https://www.rfc-editor.org/info/rfc10024)
- [RFC 9846, TLS 1.3](https://www.rfc-editor.org/info/rfc9846)
- [RFC 9000, QUIC](https://www.rfc-editor.org/info/rfc9000) and [RFC 9001, Using TLS to secure QUIC](https://www.rfc-editor.org/info/rfc9001)
- [RFC 2986, PKCS #10](https://www.rfc-editor.org/info/rfc2986)
- [RFC 5280, X.509 certificate and CRL profile](https://www.rfc-editor.org/info/rfc5280)
- [`draft-ietf-tls-composite-mldsa`](https://datatracker.ietf.org/doc/draft-ietf-tls-composite-mldsa/)
- [`draft-ietf-tls-trust-anchor-ids`](https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids/)
- [`draft-ietf-wimse-identifier`](https://datatracker.ietf.org/doc/draft-ietf-wimse-identifier/) and [`draft-ietf-wimse-mutual-tls`](https://datatracker.ietf.org/doc/draft-ietf-wimse-mutual-tls/)
