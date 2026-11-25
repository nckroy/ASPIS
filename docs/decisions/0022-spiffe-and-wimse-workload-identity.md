<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0022. Workload identity that conforms to SPIFFE and WIMSE

- **Status:** Accepted
- **Date:** 2026-11-24, updated 2026-11-25

## Context

The question: are SPIFFE and the IETF WIMSE drafts compatible with ASPIS as described so far? [0015](0015-jwt-tokens-and-oidc-identity.md) named both as models for workload identity, and [0020](0020-realm-certificate-authority.md) puts a WIMSE identifier in node and workload certificates.

Facts this decision relies on (details and sources in the [design note](../design/workload-identity.md)):

- **SPIFFE IDs.** A SPIFFE ID is `spiffe://<trust-domain>/<path>`. Trust domains are lowercase, and path segments use only `[a-zA-Z0-9.-_]`. A path may be an opaque identifier whose metadata lives in a registry.
- **X.509-SVIDs.** An X.509-SVID carries exactly one URI SAN and sets no requirements on algorithms, so 0020's certificates already conform. WIMSE calls its own certificate profile "fully compatible with the X509-SVID".
- **JWT-based SVIDs.** JWT-SVIDs are bearer tokens. Both JWT-SVID and the incubating WIT-SVID allow RS, ES, PS and ML-DSA algorithms, but not composite signatures.
- **WIMSE tokens.** WIMSE's Workload Identity Token (WIT) is always sender-constrained through `cnf`, and its `sub` is the identifier URI. The Workload Proof Token (WPT) proves possession, and so far is defined only for HTTP.
- **The Workload API.** SPIFFE's Workload API is gRPC over a Unix socket. It identifies callers out of band, never by client authentication.
- **Federation.** SPIFFE federation exchanges bundles, each scoped to one trust domain, and bundles are never merged.
- **WIMSE is still in drafts.** The architecture is at -09, the identifier at -04, the credentials at -03 and the proof token at -02.

The analysis finds the two compatible with ASPIS, given the rules below.

## Decision

1. **The realm is a SPIFFE and WIMSE trust domain**, named by its DNS name in lower case.
2. **Identity URIs use the `spiffe` scheme.** Node and workload certificates carry the identity URI as their URI subjectAltName ([0020](0020-realm-certificate-authority.md), rule 5).
   - A principal's identity URI is `spiffe://<realm-domain>/<object-id-text>`. The same URI is both a SPIFFE ID and a WIMSE identifier.
   - The URI renders the principal's object ID, and the registry keeps the principal's metadata.
   - The object ID's text form ([0001](0001-object-identifiers.md), [0013](0013-abnf-for-protocols-and-calls.md)) uses only SPIFFE path characters.
3. **Certificates are X.509-SVIDs.**
   - Node and workload certificates ([0020](0020-realm-certificate-authority.md)) already meet X.509-SVID and the WIMSE certificate profile.
   - The RPC CA's certificate also carries `spiffe://<realm-domain>` as its URI SAN, which makes it a SPIFFE signing certificate.
4. **Workload tokens are WITs.**
   - The workload tokens of [0015](0015-jwt-tokens-and-oidc-identity.md) take the WIMSE WIT form:
     - `typ` is `wit+jwt`;
     - `sub` is the identity URI;
     - `cnf` holds the process's key.
   - Proofs of possession at bind time take the WPT form. ASPIS defines an RPC binding for them, in which `aud` names the object, interface and version being bound ([0014](0014-versioned-object-apis.md)).
   - Access tokens keep the object ID as their `sub` ([0015](0015-jwt-tokens-and-oidc-identity.md), rule 2).
5. **Signatures.**
   - Inside ASPIS, WITs and proofs use the composite algorithm ([0015](0015-jwt-tokens-and-oidc-identity.md), rule 3).
   - For peers outside ASPIS, the realm signs with a separate key: ML-DSA-65 where the peer accepts it, as JWT-SVID and WIT-SVID do, and a classical algorithm otherwise.
   - ASPIS never accepts those tokens back.
6. **JWT-SVIDs are used only at the edge.**
   - JWT-SVIDs are bearer tokens. The realm issues one only to an external audience that requires it, always for a single audience, and never accepts one inside ASPIS.
   - A JWT-SVID presented at the edge is exchanged for an ASPIS token (RFC 8693), as the realm already does for other external tokens ([0017](0017-openid-federation-membership.md)).
7. **The process manager attests workloads.**
   - A workload's identity is assigned when the process manager starts it, from the capabilities involved: the program object and the service principal. It is never derived from a process ID.
   - Cedar policy decides which principal may hold which identity URI ([0020](0020-realm-certificate-authority.md), rule 6).
8. **The POSIX personality serves the SPIFFE Workload API.**
   - For unmodified software, the POSIX personality ([0012](0012-posix-compatibility-layer.md)) serves the SPIFFE Workload Endpoint: gRPC on a Unix socket named by `SPIFFE_ENDPOINT_SOCKET`.
   - Native interfaces back it, and it identifies each caller through the POSIX process server.
   - Native programs use the native interface.
9. **SPIFFE federation runs alongside OpenID Federation.**
   - The realm serves a SPIFFE bundle endpoint, using the `https_web` profile and its edge certificate ([0020](0020-realm-certificate-authority.md), rule 11).
   - The bundle holds the realm's root certificate (`x509-svid`) and the keys that sign tokens for external peers (`jwt-svid`, `wit-svid`).
   - ASPIS realms still trust one another through OpenID Federation and cross-certification ([0017](0017-openid-federation-membership.md), [0020](0020-realm-certificate-authority.md)).
10. **WIMSE drafts are pinned.** The identifier, credentials and proof-token drafts are pinned by revision, as [0015](0015-jwt-tokens-and-oidc-identity.md) pins its JOSE drafts.

## Consequences

- **Interoperability without a second identity model.** ASPIS workloads can work with service meshes, SPIRE-managed clusters, cloud workload identity federation and WIMSE-aware services. Every identity is still a principal's object ID.
- **Composite signatures remain a barrier for peers.** Mutual TLS with an X.509-SVID needs a peer that verifies composite signatures. Until peers can, they get tokens signed with ML-DSA-65 or classical keys, which are weaker at the edge, as [0017](0017-openid-federation-membership.md) already notes for classical trust.
- **New work:** a Workload Endpoint server in the POSIX personality, which brings in a gRPC stack, and an RPC binding for proof tokens.
- **The ID format gains a constraint:** its text form must be safe in a SPIFFE path.
- **More keys to manage.** The realm holds an ML-DSA-65 key and a classical key for external token formats, each with its own rotation.
- **Drafts may move.** WIMSE is still in working-group drafts, so changes there may ripple into ASPIS's profile.

## References

- [Workload identity design note](../design/workload-identity.md)
- [SPIFFE standards](https://github.com/spiffe/spiffe/tree/main/standards)
- [WIMSE working-group documents](https://datatracker.ietf.org/wg/wimse/documents/)
