<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0017. Joining OpenID Federation topologies

- **Status:** Accepted
- **Date:** 2026-11-24, updated 2026-11-25

## Context

The brief: the environment can be joined to one or more OpenID Federation topologies, and it accepts and issues user and workload identities through the OpenID Federation mechanism.

The current specifications are **OpenID Federation 1.1**, the protocol-independent core, and **OpenID Federation for OpenID Connect 1.1**, which adds the OIDC and OAuth entity types and client registration. Both were published as Final on 5 May 2026. Together they are functionally equivalent to OpenID Federation 1.0 (Final, February 2026), and their section numbers stay aligned with it.

Facts this decision relies on (details and sources in the [design note](../design/openid-federation.md)):

- **Entity identifiers and statements.** Entity identifiers are HTTPS URLs. Each entity publishes a signed Entity Configuration at `/.well-known/openid-federation`, and superiors issue signed Subordinate Statements about it.
- **Multiple superiors.** An entity may list several superiors in `authority_hints`, so it can sit in several topologies at once. Policy is evaluated per trust chain.
- **Algorithms are set per federation.** Each federation specifies its mandatory signing algorithms; the OIDC profile says implementations should support RS256.
- **Defining new entity types.** The core defines only `federation_entity` and lets other protocols define their own types. The OIDC profile defines `openid_provider`, `openid_relying_party`, `oauth_authorization_server`, `oauth_client` and `oauth_resource`.
- **Endpoints for superiors.** Intermediates and trust anchors must publish fetch and list endpoints; leaves must not.
- **Registration.** Automatic registration lets a client use its entity identifier as its `client_id`, with no prior registration, provided it uses asymmetric keys.
- **What the specs leave open.** The core defines no revocation process and leaves it to each federation. Neither specification addresses workload identities as such.

## Decision

1. **The realm is a federation entity.**
   - Each realm has an HTTPS entity identifier and publishes an Entity Configuration.
   - It lists one `authority_hints` entry for each topology it has joined. Belonging to several topologies at once is normal.
   - Joining a topology means a superior in it issues a Subordinate Statement about the realm. Leaving means removing the hint, and the superior withdrawing its statement.
2. **Roles in OIDC and OAuth topologies.** The realm publishes, under OpenID Federation for OpenID Connect 1.1:
   - `openid_provider` and `oauth_authorization_server`, to issue user and workload identities to relying parties and resource servers in the federation;
   - `openid_relying_party` and `oauth_client`, to accept identities from the federation's providers;
   - `oauth_resource`, for ASPIS objects exposed to external clients.
3. **Workloads are federation entities under the realm.**
   - The realm acts as an intermediate for its own workloads, so it publishes fetch and list endpoints.
   - Each workload that deals with external parties gets:
     - an entity identifier under the realm's domain;
     - an Entity Configuration that the realm serves;
     - a Subordinate Statement from the realm.
   - External parties verify an ASPIS workload through the chain workload → realm → their trust anchor.
   - Workloads register at external authorization servers by automatic registration.
   - Workloads that never deal with external parties use realm-issued tokens only ([0015](0015-jwt-tokens-and-oidc-identity.md)).
4. **Accepting external identities.** An external identity is accepted only if all of these hold:
   - its issuer resolves through a valid trust chain to a trust anchor the realm accepts for that purpose;
   - its Resolved Metadata satisfies the realm's policy;
   - every trust mark the realm requires for that topology is present and active.

   The realm then:
   - maps the identity's `iss` and `sub` to an ASPIS principal;
   - records that principal in the principal tree ([0016](0016-authorization-sparse-merkle-tree.md));
   - issues post-quantum-signed ASPIS tokens for use inside the realm.
5. **Each external issuer gets its own minting authority.**
   - Principals created from one external issuer's identities are minted under an authority dedicated to that issuer. An authority needn't be a node: [0001](0001-object-identifiers.md)'s reserved ASPIS authority is the precedent.
   - Distrusting an issuer is then one branch revocation in the principal tree.
   - Leaving a topology revokes, in a single epoch, the branches of the issuers trusted only through it.
6. **Federation keys per class of topology.**
   - **External topologies:** keys use the algorithms the topology mandates, in practice classical ones. They sign only statements and tokens that leave the realm ([0015](0015-jwt-tokens-and-oidc-identity.md), rule 6).
   - **ASPIS-native topologies** (realm to realm): keys use the composite ML-DSA-65 + Ed25519 algorithm, which those federations mandate ([0003](0003-hybrid-post-quantum-cryptography.md)).
7. **Conflicting policies get separate identifiers.** Superiors constrain the realm's metadata through metadata policy. If two topologies' policies can't both be satisfied by one Entity Configuration, the realm joins the conflicting topology under a second entity identifier.
8. **ASPIS-native federation uses the core specification.** For trust between realms, ASPIS defines its own entity types under OpenID Federation 1.1's protocol-independent core. Their metadata names the realm's:
   - root certificate ([0020](0020-realm-certificate-authority.md), rule 1);
   - intermediates' CSRs ([0020](0020-realm-certificate-authority.md), rule 8);
   - intermediates' current certificates;
   - RPC endpoints;
   - authorization-tree root distribution;
   - catalog endpoint ([0028](0028-discovery-and-realm-catalog.md), rule 11).

   Realms then find and trust one another with the same trust chains.
9. **HTTPS presence.** Each realm needs a DNS name and HTTPS endpoints:
   - its Entity Configuration;
   - the fetch and list endpoints;
   - the provider and authorization-server endpoints;
   - an HTML login page for users arriving from external relying parties. The realm serves this page; ASPIS itself never renders HTML.

   TLS uses hybrid post-quantum key exchange where the peer supports it. The endpoints' certificates follow [0020](0020-realm-certificate-authority.md), rule 11: a hybrid chain from the realm's HTTPS CA, and also a Web PKI certificate where clients can verify only classical signatures.
10. **Brokered login** ([0015](0015-jwt-tokens-and-oidc-identity.md), rule 2).
    - A dm user whose identity comes from an external provider logs in with the device authorization grant against the realm's own provider.
    - The realm's provider brokers to the external provider using the standard authorization-code flow, in the user's browser on another device.
    - External providers therefore need only standard OIDC and federation registration, not device-grant or CIBA support.
11. **Revocation inside ASPIS's own federation.** OpenID Federation leaves revocation to each federation. For the subordinates the realm issues statements about (its workloads), revocation is the authorization tree ([0016](0016-authorization-sparse-merkle-tree.md)). Revoking a workload's branch:
    - stops the realm issuing that workload's Subordinate Statement;
    - marks its keys revoked in the realm's historical-keys endpoint.

## Consequences

- **No bilateral setup.** ASPIS users and workloads can work across research, government or enterprise federations, because automatic registration and trust chains replace one-to-one configuration.
- **Larger attack surface.** The realm depends on DNS, HTTPS and a web front end for its provider, all of which must run isolated in user space.
- **Classical trust at the edge.** Every external topology's trust chains use classical signatures, so an external identity is only as strong as its chain. Policy and grants should reflect that.
- **Operational cost.** Several topologies mean several key sets, and possibly several entity identifiers.
- **A profile to specify.** ASPIS needs its own OpenID Federation profile, covering its entity types, the workload profile and the revocation rules. Textual parts are specified in ABNF ([0013](0013-abnf-for-protocols-and-calls.md)).

## References

- [OpenID Federation design note](../design/openid-federation.md)
- [OpenID Federation 1.1](https://openid.net/specs/openid-federation-1_1.html)
- [OpenID Federation for OpenID Connect 1.1](https://openid.net/specs/openid-federation-connect-1_1.html)
