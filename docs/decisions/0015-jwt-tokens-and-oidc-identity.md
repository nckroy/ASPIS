<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0015. Security tokens: JWTs, with OpenID Connect for user and workload identity

- **Status:** Accepted
- **Date:** 2026-11-24, updated 2026-11-25

## Context

The brief says security constructs for interaction with APIs use JWTs, building up to user and workload identities that use OpenID Connect (OIDC) for authentication and access management.

Accepted decisions constrain how this works:

- every kernel operation goes through a capability ([0002](0002-capability-security-model.md));
- signatures are hybrid post-quantum ([0003](0003-hybrid-post-quantum-cryptography.md));
- remote failure is visible, and realms federate ([0004](0004-network-transparency-and-failure.md)).

The [security tokens design note](../design/security-tokens.md) works through the conflicts and the current state of the standards.

## Decision

1. **Two layers of authority.**
   - JWTs are the portable form of authority. A client presents one when it binds to an object interface ([0014](0014-versioned-object-apis.md)), when a session crosses nodes, and when authority is delegated to a party that will bind for itself, including across nodes ([0002](0002-capability-security-model.md), rule 5). A capability passed as a call parameter is not such a delegation: its session doesn't move, and a receiver on another node gets a proxy that routes back through the node that passed it, and ends with that session ([0066](0066-capability-parameters-and-server-streams.md), rules 4 and 5).
   - The object's manager verifies the token once. It then returns a kernel capability for a local client, or a session bound to the secure channel for a remote one. Calls go through that capability or session, with no token per call.
   - A session ends when its token expires, or as soon as a new root of the authorization tree ([0016](0016-authorization-sparse-merkle-tree.md)) revokes a branch that holds one of the policies that determined its decision ([0019](0019-authzen-decision-protocol.md), rule 8). Renewing a session needs a fresh token.
   - The kernel never sees or parses tokens.
2. **Identity is OIDC-based.**
   - Each realm runs an OpenID Provider and OAuth authorization server as part of its registry.
   - `iss` is the realm's issuer. In an access token, `sub` is the principal's object ID in its ABNF text form ([0013](0013-abnf-for-protocols-and-calls.md)). In a workload identity token (WIT), `sub` is the principal's identity URI ([0022](0022-spiffe-and-wimse-workload-identity.md), rule 4).
   - Managers accept access tokens and WITs, never ID tokens. A bind carries the token with a proof of possession in WPT form ([0022](0022-spiffe-and-wimse-workload-identity.md), rule 4).
   - **Users** log in through dm, authenticating natively to the realm's provider with a password, passkey or smart card, since ASPIS has no web browser. A user whose identity comes from an external provider logs in with the OAuth device authorization grant (RFC 8628) against the realm's own provider. The realm's provider brokers to the external provider with the standard authorization-code flow, in the user's browser on another device ([0017](0017-openid-federation-membership.md), rule 10). External providers therefore need only standard OIDC and federation registration, not device-grant or CIBA support.
   - **Workloads** (services, processes and nodes) receive WITs bound to keys they hold. A node bootstraps its identity from its genesis key ([0001](0001-object-identifiers.md), [0003](0003-hybrid-post-quantum-cryptography.md)). Workload identity conforms to SPIFFE and the IETF WIMSE drafts ([0022](0022-spiffe-and-wimse-workload-identity.md)).
3. **Token profile.**
   - Tokens use JWS Compact Serialization with an explicit `typ`, such as `at+jwt` (RFC 9068).
   - **Signatures** use the composite ML-DSA-65 + Ed25519 algorithm from the IETF JOSE composite-signature draft, which matches [0003](0003-hybrid-post-quantum-cryptography.md). The draft revision is pinned until it becomes an RFC. RFC 9964 already standardizes ML-DSA on its own for JOSE; that is the fallback if the composite draft stalls.
   - RFC 8725's rules apply: algorithms are allow-listed per token type, `none` is forbidden, and headers can't carry key URLs (`jku`, `x5u`).
   - Tokens are sender-constrained. A `cnf` claim (RFC 7800) binds each token to its holder's key, and binding requires proof of possession.
   - Access tokens live for minutes. `exp`, `nbf` and `iat` are parsed as 64-bit integers.
   - Authorization claims name objects, interfaces, versions and methods. Their syntax is defined in ABNF ([0013](0013-abnf-for-protocols-and-calls.md)).
   - Token scopes are an upper bound, enforced by a realm-wide Cedar `forbid` rule: no decision ever exceeds the token's scopes ([0019](0019-authzen-decision-protocol.md), rule 8). Revocation is tracked through the policies that determined each decision, not through grant keys named in the token (rule 1).
4. **Delegation and call chains.**
   - OAuth Token Exchange (RFC 8693) issues narrower or on-behalf-of tokens.
   - The OAuth Transaction Tokens draft is the model for carrying a user's context through a chain of calls.
5. **Federation.** Realms trust one another through OpenID Federation trust chains. [0004](0004-network-transparency-and-failure.md) left this mechanism open.
   - The specifications are OpenID Federation 1.1, the protocol-independent core, and OpenID Federation for OpenID Connect 1.1. Together they are functionally equivalent to OpenID Federation 1.0.
   - A realm is a federation entity. It may join several topologies at once, and it accepts and issues user and workload identities through them ([0017](0017-openid-federation-membership.md), rules 1 to 3).
   - Between ASPIS realms, trust uses ASPIS's own entity types under the protocol-independent core ([0017](0017-openid-federation-membership.md), rule 8).
   - Principals created from one external issuer's identities are minted under an authority dedicated to that issuer, so distrusting an issuer is one branch revocation ([0017](0017-openid-federation-membership.md), rule 5).
6. **External interoperability.**
   - Tokens from external identity providers use classical algorithms. They are accepted only at the realm's edge, only through a valid trust chain to a trust anchor the realm accepts ([0017](0017-openid-federation-membership.md), rule 4), and the realm re-issues post-quantum-signed ASPIS tokens in their place.
   - Some peers outside ASPIS can't verify composite signatures. Tokens for them are signed with a separate key: ML-DSA-65 where the peer accepts it, and a classical algorithm only otherwise ([0022](0022-spiffe-and-wimse-workload-identity.md), rule 5). ASPIS never accepts those tokens back.
   - In external federation topologies, the realm's federation keys use the algorithms the topology mandates, in practice classical ones. They sign only statements and tokens that leave the realm. Between ASPIS realms, federation keys use the composite algorithm of rule 3 ([0017](0017-openid-federation-membership.md), rule 6).
7. **Time is security-critical.** Token validity depends on clocks, so authenticated time synchronization becomes a requirement. Its design is a design-session item.

## Consequences

- One identity system runs from login to every API binding, and it interoperates with the OIDC and OAuth ecosystem at the realm's edge.
- **Tokens are large.** ML-DSA-65 + Ed25519 signatures put a token near 5 KB. That is acceptable at bind time but rules out a token on every call.
- **The realm's provider becomes critical infrastructure.** It must be replicated, and nodes need cached keys so they can keep verifying tokens during a partition.
- **The standards are still settling.** ASPIS depends on post-quantum JOSE work that isn't final yet, so algorithm identifiers must stay agile.
- **JSON parsing enters every manager's trust boundary.** Verification therefore lives in one hardened, shared library.
- **The token profile is still to be specified.** It must say what claims each token carries, and how an access token travels with a WPT-form proof (rule 2).
  - Under the pinned WPT draft, a proof binds to a WIT ([0022](0022-spiffe-and-wimse-workload-identity.md), rule 10).
  - So programs that bind on a user's behalf, such as those dm starts, need WITs too.
  - The profile must say how the user's access token travels with them.

## References

- [Security tokens design note](../design/security-tokens.md)
