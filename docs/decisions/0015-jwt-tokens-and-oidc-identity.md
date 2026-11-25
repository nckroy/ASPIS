<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->

# 0015. Security tokens: JWTs, with OpenID Connect for user and workload identity

- **Status:** Accepted. Amends [0002](0002-capability-security-model.md), rule 5. Amended by [0017](0017-openid-federation-membership.md) (rules 2, 5 and 6), [0019](0019-authzen-decision-protocol.md) (rule 3), [0022](0022-spiffe-and-wimse-workload-identity.md) (rule 2) and [0030](0030-bind-tokens-sessions-and-group-memberships.md) (rules 1 and 2).
- **Date:** 2026-11-24

## Context

The brief says security constructs for interaction with APIs use JWTs, building up to user and workload identities that use OpenID Connect (OIDC) for authentication and access management.

Accepted decisions constrain how this works:

- every kernel operation goes through a capability ([0002](0002-capability-security-model.md));
- signatures are hybrid post-quantum ([0003](0003-hybrid-post-quantum-cryptography.md));
- remote failure is visible, and realms federate ([0004](0004-network-transparency-and-failure.md)).

The [security tokens design note](../design/security-tokens.md) works through the conflicts and the current state of the standards.

## Decision

1. **Two layers of authority.**
   - JWTs are the portable form of authority. A client presents one when it binds to an object interface ([0014](0014-versioned-object-apis.md)), when a session crosses nodes, and when authority is delegated.
   - The object's manager verifies the token once. It then returns a kernel capability for a local client, or a session bound to the secure channel for a remote one. Calls go through that capability or session, with no token per call.
   - A session ends when its token expires, or as soon as the authorization tree revokes a grant the token relies on ([0016](0016-authorization-sparse-merkle-tree.md)). Renewing a session needs a fresh token.
   - The kernel never sees or parses tokens.
2. **Identity is OIDC-based.**
   - Each realm runs an OpenID Provider and OAuth authorization server as part of its registry.
   - `iss` is the realm's issuer, and `sub` is the principal's object ID in its ABNF text form ([0013](0013-abnf-for-protocols-and-calls.md)).
   - Managers accept access tokens only, never ID tokens.
   - **Users** log in through dm, authenticating natively to the realm's provider with a password, passkey or smart card, since ASPIS has no web browser. External identity providers are reached with the OAuth device authorization grant (RFC 8628) or OpenID CIBA.
   - **Workloads** (services, processes and nodes) receive tokens bound to keys they hold. A node bootstraps its identity from its genesis key ([0001](0001-object-identifiers.md), [0003](0003-hybrid-post-quantum-cryptography.md)). The IETF WIMSE workload drafts and SPIFFE are the models.
3. **Token profile.**
   - Tokens use JWS Compact Serialization with an explicit `typ`, such as `at+jwt` (RFC 9068).
   - **Signatures** use the composite ML-DSA-65 + Ed25519 algorithm from the IETF JOSE composite-signature draft, which matches [0003](0003-hybrid-post-quantum-cryptography.md). The draft revision is pinned until it becomes an RFC. RFC 9964 already standardizes ML-DSA on its own for JOSE; that is the fallback if the composite draft stalls.
   - RFC 8725's rules apply: algorithms are allow-listed per token type, `none` is forbidden, and headers can't carry key URLs (`jku`, `x5u`).
   - Tokens are sender-constrained. A `cnf` claim (RFC 7800) binds each token to its holder's key, and binding requires proof of possession.
   - Access tokens live for minutes. `exp`, `nbf` and `iat` are parsed as 64-bit integers.
   - Authorization claims name objects, interfaces, versions and methods, along with the authorization-tree grant keys they rely on ([0016](0016-authorization-sparse-merkle-tree.md)). Their syntax is defined in ABNF ([0013](0013-abnf-for-protocols-and-calls.md)).
4. **Delegation and call chains.**
   - OAuth Token Exchange (RFC 8693) issues narrower or on-behalf-of tokens.
   - The OAuth Transaction Tokens draft is the model for carrying a user's context through a chain of calls.
5. **Federation.** Realms trust one another through OpenID Federation 1.0 trust chains. [0004](0004-network-transparency-and-failure.md) left this mechanism open.
6. **External interoperability.**
   - Tokens from external identity providers use classical algorithms. They are accepted only at the realm's edge, and the realm re-issues post-quantum-signed ASPIS tokens in their place.
   - Some external audiences can't verify post-quantum signatures. Tokens for them are signed with a separate classical key, and ASPIS never accepts those tokens back.
7. **Time is security-critical.** Token validity depends on clocks, so authenticated time synchronization becomes a requirement. Its design is a design-session item.
8. **Amends 0002.** Rule 5 of [0002](0002-capability-security-model.md) left open the format for delegating authority across nodes. This record fills it with JWTs.

## Consequences

- One identity system runs from login to every API binding, and it interoperates with the OIDC and OAuth ecosystem at the realm's edge.
- **Tokens are large.** ML-DSA-65 + Ed25519 signatures put a token near 5 KB. That is acceptable at bind time but rules out a token on every call.
- **The realm's provider becomes critical infrastructure.** It must be replicated, and nodes need cached keys so they can keep verifying tokens during a partition.
- **The standards are still settling.** ASPIS depends on post-quantum JOSE work that isn't final yet, so algorithm identifiers must stay agile.
- **JSON parsing enters every manager's trust boundary.** Verification therefore lives in one hardened, shared library.

## References

- [Security tokens design note](../design/security-tokens.md)
