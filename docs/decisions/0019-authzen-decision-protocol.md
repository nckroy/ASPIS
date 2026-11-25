<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->

# 0019. AuthZEN for requesting and receiving authorization decisions

- **Status:** Accepted. Amends [0015](0015-jwt-tokens-and-oidc-identity.md), rule 3, and [0016](0016-authorization-sparse-merkle-tree.md), rule 6.
- **Date:** 2026-11-24

## Context

The brief says ASPIS uses the AuthZEN wire protocol to request and receive authorization decisions.

The OpenID AuthZEN **Authorization API 1.0** became an OpenID Final Specification in January 2026. It defines:

- **Information model:** a subject, an action, a resource and a context. Subjects and resources each have a type, an id and optional properties; an action has a name.
- **Evaluation APIs:** single access evaluation, and batch evaluation with `execute_all`, `deny_on_first_deny` or `permit_on_first_permit` semantics.
- **Search APIs:** subject, resource and action search, with pagination.
- **Metadata:** published at `/.well-known/authzen-configuration`.
- **HTTPS binding:** HTTPS with I-JSON is the binding every compliant policy decision point (PDP) must implement, and the spec allows other bindings as profiles.
- **Left open:** how the policy enforcement point (PEP) authenticates, how far PEP-supplied attributes are trusted, and the format of reasons and obligations in a decision's context.

See the [design note](../design/policy-and-decisions.md).

## Decision

1. **AuthZEN carries every authorization decision in ASPIS.**
   - Object managers act as policy enforcement points and request decisions from PDPs running Cedar ([0018](0018-cedar-policy-language.md)).
   - A bind ([0014](0014-versioned-object-apis.md)) that needs several methods is checked with one batch evaluation.
2. **Two bindings, same messages.**
   - **ASPIS RPC binding.** This is a profile, which the spec allows. The AuthZEN JSON messages travel unchanged over ASPIS IPC and RPC. The interface is defined in the IDL with its ABNF, and JSON's own grammar is ABNF (RFC 8259), so the messages fit [0013](0013-abnf-for-protocols-and-calls.md).
   - **HTTPS binding.** This is for enforcement points outside ASPIS, such as services in joined federations ([0017](0017-openid-federation-membership.md)). The realm publishes signed AuthZEN metadata.
3. **Every node runs a PDP.**
   - It evaluates against the node's replica of the authorization tree ([0016](0016-authorization-sparse-merkle-tree.md)), so decisions are local and keep working during a partition, within 0016's staleness bound.
   - Managers reach it over local IPC.
   - The realm also runs an HTTPS PDP endpoint for external enforcement points.
4. **Mapping to AuthZEN fields.** The string forms are defined in ABNF ([0013](0013-abnf-for-protocols-and-calls.md)).
   - The subject is a principal, identified by its object ID.
   - The resource is an object, identified by its ID and typed by its object type.
   - The action name is the interface, major version and method.
   - The context carries verified token claims, the tree epoch and the calling channel.
5. **Attribute trust (ASPIS profile).** AuthZEN lets enforcement points supply properties without verification. In ASPIS:
   - the PDP resolves principal attributes and group memberships itself, from the principal tree;
   - an enforcement point may supply properties only for objects it manages, and the PDP checks that it does.
6. **Authentication.**
   - Local requests need a kernel capability to the node's PDP.
   - Remote requests travel on the post-quantum channel ([0003](0003-hybrid-post-quantum-cryptography.md)), carrying the enforcement point's workload token ([0015](0015-jwt-tokens-and-oidc-identity.md)).
   - Requests over HTTPS use OAuth, as AuthZEN recommends.
7. **Decision context (ASPIS profile).** A decision's context carries:
   - the policies that determined it, as authorization-tree keys taken from Cedar's diagnostics;
   - the epoch it was evaluated at;
   - step-up hints such as `acr_values`.

   An enforcement point rejects a permit whose context it doesn't understand, as the spec allows. Decisions sent across nodes are signed with the node's key.
8. **Revocation tracking. This amends [0015](0015-jwt-tokens-and-oidc-identity.md) rule 3 and [0016](0016-authorization-sparse-merkle-tree.md) rule 6.**
   - Managers tag each session and capability with the determining policies from the decision, instead of the grant keys named in tokens. When a new root revokes any of those branches, the session ends.
   - Token scopes become an upper bound, enforced by a realm-wide Cedar `forbid` rule: no decision ever exceeds the token's scopes.
9. **Search.** Subject and action search come first, because they can be answered from an object's branch. Resource search follows once a per-principal index exists.

## Consequences

- **Standards compatibility.** Every decision in the system uses a standard protocol, and the same PDP can serve external enforcement points.
- **JSON parsing.** Parsing JSON adds cost to each decision. That's acceptable because decisions happen at bind time, not on every call ([0015](0015-jwt-tokens-and-oidc-identity.md)).
- **An ASPIS profile.** ASPIS needs its own AuthZEN profile covering the RPC binding, attribute trust, context keys and type and action naming. It should be published so other implementations can interoperate.
- **New forbid policies.** A newly added `forbid` doesn't appear as a revoked branch. Managers must re-evaluate the sessions it could affect when a new root touches the relevant branches.

## References

- [Policy and decisions design note](../design/policy-and-decisions.md)
- [AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html)
