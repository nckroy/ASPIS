<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0018. Cedar as the realm's policy language and engine

- **Status:** Accepted. Amends [0016](0016-authorization-sparse-merkle-tree.md), rule 1. Amended by [0030](0030-bind-tokens-sessions-and-group-memberships.md) (rule 3).
- **Date:** 2026-11-24

## Context

The brief: integrate the Cedar policy language as the realm's policy description and engine.

Cedar is an open-source authorization language. Its model is a principal performing an action on a resource in a context:

- `permit` and `forbid` policies;
- default deny, with `forbid` overriding `permit`;
- entity hierarchies, so a principal can be `in` a group and a resource `in` a directory;
- policy templates with `?principal` and `?resource` slots;
- a schema validator.

The engine is written in Rust. The project keeps a definitional model of the language in Lean and tests the engine against it. Cedar became a CNCF Sandbox project in October 2025 ([design note](../design/policy-and-decisions.md)).

[0016](0016-authorization-sparse-merkle-tree.md) stores permissions in each realm's authorization tree and revokes them by branch, but it leaves open what a permission *is*. Cedar answers that.

## Decision

1. **Every realm policy is a Cedar policy.** That covers:
   - realm-wide rules;
   - per-object grants;
   - rules for principals from external federations ([0017](0017-openid-federation-membership.md));
   - the rules behind POSIX permissions ([0012](0012-posix-compatibility-layer.md)).
2. **Policies live in the authorization tree.** This amends [0016](0016-authorization-sparse-merkle-tree.md), rule 1.
   - **Grants** are template-linked policies: a template (a fixed set of actions) linked to one principal and one resource. They sit at grant leaves under the object's branch.
   - **Realm-wide policies** (static policies and templates) sit under a reserved realm-policy branch.
   - The signed root therefore commits to every policy in force.
3. **Entities come from trusted sources.**
   - **Principals** and their group memberships come from the principal tree and the realm registry.
   - **Resources**, with their attributes and parent (such as the containing directory), come from the object's manager.
   - **Context** comes from verified token claims ([0015](0015-jwt-tokens-and-oidc-identity.md)), including issuer, assurance, federation topology and trust marks, together with the tree's epoch and the calling channel.
4. **The schema comes from the IDL.** The IDL compiler ([0013](0013-abnf-for-protocols-and-calls.md)) emits a Cedar schema fragment for each interface version ([0014](0014-versioned-object-apis.md)):
   - each method becomes a Cedar action;
   - the action groups declared in the IDL (such as read, write or administer) become Cedar action groups;
   - object types become entity types.

   Policies are validated against the schema before they are written; a policy that names an unknown action or attribute is rejected.
5. **The engine runs in user space.** The Rust Cedar engine runs inside policy decision points ([0019](0019-authzen-decision-protocol.md)), never in the kernel ([0002](0002-capability-security-model.md)). Until the first decision point starts, authority comes only from the capabilities the root server hands out at boot.
6. **Revocation still works by branch.** Removing a branch removes its `permit`s. Where a denial must override every other permit — an emergency lock-out, say — the realm adds a `forbid` policy or revokes the principal in the principal tree.
7. **Policy changes are checked before they're written.** The realm's policy service validates each change against the schema. It can also refuse changes that break realm invariants, such as one giving external principals write access to system objects.

## Consequences

- One readable, analysable language covers every permission in the system, from file access to federation rules.
- Directory-inherited access, group membership and assurance-based rules come from Cedar's entity model rather than from code inside each manager.
- **IDL-derived schema.** Interface versions now carry policy schema, so a new major version needs its policies reviewed.
- **Fixed action sets.** Templates can't take an action slot, so each grant template fixes its own set of actions.
- **Std dependency.** The Cedar engine depends on Rust's standard library, so decision points arrive after the Rust `std` port ([0012](0012-posix-compatibility-layer.md)).

## References

- [Policy and decisions design note](../design/policy-and-decisions.md)
