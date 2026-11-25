<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0030. What managers accept, when sessions end, and where group memberships come from

- **Status:** Superseded by [0015](0015-jwt-tokens-and-oidc-identity.md) and [0018](0018-cedar-policy-language.md)
- **Date:** 2026-11-24

## Context

Correcting the design notes on 2026-11-24 turned up three places where an accepted record still says something that a later accepted record replaced, without the later one recording the amendment. The later records make the intent clear. This record makes the earlier text say it.

1. **What managers accept at bind.**
   - [0015](0015-jwt-tokens-and-oidc-identity.md) rule 2 says: "Managers accept access tokens only, never ID tokens."
   - [0022](0022-spiffe-and-wimse-workload-identity.md) rule 4 later made 0015's workload tokens WITs. It also made every proof of possession at bind take the WPT form, which the WIMSE draft binds to a WIT.
   - [0025](0025-twelve-factor-app-contract.md) rule 5 has a process bind to an ASPIS-native service "with its workload identity".
   - 0022 records an amendment of 0015 rule 2 only for the WIT's `sub`, so 0015 rule 2 still excludes WITs at bind.
2. **When a session ends.**
   - [0015](0015-jwt-tokens-and-oidc-identity.md) rule 1 ends a session "as soon as the authorization tree revokes a grant the token relies on".
   - [0019](0019-authzen-decision-protocol.md) rule 8 replaced the grant keys named in tokens with the policies that determined the decision. Managers tag each session and capability with those policies, and a session ends when a new root revokes any of their branches.
   - 0019 records that it amends 0015 rule 3 and [0016](0016-authorization-sparse-merkle-tree.md) rule 6, but not 0015 rule 1.
3. **Where group memberships come from.**
   - [0018](0018-cedar-policy-language.md) rule 3 says principals and their group memberships come "from the principal tree and the realm registry".
   - [0019](0019-authzen-decision-protocol.md) rule 5 has the decision point resolve principal attributes and group memberships itself, "from the principal tree".

## Decision

1. **Managers accept access tokens and WITs, never ID tokens.**
   - This replaces the third bullet of [0015](0015-jwt-tokens-and-oidc-identity.md) rule 2.
   - A bind carries the token with a proof of possession in WPT form ([0022](0022-spiffe-and-wimse-workload-identity.md), rule 4).
   - An access token's `sub` stays the principal's object ID, and a WIT's is the identity URI ([0022](0022-spiffe-and-wimse-workload-identity.md), rule 4).
2. **A session ends when its token expires, or as soon as a new root of the authorization tree revokes a branch that holds one of the policies that determined its decision** ([0019](0019-authzen-decision-protocol.md), rule 8).
   - This replaces the third bullet of [0015](0015-jwt-tokens-and-oidc-identity.md) rule 1.
   - Renewing a session still needs a fresh token.
3. **Principals' attributes and group memberships come from the principal tree alone.**
   - This replaces the first bullet of [0018](0018-cedar-policy-language.md) rule 3, to match [0019](0019-authzen-decision-protocol.md) rule 5.
   - The realm registry still holds principals ([0002](0002-capability-security-model.md), rule 4). A decision point reads what it needs about them only from its node's replica of the tree.
4. **Nothing else in 0015 or 0018 changes.**

## Consequences

- **The design doesn't change.** The records now say what 0019 and 0022 already decided, and the design notes and views follow this reading.
- **Decisions keep working during a partition.** Everything a decision point needs about a principal is in its node's replica ([0019](0019-authzen-decision-protocol.md), rule 3).
- **Group memberships must be recorded in the principal tree,** not only in the registry. How the registry's changes reach the tree is part of the tree's write path, which is still to be designed.
- **The token profile is still to be specified.** It must say what claims each token carries, and how an access token travels with a WPT-form proof.
  - Under the pinned WPT draft, a proof binds to a WIT ([0022](0022-spiffe-and-wimse-workload-identity.md), rule 10).
  - So programs that bind on a user's behalf, such as those dm starts, need WITs too.
  - The profile must say how the user's access token travels with them.

## References

- [0015](0015-jwt-tokens-and-oidc-identity.md), [0018](0018-cedar-policy-language.md), [0019](0019-authzen-decision-protocol.md), [0022](0022-spiffe-and-wimse-workload-identity.md), [0025](0025-twelve-factor-app-contract.md)
- [IETF WIMSE, Workload Proof Token, draft-ietf-wimse-wpt-02 (27 August 2026)](https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/)
