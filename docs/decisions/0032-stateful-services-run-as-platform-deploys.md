<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0032. Stateful services run as platform deploys

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

[0027](0027-applications-extend-the-system.md) lets an application such as a relational database offer what looks like a core OS function. An application's exports can be registered two ways ([0027](0027-applications-extend-the-system.md), rule 6): by the app platform when a release goes live, or by a native service that runs outside the platform, through its own service principal.

That left open where stateful services such as databases run. The [twelve-factor design note](../design/twelve-factor-apps.md#9-open-questions) asked whether databases run on the platform, through storage bindings and singleton process types. The project owner decided on 2026-11-24 that they do.

## Decision

1. **Stateful services, such as databases, run as platform deploys.** They are twelve-factor apps that the realm builds, releases, runs and routes like any other ([0025](0025-twelve-factor-app-contract.md), [0026](0026-realm-as-cloud-provider.md)).
2. **Their processes stay stateless.** A stateful service's data lives behind storage bindings: mapped objects in the single-level store ([0025](0025-twelve-factor-app-contract.md), rule 6), which the realm offers as a service ([0026](0026-realm-as-cloud-provider.md), rule 7).
3. **A process type that must run as one instance, such as a database's primary, is declared singleton.** It runs under a lease, so a partition never leaves two instances running ([0026](0026-realm-as-cloud-provider.md), rule 5).
4. **They extend the system as any application does.** The manifest declares their exports, and the platform registers them when a release goes live ([0027](0027-applications-extend-the-system.md), rule 6). An administrator can mount them at a system name or make them a default provider ([0027](0027-applications-extend-the-system.md), rule 8).

## Consequences

- **Databases get the platform's guarantees:** builds with provenance, numbered releases and rollback, quotas and metering, and one log stream per deploy ([0026](0026-realm-as-cloud-provider.md)).
- **A native service outside the platform remains possible** for other kinds of service ([0027](0027-applications-extend-the-system.md), rule 6). This decision covers stateful services.
- **Still to be designed:**
  - how a storage binding is provisioned, sized and charged against quotas;
  - replication and failover beyond a single singleton instance;
  - backing up a stateful deploy's storage, as part of the realm's backup and recovery work;
  - how singleton leases behave across partitions and clock skew. Leases depend on synchronized time ([0026](0026-realm-as-cloud-provider.md), Consequences).

## References

- [Twelve-factor apps, and the realm as their cloud](../design/twelve-factor-apps.md), §9
- [Applications that extend the system](../design/extensibility-and-discovery.md), §6 (a relational database added later)
