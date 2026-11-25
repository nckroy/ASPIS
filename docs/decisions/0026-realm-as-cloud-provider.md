<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->

# 0026. The realm as a virtual cloud provider for twelve-factor apps

- **Status:** Accepted. Amends [0020](0020-realm-certificate-authority.md) (rule 11). Amended by [0027](0027-applications-extend-the-system.md) (rule 7) and [0028](0028-discovery-and-realm-catalog.md) (rule 7).
- **Date:** 2026-11-24

## Context

The tenet: a realm acts as a virtual cloud provider for twelve-factor apps. [0025](0025-twelve-factor-app-contract.md) defines what an app sees; this record defines what the realm runs to provide it.

A twelve-factor platform does six jobs:

- it builds a codebase into a bundle;
- it releases the bundle with each deploy's config;
- it schedules processes by type and count;
- it routes hostnames to web processes;
- it attaches backing services;
- it collates logs.

Facts this decision relies on (details and sources in the [design note](../design/twelve-factor-apps.md)):

- **Heroku's platforms.**
  - Heroku's original platform is where twelve-factor came from.
  - Heroku's Fir platform, generally available since 14 April 2025, rebuilt the same contract on Kubernetes, Cloud Native Buildpacks and OCI images, with OpenTelemetry drains in place of its old logging.
- **The standards a platform uses.**
  - Cloud Native Buildpacks: Buildpack API 0.12 and Platform API 0.15, both December 2025.
  - OCI image specification 1.1.1 and distribution specification 1.1.1.
  - Service Binding Specification for Kubernetes 1.1.0.
  - Open Service Broker API v2.17, maintained under Cloud Foundry.
  - OpenTelemetry, a CNCF graduated project since May 2026.
  - Syslog: RFC 5424, with TLS transport in RFC 5425, updated by RFC 9662.
  - SLSA 1.2, approved in November 2025.
- **Cloud credentials.** Clouds give VMs credentials through a link-local metadata endpoint. Request forgery made that a target, which AWS's IMDSv2 (November 2019) works to blunt.

Much of what a cloud provider runs, a realm already runs:

- an identity provider and a CA ([0015](0015-jwt-tokens-and-oidc-identity.md), [0020](0020-realm-certificate-authority.md));
- the authorization tree and PDPs ([0016](0016-authorization-sparse-merkle-tree.md) to [0019](0019-authzen-decision-protocol.md));
- workload attestation ([0022](0022-spiffe-and-wimse-workload-identity.md));
- a secure network between nodes ([0004](0004-network-transparency-and-failure.md), [0020](0020-realm-certificate-authority.md));
- a single-level store ([0005](0005-single-level-store.md));
- federation with other realms ([0017](0017-openid-federation-membership.md)).

## Decision

1. **The realm is the provider.**
   - A realm pools its nodes for apps, whether those nodes are bare metal or VMs at a cloud provider. Apps never name nodes.
   - The realm runs eight new services:
     - an App API;
     - a builder;
     - a release store;
     - a scheduler;
     - a router;
     - a service broker;
     - a secret store;
     - a log router.
   - Each has versioned interfaces ([0014](0014-versioned-object-apis.md)), authenticates with its workload identity, and asks its node's PDP for decisions ([0018](0018-cedar-policy-language.md), [0019](0019-authzen-decision-protocol.md)).
2. **Apps, deploys, builds and releases are objects.** Each is a new class in [0001](0001-object-identifiers.md)'s registry.
   - An **app** names one codebase: a repository, and optionally a directory within it. It has many deploys.
   - A **deploy** is a running instance of an app. It holds its config vars, bindings, routes, formation, current release and minting authority (rule 11). It is named in the realm's namespace, for example `//<realm>/apps/<app>/<deploy>`, so Cedar's entity hierarchy can grant access by app or by subtree.
   - A **build** is immutable. It comes from one commit of its app's codebase.
   - A **release** is immutable. It joins a build, its base, the deploy's config and its bindings.
     - Each deploy numbers its releases with a 64-bit counter, `v1`, `v2` and so on, and each release also has an object ID. Neither contains a clock.
     - Every new build, config change or binding change creates a release.
     - A rollback creates a new release from an old one, so the history is append-only.
3. **Build.**
   - The builder runs buildpacks, following the Cloud Native Buildpacks Buildpack API 0.12, in a sandbox under the POSIX personality ([0012](0012-posix-compatibility-layer.md)).
   - Its network grants reach only the package registries the app declares, or a realm mirror.
   - Each build carries an SBOM, and SLSA 1.2 build provenance signed with the builder's workload identity.
   - Builds never contain config or credentials ([0021](0021-entropy-before-keys.md), rule 11).
   - Builds are exported to and imported from OCI registries as OCI artifacts (image specification 1.1.1, distribution specification 1.1.1).
4. **Release and run.**
   - A deploy runs a build only if its provenance verifies and meets the deploy's Cedar policy, which may require a particular builder or SLSA build level.
   - A release's task, if it has one, runs to completion as a one-off process before the release goes live. If the task fails, the release stops there.
   - Deploys roll out in four steps:
     1. new instances start;
     2. they report ready;
     3. the router moves traffic to them;
     4. the old instances receive stop notices.
   - Nodes cache builds freely, because immutable objects need no coherence protocol ([0005](0005-single-level-store.md), rule 4). Instances map their build; they never unpack an image.
5. **Scheduling.**
   - A deploy's formation gives each process type a count and a size. The scheduler keeps the formation running:
     - it places instances across nodes and failure domains;
     - it restarts crashed instances, with backoff;
     - it moves instances off nodes that fail or drain.
   - Sizes are budgets that the kernel enforces on each instance's job ([0025](0025-twelve-factor-app-contract.md), rule 12).
   - A process type declared singleton runs under a lease ([0005](0005-single-level-store.md), rule 4), so a partition never leaves two instances running.
   - Each owner (a principal or a group) has quotas. The scheduler admits a formation only within its owner's quota, and the realm meters instance time by size for each deploy.
6. **Routing.**
   - The router runs on edge nodes and terminates TLS for each route.
     - It spreads requests across ready instances, without session affinity.
     - It carries each connection to its instance over the realm's RPC channel: TLS 1.3 over QUIC, mutually authenticated between nodes ([0020](0020-realm-certificate-authority.md), rule 3).
   - **Public routes** map a hostname, and optionally a path prefix, to a deploy's `web` processes.
     - Hostnames in the realm's domain hold an HTTPS CA certificate, plus a Web PKI certificate for clients that need one (rule 14).
     - Custom domains hold Web PKI certificates only.
   - **Internal routes** are reachable only by deploys bound to them.
     - The router is their enforcement point ([0019](0019-authzen-decision-protocol.md)).
     - The network server on the caller's node vouches for which process opened the connection. The router checks that the caller's deploy holds the binding's grant.
7. **Backing services.**
   - The service broker keeps a catalog of service types and plans. It provisions, binds, unbinds and deprovisions instances, on the Open Service Broker API's model. Third-party brokers can be registered with it.
   - **Binding grants; unbinding revokes.** A binding grants the deploy's principals access to the service through the authorization tree ([0016](0016-authorization-sparse-merkle-tree.md)). Unbinding revokes the grant's branch.
   - **Kinds of service:**
     - External services are bound as user-provided instances: a locator, plus credentials held in the secret store.
     - A deploy binds to another deploy through that deploy's internal route.
     - The realm offers storage on the single-level store as a service.
8. **Config and secrets.**
   - A deploy's config vars belong to the deploy. Setting one is an authorized call, and creates a release.
   - The secret store encrypts credentials with keys from the key service ([0003](0003-hybrid-post-quantum-cryptography.md), rule 6).
   - It releases them only to the instances of deploys bound to them, and to principals explicitly granted the right to read them.
9. **Logs.**
   - The log router merges each deploy's instances into one stream, together with platform events: builds, releases, scaling, crashes and router access logs.
   - Each event carries the deploy, release, process type, instance and stream, a timestamp, and a sequence number per instance.
   - Destinations:
     - live tails in dm pads ([0011](0011-dm-window-system.md));
     - bounded retention in the realm;
     - drains over OTLP, and over syslog (RFC 5424) on TLS (RFC 5425, as updated by RFC 9662).
   - Reading a deploy's logs and adding a drain are authorized calls.
10. **Admin processes.**
    - A `run` call starts a one-off process from a release of a deploy, with the deploy's config, bindings and identity.
    - The process either attaches to a dm pad or runs detached, with its output in the deploy's log stream.
    - Its token names the operator who started it as the actor (RFC 8693's `act` claim).
    - The realm's audit log records every run, and Cedar policy decides who may run what on which deploy.
11. **Each deploy has its own minting authority.**
    - A deploy's principals are minted under an authority of its own, as each external issuer's are ([0017](0017-openid-federation-membership.md), rule 5). There is one principal per process type.
    - Revoking a deploy is then a single branch revocation in the principal tree.
    - An instance uses its process type's identity URI and holds its own key ([0022](0022-spiffe-and-wimse-workload-identity.md)).
12. **The App API.**
    - The API is resource-oriented, with two bindings, as AuthZEN has ([0019](0019-authzen-decision-protocol.md), rule 2):
      - ASPIS RPC, from the IDL;
      - HTTPS with JSON, at the edge.
    - Requests carry IDs, so retries are safe ([0004](0004-network-transparency-and-failure.md), rule 3).
    - **Authentication.**
      - External clients use OAuth access tokens.
      - CI systems exchange their own OIDC tokens at the edge (RFC 8693, [0017](0017-openid-federation-membership.md)), so no pipeline needs a long-lived API key.
    - The API is declarative enough to back an OpenTofu provider, so realms and their apps can be managed as code.
    - Code reaches the realm by `git push` to the edge, or the builder fetches a commit from the codebase's host.
13. **Parity and promotion.**
    - **Pipelines.** A pipeline orders an app's deploys. Promotion creates a release in the next deploy from the same build, never a rebuild. Config stays with each deploy.
    - **The same services everywhere.** Every realm offers the same service types; only their plans differ.
    - **Small realms.** A single-node realm on QEMU ([0007](0007-initial-hardware-targets.md)) has the same APIs as a production realm.
    - **Across realms.**
      - A release can be promoted from one realm to another when the target trusts the source realm's builder through ASPIS-native federation ([0017](0017-openid-federation-membership.md); [0020](0020-realm-certificate-authority.md), rule 10).
      - A deploy may bind services in a federated realm ([0004](0004-network-transparency-and-failure.md), rule 1).
14. **Amends [0020](0020-realm-certificate-authority.md), rule 11.**
    - App routes join the edge endpoints that rule 11 lists. A public route in the realm's domain also holds a Web PKI certificate, obtained with ACME.
    - A custom domain outside the realm's domain holds Web PKI certificates only, because the HTTPS CA's name constraints confine it to the realm's domain ([0020](0020-realm-certificate-authority.md), rules 1 and 5).
    - ASPIS clients still never accept a Web PKI certificate for a name in the realm's domain.

## Consequences

- **A familiar platform with stronger guarantees.** Developers push, release, scale and attach as on Heroku. In addition:
  - bindings to ASPIS-native services need no secrets, and unbinding revokes access;
  - deploys run only builds whose provenance checks out;
  - CI pipelines hold no long-lived keys.
- **More critical infrastructure.** The scheduler, router and secret store join the provider, the CA, the authorization service and the PDPs. The control plane's own state must be replicated, and how is a design-session item.
- **A larger edge.** Public routes bring app traffic onto the realm's HTTPS edge, with classical certificates for browsers.
- **Custom domains are classical only** until public post-quantum certificates arrive. A route under the realm's domain gives ASPIS clients a hybrid chain.
- **Ecosystem work comes first.** Buildpacks and their base images assume Linux. ASPIS needs a base, and buildpacks that target ASPIS, before apps can build.
- **Clocks matter again.** Log ordering across instances and singleton leases both depend on synchronized time ([0015](0015-jwt-tokens-and-oidc-identity.md), rule 7), which is already a requirement.
- **The realm keeps accounts.** Quotas and metering make it accountable for resources as a provider is. Billing is out of scope.
- **Familiar tools work:** OCI registries, buildpacks, Service Binding libraries, Open Service Broker brokers, OpenTelemetry and syslog collectors, and OpenTofu.

## References

- [Twelve-factor apps design note](../design/twelve-factor-apps.md)
- [Cloud Native Buildpacks specification](https://github.com/buildpacks/spec)
- [OCI image specification](https://github.com/opencontainers/image-spec) and [distribution specification](https://github.com/opencontainers/distribution-spec)
- [Service Binding Specification for Kubernetes 1.1.0](https://servicebinding.io/spec/core/1.1.0/)
- [Open Service Broker API](https://github.com/cloudfoundry/servicebroker)
- [SLSA 1.2](https://slsa.dev/spec/v1.2/)
- [RFC 5424](https://www.rfc-editor.org/info/rfc5424), [RFC 5425](https://www.rfc-editor.org/info/rfc5425) and [RFC 9662](https://www.rfc-editor.org/info/rfc9662), syslog
- [RFC 8693, OAuth 2.0 Token Exchange](https://www.rfc-editor.org/info/rfc8693)
- [Heroku Fir](https://devcenter.heroku.com/changelog-items/3188)
