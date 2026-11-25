<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0025. Twelve-factor apps: the app's contract as native APIs

- **Status:** Accepted
- **Date:** 2026-11-24, updated 2026-11-25

## Context

The tenet: ASPIS supports twelve-factor apps as a core concern, through its native APIs, and supports the twelve-factor design principles. A realm acts as a virtual cloud provider for these apps. This record covers the app's side of that contract; [0026](0026-realm-as-cloud-provider.md) covers the realm's side.

Facts this decision relies on (details and sources in the [design note](../design/twelve-factor-apps.md)):

- **The text.** *The Twelve-Factor App* dates from 2011, and 12factor.net's text was last updated in 2017.
- **The revision.** Heroku opened the manifesto on 12 November 2024, under CC BY 4.0.
  - A revision is under way on the `next` branch of `twelve-factor/twelve-factor`. It has restructured each factor, but kept their titles and substance, and the maintainers intend to keep exactly twelve.
  - Nothing has been released from it.
- **The contract.** The maintainers describe the factors as a contract between an app's code and its platform, and want that contract narrow: reachability, secure connections and configuration.
- **Open proposals.** None was merged as of November 2026.
  - **Identity** (pull request 34) adds a factor for short-lived, narrowly scoped workload credentials, delivered by the platform and validated by backing services.
  - Two other proposals fold admin processes into the processes factor, and group the factors into facets.
- **Platform conventions.**
  - Heroku's Procfile names process types. Only `web` receives HTTP traffic, on `$PORT`, and `release` runs before a release goes live.
  - The Service Binding Specification for Kubernetes 1.1.0 projects each binding as a directory under `SERVICE_BINDING_ROOT`.
  - systemd passes credentials as files, not environment variables, because environment variables are inherited down the process tree.

What ASPIS already has, and where it conflicts:

- **What fits.**
  - No ambient authority ([0002](0002-capability-security-model.md)) already isolates dependencies.
  - Network transparency with visible failure ([0004](0004-network-transparency-and-failure.md)) is twelve-factor's view of backing services.
  - IDs without clocks ([0001](0001-object-identifiers.md)) suit release identity.
  - Workload identity ([0015](0015-jwt-tokens-and-oidc-identity.md), [0022](0022-spiffe-and-wimse-workload-identity.md)) already does what the Identity proposal asks.
- **What conflicts.**
  - Twelve-factor puts credentials in environment variables, where ASPIS grants authority only through capabilities and tokens.
  - The single-level store persists data by default ([0005](0005-single-level-store.md)), where twelve-factor processes keep nothing.
  - Ports are a host-wide namespace, where ASPIS has no ambient network authority.
  - The POSIX personality supports `fork` and daemons ([0012](0012-posix-compatibility-layer.md)), so a process can try to escape the platform's process manager.

## Decision

1. **The contract is native, with a portable form.**
   - Each element of the contract is a versioned interface defined in the IDL ([0014](0014-versioned-object-apis.md)), below the POSIX layer.
   - The POSIX personality presents the portable form:

     | Factor | Native | POSIX |
     |---|---|---|
     | Config | An environment block, delivered at spawn | `environ` |
     | Backing services | The binding interface | `SERVICE_BINDING_ROOT`, as Service Binding 1.1.0 defines it |
     | Port binding | An exported listener endpoint | `PORT` |
     | Disposability | The lifecycle interface | `SIGTERM` |
     | Logs | Standard output and error | File descriptors 1 and 2 |
     | Identity | The workload identity interface | The SPIFFE Workload Endpoint ([0022](0022-spiffe-and-wimse-workload-identity.md), rule 8) |

   - An app written to the POSIX column runs unchanged on ASPIS and on other twelve-factor platforms.
2. **The manifest.**
   - An app's manifest declares its process types, its base, the bindings it expects and its release task.
   - It is written in TOML 1.1, whose specification publishes an ABNF grammar, so it fits [0013](0013-abnf-for-protocols-and-calls.md) rule 2. ASPIS's schema is also given in ABNF.
   - A Procfile alone is a valid minimal manifest. The `web` and `release` process types keep their Heroku meanings.
   - An app's manifest also declares the interfaces, types and published objects it exports. When a release goes live, the platform registers them in the realm catalog for the deploy ([0027](0027-applications-extend-the-system.md), rule 6).
3. **Dependencies are isolated by construction.**
   - A process's namespace holds only four things: its build, read-only; its base; its scratch area; and its bindings.
   - The **base** is the runtime and POSIX userland the build runs on. It is an immutable, versioned object that each build pins.
   - Nothing installed system-wide is reachable, so an undeclared dependency fails in development as it would in production.
4. **Config is the environment, and it is data.**
   - Every process receives an environment block at spawn: an ordered list of name–value pairs of byte strings, UTF-8 by convention.
     - Rust's standard library reads it directly ([0012](0012-posix-compatibility-layer.md), rule 9).
     - The POSIX libc builds `environ` from it.
   - A deploy's config vars fill the block, and they stay fixed for the life of a release.
   - Names use POSIX's portable form: upper-case letters, digits and `_`, not starting with a digit. The grammar is ABNF.
   - The platform sets a small, documented set of variables:
     - `PORT`, `SERVICE_BINDING_ROOT` and `SPIFFE_ENDPOINT_SOCKET`;
     - variables prefixed `ASPIS_`, naming the process type, the instance and the release.

     Every other name belongs to the deploy.
   - **Config grants nothing**, just as an object ID grants nothing ([0002](0002-capability-security-model.md), rule 2). Credentials are never config vars. They arrive through bindings (rule 5) and workload identity (rule 11).
5. **Backing services are bindings.**
   - A binding has a name, a type and a provider, in the Service Binding specification's vocabulary. It points at an ASPIS object or at an external locator.
   - **ASPIS-native services.** The process receives the object's ID, and binds to it with its workload identity. No secret is involved.
   - **External services.** Their credentials reach the process from the realm's secret store ([0026](0026-realm-as-cloud-provider.md)):
     - as files in a POSIX process, or as read-only objects natively;
     - never inherited by child processes unless passed explicitly;
     - able to rotate in place, with an eventcount signaling each change.
   - **POSIX processes** see each binding as a directory under `SERVICE_BINDING_ROOT`.
   - **Environment variables.** A deploy may map a binding's entries into environment variables, for apps that expect a URL such as `DATABASE_URL`. That is an opt-in, and Cedar policy can forbid it ([0018](0018-cedar-policy-language.md)).
6. **Processes are stateless.**
   - Each process instance gets a scratch area: anonymous memory objects, private to the instance and destroyed when it ends. `/tmp`, `TMPDIR` and `HOME` point there in the POSIX personality.
   - The build is mapped read-only and is immutable, so code can't change at run time.
   - Persistent state lives only behind bindings. A storage binding gives mapped access to objects in the single-level store ([0005](0005-single-level-store.md)), as an attached resource.
7. **Port binding is an exported endpoint.**
   - **Natively,** a process exports a listener endpoint that accepts connections.
   - A native process's listener endpoint serves only routes: browsers, clients outside ASPIS, and POSIX callers. A native app offers its functionality to other programs, to the system and to the realm through objects and interfaces ([0027](0027-applications-extend-the-system.md), rule 1).
   - **In POSIX,** a `web` process binds the port named in `PORT`, and the process manager attaches that socket to the instance's endpoint.
   - Port numbers are local to the instance, so instances never collide.
   - The app parses its own protocol: the platform injects no web server.
8. **Each instance runs in a job.**
   - A job holds the instance and everything it starts. When the instance ends, the job ends, so a process that daemonizes can't outlive it, and there are no PID files to write.
   - Each instance of a POSIX app runs in a POSIX instance of its own ([0012](0012-posix-compatibility-layer.md), rule 3).
9. **The lifecycle interface.**
   - **Readiness.** A native process reports when it is ready. A POSIX `web` process counts as ready once it listens on `PORT`, and other types once they have started.
   - **Stopping.**
     - The process manager delivers a stop notice with a deadline: 30 seconds by default, and settable per process type.
     - A POSIX process receives `SIGTERM`.
     - At the deadline, the job is destroyed.
   - **Sudden death is normal.** Request IDs with at-most-once execution ([0004](0004-network-transparency-and-failure.md), rule 3) and leases ([0005](0005-single-level-store.md), rule 4) let clients retry, and let locks lapse.
10. **Logs are standard output and error.**
    - A process writes an unbuffered stream of events to standard output and error, one event per line.
    - It never opens log files and never routes its logs.
    - The process manager holds the other end of both streams.
11. **Identity is part of the contract.** ASPIS adopts the proposed Identity factor now, because [0015](0015-jwt-tokens-and-oidc-identity.md) and [0022](0022-spiffe-and-wimse-workload-identity.md) already provide it.
    - Each instance receives a workload identity from the process manager ([0022](0022-spiffe-and-wimse-workload-identity.md), rule 7): its process type's principal, a key the instance holds, and a WIT bound to that key.
    - The credentials are short-lived, and they rotate without a restart.
    - Identity reaches the process through its capabilities. There is no metadata endpoint on the network.
12. **The kernel provides jobs and budgets.**
    - Jobs can be stopped as a unit.
    - Each job has a memory budget and a CPU budget.
    - Memory objects can be immutable and shared across processes, and anonymous memory objects end with their job.

    These are general-purpose features. They join the POSIX personality's kernel needs as inputs to the kernel specification ([design note §8](../design/twelve-factor-apps.md#8-what-the-kernel-must-provide)).

## Consequences

- **No ASPIS-specific code needed.** Twelve-factor apps run unchanged in the POSIX personality, and native apps get the same contract through typed interfaces.
- **Four factors are enforced, not just recommended:**
  - dependency isolation, through namespaces;
  - code that can't change at run time, through immutable builds;
  - stateless processes, through scratch areas;
  - no escaping the process manager, through jobs.
- **Credentials leave the environment by default.** Apps that read credentials from environment variables need an explicit mapping, which policy may refuse.
- **Some software won't fit.** Programs that write beside their code or keep local state need a scratch path or a storage binding. Otherwise they run as ordinary processes, outside the app model. The app model is the supported path for services; it isn't required of every program.
- **New interfaces to specify:**
  - the environment block;
  - bindings;
  - the lifecycle interface;
  - listener endpoints;
  - the manifest schema and its grammar.
- **The kernel gains requirements:** jobs and budgets. They are general-purpose, and seL4's untyped memory and MCS scheduling contexts already provide most of them.
- **A moving reference.** The twelve-factor revision and its Identity proposal may still change. ASPIS follows the published text, and records where it goes further.

## References

- [Twelve-factor apps design note](../design/twelve-factor-apps.md)
- [The Twelve-Factor App](https://12factor.net/) and its [revision in progress](https://github.com/twelve-factor/twelve-factor)
- [Service Binding Specification for Kubernetes 1.1.0](https://servicebinding.io/spec/core/1.1.0/)
- [TOML 1.1.0](https://toml.io/en/v1.1.0)
- [systemd credentials](https://systemd.io/CREDENTIALS/)
