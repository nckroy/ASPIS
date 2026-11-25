<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0028. Discovery: a realm catalog of interfaces, types and objects, updated in real time

- **Status:** Accepted. Amends [0014](0014-versioned-object-apis.md) (rule 5), [0017](0017-openid-federation-membership.md) (rule 8) and [0026](0026-realm-as-cloud-provider.md) (rule 7).
- **Date:** 2026-11-24

## Context

The tenet: API and object discoverability is a core concern of the OS and the realm. A catalog, updated in real time, enumerates the APIs and objects through the discovery system. [0027](0027-applications-extend-the-system.md) covers the first half of the tenet: applications that provide objects and interfaces as the system does.

**What ASPIS already has.**
- **Discovery for each object.** Every object reports its interfaces, versions, type and attributes, and any program can fetch an interface's IDL and ABNF ([0014](0014-versioned-object-apis.md), rules 2 and 5).
- **A location service, so far only named.** An ID's authority is the first location hint, and a location service tracks objects that move ([0004](0004-network-transparency-and-failure.md), rule 5).
- **A search that is waiting.** AuthZEN resource search waits for a per-principal index ([0019](0019-authzen-decision-protocol.md), rule 9).
- **A narrower catalog.** The service broker keeps a catalog of service types and plans ([0026](0026-realm-as-cloud-provider.md), rule 7).

Facts this decision relies on (details and sources in the [design note](../design/extensibility-and-discovery.md)):

- **NCS location brokers (Apollo).**
  - Entries held an object UUID, a type UUID, an interface UUID, a flag, an annotation and a socket address.
  - Every host ran a broker, and a Global Location Broker could be replicated. Clients looked up any combination of object, type and interface.
  - A server that died without unregistering left its entry behind until an administrator removed it with `lb_admin`.
- **DCE RPC.** DCE keeps the stable part of a binding in its name service, and the volatile endpoint in each host's endpoint map.
- **D-Bus** lists the names on the bus and broadcasts `NameOwnerChanged` as they come and go.
- **Kubernetes** lists every resource through aggregated discovery, stable since version 1.30. Clients list, then watch for changes.
- **RFC 9727** (api-catalog, Proposed Standard, June 2025) defines `/.well-known/api-catalog`. It returns a Linkset (RFC 9264) of a publisher's APIs, each linked to its description, such as an OpenAPI 3.2 document.
- **Scale.** Every file is an object, so a realm may hold billions of objects, and they change constantly.

## Decision

1. **Discovery has three layers.**
   - **Each object** implements the base discovery interface. It now also reports the object's publisher, and the object's catalog entry if it has one. This amends [0014](0014-versioned-object-apis.md), rule 5.
   - **Each manager** implements an enumeration interface:
     - it lists the objects the manager holds, one page at a time;
     - it lists them only to callers allowed to see them;
     - it notifies watchers of changes.
   - **The realm** runs the catalog.
2. **What the catalog lists.**
   - **Eagerly and completely:**
     - every interface and version, with the hashes of its IDL, ABNF and Cedar schema;
     - every type, with its managers and interfaces;
     - every published object, such as a service, database, queue or route;
     - mounts at system names, and default providers.

     Every entry names its publisher.
   - **Every other object** is enumerated on request through its manager. The catalog answers such requests by delegating to the collection's manager. Enumeration therefore reaches every object, without the catalog copying every object or holding a complete map of the realm.
3. **The catalog is an object.**
   - It has a versioned interface, `aspis.catalog`, and a well-known ID under the reserved authority ([0001](0001-object-identifiers.md), rule 7). It lists itself.
   - Every node holds a replica.
   - The service broker's catalog of service types and plans becomes part of it. This amends [0026](0026-realm-as-cloud-provider.md), rule 7.
4. **Registrations are signed state.**
   - Registrations are recorded in the authorization tree, in a catalog branch, as certificates already are ([0020](0020-realm-certificate-authority.md), rule 7).
   - Keys are laid out so that everything one publisher registered shares a prefix ([0016](0016-authorization-sparse-merkle-tree.md), rule 2).
   - Each entry holds the hashes of the definitions it registers, so a client can check a definition it fetched against a signed root.
   - Revoking a publisher's branch withdraws all its entries in one epoch, together with its grants.
5. **Availability is soft state.**
   - Which instances serve an entry right now is held by the location service, outside the tree.
   - A process manager registers an instance when it becomes ready, and withdraws it when the instance stops.
   - Every registration is a lease, so a crashed server's entries lapse on their own.
6. **Real time.**
   - **Sequence numbers.** Every change to the catalog has a 64-bit sequence number: a registration when its epoch is signed, and an availability change when its lease starts or ends.
   - **List, then watch.** A client lists at a sequence number and then watches from it, so it misses no change and sees none twice.
   - **Delivery.** Local watchers are woken through eventcounts; remote watchers receive a stream over RPC.
   - **Partitions.**
     - Lookups are answered from the node's replica, so they keep working during a partition.
     - Each answer is marked with the epoch it reflects.
     - Binds still fail closed when the node's tree is too stale ([0016](0016-authorization-sparse-merkle-tree.md), rule 7).

   The design session sets how quickly changes must reach replicas and watchers.
7. **Queries.**
   - A query can select by ID, name, publisher, type or attribute. It can also select by interface and minimum version, under the DCE rule ([0014](0014-versioned-object-apis.md), rule 3).
   - Results arrive a page at a time, with a sequence number to watch from.
   - Queries and results have text forms, defined in ABNF ([0013](0013-abnf-for-protocols-and-calls.md), rule 5).
8. **Discovery is authorized.**
   - Seeing an entry is a Cedar action, `discover`. The catalog asks its node's PDP in batches ([0019](0019-authzen-decision-protocol.md)).
   - By default:
     - interfaces and types are visible to every principal in the realm;
     - published objects follow their publisher's and the realm's policy;
     - principals from outside the realm see only the entries exported to them.
   - The catalog's index of published objects is the per-principal index that AuthZEN resource search was waiting for ([0019](0019-authzen-decision-protocol.md), rule 9).
9. **Registration is checked.**
   - The catalog applies the interface standard's checks ([0027](0027-applications-extend-the-system.md), rule 2) before an entry appears.
   - It passes each Cedar schema fragment to the policy service ([0018](0018-cedar-policy-language.md), rule 4) before the entry appears.
10. **Views.**
    - **POSIX.** The catalog implements the directory interface, so POSIX tools can browse it. Definitions read as text.
    - **dm.** dm offers a catalog browser that updates as entries change.
    - **HTTPS.**
      - The realm serves `/.well-known/api-catalog` (RFC 9727): a Linkset of its HTTPS APIs, each with a `service-desc` link to its OpenAPI description.
      - The catalog's own interface is also offered over HTTPS, for tools outside ASPIS.
11. **Federation.**
    - ASPIS-native federation metadata names the realm's catalog endpoint. This amends [0017](0017-openid-federation-membership.md), rule 8, as [0020](0020-realm-certificate-authority.md) already amended it.
    - A realm can query another realm's catalog for the entries exported to it. Each entry carries its own realm's signed root.

## Consequences

- **One way to find anything.**
  - Every interface, type and published object in the realm is found the same way.
  - Clients stay current by watching, not polling.
- **Stale entries fix themselves**, because availability is leased.
- **A catalog that can be trusted.** Definitions are checked against signed roots, and a revoked publisher disappears from the catalog in the same epoch as its grants.
- **Discovery needs guarding.**
  - The catalog is a map of what the realm offers, so discovery is authorized like any other action.
  - It deliberately holds no index of ordinary objects.
- **Every manager does more.** Each one, including every application's, implements enumeration with change notification.
- **More load on the tree.** Its epochs carry registrations as well as grants. Registrations change only when releases go live or services register, not when instances come and go.
- **New work:**
  - the catalog service and its replicas;
  - the enumeration interface;
  - the location service, with leases;
  - the watch protocol, including for HTTPS clients;
  - OpenAPI generation and the RFC 9727 endpoint.

## References

- [Design note: applications that extend the system, and the catalog that finds them](../design/extensibility-and-discovery.md)
- [RFC 9727, api-catalog](https://www.rfc-editor.org/info/rfc9727), [RFC 9264, Linkset](https://www.rfc-editor.org/info/rfc9264)
- [DCE 1.1: Remote Procedure Call, Name Service Interface](https://pubs.opengroup.org/onlinepubs/9629399/chap2.htm)
- [IBM AIX, The Location Broker (NCS)](http://ps-2.kev009.com/wisclibrary/aix52/usr/share/man/info/en_US/a_doc_lib/aixprggd/progcomc/rpc_lb.htm)
- [Kubernetes API discovery](https://kubernetes.io/docs/concepts/overview/kubernetes-api/)
