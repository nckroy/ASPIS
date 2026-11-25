<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->

# 0027. Applications extend the system through objects and versioned interfaces

- **Status:** Accepted. Amends [0025](0025-twelve-factor-app-contract.md) (rules 2 and 7) and [0026](0026-realm-as-cloud-provider.md) (rule 7).
- **Date:** 2026-11-24

## Context

The tenet:

- Applications at the ASPIS level, below the POSIX layer, expose their functionality to the system and the realm as objects, with the same versioned API standards as ASPIS itself.
- An application such as a relational database service can then offer the whole realm what looks like a core OS function, although it was added later as an application rather than built in.

[0028](0028-discovery-and-realm-catalog.md) covers the second half of the tenet: discovery, and the realm catalog.

**What [0014](0014-versioned-object-apis.md) already provides.**
- Every interaction goes through an interface.
- Interfaces are objects, and one defined outside ASPIS uses its definer's authority.
- Every object reports its interfaces, versions, type and attributes.

**What is missing.**
- An obligation on applications to offer their functionality only this way.
- The means for applications to register their own types and interfaces at run time.
- A way for an application's objects to be reached from anywhere in the realm.
- A way for an administrator to give an application's service a place among the system's own.

**AEGIS fell short here** ([research §2.4, §3.2](../research/aegis-domain-os.md#24-typed-objects-type-managers-and-traits)).
- Its type managers implemented traits, and a type database mapped types to managers.
- Apollo never published how to write a trait, so few third-party ones existed.

Precedents (details and sources in the [design note](../design/extensibility-and-discovery.md)):

- **D-Bus.** Applications on the system bus provide services just as system components do. They name their interfaces in reverse-domain form, and the specification recommends a major version in the name.
- **Kubernetes.** Custom resources appear and disappear in a running cluster through dynamic registration, and are used like built-in ones. Many core functions are built as custom resources.
- **Fuchsia.** Components declare what they `expose`.

**What conflicts.**
- [0025](0025-twelve-factor-app-contract.md) rule 7 lets a native process offer services on a listener endpoint.
- [0026](0026-realm-as-cloud-provider.md) rule 7 has one deploy reach another through an internal route.

Both would let a native application offer functionality outside the object model.

## Decision

1. **Objects and interfaces are how a native application offers functionality**, whether to other programs, to the system or to the realm.
   - Its listener endpoints serve only routes: browsers, clients outside ASPIS, and POSIX callers.
   - This amends [0025](0025-twelve-factor-app-contract.md), rule 7.
2. **One interface standard, for ASPIS and applications alike.** An application's interfaces meet the standard that ASPIS's own interfaces meet:
   - they are defined in the IDL, with ABNF generated and published ([0013](0013-abnf-for-protocols-and-calls.md));
   - they are objects with IDs, versioned major.minor under the DCE rule, with stable method numbers ([0014](0014-versioned-object-apis.md));
   - every object implements the base discovery interface ([0014](0014-versioned-object-apis.md), rule 5);
   - clients bind with a token and proof of possession ([0015](0015-jwt-tokens-and-oidc-identity.md), [0022](0022-spiffe-and-wimse-workload-identity.md));
   - the manager is the enforcement point, with Cedar schema generated from the IDL and decisions carried by AuthZEN ([0018](0018-cedar-policy-language.md), [0019](0019-authzen-decision-protocol.md));
   - calls have deadlines and request IDs, and failure is visible ([0004](0004-network-transparency-and-failure.md));
   - errors are typed, and namespaced by interface;
   - each major version has a declared support period ([0014](0014-versioned-object-apis.md), rule 7).

   **The catalog enforces the standard.** It refuses an interface version that fails the checks ASPIS's own interfaces pass in CI ([0013](0013-abnf-for-protocols-and-calls.md), rule 6):
   - the IDL compiles;
   - the generated grammar parses and matches its test vectors;
   - the Cedar schema fragment validates;
   - the version is compatible with its major version's earlier minor versions.
3. **Parity.**
   - The system treats an application's interfaces and types as it treats its own:
     - the same bind path and the same kernel capabilities;
     - the same policy and the same catalog;
     - the same tools, such as dm and the command-line tool;
     - the same POSIX projection: a type that implements the `io` or directory interface appears to POSIX programs as files or directories.
   - Only two things set ASPIS's own interfaces apart:
     - they carry the reserved authority in their IDs ([0001](0001-object-identifiers.md), rule 7);
     - they exist before the app platform starts.

     Nothing else is reserved for built-in code.
4. **Types without new ID classes.**
   - An application defines a type with a type object, minted under its own authority. The type object names the type's manager and its interfaces.
   - Objects of an application's type use a general-purpose class from [0001](0001-object-identifiers.md)'s registry. Their type is an attribute, which their manager reports through the base interface, as AEGIS recorded an object's type in its volume table of contents.
5. **Realm-wide reach.**
   - Objects an application creates are minted under an authority the realm assigns to its deploy ([0026](0026-realm-as-cloud-provider.md), rule 11). The control plane holds the authority's counter, and gives instances blocks of sequence numbers ([0001](0001-object-identifiers.md), rule 4).
   - The location service ([0004](0004-network-transparency-and-failure.md), rule 5) resolves the authority to the deploy's ready instances. A bind to any of the application's objects therefore reaches it from anywhere in the realm, as a bind to a system object does.
   - A manager that shards its objects across instances can register finer-grained locations.
6. **Exports are declared.**
   - An application's manifest declares the interfaces, types and published objects it exports. This amends [0025](0025-twelve-factor-app-contract.md), rule 2.
   - When a release goes live, the platform registers the exports in the catalog for the deploy, so the platform attests every registration.
   - A native service that runs outside the app platform registers through its own service principal.
   - Registration is an authorized call.
7. **Names.**
   - Interface and type names are dotted and reverse-DNS, such as `org.example.sql.table`. The prefix `aspis.` is reserved for ASPIS.
   - Cedar policy decides which publisher may register which prefix.
   - Binding always uses IDs, so a look-alike name can't capture a binding.
   - The grammar of names is defined in ABNF.
8. **Becoming a realm function.** A realm administrator can make an application's service look like part of the OS:
   - by mounting its published object at a system name in the realm's namespace, such as `//<realm>/sys/sql`;
   - by making it the realm's default provider of an interface.

   The catalog still shows who provides the service. An interface mounted as a realm function follows the realm's deprecation policy, as ASPIS's own interfaces do.
9. **Binding between applications.**
   - A native deploy binds directly to another application's published objects, with grants in the authorization tree ([0025](0025-twelve-factor-app-contract.md), rule 5). Internal routes remain for POSIX apps. This amends [0026](0026-realm-as-cloud-provider.md), rule 7.
   - A binding may name an interface rather than an object. The platform resolves it through the catalog when it creates the release, and the release pins the object it resolved to ([0026](0026-realm-as-cloud-provider.md), rule 2).
10. **HTTPS bindings.**
    - Any interface may also be offered over HTTPS, through a binding the IDL compiler generates, as the App API and AuthZEN already are.
    - The compiler also generates an OpenAPI 3.2 description, and the realm lists the API at its edge ([0028](0028-discovery-and-realm-catalog.md)).

## Consequences

- **Added later, used like built in.** A database, queue or search engine installed later is named, bound, authorized and discovered exactly as an OS service is.
- **AEGIS's closed trait system is opened.** Third parties write types and interfaces with the same tools and checks as ASPIS's own.
- **Applications carry the cost of the standard.** They need IDL, versioning discipline and conformance checks. Native applications give up ad hoc protocols; POSIX applications keep theirs.
- **Trust is visible, not built in.**
  - The catalog always names the publisher, and policy decides who may publish, mount and become a default provider.
  - An application mounted as a realm function becomes critical infrastructure: its availability and its deprecations now affect everyone.
- **The bootstrap line holds.** Nothing that the catalog, the app platform or the identity services depend on can be provided by an application.
- **New work:**
  - interfaces for registering types;
  - the location service's protocol for deploy authorities, including moving an authority to a successor deploy;
  - the HTTPS binding generator;
  - the policy for name prefixes.

## References

- [Design note: applications that extend the system, and the catalog that finds them](../design/extensibility-and-discovery.md)
- [Research notes §2.4, §3.2 and §5](../research/aegis-domain-os.md)
- [D-Bus Specification](https://dbus.freedesktop.org/doc/dbus-specification.html)
- [Kubernetes custom resources](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/)
- [OpenAPI Specification 3.2.0](https://spec.openapis.org/oas/v3.2)
