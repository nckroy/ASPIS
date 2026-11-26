<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0014. Versioned object APIs

- **Status:** Accepted
- **Date:** 2026-11-24, updated 2026-11-25

## Context

The brief says all objects expose versioned APIs and that this is how every interaction with an object happens. These APIs are a native ASPIS construct, below the POSIX layer.

Precedents:

- **AEGIS traits.** A trait was a set of operations that an object's type manager implemented ([research §2.4](../research/aegis-domain-os.md#24-typed-objects-type-managers-and-traits)).
- **DCE RPC.** DCE RPC grew out of Apollo's NCS. It identifies each interface by a UUID and a major.minor version.
- **COM.** COM made interfaces immutable.
- **Fuchsia.** Fuchsia programs reach system calls only through a vDSO, so the kernel ABI can change underneath them.

## Decision

1. **Interfaces are the only way in.** Every interaction with an object goes through one of its interfaces. That applies to:
   - native programs;
   - system servers;
   - the POSIX layer ([0012](0012-posix-compatibility-layer.md));
   - Display SVG and dm ([0010](0010-svg-core-primitive.md), [0011](0011-dm-window-system.md)).
2. **Interfaces are objects.** Each interface has an ID ([0001](0001-object-identifiers.md)). System interfaces use the reserved ASPIS authority; any other interface uses the authority of whoever defines it. An interface object holds the IDL and the generated ABNF ([0013](0013-abnf-for-protocols-and-calls.md)) for each of its versions, so any program can fetch the definition of any interface.
3. **Versions are major.minor, following DCE RPC's rule.**
   - A client asking for M.n can use an implementation of M.m whenever m ≥ n.
   - Minor versions only add things old clients can ignore: methods, optional fields, error codes, union arms, enum values and flag bits, and new types, constants, action groups and deprecation marks ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rules 10 and 13). Anything incompatible needs a new major version.
   - Types are open unless the IDL declares them closed. Generated bindings accept values they don't know, and preserve them. A closed type never changes within a major version ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rule 10).
   - A manager can serve several major versions at once.
4. **Binding.** A client binds to an object, an interface ID, a major version and a minimum minor version. The manager replies with the version it will speak and a capability or session ([0002](0002-capability-security-model.md), [0015](0015-jwt-tokens-and-oidc-identity.md)). Method numbers stay stable within a major version.
5. **Every object that has an ID implements a base interface for discovery.** It reports which interfaces and versions the object supports, its type, its attributes and its publisher, and the object's catalog entry if it has one ([0028](0028-discovery-and-realm-catalog.md)). AEGIS's trait lookup and COM's `QueryInterface` did the same job.
6. **The kernel is versioned too.** Programs reach system calls only through a kernel interface library mapped into every process, as with Fuchsia's vDSO. The library exposes versioned interfaces for kernel objects, and the raw system-call ABI can change underneath it.
7. **Deprecation.** A major version stays available for a declared support period after its successor ships. The design session sets that period in the API policy.

## Consequences

- Old and new clients coexist, and components upgrade independently.
- Every object that has an ID can be introspected through its base interface, which helps tools, debuggers, dm and the POSIX layer. A kernel object that no server presents has no ID, and is inspected through its capability and its kernel interface ([0050](0050-ids-for-kernel-objects.md)).
- Managers must maintain several major versions during transitions, and the IDL compiler must check that minor versions are compatible.
- Version negotiation costs a little at bind time, and nothing per call.

## References

- [Research notes §2.4](../research/aegis-domain-os.md#24-typed-objects-type-managers-and-traits)
- [DCE 1.1: Remote Procedure Call (The Open Group, C706)](https://pubs.opengroup.org/onlinepubs/9629399/)
- [Fuchsia vDSO](https://fuchsia.dev/fuchsia-src/concepts/kernel/vdso)
