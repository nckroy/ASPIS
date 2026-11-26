<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0050. User-space servers name the kernel objects they present

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

[0001](0001-object-identifiers.md)'s Context says: "ASPIS names every object a program can touch with an identifier: files, directories, processes, threads, endpoints, types, principals and nodes." The [founding requirements](README.md#founding-requirements) say: "Files and every other OS fixture programs touch are objects named by unique IDs with an indexable part and a guaranteed globally unique part." Founding requirements aren't re-decided.

As accepted, [0014](0014-versioned-object-apis.md), rule 5 said that every object implements the base discovery interface, and [0028](0028-discovery-and-realm-catalog.md), rule 1 and [0027](0027-applications-extend-the-system.md), rule 2 said the same. [0028](0028-discovery-and-realm-catalog.md), rule 2 had every object that the catalog doesn't list eagerly enumerated through its manager, so that "enumeration therefore reaches every object". [0002](0002-capability-security-model.md), rule 1 calls threads, endpoints and the rest kernel objects. But the kernel can't mint IDs:

- An ID's sequence number comes from a block that the node durably records before using it ([0001](0001-object-identifiers.md), rule 4). The kernel has no storage.
- An ID's 40 random bits come from a CSPRNG ([0001](0001-object-identifiers.md), rule 5), and the kernel uses no randomness ([0021](0021-entropy-before-keys.md), rule 3).
- Kernel objects are reached by capability, never by ID ([0002](0002-capability-security-model.md), rules 1 and 2), and the kernel keeps no names ([0047](0047-the-kernel-follows-sel4.md), Consequences).

Programs also make threads and endpoints all the time, for their own use, and many of these are never seen by anyone else. Minting an ID for each would put a storage write and the entropy service on the path of every thread a program starts, and would make starting the node's first servers impossible, since they run before storage and before the entropy gate.

The [design backlog, D16](../design/design-backlog.md#m2-kernel-objects) asks who mints the IDs of processes, threads and endpoints, whether other kernel objects carry IDs, and who answers their base interface. It names one option: the user-space server that creates the object mints its ID and answers its base interface. It notes that giving IDs to only some threads and endpoints would narrow 0001.

No rule of 0001 says which objects must carry an ID. Its rules say how an ID is built and minted, and its Context and its ID table name processes, threads and endpoints as examples. This record reads 0001's list as the kinds of thing an ID may name, so it changes no rule of 0001. The project owner chose that reading on 2026-11-25, over adding a rule to 0001. This record reads the founding requirement the same way: an object that a program reaches only through its own capability, and that no server presents, isn't one of the OS fixtures that programs touch as objects. Once a server presents it, it gets an ID (rule 2).

Those are rules, not context, and a reading can't narrow them. A kernel object that no server presents has no ID, and no server to answer the base interface for it. So this record was proposed with an edit to each, in the same pull request: [0014](0014-versioned-object-apis.md), rule 5, [0027](0027-applications-extend-the-system.md), rule 2 and [0028](0028-discovery-and-realm-catalog.md), rules 1 and 2 and the matching bullet of 0014's Consequences now give the duty, and enumeration's reach, only to objects that have an ID. This record changes nothing else in them (rule 7).

Claude drafted this record on 2026-11-25.

## Decision

1. **Kernel objects have no IDs inside the kernel.** The kernel never stores, checks or returns an ID. Minting needs storage and randomness, which the kernel doesn't have.
2. **An object gets an ID when a user-space server presents it as an object**: when the server answers the base interface for it ([0014](0014-versioned-object-apis.md), rule 5).
   - The server mints the ID under the minting authority the records assign it. A node's system servers mint under the node's authority, through the node's ID allocation. An application's objects are minted under the authority the realm assigns to its deploy ([0027](0027-applications-extend-the-system.md), rule 5).
   - The server answers that base interface.
3. **Processes and their first threads are named by the server that creates them.** That is the process manager for native processes, and the root server for the servers it starts before the process manager runs. The POSIX process server presents POSIX processes, whose pids are its own ([0012](0012-posix-compatibility-layer.md), rule 3).
4. **Threads and endpoints that a program makes for itself carry no ID** until the program, or a server acting for it, presents them as objects. A debugger or a monitoring tool reaches a process's threads through the process's manager, which holds the process's job capability ([0058](0058-jobs-and-budgets.md)).
5. **A manager names the objects it serves.** The endpoint capability a client gets at bind ([0014](0014-versioned-object-apis.md), rule 4) isn't named in their place. It carries no ID of its own unless a server presents the endpoint as an object, under 0001's endpoint class, as rule 4 allows.
6. **Objects that exist before the entropy gate are the node's well-known objects**, named from 0001's reserved sequence range ([0021](0021-entropy-before-keys.md), rule 3; [0001](0001-object-identifiers.md), rule 4).
   - D36 decides only the authority they are named under and what fills their random field. The servers that start them present them under those names.
   - Until D36 is settled, the build names none of them, and they carry no ID.
   - Objects made after the gate but before storage can't take a sequence number from a durably recorded block ([0001](0001-object-identifiers.md), rule 4). How they are named is still open ([design backlog, D161](../design/design-backlog.md#m3-node-user-space-and-the-entropy-gate); [kernel specification K12](../design/kernel-specification.md#k12-naming-objects-made-after-the-entropy-gate-but-before-storage)).
7. **Discovery covers the objects that have an ID.** Only they implement the base discovery interface, and only they are reached by enumeration ([0014](0014-versioned-object-apis.md), rule 5; [0027](0027-applications-extend-the-system.md), rule 2; [0028](0028-discovery-and-realm-catalog.md), rules 1 and 2).
   - A kernel object reached only by capability has no ID and no base interface. Its holders reach it through its kernel interface, by way of the kernel interface library ([0059](0059-the-kernel-interface-library.md), rule 1), until a server presents it (rule 2).

## Consequences

- **Making a thread or an endpoint stays cheap.** It is a kernel call, with no ID, no storage write and no entropy.
- **Every named process can be found and inspected by ID**, through the process manager's base interface, as can anything a server chooses to present.
- **Some threads and endpoints never have IDs.** Tools that want to see every thread of a process ask the process's manager. A process doesn't hold its own job's capability. The manager does, and through it the manager lists the threads in the job and its descendants, with each thread's address space, and gets capabilities to them ([0058](0058-jobs-and-budgets.md)). So it reaches every thread of the process, including those the runtime makes after the first ([0060](0060-processes-native-spawn-and-elf.md)). Debuggers and crash dumps reach threads through the manager the same way ([0061](0061-debugging.md)).
- **Kernel objects that no server presents aren't in discovery.** They have no base interface and no catalog entry, and enumeration doesn't reach them (rule 7). Objects that have an ID are introspected through the base interface. A kernel object without one is inspected through its capability and its kernel interface ([0059](0059-the-kernel-interface-library.md), rule 1).
- **A presenting server keeps the link between an ID and the object.** The kernel holds no ID, so the server maps each ID it mints to the capability it holds. The [kernel specification](../design/kernel-specification.md#kernel-objects-and-ids) says what the kernel offers for this.
- **The "IDs for kernel objects" conflict is settled** ([design backlog](../design/design-backlog.md#conflicts-between-accepted-adrs)): by this record's reading of 0001 and the founding requirement, and by the edits to 0014, 0027 and 0028 that rule 7 relies on.
- **This record settles D16.** Who mints the IDs of processes, threads and endpoints: the server that presents them (rules 2, 3 and 5). Whether other kernel objects carry IDs: only when a server presents them (rules 1 and 4). Who answers their base interface: that server (rule 2).
- **D36 decides the rest of the early names**: the authority and the random field of the node's well-known objects. Naming objects made after the gate but before storage is a separate open question, which [D161](../design/design-backlog.md#m3-node-user-space-and-the-entropy-gate) asks ([kernel specification K12](../design/kernel-specification.md#k12-naming-objects-made-after-the-entropy-gate-but-before-storage)).

## References

- [Founding requirements](README.md#founding-requirements)
- [0001. Object identifiers](0001-object-identifiers.md); [0014. Versioned object APIs](0014-versioned-object-apis.md), rules 4 and 5; [0021. Entropy before keys](0021-entropy-before-keys.md), rule 3
- [0027. Applications extend the system](0027-applications-extend-the-system.md), rules 2 and 5; [0028. Discovery and the realm catalog](0028-discovery-and-realm-catalog.md), rules 1 and 2
- [0058. Jobs and budgets](0058-jobs-and-budgets.md); [0059. The kernel interface library](0059-the-kernel-interface-library.md), rule 1; [0060. Processes](0060-processes-native-spawn-and-elf.md); [0061. Debugging](0061-debugging.md)
- [Design backlog: conflicts between accepted ADRs](../design/design-backlog.md#conflicts-between-accepted-adrs)
- [The kernel specification](../design/kernel-specification.md)
