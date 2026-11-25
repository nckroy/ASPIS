<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Design backlog

*2026-11-24, updated 2026-11-25. Every open design decision, in the order the build needs them. The companion to the [build plan](build-plan.md).*

This note lists the design decisions that ASPIS still has to make. Each sits under the milestone it must be settled before, and the entries are numbered D01, D02, … in that order. Within a milestone they follow the order in which the build reaches them. The [build plan](build-plan.md) splits the build into chunks (C01, C02, …) and milestones, and says which chunk each decision unblocks.

An entry has a title and four parts:

- **Decide:** what has to be decided.
- **Why open:** what the accepted records leave open, with citations.
- **Options:** the options the documents have named so far. The backlog chooses none of them.
- **Blocks:** the chunks that can't be finished without the decision. **Depends on:** the decisions it needs first.

A settled entry stays in place, with a **Settled:** line naming the record that settled it and the date it was accepted. An entry that is only partly settled has a **Settled in part:** line instead, which says what is still open. The rest of the entry is kept as the record of what was asked.

Once made, each decision becomes an ADR, or a change to one. On 2026-11-25 the project owner accepted [0029](../decisions/0029-founding-node-self-signed-certificate.md) and [0031](../decisions/0031-abnf-is-not-a-command-language.md), which had been proposed, and [0033](../decisions/0033-contributions-docs-license-and-notice-years.md) to [0042](../decisions/0042-log-ring-and-panic-path.md), which settle D01 to D10. Where accepted records conflict, the texts and the options are set out in [Conflicts between accepted ADRs](#conflicts-between-accepted-adrs); two of those conflicts block the build. [Settled since the reading phase](#settled-since-the-reading-phase) lists what has been decided since these items were first collected, so that nothing drops out unrecorded.

1. [M1. First light](#m1-first-light)
2. [M2. Kernel objects](#m2-kernel-objects)
3. [M3. Node user space and the entropy gate](#m3-node-user-space-and-the-entropy-gate)
4. [M4. A founding node with an identity](#m4-a-founding-node-with-an-identity)
5. [M5. Two nodes, one realm](#m5-two-nodes-one-realm)
6. [M6. A console you can log in to](#m6-a-console-you-can-log-in-to)
7. [M7. Workloads and discovery](#m7-workloads-and-discovery)
8. [M8. Twelve-factor apps on a multi-node realm](#m8-twelve-factor-apps-on-a-multi-node-realm)
9. [M9. Federation and extension](#m9-federation-and-extension)
10. [MH. Hardware and hardening](#mh-hardware-and-hardening)
11. [Conflicts between accepted ADRs](#conflicts-between-accepted-adrs)
12. [Settled since the reading phase](#settled-since-the-reading-phase)

## M1. First light

Chunks C01 to C05, C68 and C69 ([build plan](build-plan.md#m1-first-light)). All ten of M1's decisions were settled on 2026-11-25.

**D01. Contribution policy, notice years and the documentation license**

- **Decide:** the terms outside contributions come under; how notices name years after 2026; the documentation license.
- **Why open:** [0008](../decisions/0008-mpl-2.0-license.md), rule 5 left the documentation license to a separate decision. [0023](../decisions/0023-copyright-notices.md) left the contribution policy and later years open (Consequences), so documents carried no license and full REUSE compliance waited.
- **Options:** a DCO, a CLA or an assignment ([0023](../decisions/0023-copyright-notices.md), Consequences). None named for the documentation license.
- **Blocks:** C01, before outside contributions. **Depends on:** none.
- **Settled:** [0033](../decisions/0033-contributions-docs-license-and-notice-years.md), accepted 2026-11-25: the DCO for contributions (rule 1), CC BY 4.0 for documents (rule 2), license texts in `LICENSES/` and a REUSE check in CI (rule 3), and years as ranges (rule 4). [0023](../decisions/0023-copyright-notices.md), rules 1 and 2 give the notices' years and tags to match.

**D02. Rust targets, image linkage and the ESP layout**

- **Decide:** how a stub built for `aarch64-unknown-uefi` and a kernel built for `aarch64-unknown-none` become one PE32+ image with major image version 1 or higher; how user-space programs are built before ASPIS has a target of its own upstream; where `aspis.efi`, `initfs.img` and `grub.cfg` sit on the ESP; whether the stub randomizes the kernel's placement.
- **Why open:** [0006](../decisions/0006-uefi-boot-image.md), rules 1 and 3 fix the image and the GRUB entry, not the build. The linkage also decides whether the stub can randomize the kernel's placement, since the kernel uses no randomness ([0021](../decisions/0021-entropy-before-keys.md), rule 3).
- **Options:** one UEFI target; a kernel payload that the stub relocates; a custom target specification with `build-std` for user space. The ESP layout should leave room for the two boot entries D146 may need.
- **Blocks:** C02, C04, C26, C78. **Depends on:** none.
- **Settled:** [0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), accepted 2026-11-25. It leaves three things to later decisions: whether the stub randomizes the kernel's placement is decided with C78 (rule 4; D145); whether and when to port Rust's standard library waits until the POSIX personality or applications need it (rule 5; D60); how a slot is chosen, and how a failed boot falls back, are D146's (rule 6).

**D03. QEMU configuration, the test framework and the test seed hook**

- **Decide:** the CPU model, core count and memory; the GICv2 and GICv3 matrix; which devices are virtio-pci; kernel unit tests and in-QEMU integration tests; how a test build carries a seed hook that a production build can't contain.
- **Why open:** [0021](../decisions/0021-entropy-before-keys.md), rule 12, [0009](../decisions/0009-text-as-graphics-console.md), rule 2 and [0007](../decisions/0007-initial-hardware-targets.md), rule 1 fix virtio-rng, `ramfb`, the SMMUv3 and multi-node runs, and nothing else. QEMU's SMMUv3 translates only devices in the PCIe topology ([QEMU `virt`](https://www.qemu.org/docs/master/system/arm/virt.html)), so DMA isolation needs virtio-pci. [0021](../decisions/0021-entropy-before-keys.md) asks for the seed hook (Consequences).
- **Options:** the `max` CPU, which gives `RNDR` under TCG; a Cortex-A72 model, which mirrors the Pi 4; a matrix over GIC versions and core counts.
- **Blocks:** C02, C68, C21. **Depends on:** none.
- **Settled:** [0036](../decisions/0036-qemu-configuration-and-test-builds.md), accepted 2026-11-25.

**D04. The initial image's format and contents**

- **Decide:** the container format of `initfs.img`, and which servers it carries.
- **Why open:** [0006](../decisions/0006-uefi-boot-image.md), rule 2 names the root server and the core servers for storage and networking. Boot also needs the entropy service and the RNG drivers ([0021](../decisions/0021-entropy-before-keys.md), rule 1 and Consequences), `bootfb` ([0009](../decisions/0009-text-as-graphics-console.md), rule 4) and the key service.
- **Options:** none named for the format. For the contents, read rule 2's list as not exhaustive: the image carries everything the root server starts before storage is up, as its boot manifest (D40) lists.
- **Blocks:** C02, C19. **Depends on:** none.
- **Settled:** [0037](../decisions/0037-initial-image-format-and-contents.md), accepted 2026-11-25. The boot manifest's format is D40's (rule 3), and how the image's memory becomes a memory object is decided with the kernel specification (rule 4; D13).

**D05. Reproducible builds and provenance for ASPIS's own images**

- **Decide:** what makes `aspis.efi` and `initfs.img` reproducible bit for bit; the SBOM and provenance formats; what signs provenance for images built outside any realm.
- **Why open:** [0026](../decisions/0026-realm-as-cloud-provider.md), rules 3 and 4 demand an SBOM and SLSA 1.2 provenance for every app build, but no decision covers ASPIS's own images, and measured boot needs known-good measurements (C64).
- **Options:** CycloneDX for the SBOM, as the project owner directed, and an in-toto statement with the SLSA predicate in DSSE. D128 reuses the choice.
- **Blocks:** C69, C64. **Depends on:** D02.
- **Settled:** [0038](../decisions/0038-reproducible-builds-and-provenance.md), accepted 2026-11-25. It also makes CycloneDX the SBOM format for app builds (rule 2), which settles that part of D128.

**D06. The font family and its license**

- **Decide:** the OpenType family that the kernel's glyph atlases and the SVG layer share, and the atlas sizes.
- **Why open:** [0009](../decisions/0009-text-as-graphics-console.md), rule 3 requires one family for both and names none. [0008](../decisions/0008-mpl-2.0-license.md), rule 4 admits only permissive licenses and MPL-2.0, and many font families use a font license (see [Conflicts](#conflicts-between-accepted-adrs)).
- **Options:** a family under an admitted license; an amendment to 0008 rule 4 that admits a font license, such as the SIL Open Font License, for data assets.
- **Blocks:** C03, C44. **Depends on:** none.
- **Settled:** [0034](../decisions/0034-noto-fonts-under-ofl.md), accepted 2026-11-25: Noto Sans Mono and Noto Sans (rule 1), atlases 16, 24 and 32 pixels high (rule 4), and OFL-1.1 admitted for fonts only (rule 2; [0008](../decisions/0008-mpl-2.0-license.md), rule 4). That settles [the font's license](#conflicts-that-dont-block-the-build) conflict.

**D07. UEFI runtime services**

- **Decide:** whether ASPIS calls UEFI runtime services (`ResetSystem`, `GetTime`, `SetVirtualAddressMap`) after the stub exits boot services.
- **Why open:** [0006](../decisions/0006-uefi-boot-image.md), rule 4 has the stub exit boot services and says nothing about runtime services. If they are used, the stub and the kernel must keep their regions mapped.
- **Options:** use them; don't, and reset and power off through PSCI (D56).
- **Blocks:** C04, C72. **Depends on:** none.
- **Settled:** [0039](../decisions/0039-no-uefi-runtime-services.md), accepted 2026-11-25: ASPIS calls no runtime service (rule 1), and resets and powers off through PSCI (rule 3). The rest of power management is D56's (rule 3), and boot selection without UEFI variables is D146's (rule 5).

**D08. How the stub checks the initial image**

- **Decide:** how the stub verifies or measures `initfs.img`, whether GRUB serves it over `LoadFile2` or the stub loads it from the ESP.
- **Why open:** Secure Boot needs a signed `aspis.efi` ([0006](../decisions/0006-uefi-boot-image.md), Consequences), but GRUB serves the initial image separately, so the signature on `aspis.efi` doesn't cover it ([key flows §1](key-flows.md#1-boot-to-the-entropy-gate)).
- **Options:** check it against a hash inside the signed image; measure it into a TPM 2.0.
- **Blocks:** C04, C77, C64. **Depends on:** D04.
- **Settled:** [0040](../decisions/0040-the-stub-checks-the-initial-image.md), accepted 2026-11-25: both options, a SHA-512 digest inside the signed `aspis.efi` (rules 1 and 2) and a measurement into PCR 9 where a TPM exists (rule 3).

**D09. The boot ABI**

- **Decide:** the layout of the boot information that the stub hands the kernel; the grammar of the kernel arguments; the ESP path the stub loads the initial image from under `chainloader` and direct boot.
- **Why open:** [0006](../decisions/0006-uefi-boot-image.md), rule 4 lists what the stub collects but not how it is passed, and rule 3 fixes neither the arguments nor the fallback path. Every text format needs an ABNF grammar ([0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 2).
- **Options:** none named. The layout must leave room for the initial image's hash (D08).
- **Blocks:** C04, C05. **Depends on:** D02, D08.
- **Settled:** [0041](../decisions/0041-boot-abi.md), accepted 2026-11-25. How the seed's page is handed on from the kernel is D42's (rule 4).

**D10. The log ring and the panic path**

- **Decide:** the kernel log ring's format, and who may read it; how the kernel knows at a panic whether the boot framebuffer is still the active scan-out.
- **Why open:** [0009](../decisions/0009-text-as-graphics-console.md), rule 3 sends console output to a log ring buffer, and rule 5 draws a panic on the framebuffer only if it is still the active scan-out. Neither says how.
- **Options:** the log ring as the source Display SVG imports the console's text from, read through a kernel interface (D55).
- **Blocks:** C05, C24. **Depends on:** none.
- **Settled:** [0042](../decisions/0042-log-ring-and-panic-path.md), accepted 2026-11-25. The ring's interface is written in the IDL with the other kernel interfaces in M2 (rule 5). Display SVG's import is D55's, and keeping panic records across a reboot is C73's (rule 7).

## M2. Kernel objects

Chunks C06, C07, C10 to C12, C13a, C13b, C14 to C17, C70 and C71 ([build plan](build-plan.md#m2-kernel-objects)).

**D11. Byte order and signed integers in the core rules**

- **Decide:** the byte order of fixed-width integers in ASPIS messages, and whether the core rules define signed integers.
- **Why open:** [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 4 makes byte order a design-session item and keeps IDs big-endian. Every field of an ID is unsigned ([0001](../decisions/0001-object-identifiers.md), rule 2), but POSIX's `off_t` is signed, and [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 3 parses token times as 64-bit integers without fixing their sign. The initial image and the boot information are little-endian, because they are in-memory structures, not messages ([0037](../decisions/0037-initial-image-format-and-contents.md), rule 1; [0041](../decisions/0041-boot-abi.md), rule 2), so they leave messages' byte order to this entry.
- **Options:** big-endian everywhere, so that byte order is sort order ([research notes §5](../research/aegis-domain-os.md#5-implications-for-aspis)); two's complement or offset binary for signed values.
- **Blocks:** C06. **Depends on:** none.

**D12. Method names, the canonical call text, and interface and type names**

- **Decide:** method names beside their stable numbers; the ABNF of the canonical text form of calls; the grammar of interface and type names and of interface references.
- **Why open:** [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 5 requires a text form for every call, and it must line up with Cedar action names, which are the interface, major version and method ([0019](../decisions/0019-authzen-decision-protocol.md), rule 4), and with token scopes. [0031](../decisions/0031-abnf-is-not-a-command-language.md), rule 3 makes that form machine-facing only, for logs, traces and token scopes, not what people type. [0027](../decisions/0027-applications-extend-the-system.md), rule 7 makes names dotted and reverse-DNS, reserves `aspis.` and leaves the grammar to ABNF.
- **Options:** the illustrative grammar in the [discovery note §4.6](extensibility-and-discovery.md#46-names): at least two lower-case labels, with majors and minors up to 65,535.
- **Blocks:** C07, C31. **Depends on:** none.

**D13. The kernel specification, and how far it follows seL4**

- **Decide:** how the kernel meets the POSIX personality's needs (copy-on-write clones, a capability-table copy, cancelable waits, thread suspend and register access, fault delivery, eventcount sets and words, a thread-pointer register) and the twelve-factor needs (jobs, budgets, immutable and job-scoped memory objects); which of seL4's mechanisms it adopts.
- **Why open:** [0012](../decisions/0012-posix-compatibility-layer.md) makes the [POSIX note §5](posix-compatibility.md#5-what-the-kernel-must-provide) an input to the kernel specification (Consequences), and [0025](../decisions/0025-twelve-factor-app-contract.md), rule 12 adds jobs and budgets. seL4 is the reference model ([0002](../decisions/0002-capability-security-model.md), rule 1), and its untyped memory and MCS scheduling contexts already provide most of jobs and budgets ([0025](../decisions/0025-twelve-factor-app-contract.md), Consequences), but no decision adopts them ([kernel view §3](kernel-components.md#3-open)). [0037](../decisions/0037-initial-image-format-and-contents.md), rule 4 also leaves to the kernel specification how the initial image's memory becomes a memory object.
- **Options:** seL4 as the model throughout; a choice part by part, in D14 to D30.
- **Blocks:** C10, C11, C12, C13a, C13b, C14, C15, C16, C17. **Depends on:** none.

**D14. Kernel memory management**

- **Decide:** how kernel objects get their memory; the physical frame allocator; the translation granule; the address-space layout; whether W^X, PAN and PXN apply from the first page tables (D145).
- **Why open:** [0005](../decisions/0005-single-level-store.md) calls the virtual-memory subsystem early, critical work (Consequences), and no decision fixes the model. Job memory budgets follow from it ([0025](../decisions/0025-twelve-factor-app-contract.md), rule 12). [0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), rule 2 links the kernel in the upper half of the address space and leaves the exact base to C05. The initial image aligns its files to 64 KiB until the kernel specification fixes the page size ([0037](../decisions/0037-initial-image-format-and-contents.md), rule 1).
- **Options:** seL4's untyped memory and retype; a kernel heap with quotas per job.
- **Blocks:** C10, C16, C78. **Depends on:** D13.

**D15. Capability spaces, rights and revocation**

- **Decide:** the structure of a capability space; the rights bits; how derived capabilities are tracked, so that a manager can revoke what it handed out; how a manager tells which session a call belongs to.
- **Why open:** [0002](../decisions/0002-capability-security-model.md), rule 1 says capabilities can be copied with fewer rights, passed over IPC and revoked, and its Consequences say revocation needs careful design. Managers revoke the capabilities tagged with a revoked branch's policies ([0019](../decisions/0019-authzen-decision-protocol.md), rule 8).
- **Options:** seL4 CNodes, with a capability derivation tree and badges; a flat handle table in Zircon's style.
- **Blocks:** C11. **Depends on:** D14.

**D16. Who mints IDs for processes, threads and endpoints**

- **Decide:** who mints the IDs of processes, threads and endpoints; whether other kernel objects carry IDs; who answers their base discovery interface.
- **Why open:** [0001](../decisions/0001-object-identifiers.md) counts processes, threads and endpoints among the objects IDs name (Context), and every object implements the base interface ([0014](../decisions/0014-versioned-object-apis.md), rule 5). The kernel uses no randomness ([0021](../decisions/0021-entropy-before-keys.md), rule 3), so it can't mint ordinary IDs (see [Conflicts](#conflicts-between-accepted-adrs)).
- **Options:** the user-space server that creates the object (the root server, a process manager or the POSIX process server) mints its ID and answers its base interface. Giving IDs to only some threads and endpoints would narrow 0001 and needs a change to it.
- **Blocks:** C11, C19, C41. **Depends on:** none.

**D17. Scheduling, priorities, CPU budgets, timers and deadlines**

- **Decide:** the scheduler; priorities for drivers, interrupt handling and the display; how priority inversion is avoided when many clients call shared servers (the PDP, the entropy service, the network server, pagers); how a job's CPU budget applies; which ARM timer the kernel uses, including under a hypervisor; how the kernel represents a deadline, and where wall time lives.
- **Why open:** [0025](../decisions/0025-twelve-factor-app-contract.md), rule 12 requires CPU budgets and [0004](../decisions/0004-network-transparency-and-failure.md), rule 3 deadlines. No decision covers the scheduler or priorities ([kernel view §3](kernel-components.md#3-open)).
- **Options:** seL4 MCS scheduling contexts (budget and period), with passive servers and scheduling-context donation; fixed priorities with budgets; fair share per job; monotonic deadlines from the ARM generic timer, with wall time in a user-space service.
- **Blocks:** C12, C13a. **Depends on:** D14.

**D18. SMP bring-up and locking**

- **Decide:** how the secondary cores start, and the kernel's locking model.
- **Why open:** the Pi 4 has four cores ([0007](../decisions/0007-initial-hardware-targets.md), rule 2), and no decision covers SMP ([kernel view §3](kernel-components.md#3-open)). Inter-processor interrupts need the GIC (C13a).
- **Options:** PSCI `CPU_ON`, on both firmwares; a big kernel lock first; run queues per core.
- **Blocks:** C12, C13a. **Depends on:** D17.

**D19. Eventcount semantics**

- **Decide:** how an eventcount is advanced, read and awaited; its width; how it relates to a word in user memory; limits on waiting on a set.
- **Why open:** eventcounts are kernel objects ([0002](../decisions/0002-capability-security-model.md), rule 1), and POSIX waits ([POSIX note §5](posix-compatibility.md#5-what-the-kernel-must-provide)), credential rotation ([0025](../decisions/0025-twelve-factor-app-contract.md), rule 5) and catalog watchers ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 6) rely on them. No decision says how they work.
- **Options:** AEGIS's `ec2_$` semantics with 64-bit counts ([research notes §2.5](../research/aegis-domain-os.md#25-processes-synchronization-and-errors)).
- **Blocks:** C14. **Depends on:** none.

**D20. IPC semantics**

- **Decide:** synchronous or asynchronous messaging; message size and buffers; capability transfer; call and reply; timeouts and cancellation.
- **Why open:** [0002](../decisions/0002-capability-security-model.md), rule 1 says only that capabilities pass over IPC, and [0005](../decisions/0005-single-level-store.md), rule 2 that page faults reach pagers over it. The choice shapes the pager protocol and every server.
- **Options:** seL4-style synchronous endpoints with call and reply; Zircon-style channels; synchronous endpoints, with eventcounts as the asynchronous primitive ([research notes §5](../research/aegis-domain-os.md#5-implications-for-aspis)).
- **Blocks:** C14, C18. **Depends on:** D15, D19.

**D21. Interrupt objects for user-space drivers**

- **Decide:** what an interrupt object signals, and how a driver acknowledges it; MSI for PCIe devices; where the Pi 4's second-level controller is handled.
- **Why open:** interrupts are kernel objects ([0002](../decisions/0002-capability-security-model.md), rule 1), and the Pi 4 adds a Broadcom second-level controller to its GIC-400 ([0007](../decisions/0007-initial-hardware-targets.md), Consequences). virtio-pci needs MSI: GICv2m with GICv2, the ITS with GICv3.
- **Options:** the interrupt signals an eventcount; an endpoint notification, as in seL4.
- **Blocks:** C13b, C20. **Depends on:** D19, D20.

**D22. The fault model, and who sets a page fetch's deadline**

- **Decide:** the kinds of typed fault and their message; how a thread's fault handler is set; who sets the deadline for fetching a page.
- **Why open:** the kernel delivers a typed fault when a page can't be fetched by its deadline ([0004](../decisions/0004-network-transparency-and-failure.md), rule 4), but knows nothing about the network (rule 5), so it can only enforce a deadline it is given.
- **Options:** a fault endpoint per thread, as in seL4; the deadline as an attribute of the mapping; the deadline supplied by the pager.
- **Blocks:** C15. **Depends on:** D17, D20.

**D23. The pager protocol**

- **Decide:** the messages between the kernel and pagers; page supply; write-back and eviction; copy-on-write; remote pages through the network server.
- **Why open:** [0005](../decisions/0005-single-level-store.md), rule 2 puts pagers in user space, and its Consequences call the protocol early, critical work.
- **Options:** Mach's external pagers; seL4's user-level paging; Fuchsia's VMOs and pagers.
- **Blocks:** C15, C22. **Depends on:** D20, D22.

**D24. What a job's size is**

- **Decide:** the units of memory and CPU budgets; how budgets nest; whether a scratch area counts against memory; who is charged for immutable build pages that many instances map.
- **Why open:** [0025](../decisions/0025-twelve-factor-app-contract.md), rule 12 gives each job budgets, rule 6 makes scratch areas anonymous memory objects, and [0026](../decisions/0026-realm-as-cloud-provider.md), rule 5 makes sizes budgets. None defines a size.
- **Options:** named sizes that map to memory bytes and a CPU budget and period; build pages charged to the node's cache.
- **Blocks:** C16, C54. **Depends on:** D14, D17.

**D25. The call header and the wire encoding**

- **Decide:** the message types (request, reply, error reply, cancel, stream item and end); whether each call repeats object, interface and version or refers to state fixed at bind; the deadline, session reference, flags and trace context; the length-field width and the largest message; framing on kernel IPC and on QUIC streams.
- **Why open:** [0013](../decisions/0013-abnf-for-protocols-and-calls.md) labels its call header "An illustrative example (not normative)". Versions are fixed at bind ([0014](../decisions/0014-versioned-object-apis.md), rule 4) and calls carry no token ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 1), while every call that may cross the network carries a deadline ([0004](../decisions/0004-network-transparency-and-failure.md), rule 3), which the example omits.
- **Options:** the illustrative header (`%x01`, a 16-octet request ID, 32-octet object and interface IDs, a 2+2-octet version and a 2-octet method: 87 octets); a header carrying a session or capability reference, the method, the request ID and the deadline.
- **Blocks:** C07, C18, C29. **Depends on:** D11, D20.

**D26. Typed errors and minor versions on the wire**

- **Decide:** how typed errors are encoded and carried across RPC; the system's own errors (version unsupported, no such method, bind refused, tree too stale, session revoked, deadline passed); how a minor version adds optional fields that old clients can parse; how a call to a method that is too new is refused.
- **Why open:** errors are typed and namespaced by interface ([0027](../decisions/0027-applications-extend-the-system.md), rule 2), and minor versions add only methods or optional fields ([0014](../decisions/0014-versioned-object-apis.md), rule 3). Neither says how this looks on the wire.
- **Options:** a tagged optional tail; a length-prefixed extension block.
- **Blocks:** C07. **Depends on:** D25.

**D27. Capability parameters and streams**

- **Decide:** how a parameter that carries a capability appears in the IDL and in its ABNF, and how it is translated between nodes; server streams for catalog watches, rotation pushes and log tails.
- **Why open:** ABNF can't express a capability transfer, and raw capabilities never travel between nodes ([0002](../decisions/0002-capability-security-model.md), rules 1 and 5). Remote catalog watchers receive a stream over RPC ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 6).
- **Options:** none named.
- **Blocks:** C07. **Depends on:** D25, D20.

**D28. The IDL**

- **Decide:** its syntax and ABNF; its types (integers, bytes, strings, IDs, capabilities, optionals, unions or errors, sequences, streams); its annotations (action groups, support periods, doc comments and how dm renders them); its bindings (Rust `no_std` and `std`, and C for relibc).
- **Why open:** [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 3 makes the IDL the source of truth, and [0018](../decisions/0018-cedar-policy-language.md), rule 4 and [0027](../decisions/0027-applications-extend-the-system.md), rules 2 and 10 add Cedar schema, support periods and HTTPS bindings to what it must carry. No IDL exists yet.
- **Options:** a new IDL in the NCS and DCE tradition; FIDL, the Cap'n Proto schema language or Smithy, adapted with an ABNF back end.
- **Blocks:** C07, C31. **Depends on:** D11, D12, D25, D26, D27.

**D29. The kernel interface library**

- **Decide:** its name, packaging and mapping; whether its interfaces are defined in the IDL under the reserved authority; whether the kernel accepts calls only from it; how long its versions are supported; how early servers, relibc and `std` use it.
- **Why open:** [0014](../decisions/0014-versioned-object-apis.md), rule 6 exposes versioned interfaces over a raw ABI that "can change underneath it", while [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 2 puts every IPC call in generated ABNF (see [Conflicts](#conflicts-between-accepted-adrs)).
- **Options:** interfaces defined in the IDL under the reserved authority, over a private, unpublished system-call ABI.
- **Blocks:** C17. **Depends on:** D28, D20.

**D30. The process model, native spawn and the executable format**

- **Decide:** what a process is at kernel level; the native spawn interface; program loading; the initial capabilities; how the environment block is delivered; the executable format, and where the dynamic linker lives.
- **Why open:** native process creation is spawn-only ([POSIX note §4.2](posix-compatibility.md#42-process-creation)), and the environment block arrives at spawn ([0025](../decisions/0025-twelve-factor-app-contract.md), rule 4). The format and the linker are open ([POSIX note §8](posix-compatibility.md#8-open-questions)).
- **Options:** ELF for native and POSIX programs. The programs in the initial image are already static ELF64 AArch64 programs ([0037](../decisions/0037-initial-image-format-and-contents.md), rule 3), and user-space programs are built `no_std` for `aarch64-unknown-none` until there is a std port ([0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), rule 5).
- **Blocks:** C17, C47. **Depends on:** D16, D29.

**D31. Debugging**

- **Decide:** the kernel debugging workflow; the interface through which a debugger reads and writes a user thread's registers and memory, and what authority it needs; symbolized panics; crash dumps.
- **Why open:** no decision covers debugging. [0014](../decisions/0014-versioned-object-apis.md) names debuggers among the users of introspection (Consequences), and POSIX needs thread suspend and register access ([POSIX note §5](posix-compatibility.md#5-what-the-kernel-must-provide)), but nothing defines a debugger's authority.
- **Options:** QEMU's gdbstub; a debugger capability for user threads; a UART stub on the Pi 4 later.
- **Blocks:** C70. **Depends on:** D15, D30.

**D32. The fuzzing and differential-testing gate**

- **Decide:** which parsers must be fuzzed before their chunk counts as done; how the PDP is tested against Cedar; whether leases and catalog sequence numbers are model-checked; partition fault injection.
- **Why open:** JSON parsing enters every manager's trust boundary ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), Consequences), and decoders run isolated because their input may be hostile ([0010](../decisions/0010-svg-core-primitive.md), rule 11). [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 6 checks grammars against test vectors, not hostile input.
- **Options:** none named beyond the list of parsers at trust boundaries (C71). Two accepted records already make their parsers fuzzing targets: the initial image's ([0037](../decisions/0037-initial-image-format-and-contents.md), rule 2) and the kernel arguments' ([0041](../decisions/0041-boot-abi.md), rule 5).
- **Blocks:** C71. **Depends on:** D03.

## M3. Node user space and the entropy gate

Chunks C08, C09, C18 to C24, C72 and C73 ([build plan](build-plan.md#m3-node-user-space-and-the-entropy-gate)). Until D36 is settled, M3 can name only objects under the reserved authority.

**D33. The cryptography libraries**

- **Decide:** the implementations of ML-KEM-768, ML-DSA-65, X25519, Ed25519, SHA-3, SHA-256, SHA-384, SHA-512 with HMAC, HKDF, ChaCha20-Poly1305, AES-256-GCM and RFC 10073's composite; whether they work in `no_std` with `alloc` for early servers; whether their licenses fit [0008](../decisions/0008-mpl-2.0-license.md), rule 4.
- **Why open:** [0003](../decisions/0003-hybrid-post-quantum-cryptography.md), rule 7 defers the choice. TLS 1.3's key schedule needs SHA-256 or SHA-384 ([0003](../decisions/0003-hybrid-post-quantum-cryptography.md), rule 3; [0020](../decisions/0020-realm-certificate-authority.md), rule 3), and choosing the TLS stack joins this choice ([0020](../decisions/0020-realm-certificate-authority.md), Consequences).
- **Options:** RustCrypto's `ml-kem` and `ml-dsa`; Cryspen's `libcrux-ml-kem` and `libcrux-ml-dsa` ([0003](../decisions/0003-hybrid-post-quantum-cryptography.md), rule 7).
- **Blocks:** C08, C29. **Depends on:** none.

**D34. The ID format specification**

- **Decide:** the ABNF text form; the class registry; the domain-separated encoding hashed into a node's UUID.
- **Why open:** [0001](../decisions/0001-object-identifiers.md) leaves all three to the ID format specification (Decision, closing paragraph). The text form may use only SPIFFE path characters ([0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 2). [0026](../decisions/0026-realm-as-cloud-provider.md), rule 2 adds four classes, while the [twelve-factor note §5.3](twelve-factor-apps.md#53-objects) has seven platform objects. [0001](../decisions/0001-object-identifiers.md), rule 3 hashes "the hybrid key bundle", and the genesis key is the composite signature key ([0003](../decisions/0003-hybrid-post-quantum-cryptography.md), rule 2).
- **Options:** the four classes, with bindings, routes and instances in the general-purpose class and a type attribute ([0027](../decisions/0027-applications-extend-the-system.md), rule 4), or with classes of their own; hashing the composite signature public key only.
- **Blocks:** C09. **Depends on:** D11.

**D35. The reserved authority and the well-known table**

- **Decide:** the value of the reserved ASPIS authority, and the assignments below 2^16: the node object, the root directory, the catalog, the entropy and key services, interface objects and the kernel interface library's interfaces.
- **Why open:** [0001](../decisions/0001-object-identifiers.md), rules 4 and 7 reserve the range and the authority without assigning them. System interfaces use the reserved authority ([0014](../decisions/0014-versioned-object-apis.md), rule 2), and so does the catalog ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 3).
- **Options:** none named.
- **Blocks:** C09, C19. **Depends on:** D34.

**D36. Names before the gate on a first boot** (blocking)

- **Decide:** which authority names the node's well-known objects before the genesis key exists, and what fills the 40-bit random field of well-known and reserved-authority IDs.
- **Why open:** accepted records conflict: [Names before the gate](#names-before-the-gate-on-a-first-boot).
- **Options:** listed with the conflict.
- **Blocks:** C09, C19, C25. **Depends on:** D34, D35.

**D37. Minting authorities that aren't nodes**

- **Decide:** how the authorities of external issuers and deploys are formed without a genesis key, enrolled as unique, and given counters.
- **Why open:** [0017](../decisions/0017-openid-federation-membership.md), rule 5 says an authority needn't be a node, and [0026](../decisions/0026-realm-as-cloud-provider.md), rule 11 and [0027](../decisions/0027-applications-extend-the-system.md), rule 5 give each deploy one. [0001](../decisions/0001-object-identifiers.md), rule 3 derives a node's authority from its genesis key and leaves open how other authorities are formed, enrolled and given counters, and the registry refuses an authority it already knows (rule 6).
- **Options:** a UUIDv8 from SHA3-256 over a domain-separated realm, kind and name; a random UUID registered with the registry; the registry as the only minter. An authority that must stay the same across realms, such as a publisher's (D110), rules out the last two.
- **Blocks:** C09, C36, C54. **Depends on:** D34.

**D38. Request IDs, the reply cache and deadlines on the wire**

- **Decide:** how request IDs stay unique before the gate and after `fork`; how long servers keep replies; how deadlines are encoded, on which clock, and how they pass through nested calls.
- **Why open:** requests carry IDs for at-most-once execution, and remote operations carry deadlines ([0004](../decisions/0004-network-transparency-and-failure.md), rule 3). Nothing before the gate may use randomness ([0021](../decisions/0021-entropy-before-keys.md), rule 3), and a duplicate ID after `fork` would replay the parent's reply to the child.
- **Options:** a nonce per caller with a counter, re-keyed on `fork`; a counter per session; relative timeouts between nodes and absolute monotonic deadlines on a node.
- **Blocks:** C18. **Depends on:** D25, D17.

**D39. The bind message**

- **Decide:** whether a bind lists the methods it needs or implies all of them; the reply when no compatible major is served; the bind interface's own numbering; how about 15 KB of WIT, proof and access token reach the manager.
- **Why open:** [0014](../decisions/0014-versioned-object-apis.md), rule 4 names an object, an interface, a major and a minimum minor, and [0019](../decisions/0019-authzen-decision-protocol.md), rule 1 checks "a bind … that needs several methods" in one batch. Under [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 2 a bind carries a token with a WPT-form proof, each about 5 KB with composite signatures.
- **Options:** length-prefixed `bytes` fields ([0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 4); the credentials in a shared memory object.
- **Blocks:** C18, C39. **Depends on:** D25, D20.

**D40. The root server**

- **Decide:** its interface; the boot manifest's format; the capabilities the kernel grants it; how it starts and watches the servers it starts; its relation to the process manager.
- **Why open:** [0006](../decisions/0006-uefi-boot-image.md), rule 2, [0018](../decisions/0018-cedar-policy-language.md), rule 5 and [0021](../decisions/0021-entropy-before-keys.md), rule 1 give the root server its jobs, not its design ([node view §2](node-components.md#2-boot-time-core)). Accepted records now fix some of its inputs. The boot manifest is an entry of the initial image, whose format is left to this entry ([0037](../decisions/0037-initial-image-format-and-contents.md), rule 3). The manifest lists everything the root server starts before storage is up (rule 5), and the root server checks each entry's digest before it starts or reads it (rule 7). The kernel gives the log ring's capability only to the root server, which passes it on ([0042](../decisions/0042-log-ring-and-panic-path.md), rule 5), and kernel arguments under `root.` reach the root server unread ([0041](../decisions/0041-boot-abi.md), rule 5).
- **Options:** none named.
- **Blocks:** C19. **Depends on:** D04, D30.

**D41. Binding before the first decision point**

- **Decide:** how early servers bind and agree a version while authority comes only from the root server's capabilities.
- **Why open:** [0018](../decisions/0018-cedar-policy-language.md), rule 5 settles where authority comes from before the first PDP. [0027](../decisions/0027-applications-extend-the-system.md), rule 2 has ASPIS's own interfaces bind "with a token and proof of possession", and nothing says what stands in for that below the bootstrap line ([0027](../decisions/0027-applications-extend-the-system.md), Consequences).
- **Options:** a bootstrap bind, authorized by holding a root-server capability; no bind below the bootstrap line.
- **Blocks:** C18, C19. **Depends on:** D39, D40.

**D42. How the seed reaches the entropy service**

- **Decide:** the stub's seed's path from the kernel, through the root server, to the entropy service, and how each copy is erased.
- **Why open:** the kernel hands the seed over and keeps no copy, and the root server starts the entropy service ([0021](../decisions/0021-entropy-before-keys.md), rule 1), so the seed passes through the root server. [0041](../decisions/0041-boot-abi.md), rule 4 settles the first step: the stub puts the seed in a page of its own and erases every other copy, and the kernel never reads that page. It hands the page on as this entry decides, and keeps no copy. The rest of the path is open.
- **Options:** the seed in a memory object whose capability the root server passes on unread, zeroized once it is ingested. The seed's own page suits this ([0041](../decisions/0041-boot-abi.md), Consequences).
- **Blocks:** C19, C21. **Depends on:** D09, D40.

**D43. Device discovery and the driver model**

- **Decide:** who parses the device tree; the capability types for MMIO, interrupts and DMA; who programs the SMMUv3; PCIe enumeration through ECAM, and virtio-pci; which drivers exist on QEMU and on the Pi 4.
- **Why open:** drivers run in user space ([0009](../decisions/0009-text-as-graphics-console.md), Context) and device tree comes first ([0007](../decisions/0007-initial-hardware-targets.md), rule 3), but no decision gives the model ([node view §1](node-components.md#1-overview)). On QEMU every virtio device is on PCIe, behind the SMMUv3, and ASPIS uses no virtio-mmio ([0036](../decisions/0036-qemu-configuration-and-test-builds.md), rule 2). The initial image carries the PCIe, SMMUv3, virtio-blk and virtio-net drivers ([0037](../decisions/0037-initial-image-format-and-contents.md), rule 5).
- **Options:** the kernel parses only what it needs, and a device manager or the root server parses the rest and starts drivers with capabilities.
- **Blocks:** C20. **Depends on:** D21, D40.

**D44. A command interpreter on the serial console before dm**

- **Decide:** whether node bring-up and CI get a minimal command interpreter on the UART before dm and the POSIX shell exist; what it may do; how it relates to a native command interpreter, if ASPIS has one (D102).
- **Why open:** the kernel writes its console to the serial UART as well as the framebuffer ([0009](../decisions/0009-text-as-graphics-console.md), rule 3), but nothing reads commands there. dm is the console and login happens in a dm pad ([0011](../decisions/0011-dm-window-system.md), rule 5), and the POSIX shell comes with the POSIX personality ([0012](../decisions/0012-posix-compatibility-layer.md), rule 2), both in M6. Until then, bring-up and CI see only output. Before the first PDP, authority comes only from the root server's capabilities ([0018](../decisions/0018-cedar-policy-language.md), rule 5), which bounds what such an interpreter could do. The project owner has ruled out ABNF as its language, as [0031](../decisions/0031-abnf-is-not-a-command-language.md), rule 1 records.
- **Options:** none named. Without one, interactive use of a node waits for dm's pads (C46).
- **Blocks:** C19, C20. **Depends on:** D40, D43.

**D45. Entropy credit rates and the reseed interval**

- **Decide:** the credit rate of each source on each platform, with jitter measured on the Pi 4; how far the Pi 4's SoC generator is credited; the firmware seed's limit on each platform; the reseed interval.
- **Why open:** [0021](../decisions/0021-entropy-before-keys.md), rule 4 credits only justified estimates, and rule 9 reseeds periodically without a period ([entropy note §6](entropy-and-first-keys.md#6-open-questions)).
- **Options:** start the Pi 4 conservatively ([0021](../decisions/0021-entropy-before-keys.md), Consequences).
- **Blocks:** C21, C63. **Depends on:** D03.

**D46. The entropy service's interface and health tests**

- **Decide:** its methods (generate, generate with prediction resistance, instantiate a child, report what it waits for); how sources submit samples and claim credit; how its capabilities are handed out; whether the drivers or the service run the SP 800-90B tests; what "never blocks again" means for requests that wait.
- **Why open:** [0021](../decisions/0021-entropy-before-keys.md) fixes behavior, not an interface (rules 2, 4, 5, 7 and 9). Rule 2's "never blocks again" sits beside the waits in rules 5 and 9 (see [Conflicts](#conflicts-between-accepted-adrs)).
- **Options:** an IDL interface on a well-known object, with separate capabilities for consumers and sources.
- **Blocks:** C21. **Depends on:** D28, D35.

**D47. Child DRBGs and `fork`**

- **Decide:** where each process's child DRBG lives, and what `fork` does to it.
- **Why open:** each process gets a child DRBG ([0021](../decisions/0021-entropy-before-keys.md), rule 7), and `fork` clones memory copy-on-write ([0012](../decisions/0012-posix-compatibility-layer.md), rule 4), so a copied child DRBG would give parent and child the same output.
- **Options:** child state held in the entropy service for each process; a child in the process, in a memory object wiped on `fork`; a hook that reseeds the child after `fork`.
- **Blocks:** C21, C41. **Depends on:** D46.

**D48. Detecting a restore, a clone, a resume or a new VM generation**

- **Decide:** how a node detects each of these.
- **Why open:** [0021](../decisions/0021-entropy-before-keys.md), rule 9 reseeds after each, and [0001](../decisions/0001-object-identifiers.md), rule 5 takes a new authority after a restore or clone, but nothing says how they are detected. How the node then re-enrolls is part of D82.
- **Options:** a boot counter or nonce compared with the registry; a VM generation ID device where the hypervisor offers one; the registry noticing an authority used twice.
- **Blocks:** C21, C25. **Depends on:** none.

**D49. Where the persisted seed lives**

- **Decide:** where the persisted seed is kept, when it is read and rewritten, and whether storage starts before the gate to read it.
- **Why open:** a persisted seed is mixed in but never credited ([0021](../decisions/0021-entropy-before-keys.md), rule 4), and anything that mints IDs starts after the entropy service ([0021](../decisions/0021-entropy-before-keys.md), Consequences), yet the seed is kept in the store ([entropy note §6](entropy-and-first-keys.md#6-open-questions)).
- **Options:** storage starts before the gate, in a mode that mints nothing; the seed lives elsewhere, such as on the ESP.
- **Blocks:** C21, C22, C72. **Depends on:** none.

**D50. The object store and the storage servers**

- **Decide:** the on-disk format; storage pagers; block drivers; crash consistency; where durable sequence-block records live.
- **Why open:** core servers bring up storage ([0006](../decisions/0006-uefi-boot-image.md), rule 2), pagers supply pages from it ([0005](../decisions/0005-single-level-store.md), rule 2) and sequence blocks are recorded durably ([0001](../decisions/0001-object-identifiers.md), rule 4). None says how.
- **Options:** back-references and checksums in the object store ([research notes §5](../research/aegis-domain-os.md#5-implications-for-aspis), not adopted).
- **Blocks:** C22. **Depends on:** D23, D43.

**D51. The realm's namespace and friendly node names**

- **Decide:** where `//<realm>/sys/…`, `//<realm>/apps/…` and the catalog's view sit; how nodes appear; how friendly names sit over node UUIDs; where the name service runs.
- **Why open:** "Node names are UUIDs with a friendly name on top" is a [founding requirement](../decisions/README.md#founding-requirements) with no mechanism yet. [0026](../decisions/0026-realm-as-cloud-provider.md), rule 2 and [0027](../decisions/0027-applications-extend-the-system.md), rule 8 use names under `//<realm>/` without a layout ([discovery note §8](extensibility-and-discovery.md#8-open-questions)).
- **Options:** none named.
- **Blocks:** C23. **Depends on:** D34.

**D52. Path resolution**

- **Decide:** whether lookups return IDs or capabilities; the checks at each component; `..` at an instance's root and at `//`; symbolic links and the syntax of variant links; how a process that holds only root and working-directory capabilities reaches `//`.
- **Why open:** [0012](../decisions/0012-posix-compatibility-layer.md), rule 5 makes `//` the network root, while [0025](../decisions/0025-twelve-factor-app-contract.md), rule 3 gives an app's processes a namespace of four things (see [Conflicts](#conflicts-between-accepted-adrs)). [0002](../decisions/0002-capability-security-model.md), rule 3 makes the name service the manager that binds a process to a directory.
- **Options:** `//` reached only through a capability: the root of the default per-node POSIX instance includes it, and app instances reach realm names only through bindings.
- **Blocks:** C23, C42. **Depends on:** D51.

**D53. The base discovery interface**

- **Decide:** its name, ID and methods; whether calling it needs a bind and a token; how objects whose manager holds no policy for them, such as kernel objects with IDs, answer it.
- **Why open:** [0014](../decisions/0014-versioned-object-apis.md), rule 5 and [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 1 say what it reports, not its form.
- **Options:** none named.
- **Blocks:** C23. **Depends on:** D16, D28.

**D54. The enumeration interface**

- **Decide:** what a collection is; page tokens, ordering and consistency under change; how results are filtered by visibility; under whose identity a delegated enumeration runs.
- **Why open:** [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 1 has every manager list its objects a page at a time, only to callers allowed to see them, and notify watchers; rule 2 has the catalog delegate to "the collection's manager". Neither defines a collection.
- **Options:** a collection is an object whose manager implements enumeration, and rows are objects only if their manager gives them IDs.
- **Blocks:** C23. **Depends on:** D27, D53.

**D55. The display driver interface, input and the console handoff**

- **Decide:** the interface Display SVG presents frames through, with mode setting and page flipping for hardware drivers; how keyboard and pointer events reach Display SVG; several displays; how Display SVG imports the console's text, and how the kernel learns to stop drawing.
- **Why open:** [0009](../decisions/0009-text-as-graphics-console.md), rule 4 and [0010](../decisions/0010-svg-core-primitive.md), rules 6 and 9 fix the parts and the behavior, not the interfaces ([node view §4](node-components.md#4-graphics-and-the-console)). [0042](../decisions/0042-log-ring-and-panic-path.md) settles two parts. Display SVG imports the console's text from the log ring by sequence number, with a capability the root server passes on (rule 5 and Consequences). The kernel stops drawing when the boot framebuffer moves from Kernel to Adopted, by a call on its kernel object, and a hardware display driver must retire it before it changes the scan-out (rule 6). The display driver interface, input and several displays are still open.
- **Options:** none named for the interface. The import source is settled: the log ring ([0042](../decisions/0042-log-ring-and-panic-path.md), rule 5).
- **Blocks:** C24, C45, C48. **Depends on:** D10, D43.

**D56. Shutdown, reboot and power**

- **Decide:** how a node powers off, resets and idles; what an orderly shutdown does, such as flushing dirty pages and rewriting the persisted seed; suspend and resume, and the Pi 4's thermal throttling, later.
- **Why open:** [0039](../decisions/0039-no-uefi-runtime-services.md) settles reset and power-off: they go through PSCI `SYSTEM_RESET` and `SYSTEM_OFF` (rule 3), and ASPIS calls no UEFI runtime service (rule 1). It leaves the rest of power management to this entry. On the Pi 4, `SYSTEM_OFF` only halts the board (Consequences). [0021](../decisions/0021-entropy-before-keys.md), rule 9 presumes a resume from suspend, and when the persisted seed is rewritten is open ([entropy note §6](entropy-and-first-keys.md#6-open-questions)).
- **Options:** PSCI `SYSTEM_OFF`, `SYSTEM_RESET` and `CPU_OFF`; WFI when idle. UEFI runtime services, the option if D07 had kept them, are ruled out ([0039](../decisions/0039-no-uefi-runtime-services.md), rule 1).
- **Blocks:** C72. **Depends on:** D07, D49.

**D57. Supervision and crash recovery of system servers**

- **Decide:** restart policy and state recovery for the entropy service, the key service, the network server, the PDP, pagers and the root server; what a fault returns when an object's pager has died; panic records that survive on headless nodes; a watchdog.
- **Why open:** no decision covers it. [0004](../decisions/0004-network-transparency-and-failure.md), rule 4 covers pages that can't be fetched in time, and nothing covers a local pager that has crashed ([key flows §6](key-flows.md#6-mapping-an-object-and-taking-a-page-fault)). A panic always reaches the UART and the log ring, and keeping panic records across a reboot is left to C73 ([0042](../decisions/0042-log-ring-and-panic-path.md), rule 7).
- **Options:** none named.
- **Blocks:** C19, C73. **Depends on:** D22, D40.

## M4. A founding node with an identity

Chunks C25 to C36, C74 and C75 ([build plan](build-plan.md#m4-a-founding-node-with-an-identity)).

**D58. Key custody, and which keys count as long-lived**

- **Decide:** how keys are protected on boards without a TPM; where workloads keep their keys; which keys beyond those [0021](../decisions/0021-entropy-before-keys.md), rule 5 lists need a physical source and prediction resistance (the provider's signing keys, the external ML-DSA-65 and classical keys, decision-signing keys, the AuthZEN metadata key, the secret store's keys); how federation keys are minted for topologies joined later.
- **Why open:** intermediate keys need hardware protection where the board has it ([0020](../decisions/0020-realm-certificate-authority.md), Consequences). The ceremony mints "its federation keys" ([0021](../decisions/0021-entropy-before-keys.md), rule 6), but there are keys per class of topology and topologies can be joined later ([0017](../decisions/0017-openid-federation-membership.md), rules 6 and 7; see [Conflicts](#conflicts-between-accepted-adrs)).
- **Options:** TPM, TrustZone or memory only ([security tokens note §5](security-tokens.md#5-open-questions)); every realm signing key treated as long-lived; later federation keys minted under 0021 rule 5 on a qualifying node, in a later ceremony where policy requires one.
- **Blocks:** C25, C35. **Depends on:** D46.

**D59. The key service, and where signing happens**

- **Decide:** the key service's interface (generating keys, and signing by capability); whether the CAs, the provider, the authorization service and the federation entity sign through it.
- **Why open:** cryptography runs in "the network server and a key service" ([0003](../decisions/0003-hybrid-post-quantum-cryptography.md), rule 6), and the secret store's keys come from the key service ([0026](../decisions/0026-realm-as-cloud-provider.md), rule 8), but the signers are services of their own ([0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 4; [0020](../decisions/0020-realm-certificate-authority.md), rule 6).
- **Options:** every signer signs through the key service by capability and never holds its key.
- **Blocks:** C25. **Depends on:** D28, D33.

**D60. The Rust `std` port: its name and its randomness**

- **Decide:** the target's name; where `std` gets randomness, such as `HashMap` seeds; whether any server that starts before the gate may use `std`.
- **Why open:** `aarch64-unknown-aspis` is only an example ([POSIX note §7](posix-compatibility.md#7-c-library-and-rust)). The entropy service is the only source of randomness ([0021](../decisions/0021-entropy-before-keys.md), rule 1), and it waits at the gate (rule 2). [0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), rule 5 builds every user-space program `no_std` until there is a std port, and leaves whether and when to port it until the POSIX personality or applications need it. A port needs a custom target, so nightly Rust, until `build-std` is stable, and rule 1 allows no nightly feature without a decision of its own.
- **Options:** `std` draws on the process's child DRBG or on the entropy service; every server that starts before the gate is `no_std`. For now every user-space program is `no_std` ([0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), rule 5).
- **Blocks:** C26. **Depends on:** D02, D47.

**D61. The authorization tree's key layout**

- **Decide:** how the grant tree, principal tree, realm-policy branch, CA branches and catalog branch share one signed root; depth and fan-out; whether a grant key keeps the object's authority as a raw prefix; how an object whose branch was revoked gets fresh keys.
- **Why open:** 0016's two trees are a strawman "to be refined in the design session" ([0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 2), and later records add branches ([0018](../decisions/0018-cedar-policy-language.md), rule 2; [0020](../decisions/0020-realm-certificate-authority.md), rule 7; [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 4). Revoking a publisher withdraws its entries "together with its grants" in one epoch ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 4), but the strawman's grant keys begin with a hash of the object ID ([authorization tree note §3.1](authorization-tree.md#31-grant-tree)), and revocation is permanent ([0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 3).
- **Options:** a type tag in the 256-bit key; roots per kind under a small fixed Merkle tree; a raw authority prefix; a hashed prefix; a generation in the object part.
- **Blocks:** C27. **Depends on:** D34.

**D62. Grant and principal records**

- **Decide:** the encoding and ABNF of a grant leaf and of a principal's record; how group memberships are recorded in the principal tree.
- **Why open:** each grant is a template-linked Cedar policy ([0018](../decisions/0018-cedar-policy-language.md), rule 2), but the record's encoding is open ([authorization tree note §6](authorization-tree.md#6-open-questions)). Memberships come from the principal tree alone ([0018](../decisions/0018-cedar-policy-language.md), rule 3), so they must be recorded there (Consequences).
- **Options:** a principal record that holds its memberships; a separate group branch.
- **Blocks:** C27. **Depends on:** D61.

**D63. Certificate profile details**

- **Decide:** distinguished names for the root and the intermediates; end-entity subjects; key identifiers; which extensions are critical; AIA on the root.
- **Why open:** [0020](../decisions/0020-realm-certificate-authority.md), rules 5 and 9 and [0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 3 fix the subjectAltName, the name constraints and AIA, and leave the other fields ([CA note §8](realm-certificate-authority.md#8-open-questions)).
- **Options:** follow the X.509-SVID and WIMSE mutual-TLS profiles (an empty subject and a critical subjectAltName); critical name constraints.
- **Blocks:** C28. **Depends on:** D34.

**D64. Node networking**

- **Decide:** how a node configures IPv6 and finds its neighbors; how RPC fits QUIC's 1,200-byte datagram floor; DNS for realm names; how a node authority, the first location hint, becomes a transport address.
- **Why open:** RPC runs over IPv6 and UDP ([0004](../decisions/0004-network-transparency-and-failure.md), rule 1; [0020](../decisions/0020-realm-certificate-authority.md), rule 3), and an ID's authority is the first hint of where it lives ([0004](../decisions/0004-network-transparency-and-failure.md), rule 5), but no decision covers addressing or name resolution.
- **Options:** SLAAC or DHCPv6.
- **Blocks:** C75, C29, C40. **Depends on:** D43.

**D65. The TLS and QUIC stack, the composite codepoint and RPC's ALPN identifier**

- **Decide:** one TLS 1.3 and QUIC stack for RPC and HTTPS that supports RFC 10024, RFC 10073 and `draft-ietf-tls-composite-mldsa`; the private-use codepoint, the pinned draft revision and the move to IANA's value; RPC's ALPN identifier in ABNF; whether the stack needs `std` or an async runtime, which would make C29 depend on C26.
- **Why open:** [0020](../decisions/0020-realm-certificate-authority.md), rules 2 and 3 and its Consequences require all of this and name no stack.
- **Options:** none named.
- **Blocks:** C29, C52. **Depends on:** D33.

**D66. The network server and the network stack server**

- **Decide:** who owns the IPv6 and UDP stack and the NIC drivers, and whether the POSIX network stack server shares them; whether there is one network stack server per node or one per POSIX instance; NAT traversal; the life of proxy endpoints; remote page fetch; how outbound connections are authorized without ambient network authority.
- **Why open:** [0004](../decisions/0004-network-transparency-and-failure.md), rule 5 and [0012](../decisions/0012-posix-compatibility-layer.md), rule 1 define the two servers separately ([node view §1](node-components.md#1-overview)), and [0004](../decisions/0004-network-transparency-and-failure.md), rule 1 assumes NAT traversal.
- **Options:** none named.
- **Blocks:** C29, C43. **Depends on:** D43, D64.

**D67. 0-RTT and QUIC transport parameters**

- **Decide:** whether RPC allows 0-RTT; idle timeouts, migration and keep-alives for long-lived connections between nodes.
- **Why open:** 0-RTT data can be replayed, which works against at-most-once execution ([0004](../decisions/0004-network-transparency-and-failure.md), rule 3). Long-lived connections and resumption spread the large handshakes' cost ([0020](../decisions/0020-realm-certificate-authority.md), Consequences).
- **Options:** forbid 0-RTT on RPC; allow it only for idempotent requests that carry request IDs.
- **Blocks:** C29. **Depends on:** D65.

**D68. Root distribution, the staleness bound and the tree-signing key's trust path**

- **Decide:** the batch interval; the distribution protocol; the staleness bound, and how a root's age is measured; how a stale PDP answers; how a node learns and trusts the tree-signing public key.
- **Why open:** [0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 7 refuses binds past "a policy bound", and rule 4 orders roots by epoch, not by clock. A node trusts one anchor, its realm's root ([0020](../decisions/0020-realm-certificate-authority.md), rule 10), and the root signs only intermediate certificates, cross-certificates and its CRL (rule 1).
- **Options:** a signed issue time in each root, with heartbeat roots; the enforcement point judging age from the decision's epoch; the key published in ASPIS-native metadata, delivered at enrollment or certified from an intermediate.
- **Blocks:** C30. **Depends on:** D61.

**D69. The authorization service: availability, its signing key, transparency and read access**

- **Decide:** replication, consensus or sharding by prefix; custody of the online tree-signing key in a replicated service; whether signed roots also go into a transparency log; who may read which branches.
- **Why open:** the authorization service and root distribution must be replicated, and subtrees can be sharded by prefix ([0016](../decisions/0016-authorization-sparse-merkle-tree.md), Consequences). How is open ([authorization tree note §6](authorization-tree.md#6-open-questions)).
- **Options:** one active signer with failover; threshold signing; a key per shard, certified by a ceremony key.
- **Blocks:** C30. **Depends on:** D58.

**D70. The write path into the authorization service**

- **Decide:** how changes reach the authorization service; batching; whether the policy service alone writes policy branches while the CAs, the catalog and the registry write their own; how the registry's principals and memberships reach the principal tree; how records that aren't policies are validated.
- **Why open:** [0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 4 has the authorization service apply batches, and [0018](../decisions/0018-cedar-policy-language.md), rule 7 has the policy service validate policy changes. [0018](../decisions/0018-cedar-policy-language.md) leaves how registry changes reach the tree to the write path (Consequences).
- **Options:** one typed submission interface; a writer per branch.
- **Blocks:** C30. **Depends on:** D61, D62.

**D71. Collecting expired grants and records**

- **Decide:** how expired grants and certificate records are collected, given that revocation is permanent and each parent has a fixed number of grant slots.
- **Why open:** [0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 3 makes revocation permanent, the strawman gives a parent at most 65,535 grants ([authorization tree note §3.1](authorization-tree.md#31-grant-tree)), and collection is open ([authorization tree note §6](authorization-tree.md#6-open-questions)).
- **Options:** collection reclaims expired leaves but never reuses a revoked key; grants revoked one by one where access may return.
- **Blocks:** C30. **Depends on:** D61.

**D72. The audit log**

- **Decide:** which component keeps the realm's audit log; where it is stored; its interface; retention.
- **Why open:** the audit log records what each revoked marker removed ([0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 3) and every admin run ([0026](../decisions/0026-realm-as-cloud-provider.md), rule 10), and no decision says which service keeps it ([realm view §2](realm-containers.md#2-identity-pki-and-authorization)).
- **Options:** append-only objects in the single-level store; a log-router stream; hashes committed in the tree.
- **Blocks:** C30, C58. **Depends on:** D50.

**D73. Cedar schema generated from the IDL**

- **Decide:** entity types and attributes; how IDL action groups span major versions; how reverse-DNS type names map to Cedar entity types; the full action ID of `discover`, and what it is evaluated against.
- **Why open:** [0018](../decisions/0018-cedar-policy-language.md), rule 4 has the IDL compiler emit a schema fragment for each interface version, and [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 8 adds `discover`. The mapping is open ([policy note §7](policy-and-decisions.md#7-open-questions)).
- **Options:** none named.
- **Blocks:** C31. **Depends on:** D12, D28.

**D74. The ASPIS AuthZEN profile**

- **Decide:** the RPC binding; type and action names in ABNF; the context keys (determining policies, epoch, step-up hints); who computes the token-scope ceiling; how a remote enforcement point's workload token travels; publication.
- **Why open:** [0019](../decisions/0019-authzen-decision-protocol.md) calls for the profile (Consequences) and fixes what it covers (rules 2 and 4 to 8), not its form. Rule 6 has remote requests carry the enforcement point's workload token, while calls carry no token ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 1; see [Conflicts](#conflicts-between-accepted-adrs)).
- **Options:** the illustrative keys `aspis_determining_policies` and `aspis_epoch` ([policy note §4](policy-and-decisions.md#4-mapping-aspis-onto-cedar-and-authzen)); a remote enforcement point binds to the PDP once with its token and then uses the session.
- **Blocks:** C31. **Depends on:** D12, D73.

**D75. PDP checks and decision signing**

- **Decide:** how the PDP checks that an enforcement point manages the object; how it gets the ancestors Cedar's `in` needs (directory chains across managers, nested groups); which key signs decisions sent across nodes and the AuthZEN metadata; whether local decisions are signed too.
- **Why open:** [0019](../decisions/0019-authzen-decision-protocol.md), rule 5 has the PDP check that an enforcement point manages the objects it describes, and rule 7 signs decisions sent across nodes "with the node's key" without naming the key. Signing local decisions is open ([policy note §7](policy-and-decisions.md#7-open-questions)).
- **Options:** type to manager from the catalog replica; authority to deploy from the location service; ancestor chains supplied by managers; a decision-signing key certified by the genesis key.
- **Blocks:** C32. **Depends on:** D62, D74.

**D76. Realm invariants and delegation**

- **Decide:** which invariants the policy service enforces at write time, and whether Cedar's analysis tools check them; which action authorizes creating a delegated grant, and how a delegated grant stays within its parent's rights.
- **Why open:** [0018](../decisions/0018-cedar-policy-language.md), rule 7 lets the policy service refuse changes that break invariants, and [0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 2 nests delegations under their grant. Neither says how.
- **Options:** an administer or delegate action group declared in the IDL; a child's actions a subset of its parent's.
- **Blocks:** C33. **Depends on:** D73.

**D77. Authenticated time synchronization**

- **Decide:** a post-quantum authenticated protocol whose bootstrap doesn't need certificates the node can't yet validate; clock-skew tolerance; the first-boot time gate; where wall time is served.
- **Why open:** [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 7 makes authenticated time a requirement whose design is open, and [0020](../decisions/0020-realm-certificate-authority.md) adds that it must not depend on a certificate the node can't validate before its clock is set (Consequences). The Pi 4 has no battery-backed clock ([0021](../decisions/0021-entropy-before-keys.md), Consequences). Time doesn't come from firmware: on QEMU a driver reads the PL031, and the Pi 4 has no clock to read ([0039](../decisions/0039-no-uefi-runtime-services.md), rule 4).
- **Options:** NTS (RFC 8915), which depends on TLS.
- **Blocks:** C34, C63. **Depends on:** D17.

**D78. Accepting ADR 0029**

- **Decide:** whether to accept [0029](../decisions/0029-founding-node-self-signed-certificate.md), which was then proposed: the founding node certifies its operational key with its genesis key, records that certificate in the genesis state, uses it alone, and replaces it by a renewal with the RPC CA before any other node enrolls.
- **Why open:** the project owner decided that the founding node signs its own initial certificate. Rules 3 to 6 of 0029, which spell that out, were proposals that would change [0020](../decisions/0020-realm-certificate-authority.md), rules 4 and 6. Until 0029 was accepted, the accepted rules had the RPC CA issue every node certificate after enrollment, as [0021](../decisions/0021-entropy-before-keys.md)'s Context also says.
- **Options:** accept 0029 as written; accept it with changes to rules 3 to 6.
- **Blocks:** C35, C36. **Depends on:** none.
- **Settled:** [0029](../decisions/0029-founding-node-self-signed-certificate.md), accepted 2026-11-25. [0020](../decisions/0020-realm-certificate-authority.md), rules 4 and 6 make the founding node's initial certificate the exception. The ceremony and the genesis state are still D79's.

**D79. The ceremony's procedure and the genesis tree state**

- **Decide:** the order of minting; what the ceremony outputs (the root certificate, CSRs, metadata, the first signed root); the genesis batch (first epoch, founding administrator, the realm-policy branch with the token-scope ceiling and the CAs' issuing rules, the founding node's principal, genesis key and initial certificate, and the policies that let it renew and enroll the next node); where the online keys go; the scripted QEMU mode and the ceremony tool.
- **Why open:** [0021](../decisions/0021-entropy-before-keys.md), rule 6 makes creating a realm a ceremony and lists what it mints: the CA root and intermediates of [0020](../decisions/0020-realm-certificate-authority.md), rule 1, the federation keys and the tree-signing key. [0029](../decisions/0029-founding-node-self-signed-certificate.md) lists what the genesis state must hold (rule 3 and Consequences). No procedure exists ([key flows §3](key-flows.md#3-realm-creation-ceremony)).
- **Options:** the ceremony writes and signs a genesis batch; bootstrap templates as well-known objects.
- **Blocks:** C35. **Depends on:** D58, D61, D78.

**D80. Lifetimes, the certificate policy and the root's CRL**

- **Decide:** the root's and the intermediates' lifetimes; the end-entity lifetime under the seven-day ceiling, and when renewal starts; the certificate policy (OIDs, assurance, audit) and how realms get OID arcs; the root CRL's cadence, `nextUpdate` and URL.
- **Why open:** [0020](../decisions/0020-realm-certificate-authority.md), rule 7 sets a seven-day ceiling and automatic renewal, and rule 8 a policy OID and an RFC 3647 policy. The values are open ([CA note §8](realm-certificate-authority.md#8-open-questions)).
- **Options:** an IANA Private Enterprise Number with arcs per realm; OIDs derived from UUIDs under 2.25. None named for lifetimes.
- **Blocks:** C35, C36. **Depends on:** none.

**D81. Enrollment proofs, the CA's interface and certificate records**

- **Decide:** the format of the genesis key's certification of an operational key, and of the enrollment proof; the CA's interface (name, methods, errors, revocation requests); the layout of certificate records under each CA's branch; whether node certificates carry the genesis proof, about 5 KB more.
- **Why open:** [0020](../decisions/0020-realm-certificate-authority.md), rules 4, 6 and 7 require each of these without a format ([CA note §8](realm-certificate-authority.md#8-open-questions)). Under [0029](../decisions/0029-founding-node-self-signed-certificate.md), rule 2, the founding node's initial certificate is that certification in X.509 form.
- **Options:** a CSR attribute holding a composite signature over the key; an ASPIS-defined statement in ABNF; an `aspis.ca/1` interface with enroll, renew, issue and get-chain.
- **Blocks:** C36. **Depends on:** D28, D61, D63, D78.

**D82. Node admission, trust anchors and recovery after expiry**

- **Decide:** who approves a node joining; how its first enrollment call travels before it has a certificate; how it gets the realm root, the tree-signing key and a first signed root; how a node that was offline for more than seven days, or took a new authority (D48), gets back.
- **Why open:** RPC needs a node certificate at each end ([0020](../decisions/0020-realm-certificate-authority.md), rule 3), renewal needs the current certificate (rule 6), and the registry refuses an authority it knows ([0001](../decisions/0001-object-identifiers.md), rule 6). Images carry no secrets ([0021](../decisions/0021-entropy-before-keys.md), rule 11), so a join credential can't come in a shared image.
- **Options:** a one-time join token, issued by an operator and bound to the genesis key's hash; server-only TLS on a bootstrap ALPN identifier; anchors pinned by hash; a re-certification call proven with the genesis key.
- **Blocks:** C36, C76. **Depends on:** D65, D68.

**D83. Identity for system services at boot**

- **Decide:** how the PDP, the CAs, the catalog and the provider's replicas get workload identity before the provider and a PDP can be reached, on the founding node and after a boot inside a partition.
- **Why open:** the process manager attests workloads ([0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 7), but system services start below the bootstrap line, where root-server capabilities are the only authority ([0018](../decisions/0018-cedar-policy-language.md), rule 5).
- **Options:** root-server capabilities until the provider can be reached; issuance on the node under its own authority; WITs issued in advance at enrollment.
- **Blocks:** C32, C36. **Depends on:** D41, D78.

**D84. Observability of system services**

- **Decide:** where system servers log; what health and metrics they expose; how a headless node reports what it is waiting for; how trace context crosses RPC.
- **Why open:** a node that waits for entropy "reports what it is waiting for" ([0021](../decisions/0021-entropy-before-keys.md), rule 5), and the log router serves only deploys ([0026](../decisions/0026-realm-as-cloud-provider.md), rule 9). Nothing covers system services. For the kernel's own messages, the root server passes the log ring's capability to the server that collects system logs (C74; [0042](../decisions/0042-log-ring-and-panic-path.md), rule 5).
- **Options:** none named.
- **Blocks:** C74. **Depends on:** D10, D25.

## M5. Two nodes, one realm

Chunks C37 to C40 and C76 ([build plan](build-plan.md#m5-two-nodes-one-realm)).

**D85. The token profile**

- **Decide:** the claims of `at+jwt`, `wit+jwt` and `wpt+jwt`, and their ABNF; scope syntax; the forms of `aud` and of the realm's `iss`; access-token, refresh and session lifetimes, and clock skew; how an access token travels with a WPT-form proof, and the `oth` key in ASPIS's RPC binding; what programs that bind on a user's behalf present; whether the token-scope ceiling applies to a bind made with a WIT; whether tokens still carry an issue epoch or attached proofs; replay protection for proofs.
- **Why open:** [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md) leaves the profile to be specified, including how a user's access token travels with a proof that binds to a WIT ([0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rules 4 and 10), so programs dm starts need WITs too (Consequences). [0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 5's attached proofs predate tokens losing their grant keys ([0019](../decisions/0019-authzen-decision-protocol.md), rule 8; see [Conflicts](#conflicts-between-accepted-adrs)).
- **Options:** scopes in the canonical call text, such as `aspis.io/1/read`; the access token covered by the WPT's `oth`; exchanging the WIT for an access token before each bind; a `jti` cache per manager, bounded by a short proof lifetime; a nonce the manager supplies; attached proofs kept only for grants checked against another realm's roots.
- **Blocks:** C37, C39. **Depends on:** D12, D34.

**D86. Draft revisions and composite JOSE identifiers**

- **Decide:** which revisions to pin (the WIMSE identifier, credentials, proof token and mutual-TLS drafts; the JOSE composite draft); the composite `alg` string and its JWK form; when to fall back to RFC 9964's ML-DSA-65.
- **Why open:** [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 3 and [0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 10 pin drafts by revision without choosing the revisions ([workload identity note §7](workload-identity.md#7-open-questions)).
- **Options:** the current revisions: identifier -04, credentials -03, proof token -02, mutual TLS -03, JOSE composite -06.
- **Blocks:** C37. **Depends on:** D33.

**D87. The lease and coherence protocol**

- **Decide:** leases or tokens for shared remote objects; duration, renewal, grace and how far they depend on clocks; whether immutable objects are exempt; what singleton leases, availability leases and POSIX advisory locks reuse; how a lease is sure to lapse before its replacement starts.
- **Why open:** [0005](../decisions/0005-single-level-store.md), rule 4 leaves the protocol to the design session, and [0025](../decisions/0025-twelve-factor-app-contract.md), rule 9, [0026](../decisions/0026-realm-as-cloud-provider.md), rules 4 and 5 and [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 5 depend on it. [0032](../decisions/0032-stateful-services-run-as-platform-deploys.md), rule 3 runs a stateful service's primary under a singleton lease, and leaves how those leases behave across partitions and clock skew open (Consequences). The unread AEGIS sources on lock modes and remote page validation may inform it ([research notes §6](../research/aegis-domain-os.md#6-gaps-and-next-sources)).
- **Options:** leases; tokens ([0005](../decisions/0005-single-level-store.md), rule 4).
- **Blocks:** C40, C42, C50, C54. **Depends on:** D77.

**D88. Placement and replication of realm services**

- **Decide:** which nodes run the registry, the provider, the CAs, the federation entity, the catalog service and the app platform's services; how each replicates; where their keys live; how CA serial numbers stay unique.
- **Why open:** the router runs on edge nodes ([0026](../decisions/0026-realm-as-cloud-provider.md), rule 6), and every node runs a PDP and a catalog replica ([0019](../decisions/0019-authzen-decision-protocol.md), rule 3; [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 3). The rest must be replicated ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), [0016](../decisions/0016-authorization-sparse-merkle-tree.md) and [0026](../decisions/0026-realm-as-cloud-provider.md), Consequences), and no decision says how. In M4's single-node realm every realm service runs on the founding node, so placement and replication come due with the second node.
- **Options:** designated nodes, with keys in the key service; active and passive replicas under a singleton lease; one signer with read replicas; a signing key per replica; threshold signing.
- **Blocks:** C38, C40, C50, C54. **Depends on:** D58, D87.

**D89. The provider's signing keys**

- **Decide:** custody, entropy class, where they are minted, rotation, the `kid` scheme and publication, for the composite token-signing key and for the external ML-DSA-65 and classical keys.
- **Why open:** nodes need cached keys to keep verifying tokens in a partition ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), Consequences), and the external keys rotate separately ([0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 5 and Consequences). None of them is in [0021](../decisions/0021-entropy-before-keys.md), rule 5's list.
- **Options:** an ASPIS-native federation key minted at the ceremony; an online key certified by a ceremony key; a key-set object with a well-known ID.
- **Blocks:** C38. **Depends on:** D58, D88.

**D90. Token exchange and delegation**

- **Decide:** who may exchange what (subject and actor tokens, `may_act`, narrowing, chain depth); how `act` chains and transaction tokens are represented.
- **Why open:** [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 4 adopts token exchange and the transaction-tokens draft as models, and [0026](../decisions/0026-realm-as-cloud-provider.md), rule 10 uses `act`. The rules for each are open.
- **Options:** a Cedar action on the provider for each kind of exchange; nested `act` claims; a transaction-token profile once the draft becomes an RFC.
- **Blocks:** C38. **Depends on:** D85.

**D91. How a node authenticates to the provider**

- **Decide:** the mechanism.
- **Why open:** the key is settled: an operational key that the genesis key has certified ([0001](../decisions/0001-object-identifiers.md), rule 3; [0020](../decisions/0020-realm-certificate-authority.md), rule 4). The mechanism isn't ([key flows §2](key-flows.md#2-first-boot-genesis-identity-and-enrollment)).
- **Options:** a client assertion signed with that key ([security tokens note §4.2](security-tokens.md#42-workload-identity)); mutual TLS with the node certificate (RFC 8705).
- **Blocks:** C38. **Depends on:** D81.

**D92. Sessions: channel binding and the cost of a bind**

- **Decide:** the renewal call; how a remote session is bound to its secure channel; session IDs, migration and resumption; how a local capability ends when its token expires; how a POSIX `open()` stays cheap when each bind needs a token, a composite-signed proof and a PDP batch.
- **Why open:** a session ends when its token expires or a branch holding one of its determining policies is revoked, and renews with a fresh token ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 1). Nothing says how a session is tied to its channel, or what a bind may cost.
- **Options:** channel binding through the TLS exporter; a manager timer that revokes the capability at `exp`; broad-scope tokens reused across binds; directory-scoped binds that yield child capabilities.
- **Blocks:** C39, C42. **Depends on:** D39, D85.

**D93. Re-evaluating sessions after a new `forbid`**

- **Decide:** when a new root's `forbid` policies trigger re-evaluation of live sessions, and what that may cost.
- **Why open:** a new `forbid` doesn't appear as a revoked branch, so managers must re-evaluate the sessions it could affect ([0019](../decisions/0019-authzen-decision-protocol.md), Consequences).
- **Options:** re-evaluate the sessions a new `forbid` could affect when the root touches the relevant branches.
- **Blocks:** C39. **Depends on:** D74.

**D94. Node provisioning before enrollment**

- **Decide:** where a new node's realm domain, enrollment endpoint, anchor hash, network settings, time sources and friendly name come from; how an administrator admits it.
- **Why open:** images carry no secrets ([0021](../decisions/0021-entropy-before-keys.md), rule 11) and cloned SD cards must stay safe (Consequences), so per-node settings and any join credential arrive out of band ([key flows §2](key-flows.md#2-first-boot-genesis-identity-and-enrollment)). Kernel arguments are now defined: ASCII only, at most 4096 bytes, with keys under `root.` passed to the root server unread ([0041](../decisions/0041-boot-abi.md), rule 5). So settings that are passed as kernel arguments can't carry text that isn't ASCII, such as some friendly names.
- **Options:** kernel arguments, a file on the ESP or a console prompt; an administrator approves the genesis-key fingerprint the node shows on its console.
- **Blocks:** C76, C40, C63. **Depends on:** D64, D82.

## M6. A console you can log in to

Chunks C41 to C48 ([build plan](build-plan.md#m6-a-console-you-can-log-in-to)).

**D95. `fork`, `exec`, and credentials that must not be inherited**

- **Decide:** whether `fork` copies only the calling thread; what it must re-mint rather than copy (capabilities that identify the parent, the child DRBG, the request-ID generator, the WIT and its key); what `exec` carries across; how binding credentials stay with the parent.
- **Why open:** [0012](../decisions/0012-posix-compatibility-layer.md), rule 4 copies the capability table on `fork`, while [0025](../decisions/0025-twelve-factor-app-contract.md), rule 5 says credentials are never inherited unless passed (see [Conflicts](#conflicts-between-accepted-adrs)). Every process that binds needs a WIT ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), Consequences).
- **Options:** the POSIX minimum, or more ([POSIX note §8](posix-compatibility.md#8-open-questions)); `fork` leaves credential capabilities behind unless they are passed explicitly.
- **Blocks:** C41. **Depends on:** D38, D47, D85.

**D96. POSIX instances, signals, pids, `errno` and extensions**

- **Decide:** who starts the default instance on each node, and as which principal; pid 1 and the re-parenting of orphans; which processes get `SIGTERM` on a stop notice; which policy decides whether one process may signal another; whether pids reach other nodes; the `errno` mapping table, and the call that returns the original typed error; which Linux and BSD extensions are in scope (`epoll`, `kqueue`, `/proc`, `ptrace`, `inotify`, `eventfd`).
- **Why open:** [0012](../decisions/0012-posix-compatibility-layer.md), rules 3 and 7 and [0025](../decisions/0025-twelve-factor-app-contract.md), rule 9 set the frame; the details are open ([POSIX note §8](posix-compatibility.md#8-open-questions)).
- **Options:** native APIs only for other nodes; pids that reach other nodes.
- **Blocks:** C41. **Depends on:** D26.

**D97. POSIX permissions, owners and uid numbers**

- **Decide:** who owns uid numbers; whether an object stores uid and gid numbers or owner and group principals; which subjects stand for group and other; which templates map to read, write and execute for each type; how `chmod` becomes template links; when a listing shows the marker for a richer ACL; setuid, setgid and the sticky bit; id mapping between federated realms.
- **Why open:** mode bits are a view onto ACLs ([0012](../decisions/0012-posix-compatibility-layer.md), rule 6; [0016](../decisions/0016-authorization-sparse-merkle-tree.md), Consequences), so they aren't stored. Rule 6's registry-assigned uids sit beside rule 3's per-instance map (see [Conflicts](#conflicts-between-accepted-adrs)), and the [POSIX note §3](posix-compatibility.md#3-proposed-architecture) stores uid and gid as attributes.
- **Options:** IDL action groups mapped to the bits; "other" as a realm-wide group principal; realm-wide numbers that each instance's map projects; NFSv4-style id mapping.
- **Blocks:** C42. **Depends on:** D62, D73.

**D98. Failure policy, locks, `/dev` and pipes**

- **Decide:** where a subtree's failure policy is recorded; the advisory-lock protocol and the lock owner; which component serves `/dev`, and how `ioctl`s map to typed calls; who serves pipes and FIFOs.
- **Why open:** [0012](../decisions/0012-posix-compatibility-layer.md), rule 7 gives each subtree a failure policy without saying where it lives, and locks rest on leases ([0025](../decisions/0025-twelve-factor-app-contract.md), rule 9; [POSIX note §4.13](posix-compatibility.md#413-locks)).
- **Options:** a directory attribute, a mount option, a Cedar policy or the instance's configuration, for the failure policy.
- **Blocks:** C42. **Depends on:** D87.

**D99. `AF_UNIX`, and the default for outbound traffic**

- **Decide:** which server implements `AF_UNIX`; how socket files appear in the namespace; how `SCM_RIGHTS` becomes a capability transfer; whether a deploy's processes reach only their bound services by default.
- **Why open:** sockets' details are open ([POSIX note §4.20](posix-compatibility.md#420-sockets)), and so is the egress default ([twelve-factor note §9](twelve-factor-apps.md#9-open-questions)). The Workload Endpoint identifies its callers through the POSIX process server ([0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 8).
- **Options:** none named.
- **Blocks:** C43, C49. **Depends on:** D66.

**D100. The ASPIS SVG profile, the renderer and the text stack**

- **Decide:** the exact SVG 2 static subset, filter subset and CSS subset; the CPU renderer; text shaping, with fonts as objects; what must work in `no_std`.
- **Why open:** [0010](../decisions/0010-svg-core-primitive.md), rule 2 leaves the profile to the design session, and rule 10 the library. The fonts are settled: the SVG layer uses Noto Sans Mono and Noto Sans, with other Noto families as fallbacks for other scripts ([0034](../decisions/0034-noto-fonts-under-ofl.md), rule 1).
- **Options:** resvg with usvg and tiny-skia (0.47); `vello_cpu` (alpha); `vello_hybrid` (0.0.x) ([0010](../decisions/0010-svg-core-primitive.md), rule 10).
- **Blocks:** C44. **Depends on:** D06.

**D101. Element handles in the DOM protocol**

- **Decide:** how the DOM protocol names elements, and so what "the ID of the element hit" in an input event is.
- **Why open:** [0010](../decisions/0010-svg-core-primitive.md), rule 9 tags input events "with the ID of the element hit", but SVG elements aren't objects in [0001](../decisions/0001-object-identifiers.md)'s sense (see [Conflicts](#conflicts-between-accepted-adrs)). The handles may also serve assistive technology (D142).
- **Options:** handles assigned by the client or by the server, scoped to the client's document.
- **Blocks:** C45. **Depends on:** D28.

**D102. A native command interpreter, and accepting ADR 0031**

- **Decide:** whether ASPIS has a native command interpreter besides dm's commands and the POSIX shell; if so, what its language is, and how that language is specified, which [0031](../decisions/0031-abnf-is-not-a-command-language.md), rule 1 says is not ABNF; whether to accept 0031.
- **Why open:** [0011](../decisions/0011-dm-window-system.md), rule 6 leaves dm's command language to the design session, and [0012](../decisions/0012-posix-compatibility-layer.md) brings the POSIX.1-2024 shell (rule 2). No accepted record says whether ASPIS has an interpreter of its own beside them. The project owner decided that ABNF is a protocol specification metalanguage, not the language of a command interpreter people use. [0031](../decisions/0031-abnf-is-not-a-command-language.md) records that decision and frames this question (Consequences). [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 2 leaves the command interpreter's language, dm's included, out of the formats ABNF describes, and rule 5 makes the canonical call text machine-facing, not the syntax people type at the command line.
- **Options:** for 0031, accept it as written or with changes to its wording. None named yet for the interpreter or its language.
- **Blocks:** C46. **Depends on:** none.
- **Settled in part:** whether to accept 0031. [0031](../decisions/0031-abnf-is-not-a-command-language.md) was accepted 2026-11-25. Whether ASPIS has a native interpreter, what its language is and how that language is specified are still open.

**D103. dm's detailed design**

- **Decide:** the command language, and how it is specified; key bindings; pad types, including terminal mode and the login pad; window policies; the catalog browser, and how IDL documentation is rendered.
- **Why open:** [0011](../decisions/0011-dm-window-system.md), rule 6 leaves these to the design session, and [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 10 adds the catalog browser. [0031](../decisions/0031-abnf-is-not-a-command-language.md), rule 2 takes the dm command language off [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 2's list of formats ABNF describes, and leaves the language's design to choose how it is specified (D102).
- **Options:** none named for the language or the pads.
- **Blocks:** C46. **Depends on:** D100, D102.

**D104. Terminal pads**

- **Decide:** window size and `SIGWINCH`; `SIGHUP` when a pad closes; how `termios` settings reach the pad. Whether bring-up and CI get an interpreter on the serial console before dm is D44.
- **Why open:** the emulator is a pad mode the POSIX layer provides ([0011](../decisions/0011-dm-window-system.md), rule 3), and the TTY server, one of the personality's parts ([0012](../decisions/0012-posix-compatibility-layer.md), rule 1), provides the pseudo-terminals that dm pads back (rule 8). The rest is open ([node view §3](node-components.md#3-the-posix-personality)).
- **Options:** none named.
- **Blocks:** C41, C46. **Depends on:** D96.

**D105. Native login, user credentials and step-up**

- **Decide:** the login protocol between dm and the provider; how passwords, passkeys over USB HID and smart cards are stored and checked; which key a user's tokens bind to; `acr` values and the step-up flow.
- **Why open:** [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 2 names the credentials, [0019](../decisions/0019-authzen-decision-protocol.md), rule 7 the step-up hints, and the realm's CA certifies no people ([0020](../decisions/0020-realm-certificate-authority.md), rule 4).
- **Options:** a native IDL interface on the provider; a per-session dm key in the key service; a typed error carrying `acr_values`; smart-card keys registered with the provider, as passkeys are, or certified by an external PKI configured per realm.
- **Blocks:** C46. **Depends on:** D85.

**D106. The userland, the base and conformance**

- **Decide:** which shell and utilities meet POSIX.1-2024 under 0008's license rule; how the twelve-factor base is built; conformance suites and certification.
- **Why open:** [0012](../decisions/0012-posix-compatibility-layer.md), rule 2 targets POSIX.1-2024, [0008](../decisions/0008-mpl-2.0-license.md), rule 4 limits licenses, and [0025](../decisions/0025-twelve-factor-app-contract.md), rule 3 makes the base an immutable, versioned object.
- **Options:** the Open POSIX Test Suite; parts of the Linux Test Project; formal certification later ([POSIX note §8](posix-compatibility.md#8-open-questions)).
- **Blocks:** C47, C55. **Depends on:** D30.

## M7. Workloads and discovery

Chunks C49 to C53 ([build plan](build-plan.md#m7-workloads-and-discovery)).

**D107. The app contract's interfaces, variables and namespace**

- **Decide:** the IDL of the environment block, the binding, lifecycle and listener interfaces and the native workload identity interface, with rotation signaling; the exact `ASPIS_*` names; the values of `SERVICE_BINDING_ROOT`, the Workload Endpoint socket, `TMPDIR`, `HOME` and `PORT`; what a process reaches beyond its four namespace entries; whether the process or its process manager generates the instance's key.
- **Why open:** [0025](../decisions/0025-twelve-factor-app-contract.md) lists these as new interfaces (Consequences). Rule 4's documented variables omit `TMPDIR` and `HOME`, which rule 6 sets, and rule 3's four entries omit the Workload Endpoint socket ([0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 8) and the entropy devices ([0021](../decisions/0021-entropy-before-keys.md), rule 10) (see [Conflicts](#conflicts-between-accepted-adrs)). Rule 11 says only "a key the instance holds".
- **Options:** an eventcount per credential set; `ASPIS_PROCESS_TYPE`, `ASPIS_INSTANCE` and `ASPIS_RELEASE`; `TMPDIR` and `HOME` added to the documented set; platform services listed as capabilities outside the namespace.
- **Blocks:** C49. **Depends on:** D28, D30.

**D108. Workload credential lifetimes, X.509-SVIDs and cutting off one instance**

- **Decide:** WIT and workload-certificate lifetimes under the seven-day ceiling; which workloads get X.509-SVIDs; how to cut off one compromised instance when the instances of a process type share its principal.
- **Why open:** [0020](../decisions/0020-realm-certificate-authority.md), rule 4 gives workload certificates only to workloads that need mutual TLS with parties outside ASPIS, while the Workload Endpoint serves SVIDs to unmodified programs ([0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 8; see [Conflicts](#conflicts-between-accepted-adrs)). Instances share their type's identity URI ([0026](../decisions/0026-realm-as-cloud-provider.md), rule 11).
- **Options:** lifetimes of hours, as in SPIFFE practice ([workload identity note §7](workload-identity.md#7-open-questions)); Cedar deciding per principal whether the endpoint serves an X.509-SVID; instance keys, WIT `jti`s or certificate serials recorded under the principal's branch; very short WIT lifetimes.
- **Blocks:** C49, C60. **Depends on:** D81, D85.

**D109. The location service**

- **Decide:** where it runs and how it replicates; how it resolves a node authority, a deploy authority and a moved object; which component asks it during a bind; how it picks an instance; what happens to sessions when an instance fails; shard locations and their leases; partitions; moving a deploy's authority to a successor deploy.
- **Why open:** [0004](../decisions/0004-network-transparency-and-failure.md), rule 5 names the service, and [0027](../decisions/0027-applications-extend-the-system.md), rule 5 and [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 5 give it jobs. Both list its protocol as new work (Consequences), and no decision says which component asks it ([key flows §5](key-flows.md#5-binding-and-calling-across-nodes)).
- **Options:** none named for the protocol. Process managers lease instances and sharding managers lease their shards; both registrations hold ([0027](../decisions/0027-applications-extend-the-system.md), rule 5; [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 5).
- **Blocks:** C50. **Depends on:** D37, D87.

**D110. What a publisher is, and who mints an application's interfaces and types** (blocking)

- **Decide:** what a publisher is; which authority mints an application's interface and type objects; which publisher may register which prefix, and how ownership is checked; whether names are unique in a realm; where `aspis.` is enforced; registrants outside the app platform.
- **Why open:** accepted records conflict: [What a publisher is](#what-a-publisher-is-and-who-mints-an-applications-interfaces-and-types). Cedar actions are keyed by name ([0019](../decisions/0019-authzen-decision-protocol.md), rule 4) while binds use IDs ([0027](../decisions/0027-applications-extend-the-system.md), rule 7), so names must not collide either.
- **Options:** listed with the conflict.
- **Blocks:** C51, C54. **Depends on:** D37.

**D111. Catalog registration and its lifecycle**

- **Decide:** the interfaces for registering types, interfaces and published objects; what a refused registration does to a release; whether each release re-registers, and whether replacement is atomic; what happens to withdrawn versions and their definitions; whether a release may drop a major inside its support period; whether a type has one manager or several.
- **Why open:** [0027](../decisions/0027-applications-extend-the-system.md) lists interfaces for registering types as new work (Consequences), and rule 6 registers a release's exports when it goes live. In rule 4 the type object names "the type's manager", while [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 2 lists each type "with its managers" (see [Conflicts](#conflicts-between-accepted-adrs)).
- **Options:** none named for the interfaces. For managers: one manager per type, whose instances the location service finds.
- **Blocks:** C51. **Depends on:** D28, D110.

**D112. The catalog branch, sequence numbers and delay targets**

- **Decide:** the keys and records for interfaces, versions, types, published objects, mounts, defaults and service plans; how definitions are made canonical before hashing; who assigns sequence numbers, so that a watcher can resume on another replica; how long history is kept; how quickly changes reach replicas and watchers.
- **Why open:** [0028](../decisions/0028-discovery-and-realm-catalog.md), rules 4 and 6 fix the branch and the 64-bit sequence numbers, and leave the delay targets to the design session.
- **Options:** one realm-wide sequencer in the catalog service; sequences per replica, anchored to epochs.
- **Blocks:** C51. **Depends on:** D61, D68.

**D113. Catalog queries, defaults and resolution**

- **Decide:** fixed kinds of query or a small query language, with their ABNF text forms; how many default providers an interface major may have in a realm; the error when several providers exist and none is the default; minor-version mismatches; what happens to pinned releases when a provider is revoked.
- **Why open:** [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 7 says what a query can select and that queries have text forms; [0027](../decisions/0027-applications-extend-the-system.md), rules 8 and 9 add default providers and resolution when a release is made.
- **Options:** fixed kinds of query; a small query language ([discovery note §8](extensibility-and-discovery.md#8-open-questions)).
- **Blocks:** C51. **Depends on:** D12.

**D114. The catalog's own entries, routing to replicas, and where definitions live**

- **Decide:** how ASPIS's own interfaces and types, and the catalog itself, get entries, and who their publisher is; how a bind to the catalog's reserved ID reaches the local replica while registrations reach the realm's service; how another realm's catalog is reached; which manager holds interface and type objects; where IDL, ABNF, Cedar schema, OpenAPI and test vectors are stored; the test-vector format for third parties.
- **Why open:** the catalog's ID is the same on every node ([0001](../decisions/0001-object-identifiers.md), rule 7; [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 3), yet a realm can query another realm's catalog (rule 11; see [Conflicts](#conflicts-between-accepted-adrs)). Interface objects hold their definitions ([0014](../decisions/0014-versioned-object-apis.md), rule 2).
- **Options:** entries seeded at realm creation, or built into replicas; reads to the local replica, writes forwarded to the realm's catalog service, and other realms reached through the endpoint in their federation metadata.
- **Blocks:** C51. **Depends on:** D35, D79.

**D115. Support periods and deprecation**

- **Decide:** the support period in the API policy, the kernel interface library's included; where an app declares a major version's period; whether the catalog enforces it; what end of support means, and how clients learn of it; the realm's deprecation policy for realm functions.
- **Why open:** [0014](../decisions/0014-versioned-object-apis.md), rule 7 leaves the period to the API policy, and [0027](../decisions/0027-applications-extend-the-system.md), rules 2 and 8 add declared periods and a realm deprecation policy.
- **Options:** none named.
- **Blocks:** C51, C79. **Depends on:** D111.

**D116. HTTPS bindings, OpenAPI and the JSON mapping**

- **Decide:** how the IDL compiler generates HTTPS bindings and OpenAPI 3.2 descriptions; where generated bindings run; how 64-bit integers and 32-octet IDs map to I-JSON; how errors map.
- **Why open:** [0027](../decisions/0027-applications-extend-the-system.md), rule 10 requires the generator and [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 10 lists the APIs at the edge. Neither gives the mapping.
- **Options:** 64-bit values as decimal strings; IDs in their ABNF text form; bindings behind a route, or in a realm gateway.
- **Blocks:** C52. **Depends on:** D26, D28.

**D117. The edge: transport, the certificate list and sender constraint**

- **Decide:** TLS over TCP and IPv4 for browsers; HTTP/3 at the edge; classical key exchange and Web PKI key types; which further endpoints hold Web PKI certificates; how external HTTPS clients prove possession of their tokens.
- **Why open:** [0020](../decisions/0020-realm-certificate-authority.md), rule 11 says nothing of the App API's HTTPS binding and `git push` ([0026](../decisions/0026-realm-as-cloud-provider.md), rule 12), generated HTTPS bindings ([0027](../decisions/0027-applications-extend-the-system.md), rule 10) or `/.well-known/api-catalog` ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 10) (see [Conflicts](#conflicts-between-accepted-adrs)). Every token is sender-constrained ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 3).
- **Options:** DPoP; RFC 8705 mutual TLS; WIMSE's proof-token HTTP binding; `X25519MLKEM768` with an X25519 fallback; ECDSA P-256 Web PKI certificates.
- **Blocks:** C52. **Depends on:** D65, D66.

**D118. DNS, ACME, outbound Web PKI trust, and hosts that aren't nodes**

- **Decide:** who runs the ACME client, and with which challenge; who serves DNS for the realm and its routes; how a node becomes an edge node; the trust store for outbound Web PKI connections; how hosts that aren't ASPIS nodes get certificates for realm names; when the edge adopts Merkle Tree Certificates.
- **Why open:** [0020](../decisions/0020-realm-certificate-authority.md), rule 11 obtains Web PKI certificates with ACME without naming the client ([realm view §4](realm-containers.md#4-the-https-edge)), and ASPIS clients validate realm names only through the realm's root ([0020](../decisions/0020-realm-certificate-authority.md), rule 11).
- **Options:** HTTP-01, TLS-ALPN-01 or DNS-01; DNS served by the realm or by a provider; a CA bundle as a versioned realm object; ACME or EST for other hosts ([CA note §8](realm-certificate-authority.md#8-open-questions)).
- **Blocks:** C52. **Depends on:** D117.

**D119. The router**

- **Decide:** TCP and UDP routes; HTTP/3; whether the router starts traces; how a connection is framed to its instance, and what client metadata the app sees; internal-route addressing, and the form of the network server's vouching; how the router, as an enforcement point, passes the PDP's check that it manages what it describes ([0019](../decisions/0019-authzen-decision-protocol.md), rule 5); how the router learns which instances are ready; who requests route certificates.
- **Why open:** [0026](../decisions/0026-realm-as-cloud-provider.md), rule 6 fixes the router's role, including as the enforcement point for internal routes. The [twelve-factor note §7.1](twelve-factor-apps.md#71-deploying-a-change) has the scheduler tell the router about ready instances, where availability leases could serve instead ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 5; [key flows §9](key-flows.md#9-deploying-a-change)). That question is decided with the location service (C50), so that the router (C56) inherits the answer ([build plan](build-plan.md#m7-workloads-and-discovery)).
- **Options:** one QUIC stream per connection; PROXY protocol v2; `Forwarded` headers; internal hostnames under a realm subdomain; a watch on the location service.
- **Blocks:** C50, C56. **Depends on:** D109, D117.

**D120. Watching over HTTPS, and who sees the api-catalog**

- **Decide:** how HTTPS clients watch the catalog and live tails; whether `/.well-known/api-catalog` is filtered per caller or lists only the APIs exported to the public.
- **Why open:** [0028](../decisions/0028-discovery-and-realm-catalog.md) lists the HTTPS watch as new work (Consequences). Rule 8 shows outside principals only what is exported to them, while rule 10's endpoint is normally fetched anonymously (see [Conflicts](#conflicts-between-accepted-adrs)).
- **Options:** server-sent events, WebSockets or long polling ([discovery note §8](extensibility-and-discovery.md#8-open-questions)); a Linkset of public APIs only, with authenticated callers using the catalog's HTTPS binding.
- **Blocks:** C53. **Depends on:** D116.

## M8. Twelve-factor apps on a multi-node realm

Chunks C54 to C58 and C80 ([build plan](build-plan.md#m8-twelve-factor-apps-on-a-multi-node-realm)).

**D121. Control-plane state**

- **Decide:** where desired state lives; how it is replicated, deploy authorities' counters included; how it behaves in a partition.
- **Why open:** [0026](../decisions/0026-realm-as-cloud-provider.md) makes this a design-session item (Consequences), and [0027](../decisions/0027-applications-extend-the-system.md), rule 5 has the control plane hold each deploy authority's counter.
- **Options:** none named for the store. The partition behavior is stated: changes fail visibly, and running instances keep running ([twelve-factor note §6](twelve-factor-apps.md#6-conflicts-and-resolutions), item 10).
- **Blocks:** C54. **Depends on:** D87, D88.

**D122. The manifest's file name and schema**

- **Decide:** the file name; the schema and its ABNF (process types, base, bindings, release task, exports); where per-type settings live (the singleton flag, the stop deadline, the default size).
- **Why open:** [0025](../decisions/0025-twelve-factor-app-contract.md), rule 2 fixes TOML 1.1 and a Procfile as the minimum, and [0027](../decisions/0027-applications-extend-the-system.md), rule 6 adds exports.
- **Options:** a TOML superset of the buildpacks project descriptor ([twelve-factor note §9](twelve-factor-apps.md#9-open-questions)).
- **Blocks:** C54. **Depends on:** D12.

**D123. The App API, the command-line tool and the OpenTofu provider**

- **Decide:** the App API's resources and methods; its declarative semantics (desired state, preconditions, drift); the command-line tool's name, where it runs and how it logs in; the OpenTofu provider's name and where it is published.
- **Why open:** [0026](../decisions/0026-realm-as-cloud-provider.md), rule 12 makes the API resource-oriented and "declarative enough to back an OpenTofu provider", and names no resources.
- **Options:** resources modeled on Heroku's Platform API; versions per resource, for optimistic concurrency; a cross-platform client that uses the HTTPS binding and the device grant. The provider is built and tested with OpenTofu (`tofu`), never Terraform.
- **Blocks:** C54, C58. **Depends on:** D116.

**D124. Sizes, quotas, metering and failure domains**

- **Decide:** the named sizes and their budgets; quota units per owner, and where they are kept; metering records; how nodes declare failure domains.
- **Why open:** [0026](../decisions/0026-realm-as-cloud-provider.md), rule 5 requires all four without defining them.
- **Options:** limits per owner on instances, memory and CPU; metering as signed records or as log events; a registry attribute per node for its rack, site or zone.
- **Blocks:** C54. **Depends on:** D24.

**D125. Rollout, release tasks, restarts and retention**

- **Decide:** surge size, what to wait for, and whether to halt or roll back when new instances crash; the release task's deadline, principal, retries and logging; the boot deadline, restart backoff, and whether liveness checks exist; how long logs, releases and builds are kept, and how unreferenced builds are collected.
- **Why open:** [0026](../decisions/0026-realm-as-cloud-provider.md), rules 4 and 5 fix the four rollout steps and restarts with backoff, not their parameters, and retention is open ([twelve-factor note §9](twelve-factor-apps.md#9-open-questions)).
- **Options:** one new instance per type at a time; never fewer instances than the formation; exponential backoff with a cap.
- **Blocks:** C54. **Depends on:** D122.

**D126. Who checks provenance, and who registers exports**

- **Decide:** which platform service asks the PDP whether a build's provenance meets the deploy's policy, and which registers a release's exports in the catalog, at which step of the rollout.
- **Why open:** [0026](../decisions/0026-realm-as-cloud-provider.md), rule 4 and [0027](../decisions/0027-applications-extend-the-system.md), rule 6 say what happens, not which service does it ([key flows §9](key-flows.md#9-deploying-a-change)). Each platform service asks its node's PDP ([0026](../decisions/0026-realm-as-cloud-provider.md), rule 1).
- **Options:** none named. The key flows draw the App API asking, and leave it marked open.
- **Blocks:** C54, C55. **Depends on:** D111, D125.

**D127. Buildpacks, the `os` value and the ASPIS base**

- **Decide:** all of Platform API 0.15, or only Buildpack API 0.12; the `os` value in buildpack targets and OCI platforms; who publishes bases, how manifests name them, and whether a base can be patched without a rebuild; buildpacks that target ASPIS.
- **Why open:** [0026](../decisions/0026-realm-as-cloud-provider.md), rule 3 adopts Buildpack API 0.12, and its Consequences say ASPIS needs a base, and buildpacks that target it, before apps can build.
- **Options:** versioned base objects that the realm publishes; rebasing, as Cloud Native Buildpacks do.
- **Blocks:** C55. **Depends on:** D106.

**D128. SBOM, provenance and the OCI layout of app builds**

- **Decide:** the SBOM and provenance formats, and their signatures for verifiers outside ASPIS; the OCI layout of a build (media types, layers, the base referenced or embedded).
- **Why open:** [0026](../decisions/0026-realm-as-cloud-provider.md), rule 3 signs provenance with the builder's workload identity, a composite, and exchanges builds as OCI artifacts. Verifiers outside ASPIS may not check composites, a problem [0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 5 solves for tokens.
- **Options:** an in-toto statement with the SLSA predicate in DSSE; an added ML-DSA-65 or classical signature on export. The SBOM format is CycloneDX, for app builds as for ASPIS's own images ([0038](../decisions/0038-reproducible-builds-and-provenance.md), rule 2).
- **Blocks:** C55. **Depends on:** D05, D86.
- **Settled in part:** the SBOM format, by [0038](../decisions/0038-reproducible-builds-and-provenance.md), accepted 2026-11-25: CycloneDX is ASPIS's only SBOM format (rule 2). What remains is the OCI layout of app builds and the signatures that verifiers outside ASPIS can check (Consequences).

**D129. Code intake and the realm mirror**

- **Decide:** the transport and authentication for `git push` at the edge; build-time credentials for private codebases and registries; what the realm mirror is and who runs it; the per-node build cache.
- **Why open:** [0026](../decisions/0026-realm-as-cloud-provider.md), rules 3 and 12 name `git push` and the mirror without defining them, and nodes cache builds freely (rule 4).
- **Options:** Git smart HTTP with an OAuth token; build-time bindings from the secret store; the mirror as a realm service, as an app, or provided by the operator.
- **Blocks:** C55. **Depends on:** D117.

**D130. The first services, standard interfaces and stateful services**

- **Decide:** which services the realm offers first; whether ASPIS defines `aspis.sql`, `aspis.kv` and `aspis.queue`; how a storage binding is provisioned, sized and charged against quotas; how a stateful service replicates and fails over beyond one singleton instance.
- **Why open:** [0032](../decisions/0032-stateful-services-run-as-platform-deploys.md) settles that stateful services such as databases run as platform deploys, with their data behind storage bindings and a singleton process type where one instance must run (rules 1 to 3). It leaves storage bindings' provisioning, sizing and charging, and replication beyond one singleton instance, to be designed (Consequences). The rest is open ([twelve-factor note §9](twelve-factor-apps.md#9-open-questions); [discovery note §8](extensibility-and-discovery.md#8-open-questions)).
- **Options:** for the first services, storage on the single-level store, a queue, and PostgreSQL run as an app. None named for provisioning or replication.
- **Blocks:** C57. **Depends on:** D111, D124.

**D131. The secret store, the broker protocol and binding views**

- **Decide:** the secret store's encryption envelope, storage and replication, and who starts a rotation; the Open Service Broker wire protocol and how brokers authenticate; how broker types and plans appear in the catalog; what a POSIX app sees for a native binding or a storage binding.
- **Why open:** [0026](../decisions/0026-realm-as-cloud-provider.md), rules 7 and 8 fix the roles, [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 3 moves the broker's catalog into the realm's, and [0025](../decisions/0025-twelve-factor-app-contract.md), rule 5 has credentials rotate in place.
- **Options:** a data key per secret, wrapped by a key-service key; OSB v2.17 over HTTPS, with broker credentials in the secret store; a binding directory holding `type`, `provider` and `object-id`.
- **Blocks:** C57. **Depends on:** D59, D95, D107.

**D132. gRPC and OTLP as protocols with their own notation**

- **Decide:** whether gRPC and OTLP join the protocols that keep their own normative notation.
- **Why open:** [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 2 exempts only TLS, QUIC, X.509, PKCS #10 and CMS. [0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 8 serves the Workload API over gRPC, and [0026](../decisions/0026-realm-as-cloud-provider.md), rule 9 drains logs over OTLP (see [Conflicts](#conflicts-between-accepted-adrs)).
- **Options:** a small change to 0013 rule 2 that adds them; reading 0013 rule 2 as covering only what ASPIS defines.
- **Blocks:** C58, C60. **Depends on:** none.

**D133. Log mapping and one-off processes**

- **Decide:** OTLP transport and attribute names; RFC 5424 structured data; line limits, and output that isn't UTF-8; which principal a `run` process uses, and which release it starts from; how a remote command-line tool attaches.
- **Why open:** [0026](../decisions/0026-realm-as-cloud-provider.md), rule 9 names the destinations, not the mapping. Rule 10 runs a one-off process with "the deploy's config, bindings and identity", while rule 11 gives each process type its own principal, and a `run` has no type (see [Conflicts](#conflicts-between-accepted-adrs)).
- **Options:** OTLP over HTTP with `service.name` and `service.instance.id`; a `run` principal per deploy; the principal of a type the operator names; an exchanged token with the operator as `act`.
- **Blocks:** C58. **Depends on:** D90, D120, D132.

**D134. Realm backup and disaster recovery**

- **Decide:** backups of the authorization service, the registry, the control plane, the secret store, the provider's keys and the storage of stateful deploys ([0032](../decisions/0032-stateful-services-run-as-platform-deploys.md), Consequences); the root key's custody; how a restored authorization service is kept from signing a second, different root for an epoch it has already used.
- **Why open:** epochs, not clocks, order the tree's history ([0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 4), so a restore that reuses an epoch forks it. No decision covers backup.
- **Options:** none named.
- **Blocks:** C80. **Depends on:** D58, D69, D121.

## M9. Federation and extension

Chunks C59 to C62, C67 and C82 ([build plan](build-plan.md#m9-federation-and-extension)).

**D135. The ASPIS OpenID Federation profile**

- **Decide:** the metadata of ASPIS-native entity types and its ABNF (root certificate, CSRs and certificates, RPC endpoints, root distribution, catalog endpoint); how the realm chooses among trust chains; trust marks and defaults per topology; workload entity identifiers and statement lifetimes; key rollover per topology.
- **Why open:** [0017](../decisions/0017-openid-federation-membership.md), rule 8 says what the metadata names, and [0017](../decisions/0017-openid-federation-membership.md) calls for a profile (Consequences; [federation note §6](openid-federation.md#6-open-questions)).
- **Options:** none named. HTTPS entity identifiers are decided ([0017](../decisions/0017-openid-federation-membership.md), rule 1).
- **Blocks:** C59, C62. **Depends on:** D12.

**D136. The realm as an intermediate for its workloads**

- **Decide:** what superiors' constraints must allow (path length, naming, entity types) for chains from a workload through the realm to an anchor; constraints on the realm's own statements about workloads; who signs a workload's Entity Configuration and holds its federation key; whether to offer explicit registration, a resolve endpoint or trust marks the realm issues.
- **Why open:** [0017](../decisions/0017-openid-federation-membership.md), rule 3 makes the realm an intermediate for its workloads, and rule 7 allows a second entity identifier, but nothing says what superiors must permit.
- **Options:** require a path length of 1 or more when joining; put workloads under a second entity identifier; workloads sign through a key-service capability.
- **Blocks:** C59. **Depends on:** D135.

**D137. Identity at the edge**

- **Decide:** classical algorithms for external audiences; SPIFFE bundle profiles; whether to propose composite JOSE algorithms for SVIDs; how CI issuers without federation chains are trusted; whether the provider offers login to hosted apps' users; which edge services run as twelve-factor apps.
- **Why open:** [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 6 and [0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rules 5, 6 and 9 set the frame. [0026](../decisions/0026-realm-as-cloud-provider.md), rule 12 has CI systems exchange their own tokens, while [0017](../decisions/0017-openid-federation-membership.md), rule 4 accepts an external identity only through a trust chain (see [Conflicts](#conflicts-between-accepted-adrs)). The rest is open ([workload identity note §7](workload-identity.md#7-open-questions); [twelve-factor note §9](twelve-factor-apps.md#9-open-questions)).
- **Options:** RS256 or ES256, per audience; the `https_web` profile only, or `https_spiffe` too; the realm as trust anchor, issuing statements for configured CI issuers; an issuer with a pinned JWKS under policy, which would need a change to 0017 rule 4.
- **Blocks:** C59. **Depends on:** D89.

**D138. PKI publication**

- **Decide:** the URLs and media types for CSRs, `caIssuers` bundles, the CRL, the root certificate and the certificate policy.
- **Why open:** [0020](../decisions/0020-realm-certificate-authority.md), rules 7 to 9 require publication without paths.
- **Options:** `/.well-known/` paths under the entity identifier; `application/pkcs10`, `application/pkcs7-mime`, `application/pkix-crl` and `application/pkix-cert`.
- **Blocks:** C59. **Depends on:** D80.

**D139. The SPIFFE Workload Endpoint**

- **Decide:** whether the endpoint runs per node or per POSIX instance; what authority it holds over other processes' SVIDs; which gRPC stack; whether native programs are offered SPIFFE's API too.
- **Why open:** [0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 8 puts it in the POSIX personality and has it identify callers through the POSIX process server. The rest is open ([node view §3](node-components.md#3-the-posix-personality); [workload identity note §7](workload-identity.md#7-open-questions)).
- **Options:** one endpoint per POSIX instance; identity capabilities handed to it by the process manager.
- **Blocks:** C60. **Depends on:** D99, D107, D132.

**D140. AuthZEN resource search**

- **Decide:** which component answers resource search, and how its index for each principal works with batched `discover` decisions.
- **Why open:** the catalog's index of published objects is the index resource search was waiting for ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 8; [0019](../decisions/0019-authzen-decision-protocol.md), rule 9), so search covers published objects only. Who answers is open.
- **Options:** none named.
- **Blocks:** C61. **Depends on:** D112.

**D141. Trust between realms**

- **Decide:** CRLs from intermediates, if a cross-signer demands them; how another realm's signed roots are distributed, and how stale they may be for handshake checks; whether managers accept another realm's tokens directly or require an exchange; how catalog entries are exported and authenticated; who runs trust anchors for ASPIS-native federations.
- **Why open:** [0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 8 and [0020](../decisions/0020-realm-certificate-authority.md), rule 10 check a peer against its own realm's roots, and [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 11 lets realms query each other's catalogs. The mechanics are open ([CA note §8](realm-certificate-authority.md#8-open-questions); [security tokens note §4.6](security-tokens.md#46-federation)).
- **Options:** subscribing to a peer's roots over RPC; always exchanging at the target realm's provider; ASPIS shipping trust-anchor software; a realm acting as a trust anchor. An online cross-certification CA would need a change to 0020 rule 1.
- **Blocks:** C62. **Depends on:** D135.

**D142. Assistive technology**

- **Decide:** the interface through which assistive technology reads the text on screen, in Display SVG and in dm.
- **Why open:** [0010](../decisions/0010-svg-core-primitive.md), rule 5 promises that any text on screen can be "read by assistive technology", and no interface exists for it.
- **Options:** none named.
- **Blocks:** C82. **Depends on:** D101, D103.

## MH. Hardware and hardening

Chunks C63 to C66, C77 to C79 and C81 ([build plan](build-plan.md#mh-hardware-and-hardening)).

**D143. The Pi 4: confirmations, firmware and drivers**

- **Decide:** whether the BCM2711 has an IOMMU, from its datasheet; whether the pftf firmware's GOP gives a linear framebuffer, on hardware; whether to reconfigure the firmware for device tree or take ACPI first; the Pi 4's drivers for SD and EMMC2, GENET Ethernet and USB through PCIe and the VL805.
- **Why open:** [0007](../decisions/0007-initial-hardware-targets.md) asks for the IOMMU check (Consequences) and puts device tree first (rule 3), but the pftf firmware defaults to ACPI and a 3 GB RAM limit ([pftf/RPi4](https://github.com/pftf/RPi4)).
- **Options:** reconfigure the firmware; bring ACPI (C65) first.
- **Blocks:** C63. **Depends on:** D43, D45.

**D144. Secure Boot and measured boot**

- **Decide:** how the image is signed; how measured boot works, and what it measures.
- **Why open:** [0006](../decisions/0006-uefi-boot-image.md) leaves both to later (Consequences). Later records fix parts of each. The stub checks `initfs.img` against a SHA-512 digest inside the signed `aspis.efi`, so a signature on `aspis.efi` covers the initial image too ([0040](../decisions/0040-the-stub-checks-the-initial-image.md), rules 1 and 2). Where a TPM exists, the stub extends PCR 9 with the image (rule 3), and the boot information reserves a record for the TPM event log ([0041](../decisions/0041-boot-abi.md), rule 3). A release's hashes are the known-good values ([0038](../decisions/0038-reproducible-builds-and-provenance.md), rule 5). How `aspis.efi` is signed, and the rest of what measured boot measures, are still open.
- **Options:** shim; ASPIS's own key; GRUB 2.14's shim loader protocol; TPM 2.0 ([0006](../decisions/0006-uefi-boot-image.md), Consequences).
- **Blocks:** C64, C77. **Depends on:** D05, D08, D58.

**D145. Kernel hardening**

- **Decide:** Spectre-class mitigations on the Cortex-A72; when W^X, PAN and PXN arrive; layout randomization for servers that start before the gate; whether the stub randomizes the kernel's placement, which [0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), rule 4 leaves to be decided with C78.
- **Why open:** no decision covers hardening. The kernel uses no randomness ([0021](../decisions/0021-entropy-before-keys.md), rule 3), so only the stub could randomize its placement, and servers that start before the gate get no randomness from the entropy service. D02 is settled: the kernel is position-independent and the stub relocates it, so the stub can choose its virtual base. To randomize it, the stub would use the firmware's seed for its own purpose, as [0021](../decisions/0021-entropy-before-keys.md), rule 3 allows. Until C78 the base is fixed ([0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), rules 2 to 4).
- **Options:** mitigations for branch-target injection and Spectre-BHB, with firmware workarounds on context switch; W^X and PAN from the first page tables (D14).
- **Blocks:** C78. **Depends on:** D02, D14.

**D146. Node software update and rollback**

- **Decide:** how `aspis.efi`, `initfs.img` and node servers are updated; how a failed boot rolls back; how the kernel interface library stays compatible; rolling upgrades of realm services across interface majors; how measurements change under measured boot.
- **Why open:** no decision says how updates are made or rolled back. [0014](../decisions/0014-versioned-object-apis.md), rules 6 and 7 let the raw ABI change under a versioned library whose majors have support periods. Accepted records now fix the layout and rule out one mechanism:
  - The ESP has two slots, `/aspis/a/` and `/aspis/b/`, each holding an `aspis.efi` and an `initfs.img`, with the menu in `/aspis/grub.cfg` and GRUB at `/EFI/BOOT/BOOTAA64.EFI`. Slot `b` stays empty until updates exist (C79). How a slot is chosen, and how a failed boot falls back, are left to this entry ([0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), rule 6).
  - `aspis.efi` embeds the initial image's digest, so the two are released and updated together, one slot at a time ([0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), Consequences; [0040](../decisions/0040-the-stub-checks-the-initial-image.md), Consequences).
  - Boot selection uses files on the ESP that GRUB and the stub can read, never UEFI variables ([0039](../decisions/0039-no-uefi-runtime-services.md), rule 5).
- **Options:** A/B boot entries through `grub.cfg`, choosing between the two slots by files on the ESP. UEFI `BootNext` is ruled out ([0039](../decisions/0039-no-uefi-runtime-services.md), rule 5).
- **Blocks:** C79. **Depends on:** D02, D29, D115, D144.

**D147. Cloud VM nodes**

- **Decide:** when VMs at a cloud provider can be nodes, given that they need ACPI, PCIe, NVMe, the cloud's NIC and the EL1 virtual timer, and usually have only a UART console; which cloud platform comes first.
- **Why open:** [0026](../decisions/0026-realm-as-cloud-provider.md), rule 1 lets realm nodes be VMs at a cloud provider, while [0007](../decisions/0007-initial-hardware-targets.md), rule 3 puts ACPI later (see [Conflicts](#conflicts-between-accepted-adrs)). Without a framebuffer the console stays on the UART ([0009](../decisions/0009-text-as-graphics-console.md), rule 2).
- **Options:** bring ACPI (C65) forward; keep cloud nodes until after C65.
- **Blocks:** C81, and decides how early C65 is needed. **Depends on:** D17, D43.

**D148. Later POSIX work**

- **Decide:** the Linux binary personality; a Wayland bridge; a two-phase protocol that makes `rename` atomic across nodes.
- **Why open:** [0012](../decisions/0012-posix-compatibility-layer.md), rule 2 defers Linux binaries to a later personality, and `rename` across nodes fails with `EXDEV` until a protocol exists ([POSIX note §4.16](posix-compatibility.md#416-unlink-while-open-links-and-rename)).
- **Options:** the Starnix model ([0012](../decisions/0012-posix-compatibility-layer.md), rule 2); client buffers as `<image>` elements, for Wayland ([POSIX note §4.21](posix-compatibility.md#421-graphics)).
- **Blocks:** C66. **Depends on:** D106.

**D149. Later features with no chunk yet**

- **Decide:** a declarative animation API; offering the catalog through an agent protocol; autoscaling formations; short-lived review deploys.
- **Why open:** [0010](../decisions/0010-svg-core-primitive.md), rule 3 promises animation "through a separate declarative API rather than SMIL". The others are open questions in the [discovery note §8](extensibility-and-discovery.md#8-open-questions) and the [twelve-factor note §9](twelve-factor-apps.md#9-open-questions).
- **Options:** none named.
- **Blocks:** no chunk yet. **Depends on:** none.

## Conflicts between accepted ADRs

Where accepted records disagree, the fix is a change to one of them, or a reading that a record writes down. Two of these conflicts block the build. The others can wait until the decision they belong to is made, and each names that decision.

### Names before the gate on a first boot

- **The texts.** [0001](../decisions/0001-object-identifiers.md), rule 3 makes a node's authority a hash of its genesis public key, and rule 4 reserves the sequence numbers below 2^16 for well-known objects "such as the node object and the node's root directory", which carry that authority. [0021](../decisions/0021-entropy-before-keys.md), rule 3 names every object that exists before the gate from that reserved range, and rule 5 mints the genesis key only after the gate, once a physical source has contributed and the generator has reseeded. On a first boot, then, no node authority exists before the gate.
- **The random field.** [0001](../decisions/0001-object-identifiers.md)'s ID layout fills an ID's 40 random bits with "CSPRNG output chosen when the ID is minted", and rule 5 relies on them to keep IDs distinct after a restore or clone, while rule 7 makes the IDs of objects under the reserved authority "identical on every node". [0021](../decisions/0021-entropy-before-keys.md) notes that 0001 "needs one more answer": what fills the random field of IDs that exist before the gate (Consequences).
- **Options.** The reserved ASPIS authority until the genesis key exists; a provisional authority, renamed later; mint the genesis key before naming any object under the node's authority, computing those IDs from the fixed reserved sequence numbers as soon as the key exists, so that nothing stores such an ID before the gate; a fixed or derived random field for well-known IDs.
- **Settled by:** D36, in the ID format specification or a change to 0001. It blocks C09, C19 and C25.

### What a publisher is, and who mints an application's interfaces and types

- **The texts.** [0014](../decisions/0014-versioned-object-apis.md), rule 2: an interface that isn't ASPIS's own "uses the authority of whoever defines it". [0027](../decisions/0027-applications-extend-the-system.md), rule 4: an application's type object is "minted under its own authority". Rule 5: objects an application creates are minted "under an authority the realm assigns to its deploy". Rule 7: "Cedar policy decides which publisher may register which prefix", and "Binding always uses IDs". [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 4 lays out registrations so that "everything one publisher registered shares a prefix", and revoking a publisher's branch withdraws its entries "together with its grants". No record defines a publisher.
- **Why it blocks.** If an application's interfaces and types take its deploy's authority, one interface has a different ID in staging, in production and in every realm, so compiled clients can't embed it. The discovery note reads a publisher both as a minting authority ([discovery note §5.3](extensibility-and-discovery.md#53-signed-registrations-soft-availability)) and as an organization that proves it owns a prefix ([discovery note §8](extensibility-and-discovery.md#8-open-questions)).
- **Options.** The deploy's minting authority; the app's owning principal or group; a service principal; an organization identified by its OpenID Federation entity identifier; a publisher authority that stays the same across deploys and realms. Because the registry refuses an authority it already knows ([0001](../decisions/0001-object-identifiers.md), rule 6), an authority that stays the same across realms must be derived deterministically from a globally unique identity, such as an entity identifier; that rules out a random authority registered with the registry, or the registry as the only minter (D37).
- **Settled by:** D110, with D37 for the derivation and D61 for revoking a publisher's grants. It blocks C51 and C54.

### Conflicts that don't block the build

- **Who owns uid numbers.** [0012](../decisions/0012-posix-compatibility-layer.md), rule 6: "The realm registry assigns uids and gids to principals". Rule 3: each POSIX instance is a process server "with its own pid space, uid/gid map". Options: realm-wide numbers that each instance's map projects; numbers per instance. Settled by D97.
- **`fork` and credentials.** [0012](../decisions/0012-posix-compatibility-layer.md), rule 4: `fork` makes "a copy of the capability table". [0025](../decisions/0025-twelve-factor-app-contract.md), rule 5: credentials are "never inherited by child processes unless passed explicitly". Options: `fork` leaves credential capabilities behind unless they are passed; 0025 rule 5 gives way. Settled by D95.
- **One manager or several per type.** [0027](../decisions/0027-applications-extend-the-system.md), rule 4: "The type object names the type's manager". [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 2: "every type, with its managers and interfaces". Options: one manager, whose instances the location service finds; several managers. Settled by D111.
- **Which principal a one-off process uses.** [0026](../decisions/0026-realm-as-cloud-provider.md), rule 10 runs it with "the deploy's config, bindings and identity". Rule 11 gives each process type its own principal, and a `run` has no type. Options: a `run` principal per deploy; the principal of a type the operator names; either with the operator as `act`. Settled by D133.
- **Proofs attached to tokens.** [0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 5: a client "may also attach a proof and a signed root to its token". [0019](../decisions/0019-authzen-decision-protocol.md), rule 8 removed the grant keys tokens named, so nothing says what such a proof covers, or whether tokens still carry an issue epoch. Options: keep attached proofs only for grants checked against another realm's roots; drop the issue epoch unless the profile needs it. Settled by D85.
- **IDs for kernel objects.** [0001](../decisions/0001-object-identifiers.md)'s Context names processes, threads and endpoints among the objects IDs name. Kernel objects are reached by capability ([0002](../decisions/0002-capability-security-model.md), rule 1), and the kernel uses no randomness ([0021](../decisions/0021-entropy-before-keys.md), rule 3), so it can't mint their IDs. Options: the user-space server that creates the object mints its ID; IDs for only some threads and endpoints, which needs a change to 0001. Settled by D16.
- **The kernel's interfaces and ABNF.** [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 2 puts "every RPC and IPC call" in generated ABNF. [0014](../decisions/0014-versioned-object-apis.md), rule 6 has the raw system-call ABI "change underneath" the kernel interface library. Options: define the library's interfaces in the IDL, and treat the raw ABI as no IPC call, unpublished. Settled by D29.
- **The font's license.** [0009](../decisions/0009-text-as-graphics-console.md), rule 3 shares one OpenType family between the kernel and the SVG layer. [0008](../decisions/0008-mpl-2.0-license.md), rule 4 admits only permissive licenses and MPL-2.0, which a font under a font license would break. Options: a family under an admitted license; an amendment to 0008 rule 4. Settled by D06: [0034](../decisions/0034-noto-fonts-under-ofl.md), accepted 2026-11-25, adopts fonts under OFL-1.1 (rule 2), and [0008](../decisions/0008-mpl-2.0-license.md), rule 4 admits OFL-1.1 for fonts and the data derived from them, never for code. The conflict is closed.
- **An entropy service that "never blocks again".** [0021](../decisions/0021-entropy-before-keys.md), rule 2: once the gate opens, "the service never blocks again". Rule 5 makes requests for long-lived keys wait without a healthy physical source, and rule 9 reseeds "before giving any further output" after a restore. Options: "never blocks" covers ordinary requests, requests with prediction resistance wait by design, and output after a restore pauses only for the reseed. Settled by D46.
- **Tokens on remote PDP requests.** [0019](../decisions/0019-authzen-decision-protocol.md), rule 6: remote requests travel "carrying the enforcement point's workload token". [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 1: calls go through a session "with no token per call". Options: the remote enforcement point binds to the PDP once with its token, then uses the session. Settled by D74.
- **Reaching `//` from a confined process.** [0012](../decisions/0012-posix-compatibility-layer.md), rule 5: "`//` is the network root". [0025](../decisions/0025-twelve-factor-app-contract.md), rule 3: a process's namespace "holds only four things". Options: `//` reached only through a capability, which the default per-node POSIX instance's root includes, with app instances reaching realm names only through bindings. Settled by D52.
- **The app's namespace and the platform's variables.** [0025](../decisions/0025-twelve-factor-app-contract.md), rule 3's four things leave out the Workload Endpoint's socket ([0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 8) and the entropy devices ([0021](../decisions/0021-entropy-before-keys.md), rule 10). Rule 4 says "Every other name belongs to the deploy", yet rule 6 sets `TMPDIR` and `HOME`. Options: add `TMPDIR` and `HOME` to the documented set; list platform services as capabilities outside the namespace. Settled by D107.
- **Workload certificates for unmodified programs.** [0020](../decisions/0020-realm-certificate-authority.md), rule 4 certifies only workloads "that need mutual TLS with parties outside ASPIS". [0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 8 serves the SPIFFE Workload API, which hands X.509-SVIDs to any program that asks. Options: Cedar decides per principal, and the endpoint serves an X.509-SVID only where policy allows a workload certificate. Settled by D108.
- **Federation keys for topologies joined later.** [0021](../decisions/0021-entropy-before-keys.md), rule 6: the ceremony mints "its federation keys". [0017](../decisions/0017-openid-federation-membership.md), rules 6 and 7 have keys per class of topology, and per entity identifier, and topologies can be joined after the ceremony. Options: mint later keys under 0021 rule 5 on a qualifying node, in a later ceremony where policy requires one. Settled by D58.
- **One catalog ID, many realms.** [0001](../decisions/0001-object-identifiers.md), rule 7 and [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 3 give the catalog one ID under the reserved authority, the same on every node. [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 11: "A realm can query another realm's catalog." Options: reads go to the local replica, writes are forwarded to the realm's catalog service, and another realm's catalog is reached through the endpoint in its federation metadata. Settled by D114.
- **Authorized discovery and the public api-catalog.** [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 8: principals from outside the realm "see only the entries exported to them". Rule 10 serves `/.well-known/api-catalog`, which clients normally fetch anonymously. Options: the Linkset lists only APIs exported to the public, and authenticated callers use the catalog's HTTPS binding. Settled by D120.
- **Element IDs in input events.** [0010](../decisions/0010-svg-core-primitive.md), rule 9 tags each event "with the ID of the element hit", but SVG elements aren't objects with [0001](../decisions/0001-object-identifiers.md) IDs. Options: the element's handle in the client's document, from the DOM protocol. Settled by D101.
- **CI issuers without federation chains.** [0026](../decisions/0026-realm-as-cloud-provider.md), rule 12: "CI systems exchange their own OIDC tokens at the edge". [0017](../decisions/0017-openid-federation-membership.md), rule 4 accepts an external identity only through "a valid trust chain to a trust anchor the realm accepts". Options: the realm acts as trust anchor and issues statements for configured CI issuers; only issuers that take part in federation; an issuer with a pinned JWKS, which needs a change to 0017 rule 4. Settled by D137.
- **Protocols with their own notation.** [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 2: only "TLS, QUIC, X.509, PKCS #10 and CMS keep their own normative notations". [0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 8 uses gRPC, and [0026](../decisions/0026-realm-as-cloud-provider.md), rule 9 OTLP. Options: add them to the list; read 0013 rule 2 as covering only what ASPIS defines. Settled by D132.
- **Edge endpoints without a certificate rule.** [0020](../decisions/0020-realm-certificate-authority.md), rule 11 lists the endpoints that also hold Web PKI certificates. The App API's HTTPS binding and `git push` ([0026](../decisions/0026-realm-as-cloud-provider.md), rule 12), generated HTTPS bindings ([0027](../decisions/0027-applications-extend-the-system.md), rule 10) and `/.well-known/api-catalog` ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 10) are left out. Options: extend the list in 0020 rule 11, as was done for app routes. Settled by D117.
- **Cloud VM nodes and "ACPI later".** [0026](../decisions/0026-realm-as-cloud-provider.md), rule 1 pools nodes "whether those nodes are bare metal or VMs at a cloud provider". [0007](../decisions/0007-initial-hardware-targets.md), rule 3: "Device tree first; ACPI later". Cloud VMs of the Graviton class need ACPI. Options: bring ACPI forward; keep cloud nodes until after ACPI. Settled by D147.
- **Records that didn't yet say what later records decided.** [0019](../decisions/0019-authzen-decision-protocol.md), rules 1 and 3 moved the check at bind into the PDP, but [0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 5 still had a manager check grants against its replica. [0001](../decisions/0001-object-identifiers.md) defined the authority as the "UUID of the node that minted the ID", while [0017](../decisions/0017-openid-federation-membership.md), rule 5, [0026](../decisions/0026-realm-as-cloud-provider.md), rule 11 and [0027](../decisions/0027-applications-extend-the-system.md), rule 5 add authorities that aren't nodes. [0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 5 signs tokens for peers outside ASPIS with ML-DSA-65 where the peer accepts it, while [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 6 named only a separate classical key. [0008](../decisions/0008-mpl-2.0-license.md), rule 5 still left the documentation license to a separate decision, which [0033](../decisions/0033-contributions-docs-license-and-notice-years.md), rule 2 had made, and [0002](../decisions/0002-capability-security-model.md), rule 3 called a bind "opening" an object. On 2026-11-25 these records were edited in place to say what is in force, with no rule changed: [0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 5 has the node's decision point check grants at bind, [0001](../decisions/0001-object-identifiers.md) admits minting authorities that aren't nodes, [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 6 signs those tokens with ML-DSA-65 where the peer accepts it, [0008](../decisions/0008-mpl-2.0-license.md), rule 5 names CC BY 4.0, and [0002](../decisions/0002-capability-security-model.md), rule 3 calls the step a bind ([0014](../decisions/0014-versioned-object-apis.md), rule 4). The conflict is closed.

## Settled since the reading phase

The reading phase collected the open items and the conflicts between the documents. Since then, two new records, three of the project owner's decisions, the twelve records accepted on 2026-11-25, a check of every item against the accepted rules and a correction of the older design notes have settled some of them. Each is listed here with what settled it. Where only part was settled, the rest is in the decision named.

### By ADR 0030

[0030](../decisions/0030-bind-tokens-sessions-and-group-memberships.md) settled these. It is superseded now, and its rules are part of [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rules 1 and 2, and [0018](../decisions/0018-cedar-policy-language.md), rule 3.

- **What managers accept at bind.** This was a blocking conflict between [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 2, as first accepted ("Managers accept access tokens only"), and [0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 4 (proofs at bind take the WPT form, which binds to a WIT). Settled in [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 2: managers accept access tokens and WITs, never ID tokens, each with a WPT-form proof. How an access token travels with the proof, and what programs dm starts present, are in D85.
- **When a session ends.** [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 1: at token expiry, or when a new root revokes a branch holding one of the determining policies of [0019](../decisions/0019-authzen-decision-protocol.md), rule 8, in place of "a grant the token relies on". Channel binding and the cost of a bind are in D92.
- **Where group memberships come from.** [0018](../decisions/0018-cedar-policy-language.md), rule 3: from the principal tree alone, as [0019](../decisions/0019-authzen-decision-protocol.md), rule 5 has it. Recording them is in D62, and how the registry's changes reach the tree in D70.

### By ADR 0032

- **Where stateful services run.** [0032](../decisions/0032-stateful-services-run-as-platform-deploys.md), rule 1: stateful services such as databases run as platform deploys. Their data lives behind storage bindings (rule 2), and a process type that must run as one instance, such as a database's primary, is singleton (rule 3). It had been open whether a database runs on the platform or as a native service outside it, which [0027](../decisions/0027-applications-extend-the-system.md), rule 6 also allows; native services outside the platform remain possible for other kinds of service (Consequences). Storage bindings' provisioning and replication beyond one instance are in D130, backing up a stateful deploy's storage in D134, and singleton leases across partitions in D87.

### By the project owner's decisions

- **The founding node's first certificate.** The project owner decided that the founding node signs its initial certificate itself, with its genesis key. [0029](../decisions/0029-founding-node-self-signed-certificate.md) records the decision and spells it out. The project owner accepted it on 2026-11-25, which settles D78. [0020](../decisions/0020-realm-certificate-authority.md), rules 4 and 6 make the founding node's initial certificate the exception. What remains is designing the ceremony and the genesis state (D79).
- **ABNF and the command language.** The project owner decided that ABNF is a protocol specification metalanguage, never the language of a command interpreter people use. [0031](../decisions/0031-abnf-is-not-a-command-language.md) records the decision, and the project owner accepted it on 2026-11-25. [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 2 leaves the command interpreter's language, dm's included, out of the formats ABNF describes, and rule 5 makes the canonical text form of calls machine-facing only ([0031](../decisions/0031-abnf-is-not-a-command-language.md), rules 2 and 3). What remains is deciding on a native interpreter (D102), dm's design (D103), and any interpreter on the serial console before dm (D44).
- **Whose historical-keys endpoint marks a revoked workload's keys.** [0017](../decisions/0017-openid-federation-membership.md), rule 11 stands: revoking a workload marks its keys revoked in the realm's historical-keys endpoint. It had been questioned because OpenID Federation 1.1 lists an entity's own past keys at its own endpoint. It isn't open.

### By the records accepted on 2026-11-25

On 2026-11-25 the project owner accepted sixteen records. Each settled or narrowed these items:

- **[0029](../decisions/0029-founding-node-self-signed-certificate.md), the founding node's initial certificate.** Settles D78. [0020](../decisions/0020-realm-certificate-authority.md), rules 4 and 6 make the founding node's initial certificate the exception. The ceremony and the genesis state stay in D79.
- **[0031](../decisions/0031-abnf-is-not-a-command-language.md), ABNF is not a command language.** Settles D102's question whether to accept it. [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rules 2 and 5 keep the command interpreter's language out of ABNF and the canonical text form machine-facing. The native interpreter stays in D102, and dm's command language in D103.
- **[0033](../decisions/0033-contributions-docs-license-and-notice-years.md), contributions, the documentation license and notice years.** Settles D01: the DCO 1.1, CC BY 4.0 for documents, a REUSE check in CI and years as ranges. [0023](../decisions/0023-copyright-notices.md), rules 1 and 2 give the notices' years and tags to match. It also answers the two licensing questions [0008](../decisions/0008-mpl-2.0-license.md), rule 5 and [0023](../decisions/0023-copyright-notices.md)'s Consequences had left open. [0008](../decisions/0008-mpl-2.0-license.md), rule 5 was edited on 2026-11-25 to name CC BY 4.0.
- **[0034](../decisions/0034-noto-fonts-under-ofl.md), the fonts.** Settles D06: Noto Sans Mono and Noto Sans, with atlases 16, 24 and 32 pixels high. [0008](../decisions/0008-mpl-2.0-license.md), rule 4 admits OFL-1.1 for fonts only, which closes [the font's license](#conflicts-that-dont-block-the-build) conflict. Gives D100 its fonts.
- **[0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), the toolchain, image linkage and the ESP layout.** Settles D02: pinned stable Rust 1.100.0, the kernel as a position-independent ELF payload in the stub's `.kernel` section, `no_std` user space, and two ESP slots. [0006](../decisions/0006-uefi-boot-image.md), rule 3 names slot `a`'s paths, such as `/aspis/a/aspis.efi`. Narrows D146 (the slots), D60 (no std port yet), D145 (randomizing the kernel's placement is decided with C78), D14 (the kernel linked in the upper half) and D30 (`no_std` user space).
- **[0036](../decisions/0036-qemu-configuration-and-test-builds.md), QEMU and test builds.** Settles D03: QEMU 11.1.3, two configurations on every change and a nightly matrix, host and in-QEMU tests, and test builds marked by `--cfg aspis_test_build`, which alone carry the seed hook. Narrows D43 (every virtio device on PCIe).
- **[0037](../decisions/0037-initial-image-format-and-contents.md), the initial image.** Settles D04: an ASPIS format with page-aligned files and a SHA-512 digest for each, and contents that cover everything the root server starts before storage. Narrows D40 (the boot manifest is an entry of the image, its format still D40's), D13 (how the image becomes memory objects), D14 (64 KiB alignment until the page size is fixed), D43 (the drivers the image carries), D11, D30 and D32.
- **[0038](../decisions/0038-reproducible-builds-and-provenance.md), reproducible builds and provenance.** Settles D05: bit-for-bit reproducible images, CycloneDX 1.7 SBOMs, SLSA 1.2 provenance and Sigstore signing. Settles D128's SBOM format, CycloneDX for app builds too, so D128 narrows to the OCI layout and signatures for outside verifiers. Narrows D144 (a release's hashes are the known-good values).
- **[0039](../decisions/0039-no-uefi-runtime-services.md), no UEFI runtime services.** Settles D07: reset and power-off through PSCI, and boot selection by files on the ESP, not UEFI variables. Narrows D56 (runtime services ruled out), D146 (UEFI `BootNext` ruled out) and D77 (no time from firmware).
- **[0040](../decisions/0040-the-stub-checks-the-initial-image.md), the stub checks the initial image.** Settles D08: a SHA-512 digest embedded in the signed `aspis.efi`, and a PCR 9 measurement where a TPM exists. Narrows D144 and D146 (the two images are updated together).
- **[0041](../decisions/0041-boot-abi.md), the boot ABI.** Settles D09: the kernel's entry state, tagged boot-information records, the kernel-argument grammar and the order the stub searches for the initial image. Narrows D42 (the seed comes in a page of its own, which the kernel never reads), D144 (a record reserved for the TPM event log), D11, D32, D40 and D94.
- **[0042](../decisions/0042-log-ring-and-panic-path.md), the log ring and the panic path.** Settles D10: the ring's record format, reading by capability, and the boot framebuffer's Kernel, Adopted and Retired states. Narrows D55 (the import source and how the kernel stops drawing), D40 (the root server alone gets the ring's capability), D57 and D84.
- **[0043](../decisions/0043-qemu-boots-with-acpi-off.md), ACPI off on QEMU.** Now part of [0036](../decisions/0036-qemu-configuration-and-test-builds.md), rule 2, and 0043 is superseded: EDK2 passes ACPI or the device tree, never both, so QEMU runs with `acpi=off` until ACPI support comes (C65).
- **[0044](../decisions/0044-stub-undoes-grubs-command-line.md), GRUB's command line.** Now part of [0041](../decisions/0041-boot-abi.md), rule 5, and 0044 is superseded: the stub drops GRUB's `BOOT_IMAGE=` word and undoes its escaping and quoting.
- **[0045](../decisions/0045-linking-the-kernel-and-stub-on-stable-rust.md), linking on stable Rust.** Now part of [0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), rules 2 and 3, and 0045 is superseded: the kernel links as a static PIE with `-z notext`, and the stub with `/DEBUG:NONE`.
- **[0046](../decisions/0046-fallback-fonts-for-wgl4-symbols.md), fallback fonts.** [0034](../decisions/0034-noto-fonts-under-ofl.md), rule 1 has Noto Sans Math and Noto Sans Symbols supply the 18 WGL4 symbols Noto Sans Mono lacks, and rule 4 leaves the ligatures and private-use code points out of the atlases' set. 0046 settles the soft hyphen and those code points (rules 1 and 2).

### By rules already accepted

Items listed as open, or as conflicts, that an accepted rule already decides.

- **The identity URI's path.** [0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 2: `spiffe://<realm-domain>/<object-id-text>`, the bare object ID, as [0020](../decisions/0020-realm-certificate-authority.md), rule 5 requires. A typed prefix would need a change to that rule. Closed.
- **The root's algorithm.** [0020](../decisions/0020-realm-certificate-authority.md), rule 2: `id-MLDSA65-Ed25519-SHA512` for every certificate the realm issues, the root's included. A stronger root would need a change to that rule, which [0003](../decisions/0003-hybrid-post-quantum-cryptography.md), rule 5 allows.
- **The form of entity identifiers.** [0017](../decisions/0017-openid-federation-membership.md), rule 1: HTTPS. An `aspis:` profile would need a change to that rule.
- **Cross-certifying other realms.** [0020](../decisions/0020-realm-certificate-authority.md), rules 1 and 10: the root issues each cross-certificate, in a ceremony. An online cross-certification CA would need a change to rule 1. The rest is in D141.
- **Whether the root key needs a full-entropy source.** [0021](../decisions/0021-entropy-before-keys.md), rules 5 and 6: the ceremony runs on a node with a physical source and prediction resistance, and an HSM's entropy may be mixed in but is never credited ([entropy note §6](entropy-and-first-keys.md#6-open-questions)).
- **QEMU's fixed parts.** virtio-rng always ([0021](../decisions/0021-entropy-before-keys.md), rule 12); `ramfb` ([0009](../decisions/0009-text-as-graphics-console.md), rule 2); the SMMUv3 and multi-node runs ([0007](../decisions/0007-initial-hardware-targets.md), rule 1). The rest was D03, which [0036](../decisions/0036-qemu-configuration-and-test-builds.md) settled.
- **The seed's path.** Not a conflict: the root server starts the entropy service ([0021](../decisions/0021-entropy-before-keys.md), rule 1), so the seed passes through it. The kernel receives it in a page of its own and never reads it ([0041](../decisions/0041-boot-abi.md), rule 4). The rest of the mechanism is D42.
- **Whether kernel objects carry IDs.** They do: [0001](../decisions/0001-object-identifiers.md) names processes, threads and endpoints (Context). Who mints them is D16.
- **The key a node uses with the provider.** An operational key the genesis key has certified ([0001](../decisions/0001-object-identifiers.md), rule 3; [0020](../decisions/0020-realm-certificate-authority.md), rule 4). The mechanism is D91.
- **Where some realm services run.** The router on edge nodes ([0026](../decisions/0026-realm-as-cloud-provider.md), rule 6); the provider and the authorization service with the registry ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 2; [authorization tree note §4](authorization-tree.md#4-roots-epochs-and-replication)); a PDP and a catalog replica on every node ([0019](../decisions/0019-authzen-decision-protocol.md), rule 3; [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 3). The rest is D88.
- **How the Workload Endpoint identifies callers.** Through the POSIX process server ([0022](../decisions/0022-spiffe-and-wimse-workload-identity.md), rule 8). The rest is in D139 and D99.
- **Renewing a session.** It needs a fresh token ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 1).
- **Authority before the first PDP.** Only the root server's capabilities ([0018](../decisions/0018-cedar-policy-language.md), rule 5), and "The bootstrap line holds" ([0027](../decisions/0027-applications-extend-the-system.md), Consequences). The mechanics are D41.
- **Mode bits.** A view onto ACLs, computed and never stored ([0012](../decisions/0012-posix-compatibility-layer.md), rule 6; [0016](../decisions/0016-authorization-sparse-merkle-tree.md), Consequences). The rest is D97.
- **Scaling and releases.** Changing a formation creates no release. The formation is deploy state, and a release comes from a new build, a config change, a binding change or a rollback ([0026](../decisions/0026-realm-as-cloud-provider.md), rule 2). The rest is D125.
- **How errors are namespaced.** By interface ([0027](../decisions/0027-applications-extend-the-system.md), rule 2). The encoding is D26.
- **Scratch paths.** `/tmp`, `TMPDIR` and `HOME` point at the scratch area ([0025](../decisions/0025-twelve-factor-app-contract.md), rule 6). The exact values are in D107.
- **Where the terminal emulator runs.** In a pad mode the POSIX layer provides ([0011](../decisions/0011-dm-window-system.md), rule 3). The rest is D104.
- **What resource search covers.** Published objects only ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 8). Who answers is D140.
- **Who registers shard locations.** Process managers register instances, and a sharding manager registers its shards; the rules don't conflict ([0027](../decisions/0027-applications-extend-the-system.md), rule 5; [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 5). The protocol is D109.
- **Authorities that aren't nodes.** Allowed ([0017](../decisions/0017-openid-federation-membership.md), rule 5), and [0001](../decisions/0001-object-identifiers.md) says so since it was edited on 2026-11-25. The derivation is D37.
- **Who checks grants at bind.** The PDP, against the node's replica ([0019](../decisions/0019-authzen-decision-protocol.md), rules 1 and 3), so [0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 5 holds through the PDP. 0016 rule 5 says so since it was edited on 2026-11-25 ([Conflicts](#conflicts-that-dont-block-the-build)).
- **The policy service and the authorization service.** The policy service validates changes and submits them; the authorization service batches and signs ([0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 4; [0018](../decisions/0018-cedar-policy-language.md), rule 7). The write path is D70.
- **The strawman's two trees.** [0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 2 asks for the strawman to be refined; that is D61, not a conflict.
- **The same-epoch CRL.** Epochs order the tree's history ([0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 4) and a CRL has none, so "the same epoch" in [0020](../decisions/0020-realm-certificate-authority.md), rule 10 means the tree's; the CRL follows at the next ceremony.
- **Where signing happens.** [0003](../decisions/0003-hybrid-post-quantum-cryptography.md), rule 6 keeps cryptography out of the kernel, and its list of servers isn't exhaustive. Signing through the key service is a choice, D59.
- **Smart cards without certificates for people.** [0020](../decisions/0020-realm-certificate-authority.md), rule 4 covers what the realm's CA issues; a card's key can be registered with the provider, as a passkey is. The rest is D105.
- **Deadlines without network knowledge.** The kernel enforces a deadline it is given ([0004](../decisions/0004-network-transparency-and-failure.md), rules 3 and 4). Who sets it is D22.
- **The example call header.** It is "illustrative … (not normative)" ([0013](../decisions/0013-abnf-for-protocols-and-calls.md)), so nothing conflicts with it. The header is D25.
- **What a bind names.** A bind that needs several methods is checked in one batch ([0019](../decisions/0019-authzen-decision-protocol.md), rule 1). The message is D39.
- **The random field of pre-gate IDs.** Deferred in so many words ([0021](../decisions/0021-entropy-before-keys.md), Consequences), so not a conflict of its own; it is part of the blocking conflict, D36.
- **Coherence for immutable objects, and the singleton guarantee.** Requirements on the lease protocol ([0026](../decisions/0026-realm-as-cloud-provider.md), rules 4 and 5), not conflicts. They are in D87.
- **Grant keys named in tokens.** Replaced by the determining policies ([0019](../decisions/0019-authzen-decision-protocol.md), rule 8; [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rules 1 and 3; [0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 6).
- **One principal per process type, or one per deploy.** One per process type ([0026](../decisions/0026-realm-as-cloud-provider.md), rule 11).

### By the design-note corrections

On 2026-11-24 the older design notes were checked against the accepted records, and 46 statements were corrected.

- **Which collections can be watched.** Every manager's enumeration interface notifies watchers, so watching isn't limited to directories ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 1; recorded in [discovery note §8](extensibility-and-discovery.md#8-open-questions)). The rest is D54.
- **Statements that were only stale.** The realm as a leaf in its topologies, now an intermediate ([federation note §3](openid-federation.md#3-the-realms-place-in-a-topology)); the genesis key signing the node's client assertion, now an operational key ([security tokens note §4.2](security-tokens.md#42-workload-identity)); mode bits stored as attributes ([POSIX note §3](posix-compatibility.md#3-proposed-architecture)); errors namespaced by subsystem ([POSIX note §4.19](posix-compatibility.md#419-errors)); the identity URI's path as a placeholder ([CA note §8](realm-certificate-authority.md#8-open-questions); [workload identity note §7](workload-identity.md#7-open-questions)); an enrollment diagram that renewed at half the lifetime, while when renewal starts is still open (D80); and the wording and diagram slips the reading phase graded cosmetic.

### Not design decisions

- **The architecture views.** The realm, node and kernel views and the key flows, which the reading phase listed as the session's own work, now exist: [Inside a realm](realm-containers.md), [Inside a node](node-components.md), [Inside the kernel](kernel-components.md) and [Key flows](key-flows.md).
- **Tracking the twelve-factor revision.** ASPIS follows the published text and records where it goes further ([0025](../decisions/0025-twelve-factor-app-contract.md), Consequences). That is a standing practice, not a decision.
- **Two sentences in the notes that need only an edit.** The [discovery note §5.3](extensibility-and-discovery.md#53-signed-registrations-soft-availability) says registrations change "only when releases go live", which is narrower than [0027](../decisions/0027-applications-extend-the-system.md), rule 6 and [0028](../decisions/0028-discovery-and-realm-catalog.md)'s Consequences, where services that run outside the app platform register too. It sits in the case against a rejected alternative, so the conclusion stands. The [key flows §3](key-flows.md#3-realm-creation-ceremony) still list whether the root key needs a full-entropy source as open, which [0021](../decisions/0021-entropy-before-keys.md), rules 5 and 6 decide, as the [entropy note §6](entropy-and-first-keys.md#6-open-questions) records.
- **Reading the unread AEGIS sources.** Research, not a decision. They should cover lock modes, remote page validation, the hint manager and remote-node failure ([research notes §6](../research/aegis-domain-os.md#6-gaps-and-next-sources)), which makes them input to D87 and D109.
