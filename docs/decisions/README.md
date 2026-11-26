<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Architecture decision records

Each record captures one decision: its context, what was decided, and the consequences. Records are numbered in order and never renumbered.

During the build phase, records are edited in place, so each one always says what is in force. A change to an accepted record is proposed as an edit in a pull request, and merging it accepts the change. Git history records what changed and when. A record's `Date` line is the date it was first written. When a record is edited on a later day than its date, its Date line adds "updated" and that day, as 2026-11-24, updated 2026-11-26. The index copies each record's Date line. A record that no longer applies keeps its file and its number, with its status changed to "Superseded by NNNN" or "Withdrawn".

## Founding requirements

These come from the project brief and aren't re-decided here:

- A microkernel written in Rust, targeting ARM64, bootable with GRUB.
- Modeled on Apollo AEGIS / Domain/OS (see [the research notes](../research/aegis-domain-os.md)).
- Files and every other OS fixture programs touch are objects named by unique IDs with an indexable part and a guaranteed globally unique part.
- All resources are API calls that work transparently on local or remote resources, over RPC secured with lattice-based post-quantum cryptography.
- Node names are UUIDs with a friendly name on top.
- After the preboot environment, a graphics driver takes the system into a text-as-graphics mode that supports text and graphics natively.
- SVG is a core graphics primitive. The windowing system, `dm`, is built on "Display SVG", running on the native SVG layer.
- A native *NIX compatibility layer runs on top of the ASPIS APIs.
- Protocols are described in ABNF where necessary, and ABNF also describes the RPC and IPC calls.
- Every object exposes versioned APIs, and all interaction with objects goes through them. They are native OS constructs, below the POSIX layer.
- Security constructs for interaction with APIs use JWTs, building up to user and workload identities that use OpenID Connect for authentication and access management.
- Permissions (authorization) across the network-transparent environment are stored in a sparse Merkle tree. Revocation marks the relevant branch of the tree as revoked.
- The environment can be joined to one or more OpenID Federation topologies. It accepts and issues user and workload identities through the OpenID Federation mechanism.
- The Cedar policy language is the realm's policy description and engine. The AuthZEN wire protocol carries requests for authorization decisions and their answers.
- Where in the OS's initialization lifecycle the first certificates are minted decides how much entropy is available when they are. Sufficient entropy, with blocking until there is enough, is a core concern.
- Copyrights are 2026 Nicole Roy for novel work and code.
- Diagrams are written in Mermaid, and context diagrams use the C4 model.
- The OS supports twelve-factor apps as a core concern, through its native APIs, and supports the twelve-factor design principles. A realm acts as a virtual cloud provider for these apps.
- Applications at the ASPIS level, below the POSIX layer, expose their functionality to the system and the realm as objects, with the same versioned API standards as ASPIS itself. An application such as a relational database service can then offer what looks like a core OS function, although it was added later rather than built in.
- API and object discoverability is a core concern of the OS and the realm. A catalog, updated in real time, enumerates the APIs and objects through the discovery system.

## Records

| # | Decision | Status | Date |
|---|---|---|---|
| [0001](0001-object-identifiers.md) | Object identifiers: 256 bits, self-certifying, no clock | Accepted | 2026-11-24, updated 2026-11-25 |
| [0002](0002-capability-security-model.md) | Capabilities in the kernel; object IDs are names | Accepted | 2026-11-24, updated 2026-11-25 |
| [0003](0003-hybrid-post-quantum-cryptography.md) | Hybrid post-quantum cryptography | Accepted | 2026-11-24, updated 2026-11-25 |
| [0004](0004-network-transparency-and-failure.md) | Network transparency: scope and failure semantics | Accepted | 2026-11-24 |
| [0005](0005-single-level-store.md) | Single-level store as the primary I/O model | Accepted | 2026-11-24 |
| [0006](0006-uefi-boot-image.md) | Boot: a UEFI PE32+ image loaded by GRUB | Accepted | 2026-11-24, updated 2026-11-25 |
| [0007](0007-initial-hardware-targets.md) | Initial hardware targets: QEMU `virt`, then Raspberry Pi 4 | Accepted | 2026-11-24 |
| [0008](0008-mpl-2.0-license.md) | License: MPL-2.0 | Accepted | 2026-11-24, updated 2026-11-25 |
| [0009](0009-text-as-graphics-console.md) | Console: text as graphics from the first kernel message | Accepted | 2026-11-24 |
| [0010](0010-svg-core-primitive.md) | SVG as a core primitive: the native SVG layer and Display SVG | Accepted | 2026-11-24 |
| [0011](0011-dm-window-system.md) | dm: the window system, built on Display SVG | Accepted | 2026-11-24 |
| [0012](0012-posix-compatibility-layer.md) | POSIX compatibility: a user-space personality on ASPIS APIs | Accepted | 2026-11-24 |
| [0013](0013-abnf-for-protocols-and-calls.md) | ABNF for protocols, formats, and every RPC and IPC call | Accepted | 2026-11-24, updated 2026-11-25 |
| [0014](0014-versioned-object-apis.md) | Versioned object APIs | Accepted | 2026-11-24, updated 2026-11-25 |
| [0015](0015-jwt-tokens-and-oidc-identity.md) | Security tokens: JWTs, with OpenID Connect for user and workload identity | Accepted | 2026-11-24, updated 2026-11-25 |
| [0016](0016-authorization-sparse-merkle-tree.md) | Authorization store: a sparse Merkle tree, revoked by branch | Accepted | 2026-11-24, updated 2026-11-25 |
| [0017](0017-openid-federation-membership.md) | Joining OpenID Federation topologies | Accepted | 2026-11-24, updated 2026-11-25 |
| [0018](0018-cedar-policy-language.md) | Cedar as the realm's policy language and engine | Accepted | 2026-11-24, updated 2026-11-25 |
| [0019](0019-authzen-decision-protocol.md) | AuthZEN for requesting and receiving authorization decisions | Accepted | 2026-11-24, updated 2026-11-25 |
| [0020](0020-realm-certificate-authority.md) | The realm as its own certificate authority, with hybrid post-quantum certificates | Accepted | 2026-11-24, updated 2026-11-25 |
| [0021](0021-entropy-before-keys.md) | Entropy: no key before the generator is seeded | Accepted | 2026-11-24 |
| [0022](0022-spiffe-and-wimse-workload-identity.md) | Workload identity that conforms to SPIFFE and WIMSE | Accepted | 2026-11-24, updated 2026-11-25 |
| [0023](0023-copyright-notices.md) | Copyright notices | Accepted | 2026-11-24, updated 2026-11-25 |
| [0024](0024-diagrams-mermaid-and-c4.md) | Diagrams: Mermaid, with the C4 model for context diagrams | Accepted | 2026-11-24 |
| [0025](0025-twelve-factor-app-contract.md) | Twelve-factor apps: the app's contract as native APIs | Accepted | 2026-11-24, updated 2026-11-25 |
| [0026](0026-realm-as-cloud-provider.md) | The realm as a virtual cloud provider for twelve-factor apps | Accepted | 2026-11-24, updated 2026-11-25 |
| [0027](0027-applications-extend-the-system.md) | Applications extend the system through objects and versioned interfaces | Accepted | 2026-11-24, updated 2026-11-25 |
| [0028](0028-discovery-and-realm-catalog.md) | Discovery: a realm catalog of interfaces, types and objects, updated in real time | Accepted | 2026-11-24, updated 2026-11-25 |
| [0029](0029-founding-node-self-signed-certificate.md) | The founding node's initial certificate is self-signed | Accepted | 2026-11-24, updated 2026-11-25 |
| [0030](0030-bind-tokens-sessions-and-group-memberships.md) | What managers accept, when sessions end, and where group memberships come from | Superseded by [0015](0015-jwt-tokens-and-oidc-identity.md) and [0018](0018-cedar-policy-language.md) | 2026-11-24 |
| [0031](0031-abnf-is-not-a-command-language.md) | ABNF specifies protocols and formats, not the command interpreter | Accepted | 2026-11-24, updated 2026-11-25 |
| [0032](0032-stateful-services-run-as-platform-deploys.md) | Stateful services run as platform deploys | Accepted | 2026-11-24 |
| [0033](0033-contributions-docs-license-and-notice-years.md) | Contributions under the DCO, documents under CC BY 4.0, and year ranges in notices | Accepted | 2026-11-25 |
| [0034](0034-noto-fonts-under-ofl.md) | Fonts: Noto, under the SIL Open Font License, with atlases at 16, 24 and 32 pixels | Accepted | 2026-11-25 |
| [0035](0035-toolchain-image-linkage-and-esp-layout.md) | Toolchain, image linkage and the ESP layout | Accepted | 2026-11-25 |
| [0036](0036-qemu-configuration-and-test-builds.md) | QEMU configuration, the test framework and test builds | Accepted | 2026-11-25 |
| [0037](0037-initial-image-format-and-contents.md) | The initial image: an ASPIS format, carrying everything that starts before storage | Accepted | 2026-11-25 |
| [0038](0038-reproducible-builds-and-provenance.md) | Reproducible builds, CycloneDX SBOMs and SLSA provenance | Accepted | 2026-11-25 |
| [0039](0039-no-uefi-runtime-services.md) | No UEFI runtime services after boot | Accepted | 2026-11-25 |
| [0040](0040-the-stub-checks-the-initial-image.md) | The stub checks the initial image against a digest in `aspis.efi` | Accepted | 2026-11-25 |
| [0041](0041-boot-abi.md) | The boot ABI: entry state, boot information and kernel arguments | Accepted | 2026-11-25 |
| [0042](0042-log-ring-and-panic-path.md) | The kernel log ring and the panic path | Accepted | 2026-11-25 |
| [0043](0043-qemu-boots-with-acpi-off.md) | QEMU configurations turn ACPI off, so the firmware passes the device tree | Superseded by [0036](0036-qemu-configuration-and-test-builds.md) | 2026-11-25 |
| [0044](0044-stub-undoes-grubs-command-line.md) | The stub undoes GRUB's rewriting of the command line | Superseded by [0041](0041-boot-abi.md) | 2026-11-25 |
| [0045](0045-linking-the-kernel-and-stub-on-stable-rust.md) | Linking the kernel and the stub on stable Rust | Superseded by [0035](0035-toolchain-image-linkage-and-esp-layout.md) | 2026-11-25 |
| [0046](0046-fallback-fonts-for-wgl4-symbols.md) | Fallback Noto fonts for the WGL4 symbols Noto Sans Mono lacks | Accepted | 2026-11-25 |
| [0047](0047-the-kernel-follows-sel4.md) | The kernel follows seL4's design, with ASPIS's own objects where the records need them | Accepted | 2026-11-25, updated 2026-11-26 |
| [0048](0048-kernel-memory-and-address-spaces.md) | Kernel memory: untyped memory, 4 KiB pages, and no access to user addresses | Accepted | 2026-11-25 |
| [0049](0049-capability-spaces-rights-and-revocation.md) | Capability spaces, rights, badges and revocation | Accepted | 2026-11-25, updated 2026-11-26 |
| [0050](0050-ids-for-kernel-objects.md) | User-space servers name the kernel objects they present | Accepted | 2026-11-25 |
| [0051](0051-scheduling-timers-and-deadlines.md) | Scheduling, the timer and deadlines | Accepted | 2026-11-25 |
| [0052](0052-smp-bring-up-and-the-kernel-lock.md) | SMP: PSCI bring-up and one kernel lock | Accepted | 2026-11-25 |
| [0053](0053-eventcounts.md) | Eventcounts | Accepted | 2026-11-25 |
| [0054](0054-ipc-endpoints.md) | IPC: synchronous endpoints with deadlines and cancellation | Accepted | 2026-11-25 |
| [0055](0055-interrupt-objects.md) | Interrupt objects for user-space drivers | Accepted | 2026-11-25 |
| [0056](0056-faults-and-page-fetch-deadlines.md) | Typed faults, and the deadline for fetching a page | Accepted | 2026-11-25 |
| [0057](0057-memory-objects-and-the-pager-protocol.md) | Memory objects and the pager protocol | Accepted | 2026-11-25 |
| [0058](0058-jobs-and-budgets.md) | Jobs, memory reservations and limits, and CPU shares | Accepted | 2026-11-25 |
| [0059](0059-the-kernel-interface-library.md) | The kernel interface library | Accepted | 2026-11-25 |
| [0060](0060-processes-native-spawn-and-elf.md) | Processes, native spawn and the executable format | Accepted | 2026-11-25 |
| [0061](0061-debugging.md) | Debugging: the kernel, user threads and crash dumps | Accepted | 2026-11-25 |
| [0062](0062-core-rules-big-endian-fixed-width.md) | Core rules: big-endian, fixed-width binary conventions | Accepted | 2026-11-25, updated 2026-11-26 |
| [0063](0063-names-and-the-canonical-call-text.md) | Names and the canonical call text | Accepted | 2026-11-25 |
| [0064](0064-the-call-header-and-wire-encoding.md) | The call header and the wire encoding | Accepted | 2026-11-25 |
| [0065](0065-typed-errors-and-minor-versions-on-the-wire.md) | Typed errors and minor versions on the wire | Accepted | 2026-11-25 |
| [0066](0066-capability-parameters-and-server-streams.md) | Capability parameters and server streams | Accepted | 2026-11-25 |
| [0067](0067-the-aspis-idl.md) | The ASPIS IDL | Accepted | 2026-11-25 |
| [0068](0068-the-fuzzing-and-differential-testing-gate.md) | The fuzzing and differential-testing gate | Accepted | 2026-11-25 |
