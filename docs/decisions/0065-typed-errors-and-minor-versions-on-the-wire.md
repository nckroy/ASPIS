<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0065. Typed errors and minor versions on the wire

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Errors are typed and namespaced by interface ([0027](0027-applications-extend-the-system.md), rule 2). As accepted, [0014](0014-versioned-object-apis.md), rule 3 let minor versions add only methods or optional fields. Neither rule said how this looks on the wire. The [design backlog, D26](../design/design-backlog.md#m2-kernel-objects) asks how errors are encoded and carried, what the system's own errors are, how a minor adds fields old clients can parse, and how a too-new call is refused. AEGIS errors were status codes naming their subsystem, kept across RPC ([research notes §2.5](../research/aegis-domain-os.md#25-processes-synchronization-and-errors)).

On 2026-11-25 the project owner decided:

- minor versions may also add error codes, union arms and enum values;
- types are open by default, and generated bindings preserve values they don't know. The IDL offers `closed` for types that must never grow;
- a denied bind answers "no such object" unless the caller may `discover` the object ([0028](0028-discovery-and-realm-catalog.md), rule 8), and "bind refused" if it may.

The owner also accepted two defaults that Claude proposed with these records: field tags derived from position, and u32 counts ([0062](0062-core-rules-big-endian-fixed-width.md), rule 6).

The pull request that proposes this record also edits ADR 0014, rule 3, as the owner's explicit decision, to say what a minor may add (rules 10 and 13) and that types are open unless declared closed (rule 10).

Layouts, grammars and tables are in the [call-language specification](../design/call-language.md), under [Typed errors](../design/call-language.md#typed-errors) and [Evolution on the wire](../design/call-language.md#evolution-on-the-wire). Claude drafted this record from the owner's decisions.

## Decision

1. **One error envelope** is the body of every error reply, the value of a cause, and the error that ends a stream. It is an open struct (rule 9): outcome, disposition, the error key (rule 2) and a detail struct, then an optional cause and retry-after. Its size and the depth of nested causes are bounded so that it never spills ([0064](0064-the-call-header-and-wire-encoding.md), rule 11). The specification gives the bounds, which [L23](../design/call-language.md#l23-error-size-limits-and-free-text) may still tune. It carries no capabilities, so network servers forward it as opaque octets ([The error envelope](../design/call-language.md#the-error-envelope)).
2. **The error key names the interface by ID**: the interface's ID, its major and the code, never a name. So an error describes itself wherever it goes. A pager's Fail, and the page-unavailable fault it causes, carry only the key, because the kernel has no heap for envelopes ([0056](0056-faults-and-page-fetch-deadlines.md), rule 3; [0057](0057-memory-objects-and-the-pager-protocol.md), rule 7).
3. **Codes are u16, per interface major**, from 1; 0 is reserved. A code is never renamed or reused within its major. No interface reserves codes for the system (rule 6).
4. **No free text.** An error's description is its IDL doc comment ([0014](0014-versioned-object-apis.md), rule 2). Facts go in typed detail fields.
5. **Every error carries one of four outcomes**, which carry [0004](0004-network-transparency-and-failure.md), rule 3's classes: **refused** (delivered and didn't run, so a retry is safe), **failed** (ran, or may have), **unreachable** (never delivered) and **indeterminate** (may have run, with no answer). Refused and failed split ADR 0004's "application error" as DCE splits a reject from a fault. A server sends only refused or failed, and puts an error it forwards in the cause of its own; the other two come only from the caller's runtime, or a network server for its hop. An interface's error is failed unless the IDL declares it `[refused]`. An unknown disposition means don't retry ([Outcomes](../design/call-language.md#outcomes)).
6. **The system's errors are the interface `aspis.rpc`, major 1**, under the reserved authority. Every method may return them, and none lists them. The specification lists them ([The system errors](../design/call-language.md#the-system-errors)), including D26's examples: `version_unsupported`, `no_such_method`, `bind_refused`, `tree_too_stale`, `session_ended` with reason `revoked`, and `deadline_passed`.
7. **A denied bind** answers `no_such_object` when the object doesn't exist or the caller may not `discover` it ([0028](0028-discovery-and-realm-catalog.md), rule 8), and `bind_refused` otherwise. Both decisions come from one AuthZEN batch ([0019](0019-authzen-decision-protocol.md), rule 1), so timing doesn't tell them apart. `tree_too_stale` comes first ([A denied bind](../design/call-language.md#a-denied-bind)).
8. **Kernel results become typed errors.** The runtime turns "timed out" and "canceled" into `deadline_passed` and `canceled`, unreachable before delivery and indeterminate after, so those kernel results must say whether the message was delivered ([0054](0054-ipc-endpoints.md), rules 5 and 6). Kernel interfaces' failures are typed errors of their own `aspis.kernel.*` interfaces ([0059](0059-the-kernel-interface-library.md), rules 1 and 2; [Kernel results](../design/call-language.md#kernel-results)).
9. **A tagged optional tail.** An open struct is its required fields in order, then a counted tail of its present optional fields, each a tag and a length-prefixed value, tags ascending. A tag is the field's position in its struct. Fields are only appended within a major, and those a minor adds are optional, so tags never move and new ones are higher. A reader accepts an unknown tag only above every field it knows. A block per minor isn't used ([The struct encoding](../design/call-language.md#the-struct-encoding)).
10. **Types are open unless declared `closed`** (the owner's decision). Minors may add methods, optional fields, error codes, union arms, enum values, flag bits, types and constants. An open union's arm is its tag, then its value as a length-prefixed byte string, so a reader can skip and preserve an unknown arm; a closed union's arm is unprefixed. Generated bindings accept what they don't know, preserve it, and re-encode it unchanged. A closed type never changes within its major, treats unknown values as malformed, and holds no open struct or union. Error sets are always open ([Open and closed types](../design/call-language.md#open-and-closed-types)).
11. **Strict requests, tolerant reads, one encoding.** A client never sends anything newer than the minor fixed at bind ([0014](0014-versioned-object-apis.md), rule 4). Replies, error details, stream items and the kernel's requests are read tolerantly, so message bodies need no critical bit; only the header has must-understand flags and critical extensions ([0064](0064-the-call-header-and-wire-encoding.md), rules 4 and 10). Each value has one encoding: ascending tags, no duplicates, absent fields omitted, no padding. Anything else is `malformed` ([Rules for readers](../design/call-language.md#rules-for-readers)).
12. **Refusing what is too new.** The manager keeps the bind's minor in its session table, and the client stub never sends anything newer. Before dispatch, the server refuses an unknown or newer method (`no_such_method`) or request field (`field_too_new`), and a known but newer enum value, flag bit or union arm (`value_too_new`). A value it doesn't know at all goes to the implementation as unknown. A bind to a major or minor not served gets `version_unsupported`, listing what is served. Dispatchers for interfaces the kernel calls refuse nothing ([0064](0064-the-call-header-and-wire-encoding.md), rule 9; [Refusing what is too new](../design/call-language.md#refusing-what-is-too-new)).
13. **The compatibility check.** The IDL compiler in CI, and the catalog on registration ([0027](0027-applications-extend-the-system.md), rule 2), check each new minor against its major's published minors. A minor adds only what rule 10 lists, plus action groups, methods in existing groups and deprecation marks; it changes, reorders, removes and reuses nothing. Docs aren't part of the canonical form, so changing them isn't a change ([0067](0067-the-aspis-idl.md), rule 5). A field or arm added in a minor holds no capability, so preserved octets never carry a capability index ([0066](0066-capability-parameters-and-server-streams.md), rule 2). Each minor's reply, error-detail and stream-item vectors must match the previous minor's grammar ([The compatibility check](../design/call-language.md#the-compatibility-check)).

## Consequences

- Any caller can tell a safe retry from an unsafe one. Interfaces gain errors, arms and values without a new major.
- `closed` buys fixed sizes, at the price of a new major for any change.
- One encoding per value gives the fuzzing gate its round trip ([0068](0068-the-fuzzing-and-differential-testing-gate.md), rule 5), and lets reply caches compare octets.
- [0054](0054-ipc-endpoints.md), [0056](0056-faults-and-page-fetch-deadlines.md) and [0057](0057-memory-objects-and-the-pager-protocol.md) match it: "timed out" and "canceled" report delivery, and Fail carries the error key.
- **D26 is settled**: errors by rules 1 to 5, the system's errors by rules 6 and 7, new fields by rules 9 to 11, and too-new calls by rule 12.
- **Still open**, in the specification: [L13](../design/call-language.md#l13-token-rejected-reasons) (token-rejected reasons), [L23](../design/call-language.md#l23-error-size-limits-and-free-text) (error size and free text), [L14](../design/call-language.md#l14-errno-mapping) and [L15](../design/call-language.md#l15-the-https-binding) (errno and HTTPS), [L43](../design/call-language.md#l43-keeping-a-fails-error-key) (a Fail's key), [L02](../design/call-language.md#l02-reserved-numbers) (`aspis.rpc`'s number), [L04](../design/call-language.md#l04-request-ids-the-reply-cache-and-default-deadlines) (the reply cache), [L20](../design/call-language.md#l20-the-tree-staleness-bound) (the staleness bound) and [L21](../design/call-language.md#l21-older-majors-of-the-interfaces-the-kernel-calls) (older majors of the interfaces the kernel calls).

## References

- [Call-language specification](../design/call-language.md): [Typed errors](../design/call-language.md#typed-errors); [Evolution on the wire](../design/call-language.md#evolution-on-the-wire)
- [Design backlog, D26](../design/design-backlog.md#m2-kernel-objects)
- [Research notes §2.5](../research/aegis-domain-os.md#25-processes-synchronization-and-errors): AEGIS status codes
- [DCE 1.1: Remote Procedure Call (The Open Group, C706)](https://pubs.opengroup.org/onlinepubs/9629399/): rejects and faults
- [Google AIP-193: Errors](https://google.aip.dev/193)
- [0004](0004-network-transparency-and-failure.md); [0014](0014-versioned-object-apis.md); [0019](0019-authzen-decision-protocol.md); [0027](0027-applications-extend-the-system.md); [0028](0028-discovery-and-realm-catalog.md); [0062](0062-core-rules-big-endian-fixed-width.md); [0064](0064-the-call-header-and-wire-encoding.md); [0066](0066-capability-parameters-and-server-streams.md); [0068](0068-the-fuzzing-and-differential-testing-gate.md)
