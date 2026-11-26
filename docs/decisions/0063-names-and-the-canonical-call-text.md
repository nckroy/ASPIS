<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0063. Names and the canonical call text

- **Status:** Accepted
- **Date:** 2026-11-25, updated 2026-11-26

## Context

Several accepted rules need one spelling for interfaces, methods and calls:

- [0013](0013-abnf-for-protocols-and-calls.md), rule 5 gives every call a text rendering in ABNF, for logs, traces and token scopes. [0031](0031-abnf-is-not-a-command-language.md), rule 3 makes it machine-facing only.
- [0019](0019-authzen-decision-protocol.md), rule 4 makes an action name the interface, major version and method. [0018](0018-cedar-policy-language.md), rule 4 makes methods and the IDL's groups Cedar actions and action groups.
- [0027](0027-applications-extend-the-system.md), rule 7 makes names dotted and reverse-DNS, reserves `aspis.`, and leaves the grammar to ABNF.
- [0014](0014-versioned-object-apis.md), rule 4 keeps method numbers stable within a major.

[D12](../design/design-backlog.md#m2-kernel-objects) asks for method names beside their numbers, the ABNF of the canonical call text, and the grammar of names and interface references. The [discovery note's sketch](../design/extensibility-and-discovery.md#46-names) allowed hyphens, which a Cedar entity-type path can't hold.

The project owner decided on 2026-11-25 that members are snake_case; every method carries an explicit `@n` number; the call text is `action target`, with arguments opt-in in the IDL's compact JSON mapping and sensitive fields redacted; and kernel interfaces are named under `aspis.kernel.`. The owner accepted the other choices Claude proposed as defaults the same day, including that a group may gain methods in a minor.

The grammar, vectors and examples are in the [call-language specification](../design/call-language.md#names-and-the-canonical-call-text). This record edits no accepted rule. Claude drafted it on 2026-11-25.

## Decision

1. **One name grammar serves interfaces and types** ([spec](../design/call-language.md#interface-and-type-names)).
   - A name is lowercase ASCII, dotted and reverse-DNS, with at least two labels. A label uses `a-z`, digits and `_`, never `-`, and starts with a letter, or with `_` and a letter or digit. Labels and names have length limits.
   - No label is a Cedar reserved word, or `self`, `super` or `crate`, which Rust can't take as raw identifiers in a generated module path.
   - So every type name is a Cedar entity-type path, and every action string a Cedar string and an RFC 6749 scope-token, with no escaping. CI checks both.
   - An interface and a type may share a name; an interface reference carries a major.
   - The grammar is `grammars/names.abnf`, hand-written and checked against C07's generator ([The names grammar](../design/call-language.md#the-names-grammar)).
2. **Publishers transliterate DNS names the D-Bus way.** A hyphen becomes `_`. A label that starts with a digit, or is a Cedar reserved word or one of `self`, `super` and `crate`, takes a leading `_`: `org.aspis_os.sql`, `org._7_zip.archive`, `_in.co.example.ledger`, `io._crate.registry`.
3. **The `aspis.` prefix is reserved by ASPIS policy** ([0027](0027-applications-extend-the-system.md), rule 7). `aspis` isn't a top-level domain.
   - Kernel interfaces are `aspis.kernel.<object>`, one per kind of kernel object ([0059](0059-the-kernel-interface-library.md), rule 1), such as `aspis.kernel.eventcount`.
   - The interfaces the kernel calls are `aspis.kernel.fault`, `aspis.kernel.pager` and `aspis.kernel.memory_request`. No kernel object's interface takes one of these names: the pager capability's is `aspis.kernel.pager_object`.
4. **Members are lower snake_case, and frozen within a major.** Members are methods, fields, parameters, results, errors, enum values, union arms and action groups. A member name has a length limit, no `__` and no trailing `_`, and a few reserved words are refused ([spec](../design/call-language.md#member-names)). Policies, scopes and logs carry member names, so renaming one takes a new major.
5. **Interface references carry a major and an optional minor**, as `aspis.catalog/1` or `aspis.catalog/1.2`. Both are 0 to 65,535, without leading zeros. A missing minor means `.0`. In a requirement (a bind, a query, a manifest, an IDL `use` or a `cap<...>` type) the minor means "this minor or later" ([0014](0014-versioned-object-apis.md), rule 3). In a registration or a catalog result it means exactly that version.
6. **Method numbers sit beside names** ([spec](../design/call-language.md#method-numbers)).
   - The IDL declares each method as `@n name(...)` ([0067](0067-the-aspis-idl.md), rule 4). The wire carries the number ([0064](0064-the-call-header-and-wire-encoding.md), rule 4); text carries the name.
   - Within a major, names and numbers are each unique, never renamed and never reused. There is no overloading. A retired number stays reserved.
   - IDL methods use 1 to 65,279. 0 is invalid.
   - `0xFF00` to `0xFFFF` are the call protocol's own methods ([0064](0064-the-call-header-and-wire-encoding.md), rule 8). They are defined with the call header, in `grammars/call-header.abnf`, not in any interface's IDL, so none is a Cedar action. Text forms name them under `aspis.rpc`, as `aspis.rpc/1/stream_next`.
7. **Action strings, groups and scopes** ([The names grammar](../design/call-language.md#the-names-grammar)).
   - An action string is `interface/major/method`, such as `aspis.catalog/1/watch`. A group is `interface/major/@group`, and all of a major's methods `interface/major/*`. Each is also a scope-token.
   - An error is named `interface/major!error`, such as `aspis.catalog/1!stream_expired`, or `id/major!#code` when its name isn't known.
   - The minor is never in an action string. It is fixed at bind, and logged there.
   - An interface declares its action groups, each in one major. A minor may add a new method to a group. It never moves a method between groups or removes one.
   - A realm action that isn't a method, such as `discover` ([0028](0028-discovery-and-realm-catalog.md), rule 8), is a method of a well-known interface: `aspis.catalog/1/discover`.
8. **One string serves everywhere** ([spec](../design/call-language.md#one-string-everywhere)). An action string, unchanged, names the Cedar action, with every interface's actions in the one namespace `aspis`. It is also the AuthZEN `action.name`, a token's scope-token, the OpenTelemetry span name and `rpc.method`, and, as a suggestion to D116, the HTTPS path. A type name becomes a Cedar entity type by replacing each `.` with `::`, and is the AuthZEN `resource.type` verbatim. Only the action type, `aspis::Action`, is capitalized.
9. **The canonical call text is the action and its target, with arguments opt-in** ([spec](../design/call-language.md#the-canonical-call-text)).
   - The target is the object the session is bound to, known from bind state ([0064](0064-the-call-header-and-wire-encoding.md), rule 1). The kernel knows no object's ID ([0050](0050-ids-for-kernel-objects.md), rule 1), and a `[kernel]` call names its object only by capability, so its target is `-`.
   - Arguments, when a log or trace enables them, are one object in the JSON mapping's compact form ([0067](0067-the-aspis-idl.md), rule 8). A `sensitive` field keeps its key, with the value `null`.
   - Badges, session IDs, export IDs, capability-space addresses and spill descriptors are never rendered. A `slot<...>` parameter, a capability-space address, keeps its key with the value `null`, like a sensitive field. No other struct field or parameter is ever `null`. A capability parameter is `{"cap":N}`, its index ([0066](0066-capability-parameters-and-server-streams.md), rule 2).
   - A reply is `ok`, with results opt-in the same way, or an outcome word and an error reference, such as `indeterminate aspis.rpc/1!deadline_passed` ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rules 5 and 6).
   - The request ID, deadline, trace context, bound version and reply are separate fields of the log record or span.
10. **The call text is output only.** Only interface, action and error references are parsed: by the PDP, the token library and the catalog. The call text is never parsed back into a call, so it can't become a command language ([0031](0031-abnf-is-not-a-command-language.md), rule 3). For a `[kernel]` interface, which has no wire form, conformance tests check its generated text grammar ([0013](0013-abnf-for-protocols-and-calls.md), rule 3).

## Consequences

- **This record settles D12.** Method names beside numbers: rules 4 and 6. The call text's ABNF: rules 9 and 10, given in full in `grammars/names.abnf`; C07 generates each method's argument and result rules ([0067](0067-the-aspis-idl.md), rule 9). Names and interface references: rules 1, 5 and 7.
- **What stays open** is in the specification: [L01](../design/call-language.md#l01-the-object-id-text-form) (the object-ID text form, D34), [L02](../design/call-language.md#l02-reserved-numbers) (reserved numbers, D29, D35), [L03](../design/call-language.md#l03-minting-application-ids-and-prefix-ownership) (application IDs and prefix ownership, D110), [L09](../design/call-language.md#l09-tracing) (the log record, D84), [L10](../design/call-language.md#l10-scope-semantics) and [L11](../design/call-language.md#l11-groups-that-grow-in-a-minor) (scope semantics and growing groups, D85), [L12](../design/call-language.md#l12-cedar-schema-details) (Cedar schema details, C31) and [L15](../design/call-language.md#l15-the-https-binding) (HTTPS paths, D116).
- **Two choices depart from the D12 research.** Methods stop at 65,279, leaving the top range to protocol methods. A failed reply is an outcome and an error reference, not `timed_out` or `canceled` words, which are `aspis.rpc` errors.
- **Two design notes follow it.** The [discovery note §4.6](../design/extensibility-and-discovery.md#46-names) points here instead of its sketch grammar, and the [policy note](../design/policy-and-decisions.md) uses `aspis::Action`, `aspis::principal` and `aspis.principal`.

## References

- [0013](0013-abnf-for-protocols-and-calls.md), rules 3 and 5; [0014](0014-versioned-object-apis.md), rules 3 and 4; [0018](0018-cedar-policy-language.md), rule 4; [0019](0019-authzen-decision-protocol.md), rule 4
- [0027](0027-applications-extend-the-system.md), rule 7; [0028](0028-discovery-and-realm-catalog.md), rule 8; [0031](0031-abnf-is-not-a-command-language.md), rule 3; [0050](0050-ids-for-kernel-objects.md), rule 1; [0059](0059-the-kernel-interface-library.md), rule 1
- [0064](0064-the-call-header-and-wire-encoding.md), [0065](0065-typed-errors-and-minor-versions-on-the-wire.md), [0066](0066-capability-parameters-and-server-streams.md) and [0067](0067-the-aspis-idl.md)
- [The call language: names and the canonical call text](../design/call-language.md#names-and-the-canonical-call-text)
- [Design backlog, D12](../design/design-backlog.md#m2-kernel-objects); [discovery note §4.6](../design/extensibility-and-discovery.md#46-names); [policy note](../design/policy-and-decisions.md)
- [RFC 5234, ABNF](https://www.rfc-editor.org/rfc/rfc5234) (STD 68), and [RFC 7405, Case-Sensitive String Support in ABNF](https://www.rfc-editor.org/rfc/rfc7405); [RFC 6749, OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749), §3.3 (scope-token); [RFC 8259, JSON](https://www.rfc-editor.org/rfc/rfc8259) (STD 90)
- [Cedar language version 4.7](https://docs.cedarpolicy.com/other/doc-history.html) (reserved identifiers); [D-Bus Specification, version 0.43](https://dbus.freedesktop.org/doc/dbus-specification.html), 2024-10-29 (valid names)
