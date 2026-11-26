<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0067. The ASPIS IDL

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

[0013](0013-abnf-for-protocols-and-calls.md), rule 3 makes the ASPIS IDL the source of truth for every interface. It must also carry versions ([0014](0014-versioned-object-apis.md), rule 3), Cedar actions, groups and entity types ([0018](0018-cedar-policy-language.md), rule 4), and what the catalog checks and HTTPS bindings need ([0027](0027-applications-extend-the-system.md), rules 2 and 10). The [design backlog, D28](../design/design-backlog.md#m2-kernel-objects) asks for its syntax and ABNF, types, annotations and bindings. Its options were a new IDL in the NCS and DCE tradition, or FIDL, Cap'n Proto or Smithy with an ABNF back end.

NCS gave Domain/OS its RPC and IDL ([research note, §2.8](../research/aegis-domain-os.md#28-networking-and-rpc)). DCE 1.1's IDL (C706) kept its bracketed header. C706 also has pointer classes and size expressions, which describe C memory, not messages.

On 2026-11-25 the project owner decided:

- a new IDL in the NCS/DCE lineage, with a DCE-style bracketed header and a modern body;
- the header shape `[id(aspis.kernel.eventcount), object_id(reserved(0x0103)), version(1.0)] interface eventcount`, with the prefix `aspis.kernel.` for kernel interfaces;
- snake_case for methods, fields, errors and groups;
- call-text arguments in the IDL's compact JSON mapping, with sensitive fields redacted;
- types open by default, with a `closed` opt-out;
- three capability transfers per message, which bounds what a method may carry.

The owner also accepted defaults that Claude proposed with these records: a declared maximum on every variable-length type, u32 counts, field tags by position, object types declared in the IDL, and groups that may gain methods in a minor.

This record edits no accepted record. The [call-language specification](../design/call-language.md#the-idl) holds the grammar, tables and worked examples. Claude drafted it from the discussion.

## Decision

1. **A new IDL in the NCS/DCE lineage** ([The lineage](../design/call-language.md#the-lineage)).
   - It keeps the bracketed interface header and attributes, at-most-once calls with `[idempotent]` as the exception, and tagged unions.
   - Its bodies are modern: `name: type` declarations, `->` results, explicit `@n` method numbers and bounded generic types.
   - It drops C706's pointer classes, `size_is` and `length_is`, NUL-terminated strings, operation numbers implied by order, and the ACS file.
   - Grammars, bindings, Cedar schema and the HTTPS binding are all generated from it.
2. **Files and the header** ([Files and the interface header](../design/call-language.md#files-and-the-interface-header)).
   - One UTF-8 file per interface major, under a new top-level `interfaces/` that mirrors the dotted name: `interfaces/aspis/catalog/v1.idl`. It is MPL-2.0 code.
   - It begins `edition 2026;`, so later editions can change defaults. `use` lines import another major's types.
   - The header has the owner's shape. `id(...)` holds the full dotted name ([0063](0063-names-and-the-canonical-call-text.md), rule 1), and the label after `interface` must equal its last label. `object_id(...)` holds the 32-octet ID, written `reserved(n)` or `hex(...)` until D34 fixes the ID text form. `version(M.m)` is the newest minor described.
3. **Types** ([Types](../design/call-language.md#types)).
   - `bool`, `u8` to `u64`, `i8` to `i64`, `f32`, `f64`, `id`, `uuid`, `string<N>`, `bytes<N>`, `seq<T, N>`, `array<T, N>`, `T?`, structs, unions, enums, flags, `cap<...>` and `slot<...>` ([0066](0066-capability-parameters-and-server-streams.md), rule 1), and `stream<T>` as a result; also constants and aliases.
   - Every variable-length type declares its maximum. The compiler checks each method's worst-case size and capability count ([0064](0064-the-call-header-and-wire-encoding.md), rule 14; [0066](0066-capability-parameters-and-server-streams.md), rule 3), and decoders never allocate without a bound.
   - Structs, unions, enums and flags are open unless declared `[closed]` ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rule 10).
   - Edition 2026 has no maps, user-defined generic types, recursive types or inheritance; an object implements several interfaces instead ([0014](0014-versioned-object-apis.md), rule 5).
   - **Object types** are `object` declarations with `type(...)` and `parents(...)`, in the serving manager's file. They become Cedar entity types ([0018](0018-cedar-policy-language.md), rule 4). Their attributes use only types Cedar can hold, and grow as struct fields do.
4. **Methods, results and errors.**
   - A method is `@n name(params) -> results error(...)`. Its parameters form the request struct, so optional ones sit in the tail ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rule 9).
   - Results are one type or named fields, optionally followed by a server stream ([0066](0066-capability-parameters-and-server-streams.md), rule 6).
   - The target is implicit: the session, or the invoked capability for a `[kernel]` interface.
   - Errors are declared `error name = n`, with optional detail fields. `error(...)` lists a method's own; system errors are implicit ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rule 6).
5. **Attributes and doc comments** ([Attributes](../design/call-language.md#attributes)).
   - The attribute set is closed: an unknown attribute is an error.
   - `groups(...)` declares an interface's action groups, and `group(...)` puts a method in them ([0063](0063-names-and-the-canonical-call-text.md), rule 7).
   - Support periods aren't attributes but registration data ([0014](0014-versioned-object-apis.md), rule 7), since dates in the source would change its hash.
   - `///` documents the next item and `//!` the file, in a CommonMark subset. The compiler emits a doc model. Docs are outside the canonical form, so fixing one needs no new minor.
6. **Numbers stay stable** ([How numbers stay stable](../design/call-language.md#how-numbers-stay-stable)). Method numbers ([0063](0063-names-and-the-canonical-call-text.md), rule 6), union arms, enum and flag values, and error codes are explicit and never reused; `reserved` retires one. Struct fields are numbered by position and only appended.
7. **The lock and the compatibility check** ([The lock and the canonical form](../design/call-language.md#the-lock-and-the-canonical-form)).
   - A minor's canonical form is the source projected to that minor, without comments or docs, with derived numbers written out.
   - `v1.idl.lock` holds the SHA3-256 hash of each published minor's canonical form, the octets the catalog hashes ([0028](0028-discovery-and-realm-catalog.md), rule 2).
   - `idlc check`, and the catalog on registration, fail if a published minor changed, or a step between minors breaks [0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rule 13.
8. **The JSON mapping is part of the IDL** ([The JSON mapping](../design/call-language.md#the-json-mapping)).
   - It serves the canonical call text in compact form ([0063](0063-names-and-the-canonical-call-text.md), rule 9) and the HTTPS bindings, which add parsing. Its output is I-JSON.
   - Every wire value has a JSON form. 64-bit integers are decimal strings, bytes unpadded base64url, unknown values their tags or numbers, and sensitive values and `slot<...>` values `null` ([0063](0063-names-and-the-canonical-call-text.md), rule 9).
9. **Generated grammars** ([Generated grammars](../design/call-language.md#generated-grammars)).
   - Each minor has a committed wire grammar and canonical-text grammar, with vectors, which CI regenerates and compares ([0013](0013-abnf-for-protocols-and-calls.md), rule 6). In text grammars, arguments and results follow RFC 8259 and the JSON mapping. A `[kernel]` interface has only a text grammar ([0059](0059-the-kernel-interface-library.md), rule 1).
   - Rule names are prefixed and one to one. Bounds become constraints. Requests are strict; replies, items and error details accept unknown tail fields ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rule 11).
10. **Back ends** ([Back ends](../design/call-language.md#back-ends)).
    - C07 builds the Rust `no_std` binding (views, allocation-free encoders, client stubs, server dispatchers), an `alloc` feature with owned types for host tools and the later `std` port, the JSON encoder, the doc model and fuzz support.
    - Generated crates forbid `unsafe`. The function-table glue for `[kernel]` interfaces lives in `aspis-rt` ([0059](0059-the-kernel-interface-library.md), rule 8).
    - The `std` binding is the `alloc` feature. Async bindings for the `std` port are open ([L31](../design/call-language.md#l31-async-rust-bindings)).
    - C31 adds Cedar schema fragments, and C52 the HTTPS binding and OpenAPI. The C binding waits for a C consumer.
11. **The compiler** ([Crates](../design/call-language.md#crates)).
    - `crates/idl` is `no_std` with `alloc`, so the catalog runs CI's checks ([0027](0027-applications-extend-the-system.md), rule 2). Beside it are `crates/idl-rt`, the generated code's runtime, and `tools/idlc`. All are MPL-2.0, on pinned stable Rust.
    - The parser is hand-written, tested against the normative `grammars/idl.abnf` and its vectors, and fuzzed against it ([0068](0068-the-fuzzing-and-differential-testing-gate.md), rule 6).
    - Generated Rust is built deterministically ([0038](0038-reproducible-builds-and-provenance.md)).

## Consequences

- **One source for every interface artifact.** ASPIS's and applications' interfaces pass the same compiler and checks, and every method's worst-case size is known at compile time.
- **C07 comes before C17 and C18.** CLAUDE.md's layout gains `interfaces/`.
- **This record settles D28.** Syntax and ABNF: rules 2, 4 and 11. Types: rules 3 and 4. Annotations: rule 5. Bindings: rule 10.
- **Open in the specification:** support periods ([L17](../design/call-language.md#l17-registration-documentation-revisions-and-support-periods)), rendering doc comments ([L32](../design/call-language.md#l32-rendering-doc-comments)), async Rust ([L31](../design/call-language.md#l31-async-rust-bindings)), the C binding ([L30](../design/call-language.md#l30-the-c-binding)), the ID text form ([L01](../design/call-language.md#l01-the-object-id-text-form)), reserved numbers ([L02](../design/call-language.md#l02-reserved-numbers)), application IDs ([L03](../design/call-language.md#l03-minting-application-ids-and-prefix-ownership)), Cedar ([L12](../design/call-language.md#l12-cedar-schema-details), [L44](../design/call-language.md#l44-object-types-in-cedar)), HTTPS ([L15](../design/call-language.md#l15-the-https-binding)), client streams ([L29](../design/call-language.md#l29-client-and-bidirectional-streams)) and dynamic invocation ([L33](../design/call-language.md#l33-dynamic-invocation)).

## References

- The Open Group, [*DCE 1.1: Remote Procedure Call* (C706)](https://pubs.opengroup.org/onlinepubs/9629399/), chapter 4, "Interface Definition Language"
- [Research note: AEGIS and Domain/OS](../research/aegis-domain-os.md), §2.8
- [0013](0013-abnf-for-protocols-and-calls.md), [0014](0014-versioned-object-apis.md), [0018](0018-cedar-policy-language.md), [0027](0027-applications-extend-the-system.md), [0028](0028-discovery-and-realm-catalog.md); [0063](0063-names-and-the-canonical-call-text.md) to [0066](0066-capability-parameters-and-server-streams.md), [0068](0068-the-fuzzing-and-differential-testing-gate.md)
- [The call-language specification](../design/call-language.md#the-idl)
- RFC 8259 (JSON); RFC 7493 (I-JSON)
