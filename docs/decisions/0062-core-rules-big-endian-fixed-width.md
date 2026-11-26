<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0062. Core rules: big-endian, fixed-width binary conventions

- **Status:** Proposed
- **Date:** 2026-11-25

## Context

[0013](0013-abnf-for-protocols-and-calls.md), rule 4 asks for a small set of ASPIS core rules: fixed-width integers, 32-octet IDs and length-prefixed fields, with normative constraint comments. It left integer byte order to the design session, and listed only unsigned integers. The [design backlog, D11](../design/design-backlog.md#m2-kernel-objects) asks for the byte order, and whether the core rules define signed integers. POSIX's `off_t`, for one, is signed.

IDs are big-endian octet strings that compare bytewise ([0001](0001-object-identifiers.md)), and the research notes propose big-endian everywhere, so that byte order is sort order ([research notes §5](../research/aegis-domain-os.md#5-implications-for-aspis)). XDR and most IETF protocols do the same. The initial image and the boot information are little-endian because they aren't messages ([0037](0037-initial-image-format-and-contents.md), rule 1; [0041](0041-boot-abi.md), rule 2), and so don't fix the byte order of messages.

On 2026-11-25 the project owner decided that messages are big-endian and signed integers are two's complement. The owner also accepted two defaults that Claude proposed with these records: u32 lengths and counts, and an in-place edit of ADR 0013, rule 4. The pull request that proposes this record makes that edit: rule 4's first bullet now lists the core rules defined here, and its third bullet states the byte order (rule 2) instead of calling it open. The same pull request corrects [0037](0037-initial-image-format-and-contents.md), rule 1, which cited the open item.

This record states decisions and invariants. The grammar, tables and vector format are in the call-language specification's [Core rules](../design/call-language.md#core-rules). Claude drafted this record from the owner's decisions.

## Decision

1. **Notation.** Grammars are RFC 5234 ABNF (STD 68), as updated by RFC 7405, in RFC 5234's binary-octet external encoding (section 2.4): each terminal value is one octet. RFC 5234's `BIT` rule is never used for binary data.
2. **Byte order and signed integers.**
   - Every multi-octet integer in an ASPIS message is big-endian: the most significant octet comes first.
   - Signed integers are two's complement.
   - IDs stay big-endian octet strings ([0001](0001-object-identifiers.md)).
   - A field used as a sort or index key, such as an authorization-tree key or a sequence number, is unsigned.
   - No ASPIS message uses a variable-length integer.
3. **The core rules.** C06 commits them as `grammars/core.abnf` ([The core grammar](../design/call-language.md#the-core-grammar)). They define:
   - `u8` to `u64` and `i8` to `i64`. Every width divides a 64-bit word. A 16-octet value, such as a UUID or a request ID, is an octet string, not an integer;
   - `f32`, `f64` (rule 5) and `bool`, which is `%x00` or `%x01` and nothing else;
   - `object-id`, which accepts any version octet, `object-id-v1`, and `uuid`;
   - lengths, counts, byte strings, text and presence (rules 4 and 6);
   - the shapes of struct tails, union arm tags and capability references, whose meaning [0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rules 9 and 10 and [0066](0066-capability-parameters-and-server-streams.md), rule 2 give.

   **Each value has exactly one encoding.** A decoder rejects every other octet string as malformed, so an accepted message re-encodes to the same octets. Core rule names are reserved in every letter case. Core rules may be added; an existing one never changes its meaning.
4. **Text.** Text is UTF-8 as RFC 3629 defines it, without U+0000, so a C binding can end a string with NUL. No Unicode normalization is applied or checked: strings compare octet by octet. A length counts octets, not characters. The UTF-8 rules are ASPIS's own ABNF, written from RFC 3629's definition, not copied from it.
5. **Floats.** `f32` and `f64` are IEEE 754-2019 binary32 and binary64, most significant octet first. Every NaN is encoded as the canonical quiet NaN, and a decoder rejects any other NaN ([What the core rules define](../design/call-language.md#what-the-core-rules-define)). Positive and negative zero are distinct, valid values. **Departure:** the D11 research had decoders accept any bit pattern, which gives one value several encodings (rule 3).
6. **Lengths, counts and optional values.**
   - Every length and count in a value encoding is a u32: a byte string's or text's octet length, a sequence's element count, a struct tail's field count. So are a stream batch's entry count and a pull's `max_items`.
   - The call header's fixed fields have the widths that [0064](0064-the-call-header-and-wire-encoding.md) and the specification give, such as the one-octet header-word and extension word counts, the u64 spill length, and the QUIC frame's capability count, a closed code from 0 to 3 ([The call-header grammar](../design/call-language.md#the-call-header-grammar)).
   - A sequence is its count, then its elements.
   - Every byte string, text and sequence has a declared maximum in the IDL ([0067](0067-the-aspis-idl.md), rule 3), written as a constraint in the generated grammar. Raising a maximum never changes the wire format.
   - An optional value in an open struct is a tail field, present or omitted ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rule 9). Anywhere else it is a presence octet, `%x00` or `%x01`, then the value when present.
7. **The constraint vocabulary.** `; constraint:` comments are normative ([0013](0013-abnf-for-protocols-and-calls.md), rule 4), and a rule name in one stands for its value as an integer. Generated grammars use only the closed set of forms in [The constraint vocabulary](../design/call-language.md#the-constraint-vocabulary). Other constraint text is prose, allowed only in hand-written grammars and enforced by that format's own decoder tests. A form joins the set only with its enforcement in the checker.
8. **Checkers and vectors.** Two independent checkers run the same vector files ([Vector files](../design/call-language.md#vector-files); [Checkers](../design/call-language.md#checkers)):
   - **`tools/ci/check-grammars.py`** checks the context-free grammar. It loads the core rules for a grammar whose header says `; uses: core`, and rejects a grammar that defines a core rule name.
   - **`crates/abnf`**, C06's Rust checker, also enforces the constraint vocabulary. It is `no_std`, forbids unsafe code, has no dependencies, and bounds its time and memory, because the catalog runs it on publishers' grammars ([0027](0027-applications-extend-the-system.md), rule 2).
   - A vector can be marked as matching the context-free grammar but breaking a constraint, and can be given the capability count and mask that a body can't carry.
   - `grammars/core.vectors` covers every core rule, at its extremes and with malformed cases.
   - The two checkers are a differential pair for the fuzzing gate ([0068](0068-the-fuzzing-and-differential-testing-gate.md), rule 6).
9. **Scope.** The core rules serve every ASPIS message, every IDL-generated grammar and the canonical call text. Outside them stay:
   - the initial image and the boot information, in-memory structures with their own little-endian rules ([0037](0037-initial-image-format-and-contents.md), rule 1; [0041](0041-boot-abi.md), rule 2);
   - QUIC's variable-length integers, inside QUIC's framing ([0020](0020-realm-certificate-authority.md), rule 3);
   - TLS, X.509, PKCS #10 and CMS, with their own notations ([0013](0013-abnf-for-protocols-and-calls.md), rule 2).

## Consequences

- Unsigned fields, IDs included, sort and compare bytewise, with no decoding.
- ASPIS's targets are little-endian AArch64, so generated bindings byte-swap each multi-octet field, one `REV` instruction each. The kernel reads no message contents ([0054](0054-ipc-endpoints.md), rule 4). It writes the bodies of the messages it sends (faults, page and memory requests) big-endian, and copies all other messages without swapping them.
- One encoding per value lets reply caches and signatures compare octets, and lets the fuzzing gate require exact re-encoding ([0068](0068-the-fuzzing-and-differential-testing-gate.md), rule 5).
- A bridge to NDR or SSH, which accept any nonzero boolean, normalizes values before encoding them.
- Fixed widths cost octets on small values, and in return each field's offset is known without parsing.
- Both items D11 asks are decided, in rule 2. Two adjacent questions stay open in the specification: [L22](../design/call-language.md#l22-the-constraint-vocabularys-grammar-and-the-rust-checker), the vocabulary's own ABNF and the Rust checker's design (C06); and [L34](../design/call-language.md#l34-wall-clock-times-in-messages), the unit and sign of wall-clock times in messages (the time service, C34).

## References

- [RFC 5234, ABNF](https://www.rfc-editor.org/rfc/rfc5234) (STD 68), and [RFC 7405, Case-Sensitive String Support in ABNF](https://www.rfc-editor.org/rfc/rfc7405), which updates it
- [RFC 3629, UTF-8](https://www.rfc-editor.org/rfc/rfc3629) (STD 63)
- [IEEE 754-2019, Floating-Point Arithmetic](https://standards.ieee.org/ieee/754/6210/); ISO/IEC 60559:2020 is technically identical
- [RFC 4506, XDR](https://www.rfc-editor.org/rfc/rfc4506) (STD 67)
- [RFC 9000, QUIC](https://www.rfc-editor.org/rfc/rfc9000), section 16
- [The call-language specification: Core rules](../design/call-language.md#core-rules)
