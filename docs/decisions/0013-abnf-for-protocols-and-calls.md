<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0013. ABNF for protocols, formats, and every RPC and IPC call

- **Status:** Accepted
- **Date:** 2026-11-24, updated 2026-11-26

## Context

The brief says protocols are described using ABNF where necessary, and that ABNF also describes the RPC and IPC calls.

The project owner added rule 7 on 2026-11-26, so that a query or filter language never becomes a parser of its own at a trust boundary of ASPIS's own interfaces.

ABNF is the IETF's grammar notation: RFC 5234, extended by RFC 7405 for case-sensitive strings. It is context-free and works on octets. It can describe binary layouts with `%x` values and repetition counts such as `32OCTET`. It can't, however, tie a length field to the number of octets that follow, and it has no notion of types.

## Decision

1. **ABNF is ASPIS's normative grammar notation.** Specifications use RFC 5234 ABNF, plus RFC 7405 for case-sensitive strings.
2. **Scope.** ABNF describes:
   - every RPC and IPC call: the message header, each method's request and reply, and error replies, except the private system-call ABI between the kernel and its interface library ([0059](0059-the-kernel-interface-library.md), rule 2);
   - every network protocol message;
   - every machine-read text format, including:
     - the object ID text form ([0001](0001-object-identifiers.md));
     - names and paths;
     - token claim values ([0015](0015-jwt-tokens-and-oidc-identity.md));
     - configuration files.

   TLS, QUIC, X.509, PKCS #10 and CMS keep their own normative notations. ABNF covers what ASPIS defines within them: identity URIs, the ALPN identifier and every RPC message ([0020](0020-realm-certificate-authority.md)).

   ABNF doesn't describe the language of the command interpreter that people use, dm's command language included. That language is designed with the interpreter, and that design chooses how it is specified ([0031](0031-abnf-is-not-a-command-language.md)).
3. **Source of truth.**
   - Interfaces are written in the ASPIS IDL, which carries types, versions ([0014](0014-versioned-object-apis.md)) and method numbers.
   - The IDL compiler generates each interface's ABNF. The generated grammar is published with the interface and is normative for the wire format. For the `[kernel]` interfaces that programs reach through the kernel interface library, which have no wire form, it defines the canonical text form of their calls (rule 5; [0059](0059-the-kernel-interface-library.md), rule 1). The interfaces the kernel calls keep wire grammars ([0059](0059-the-kernel-interface-library.md), rule 2).
   - Conformance tests check real messages against it, or, for the `[kernel]` interfaces, text renderings of their calls.
4. **Binary conventions.**
   - A small set of ASPIS core rules defines fixed-width integers, unsigned and signed; IEEE 754 floating-point numbers; booleans; IDs (32 octets); UTF-8 text; and length-prefixed fields ([0062](0062-core-rules-big-endian-fixed-width.md), rule 3).
   - Where a length field governs what follows, the rule carries a normative constraint comment, as IMAP does for literals, and the conformance tooling enforces it.
   - Integers in messages are big-endian, and signed integers are two's complement ([0062](0062-core-rules-big-endian-fixed-width.md), rule 2). IDs stay big-endian octet strings ([0001](0001-object-identifiers.md)).
5. **Canonical text form of calls.** Every call also has a text rendering, defined in ABNF, for logs, traces and token scopes. It is machine-facing: it is not the syntax people type at the command line ([0031](0031-abnf-is-not-a-command-language.md)).
6. **Grammars are machine-checked.** CI parses every grammar and runs its test vectors. A grammar that doesn't parse, or doesn't match its vectors, fails the build.
7. **In ASPIS's interfaces, queries and filters are values, not languages.**
   - A query or filter that selects data, in an interface that ASPIS defines, is an IDL value, such as a union of the ways to select, and the interface's generated decoder reads it. No ASPIS server parses a string in a query or filter language of its own.
   - Its text forms are those of the call that carries it: the canonical text (rule 5) and the JSON mapping ([0067](0067-the-aspis-idl.md), rule 8).
   - Where people write queries, the tool they use translates its own syntax into the value before it sends it ([0031](0031-abnf-is-not-a-command-language.md), rule 2).
   - Names, paths, action patterns and token claim values are machine-read formats (rule 2), not query languages.
   - A protocol or language that ASPIS takes from an outside standard keeps its own syntax, such as AuthZEN search ([0019](0019-authzen-decision-protocol.md)) and Cedar policies ([0018](0018-cedar-policy-language.md)). Its parser is a trust-boundary parser ([0068](0068-the-fuzzing-and-differential-testing-gate.md), rule 1).
   - The rule binds ASPIS's own interfaces. An application, or a service installed later, such as a database, keeps its own query language ([0027](0027-applications-extend-the-system.md)).
   - The kernel interprets no query, filter or program language, following seL4 ([0047](0047-the-kernel-follows-sel4.md), rule 1).

An illustrative example, written before the call header was designed (not normative; [0064](0064-the-call-header-and-wire-encoding.md) defines the header):

```abnf
call-request = call-header method-args
call-header  = %x01 request-id object-id interface-id version method
request-id   = 16OCTET   ; unique per caller, for at-most-once execution (0004)
object-id    = 32OCTET   ; layout per 0001
interface-id = 32OCTET   ; an interface is itself an object (0014)
version      = major minor
major        = 2OCTET    ; unsigned
minor        = 2OCTET    ; unsigned
method       = 2OCTET    ; stable within a major version
method-args  = *OCTET    ; generated per method from the IDL

bytes        = length *OCTET
length       = 4OCTET    ; constraint: exactly `length` octets follow
```

## Consequences

- Every message ASPIS defines has a precise, language-neutral description that other implementations can be built from (rule 2).
- ABNF can't express types or length dependencies by itself. The IDL and the constraint comments fill those gaps.
- The project needs tooling: an IDL compiler that emits ABNF, an ABNF checker, and conformance tests.
- Queries and filters in ASPIS's interfaces need no parsers of their own. Their decoders are generated, and fuzzed with their interface ([0068](0068-the-fuzzing-and-differential-testing-gate.md), rule 4). A filter syntax that people type belongs to the tool that offers it (rule 7).

## References

- [RFC 5234, Augmented BNF for Syntax Specifications: ABNF](https://www.rfc-editor.org/rfc/rfc5234)
- [RFC 7405, Case-Sensitive String Support in ABNF](https://www.rfc-editor.org/rfc/rfc7405)
