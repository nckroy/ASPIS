<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0013. ABNF for protocols, formats, and every RPC and IPC call

- **Status:** Accepted. Amended by [0020](0020-realm-certificate-authority.md) (rule 2) and [0031](0031-abnf-is-not-a-command-language.md) (rules 2 and 5).
- **Date:** 2026-11-24

## Context

The brief says protocols are described using ABNF where necessary, and that ABNF also describes the RPC and IPC calls.

ABNF is the IETF's grammar notation: RFC 5234, extended by RFC 7405 for case-sensitive strings. It is context-free and works on octets. It can describe binary layouts with `%x` values and repetition counts such as `32OCTET`. It can't, however, tie a length field to the number of octets that follow, and it has no notion of types.

## Decision

1. **ABNF is ASPIS's normative grammar notation.** Specifications use RFC 5234 ABNF, plus RFC 7405 for case-sensitive strings.
2. **Scope.** ABNF describes:
   - every RPC and IPC call: the message header, each method's request and reply, and error replies;
   - every network protocol message, including the secure transport's handshake ([0003](0003-hybrid-post-quantum-cryptography.md));
   - every text format, including:
     - the object ID text form ([0001](0001-object-identifiers.md));
     - names and paths;
     - token claim values ([0015](0015-jwt-tokens-and-oidc-identity.md));
     - the dm command language;
     - configuration files.
3. **Source of truth.**
   - Interfaces are written in the ASPIS IDL, which carries types, versions ([0014](0014-versioned-object-apis.md)) and method numbers.
   - The IDL compiler generates each interface's ABNF. The generated grammar is published with the interface and is normative for the wire format.
   - Conformance tests check real messages against it.
4. **Binary conventions.**
   - A small set of ASPIS core rules defines fixed-width unsigned integers, IDs (32 octets) and length-prefixed fields.
   - Where a length field governs what follows, the rule carries a normative constraint comment, as IMAP does for literals, and the conformance tooling enforces it.
   - Integer byte order is a design-session item. IDs stay big-endian octet strings ([0001](0001-object-identifiers.md)).
5. **Canonical text form of calls.** Every call also has a text rendering, defined in ABNF, for logs, traces, token scopes and the command line.
6. **Grammars are machine-checked.** CI parses every grammar and runs its test vectors. A grammar that doesn't parse, or doesn't match its vectors, fails the build.

An illustrative example (not normative):

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

- Every message in the system has a precise, language-neutral description that other implementations can be built from.
- ABNF can't express types or length dependencies by itself. The IDL and the constraint comments fill those gaps.
- The project needs tooling: an IDL compiler that emits ABNF, an ABNF checker, and conformance tests.

## References

- [RFC 5234, Augmented BNF for Syntax Specifications: ABNF](https://www.rfc-editor.org/rfc/rfc5234)
- [RFC 7405, Case-Sensitive String Support in ABNF](https://www.rfc-editor.org/rfc/rfc7405)
