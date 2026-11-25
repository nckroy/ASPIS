<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->

# 0031. ABNF specifies protocols and formats, not the command interpreter

- **Status:** Proposed. Would amend [0013](0013-abnf-for-protocols-and-calls.md) (rules 2 and 5).
- **Date:** 2026-11-24

## Context

[0013](0013-abnf-for-protocols-and-calls.md) makes ABNF the normative grammar notation for ASPIS's protocols, messages and text formats. Two of its rules also reach into the language people type:

- Rule 2 lists "the dm command language" among the text formats ABNF describes.
- Rule 5 gives every call a canonical text form, defined in ABNF, "for logs, traces, token scopes and the command line".

The command interpreter that users work in is still to be designed. That includes dm's command language, which [0011](0011-dm-window-system.md) rule 6 leaves to the design session. Nicole decided on 2026-11-24 that ABNF is a protocol specification metalanguage, and is not appropriate for a user-facing command interpreter. Rules 1 to 3 below record that decision; their exact wording is proposed.

## Decision

1. **ABNF is for what machines exchange and read:** protocols, messages, calls and machine-read formats such as the object ID text form, token claim values, configuration files and the kernel's arguments. It is not the language of the command interpreter that people use.
2. **0013 rule 2 no longer lists the dm command language.** The command interpreter's language, dm's command language included, is designed with the interpreter. That design chooses how the language is specified.
3. **The canonical text form of calls is machine-facing.** It serves logs, traces and token scopes ([0013](0013-abnf-for-protocols-and-calls.md), rule 5). It is not the syntax people type at the command line.

## Consequences

- The command interpreter is a design question of its own: whether there is a native interpreter besides dm's commands and the POSIX shell ([0012](0012-posix-compatibility-layer.md)), what its language looks like, and how it is specified.
- Nothing else in 0013 changes. Every RPC and IPC call, every protocol message and every machine-read format keeps its normative ABNF grammar.
- **Amends [0013](0013-abnf-for-protocols-and-calls.md), once accepted.**
  - Rule 2: "the dm command language" leaves the list of text formats ABNF describes.
  - Rule 5: the canonical text form serves logs, traces and token scopes; "the command line" is dropped.

## References

- [0011, dm](0011-dm-window-system.md), rule 6
- [0013, ABNF for protocols, formats, and every RPC and IPC call](0013-abnf-for-protocols-and-calls.md), rules 2 and 5
- [RFC 5234, Augmented BNF for Syntax Specifications: ABNF](https://www.rfc-editor.org/rfc/rfc5234)
