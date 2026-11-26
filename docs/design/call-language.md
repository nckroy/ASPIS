<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# The call language

*2026-11-25. The call-language specification: the grammars, octet layouts, tables and worked examples behind the M2 call-language records. It follows ADRs 0062 to 0068.*

This note is the detail that the call-language records cite. The records say what is decided, what is guaranteed, and why. This note says exactly how: every octet layout, grammar, constraint, table and worked example.

- **The records.** [0062](../decisions/0062-core-rules-big-endian-fixed-width.md) settles the core rules (D11), [0063](../decisions/0063-names-and-the-canonical-call-text.md) names and the canonical call text (D12), [0064](../decisions/0064-the-call-header-and-wire-encoding.md) the call header and the wire encoding (D25), [0065](../decisions/0065-typed-errors-and-minor-versions-on-the-wire.md) typed errors and minor versions on the wire (D26), [0066](../decisions/0066-capability-parameters-and-server-streams.md) capability parameters and server streams (D27), [0067](../decisions/0067-the-aspis-idl.md) the ASPIS IDL (D28), and [0068](../decisions/0068-the-fuzzing-and-differential-testing-gate.md) the fuzzing and differential-testing gate (D32).
- **The records win.** If a section here and a record disagree, the record is right and the section is wrong.
- **It changes with the build.** C06, C07, C18, C29 and C71 build what this note describes. A detail here may change with them, as long as every record's rules still hold. A change that would break a rule is an edit to that record, proposed in the pull request that needs it.
- **Open questions are numbered.** Each is listed once, as L01, L02, …, under [Open questions](#open-questions) at the end, and the sections link to them.
- **The records are accepted.** The project owner accepted ADRs 0062 to 0068 on 2026-11-25. The pull request that proposed them also edited four accepted rules in place: [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 4 (with 0062), [0014](../decisions/0014-versioned-object-apis.md), rule 3 (with 0065), and [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 1 and [0002](../decisions/0002-capability-security-model.md), rule 5 (with 0066). It also corrected the citation in [0037](../decisions/0037-initial-image-format-and-contents.md), rule 1, which called the byte order of messages open.

**Conventions.** An octet is 8 bits. Every integer on the wire is big-endian. `%xHH` is one octet. Grammar blocks are RFC 5234 ABNF, with RFC 7405's `%s"..."` for case-sensitive literals. A message is an octet string, held in memory in octet order. A word is eight consecutive octets of a message, starting at a multiple of 8. On kernel IPC the first four words travel in registers, each loaded as the big-endian reading of its octets ([Octets and words](#octets-and-words)).

The sections follow the order of the records: the core rules, names and the call text, the call header, typed errors, evolution on the wire, capability parameters and streams, the IDL, and the fuzzing gate.

## Core rules

[0062](../decisions/0062-core-rules-big-endian-fixed-width.md) settles these. C06 builds them.

### Notation and byte order

- **Notation.** RFC 5234 (STD 68), as updated by RFC 7405, in RFC 5234 §2.4's binary-octet external encoding: one terminal value is one octet. The RFC 5234 core rule `BIT` is never used for binary data. Nothing newer than RFC 5234 and RFC 7405 exists (checked 2026-11-25).
- **Byte order.** Every multi-octet integer in an ASPIS message is big-endian: the most significant octet comes first. Signed integers are two's complement. IDs stay big-endian octet strings ([0001](../decisions/0001-object-identifiers.md)). This settles the item that [0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 4 left to the design session, and ADR 0013, rule 4 is edited to match in the same pull request.
- **Scope.** The core rules serve every ASPIS message, every IDL-generated grammar and the canonical text. The initial image and the boot information keep their own little-endian rules (`u16le`, `u32le`, `u64le`), because they are in-memory structures, not messages ([0037](../decisions/0037-initial-image-format-and-contents.md), rule 1; [0041](../decisions/0041-boot-abi.md), rule 2). QUIC's own variable-length integers stay inside QUIC's framing ([0020](../decisions/0020-realm-certificate-authority.md), rule 3). No ASPIS message uses a variable-length integer.
- **Only unsigned fields are keys.** Two's-complement values don't sort bytewise. A field used as a sort or index key, such as an authorization-tree key or a sequence number, is unsigned.

### The core grammar

C06 commits this file as `grammars/core.abnf`. A grammar that uses the core rules says so on a header line, `; uses: core` ([Checkers](#checkers)). C06 committed it unchanged, and `cargo xtask grammars` checks that the file and the block below stay the same, octet for octet. `grammars/core.vectors` holds its vectors ([Vector files](#vector-files)).

The UTF-8 rules are ASPIS's own text, written from RFC 3629's definition rather than copied from section 4 of the RFC. So the file carries only ASPIS's SPDX tags and needs no REUSE snippet. RFC 3629 (2003) predates the IETF Trust's code-component license (RFC 5378), so copying its ABNF would raise a licensing question. RFC 5234's own core rules (`OCTET`, `DIGIT`, `SP`) are referenced, not copied.

```abnf
; SPDX-FileCopyrightText: 2026 Nicole Roy
; SPDX-License-Identifier: MPL-2.0
;
; ASPIS core rules (ADR 0062).
;
; Notation: RFC 5234 ABNF, updated by RFC 7405, in the binary-octet
; external encoding (RFC 5234, section 2.4): each terminal value is
; one octet. Integers are big-endian: the most significant octet comes
; first. Signed integers are two's complement.
;
; Comments marked "constraint:" are normative (ADR 0013, rule 4) and
; use only the forms ADR 0062 lists. In a constraint, a rule name stands
; for its value as an integer, read as the core type the rule is.
; Every name in this file is reserved: no other grammar may define it,
; in any letter case.

; ---- Integers ----------------------------------------------------
u8          = OCTET              ; 0 .. 255
u16         = 2OCTET             ; 0 .. 65535
u32         = 4OCTET             ; 0 .. 2^32 - 1
u64         = 8OCTET             ; 0 .. 2^64 - 1
i8          = OCTET              ; -128 .. 127, two's complement
i16         = 2OCTET             ; two's complement
i32         = 4OCTET             ; two's complement
i64         = 8OCTET             ; two's complement

; ---- Floating point: IEEE 754-2019, most significant octet first --
f32         = 4OCTET             ; binary32
              ; constraint: canonical float
f64         = 8OCTET             ; binary64
              ; constraint: canonical float

; ---- Booleans ----------------------------------------------------
bool        = %x00 / %x01        ; false / true; no other value

; ---- IDs (ADR 0001) ----------------------------------------------
object-id    = id-authority id-sequence id-version id-class id-random
id-authority = 16OCTET           ; UUID of the minting authority (0001, rule 3)
id-sequence  = 8OCTET            ; unsigned
id-version   = OCTET             ; 1 is defined; others pass through
id-class     = 2OCTET            ; unsigned; the registry is D34's
id-random    = 5OCTET
object-id-v1 = id-authority id-sequence %x01 id-class id-random
uuid         = 16OCTET           ; RFC 9562 octet order

; ---- Lengths, counts and presence ---------------------------------
len32       = 4OCTET             ; a length in octets, unsigned
count32     = 4OCTET             ; a count of elements, unsigned
octets      = len32 *OCTET
              ; constraint: exactly len32 octets
text        = len32 *text-char
              ; constraint: exactly len32 octets
presence    = %x00 / %x01        ; absent / present

; ---- Struct tails (ADR 0065) ---------------------------------------
; A generic tail, for a struct with no required fields and no optional
; field known to the reader. Generated grammars build each struct's own
; tail from tail-count, tag and octets, and bound its unknown tags
; (ADR 0065).
tail        = tail-count *tail-field
              ; constraint: ascending tags
              ; constraint: exactly tail-count tail-field elements
tail-count  = 4OCTET
              ; constraint: at most 65535
tail-field  = tag octets
tag         = 2OCTET
              ; constraint: not 0

; ---- Unions (ADR 0065) ---------------------------------------------
arm-tag     = 2OCTET
              ; constraint: not 0

; ---- Capability references (ADR 0066) ------------------------------
cap-ref     = %x00-02
              ; constraint: capability index

; ---- Text: UTF-8 without U+0000 (ADR 0062) --------------------------
; UTF-8 as RFC 3629 defines it, written out here: no overlong forms,
; no surrogates, nothing above U+10FFFF.
text-char   = %x01-7F / utf8-2 / utf8-3 / utf8-4
utf8-2      = %xC2-DF utf8-tail
utf8-3      = %xE0 %xA0-BF utf8-tail / %xE1-EC 2utf8-tail
            / %xED %x80-9F utf8-tail / %xEE-EF 2utf8-tail
utf8-4      = %xF0 %x90-BF 2utf8-tail / %xF1-F3 3utf8-tail
            / %xF4 %x80-8F 2utf8-tail
utf8-tail   = %x80-BF
```

### What the core rules define

- **Every width divides a 64-bit word.** There is no `u24` and no 128-bit integer. Either can be added later as a new core rule without breaking anything.
- **16-octet values are octet strings**, not integers: `uuid`, and request IDs. Nothing does arithmetic on them.
- **`object-id` accepts any version octet**, so an ID of a later version parses and compares bytewise. `object-id-v1` is for the places that need exactly version 1.
- **Booleans are strict.** Any octet other than `%x00` or `%x01` is malformed. NDR and SSH treat any nonzero octet as true. ASPIS doesn't, so each value has one encoding.
- **Floats.** `f32` and `f64` are IEEE 754-2019 binary32 and binary64. ISO/IEC 60559:2020 is technically identical. Encoders write every NaN as the canonical quiet NaN: `7FC00000` for `f32`, `7FF8000000000000` for `f64`. A decoder rejects any other NaN pattern as malformed. That keeps one encoding per value: every accepted message re-encodes to the same octets, which the fuzzing gate checks ([The gate for each target](#the-gate-for-each-target), item 2), and reply caches and signatures compare octets. Positive and negative zero are distinct values, and both are valid.
- **Text.** UTF-8 as RFC 3629 defines it, without U+0000, so a C binding can end a string with NUL. No Unicode normalization is applied or checked: strings compare octet by octet. The names that need one spelling ([Names and the canonical call text](#names-and-the-canonical-call-text)) are ASCII only, so they need none. A length counts octets, not characters.
- **Sequences** are a `count32` element count followed by the elements. Element types are fixed-size or self-delimiting ([Types](#types)), so no octet length is needed.
- **Byte strings and text** carry an octet length, `len32`. Every one of them has a declared maximum in the IDL, written as a constraint in the generated grammar.
- **One width for every length and count in a value encoding: u32.** That covers sequences, byte strings, text and struct tails' field counts, and also stream batches' entry counts and a pull's `max_items`. Raising a maximum never changes the wire format. The call header's fixed fields have their own widths ([The call-header grammar](#the-call-header-grammar)): the one-octet header-words count and extension word counts, the u64 spill offset and length, the u64 count of a `lost` stream entry, and the QUIC frame's capability count, one octet from 0 to 3, which is a closed code rather than a count that can grow ([QUIC framing](#quic-framing)).
- **Optional values have two encodings.** As a field of an open struct, an optional value is a tail field, present or omitted ([The struct encoding](#the-struct-encoding)). Anywhere else (a closed struct, a sequence element, a union arm) it is `presence`, followed by the value when present.

### The constraint vocabulary

`; constraint:` comments keep the convention of `grammars/initfs.abnf`. They are normative, and a rule name stands for its value as an integer (or, for a decimal text rule, the number it spells). Generated grammars use only the forms below, which C06's checker enforces. Any other constraint text is prose. Prose is allowed only in hand-written grammars, and that format's own decoder tests enforce it, as `crates/initfs` does today. The vocabulary's own ABNF is `grammars/constraint.abnf`, with vectors in `grammars/constraint.vectors` ([L22](#l22-the-constraint-vocabularys-grammar-and-the-rust-checker)). Several forms act on the rule's *target*, and [How constraints bind](#how-constraints-bind) says exactly what each form reads.

| Form | Meaning |
|---|---|
| `exactly R octets` | The rule's target holds exactly R octets. |
| `exactly R E elements` | The target holds exactly R matches of rule E. |
| `exactly R words` | The target holds exactly 8 × R octets. |
| `header words R` | The target ends exactly 8 × R octets after the rule's first octet. For a message rule, that is the message's first octet, so R is the number of 8-octet words through the end of its last header extension ([Word 0](#word-0)). |
| `at most N`, `at least N`, `in N..M`, `not N` | Bounds on the rule's integer value. N and M are decimal, and may be negative for signed rules. |
| `not one of N, M, ...` | The value is none of the listed integers. |
| `length at most N` | The whole match is at most N octets. |
| `not word W1 W2 ...` | The match, as ASCII text, is none of the listed words. |
| `ascending R` | Successive matches of R inside the target strictly increase. A match of R counts for the innermost such target open around it. |
| `ascending tags` | In the target, the first two octets of each element, read as a u16, strictly increase. Generated tails use it, because their known fields begin with literal tags ([The struct encoding](#the-struct-encoding)). |
| `capability index` | The value is less than the message's capability count, and the indexes appear in ascending order, each exactly once ([Capability indexes](#capability-indexes)). The count is out of band: the kernel's message info, or the frame's descriptor table. In a vector file it comes from the `# caps:` directive. A core rule's match is a fragment of a body, so a vector that tests one checks only the range and repeats. |
| `canonical float` | A NaN is the canonical quiet NaN. |
| `remaining octets` | The target takes every octet left in the message, as framed by [the call header](#the-call-header-and-wire-encoding): up to the end of the innermost enclosing match bounded by `exactly R octets` or `exactly R words`, or else to the end of the input. |

### How constraints bind

C06 settled these rules ([L22](#l22-the-constraint-vocabularys-grammar-and-the-rust-checker)). The Rust checker enforces them, and generated decoders follow them.

- **Attachment.** A `; constraint:` comment belongs to the rule whose text holds it: the rule's own lines and its indented continuation lines. A constraint comment outside every rule, at column 0 between rules or after a blank line, is an error. A comment is a constraint comment when its text, after the `;` and any spaces or tabs, starts with `constraint:`, in that case. The constraint is the rest of the line after one or more spaces, without trailing spaces or tabs.
- **Strictness.** `core.abnf`, every grammar that uses it (directly or through another grammar), and every grammar the catalog checks are strict: they hold no prose constraint and no prose-val (`<...>`). Other hand-written grammars, such as `initfs.abnf`, may hold both. The checker counts prose constraints and doesn't enforce them. A prose-val whose text is exactly a rule name, such as `<b>`, names that rule, as RFC 5234 section 2.1 allows and abnf 2.9.1 reads it. Any other prose-val matches nothing, as in abnf 2.9.1. A vocabulary form is enforced in every grammar, strict or not.
- **The target.** Seven forms act on the rule's target: `exactly R octets`, `exactly R E elements`, `exactly R words`, `header words R`, `ascending R`, `ascending tags` and `remaining octets`.
  - The rule's definition, after every `=/`, must be one concatenation. One element counts as a concatenation of one.
  - The target is the first element of that concatenation with a variable repeat: `*`, `n*`, `*m`, or `n*m` with n below m. A fixed count, such as `16OCTET`, and an option `[ ]` don't count.
  - With no such element, the target is the rule's whole match. That is allowed for `exactly R octets`, `exactly R words`, `header words R` and `remaining octets`, as the call header's `frame-rest` uses it. `exactly R E elements` and both `ascending` forms need a repetition, and `exactly R E elements` needs it to repeat rule E itself.
  - Several forms on one target apply together, as `tail`'s two do. A count outside the repetition's own bounds matches nothing.
- **Which match R is.** R stands for its latest match among the constrained rule's own elements so far, at any depth of the rule's own definition, but not inside other rules. If the rule hasn't matched R, the rule that called it is searched, at the point of the call, and so on outward. So `cap-table` finds `frame-rest`'s `cap-count`, and a `len32` inside an earlier field's `octets` is never found. If no rule has matched R, the form fails.
- **How a value reads.** Each rule's reading is fixed when the grammar loads.
  - A rule that is `i8` to `i64`, or is defined as just one of them, reads as two's complement.
  - A rule whose every octet is an ASCII digit reads as the decimal number it spells.
  - Any other rule must have a fixed width of 1 to 16 octets, and reads as an unsigned big-endian integer. So `trace-id`'s `not 0` covers all 16 octets.
  - A rule with no reading can't be R, or carry a value form. A negative bound needs a signed rule, and `in N..M` needs N ≤ M. These are load errors.
  - Every form reads big-endian, so a little-endian grammar such as `initfs.abnf` writes its constraints as prose.
- **Values that fit nothing.** A decimal above 2^64 - 1 is greater than every bound. An empty match has no value, so a form that reads it fails. A negative R, or one larger than the input, holds no octets, words or elements, so its form matches nothing.
- **Framing.** `exactly R octets` and `exactly R words` frame a message: inside the span they bound, `remaining octets` ends where the span ends. `header words R` bounds the header but frames nothing.
- **Capabilities.** In a vector of a core rule, `capability index` checks each index's range and repeats only, since a core rule is a fragment of a body. In a vector of any other rule, the indexes must appear in ascending order, each once, and every index below the count must appear ([Capability indexes](#capability-indexes)).

### Vector files

`grammars/core.vectors` uses the format of today's vector files: `ok` or `err`, an optional `@rule`, a tab, then the octets with C escapes and `\xHH`; and the `# rule:` and `# max-length:` directives. [0062](../decisions/0062-core-rules-big-endian-fixed-width.md), rule 8 adds two things.

- **The tag `errc`** marks a vector that matches the context-free grammar but breaks a constraint. The context-free checker treats `errc` as `ok`, and the constraint checker treats it as `err`, so each such vector tests both.
- **The directives `# caps: N`** (0 to 3) **and `# unwrapped: M`** (a 3-bit mask, in hex) give the capability count and the unwrapped mask that the following lines are checked against, until the next such directive. They stand in for the kernel's message info or the frame's descriptor table, which a vector line can't carry, since it holds only body octets. Without them the count is 0.
- **Positions and repeats.** `# caps:` resets the unwrapped mask to 0. `# unwrapped:` is one hex digit whose bits are below the count. A position delivered unwrapped still has its index, so neither checker judges by the mask; generated bindings' conformance tests do. `# rule:` and `# max-length:` hold for the whole file, and each appears at most once. `# rule:` is needed only when some line has no `@rule`.
- **Strict lines.** Every vector line has its tab, even with an empty body. A `#` line that names one of the four directives must be exactly `# keyword: value`. A file holds no CR; a vector writes one as `\x0d`.
- **`max-length` belongs to the context-free judgment**, so an `errc` vector is within it too.
- **No spaced-hex form.** `\xHH` stays the only escape, so the two readers stay the same ([L22](#l22-the-constraint-vocabularys-grammar-and-the-rust-checker)).

The core vectors cover at least:

- every integer rule at its extremes, and a truncated value (`err`);
- `bool` with `%x02` and `%xFF` (`err`);
- `object-id` with version `%x01` and `%x07` (`ok`), and `object-id-v1` with `%x07` (`err`);
- `text`: plain ASCII; a 4-octet code point; U+0000 (`err`); the overlong `%xC0 %x80` (`err`); the surrogate `%xED %xA0 %x80` (`err`); a length longer than the octets (`errc`);
- `f32` and `f64`: the canonical NaN (`ok`), another NaN payload (`errc`), both zeros (`ok`);
- `tail`: an empty tail, `%x00.00.00.00`; two fields in order (`ok`); out of order, duplicated, or tag 0 (`errc`); a count of 65,536 (`errc`);
- `octets` with a length that disagrees (`errc`);
- `cap-ref`: under `# caps: 2`, index 0 and index 1, each alone (`ok` as rule matches); under `# caps: 1`, index 1 (`errc`); index 3 (`err`, since the grammar can't match it).

Whole-message capability vectors (a repeated index, an index no capability fills, a capability no index names) live in the generated grammars' files ([Evolution vectors](#evolution-vectors)).

### Checkers

- **`tools/ci/check-grammars.py`**, changed by C06. The `; uses:` header line takes a list of shared grammars to preload, such as `; uses: core, names`. A grammar whose header says `; uses: core` is loaded into the same rule class as `core.abnf`, so its rules resolve against the core rules. The checker rejects any grammar that defines a core rule name, in any letter case. `initfs.abnf` and `kernel-args.abnf` don't say `; uses: core`, and are unchanged. The Python checker can't bind a length to a repetition, so it checks the context-free grammar only, and treats `errc` as `ok`. It follows `; uses:` transitively, loading each grammar once, and fails on a cycle or a missing grammar. It turns abnf's redefinition warnings into failures, and fails num-vals above 255, empty ranges, and `=/` on a rule the file hasn't defined. It reads files as octets, so it treats a CR as the Rust checker does, and it checks every escape and directive.
- **C06's Rust checker**, `crates/abnf`: `#![no_std]` with `alloc`, `#![forbid(unsafe_code)]`, no dependencies, MPL-2.0. It parses ABNF, matches vectors and enforces the constraint vocabulary. It bounds its time and memory, because the catalog will run it on publishers' grammars ([0027](../decisions/0027-applications-extend-the-system.md), rule 2). It runs the same vector files, and judges `errc` as `err`.
  - It has a hand-written parser and a matcher that works on sets of states, which is exact for ABNF's ambiguity: alternatives are unioned, and nothing is committed early.
  - Its budgets cover grammar size and nesting, input size, steps (linear in the input, with a cap, and charged for constraint work too), the memory its live states hold, recursion depth, and the steps of a whole vector file ([L22](#l22-the-constraint-vocabularys-grammar-and-the-rust-checker)). A run over a budget is reported as exhausted, never as a match or a mismatch.
  - It rejects undefined rule names and left recursion when a grammar loads, and checks that every constraint can apply where it is written ([How constraints bind](#how-constraints-bind)).
  - `cargo xtask grammars` runs it over `grammars/` in CI's `docs` job, on every change, and checks that `grammars/core.abnf` is the block above, octet for octet. `cargo xtask test` runs it too.
- **Two checkers, on purpose.** The Python checker stays in CI as an independent implementation. The two are a differential pair for C71 ([Differential tests](#differential-tests)). Some grammars only the Rust checker rejects: undefined names (abnf 2.9.1 fails one only when a vector reaches it), left recursion (which abnf 2.9.1 answers wrongly), prose and prose-vals in strict grammars, misused constraints, and constraint integers out of range. On very deep input, Python's recursion limit gives a parse error where the Rust checker reports exhaustion. So the differential compares only grammars both accept, and only answers both give.
- **No spaced-hex form.** `\xHH` stays the only vector escape ([L22](#l22-the-constraint-vocabularys-grammar-and-the-rust-checker)).

## Names and the canonical call text

[0063](../decisions/0063-names-and-the-canonical-call-text.md) settles these. C07 builds them, with C06's checker.

### Interface and type names

- **One name grammar for interfaces and types.** Names are dotted, reverse-DNS, lowercase ASCII, with at least two labels ([0027](../decisions/0027-applications-extend-the-system.md), rule 7). Labels use `a-z`, digits and `_`, never `-`. Every type name is then a Cedar entity-type path, and every action string is a Cedar string and an OAuth scope-token, with no escaping.
- **Publishers transliterate DNS names the D-Bus way.** A hyphen becomes `_`. A label that starts with a digit, or that is one of Cedar's reserved words `true false if then else in is like has`, takes a leading `_`. Examples: `org.aspis_os.sql`, `org._7_zip.archive`, `_in.co.example.ledger`. (`.in`, `.is` and `.like` are real top-level domains that are also Cedar reserved words.)
- **The `aspis.` prefix is reserved** by ASPIS policy, as Fuchsia reserves `fuchsia.`. `aspis` isn't a top-level domain (IANA root zone list, version 2026112402), and no registration is needed. Where the reservation is enforced, and who owns other prefixes, is D110's ([L03](#l03-minting-application-ids-and-prefix-ownership)).
- **An interface and a type may share a name.** The discovery note's `org.example.sql.table` is both. References tell them apart, because an interface reference carries `/major`.
- **Limits.** A label is 1 to 63 octets; a name at most 255.

### Member names

- **Members are lower snake_case**: methods, fields, parameters, results, errors, enum values, union arms and action groups.
- **No two underscores in a row, and no trailing underscore.** That keeps generated rule names one to one ([Generated grammars](#generated-grammars)).
- **A few words are refused**: Cedar's reserved words, and `self`, `super` and `crate`, which Rust can't take as raw identifiers.
- **Members are frozen within a major version**, because Cedar actions, scopes and the call text use them.
- **Limit.** At most 63 octets.

### Interface references

An interface reference carries a major and an optional minor, as `aspis.catalog/1` or `aspis.catalog/1.2`. A missing minor means `.0`. Majors and minors are 0 to 65,535, to fit the `u16` fields that carry them on the wire, such as the error envelope's major.

- **In a requirement**, the minor means "this minor or later" ([0014](../decisions/0014-versioned-object-apis.md), rule 3). Requirements are a bind, a query, a manifest, an IDL `use` line and a `cap<...>` type.
- **In a registration or a catalog result**, it means "exactly this version".

### Method numbers

- **Method numbers sit beside names.** The IDL declares every method as `@n name(...)`. The wire carries the number ([Word 0](#word-0)); text forms carry the name.
- **Within a major, names and numbers are each unique**, never renamed and never reused. There is no overloading. A retired number is kept with `reserved @n;`.
- **IDL methods use 1 to 65,279** (`0x0001` to `0xFEFF`). 0 is invalid. `0xFF00` to `0xFFFF` are the call protocol's own methods ([Protocol methods](#protocol-methods)), so they never collide with an interface's.
- **The minor version is never in an action name.** The minor spoken on a session is fixed at bind ([0014](../decisions/0014-versioned-object-apis.md), rule 4), so it is logged with the bind, not with each call.

### Action groups

- **An interface declares its action groups**, and each method names the groups it belongs to ([Attributes](#attributes)).
- **A minor may add a new method to an existing group.** It may not move an existing method between groups, or remove one from a group. Whether a group that grows in a minor should widen existing grants silently is a policy question ([L11](#l11-groups-that-grow-in-a-minor)).
- **A group belongs to one major**, as `aspis.io/1/@read`. Whether policy can name a group in every major is open ([L12](#l12-cedar-schema-details)).
- **Realm actions that aren't methods**, such as `discover` ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 8), become methods of a well-known interface, such as `aspis.catalog/1/discover`. C51 and D110 confirm it.

### The names grammar

C07 commits this file as `grammars/names.abnf`. It is hand-written, and checked against C07's generator and by CI. `DIGIT` and `SP` are RFC 5234 core rules.

```abnf
; SPDX-FileCopyrightText: 2026 Nicole Roy
; SPDX-License-Identifier: MPL-2.0
;
; Names, references, action strings and the canonical call text (ADR 0063).
; Literal words use RFC 7405 %s"...": plain ABNF strings are case-insensitive.

; ---- Names --------------------------------------------------------
name          = label 1*( "." label )
                ; constraint: length at most 255
label         = lc-alpha *lchar / "_" ( lc-alpha / DIGIT ) *lchar
                ; constraint: length at most 63
                ; constraint: not word true false if then else in is like has
lchar         = lc-alpha / DIGIT / "_"
lc-alpha      = %x61-7A                       ; a-z only
interface-name = name
type-name     = name

member-name   = lc-alpha *( lc-alpha / DIGIT / "_" ( lc-alpha / DIGIT ) )
                ; no "__" and no trailing "_", so "--" never comes from a
                ; name in generated rule names (ADR 0067)
                ; constraint: length at most 63
                ; constraint: not word true false if then else in is like has self super crate

; ---- Versions and references -------------------------------------
number        = "0" / %x31-39 *4DIGIT         ; no leading zeros
                ; constraint: at most 65535
major         = number
minor         = number
interface-ref = interface-name "/" major [ "." minor ]

; ---- Actions, groups and scopes ------------------------------------
action-name   = interface-name "/" major "/" member-name    ; one method
group-name    = interface-name "/" major "/@" member-name   ; an IDL action group
all-methods   = interface-name "/" major "/*"               ; every method of the major
action-ref    = action-name / group-name / all-methods
scope-token   = action-ref                    ; the ASPIS form of an RFC 6749 scope-token

; ---- Errors ---------------------------------------------------------
error-ref     = interface-name "/" major "!" member-name
              / id-text "/" major "!#" error-code-text  ; name not known
error-code-text = number
                ; constraint: in 1..65535

; ---- Canonical call text (output only) ---------------------------------
call-text     = action-name SP target [ SP call-args ]
target        = id-text / "-"                 ; "-": a [kernel] call, named by capability (ADR 0050)
id-text       = 64hex                         ; interim; replaced by D34's object-ID text form
call-args     = json-object                   ; per method, generated (ADR 0067)
reply-text    = %s"ok" [ SP reply-results ]
              / outcome-word SP error-ref
outcome-word  = %s"refused" / %s"failed" / %s"unreachable" / %s"indeterminate"
reply-results = json-object                   ; per method, generated (ADR 0067)
request-id-text = 32hex                       ; for log records and spans, not the call text
hex           = DIGIT / %x61-66               ; 0-9 a-f, lowercase only
json-object   = <RFC 8259 object, as constrained by the IDL's JSON mapping>
```

The last rule is a placeholder. C07 generates, for each method, the exact `call-args` and `reply-results` rules, from RFC 8259's grammar and [the JSON mapping](#the-json-mapping).

Only `interface-ref`, `action-ref` and `error-ref` are ever parsed: by the PDP, the token library and the catalog. An `action-ref` is at most 326 octets.

### One string everywhere

An action name such as `aspis.catalog/1/watch` is, unchanged:

- **the Cedar action UID** `aspis::Action::"aspis.catalog/1/watch"`. Every interface version's schema fragment declares its actions as quoted strings in the one namespace `aspis`. Groups are `aspis::Action::"aspis.catalog/1/@discover"`. `all-methods` isn't declared as a Cedar group; whether a scope of `*` is expanded by the ceiling rule is D85's ([L10](#l10-scope-semantics));
- **the AuthZEN `action.name`** ([0019](../decisions/0019-authzen-decision-protocol.md), rule 4);
- **a token's scope-token.** Every character fits RFC 6749 §3.3's `scope-token`. Scopes are case-sensitive, and lowercase-only names can't differ by case. Scope semantics are D85's;
- **the OpenTelemetry span name and `rpc.method`**, with `rpc.system.name = aspis` (semantic conventions v1.45.0, RPC spans, stable);
- **the HTTPS binding's path**, as a suggestion to D116. Every character is an RFC 3986 `pchar`.

**Types in Cedar and AuthZEN.** A type name maps to a Cedar entity type by replacing each `.` with `::`: `aspis.file` becomes `aspis::file`. Entity UIDs are `aspis::file::"<id-text>"`. The AuthZEN `resource.type` is the type name verbatim. ASPIS's built-in entity types follow the same rule, such as `aspis::principal`. Only the action type, `aspis::Action`, is capitalized, so no lowercase name collides with it. The [policy note](policy-and-decisions.md)'s `Aspis::Action`, `Aspis::Principal` and AuthZEN subject type `aspis:principal` become `aspis::Action`, `aspis::principal` and `aspis.principal`. Cedar language version 4.7 (crate `cedar-policy` 4.15.0) is the reference; C31 pins it.

### The canonical call text

The canonical call text is output only. The full call text is never parsed back into a call, which keeps it from becoming a command language ([0031](../decisions/0031-abnf-is-not-a-command-language.md), rule 3).

- **Always on:** `action-name SP target`, such as `aspis.catalog/1/watch 0123...cdef`. The target is in the interim 64-digit hex form until D34 gives the object-ID text form ([L01](#l01-the-object-id-text-form)).
- **The target** is the object the session is bound to. The server knows it from its badge table (locally) or its session table (remotely). It isn't in the message ([Calls refer to bind state](#calls-refer-to-bind-state)). The kernel knows no object's ID ([0050](../decisions/0050-ids-for-kernel-objects.md), rule 1), and a `[kernel]` call names its object only by capability, so its target is `-`.
- **Arguments are opt-in.** When a log or trace enables them, `SP call-args` follows: the request's parameters in the compact form of [the JSON mapping](#the-json-mapping), keys in declaration order, no whitespace.
- **Sensitive fields are redacted.** A field the IDL marks `[sensitive]` keeps its key, and its value is replaced by JSON `null`.
- **Never rendered:** badges, session IDs, export IDs, capability-space addresses and spill descriptors. A `slot<...>` parameter, which is a capability-space address, keeps its key, with the value `null`, as a sensitive field does.
- **`null` under a field or parameter key always means redacted.** The mapping writes `null` for no other struct field or parameter: an absent optional field is omitted. (An absent optional value elsewhere, such as an optional union arm's value, is `null`, but that is never a field or parameter.)
- **Capabilities.** A capability parameter renders as `{"cap":N}`, its index in the message's capability list ([Capability indexes](#capability-indexes)).
- **Separate fields of the log record or span** (C74, D84): the request ID as 32 lowercase hex digits (`request-id-text`), the deadline, trace context, the bound interface version, and the outcome as `reply-text`, such as `indeterminate aspis.rpc/1!deadline_passed`.
- **Protocol methods** render with action names under `aspis.rpc`, such as `aspis.rpc/1/stream_next`. They aren't IDL methods of `aspis.rpc` or Cedar actions: they ride the session they are sent on ([Protocol methods](#protocol-methods)).

### Kernel interface names

Kernel interfaces are named under the prefix `aspis.kernel.`, one interface per kind of kernel object ([0059](../decisions/0059-the-kernel-interface-library.md), rule 1): `aspis.kernel.endpoint`, `.reply`, `.thread`, `.sched_context`, `.cspace`, `.untyped`, `.address_space`, `.memory`, `.pager_object`, `.eventcount`, `.wait_set`, `.interrupt`, `.job`, `.log_ring` and `.boot_framebuffer`. D29 confirms the list, and D35 assigns each interface's well-known number ([L02](#l02-reserved-numbers)). `.pager_object` is the pager capability's interface, named so that it doesn't collide with `aspis.kernel.pager`, the interface pagers implement.

- **Interfaces the kernel calls**, which user-space servers implement: `aspis.kernel.fault`, `aspis.kernel.pager` and `aspis.kernel.memory_request` ([Messages the kernel sends](#messages-the-kernel-sends)). These three are `[local]`, not `[kernel]`: they have wire grammars ([0059](../decisions/0059-the-kernel-interface-library.md), rule 2), and no network server carries them.
- **Kernel interfaces' errors** are namespaced under their own names, such as `aspis.kernel.eventcount/1!overflow`.

### Name vectors

`grammars/names.vectors` covers at least:

- **ok:** `aspis.catalog`, `org._7_zip.archive`, `_in.co.example.ledger`, `aspis.catalog/1`, `aspis.catalog/1.2`, `aspis.catalog/1/watch`, `aspis.catalog/1/@discover`, `aspis.catalog/1/*`;
- **err:** uppercase; a hyphen; a leading digit; a single label; `01` as a major; a member name `query__all` or `query_`; `__cedar` (the grammar can't match it);
- **errc:** `65536` as a major; a 64-octet label; a 256-octet name; a label `in`, `is` or `like`.

CI also checks, mechanically, that every valid type name parses as a Cedar `Path`, and every `action-ref` as an RFC 6749 `scope-token`. That proves the "no escaping" property.

## The call header and wire encoding

[0064](../decisions/0064-the-call-header-and-wire-encoding.md) settles these. C07, C18 and C29 build them.

### Calls refer to bind state

- **A call names no object, interface or version.** Locally, the session is the 64-bit badge the kernel delivers with the message ([0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 5). Remotely, it is a session ID in the request header. The manager's session table gives the object, the interface, the major, and the minor fixed at bind ([0014](../decisions/0014-versioned-object-apis.md), rule 4, and its Consequences: "nothing per call"). The illustrative 87-octet header in [0013](../decisions/0013-abnf-for-protocols-and-calls.md) was never normative, and this layout replaces it.
- **One layout on both transports.** Word 0 is the same everywhere. Requests differ only in what the deadline means, and in the session ID that the network adds. The network server is IDL-unaware: it never parses a body.
- **Every request carries a deadline and a request ID**, local or not, because a client can't tell a proxy endpoint from a local one ([0004](../decisions/0004-network-transparency-and-failure.md), rules 2 and 3).
- **The header carries no token, priority or baggage.** Tokens are presented at bind only ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 1). Priority is local: scheduling-context donation ([0051](../decisions/0051-scheduling-timers-and-deadlines.md)). Baggage is D84's ([L09](#l09-tracing)).
- **Every header is a whole number of words**, and the body starts on a word boundary. Inside the body there is no padding ([Types](#types)).

### Octets and words

**A message is an octet string, in memory order.** Octet `n` of a message is at offset `n` of the buffer that holds it, on every transport. Word `w` is octets `8w` to `8w + 7`.

- **On kernel IPC** ([0054](../decisions/0054-ipc-endpoints.md), rule 3), words 4 and up live in the IPC buffer's message area as plain octets. The kernel copies them a word at a time, which keeps memory order, so it never swaps or interprets them.
- **The four register words** (octets 0 to 31) are the only ones that move through registers. The sending library loads each with `u64::from_be_bytes` from the message's first 32 octets. The receiving library stores each back with `to_be_bytes` into the first 32 octets of its IPC buffer's message area, which seL4's layout leaves for the register words. That is four `REV` instructions on each side of a message. As a register value, word 0 is then the big-endian reading of its octets, as [Word 0](#word-0) gives it.
- **So the received message is one contiguous octet string**, and decoders borrow from it directly. Text, byte strings and any field that straddles a word are `&str` and `&[u8]` views, with no copy. A `u64` field anywhere, in a register word or in the buffer, is read with `from_be_bytes`, like every other integer.
- **The network server needs no conversion.** It copies the octet string into a QUIC frame and back.

Whether the library writes the register words into the buffer's first 32 octets, or keeps a separate 32-octet header area beside a view of the buffer, is the private ABI's ([K28](kernel-specification.md#k28-message-and-buffer-layout); D156). Either way the decoder sees one octet string.

**Message lengths are in octets.** The kernel reports each message's length in octets, from 0 to 960, through the private ABI, beside its capability count. seL4's message info word gives the length in words, so the kernel specification's message info changes to match ([K28](kernel-specification.md#k28-message-and-buffer-layout)). The published message is exactly those octets, so every body has an exact end. The published header lives in the message words, never in the message info's label.

### Message types

| Code | Type | Sent by | Header words | Body |
|---|---|---|---|---|
| `%x01` | request | a client, or the kernel ([Messages the kernel sends](#messages-the-kernel-sends)) | IPC: 4 plus extensions. QUIC: 5 plus extensions | The method's request struct, or a protocol method's body |
| `%x02` | reply | a server | 1 | The method's reply struct. With the stream flag: a stream ID (u32) and the stream's start position (u64), then the reply struct ([Server streams in the IDL](#server-streams-in-the-idl)) |
| `%x03` | error reply | a server, or a runtime or network server for the hop it controls | 1 | The error envelope ([The error envelope](#the-error-envelope)) |
| `%x04` | cancel | a client, on IPC only | 3 | None |
| `%x05` | stream item | a server | 1 | A batch of stream entries ([Stream messages](#stream-messages)) |
| `%x06` | stream end | a server | 1 | An end reason, and an error envelope when the reason is `error` |

Any other type code is malformed. One-way isn't a message type: the protocol methods that expect no reply say so ([Protocol methods](#protocol-methods)), and so do IDL methods declared `[oneway]` ([Attributes](#attributes)).

### Word 0

Word 0 is common to every message.

| Octets | Field | Width | Values |
|---|---|---|---|
| 0 | protocol version | u8 | `%x01`. A receiver that doesn't know the version answers `aspis.rpc/1!protocol_unsupported`, outcome refused. It must agree with the version in RPC's ALPN identifier (D65). |
| 1 | type | u8 | [Message types](#message-types) |
| 2-3 | flags | u16 | [Flags](#flags) |
| 4-5 | method | u16 | 1 to `0xFEFF` for IDL methods; `0xFF00` to `0xFFFF` for protocol methods; 0 is invalid. Replies, error replies, stream items and stream ends echo the request's method, and bindings check it, which catches crossed replies. A cancel carries the canceled call's method. |
| 6 | header words | u8 | Words from octet 0 through the last extension. At most 32 in protocol version 1. |
| 7 | reserved | u8 | `%x00` |

As a register value, word 0 is `version << 56 | type << 48 | flags << 32 | method << 16 | header_words << 8`.

### Flags

Bits 0 to 7 (octet 3) are **must-understand**: a receiver that sees one it doesn't know set rejects the message as malformed. Bits 8 to 15 (octet 2) are **informational**: a receiver ignores ones it doesn't know.

| Bit | Mask | Name | On | Meaning |
|---|---|---|---|---|
| 0 | `0x0001` | spilled | request, reply, stream item; IPC only | The body is in a memory object ([Spilling](#spilling)). Never on an error reply or a stream end. |
| 1 | `0x0002` | stream | reply only | This reply opens a server stream. The body starts with the stream ID and the start position. |
| 8 | `0x0100` | replayed | reply, error reply | The server answered from its reply cache (D38). |

There is no one-way flag and no "not executed" flag. The error envelope's outcome octet, at a fixed offset, already says whether the call ran ([Outcomes](#outcomes)), and two places for one fact could disagree. A network server that needs it reads that octet. One-way behavior belongs to the method, not the message.

### The IPC request

The IPC request header is 32 octets: four words, seL4 AArch64's four fast message registers.

| Word | Octets | Field | Width | Meaning |
|---|---|---|---|---|
| 0 | 0-7 | word 0 | 8 | Type `%x01`; header words at least 4 |
| 1 | 8-15 | deadline | u64 | An absolute value of the node's virtual count ([0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 5); 0 means none. The library writes the value it passes to the kernel's call. A caller that lies only hurts itself. |
| 2-3 | 16-31 | request ID | 16 octets | Opaque, compared only for equality, as RFC 5531 compares transaction IDs. A retry reuses it. All zero only in kernel-sent requests. How it is made unique, before the entropy gate and after `fork`, is D38's ([L04](#l04-request-ids-the-reply-cache-and-default-deadlines)). |
| 4 and up | 32 and up | extensions | 8 × n | [Header extensions](#header-extensions) |
| then | | body | at most 928 without extensions; at most 704 with the largest header (32 words) | Generated per method; starts on a word boundary |

The session isn't in the header: it is the badge. The object, interface and version are bind state.

### Replies, errors and stream messages

A reply, error reply, stream item or stream end is word 0, with header words 1, then the body: up to 952 octets on IPC.

- **No request ID is needed.** An IPC reply goes through the call's reply object, and an RPC reply goes on the call's own QUIC stream.
- **No extensions.** In protocol version 1, these messages carry none.

### Cancel

A cancel is IPC only, 24 octets: word 0 (type `%x04`, flags 0, the canceled call's method, header words 3), then the 16-octet request ID of the canceled call. It has no body.

- **When.** After a call returns "canceled" or "timed out" following delivery, the library sends a cancel with the non-blocking send, on the same session capability, so with the same badge.
- **It is advisory.** The guarantee is still the invalidated reply object ([0054](../decisions/0054-ipc-endpoints.md), rule 6): a server whose reply fails with "no caller" stops. A busy server may never receive the cancel. Network servers always keep a receiver waiting, so cancels to proxy endpoints get through.
- **The server.** A server that receives a cancel for a request it is running may stop, and need not reply. It ignores a cancel for a request it doesn't know.
- **Over QUIC** there is no cancel message: the client resets the stream ([QUIC resets](#quic-resets)).

### Protocol methods

Protocol methods use the numbers `0xFF00` to `0xFFFF`. They are defined only here and in [the call-header grammar](#the-call-header-grammar), never in an IDL file, so no IDL method has these numbers ([Method numbers](#method-numbers)). Text forms name them under the `aspis.rpc` prefix, with the names below, but `aspis.rpc`'s IDL declares no methods. They aren't Cedar actions: they ride the session they are sent on. Every interface's sessions accept them.

| Method | Name | Body | Reply | Notes |
|---|---|---|---|---|
| `0xFF01` | `stream_next` | stream ID (u32), after (u64), max items (u32, at least 1) | a stream item (possibly empty), a stream end, or an error reply | The local pull and its credit. It never blocks: the server answers at once ([Local pull with credit](#local-pull-with-credit)). |
| `0xFF02` | `stream_close` | stream ID (u32) | none (one-way) | Sent with send, not call, with a short deadline |
| `0xFF03` | `stream_ready` | stream ID (u32) | one capability, an eventcount with read (`cap-ref`), then an empty tail | Local only. Network server A answers it for remote streams ([Remote push within QUIC's credit](#remote-push-within-quics-credit)). |
| `0xFF04` | `session_close` | empty | none (one-way) | Releases the badge it is sent on, and only that badge. The binding sends it when the last local handle to a badge it owns goes. The session ends when its last badge is released ([Sessions, badges and proxies](#sessions-badges-and-proxies)). |
| `0xFF05` | `export_release` | export ID (u64), wire delta (u32, at least 1) | none (one-way) | Importer to exporter, between network servers only, on session ID 0 ([Translation between nodes](#translation-between-nodes)) |
| `0xFF06` | `export_read` | export ID (u64), offset (u64), length (u32, at most 65,536) | the octets (`octets`), then an empty tail | Importer to exporter, on session ID 0: a page fetch for an immutable memory object |
| `0xFF07` | `export_ended` | export ID (u64) | none (one-way) | Exporter to importer, on session ID 0: the exported capability is gone |
| `0xFF08` | `session_dup` | empty | one capability, a new badge of the same session (`cap-ref`), then an empty tail | The sending stub calls it before passing a copy of a session capability as a parameter. Network server B answers it itself for its proxies. |
| `0xFF09`-`0xFFFF` | | | | Reserved |

One-way protocol methods still carry a nonzero request ID. On QUIC they use a client-initiated unidirectional stream.

### Messages the kernel sends

Faults, page requests and memory requests ([0056](../decisions/0056-faults-and-page-fetch-deadlines.md); [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 6; [0058](../decisions/0058-jobs-and-budgets.md), rule 6) are ordinary requests on the common header:

- **Header.** Type `%x01`, flags 0, header words 4, deadline 0, and a request ID of all zeros.
- **Method.** The method number comes from an IDL interface under the reserved authority, which the receiving server implements: `aspis.kernel.fault/1` (one method per fault kind, so the method number is [0056](../decisions/0056-faults-and-page-fetch-deadlines.md) rule 3's "kind"), `aspis.kernel.pager/1` and `aspis.kernel.memory_request/1`. All three are `[local]` interfaces with wire grammars, not `[kernel]` ones ([Kernel interface names](#kernel-interface-names)).
- **Body.** The body is that method's request struct, generated like any other, so fault handlers and pagers are generated from the IDL ([0059](../decisions/0059-the-kernel-interface-library.md), rule 2).
- **Badge.** The badge identifies the faulting thread or the memory object, as ADRs 0056 and 0057 say.
- **Read tolerantly.** These requests never cross the network. No bind fixes their minor version, so the receiving server reads them tolerantly: it skips tail fields it doesn't know, unlike other requests ([Rules for readers](#rules-for-readers)). The kernel and its interfaces are built together. How a handler that speaks an older major would be served is open ([L21](#l21-older-majors-of-the-interfaces-the-kernel-calls)).

**Which ones get a reply.**

- **Page requests and memory requests are `[oneway]`.** The pager answers with Supply or Fail through its pager capability, not with a reply ([0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rules 6 and 7). The memory server answers through the job's capability, by lending, freeing or refusing ([kernel specification](kernel-specification.md#memory-requests-and-reclaim); [L45](#l45-the-memory-servers-answers)). Their dispatchers never reply.
- **Fault methods are ordinary two-way methods.** The handler's reply resumes the thread; not replying leaves it stopped ([0056](../decisions/0056-faults-and-page-fetch-deadlines.md), rule 2).
- **The kernel reads no reply contents.** A handler that changes the faulting thread's registers does it through the thread's capability ([0061](../decisions/0061-debugging.md)) before it replies, and the reply only resumes the thread. That keeps [0054](../decisions/0054-ipc-endpoints.md), rule 4 ("the kernel doesn't read message contents") true, and keeps every message decoder out of the kernel. It departs from seL4, whose fault replies carry register values. [0047](../decisions/0047-the-kernel-follows-sel4.md), rule 3 records the departure.

**Their dispatchers never send an error reply.** For these three interfaces, the generated dispatcher makes none of the refusals of [Refusing what is too new](#refusing-what-is-too-new). An unknown method number, a method newer than the handler knows, or a body that doesn't decode is handed to the handler as an `unknown` event, with the method number, the badge and the raw octets. The generated default for `unknown` sends nothing.

- **For a fault,** the thread stays stopped, so an unknown kind is fatal, as the [kernel specification](kernel-specification.md#fault-delivery) requires ("A handler that doesn't know a kind treats it as fatal"). The handler then acts on the thread through its capability, as ADR 0056, rule 2 allows: it suspends it, or has its job ended. A reply would resume the thread, and the fault would repeat forever.
- **For a page or memory request,** nothing is supplied. The waiting thread's fetch timeout ends its wait with a page-deadline fault ([0056](../decisions/0056-faults-and-page-fetch-deadlines.md), rule 4). The handler logs the event.

### Header extensions

Each extension block is a whole number of words.

| Octet | Field |
|---|---|
| 0 | Kind. Bit 7 set means critical: a receiver that doesn't know a critical kind rejects the request (`aspis.rpc/1!malformed`, outcome refused). Unknown non-critical kinds are skipped. |
| 1 | The number of words that follow the block's first word |
| 2 and up | Kind-specific, padded with zero octets to a word boundary |

| Kind | Name | Size | Layout |
|---|---|---|---|
| `%x01` | trace context | 4 words, 32 octets | kind `%x01`, `%x03`, traceparent version `%x00`, trace-flags (1 octet), 4 zero octets, trace-id (16 octets, not all zero), parent-id (8 octets, not all zero) |
| `%x02` | tracestate | variable | Reserved. Its layout and size are D84's. |
| others | | | Unassigned. New kinds are added by a minor revision of `aspis.rpc`. |

- **Trace context** carries the traceparent fields of W3C Trace Context Level 1 (Recommendation, 2021-11-23), in binary. Trace-flags also takes Level 2's `random` bit (`0x02`) beside `sampled` (`0x01`). Level 2 is a draft: a Candidate Recommendation Draft of 2024-03-28.
- **When trace context is set and sampled**, and whether it is stripped at the realm edge, are D84's ([L09](#l09-tracing)). C74 implements an OpenTelemetry propagator whose carrier is this extension.
- **Requests only.** In protocol version 1, extensions appear only on requests, and a request's header is at most 32 words.

### Spilling

Spilling moves a large body into shared memory. It happens on IPC only.

- **The spilled flag.** If a request, reply or stream item doesn't fit in 960 octets, the library sets the spilled flag. The inline body is then exactly 16 octets: the offset (u64) and length (u64) of the body inside a memory object. The memory object travels as the **last** capability of the message. The body's own capability parameters take the positions before it, so their indexes are the same whether or not the body spilled.
- **Error replies and stream ends never spill.** An error envelope is at most 768 octets ([The error envelope](#the-error-envelope)), and a stream end is one octet plus at most one envelope, so both always fit beside their 8-octet header.
- **The compiler makes spilling safe statically.** It knows every method's worst-case encoded size, since every bound is declared ([Types](#types)). "May spill" is judged against the largest header the message can carry:
  - for a request, 32 words ([Header extensions](#header-extensions)), which leaves an inline body of **704 octets**;
  - for a reply or stream item, which carries no extensions in protocol version 1, 1 word, which leaves **952 octets**.
- **Two capabilities when a body may spill.** A method whose worst-case request body exceeds 704 octets may declare at most two capability positions in its request. One whose worst-case reply or item body exceeds 952 may declare at most two in its reply. So no extension that a client or network server adds at run time can force a spill with no free position.
- **A spill buffer per session** is allowed as a C18 optimization, but each spilled message still names its memory object.
- **Network server B** keeps every extension when it turns an RPC request back into IPC ([What network servers translate](#what-network-servers-translate)). The RPC header is at most 32 words, so the IPC header it makes is at most 31, within the bound the compiler assumed.
- **What spills in practice:** the bind (D39, about 15 KB of credentials) and AuthZEN JSON ([0019](../decisions/0019-authzen-decision-protocol.md), rule 2).

### The RPC request

On QUIC, a request carries one more word than on IPC: the session ID. The header is 40 octets plus extensions.

| Word | Field | Width | Meaning |
|---|---|---|---|
| 0 | word 0 | 8 | Type `%x01`; header words at least 5 |
| 1 | time remaining | u64 | Nanoseconds until the deadline, at least 1. Between nodes a deadline is a duration, never a count ([0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 5). |
| 2-3 | request ID | 16 octets | As on IPC; never all zero |
| 4 | session ID | u64 | Minted by the remote network server at bind, from the CSPRNG (so after the entropy gate). It is scoped to the authenticated peer node, and never reused while that peer's connections live. 0 addresses the peer network server's own interface, for bind forwarding and export release (D66). Clients never write it. |
| 5 and up | extensions, then the body | | As on IPC |

### QUIC framing

Each message on a QUIC stream (RFC 9000) is one frame.

| Octets | Field | Width |
|---|---|---|
| 0-3 | frame length | u32: the octets that follow, at most 4 + 72 + 2^24 |
| 4 | capability count | u8, 0 to 3 |
| 5-7 | reserved | `%x00.00.00` |
| 8 and up | capability descriptors | 24 octets each ([Translation between nodes](#translation-between-nodes)) |
| then | the message | word 0 onward; at most 2^24 octets |

**Streams.**

- **One client-initiated bidirectional QUIC stream per call.** The client writes one request frame, then FIN. The server writes one reply or error frame; or a reply with the stream flag, then stream-item frames, then one stream-end or error frame; then FIN.
- **One-way protocol methods** go on a client-initiated unidirectional stream.
- **Calls on one session are unordered**, unless the client waits for each reply.
- **No spilling.** The spilled flag never appears on QUIC: the network server inlines spilled bodies ([What network servers translate](#what-network-servers-translate)).

### QUIC resets

Resets use QUIC application error codes, in the space of RPC's ALPN identifier. The names and meanings are fixed here. D65 confirms the numeric values with the ALPN ([L06](#l06-the-alpn-identifier-and-reset-codes)).

| Code | Name | Use | The caller's outcome |
|---|---|---|---|
| `0x00` | `ASPIS_NO_ERROR` | Closing a connection normally | |
| `0x01` | `ASPIS_CANCELED` | The client cancels: STOP_SENDING and RESET_STREAM | `canceled`: unreachable if no part of the request was delivered, otherwise indeterminate |
| `0x02` | `ASPIS_REJECTED` | The server's network server didn't deliver the request to the manager | unreachable (`aspis.rpc/1!unreachable`) |
| `0x03` | `ASPIS_ABANDONED` | The server's network server stopped after delivering it | indeterminate (`aspis.rpc/1!indeterminate`) |
| `0x04` | `ASPIS_MALFORMED` | A frame or header that doesn't parse | refused (`malformed`), when the server sends it |
| `0x05` | `ASPIS_TOO_LARGE` | A frame over the limit | refused (`too_large`) |

Losing the connection before the request frame was fully written means unreachable; after it, indeterminate. This maps HTTP/3's REQUEST_REJECTED and REQUEST_CANCELLED (RFC 9114) onto [0004](../decisions/0004-network-transparency-and-failure.md)'s four outcomes. QUIC multipath (RFC 10069, November 2026) doesn't change the framing, and isn't used. 0-RTT, stream limits and idle timeouts are D67's ([L08](#l08-quic-transport-settings)).

### What network servers translate

**Requests, outbound: network server A, on the client's node.**

1. Maps the proxy endpoint's badge to a connection and a session ID, and writes word 4.
2. Converts the absolute count to nanoseconds remaining. A local call with no deadline gets A's default (D38's value). A deadline already past fails locally: `deadline_passed`, outcome unreachable.
3. Inlines a spilled body, drops the spill capability, and clears the spilled bit.
4. Translates each capability in the message into a descriptor ([Translation between nodes](#translation-between-nodes)), all or nothing. If any can't be translated, the call fails locally with `capability_not_remotable`, outcome unreachable.
5. Passes the method, request ID, flags, extensions and body through unchanged, except the spilled bit (step 3) and the header-words octet, which grows by one for word 4.
6. Adds the frame length and the capability table.
7. On a reset or a lost connection, makes the error reply from [QUIC resets](#quic-resets).
8. Turns a local cancel into STOP_SENDING and RESET_STREAM with `ASPIS_CANCELED`.
9. Answers `session_close` and `session_dup` on its proxy badges itself ([Sessions, badges and proxies](#sessions-badges-and-proxies)).

**Requests, inbound: network server B, on the server's node.**

1. Checks the frame, and that the session ID belongs to this peer. Rejects a zero request ID as malformed.
2. Converts the duration to `now + duration` in the local count. Any allowance for round-trip time is D38's.
3. Strips word 4, and turns the RPC request into an IPC request: the header-words octet shrinks by one, and everything else in the header and the extensions is unchanged.
4. Turns descriptors into local proxies, and spills a body that doesn't fit inline, setting the spilled bit and putting the memory object last.
5. Calls the manager through the session's badged capability, with that deadline.
6. Turns STOP_SENDING into an IPC cancel.

**Replies, error replies and stream messages, the other way.**

1. **B** receives the manager's reply on IPC. If it spilled, B inlines the body, drops the memory object and clears the spilled bit. B translates each capability in the reply into a descriptor. If a reply capability can't be translated, B sends the error reply `capability_not_remotable` instead, with outcome **failed**, because the method ran. The compiler makes this rare: a method that returns a non-remotable kind is local, and the manager refuses it on a remote session before it runs ([Local methods and interfaces](#local-methods-and-interfaces)). Then B frames the message on the call's QUIC stream.
2. **A** turns each descriptor in the reply into a local proxy, or unwraps a receiver export to its original capability. If the body exceeds 952 octets, A spills it for its local client: the body goes into a memory object of A's, which is the reply's last capability. Then A replies through the call's reply object.
3. **Error replies and stream ends** carry no capabilities and never spill, so both servers pass their octets through.
4. **Streams.** A buffers items, and answers local `stream_next` and `stream_ready` calls itself. It rewrites the stream ID in the opening reply with one it allocates for the local client, and passes the start position unchanged. B pulls from the local server, and pushes items within QUIC's credit ([Remote push within QUIC's credit](#remote-push-within-quics-credit)).

A differential test checks exactly this ([Differential tests](#differential-tests)): after IPC to RPC to IPC, the method, request ID, flags other than spilled, extensions and body are unchanged, and the header-words octet is restored. Who keeps the reply cache, and for how long, is D38's ([L04](#l04-request-ids-the-reply-cache-and-default-deadlines)).

### Size limits

| Limit | Value | Enforced by |
|---|---|---|
| IPC message, inline | 960 octets, header included | the kernel ([0054](../decisions/0054-ipc-endpoints.md), rule 3) |
| IPC request body, inline, no extensions | 928 octets | the library |
| IPC request body, inline, largest header | 704 octets | the compiler, for "may spill" |
| IPC reply, error, item or end body, inline | 952 octets | the library |
| Request header | 32 words (256 octets) | every receiver |
| Error envelope | 768 octets, causes included | every encoder and decoder |
| Largest message, either transport | 2^24 octets (16 MiB), header and body | the compiler, statically; every receiver |
| QUIC frame | 4 + 4 + 72 + 2^24 octets | network servers (`ASPIS_TOO_LARGE`) |

Bulk data beyond 16 MiB goes through memory objects or streams. Raising the limit needs a new protocol version ([L25](#l25-the-message-size-limit)).

### The call-header grammar

C18 commits this file as `grammars/call-header.abnf`. It is hand-written, and checked against C07's output. It also holds the error envelope, given under [The error envelope](#the-error-envelope).

```abnf
; SPDX-FileCopyrightText: 2026 Nicole Roy
; SPDX-License-Identifier: MPL-2.0
; uses: core
;
; The ASPIS call header, framing and protocol methods (ADR 0064),
; stream entries (ADR 0066) and the error envelope (ADR 0065).

; ---- Messages on kernel IPC -------------------------------------------
ipc-message   = ipc-request / response / ipc-cancel
ipc-request   = %x01 %x01 req-flags method hwords %x00 deadline-count
                request-id *extension body
                ; constraint: header words hwords
deadline-count = u64                       ; absolute virtual count; 0 = none
ipc-cancel    = %x01 %x04 %x00 %x00 method %x03 %x00 request-id

response      = %x01 ( %x02 reply-flags / %x03 OCTET %x00 / %x05 item-flags
                     / %x06 OCTET %x00 ) method %x01 %x00 body

req-flags     = OCTET ( %x00 / %x01 )      ; informational octet, then spilled
reply-flags   = OCTET %x00-03              ; spilled, stream
item-flags    = OCTET ( %x00 / %x01 )      ; spilled
method        = u16
                ; constraint: not 0
hwords        = u8
                ; constraint: in 1..32
request-id    = 16OCTET
body          = *OCTET                     ; per method, generated (ADR 0067)
                ; constraint: remaining octets
spill-ref     = u64 spill-length           ; offset, length, in the last capability
spill-length  = u64
                ; constraint: at most 16777216

; ---- Header extensions ---------------------------------------------------
extension     = trace-ext / other-ext
trace-ext     = %x01 %x03 %x00 trace-flags 4%x00 trace-id parent-id
trace-flags   = OCTET
trace-id      = 16OCTET
                ; constraint: not 0
parent-id     = 8OCTET
                ; constraint: not 0
other-ext     = ext-kind ext-words 6OCTET ext-rest
ext-kind      = %x02-7F / %x80-FF          ; bit 7: critical
ext-words     = u8
ext-rest      = *OCTET
                ; constraint: exactly ext-words words

; ---- Messages on QUIC streams --------------------------------------------
rpc-frame     = frame-length frame-rest
frame-length  = u32
                ; constraint: at most 16777292
frame-rest    = cap-count %x00.00.00 cap-table rpc-message
                ; constraint: exactly frame-length octets
cap-table     = *3cap-desc
                ; constraint: exactly cap-count cap-desc elements
cap-count     = %x00-03                    ; a closed code, not a growing count
rpc-message   = rpc-request / rpc-response
rpc-request   = %x01 %x01 rpc-flags method hwords %x00 time-remaining
                request-id session-id *extension body
                ; constraint: header words hwords
rpc-response  = %x01 ( %x02 rpc-reply-flags / %x03 rpc-flags / %x05 rpc-flags
                     / %x06 rpc-flags ) method %x01 %x00 body
rpc-flags     = OCTET %x00                 ; no spill on QUIC
rpc-reply-flags = OCTET ( %x00 / %x02 )    ; stream
time-remaining = u64                       ; nanoseconds
                 ; constraint: not 0
session-id    = u64                        ; 0 = the peer network server

; capability descriptors (ADR 0066)
cap-desc      = cap-kind rights 6%x00 export-id object-size
cap-kind      = %x01                       ; sender export
              / %x02                       ; receiver export: returned to its exporter
              / %x03                       ; immutable memory object, read-only
rights        = %x00-0F                    ; bit 0 read, 1 write, 2 grant, 3 grant-reply
export-id     = u64
object-size   = u64                        ; octets, for kind %x03; otherwise 0

; ---- Protocol method bodies -------------------------------------------------
stream-id     = u32
                ; constraint: not 0
stream-next   = stream-id u64 max-items    ; method 0xFF01
max-items     = u32
                ; constraint: not 0
stream-close  = stream-id                  ; method 0xFF02
stream-ready  = stream-id                  ; method 0xFF03
stream-ready-rep = cap-ref one-field-tail  ; its reply
session-close = ""                         ; method 0xFF04: empty body
export-release = export-id wire-delta      ; method 0xFF05
wire-delta    = u32
                ; constraint: not 0
export-read   = export-id u64 read-length  ; method 0xFF06
read-length   = u32
                ; constraint: in 1..65536
export-read-rep = octets one-field-tail    ; its reply
export-ended  = export-id                  ; method 0xFF07
session-dup   = ""                         ; method 0xFF08: empty body
session-dup-rep = cap-ref one-field-tail   ; its reply

; The tail of a protocol reply struct with one required field (position 1):
; no optional field is known, so every tail tag is 2 or above.
one-field-tail = tail-count *later-field
                 ; constraint: ascending tags
                 ; constraint: exactly tail-count later-field elements
later-field   = tag-after-1 octets
tag-after-1   = u16
                ; constraint: at least 2

; ---- Stream messages (ADR 0066) ------------------------------------------------
stream-open   = stream-id position         ; prefix of an opening reply's body
stream-batch  = entry-count *stream-entry  ; body of a stream item
                ; constraint: exactly entry-count stream-entry elements
                ; constraint: ascending position
entry-count   = u32                        ; 0: nothing yet (an empty batch)
stream-entry  = item-entry / progress-entry / lost-entry
item-entry    = %x01 position octets       ; the item, encoded per the IDL
progress-entry = %x02 position             ; nothing for this stream up to position
lost-entry    = %x03 position u64          ; that many items before position are lost
position      = u64
stream-end    = %x04 error                 ; error: an envelope follows
              / %x00-03 / %x05-FF          ; 0 complete, 1 closed, 2 expired,
                                           ; 3 session ended, 5 superseded;
                                           ; others: unknown, read as closed

; ---- The error envelope (ADR 0065) follows ------------------------------------
```

`session-close = ""` is ABNF's empty string, which RFC 5234's char-val allows. The Python checker (abnf 2.9.1) accepts it, and so does C06's Rust checker.

`grammars/call-header.vectors` covers at least: every message type, on both transports; a trace extension; an unknown non-critical extension (`ok`); an unknown critical kind (`ok` to the grammar, refused by the receiver); must-understand flag bit 2 set (`err`); the spilled bit on an error reply or a stream end (`err`); header words that disagree with the extensions (`errc`); method 0 (`errc`); a zero time remaining (`errc`); a frame length that disagrees (`errc`); a capability count that disagrees with the table (`errc`); each descriptor kind; an empty batch; each stream entry; positions out of order (`errc`); each end reason; and an unknown end reason, `%x09` (`ok`).

## Typed errors

[0065](../decisions/0065-typed-errors-and-minor-versions-on-the-wire.md) settles these, with the minor-version rules of [Evolution on the wire](#evolution-on-the-wire). C07 and C18 build them.

### The error envelope

One error envelope is the body of every error reply. It is also the value carried as a cause, and in a stream end.

- **An error names its interface by ID**, never by a name: the interface ID (32 octets), the major (u16) and the code (u16). These three are the **error key**, always explicit. This is the AEGIS structure (who, plus a code, kept across RPC), with the 32-octet interface ID in place of AEGIS's small, centrally assigned subsystem numbers, which would break parity ([0027](../decisions/0027-applications-extend-the-system.md), rules 3 and 7). So an error describes itself when it is forwarded, logged, copied into a fault, or proxied by a network server that doesn't parse it.
- **Codes are u16, per interface major**, starting at 1. 0 is reserved. A code is never reused or renamed within its major.
- **No free text.** An error's description is its IDL doc comment, fetched from the interface object ([0014](../decisions/0014-versioned-object-apis.md), rule 2), and rendered by dm and logs. Facts are typed detail fields. The envelope's tail leaves room for a bounded note in a later minor of `aspis.rpc`, if C18's experience shows the need ([L23](#l23-error-size-limits-and-free-text)).
- **The system's own errors live in an ordinary IDL interface**, `aspis.rpc` major 1, under the reserved authority ([The system errors](#the-system-errors)). Its well-known number is D35's. There are no reserved code ranges inside other interfaces.
- **Errors carry no capabilities.** Network servers forward them as opaque octets.
- **Unknown codes are preserved.** A binding that doesn't know an error key keeps the envelope's octets whole, exposes the key and the raw detail, and re-encodes them unchanged when it forwards the error as a cause.
- **The kernel carries only the key.** A pager's Fail, and the page-unavailable fault it causes, carry only the 36-octet error key, never a whole envelope. The kernel must keep that value until each waiting thread's fault is delivered, and it has no heap ([0056](../decisions/0056-faults-and-page-fetch-deadlines.md), rule 3; [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 7). The detail stays with the pager. A handler that wants it asks the pager with an ordinary call, which C15 and C17 define ([L43](#l43-keeping-a-fails-error-key)).

The envelope is itself an open struct ([The struct encoding](#the-struct-encoding)): six required fields, then a tail whose tags are the positions of its optional fields.

| Position | Field | Type | Meaning |
|---|---|---|---|
| 1 | outcome | u8, closed | `1` refused: delivered, and the server guarantees the method didn't run. `2` failed: the server ran it, or may have, and answers with an error. `3` unreachable: never delivered. `4` indeterminate: may have run, and no answer came. |
| 2 | disposition | u8, open | `0` don't retry unchanged. `1` retry later with the same request ID. `2` bind again (a fresh token or session), then retry. `3` retry at a higher level: re-read state, then decide. A client treats an unknown value as `0`. |
| 3 | interface | `id` (32 octets) | The interface the code belongs to |
| 4 | major | u16 | That interface's major version |
| 5 | code | u16, not 0 | The error's code |
| 6 | detail | `octets` | The error's detail struct, encoded as any open struct. An error with no fields still carries an empty struct: `%x00.00.00.04 %x00.00.00.00`. |
| 7 (tail) | cause | `octets`, optional | Another envelope, nested at most 3 deep |
| 8 (tail) | retry_after | u64, optional | A duration in nanoseconds, never a count ([0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 5) |

The encoded envelope, causes included, is at most **768 octets**. It always fits one IPC message beside a reply header (8 octets) or a stream end's reason octet, so it never spills. The error key alone (interface, major, code: 36 octets) is the closed struct `aspis.rpc/1.error_key`, which the kernel interfaces use for Fail and the page-unavailable fault.

These rules end `grammars/call-header.abnf`:

```abnf
; ---- The error envelope (ADR 0065) ------------------------------------------
error         = outcome disposition object-id u16 error-code octets error-tail
                ; constraint: length at most 768
outcome       = %x01-04
disposition   = OCTET                      ; open: unknown values mean "don't retry"
error-code    = u16
                ; constraint: not 0
error-tail    = tail-count *error-opt
                ; constraint: ascending tags
                ; constraint: exactly tail-count error-opt elements
error-opt     = error-cause / error-retry-after / error-unknown
error-cause   = %x00.07 octets             ; holds an error; at most 3 nested (prose)
error-retry-after = %x00.08 %x00.00.00.08 u64   ; nanoseconds
error-unknown = error-unknown-tag octets   ; a field a later aspis.rpc minor adds
error-unknown-tag = u16
                ; constraint: at least 9
error-key     = object-id u16 error-code   ; 36 octets: Fail and page-unavailable faults
```

Every decoder enforces the nesting limit and the 768-octet limit. C06's vocabulary carries the length limit. The nesting depth is a prose constraint in this hand-written grammar, checked by the decoder and its tests.

### Outcomes

- **A server's runtime sends only refused or failed.**
- **Unreachable and indeterminate** are made only by the caller's runtime, from kernel results ([Kernel results](#kernel-results)), or by a network server for the hop it controls.
- **A server that forwards an error** from a call it made puts that error in the `cause` of its own error. It never forwards the inner outcome as its own.
- **An interface's own error is failed**, unless the IDL declares it `[refused]` ([Attributes](#attributes)). A refused error promises that nothing ran.
- **The reply cache.** Refused errors need not enter the reply cache, since nothing ran. Failed errors are cached and replayed like replies. D38 owns retention.

[0004](../decisions/0004-network-transparency-and-failure.md), rule 3's outcome classes are carried like this:

| 0004 class | On the wire |
|---|---|
| success | a reply (type `%x02`), or a stream that ends `complete` |
| an application error | an error reply whose outcome is refused or failed, whatever interface its key names |
| unreachable | an error reply whose outcome is unreachable |
| indeterminate | an error reply whose outcome is indeterminate |

Refused and failed are both ADR 0004's "error". Refused adds the guarantee that a retry is safe. That is DCE's split between a reject and a fault.

### The system errors

The system errors are `aspis.rpc` 1.0. Every method may return any of them, and methods don't list them ([Example: the eventcount interface](#example-the-eventcount-interface)). Detail fields use the IDL's types, and every enum below is open.

| Code | Name | Outcome | Disposition | Detail fields | Notes and analogs |
|---|---|---|---|---|---|
| 1 | `malformed` | refused | 0 | none | A header, frame or body doesn't parse, or breaks a constraint. DCE `nca_proto_error`; gRPC INVALID_ARGUMENT |
| 2 | `too_large` | refused | 0 | `limit: u32` | Over a size limit ([Size limits](#size-limits)). DCE `nca_out_args_too_big` |
| 3 | `protocol_unsupported` | refused | 0 | `highest: u8` | An unknown protocol version in word 0 |
| 4 | `version_unsupported` | refused | 0 | `served: seq<version_range, 16>`, where `version_range` is the closed struct `{ major: u16, highest_minor: u16 }` | A bind to a major that isn't served, or a minimum minor above what is served. The detail lets the client choose without another discovery call. |
| 5 | `no_such_interface` | refused | 0 | none | The object doesn't implement it. DCE `nca_unk_if` |
| 6 | `no_such_method` | refused | 0 | `method: u16`, `session_minor: u16`, `since_minor: u16?` | An unknown method number, or one newer than the session's minor. DCE `nca_op_rng_error`; FIDL UNKNOWN_METHOD |
| 7 | `field_too_new` | refused | 0 | `tags: seq<u16, 8>` | A request field newer than the session's minor |
| 8 | `no_such_object` | refused | 0 | none | No such object, **or** a bind the caller may not make on an object it may not `discover` ([A denied bind](#a-denied-bind)) |
| 9 | `bind_refused` | refused | 0 | `acr_values: string<255>?`, `max_age: u64?` | Policy denied a bind the caller may see. The two fields are RFC 9470's, present only when the decision context carries step-up hints ([0019](../decisions/0019-authzen-decision-protocol.md), rule 7). |
| 10 | `token_rejected` | refused | 2 | `reason: token_problem` (`expired` 1, `bad_proof` 2, `wrong_audience` 3, `unknown_issuer` 4, `other` 5) | The values follow the token profile, which is D85's ([L13](#l13-token-rejected-reasons)) |
| 11 | `tree_too_stale` | refused | 1 | none; `retry_after` in the tail | A bind refused because the node's signed root is too old ([0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 7; [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 6). Given before any existence check, so it reveals nothing. |
| 12 | `session_ended` | refused, unreachable or indeterminate | 2 | `reason: session_end` (`expired` 1, `revoked` 2, `closed` 3, `unknown` 4) | A revoked session is `reason = revoked` ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 1; [0019](../decisions/0019-authzen-decision-protocol.md), rule 8). Refused when the manager answers it; otherwise by delivery state ([Kernel results](#kernel-results)). Cap'n Proto "disconnected" |
| 13 | `method_not_granted` | refused | 0 | none | The method is outside what the bind authorized. gRPC PERMISSION_DENIED |
| 14 | `deadline_passed` | unreachable or indeterminate | 1 | none | Unreachable if it passed before delivery, indeterminate after. gRPC DEADLINE_EXCEEDED |
| 15 | `canceled` | unreachable or indeterminate | 0 | none | As for `deadline_passed`. DCE `nca_s_fault_cancel` |
| 16 | `unreachable` | unreachable | 1 | `cause: unreachable_cause` (`no_route` 1, `location_unknown` 2, `peer_authentication_failed` 3, `connection_failed` 4, `manager_not_running` 5) | Made by a runtime or a network server |
| 17 | `indeterminate` | indeterminate | 1 | `cause: indeterminate_cause` (`connection_lost` 1, `server_exited` 2, `abandoned` 3) | Made by a runtime or a network server |
| 18 | `overloaded` | refused | 1 | none; `retry_after` in the tail | DCE `nca_server_too_busy`; gRPC RESOURCE_EXHAUSTED |
| 19 | `no_memory` | refused or failed | 1 | none | The server, or the runtime, couldn't get memory for the call within its job's budget ([0058](../decisions/0058-jobs-and-budgets.md)) |
| 20 | `resource_limit` | refused | 0 | `limit: limit_kind` (`streams_per_session` 1, `imports_per_session` 2, `sessions` 3, `pending_calls` 4, `badges_per_session` 5), `maximum: u32` | A per-session or per-server limit ([Stream limits and rundown](#stream-limits-and-rundown)) |
| 21 | `capability_not_remotable` | unreachable or failed | 0 | `position: u8` | Unreachable when network server A refuses the whole call before sending it; failed when network server B can't export a capability in a reply, after the method ran ([Translation between nodes](#translation-between-nodes)) |
| 22 | `capability_rights` | refused | 0 | `position: u8`, `missing: u8` (rights bits) | A received capability lacks the declared rights ([Capability types](#capability-types)) |
| 23 | `local_only` | refused | 0 | none | A bind through a network server to an interface declared `[local]` or `[kernel]`, or a call on a remote session to a local method. Refused before the method runs ([Local methods and interfaces](#local-methods-and-interfaces)). |
| 24 | `stream_expired` | refused | 3 | `oldest: u64?` | A stream opened or pulled `after` a position older than the server keeps: list again ([Local pull with credit](#local-pull-with-credit)) |
| 25 | `no_such_stream` | refused | 0 | none | `stream_next`, `stream_close` or `stream_ready` names a stream the session doesn't have |
| 26 | `request_id_conflict` | refused | 0 | none | The same request ID arrived with a different body (the reply cache, C18) |
| 27 | `internal` | failed | 0 | none | gRPC INTERNAL |
| 28 | `value_too_new` | refused | 0 | `since_minor: u16` | A request carries an enum value, flag bit or union arm that the server knows but that is newer than the session's minor |

Later minors of `aspis.rpc` may add codes. The same interface holds the extension-kind registry ([Header extensions](#header-extensions)) and the closed struct `error_key`. It declares no methods: the protocol methods (`0xFF01` to `0xFF08`) are defined with the call header, and only their text forms use the `aspis.rpc` prefix ([Protocol methods](#protocol-methods)).

### A denied bind

A manager, the catalog, or a network server forwarding a bind answers a bind that fails like this:

- **`no_such_object`** when the object doesn't exist, **or** when policy denies the bind and the caller may not `discover` the object ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 8);
- **`bind_refused`** when policy denies the bind and the caller may `discover` the object, with step-up hints when the decision context has them.

The manager asks for `discover` in the same AuthZEN batch as the bind's decision ([0019](../decisions/0019-authzen-decision-protocol.md), rule 1). So both answers take the same round trip, and timing doesn't tell them apart. Interfaces and types are visible to every principal in the realm by default ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 8), so a denied bind to an interface object normally gets `bind_refused`. `tree_too_stale` comes before either check.

### Kernel results

The call runtime (`aspis-rt`, C18) turns kernel results on IPC into `aspis.rpc` errors:

| Kernel result ([0054](../decisions/0054-ipc-endpoints.md)) | Error | Outcome |
|---|---|---|
| "timed out" before delivery | `deadline_passed` | unreachable |
| "timed out" after delivery | `deadline_passed` | indeterminate |
| "canceled", before or after delivery | `canceled` | unreachable or indeterminate |
| an invalid session capability (revoked), or a send canceled in the queue | `session_ended`, reason `unknown` | unreachable |
| the server's reply object destroyed, because the server exited | `indeterminate`, cause `server_exited` | indeterminate |

This needs the kernel's "timed out" and "canceled" results to say whether the message had been delivered. [0054](../decisions/0054-ipc-endpoints.md), rules 5 and 6 and the kernel specification's [IPC deadlines and cancellation](kernel-specification.md#ipc-deadlines-and-cancellation) are revised to carry that bit.

Kernel interfaces' own failures are typed errors of their `aspis.kernel.*` interfaces, declared in their IDL. The raw status numbers stay private ([0059](../decisions/0059-the-kernel-interface-library.md), rules 1 and 2).

### Errors in bindings and text

- **Rust.** A call returns `Result<Reply, CallError>`. `CallError` holds the outcome, the disposition and a kind. The kind is one of:
  - `App(E)`, where `E` is a generated `#[non_exhaustive]` enum of the interface's own errors, with an `Unknown { code, detail }` arm;
  - `Rpc(RpcError)`, for `aspis.rpc` errors;
  - `Foreign(RawError)`, for the keys of any other interface.

  Every variant keeps the raw octets, for re-encoding.
- **Canonical text:** an `error-ref` ([The names grammar](#the-names-grammar)), such as `aspis.catalog/1!stream_expired`, or `<id-text>/1!#17` when the name isn't known.
- **JSON** ([The JSON mapping](#the-json-mapping)): `{"interface":"<id-text>","name":"aspis.rpc","major":1,"code":14,"error":"deadline_passed","outcome":"indeterminate","disposition":1,"detail":{...}}`, with `name` and `error` omitted when they aren't known.
- **errno** ([POSIX note, §4.19](posix-compatibility.md#419-errors)): D96 maps the outcome and code to errno, and keeps the original envelope retrievable ([L14](#l14-errno-mapping)).
- **HTTPS:** D116 maps the envelope to RFC 9457 problem details. Its `type` URI derives from the error key, never from a name ([L15](#l15-the-https-binding)).

## Evolution on the wire

[0065](../decisions/0065-typed-errors-and-minor-versions-on-the-wire.md) settles these. C07 builds them.

### Strict requests, tolerant reads

- **A tagged optional tail, not an extension block.** Every open struct is a positional head of its required fields, then a tail of its optional fields, each tagged and length-prefixed. The other option, a length-prefixed block per minor, needs a presence bitmap inside each block, makes a field's location depend on the minor that added it, and forces empty blocks for every minor in between.
- **Types are open unless declared `closed`.** Generated bindings accept values they don't know (struct fields, union arms, enum values, flag bits, error codes), and preserve them. A `closed` type never changes within its major, and an unknown value in it is malformed.
- **What a minor version may add**: methods, optional fields, error codes, union arms, enum values and flag bits (to open types), and new types, constants, action groups and deprecation marks. Docs may change too, since they are outside the canonical form. [0014](../decisions/0014-versioned-object-apis.md), rule 3 says so, as edited with ADR 0065. A field or arm added in a minor never holds a capability ([The compatibility check](#the-compatibility-check)).
- **Requests are strict to the session's minor; everything a client reads is tolerant.** A conforming client knows the minor fixed at bind, so it never sends anything newer. A server may speak a newer minor than the client was built for. So message bodies need no critical bit; only the header has must-understand flags and critical extensions ([Flags](#flags); [Header extensions](#header-extensions)). (CoAP needs one only because it has no version negotiation.)
- **Encoding is canonical.** Each value has one encoding: tags strictly ascending, no duplicates, absent fields omitted (never encoded as empty), no padding, strict booleans, the canonical NaN. A decoder rejects anything else as `malformed`. Reply caches, signatures and the fuzzing gate's round-trip property rely on it.

### The struct encoding

**An open struct** (the default) is a head, then a tail:

- **The head** is each required field's encoding, in declaration order, unpadded.
- **The tail** is `tail-count` (u32), then that many tail fields. Each tail field is a `tag` (u16), then the field's encoding as `octets` (a `len32`, then the field). These are the core rules of [The core grammar](#the-core-grammar).

The rules:

- **A field's tag is its position**: the 1-based index of the field among all the struct's fields, required and optional, in declaration order. Required fields have positions too, but never appear in the tail. A struct's fields are only ever appended within a major, and the compatibility check refuses any reorder, rename, removal or retyping, so a position never changes. The IDL source writes no field numbers; the lock file ([The lock and the canonical form](#the-lock-and-the-canonical-form)) keeps positions as stable as written numbers.
- **Only optional fields (`T?`) go in the tail.** A present field appears once; an absent one is omitted. Tags ascend.
- **New fields in a minor are optional, appended, and carry `[since(M.n)]`.** They take the next positions, so their tags are higher than every older tag.
- **Overhead:** 4 octets per open struct (an empty tail is `%x00.00.00.00`), and 6 octets per optional field present. The count is u32, the width of every count, though tags being u16 bound it to 65,535.
- **The same rule applies to every open struct:** method requests and replies (a method's parameters and its results each form a struct), error details, stream items, and the error envelope.

**A closed struct** (`[closed]`) is the head only, fixed for the life of the major. An optional field inside a closed struct is `presence`, then the value. A closed struct whose fields are all fixed-width is itself fixed-size. Register-sized kernel records and fixed-size array elements use those.

**Example.** This is the generated grammar for `struct change { seq: u64, kind: change_kind, entry: id, [since(1.1)] publisher: id? }`. Its fields have positions 1 to 4, and tag 4 is the only tail field.

```abnf
; aspis.catalog/1.1: struct change
t-change            = u64 t-change-kind object-id t-change--tail
t-change--tail      = tail-count *t-change--opt
                      ; constraint: ascending tags
                      ; constraint: exactly tail-count t-change--opt elements
t-change--opt       = t-change--publisher / t-change--unknown
t-change--publisher = %x00.04 %x00.00.00.20 object-id      ; tag 4, since 1.1
t-change--unknown   = t-change--unknown-tag octets
t-change--unknown-tag = u16
                      ; constraint: at least 5
t-change-kind       = u8                                   ; open enum change_kind
```

- **Helper rules are scoped to their struct** (`t-change--...`), so two structs in one file never define the same rule ([Generated grammars](#generated-grammars)).
- **An unknown tag is bounded below** by the position after the last field known at that minor, so it can never be a required field's position. That keeps one encoding per value, and the decoder and the grammar agree exactly ([The gate for each target](#the-gate-for-each-target), item 3).
- **At 1.0** the same struct's grammar has no `t-change--publisher`, and its unknown tag is "at least 4". So every 1.1 reply vector still matches the 1.0 grammar, which is what the compatibility check runs.
- **In a request grammar**, which is strict, the unknown alternative is absent.

### Rules for readers

| What is read | An unknown tail field | An unknown union arm, enum value, flag bit or error code in an open type |
|---|---|---|
| a reply, an error detail, a stream item | skipped by its length, and preserved | accepted, and preserved |
| a request from a client | refused: `field_too_new`, outcome refused | If the server knows it, but it is newer than the session's minor: refused, `value_too_new`. If even the server doesn't know it (an open type's value from no minor it knows): accepted and preserved by the binding, and handed to the implementation as unknown. |
| a request the kernel sent ([Messages the kernel sends](#messages-the-kernel-sends)) | skipped, and preserved | accepted, and preserved |
| anything in a closed type | not applicable | `malformed` |

**Preserved** means the binding keeps the raw tag and octets (or the raw arm, value or bits), exposes them as unknown, and re-encodes them unchanged and in order when the value is written back. A read-modify-write by an older client then doesn't drop a newer client's fields. The JSON mapping preserves them too ([The JSON mapping](#the-json-mapping)).

**Preserved octets never hold a capability.** A field or arm added in a minor may not contain a capability type, directly or nested. So an unknown tail field or arm is pure data:

- a reader never meets a `cap-ref` it can't see;
- every capability in a message is named by a field the reader knows;
- re-encoding preserved octets can't carry a stale index.

New capability-bearing data comes only with new methods, whose capability counts and rights are fixed from the minor that adds them.

### Refusing what is too new

- **The bind fixes the minor**, M.s ([0014](../decisions/0014-versioned-object-apis.md), rule 4). The manager records s in its session table, keyed by badge locally ([0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 5) and by session ID at network server B.
- **The client stub refuses locally, without sending.** A method whose `since` is newer than s returns `no_such_method`, outcome refused. The stub never encodes a field whose `since` is newer than s.
- **The server runtime refuses, as a check before dispatch:**
  - an unknown method number, or one whose `since` is newer than s, gets `no_such_method`;
  - a request field whose tag is unknown or newer than s gets `field_too_new`, with the offending tags;
  - an enum value, flag bit or union arm that the server knows, but whose `since` is newer than s, gets `value_too_new`.

  All three are refused, so nothing ran and a retry is safe. A value the server doesn't know at all isn't refused ([Rules for readers](#rules-for-readers)).
- **Interfaces the kernel calls** make none of these refusals. Their dispatchers hand anything unknown to the handler ([Messages the kernel sends](#messages-the-kernel-sends)).
- **A bind** to a major the manager doesn't serve, or with a minimum minor above what it serves, gets `version_unsupported`, listing what is served. What else the bind message carries is D39's ([L05](#l05-the-bind-message)).

### Open and closed types

| Type | Open (the default) | Closed (`[closed]`) |
|---|---|---|
| struct | head and tail; grows by optional fields | head only; never grows |
| union | `arm-tag` (u16, not 0), then the arm's value as `octets`, so a reader can skip an unknown arm | `arm-tag`, then the arm's value, unprefixed |
| enum | the declared width (u8, u16 or u32); any value is valid, and unknown ones are preserved | only declared values; anything else is malformed |
| flags | the declared width (u8 to u64); unknown bits are preserved | unknown bits are malformed |
| error set | always open: an interface's errors grow by minors, and every binding carries unknown codes | errors can't be closed |

An optional (`T?`) union arm, sequence element or array element is `presence`, then the value.

**What a closed type may hold.** A closed type holds only types that can't grow within the major: integers, `bool`, floats, `id`, `uuid`, enums and flags, `string<N>`, `bytes<N>`, closed structs and closed unions, optionals, sequences and arrays of these, and capability types. It never holds an open struct or an open union, which could grow by a minor and so change the closed type's encoding. The compiler refuses one that does.

- **Enums and flags inside a closed type may be open.** Their width is fixed, so an open enum or flags field keeps the closed type's encoding unchanged when a minor adds a value. A reader that meets an unknown value there preserves it, as anywhere, and the closed type around it isn't malformed. Only a closed enum or flags type rejects an unknown value.
- **Fixed size.** A closed struct or array whose members are all fixed-width (integers, `bool`, floats, `id`, `uuid`, enums, flags, capability types, and closed structs and arrays of these) has a size the compiler computes. Only such types make `N × size` arrays ([Types](#types)). Other arrays are N self-delimiting elements.

### The compatibility check

C07 runs this check in the repository, and the catalog runs it on registration ([0027](../decisions/0027-applications-extend-the-system.md), rule 2). For each published minor m-1 of the major, the compiler projects the new source to m-1, and compares it with m-1's recorded canonical form ([The lock and the canonical form](#the-lock-and-the-canonical-form)). Minor m may only:

1. add a method, with a new number and `[since(M.m)]`;
2. append an optional field with `[since(M.m)]` to an open struct, including a method's parameters or results, if the field's type contains no capability type, directly or nested;
3. add a union arm (a new `@n`) to an open union, if the arm's type contains no capability type; add an enum value or flag bit to an open type;
4. add an error code to the interface, and add it to a method's `error(...)` list;
5. add types, constants and aliases, and new action groups, and add a new method to an existing group;
6. change doc comments, and add `[deprecated(...)]`.

Everything else is refused, including:

- changing a head, a type, a bound or a name;
- reordering, removing or reusing anything;
- making an optional field required, or the reverse;
- changing a closed type at all;
- adding a field or arm that contains a capability type (a method's capability count, and the rights its sessions need, are fixed when the method is added);
- changing a method's groups once published;
- changing an error's code or outcome attribute;
- changing `[idempotent]`, `[readonly]`, `[sensitive]` or `[oneway]`, or an interface's `[local]`.

The check also runs on vectors. Every reply, error-detail and stream-item vector of M.m must match M.(m-1)'s grammar. Every request vector of M.m that uses no method or field newer than m-1 must match it too.

### Evolution vectors

Every generated grammar's vector file carries at least:

- **ok:** a reply with an unknown tail field; a reply with an unknown arm of an open union and an unknown value of an open enum; an unknown enum value inside a closed struct;
- **err or errc:** tail tags out of order or duplicated; tag 0; an unknown tag that is a required field's position (`errc`); error code 0; a cause nested 4 deep; an envelope over 768 octets; a request with a field newer than the minor (in the request grammar); an unknown arm of a closed union;
- **capabilities**, for every method with capability positions, under the matching `# caps:` directive ([Vector files](#vector-files)): each optional capability present and absent (`ok`); an index not less than the count, a repeated index, and a count with a capability no index names (`errc`); and, under `# unwrapped:`, a position delivered unwrapped (`ok`).

## Capability parameters and server streams

[0066](../decisions/0066-capability-parameters-and-server-streams.md) settles these. C07, C18 and C29 build them.

### Capability types

A capability parameter is typed in the IDL: by interface, and for kernel objects by rights too. It is a resource type. It can't be copied implicitly (sharing a session capability is an explicit `session_dup`), compared, or rendered by value, and it can't be placed in a sequence, an array, a stream item or an error.

| Form | Meaning | Rights sent |
|---|---|---|
| `cap<org.example.sql.table/1.2>` | A session capability: an endpoint capability to a session speaking that interface, major 1, minor 2 or later. It names an interface, never an object ([0050](../decisions/0050-ids-for-kernel-objects.md), rule 5). | Computed by the compiler ([Rights a session needs](#rights-a-session-needs)) |
| `cap<aspis.kernel.memory/1, read>` | A kernel object capability, typed by its kernel interface and the rights it must have, from [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 2's four: `read`, `write`, `grant`, `grant_reply` | Exactly those listed |
| `cap<aspis.kernel.memory/1, read, immutable>` | As above, and the memory object must be immutable ([0057](../decisions/0057-memory-objects-and-the-pager-protocol.md)). The only memory capability that can cross nodes. | read |
| `slot<aspis.kernel.eventcount/1, read>` | Kernel interfaces only: a capability address in the caller's own capability space (a u64), not a transfer | none move |

- **Declared rights are a ceiling and a floor.** The sending stub attenuates each capability to exactly the declared rights. It copies it with fewer rights into a scratch slot, sends the copy, and deletes the scratch slot. The receiver's child copy survives the delete, as in seL4.
- **The receiving stub checks each capability's kind and rights** with the kernel's identify operation, and refuses the call with `capability_rights` if they fall short. [0047](../decisions/0047-the-kernel-follows-sel4.md), rule 3 records identify as a departure from seL4, which offers it only as a debugging aid ([L41](#l41-the-identify-operation)). The kernel can't check that a session capability speaks the declared interface. A mismatch shows as `no_such_method` or `version_unsupported` on first use.
- **Any capability type may be optional**, `cap<...>?`. As an open-struct field it is a tail field; elsewhere it is `presence`, then the index.
- **Unwrapped capabilities.** A capability that names the endpoint the message travels through arrives unwrapped, as its badge ([0054](../decisions/0054-ipc-endpoints.md), rule 7). It still occupies its position in the list, and the binding exposes it as `Own(badge)` instead of a received slot.

### Capability indexes

On the wire, a capability parameter is a one-octet index into the message's capability list, the core rule `cap-ref` (`%x00-02`, with the constraint `capability index`). The body is the same on kernel IPC and on QUIC, so one generated grammar serves both.

- **The capability list.** On kernel IPC, it is the capabilities the kernel moved, in the order the sender named them, with the kernel's unwrapped mask. On QUIC, it is the frame's descriptor table ([QUIC framing](#quic-framing)). A spilled message's memory object is last in the list, and no `cap-ref` names it.
- **Up to three per message, in each direction.** These are three real transfers, with the receiver naming up to three receive slots. This departs from seL4, which transfers one capability plus unwrapped badges; [0047](../decisions/0047-the-kernel-follows-sel4.md), rule 3, [0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 6 and [0054](../decisions/0054-ipc-endpoints.md), rule 7 say so. A body that may spill gets two ([Spilling](#spilling)).
- **Each index appears exactly once** in a message, and indexes appear in ascending order in the body's encoding order: the stub assigns them as it encodes. A decoder rejects a message with an index not less than the count, a repeated index, or a capability that no index names.
- **The count is static.** The compiler counts capability positions per direction over the worst case: an optional capability counts, and a union counts its largest arm. More than three (two if the body may spill) is a compile error.
- **No sentinel.** There is no "absent" index value. Optional capabilities use the tail or `presence`.
- **Text.** A capability renders as `{"cap":N}` in the JSON mapping, its index. Never a badge or an export ID.

### Rights a session needs

These follow [0054](../decisions/0054-ipc-endpoints.md), rule 7 and the [kernel specification](kernel-specification.md#rights-by-object-type).

- **Write and grant-reply always.** A call needs grant or grant-reply on the caller's endpoint capability. Without either, seL4 makes the caller inactive, and no reply ever comes. So every session capability carries write and grant-reply.
- **Grant when requests carry capabilities.** The compiler adds grant when any request of the interface carries capabilities, since sending capabilities needs it.
- **Reply capabilities need grant on the server's side.** Whether a reply may carry capabilities depends on the endpoint capability the manager receives on. That is server configuration. Every manager needs it, because the protocol method `session_dup` replies with a capability. So the generated server runtime refuses to start on a receive capability without grant.
- **The metadata records it.** The compiler records in the interface's metadata which requests and replies carry capabilities, and a manager hands out session capabilities with exactly the rights the metadata says.
- **One-way protocol sends** (`stream_close`, `session_close` and the cancel message) need only write.

### More than three capabilities

A call that needs more than three capabilities uses a **builder session**. A method returns `cap<...builder/1>`; each `add` call carries up to three named capabilities; and a `commit` call finishes. Native spawn's named initial capabilities ([0060](../decisions/0060-processes-native-spawn-and-elf.md), rule 2) are the first case: begin, add, then start.

### Translation between nodes

Across nodes, capabilities are proxied, with object-capability semantics. The session stays bound to its original channel, calls route back through the exporting node, and ending the session kills every proxy. Raw capabilities never leave a node ([0002](../decisions/0002-capability-security-model.md), rule 5). Network servers translate capabilities without ever parsing a body.

Each network server serves all its proxies on one endpoint, told apart by badge. So seL4 unwrapping shows, at no cost, when a capability sent through one of its proxies is one of its own proxies.

For each capability in an outbound message, network server A learns its kind and rights: from the badge, for its own proxies (unwrapped); from the kernel's identify operation, for anything else. Then:

| The capability is | A sends | B does |
|---|---|---|
| a session or endpoint capability with write, served on A's node | kind `%x01`, sender export. A keeps a copy in its export table for this connection, under an export ID. The rights are those after attenuation, never read, which would let B receive on it. | Mints a proxy (a badged copy of its proxy endpoint) with those rights, and puts it in the same list position |
| one of A's proxies, for an export that B made | kind `%x02`, receiver export, with B's export ID | Unwraps it to B's original capability. No proxy of a proxy is ever built. |
| one of A's proxies, for an export from a third node C | kind `%x01`, exporting the proxy | Mints a proxy. Calls then route B to A to C, a proxy chain. There is no three-party handoff ([L26](#l26-three-party-handoff)). |
| an immutable memory object with read | kind `%x03`, immutable export, with its size | Creates an immutable, pager-backed memory object whose pager is B's network server. It fetches pages from A with `export_read`, under the mapping's fetch timeout ([0057](../decisions/0057-memory-objects-and-the-pager-protocol.md); [0056](../decisions/0056-faults-and-page-fetch-deadlines.md)). The content never changes, so there is no coherence problem. |
| anything else: writable memory, an eventcount, a thread, an address space, a capability space, untyped memory, a job, an interrupt, a pager object, a reply object, a scheduling context, a wait set, an endpoint's receive right | nothing: A refuses the whole call before sending, with `capability_not_remotable`, outcome unreachable ([L27](#l27-writable-memory-across-nodes)) | |

- **All or nothing**, as Zircon's channel write is. A call whose capabilities can't all be translated isn't sent, so it is safe to retry.
- **Export IDs** are u64, unique per connection and direction, and never reused while the connection lives.
- **Exports are reference-counted.** Each send raises the count, and releases carry a wire delta (`export_release`), after CapTP's `op:gc-exports` and Cap'n Proto's Release. So a release can't race a send in flight.
- **Authority and audit.** A proxy carries the exporting session's authority. The manager's PDP decided once, for the original principal, at bind. It doesn't see the node that now uses the session. That is capability delegation by design. A party that needs its own authority, or one that outlives the session, takes the object ID and binds itself, with a delegated token from RFC 8693 token exchange where needed ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rules 1 and 4). ADR 0015, rule 1 and ADR 0002, rule 5 are edited with ADR 0066 to say that a capability passed as a parameter crosses as a proxy, not as a delegation that needs a token.

### Local methods and interfaces

Locality is per method, so adding a method in a minor never changes whether an interface can be reached remotely.

- **A method is local** when its parameters or results contain a non-remotable capability kind. The compiler infers it, and records it in the interface's metadata. `[local]` may also be written on a method, to make it local by choice.
- **A manager's generated dispatcher refuses** a call to a local method, on a session that came through a network server, with `local_only`, before dispatch, so nothing ran. Network server A is IDL-unaware and can't make this check. It already refuses any request that carries a non-remotable capability, with `capability_not_remotable`.
- **An interface is local** only when it declares `[local]` or `[kernel]` explicitly. The catalog records the mark. A manager refuses a bind that arrives through a network server to a local interface, with `local_only`.
- **A session's remoteness is bind state.** The manager knows whether the bind came through a network server, and records it beside the minor. How the forwarded bind says so is D39's and D66's ([L05](#l05-the-bind-message)).

### Sessions, badges and proxies

seL4 doesn't tell a server when a client deletes a capability, and capabilities are copied freely: every IPC transfer is a copy, and passing session capabilities as parameters is the point of 0066. So a close must never end the session for another holder. **Each holder closes only its own badge.**

- **A session has one or more badges.** The bind returns the first. `session_dup` returns another badge of the same session: the same object, interface, minor, authority and remoteness, with rights no greater than the badge it was sent on. The manager keeps a parent copy of each badge it minted, so it can revoke one badge, or all of them.
- **`session_close` releases the badge it is sent on, and only that badge.** The manager revokes its kept copy of that badge, which deletes every copy made from it. The session itself ends when its last badge is released; or at once when its token expires, when it is revoked ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 1), or when idle rundown ends it.
- **The binding owns badges, and closes only what it owns.** A session handle in a generated binding owns one badge. When its last local handle goes, the binding sends `session_close` on that badge.
  - **Moving** a session capability as a parameter (the Rust stub takes it by value) sends that badge and gives it up. The sender's binding then never closes it, and the receiver's binding owns it.
  - **Sharing** one (the stub takes it by reference) makes the stub call `session_dup` first, and send the new badge. The sender keeps its own, and each holder closes only its own. A dup is one local call, to the manager, or to network server B for a proxy.
  - A capability received as a parameter is owned by the receiver's binding, like one from a bind.
  - If a call that carried a new badge comes back unreachable, the stub releases that badge itself. If it comes back indeterminate, the badge may have arrived, so it is left to idle rundown or the session's end.
  - A program that copies a session capability with raw capability-space operations, outside the binding, gets no such protection: closing any copy's badge deletes them all. The runtime's spawn and initial-capability paths use the binding.
- **Limits.** At most 64 badges per session by default (`resource_limit`, `badges_per_session`). C18 tunes it.
- **Proxies follow the same rule.** When B mints a proxy for an imported descriptor, it is a badge of B's proxy endpoint, owned by the receiving process's binding.
  - `session_dup` on a proxy badge is answered by B itself: it mints another badge for the same import, and counts it.
  - `session_close` on a proxy badge is also B's: it revokes that badge. When the last local badge of an import is released, B sends `export_release` with the wire delta to A. A then sends `session_close` on the badge it kept in its export table. That badge was one only A held, since the sending stub moved or duplicated it.
- **A proxy lives until the first of:** the release of its last local badge on B; the end of the session the export came from (closed, revoked or expired); or the loss of the connection. On the second and third, B revokes its kept parent of every badge of the import, which deletes every copy it passed on ([0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 4).
- **Revoking the session kills every proxy.** When the manager ends the session, every badge of it dies, and calls through A's exported copy fail with `session_ended`. A then drops the export and sends `export_ended` to the importer. The importer revokes every badge of its proxy, and does the same for anything it re-exported. A call that reaches a dead session fails with `session_ended`, so no call outlives the revocation. A learns of a revocation on the next use, or from the manager's error. Prompt notice without a call is open ([L07](#l07-sessions-across-reconnection)).
- **Managers also run down idle sessions**, and sessions whose token expires ([0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), rule 1). Idle rundown is the backstop for badges whose holders never close them.
- **Imports.** At most 256 live imports per session, by default. C18 and C29 tune it. B refuses a call that would exceed it with `resource_limit`, and releases what it received.

### Server streams in the IDL

Streams are server streams only: one construct, a method's result `stream<T>`. It is pulled with credit on kernel IPC, pushed within QUIC's credit between nodes, and resumable from a 64-bit position. Client and bidirectional streams are left out ([L29](#l29-client-and-bidirectional-streams)); uploads use `bytes` and spilling.

```
/// Streams every change matching `query` after `after` (ADR 0028, rule 6).
[group(discover), readonly]
@2 watch(query: query, after: u64?) -> (at: u64) stream<change> error(query_too_broad);
```

- **`stream<T>` appears only as a method's result**, after the optional ordinary results. It is DCE's pipe made resumable: top level only, never nested.
- **`T` is a struct type with no capabilities in it.** Items are pure data, so network servers forward them without exporting anything. A credential rotation stream says "generation g is ready", and the client fetches the read-only object with an ordinary call.
- **Every stream method has a resume parameter, `after: u64?`.** Absent means "from now", or as the method's doc says. Present means "every item with a position greater than this". The compiler requires it, so the binding can resume any stream.
- **Kinds**, as a method attribute:
  - lossless, the default. When history is gone, the stream ends `expired`, which means list again. Catalog and enumeration watches are lossless;
  - `[lossy]`: reports a lost entry, and continues. Log tails are lossy;
  - `[coalescing]`: always delivers the newest item, and skips older ones. Credential generations coalesce.
- **Opening is the authorized action.** `aspis.catalog/1/watch` is the Cedar action, with its request ID and deadline. Pulls ride the session.
- **The opening reply** has the stream flag. Its body is the stream ID (u32, not 0, unique within the session), then the **start position** (u64), then the method's reply struct. The start position is the position the first pull continues after: the `after` the client passed, or, when it passed none, the server's current position for "from now". So the binding always knows where it is, for any stream, and can resume it generically.

### Stream messages

The grammar is in [the call-header grammar](#the-call-header-grammar).

- **A stream item** (`%x05`) is a batch of entries. It is empty only in a local pull's immediate answer ([Local pull with credit](#local-pull-with-credit)). An entry is one of:
  - `item`: a position, then the item as `octets`;
  - `progress`: a position only, meaning nothing for this stream up to there. It is a bookmark;
  - `lost`: a position, and how many items before it are gone.
- **Positions** are u64, strictly increasing within a stream, and not necessarily contiguous: the catalog's sequence number ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 6), a log record's sequence number ([0042](../decisions/0042-log-ring-and-panic-path.md), rule 3), a credential generation.
- **Every entry is length-delimited**, so a network server can split or merge batches at entry boundaries without the IDL. Network server A then answers local pulls of any size from its buffer.
- **A stream end** (`%x06`) is an end reason: complete, closed, expired, session ended, error or superseded. With `error`, an error envelope follows. The end reason is an open enum, written context-free in the grammar. A reason the receiver doesn't know carries no envelope, and is read as `closed`: reopen, or give up.
- **Lossless streams send progress entries** when a filter skips positions, so a quiet watcher can resume without re-listing after history is compacted. This is the lesson of Kubernetes' bookmarks.

### Local pull with credit

On kernel IPC, a stream is pulled.

- **The pull.** The client calls `stream_next(stream ID, after, max_items)`, with its own deadline. **`max_items` is the credit.** The server sends at most that many entries, and only in reply to a `stream_next`. It never pushes.
- **A pull never blocks.** The server answers at once: with a stream item holding up to `max_items` entries, or an empty batch (entry count 0) when nothing is ready; or with a stream end. A server that held a pull until an item arrived would keep the caller's donated scheduling context while serving others. Every idle pull whose deadline passed would then give the server a context-withdrawn fault ([0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 3). The catalog replica and the network servers' client-serving threads are passive, so pulls must return.
- **Waiting is on the readiness eventcount**, the pattern [0053](../decisions/0053-eventcounts.md) provides. `stream_ready` returns an eventcount with read, and the server advances it once for each item it makes available. The binding reads the count v, pulls, and, given an empty batch, waits for the count to pass v with the caller's deadline, then pulls again. An item that arrives between the read and the pull advances the count, so no wakeup is lost. The binding fetches the eventcount once per stream, on the first empty batch.
- **Pulls are idempotent.** `after` names the position the client continues from, so a retried pull is idempotent, and the server keeps only the stream's filter, not a per-client buffer.
- **An `after` older than the server keeps.** A lossless stream ends `expired`. A lossy one sends a `lost` entry, and continues. Opening with such an `after` fails with `stream_expired`.
- **Close** the stream with `stream_close`. A pull returns at once, so there is no blocked pull to cancel. A wait on the eventcount is canceled as any kernel wait is ([0054](../decisions/0054-ipc-endpoints.md), rule 6).
- **Many streams.** A program waiting on many streams waits on their eventcounts, up to 60 in one wait set ([0053](../decisions/0053-eventcounts.md), rule 4), then pulls. A server with many watchers of one collection may share one eventcount per collection. The catalog replica's eventcount then mirrors its sequence numbers, which is [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 6's local delivery.

### Remote push within QUIC's credit

Between nodes, a stream is pushed.

- **One ASPIS stream is one QUIC stream**: the opening call's own. After the opening reply, B's network server pushes stream-item frames, then a stream-end or error frame, then FIN.
- **B pulls** from the local server as a local client, after the last position it pulled. It waits on the stream's eventcount between pulls, on a thread with its own scheduling context, since that is work with no caller present ([0051](../decisions/0051-scheduling-timers-and-deadlines.md), rule 3). It writes entries only while QUIC's MAX_STREAM_DATA credit allows. **QUIC's credit is the flow control**: ASPIS adds no credit messages on the wire. B never sends an empty batch.
- **A buffers** at most the window it advertises, and raises MAX_STREAM_DATA only as its local client consumes. It answers the local client's `stream_next` from the buffer, at once, splitting batches at entry boundaries. It answers `stream_ready` with an eventcount of its own, advanced per item. That is the bridge [0053](../decisions/0053-eventcounts.md), rule 9 describes.
- **The window always fits a whole entry.** The compiler records each stream method's worst-case entry size: the item type's maximum encoded size, plus 13 octets (kind, position, length). A advertises a per-stream window of at least the larger of 64 KiB and that worst case plus 20 octets of framing (the frame header, word 0 and the entry count). So B can always send one whole entry, and A can always hand one whole entry to its client; neither waits on the other. The 16 MiB message limit bounds the window, and A charges its buffers to its own job ([0058](../decisions/0058-jobs-and-budgets.md)).
- **Close.** A local `stream_close` becomes STOP_SENDING and RESET_STREAM with `ASPIS_CANCELED`. B then sends `stream_close` to the server.
- **A lost connection.** A ends the local client's stream with `unreachable` or `indeterminate`. The generated binding reopens the stream with `after` set to the last position it delivered (or the start position, if it delivered none), unless the caller opted out. Opening a watch has no side effects, so this is safe. For a lossless stream, the application sees nothing, or `expired` if history is gone (list again). That gives [0028](../decisions/0028-discovery-and-realm-catalog.md), rule 6's "misses no change and sees none twice".
- **Deadlines.** The opening call's deadline crosses as a duration. The stream itself has no deadline. Each local pull has its own, which A answers.

### Stream limits and rundown

| Limit | Default | Owner of the value |
|---|---|---|
| Capability positions per message, each direction | 3, or 2 when the body may spill | 0066 (fixed) |
| Live imports per session | 256 | C18, C29 |
| Badges per session | 64 | C18 |
| Open streams per session | 16 (`resource_limit` beyond) | C18 |
| Idle rundown: no pull for | 60 s, then the stream ends `closed` | C18 |
| QUIC window per stream | the larger of 64 KiB and the stream's worst-case entry plus 20 octets | C29 (the 64 KiB floor) |
| Open streams per connection | QUIC's MAX_STREAMS | D67 |

A server must end every stream of a session, with `session_ended`, when the session ends. A network server ends the local half of every stream on a lost connection. The defaults are tuned by C18 and C29 ([L24](#l24-per-session-defaults)).

### Worked fits

- **The catalog watch,** `aspis.catalog/1/watch(query, after) -> stream<change>`: lossless, with one readiness eventcount per replica.
- **The kernel log ring** ([0042](../decisions/0042-log-ring-and-panic-path.md), rule 5): `aspis.kernel.log_ring/1/tail(after) -> stream<log_record>`, `[lossy]`, served by the kernel through the interface library. As a kernel interface it has no wire form. The library implements `stream_next` as a non-blocking read of the ring from a sequence number, and the wait between reads as the ring's own "wait for new records" operation with a deadline (ADR 0042, rule 5; [0053](../decisions/0053-eventcounts.md), rule 7). Whether that wait is an eventcount the library can hand out through `stream_ready` is the kernel interface's detail (C05, C17). Lost entries carry ADR 0042's gap.
- **Workload credentials** ([0025](../decisions/0025-twelve-factor-app-contract.md), rule 5): `watch_credentials(after) -> stream<generation>`, `[coalescing]`. Locally it uses the same eventcount that ADR 0025, rule 5 describes.

## The IDL

[0067](../decisions/0067-the-aspis-idl.md) settles the ASPIS IDL. C07 builds it, then C31 and C52 add their back ends.

### The lineage

- **A new IDL in the NCS/DCE lineage.** It keeps the lineage's interface header (an ID and `version(M.m)` in bracketed attributes), bracketed attributes on declarations, at-most-once calls with `[idempotent]` as the exception, and tagged unions. Its bodies are modern: `name: type` declarations, `->` results, explicit `@n` method numbers, and bounded generic types.
- **What it leaves out of C706 (DCE 1.1 RPC):** pointer classes, `size_is` and `length_is` expressions, NUL-terminated `[string]` arrays, operation numbers implied by order, and the separate ACS file.
- **The IDL is the source of truth** ([0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 3). The compiler generates the wire grammar, the canonical-text grammar, the Rust bindings, the Cedar schema fragment and the HTTPS binding from it.
- **Every variable-length type declares its maximum.** So the compiler knows each method's worst-case encoded size and capability count, and checks them statically against [Size limits](#size-limits) and [Capability indexes](#capability-indexes). Decoders never allocate without a bound.
- **The JSON mapping is part of the IDL**, defined now, because the canonical call text uses it ([The JSON mapping](#the-json-mapping)). The HTTPS bindings (D116, C52) inherit it.
- **The attribute set is closed.** The compiler knows every attribute, and an unknown one is an error. There are no user-defined annotations in edition 2026.
- **The compiler is a Rust host tool and a `no_std` library**, MPL-2.0, with a hand-written parser, so the catalog can run the same checks ([0027](../decisions/0027-applications-extend-the-system.md), rule 2; [Crates](#crates)).

### Files and the interface header

- **One file per interface major version**, UTF-8, extension `.idl`, under a new top-level `interfaces/` directory that mirrors the dotted name: `interfaces/aspis/catalog/v1.idl`. Beside it, committed and checked:
  - `v1.0.abnf`, `v1.1.abnf`, …: the wire grammar of each minor;
  - `v1.1.text.abnf`: the canonical-text grammar of each minor;
  - `v1.1.vectors`: each minor's vectors;
  - `v1.idl.lock` ([The lock and the canonical form](#the-lock-and-the-canonical-form)).
- **SPDX tags** are `//` comments on the first two lines. The IDL is code, so it is MPL-2.0.
- **`edition 2026;`** is the first declaration. Later editions may change defaults without breaking old sources, as protobuf editions do.
- **Imports.** `use aspis.base/1.{object_info, interface_req};` brings named types of another interface's major into scope. Types are namespaced by interface and major, as `aspis.base/1.object_info`.

**The header** uses DCE's bracketed attributes:

```
[id(aspis.kernel.eventcount), object_id(reserved(0x0103)), version(1.0)]
interface eventcount { ... }
```

- **`id(...)` is required**, and holds the interface's full dotted name ([Interface and type names](#interface-and-type-names)). Cedar actions, scopes, the call text and `use` lines need the name.
- **`interface` takes the name's last label**, and the checker requires the two to match. Inside the file, types and members are named relative to it.
- **`object_id(...)` holds the interface's 32-octet object ID**, which bindings need at build time, since binding always uses IDs ([0027](../decisions/0027-applications-extend-the-system.md), rule 7). Until D34 fixes the ID text form, it is written `reserved(n)` (the reserved authority with the well-known sequence number n, which D35 assigns) or `hex(<64 lowercase hex digits>)`. Who mints an application's interface IDs is D110's. If D110 derives IDs from names, the compiler computes the ID, and the attribute becomes optional ([L03](#l03-minting-application-ids-and-prefix-ownership)).
- **`version(M.m)`** is the newest minor the file describes. M and m are 0 to 65,535.

### Types

Integers are big-endian ([Core rules](#core-rules)). Nothing is padded or aligned inside a body.

| IDL type | Encoding | Size in octets | Bounds and rules |
|---|---|---|---|
| `bool` | `bool` | 1 | `%x00` or `%x01` only |
| `u8` `u16` `u32` `u64` | core rule | 1, 2, 4, 8 | |
| `i8` `i16` `i32` `i64` | core rule, two's complement | 1, 2, 4, 8 | |
| `f32` `f64` | core rule, IEEE 754-2019 | 4, 8 | The canonical NaN. Not allowed in an object type's attributes or in Cedar context, since Cedar has no float. |
| `id` | `object-id` | 32 | any ID version |
| `uuid` | `uuid` | 16 | RFC 9562 |
| `string<N>` | `text` | 4 + at most N | UTF-8, no U+0000, no normalization; N counts octets; 1 ≤ N ≤ 2^32 - 1 |
| `bytes<N>` | `octets` | 4 + at most N | 1 ≤ N ≤ 2^32 - 1 |
| `seq<T, N>` | `count32`, then the elements | 4 + at most N elements | 1 ≤ N ≤ 2^32 - 1 |
| `array<T, N>` | exactly N elements, no prefix | N × size when T is fixed-size ([Open and closed types](#open-and-closed-types)); otherwise the sum | 1 ≤ N ≤ 65,535 |
| `T?` | a tail field in an open struct; `presence`, then T, elsewhere | | [The struct encoding](#the-struct-encoding) |
| `struct` (open) | head, then tail | | [The struct encoding](#the-struct-encoding) |
| `[closed] struct` | head only | | never grows |
| `union` (open) | `arm-tag`, then the arm as `octets` | 6 + the arm | arms `@1`, … are explicit |
| `[closed] union` | `arm-tag`, then the arm | 2 + the arm | |
| `enum name: u8` (or `u16`, `u32`) | the declared width | 1, 2 or 4 | values explicit; open unless closed |
| `flags name: u8` (to `u64`) | the declared width | 1 to 8 | bit values explicit; open unless closed |
| `cap<...>` | `cap-ref` | 1 | [Capability types](#capability-types); at most 3 per message in each direction |
| `slot<...>` | `u64` | 8 | `[kernel]` interfaces only: a capability address, no transfer |
| `stream<T>` | [Stream messages](#stream-messages) | | a method result only |
| `const name: u32 = 60;` | none | | integer constants, for bounds and docs |
| `alias name = type;` | as the type | | |
| `[format(json)] string<N>` | `text` | | JSON text carried as a string, such as AuthZEN's ([0019](../decisions/0019-authzen-decision-protocol.md), rule 2). The JSON mapping embeds it as JSON. |

- **Element types** of `seq` and `array` are any type except `cap<...>`, `stream<...>` and an error. Every element is self-delimiting, so a sequence needs only a count.
- **Not in edition 2026:** maps, user-defined generic types, recursive types and interface inheritance. Objects implement several interfaces instead, as AEGIS traits and COM's `QueryInterface` did ([0014](../decisions/0014-versioned-object-apis.md), rule 5).
- **Limits.** Identifiers are 1 to 63 octets. Type nesting is at most 32 deep. A method's worst-case request and reply are each at most 2^24 octets with the largest header. At most 3 capability positions in each direction, or 2 if the body may spill, judged against the largest header: 704 octets of request body, or 952 of reply or item body ([Spilling](#spilling)).

### Object types

[0018](../decisions/0018-cedar-policy-language.md), rule 4 has the compiler turn object types into Cedar entity types, so the IDL declares them. An object type is declared inside the interface file of the manager that serves it:

```
/// A file in a directory.
[type(aspis.file), parents(aspis.directory)]
object file {
    owner: id,
    size: u64,
    [since(1.1)] labels: seq<string<63>, 16>?,
}
```

- **`type(...)`** holds the full dotted type name, whose last label matches the name after `object`. It is the Cedar entity type `aspis::file` and the AuthZEN `resource.type` ([One string everywhere](#one-string-everywhere)).
- **`parents(...)`** lists the types that an entity of this type may have as parents: Cedar's `memberOfTypes`.
- **Attributes** use the IDL's types, limited to those with a Cedar mapping: no floats, `bytes`, capabilities, slots or streams. An optional attribute is a Cedar optional attribute. Attributes are what the manager reports to the PDP for an object, and they grow by the struct rules: only optional attributes, appended in a minor.
- **Still open, with C31:** the exact Cedar mapping of each attribute type, entity tags, and how the manager presents attributes in an AuthZEN request ([L44](#l44-object-types-in-cedar)).

### Example: the eventcount interface

A kernel interface, with doc comments and the kernel attributes:

```
// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0
edition 2026;

//! Eventcounts: the kernel's asynchronous primitive (ADR 0053).

[id(aspis.kernel.eventcount), object_id(reserved(0x0103)), version(1.0), kernel]
interface eventcount {
    /// The count is already 2^64 - 1, its maximum.
    [refused]
    error overflow = 1;

    /// Adds one to the count, and wakes every waiter whose target it reaches.
    [requires(write)]
    @1 advance() -> u64 error(overflow);

    /// Blocks until the count reaches `target`, or until `deadline`,
    /// an absolute value of the node's virtual count (ADR 0051, rule 5).
    [requires(read), readonly]
    @2 wait(target: u64, deadline: u64?) -> u64;

    /// Returns the count.
    [requires(read), readonly]
    @3 read() -> u64;
}
```

- **The target object is implicit.** For a `[kernel]` interface it is the capability the call is made through; for a server interface, the session.
- **`[kernel]`** means the interface is reached through the interface library's function tables ([0059](../decisions/0059-the-kernel-interface-library.md), rules 1 and 5). The compiler emits types, signatures, the canonical-text grammar and the function-table types, but no wire grammar. Every `[kernel]` interface is also `[local]`.
- **`deadline` is optional**: absent means wait without one. As an optional parameter it is tail position 2 in the request struct. For a kernel interface that matters only to the JSON mapping and the text form, since there is no wire form.
- **System errors are implicit.** "Timed out", "canceled" and the other system errors may come from every method ([The system errors](#the-system-errors)). `error(...)` lists only the interface's own.
- **Canonical text:** `aspis.kernel.eventcount/1/wait - {"target":"42"}`.

The `0x0103` here, and the catalog's `0x0201` below, are placeholders until D35 assigns the well-known numbers ([L02](#l02-reserved-numbers)).

### Example: the catalog across two minors

`aspis.catalog` at 1.1 shows an open enum, a closed struct, an open union, an error set with detail, a capability parameter, a sensitive field, a stream method, and optional fields added in minor 1.1. It is illustrative: the catalog's real interface is C51's, with D111 to D114.

```
// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0
edition 2026;

//! The realm catalog (ADR 0028).

[id(aspis.catalog), object_id(reserved(0x0201)), version(1.1), groups(discover, register)]
interface catalog {
    /// Most entries in one page.
    const max_page: u32 = 256;

    /// What happened to an entry.
    enum change_kind: u8 {
        registered = 1,
        withdrawn = 2,
        available = 3,
        unavailable = 4,
    }

    /// One change, at a catalog sequence number.
    struct change {
        seq: u64,
        kind: change_kind,
        entry: id,
        /// The entry's publisher, where it has one.
        [since(1.1)]
        publisher: id?,
    }

    /// An interface and the versions acceptable.
    [closed]
    struct interface_req {
        interface: id,
        major: u16,
        min_minor: u16,
    }

    /// What a query selects by.
    union selector {
        @1 by_id: id,
        @2 by_name: string<255>,
        @3 by_interface: interface_req,
    }

    struct query {
        select: selector,
        limit: u32?,
    }

    /// The query selects more than one watch may follow.
    error query_too_broad = 1 { limit: u32 };

    /// That interface version is already registered.
    [refused]
    error already_registered = 2;

    /// Lists the entries matching `query`, a page at a time, at one sequence number.
    [group(discover), readonly, idempotent]
    @1 list(query: query, page: bytes<64>?)
        -> (at: u64, entries: seq<id, max_page>, next_page: bytes<64>?)
        error(query_too_broad);

    /// Streams every change matching `query` after `after` (ADR 0028, rule 6).
    [group(discover), readonly]
    @2 watch(query: query, after: u64?) -> (at: u64) stream<change> error(query_too_broad);

    /// Registers an interface version from its signed definition.
    [group(register)]
    @3 register(
        definition: cap<aspis.kernel.memory/1, read, immutable>,
        length: u32,
        [sensitive] proof: string<8192>,
        [since(1.1)] dry_run: bool?,
    ) -> u64 error(already_registered);
}
```

What the compiler derives from it:

| Item | Derived |
|---|---|
| `change` | An open struct. Head `seq`, `kind`, `entry` (41 octets); tail tag 4, `publisher`, since 1.1. |
| `interface_req` | Closed, 36 octets, usable in arrays. |
| `selector` | An open union. Unknown arms are preserved. |
| `query` | An open struct. Head `select`; tail tag 2, `limit`. |
| `register` request | Head `definition` (1 octet, capability index 0), `length`, `proof`; tail tag 4, `dry_run`, since 1.1. Its worst case is over 704 octets, the inline body beside the largest header, so the request may spill: at most 2 capabilities, and it uses 1. It needs the grant right on the session capability, and grant-reply, as every session does ([Rights a session needs](#rights-a-session-needs)). |
| `watch` | A stream method, lossless, with the required `after: u64?`. |
| Cedar actions | `aspis.catalog/1/list`, `/watch` and `/register`; the groups `aspis.catalog/1/@discover` (list, watch) and `/@register` (register). |
| Canonical text, arguments on | `aspis.catalog/1/register <id-text> {"definition":{"cap":0},"length":5120,"proof":null}` |

At 1.0, the same file without the two `[since(1.1)]` members projects to the 1.0 canonical form, whose hash `v1.idl.lock` keeps. The compatibility check confirms that 1.1 only appended optional fields.

### Attributes

The attribute set is closed.

| Attribute | On | Meaning |
|---|---|---|
| `id(...)` | interface | Required. The interface's full dotted name. `interface` takes its last label. |
| `object_id(...)` | interface | The interface's 32-octet object ID. Required until D110 says whether IDs derive from names. |
| `type(...)`, `parents(...)` | object | The object type's full dotted name, and the types its entities' parents may have ([Object types](#object-types)). |
| `version(M.m)` | interface | Required. The newest minor described. |
| `kernel` | interface | Reached through the kernel interface library. No wire grammar. Implies `local` ([0059](../decisions/0059-the-kernel-interface-library.md)). |
| `local` | interface, method | On an interface: never reached across nodes; a bind through a network server is refused. On a method: refused on a remote session. The compiler also infers it for any method whose parameters or results hold a non-remotable capability kind ([Local methods and interfaces](#local-methods-and-interfaces)). |
| `oneway` | a method of a `[local]` interface | No reply of any kind, not even an error. The request is sent with send, not call, and the method has no results and no `error(...)` list. In edition 2026 only `[local]` interfaces may use it; `aspis.kernel.pager` and `aspis.kernel.memory_request` do ([Messages the kernel sends](#messages-the-kernel-sends)). Its request ID may be zero only in kernel-sent requests. |
| `groups(g, ...)` | interface | Declares action groups. Each becomes the Cedar action group `iface/major/@g` ([0018](../decisions/0018-cedar-policy-language.md), rule 4). |
| `group(g, ...)` | method | The groups the method belongs to. Fixed once published ([Action groups](#action-groups)). |
| `idempotent` | method | Safe to run more than once with the same effect, so a client may retry after the reply cache expired. From DCE. |
| `readonly` | method | Changes no state. Feeds retries and the HTTPS method mapping (D116). |
| `lossy`, `coalescing` | stream method | The stream kind; lossless otherwise ([Server streams in the IDL](#server-streams-in-the-idl)). |
| `requires(rights)` | a method of a `[kernel]` interface | The rights the invoked capability needs ([0049](../decisions/0049-capability-spaces-rights-and-revocation.md), rule 2). |
| `static` | a method of a `[kernel]` interface | No target capability. |
| `since(M.m)` | any member, field, arm or value | The minor that added it. Absent means M.0. |
| `deprecated(M.m)` | any member, field, arm or value | Deprecated as of that minor. The text goes in the doc comment. |
| `sensitive` | field, parameter, result | Redacted in the canonical text and in logs; never in a span attribute ([The canonical call text](#the-canonical-call-text)). |
| `closed` | struct, union, enum, flags | Never grows within the major ([Open and closed types](#open-and-closed-types)). |
| `refused` | error | The error promises that the method didn't run ([Outcomes](#outcomes)). |
| `retry(never \| later \| rebind \| higher)` | error | The error's default disposition, 0 to 3 ([The error envelope](#the-error-envelope)). `never` if absent. |
| `format(json)` | `string<N>` | The string holds JSON text. |

### Doc comments

- **Syntax.** `///` documents the item that follows, and `//!` the file. They use a CommonMark subset: paragraphs, lists, code spans, fenced code and links, with cross-references written `[aspis.catalog/1.watch]`.
- **An error's doc comment is its description** ([The error envelope](#the-error-envelope)).
- **The compiler emits a doc model.** How dm renders it is the dm design's ([0011](../decisions/0011-dm-window-system.md), rule 6; [L32](#l32-rendering-doc-comments)).
- **Docs aren't part of the canonical form**, so fixing one needs no new minor.
- **Support periods aren't IDL attributes.** A major's support period and deprecation dates are registration data in the catalog (D115), because dates in the source would change the interface's hash and force a new minor. The IDL carries only `[deprecated(M.m)]` ([L17](#l17-registration-documentation-revisions-and-support-periods)).

### How numbers stay stable

- **Methods:** explicit `@n`, 1 to 65,279, unique in the major, never reused. A new major that drops a method keeps `reserved @n;`.
- **Union arms:** explicit `@n`, 1 to 65,535, never reused. `reserved @n` inside the union retires one.
- **Enum and flag values:** explicit, never reused. `reserved n` inside the type retires one.
- **Error codes:** explicit `= n`, 1 to 65,535, never reused.
- **Struct fields:** by position ([The struct encoding](#the-struct-encoding)). Fields are only appended. The compiler refuses a reorder, removal or rename against the lock file.

### The lock and the canonical form

- **The canonical form** of one minor is the source projected to that minor, with comments and docs removed, every derived number written out (field tags as `@n`), attributes in a fixed order, and fixed whitespace. Its octets are what the lock and the catalog hash ([0028](../decisions/0028-discovery-and-realm-catalog.md), rule 2). Where documentation revisions live, beside that hash, is D111's and D114's.
- **The lock file**, `v1.idl.lock`, records, for each published minor, the SHA3-256 hash of that minor's canonical form. SHA3-256 is the authorization tree's hash function ([0016](../decisions/0016-authorization-sparse-merkle-tree.md); C27).
- **`idlc check`**, and the catalog on registration, does this for each published minor m-1 below the file's version:
  1. projects the source to m-1, computes the canonical form's hash, and compares it with the lock (or the catalog's stored version). A mismatch means a published minor was edited, and fails;
  2. checks that the step from m-1 to m makes only the changes [The compatibility check](#the-compatibility-check) allows;
  3. runs that section's vector check.
- **Publishing a minor** adds its hash to the lock, in the same change.

### The JSON mapping

One mapping serves the canonical call text (output only, in M2) and the HTTPS bindings and OpenAPI (D116, C52, which add the parsing side). It produces I-JSON (RFC 7493) over RFC 8259.

| IDL type | JSON |
|---|---|
| `bool` | `true` or `false` |
| `u8` `u16` `u32` `i8` `i16` `i32` | a number |
| `u64` `i64` | a string of decimal digits, no leading zeros, with `-` for a negative `i64`. I-JSON can't carry them exactly as numbers (RFC 7493, §2.2). |
| `f32` `f64` | A number. For `f64`, RFC 8785 §3.2.2.3's serialization, except that negative zero is written `-0`: RFC 8785, following ECMAScript, writes `0`, which would lose a value the wire keeps distinct. For `f32`, the shortest decimal that round-trips to the same binary32, with the same exception. NaN and the infinities are the strings `"NaN"`, `"Infinity"` and `"-Infinity"`. |
| `id` | a string: D34's text form. Until D34, 64 lowercase hex digits. |
| `uuid` | a string: RFC 9562's 36-character lowercase form |
| `string<N>` | a string, escaped as RFC 8785 §3.2.2.2 does (only `"`, `\` and control characters) |
| `[format(json)] string<N>` | the JSON value itself, embedded |
| `bytes<N>` | a string: base64url without padding (RFC 4648, §5) |
| `seq`, `array` | an array |
| struct | An object. Keys are field names, in declaration order. An absent optional field is omitted. An unknown tail field is the key `"@<tag>"`, with its raw octets as base64url. |
| `T?` outside a struct field | the value, or `null` when absent |
| union | an object with exactly one key, the arm's name. An unknown arm is `{"@<tag>":"<base64url>"}`. |
| enum | a string, the value's name. An unknown value is its number (enums are at most `u32`). |
| flags | An array of the set bits' names, in value order. Unknown bits come as one value at the end, written as the integer of that width is: a number up to `u32`, and a decimal string for `u64`, so it stays within I-JSON. |
| `cap<...>` | `{"cap":N}`, the capability index |
| `slot<...>` | `null`: a capability-space address is never rendered ([The canonical call text](#the-canonical-call-text)) |
| an error envelope | [Errors in bindings and text](#errors-in-bindings-and-text) |
| a redacted (`[sensitive]`) field | its key, with the value `null` |

- **The call text** uses the mapping's compact form: no whitespace, keys in declaration order, a method's parameters as one object (`call-args`) and its results as another (`reply-results`). A single unnamed result, `-> T`, is the key `result`.
- **Parsing** (D116): inputs may order keys freely; unknown names are an error, unless they are `"@<tag>"` forms; and `null` for an optional field means absent. D116 settles the rest, including problem details for errors (RFC 9457), and how capabilities and streams appear at the HTTPS edge (D120; [L15](#l15-the-https-binding), [L16](#l16-streams-over-https)).
- **Cedar** (C31): `u8` to `u32` and the signed types map to Cedar's `Long`. `u64` maps to `Long` only where the value fits in 2^63 - 1, and a value above it makes the decision fail closed. Floats and capabilities have no Cedar mapping, and can't be entity attributes or context. C31 settles the rest ([L12](#l12-cedar-schema-details)).

### Generated grammars

- **One file per interface version**, such as `v1.1.abnf`, with `; uses: core`. CI regenerates it, and fails if it differs from the committed file.
- **Rule names are one to one with what they name.** Each name maps `_` to `-`, since RFC 5234 rule names can't contain `_`. A member name never has `__` or a trailing `_` ([Member names](#member-names)), so `--` never comes from a name, and `--` separates a name from what follows it. Every rule carries a prefix, so none collides with the core rules or `call-header.abnf`:
  - types are `t-<type>`; a struct's field rules `t-<type>--<field>`, its tail `t-<type>--tail`, its tail alternatives `t-<type>--opt`, and its unknown-field rules `t-<type>--unknown` and `t-<type>--unknown-tag`;
  - method bodies are `m-<method>--req`, `m-<method>--rep` and `m-<method>--item`, with helpers `m-<method>--req--tail` and so on;
  - error details are `e-<error>`, with helpers `e-<error>--tail` and so on;
  - an imported type's rules are `u<k>--t-<type>`, where k is the import's position in the file's `use` lines, so two imports never clash.
- **Every open struct gets its own tail rules**, method requests and replies included: known optional fields as literal-tagged alternatives, and, in reply, item and error-detail grammars, one unknown alternative whose tag is at least the position after the last field known at that minor. Generated grammars never use the core rule `tail`, which can't bound a tag from below.
- **Bounds become constraints:** `; constraint: at most 255` on a `len32`, `; constraint: at most 256` on a `count32`.
- **Request grammars are strict**, with no unknown alternative. Reply, error-detail and item grammars carry one per open struct.
- **Vectors** (`v1.1.vectors`) are golden encodings from the Rust encoder, plus hand-written `err` and `errc` cases.

For example, for `watch`, with the `change` rules of [The struct encoding](#the-struct-encoding):

```abnf
; aspis.catalog/1.1, method 2 "watch"
m-watch--req          = t-query m-watch--req--tail
m-watch--req--tail    = tail-count *m-watch--req--after
                        ; constraint: ascending tags
                        ; constraint: exactly tail-count m-watch--req--after elements
m-watch--req--after   = %x00.02 %x00.00.00.08 u64        ; tag 2: after
m-watch--rep          = u64 m-watch--rep--tail           ; at, then an open tail
m-watch--rep--tail    = tail-count *m-watch--rep--unknown
                        ; constraint: ascending tags
                        ; constraint: exactly tail-count m-watch--rep--unknown elements
m-watch--rep--unknown = m-watch--rep--unknown-tag octets
m-watch--rep--unknown-tag = u16
                        ; constraint: at least 2
m-watch--open         = stream-open m-watch--rep        ; the opening reply's body
m-watch--item         = t-change

; struct query, in this request grammar: strict, so no unknown alternative
t-query               = t-selector t-query--tail
t-query--tail         = tail-count *t-query--limit
                        ; constraint: ascending tags
                        ; constraint: exactly tail-count t-query--limit elements
t-query--limit        = %x00.02 %x00.00.00.04 u32        ; tag 2: limit
t-selector            = arm-tag octets                   ; open union selector;
                                                         ; arms 1 to 3 not shown
```

`t-change-kind` is the type `change_kind`; the field `kind` of struct `change` would be `t-change--kind`, so the two never collide.

### Back ends

In build order:

| Order | Back end | Chunk | Notes |
|---|---|---|---|
| 1 | The front end: parse, resolve, check (types, bounds, worst-case sizes, capability counts, names), project, canonical form, lock, compatibility check | C07 | `crates/idl` |
| 2 | ABNF: the wire grammar and the canonical-text grammar of each minor, and vector scaffolding | C07 | committed outputs |
| 3 | Rust `no_std` | C07 | Used by C17 and C18. See below. |
| 4 | Rust `alloc`: owned types (`String`, `Vec`) for host tools and the later `std` port | C07 | Behind an `alloc` feature of the generated crate. It is a library feature, not test code, so [0036](../decisions/0036-qemu-configuration-and-test-builds.md), rule 6 doesn't apply. |
| 5 | The JSON mapping's encoder, for the call text | C07 | `no_std`, into a buffer |
| 6 | The doc model | C07 | dm renders it later |
| 7 | Fuzz support: `arbitrary::Arbitrary` impls under `cfg(fuzzing)`, round-trip tests, and a fuzz-target stub per interface version | C07, with C71 | host only ([The fuzzing gate](#the-fuzzing-gate)) |
| 8 | Cedar schema fragments | C31 | |
| 9 | The HTTPS binding, the JSON decoder, and OpenAPI 3.2.1 | C52 | OpenAPI 3.2.1 (2026-09-10) is a patch release of the 3.2 that [0027](../decisions/0027-applications-extend-the-system.md), rule 10 names. |
| 10 | C headers and shims | deferred | Until a C consumer exists. relibc is Rust and builds on `aspis-rt` ([0059](../decisions/0059-the-kernel-interface-library.md), rule 8), so M2 to M5 need none ([L30](#l30-the-c-binding)). |

**The Rust `no_std` back end** emits:

- borrowed decoding views over a message ([Octets and words](#octets-and-words)), and encoders into `&mut [u8]` with no allocator;
- client stubs with per-call options (deadline, request ID), and the move-or-dup rule for session capabilities ([Sessions, badges and proxies](#sessions-badges-and-proxies));
- server traits, with a dispatcher that makes the refusals of [Refusing what is too new](#refusing-what-is-too-new), or, for interfaces the kernel calls, hands unknowns to the handler;
- error enums, and the outcome and `CallError` types.

Every generated interface crate is `#![forbid(unsafe_code)]`, because it decodes input from across a trust boundary ([What the gate covers](#what-the-gate-covers)). For `[kernel]` interfaces, the `#[repr(C)]` function-table types and the glue that reaches ADR 0059's entry table need `unsafe`. They are emitted into `aspis-rt`, the one crate that knows the entry table ([0059](../decisions/0059-the-kernel-interface-library.md), rule 8), and that glue parses nothing.

**Generated Rust names:** types in UpperCamelCase; functions and fields in snake_case, as written. A name that is a Rust keyword is emitted as a raw identifier, such as `r#type`. `self`, `super` and `crate` are refused by the name grammar.

### Crates

| Crate | Kind | Contents | Dependencies |
|---|---|---|---|
| `crates/idl` | `#![no_std]` with `alloc`, `#![forbid(unsafe_code)]` | The lexer, a hand-written recursive-descent parser, the resolver, the checker, projection, the canonical form, the compatibility check, and the ABNF and (later) Cedar back ends. The catalog runs it. | `sha3` (RustCrypto, MIT OR Apache-2.0) for SHA3-256, pending D33's choice of crypto crates; nothing else |
| `crates/idl-rt` | `#![no_std]`, `#![forbid(unsafe_code)]` | The runtime for generated code: core-rule codecs, tails, bounded views, unknown-value carriers, the outcome and error types, the JSON encoder, and the parsers for `interface-ref`, `action-ref` and `error-ref`, which the PDP, the token library and the catalog use | none |
| `tools/idlc` | a `std` command-line tool | `idlc build`, `check`, `fmt` and `lock`; diagnostics | `annotate-snippets` 0.12 (MIT OR Apache-2.0, as rustc uses) |

- **Why a hand-written parser.** It builds `no_std`, gives the best diagnostics, adds no dependency churn, and fuzzes well; rustc, fidlc and wit-parser do the same. Parser generators (pest, lalrpop, chumsky, winnow) would put the grammar in two places, and vary in `no_std` support. The normative grammar is `grammars/idl.abnf`. The parser is checked against its vectors, and fuzzed against it ([Differential tests](#differential-tests)).
- **Generated Rust** is produced at build time by `build.rs`, through `crates/idl`, deterministically ([0038](../decisions/0038-reproducible-builds-and-provenance.md)). Generated grammars and locks are committed. `cargo xtask idl` regenerates and checks them.
- **Tests** are golden files and round trips: every Rust encoding matches the ABNF and its constraints, and corrupted encodings are rejected. Each test file is declared in `Cargo.toml` (`autotests = false`).
- **Toolchain.** Pinned stable Rust 1.100.0, no nightly feature; MPL-2.0 throughout.

### The IDL grammar

The IDL is a machine-read text format, so its grammar is ABNF ([0013](../decisions/0013-abnf-for-protocols-and-calls.md), rule 2; [0031](../decisions/0031-abnf-is-not-a-command-language.md), rule 1). This is a sketch. C07 writes `grammars/idl.abnf` in full, with vectors, and a `; uses: core, names` line that preloads the core grammar (for the UTF-8 rules) and the names grammar ([Checkers](#checkers)). Plain `//` comments are whitespace. `///` and `//!` start doc comments, which the grammar keeps apart.

```abnf
idl-file     = s edition [ file-docs ] s *( use-decl s ) interface s
edition      = %s"edition" w "2026" s ";"
use-decl     = %s"use" w interface-ref ".{" s decl-name *( s "," s decl-name ) s "}" s ";"
interface    = [ docs s ] attrs s %s"interface" w label s "{" *( s member ) s "}"
member       = [ docs s ] [ attrs s ] ( const-decl / alias-decl / struct-decl
               / union-decl / enum-decl / error-decl / object-decl / method
               / reserved-method )
const-decl   = %s"const" w member-name s ":" s int-type s "=" s int-lit s ";"
alias-decl   = %s"alias" w decl-name s "=" s type s ";"
struct-decl  = %s"struct" w decl-name s field-block
object-decl  = %s"object" w decl-name s field-block
field-block  = "{" s [ field *( s "," s field ) [ s "," ] ] s "}"
union-decl   = %s"union" w decl-name s "{" s [ arm *( s "," s arm ) [ s "," ] ] s "}"
enum-decl    = ( %s"enum" / %s"flags" ) w decl-name s ":" s uint-type s "{" s
               [ value *( s "," s value ) [ s "," ] ] s "}"
error-decl   = %s"error" w member-name s "=" s int-lit [ s field-block ] s ";"
method       = "@" ordinal w member-name s "(" s [ field *( s "," s field ) [ s "," ] ] s ")"
               [ s "->" s results ] [ s %s"error" s "(" s member-name *( s "," s member-name ) s ")" ] s ";"
results      = type [ w stream-type ] / "(" s field *( s "," s field ) [ s "," ] s ")" [ w stream-type ]
               / stream-type
stream-type  = %s"stream" "<" s type-ref s ">"
reserved-method = %s"reserved" w "@" ordinal s ";"         ; interface level: methods only
field        = [ docs s ] [ attrs s ] member-name s ":" s type
arm          = [ docs s ] [ attrs s ] "@" ordinal w member-name s ":" s type
             / %s"reserved" w "@" ordinal                   ; a retired arm
value        = [ docs s ] [ attrs s ] member-name s "=" s int-lit
             / %s"reserved" w int-lit                       ; a retired value
type         = base-type [ "?" ]
base-type    = %s"bool" / int-type / %s"f32" / %s"f64" / %s"id" / %s"uuid"
             / ( %s"string" / %s"bytes" ) "<" s bound s ">"
             / ( %s"seq" / %s"array" ) "<" s type s "," s bound s ">"
             / ( %s"cap" / %s"slot" ) "<" s interface-ref *( s "," s cap-qual ) s ">"
             / type-ref
int-type     = uint-type / %s"i8" / %s"i16" / %s"i32" / %s"i64"
uint-type    = %s"u8" / %s"u16" / %s"u32" / %s"u64"
cap-qual     = %s"read" / %s"write" / %s"grant" / %s"grant_reply" / %s"immutable"
bound        = int-lit / member-name                        ; a const
type-ref     = decl-name / interface-ref "." decl-name      ; local or imported
decl-name    = member-name                                  ; a declared type's name
               ; constraint: not word bool u8 u16 u32 u64 i8 i16 i32 i64 f32 f64 id uuid string bytes seq array cap slot stream
attrs        = "[" s attr *( s "," s attr ) s "]"
attr         = member-name [ "(" s attr-arg *( s "," s attr-arg ) s ")" ]
attr-arg     = version-lit / int-lit / interface-name / member-name / id-lit
version-lit  = number "." number
id-lit       = %s"reserved(" s int-lit s ")" / %s"hex(" 64( DIGIT / %x61-66 ) ")"
int-lit      = [ "-" ] ( "0" / %x31-39 *DIGIT ) / %s"0x" 1*( DIGIT / %x61-66 )
ordinal      = "0" / %x31-39 *4DIGIT
               ; constraint: in 1..65535

; ---- Whitespace, comments and doc comments ---------------------------
s            = *( WSP / CR / LF / comment )                 ; optional
w            = 1*( WSP / CR / LF / comment )                ; required
comment      = "//" [ comment-start *doc-char ] LF
               ; a third character "/" or "!" would make a doc comment
comment-start = %x01-09 / %x0B-20 / %x22-2E / %x30-7F / utf8-2 / utf8-3 / utf8-4
docs         = 1*( s "///" *doc-char LF )                   ; the item that follows
file-docs    = 1*( s "//!" *doc-char LF )                   ; the file
doc-char     = %x01-09 / %x0B-7F / utf8-2 / utf8-3 / utf8-4 ; anything but LF and NUL
```

- **Docs are never whitespace.** `comment` can't start with `///` or `//!`, so `s` and `w` never swallow a doc comment. Every place a doc comment may stand is written `[ docs s ]`, which allows the newline and indentation between a doc comment and the attributes or item it documents, as in the eventcount example's `/// ...` then `[refused]`.
- **Built-in type names are reserved.** `decl-name` excludes them, so `u64` as a type is only ever the built-in, and no user type can be named `u64`. `type-ref` uses `decl-name`, which removes the ambiguity between `base-type`'s alternatives.
- **`reserved`** retires a method at interface level (`reserved @n;`), an arm inside a union (`reserved @n`), and a value inside an enum or flags type (`reserved n`).
- **The checker adds what the grammar doesn't say.** It limits method ordinals to 1 to 65,279 ([Method numbers](#method-numbers)). It requires the label after `interface` to equal the last label of `id(...)`, and the same for `object` and `type(...)`.

## The fuzzing gate

[0068](../decisions/0068-the-fuzzing-and-differential-testing-gate.md) settles the fuzzing and differential-testing gate. C71 builds it, and each parser's chunk brings its own targets.

### What the gate covers

- **A parser at a trust boundary isn't done until it passes the gate** ([The gate for each target](#the-gate-for-each-target)). Its input comes from another principal, the network, removable media, the boot command line, or a publisher through the catalog. Its chunk brings its own targets ([build plan](build-plan.md), C71).
- **Fuzzing runs on the pinned stable toolchain only**: Rust 1.100.0 ([0035](../decisions/0035-toolchain-image-linkage-and-esp-layout.md), rule 1). There are no sanitizers, so **every crate that parses input from across a trust boundary is `#![forbid(unsafe_code)]`**, as `crates/initfs` already is. That includes every IDL-generated interface crate. The `unsafe` glue that reaches the kernel interface library's entry table lives in `aspis-rt`, and parses nothing ([Back ends](#back-ends)). The oracle is panics, Rust's overflow checks and debug assertions.
- **Differential tests** check decoders against their grammars, the two ABNF checkers against each other, and ASPIS's PDP against Cedar's own engine.
- **Model checking** is TLA+ with TLC, for leases and catalog sequence numbers.
- **A nightly in-QEMU fuzzer of the kernel's call surface**, generated from the kernel interfaces' IDL, runs from C13 to C17. It doesn't block per-change CI.
- **Partition fault injection** between QEMU instances comes from C40, through an unprivileged host-side switch.
- **Disclosure.** Fuzzing runs in public CI until ASPIS's first release. After it, nightly crash artifacts have short retention and go into a private advisory, and long campaigns run on a private fork or runner ([Triage and disclosure](#triage-and-disclosure)).

### Engine and tools

| Tool | Version | License | Use |
|---|---|---|---|
| cargo-fuzz | 0.13.x | MIT OR Apache-2.0 | The driver, always with `--sanitizer none` (`-s none`), which adds only stable `-C` flags and `--cfg fuzzing` |
| libfuzzer-sys | 0.4.x | (MIT OR Apache-2.0) AND NCSA (the bundled LLVM libFuzzer) | The engine. NCSA is a BSD-style permissive license. |
| arbitrary | 1.5.x | MIT OR Apache-2.0 | Structure-aware inputs. The IDL compiler emits impls ([Back ends](#back-ends)). |
| afl.rs | 0.18.x | Apache-2.0 | A fallback only, if libFuzzer on stable fails C71's first check |
| TLA+ tools (TLC) | v1.7.4, the newest release that isn't a prerelease (v1.8.0 is a prerelease of 2026-11-19) | MIT | Model checking ([Model checking](#model-checking)) |
| Apalache | 0.63.x | Apache-2.0 | Optional, for inductive invariants |
| Eclipse Temurin 21 (LTS), a JRE | pinned to a patch release | GPL-2.0-only WITH Classpath-exception-2.0 | Runs TLC and Apalache. Installed with GitHub's own `actions/setup-java` (`distribution: temurin`), pinned by SHA, as every action in `ci.yml` is. |

- **CI-only tools and ADR 0008, rule 4.** [0008](../decisions/0008-mpl-2.0-license.md), rule 4 governs ASPIS's dependencies: what is linked into ASPIS code, or ships in its images. A tool that only runs in CI, is never linked into ASPIS code and never ships is outside it. That reading covers libFuzzer's NCSA license and the JRE's GPL-2.0 with the Classpath exception alike. `fuzz/`'s cargo-deny configuration, and the model-checking jobs' configurations, name each one explicitly.
- **Not used:**
  - honggfuzz-rs, which links GPL libbfd on Linux;
  - a nightly toolchain for sanitizers. When ASan and LSan stabilize (rust-lang/rust#123617), they come on stable with no rule change;
  - OSS-Fuzz and ClusterFuzzLite, which need an unpinned nightly. Revisit after the first release ([L40](#l40-kernel-coverage-kani-and-oss-fuzz));
  - Cedar's Lean engine, since Cedar's own differential testing covers the engine;
  - Jepsen (JVM, Clojure, EPL).
- **C71's first task** is to show that `cargo fuzz build -s none` and `cargo fuzz run` work on Rust 1.100.0, on aarch64 Linux (the CI runner) and on aarch64 macOS. The evidence so far is cargo-fuzz's source and cedar-spec's stable CI job; it hasn't been run. If it fails, afl.rs on stable (without CMPLOG) takes its place, and the gate stays the same ([L35](#l35-fuzzing-on-stable-rust)).
- **Fuzz-only hooks** in a crate sit behind `cfg(fuzzing)`, never a Cargo feature ([0036](../decisions/0036-qemu-configuration-and-test-builds.md), rule 6). The workspace's `check-cfg` adds `fuzzing` beside `aspis_test_build`.

### Layout

- **`fuzz/` is a separate Cargo workspace**, with its own `Cargo.lock`. The root workspace has `exclude = ["fuzz"]`. Fuzz dependencies never enter the product lock file, the images or the CycloneDX SBOM ([0038](../decisions/0038-reproducible-builds-and-provenance.md)).
- **Files:**
  - `fuzz/fuzz_targets/<target>.rs`;
  - `fuzz/seeds/<target>/`: small, hand-made, committed;
  - `fuzz/regressions/<target>/<name>`: minimized crash inputs, committed. Names are lowercase with hyphens and no spaces, and tools list them with `git ls-files`.
- **Seeds from vectors.** Seeds are also generated at build time from every line of the target's `grammars/*.vectors`, so vectors and seeds can't drift.
- **The growing corpus is never committed, and never in iCloud.** Locally it is `build/fuzz/corpus/<target>` (`build` is a `.nosync` symlink); in CI it is an Actions cache.
- **Target metadata** is a Cargo table, `[package.metadata.aspis-fuzz.<target>]` in `fuzz/Cargo.toml`: the chunk, the ADR, `max_len`, the timeout, the RSS limit, the grammar and rule (for the differential), and the crates it covers. Cargo's format adds no new text format that would need ABNF.
- **Commands:** `cargo xtask fuzz list | build | replay | run <target> [--time s] | smoke | coverage | tmin`.
- **Dictionaries.** C06 emits a libFuzzer dictionary per grammar from its literals, with big-endian "interesting" integers. Little-endian formats (initfs, the boot information) keep little-endian values.

### Trust-boundary parsers

Each parser at a trust boundary, and the chunk that owns it:

| Parser | Chunk | Notes |
|---|---|---|
| Kernel arguments (`crates/kargs`) | C04, C05 | Already a named target ([0041](../decisions/0041-boot-abi.md), rule 5). `max_len` 4096 + 1024. |
| The initial image (`crates/initfs`) | C19 | Already a named target ([0037](../decisions/0037-initial-image-format-and-contents.md), rule 2). Little-endian. |
| The ABNF parser, matcher, constraint checker and vector-file reader (`crates/abnf`) | C06 | Run by the catalog on publishers' grammars, so also bounded in time and memory |
| The parsers of `interface-ref`, `action-ref` and `error-ref` (`crates/idl-rt`) | C06, C07 | Used by the PDP, the token library and the catalog |
| The IDL front end, projection and compatibility checker (`crates/idl`) | C07 | Run by the catalog on publishers' IDL |
| Every IDL-generated decoder | C07 | One target per kernel interface. For other interfaces, one target for the generic decoding runtime, plus a sample of generated interfaces. Applications' generated decoders get the same targets from their compiler run (parity, [0027](../decisions/0027-applications-extend-the-system.md), rule 3). |
| The call header, protocol-method bodies, the error envelope, struct tails and stream entries; the canonical-text and JSON encoders (round trip) | C18 | Every manager and both network servers parse these |
| QUIC frames and capability descriptors; stream push; the network server's translation | C29 | Input from another node |
| The object-ID text form | C09 | D34 |
| The process manager's ELF parser | C17 | [0060](../decisions/0060-processes-native-spawn-and-elf.md) |
| Authorization-tree proofs, signed roots, grant records | C27 | |
| DER, X.509, CMS, PKCS #10, CRLs | C28 | |
| JOSE, JWT and JSON, the shared verification library | C37 | [0015](../decisions/0015-jwt-tokens-and-oidc-identity.md), Consequences |
| AuthZEN messages | C31, C32, C61 | |
| The secure transport's handshake messages | C29 | with D65's stack |
| Catalog queries and their text forms | C51 | |
| The JSON mapping's decoder (HTTPS input) | C52 | |
| TOML manifests | C54 | |
| SVG, XML, font and image decoders | C44 | Isolated, but still targets ([0010](../decisions/0010-svg-core-primitive.md), rule 11) |
| Every later parser that meets the definition | its chunk | |

- **Trusted inputs.** Boot-information records and the device tree are trusted on the boot path. They are optional targets.
- **Third-party parsers.** For a parser taken from a third-party crate, the chunk fuzzes ASPIS's wrapper at the boundary, and records whether the crate is fuzzed upstream (by OSS-Fuzz or its own CI). If it isn't, ASPIS fuzzes the crate directly ([L39](#l39-third-party-parsers)).

### The gate for each target

1. **No panic or abort.** Each input finishes within the timeout (default `-timeout=1`), and memory stays bounded (defaults `-rss_limit_mb=512 -malloc_limit_mb=64`). `-max_len` is the format's limit plus 1 KiB, so rejection of over-limit input is exercised: 4096 + 1024 for kernel arguments, 960 + 1024 for one IPC message, 2^24 + 1024 for an RPC frame, and 1 MiB for formats without a limit. Every accessor of a successful parse is exercised, as `crates/initfs/tests/robustness.rs`'s `exercise` does.
2. **Round trips**, where an encoder exists: `decode(encode(x)) == x`, and `encode(decode(b)) == b` for every accepted `b`. The second holds because ASPIS encodings are canonical ([Strict requests, tolerant reads](#strict-requests-tolerant-reads)).
3. **Agreement with the grammar**, where one exists: the decoder accepts `b` exactly when C06's matcher, with its constraints, accepts `b`. This generalizes `crates/kargs/tests/reference.rs`.
4. **Seeds include every vector line**, and a test shows that each of the parser's error kinds is reached by some corpus input.
5. **At least 1 CPU-hour of cumulative fuzzing**, from nightlies or `cargo xtask fuzz run --time 3600`, with no open finding. It is recorded in the chunk's pull request, with a coverage report from `cargo fuzz coverage` (llvm-tools, already pinned) reviewed there. There is no numeric coverage threshold yet; thresholds come after the first campaigns ([L36](#l36-coverage-thresholds)).
6. **Determinism and linear work.** Every parse is deterministic, and takes work linear in its input, with an explicit depth limit on any recursion: the IDL's 32, the error envelope's 3.

### Differential tests

| Pair | What must agree | When |
|---|---|---|
| A generated decoder, and C06's matcher with constraints | accept or reject, on every input | per target ([The gate for each target](#the-gate-for-each-target), item 3) |
| C06's Rust checker, and the Python `abnf` 2.9.1 package (MIT) | the context-free match, on generated grammars and inputs | nightly |
| The IDL parser, and `grammars/idl.abnf` | accept or reject | per target |
| Generated type names and action strings, and Cedar's parser and RFC 6749's `scope-token` | every valid name parses as a Cedar `Path`; every `action-ref` is a `scope-token` | per change |
| IPC to RPC to IPC translation through both network servers' code (a host build), in both directions | The method, request ID, extensions and body survive unchanged. So do the flags, except the spilled bit, which tracks whether each IPC side spilled. The header-words octet is restored ([What network servers translate](#what-network-servers-translate)). | per target (C29) |
| Old and new minor versions of a generated interface | an old decoder accepts a new minor's replies and preserves the unknown parts; a new decoder accepts an old minor's messages | per change, from C07 |
| The JSON encoder, and a reference JSON parser (in `fuzz/` only) | the call text's `call-args` is valid I-JSON, and matches its generated rule | per target |
| ASPIS's PDP, and `cedar_policy::Authorizer` | decisions, and their reasons ([The PDP against Cedar](#the-pdp-against-cedar)) | per change and nightly, from C32 |

### Per change

`ci.yml` gains a `fuzz` job, on `ubuntu-24.04-arm`:

- builds every target with `cargo fuzz build -s none`;
- replays seeds, regressions and the cached corpus, once each (`-runs=0`);
- fuzzes, for 60 s, each target whose covered crates changed since the merge base, with at most 10 minutes in total;
- from C32, runs 10,000 fixed-seed PDP differential cases;
- when a TLA+ spec changes, runs TLC with CI-sized constants, for at most 10 minutes;
- from C40, runs a two-node smoke test with one scripted partition, asserting that new binds fail closed.

`cargo xtask test` also runs an engine-neutral replay test, which feeds `fuzz/seeds` and `fuzz/regressions` to the same entry functions under plain `cargo test`. So a regression fails locally without libFuzzer.

### Nightly

`nightly.yml` runs these, sharded beside the QEMU matrix, with each job under 2 hours:

- every target for 10 minutes (`-max_total_time=600`). The corpus is restored from the cache, merged (`-merge=1`) and saved, and a coverage summary is uploaded;
- the ABNF differential ([Differential tests](#differential-tests));
- the PDP differential for 30 minutes, structure-aware through `arbitrary`;
- TLC with nightly constants, for at most 60 minutes;
- from C13 to C17, the in-QEMU kernel-call fuzzer ([The kernel-call fuzzer](#the-kernel-call-fuzzer));
- from C40, a partition campaign: 3 nodes, and 20 seeded fault schedules of 5 minutes each ([Partition injection](#partition-injection)).

### The PDP against Cedar

C32 builds this test.

- **The generator**, built on `arbitrary`, makes a small realm: principals with group memberships; resources with parents, and attributes from their managers; grants as template-linked policies; realm-wide policies and `forbid`s; an IDL-generated schema; and AuthZEN single and batch requests. It writes the realm into a real authorization tree (C27), with a signed root.
- **The system under test** is ASPIS's PDP library, built for the host with `std`.
- **The oracle** builds `PolicySet`, `Entities` and `Request` straight from the generated model, without the tree encoding, and calls `cedar_policy::Authorizer::is_authorized` from the pinned `cedar-policy` (4.15.0, Cedar language 4.7, today).
- **They must agree on:** the decision; the determining policies (Cedar's `reason` set); that errors deny; that a batch equals each request evaluated alone; and "deny, or stale" once the root is older than the bound ([0016](../decisions/0016-authorization-sparse-merkle-tree.md), rule 7).
- **Schemas validate.** Every IDL-generated schema fragment validates in Cedar, and validated policies raise no type errors.
- **Upgrades.** Upgrading `cedar-policy` is a commit of its own, and runs a 4-hour differential.
- **Why this target.** The test aims at ASPIS's integration around the engine, which is where ASPIS adds risk. Cedar's own differential testing against its Lean model covers the engine.

### Model checking

- **TLA+, checked with TLC v1.7.4**; Apalache is optional. Specs live in `specs/<name>.tla`, with MPL-2.0 SPDX tags in TLA+ comments, and come with the chunk whose protocol they model. The JVM is a CI dependency of these jobs only.
- **Leases (C40, C50):**
  - a lookup never returns an instance more than the lease length plus the clock-uncertainty bound after its last successful renewal;
  - an exclusive lease has at most one holder acting, enforced by a monotonic fencing epoch;
  - a crashed holder's entry lapses within the lease length plus that bound;
  - a renewal after a lapse never revives an entry without a new sequence number.
- **Catalog sequence numbers (C51):**
  - they strictly increase, and are never reused across restart or failover;
  - a list at n, then a watch from n, delivers every change after n exactly once, and in order;
  - watching from a compacted n ends with an explicit `expired`, never a silent skip;
  - an answer marked with epoch e reflects exactly the changes up to e.

  This is also where stream resumption ([Remote push within QUIC's credit](#remote-push-within-quics-credit)) is checked.
- **Recommended, not required by the gate:** the call protocol's at-most-once reply cache and cancel (C18; [0004](../decisions/0004-network-transparency-and-failure.md), rule 3; [0054](../decisions/0054-ipc-endpoints.md)), and export reference counting with release and `export_ended` (C29).
- **Sans-IO cores.** The protocol cores are written as sans-IO, `no_std`, host-buildable state machines. Later, test builds emit traces that TLC validates (trace validation: Cirstea and others, arXiv 2404.16075).

### The kernel-call fuzzer

This runs nightly, from C13 to C17.

- **Where.** In a test build (`cfg(aspis_test_build)`, [0036](../decisions/0036-qemu-configuration-and-test-builds.md)), on QEMU `max` with GICv3 and 4 cores: 4 seeds × 10 minutes, each seed logged so a run replays.
- **What.** It generates random call sequences from the kernel interfaces' IDL ([0059](../decisions/0059-the-kernel-interface-library.md), rule 1), and calls through the interface library, since the kernel accepts calls from nowhere else (rule 4).
- **The oracle.** The kernel never panics; every call returns a result or a typed error; the invariants the test build checks ([0047](../decisions/0047-the-kernel-follows-sel4.md), rule 6) hold after every call; and faults are the typed faults of [0056](../decisions/0056-faults-and-page-fetch-deadlines.md).
- **Not a gate.** It doesn't block per-change CI. Coverage guidance inside the kernel (sancov callbacks in test builds) comes later ([L40](#l40-kernel-coverage-kani-and-oss-fuzz)).

### Partition injection

C40 builds this.

- **A realm switch.** `cargo xtask` runs a host-side Rust process. Each node's `virtio-net-pci` uses `-netdev dgram,id=n0,local.type=unix,local.path=<sockdir>/<node>.sock,remote.type=unix,remote.path=<sockdir>/switch.sock` (QEMU 11.1.3, [0036](../decisions/0036-qemu-configuration-and-test-builds.md)). `<sockdir>` is under `$TMPDIR`: Unix socket paths are limited to about 104 octets on macOS, and sockets don't belong in iCloud. No root, and no tap devices.
- **Faults.** The switch forwards Ethernet frames by MAC address, and applies a fault schedule generated from a logged 64-bit seed: full, one-way and partial partitions, loss, delay and jitter, duplication, and reordering. Through QMP, xtask adds `set_link` (carrier loss), `stop` and `cont` (pauses), and kill-and-restart (crashes).
- **Checks.** Clients in test builds log each operation's request ID, its invocation and its outcome (one of the four) on the UART. Host checkers in Rust verify that:
  - no request ID executed twice;
  - every success executed, and every unreachable didn't;
  - new binds fail closed once the root is stale;
  - revocation ends sessions, connections and every proxy derived from them, within the bound ([Sessions, badges and proxies](#sessions-badges-and-proxies));
  - local decisions continue within the staleness bound.
- **Clock skew.** Clock-skew injection waits for the time service's design, C34 ([L38](#l38-clock-skew-injection)).

### Triage and disclosure

- **A failing job** uploads the minimized input (`cargo fuzz tmin`) and the backtrace. The fix commit adds the input to `fuzz/regressions/<target>/`, and, where it helps, a named unit test in the crate. Regressions replay on every change from then on.
- **Flaky findings are bugs.** A finding that doesn't reproduce in 10 reruns is itself a bug, since parsers must be deterministic.
- **Until ASPIS's first release,** fuzzing runs in public CI, and findings are fixed in the open.
- **From the first release,** nightly crash artifacts have short retention, a finding goes into a private GitHub security advisory under [SECURITY.md](../../SECURITY.md), and long campaigns (beyond the nightly 10 minutes per target) run on a private fork or a private runner. On a public repository, any signed-in GitHub user can download a workflow's artifacts while they are retained, and job logs stay public. So, from then on:
  - the public nightly's log names only the target and the number of crashes: no backtrace, no input, no panic message;
  - the minimized input and the backtrace are encrypted to the triagers' public keys with `age` (BSD-3-Clause, CI-only) before upload, and uploaded with a retention of 1 day;
  - the triager decrypts them, opens the private advisory, and fixes the bug there;
  - per-change replay of committed regressions stays public, since a committed regression is already fixed.

  What stays public is that a crash exists, and which target crashed, for the hours before a fix.

## Open questions

Each question names who settles it, and what this note assumes until then.

### L01. The object-ID text form

What is the text form of an object ID? Call targets, the JSON mapping, Cedar entity IDs and the IDL's `object_id(...)` all need it.

- **Owner:** D34 (C09).
- **Meanwhile:** 64 lowercase hex digits; `reserved(n)` and `hex(...)` in the IDL.
- **From:** [The canonical call text](#the-canonical-call-text); [Files and the interface header](#files-and-the-interface-header); [The JSON mapping](#the-json-mapping).

### L02. Reserved numbers

What is the reserved authority's value, and what are the well-known sequence numbers of `aspis.rpc`, `aspis.catalog`, `aspis.memory` ([0058](../decisions/0058-jobs-and-budgets.md), rule 6) and every `aspis.kernel.*` interface? C17 needs the kernel ones in M2, ahead of D35's milestone. D29 also confirms the list of kernel interfaces.

- **Owner:** D35 (C09, C19), with D29.
- **Meanwhile:** `reserved(n)` placeholders, such as `0x0103` and `0x0201` in the examples.
- **From:** [Kernel interface names](#kernel-interface-names); [The system errors](#the-system-errors); [Example: the eventcount interface](#example-the-eventcount-interface).

### L03. Minting application IDs, and prefix ownership

Who mints application interface and type IDs? Who owns a name prefix, how are names kept unique in a realm, and where is the `aspis.` reservation enforced?

- **Owner:** D110.
- **From:** [Interface and type names](#interface-and-type-names); [Files and the interface header](#files-and-the-interface-header).

### L04. Request IDs, the reply cache and default deadlines

How are request IDs made unique, before the entropy gate and after `fork`? Who keeps the reply cache, and for how long? What is network server A's default deadline, is there an allowance for round-trip time, and how do deadlines pass through nested calls?

- **Owner:** D38 (C18), with D95.
- **Meanwhile:** request IDs are opaque 16 octets, compared only for equality.
- **From:** [The IPC request](#the-ipc-request); [What network servers translate](#what-network-servers-translate); [Outcomes](#outcomes).

### L05. The bind message

What does the bind message carry? How is the bind interface numbered, what is the session-0 forwarding interface, and how does a forwarded bind tell the manager that the session is remote?

- **Owner:** D39 (C18, C39), with D66.
- **Meanwhile:** the bind spills locally, and is inline on QUIC.
- **From:** [Spilling](#spilling); [Refusing what is too new](#refusing-what-is-too-new); [Local methods and interfaces](#local-methods-and-interfaces).

### L06. The ALPN identifier and reset codes

What is RPC's ALPN identifier, and what are the numeric values of the `ASPIS_*` stream error codes?

- **Owner:** D65 (C29).
- **Meanwhile:** the values in [QUIC resets](#quic-resets).
- **From:** [Word 0](#word-0); [QUIC resets](#quic-resets).

### L07. Sessions across reconnection

How do sessions survive a QUIC reconnection? How long do proxy endpoints live beyond what [Sessions, badges and proxies](#sessions-badges-and-proxies) says? How does an exporting network server learn promptly that a manager ended a session it exported, without waiting for the next call?

- **Owner:** D66 (C29).
- **Meanwhile:** the exporter learns on the next use.
- **From:** [Sessions, badges and proxies](#sessions-badges-and-proxies).

### L08. QUIC transport settings

0-RTT, MAX_STREAMS, idle timeouts, and RFC 10069 multipath.

- **Owner:** D67 (C29).
- **Meanwhile:** none of them is used.
- **From:** [QUIC resets](#quic-resets); [Stream limits and rundown](#stream-limits-and-rundown).

### L09. Tracing

When is trace context set and sampled? What are the layout and size of tracestate (extension kind `%x02`)? How is baggage carried, is trace context stripped at the realm edge, and what log record surrounds the call text?

- **Owner:** D84 (C74).
- **Meanwhile:** trace context is an optional extension.
- **From:** [Header extensions](#header-extensions); [The canonical call text](#the-canonical-call-text).

### L10. Scope semantics

What do scopes mean on top of `scope-token = action-ref`? Does the ceiling rule expand `@group` and `*`?

- **Owner:** D85 (C37).
- **From:** [One string everywhere](#one-string-everywhere).

### L11. Groups that grow in a minor

A minor may add a method to an existing action group. Should that widen existing grants silently?

- **Owner:** C31 and D85, with policy review under [0018](../decisions/0018-cedar-policy-language.md)'s Consequences.
- **Meanwhile:** it is allowed, and the catalog shows the change.
- **From:** [Action groups](#action-groups).

### L12. Cedar schema details

Can policy name an action group across majors? Does C31 emit Cedar schema for `[kernel]` interfaces? How do Cedar fragments share the `aspis` namespace? What happens when a type path is also another type's namespace prefix, as `aspis::file` and `aspis::file::version`? How is a `u64` above 2^63 - 1 handled beyond failing closed?

- **Owner:** C31.
- **Meanwhile:** the JSON mapping's fail-closed rule.
- **From:** [Action groups](#action-groups); [The JSON mapping](#the-json-mapping).

### L13. Token-rejected reasons

What are the reasons a `token_rejected` error can give?

- **Owner:** D85.
- **Meanwhile:** the list in [The system errors](#the-system-errors).
- **From:** [The system errors](#the-system-errors).

### L14. errno mapping

How do outcomes and codes map to errno, and which call returns the original typed error?

- **Owner:** D96 (C41).
- **From:** [Errors in bindings and text](#errors-in-bindings-and-text).

### L15. The HTTPS binding

The JSON decoder; problem details (RFC 9457) and their `type` URI; HTTP methods; resources for the App API ([0026](../decisions/0026-realm-as-cloud-provider.md), rule 12); and the attributes `http(...)` and `resource(...)`.

- **Owner:** D116 (C52).
- **Meanwhile:** [The JSON mapping](#the-json-mapping).
- **From:** [Errors in bindings and text](#errors-in-bindings-and-text); [The JSON mapping](#the-json-mapping).

### L16. Streams over HTTPS

How do server streams appear at the HTTPS edge: OpenAPI 3.2's sequential media types, or server-sent events?

- **Owner:** D120 (C52, C53).
- **From:** [The JSON mapping](#the-json-mapping).

### L17. Registration, documentation revisions and support periods

How are interfaces registered? Where do documentation revisions live, beside the hashed canonical form? How are support periods recorded?

- **Owner:** D111, D114 and D115.
- **Meanwhile:** none of these is in the IDL.
- **From:** [Doc comments](#doc-comments); [The lock and the canonical form](#the-lock-and-the-canonical-form).

### L18. Stream history and replicas

How much history does a server retain, which decides when a lossless stream ends `expired`? Can a stream resume on another replica?

- **Owner:** D112 and D54.
- **From:** [Local pull with credit](#local-pull-with-credit); [Remote push within QUIC's credit](#remote-push-within-quics-credit).

### L19. Base discovery and enumeration interfaces

What are the base discovery interface (`aspis.base`) and the enumeration interface?

- **Owner:** D53 and D54 (C23).
- **From:** [Files and the interface header](#files-and-the-interface-header).

### L20. The tree-staleness bound

What is the tree-staleness bound behind `tree_too_stale`, and its `retry_after`?

- **Owner:** the authorization tree's open questions (C30).
- **From:** [The system errors](#the-system-errors).

### L21. Older majors of the interfaces the kernel calls

How is a fault handler, pager or memory server served when it speaks an older major of `aspis.kernel.fault`, `aspis.kernel.pager` or `aspis.kernel.memory_request`?

- **Owner:** the [kernel specification](kernel-specification.md), with C15 and C17.
- **Meanwhile:** major 1 only, read tolerantly.
- **From:** [Messages the kernel sends](#messages-the-kernel-sends).

### L22. The constraint vocabulary's grammar and the Rust checker

The question was: what is the exact ABNF of the constraint vocabulary, how is C06's Rust checker designed, and is the spaced-hex vector form added?

- **Settled with C06:**
  - **The vocabulary's ABNF** is `grammars/constraint.abnf`, with vectors in `grammars/constraint.vectors`. Keywords are case-sensitive, words are separated by exactly one space, and integers have no leading zeros and no `-0`. Integers lie in -2^63 to 2^64 - 1. The grammar can't say that, so the checker does. `ascending tags` is always the tags form, so a rule named `tags` can't be the R of `ascending R`.
  - **Binding.** [How constraints bind](#how-constraints-bind) gives the rules: attachment by the rule's text, strictness, the target, which match R is, and how a value reads (signed, decimal, or unsigned of 1 to 16 octets).
  - **The Rust checker**, `crates/abnf`, has a hand-written parser for RFC 5234 and RFC 7405, a loader, the vocabulary's parser, a matcher and a vector reader. It does no I/O: it takes grammar text, and a resolver for the names on `; uses:` lines. Only the caller marks a grammar as `core.abnf`; a grammar merely named "core" isn't core. The loader's analyses are linear in the grammar, and none recurses along rule references.
  - **The matcher** works on sets of states, depth-first over the grammar and breadth-first over the input, so its recursion follows the grammar's nesting, never the input's length. With constraints on, a state also carries its rule's bindings, the capability indexes seen, and the open `ascending` frames. A rule that carries a constraint, or is named as R, is matched one start at a time, so its value is known. Each target runs once, with all its forms applied together.
  - **Budgets.** Loading bounds the grammar text (1 MiB, used grammars included), the rules (16,384), the elements (262,144), the nesting of groups and options (64) and the depth of `; uses:` (8). Each match bounds the input (64 KiB: a vector is one line of text, and whole messages are the generated decoders' to check), the steps (1 M, plus 10,000 an octet, at most 100 M), the memory its live states hold (64 MiB), and the depth of nested calls (768). Each group, repetition and rule call nests one level. 768 levels need about 560 KiB of stack in an optimized build, and about 1.5 MiB without optimization. A linear grammar takes about 20 steps an octet, so a valid 64 KiB input takes about 1.3 M steps. 100 M steps take a few seconds. Constraint work is charged as steps too: each check, each octet of a match read for its value or compared with a `not word` list, each bound, and each caller's frame searched for R. Loading sorts and deduplicates each rule's constraints, and the matcher searches `not one of` and `not word` lists by halves. A vector file has one budget for all its matches (500 M steps), and its check stops at the first vector over any budget. So a publisher's file costs the catalog a bounded time, however many vectors it holds. A state is charged 72 octets, and 48 more for each binding or open frame, so even a state with one binding for every octet of a 64 KiB input stays under 8 MiB. A run over a budget is reported as exhausted, never as a verdict.
  - **Linear work.** A general ABNF matcher can't be linear in its input. The step budget is how this one meets [0068](../decisions/0068-the-fuzzing-and-differential-testing-gate.md), rule 5: work above a linear bound is refused as exhausted.
  - **Capabilities.** A whole body names its indexes in ascending order, each once, and every index below the count. A core rule's vector is a fragment, checked for range and repeats only.
  - **No spaced-hex vector form.** `\xHH` stays the only escape, so the two vector readers stay the same. C07 may add the form if generated vectors need it.
- **From:** [The constraint vocabulary](#the-constraint-vocabulary); [Checkers](#checkers).

### L23. Error size limits and free text

Are 768 octets and a cause depth of 3 right? Should errors ever gain a bounded free-text note?

- **Owner:** C18 and C29, through a minor of `aspis.rpc`.
- **From:** [The error envelope](#the-error-envelope).

### L24. Per-session defaults

The exact defaults: 256 imports, 64 badges and 16 streams per session, 60 s idle rundown, and the 64 KiB floor of the QUIC window.

- **Owner:** C18 and C29.
- **Meanwhile:** the values in [Stream limits and rundown](#stream-limits-and-rundown).
- **From:** [Sessions, badges and proxies](#sessions-badges-and-proxies); [Stream limits and rundown](#stream-limits-and-rundown).

### L25. The message size limit

Should the 16 MiB message limit be raised? Raising it needs a new protocol version.

- **Owner:** decided after C29's measurements.
- **From:** [Size limits](#size-limits).

### L26. Three-party handoff

Should a capability passed on from a third node get a direct path, instead of a proxy chain? That is likely an object ID, an RFC 8693 delegated token and a bind.

- **Owner:** a later record, with C29 or C39.
- **Meanwhile:** proxy chains.
- **From:** [Translation between nodes](#translation-between-nodes).

### L27. Writable memory across nodes

How can a writable memory object cross nodes?

- **Owner:** the lease and coherence record (C22, C29, C40; [0005](../decisions/0005-single-level-store.md), rule 4; [0057](../decisions/0057-memory-objects-and-the-pager-protocol.md), rule 9).
- **Meanwhile:** refused, with `capability_not_remotable`.
- **From:** [Translation between nodes](#translation-between-nodes).

### L28. Content-hash descriptors

Should immutable memory objects cross nodes with a content-hash descriptor, so nodes can cache build images?

- **Owner:** C29, with the app platform (M5 or later).
- **From:** [Translation between nodes](#translation-between-nodes).

### L29. Client and bidirectional streams

Should the IDL gain client and bidirectional streams?

- **Owner:** a later record, or an edit of 0066 and 0067.
- **Meanwhile:** server streams only.
- **From:** [Server streams in the IDL](#server-streams-in-the-idl).

### L30. The C binding

When does the C binding come, and what shape does it take?

- **Owner:** the first C consumer; likely M6 (C47).
- **Meanwhile:** deferred.
- **From:** [Back ends](#back-ends).

### L31. Async Rust bindings

What do async Rust bindings look like, for the network server and the `std` port?

- **Owner:** C26 and C29.
- **From:** [Back ends](#back-ends).

### L32. Rendering doc comments

How does dm render doc comments, and how does the catalog browser show definitions?

- **Owner:** the dm design ([0011](../decisions/0011-dm-window-system.md), rule 6).
- **Meanwhile:** the compiler emits a doc model.
- **From:** [Doc comments](#doc-comments).

### L33. Dynamic invocation

How do tools call an interface from its IDL, fetched at run time?

- **Owner:** the command-interpreter design ([0031](../decisions/0031-abnf-is-not-a-command-language.md), Consequences).
- **Meanwhile:** `crates/idl` is `no_std`, so it can be used that way.
- **From:** [Crates](#crates).

### L34. Wall-clock times in messages

What are the time unit and sign of wall-clock times in messages?

- **Owner:** the time service (C34), with D38.
- **Meanwhile:** durations are u64 nanoseconds.
- **From:** [The RPC request](#the-rpc-request); [The error envelope](#the-error-envelope).

### L35. Fuzzing on stable Rust

Do `cargo fuzz build -s none` and `cargo fuzz run` work on Rust 1.100.0, on aarch64 Linux and macOS?

- **Owner:** C71's first task.
- **Meanwhile:** afl.rs is the fallback.
- **From:** [Engine and tools](#engine-and-tools).

### L36. Coverage thresholds

What coverage threshold should each fuzz target meet?

- **Owner:** C71, after the first campaigns.
- **Meanwhile:** none.
- **From:** [The gate for each target](#the-gate-for-each-target).

### L37. The TLA+ specs

The TLA+ specs themselves.

- **Owner:** C40 and C50 (leases); C51 (sequence numbers).
- **Meanwhile:** the properties in [Model checking](#model-checking).
- **From:** [Model checking](#model-checking).

### L38. Clock-skew injection

How is clock skew injected, and what is the lease's clock-uncertainty bound?

- **Owner:** the time service (C34).
- **From:** [Partition injection](#partition-injection); [Model checking](#model-checking).

### L39. Third-party parsers

Which crates supply DER, JOSE, JSON, TLS, QUIC and TOML, and is each fuzzed upstream?

- **Owner:** D33, and the chunks that use them.
- **From:** [Trust-boundary parsers](#trust-boundary-parsers).

### L40. Kernel coverage, Kani and OSS-Fuzz

Coverage guidance inside the kernel (sancov in test builds); Kani proofs for small parsers; and applying to OSS-Fuzz.

- **Owner:** C71, later.
- **Meanwhile:** optional.
- **From:** [Engine and tools](#engine-and-tools); [The kernel-call fuzzer](#the-kernel-call-fuzzer).

### L41. The identify operation

Is the identify operation, which reads a capability's kind and rights, a published kernel interface method, or internal to the runtime crate?

- **Owner:** the [kernel specification](kernel-specification.md), and C17.
- **Meanwhile:** published, in `aspis.kernel.cspace`.
- **From:** [Capability types](#capability-types); [Translation between nodes](#translation-between-nodes).

### L42. The AEGIS status layout

What is the bit layout of AEGIS's `status_$t`? Until it is checked, records cite only "subsystem, module and code fields".

- **Owner:** the research note ([aegis-domain-os.md](../research/aegis-domain-os.md)), from *Programming With General System Calls* (008858-00).
- **Meanwhile:** cite only the structure.
- **From:** [The error envelope](#the-error-envelope).

### L43. Keeping a Fail's error key

Where does the kernel keep a Fail's error key (36 octets) until every waiting thread's page-unavailable fault is delivered? One option is the pending-page record, charged to the object's job. And by which call does a handler fetch the full error from the pager?

- **Owner:** the [kernel specification](kernel-specification.md) (an open question beside [K43](kernel-specification.md#k43-how-a-pager-fills-a-frame)), with C15 and C17.
- **Meanwhile:** the key travels; the detail stays with the pager.
- **From:** [The error envelope](#the-error-envelope).

### L44. Object types in Cedar

What is the Cedar mapping of each attribute type? How are entity tags used, and how does a manager present attributes in AuthZEN requests?

- **Owner:** C31, with D85.
- **Meanwhile:** the IDL's `object` declaration.
- **From:** [Object types](#object-types).

### L45. The memory server's answers

Settled by [0058](../decisions/0058-jobs-and-budgets.md), rule 6: the memory server's answers to a memory request (lend, free, refuse) are operations on the job's capability, never a reply, and `memory_request` is `[oneway]`. A runtime whose explicit call failed with "no memory" asks on the two-way `[local]` interface `aspis.memory/1`, which C83 defines, and gets a reply. The number is kept so that links to it still resolve.

- **From:** [Messages the kernel sends](#messages-the-kernel-sends).
