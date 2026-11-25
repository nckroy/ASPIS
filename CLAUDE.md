<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->

# Working in the ASPIS repository

This file tells Claude Code how to work in this repository.

ASPIS is an open-source microkernel operating system, written in Rust for ARM64 and modeled on Apollo AEGIS / Domain/OS. It is in its design phase. The repository holds research, design notes and architecture decision records (ADRs), and no code yet.

## Repository layout

- `docs/research/`: background research. [aegis-domain-os.md](docs/research/aegis-domain-os.md) covers AEGIS and Domain/OS, with a source tag on every fact.
- `docs/decisions/`: the ADRs, one per file, named `NNNN-short-title.md`. [README.md](docs/decisions/README.md) lists the founding requirements and indexes every record with its status.
- `docs/design/`: design notes and architecture views.
  - The design notes fed the ADRs, and each names the records it led to. Examples: [authorization-tree.md](docs/design/authorization-tree.md), [security-tokens.md](docs/design/security-tokens.md), [twelve-factor-apps.md](docs/design/twelve-factor-apps.md).
  - [system-context.md](docs/design/system-context.md) is the C4 system context: an ASPIS realm, the people who use it and the systems around it.
  - The views zoom in from there: [realm-containers.md](docs/design/realm-containers.md) (the realm's services), [node-components.md](docs/design/node-components.md) (one node's servers), [kernel-components.md](docs/design/kernel-components.md) (the kernel) and [key-flows.md](docs/design/key-flows.md) (sequence diagrams across all three).
  - [build-plan.md](docs/design/build-plan.md) divides the build into chunks (C01…) and milestones (M1–M9, and MH for hardware and hardening). [design-backlog.md](docs/design/design-backlog.md) lists the open decisions (D01…) under the milestone each must be settled before. When a decision is made, record it as an ADR and mark its backlog entry settled.
- [LICENSE](LICENSE): the verbatim text of the Mozilla Public License 2.0 ([0008](docs/decisions/0008-mpl-2.0-license.md), rule 3). Don't edit it.

## How the project works

- The work goes in three steps: research and discussion; a design session (architecture views, documentation, and dividing the build into chunks); then implementation.
- The design session settles what the ADRs leave open, in the order the build needs it.
- The project owner may add a tenet mid-discussion. Fold each new one into the ADRs and design notes.
- Read the relevant research, design notes and ADRs before proposing a design.
- Accepted ADRs are settled. Follow the effective rule after any amendments, and don't re-argue them.
- If two accepted records conflict, say so and propose an amending record, as [0030](docs/decisions/0030-bind-tokens-sessions-and-group-memberships.md) does.
- Record a new decision as the next numbered ADR, and add it to the index in [docs/decisions/README.md](docs/decisions/README.md). Records are never renumbered.
- Mark a new record "Proposed" until the project owner accepts it. A Proposed record, such as [0029](docs/decisions/0029-founding-node-self-signed-certificate.md), isn't settled: check the index for each record's status.
- Amend a record; never rewrite it.
  - The amended record's status line gets "Amended by NNNN (rule k)", once the amending record is accepted.
  - The new record's status line says "Amends NNNN, rule k". A Proposed record says "Would amend".
  - A replaced record keeps its file, with its status changed to "Superseded by NNNN".
- Design notes are inputs to decisions. When a decision makes a note stale, correct the note in place and cite the ADR that settles it.
- Where something isn't decided yet, say so. Don't guess.

### ADR format

Follow the existing records:

- Title `# NNNN. The decision in a few words`.
- A `- **Status:**` line and a `- **Date:**` line.
- Four sections: Context, Decision (numbered rules), Consequences and References.

## Writing conventions

- **Copyright.** Line 1 of every novel Markdown file is exactly `<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->` ([0023](docs/decisions/0023-copyright-notices.md)).
  - Markdown carries the copyright tag only, with no license tag, because the documentation license is still undecided.
  - Code files begin with `SPDX-FileCopyrightText: 2026 Nicole Roy` and `SPDX-License-Identifier: MPL-2.0`, in the file's comment syntax.
  - Third-party material keeps its own notices: quotations, code copied or vendored from elsewhere, and test vectors taken from standards.
- **Tone.** Plain, short sentences. Say what is decided and where. Say plainly what is still open.
- **Spelling.** American English in every document (the project owner's rule): "license" for both noun and verb, "behavior", "organization", "enrollment", "synchronization", "modeled", "canceled". Third-party text, such as `LICENSE` and quotations, keeps its own spelling.
- **Terminology.**
  - Write "the authorization tree", never "SMT". Cedar's policy analysis is built on SMT solvers, so the abbreviation is ambiguous ([policy note §6](docs/design/policy-and-decisions.md#6-conflicts-and-resolutions), item 8).
  - Getting a capability or session from an object's manager is a "bind" ([0014](docs/decisions/0014-versioned-object-apis.md), rule 4). ADR 0002 rule 3, written earlier, calls the same step "opening" an object.
  - "The provider" is the realm's OpenID Provider and OAuth authorization server ([0015](docs/decisions/0015-jwt-tokens-and-oidc-identity.md), rule 2).
- **Citations.**
  - Cite an ADR as "ADR 0020" or as a link, `[0020](docs/decisions/0020-realm-certificate-authority.md)`. Add the rule where it matters: "([0026](docs/decisions/0026-realm-as-cloud-provider.md), rule 6)".
  - Cite a design note by a link to it, with a section anchor where that helps.
  - Links are relative and must resolve. From `docs/design/`, an ADR is `../decisions/NNNN-short-title.md`.
  - Design notes and views open with an italic line: the date, and what the note is or which records it led to.
- **Standards.** Before citing one, check for a newer version, or a split into companion documents.
  - Cite the newest Final version, and note when an earlier version is equivalent.
  - Flag drafts as drafts, with their revision and date.
  - Example: OpenID Federation 1.1 split into a protocol-independent core and OpenID Federation for OpenID Connect 1.1.

## Diagrams

[0024](docs/decisions/0024-diagrams-mermaid-and-c4.md) sets the rules.

- Every diagram is Mermaid, in a fenced `mermaid` block in the Markdown that uses it. No images and no ASCII art.
- Context diagrams use the C4 model, drawn with `C4Context`. Views that zoom in may use `C4Container` and `C4Component`.
- Other diagrams use the type that fits: `sequenceDiagram` for flows, `flowchart` for hierarchies and trees, `stateDiagram-v2` for state machines.

### Check that every diagram renders

Don't call a diagram done until you have seen it render.

- Check against the newest stable Mermaid only: the `latest` tag from `npm view mermaid dist-tags`. Don't test older versions.
- Plain `mmdc` isn't enough for C4. Mermaid's C4 layout wraps rows at `screen.availWidth`, and headless Chrome reports a narrow screen, so every C4 diagram collapses into one column. Window-size flags don't change it.
- So use a small Puppeteer script:
  - Pin `screen.availWidth` with `page.evaluateOnNewDocument`. Use 1512, a laptop's logical width.
  - Load a `file://` host page with `page.goto`. `setContent` doesn't run the `evaluateOnNewDocument` hook.
  - Parse and render each block, size each SVG to its viewBox, and look at the screenshots.
- When searching SVGs for failures, match `Syntax error in text`, not `error-icon`: every Mermaid SVG carries an `.error-icon` CSS rule.

### Layout rules that work

- Put three shapes in a row: `UpdateLayoutConfig($c4ShapeInRow="3", $c4BoundaryInRow="1")`. In a context diagram, put the system in the center of the grid.
- Widen spacing in the frontmatter, under `config: c4:`, with `c4ShapeMargin`.
- In `C4Container`, Mermaid puts every element that is outside a boundary above it, whatever the order.
  - Keep those elements to one row. Leave out externals that would start a second row.
  - Order elements so related ones sit side by side and no line crosses a box. Put hubs in the top row, under the person who uses them.
- Keep labels short.
  - Lift a label that hits the boundary title with `UpdateRelStyle(from, to, $offsetY="-40")`.
  - On a short edge between neighbors, use a one-word label lifted with `$offsetY="-16"`.
- Component views set darker `component_*` and `external_*` fills in the `c4` frontmatter, so white text reaches 4.5:1 contrast. Copy them from [node-components.md](docs/design/node-components.md).
- Never put `;` in a sequence-diagram message. It ends the statement and breaks parsing.
- In `erDiagram`, the first entity of a relationship ranks above the second. Flip a relationship to move a node down and out of other edges' way.

## Code and dependencies

There is no code yet. When it starts:

- Write it in Rust: a microkernel for ARM64, bootable with GRUB ([founding requirements](docs/decisions/README.md#founding-requirements)). The boot image is a UEFI PE32+ image ([0006](docs/decisions/0006-uefi-boot-image.md)). The targets are QEMU `virt` first, then Raspberry Pi 4 ([0007](docs/decisions/0007-initial-hardware-targets.md)).
- All ASPIS code is licensed under MPL-2.0 ([0008](docs/decisions/0008-mpl-2.0-license.md)). Every source file carries both SPDX tags.
- Dependencies must use MIT, Apache-2.0, BSD or MPL-2.0. The kernel and core servers take no GPL-only dependencies ([0008](docs/decisions/0008-mpl-2.0-license.md), rule 4).
- Interfaces are written in the ASPIS IDL, and the IDL compiler generates each interface's ABNF. CI parses every grammar and runs its test vectors ([0013](docs/decisions/0013-abnf-for-protocols-and-calls.md)).
- ABNF is a protocol specification metalanguage: it describes protocols, calls and machine-read formats, never the language of the command interpreter people use. Don't propose ABNF, or the canonical text form of calls, as the interpreter's syntax (the project owner's rule; [0031](docs/decisions/0031-abnf-is-not-a-command-language.md), proposed).
- Infrastructure as code uses OpenTofu, never Terraform. [0026](docs/decisions/0026-realm-as-cloud-provider.md) rule 12 makes the App API declarative enough to back an OpenTofu provider.

## Still open

Many ADRs leave details to the design session, and say which. Two licensing questions are open too. Don't assume an answer to either:

- **The documentation license** ([0008](docs/decisions/0008-mpl-2.0-license.md), rule 5). Until it is decided, documents carry the copyright line only.
- **The contribution policy**: a DCO, a CLA or an assignment ([0023](docs/decisions/0023-copyright-notices.md), Consequences). ASPIS needs one before it accepts outside contributions.
