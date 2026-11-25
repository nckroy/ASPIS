<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0024. Diagrams: Mermaid, with the C4 model for context diagrams

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

The direction: Mermaid is used for diagrams, and context diagrams use the C4 model.

So far every diagram in ASPIS's documents is Mermaid, either a flowchart or a sequence diagram. None is ASCII art or an image.

**The C4 model** describes software architecture at four levels of zoom: system context, containers, components and code. A system context diagram shows the system as a single box, surrounded by the people and the external systems it deals with.

**Mermaid's support for C4.**

- Mermaid draws five kinds of C4 diagram: `C4Context`, `C4Container`, `C4Component`, `C4Dynamic` and `C4Deployment`.
- It lays them out in the order the elements are written, rather than automatically.
- It doesn't yet support C4's sprites, tags, links or legends.

## Decision

1. **Every diagram is Mermaid.** It is written as a fenced `mermaid` block in the Markdown that uses it. ASPIS documents contain no diagram images and no ASCII-art diagrams.
2. **Context diagrams use the C4 model**, drawn with `C4Context`: the system as one box, with the people and external systems that use it or that it depends on.
3. **Views that zoom in may use C4's next levels**, `C4Container` and `C4Component`, so that they nest inside the context diagram.
4. **Other diagrams use the Mermaid type that fits:**
   - `sequenceDiagram` for flows;
   - `flowchart` for hierarchies and trees;
   - `stateDiagram-v2` for state machines.
5. **This applies to existing documents now.**
   - ASPIS gets a system context diagram ([ASPIS in context](../design/system-context.md)).
   - The diagram of the realm's place in federation topologies ([OpenID Federation design note](../design/openid-federation.md)) is a context diagram, so it is redrawn in C4.

## Consequences

- **Diagrams are text**, so they are versioned, diffed and reviewed along with the documents.
- **The docs build should check that every diagram renders**, alongside the grammar checks of [0013](0013-abnf-for-protocols-and-calls.md) rule 6.
- **Large C4 views need care.** Element order decides the layout, so a large view may need reordering, or splitting into several diagrams.

## References

- [The C4 model](https://c4model.com/)
- [Mermaid C4 diagrams](https://mermaid.js.org/syntax/c4.html)
