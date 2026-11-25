<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0023. Copyright notices

- **Status:** Accepted
- **Date:** 2026-11-24, updated 2026-11-25

<!-- REUSE-IgnoreStart -->

## Context

The direction: copyrights are 2026 Nicole Roy for novel work and code.

[0008](0008-mpl-2.0-license.md), as first accepted, did three relevant things:

- it licensed all ASPIS code under MPL-2.0;
- it required every source file to begin with `SPDX-License-Identifier: MPL-2.0`;
- it left the documentation license to a separate decision, which [0033](0033-contributions-docs-license-and-notice-years.md) has since made.

The REUSE specification standardizes machine-readable copyright and license tags in each file, `SPDX-FileCopyrightText` and `SPDX-License-Identifier`, which tools can check.

## Decision

1. **Novel work and code name Nicole Roy as the copyright holder.**
   - Novel work means ASPIS's own documents, designs and diagrams.
   - Code means everything [0008](0008-mpl-2.0-license.md) covers.
   - A notice names the years as a range. It starts with the year the holder first published the file, so `2026 Nicole Roy` for a file first published in 2026.
   - When the holder changes the file in a later year, the notice becomes a range up to that year: `2026-2027 Nicole Roy`. The range runs from the first year to the latest, with no gaps listed.
   - Each holder's line counts that holder's own changes. A contributor's change doesn't extend Nicole Roy's range ([0033](0033-contributions-docs-license-and-notice-years.md), rule 4).
2. **The notice and the license are SPDX tags at the top of each file, in that file's comment syntax.**
   - **Source files** begin with both tags, as [0008](0008-mpl-2.0-license.md), rule 2 requires. In Rust:

     ```rust
     // SPDX-FileCopyrightText: 2026 Nicole Roy
     // SPDX-License-Identifier: MPL-2.0
     ```

   - **Markdown documents** begin with both tags. Line 1 is the copyright tag, and line 2 is the license tag, since documents are licensed under CC BY 4.0 ([0033](0033-contributions-docs-license-and-notice-years.md), rule 2):

     ```html
     <!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
     <!-- SPDX-License-Identifier: CC-BY-4.0 -->
     ```

3. **Third-party material keeps its own notices.** This covers quotations, code copied or vendored from elsewhere, and test vectors taken from standards.
4. **Every existing document gets the notice now.**

<!-- REUSE-IgnoreEnd -->

## Consequences

- **The tags follow REUSE**, so a check can confirm that every file carries its notice and its license.
- **Outside contributions need a policy.** Copyright in a contribution stays with its author unless an agreement assigns or licenses it. The policy is the DCO, and contributors keep their copyright ([0033](0033-contributions-docs-license-and-notice-years.md), rule 1).
- **Notices change in a new year.** The first change a holder makes to a file in a new year extends that file's range.

## References

- [0008. License: MPL-2.0](0008-mpl-2.0-license.md); [0033. Contributions under the DCO, documents under CC BY 4.0, and year ranges in notices](0033-contributions-docs-license-and-notice-years.md)
- [REUSE specification](https://reuse.software/spec/)
- [SPDX License List](https://spdx.org/licenses/)
