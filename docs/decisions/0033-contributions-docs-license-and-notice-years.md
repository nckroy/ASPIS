<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0033. Contributions under the DCO, documents under CC BY 4.0, and year ranges in notices

- **Status:** Accepted. Amends [0023](0023-copyright-notices.md) (rules 1 and 2).
- **Date:** 2026-11-25

## Context

Three licensing questions were left open, and the first milestone's repository chunk (C01) needs all three answered ([design backlog, D01](../design/design-backlog.md#m1-first-light)):

- **The documentation license.** [0008](0008-mpl-2.0-license.md), rule 5 leaves it to a separate decision. Until then, documents carry a copyright notice and no license, so nobody else may reuse them, and a REUSE check can't pass ([0023](0023-copyright-notices.md), Consequences).
- **The contribution policy.** Copyright in a contribution stays with its author unless an agreement assigns or licenses it. ASPIS needs a policy before it accepts outside contributions: a DCO, a CLA or an assignment ([0023](0023-copyright-notices.md), Consequences).
- **Years after 2026.** [0023](0023-copyright-notices.md), rule 1 names 2026, and its Consequences leave later years open.

The options:

- **The Developer Certificate of Origin 1.1** is a short statement a contributor certifies by adding a `Signed-off-by:` line to each commit. The contributor keeps the copyright and licenses the work under the license of the files it changes. The Linux kernel and many other projects use it.
- **A contributor license agreement** grants the project a broad license, often enough to relicense. It needs a signing process, and some contributors and employers won't sign one.
- **An assignment** transfers the copyright. It keeps one holder, at the most friction.
- MPL-2.0 already lets anyone use a later MPL version (§10.2), so ASPIS doesn't need a CLA to follow the license's own updates.

The project owner decided on 2026-11-25: the DCO for contributions, CC BY 4.0 for documents, and year ranges in notices. The rules below spell those decisions out.

## Decision

1. **Contributions come under the Developer Certificate of Origin 1.1.**
   - Every commit in an outside contribution carries a `Signed-off-by:` line, which certifies the DCO. The name in it identifies the contributor; anonymous contributions aren't accepted.
   - Contributions are licensed under the license of the files they change or add: MPL-2.0 for code ([0008](0008-mpl-2.0-license.md), rule 1), CC BY 4.0 for documents (rule 2). ASPIS asks for no CLA and no assignment.
   - Contributors keep their copyright. A contributor whose change to a file is copyrightable adds their own `SPDX-FileCopyrightText` line to it, and a file a contributor creates names them. Nicole Roy's notices stay as they are ([0023](0023-copyright-notices.md), rule 1).
   - CI checks that every commit in a pull request carries a sign-off.
2. **Documents are licensed under Creative Commons Attribution 4.0 International (CC BY 4.0).**
   - This covers ASPIS's own documents: the research, the decision records, the design notes, the README and the other Markdown in the repository, with the diagrams they contain.
   - Every Markdown document carries a license tag as well as its copyright tag. Line 1 stays the copyright tag, and line 2 is:

     ```html
     <!-- SPDX-License-Identifier: CC-BY-4.0 -->
     ```

     This amends [0023](0023-copyright-notices.md), rule 2, which gave Markdown the copyright tag only until this decision.
   - Code examples inside a document are part of it, under CC BY 4.0. Code meant to be built or run lives in source files, under MPL-2.0.
   - Third-party material keeps its own notices ([0023](0023-copyright-notices.md), rule 3).
3. **License texts follow REUSE.** The repository holds `LICENSES/MPL-2.0.txt` and `LICENSES/CC-BY-4.0.txt`. `LICENSE` stays, with the MPL-2.0 text ([0008](0008-mpl-2.0-license.md), rule 3). Files that can't carry a comment, such as `.gitignore` and generated assets, are covered by a `REUSE.toml`. A REUSE check runs in CI and fails the build on any file without both tags.
4. **A notice names the years as a range.**
   - A notice starts with the year the holder first published the file.
   - When the holder changes the file in a later year, the notice becomes a range up to that year: `2026-2027 Nicole Roy`. The range runs from the first year to the latest, with no gaps listed.
   - Each holder's line counts that holder's own changes. A contributor's change doesn't extend Nicole Roy's range.
   - This amends [0023](0023-copyright-notices.md), rule 1, which named 2026 only.
5. **The tags go on every existing document once this record is accepted**, as [0023](0023-copyright-notices.md), rule 4 did for the copyright tag.

## Consequences

- **The documents can be reused.** Anyone may copy and adapt the research, records and notes, with attribution. Other implementers can build on ASPIS's designs.
- **The REUSE check can pass.** Every file has a copyright notice and a license, so C01's check can be strict from the start.
- **ASPIS can accept outside contributions** once C01 adds a `CONTRIBUTING.md` that quotes the DCO and the CI check is in place.
- **Copyright is no longer held by one person.** Each contribution's author keeps it. Relicensing ASPIS beyond what MPL-2.0 §10.2 allows would need every holder's consent. This is the usual trade for a low-friction policy.
- **Notices change in a new year.** The first change a holder makes to a file in a new year also extends that file's range. Tooling, such as a pre-commit hook, can do it.
- **Working rules change.** `CLAUDE.md` and the `README` must describe the two tags and the year ranges once this record is accepted.

## References

- [Developer Certificate of Origin 1.1](https://developercertificate.org/)
- [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/legalcode)
- [REUSE specification](https://reuse.software/spec/)
- [Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/), §10.2
- [0008. License: MPL-2.0](0008-mpl-2.0-license.md); [0023. Copyright notices](0023-copyright-notices.md)
