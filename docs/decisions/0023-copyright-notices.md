<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0023. Copyright notices

- **Status:** Accepted. Amends [0008](0008-mpl-2.0-license.md), rule 2. Amended by [0033](0033-contributions-docs-license-and-notice-years.md) (rules 1 and 2).
- **Date:** 2026-11-24

<!-- REUSE-IgnoreStart -->

## Context

The direction: copyrights are 2026 Nicole Roy for novel work and code.

[0008](0008-mpl-2.0-license.md) does three relevant things:

- licenses all ASPIS code under MPL-2.0;
- requires every source file to begin with `SPDX-License-Identifier: MPL-2.0`;
- leaves the documentation license to a separate decision.

The REUSE specification standardizes machine-readable copyright and license tags in each file, `SPDX-FileCopyrightText` and `SPDX-License-Identifier`, which tools can check.

## Decision

1. **Novel work and code name 2026 Nicole Roy as the copyright holder.**
   - Novel work means ASPIS's own documents, designs and diagrams.
   - Code means everything [0008](0008-mpl-2.0-license.md) covers.
2. **The notice is an SPDX tag at the top of each file, in that file's comment syntax.**
   - **Source files** begin with both tags. This amends [0008](0008-mpl-2.0-license.md) rule 2, which required only the license tag. In Rust:

     ```rust
     // SPDX-FileCopyrightText: 2026 Nicole Roy
     // SPDX-License-Identifier: MPL-2.0
     ```

   - **Markdown documents** begin with `<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->`. They carry no license tag until the documentation license is decided ([0008](0008-mpl-2.0-license.md), rule 5).
3. **Third-party material keeps its own notices.** This covers quotations, code copied or vendored from elsewhere, and test vectors taken from standards.
4. **Every existing document gets the notice now.**

<!-- REUSE-IgnoreEnd -->

## Consequences

- **The tags follow REUSE**, so a check can confirm that every file carries its notice once the repository exists. Full REUSE compliance also needs a license for every file, which waits on the documentation license.
- **Documents carry no license yet.** Until the documentation license is decided, the documents carry a copyright notice and no license, so nobody else has a license to reuse them.
- **Outside contributions need a policy.** Copyright in a contribution stays with its author unless an agreement assigns or licenses it. Before ASPIS accepts outside contributions, it needs a contribution policy, such as a DCO, a CLA or an assignment. This record doesn't decide which.
- **Later years.** How notices name years after 2026 is decided when it arises.

## References

- [0008. License: MPL-2.0](0008-mpl-2.0-license.md)
- [REUSE specification](https://reuse.software/spec/)
- [SPDX License List](https://spdx.org/licenses/)
