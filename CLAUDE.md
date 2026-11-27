<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Working in the ASPIS repository

This file tells Claude Code how to work in this repository.

ASPIS is an open-source microkernel operating system, written in Rust for ARM64 and modeled on Apollo AEGIS / Domain/OS. It is in its design phase. The repository holds research, design notes and architecture decision records (ADRs), and code: milestone M1, "First light", and M2 as its chunks are built.

## Repository layout

- `docs/research/`: background research. [aegis-domain-os.md](docs/research/aegis-domain-os.md) covers AEGIS and Domain/OS, with a source tag on every fact. Third-party source PDFs kept beside it are for local research only: `.gitignore` excludes `docs/research/*.pdf`, so never commit them.
- `docs/decisions/`: the ADRs, one per file, named `NNNN-short-title.md`. [README.md](docs/decisions/README.md) lists the founding requirements and indexes every record with its status.
- `boot/stub/`: the UEFI boot stub, built for `aarch64-unknown-uefi`, which carries the kernel in its `.kernel` section ([0035](docs/decisions/0035-toolchain-image-linkage-and-esp-layout.md)).
- `kernel/`: the kernel, a static PIE for `aarch64-unknown-none`, with its linker script.
- `crates/`: `no_std` libraries shared by the stub, the kernel and the tools: `bootinfo` ([0041](docs/decisions/0041-boot-abi.md)), `kargs` (the kernel-argument grammar), `initfs` ([0037](docs/decisions/0037-initial-image-format-and-contents.md)), `kmem` (the kernel's memory logic, tested on the host; [0048](docs/decisions/0048-kernel-memory-and-address-spaces.md)), `kcap` (the kernel's capability logic, tested on the host; [0049](docs/decisions/0049-capability-spaces-rights-and-revocation.md)), `kirq` (the kernel's interrupt-controller and timer logic, tested on the host; [0055](docs/decisions/0055-interrupt-objects.md), [0051](docs/decisions/0051-scheduling-timers-and-deadlines.md)), `ksched` (the kernel's scheduling, donation and SMP logic, tested on the host, with traces of its donation that TLC validates; [0051](docs/decisions/0051-scheduling-timers-and-deadlines.md), [0052](docs/decisions/0052-smp-bring-up-and-the-kernel-lock.md)), `glyph-atlas` ([0034](docs/decisions/0034-noto-fonts-under-ofl.md)), `abnf`, the ABNF checker that also enforces the constraint vocabulary ([0062](docs/decisions/0062-core-rules-big-endian-fixed-width.md), rule 8), and the IDL's crates ([0067](docs/decisions/0067-the-aspis-idl.md)): `idl` (the compiler's front end and back ends, the conformance runner and fuzz entry points), `idl-rt` (the runtime of generated bindings, with `aspis.rpc`'s binding committed in `src/rpc/v1.rs`), `interfaces` (`aspis-interfaces`, the bindings of `interfaces/`, generated at build time) and `idl-fixtures` (the bindings of the compiler's test fixtures, for tests only).
- `interfaces/`: one IDL file per interface major, `<name as path>/v<M>.idl`, with each minor's generated wire and text grammars and vectors and the lock of published minors' hashes ([0067](docs/decisions/0067-the-aspis-idl.md), rule 7). `aspis.catalog` and `aspis.kernel.eventcount` are the call-language note's examples, which C51 and C17 replace. Regenerate with `cargo xtask idl --write`; publish a minor with `cargo run -p idlc -- lock FILE`. The compiler's fixtures are a second root, `crates/idl/tests/data/interfaces/`.
- `specs/`: the TLA+ specs of the kernel's concurrent protocols, one `specs/<name>.tla` each, with their TLC models (`.cfg`) and a README of what each checks ([0068](docs/decisions/0068-the-fuzzing-and-differential-testing-gate.md), rule 10). C12's is scheduling-context donation. Check them with `cargo xtask tlc`; never run `--nightly`, the 60-minute model, outside nightly CI.
- `grammars/`: ABNF grammars and their test vectors ([0013](docs/decisions/0013-abnf-for-protocols-and-calls.md), rule 6).
- `fuzz/`: the fuzz targets ([0068](docs/decisions/0068-the-fuzzing-and-differential-testing-gate.md)), a separate Cargo workspace with its own `Cargo.lock`, so fuzz dependencies never reach the product lock file. `fuzz/gate` holds the entry functions, oracles, target table and harness, and `fuzz/alloc` the memory bound. The target files, seeds, regressions and differential cases are committed. Run it through `cargo xtask fuzz`; [fuzz/README.md](fuzz/README.md) is the runbook.
- `tools/`: the glyph atlas generator, the logo rasterizer, the Dockerfile that builds GRUB, `tools/idlc` (the IDL compiler's command line: `check`, `build`, `lock`, `canon` and `rust`), and `tools/ci/`, the scripts CI runs. `xtask/`: the build tool (`cargo xtask build|run|test|matrix|lint|check-production|grub|grammars|idl|fuzz-dict|fuzz|tlc`). `test --host` runs the grammars, the interfaces and the host crates' tests without QEMU; `tlc` runs TLC over `specs/` within a 10-minute budget, with capped workers at low priority. `idl` checks the interfaces, their locks, generated files and idl-rt's `aspis.rpc` binding; `fuzz-dict` writes libFuzzer dictionaries into `build/fuzz/dict/`; `fuzz` runs the fuzz workspace ([fuzz/README.md](fuzz/README.md)).
- `.github/`: CI (C68). `ci.yml` runs on every change: REUSE, sign-offs on pull requests, the grammars and their vectors through both checkers (the generated ones included), the interfaces, their locks and generated files (`cargo xtask idl`), the Mermaid render check, rustfmt and clippy, the host and QEMU tests, and the reproducibility check; and, when a change touches `specs/`, `crates/ksched/`, `xtask/`, `.github/workflows/`, `.github/actions/`, `rust-toolchain.toml`, `Cargo.toml` or `Cargo.lock`, the `tlc` job, TLC with CI-sized constants. A change that touches only Markdown files and `docs/` skips clippy, the tests, the fuzz targets and the reproducibility check ([0036](docs/decisions/0036-qemu-configuration-and-test-builds.md), rule 3). `ci.yml`'s `fuzz` job builds every fuzz target, replays its seeds, regressions and cached corpus, fuzzes the targets a change selects, and runs the ABNF differential. `nightly.yml` runs the full QEMU matrix, every fuzz target for 10 minutes, the ABNF differential on 20,000 cases, `crates/ksched`'s seeded host tests at 20 times their per-change runs, and TLC with nightly constants. Actions are pinned to commit SHAs.
- `assets/fonts/`: Noto Sans Mono, and the fallbacks Noto Sans Math and Noto Sans Symbols ([0034](docs/decisions/0034-noto-fonts-under-ofl.md), rule 1), vendored and pinned by hash in `fonts.lock`, under OFL-1.1 (`REUSE.toml` covers them).
- `assets/logo/`: the boot logo, `aspis-boot.svg`. The build rasterizes it into coverage bitmaps for the kernel console, which holds no SVG code ([0009](docs/decisions/0009-text-as-graphics-console.md), rule 3).
- `docs/design/`: design notes and architecture views.
  - The design notes fed the ADRs, and each names the records it led to. Examples: [authorization-tree.md](docs/design/authorization-tree.md), [security-tokens.md](docs/design/security-tokens.md), [twelve-factor-apps.md](docs/design/twelve-factor-apps.md).
  - [system-context.md](docs/design/system-context.md) is the C4 system context: an ASPIS realm, the people who use it and the systems around it.
  - The views zoom in from there: [realm-containers.md](docs/design/realm-containers.md) (the realm's services), [node-components.md](docs/design/node-components.md) (one node's servers), [kernel-components.md](docs/design/kernel-components.md) (the kernel) and [key-flows.md](docs/design/key-flows.md) (sequence diagrams across all three).
  - [build-plan.md](docs/design/build-plan.md) divides the build into chunks (C01…) and milestones (M1–M9, and MH for hardware and hardening). [design-backlog.md](docs/design/design-backlog.md) lists the open decisions (D01…) under the milestone each must be settled before. When a decision is made, record it as an ADR and mark its backlog entry settled.
- [LICENSE](LICENSE): the verbatim text of the Mozilla Public License 2.0 ([0008](docs/decisions/0008-mpl-2.0-license.md), rule 3). Don't edit it.
- [LICENSES/](LICENSES): the license texts in the REUSE layout ([0033](docs/decisions/0033-contributions-docs-license-and-notice-years.md), rule 3): `MPL-2.0.txt` for code, `CC-BY-4.0.txt` for documents, `OFL-1.1.txt` for the vendored fonts, `CC-BY-SA-4.0.txt` for the code of conduct, and `LicenseRef-DCO.txt` for the DCO that `CONTRIBUTING.md` quotes. Don't edit them either.

## This working copy is in iCloud

The repository lives in `~/Documents`, which iCloud syncs, and the project owner depends on that sync. iCloud makes conflict copies named like `lib 2.rs` or `Dockerfile 3` when a file changes while it syncs. So:

- **The git database is `.git.nosync`**, behind a one-line `.git` file (`gitdir: .git.nosync`), because iCloud skips names that end in `.nosync`. Git works as usual. Other devices get the files through iCloud, but not the history.
- **`build` and `target` are symlinks** to `build.nosync` and `target.nosync`, for the same reason.
- **`fuzz/`'s builds, corpora, findings and coverage live under `build/fuzz/`.** Run fuzzing through `cargo xtask fuzz`, never `cargo fuzz run`, `tmin` or `coverage`, which write under `fuzz/`.
- **`.gitignore` ignores conflict copies**, so `git status` doesn't show them and `git add -A` can't commit them.
- **Cargo discovers no tests.** Crates with a `tests/` directory set `autotests = false` and list each test in `Cargo.toml`. Declare every new file in `tests/` there.
- **Tools that glob for files skip names with a space**, as `tools/ci/check-grammars.py` does. Prefer `git ls-files` to globbing.
- **If copies appear anyway,** move them into `build/icloud-duplicates/` with their paths; don't delete them, since some may hold older versions.

## Changing `main`

`main` is protected on GitHub. Every change reaches it through a pull request:

1. **Branch from `main`.** Never commit to `main` itself.
2. **Sign off every commit** with `git commit -s`. CI checks that every commit in a pull request carries a `Signed-off-by:` line ([0033](docs/decisions/0033-contributions-docs-license-and-notice-years.md), rule 1). The sign-off certifies the DCO, so it is the project owner's to give: commit with `-s` only when the project owner has asked for the commit.
3. **Push the branch and open a pull request.** CI's six jobs must pass (the `tlc` job runs only when its paths change, and passes when skipped), and the branch must be up to date with `main`. No approval is needed.
4. **Merge by rebase**, so history stays linear: `gh pr merge <n> --rebase --delete-branch`. Merge commits and force-pushes to `main` are refused.

GitHub deletes a pull request's branch when it is merged. In this clone, `fetch.prune` and a local `post-merge` hook then delete the local branch at the next `git pull` on `main`. The hook lives in `.git.nosync/hooks/` and isn't committed, so another clone doesn't have it. The project owner, as an admin, can still push to `main` directly; GitHub records that as a bypass.

## How the project works

- The work goes in three steps: research and discussion; a design session (architecture views, documentation, and dividing the build into chunks); then implementation.
- The design session settles what the ADRs leave open, in the order the build needs it.
- The project owner may add a tenet mid-discussion. Fold each new one into the ADRs and design notes.
- Read the relevant research, design notes and ADRs before proposing a design.
- Accepted ADRs are settled. Follow them, and don't re-argue them. To change one, propose an edit to it (below).
- If two accepted records conflict, say so and propose an edit that resolves the conflict.
- Record a new decision as the next numbered ADR, and add it to the index in [docs/decisions/README.md](docs/decisions/README.md). Records are never renumbered.
- Mark a new record "Proposed" until the project owner accepts it. A Proposed record isn't settled: check the index for each record's status.
- During the build phase, ADRs are edited in place (the project owner's rule, from 2026-11-25). We discover decisions as we build, and amendment chains made the records hard to follow.
  - Change a record by editing it, so that each record always says what is in force. Don't write amending records, and don't add "Amends" or "Amended by" notes.
  - Propose a change to an accepted record as an edit in a pull request. Merging the pull request accepts it. Git history records what changed and when.
  - A record's `Date` line is the date it was first written. When a record is edited on a later day than its date, its Date line adds "updated" and that day, as `2026-11-24, updated 2026-11-26`. The index copies each record's Date line.
  - In the same change, correct every record and design note that cites the changed rule.
  - A record that no longer applies keeps its file and its number, with its status changed to "Superseded by NNNN" or "Withdrawn".
- Design notes are inputs to decisions. When a decision makes a note stale, correct the note in place and cite the ADR that settles it.
- Where something isn't decided yet, say so. Don't guess.

### ADR format

Follow the existing records:

- Title `# NNNN. The decision in a few words`.
- A `- **Status:**` line and a `- **Date:**` line.
- Four sections: Context, Decision (numbered rules), Consequences and References.

<!-- REUSE-IgnoreStart -->

## Writing conventions

- **Copyright and license tags.** Every novel Markdown file starts with two tags ([0023](docs/decisions/0023-copyright-notices.md); [0033](docs/decisions/0033-contributions-docs-license-and-notice-years.md), rule 2):
  - Line 1 is the copyright tag: exactly `<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->` for a file first published in 2026, with the years as a range once it changes in a later year (below).
  - Line 2 is exactly `<!-- SPDX-License-Identifier: CC-BY-4.0 -->`. Documents are licensed under CC BY 4.0, and code examples inside a document are part of it.
  - SVG files, such as the mockups in `docs/mockups/`, carry the same two comments at the top.
  - Code files begin with `SPDX-FileCopyrightText: 2026 Nicole Roy` and `SPDX-License-Identifier: MPL-2.0`, in the file's comment syntax.
  - A notice names its years as a range: the year the holder first published the file, up to the latest year that holder changed it, such as `2026-2027 Nicole Roy`. A contributor's change doesn't extend Nicole Roy's range ([0033](docs/decisions/0033-contributions-docs-license-and-notice-years.md), rule 4).
  - Files that can't carry a comment, such as generated assets, are covered by a `REUSE.toml` ([0033](docs/decisions/0033-contributions-docs-license-and-notice-years.md), rule 3).
  - Third-party material keeps its own notices: quotations, code copied or vendored from elsewhere, and test vectors taken from standards.
- **Tone.** Plain, short sentences. Say what is decided and where. Say plainly what is still open.
- **Spelling.** American English in every document (the project owner's rule): "license" for both noun and verb, "behavior", "organization", "enrollment", "synchronization", "modeled", "canceled". Third-party text, such as `LICENSE` and quotations, keeps its own spelling.
- **Terminology.**
  - Write "the authorization tree", never "SMT". Cedar's policy analysis is built on SMT solvers, so the abbreviation is ambiguous ([policy note §6](docs/design/policy-and-decisions.md#6-conflicts-and-resolutions), item 8).
  - Getting a capability or session from an object's manager is a "bind" ([0014](docs/decisions/0014-versioned-object-apis.md), rule 4).
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

<!-- REUSE-IgnoreEnd -->

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

The code so far is M1's, and M2's as its chunks land (C06, C07, C10, C11, C12, C13a). For all of it:

- Write it in Rust: a microkernel for ARM64, bootable with GRUB ([founding requirements](docs/decisions/README.md#founding-requirements)). The boot image is a UEFI PE32+ image ([0006](docs/decisions/0006-uefi-boot-image.md)). The targets are QEMU `virt` first, then Raspberry Pi 4 ([0007](docs/decisions/0007-initial-hardware-targets.md)).
- The toolchain is pinned stable Rust, 1.100.0 in `rust-toolchain.toml`, with no nightly features. The kernel is an `aarch64-unknown-none` payload inside the `aarch64-unknown-uefi` stub, and user-space programs are `no_std` until there is a `std` port ([0035](docs/decisions/0035-toolchain-image-linkage-and-esp-layout.md)).
- All ASPIS code is licensed under MPL-2.0 ([0008](docs/decisions/0008-mpl-2.0-license.md)). Every source file carries both SPDX tags.
- Dependencies must use MIT, Apache-2.0, BSD or MPL-2.0. The kernel and core servers take no GPL-only dependencies ([0008](docs/decisions/0008-mpl-2.0-license.md), rule 4). Fonts, and data derived from them such as glyph atlases, may also be OFL-1.1, never code. The fonts are Noto Sans Mono and Noto Sans, with Noto Sans Math and Noto Sans Symbols as the console's fallbacks ([0034](docs/decisions/0034-noto-fonts-under-ofl.md), rule 1).
- Contributions come under the DCO: every commit in an outside contribution carries a `Signed-off-by:` line ([0033](docs/decisions/0033-contributions-docs-license-and-notice-years.md), rule 1).
- ASPIS's own images build reproducibly, bit for bit. CycloneDX is the only SBOM format: CycloneDX 1.7 for ASPIS's images, and CycloneDX for app builds too. Provenance is SLSA 1.2 ([0038](docs/decisions/0038-reproducible-builds-and-provenance.md)). Per-file copyright and license tags stay SPDX tags.
- Interfaces are written in the ASPIS IDL, and the IDL compiler generates each interface's ABNF. CI parses every grammar and runs its test vectors ([0013](docs/decisions/0013-abnf-for-protocols-and-calls.md)).
- ABNF is a protocol specification metalanguage: it describes protocols, calls and machine-read formats, never the language of the command interpreter people use. Don't propose ABNF, or the canonical text form of calls, as the interpreter's syntax (the project owner's rule; [0031](docs/decisions/0031-abnf-is-not-a-command-language.md)).
- Infrastructure as code uses OpenTofu, never Terraform. [0026](docs/decisions/0026-realm-as-cloud-provider.md) rule 12 makes the App API declarative enough to back an OpenTofu provider.

## Still open

Many ADRs leave details to the design session, and say which. [design-backlog.md](docs/design/design-backlog.md) lists the open decisions under the milestone each must be settled before. Don't assume an answer to any of them.

The two licensing questions that were open are settled: documents are under CC BY 4.0, and contributions come under the DCO ([0033](docs/decisions/0033-contributions-docs-license-and-notice-years.md)). ASPIS accepts outside contributions: [CONTRIBUTING.md](CONTRIBUTING.md) quotes the DCO and describes the workflow, CI checks sign-offs, [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) is the Contributor Covenant 3.0 (under CC BY-SA 4.0, the one document that isn't CC BY 4.0), and [SECURITY.md](SECURITY.md) points to GitHub's private vulnerability reporting.
