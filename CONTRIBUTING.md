<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Contributing to ASPIS

ASPIS is an open-source microkernel operating system for ARM64, written in Rust and modeled on Apollo AEGIS / Domain/OS. Most of it is still design: research notes, decision records and design notes. The first code, milestone M1 ("first light"), boots a UEFI stub and a kernel on QEMU and draws the kernel's console as text on the framebuffer ([build plan](docs/design/build-plan.md#m1-first-light)).

Contributions are welcome: corrections to the research and designs, discussion of open decisions, and code that follows the build plan. This guide says how the project works, how to build and test it, and what a pull request needs.

Everyone who takes part follows the [code of conduct](CODE_OF_CONDUCT.md). Report security vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes, not in a public issue.

## How the project works

- **Research, then design, then code.** The [research notes](docs/research/aegis-domain-os.md) come first. The design session turns them into decisions, architecture views and a [build plan](docs/design/build-plan.md) of chunks (C01…) and milestones (M1–M9, and MH for hardware and hardening). Code follows the plan.
- **Decisions are records.** Each architecture decision is an ADR in [docs/decisions/](docs/decisions/README.md), and the index there gives each record's status.
  - A new decision starts as a **Proposed** record. It is settled only when the project owner accepts it.
  - During the build phase, accepted records are edited in place, so each one says what is in force. Propose a change as an edit to the record in a pull request; merging it accepts the change. Git history records what changed and when.
  - The [design backlog](docs/design/design-backlog.md) lists the decisions still open, under the milestone each must be settled before. A good place to start a design discussion is an issue about one of them.
- **Larger code changes follow a chunk.** Before writing a lot of code, check the build plan for the chunk it belongs to and the decisions that chunk waits on. If a decision is still open, the code waits for it, or the pull request proposes the decision too.

## Building and testing

### What you need

- **Rust**, through [rustup](https://rustup.rs). `rust-toolchain.toml` pins the version, stable Rust with no nightly features ([0035](docs/decisions/0035-toolchain-image-linkage-and-esp-layout.md)), and rustup installs it, with both targets, on first use.
- **QEMU 11.1.3**, with the EDK2 firmware it ships ([0036](docs/decisions/0036-qemu-configuration-and-test-builds.md)).
  - On macOS: `brew install qemu`.
  - On Linux, build it from the signature-checked release tarball, as CI does. First install the build packages; on Debian or Ubuntu: `sudo apt install build-essential ninja-build pkg-config python3-venv libglib2.0-dev libpixman-1-dev libslirp-dev libpng-dev libfdt-dev flex bison bzip2`. Add `libgtk-3-dev` if you want `cargo xtask run --window`, which uses GTK on Linux. Then run `sh tools/ci/build-qemu.sh <prefix>` and put `<prefix>/bin` on your `PATH`.
- **mtools**, to build the EFI system partition image: `brew install mtools`, or `sudo apt install mtools`.
- **Docker**, to build GRUB 2.14 arm64-efi once, from its checked source: `cargo xtask grub`.
- **Optional, for model checking:** a Java runtime, 11 or later, for `cargo xtask tlc`, which fetches TLC itself and checks its hash. CI runs it only when a change touches `specs/`, `crates/ksched/`, `xtask/`, `.github/workflows/`, `.github/actions/`, `rust-toolchain.toml`, `Cargo.toml` or `Cargo.lock`.
- **Optional, for the checks CI runs on licenses and documents:** [pipx](https://pipx.pypa.io) for REUSE, Python 3 for the grammars, and Node.js with Google Chrome for the diagrams. The next section has the commands.

### Commands

| Command | What it does |
|---|---|
| `cargo xtask build [--test-build]` | Builds `aspis.efi` and `initfs.img` into `build/production` or `build/test` |
| `cargo xtask run [options]` | Boots in QEMU, through GRUB by default |
| `cargo xtask test` | Host tests, the production-image check, in-QEMU tests on two configurations, boots through GRUB, and a forced panic |
| `cargo xtask lint` | `rustfmt` and `clippy` for every crate, each on the target it builds for |
| `cargo xtask matrix` | The nightly matrix: four CPU and GIC configurations, 1, 4 and 8 cores, 1 and 3 GiB, and a boot with the firmware at EL2 |
| `cargo xtask check-production` | Fails if a production image holds test-only code |
| `cargo xtask fuzz <command>` | The fuzz targets: `install`, `build`, `replay`, `run`, `coverage` and more ([fuzz/README.md](fuzz/README.md)). Building them needs a C++ compiler, for libFuzzer |
| `cargo xtask tlc` | Model-checks the TLA+ specs in `specs/` with TLC, and validates the Rust's traces against them, within 10 minutes |

Useful `run` options:

- `--window` shows the screen in a window. `--resolution 1024x768` has GRUB set that video mode first; QEMU's `ramfb` offers 1024×768 at most.
- `--args "<kernel arguments>"` passes kernel arguments through GRUB, for example `--args "console.cell=32"` for the 32-pixel console. The grammar is in [grammars/kernel-args.abnf](grammars/kernel-args.abnf).
- `--config a72-v2|a72-v3|max-v2|max-v3` picks the CPU and GIC version. `--smp`, `--memory` and `--virtualization` set the cores, the memory and EL2 firmware.
- `--test-build` boots a test build, which runs the in-QEMU tests and exits. `--direct` boots `aspis.efi` straight from the firmware, without GRUB.
- `--expect "<text>"`, `--screenshot <file>` and `--timeout <seconds>` script a run: it succeeds once the UART shows the text, and saves the screen as it does.

### The checks CI runs

CI runs six jobs on every pull request. `cargo xtask lint`, `cargo xtask test`, `cargo xtask fuzz` and `cargo xtask tlc` cover four of them, the Rust lints, the tests, the fuzz targets and model checking. Model checking runs only when a change touches `specs/`, `crates/ksched/`, `xtask/`, `.github/workflows/`, `.github/actions/`, `rust-toolchain.toml`, `Cargo.toml` or `Cargo.lock`, and is skipped otherwise. When a pull request changes only Markdown files and `docs/`, CI skips the lints, the tests, the fuzz targets and the reproducibility check, and runs only the document checks. A change to documents or file headers needs the others too. From the repository root:

| CI job | Run it yourself |
|---|---|
| rustfmt and clippy | `cargo xtask lint` |
| Host and QEMU tests | `cargo xtask test` |
| Fuzz targets | `cargo xtask fuzz install && cargo xtask fuzz build && cargo xtask fuzz replay`, then `cargo xtask fuzz smoke --base main` and, with a Python that has `abnf==2.9.1` in `ASPIS_PYTHON`, `cargo xtask fuzz differential --self-test` and `cargo xtask fuzz differential --seed 0 --cases 300` |
| Model checking | `cargo xtask tlc`, with Java 11 or later |
| Licenses (REUSE) | `pipx run --spec 'reuse[charset-normalizer]==6.3.0' reuse lint` |
| Sign-offs | `sh tools/ci/check-dco.sh main HEAD` |
| Grammars and their vectors | `python3 -m venv ~/.venvs/abnf && ~/.venvs/abnf/bin/pip install abnf==2.9.1`, then `~/.venvs/abnf/bin/python -I tools/ci/check-grammars.py grammars` |
| Diagrams | `npm install --no-save --prefix ~/.cache/aspis-mermaid mermaid@latest puppeteer-core@25`, then `git ls-files -z '*.md' \| NODE_PATH=~/.cache/aspis-mermaid/node_modules xargs -0 node tools/ci/check-mermaid.js`. Set `CHROME_PATH` if Chrome isn't at its usual path |
| Reproducible images | Left to CI: `tools/ci/reproducible.sh` builds a second time as another user, with `sudo` |

## Conventions

[CLAUDE.md](CLAUDE.md) has the project's full working rules. The ones every change needs:

### Code

- **Rust on the pinned stable toolchain**, with no nightly features ([0035](docs/decisions/0035-toolchain-image-linkage-and-esp-layout.md)).
- **Every source file starts with two SPDX tags**, in its comment syntax ([0023](docs/decisions/0023-copyright-notices.md), [0033](docs/decisions/0033-contributions-docs-license-and-notice-years.md)):

  ```rust
  // SPDX-FileCopyrightText: 2026 Your Name
  // SPDX-License-Identifier: MPL-2.0
  ```

- **Dependencies** must be under MIT, Apache-2.0, BSD or MPL-2.0. Fonts may also be under OFL-1.1, and code never is ([0008](docs/decisions/0008-mpl-2.0-license.md), rule 4). The kernel and the core servers take no GPL-only dependency.
- **Libraries the kernel uses are `no_std`**, don't allocate unless a feature asks them to, and never panic on untrusted input.
- **A crate with a `tests/` directory sets `autotests = false`** and declares each file in it as a `[[test]]` in its `Cargo.toml`. Do both when you add a crate's first integration test.
- **A new crate is added to the package lists** in `cargo xtask test` and `cargo xtask lint` (`xtask/src/main.rs`), or CI won't test or lint it.
- **Protocols and machine-read formats have an ABNF grammar** in `grammars/`, with test vectors that CI checks ([0013](docs/decisions/0013-abnf-for-protocols-and-calls.md)). ABNF never describes the language people type at a command line ([0031](docs/decisions/0031-abnf-is-not-a-command-language.md)).

### Documents

- **American English**, plain short sentences, and links that are relative and resolve.
- **Every Markdown file starts with two tags:** `<!-- SPDX-FileCopyrightText: 2026 Your Name -->` and `<!-- SPDX-License-Identifier: CC-BY-4.0 -->`.
- **Diagrams are Mermaid**, in the Markdown that uses them, with the C4 model for context diagrams ([0024](docs/decisions/0024-diagrams-mermaid-and-c4.md)). Check that a diagram renders in the newest stable Mermaid before calling it done; CI checks every diagram.
- **Decision records follow the existing ones:** a title `# NNNN. The decision in a few words`, status and date lines, then Context, Decision (numbered rules), Consequences and References.

## Licensing and copyright

A contribution is licensed under the license of the files it changes or adds: MPL-2.0 for code, CC BY 4.0 for documents ([0033](docs/decisions/0033-contributions-docs-license-and-notice-years.md), rule 1). ASPIS asks for no contributor license agreement and no assignment, and you keep your copyright.

- When your change to a file is copyrightable, add your own `SPDX-FileCopyrightText` line to it. A file you create names you.
- A notice names its years as a range, from the year the holder first published the file to the latest year that holder changed it, such as `2026-2027 Your Name` (rule 4).
- Third-party material keeps its own notices: quotations, code copied from elsewhere, and test vectors from standards.

## Commits and pull requests

`main` is protected. Every change reaches it through a pull request:

1. **Branch from `main`.**
2. **Sign off every commit** with `git commit -s`. The sign-off certifies the Developer Certificate of Origin, below. The name in it identifies you; anonymous contributions aren't accepted.
3. **Push your branch and open a pull request.** CI runs six jobs, and all must pass on a branch that's up to date with `main`:
   - licenses (REUSE), sign-offs, grammars and their vectors, and diagrams;
   - `rustfmt` and `clippy`;
   - host tests and QEMU tests;
   - the fuzz targets: every target built, its seeds, regressions and cached corpus replayed, the targets the change touches fuzzed, and the ABNF differential ([0068](docs/decisions/0068-the-fuzzing-and-differential-testing-gate.md));
   - model checking, when the change touches the specs or the code their traces come from ([0068](docs/decisions/0068-the-fuzzing-and-differential-testing-gate.md), rule 10);
   - reproducible images: two builds, in different directories and as different users, must give the same `aspis.efi` and `initfs.img` ([0038](docs/decisions/0038-reproducible-builds-and-provenance.md)).
4. **The project owner merges by rebase**, so history stays linear.

Keep a pull request to one change, and say in its description which records and chunks it touches.

## Developer Certificate of Origin

A sign-off on a commit (`Signed-off-by: Your Name <you@example.com>`) certifies that you can make the contribution under the project's licenses. It certifies the Developer Certificate of Origin 1.1, quoted here as published at <https://developercertificate.org/>:

<!-- SPDX-SnippetBegin -->
<!-- SPDX-SnippetCopyrightText: 2004, 2006 The Linux Foundation and its contributors -->
<!-- SPDX-License-Identifier: LicenseRef-DCO -->

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

<!-- SPDX-SnippetEnd -->
