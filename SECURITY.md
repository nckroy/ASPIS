<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Security

ASPIS is meant to carry security-critical parts: hybrid post-quantum cryptography, a realm certificate authority, an authorization tree and the boot chain that loads them. Reports of weaknesses are welcome.

## Reporting a vulnerability

Report it privately, through GitHub's private vulnerability reporting: on the repository's **Security** tab, choose **Report a vulnerability**, or go straight to [the new advisory form](https://github.com/nckroy/ASPIS/security/advisories/new). The report reaches the project owner and stays private until it is resolved.

Please don't open a public issue or pull request for a vulnerability in the code.

## What's in scope

- **The code:** the boot stub, the kernel, the crates in `crates/`, the build tool (`xtask/`) and the tools in `tools/`.
- **The supply chain:** CI, the pinned toolchain and dependencies, the vendored fonts, and the sources the build fetches and checks (QEMU, GRUB and their signatures).
- **The designs:** the decision records and design notes. Nothing implements most of them yet, so a weakness in a design can be raised openly, as an issue. If you aren't sure whether a report should be private, report it privately.

## Versions

ASPIS has made no release. Only `main` is maintained, and fixes land there.

## What to expect

The project owner maintains ASPIS alone, so there is no promised response time. Each report is read, and you'll hear back through the advisory. A fix and its disclosure are coordinated in the advisory too. Reporters are credited in the advisory if they want to be.
