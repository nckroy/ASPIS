<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0038. Reproducible builds, CycloneDX SBOMs and SLSA provenance

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

[0026](0026-realm-as-cloud-provider.md), rules 3 and 4 require every app build to carry an SBOM and SLSA 1.2 provenance, and deploys to run only builds whose provenance verifies. No record covers ASPIS's own images, `aspis.efi` and `initfs.img`. Measured boot needs known-good values for them (C64), and test builds must be shown to differ from production builds ([0036](0036-qemu-configuration-and-test-builds.md), rule 8). See [design backlog, D05 and D128](../design/design-backlog.md#m1-first-light).

Facts checked on 2026-11-25:

- **SBOM formats.**
  - CycloneDX 1.7 is the newest version, published as ECMA-424, 2nd edition (December 2025); its newest patch release is 1.7.2.
  - SPDX 3.0.1 is the newest final SPDX, and 3.1 is a release candidate.
- **Provenance.** SLSA 1.2 (November 2025) is the current SLSA. Provenance travels as an in-toto Statement (`https://in-toto.io/Statement/v1`) in a DSSE envelope (1.0.2).
- **Signing.**
  - GitHub artifact attestations are built on Sigstore. For public repositories they use Sigstore's public instance and its transparency log.
  - Sigstore's ML-DSA support is experimental. Its post-quantum public instance is planned for mid-2027.
- **Rust reproducibility.**
  - Rust has stable `--remap-path-prefix`, and `--remap-path-scope` since 1.95. Cargo's `trim-paths` is still unstable.
  - LLD writes a deterministic PE timestamp with `/Brepro`.

The project owner decided on 2026-11-25: CycloneDX for SBOMs, signed through Sigstore. They also decided that CycloneDX is ASPIS's only SBOM format, including for app builds. The rules below spell those decisions out.

## Decision

1. **ASPIS's own images build bit for bit reproducibly.**
   - **Inputs are pinned:** the toolchain ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 1), `Cargo.lock`, vendored dependencies, the font files by hash ([0034](0034-noto-fonts-under-ofl.md), rule 1), and the build environment as a container image named by digest.
   - **The build fixes everything that varies:** paths are remapped with `--remap-path-prefix` and `--remap-path-scope`, each crate is built as one codegen unit, `SOURCE_DATE_EPOCH` is the commit's time, the PE timestamp comes from `/Brepro`, and the image builders sort their inputs and record no times, owners or permissions of their own.
   - **CI checks it:** every change to code builds `aspis.efi` and `initfs.img` twice, in different directories and as different users, and fails if the bytes differ. A difference is reported with diffoscope.
2. **CycloneDX is ASPIS's SBOM format.**
   - Each release of `aspis.efi` and `initfs.img` carries a CycloneDX 1.7 SBOM in JSON. It lists every crate and asset with its version, hash and license, as SPDX license identifiers, which CycloneDX uses. Assets include the fonts and their OFL-1.1 license ([0034](0034-noto-fonts-under-ofl.md), rule 3).
   - App builds use CycloneDX too. This settles the SBOM format that [0026](0026-realm-as-cloud-provider.md), rule 3 left open (D128).
   - The SBOM is generated from the same pinned inputs, so it is reproducible as well.
3. **Provenance is SLSA 1.2**, as an in-toto Statement v1 in a DSSE envelope, naming the source commit, the build workflow and the container image's digest, as [0026](0026-realm-as-cloud-provider.md), rule 3 already asks of apps.
4. **Images built outside any realm are signed through Sigstore.**
   - ASPIS's public repository signs each release's SBOM and provenance with GitHub artifact attestations. That is Sigstore keyless signing, recorded in Sigstore's public transparency log.
   - Those signatures are classical, not post-quantum. Once Sigstore's post-quantum instance is in production, releases add an ML-DSA signature, as [0003](0003-hybrid-post-quantum-cryptography.md) intends for everything long-lived.
   - Inside a realm, the builder signs with its workload identity ([0026](0026-realm-as-cloud-provider.md), rule 3). A realm that runs ASPIS's own images verifies the Sigstore attestation, or rebuilds the images and compares them.
5. **The release's hashes are the known-good values** that measured boot (C64) compares against.

## Consequences

- **Anyone can check a release** by rebuilding it from the commit and comparing hashes, without trusting ASPIS's CI.
- **One SBOM format across ASPIS.** The images and the app platform use the same tooling, and a realm reads one format. The per-file copyright and license tags stay SPDX tags in the REUSE format ([0023](0023-copyright-notices.md), [0033](0033-contributions-docs-license-and-notice-years.md)). CycloneDX names licenses with the same SPDX identifiers.
- **Release signatures are classical until mid-2027 or later.** Sigstore's post-quantum timing is outside ASPIS's control. Rebuilding is the post-quantum-safe check until then.
- **Builds are slower.** One codegen unit per crate and two builds per code change cost CI time.
- **D128 narrows** to the OCI layout of app builds and the signatures that verifiers outside ASPIS can check.

## References

- [CycloneDX specification releases](https://github.com/CycloneDX/specification/releases); [ECMA-424](https://ecma-international.org/publications-and-standards/standards/ecma-424/)
- [SLSA 1.2 announcement](https://slsa.dev/blog/2025/11/announce-slsa-v1.2); [in-toto attestation framework](https://github.com/in-toto/attestation); [DSSE](https://github.com/secure-systems-lab/dsse)
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations); [Sigstore: post-quantum plans](https://blog.sigstore.dev/pqc-sigstore/)
- [Reproducible Builds: `SOURCE_DATE_EPOCH`](https://reproducible-builds.org/docs/source-date-epoch/); [rust-lang/rust#147611: `--remap-path-scope`](https://github.com/rust-lang/rust/pull/147611)
- [0026. The realm as a virtual cloud provider](0026-realm-as-cloud-provider.md)
