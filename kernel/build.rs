// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Links the kernel with its own linker script (ADR 0035, rule 2), and
//! points it at the glyph atlases the build tool generated (ADR 0034).

use std::{env, path::PathBuf};

fn main() {
    let dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let script = dir.join("link.ld");
    println!("cargo:rerun-if-changed={}", script.display());
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("none") {
        println!("cargo:rustc-link-arg-bins=-T{}", script.display());
        // A static PIE: this target links statically and doesn't make a PIE
        // by itself, even with `-C relocation-model=pie`.
        println!("cargo:rustc-link-arg-bins=-pie");
        println!("cargo:rustc-link-arg-bins=--no-dynamic-linker");
        // The prebuilt `core` for this target isn't compiled as PIC, so some
        // of its read-only data holds absolute pointers that need dynamic
        // relocations. Rebuilding `core` needs `build-std`, which is
        // nightly-only (ADR 0035, rule 1). The stub applies every relocation
        // before the kernel runs, with nothing yet write-protected, so
        // relocations in read-only sections are harmless here.
        println!("cargo:rustc-link-arg-bins=-z");
        println!("cargo:rustc-link-arg-bins=notext");
    }
    // `cargo xtask build` sets this to the directory holding atlas-16.bin,
    // atlas-24.bin and atlas-32.bin.
    println!("cargo:rerun-if-env-changed=ASPIS_ATLAS_DIR");
    let atlas = env::var("ASPIS_ATLAS_DIR").unwrap_or_else(|_| {
        panic!("ASPIS_ATLAS_DIR is not set: build the kernel with `cargo xtask build`")
    });
    for size in [16, 24, 32] {
        println!("cargo:rerun-if-changed={atlas}/atlas-{size}.bin");
        println!("cargo:rerun-if-changed={atlas}/logo-{size}.bin");
    }
    println!("cargo:rustc-env=ASPIS_ATLAS_DIR={atlas}");
}
