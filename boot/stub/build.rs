// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Embeds the kernel's ELF and the initial image's digest, and sets the PE
//! image version (ADR 0035, rule 3; ADR 0040, rule 1).
//!
//! The build tool (`cargo xtask build`) sets `ASPIS_KERNEL_ELF` and
//! `ASPIS_INITFS_DIGEST`. Built any other way, the stub gets placeholders and
//! refuses to boot.

use std::{env, fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    for (var, name, placeholder) in [
        ("ASPIS_KERNEL_ELF", "kernel.elf", &[][..]),
        ("ASPIS_INITFS_DIGEST", "initfs.sha512", &[0u8; 64][..]),
    ] {
        println!("cargo:rerun-if-env-changed={var}");
        let dest = out.join(name);
        match env::var(var) {
            Ok(path) => {
                println!("cargo:rerun-if-changed={path}");
                fs::copy(&path, &dest).unwrap_or_else(|e| panic!("{var}={path}: {e}"));
            }
            Err(_) => fs::write(&dest, placeholder).unwrap(),
        }
    }
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("uefi") {
        // GRUB serves the initial image through LoadFile2 only to images whose
        // PE major image version is 1 or higher (ADR 0006, rule 1).
        println!("cargo:rustc-link-arg-bins=/version:1.0");
        // A deterministic PE timestamp (ADR 0038, rule 1).
        println!("cargo:rustc-link-arg-bins=/Brepro");
        // No PDB and no CodeView record: the PDB's GUID depends on build
        // paths, which would make aspis.efi differ between build directories.
        println!("cargo:rustc-link-arg-bins=/DEBUG:NONE");
    }
}
