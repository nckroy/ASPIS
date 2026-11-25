// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The EFI system partition image, with mtools (ADR 0035, rule 6).
//!
//! Two layouts:
//!
//! - **GRUB**, as ADR 0035 rule 6 lays it out: GRUB at
//!   `/EFI/BOOT/BOOTAA64.EFI`, its menu at `/aspis/grub.cfg`, and slot `a`
//!   at `/aspis/a/`. Slot `b` stays empty until updates exist (C79).
//! - **Direct**, for booting `aspis.efi` from the firmware without GRUB:
//!   `aspis.efi` as `/EFI/BOOT/BOOTAA64.EFI`, with `initfs.img` beside it,
//!   where the stub looks for it (ADR 0041, rule 6).

use crate::{fail, run_cmd};
use std::{fs, path::Path, process::Command};

const SIZE: u64 = 64 << 20;

fn mtools(tool: &str, img: &Path) -> Command {
    let mut c = Command::new(tool);
    c.env("MTOOLS_SKIP_CHECK", "1").arg("-i").arg(img);
    c
}

fn mkdirs(img: &Path, dirs: &[&str]) {
    for d in dirs {
        run_cmd(mtools("mmd", img).arg(format!("::{d}")));
    }
}

fn copy(img: &Path, from: &Path, to: &str) {
    run_cmd(mtools("mcopy", img).arg(from).arg(format!("::{to}")));
}

fn blank(img: &Path) {
    let _ = fs::remove_file(img);
    let f = fs::File::create(img).unwrap_or_else(|e| fail(format!("{}: {e}", img.display())));
    f.set_len(SIZE).unwrap();
    run_cmd(mtools("mformat", img).args(["-F", "-v", "ASPIS", "::"]));
}

/// The ESP with GRUB and slot `a`, booting with `args`. With a
/// `resolution` such as `1024x768`, GRUB sets that video mode through
/// gfxterm before it boots, and the stub keeps it (ADR 0009: the resolution
/// is whatever was set before the kernel).
pub fn grub(img: &Path, images: &Path, grub: &Path, args: &str, resolution: Option<&str>) {
    blank(img);
    mkdirs(
        img,
        &["/EFI", "/EFI/BOOT", "/aspis", "/aspis/a", "/aspis/b"],
    );
    copy(img, grub, "/EFI/BOOT/BOOTAA64.EFI");
    let cfg = images.join("grub.cfg");
    // gfxterm stays the terminal through the boot, or GRUB would put the
    // firmware's mode back. Its own lines then show only on the screen.
    let video = resolution.map_or(String::new(), |r| {
        format!("set gfxmode={r}\nset gfxpayload=keep\nterminal_output gfxterm\n")
    });
    fs::write(
        &cfg,
        format!(
            "set timeout=0\nset default=0\n{video}\nmenuentry \"ASPIS\" {{\n    linux  /aspis/a/aspis.efi {args}\n    initrd /aspis/a/initfs.img\n}}\n"
        ),
    )
    .unwrap();
    copy(img, &cfg, "/aspis/grub.cfg");
    copy(img, &images.join("aspis.efi"), "/aspis/a/aspis.efi");
    copy(img, &images.join("initfs.img"), "/aspis/a/initfs.img");
}

/// The ESP for booting `aspis.efi` straight from the firmware.
pub fn direct(img: &Path, images: &Path) {
    blank(img);
    mkdirs(img, &["/EFI", "/EFI/BOOT"]);
    copy(img, &images.join("aspis.efi"), "/EFI/BOOT/BOOTAA64.EFI");
    copy(img, &images.join("initfs.img"), "/EFI/BOOT/initfs.img");
}
