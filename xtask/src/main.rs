// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `cargo xtask`: builds ASPIS's images, assembles the ESP and runs QEMU.
//!
//! ```text
//! cargo xtask build [--test-build]          aspis.efi and initfs.img
//! cargo xtask run [options]                 boot in QEMU
//! cargo xtask test                          host tests, then QEMU tests
//! cargo xtask check-production              no test code in production images
//! cargo xtask matrix                        the nightly QEMU matrix
//! cargo xtask lint                          rustfmt and clippy, every target,
//!                                           and the no_std crates built for
//!                                           a target without std
//! cargo xtask grammars                      every grammar and its vectors,
//!                                           with the Rust checker
//! cargo xtask idl [--write]                 idlc check over interfaces/:
//!                                           locks, compatibility, the
//!                                           generated grammars and vectors,
//!                                           and idl-rt's aspis.rpc binding
//!                                           (--write regenerates them;
//!                                           a stale aspis.rpc binding
//!                                           never blocks this, since
//!                                           idlc builds idl-rt without it)
//! cargo xtask fuzz-dict                     a libFuzzer dictionary per
//!                                           grammar, in build/fuzz/dict
//! cargo xtask grub                          GRUB 2.14 arm64-efi, in Docker
//! ```
//!
//! `run` options:
//!
//! ```text
//! --test-build            boot a test build
//! --direct                boot aspis.efi from the firmware, without GRUB
//! --config a72-v2|max-v3  the QEMU configuration (ADR 0036, rule 3)
//! --args "<args>"         kernel arguments, through GRUB
//! --expect "<text>"       stop with success once the UART shows <text>
//! --screenshot <file>     save the screen (PNG) when --expect matches
//! --timeout <seconds>     give up after this long (default 120)
//! --smp <n>               cores (default 4)
//! --memory <size>         memory (default 1G)
//! --virtualization        the firmware runs at EL2
//! --resolution <w>x<h>    GRUB sets this video mode (ramfb: up to 1024x768)
//! --window                show the screen in a window
//! ```

mod esp;
mod fuzz_dict;
mod grammars;
mod idl;
mod qemu;

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, exit},
};

/// The workspace root.
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

pub fn build_dir() -> PathBuf {
    root().join("build")
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flavor {
    Production,
    Test,
}

impl Flavor {
    pub fn name(self) -> &'static str {
        match self {
            Flavor::Production => "production",
            Flavor::Test => "test",
        }
    }

    pub fn out(self) -> PathBuf {
        build_dir().join(self.name())
    }

    /// Test builds use their own target directory (ADR 0036, rule 6).
    fn target_dir(self) -> PathBuf {
        match self {
            Flavor::Production => root().join("target"),
            Flavor::Test => build_dir().join("target-test"),
        }
    }
}

pub fn fail(msg: impl AsRef<str>) -> ! {
    eprintln!("xtask: {}", msg.as_ref());
    exit(1)
}

pub fn run_cmd(cmd: &mut Command) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| fail(format!("{cmd:?}: {e}")));
    if !status.success() {
        fail(format!("{:?} failed: {status}", cmd.get_program()));
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        eprintln!(
            "usage: cargo xtask build|run|test|check-production|matrix|lint|grammars|idl|fuzz-dict|grub [options]"
        );
        exit(2)
    };
    let rest = &args[1..];
    let flavor = if rest.iter().any(|a| a == "--test-build") {
        Flavor::Test
    } else {
        Flavor::Production
    };
    match cmd.as_str() {
        "build" => {
            build(flavor);
        }
        "run" => {
            let opts = qemu::Options::parse(rest);
            build(opts.flavor);
            let code = qemu::run(&opts);
            exit(code);
        }
        "test" => test(),
        "check-production" => {
            build(Flavor::Production);
            check_production();
        }
        "grub" => {
            grub();
        }
        "matrix" => matrix(),
        "lint" => lint(),
        "grammars" => grammars::check(),
        "idl" => idl::check(rest.iter().any(|a| a == "--write")),
        "fuzz-dict" => fuzz_dict::write(),
        other => fail(format!("unknown command {other}")),
    }
}

/// The commit's time, so builds are reproducible (ADR 0038, rule 1).
/// A `SOURCE_DATE_EPOCH` already set wins, so a build without `.git` can
/// match one with it.
fn source_date_epoch() -> String {
    if let Ok(epoch) = env::var("SOURCE_DATE_EPOCH")
        && !epoch.is_empty()
    {
        return epoch;
    }
    Command::new("git")
        .args(["log", "-1", "--format=%ct"])
        .current_dir(root())
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "0".into())
}

/// Flags for one target: remapped paths (ADR 0038, rule 1), the kernel's
/// relocation model, and the test-build switch (ADR 0036, rule 6).
fn rustflags(flavor: Flavor, pie: bool) -> String {
    let home = env::var("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env::var("HOME").unwrap()).join(".cargo"));
    let mut f = vec![
        format!("--remap-path-prefix={}=/aspis", root().display()),
        format!("--remap-path-prefix={}=/cargo", home.display()),
    ];
    if pie {
        f.push("-Crelocation-model=pie".into());
    }
    if flavor == Flavor::Test {
        f.push("--cfg=aspis_test_build".into());
    }
    f.join(" ")
}

fn cargo(flavor: Flavor) -> Command {
    let mut c = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    c.current_dir(root())
        .env("SOURCE_DATE_EPOCH", source_date_epoch())
        .env("CARGO_TARGET_DIR", flavor.target_dir())
        .env(
            "CARGO_TARGET_AARCH64_UNKNOWN_NONE_RUSTFLAGS",
            rustflags(flavor, true),
        )
        .env(
            "CARGO_TARGET_AARCH64_UNKNOWN_UEFI_RUSTFLAGS",
            rustflags(flavor, false),
        );
    c
}

/// The glyph atlases, from the pinned fonts (ADR 0034, ADR 0046), and the
/// logo.
fn atlases() -> PathBuf {
    let out = build_dir().join("atlas");
    fs::create_dir_all(&out).unwrap();
    let fonts = root().join("assets/fonts");
    verify_fonts(&fonts);
    run_cmd(
        Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .current_dir(root())
            .args([
                "run",
                "--locked",
                "--quiet",
                "--release",
                "-p",
                "atlas",
                "--",
                "--font",
            ])
            .arg(fonts.join("NotoSansMono-Regular.ttf"))
            // The fallbacks, in the order to try them (ADR 0034, rule 1).
            .arg("--fallback")
            .arg(fonts.join("NotoSansMath-Regular.ttf"))
            .arg("--fallback")
            .arg(fonts.join("NotoSansSymbols-Regular.ttf"))
            .arg("--out")
            .arg(&out),
    );
    // The boot logo, at the size of each atlas (ADR 0009, rule 3).
    run_cmd(
        Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .current_dir(root())
            .args([
                "run",
                "--locked",
                "--quiet",
                "--release",
                "-p",
                "logo",
                "--",
                "--svg",
            ])
            .arg(root().join("assets/logo/aspis-boot.svg"))
            .arg("--out")
            .arg(&out),
    );
    out
}

/// Checks every font file `fonts.lock` lists against its SHA-512, before the
/// build uses it (ADR 0034, rule 1).
fn verify_fonts(dir: &Path) {
    let lock = fs::read_to_string(dir.join("fonts.lock"))
        .unwrap_or_else(|e| fail(format!("fonts.lock: {e}")));
    let value = |line: &str, key: &str| {
        line.strip_prefix(key)
            .and_then(|r| r.trim_start().strip_prefix('='))
            .map(|r| r.trim().trim_matches('"').to_string())
    };
    let mut file: Option<String> = None;
    let mut checked = 0;
    for line in lock.lines().map(str::trim) {
        if line == "[[font]]" {
            file = None;
        } else if let Some(f) = value(line, "file") {
            file = Some(f);
        } else if let Some(want) = value(line, "sha512") {
            let name = file
                .take()
                .unwrap_or_else(|| fail("fonts.lock: a sha512 before its file"));
            let bytes = fs::read(dir.join(&name)).unwrap_or_else(|e| fail(format!("{name}: {e}")));
            let got: String = initfs::image_digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if got != want {
                fail(format!("{name} doesn't match its SHA-512 in fonts.lock"));
            }
            checked += 1;
        }
    }
    if checked == 0 {
        fail("fonts.lock lists no fonts");
    }
}

/// The boot manifest's placeholder. Its format is the root server's
/// decision (D40), and M1 carries no servers yet.
const MANIFEST: &str = "# ASPIS boot manifest\n\
# Its format is decided with the root server (design backlog D40).\n\
# M1 carries no servers yet.\n";

/// Builds `initfs.img` (ADR 0037) and returns it.
fn initfs(out: &Path) -> Vec<u8> {
    let mut b = initfs::Builder::new(initfs::DEFAULT_ALIGNMENT);
    b.manifest(MANIFEST.as_bytes().to_vec());
    let img = b.build().unwrap_or_else(|e| fail(format!("initfs: {e:?}")));
    fs::write(out.join("initfs.img"), &img).unwrap();
    img
}

/// Builds `aspis.efi` and `initfs.img` into `build/<flavor>/`.
pub fn build(flavor: Flavor) -> PathBuf {
    let out = flavor.out();
    fs::create_dir_all(&out).unwrap();
    let atlas = atlases();

    // 1. The kernel (ADR 0035, rule 2).
    run_cmd(
        cargo(flavor)
            .args(["build", "--locked", "--release", "-p", "aspis-kernel"])
            .args(["--target", "aarch64-unknown-none"])
            .env("ASPIS_ATLAS_DIR", &atlas),
    );
    let kernel = flavor
        .target_dir()
        .join("aarch64-unknown-none/release/aspis-kernel");
    fs::copy(&kernel, out.join("kernel.elf")).unwrap();

    // 2. The initial image, and its digest (ADR 0040, rule 1).
    let img = initfs(&out);
    let digest = initfs::image_digest(&img);
    fs::write(out.join("initfs.sha512"), digest).unwrap();

    // 3. The stub, which embeds both, then signing (not yet: C64).
    run_cmd(
        cargo(flavor)
            .args(["build", "--locked", "--release", "-p", "aspis-stub"])
            .args(["--target", "aarch64-unknown-uefi"])
            .env("ASPIS_KERNEL_ELF", out.join("kernel.elf"))
            .env("ASPIS_INITFS_DIGEST", out.join("initfs.sha512")),
    );
    let stub = flavor
        .target_dir()
        .join("aarch64-unknown-uefi/release/aspis-stub.efi");
    fs::copy(&stub, out.join("aspis.efi")).unwrap();
    eprintln!(
        "xtask: built {} aspis.efi ({} KiB) and initfs.img ({} KiB) in {}",
        flavor.name(),
        fs::metadata(out.join("aspis.efi")).unwrap().len() / 1024,
        img.len() / 1024,
        out.display()
    );
    out
}

/// GRUB 2.14 arm64-efi, built in Docker (ADR 0036, rule 1).
/// `ASPIS_GRUB_EFI` names a `BOOTAA64.EFI` built elsewhere, as CI does.
pub fn grub() -> PathBuf {
    if let Ok(path) = env::var("ASPIS_GRUB_EFI") {
        return PathBuf::from(path);
    }
    let out = build_dir().join("grub/BOOTAA64.EFI");
    if out.exists() {
        return out;
    }
    fs::create_dir_all(out.parent().unwrap()).unwrap();
    run_cmd(
        Command::new("docker")
            .args(["build", "-t", "aspis-grub:2.14"])
            .arg(root().join("tools/grub")),
    );
    let id = Command::new("docker")
        .args(["create", "aspis-grub:2.14"])
        .output()
        .unwrap_or_else(|e| fail(format!("docker: {e}")));
    let id = String::from_utf8(id.stdout).unwrap().trim().to_string();
    run_cmd(
        Command::new("docker")
            .args(["cp", &format!("{id}:/BOOTAA64.EFI")])
            .arg(&out),
    );
    run_cmd(Command::new("docker").args(["rm", &id]));
    out
}

/// Fails if a production image holds test-only code (ADR 0036, rule 8):
/// the test-build marker, or a semihosting call (`hlt #0xf000`).
fn check_production() {
    let out = Flavor::Production.out();
    let marker = b"ASPIS-TEST-BUILD";
    let hlt_f000 = 0xd45e_0000u32.to_le_bytes();
    for name in ["aspis.efi", "kernel.elf", "initfs.img"] {
        let bytes = fs::read(out.join(name)).unwrap();
        if bytes.windows(marker.len()).any(|w| w == marker) {
            fail(format!("{name} holds the test-build marker"));
        }
        if bytes.as_chunks::<4>().0.contains(&hlt_f000) {
            fail(format!("{name} holds a semihosting call"));
        }
    }
    eprintln!("xtask: production images hold no test code");
}

fn test() {
    // The grammars and their vectors, with the Rust checker (ADR 0062,
    // rule 8), then the interfaces, their locks and generated files (ADR
    // 0067, rules 7 and 9).
    grammars::check();
    idl::check(false);
    // Host tests for the crates that build on the host.
    run_cmd(
        Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .current_dir(root())
            .args(["test", "--locked", "--quiet"])
            .args([
                "-p",
                "bootinfo",
                "-p",
                "kargs",
                "-p",
                "kmem",
                "-p",
                "kcap",
                "-p",
                "initfs",
                "-p",
                "glyph-atlas",
                "-p",
                "atlas",
                "-p",
                "logo",
                "-p",
                "abnf",
                "-p",
                "idl-rt",
                "-p",
                "idl",
                "-p",
                "idlc",
                "-p",
                "aspis-interfaces",
                "-p",
                "idl-fixtures",
            ]),
    );
    // Owned values (ADR 0067, rule 10), a library feature of the
    // generated crates.
    run_cmd(
        Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
            .current_dir(root())
            .args(["test", "--locked", "--quiet", "-p", "aspis-interfaces"])
            .args(["--features", "alloc"]),
    );
    build(Flavor::Production);
    check_production();
    build(Flavor::Test);

    let mut failed = Vec::new();
    for config in ["a72-v2", "max-v3"] {
        // The in-QEMU tests: they end QEMU through semihosting.
        let opts = qemu::Options {
            flavor: Flavor::Test,
            config: config.into(),
            expect: None,
            ..qemu::Options::default()
        };
        eprintln!("xtask: in-QEMU tests on {config}");
        if qemu::run(&opts) != 0 {
            failed.push(format!("in-QEMU tests on {config}"));
        }
        // A production boot through GRUB reaches the kernel's idle line.
        let opts = qemu::Options {
            flavor: Flavor::Production,
            config: config.into(),
            expect: Some("M1 ends here".into()),
            screenshot: Some(build_dir().join(format!("screen-{config}.png"))),
            ..qemu::Options::default()
        };
        eprintln!("xtask: production boot through GRUB on {config}");
        if qemu::run(&opts) != 0 {
            failed.push(format!("production boot on {config}"));
        }
    }
    // A quoted value in a GRUB menu entry reaches the kernel intact
    // (ADR 0041, rule 5): GRUB rewrites it, and the stub undoes that.
    let opts = qemu::Options {
        flavor: Flavor::Production,
        config: "a72-v2".into(),
        args: "root.name=\"two words\" log.level=debug".into(),
        expect: Some("root.name is for the root server".into()),
        reject: Some("error at byte".into()),
        ..qemu::Options::default()
    };
    eprintln!("xtask: quoted kernel arguments through GRUB");
    if qemu::run(&opts) != 0 {
        failed.push("quoted kernel arguments".into());
    }
    // A forced panic reaches the UART and the framebuffer (M1's outcome).
    let opts = qemu::Options {
        flavor: Flavor::Test,
        config: "a72-v2".into(),
        args: "test.panic".into(),
        expect: Some("KERNEL PANIC".into()),
        screenshot: Some(build_dir().join("screen-panic.png")),
        ..qemu::Options::default()
    };
    eprintln!("xtask: forced panic");
    if qemu::run(&opts) != 0 {
        failed.push("forced panic".into());
    }
    if failed.is_empty() {
        eprintln!("xtask: all tests passed");
    } else {
        fail(format!("failed: {}", failed.join(", ")));
    }
}

/// The nightly matrix (ADR 0036, rule 4): each CPU with each GIC, at 1, 4
/// and 8 cores and 1 and 3 GiB, running the in-QEMU tests; then one run
/// with the firmware at EL2, which tests the stub's path from EL2 to EL1.
fn matrix() {
    build(Flavor::Test);
    let mut runs = Vec::new();
    for config in ["a72-v2", "a72-v3", "max-v2", "max-v3"] {
        for smp in [1, 4, 8] {
            for memory in ["1G", "3G"] {
                runs.push(qemu::Options {
                    flavor: Flavor::Test,
                    config: config.into(),
                    smp,
                    memory: memory.into(),
                    timeout: 300,
                    ..qemu::Options::default()
                });
            }
        }
    }
    runs.push(qemu::Options {
        flavor: Flavor::Test,
        config: "max-v3".into(),
        virtualization: true,
        timeout: 300,
        ..qemu::Options::default()
    });
    let mut failed = Vec::new();
    for (i, o) in runs.iter().enumerate() {
        let name = format!(
            "{}, {} cores, {}{}",
            o.config,
            o.smp,
            o.memory,
            if o.virtualization { ", EL2" } else { "" }
        );
        eprintln!("xtask: matrix {}/{}: {name}", i + 1, runs.len());
        if qemu::run(o) != 0 {
            failed.push(name);
        }
    }
    if failed.is_empty() {
        eprintln!("xtask: all {} matrix runs passed", runs.len());
    } else {
        fail(format!("matrix runs failed: {}", failed.join("; ")));
    }
}

/// rustfmt and clippy over every crate, each for the target it builds for.
fn lint() {
    let cargo = || {
        let mut c = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        c.current_dir(root());
        c
    };
    run_cmd(cargo().args(["fmt", "--all", "--check"]));
    run_cmd(cargo().args(["clippy", "--locked", "--all-targets"]).args([
        "-p",
        "bootinfo",
        "-p",
        "kargs",
        "-p",
        "kmem",
        "-p",
        "kcap",
        "-p",
        "initfs",
        "-p",
        "glyph-atlas",
        "-p",
        "atlas",
        "-p",
        "logo",
        "-p",
        "abnf",
        "-p",
        "idl-rt",
        "-p",
        "idl",
        "-p",
        "idlc",
        "-p",
        "aspis-interfaces",
        "-p",
        "idl-fixtures",
        "-p",
        "xtask",
        "--",
        "-D",
        "warnings",
    ]));
    run_cmd(
        cargo()
            .args(["clippy", "--locked", "--all-targets"])
            .args([
                "-p",
                "idl-rt",
                "-p",
                "aspis-interfaces",
                "-p",
                "idl-fixtures",
            ])
            .args([
                "--features",
                "idl-rt/alloc,aspis-interfaces/alloc,idl-fixtures/alloc",
            ])
            .args(["--", "-D", "warnings"]),
    );
    // The crates the catalog and generated bindings run are no_std (ADR
    // 0067, rule 11): build them for a target without std, so a dependency
    // that pulls std in fails here, not later.
    run_cmd(
        cargo()
            .args(["build", "--locked", "--target", "aarch64-unknown-none"])
            .args(["-p", "abnf", "-p", "idl-rt", "-p", "idl"])
            .args([
                "-p",
                "aspis-interfaces",
                "--features",
                "aspis-interfaces/alloc",
            ])
            .env("CARGO_TARGET_DIR", build_dir().join("target-nostd")),
    );
    run_cmd(
        cargo()
            .args(["build", "--locked", "--target", "aarch64-unknown-none"])
            .args(["-p", "idl-rt", "-p", "aspis-interfaces"])
            .env("CARGO_TARGET_DIR", build_dir().join("target-nostd")),
    );
    // The kernel and the stub need the build's inputs: lint against them.
    let out = build(Flavor::Production);
    let atlas = build_dir().join("atlas");
    for flavor in [Flavor::Production, Flavor::Test] {
        run_cmd(
            cargo()
                .args([
                    "clippy",
                    "--locked",
                    "-p",
                    "aspis-kernel",
                    "--target",
                    "aarch64-unknown-none",
                ])
                .args(["--", "-D", "warnings"])
                .env("ASPIS_ATLAS_DIR", &atlas)
                .env(
                    "CARGO_TARGET_DIR",
                    build_dir().join(format!("target-clippy-{}", flavor.name())),
                )
                .env(
                    "CARGO_TARGET_AARCH64_UNKNOWN_NONE_RUSTFLAGS",
                    rustflags(flavor, true),
                ),
        );
    }
    run_cmd(
        cargo()
            .args([
                "clippy",
                "--locked",
                "-p",
                "aspis-stub",
                "--target",
                "aarch64-unknown-uefi",
            ])
            .args(["--", "-D", "warnings"])
            .env("ASPIS_KERNEL_ELF", out.join("kernel.elf"))
            .env("ASPIS_INITFS_DIGEST", out.join("initfs.sha512"))
            .env(
                "CARGO_TARGET_DIR",
                build_dir().join("target-clippy-production"),
            ),
    );
    eprintln!("xtask: lint clean");
}
