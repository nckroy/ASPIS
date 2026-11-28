// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! `cargo xtask`: builds ASPIS's images, assembles the ESP and runs QEMU.
//!
//! ```text
//! cargo xtask build [--test-build]          aspis.efi and initfs.img
//! cargo xtask run [options]                 boot in QEMU
//! cargo xtask test [--host]                 host tests, then QEMU tests
//!                                           (--host: the grammars, the
//!                                           interfaces and the host
//!                                           crates' tests only)
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
//! cargo xtask tlc [--nightly]               the TLA+ specs in specs/, with
//!                                           TLC, and trace validation of
//!                                           ksched's donation and kipc's
//!                                           endpoints and eventcounts
//!                                           (nightly: the nightly models
//!                                           too)
//! cargo xtask grub                          GRUB 2.14 arm64-efi, in Docker
//! cargo xtask fuzz <command>                the fuzz targets (fuzz/README.md)
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
mod fuzz;
mod fuzz_dict;
mod grammars;
mod idl;
mod qemu;
mod tlc;

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
            "usage: cargo xtask build|run|test|check-production|matrix|lint|grammars|idl|fuzz-dict|fuzz|tlc|grub [options]"
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
        "test" => test(rest.iter().any(|a| a == "--host")),
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
        "fuzz" => fuzz::run(rest),
        "tlc" => tlc::check(rest.iter().any(|a| a == "--nightly")),
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
    // With the rust-src component installed, rustc writes the standard
    // library's paths as the local sysroot's, not as `/rustc/<commit>`.
    // Map them back, so an image is the same with or without rust-src.
    if let Some(m) = sysroot_src_remap() {
        f.push(m);
    }
    if pie {
        f.push("-Crelocation-model=pie".into());
    }
    if flavor == Flavor::Test {
        f.push("--cfg=aspis_test_build".into());
    }
    f.join(" ")
}

/// `--remap-path-prefix=<sysroot>/lib/rustlib/src/rust=/rustc/<commit>`,
/// for the pinned toolchain, or `None` if rustc can't say.
fn sysroot_src_remap() -> Option<String> {
    let rustc = || {
        let mut c = Command::new(env::var("RUSTC").unwrap_or_else(|_| "rustc".into()));
        c.current_dir(root());
        c
    };
    let out = |c: &mut Command| {
        c.output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
    };
    let sysroot = out(rustc().args(["--print", "sysroot"]))?;
    let commit = out(rustc().arg("-vV"))?
        .lines()
        .find_map(|l| l.strip_prefix("commit-hash: ").map(str::to_string))?;
    Some(format!(
        "--remap-path-prefix={}/lib/rustlib/src/rust=/rustc/{}",
        sysroot.trim(),
        commit.trim()
    ))
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
/// the test-build marker, the test trap's or the EL0 test programs' markers,
/// the test trap's `svc #0x7e57`, or a semihosting call (`hlt #0xf000`).
/// The test build's marker, the test trap's (C12) and the EL0 test
/// programs' (C12): production images hold none of them.
const TEST_MARKERS: [&[u8]; 3] = [
    b"ASPIS-TEST-BUILD",
    b"ASPIS-TEST-TRAP!",
    b"ASPIS-USER-TESTS",
];

/// `svc #0x7e57`, the test trap's instruction (C12), as the images hold it:
/// little-endian, at a 4-byte-aligned offset.
fn svc_trap() -> [u8; 4] {
    (0xd400_0001u32 | 0x7e57 << 5).to_le_bytes()
}

/// Checks that the test images hold what [`check_production`] looks for,
/// so a change in the images' format can't make that check pass unseen.
fn check_test_markers() {
    let out = Flavor::Test.out();
    for name in ["aspis.efi", "kernel.elf"] {
        let bytes = fs::read(out.join(name)).unwrap();
        for marker in TEST_MARKERS {
            if !bytes.windows(marker.len()).any(|w| w == marker) {
                fail(format!(
                    "the test {name} lacks the test marker {}: check-production can't see it",
                    String::from_utf8_lossy(marker)
                ));
            }
        }
        if !bytes.as_chunks::<4>().0.contains(&svc_trap()) {
            fail(format!(
                "the test {name} lacks the test trap's svc: check-production can't see it"
            ));
        }
    }
}

fn check_production() {
    let out = Flavor::Production.out();
    let markers = TEST_MARKERS;
    let hlt_f000 = 0xd45e_0000u32.to_le_bytes();
    let svc_trap = svc_trap();
    for name in ["aspis.efi", "kernel.elf", "initfs.img"] {
        let bytes = fs::read(out.join(name)).unwrap();
        for marker in markers {
            if bytes.windows(marker.len()).any(|w| w == marker) {
                fail(format!(
                    "{name} holds the test marker {}",
                    String::from_utf8_lossy(marker)
                ));
            }
        }
        if bytes.as_chunks::<4>().0.contains(&hlt_f000) {
            fail(format!("{name} holds a semihosting call"));
        }
        if bytes.as_chunks::<4>().0.contains(&svc_trap) {
            fail(format!("{name} holds the test trap's svc"));
        }
    }
    eprintln!("xtask: production images hold no test code");
}

/// The cfgs that make RustCrypto's and dalek's crates use their portable
/// software backends. `aarch64-unknown-none` can't detect CPU features at
/// run time, so there SHA-2, SHA-3, AES and POLYVAL run in software, while
/// a host detects the CPU's instructions and uses them. (On aarch64,
/// ChaCha20 takes NEON at compile time; forcing its software backend too
/// covers the rest of its code.) curve25519-dalek is forced to `serial`,
/// the backend `aarch64-unknown-none` uses, so an x86_64 host doesn't run
/// its AVX2 backend instead.
const CRYPTO_SOFT_BACKENDS: &str = "--cfg sha2_backend=\"soft\" --cfg keccak_backend=\"soft\" \
     --cfg aes_backend=\"soft\" --cfg polyval_backend=\"soft\" \
     --cfg chacha20_backend=\"soft\" --cfg poly1305_backend=\"soft\" \
     --cfg curve25519_dalek_backend=\"serial\"";

/// aspis-crypto's host tests beyond the default run (ADR 0069, rule 7):
/// with `alloc`, which changes how the lattice key state is stored, and
/// with the software backends forced, which the known answers otherwise
/// never reach on a host that has the CPU features. Both add the opt-in
/// `quic` feature, so AES-128-GCM's and QUIC's vectors run too; the
/// default run checks the crate without it.
fn crypto_tests() {
    let cargo = || {
        let mut c = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
        c.current_dir(root());
        c
    };
    run_cmd(
        cargo()
            .args(["test", "--locked", "--quiet", "-p", "aspis-crypto"])
            .args(["--features", "alloc,quic"]),
    );
    eprintln!("xtask: aspis-crypto with the software backends");
    run_cmd(
        cargo()
            .args(["test", "--locked", "--quiet", "-p", "aspis-crypto"])
            .args(["--features", "quic"])
            .env("RUSTFLAGS", CRYPTO_SOFT_BACKENDS)
            .env("CARGO_TARGET_DIR", build_dir().join("target-crypto-soft")),
    );
}

fn test(host_only: bool) {
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
                "kirq",
                "-p",
                "ksched",
                "-p",
                "kipc",
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
                "aspis-crypto",
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
    crypto_tests();
    // The fuzz targets' seeds and regressions, through their entry
    // functions without libFuzzer, and the harness's own tests (ADR 0068,
    // rule 7). Neither crate depends on libFuzzer, so this builds no C++.
    run_cmd(
        fuzz::cargo()
            .args([
                "test",
                "--locked",
                "--quiet",
                "--manifest-path",
                fuzz::MANIFEST,
            ])
            .args(["-p", "fuzz-gate", "-p", "fuzz-alloc", "--target-dir"])
            .arg(fuzz::host_target_dir()),
    );
    if host_only {
        eprintln!("xtask: host tests passed");
        return;
    }
    build(Flavor::Production);
    check_production();
    build(Flavor::Test);
    check_test_markers();

    let mut failed = Vec::new();
    for config in ["a72-v2", "max-v3"] {
        // The in-QEMU tests: they end QEMU through semihosting.
        // Five minutes, as the matrix allows: C12's tests run threads on
        // every core under TCG, beside whatever else the host runs.
        let opts = qemu::Options {
            flavor: Flavor::Test,
            config: config.into(),
            expect: None,
            timeout: 300,
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
    // A forced panic reaches the UART and the framebuffer (M1's outcome),
    // and stops every other core, each of which waits for the kernel lock
    // the panicking core holds (ADR 0052, rule 4; kernel
    // specification, "Cross-core signals and TLB maintenance"). The
    // count is the report's last line, after "KERNEL PANIC".
    let opts = qemu::Options {
        flavor: Flavor::Test,
        config: "a72-v2".into(),
        args: "test.panic".into(),
        expect: Some("stopped 3 of 3 other cores".into()),
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

/// aspis-crypto's default families, each a cargo feature (ADR 0069, rule
/// 2). They are its default features, and [`check_crypto_families`] fails
/// lint if the two lists differ.
const CRYPTO_FAMILIES: &[&str] = &[
    "sha3",
    "sha2",
    "aead",
    "x25519",
    "ed25519",
    "ml-kem",
    "ml-dsa",
    "composite",
    "hybrid",
];

/// aspis-crypto's opt-in families, which no default includes: `quic`, the
/// only way to reach AES-128 (ADR 0069, rule 2). Lint checks each alone,
/// as it does the default ones.
const CRYPTO_OPT_IN: &[&str] = &["quic"];

/// The crates that would bring std or a source of randomness into
/// aspis-crypto (ADR 0069, rule 1). `rand_core`, which holds only traits,
/// is allowed. The tree is taken for `aarch64-unknown-none`, so `libc`,
/// `wasi` and `windows-sys` match only if a crate depends on them
/// unconditionally: on a host, `cpufeatures` takes `libc` legitimately.
const CRYPTO_FORBIDDEN: &[&str] = &[
    "getrandom",
    "rand",
    "rand_chacha",
    "rand_hc",
    "rand_os",
    "libc",
    "wasi",
    "windows-sys",
];

/// Fails if [`CRYPTO_FAMILIES`] isn't aspis-crypto's `default` feature list,
/// in crates/crypto/Cargo.toml, or if a feature other than `default` and
/// `alloc` is in neither it nor [`CRYPTO_OPT_IN`], so no family skips the
/// per-family lint. An opt-in family in `default` fails too.
fn check_crypto_families() {
    let manifest = fs::read_to_string(root().join("crates/crypto/Cargo.toml"))
        .unwrap_or_else(|e| fail(format!("crates/crypto/Cargo.toml: {e}")));
    let features: Vec<&str> = manifest
        .lines()
        .skip_while(|l| l.trim() != "[features]")
        .skip(1)
        .take_while(|l| !l.trim_start().starts_with('['))
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| l.split_once('=').map(|(name, _)| name.trim()))
        .collect();
    for feature in &features {
        let known = ["default", "alloc"].contains(feature)
            || CRYPTO_FAMILIES.contains(feature)
            || CRYPTO_OPT_IN.contains(feature);
        if !known {
            fail(format!(
                "aspis-crypto's feature {feature:?} is in neither xtask's CRYPTO_FAMILIES nor CRYPTO_OPT_IN"
            ));
        }
    }
    for family in CRYPTO_OPT_IN {
        if !features.contains(family) {
            fail(format!(
                "aspis-crypto has no feature {family:?}, which xtask's CRYPTO_OPT_IN names"
            ));
        }
    }
    let default = manifest
        .lines()
        .find_map(|l| l.trim().strip_prefix("default = ["))
        .and_then(|l| l.strip_suffix(']'))
        .unwrap_or_else(|| fail("crates/crypto/Cargo.toml has no one-line default feature list"));
    let listed: Vec<&str> = default
        .split(',')
        .map(|f| f.trim().trim_matches('"'))
        .filter(|f| !f.is_empty())
        .collect();
    if listed != CRYPTO_FAMILIES {
        fail(format!(
            "aspis-crypto's default features {listed:?} differ from xtask's CRYPTO_FAMILIES {CRYPTO_FAMILIES:?}"
        ));
    }
}

/// The manifests allowed to turn on aspis-crypto's `quic` feature, and so
/// reach AES-128 (ADR 0003, rule 4; ADR 0069, rule 2). None does yet: C29's
/// QUIC is the first that should, and the fuzz workspace's manifests join
/// when C71 wraps aspis-crypto's fuzz entry points (rule 8).
const CRYPTO_QUIC_USERS: &[&str] = &[];

/// Fails if a manifest outside [`CRYPTO_QUIC_USERS`] turns on aspis-crypto's
/// `quic` feature. Cargo merges features across a build, so naming `quic`
/// anywhere can bring AES-128 to every crate built beside it.
///
/// The check reads each manifest as text, so it errs on the side of
/// failing: a manifest fails if it forwards `aspis-crypto/quic` (or
/// `aspis-crypto?/quic`), or if it names aspis-crypto at all and has a
/// `"quic"` string outside a comment. A manifest that fails only because
/// another crate has a `quic` feature belongs to QUIC code anyway, and
/// goes on the list.
fn check_crypto_quic_users() {
    let manifests = grammars::tracked(&["*Cargo.toml"]);
    for path in manifests
        .iter()
        .filter(|p| Path::new(p).file_name().is_some_and(|n| n == "Cargo.toml"))
        .filter(|p| *p != "crates/crypto/Cargo.toml")
        .filter(|p| !CRYPTO_QUIC_USERS.contains(&p.as_str()))
    {
        let text =
            fs::read_to_string(root().join(path)).unwrap_or_else(|e| fail(format!("{path}: {e}")));
        let lines: Vec<&str> = text
            .lines()
            .map(|l| l.split_once('#').map_or(l, |(code, _)| code))
            .collect();
        let forwards = lines
            .iter()
            .any(|l| l.contains("aspis-crypto/quic") || l.contains("aspis-crypto?/quic"));
        let names_crypto = lines.iter().any(|l| l.contains("aspis-crypto"));
        let names_quic = lines.iter().any(|l| l.contains("\"quic\""));
        if forwards || (names_crypto && names_quic) {
            fail(format!(
                "{path} may turn on aspis-crypto's `quic` feature, which reaches AES-128; \
                 only the manifests in xtask's CRYPTO_QUIC_USERS may (ADR 0069, rule 2)"
            ));
        }
    }
}

/// Fails if aspis-crypto's tree, with every feature, for the target
/// without std, holds a crate of [`CRYPTO_FORBIDDEN`] (ADR 0069, rule 1).
fn crypto_dependencies() {
    let out = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .current_dir(root())
        .args(["tree", "--locked", "-p", "aspis-crypto", "--all-features"])
        .args(["--target", "aarch64-unknown-none", "-e", "normal"])
        .args(["--prefix", "none"])
        .output()
        .unwrap_or_else(|e| fail(format!("cargo tree: {e}")));
    if !out.status.success() {
        fail(format!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let tree = String::from_utf8_lossy(&out.stdout);
    let mut crates: Vec<&str> = tree
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|name| *name != "aspis-crypto")
        .collect();
    crates.sort_unstable();
    crates.dedup();
    let found: Vec<&str> = crates
        .iter()
        .copied()
        .filter(|name| CRYPTO_FORBIDDEN.contains(name))
        .collect();
    if !found.is_empty() {
        fail(format!(
            "aspis-crypto depends on {} (ADR 0069, rule 1)",
            found.join(", ")
        ));
    }
    eprintln!(
        "xtask: aspis-crypto's {} crates bring in no std or randomness",
        crates.len()
    );
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
        "kirq",
        "-p",
        "ksched",
        "-p",
        "kipc",
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
        "aspis-crypto",
        "-p",
        "xtask",
        "--",
        "-D",
        "warnings",
    ]));
    // Each crypto family alone, as a user such as the IDL compiler builds
    // it (ADR 0069, rule 2): every target still compiles, nothing is left
    // unused, and the family alone builds without std.
    check_crypto_families();
    check_crypto_quic_users();
    for family in CRYPTO_FAMILIES.iter().chain(CRYPTO_OPT_IN) {
        run_cmd(
            cargo()
                .args(["clippy", "--locked", "--all-targets", "-p", "aspis-crypto"])
                .args(["--no-default-features", "--features", family])
                .args(["--", "-D", "warnings"]),
        );
        run_cmd(
            cargo()
                .args(["check", "--locked", "--target", "aarch64-unknown-none"])
                .args(["-p", "aspis-crypto", "--no-default-features"])
                .args(["--features", family])
                .env("CARGO_TARGET_DIR", build_dir().join("target-nostd")),
        );
    }
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
                "-p",
                "aspis-crypto",
            ])
            .args([
                "--features",
                "idl-rt/alloc,aspis-interfaces/alloc,idl-fixtures/alloc,aspis-crypto/alloc,aspis-crypto/quic",
            ])
            .args(["--", "-D", "warnings"]),
    );
    // The crates the catalog and generated bindings run are no_std (ADR
    // 0067, rule 11), and so are ksched and kipc, the kernel's: build them
    // for a target without std, so a dependency that pulls std in fails
    // here, not later. So is aspis-crypto, with and without alloc (ADR 0069,
    // rule 2).
    run_cmd(
        cargo()
            .args(["build", "--locked", "--target", "aarch64-unknown-none"])
            .args(["-p", "abnf", "-p", "idl-rt", "-p", "idl", "-p", "ksched"])
            .args(["-p", "kipc", "-p", "aspis-interfaces", "-p", "aspis-crypto"])
            .args(["--features", "aspis-interfaces/alloc,aspis-crypto/alloc"])
            .env("CARGO_TARGET_DIR", build_dir().join("target-nostd")),
    );
    run_cmd(
        cargo()
            .args(["build", "--locked", "--target", "aarch64-unknown-none"])
            .args([
                "-p",
                "idl-rt",
                "-p",
                "aspis-interfaces",
                "-p",
                "aspis-crypto",
            ])
            .env("CARGO_TARGET_DIR", build_dir().join("target-nostd")),
    );
    // The fuzz workspace: the harness, the allocator and the targets.
    // Checking the targets builds libFuzzer's C++ once.
    run_cmd(fuzz::cargo().args(["fmt", "--all", "--check", "--manifest-path", fuzz::MANIFEST]));
    run_cmd(
        fuzz::cargo()
            .args(["clippy", "--locked", "--manifest-path", fuzz::MANIFEST])
            .args(["--workspace", "--all-targets", "--target-dir"])
            .arg(fuzz::host_target_dir())
            .args(["--", "-D", "warnings"]),
    );
    crypto_dependencies();
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
