// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Running ASPIS on QEMU `virt` with EDK2 (ADR 0007, rule 1; ADR 0036).

use crate::{Flavor, build_dir, esp, fail};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct Options {
    pub flavor: Flavor,
    pub direct: bool,
    pub config: String,
    pub args: String,
    pub expect: Option<String>,
    /// Fail at once if the UART shows this text.
    pub reject: Option<String>,
    pub screenshot: Option<PathBuf>,
    pub timeout: u64,
    /// Cores, memory, and whether the firmware runs at EL2 (ADR 0036, rule 4).
    pub smp: u32,
    pub memory: String,
    pub virtualization: bool,
    /// A video mode for GRUB to set, such as `1024x768`. QEMU's ramfb
    /// under EDK2 offers 640x480, 800x600 (the default) and 1024x768.
    pub resolution: Option<String>,
    /// Show the screen in a window, not only through `--screenshot`.
    pub window: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            flavor: Flavor::Production,
            direct: false,
            config: "a72-v2".into(),
            args: String::new(),
            expect: None,
            reject: None,
            screenshot: None,
            timeout: 120,
            smp: 4,
            memory: "1G".into(),
            virtualization: false,
            resolution: None,
            window: false,
        }
    }
}

impl Options {
    pub fn parse(args: &[String]) -> Self {
        let mut o = Self::default();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let mut value = || {
                it.next()
                    .cloned()
                    .unwrap_or_else(|| fail(format!("{a} needs a value")))
            };
            match a.as_str() {
                "--test-build" => o.flavor = Flavor::Test,
                "--direct" => o.direct = true,
                "--config" => o.config = value(),
                "--args" => o.args = value(),
                "--expect" => o.expect = Some(value()),
                "--screenshot" => o.screenshot = Some(PathBuf::from(value())),
                "--smp" => o.smp = value().parse().unwrap_or_else(|_| fail("bad --smp")),
                "--memory" => o.memory = value(),
                "--virtualization" => o.virtualization = true,
                "--resolution" => {
                    let r = value();
                    let ok = r.split_once('x').is_some_and(|(w, h)| {
                        w.parse::<u32>().is_ok_and(|w| w > 0)
                            && h.parse::<u32>().is_ok_and(|h| h > 0)
                    });
                    if !ok {
                        fail(format!(
                            "bad --resolution {r}; use <width>x<height>, such as 1024x768"
                        ));
                    }
                    o.resolution = Some(r);
                }
                "--window" => o.window = true,
                "--timeout" => {
                    o.timeout = value().parse().unwrap_or_else(|_| fail("bad --timeout"))
                }
                other => fail(format!("unknown option {other}")),
            }
        }
        o
    }
}

/// A configuration is a CPU and a GIC version: `a72-v2` and `max-v3` run
/// on every change (ADR 0036, rule 3), and `a72-v3` and `max-v2` join them
/// nightly (rule 4).
fn machine(config: &str) -> (&'static str, &'static str) {
    let (cpu, gic) = config.split_once("-v").unwrap_or(("", ""));
    let cpu = match cpu {
        "a72" => "cortex-a72",
        "max" => "max",
        _ => fail(format!(
            "unknown configuration {config}; use a72-v2, a72-v3, max-v2 or max-v3"
        )),
    };
    let gic = match gic {
        "2" => "2",
        "3" => "3",
        _ => fail(format!("unknown GIC version in {config}")),
    };
    (cpu, gic)
}

/// QEMU's bundled EDK2 firmware (ADR 0036, rule 1).
fn firmware_dir() -> PathBuf {
    let qemu = Command::new("sh")
        .args(["-c", "command -v qemu-system-aarch64"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| p.exists())
        .unwrap_or_else(|| fail("qemu-system-aarch64 not found"));
    let real = fs::canonicalize(&qemu).unwrap_or(qemu);
    let share = real.parent().unwrap().parent().unwrap().join("share/qemu");
    if !share.join("edk2-aarch64-code.fd").exists() {
        fail(format!("no edk2-aarch64-code.fd in {}", share.display()));
    }
    share
}

/// Boots and returns an exit status: QEMU's own for a run without
/// `--expect` (a test build ends it through semihosting), or 0 once the
/// expected text appears.
pub fn run(o: &Options) -> i32 {
    let images = o.flavor.out();
    let work = build_dir().join(format!(
        "run-{}-{}-{}c-{}{}",
        o.flavor.name(),
        o.config,
        o.smp,
        o.memory,
        if o.virtualization { "-el2" } else { "" }
    ));
    fs::create_dir_all(&work).unwrap();
    let esp_img = work.join("esp.img");
    if o.direct {
        if !o.args.is_empty() {
            fail("--direct boots without GRUB, so it can't pass --args");
        }
        if o.resolution.is_some() {
            fail("--direct boots without GRUB, so it can't set --resolution");
        }
        esp::direct(&esp_img, &images);
    } else {
        let grub = crate::grub();
        esp::grub(&esp_img, &images, &grub, &o.args, o.resolution.as_deref());
    }
    let fw = firmware_dir();
    let vars = work.join("vars.fd");
    fs::copy(fw.join("edk2-arm-vars.fd"), &vars).unwrap();
    let qmp = work.join("qmp.sock");
    let _ = fs::remove_file(&qmp);

    let (cpu, gic) = machine(&o.config);
    let mut cmd = Command::new("qemu-system-aarch64");
    cmd.args([
        "-machine",
        &format!(
            "virt,gic-version={gic},iommu=smmuv3,acpi=off,virtualization={}",
            if o.virtualization { "on" } else { "off" }
        ),
    ])
    .args(["-cpu", cpu])
    .args(["-smp", &o.smp.to_string(), "-m", &o.memory])
    .arg("-drive")
    .arg(format!(
        "if=pflash,format=raw,unit=0,readonly=on,file={}",
        fw.join("edk2-aarch64-code.fd").display()
    ))
    .arg("-drive")
    .arg(format!(
        "if=pflash,format=raw,unit=1,file={}",
        vars.display()
    ))
    .arg("-drive")
    .arg(format!(
        "if=none,id=esp,format=raw,file={}",
        esp_img.display()
    ))
    .args(["-device", "virtio-blk-pci,drive=esp,bootindex=0"])
    .args(["-device", "ramfb"])
    .args(["-device", "virtio-rng-pci"])
    .args(["-netdev", "user,id=net0"])
    .args(["-device", "virtio-net-pci,netdev=net0,romfile="])
    .args([
        "-nodefaults",
        "-display",
        // `default` takes no options; Cocoa and GTK both scale the screen
        // to the window.
        if o.window && cfg!(target_os = "macos") {
            "cocoa,zoom-to-fit=on"
        } else if o.window {
            "gtk,zoom-to-fit=on"
        } else {
            "none"
        },
    ])
    .args([
        "-chardev",
        "stdio,id=uart,signal=off",
        "-serial",
        "chardev:uart",
    ])
    // QEMU runs in the run directory, and the socket's path is relative to
    // it: a UNIX socket's path is limited to 104 octets on macOS, and a
    // checkout's own path can be longer than that.
    .arg("-qmp")
    .arg("unix:qmp.sock,server=on,wait=off")
    .current_dir(&work);
    if o.flavor == Flavor::Test {
        cmd.args(["-semihosting-config", "enable=on,target=native"]);
    }
    // Extra QEMU arguments for debugging, such as `-d int -D <file>`.
    if let Ok(extra) = std::env::var("ASPIS_QEMU_EXTRA") {
        cmd.args(extra.split_whitespace());
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = cmd
        .spawn()
        .unwrap_or_else(|e| fail(format!("qemu-system-aarch64: {e}")));

    // Copy the UART to our output, watching for the expected text.
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel::<String>();
    let reader = thread::spawn(move || {
        let mut r = BufReader::new(stdout);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match r.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let line = String::from_utf8_lossy(&buf).into_owned();
                    print!("{line}");
                    let _ = std::io::stdout().flush();
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let deadline = Instant::now() + Duration::from_secs(o.timeout);
    let mut seen = String::new();
    let status = loop {
        if let Some(code) = child.try_wait().unwrap() {
            break code.code().unwrap_or(-1);
        }
        while let Ok(line) = rx.try_recv() {
            seen.push_str(&line);
        }
        if let Some(r) = &o.reject
            && seen.contains(r.as_str())
        {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("xtask: saw \"{r}\", which fails the run");
            break 1;
        }
        if let Some(e) = &o.expect
            && seen.contains(e.as_str())
        {
            // Let the console finish drawing before the screenshot.
            thread::sleep(Duration::from_millis(500));
            if let Some(shot) = &o.screenshot {
                match screendump(&qmp, shot) {
                    Ok(()) => eprintln!("xtask: screenshot in {}", shot.display()),
                    Err(err) => eprintln!("xtask: screenshot failed: {err}"),
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("xtask: saw \"{e}\"");
            break 0;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("xtask: timed out after {} s", o.timeout);
            break 124;
        }
        thread::sleep(Duration::from_millis(50));
    };
    let _ = reader.join();
    if o.expect.is_none() {
        eprintln!("xtask: QEMU exited with status {status}");
    }
    status
}

/// Saves the screen as a PNG through QMP.
fn screendump(sock: &Path, out: &Path) -> Result<(), String> {
    if let Some(dir) = out.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    // Connect by the socket's name from its directory, as QEMU made it,
    // so a long checkout path never reaches the 104-octet limit.
    let back = std::env::current_dir().map_err(|e| e.to_string())?;
    std::env::set_current_dir(sock.parent().unwrap()).map_err(|e| e.to_string())?;
    let s = UnixStream::connect(sock.file_name().unwrap());
    std::env::set_current_dir(back).map_err(|e| e.to_string())?;
    let mut s = s.map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut r = BufReader::new(s.try_clone().map_err(|e| e.to_string())?);
    let mut line = String::new();
    r.read_line(&mut line).map_err(|e| e.to_string())?; // greeting
    let out = fs::canonicalize(out.parent().unwrap())
        .map_err(|e| e.to_string())?
        .join(out.file_name().unwrap());
    let path = out
        .display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    for msg in [
        "{\"execute\":\"qmp_capabilities\"}".to_string(),
        format!(
            "{{\"execute\":\"screendump\",\"arguments\":{{\"filename\":\"{path}\",\"format\":\"png\"}}}}"
        ),
    ] {
        s.write_all(msg.as_bytes()).map_err(|e| e.to_string())?;
        s.write_all(b"\n").map_err(|e| e.to_string())?;
        loop {
            line.clear();
            r.read_line(&mut line).map_err(|e| e.to_string())?;
            if line.contains("\"return\"") {
                break;
            }
            if line.contains("\"error\"") {
                return Err(line.trim().to_string());
            }
        }
    }
    let mut check = [0u8; 4];
    fs::File::open(&out)
        .and_then(|mut f| f.read_exact(&mut check))
        .map_err(|e| e.to_string())?;
    Ok(())
}
