// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The ASPIS boot stub: the UEFI program inside `aspis.efi`.
//!
//! It finds and checks the initial image, loads the kernel carried in its
//! `.kernel` section, collects what the kernel needs into the boot
//! information, exits boot services and enters the kernel at EL1
//! (ADR 0006, rule 4; ADRs 0035, 0039, 0040 and 0041). It calls no UEFI
//! runtime service afterwards (ADR 0039, rule 1).

#![no_std]
#![no_main]

extern crate alloc;

mod elf;
mod handoff;

use alloc::string::String;
use bootinfo::{
    Framebuffer, InitialImage, KernelPlacement, MemoryRange, MemoryType as Bi, Seed, Stub, Writer,
    initfs_check, kind, pixel_format, seed_source, start,
};
use core::fmt::Write as _;
use sha2::{Digest, Sha512};
use uefi::{
    CString16,
    boot::{self, AllocateType, MemoryType, OpenProtocolAttributes, OpenProtocolParams},
    mem::memory_map::MemoryMap,
    prelude::*,
    proto::{
        console::gop::{GraphicsOutput, PixelFormat},
        device_path::{
            DevicePath,
            text::{AllowShortcuts, DisplayOnly},
        },
        loaded_image::LoadedImage,
        media::{
            file::{File, FileAttribute, FileMode, RegularFile},
            load_file::LoadFile2,
        },
        rng::Rng,
    },
    table::cfg::ConfigTableEntry,
};

/// The stub's version: major in the high 16 bits.
const STUB_VERSION: u32 = 0x0000_0001;

/// The kernel's virtual base. It is fixed until C78 decides on
/// randomizing it (ADR 0035, rule 4), and equals the link base.
const KERNEL_VIRTUAL_BASE: u64 = 0xffff_8000_0000_0000;

/// OS-loader memory types, so the stub's allocations show in the final
/// memory map as what they are (ADR 0041, rule 3).
const MT_KERNEL: u32 = 0x8000_0001;
const MT_INITFS: u32 = 0x8000_0002;
const MT_BOOTINFO: u32 = 0x8000_0003;
const MT_SEED: u32 = 0x8000_0004;

/// `EFI_DTB_TABLE_GUID`.
const DTB_GUID: uefi::Guid = uefi::guid!("b1b621d5-f19c-41a5-830b-d9152c69aae0");

/// A vendor media device path for `LINUX_EFI_INITRD_MEDIA_GUID`
/// (5568e427-68fc-4f3d-ac74-ca555231cc68), then the end node. GRUB's
/// `linux` command installs `LoadFile2` on it.
const INITRD_MEDIA_PATH: [u8; 24] = [
    0x04, 0x03, 0x14, 0x00, 0x27, 0xe4, 0x68, 0x55, 0xfc, 0x68, 0x3d, 0x4f, 0xac, 0x74, 0xca, 0x55,
    0x52, 0x31, 0xcc, 0x68, 0x7f, 0xff, 0x04, 0x00,
];

const MAX_COMMAND_LINE: usize = 4096;

#[repr(C, align(4096))]
struct Aligned<const N: usize>([u8; N]);

/// The kernel's ELF, embedded by the build (ADR 0035, rule 3).
#[used]
#[unsafe(link_section = ".kernel")]
static KERNEL: Aligned<{ include_bytes!(concat!(env!("OUT_DIR"), "/kernel.elf")).len() }> =
    Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/kernel.elf")));

/// The initial image's SHA-512, embedded before signing (ADR 0040, rule 1).
#[used]
#[unsafe(link_section = ".initfs")]
static INITFS_DIGEST: [u8; 64] = *include_bytes!(concat!(env!("OUT_DIR"), "/initfs.sha512"));

/// Marks test builds, which CI checks production images never contain
/// (ADR 0036, rule 8).
#[cfg(aspis_test_build)]
#[used]
#[unsafe(link_section = ".tstmark")]
static TEST_BUILD_MARKER: [u8; 16] = *b"ASPIS-TEST-BUILD";

macro_rules! say {
    ($($t:tt)*) => {
        uefi::system::with_stdout(|out| { let _ = writeln!(out, $($t)*); })
    };
}

#[entry]
fn main() -> Status {
    match run() {
        Ok(never) => match never {},
        Err(why) => {
            say!("aspis stub: {why}. Not entering the kernel.");
            Status::LOAD_ERROR
        }
    }
}

/// A buffer of whole pages, zeroed, with an OS-loader memory type.
fn pages(memory_type: u32, bytes: usize, align: usize) -> Result<&'static mut [u8], &'static str> {
    let count = bytes.div_ceil(4096) + align.saturating_sub(4096) / 4096;
    let base = boot::allocate_pages(
        AllocateType::AnyPages,
        MemoryType::custom(memory_type),
        count.max(1),
    )
    .map_err(|_| "out of memory")?;
    let addr = base.as_ptr() as usize;
    let aligned = addr.next_multiple_of(align.max(4096));
    // SAFETY: the firmware gave us `count` pages at `base`, and `aligned`
    // plus `bytes` stays inside them.
    let buf = unsafe { core::slice::from_raw_parts_mut(aligned as *mut u8, bytes.max(1)) };
    buf.fill(0);
    Ok(buf)
}

fn run() -> Result<core::convert::Infallible, &'static str> {
    let el = handoff::current_el();
    say!(
        "aspis stub {}.{} at EL{el}",
        STUB_VERSION >> 16,
        STUB_VERSION & 0xffff
    );

    let command_line = command_line()?;

    // The initial image: GRUB's LoadFile2 first, then the `initfs` argument,
    // then our own directory (ADR 0041, rule 6).
    let (initfs, how) = match load_initfs_loadfile2() {
        Some(img) => (img, start::GRUB_LINUX),
        None => (
            load_initfs_file(&command_line)?,
            start::CHAINLOADER_OR_DIRECT,
        ),
    };
    let digest: [u8; 64] = Sha512::digest(&*initfs).into();
    let check = if digest == INITFS_DIGEST {
        initfs_check::MATCHED
    } else if cfg!(aspis_test_build) {
        say!("aspis stub: initfs.img doesn't match; a test build waives the check");
        initfs_check::WAIVED
    } else {
        // ADR 0040, rule 2: refuse, report, and return to the caller.
        return Err("initfs.img doesn't match the digest in aspis.efi");
    };

    // The kernel.
    let kernel = elf::Kernel::parse(&KERNEL.0).map_err(|e| {
        say!("aspis stub: kernel ELF: {e:?}");
        "the embedded kernel is not a valid ELF"
    })?;
    let kernel_mem = pages(MT_KERNEL, kernel.span as usize, 2 << 20)?;
    kernel.load(kernel_mem, KERNEL_VIRTUAL_BASE).map_err(|e| {
        say!("aspis stub: kernel ELF: {e:?}");
        "couldn't load and relocate the kernel"
    })?;
    let kernel_phys = kernel_mem.as_ptr() as u64;
    let entry_phys = kernel_phys + (kernel.entry - kernel.link_base);

    let framebuffer = framebuffer();
    let (acpi, device_tree) = firmware_tables()?;
    let seed = seed()?;

    // The boot information, all but the memory map.
    let info_mem = pages(MT_BOOTINFO, 64 << 10, 4096)?;
    let info_phys = info_mem.as_ptr() as u64;
    let info_len = info_mem.len();
    let mut w = Writer::new(info_mem).map_err(|_| "boot information too small")?;
    let full = |_| "boot information too small";
    w.record(kind::COMMAND_LINE, &[command_line.as_bytes()])
        .map_err(full)?;
    let placement = KernelPlacement {
        physical_base: kernel_phys,
        virtual_base: KERNEL_VIRTUAL_BASE,
        slide: KERNEL_VIRTUAL_BASE.wrapping_sub(kernel.link_base),
        size: kernel.span,
    };
    w.record(kind::KERNEL_PLACEMENT, &[&placement.to_bytes()])
        .map_err(full)?;
    if let Some(fb) = framebuffer {
        w.record(kind::FRAMEBUFFER, &[&fb.to_bytes()])
            .map_err(full)?;
    }
    if let Some(rsdp) = acpi {
        w.record(kind::ACPI, &[&rsdp.to_le_bytes()]).map_err(full)?;
    }
    if let Some((addr, size)) = device_tree {
        w.record(
            kind::DEVICE_TREE,
            &[&addr.to_le_bytes(), &size.to_le_bytes()],
        )
        .map_err(full)?;
    }
    let image = InitialImage {
        base: initfs.as_ptr() as u64,
        size: initfs.len() as u64,
        digest,
        check,
    };
    w.record(kind::INITIAL_IMAGE, &[&image.to_bytes()])
        .map_err(full)?;
    if let Some(s) = seed {
        w.record(kind::SEED, &[&s.to_bytes()]).map_err(full)?;
    }
    let mut vendor = [0u8; 64];
    for (d, c) in vendor
        .iter_mut()
        .zip(uefi::system::firmware_vendor().iter())
    {
        let c = u16::from(*c);
        *d = if (0x20..0x7f).contains(&c) {
            c as u8
        } else {
            b'?'
        };
    }
    let stub = Stub {
        version: STUB_VERSION,
        start: how,
        entered_el: el,
        firmware_revision: uefi::system::firmware_revision(),
        firmware_vendor: vendor,
    };
    w.record(kind::STUB, &[&stub.to_bytes()]).map_err(full)?;

    // Room for the final memory map, which exists only after
    // ExitBootServices. Splitting around the framebuffer adds at most three
    // ranges, and exiting allocates a little more.
    let now = boot::memory_map(MemoryType::LOADER_DATA)
        .map_err(|_| "no memory map")?
        .entries()
        .count();
    let capacity = now * 2 + 64;
    let slot = w.memory_map_slot(capacity).map_err(full)?;

    say!(
        "aspis stub: kernel at {kernel_phys:#x}, initfs {} bytes ({}), entering the kernel",
        initfs.len(),
        if check == initfs_check::MATCHED {
            "matched"
        } else {
            "waived"
        }
    );

    // From here on, no boot services and no output.
    // SAFETY: nothing borrowed from boot services is used after this; the
    // pages we allocated stay ours under their own memory types.
    let map = unsafe { boot::exit_boot_services(None) };
    let fb_range = framebuffer.map(|f| (f.base, f.base + f.size));
    let mut n = 0usize;
    {
        let out = w.slot(slot.clone());
        let mut push = |r: MemoryRange| {
            if n < capacity {
                let at = n * MemoryRange::LEN;
                let mut e = [0u8; MemoryRange::LEN];
                r.write(&mut e);
                out[at..at + MemoryRange::LEN].copy_from_slice(&e);
                n += 1;
            }
        };
        for d in map.entries() {
            let range = MemoryRange {
                base: d.phys_start,
                pages: d.page_count,
                kind: aspis_type(d.ty.0) as u32,
                uefi_type: d.ty.0,
                uefi_attributes: d.att.bits(),
            };
            split_around(range, fb_range, &mut push);
        }
        // A framebuffer the firmware's map doesn't cover still gets a range.
        if let Some((fb_start, fb_end)) = fb_range {
            let covered = map
                .entries()
                .any(|d| d.phys_start < fb_end && d.phys_start + d.page_count * 4096 > fb_start);
            if !covered {
                push(MemoryRange {
                    base: fb_start & !4095,
                    pages: (fb_end - (fb_start & !4095)).div_ceil(4096),
                    kind: Bi::Framebuffer as u32,
                    uefi_type: 0,
                    uefi_attributes: 0,
                });
            }
        }
    }
    w.set_memory_map_count(slot.start, n as u32);
    w.finish();

    for (start, len) in [
        (kernel_phys as usize, kernel.span as usize),
        (info_phys as usize, info_len),
        (image.base as usize, image.size as usize),
    ]
    .into_iter()
    .chain(device_tree.map(|(a, s)| (a as usize, s as usize)))
    .chain(seed.map(|s| (s.address as usize, 4096)))
    {
        handoff::clean_invalidate(start, len);
    }
    // SAFETY: the kernel is loaded and relocated, and the boot information
    // is complete; both are cleaned to the PoC.
    unsafe { handoff::enter_kernel(entry_phys, info_phys) }
}

/// Splits `r` around the framebuffer, marking the overlap as framebuffer.
fn split_around(r: MemoryRange, fb: Option<(u64, u64)>, push: &mut impl FnMut(MemoryRange)) {
    let end = r.base + r.pages * 4096;
    let Some((fs, fe)) = fb else { return push(r) };
    let (fs, fe) = (fs & !4095, fe.next_multiple_of(4096));
    if fe <= r.base || fs >= end {
        return push(r);
    }
    let piece = |base: u64, top: u64, kind: u32| MemoryRange {
        base,
        pages: (top - base) / 4096,
        kind,
        ..r
    };
    if fs > r.base {
        push(piece(r.base, fs, r.kind));
    }
    push(piece(fs.max(r.base), fe.min(end), Bi::Framebuffer as u32));
    if fe < end {
        push(piece(fe, end, r.kind));
    }
}

/// Maps a UEFI memory type to an ASPIS one (ADR 0041, rule 3).
fn aspis_type(t: u32) -> Bi {
    match t {
        // Loader code and data, boot services code and data, conventional.
        1 | 2 | 3 | 4 | 7 => Bi::Usable,
        // Runtime services code and data: never used (ADR 0039, rule 2).
        5 | 6 => Bi::FirmwareReserved,
        8 | 14 | 15 => Bi::Unusable,
        9 => Bi::AcpiReclaimable,
        10 => Bi::AcpiNonVolatile,
        11 | 12 => Bi::Mmio,
        MT_KERNEL => Bi::KernelImage,
        MT_INITFS => Bi::InitialImage,
        MT_BOOTINFO => Bi::BootInformation,
        MT_SEED => Bi::Seed,
        _ => Bi::FirmwareReserved,
    }
}

/// The load options as ASCII, without GRUB's leading `BOOT_IMAGE=` word.
fn command_line() -> Result<String, &'static str> {
    let image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
        .map_err(|_| "no loaded-image protocol")?;
    let mut out = String::new();
    let mut dropped = false;
    if let Ok(opts) = image.load_options_as_cstr16() {
        for c in opts.iter() {
            let c = u16::from(*c);
            if (0x20..0x7f).contains(&c) {
                out.push(c as u8 as char);
            } else {
                // ADR 0041, rule 5: characters outside ASCII are rejected.
                dropped = true;
            }
        }
    }
    if dropped {
        say!("aspis stub: dropped characters outside ASCII from the command line");
    }
    // GRUB's arm64 `linux` command puts `BOOT_IMAGE=<path>` first, escapes
    // `\`, `'` and `"`, and quotes whole words that hold a space. Undo that,
    // so the kernel gets the grammar's own form (ADR 0041, rule 5).
    if kargs::is_grub(out.as_bytes()) {
        let mut converted = alloc::vec![0u8; out.len() * 2 + 16];
        let mut word = alloc::vec![0u8; out.len() + 1];
        match kargs::from_grub(out.as_bytes(), &mut converted, &mut word) {
            Ok(n) => {
                converted.truncate(n);
                // ASCII in, ASCII out.
                out = String::from_utf8(converted).unwrap_or_default();
            }
            Err(e) => {
                say!("aspis stub: can't read GRUB's command line ({e:?}); passing no arguments");
                out.clear();
            }
        }
    }
    if out.len() > MAX_COMMAND_LINE {
        out.truncate(MAX_COMMAND_LINE);
        say!("aspis stub: command line cut to {MAX_COMMAND_LINE} bytes");
    }
    Ok(out)
}

/// Reads the initial image through GRUB's `LoadFile2`, if GRUB offers it.
fn load_initfs_loadfile2() -> Option<&'static mut [u8]> {
    let path = <&DevicePath>::try_from(&INITRD_MEDIA_PATH[..])
        .map_err(|e| say!("aspis stub: LoadFile2: bad device path: {e:?}"))
        .ok()?;
    let mut remaining = path;
    // No handle means GRUB isn't serving the image: not an error.
    // GRUB, like Linux's stub, expects the path that remains after
    // LocateDevicePath: the end node.
    let handle = boot::locate_device_path::<LoadFile2>(&mut remaining).ok()?;
    let mut proto = boot::open_protocol_exclusive::<LoadFile2>(handle)
        .map_err(|e| say!("aspis stub: LoadFile2: can't open: {:?}", e.status()))
        .ok()?;
    // SAFETY: `LoadFile2` is a transparent wrapper around the raw protocol.
    let raw = unsafe {
        &mut *(&mut *proto as *mut LoadFile2).cast::<uefi_raw::protocol::media::LoadFile2Protocol>()
    };
    let mut size = 0usize;
    // SAFETY: a size query, with a null buffer.
    let status = unsafe {
        (raw.load_file)(
            raw,
            remaining.as_ffi_ptr().cast(),
            uefi_raw::Boolean::FALSE,
            &mut size,
            core::ptr::null_mut(),
        )
    };
    if status != uefi_raw::Status::BUFFER_TOO_SMALL || size == 0 {
        say!("aspis stub: LoadFile2: size query returned {status:?}, size {size}");
        return None;
    }
    let buf = pages(MT_INITFS, size, 4096).ok()?;
    let mut got = size;
    // SAFETY: `buf` holds `size` bytes.
    let status = unsafe {
        (raw.load_file)(
            raw,
            remaining.as_ffi_ptr().cast(),
            uefi_raw::Boolean::FALSE,
            &mut got,
            buf.as_mut_ptr().cast(),
        )
    };
    if !status.is_success() || got != size {
        say!("aspis stub: LoadFile2: load returned {status:?}, {got} of {size} bytes");
        return None;
    }
    Some(buf)
}

/// Reads the initial image from the ESP: the `initfs` argument's path, or
/// `initfs.img` beside `aspis.efi` (ADR 0041, rule 6).
fn load_initfs_file(command_line: &str) -> Result<&'static mut [u8], &'static str> {
    let path: String = match kargs::lookup(command_line.as_bytes(), "initfs").value {
        Some(Some(v)) => v.raw().replace('/', "\\"),
        _ => {
            let image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
                .map_err(|_| "no loaded-image protocol")?;
            let own = image
                .file_path()
                .and_then(|p| {
                    p.to_string16(DisplayOnly(false), AllowShortcuts(false))
                        .ok()
                })
                .map(|s| String::from(&*s))
                .ok_or("can't tell where aspis.efi was loaded from")?;
            let dir = own.rfind('\\').map_or("", |i| &own[..i]);
            let mut p = String::from(dir);
            p.push_str("\\initfs.img");
            p
        }
    };
    let path = CString16::try_from(path.as_str()).map_err(|_| "bad initfs path")?;
    let mut fs = boot::get_image_file_system(boot::image_handle())
        .map_err(|_| "no file system to read initfs.img from")?;
    let mut root = fs.open_volume().map_err(|_| "can't open the ESP")?;
    let mut file: RegularFile = root
        .open(&path, FileMode::Read, FileAttribute::empty())
        .map_err(|_| "initfs.img not found")?
        .into_regular_file()
        .ok_or("initfs.img is not a file")?;
    file.set_position(RegularFile::END_OF_FILE)
        .map_err(|_| "can't size initfs.img")?;
    let size = file.get_position().map_err(|_| "can't size initfs.img")? as usize;
    file.set_position(0).map_err(|_| "can't read initfs.img")?;
    let buf = pages(MT_INITFS, size, 4096)?;
    let mut at = 0;
    while at < size {
        let n = file
            .read(&mut buf[at..size])
            .map_err(|_| "can't read initfs.img")?;
        if n == 0 {
            return Err("initfs.img is shorter than its size");
        }
        at += n;
    }
    Ok(&mut buf[..size])
}

/// The linear GOP framebuffer, if there is one (ADR 0009, rule 2).
fn framebuffer() -> Option<Framebuffer> {
    let handle = boot::get_handle_for_protocol::<GraphicsOutput>().ok()?;
    // Opened non-exclusively, so the firmware's console keeps drawing.
    // SAFETY: we only read mode information and the framebuffer address.
    let mut gop = unsafe {
        boot::open_protocol::<GraphicsOutput>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()?;
    if gop.current_mode_info().pixel_format() == PixelFormat::BltOnly {
        let linear = gop
            .modes()
            .find(|m| m.info().pixel_format() != PixelFormat::BltOnly)?;
        gop.set_mode(&linear).ok()?;
    }
    let info = gop.current_mode_info();
    let (width, height) = info.resolution();
    let (format, masks) = match info.pixel_format() {
        PixelFormat::Bgr => (
            pixel_format::BGRX8888,
            [0x00ff_0000, 0x0000_ff00, 0x0000_00ff, 0xff00_0000],
        ),
        PixelFormat::Rgb => (
            pixel_format::RGBX8888,
            [0x0000_00ff, 0x0000_ff00, 0x00ff_0000, 0xff00_0000],
        ),
        PixelFormat::Bitmask => {
            let m = info.pixel_bitmask()?;
            (pixel_format::BITMASK, [m.red, m.green, m.blue, m.reserved])
        }
        PixelFormat::BltOnly => return None,
    };
    let mut fb = gop.frame_buffer();
    Some(Framebuffer {
        base: fb.as_mut_ptr() as u64,
        size: fb.size() as u64,
        width: width as u32,
        height: height as u32,
        stride: info.stride() as u32,
        format,
        red_mask: masks[0],
        green_mask: masks[1],
        blue_mask: masks[2],
        reserved_mask: masks[3],
    })
}

/// The ACPI 2.0 RSDP, and a copy of the device tree in pages of our own.
#[allow(clippy::type_complexity)]
fn firmware_tables() -> Result<(Option<u64>, Option<(u64, u64)>), &'static str> {
    let (acpi, dtb) = uefi::system::with_config_table(|entries: &[ConfigTableEntry]| {
        let find = |g| {
            entries
                .iter()
                .find(|e| e.guid == g)
                .map(|e| e.address as u64)
        };
        (find(ConfigTableEntry::ACPI2_GUID), find(DTB_GUID))
    });
    let device_tree = match dtb {
        Some(addr) => {
            // SAFETY: the firmware's device tree is readable; its header's
            // first two words are the magic and the total size, big-endian.
            let header = unsafe { core::slice::from_raw_parts(addr as *const u8, 8) };
            if header[0..4] != [0xd0, 0x0d, 0xfe, 0xed] {
                return Err("the device tree has a bad magic number");
            }
            let size = u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
            let copy = pages(MT_BOOTINFO, size, 4096)?;
            // SAFETY: the blob is `size` bytes long.
            copy.copy_from_slice(unsafe { core::slice::from_raw_parts(addr as *const u8, size) });
            Some((copy.as_ptr() as u64, size as u64))
        }
        None => None,
    };
    Ok((acpi, device_tree))
}

/// The firmware's seed, in a page of its own (ADR 0041, rule 4). The stub
/// uses none of it, so it passes all of it on.
fn seed() -> Result<Option<Seed>, &'static str> {
    let Ok(handle) = boot::get_handle_for_protocol::<Rng>() else {
        say!("aspis stub: no EFI_RNG_PROTOCOL, so no seed");
        return Ok(None);
    };
    let Ok(mut rng) = boot::open_protocol_exclusive::<Rng>(handle) else {
        return Ok(None);
    };
    let page = pages(MT_SEED, 4096, 4096)?;
    const LEN: usize = 64;
    if rng.get_rng(None, &mut page[..LEN]).is_err() {
        page.fill(0);
        return Ok(None);
    }
    Ok(Some(Seed {
        address: page.as_ptr() as u64,
        length: LEN as u32,
        source: seed_source::EFI_RNG_PROTOCOL,
    }))
}
