// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The boot information the stub hands the kernel (ADR 0041, rules 2 and 3).
//!
//! A header is followed by tagged records. Each record has a 32-bit type and
//! a 32-bit length that counts its own 8-byte header, then its payload,
//! padded to 8 bytes. Integers are little-endian: this is an in-memory
//! structure between two programs on one processor, not a message.
//!
//! A reader skips record types it doesn't know, unless the type has its top
//! bit set ([`CRITICAL`]), in which case it must refuse to boot.
//!
//! This crate is shared by the stub, which writes the structure with
//! [`Writer`], and the kernel, which reads it with [`BootInfo::parse`].
//! Neither side allocates, and parsing never panics on malformed input.

#![no_std]

/// `ASPISBI\0`.
pub const MAGIC: [u8; 8] = *b"ASPISBI\0";
/// A new record type is a minor version; changing a record's meaning is a major one.
pub const VERSION_MAJOR: u16 = 1;
pub const VERSION_MINOR: u16 = 0;
/// The header's length in bytes.
pub const HEADER_LEN: usize = 32;
/// A record type with this bit set must be understood, or the kernel refuses to boot.
pub const CRITICAL: u32 = 1 << 31;

/// Record types (ADR 0041, rule 3).
pub mod kind {
    pub const COMMAND_LINE: u32 = 1;
    pub const MEMORY_MAP: u32 = 2;
    pub const DEVICE_TREE: u32 = 3;
    pub const ACPI: u32 = 4;
    pub const FRAMEBUFFER: u32 = 5;
    pub const INITIAL_IMAGE: u32 = 6;
    pub const SEED: u32 = 7;
    pub const KERNEL_PLACEMENT: u32 = 8;
    pub const STUB: u32 = 9;
    /// Reserved for measured boot (C64). Not written yet.
    pub const TPM_EVENT_LOG: u32 = 10;
}

/// ASPIS memory types in the memory map (ADR 0041, rule 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryType {
    Usable = 1,
    /// Includes UEFI runtime regions, which ASPIS never uses (ADR 0039, rule 2).
    FirmwareReserved = 2,
    AcpiReclaimable = 3,
    AcpiNonVolatile = 4,
    Mmio = 5,
    KernelImage = 6,
    InitialImage = 7,
    /// The boot information itself, and the device tree copy it points to.
    BootInformation = 8,
    Framebuffer = 9,
    Seed = 10,
    /// Memory the firmware reported as unusable or persistent.
    Unusable = 11,
}

impl MemoryType {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => Self::Usable,
            2 => Self::FirmwareReserved,
            3 => Self::AcpiReclaimable,
            4 => Self::AcpiNonVolatile,
            5 => Self::Mmio,
            6 => Self::KernelImage,
            7 => Self::InitialImage,
            8 => Self::BootInformation,
            9 => Self::Framebuffer,
            10 => Self::Seed,
            11 => Self::Unusable,
            _ => return None,
        })
    }
}

/// The size of a page in the memory map's `pages` field.
pub const PAGE_SIZE: u64 = 4096;

/// One range of the memory map: 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRange {
    pub base: u64,
    pub pages: u64,
    pub kind: u32,
    pub uefi_type: u32,
    pub uefi_attributes: u64,
}

impl MemoryRange {
    pub const LEN: usize = 32;

    pub fn memory_type(&self) -> Option<MemoryType> {
        MemoryType::from_u32(self.kind)
    }

    pub fn end(&self) -> Option<u64> {
        self.pages
            .checked_mul(PAGE_SIZE)
            .and_then(|len| self.base.checked_add(len))
    }

    pub fn write(&self, out: &mut [u8; Self::LEN]) {
        out[0..8].copy_from_slice(&self.base.to_le_bytes());
        out[8..16].copy_from_slice(&self.pages.to_le_bytes());
        out[16..20].copy_from_slice(&self.kind.to_le_bytes());
        out[20..24].copy_from_slice(&self.uefi_type.to_le_bytes());
        out[24..32].copy_from_slice(&self.uefi_attributes.to_le_bytes());
    }

    fn read(b: &[u8]) -> Option<Self> {
        Some(Self {
            base: u64_at(b, 0)?,
            pages: u64_at(b, 8)?,
            kind: u32_at(b, 16)?,
            uefi_type: u32_at(b, 20)?,
            uefi_attributes: u64_at(b, 24)?,
        })
    }
}

/// Pixel formats of the linear framebuffer.
pub mod pixel_format {
    /// Bytes in memory are blue, green, red, reserved (UEFI `PixelBlueGreenRedReserved8BitPerColor`).
    pub const BGRX8888: u32 = 1;
    /// Bytes in memory are red, green, blue, reserved (UEFI `PixelRedGreenBlueReserved8BitPerColor`).
    pub const RGBX8888: u32 = 2;
    /// 32 bits per pixel, described by the masks.
    pub const BITMASK: u32 = 3;
}

/// The linear framebuffer (ADR 0009, rule 2): 48 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Framebuffer {
    pub base: u64,
    pub size: u64,
    pub width: u32,
    pub height: u32,
    /// Pixels per scan line.
    pub stride: u32,
    pub format: u32,
    pub red_mask: u32,
    pub green_mask: u32,
    pub blue_mask: u32,
    pub reserved_mask: u32,
}

impl Framebuffer {
    pub const LEN: usize = 48;

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0..8].copy_from_slice(&self.base.to_le_bytes());
        b[8..16].copy_from_slice(&self.size.to_le_bytes());
        let words = [
            self.width,
            self.height,
            self.stride,
            self.format,
            self.red_mask,
            self.green_mask,
            self.blue_mask,
            self.reserved_mask,
        ];
        for (i, w) in words.iter().enumerate() {
            b[16 + 4 * i..20 + 4 * i].copy_from_slice(&w.to_le_bytes());
        }
        b
    }

    fn read(b: &[u8]) -> Option<Self> {
        Some(Self {
            base: u64_at(b, 0)?,
            size: u64_at(b, 8)?,
            width: u32_at(b, 16)?,
            height: u32_at(b, 20)?,
            stride: u32_at(b, 24)?,
            format: u32_at(b, 28)?,
            red_mask: u32_at(b, 32)?,
            green_mask: u32_at(b, 36)?,
            blue_mask: u32_at(b, 40)?,
            reserved_mask: u32_at(b, 44)?,
        })
    }
}

/// What the stub found when it checked the initial image (ADR 0040, rule 4).
pub mod initfs_check {
    /// The image's SHA-512 matched the digest in `aspis.efi`.
    pub const MATCHED: u32 = 1;
    /// A test build waived the check (ADR 0036, rule 6).
    pub const WAIVED: u32 = 2;
}

/// The initial image: 88 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialImage {
    pub base: u64,
    pub size: u64,
    pub digest: [u8; 64],
    pub check: u32,
}

impl InitialImage {
    pub const LEN: usize = 88;

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0..8].copy_from_slice(&self.base.to_le_bytes());
        b[8..16].copy_from_slice(&self.size.to_le_bytes());
        b[16..80].copy_from_slice(&self.digest);
        b[80..84].copy_from_slice(&self.check.to_le_bytes());
        b
    }

    fn read(b: &[u8]) -> Option<Self> {
        let mut digest = [0u8; 64];
        digest.copy_from_slice(b.get(16..80)?);
        Some(Self {
            base: u64_at(b, 0)?,
            size: u64_at(b, 8)?,
            digest,
            check: u32_at(b, 80)?,
        })
    }
}

/// Where the seed came from.
pub mod seed_source {
    pub const EFI_RNG_PROTOCOL: u32 = 1;
}

/// The seed's page (ADR 0041, rule 4): 16 bytes. The kernel never reads the page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seed {
    pub address: u64,
    pub length: u32,
    pub source: u32,
}

impl Seed {
    pub const LEN: usize = 16;

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0..8].copy_from_slice(&self.address.to_le_bytes());
        b[8..12].copy_from_slice(&self.length.to_le_bytes());
        b[12..16].copy_from_slice(&self.source.to_le_bytes());
        b
    }

    fn read(b: &[u8]) -> Option<Self> {
        Some(Self {
            address: u64_at(b, 0)?,
            length: u32_at(b, 8)?,
            source: u32_at(b, 12)?,
        })
    }
}

/// Where the stub placed the kernel (ADR 0035, rules 3 and 4): 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelPlacement {
    pub physical_base: u64,
    pub virtual_base: u64,
    /// The virtual base minus the address the kernel was linked at.
    pub slide: u64,
    /// The size of the loaded image, in bytes.
    pub size: u64,
}

impl KernelPlacement {
    pub const LEN: usize = 32;

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0..8].copy_from_slice(&self.physical_base.to_le_bytes());
        b[8..16].copy_from_slice(&self.virtual_base.to_le_bytes());
        b[16..24].copy_from_slice(&self.slide.to_le_bytes());
        b[24..32].copy_from_slice(&self.size.to_le_bytes());
        b
    }

    fn read(b: &[u8]) -> Option<Self> {
        Some(Self {
            physical_base: u64_at(b, 0)?,
            virtual_base: u64_at(b, 8)?,
            slide: u64_at(b, 16)?,
            size: u64_at(b, 24)?,
        })
    }
}

/// How the stub was started.
pub mod start {
    /// GRUB's `linux` command, which served the initial image through `LoadFile2`.
    pub const GRUB_LINUX: u32 = 1;
    /// `chainloader` or the firmware's boot manager; the stub read the image itself.
    pub const CHAINLOADER_OR_DIRECT: u32 = 2;
}

/// The stub and the firmware it ran under: 80 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stub {
    /// Major version in the high 16 bits, minor in the low 16.
    pub version: u32,
    pub start: u32,
    /// The exception level the firmware entered the stub at: 1 or 2.
    pub entered_el: u32,
    pub firmware_revision: u32,
    /// The firmware vendor, ASCII, zero-padded.
    pub firmware_vendor: [u8; 64],
}

impl Stub {
    pub const LEN: usize = 80;

    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[0..4].copy_from_slice(&self.version.to_le_bytes());
        b[4..8].copy_from_slice(&self.start.to_le_bytes());
        b[8..12].copy_from_slice(&self.entered_el.to_le_bytes());
        b[12..16].copy_from_slice(&self.firmware_revision.to_le_bytes());
        b[16..80].copy_from_slice(&self.firmware_vendor);
        b
    }

    fn read(b: &[u8]) -> Option<Self> {
        let mut firmware_vendor = [0u8; 64];
        firmware_vendor.copy_from_slice(b.get(16..80)?);
        Some(Self {
            version: u32_at(b, 0)?,
            start: u32_at(b, 4)?,
            entered_el: u32_at(b, 8)?,
            firmware_revision: u32_at(b, 12)?,
            firmware_vendor,
        })
    }

    /// The vendor string up to its first zero byte, if it is ASCII.
    pub fn vendor(&self) -> &str {
        let end = self
            .firmware_vendor
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.firmware_vendor.len());
        core::str::from_utf8(&self.firmware_vendor[..end]).unwrap_or("?")
    }
}

/// Why a buffer isn't valid boot information.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    TooShort,
    BadMagic,
    UnsupportedMajor(u16),
    BadHeaderLength,
    BadTotalLength,
    BadRecord {
        offset: usize,
    },
    RecordCountMismatch,
    /// A critical record this reader doesn't know (ADR 0041, rule 2).
    UnknownCritical(u32),
    MissingRequired(u32),
    BadPayload(u32),
}

/// One raw record.
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    pub kind: u32,
    pub payload: &'a [u8],
}

/// Parsed, validated boot information.
#[derive(Clone, Copy, Debug)]
pub struct BootInfo<'a> {
    pub minor: u16,
    records: &'a [u8],
    /// The number of records, as the header gives it.
    pub record_count: u32,
}

impl<'a> BootInfo<'a> {
    /// Validates the header and every record's framing. Rejects unknown
    /// critical records, and checks that the required records (the memory
    /// map and the kernel placement) are present and well formed.
    pub fn parse(buf: &'a [u8]) -> Result<Self, Error> {
        if buf.len() < HEADER_LEN {
            return Err(Error::TooShort);
        }
        if buf[0..8] != MAGIC {
            return Err(Error::BadMagic);
        }
        let major = u16_at(buf, 8).ok_or(Error::TooShort)?;
        let minor = u16_at(buf, 10).ok_or(Error::TooShort)?;
        if major != VERSION_MAJOR {
            return Err(Error::UnsupportedMajor(major));
        }
        let header_len = u32_at(buf, 12).ok_or(Error::TooShort)? as usize;
        let total_len = u32_at(buf, 16).ok_or(Error::TooShort)? as usize;
        let count = u32_at(buf, 20).ok_or(Error::TooShort)?;
        if header_len < HEADER_LEN || !header_len.is_multiple_of(8) || header_len > total_len {
            return Err(Error::BadHeaderLength);
        }
        if total_len > buf.len() {
            return Err(Error::BadTotalLength);
        }
        let info = Self {
            minor,
            records: &buf[header_len..total_len],
            record_count: count,
        };
        let mut seen = 0u32;
        let (mut have_map, mut have_placement) = (false, false);
        let mut it = info.raw_records();
        for r in &mut it {
            let r = r?;
            seen = seen.checked_add(1).ok_or(Error::RecordCountMismatch)?;
            match r.kind {
                kind::MEMORY_MAP => {
                    MemoryMap::parse(r.payload).ok_or(Error::BadPayload(r.kind))?;
                    have_map = true;
                }
                kind::KERNEL_PLACEMENT => {
                    KernelPlacement::read(r.payload).ok_or(Error::BadPayload(r.kind))?;
                    have_placement = true;
                }
                k if k & CRITICAL != 0 => return Err(Error::UnknownCritical(k)),
                _ => {}
            }
        }
        if seen != count {
            return Err(Error::RecordCountMismatch);
        }
        if !have_map {
            return Err(Error::MissingRequired(kind::MEMORY_MAP));
        }
        if !have_placement {
            return Err(Error::MissingRequired(kind::KERNEL_PLACEMENT));
        }
        Ok(info)
    }

    /// Every record, in order, including ones this reader doesn't know.
    pub fn records(&self) -> impl Iterator<Item = Record<'a>> + 'a {
        self.raw_records().map_while(Result::ok)
    }

    fn raw_records(&self) -> RawRecords<'a> {
        RawRecords {
            buf: self.records,
            pos: 0,
        }
    }

    fn find(&self, k: u32) -> Option<&'a [u8]> {
        self.records().find(|r| r.kind == k).map(|r| r.payload)
    }

    /// The kernel arguments, ASCII.
    pub fn command_line(&self) -> &'a [u8] {
        self.find(kind::COMMAND_LINE).unwrap_or(&[])
    }

    pub fn memory_map(&self) -> MemoryMap<'a> {
        // `parse` checked that the record exists and is well formed.
        self.find(kind::MEMORY_MAP)
            .and_then(MemoryMap::parse)
            .unwrap_or(MemoryMap { entries: &[] })
    }

    /// The physical address and size of the device tree blob.
    pub fn device_tree(&self) -> Option<(u64, u64)> {
        let p = self.find(kind::DEVICE_TREE)?;
        Some((u64_at(p, 0)?, u64_at(p, 8)?))
    }

    /// The physical address of the ACPI 2.0 RSDP.
    pub fn acpi_rsdp(&self) -> Option<u64> {
        u64_at(self.find(kind::ACPI)?, 0)
    }

    pub fn framebuffer(&self) -> Option<Framebuffer> {
        Framebuffer::read(self.find(kind::FRAMEBUFFER)?)
    }

    pub fn initial_image(&self) -> Option<InitialImage> {
        InitialImage::read(self.find(kind::INITIAL_IMAGE)?)
    }

    pub fn seed(&self) -> Option<Seed> {
        Seed::read(self.find(kind::SEED)?)
    }

    pub fn kernel_placement(&self) -> KernelPlacement {
        self.find(kind::KERNEL_PLACEMENT)
            .and_then(KernelPlacement::read)
            .unwrap_or(KernelPlacement {
                physical_base: 0,
                virtual_base: 0,
                slide: 0,
                size: 0,
            })
    }

    pub fn stub(&self) -> Option<Stub> {
        Stub::read(self.find(kind::STUB)?)
    }
}

struct RawRecords<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for RawRecords<'a> {
    type Item = Result<Record<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let bad = Error::BadRecord { offset: self.pos };
        let rest = &self.buf[self.pos..];
        let (Some(kind), Some(len)) = (u32_at(rest, 0), u32_at(rest, 4)) else {
            self.pos = self.buf.len();
            return Some(Err(bad));
        };
        let len = len as usize;
        let padded = len.checked_add(7).map(|l| l & !7);
        match padded {
            Some(padded) if len >= 8 && padded <= rest.len() => {
                self.pos += padded;
                Some(Ok(Record {
                    kind,
                    payload: &rest[8..len],
                }))
            }
            _ => {
                self.pos = self.buf.len();
                Some(Err(bad))
            }
        }
    }
}

/// The memory map record: a count, an entry size, then the entries.
#[derive(Clone, Copy, Debug)]
pub struct MemoryMap<'a> {
    entries: &'a [u8],
}

impl<'a> MemoryMap<'a> {
    fn parse(p: &'a [u8]) -> Option<Self> {
        let count = u32_at(p, 0)? as usize;
        let size = u32_at(p, 4)? as usize;
        if size != MemoryRange::LEN {
            return None;
        }
        let len = count.checked_mul(size)?;
        Some(Self {
            entries: p.get(8..8usize.checked_add(len)?)?,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len() / MemoryRange::LEN
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = MemoryRange> + 'a {
        self.entries
            .as_chunks::<{ MemoryRange::LEN }>()
            .0
            .iter()
            .filter_map(|c| MemoryRange::read(c))
    }
}

/// Writes boot information into a caller's buffer, without allocating.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
    count: u32,
}

/// The buffer is too small.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Result<Self, Full> {
        if buf.len() < HEADER_LEN {
            return Err(Full);
        }
        buf[..HEADER_LEN].fill(0);
        Ok(Self {
            buf,
            pos: HEADER_LEN,
            count: 0,
        })
    }

    /// Appends a record whose payload is the concatenation of `parts`.
    pub fn record(&mut self, kind: u32, parts: &[&[u8]]) -> Result<(), Full> {
        let payload: usize = parts.iter().map(|p| p.len()).sum();
        let len = payload.checked_add(8).ok_or(Full)?;
        let padded = len.checked_add(7).ok_or(Full)? & !7;
        let end = self.pos.checked_add(padded).ok_or(Full)?;
        if end > self.buf.len() || len > u32::MAX as usize {
            return Err(Full);
        }
        let out = &mut self.buf[self.pos..end];
        out.fill(0);
        out[0..4].copy_from_slice(&kind.to_le_bytes());
        out[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        let mut at = 8;
        for p in parts {
            out[at..at + p.len()].copy_from_slice(p);
            at += p.len();
        }
        self.pos = end;
        self.count += 1;
        Ok(())
    }

    /// Reserves a memory map record for `count` ranges and returns the slice
    /// to fill in later, with [`MemoryRange::write`]. The stub needs this
    /// because the final memory map exists only after `ExitBootServices`.
    pub fn memory_map_slot(&mut self, count: usize) -> Result<core::ops::Range<usize>, Full> {
        let len = count.checked_mul(MemoryRange::LEN).ok_or(Full)?;
        let start = self.pos.checked_add(16).ok_or(Full)?;
        let head = [
            (count as u32).to_le_bytes(),
            (MemoryRange::LEN as u32).to_le_bytes(),
        ]
        .concat_array();
        self.record_with_space(kind::MEMORY_MAP, &head, len)?;
        Ok(start..start + len)
    }

    fn record_with_space(&mut self, kind: u32, head: &[u8], space: usize) -> Result<(), Full> {
        let len = 8usize
            .checked_add(head.len())
            .and_then(|l| l.checked_add(space))
            .ok_or(Full)?;
        let padded = len.checked_add(7).ok_or(Full)? & !7;
        let end = self.pos.checked_add(padded).ok_or(Full)?;
        if end > self.buf.len() || len > u32::MAX as usize {
            return Err(Full);
        }
        let out = &mut self.buf[self.pos..end];
        out.fill(0);
        out[0..4].copy_from_slice(&kind.to_le_bytes());
        out[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        out[8..8 + head.len()].copy_from_slice(head);
        self.pos = end;
        self.count += 1;
        Ok(())
    }

    /// The bytes reserved by [`Writer::memory_map_slot`].
    pub fn slot(&mut self, range: core::ops::Range<usize>) -> &mut [u8] {
        &mut self.buf[range]
    }

    /// Rewrites the count of a reserved memory map whose slot ended up
    /// partly used. `slot_start` is the start returned by `memory_map_slot`.
    pub fn set_memory_map_count(&mut self, slot_start: usize, count: u32) {
        if let Some(c) = self.buf.get_mut(slot_start - 8..slot_start - 4) {
            c.copy_from_slice(&count.to_le_bytes());
        }
    }

    /// Writes the header and returns the total length.
    pub fn finish(self) -> usize {
        let h = &mut self.buf[..HEADER_LEN];
        h[0..8].copy_from_slice(&MAGIC);
        h[8..10].copy_from_slice(&VERSION_MAJOR.to_le_bytes());
        h[10..12].copy_from_slice(&VERSION_MINOR.to_le_bytes());
        h[12..16].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
        h[16..20].copy_from_slice(&(self.pos as u32).to_le_bytes());
        h[20..24].copy_from_slice(&self.count.to_le_bytes());
        self.pos
    }
}

trait ConcatArray {
    fn concat_array(self) -> [u8; 8];
}

impl ConcatArray for [[u8; 4]; 2] {
    fn concat_array(self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[..4].copy_from_slice(&self[0]);
        out[4..].copy_from_slice(&self[1]);
        out
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(buf: &mut [u8]) -> usize {
        let mut w = Writer::new(buf).unwrap();
        w.record(kind::COMMAND_LINE, &[b"console=fb,uart"]).unwrap();
        let slot = w.memory_map_slot(2).unwrap();
        let r = MemoryRange {
            base: 0x4000_0000,
            pages: 16,
            kind: MemoryType::Usable as u32,
            uefi_type: 7,
            uefi_attributes: 0xf,
        };
        let mut e = [0u8; MemoryRange::LEN];
        r.write(&mut e);
        w.slot(slot.clone())[..32].copy_from_slice(&e);
        w.set_memory_map_count(slot.start, 1);
        let kp = KernelPlacement {
            physical_base: 0x4020_0000,
            virtual_base: 0xffff_8000_0000_0000,
            slide: 0,
            size: 0x10_0000,
        };
        w.record(kind::KERNEL_PLACEMENT, &[&kp.to_bytes()]).unwrap();
        w.record(0x1234, &[b"unknown, skipped"]).unwrap();
        w.finish()
    }

    #[test]
    fn round_trip() {
        let mut buf = [0u8; 512];
        let n = sample(&mut buf);
        let bi = BootInfo::parse(&buf[..n]).unwrap();
        assert_eq!(bi.command_line(), b"console=fb,uart");
        let ranges: [_; 1] = [bi.memory_map().iter().next().unwrap()];
        assert_eq!(ranges[0].base, 0x4000_0000);
        assert_eq!(bi.memory_map().len(), 1);
        assert_eq!(bi.kernel_placement().virtual_base, 0xffff_8000_0000_0000);
        assert!(bi.framebuffer().is_none());
        assert_eq!(bi.records().count(), 4);
    }

    #[test]
    fn rejects_unknown_critical() {
        let mut buf = [0u8; 512];
        let n = {
            let mut w = Writer::new(&mut buf).unwrap();
            w.memory_map_slot(0).unwrap();
            w.record(kind::KERNEL_PLACEMENT, &[&[0u8; 32]]).unwrap();
            w.record(CRITICAL | 77, &[b"x"]).unwrap();
            w.finish()
        };
        assert_eq!(
            BootInfo::parse(&buf[..n]).unwrap_err(),
            Error::UnknownCritical(CRITICAL | 77)
        );
    }

    #[test]
    fn requires_memory_map_and_placement() {
        let mut buf = [0u8; 128];
        let n = Writer::new(&mut buf).unwrap().finish();
        assert_eq!(
            BootInfo::parse(&buf[..n]).unwrap_err(),
            Error::MissingRequired(kind::MEMORY_MAP)
        );
    }

    #[test]
    fn never_panics_on_mutation() {
        let mut base = [0u8; 512];
        let n = sample(&mut base);
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut b = base;
            let at = (x as usize) % n;
            b[at] = (x >> 32) as u8;
            let cut = ((x >> 16) as usize) % (n + 1);
            if let Ok(bi) = BootInfo::parse(&b[..cut]) {
                let _ = bi.memory_map().iter().count();
                let _ = (bi.framebuffer(), bi.stub(), bi.seed(), bi.initial_image());
            }
        }
    }
}
