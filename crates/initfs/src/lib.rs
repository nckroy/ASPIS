// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The ASPIS initial image, `initfs.img` (ADR 0037).
//!
//! The image is a 64-octet header, a table of 128-octet entries, and each
//! entry's contents at an offset that is a multiple of the image's
//! alignment. All integers are little-endian. `grammars/initfs.abnf` is the
//! normative grammar; this crate's reader enforces the constraints the
//! grammar states in its comments.
//!
//! Header, at offset 0:
//!
//! | Offset | Size | Field                                     |
//! |-------:|-----:|-------------------------------------------|
//! |      0 |    8 | magic, `ASPISIMG`                         |
//! |      8 |    2 | major version, 1                          |
//! |     10 |    2 | minor version, 0                          |
//! |     12 |    4 | header length, 64                         |
//! |     16 |    4 | alignment, a power of two, at least 4096  |
//! |     20 |    4 | entry count                               |
//! |     24 |    8 | table offset, a multiple of 8, at least 64 |
//! |     32 |    4 | manifest index, less than the entry count |
//! |     36 |    4 | reserved, 0                               |
//! |     40 |    8 | image length, the file's length           |
//! |     48 |   16 | reserved, 0                               |
//!
//! Entry, 128 octets each, at the table offset:
//!
//! | Offset | Size | Field                                            |
//! |-------:|-----:|--------------------------------------------------|
//! |      0 |    2 | name length, 1 to 40                             |
//! |      2 |    1 | kind: 1 executable, 2 data, 3 manifest           |
//! |      3 |    1 | flags, 0                                         |
//! |      4 |    4 | reserved, 0                                      |
//! |      8 |    8 | offset, a multiple of the alignment              |
//! |     16 |    8 | length                                           |
//! |     24 |   64 | SHA-512 digest of the entry's contents           |
//! |     88 |   40 | name, `[a-z0-9._-]`, zero after the name length  |
//!
//! [`Image::parse`] never panics, whatever the input. It doesn't check the
//! entries' digests: [`Entry::verify`] does, before an entry is used
//! (ADR 0037, rule 7).
//!
//! The `std` feature adds `Builder`, which writes an image.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
mod builder;
#[cfg(feature = "std")]
pub use builder::{BuildError, Builder, MANIFEST_NAME};

use core::fmt;
use sha2::{Digest, Sha512};

/// The magic at offset 0.
pub const MAGIC: [u8; 8] = *b"ASPISIMG";
/// The major format version this crate reads and writes.
pub const VERSION_MAJOR: u16 = 1;
/// The minor format version this crate writes. A reader accepts any minor.
pub const VERSION_MINOR: u16 = 0;
/// The header's length in octets.
pub const HEADER_LEN: u32 = 64;
/// One table entry's length in octets.
pub const ENTRY_LEN: u32 = 128;
/// The longest entry name, in octets.
pub const NAME_MAX: usize = 40;
/// The length of a SHA-512 digest, in octets.
pub const DIGEST_LEN: usize = 64;
/// The smallest alignment an image may declare.
pub const MIN_ALIGNMENT: u32 = 4096;
/// The alignment the builder uses: 64 KiB suits any translation granule
/// (ADR 0037, rule 1).
pub const DEFAULT_ALIGNMENT: u32 = 65536;

/// The table offset must be a multiple of this.
const TABLE_ALIGN: u64 = 8;
/// One table entry's length, as an array length.
const ENTRY_SIZE: usize = ENTRY_LEN as usize;

/// An entry's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Kind {
    /// A static ELF64 AArch64 program.
    Executable = 1,
    /// Data.
    Data = 2,
    /// The boot manifest. Its format is the root server's decision (D40).
    Manifest = 3,
}

impl Kind {
    /// The kind with this code, if there is one.
    pub const fn from_u8(code: u8) -> Option<Kind> {
        match code {
            1 => Some(Kind::Executable),
            2 => Some(Kind::Data),
            3 => Some(Kind::Manifest),
            _ => None,
        }
    }

    /// The kind's code in the entry table.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// An image's format version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
}

/// Why an image was rejected. Entry errors give the entry's index in the
/// table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The buffer is shorter than the header.
    Truncated,
    /// The magic isn't `ASPISIMG`.
    BadMagic,
    /// The major version isn't 1.
    UnsupportedVersion { major: u16, minor: u16 },
    /// The header length isn't 64.
    BadHeaderLength(u32),
    /// The alignment isn't a power of two of at least 4096.
    BadAlignment(u32),
    /// A reserved header field isn't zero.
    ReservedNotZero,
    /// The declared image length isn't the buffer's length.
    LengthMismatch { declared: u64, actual: u64 },
    /// The table offset is less than 64 or not a multiple of 8.
    BadTableOffset(u64),
    /// The entry table runs past the end of the image.
    TableOutOfBounds,
    /// The manifest index isn't less than the entry count.
    BadManifestIndex(u32),
    /// The name length isn't 1 to 40.
    BadNameLength { index: u32, len: u16 },
    /// The name isn't valid UTF-8.
    NameNotUtf8 { index: u32 },
    /// The name has a character outside `[a-z0-9._-]`.
    BadNameCharacter { index: u32 },
    /// An octet of the name field after the name isn't zero.
    NamePaddingNotZero { index: u32 },
    /// An earlier entry has the same name.
    DuplicateName { index: u32 },
    /// The kind isn't 1, 2 or 3.
    UnknownKind { index: u32, kind: u8 },
    /// The flags aren't zero.
    FlagsNotZero { index: u32, flags: u8 },
    /// The entry's reserved field isn't zero.
    EntryReservedNotZero { index: u32 },
    /// The entry's offset isn't a multiple of the alignment.
    Misaligned { index: u32 },
    /// The entry's contents run past the end of the image.
    EntryOutOfBounds { index: u32 },
    /// The entry's contents overlap the header.
    EntryOverlapsHeader { index: u32 },
    /// The entry's contents overlap the entry table.
    EntryOverlapsTable { index: u32 },
    /// The entry starts before the previous entry ends: the entries overlap,
    /// or aren't in ascending offset order.
    EntryOutOfOrder { index: u32 },
    /// The entry is a manifest but isn't at the manifest index, or it is at
    /// the manifest index but isn't a manifest.
    ManifestMisplaced { index: u32 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::Truncated => f.write_str("image is shorter than its header"),
            Error::BadMagic => f.write_str("bad magic"),
            Error::UnsupportedVersion { major, minor } => {
                write!(f, "unsupported format version {major}.{minor}")
            }
            Error::BadHeaderLength(len) => write!(f, "bad header length {len}"),
            Error::BadAlignment(a) => write!(f, "bad alignment {a}"),
            Error::ReservedNotZero => f.write_str("reserved header field is not zero"),
            Error::LengthMismatch { declared, actual } => {
                write!(f, "image length is {declared} but the buffer is {actual}")
            }
            Error::BadTableOffset(o) => write!(f, "bad table offset {o}"),
            Error::TableOutOfBounds => f.write_str("entry table runs past the image"),
            Error::BadManifestIndex(i) => write!(f, "manifest index {i} is out of range"),
            Error::BadNameLength { index, len } => {
                write!(f, "entry {index}: bad name length {len}")
            }
            Error::NameNotUtf8 { index } => write!(f, "entry {index}: name is not UTF-8"),
            Error::BadNameCharacter { index } => {
                write!(f, "entry {index}: name has a character outside [a-z0-9._-]")
            }
            Error::NamePaddingNotZero { index } => {
                write!(f, "entry {index}: name padding is not zero")
            }
            Error::DuplicateName { index } => write!(f, "entry {index}: duplicate name"),
            Error::UnknownKind { index, kind } => {
                write!(f, "entry {index}: unknown kind {kind}")
            }
            Error::FlagsNotZero { index, flags } => {
                write!(f, "entry {index}: flags {flags:#04x} are not zero")
            }
            Error::EntryReservedNotZero { index } => {
                write!(f, "entry {index}: reserved field is not zero")
            }
            Error::Misaligned { index } => write!(f, "entry {index}: offset is misaligned"),
            Error::EntryOutOfBounds { index } => {
                write!(f, "entry {index}: contents run past the image")
            }
            Error::EntryOverlapsHeader { index } => {
                write!(f, "entry {index}: contents overlap the header")
            }
            Error::EntryOverlapsTable { index } => {
                write!(f, "entry {index}: contents overlap the entry table")
            }
            Error::EntryOutOfOrder { index } => {
                write!(f, "entry {index}: starts before the previous entry ends")
            }
            Error::ManifestMisplaced { index } => {
                write!(
                    f,
                    "entry {index}: manifest kind does not match the manifest index"
                )
            }
        }
    }
}

impl core::error::Error for Error {}

/// Whether `name` is a valid entry name: 1 to 40 characters from
/// `[a-z0-9._-]`.
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= NAME_MAX && name.bytes().all(is_name_char)
}

fn is_name_char(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-')
}

/// The SHA-512 of a whole image, as `aspis.efi` pins it
/// (ADR 0040, rule 1).
pub fn image_digest(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    sha512(bytes)
}

fn sha512(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    Sha512::digest(bytes).into()
}

/// One entry of a parsed image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    /// The entry's name.
    pub name: &'a str,
    /// The entry's kind.
    pub kind: Kind,
    /// The offset of the entry's contents in the image.
    pub offset: u64,
    /// The entry's contents.
    pub data: &'a [u8],
    /// The SHA-512 digest the table records for the contents.
    pub digest: &'a [u8; DIGEST_LEN],
}

impl Entry<'_> {
    /// Whether the SHA-512 of the contents equals the recorded digest.
    pub fn verify(&self) -> bool {
        sha512(self.data) == *self.digest
    }
}

/// A parsed image. Every constraint but the digests has been checked.
#[derive(Clone, Copy, Debug)]
pub struct Image<'a> {
    bytes: &'a [u8],
    version: Version,
    alignment: u32,
    entry_count: u32,
    table_offset: u64,
    manifest_index: u32,
    table: &'a [[u8; ENTRY_SIZE]],
    manifest: Entry<'a>,
}

impl<'a> Image<'a> {
    /// Parses and checks an image. It never panics.
    pub fn parse(bytes: &'a [u8]) -> Result<Image<'a>, Error> {
        let h = Header::read(bytes).ok_or(Error::Truncated)?;
        if h.magic != &MAGIC {
            return Err(Error::BadMagic);
        }
        if h.major != VERSION_MAJOR {
            return Err(Error::UnsupportedVersion {
                major: h.major,
                minor: h.minor,
            });
        }
        if h.header_len != HEADER_LEN {
            return Err(Error::BadHeaderLength(h.header_len));
        }
        if !h.alignment.is_power_of_two() || h.alignment < MIN_ALIGNMENT {
            return Err(Error::BadAlignment(h.alignment));
        }
        if h.reserved0 != 0 || h.reserved1.iter().any(|&b| b != 0) {
            return Err(Error::ReservedNotZero);
        }
        let actual = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if h.image_len != actual {
            return Err(Error::LengthMismatch {
                declared: h.image_len,
                actual,
            });
        }
        if h.table_offset < u64::from(HEADER_LEN) || h.table_offset % TABLE_ALIGN != 0 {
            return Err(Error::BadTableOffset(h.table_offset));
        }
        // At most 2^32 * 2^7 octets, so this can't overflow.
        let table_len = u64::from(h.entry_count) * u64::from(ENTRY_LEN);
        let table_end = h
            .table_offset
            .checked_add(table_len)
            .filter(|&end| end <= actual)
            .ok_or(Error::TableOutOfBounds)?;
        let (table, _) = range(bytes, h.table_offset, table_end)
            .ok_or(Error::TableOutOfBounds)?
            .as_chunks::<ENTRY_SIZE>();
        if h.manifest_index >= h.entry_count {
            return Err(Error::BadManifestIndex(h.manifest_index));
        }

        let mut manifest = None;
        let mut prev_end = 0u64;
        for (i, chunk) in table.iter().enumerate() {
            let index = u32::try_from(i).unwrap_or(u32::MAX);
            let entry = decode_entry(bytes, chunk, index, h.alignment)?;
            let len = u64::try_from(entry.data.len()).unwrap_or(u64::MAX);
            // decode_entry checked that the contents lie inside the image.
            let end = entry.offset.saturating_add(len);
            if entry.offset < prev_end {
                return Err(Error::EntryOutOfOrder { index });
            }
            if len > 0 {
                if entry.offset < u64::from(HEADER_LEN) {
                    return Err(Error::EntryOverlapsHeader { index });
                }
                if entry.offset < table_end && h.table_offset < end {
                    return Err(Error::EntryOverlapsTable { index });
                }
            }
            let earlier = table.get(..i).unwrap_or_default();
            if earlier
                .iter()
                .any(|other| raw_name(other) == entry.name.as_bytes())
            {
                return Err(Error::DuplicateName { index });
            }
            let is_manifest = entry.kind == Kind::Manifest;
            if is_manifest != (index == h.manifest_index) {
                return Err(Error::ManifestMisplaced { index });
            }
            if is_manifest {
                manifest = Some(entry);
            }
            prev_end = end;
        }
        let manifest = manifest.ok_or(Error::BadManifestIndex(h.manifest_index))?;

        Ok(Image {
            bytes,
            version: Version {
                major: h.major,
                minor: h.minor,
            },
            alignment: h.alignment,
            entry_count: h.entry_count,
            table_offset: h.table_offset,
            manifest_index: h.manifest_index,
            table,
            manifest,
        })
    }

    /// The image's format version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The alignment of every entry's offset.
    pub fn alignment(&self) -> u32 {
        self.alignment
    }

    /// The number of entries.
    pub fn entry_count(&self) -> u32 {
        self.entry_count
    }

    /// The offset of the entry table.
    pub fn table_offset(&self) -> u64 {
        self.table_offset
    }

    /// The index of the boot manifest's entry.
    pub fn manifest_index(&self) -> u32 {
        self.manifest_index
    }

    /// The whole image.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The SHA-512 of the whole image.
    pub fn digest(&self) -> [u8; DIGEST_LEN] {
        image_digest(self.bytes)
    }

    /// The entries, in table order, which is ascending offset order.
    pub fn entries(&self) -> Entries<'a> {
        Entries {
            bytes: self.bytes,
            chunks: self.table.iter(),
            alignment: self.alignment,
            index: 0,
        }
    }

    /// The entry with this name, if there is one.
    pub fn entry(&self, name: &str) -> Option<Entry<'a>> {
        self.entries().find(|e| e.name == name)
    }

    /// The boot manifest's entry.
    pub fn manifest(&self) -> Entry<'a> {
        self.manifest
    }
}

/// An iterator over a parsed image's entries.
#[derive(Clone, Debug)]
pub struct Entries<'a> {
    bytes: &'a [u8],
    chunks: core::slice::Iter<'a, [u8; ENTRY_SIZE]>,
    alignment: u32,
    index: u32,
}

impl<'a> Iterator for Entries<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Entry<'a>> {
        let chunk = self.chunks.next()?;
        let index = self.index;
        self.index = self.index.saturating_add(1);
        // Image::parse checked every entry, so this doesn't fail.
        decode_entry(self.bytes, chunk, index, self.alignment).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.chunks.len()))
    }
}

/// Reads fixed-size little-endian fields from the front of a slice.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn take<const N: usize>(&mut self) -> Option<&'a [u8; N]> {
        let (head, tail) = self.0.split_first_chunk::<N>()?;
        self.0 = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|&[b]| b)
    }

    fn u16(&mut self) -> Option<u16> {
        self.take().copied().map(u16::from_le_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take().copied().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.take().copied().map(u64::from_le_bytes)
    }
}

struct Header<'a> {
    magic: &'a [u8; 8],
    major: u16,
    minor: u16,
    header_len: u32,
    alignment: u32,
    entry_count: u32,
    table_offset: u64,
    manifest_index: u32,
    reserved0: u32,
    image_len: u64,
    reserved1: &'a [u8; 16],
}

impl<'a> Header<'a> {
    fn read(bytes: &'a [u8]) -> Option<Header<'a>> {
        let mut f = Fields(bytes);
        Some(Header {
            magic: f.take()?,
            major: f.u16()?,
            minor: f.u16()?,
            header_len: f.u32()?,
            alignment: f.u32()?,
            entry_count: f.u32()?,
            table_offset: f.u64()?,
            manifest_index: f.u32()?,
            reserved0: f.u32()?,
            image_len: f.u64()?,
            reserved1: f.take()?,
        })
    }
}

struct RawEntry<'a> {
    name_len: u16,
    kind: u8,
    flags: u8,
    reserved: u32,
    offset: u64,
    length: u64,
    digest: &'a [u8; DIGEST_LEN],
    name: &'a [u8; NAME_MAX],
}

impl<'a> RawEntry<'a> {
    fn read(bytes: &'a [u8]) -> Option<RawEntry<'a>> {
        let mut f = Fields(bytes);
        Some(RawEntry {
            name_len: f.u16()?,
            kind: f.u8()?,
            flags: f.u8()?,
            reserved: f.u32()?,
            offset: f.u64()?,
            length: f.u64()?,
            digest: f.take()?,
            name: f.take()?,
        })
    }
}

/// The octets `[start, end)` of `bytes`, if they are all inside it.
fn range(bytes: &[u8], start: u64, end: u64) -> Option<&[u8]> {
    bytes.get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
}

/// The name octets of an entry that has already been checked.
fn raw_name(chunk: &[u8; ENTRY_SIZE]) -> &[u8] {
    match RawEntry::read(chunk) {
        Some(raw) => raw
            .name
            .get(..usize::from(raw.name_len))
            .unwrap_or(raw.name),
        None => &[],
    }
}

/// Decodes and checks one entry on its own. The checks across entries are
/// in `Image::parse`.
fn decode_entry<'a>(
    bytes: &'a [u8],
    chunk: &'a [u8; ENTRY_SIZE],
    index: u32,
    alignment: u32,
) -> Result<Entry<'a>, Error> {
    let raw = RawEntry::read(chunk).ok_or(Error::TableOutOfBounds)?;
    let (name, padding) = raw
        .name
        .split_at_checked(usize::from(raw.name_len))
        .filter(|(name, _)| !name.is_empty())
        .ok_or(Error::BadNameLength {
            index,
            len: raw.name_len,
        })?;
    if padding.iter().any(|&b| b != 0) {
        return Err(Error::NamePaddingNotZero { index });
    }
    let name = core::str::from_utf8(name).map_err(|_| Error::NameNotUtf8 { index })?;
    if !name.bytes().all(is_name_char) {
        return Err(Error::BadNameCharacter { index });
    }
    let kind = Kind::from_u8(raw.kind).ok_or(Error::UnknownKind {
        index,
        kind: raw.kind,
    })?;
    if raw.flags != 0 {
        return Err(Error::FlagsNotZero {
            index,
            flags: raw.flags,
        });
    }
    if raw.reserved != 0 {
        return Err(Error::EntryReservedNotZero { index });
    }
    if raw.offset % u64::from(alignment.max(1)) != 0 {
        return Err(Error::Misaligned { index });
    }
    let data = raw
        .offset
        .checked_add(raw.length)
        .and_then(|end| range(bytes, raw.offset, end))
        .ok_or(Error::EntryOutOfBounds { index })?;
    Ok(Entry {
        name,
        kind,
        offset: raw.offset,
        data,
        digest: raw.digest,
    })
}
