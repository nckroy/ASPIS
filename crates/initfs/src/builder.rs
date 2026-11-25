// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Writes an image. The output is deterministic: entries are sorted by
//! name, the table follows the header, and padding is zero
//! (ADR 0038, rule 1).

use std::fmt;
use std::string::String;
use std::vec::Vec;

use crate::{
    DIGEST_LEN, ENTRY_LEN, HEADER_LEN, Kind, MAGIC, MIN_ALIGNMENT, NAME_MAX, VERSION_MAJOR,
    VERSION_MINOR, is_valid_name, sha512,
};

/// The name the builder gives the boot manifest's entry. Readers find the
/// manifest by the header's manifest index, not by this name.
pub const MANIFEST_NAME: &str = "manifest";

/// Why an image couldn't be built.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// The alignment isn't a power of two of at least 4096.
    BadAlignment(u32),
    /// The name isn't 1 to 40 characters from `[a-z0-9._-]`.
    BadName(String),
    /// Another entry has this name. [`MANIFEST_NAME`] is reserved.
    DuplicateName(String),
    /// `add` was given [`Kind::Manifest`]; use [`Builder::manifest`].
    ManifestKind,
    /// No manifest was given.
    MissingManifest,
    /// More than `u32::MAX` entries.
    TooManyEntries,
    /// The image would be larger than this machine can address.
    TooLarge,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::BadAlignment(a) => write!(f, "bad alignment {a}"),
            BuildError::BadName(n) => write!(f, "bad entry name {n:?}"),
            BuildError::DuplicateName(n) => write!(f, "duplicate entry name {n:?}"),
            BuildError::ManifestKind => {
                f.write_str("the manifest is given with Builder::manifest, not add")
            }
            BuildError::MissingManifest => f.write_str("the image has no manifest"),
            BuildError::TooManyEntries => f.write_str("too many entries"),
            BuildError::TooLarge => f.write_str("the image is too large"),
        }
    }
}

impl std::error::Error for BuildError {}

struct File {
    name: String,
    kind: Kind,
    data: Vec<u8>,
}

/// Builds an image in memory.
pub struct Builder {
    alignment: u32,
    files: Vec<File>,
    manifest: Option<Vec<u8>>,
}

impl Default for Builder {
    fn default() -> Builder {
        Builder::new(crate::DEFAULT_ALIGNMENT)
    }
}

impl Builder {
    /// A builder for an image with this alignment. `build` checks it.
    pub fn new(alignment: u32) -> Builder {
        Builder {
            alignment,
            files: Vec::new(),
            manifest: None,
        }
    }

    /// Adds an executable or data entry.
    pub fn add(&mut self, name: &str, kind: Kind, data: Vec<u8>) -> Result<(), BuildError> {
        if kind == Kind::Manifest {
            return Err(BuildError::ManifestKind);
        }
        if !is_valid_name(name) {
            return Err(BuildError::BadName(name.into()));
        }
        if name == MANIFEST_NAME || self.files.iter().any(|f| f.name == name) {
            return Err(BuildError::DuplicateName(name.into()));
        }
        self.files.push(File {
            name: name.into(),
            kind,
            data,
        });
        Ok(())
    }

    /// Sets the boot manifest, replacing any earlier one.
    pub fn manifest(&mut self, data: Vec<u8>) {
        self.manifest = Some(data);
    }

    /// Writes the image.
    pub fn build(self) -> Result<Vec<u8>, BuildError> {
        let alignment = self.alignment;
        if !alignment.is_power_of_two() || alignment < MIN_ALIGNMENT {
            return Err(BuildError::BadAlignment(alignment));
        }
        let manifest = self.manifest.ok_or(BuildError::MissingManifest)?;
        let mut files = self.files;
        files.push(File {
            name: MANIFEST_NAME.into(),
            kind: Kind::Manifest,
            data: manifest,
        });
        files.sort_by(|a, b| a.name.cmp(&b.name));

        let count = u32::try_from(files.len()).map_err(|_| BuildError::TooManyEntries)?;
        let manifest_index = files
            .iter()
            .position(|f| f.kind == Kind::Manifest)
            .and_then(|i| u32::try_from(i).ok())
            .ok_or(BuildError::MissingManifest)?;

        let align = u64::from(alignment);
        let table_offset = u64::from(HEADER_LEN);
        let table_end = table_offset
            .checked_add(u64::from(count) * u64::from(ENTRY_LEN))
            .ok_or(BuildError::TooLarge)?;
        let mut cursor = table_end;
        let mut offsets = Vec::with_capacity(files.len());
        let mut image_len = table_end;
        for f in &files {
            let offset = align_up(cursor, align).ok_or(BuildError::TooLarge)?;
            let len = u64::try_from(f.data.len()).map_err(|_| BuildError::TooLarge)?;
            let end = offset.checked_add(len).ok_or(BuildError::TooLarge)?;
            offsets.push(offset);
            cursor = end;
            image_len = image_len.max(offset).max(end);
        }
        let total = usize::try_from(image_len).map_err(|_| BuildError::TooLarge)?;

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&VERSION_MAJOR.to_le_bytes());
        out.extend_from_slice(&VERSION_MINOR.to_le_bytes());
        out.extend_from_slice(&HEADER_LEN.to_le_bytes());
        out.extend_from_slice(&alignment.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&table_offset.to_le_bytes());
        out.extend_from_slice(&manifest_index.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&image_len.to_le_bytes());
        out.extend_from_slice(&[0; 16]);

        for (f, &offset) in files.iter().zip(&offsets) {
            let name_len =
                u16::try_from(f.name.len()).map_err(|_| BuildError::BadName(f.name.clone()))?;
            let len = u64::try_from(f.data.len()).map_err(|_| BuildError::TooLarge)?;
            let digest: [u8; DIGEST_LEN] = sha512(&f.data);
            let mut name = [0u8; NAME_MAX];
            for (slot, b) in name.iter_mut().zip(f.name.bytes()) {
                *slot = b;
            }
            out.extend_from_slice(&name_len.to_le_bytes());
            out.push(f.kind.as_u8());
            out.push(0);
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&offset.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&digest);
            out.extend_from_slice(&name);
        }

        for (f, &offset) in files.iter().zip(&offsets) {
            let offset = usize::try_from(offset).map_err(|_| BuildError::TooLarge)?;
            out.resize(offset, 0);
            out.extend_from_slice(&f.data);
        }
        out.resize(total, 0);
        Ok(out)
    }
}

/// `value` rounded up to a multiple of `align`, a power of two.
fn align_up(value: u64, align: u64) -> Option<u64> {
    let mask = align.checked_sub(1)?;
    value.checked_add(mask).map(|v| v & !mask)
}
