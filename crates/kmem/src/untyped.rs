// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Untyped memory and retype, as in seL4 (ADR 0047, rule 2; ADR 0048,
//! rule 1; kernel specification, "Untyped memory and kernel records").
//!
//! A piece of untyped memory is a naturally aligned power-of-two block, from
//! 4 KiB to 2^47 bytes, with a watermark: everything below the watermark has
//! been retyped, everything above it is free. Retype aligns the watermark up
//! to the object's size and places the objects there, one after another.
//!
//! **Free untyped memory is always zero.** The kernel zeroes RAM untyped
//! memory once at boot, and a reset clears the used part, from the top down
//! in chunks, recording its progress in the watermark as seL4's
//! `resetUntypedCap` does. So a retype never needs to clear. Device untyped
//! memory is MMIO: it is never cleared, and a reset only moves its watermark.
//!
//! C11: seL4 keeps the watermark in the untyped capability. Here it lives in
//! [`Untyped`], which a capability can embed.

use crate::{PAGE_SHIFT, align_down, align_up};

/// The smallest piece: one page.
pub const MIN_BITS: u8 = PAGE_SHIFT as u8;
/// The largest piece: 128 TiB, the direct map's reach.
pub const MAX_BITS: u8 = 47;

/// Splits `[start, end)` into naturally aligned power-of-two pieces, largest
/// first where alignment allows, between [`MIN_BITS`] and [`MAX_BITS`]. The
/// range is first rounded inward to pages. Yields `(base, bits)`.
pub fn decompose(start: u64, end: u64) -> impl Iterator<Item = (u64, u8)> {
    let mut at = align_up(start, 1 << MIN_BITS).unwrap_or(u64::MAX);
    let end = align_down(end, 1 << MIN_BITS);
    core::iter::from_fn(move || {
        if at >= end {
            return None;
        }
        let align = if at == 0 { 64 } else { at.trailing_zeros() };
        let fits = 63 - (end - at).leading_zeros();
        let bits = align.min(fits).min(MAX_BITS as u32) as u8;
        let piece = (at, bits);
        at += 1 << bits;
        Some(piece)
    })
}

/// What a retype makes (C10's objects; later chunks add theirs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectType {
    /// A smaller piece of untyped memory, of `2^bits` bytes.
    Untyped(u8),
    /// A 4 KiB frame.
    Frame4K,
    /// A 2 MiB frame.
    Frame2M,
    /// A 1 GiB frame.
    Frame1G,
    /// A translation table, at any level: 4 KiB.
    PageTable,
    /// An address space: its level-0 table at offset 0, then a 4 KiB kernel
    /// record holding its ASID word, with room for what C15 and C16 add. The
    /// level-0 table needs all 512 entries for a 48-bit lower half, so the
    /// record can't live inside it.
    AddressSpace,
}

/// The size of an address space object, in bits: 8 KiB.
pub const ADDRESS_SPACE_BITS: u8 = 13;

impl ObjectType {
    /// log2 of the object's size in bytes.
    pub const fn size_bits(self) -> u8 {
        match self {
            ObjectType::Untyped(bits) => bits,
            ObjectType::Frame4K | ObjectType::PageTable => 12,
            ObjectType::Frame2M => 21,
            ObjectType::Frame1G => 30,
            ObjectType::AddressSpace => ADDRESS_SPACE_BITS,
        }
    }

    /// Whether device untyped memory can make it. Device memory makes only
    /// frames and smaller device untyped pieces: the kernel never keeps its
    /// own records in MMIO.
    pub const fn allowed_from_device(self) -> bool {
        matches!(
            self,
            ObjectType::Untyped(_)
                | ObjectType::Frame4K
                | ObjectType::Frame2M
                | ObjectType::Frame1G
        )
    }
}

/// Why a retype failed. Nothing was changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetypeError {
    /// A count of zero.
    ZeroCount,
    /// An untyped size outside [`MIN_BITS`] to [`MAX_BITS`].
    BadSize,
    /// The object is larger than the whole piece.
    TooBig,
    /// The free part of the piece can't hold that many.
    NoRoom,
    /// Device untyped memory can't make that type.
    DeviceMemory,
}

/// A piece of untyped memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Untyped {
    base: u64,
    bits: u8,
    device: bool,
    /// Bytes from `base` that have been retyped. During a reset, the bytes
    /// below it that are still to be cleared.
    watermark: u64,
}

impl Untyped {
    /// A free piece of `2^bits` bytes at `base`, which must be aligned to its
    /// size. RAM pieces must already be zero.
    pub const fn new(base: u64, bits: u8, device: bool) -> Option<Self> {
        if bits < MIN_BITS || bits > MAX_BITS || base & ((1 << bits) - 1) != 0 {
            return None;
        }
        Some(Self {
            base,
            bits,
            device,
            watermark: 0,
        })
    }

    pub const fn base(&self) -> u64 {
        self.base
    }

    pub const fn bits(&self) -> u8 {
        self.bits
    }

    pub const fn size(&self) -> u64 {
        1 << self.bits
    }

    pub const fn is_device(&self) -> bool {
        self.device
    }

    pub const fn watermark(&self) -> u64 {
        self.watermark
    }

    /// Bytes still free above the watermark.
    pub const fn free(&self) -> u64 {
        self.size() - self.watermark
    }

    /// Makes `count` objects of type `ty`, and returns the physical address
    /// of the first. They lie one after another, each aligned to its size.
    pub fn retype(&mut self, ty: ObjectType, count: u64) -> Result<u64, RetypeError> {
        if count == 0 {
            return Err(RetypeError::ZeroCount);
        }
        if let ObjectType::Untyped(bits) = ty
            && !(MIN_BITS..=MAX_BITS).contains(&bits)
        {
            return Err(RetypeError::BadSize);
        }
        if self.device && !ty.allowed_from_device() {
            return Err(RetypeError::DeviceMemory);
        }
        let bits = ty.size_bits();
        if bits > self.bits {
            return Err(RetypeError::TooBig);
        }
        let size = 1u64 << bits;
        let start = align_up(self.watermark, size).ok_or(RetypeError::NoRoom)?;
        let end = count
            .checked_mul(size)
            .and_then(|total| start.checked_add(total))
            .filter(|&end| end <= self.size())
            .ok_or(RetypeError::NoRoom)?;
        self.watermark = end;
        Ok(self.base + start)
    }

    /// Begins a reset, once nothing made from the piece is left (C11 checks
    /// that through the derivation tree, as seL4 does). A device piece is
    /// never cleared, so its watermark drops to zero at once. A RAM piece
    /// keeps its watermark, which [`Untyped::reset_step`] lowers.
    pub fn begin_reset(&mut self) {
        if self.device {
            self.watermark = 0;
        }
    }

    /// The next range to clear, from the top down, in chunks of `chunk`
    /// bytes (a power of two, at least a page), or `None` when the reset is
    /// done. The watermark is lowered to the range's start: the caller clears
    /// the range before it next releases the kernel lock, so a reset that
    /// is preempted resumes from the watermark. A device piece yields
    /// nothing: MMIO is never written.
    pub fn reset_step(&mut self, chunk: u64) -> Option<(u64, u64)> {
        assert!(
            chunk.is_power_of_two(),
            "reset chunk must be a power of two"
        );
        if self.device {
            self.watermark = 0;
            return None;
        }
        if self.watermark == 0 {
            return None;
        }
        let start = align_down(self.watermark - 1, chunk);
        let len = self.watermark - start;
        self.watermark = start;
        Some((self.base + start, len))
    }
}
