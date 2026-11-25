// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Loading the kernel's ELF payload (ADR 0035, rule 3).
//!
//! The kernel is a static, position-independent ELF64 for AArch64. The stub
//! copies its loadable segments to a physical region, zeroes what the file
//! doesn't fill, and applies its `R_AARCH64_RELATIVE` relocations for the
//! virtual base it chose. The kernel never relocates itself.

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: u64 = 0;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_RELR: u64 = 36;
const R_AARCH64_RELATIVE: u32 = 1027;
const EM_AARCH64: u16 = 183;
const ET_DYN: u16 = 3;

/// The fields are read through `Debug`, in the stub's messages.
#[derive(Debug)]
#[allow(dead_code)]
pub enum Error {
    NotElf,
    Unsupported(&'static str),
    Truncated,
    BadSegment,
    BadRelocation(u32),
}

/// A parsed kernel image, before it is loaded.
pub struct Kernel<'a> {
    file: &'a [u8],
    phoff: usize,
    phnum: usize,
    pub entry: u64,
    /// The lowest virtual address of any loadable segment: the link base.
    pub link_base: u64,
    /// The span of the loadable segments, in bytes.
    pub span: u64,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .ok_or(Error::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .ok_or(Error::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

struct Segment {
    kind: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

impl<'a> Kernel<'a> {
    pub fn parse(file: &'a [u8]) -> Result<Self, Error> {
        if file.get(0..4) != Some(b"\x7fELF") {
            return Err(Error::NotElf);
        }
        if file[4] != 2 || file[5] != 1 {
            return Err(Error::Unsupported("not ELF64 little-endian"));
        }
        if u16_at(file, 16)? != ET_DYN {
            return Err(Error::Unsupported("not position-independent (ET_DYN)"));
        }
        if u16_at(file, 18)? != EM_AARCH64 {
            return Err(Error::Unsupported("not AArch64"));
        }
        let entry = u64_at(file, 24)?;
        let phoff = u64_at(file, 32)? as usize;
        let phentsize = u16_at(file, 54)? as usize;
        let phnum = u16_at(file, 56)? as usize;
        if phentsize != 56 {
            return Err(Error::Unsupported("program header size"));
        }
        let mut k = Self {
            file,
            phoff,
            phnum,
            entry,
            link_base: u64::MAX,
            span: 0,
        };
        let mut end = 0u64;
        for i in 0..phnum {
            let s = k.segment(i)?;
            if s.kind != PT_LOAD {
                continue;
            }
            if s.filesz > s.memsz {
                return Err(Error::BadSegment);
            }
            let seg_end = s.vaddr.checked_add(s.memsz).ok_or(Error::BadSegment)?;
            let file_end = s.offset.checked_add(s.filesz).ok_or(Error::BadSegment)?;
            if file_end > file.len() as u64 {
                return Err(Error::Truncated);
            }
            k.link_base = k.link_base.min(s.vaddr);
            end = end.max(seg_end);
        }
        if k.link_base == u64::MAX || !k.link_base.is_multiple_of(4096) {
            return Err(Error::BadSegment);
        }
        k.span = (end - k.link_base + 4095) & !4095;
        if entry < k.link_base || entry >= end {
            return Err(Error::BadSegment);
        }
        Ok(k)
    }

    fn segment(&self, i: usize) -> Result<Segment, Error> {
        let at = self.phoff + i * 56;
        Ok(Segment {
            kind: u32_at(self.file, at)?,
            offset: u64_at(self.file, at + 8)?,
            vaddr: u64_at(self.file, at + 16)?,
            filesz: u64_at(self.file, at + 32)?,
            memsz: u64_at(self.file, at + 40)?,
        })
    }

    /// Copies the segments into `dest` (which spans `self.span` bytes and is
    /// already zeroed) and relocates the image for `virtual_base`.
    pub fn load(&self, dest: &mut [u8], virtual_base: u64) -> Result<(), Error> {
        let slide = virtual_base.wrapping_sub(self.link_base);
        let mut dynamic = None;
        for i in 0..self.phnum {
            let s = self.segment(i)?;
            match s.kind {
                PT_LOAD => {
                    let at = (s.vaddr - self.link_base) as usize;
                    let src = &self.file[s.offset as usize..(s.offset + s.filesz) as usize];
                    dest.get_mut(at..at + src.len())
                        .ok_or(Error::BadSegment)?
                        .copy_from_slice(src);
                }
                PT_DYNAMIC => dynamic = Some(s),
                _ => {}
            }
        }
        let Some(d) = dynamic else {
            return Ok(());
        };
        // Read the dynamic table from the loaded image.
        let (mut rela, mut relasz, mut relaent) = (None, 0u64, 24u64);
        let base = (d.vaddr - self.link_base) as usize;
        let mut at = base;
        loop {
            let tag = u64_at(dest, at)?;
            let val = u64_at(dest, at + 8)?;
            match tag {
                DT_NULL => break,
                DT_RELA => rela = Some(val),
                DT_RELASZ => relasz = val,
                DT_RELAENT => relaent = val,
                DT_RELR => return Err(Error::Unsupported("DT_RELR relocations")),
                _ => {}
            }
            at += 16;
            if at >= base + d.memsz as usize {
                break;
            }
        }
        let Some(rela) = rela else { return Ok(()) };
        if relaent != 24 {
            return Err(Error::Unsupported("RELA entry size"));
        }
        let table = (rela - self.link_base) as usize;
        for n in 0..(relasz / 24) as usize {
            let r = table + n * 24;
            let offset = u64_at(dest, r)?;
            let info = u64_at(dest, r + 8)?;
            let addend = u64_at(dest, r + 16)?;
            let kind = info as u32;
            if kind != R_AARCH64_RELATIVE {
                return Err(Error::BadRelocation(kind));
            }
            let slot = offset
                .checked_sub(self.link_base)
                .ok_or(Error::BadRelocation(kind))? as usize;
            dest.get_mut(slot..slot + 8)
                .ok_or(Error::BadRelocation(kind))?
                .copy_from_slice(&addend.wrapping_add(slide).to_le_bytes());
        }
        Ok(())
    }
}
