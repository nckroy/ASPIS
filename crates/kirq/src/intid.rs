// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Interrupt IDs (Arm GIC architecture specification, "INTIDs"):
//!
//! | INTIDs | Kind |
//! |---|---|
//! | 0 to 15 | Software-generated interrupts (SGIs), per core |
//! | 16 to 31 | Private peripheral interrupts (PPIs), per core |
//! | 32 to 1019 | Shared peripheral interrupts (SPIs) |
//! | 1020 to 1023 | Special: no interrupt was acknowledged |
//! | 8192 and up | Locality-specific peripheral interrupts (LPIs, GICv3) |

/// An interrupt ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Intid(pub u32);

/// The first PPI.
pub const PPI_BASE: u32 = 16;
/// The first SPI.
pub const SPI_BASE: u32 = 32;
/// The last SPI.
pub const SPI_LAST: u32 = 1019;
/// The first special INTID.
pub const SPECIAL_FIRST: u32 = 1020;
/// The special INTID that says nothing is pending at a priority the CPU
/// interface would signal.
pub const SPURIOUS: u32 = 1023;
/// The first LPI.
pub const LPI_BASE: u32 = 8192;

impl Intid {
    /// PPI `n`, for `n` below 16.
    pub const fn ppi(n: u32) -> Option<Intid> {
        if n < 16 {
            Some(Intid(PPI_BASE + n))
        } else {
            None
        }
    }

    /// SPI `n`, for `n` from 0 to 987.
    pub const fn spi(n: u32) -> Option<Intid> {
        if n <= SPI_LAST - SPI_BASE {
            Some(Intid(SPI_BASE + n))
        } else {
            None
        }
    }

    pub const fn is_sgi(self) -> bool {
        self.0 < PPI_BASE
    }

    pub const fn is_ppi(self) -> bool {
        self.0 >= PPI_BASE && self.0 < SPI_BASE
    }

    /// A per-core interrupt: an SGI or a PPI, whose state is banked per
    /// core (in the GICv3's redistributor).
    pub const fn is_private(self) -> bool {
        self.0 < SPI_BASE
    }

    pub const fn is_spi(self) -> bool {
        self.0 >= SPI_BASE && self.0 <= SPI_LAST
    }

    /// 1020 to 1023: an acknowledge that returns one of these took no
    /// interrupt, and needs no end of interrupt.
    pub const fn is_special(self) -> bool {
        self.0 >= SPECIAL_FIRST && self.0 < 1024
    }

    pub const fn is_lpi(self) -> bool {
        self.0 >= LPI_BASE
    }
}
