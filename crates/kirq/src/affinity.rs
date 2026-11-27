// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! A core's affinity: the four 8-bit fields of `MPIDR_EL1` that name it
//! (Aff3, Aff2, Aff1, Aff0), and the forms other registers hold them in.

/// The bits of `MPIDR_EL1` that name a core: Aff3 (39:32), Aff2 (23:16),
/// Aff1 (15:8) and Aff0 (7:0). Bit 31 (RES1), bit 30 (U) and bit 24 (MT)
/// aren't part of it. The device tree's cpu `reg` holds these bits.
pub const MPIDR_AFFINITY_MASK: u64 = 0xff_00ff_ffff;

/// A core's affinity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Affinity {
    pub aff3: u8,
    pub aff2: u8,
    pub aff1: u8,
    pub aff0: u8,
}

impl Affinity {
    /// The affinity in an `MPIDR_EL1` value. The other bits are ignored.
    pub const fn from_mpidr(mpidr: u64) -> Affinity {
        Affinity {
            aff3: (mpidr >> 32) as u8,
            aff2: (mpidr >> 16) as u8,
            aff1: (mpidr >> 8) as u8,
            aff0: mpidr as u8,
        }
    }

    /// The affinity a device-tree cpu node's `reg` gives: the `MPIDR_EL1`
    /// affinity bits. `None` if any other bit is set, as Linux refuses
    /// such a node.
    pub const fn from_dt_reg(reg: u64) -> Option<Affinity> {
        if reg & !MPIDR_AFFINITY_MASK != 0 {
            None
        } else {
            Some(Affinity::from_mpidr(reg))
        }
    }

    /// The affinity in `GICR_TYPER`'s bits 63:32 (Aff3.Aff2.Aff1.Aff0).
    pub const fn from_gicr_typer(typer: u64) -> Affinity {
        Affinity::from_packed((typer >> 32) as u32)
    }

    /// The affinity as `Aff3.Aff2.Aff1.Aff0`, 8 bits each, Aff3 highest.
    pub const fn packed(self) -> u32 {
        (self.aff3 as u32) << 24
            | (self.aff2 as u32) << 16
            | (self.aff1 as u32) << 8
            | self.aff0 as u32
    }

    /// The inverse of [`Affinity::packed`].
    pub const fn from_packed(v: u32) -> Affinity {
        Affinity {
            aff3: (v >> 24) as u8,
            aff2: (v >> 16) as u8,
            aff1: (v >> 8) as u8,
            aff0: v as u8,
        }
    }

    /// The affinity in `MPIDR_EL1`'s layout, with no other bits.
    pub const fn mpidr(self) -> u64 {
        (self.aff3 as u64) << 32
            | (self.aff2 as u64) << 16
            | (self.aff1 as u64) << 8
            | self.aff0 as u64
    }

    /// The value of `GICD_IROUTER<n>` that routes an SPI to this core
    /// alone: Aff3 in 39:32, Aff2 in 23:16, Aff1 in 15:8, Aff0 in 7:0, and
    /// `Interrupt_Routing_Mode` (bit 31) clear.
    pub const fn irouter(self) -> u64 {
        self.mpidr()
    }
}
