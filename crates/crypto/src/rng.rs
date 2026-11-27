// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The adapter that hands ML-DSA its hedge (feature `ml-dsa`).
//!
//! ml-dsa takes hedged signing's 32 random octets (FIPS 204, Algorithm 2)
//! only from a `TryCryptoRng`. [`OneShot`] is that trait over the caller's
//! 32 octets, so the randomness stays an input (ADR 0069, rule 3): it is
//! no source of randomness, and gives its octets once. Any other request
//! is refused, so a library change that drew more, or drew differently,
//! would fail signing loudly ([`crate::Error::SigningFailed`]) rather than
//! sign with octets nobody chose.

use core::fmt;

use ml_dsa::signature::rand_core::{TryCryptoRng, TryRng};
use zeroize::Zeroize;

/// The caller's 32 octets, handed over once.
pub(crate) struct OneShot {
    octets: [u8; 32],
    used: bool,
}

impl OneShot {
    pub(crate) fn new(octets: &[u8; 32]) -> Self {
        Self {
            octets: *octets,
            used: false,
        }
    }
}

impl Drop for OneShot {
    fn drop(&mut self) {
        self.octets.zeroize();
    }
}

/// Why [`OneShot`] refused a request: it was asked twice, or for anything
/// but 32 octets.
#[derive(Debug)]
pub(crate) struct Refused;

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the hedge is 32 octets, given once")
    }
}

impl core::error::Error for Refused {}

impl TryRng for OneShot {
    type Error = Refused;

    fn try_next_u32(&mut self) -> Result<u32, Refused> {
        Err(Refused)
    }

    fn try_next_u64(&mut self) -> Result<u64, Refused> {
        Err(Refused)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Refused> {
        if self.used || dst.len() != self.octets.len() {
            return Err(Refused);
        }
        dst.copy_from_slice(&self.octets);
        self.octets.zeroize();
        self.used = true;
        Ok(())
    }
}

/// Marks the adapter as fit for key material, which it is only because
/// its octets come from the entropy service (ADR 0021, rule 1).
impl TryCryptoRng for OneShot {}
