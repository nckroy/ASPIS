// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Interface object IDs, written `reserved(n)` or `hex(...)` until D34
//! fixes the ID text form (ADR 0067, rule 2; L01, L02).

use crate::ast::IdLit;

/// The 32-octet object ID that `reserved(n)` stands for, until D35 gives
/// the reserved authority's value (L02).
///
/// The interim value is ADR 0001's layout with the nil UUID (16 zero
/// octets) as the authority, n as the sequence number (u64, big-endian),
/// version 1, class 0, and a zero random part. This function is the only
/// place that knows it, so D35 changes one place. The canonical form keeps
/// `reserved(n)`, not these octets, so D35's authority value changes no
/// lock. A well-known number n that D35 assigns differently is a source
/// edit, made with a rewrite of the published locks.
pub fn reserved(n: u64) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[16..24].copy_from_slice(&n.to_be_bytes());
    id[24] = 0x01;
    id
}

/// The octets an `id-lit` stands for, or None when `reserved(n)`'s n
/// isn't a u64.
pub fn octets(lit: &IdLit) -> Option<[u8; 32]> {
    match lit {
        IdLit::Reserved(n) => n.value.and_then(|v| u64::try_from(v).ok()).map(reserved),
        IdLit::Hex(id) => Some(*id),
    }
}
