// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The error envelope's codec (ADR 0065, rule 1; docs/design/
//! call-language.md, "The error envelope").
//!
//! The envelope is an open struct: outcome (u8, closed), disposition (u8,
//! open), the interface ID, the major, the code (not 0) and the detail
//! (`octets`), then a tail whose tags are 7 (`cause`, another envelope)
//! and 8 (`retry_after`, a u64 of nanoseconds). Later minors of
//! `aspis.rpc` may add tail fields from 9, which are preserved.
//!
//! The whole envelope, causes included, is at most [`MAX_ENVELOPE`]
//! octets, and causes nest at most [`MAX_CAUSE_DEPTH`] deep: the
//! outermost cause is depth 1, so a chain holds at most four envelopes.
//! Every decoder enforces both. C18 adds the hand-written
//! `call-header.abnf` rules and vectors for the envelope; this codec is
//! what stubs and dispatchers use.

use crate::{
    error::{Disposition, ErrorKey, Outcome, RawError},
    view::Unknown,
    wire::{DecodeCx, DecodeError, EncodeError, Mode, Reader, Tail, Writer},
};

/// The largest envelope, causes included.
pub const MAX_ENVELOPE: usize = 768;
/// How deep causes nest.
pub const MAX_CAUSE_DEPTH: usize = 3;

const CAUSE: u16 = 7;
const RETRY_AFTER: u16 = 8;
/// The envelope's fields known in `aspis.rpc` 1.0: six required, then
/// `cause` and `retry_after`.
const KNOWN: usize = 8;

/// Decodes an envelope, checking its causes too.
pub fn decode(octets: &[u8]) -> Result<RawError<'_>, DecodeError> {
    decode_at(octets, 0)
}

fn decode_at(octets: &[u8], depth: usize) -> Result<RawError<'_>, DecodeError> {
    if octets.len() > MAX_ENVELOPE {
        return Err(DecodeError::Malformed);
    }
    let mut r = Reader::new(octets);
    let outcome = Outcome::from_u8(r.u8()?).ok_or(DecodeError::Malformed)?;
    let disposition = Disposition(r.u8()?);
    let interface = r.id()?;
    let major = r.u16()?;
    let code = r.u16()?;
    if code == 0 {
        return Err(DecodeError::Malformed);
    }
    let detail = r.octets()?;
    let mut cx = DecodeCx::new(0, Mode::Tolerant, 0);
    let mut tail = Tail::read(&mut r, KNOWN)?;
    let (mut cause, mut retry_after) = (None, None);
    while let Some((tag, v)) = tail.next(&mut r, &mut cx)? {
        match tag {
            CAUSE => {
                if depth >= MAX_CAUSE_DEPTH {
                    return Err(DecodeError::Malformed);
                }
                decode_at(v, depth + 1)?;
                cause = Some(v);
            }
            RETRY_AFTER => {
                let b: [u8; 8] = v.try_into().map_err(|_| DecodeError::Malformed)?;
                retry_after = Some(u64::from_be_bytes(b));
            }
            // A required field's position.
            _ => return Err(DecodeError::Malformed),
        }
    }
    let unknown = tail.finish(&r);
    if !r.is_empty() {
        return Err(DecodeError::Malformed);
    }
    Ok(RawError {
        octets,
        outcome,
        disposition,
        key: ErrorKey {
            interface,
            major,
            code,
        },
        detail,
        cause,
        retry_after,
        unknown,
    })
}

/// What an envelope to encode holds.
pub struct Fields<'a> {
    pub outcome: Outcome,
    pub disposition: Disposition,
    pub key: ErrorKey,
    /// Another envelope's octets: a forwarded error, kept whole where it
    /// fits. [`encode`] truncates its chain of causes, innermost first,
    /// to keep within [`MAX_CAUSE_DEPTH`] and [`MAX_ENVELOPE`].
    pub cause: Option<&'a [u8]>,
    pub retry_after: Option<u64>,
}

/// Encodes an envelope, with its detail struct from `detail`.
///
/// The cause must be a valid envelope, or this is
/// [`EncodeError::Malformed`]. Causes are what the runtime drops or
/// truncates ("The error envelope"): the cause keeps at most
/// [`MAX_CAUSE_DEPTH`] envelopes, so a forwarded chain of four loses its
/// innermost one, and then loses more, innermost first, until the whole
/// fits [`MAX_ENVELOPE`] octets. A cause kept whole is copied unchanged;
/// a truncated one re-encodes its envelopes with their own fields and
/// preserved tails. Without a cause an envelope always fits, since the
/// compiler bounds every detail; a detail over the bound is
/// [`EncodeError::Bounds`].
pub fn encode(
    w: &mut Writer<'_>,
    f: &Fields<'_>,
    detail: &mut dyn FnMut(&mut Writer<'_>) -> Result<(), EncodeError>,
) -> Result<(), EncodeError> {
    if f.key.code == 0 {
        return Err(EncodeError::Bounds);
    }
    let cause = match f.cause {
        Some(c) => Some(decode(c).map_err(|_| EncodeError::Malformed)?),
        None => None,
    };
    let none = Unknown::default();
    let mut keep = cause.as_ref().map_or(Ok(0), chain)?.min(MAX_CAUSE_DEPTH);
    loop {
        let c = match &cause {
            Some(c) if keep > 0 => Some((c, keep)),
            _ => None,
        };
        let mut m = Writer::measure();
        write(&mut m, f, c, &none, detail)?;
        if m.len() <= MAX_ENVELOPE {
            return write(w, f, c, &none, detail);
        }
        if keep == 0 {
            return Err(EncodeError::Bounds);
        }
        keep -= 1;
    }
}

/// How many envelopes a valid envelope's chain holds, itself included.
fn chain(e: &RawError<'_>) -> Result<usize, EncodeError> {
    match e.cause {
        Some(c) => Ok(1 + chain(&decode(c).map_err(|_| EncodeError::Malformed)?)?),
        None => Ok(1),
    }
}

/// Writes an envelope. `cause` is a valid envelope and how many of its
/// chain's envelopes to keep, at least one.
fn write(
    w: &mut Writer<'_>,
    f: &Fields<'_>,
    cause: Option<(&RawError<'_>, usize)>,
    unknown: &Unknown<'_>,
    detail: &mut dyn FnMut(&mut Writer<'_>) -> Result<(), EncodeError>,
) -> Result<(), EncodeError> {
    w.u8(f.outcome as u8)?;
    w.u8(f.disposition.0)?;
    w.put(&f.key.interface)?;
    w.u16(f.key.major)?;
    w.u16(f.key.code)?;
    let at = w.begin_len()?;
    detail(w)?;
    w.end_len(at)?;
    let mut tail = w.tail()?;
    if let Some((c, keep)) = cause {
        let at = tail.begin(w, CAUSE)?;
        truncated(w, c, keep)?;
        tail.end(w, at)?;
    }
    if let Some(t) = f.retry_after {
        let at = tail.begin(w, RETRY_AFTER)?;
        w.u64(t)?;
        tail.end(w, at)?;
    }
    tail.unknown(w, unknown)?;
    tail.finish(w)
}

/// Writes the envelope `e` with only the first `keep` envelopes of its
/// chain: unchanged if its chain is no longer.
fn truncated(w: &mut Writer<'_>, e: &RawError<'_>, keep: usize) -> Result<(), EncodeError> {
    if chain(e)? <= keep {
        return w.put(e.octets);
    }
    let inner = match e.cause {
        Some(c) if keep > 1 => Some(decode(c).map_err(|_| EncodeError::Malformed)?),
        _ => None,
    };
    let f = Fields {
        outcome: e.outcome,
        disposition: e.disposition,
        key: e.key,
        cause: None,
        retry_after: e.retry_after,
    };
    let cause = inner.as_ref().map(|c| (c, keep - 1));
    write(w, &f, cause, &e.unknown, &mut |w| w.put(e.detail))
}
