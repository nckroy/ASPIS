// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! Variable-length values as views over a message, so decoding needs no
//! allocator (docs/design/call-language.md, "Back ends": borrowed decoding
//! views). Under the `alloc` feature each view also has an owned variant,
//! and [`IntoOwned`] turns a decoded value into the same type at
//! `'static`, for host tools and the later `std` port (ADR 0067, rule 10).

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use core::{fmt, ops::Deref};

use crate::json::JsonWriter;
use crate::wire::{DecodeCx, DecodeError, Mode, Reader};

/// A `string<N>`: UTF-8 without U+0000, its bound checked where it is
/// decoded and encoded. Borrowed and owned strings compare by content.
#[derive(Clone)]
pub enum Str<'a> {
    Borrowed(&'a str),
    #[cfg(feature = "alloc")]
    Owned(String),
}

impl Deref for Str<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        match self {
            Str::Borrowed(s) => s,
            #[cfg(feature = "alloc")]
            Str::Owned(s) => s,
        }
    }
}

impl fmt::Debug for Str<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl Default for Str<'_> {
    fn default() -> Self {
        Str::Borrowed("")
    }
}

impl<'a> From<&'a str> for Str<'a> {
    fn from(s: &'a str) -> Self {
        Str::Borrowed(s)
    }
}

/// A `bytes<N>`, or any raw octets a value keeps. Borrowed and owned
/// octets compare by content.
#[derive(Clone)]
pub enum Bytes<'a> {
    Borrowed(&'a [u8]),
    #[cfg(feature = "alloc")]
    Owned(Vec<u8>),
}

impl Deref for Bytes<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Bytes::Borrowed(s) => s,
            #[cfg(feature = "alloc")]
            Bytes::Owned(s) => s,
        }
    }
}

impl fmt::Debug for Bytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl Default for Bytes<'_> {
    fn default() -> Self {
        Bytes::Borrowed(&[])
    }
}

impl<'a> From<&'a [u8]> for Bytes<'a> {
    fn from(s: &'a [u8]) -> Self {
        Bytes::Borrowed(s)
    }
}

macro_rules! by_content {
    ($t:ident, $u:ty) => {
        impl PartialEq for $t<'_> {
            fn eq(&self, o: &Self) -> bool {
                **self == **o
            }
        }
        impl Eq for $t<'_> {}
        impl PartialOrd for $t<'_> {
            fn partial_cmp(&self, o: &Self) -> Option<core::cmp::Ordering> {
                Some(self.cmp(o))
            }
        }
        impl Ord for $t<'_> {
            fn cmp(&self, o: &Self) -> core::cmp::Ordering {
                (**self).cmp(&**o)
            }
        }
        impl core::hash::Hash for $t<'_> {
            fn hash<H: core::hash::Hasher>(&self, h: &mut H) {
                (**self).hash(h)
            }
        }
    };
}
by_content!(Str, str);
by_content!(Bytes, [u8]);

/// Reads a value again from octets a decoder already checked, as a
/// sequence's iterator does. Bounds aren't checked again: the first read
/// did. Generated types implement it with their decoder.
pub trait Elem<'a>: Sized {
    fn read(r: &mut Reader<'a>, cx: &mut DecodeCx) -> Result<Self, DecodeError>;
}

macro_rules! elem {
    ($($t:ty => $m:ident),* $(,)?) => {$(
        impl<'a> Elem<'a> for $t {
            fn read(r: &mut Reader<'a>, _: &mut DecodeCx) -> Result<Self, DecodeError> {
                r.$m()
            }
        }
    )*};
}
elem!(
    bool => bool, u8 => u8, u16 => u16, u32 => u32, u64 => u64,
    i8 => i8, i16 => i16, i32 => i32, i64 => i64, f32 => f32, f64 => f64,
    [u8; 32] => id, [u8; 16] => uuid,
);

impl<'a> Elem<'a> for Str<'a> {
    fn read(r: &mut Reader<'a>, _: &mut DecodeCx) -> Result<Self, DecodeError> {
        r.str(u32::MAX)
    }
}

impl<'a> Elem<'a> for Bytes<'a> {
    fn read(r: &mut Reader<'a>, _: &mut DecodeCx) -> Result<Self, DecodeError> {
        r.bytes(u32::MAX)
    }
}

impl<'a, T: Elem<'a>> Elem<'a> for Option<T> {
    fn read(r: &mut Reader<'a>, cx: &mut DecodeCx) -> Result<Self, DecodeError> {
        Ok(if r.presence()? {
            Some(T::read(r, cx)?)
        } else {
            None
        })
    }
}

/// A `seq<T, N>`. Elements never hold capabilities, so a decoded sequence
/// is a lazy view over its octets: decoding checks every element, and
/// iterating reads each again, by value ([`Elem`]). A sequence to encode
/// is a slice, or under `alloc` a vector. Its bound is checked where it is
/// decoded and encoded.
pub enum Seq<'a, T> {
    Slice(&'a [T]),
    Wire(WireSeq<'a>),
    #[cfg(feature = "alloc")]
    Owned(Vec<T>),
}

/// A decoded sequence's elements' octets, and how they were read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireSeq<'a> {
    raw: &'a [u8],
    count: u32,
    minor: u16,
    mode: Mode,
}

impl<'a, T> Seq<'a, T> {
    /// Decodes a `seq<T, N>`: its count, at most `max`, then each element
    /// with `elem`, which checks its bounds.
    pub fn decode(
        r: &mut Reader<'a>,
        cx: &mut DecodeCx,
        max: u32,
        elem: impl FnMut(&mut Reader<'a>, &mut DecodeCx) -> Result<T, DecodeError>,
    ) -> Result<Self, DecodeError> {
        let n = r.count(max)?;
        Self::elements(r, cx, n, elem)
    }

    fn elements(
        r: &mut Reader<'a>,
        cx: &mut DecodeCx,
        count: u32,
        mut elem: impl FnMut(&mut Reader<'a>, &mut DecodeCx) -> Result<T, DecodeError>,
    ) -> Result<Self, DecodeError> {
        let start = r.pos();
        for _ in 0..count {
            elem(r, cx)?;
        }
        Ok(Seq::Wire(WireSeq {
            raw: r.since(start),
            count,
            minor: cx.minor,
            mode: cx.mode,
        }))
    }

    pub fn len(&self) -> usize {
        match self {
            Seq::Slice(s) => s.len(),
            Seq::Wire(w) => w.count as usize,
            #[cfg(feature = "alloc")]
            Seq::Owned(v) => v.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a, T: Elem<'a> + Clone> Seq<'a, T> {
    /// The elements, by value.
    pub fn iter(&self) -> SeqIter<'_, 'a, T> {
        match self {
            Seq::Slice(s) => SeqIter::Slice(s.iter()),
            Seq::Wire(w) => SeqIter::Wire {
                r: Reader::new(w.raw),
                cx: DecodeCx::new(w.minor, w.mode, 0),
                left: w.count,
            },
            #[cfg(feature = "alloc")]
            Seq::Owned(v) => SeqIter::Slice(v.iter()),
        }
    }
}

impl<'a, T: Elem<'a>> Elem<'a> for Seq<'a, T> {
    fn read(r: &mut Reader<'a>, cx: &mut DecodeCx) -> Result<Self, DecodeError> {
        let n = r.u32()?;
        Self::elements(r, cx, n, T::read)
    }
}

impl<T> Default for Seq<'_, T> {
    fn default() -> Self {
        Seq::Slice(&[])
    }
}

impl<T: Clone> Clone for Seq<'_, T> {
    fn clone(&self) -> Self {
        match self {
            Seq::Slice(s) => Seq::Slice(s),
            Seq::Wire(w) => Seq::Wire(*w),
            #[cfg(feature = "alloc")]
            Seq::Owned(v) => Seq::Owned(v.clone()),
        }
    }
}

impl<'a, T: Elem<'a> + Clone + PartialEq> PartialEq for Seq<'a, T> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl<'a, T: Elem<'a> + Clone + fmt::Debug> fmt::Debug for Seq<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a, T> From<&'a [T]> for Seq<'a, T> {
    fn from(s: &'a [T]) -> Self {
        Seq::Slice(s)
    }
}

/// Iterates a [`Seq`] by value.
pub enum SeqIter<'s, 'a, T> {
    Slice(core::slice::Iter<'s, T>),
    Wire {
        r: Reader<'a>,
        cx: DecodeCx,
        left: u32,
    },
}

impl<'a, T: Elem<'a> + Clone> Iterator for SeqIter<'_, 'a, T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        match self {
            SeqIter::Slice(i) => i.next().cloned(),
            SeqIter::Wire { r, cx, left } => {
                if *left == 0 {
                    return None;
                }
                *left -= 1;
                // Decoding checked every element, so this can't fail; if
                // it did, the iteration would just end.
                T::read(r, cx).ok()
            }
        }
    }
}

/// An `array<T, N>`: exactly `N` elements, with no count on the wire. A
/// sequence of fixed length, as its own type, so that an array inside a
/// sequence reads back without a count.
pub struct Array<'a, T, const N: u32>(pub Seq<'a, T>);

impl<'a, T, const N: u32> Array<'a, T, N> {
    /// Decodes the `N` elements with `elem`, which checks their bounds.
    pub fn decode(
        r: &mut Reader<'a>,
        cx: &mut DecodeCx,
        elem: impl FnMut(&mut Reader<'a>, &mut DecodeCx) -> Result<T, DecodeError>,
    ) -> Result<Self, DecodeError> {
        Ok(Array(Seq::elements(r, cx, N, elem)?))
    }
}

impl<'a, T, const N: u32> Deref for Array<'a, T, N> {
    type Target = Seq<'a, T>;

    fn deref(&self) -> &Seq<'a, T> {
        &self.0
    }
}

impl<'a, T: Elem<'a>, const N: u32> Elem<'a> for Array<'a, T, N> {
    fn read(r: &mut Reader<'a>, cx: &mut DecodeCx) -> Result<Self, DecodeError> {
        Ok(Array(Seq::elements(r, cx, N, T::read)?))
    }
}

impl<T: Clone, const N: u32> Clone for Array<'_, T, N> {
    fn clone(&self) -> Self {
        Array(self.0.clone())
    }
}

impl<'a, T: Elem<'a> + Clone + PartialEq, const N: u32> PartialEq for Array<'a, T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<'a, T: Elem<'a> + Clone + fmt::Debug, const N: u32> fmt::Debug for Array<'a, T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// The tail fields of an open struct that the reader didn't know,
/// preserved: their octets as they came (tag, `len32`, value), in order.
/// They re-encode unchanged after the known fields ("Rules for readers").
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Unknown<'a> {
    raw: Bytes<'a>,
    count: u32,
}

impl<'a> Unknown<'a> {
    /// Preserved fields, as a tail decoder found them.
    pub fn wire(raw: &'a [u8], count: u32) -> Unknown<'a> {
        Unknown {
            raw: Bytes::Borrowed(raw),
            count,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    /// The fields' octets.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Each field's tag and value octets.
    pub fn iter(&self) -> impl Iterator<Item = (u16, &[u8])> + '_ {
        let mut r = Reader::new(&self.raw);
        (0..self.count).map_while(move |_| {
            let tag = r.u16().ok()?;
            Some((tag, r.octets().ok()?))
        })
    }

    pub fn first_tag(&self) -> Option<u16> {
        self.iter().next().map(|(t, _)| t)
    }

    pub fn last_tag(&self) -> Option<u16> {
        self.iter().last().map(|(t, _)| t)
    }

    /// The JSON mapping's `"@<tag>":"<base64url>"` members.
    pub fn to_json(&self, j: &mut JsonWriter<'_>) {
        for (tag, v) in self.iter() {
            j.tag_key(tag);
            j.bytes(v);
        }
    }
}

impl fmt::Debug for Unknown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

/// A value as the same type at `'static`, owning its octets.
#[cfg(feature = "alloc")]
pub trait IntoOwned {
    type Owned: 'static;
    fn into_owned(self) -> Self::Owned;
}

#[cfg(feature = "alloc")]
mod owned {
    use super::*;
    use crate::cap::CapRef;

    macro_rules! itself {
        ($($t:ty),*) => {$(
            impl IntoOwned for $t {
                type Owned = $t;
                fn into_owned(self) -> $t {
                    self
                }
            }
        )*};
    }
    itself!(
        bool, u8, u16, u32, u64, i8, i16, i32, i64, f32, f64, [u8; 32], [u8; 16], CapRef
    );

    impl<T: IntoOwned> IntoOwned for Option<T> {
        type Owned = Option<T::Owned>;
        fn into_owned(self) -> Option<T::Owned> {
            self.map(T::into_owned)
        }
    }

    impl IntoOwned for Str<'_> {
        type Owned = Str<'static>;
        fn into_owned(self) -> Str<'static> {
            match self {
                Str::Borrowed(s) => Str::Owned(s.into()),
                Str::Owned(s) => Str::Owned(s),
            }
        }
    }

    impl IntoOwned for Bytes<'_> {
        type Owned = Bytes<'static>;
        fn into_owned(self) -> Bytes<'static> {
            match self {
                Bytes::Borrowed(s) => Bytes::Owned(s.into()),
                Bytes::Owned(s) => Bytes::Owned(s),
            }
        }
    }

    impl IntoOwned for Unknown<'_> {
        type Owned = Unknown<'static>;
        fn into_owned(self) -> Unknown<'static> {
            Unknown {
                raw: self.raw.into_owned(),
                count: self.count,
            }
        }
    }

    impl<'a, T: Elem<'a> + Clone + IntoOwned> IntoOwned for Seq<'a, T> {
        type Owned = Seq<'static, T::Owned>;
        fn into_owned(self) -> Seq<'static, T::Owned> {
            Seq::Owned(self.iter().map(T::into_owned).collect())
        }
    }

    impl<'a, T: Elem<'a> + Clone + IntoOwned, const N: u32> IntoOwned for Array<'a, T, N> {
        type Owned = Array<'static, T::Owned, N>;
        fn into_owned(self) -> Array<'static, T::Owned, N> {
            Array(self.0.into_owned())
        }
    }
}
