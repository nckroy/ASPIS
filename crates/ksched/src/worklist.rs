// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! A core's list of pending interrupt work (kernel specification, "The
//! kernel lock and long operations"; K24).
//!
//! The list is intrusive and doubly linked through the objects that have
//! work pending, so it needs no memory of its own, and an object leaves it
//! in constant time. In C12 those objects are reply objects that are walk
//! cursors ([`crate::donation`]); C13b and C14 add eventcounts with a wake
//! pending. An item is a [`Tagged`] address, so the kernel knows which kind
//! of object each is: every object here is aligned to at least 64 bytes,
//! which leaves the low six bits free.

use crate::NIL;

/// An object's address with a kind tag in its low bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tagged(u64);

impl Tagged {
    /// Bits kept for the tag.
    pub const TAG_BITS: u32 = 3;
    const MASK: u64 = (1 << Self::TAG_BITS) - 1;
    /// The kinds of work.
    pub const WALK: u8 = 1;
    /// C13b and C14: an eventcount with a wake pending.
    pub const EVENTCOUNT: u8 = 2;

    /// `addr`, aligned to 8 or more, with `tag` below 8. None otherwise.
    pub const fn new(addr: u64, tag: u8) -> Option<Tagged> {
        if addr == NIL || addr & Self::MASK != 0 || tag as u64 > Self::MASK {
            None
        } else {
            Some(Tagged(addr | tag as u64))
        }
    }

    /// The raw word, as stored in a link.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// From a raw link word; None for [`NIL`].
    pub const fn from_raw(raw: u64) -> Option<Tagged> {
        if raw == NIL { None } else { Some(Tagged(raw)) }
    }

    pub const fn addr(self) -> u64 {
        self.0 & !Self::MASK
    }

    pub const fn tag(self) -> u8 {
        (self.0 & Self::MASK) as u8
    }
}

/// An item's links, as raw tagged words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WLinks {
    pub next: u64,
    pub prev: u64,
    /// Whether the item is on a list: so it is queued at most once.
    pub queued: bool,
}

/// The memory that holds the items' links.
pub trait WorkStore {
    fn wlinks(&self, item: Tagged) -> WLinks;
    fn set_wlinks(&mut self, item: Tagged, l: WLinks);
}

/// A first-in, first-out list of work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkList {
    head: u64,
    tail: u64,
}

impl WorkList {
    pub const fn new() -> WorkList {
        WorkList {
            head: NIL,
            tail: NIL,
        }
    }

    pub const fn is_empty(&self) -> bool {
        self.head == NIL
    }

    pub const fn front(&self) -> Option<Tagged> {
        Tagged::from_raw(self.head)
    }

    /// Appends `item`, unless it is queued already: true if it was added.
    pub fn push_back<S: WorkStore>(&mut self, s: &mut S, item: Tagged) -> bool {
        if s.wlinks(item).queued {
            return false;
        }
        s.set_wlinks(
            item,
            WLinks {
                next: NIL,
                prev: self.tail,
                queued: true,
            },
        );
        match Tagged::from_raw(self.tail) {
            None => self.head = item.raw(),
            Some(t) => {
                let mut l = s.wlinks(t);
                l.next = item.raw();
                s.set_wlinks(t, l);
            }
        }
        self.tail = item.raw();
        true
    }

    /// Takes `item`, which must be on this list, out of it.
    pub fn remove<S: WorkStore>(&mut self, s: &mut S, item: Tagged) {
        let l = s.wlinks(item);
        match Tagged::from_raw(l.prev) {
            None => self.head = l.next,
            Some(p) => {
                let mut pl = s.wlinks(p);
                pl.next = l.next;
                s.set_wlinks(p, pl);
            }
        }
        match Tagged::from_raw(l.next) {
            None => self.tail = l.prev,
            Some(n) => {
                let mut nl = s.wlinks(n);
                nl.prev = l.prev;
                s.set_wlinks(n, nl);
            }
        }
        s.set_wlinks(item, WLinks::default());
    }

    /// Puts `new`, which must not be queued, in `old`'s place, keeping the
    /// order: a walk's cursor moving on.
    pub fn replace<S: WorkStore>(&mut self, s: &mut S, old: Tagged, new: Tagged) {
        let l = s.wlinks(old);
        s.set_wlinks(new, l);
        match Tagged::from_raw(l.prev) {
            None => self.head = new.raw(),
            Some(p) => {
                let mut pl = s.wlinks(p);
                pl.next = new.raw();
                s.set_wlinks(p, pl);
            }
        }
        match Tagged::from_raw(l.next) {
            None => self.tail = new.raw(),
            Some(n) => {
                let mut nl = s.wlinks(n);
                nl.prev = new.raw();
                s.set_wlinks(n, nl);
            }
        }
        s.set_wlinks(old, WLinks::default());
    }

    /// Takes the first item.
    pub fn pop_front<S: WorkStore>(&mut self, s: &mut S) -> Option<Tagged> {
        let f = self.front()?;
        self.remove(s, f);
        Some(f)
    }
}
