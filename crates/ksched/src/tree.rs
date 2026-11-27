// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! An intrusive red-black tree (kernel specification, "Ordered kernel
//! queues"; K25).
//!
//! ADR 0052, rule 2 requires every ordered kernel queue to insert and remove in
//! bounded or logarithmic time, and forbids amortized bounds in practice: a
//! lock held for one long operation stalls every core. A red-black tree's
//! insert, remove and minimum are logarithmic in the worst case. seL4's
//! release queue is a sorted list with a linear insert; ASPIS departs from
//! its code here, not from its design.
//!
//! The nodes live in the kernel's objects. A node is the object's physical
//! address, never [`NIL`]; the store reads and writes its links and its key.
//! Keys must be distinct, which the kernel ensures by ending each key with
//! the node's own address. The root is the caller's word.
//!
//! **Augmentation.** A store whose [`TreeStore::AUGMENTED`] is true gets
//! [`TreeStore::update`] called for every node whose subtree changed, child
//! before parent, so it can keep a value computed from its children, such
//! as the largest interval end below it (the donation module's walk tree).

use crate::NIL;

/// A node's links. `parent` is [`NIL`] at the root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Links {
    pub left: u64,
    pub right: u64,
    pub parent: u64,
    pub red: bool,
}

/// The memory that holds a tree's nodes.
pub trait TreeStore {
    /// A node's key: distinct for every node in one tree.
    type Key: Ord + Copy;
    /// Whether [`TreeStore::update`] must be called.
    const AUGMENTED: bool = false;
    fn key(&self, n: u64) -> Self::Key;
    fn links(&self, n: u64) -> Links;
    fn set_links(&mut self, n: u64, l: Links);
    /// Recomputes `n`'s augmented value from its own and its children's.
    fn update(&mut self, _n: u64) {}
}

fn left<S: TreeStore>(s: &S, n: u64) -> u64 {
    if n == NIL { NIL } else { s.links(n).left }
}

fn right<S: TreeStore>(s: &S, n: u64) -> u64 {
    if n == NIL { NIL } else { s.links(n).right }
}

fn parent<S: TreeStore>(s: &S, n: u64) -> u64 {
    if n == NIL { NIL } else { s.links(n).parent }
}

/// A missing node is black.
fn is_red<S: TreeStore>(s: &S, n: u64) -> bool {
    n != NIL && s.links(n).red
}

fn set_red<S: TreeStore>(s: &mut S, n: u64, red: bool) {
    if n != NIL {
        let mut l = s.links(n);
        l.red = red;
        s.set_links(n, l);
    }
}

fn set_parent<S: TreeStore>(s: &mut S, n: u64, p: u64) {
    if n != NIL {
        let mut l = s.links(n);
        l.parent = p;
        s.set_links(n, l);
    }
}

fn set_left<S: TreeStore>(s: &mut S, n: u64, c: u64) {
    let mut l = s.links(n);
    l.left = c;
    s.set_links(n, l);
}

fn set_right<S: TreeStore>(s: &mut S, n: u64, c: u64) {
    let mut l = s.links(n);
    l.right = c;
    s.set_links(n, l);
}

/// Puts `new` where `old` hangs from `p` (or at the root).
fn replace_child<S: TreeStore>(s: &mut S, root: &mut u64, p: u64, old: u64, new: u64) {
    if p == NIL {
        *root = new;
    } else if left(s, p) == old {
        set_left(s, p, new);
    } else {
        set_right(s, p, new);
    }
}

/// Calls `update` from `n` up to the root.
fn update_path<S: TreeStore>(s: &mut S, mut n: u64) {
    if !S::AUGMENTED {
        return;
    }
    while n != NIL {
        s.update(n);
        n = parent(s, n);
    }
}

/// Rotates `x` down to the left: its right child takes its place.
fn rotate_left<S: TreeStore>(s: &mut S, root: &mut u64, x: u64) {
    let y = right(s, x);
    let p = parent(s, x);
    let b = left(s, y);
    set_right(s, x, b);
    set_parent(s, b, x);
    replace_child(s, root, p, x, y);
    set_parent(s, y, p);
    set_left(s, y, x);
    set_parent(s, x, y);
    if S::AUGMENTED {
        s.update(x);
        s.update(y);
    }
}

/// Rotates `x` down to the right: its left child takes its place.
fn rotate_right<S: TreeStore>(s: &mut S, root: &mut u64, x: u64) {
    let y = left(s, x);
    let p = parent(s, x);
    let b = right(s, y);
    set_left(s, x, b);
    set_parent(s, b, x);
    replace_child(s, root, p, x, y);
    set_parent(s, y, p);
    set_right(s, y, x);
    set_parent(s, x, y);
    if S::AUGMENTED {
        s.update(x);
        s.update(y);
    }
}

/// Inserts `n`, which must not be in any tree. O(log n).
pub fn insert<S: TreeStore>(s: &mut S, root: &mut u64, n: u64) {
    let key = s.key(n);
    let mut p = NIL;
    let mut cur = *root;
    let mut go_left = false;
    while cur != NIL {
        p = cur;
        go_left = key < s.key(cur);
        cur = if go_left { left(s, cur) } else { right(s, cur) };
    }
    s.set_links(
        n,
        Links {
            left: NIL,
            right: NIL,
            parent: p,
            red: true,
        },
    );
    if p == NIL {
        *root = n;
    } else if go_left {
        set_left(s, p, n);
    } else {
        set_right(s, p, n);
    }
    update_path(s, n);
    insert_fixup(s, root, n);
}

fn insert_fixup<S: TreeStore>(s: &mut S, root: &mut u64, mut z: u64) {
    while is_red(s, parent(s, z)) {
        let p = parent(s, z);
        // A red parent is never the root, so the grandparent exists.
        let g = parent(s, p);
        if p == left(s, g) {
            let u = right(s, g);
            if is_red(s, u) {
                set_red(s, p, false);
                set_red(s, u, false);
                set_red(s, g, true);
                z = g;
            } else {
                if z == right(s, p) {
                    z = p;
                    rotate_left(s, root, z);
                }
                let p = parent(s, z);
                let g = parent(s, p);
                set_red(s, p, false);
                set_red(s, g, true);
                rotate_right(s, root, g);
            }
        } else {
            let u = left(s, g);
            if is_red(s, u) {
                set_red(s, p, false);
                set_red(s, u, false);
                set_red(s, g, true);
                z = g;
            } else {
                if z == left(s, p) {
                    z = p;
                    rotate_right(s, root, z);
                }
                let p = parent(s, z);
                let g = parent(s, p);
                set_red(s, p, false);
                set_red(s, g, true);
                rotate_left(s, root, g);
            }
        }
    }
    set_red(s, *root, false);
}

/// The leftmost node under `n`.
fn leftmost<S: TreeStore>(s: &S, mut n: u64) -> u64 {
    while left(s, n) != NIL {
        n = left(s, n);
    }
    n
}

/// Removes `z`, which must be in this tree, and clears its links. O(log n).
pub fn remove<S: TreeStore>(s: &mut S, root: &mut u64, z: u64) {
    let zl = s.links(z);
    // `x` takes the removed position; `xp` is its parent, kept apart since
    // `x` may be NIL. `removed_red` is the color of the node that left the
    // tree's structure.
    let (x, xp, removed_red);
    if zl.left == NIL || zl.right == NIL {
        x = if zl.left == NIL { zl.right } else { zl.left };
        xp = zl.parent;
        removed_red = zl.red;
        replace_child(s, root, zl.parent, z, x);
        set_parent(s, x, xp);
        update_path(s, xp);
    } else {
        // Two children: the successor `y` takes z's place.
        let y = leftmost(s, zl.right);
        let yl = s.links(y);
        removed_red = yl.red;
        x = yl.right;
        if yl.parent == z {
            xp = y;
        } else {
            xp = yl.parent;
            set_left(s, xp, x);
            set_parent(s, x, xp);
            set_right(s, y, zl.right);
            set_parent(s, zl.right, y);
        }
        replace_child(s, root, zl.parent, z, y);
        let mut l = s.links(y);
        l.parent = zl.parent;
        l.left = zl.left;
        l.red = zl.red;
        s.set_links(y, l);
        set_parent(s, zl.left, y);
        update_path(s, xp);
    }
    s.set_links(z, Links::default());
    if !removed_red {
        remove_fixup(s, root, x, xp);
    }
}

fn remove_fixup<S: TreeStore>(s: &mut S, root: &mut u64, mut x: u64, mut xp: u64) {
    while x != *root && !is_red(s, x) {
        if x == left(s, xp) {
            let mut w = right(s, xp);
            if is_red(s, w) {
                set_red(s, w, false);
                set_red(s, xp, true);
                rotate_left(s, root, xp);
                w = right(s, xp);
            }
            if !is_red(s, left(s, w)) && !is_red(s, right(s, w)) {
                set_red(s, w, true);
                x = xp;
                xp = parent(s, x);
            } else {
                if !is_red(s, right(s, w)) {
                    set_red(s, left(s, w), false);
                    set_red(s, w, true);
                    rotate_right(s, root, w);
                    w = right(s, xp);
                }
                set_red(s, w, is_red(s, xp));
                set_red(s, xp, false);
                set_red(s, right(s, w), false);
                rotate_left(s, root, xp);
                x = *root;
                xp = NIL;
            }
        } else {
            let mut w = left(s, xp);
            if is_red(s, w) {
                set_red(s, w, false);
                set_red(s, xp, true);
                rotate_right(s, root, xp);
                w = left(s, xp);
            }
            if !is_red(s, left(s, w)) && !is_red(s, right(s, w)) {
                set_red(s, w, true);
                x = xp;
                xp = parent(s, x);
            } else {
                if !is_red(s, left(s, w)) {
                    set_red(s, right(s, w), false);
                    set_red(s, w, true);
                    rotate_left(s, root, w);
                    w = left(s, xp);
                }
                set_red(s, w, is_red(s, xp));
                set_red(s, xp, false);
                set_red(s, left(s, w), false);
                rotate_right(s, root, xp);
                x = *root;
                xp = NIL;
            }
        }
    }
    set_red(s, x, false);
}

/// The node with the smallest key, or [`NIL`]. O(log n).
pub fn first<S: TreeStore>(s: &S, root: u64) -> u64 {
    if root == NIL { NIL } else { leftmost(s, root) }
}

/// The node after `n` in key order, or [`NIL`]. O(log n).
pub fn next<S: TreeStore>(s: &S, n: u64) -> u64 {
    let r = right(s, n);
    if r != NIL {
        return leftmost(s, r);
    }
    let mut c = n;
    let mut p = parent(s, n);
    while p != NIL && right(s, p) == c {
        c = p;
        p = parent(s, p);
    }
    p
}

/// Why [`check`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Broken {
    /// A child's parent link doesn't name its parent.
    Parent,
    /// Keys out of order.
    Order,
    /// A red node with a red child, or a red root.
    RedRed,
    /// Paths with different numbers of black nodes.
    BlackHeight,
    /// More nodes than `limit`: a cycle.
    Cycle,
}

/// Checks the red-black invariants, and returns the number of nodes. It
/// visits at most `limit` nodes, so a corrupted tree can't loop forever.
/// For tests, in the kernel's test builds too: O(n).
pub fn check<S: TreeStore>(s: &S, root: u64, limit: usize) -> Result<usize, Broken> {
    if root == NIL {
        return Ok(0);
    }
    if s.links(root).parent != NIL || s.links(root).red {
        return Err(if s.links(root).red {
            Broken::RedRed
        } else {
            Broken::Parent
        });
    }
    // An iterative walk in key order, keeping the black height of the
    // first leaf seen.
    let mut count = 0usize;
    let mut leaf_black: Option<u32> = None;
    let mut n = leftmost(s, root);
    let mut prev: Option<S::Key> = None;
    while n != NIL {
        count += 1;
        if count > limit {
            return Err(Broken::Cycle);
        }
        let l = s.links(n);
        if let Some(k) = prev
            && k >= s.key(n)
        {
            return Err(Broken::Order);
        }
        prev = Some(s.key(n));
        for c in [l.left, l.right] {
            if c != NIL {
                if s.links(c).parent != n {
                    return Err(Broken::Parent);
                }
                if l.red && s.links(c).red {
                    return Err(Broken::RedRed);
                }
            }
        }
        if l.left == NIL || l.right == NIL {
            // A missing child: count the black nodes from here to the root.
            let mut b = 0u32;
            let mut m = n;
            let mut steps = 0usize;
            while m != NIL {
                if !s.links(m).red {
                    b += 1;
                }
                m = s.links(m).parent;
                steps += 1;
                if steps > limit {
                    return Err(Broken::Cycle);
                }
            }
            match leaf_black {
                None => leaf_black = Some(b),
                Some(want) if want != b => return Err(Broken::BlackHeight),
                Some(_) => {}
            }
        }
        n = next(s, n);
    }
    Ok(count)
}

/// The tree's height: the most nodes on a path from the root. O(n), for
/// tests.
pub fn height<S: TreeStore>(s: &S, root: u64) -> usize {
    // Depth of each node in key order, by walking up: O(n log n).
    let mut best = 0;
    let mut n = first(s, root);
    while n != NIL {
        let mut d = 0;
        let mut m = n;
        while m != NIL {
            d += 1;
            m = parent(s, m);
        }
        if d > best {
            best = d;
        }
        n = next(s, n);
    }
    best
}
