// SPDX-FileCopyrightText: 2026 Nicole Roy
// SPDX-License-Identifier: MPL-2.0

//! The matcher: sets of states, depth-first over the grammar and
//! breadth-first over the input (docs/design/call-language.md, L22).
//!
//! `node(n, from)` takes the set of states a match may be in before node
//! `n` and returns every state a match of `n` can end in. Alternatives are
//! unioned, a concatenation folds the set through its elements, and a
//! repetition iterates the set by count. Nothing is committed early, as a
//! PEG would, so the answer is exact for ABNF's ambiguity. Rust recursion
//! follows the grammar's nesting, never the input's length: `*OCTET` over
//! the whole input is a loop.
//!
//! With constraints on, a state also carries what the vocabulary needs
//! ("How constraints bind"): the bindings of the current rule's own
//! elements, the capability indexes seen, and the open `ascending` frames.
//! A rule that carries a constraint, or is bound or watched, is matched
//! one start at a time, so its value is known; every other rule is matched
//! for a whole set at once. With constraints off, states carry only their
//! position, and the same engine is a plain context-free recognizer.
//!
//! Every match is bounded ([`Limits`]): input octets, steps (linear in the
//! input, with a cap), the memory its live state sets hold, and the depth
//! of nested calls, where every node, repetition, target and rule call is
//! a level. A step is a bounded unit of work: a state visiting a node, a
//! constraint checked, an octet read for a value, a frame searched.
//! Running over any budget is [`Exhausted`], never an answer. There is no
//! hashing and no randomness, so the same inputs give the same result
//! every time.

use alloc::{collections::BTreeSet, vec::Vec};
use core::cell::Cell;

use crate::{
    Context, Exhausted, Limits,
    constraint::{Bound, Check, Target, Value},
    grammar::{Grammar, RuleId},
    syntax::{Node, NodeId},
};

/// A binding or an `ascending` frame: a rule index and a value. A bound
/// rule's match with no value (an empty decimal) binds `None`.
type Slot = (u32, Option<Value>);

/// The rule index an `ascending tags` frame carries.
const TAGS: u32 = u32::MAX;

/// Where a match may be. The fields are in this order so that a set keeps
/// states with the same bindings together.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct State {
    /// The latest match of each bound rule among the current rule's own
    /// elements, sorted by rule.
    locals: Vec<Slot>,
    pos: u32,
    /// Capability indexes seen: a count for a whole body, which must name
    /// them in order, or a bit mask for a fragment.
    caps: u8,
    /// Open `ascending R` and `ascending tags` frames, innermost last, each
    /// with the last value seen.
    asc: Vec<Slot>,
}

impl State {
    fn at(pos: u32) -> State {
        State {
            locals: Vec::new(),
            pos,
            caps: 0,
            asc: Vec::new(),
        }
    }

    /// What the state is charged while a set holds it: itself, a share of
    /// the set's tree, and its vectors.
    fn cost(&self) -> usize {
        core::mem::size_of::<State>()
            + 2 * core::mem::size_of::<usize>()
            + (self.locals.capacity() + self.asc.capacity()) * core::mem::size_of::<Slot>()
    }

    /// Records a bound rule's latest match.
    fn bind(&mut self, rule: u32, value: Option<Value>) {
        match self.locals.binary_search_by_key(&rule, |s| s.0) {
            Ok(i) => self.locals[i].1 = value,
            Err(i) => self.locals.insert(i, (rule, value)),
        }
    }
}

/// The steps and memory one match has used, against its budgets.
struct Meter {
    steps: Cell<u64>,
    step_limit: u64,
    memory: Cell<usize>,
    memory_limit: usize,
}

impl Meter {
    fn step(&self, n: u64) -> Result<(), Exhausted> {
        let s = self.steps.get().saturating_add(n);
        self.steps.set(s);
        if s > self.step_limit {
            return Err(Exhausted::Steps);
        }
        Ok(())
    }

    fn charge(&self, bytes: usize) -> Result<(), Exhausted> {
        let m = self.memory.get().saturating_add(bytes);
        self.memory.set(m);
        if m > self.memory_limit {
            return Err(Exhausted::Memory);
        }
        Ok(())
    }

    fn refund(&self, bytes: usize) {
        self.memory.set(self.memory.get().saturating_sub(bytes));
    }
}

/// A set of states, deduplicated as it is built and charged to the meter
/// while it lives. A state already in the set costs a step but no memory.
struct States<'m> {
    set: BTreeSet<State>,
    meter: &'m Meter,
}

impl<'m> States<'m> {
    fn new(meter: &'m Meter) -> Self {
        States {
            set: BTreeSet::new(),
            meter,
        }
    }

    /// Adds a state. Returns whether it was new.
    fn insert(&mut self, s: State) -> Result<bool, Exhausted> {
        self.meter.step(1)?;
        if self.set.contains(&s) {
            return Ok(false);
        }
        self.meter.charge(s.cost())?;
        self.set.insert(s);
        Ok(true)
    }

    /// Takes every state out of the set, refunding each.
    fn drain(&mut self) -> impl Iterator<Item = State> + use<'_, 'm> {
        let meter = self.meter;
        core::mem::take(&mut self.set)
            .into_iter()
            .inspect(move |s| {
                meter.refund(s.cost());
            })
    }

    /// Adds every state of `other`, taking its set when this one is empty.
    fn absorb(&mut self, mut other: States<'m>) -> Result<(), Exhausted> {
        if self.set.is_empty() {
            core::mem::swap(&mut self.set, &mut other.set);
            return Ok(());
        }
        for s in other.drain() {
            self.insert(s)?;
        }
        Ok(())
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    fn iter(&self) -> impl Iterator<Item = &State> {
        self.set.iter()
    }
}

impl Drop for States<'_> {
    fn drop(&mut self) {
        let cost: usize = self.set.iter().map(State::cost).sum();
        self.meter.refund(cost);
    }
}

/// The bindings of the rules that called the current one, each frame at
/// its call point: where a constraint's R is looked up when the current
/// rule hasn't matched it ("How constraints bind", values).
struct Env<'e> {
    locals: &'e [Slot],
    parent: Option<&'e Env<'e>>,
}

/// What holds for one rule invocation.
#[derive(Clone, Copy)]
struct Cx<'e> {
    env: Option<&'e Env<'e>>,
    /// The invoked rule's target, when it is a repetition, which `node`
    /// hands to `target`.
    target: Option<&'e Target>,
    /// The rule's first octet, for `header words R`.
    rule_start: u32,
    /// No element reads at or past this.
    limit: u32,
    /// The message's end, for `remaining octets`: the end of the innermost
    /// span bounded by `exactly R octets` or `exactly R words`, or else the
    /// end of the input.
    msg_end: u32,
}

impl Cx<'_> {
    /// R's value: its latest match in the current rule (`locals`), else in
    /// the rules that called it, innermost first. `None` when no rule has
    /// matched it, or its match has no value: the form that reads it
    /// fails. Each frame searched costs a step.
    fn lookup(&self, locals: &[Slot], r: u32, meter: &Meter) -> Result<Option<Value>, Exhausted> {
        let find = |l: &[Slot]| {
            l.binary_search_by_key(&r, |s| s.0)
                .ok()
                .and_then(|i| l.get(i))
                .map(|s| s.1)
        };
        meter.step(1)?;
        if let Some(v) = find(locals) {
            return Ok(v);
        }
        let mut env = self.env;
        while let Some(e) = env {
            meter.step(1)?;
            if let Some(v) = find(e.locals) {
                return Ok(v);
            }
            env = e.parent;
        }
        Ok(None)
    }
}

/// A constrained match's settings.
struct Mode {
    /// The capability count (indexes 0 to 7 are read).
    caps: u8,
    /// A whole body, rather than a core rule's fragment: indexes appear in
    /// ascending order and every one below the count appears.
    whole: bool,
}

struct Matcher<'a> {
    g: &'a Grammar,
    input: &'a [u8],
    meter: Meter,
    max_depth: usize,
    /// `None` reads the grammar as context-free.
    mode: Option<Mode>,
}

/// Whether `input` matches rule `r` of `g`: context-free when `cx` is
/// `None`, and keeping every constraint otherwise. The match takes no more
/// steps than `allowance` holds, and they are taken from it, whatever the
/// result.
pub(crate) fn matches(
    g: &Grammar,
    r: RuleId,
    input: &[u8],
    cx: Option<&Context>,
    allowance: &mut u64,
) -> Result<bool, Exhausted> {
    let limits: &Limits = &g.limits;
    if input.len() > limits.input_octets {
        return Err(Exhausted::Input);
    }
    let len = u32::try_from(input.len()).map_err(|_| Exhausted::Input)?;
    // Linear in the input, with an absolute cap (0068 rule 5, as L22
    // reads it for a general ABNF matcher).
    let step_limit = limits
        .steps_per_octet
        .saturating_mul(u64::from(len))
        .saturating_add(limits.steps_base)
        .min(limits.steps_max)
        .min(*allowance);
    let m = Matcher {
        g,
        input,
        meter: Meter {
            steps: Cell::new(0),
            step_limit,
            memory: Cell::new(0),
            memory_limit: limits.memory,
        },
        max_depth: limits.depth,
        mode: cx.map(|c| Mode {
            caps: c.caps.min(8),
            whole: !g.is_core(r),
        }),
    };
    let result = m.run(r, len);
    *allowance = allowance.saturating_sub(m.meter.steps.get().min(step_limit));
    result
}

impl Matcher<'_> {
    /// The match from the start of the input.
    fn run(&self, r: RuleId, len: u32) -> Result<bool, Exhausted> {
        let mut start = States::new(&self.meter);
        start.insert(State::at(0))?;
        let top = Cx {
            env: None,
            target: None,
            rule_start: 0,
            limit: len,
            msg_end: len,
        };
        let end = self.call(r.0, &start, &top, 1)?;
        let complete = |s: &State| match &self.mode {
            // A whole body names every capability (0066; "Capability indexes").
            Some(Mode { caps, whole: true }) => s.caps == *caps,
            _ => true,
        };
        Ok(end.iter().any(|s| s.pos == len && complete(s)))
    }
}

impl<'a> Matcher<'a> {
    fn deeper(&self, depth: usize) -> Result<usize, Exhausted> {
        if depth > self.max_depth {
            return Err(Exhausted::Depth);
        }
        Ok(depth + 1)
    }

    /// Every state a match of node `n` can end in, from any state in
    /// `from`.
    fn node<'m>(
        &'m self,
        n: NodeId,
        from: &States<'m>,
        cx: &Cx<'_>,
        depth: usize,
    ) -> Result<States<'m>, Exhausted> {
        let next = self.deeper(depth)?;
        // One step per state per node visit.
        self.meter.step(from.len() as u64)?;
        if let Some(t) = cx.target.filter(|t| t.node == Some(n)) {
            return self.target(n, t, from, cx, next);
        }
        let mut out = States::new(&self.meter);
        match &self.g.nodes[n as usize] {
            Node::Lit { octets, ci } => {
                for s in from.iter() {
                    let at = s.pos as usize;
                    let end = at.saturating_add(octets.len());
                    if end > cx.limit as usize {
                        continue;
                    }
                    let Some(text) = self.input.get(at..end) else {
                        continue;
                    };
                    let same = if *ci {
                        text.eq_ignore_ascii_case(octets)
                    } else {
                        text == octets.as_slice()
                    };
                    if same {
                        let mut t = s.clone();
                        t.pos = end as u32;
                        out.insert(t)?;
                    }
                }
            }
            Node::Range(lo, hi) => {
                for s in from.iter() {
                    if s.pos < cx.limit
                        && self
                            .input
                            .get(s.pos as usize)
                            .is_some_and(|b| (lo..=hi).contains(&b))
                    {
                        let mut t = s.clone();
                        t.pos += 1;
                        out.insert(t)?;
                    }
                }
            }
            Node::Prose | Node::Name { .. } => {}
            Node::Alt(alts) => {
                for &a in alts {
                    let r = self.node(a, from, cx, next)?;
                    out.absorb(r)?;
                }
            }
            Node::Cat(items) => {
                let Some((&first, rest)) = items.split_first() else {
                    return Ok(out);
                };
                let mut cur = self.node(first, from, cx, next)?;
                for &item in rest {
                    if cur.is_empty() {
                        break;
                    }
                    cur = self.node(item, &cur, cx, next)?;
                }
                return Ok(cur);
            }
            Node::Rep { min, max, node, .. } => {
                return self.rep(*min, *max, *node, false, from, cx, next);
            }
            Node::Ref(r) => return self.call(*r, from, cx, next),
        }
        Ok(out)
    }

    /// A call of rule `r`. The callee starts with no bindings of its own,
    /// and sees the caller's at the call point through its `Env`.
    ///
    /// Context-free, the whole set runs at once. With constraints on, the
    /// set runs in groups of states with the same bindings; a spanned rule
    /// runs one start at a time, and each result's span is checked, read
    /// and bound in the caller.
    fn call<'m>(
        &'m self,
        r: u32,
        from: &States<'m>,
        cx: &Cx<'_>,
        depth: usize,
    ) -> Result<States<'m>, Exhausted> {
        let next = self.deeper(depth)?;
        let rule = &self.g.rules[r as usize];
        let Some(_) = &self.mode else {
            let inner = Cx {
                target: None,
                ..*cx
            };
            return self.node(rule.body, from, &inner, next);
        };
        let compiled = &self.g.compiled;
        let spanned = compiled.spanned[r as usize];
        let target = compiled.rules[r as usize].target.as_ref();
        let mut out = States::new(&self.meter);
        let mut it = from.iter().peekable();
        while let Some(first) = it.next() {
            // The group: `first` and the states after it with the same
            // bindings (and, for a spanned rule, the same start).
            let mut group = States::new(&self.meter);
            let child = |s: &State| State {
                locals: Vec::new(),
                pos: s.pos,
                caps: s.caps,
                asc: s.asc.clone(),
            };
            group.insert(child(first))?;
            while let Some(s) =
                it.next_if(|s| s.locals == first.locals && (!spanned || s.pos == first.pos))
            {
                group.insert(child(s))?;
            }
            let env = Env {
                locals: &first.locals,
                parent: cx.env,
            };
            let start = first.pos;
            let mut inner = Cx {
                env: Some(&env),
                target: target.filter(|t| t.node.is_some()),
                rule_start: start,
                limit: cx.limit,
                msg_end: cx.msg_end,
            };
            // A whole-match target: the rule's own match must end where its
            // bounds say.
            let mut must_end = None;
            if let Some(t) = target.filter(|t| t.node.is_none()) {
                let Some((end, msg_end)) = self.bounds(&t.bounds, start, &[], &inner)? else {
                    continue;
                };
                must_end = end;
                inner.limit = end.unwrap_or(inner.limit);
                inner.msg_end = msg_end;
            }
            let mut results = self.node(rule.body, &group, &inner, next)?;
            for res in results.drain() {
                if must_end.is_some_and(|e| res.pos != e) {
                    continue;
                }
                let mut s = State {
                    locals: first.locals.clone(),
                    pos: res.pos,
                    caps: res.caps,
                    asc: res.asc,
                };
                if spanned && !self.keeps(r, start, &mut s)? {
                    continue;
                }
                out.insert(s)?;
            }
        }
        Ok(out)
    }

    /// Checks a spanned rule's match, from `start` to `s.pos`, and records
    /// what it shows: its capability index, its place in an `ascending`
    /// frame, and its binding in the caller. Returns whether it keeps every
    /// constraint.
    ///
    /// The work is charged as steps: one for each check, one for each
    /// octet of the span read or compared, and one for each open frame
    /// searched. Loading sorted and deduplicated the checks, and a
    /// `not one of` or `not word` list is searched by halves.
    fn keeps(&self, r: u32, start: u32, s: &mut State) -> Result<bool, Exhausted> {
        let compiled = &self.g.compiled;
        let rc = &compiled.rules[r as usize];
        let span = self
            .input
            .get(start as usize..s.pos as usize)
            .unwrap_or(&[]);
        let read = if rc.reads_span { span.len() as u64 } else { 0 };
        self.meter
            .step((rc.checks.len() as u64).saturating_add(read))?;
        let value = rc.reading.and_then(|rd| rd.read(span));
        for check in &rc.checks {
            let ok = match check {
                Check::AtMost(n) => value.is_some_and(|v| v <= *n),
                Check::AtLeast(n) => value.is_some_and(|v| v >= *n),
                Check::In(lo, hi) => value.is_some_and(|v| *lo <= v && v <= *hi),
                Check::Not(n) => value.is_some_and(|v| v != *n),
                Check::NotOneOf(list) => value.is_some_and(|v| list.binary_search(&v).is_err()),
                Check::LengthAtMost(n) => span.len() as u64 <= *n,
                Check::NotWord(words) => {
                    words.binary_search_by(|w| w.as_slice().cmp(span)).is_err()
                }
                Check::CanonicalFloat => canonical_float(span),
                Check::CapabilityIndex => self.capability(value, &mut s.caps),
            };
            if !ok {
                return Ok(false);
            }
        }
        if compiled.watched[r as usize] {
            self.meter.step(s.asc.len() as u64)?;
            // The innermost `ascending R` frame open around this match.
            if let Some(frame) = s.asc.iter_mut().rev().find(|f| f.0 == r) {
                match (value, frame.1) {
                    (None, _) => return Ok(false),
                    (Some(v), Some(last)) if v <= last => return Ok(false),
                    (v, _) => frame.1 = v,
                }
            }
        }
        if compiled.bound[r as usize] {
            s.bind(r, value);
        }
        Ok(true)
    }

    /// `capability index`: below the count, and in a whole body the next
    /// index in order (so each appears once); in a fragment, not seen
    /// before ("Capability indexes").
    fn capability(&self, value: Option<Value>, seen: &mut u8) -> bool {
        let (Some(mode), Some(v)) = (&self.mode, value.and_then(Value::count)) else {
            return false;
        };
        if v >= u32::from(mode.caps) {
            return false;
        }
        if mode.whole {
            if v != u32::from(*seen) {
                return false;
            }
            *seen += 1;
        } else {
            let bit = 1u8 << v;
            if *seen & bit != 0 {
                return false;
            }
            *seen |= bit;
        }
        true
    }

    /// Where a target from `pos` must end, and the message's end inside it.
    /// `Some((None, msg_end))`: no bound. `None`: the bounds can't hold (an
    /// R unbound, without a value, negative or too large; bounds that
    /// disagree; or an end outside the current span), so nothing matches.
    /// Each bound costs a step, and each lookup the frames it searches.
    fn bounds(
        &self,
        bounds: &[Bound],
        pos: u32,
        locals: &[Slot],
        cx: &Cx<'_>,
    ) -> Result<Option<(Option<u32>, u32)>, Exhausted> {
        self.meter.step(bounds.len() as u64)?;
        let mut end: Option<u32> = None;
        let mut msg_end = cx.msg_end;
        for b in bounds {
            let count = |r: u32| -> Result<Option<u32>, Exhausted> {
                Ok(cx.lookup(locals, r, &self.meter)?.and_then(Value::count))
            };
            let words = |r: u32| -> Result<Option<u32>, Exhausted> {
                Ok(count(r)?.and_then(|c| c.checked_mul(8)))
            };
            let e = match *b {
                Bound::Octets(r) => count(r)?.and_then(|c| pos.checked_add(c)),
                Bound::Words(r) => words(r)?.and_then(|w| pos.checked_add(w)),
                Bound::HeaderWords(r) => words(r)?.and_then(|w| cx.rule_start.checked_add(w)),
                Bound::Remaining => Some(cx.msg_end),
            };
            let Some(e) = e else {
                return Ok(None);
            };
            if e < pos || e > cx.limit || end.is_some_and(|x| x != e) {
                return Ok(None);
            }
            end = Some(e);
            // Only these two frame a message ("How constraints bind").
            if matches!(b, Bound::Octets(_) | Bound::Words(_)) {
                msg_end = e;
            }
        }
        Ok(Some((end, msg_end)))
    }

    /// The rule's target repetition, node `n`: every target form of the
    /// rule applied together in one run, for each state.
    fn target<'m>(
        &'m self,
        n: NodeId,
        t: &Target,
        from: &States<'m>,
        cx: &Cx<'_>,
        depth: usize,
    ) -> Result<States<'m>, Exhausted> {
        let next = self.deeper(depth)?;
        let mut out = States::new(&self.meter);
        let Node::Rep {
            min, max, node: e, ..
        } = self.g.nodes[n as usize]
        else {
            return Ok(out);
        };
        for s in from.iter() {
            self.meter
                .step((t.elements.len() + t.ascending.len()) as u64)?;
            let Some((end, msg_end)) = self.bounds(&t.bounds, s.pos, &s.locals, cx)? else {
                continue;
            };
            // `exactly R E elements`: the count, within the repetition's
            // own bounds, or nothing matches.
            let mut count = None;
            let mut fits = true;
            for &r in &t.elements {
                let c = cx.lookup(&s.locals, r, &self.meter)?.and_then(Value::count);
                fits &= c.is_some_and(|c| {
                    c >= min && max.is_none_or(|m| c <= m) && count.is_none_or(|x| x == c)
                });
                count = c;
            }
            if !fits {
                continue;
            }
            let (lo, hi) = count.map_or((min, max), |c| (c, Some(c)));
            let mut start = s.clone();
            let frames = start.asc.len();
            start.asc.extend(t.ascending.iter().map(|&r| (r, None)));
            if t.tags {
                start.asc.push((TAGS, None));
            }
            let mut one = States::new(&self.meter);
            one.insert(start)?;
            let inner = Cx {
                limit: end.unwrap_or(cx.limit),
                msg_end,
                ..*cx
            };
            let mut results = self.rep(lo, hi, e, t.tags, &one, &inner, next)?;
            for mut res in results.drain() {
                if end.is_some_and(|x| res.pos != x) {
                    continue;
                }
                res.asc.truncate(frames);
                out.insert(res)?;
            }
        }
        Ok(out)
    }

    /// `min*max element`: iterate the set by count. Once the count reaches
    /// `min`, every state reached is a result, and a state already reached
    /// at such a count is dropped: it was explored then with at least as
    /// many repetitions left. That also ends a nullable element's loop.
    ///
    /// With `tags` (`ascending tags`), each element must begin with a u16
    /// above the last one's, kept in the innermost frame.
    #[allow(clippy::too_many_arguments)]
    fn rep<'m>(
        &'m self,
        min: u32,
        max: Option<u32>,
        element: NodeId,
        tags: bool,
        from: &States<'m>,
        cx: &Cx<'_>,
        depth: usize,
    ) -> Result<States<'m>, Exhausted> {
        let depth = self.deeper(depth)?;
        // A count that can't fit in what is left fails at once.
        let width = self.g.node_min[element as usize];
        if let Some(lowest) = from.iter().map(|s| s.pos).min() {
            let left = u64::from(cx.limit.saturating_sub(lowest));
            if width.saturating_mul(u64::from(min)) > left {
                return Ok(States::new(&self.meter));
            }
        }
        let mut results = States::new(&self.meter);
        let mut frontier = States::new(&self.meter);
        for s in from.iter() {
            frontier.insert(s.clone())?;
        }
        let mut k: u32 = 0;
        loop {
            if k >= min {
                let mut fresh = States::new(&self.meter);
                for s in frontier.drain() {
                    if results.insert(s.clone())? {
                        fresh.insert(s)?;
                    }
                }
                frontier = fresh;
            }
            if max == Some(k) || frontier.is_empty() {
                break;
            }
            if tags {
                frontier = self.next_tags(frontier, cx)?;
            }
            frontier = self.node(element, &frontier, cx, depth)?;
            // Past u32::MAX only an unbounded repetition goes on, and every
            // state it reaches there is a result already.
            k = k.saturating_add(1);
        }
        Ok(results)
    }

    /// `ascending tags`: keeps the states whose next element's tag, its
    /// first two octets, is above the last tag, and records it.
    fn next_tags<'m>(
        &'m self,
        mut frontier: States<'m>,
        cx: &Cx<'_>,
    ) -> Result<States<'m>, Exhausted> {
        let mut kept = States::new(&self.meter);
        for mut s in frontier.drain() {
            let at = s.pos as usize;
            let Some(&[hi, lo]) = self
                .input
                .get(at..at.saturating_add(2))
                .filter(|_| at.saturating_add(2) <= cx.limit as usize)
            else {
                continue;
            };
            let tag = Value::NonNegative(u128::from(u16::from_be_bytes([hi, lo])));
            match s.asc.last_mut() {
                Some(frame) if frame.0 == TAGS && frame.1.is_none_or(|last| tag > last) => {
                    frame.1 = Some(tag);
                }
                _ => continue,
            }
            kept.insert(s)?;
        }
        Ok(kept)
    }
}

/// `canonical float`: a NaN is the canonical quiet NaN, `7FC00000` or
/// `7FF8000000000000` (ADR 0062, rule 5). Loading allows the form only on
/// rules 4 or 8 octets wide.
fn canonical_float(span: &[u8]) -> bool {
    match *span {
        [a, b, c, d] => {
            let bits = u32::from_be_bytes([a, b, c, d]);
            let nan = bits & 0x7F80_0000 == 0x7F80_0000 && bits & 0x007F_FFFF != 0;
            !nan || bits == 0x7FC0_0000
        }
        [a, b, c, d, e, f, g, h] => {
            let bits = u64::from_be_bytes([a, b, c, d, e, f, g, h]);
            let nan = bits & 0x7FF0_0000_0000_0000 == 0x7FF0_0000_0000_0000
                && bits & 0x000F_FFFF_FFFF_FFFF != 0;
            !nan || bits == 0x7FF8_0000_0000_0000
        }
        _ => false,
    }
}
