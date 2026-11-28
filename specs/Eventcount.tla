\* SPDX-FileCopyrightText: 2026 Nicole Roy
\* SPDX-License-Identifier: MPL-2.0

------------------------------ MODULE Eventcount ------------------------------
(***************************************************************************)
(* Eventcounts, wait sets and threads bound to an eventcount (ADR 0053;   *)
(* kernel specification, "Eventcount operations", "Wait sets" and          *)
(* "Threads bound to an eventcount"; ADR 0068, rule 10).  An advance from  *)
(* a system call adds one and wakes reached waiters until a preemption     *)
(* point, then leaves the rest pending on the work list (K31); an          *)
(* interrupt's advance leaves them all pending; the work list wakes them   *)
(* one unit at a time (K24).  Wait sets wait on many eventcounts, and      *)
(* their entries can be removed during a wait (K08).  A receive with a     *)
(* bound eventcount reports an advance first, and a receiver without a     *)
(* context is never woken by one.  Destroying an eventcount releases one   *)
(* waiter per step (K30).  The properties are the kernel specification's  *)
(* "Model checking" bullets for C14's eventcounts; specs/README.md maps    *)
(* each to its operator.                                                   *)
(*                                                                         *)
(* The whole state is one record, s, and every action is written as       *)
(* s' = Effect(s, ...), so that a trace from the Rust (crates/kipc, module *)
(* eventcount) is one expression.  An advance is one step: the kernel      *)
(* holds its lock throughout, so nothing interleaves with it; how far it   *)
(* gets before its preemption point is chosen.  Objects are numbers:       *)
(* threads 1..NT, eventcounts 1..NE, wait sets 1..NW, entries 1..NI, and   *)
(* Nil = 0.  Waiters are nodes: thread t's is node t, and entry i of set w *)
(* is node NT + (w - 1) * NI + i.  Max stands for 2^64 - 1, the count's    *)
(* maximum.                                                                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    NT,          \* threads
    NE,          \* eventcounts
    NW,          \* wait sets
    NI,          \* entries per wait set
    Max,         \* the count's maximum
    WithSets,    \* whether wait sets are used
    WithBound,   \* whether eventcounts are bound to receiving threads
    WithDestroy  \* whether eventcounts and wait sets are destroyed

Threads == 1..NT
Ecs == 1..NE
Sets == 1..NW
Idx == 1..NI
Nodes == 1..(NT + NW * NI)
Nil == 0

EntryNode(w, i) == NT + (w - 1) * NI + i
IsEntry(n) == n > NT
SetOf(n) == ((n - NT - 1) \div NI) + 1
IdxOf(n) == ((n - NT - 1) % NI) + 1
Targets == 1..Max

TState == {"ready", "wait", "wswait", "recv"}
Results == {"none", "replied", "canceled", "timedout", "destroyed"}

VARIABLE s

(***************************************************************************)
(* count, pending (a batched wake is pending; the eventcount is on a work *)
(* list exactly then) and ecst (live, draining behind its zombie, gone)   *)
(* per eventcount.  ts, ctx (holds a context), res (how its last wait     *)
(* ended) and got (the count or mask its last wait or return got) per    *)
(* thread; bound and last (last-seen) for bound eventcounts, and rp,     *)
(* which flips at each report of a bound eventcount's advance, so that a  *)
(* report is a visible step even when it would change nothing else.  lk   *)
(* (the eventcount a node is linked into) and tgt (its target) per node.  *)
(* ent, waiter and wsalive per wait set.                                   *)
(***************************************************************************)
InitState ==
    [ count   |-> [e \in Ecs |-> 0],
      pending |-> [e \in Ecs |-> FALSE],
      ecst    |-> [e \in Ecs |-> "live"],
      ts      |-> [t \in Threads |-> "ready"],
      ctx     |-> [t \in Threads |-> TRUE],
      res     |-> [t \in Threads |-> "none"],
      got     |-> [t \in Threads |-> 0],
      lk      |-> [n \in Nodes |-> Nil],
      tgt     |-> [n \in Nodes |-> 0],
      bound   |-> [t \in Threads |-> Nil],
      last    |-> [t \in Threads |-> 0],
      rp      |-> [t \in Threads |-> FALSE],
      ent     |-> [w \in Sets |-> [i \in Idx |-> Nil]],
      waiter  |-> [w \in Sets |-> Nil],
      wsalive |-> [w \in Sets |-> TRUE] ]

Init == s = InitState

TypeOK ==
    /\ s.count   \in [Ecs -> 0..Max]
    /\ s.pending \in [Ecs -> BOOLEAN]
    /\ s.ecst    \in [Ecs -> {"live", "draining", "gone"}]
    /\ s.ts      \in [Threads -> TState]
    /\ s.ctx     \in [Threads -> BOOLEAN]
    /\ s.res     \in [Threads -> Results]
    /\ s.got     \in [Threads -> 0..(2^NI + Max)]
    /\ s.lk      \in [Nodes -> Ecs \cup {Nil}]
    /\ s.tgt     \in [Nodes -> 0..Max]
    /\ s.bound   \in [Threads -> Ecs \cup {Nil}]
    /\ s.last    \in [Threads -> 0..Max]
    /\ s.rp      \in [Threads -> BOOLEAN]
    /\ s.ent     \in [Sets -> [Idx -> Ecs \cup {Nil}]]
    /\ s.waiter  \in [Sets -> Threads \cup {Nil}]
    /\ s.wsalive \in [Sets -> BOOLEAN]

(***************************************************************************)
(* Helpers.                                                                *)
(***************************************************************************)
Runs(t) == s.ts[t] = "ready" /\ s.ctx[t]

Linked(st, e) == {n \in Nodes: st.lk[n] = e}
Reached(st, e) == {n \in Linked(st, e): st.tgt[n] <= st.count[e]}
SetNodes(w) == {EntryNode(w, i) : i \in Idx}

\* The first node of a set of linked nodes in the tree's order: by target,
\* then by node.
First(st, N) ==
    CHOOSE n \in N: \A m \in N: st.tgt[n] < st.tgt[m] \/ (st.tgt[n] = st.tgt[m] /\ n <= m)

RECURSIVE SumBits(_)
SumBits(S) == IF S = {} THEN 0
              ELSE LET i == CHOOSE i \in S: TRUE IN 2^(i - 1) + SumBits(S \ {i})

\* The mask of w's present entries that have reached their targets.
Mask(st, w) ==
    SumBits({i \in Idx: st.ent[w][i] # Nil /\ st.count[st.ent[w][i]] >= st.tgt[EntryNode(w, i)]})

\* A thread's node loses its target when unlinked; an entry's keeps it.
Unlink(st, n) == [st EXCEPT !.lk[n] = Nil, !.tgt[n] = IF IsEntry(n) THEN st.tgt[n] ELSE 0]
Link(st, n, e, g) == [st EXCEPT !.lk[n] = e, !.tgt[n] = g]
UnlinkSet(st, w) ==
    [st EXCEPT !.lk = [n \in Nodes |-> IF n \in SetNodes(w) THEN Nil ELSE st.lk[n]]]

\* The waiter of w is woken: every entry is unlinked, and it gets the mask.
WakeSet(st, w) ==
    LET t == st.waiter[w] IN
    [UnlinkSet(st, w) EXCEPT !.waiter[w] = Nil, !.ts[t] = "ready", !.res[t] = "replied",
                             !.got[t] = Mask(st, w)]

\* The waiter at node n, linked into e with its target reached, is woken:
\* a direct waiter gets the count; a bound receiver that holds a context
\* gets the advance, and last-seen becomes the count; one that holds none
\* is only unlinked, and stays receiving.
WakeNode(st, n) ==
    LET e == st.lk[n] IN
    IF IsEntry(n) THEN WakeSet(st, SetOf(n))
    ELSE IF st.ts[n] = "recv"
    THEN IF st.ctx[n]
         THEN [Unlink(st, n) EXCEPT !.ts[n] = "ready", !.res[n] = "replied",
                                    !.got[n] = st.count[e], !.last[n] = st.count[e],
                                    !.rp[n] = ~st.rp[n]]
         ELSE Unlink(st, n)
    ELSE [Unlink(st, n) EXCEPT !.ts[n] = "ready", !.res[n] = "replied", !.got[n] = st.count[e]]

\* Up to k wakes of e's reached waiters, first in the tree's order.
RECURSIVE WakeK(_, _, _)
WakeK(st, e, k) ==
    IF k = 0 \/ Reached(st, e) = {} THEN st
    ELSE WakeK(WakeNode(st, First(st, Reached(st, e))), e, k - 1)

\* Reached waiters left over are pending: e goes on a work list, unless it
\* is on one.
MarkPending(st, e) ==
    IF Reached(st, e) # {} THEN [st EXCEPT !.pending[e] = TRUE] ELSE st

\* Ending t's wait with x: a cancel, a deadline.
EndAny(st, t, x) ==
    IF st.ts[t] = "wswait"
    THEN LET w == CHOOSE w \in Sets: st.waiter[w] = t IN
         [UnlinkSet(st, w) EXCEPT !.waiter[w] = Nil, !.ts[t] = "ready", !.res[t] = x]
    ELSE [Unlink(st, t) EXCEPT !.ts[t] = "ready", !.res[t] = x]

(***************************************************************************)
(* Eventcount operations.                                                  *)
(***************************************************************************)

\* A target already reached returns at once, with the count.
Wait(t, e, g) ==
    /\ Runs(t) /\ s.ecst[e] = "live"
    /\ s' = IF s.count[e] >= g THEN [s EXCEPT !.got[t] = s.count[e]]
            ELSE [Link(s, t, e, g) EXCEPT !.ts[t] = "wait", !.res[t] = "none"]

\* A system call's advance: one is added, k reached waiters are woken
\* before a preemption point finds an interrupt pending, and the rest are
\* left pending (K31).  At the maximum it fails and changes nothing.
Advance(e) ==
    /\ s.ecst[e] = "live" /\ s.count[e] < Max
    /\ \E k \in 0..Cardinality(Nodes):
         s' = MarkPending(WakeK([s EXCEPT !.count[e] = @ + 1], e, k), e)

\* An interrupt's advance (C13b's seam): every wake is left pending.
IrqAdvance(e) ==
    /\ s.ecst[e] = "live" /\ s.count[e] < Max
    /\ s' = MarkPending([s EXCEPT !.count[e] = @ + 1], e)

\* One unit of the work list: the first reached waiter is woken; when none
\* is left, the mark clears and e leaves its list (K24).
BatchUnit(e) ==
    /\ s.pending[e]
    /\ LET st == IF Reached(s, e) # {} THEN WakeNode(s, First(s, Reached(s, e))) ELSE s
       IN s' = IF Reached(st, e) = {} THEN [st EXCEPT !.pending[e] = FALSE] ELSE st

(***************************************************************************)
(* Wait sets (K08, K32).                                                   *)
(***************************************************************************)

\* During a wait the entry is linked, and ends the wait if reached.
WsAdd(w, i, e, g) ==
    /\ WithSets /\ s.wsalive[w] /\ s.ent[w][i] = Nil /\ s.ecst[e] = "live"
    /\ LET n == EntryNode(w, i)
           st == [s EXCEPT !.ent[w][i] = e, !.tgt[n] = g]
       IN s' = IF st.waiter[w] = Nil THEN st
               ELSE IF st.count[e] >= g THEN WakeSet([st EXCEPT !.lk[n] = e], w)
               ELSE [st EXCEPT !.lk[n] = e]

\* Removing an entry, or revoking its copy: the wait goes on on the
\* others; with none left linked, it ends with the others' mask, empty.
WsRemove(w, i) ==
    /\ WithSets /\ s.wsalive[w] /\ s.ent[w][i] # Nil
    /\ LET n == EntryNode(w, i)
           st == [s EXCEPT !.lk[n] = Nil]
           t == s.waiter[w]
           gone == [st EXCEPT !.ent[w][i] = Nil, !.tgt[n] = 0]
       IN s' = IF t # Nil /\ s.lk[n] # Nil /\ \A m \in SetNodes(w): st.lk[m] = Nil
               THEN [gone EXCEPT !.waiter[w] = Nil, !.ts[t] = "ready", !.res[t] = "replied",
                                 !.got[t] = Mask(gone, w)]
               ELSE gone

\* One wait at a time.  A reached entry, or no entry, returns at once.
WsWait(t, w) ==
    /\ WithSets /\ Runs(t) /\ s.wsalive[w] /\ s.waiter[w] = Nil
    /\ LET m == Mask(s, w) IN
       s' = IF m # 0 \/ \A i \in Idx: s.ent[w][i] = Nil
            THEN [s EXCEPT !.got[t] = m]
            ELSE [s EXCEPT !.lk = [n \in Nodes |->
                                     IF n \in SetNodes(w) THEN s.ent[w][IdxOf(n)] ELSE s.lk[n]],
                           !.waiter[w] = t, !.ts[t] = "wswait", !.res[t] = "none"]

\* The wait set's last capability goes: its wait ends "destroyed", and its
\* entries leave their trees and their slots.
DestroyWs(w) ==
    /\ WithSets /\ WithDestroy /\ s.wsalive[w]
    /\ LET t == s.waiter[w]
           st == UnlinkSet(s, w)
           st1 == IF t # Nil THEN [st EXCEPT !.waiter[w] = Nil, !.ts[t] = "ready",
                                             !.res[t] = "destroyed"]
                  ELSE st
       IN s' = [st1 EXCEPT !.wsalive[w] = FALSE, !.ent[w] = [i \in Idx |-> Nil],
                           !.tgt = [n \in Nodes |-> IF n \in SetNodes(w) THEN 0 ELSE st1.tgt[n]]]

(***************************************************************************)
(* Bound eventcounts (ADR 0053, rule 5).                                   *)
(***************************************************************************)
Bind(t, e) ==
    /\ WithBound /\ s.bound[t] = Nil /\ s.ecst[e] = "live"
    /\ LET st == [s EXCEPT !.bound[t] = e, !.last[t] = s.count[e]] IN
       s' = IF s.ts[t] = "recv" /\ s.ctx[t] /\ s.count[e] < Max
            THEN Link(st, t, e, s.count[e] + 1) ELSE st

\* A receive in progress goes on, on the endpoint alone.
Unbind(t) ==
    /\ WithBound /\ s.bound[t] # Nil
    /\ LET st == IF s.ts[t] = "recv" THEN Unlink(s, t) ELSE s IN
       s' = [st EXCEPT !.bound[t] = Nil, !.last[t] = 0]

\* A receive on an endpoint: an advance past last-seen is reported at
\* once, before any message; otherwise the thread waits, linked with target
\* last-seen + 1, unless last-seen is the maximum.
Recv(t) ==
    /\ WithBound /\ Runs(t)
    /\ LET e == s.bound[t] IN
       s' = IF e # Nil /\ s.count[e] > s.last[t]
            THEN [s EXCEPT !.got[t] = s.count[e], !.last[t] = s.count[e], !.res[t] = "replied",
                           !.rp[t] = ~s.rp[t]]
            ELSE LET st == [s EXCEPT !.ts[t] = "recv", !.res[t] = "none"] IN
                 IF e # Nil /\ s.last[t] < Max THEN Link(st, t, e, s.last[t] + 1) ELSE st

\* A receive made without a context: a passive server's reply and receive,
\* whose reply gives its donated context back before the receive.  It
\* neither reports an advance nor links its node: a receiver without a
\* context waits on its endpoint alone.
PassiveRecv(t) ==
    /\ WithBound /\ Runs(t)
    /\ s' = [s EXCEPT !.ctx[t] = FALSE, !.ts[t] = "recv", !.res[t] = "none"]

\* A message reaches a receiver: its receive ends, and its node leaves.
MsgArrive(t) ==
    /\ WithBound /\ s.ts[t] = "recv"
    /\ s' = [Unlink(s, t) EXCEPT !.ts[t] = "ready", !.res[t] = "replied"]

\* Its context is taken or unbound; its node stays linked until a wake.
LoseCtx(t) ==
    /\ WithBound /\ s.ctx[t]
    /\ s' = [s EXCEPT !.ctx[t] = FALSE]

\* A context is bound: a receiver hears an advance it hasn't seen, or links.
GainCtx(t) ==
    /\ WithBound /\ ~s.ctx[t]
    /\ LET st == [s EXCEPT !.ctx[t] = TRUE]
           e == s.bound[t]
       IN s' = IF s.ts[t] = "recv" /\ e # Nil
               THEN IF s.count[e] > s.last[t]
                    THEN [Unlink(st, t) EXCEPT !.ts[t] = "ready", !.res[t] = "replied",
                                               !.got[t] = s.count[e], !.last[t] = s.count[e],
                                               !.rp[t] = ~s.rp[t]]
                    ELSE IF s.lk[t] = Nil /\ s.last[t] < Max
                    THEN Link(st, t, e, s.last[t] + 1)
                    ELSE st
               ELSE st

(***************************************************************************)
(* Ending waits, and destruction.                                          *)
(***************************************************************************)
Cancel(t) ==
    /\ s.ts[t] # "ready"
    /\ s' = EndAny(s, t, "canceled")

Deadline(t) ==
    /\ s.ts[t] # "ready"
    /\ s' = EndAny(s, t, "timedout")

\* The eventcount's last capability becomes a queue zombie.  Entries and
\* bindings hold copies, so none names it.
DestroyEc(e) ==
    /\ WithDestroy /\ s.ecst[e] = "live"
    /\ \A t \in Threads: s.bound[t] # e
    /\ \A w \in Sets: \A i \in Idx: s.ent[w][i] # e
    /\ s' = [s EXCEPT !.ecst[e] = "draining"]

\* One step: the first waiter is woken with the count if its target is
\* reached, or ends "destroyed"; with none left, the eventcount leaves its
\* work list and is gone.
DrainStep(e) ==
    /\ s.ecst[e] = "draining"
    /\ LET st == IF Linked(s, e) = {} THEN s
                 ELSE LET n == First(s, Linked(s, e)) IN
                      IF s.tgt[n] <= s.count[e] THEN WakeNode(s, n)
                      ELSE [Unlink(s, n) EXCEPT !.ts[n] = "ready", !.res[n] = "destroyed"]
       IN s' = IF Linked(st, e) = {} THEN [st EXCEPT !.ecst[e] = "gone", !.pending[e] = FALSE]
               ELSE st

Next ==
    \/ \E t \in Threads:
         \/ Cancel(t) \/ Deadline(t) \/ Recv(t) \/ PassiveRecv(t) \/ MsgArrive(t)
         \/ LoseCtx(t) \/ GainCtx(t)
         \/ Unbind(t)
         \/ \E e \in Ecs: Bind(t, e) \/ \E g \in Targets: Wait(t, e, g)
         \/ \E w \in Sets: WsWait(t, w)
    \/ \E e \in Ecs: Advance(e) \/ IrqAdvance(e) \/ BatchUnit(e) \/ DestroyEc(e) \/ DrainStep(e)
    \/ \E w \in Sets:
         \/ DestroyWs(w)
         \/ \E i \in Idx: WsRemove(w, i) \/ \E e \in Ecs, g \in Targets: WsAdd(w, i, e, g)

\* The work list and the zombie's steps progress.
Fairness == \A e \in Ecs: WF_s(BatchUnit(e)) /\ WF_s(DrainStep(e))

Spec == Init /\ [][Next]_s /\ Fairness

(***************************************************************************)
(* Invariants.                                                             *)
(***************************************************************************)

\* No wake-up is lost: a linked waiter whose target is reached has a wake
\* pending, or its eventcount is draining.
NoLostWakeup ==
    \A e \in Ecs: Reached(s, e) # {} => s.pending[e] \/ s.ecst[e] = "draining"

\* A gone eventcount is on no work list and has no waiter.
GoneClean ==
    \A e \in Ecs: s.ecst[e] = "gone" => ~s.pending[e] /\ Linked(s, e) = {}

\* Each wait has its nodes, and no node is linked without one.  A receiver
\* that holds a context and is bound below the maximum is linked, with
\* target last-seen + 1.
WaitsWellFormed ==
    \A t \in Threads:
      /\ s.ts[t] = "wait" => s.lk[t] # Nil
      /\ s.ts[t] \in {"ready", "wswait"} => s.lk[t] = Nil
      /\ (s.ts[t] = "wswait") <=> (\E w \in Sets: s.waiter[w] = t)
      /\ s.ts[t] = "recv" /\ s.lk[t] # Nil => s.lk[t] = s.bound[t] /\ s.tgt[t] = s.last[t] + 1
      /\ s.ts[t] = "recv" /\ s.ctx[t] /\ s.bound[t] # Nil /\ s.last[t] < Max =>
           s.lk[t] = s.bound[t]

\* A thread waits on at most one set (checked only where NW > 1, as the
\* trace model has it); while a set's wait lasts, every present entry is
\* linked; without one, none is.  A removed entry is linked nowhere.  One
\* wait per set is WsWait's guard, s.waiter[w] = Nil, and WaitsWellFormed
\* checks it: a thread left in "wswait" is some set's waiter.
EntriesWellFormed ==
    \A w \in Sets:
      /\ \A v \in Sets: v # w /\ s.waiter[w] # Nil => s.waiter[v] # s.waiter[w]
      /\ \A i \in Idx:
           LET n == EntryNode(w, i) IN
           /\ s.ent[w][i] = Nil => s.lk[n] = Nil /\ s.tgt[n] = 0
           /\ s.ent[w][i] # Nil /\ s.waiter[w] # Nil => s.lk[n] = s.ent[w][i]
           /\ s.waiter[w] = Nil => s.lk[n] = Nil
      /\ s.waiter[w] # Nil => \E i \in Idx: s.ent[w][i] # Nil
      /\ ~s.wsalive[w] => s.waiter[w] = Nil /\ \A i \in Idx: s.ent[w][i] = Nil

\* A bound thread's last-seen count never passes the count.
LastSeenBelowCount ==
    \A t \in Threads: s.bound[t] # Nil => s.last[t] <= s.count[s.bound[t]]

Invariants ==
    /\ TypeOK /\ NoLostWakeup /\ GoneClean /\ WaitsWellFormed /\ EntriesWellFormed
    /\ LastSeenBelowCount

(***************************************************************************)
(* Action and temporal properties.                                        *)
(***************************************************************************)

\* The count never decreases, and a step adds at most one: an advance adds
\* one exactly once, however far it gets before its preemption point (K31).
CountNeverDecreases ==
    [][\A e \in Ecs: s'.count[e] \in {s.count[e], s.count[e] + 1}]_s

\* An advance wakes no waiter whose target the count hasn't reached: a
\* direct waiter gets a count at or past its target, and a wait-set waiter
\* a mask of reached entries, empty only when its last entry was removed.
WakesOnlyReached ==
    [][\A t \in Threads:
         /\ s.ts[t] = "wait" /\ s'.ts[t] = "ready" /\ s'.res[t] = "replied" =>
              s'.got[t] >= s.tgt[t]
         /\ s.ts[t] = "wswait" /\ s'.ts[t] = "ready" /\ s'.res[t] = "replied" =>
              LET w == CHOOSE w \in Sets: s.waiter[w] = t IN
              /\ \A i \in Idx: (s'.got[t] \div 2^(i - 1)) % 2 = 1 =>
                   s'.ent[w][i] # Nil /\ s'.count[s'.ent[w][i]] >= s'.tgt[EntryNode(w, i)]
              /\ s'.got[t] = 0 => \E i \in Idx: s.ent[w][i] # Nil /\ s'.ent[w][i] = Nil]_s

\* A wait whose target is reached returns at once: no thread starts to wait
\* on a reached target.
WaitReachedReturnsAtOnce ==
    [][\A t \in Threads:
         s.ts[t] = "ready" /\ s'.ts[t] = "wait" => s'.tgt[t] > s'.count[s'.lk[t]]]_s

\* Each report of a bound eventcount's advance (rp flips) tells a thread
\* still bound a count past its last-seen one, which becomes its
\* last-seen: no advance is reported twice, or that didn't happen.  A
\* bound thread's last-seen count moves only so.
NoSpuriousReport ==
    [][\A t \in Threads:
         /\ s'.rp[t] # s.rp[t] =>
              /\ s.bound[t] # Nil /\ s'.bound[t] = s.bound[t]
              /\ s'.last[t] > s.last[t] /\ s'.got[t] = s'.last[t] /\ s'.res[t] = "replied"
         /\ s.bound[t] # Nil /\ s'.bound[t] = s.bound[t] /\ s'.last[t] # s.last[t] =>
              s'.rp[t] # s.rp[t]]_s

\* A receiver without a context is never woken by an advance: its
\* last-seen count stays until it receives with a context, and nothing is
\* reported to it.  A receive made without one neither reports nor links.
PassiveNotWoken ==
    [][\A t \in Threads:
         /\ s.ts[t] = "recv" /\ ~s.ctx[t] /\ ~s'.ctx[t] /\ s'.bound[t] = s.bound[t] =>
              /\ s'.last[t] = s.last[t] /\ s'.rp[t] = s.rp[t]
              /\ s'.ts[t] = "ready" => s'.got[t] = s.got[t]
         /\ s.ts[t] = "ready" /\ s'.ts[t] = "recv" /\ ~s'.ctx[t] =>
              s'.lk[t] = Nil /\ s'.rp[t] = s.rp[t]]_s

\* Every linked waiter whose target is reached is woken, or unlinked, in
\* the end.
ReachedWoken ==
    \A e \in Ecs, n \in Nodes:
      (s.lk[n] = e /\ s.tgt[n] <= s.count[e]) ~> s.lk[n] # e

=============================================================================
