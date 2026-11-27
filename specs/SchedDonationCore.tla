\* SPDX-FileCopyrightText: 2026 Nicole Roy
\* SPDX-License-Identifier: MPL-2.0

---------------------------- MODULE SchedDonationCore ----------------------------
(***************************************************************************)
(* Scheduling-context donation along chains of calls, and taking a        *)
(* context back (ADR 0051, rule 3; kernel specification, "Passive servers  *)
(* and taking a context back").  This module holds the state and every     *)
(* action but the take-back's walk, which SchedDonation (batched) and      *)
(* SchedDonationAtOnce (atomic) each finish in their own way.              *)
(*                                                                         *)
(* The whole state is one record, s, so that a refinement mapping and a    *)
(* trace from the Rust (crates/ksched, module donation) are each one       *)
(* expression.  Every action is written as s' = Effect(s, ...), and the    *)
(* Rust's operations are the same effects: ksched::donation names each     *)
(* action it implements.                                                   *)
(*                                                                         *)
(* Objects are numbers: threads 1..NT, replies 1..NR, contexts 1..NS, and  *)
(* Nil = 0.                                                                *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    NT,          \* threads
    NR,          \* reply objects
    NS,          \* scheduling contexts
    TepInit,     \* the threads that start with a timeout endpoint
    WithDestroy, \* whether objects can be destroyed
    WithSetTep,  \* whether timeout endpoints can be set and removed (K08, K50)
    WithSuspend, \* whether threads can be suspended (ADR 0061, rule 3)
    Refine       \* the refinement model: no interference with pending walks

Threads == 1..NT
Replies == 1..NR
SCs == 1..NS
Nil == 0

TState == {"ready", "recv", "call", "fault", "other"}
RState == {"idle", "recv", "pending", "stale", "invalid"}
Results == {"none", "replied", "canceled", "timedout"}
Faults == {"none", "timeout", "withdrawn"}

VARIABLE s

(***************************************************************************)
(* The initial state: context i is bound to thread i, which runs on it.    *)
(* The other threads are passive servers, each waiting to receive on its   *)
(* own reply object while there are enough.                                *)
(***************************************************************************)
InitState ==
    [ holder  |-> [c \in SCs |-> c],
      home    |-> [c \in SCs |-> c],
      stack   |-> [c \in SCs |-> << >>],
      rst     |-> [r \in Replies |-> IF NS + r <= NT THEN "recv" ELSE "idle"],
      rcaller |-> [r \in Replies |-> Nil],
      rserver |-> [r \in Replies |-> IF NS + r <= NT THEN NS + r ELSE Nil],
      rsc     |-> [r \in Replies |-> Nil],
      ts      |-> [t \in Threads |->
                     IF t > NS /\ t - NS <= NR THEN "recv" ELSE "ready"],
      wr      |-> [t \in Threads |->
                     IF t > NS /\ t - NS <= NR THEN t - NS ELSE Nil],
      fk      |-> [t \in Threads |-> "none"],
      res     |-> [t \in Threads |-> "none"],
      serving |-> [t \in Threads |-> Nil],
      tep     |-> [t \in Threads |-> t \in TepInit],
      susp    |-> [t \in Threads |-> FALSE],
      walks   |-> {},
      talive  |-> [t \in Threads |-> TRUE],
      ralive  |-> [r \in Replies |-> TRUE],
      scalive |-> [c \in SCs |-> TRUE] ]

Init == s = InitState

TypeOK ==
    /\ s.holder  \in [SCs -> Threads \cup {Nil}]
    /\ s.home    \in [SCs -> Threads \cup {Nil}]
    /\ \A c \in SCs: s.stack[c] \in Seq(Replies)
    /\ s.rst     \in [Replies -> RState]
    /\ s.rcaller \in [Replies -> Threads \cup {Nil}]
    /\ s.rserver \in [Replies -> Threads \cup {Nil}]
    /\ s.rsc     \in [Replies -> SCs \cup {Nil}]
    /\ s.ts      \in [Threads -> TState]
    /\ s.wr      \in [Threads -> Replies \cup {Nil}]
    /\ s.fk      \in [Threads -> Faults]
    /\ s.res     \in [Threads -> Results]
    /\ s.serving \in [Threads -> Replies \cup {Nil}]
    /\ s.tep     \in [Threads -> BOOLEAN]
    /\ s.susp    \in [Threads -> BOOLEAN]
    /\ \A w \in s.walks: w \in Seq(Replies) /\ w # << >>
    /\ s.talive  \in [Threads -> BOOLEAN]
    /\ s.ralive  \in [Replies -> BOOLEAN]
    /\ s.scalive \in [SCs -> BOOLEAN]

(***************************************************************************)
(* Helpers.                                                                *)
(***************************************************************************)
Range(q) == {q[i] : i \in DOMAIN q}

\* The context thread t holds, or Nil.
CtxOf(st, t) == IF \E c \in SCs: st.holder[c] = t
                THEN CHOOSE c \in SCs: st.holder[c] = t ELSE Nil

\* The context thread t is bound to, or Nil.
HomeOf(st, t) == IF \E c \in SCs: st.home[c] = t
                 THEN CHOOSE c \in SCs: st.home[c] = t ELSE Nil

\* A thread that may run: alive, ready, not suspended, holding a context.
Runs(st, t) == /\ st.talive[t] /\ st.ts[t] = "ready" /\ ~st.susp[t]
               /\ CtxOf(st, t) # Nil

\* A live donating reply: pending, with a context, on its context's stack.
Live(st, r) == st.rst[r] = "pending" /\ st.rsc[r] # Nil

\* The index of r in sequence q.
IndexOf(q, r) == CHOOSE i \in DOMAIN q: q[i] = r

\* The walk whose replies include r.
WalkOf(st, r) == CHOOSE w \in st.walks: r \in Range(w)

\* A thread or reply that a pending walk still has to reach.
OnWalk(st, t) == \E w \in st.walks: \E q \in Range(w):
                    st.rserver[q] = t \/ st.rcaller[q] = t
ReplyOnWalk(st, r) == \E w \in st.walks: r \in Range(w)

\* "Owed": a thread whose walk step hasn't come yet (no ghost needed).
Owed(st, t) == st.serving[t] # Nil /\ st.rst[st.serving[t]] = "stale"

\* t's wait ends with result x.
EndWait(st, t, x) ==
    [st EXCEPT !.ts[t] = "ready", !.wr[t] = Nil, !.fk[t] = "none",
               !.res[t] = x]

(***************************************************************************)
(* Taking a context back: the start, O(1) in the Rust.  r is a live        *)
(* donating reply on context c, its caller gets c back with result x, and  *)
(* the segment from r to the top of c's stack becomes a walk.  The holder, *)
(* the top server, loses c, and its own wait is canceled at once (K17).    *)
(* r loses its caller; the segment's replies are stale until their step.   *)
(***************************************************************************)
CancelHolderWait(st, t) ==
    CASE st.ts[t] = "ready" -> st
      [] st.ts[t] = "recv" ->
           LET q == st.wr[t] IN
           [EndWait(st, t, "canceled") EXCEPT
               !.rst[q] = "idle", !.rserver[q] = Nil]
      [] st.ts[t] = "call" ->
           \* The holder's call can't donate: it holds the context.
           LET q == st.wr[t] IN
           [EndWait(st, t, "canceled") EXCEPT
               !.rst[q] = "invalid", !.rcaller[q] = Nil]
      [] st.ts[t] = "fault" -> EndWait(st, t, "none")
      [] st.ts[t] = "other" -> EndWait(st, t, "canceled")

TakeBackStart(st, r, x) ==
    LET c    == st.rsc[r]
        stk  == st.stack[c]
        i    == IndexOf(stk, r)
        seg  == SubSeq(stk, i, Len(stk))
        top  == st.rserver[stk[Len(stk)]]
        clr  == st.rcaller[r]
        st1  == [st EXCEPT !.holder[c] = Nil]
        st2  == CancelHolderWait(st1, top)
    IN [st2 EXCEPT
          !.stack[c]   = SubSeq(stk, 1, i - 1),
          !.rst        = [q \in Replies |->
                            IF q \in Range(seg) THEN "stale" ELSE st2.rst[q]],
          !.rcaller[r] = Nil,
          !.holder[c]  = clr,
          !.ts[clr]    = "ready",
          !.wr[clr]    = Nil,
          !.res[clr]   = x,
          !.walks      = st2.walks \cup {seg}]

(***************************************************************************)
(* One step of a walk, at its head q, whose server is S.  S's onward call, *)
(* a wait on the next reply of the walk, ends "canceled" (K17).  Then, if  *)
(* S is still without a context and has a timeout endpoint now, it gets a  *)
(* context-withdrawn fault, which donates nothing.  q becomes invalid, so  *)
(* S's later reply fails with "no caller".                                 *)
(***************************************************************************)
StepServer(st, q, nxt) ==
    LET S == st.rserver[q] IN
    IF S = Nil THEN st
    ELSE
      LET st1 == IF nxt # Nil /\ st.ts[S] = "call" /\ st.wr[S] = nxt
                 THEN [EndWait(st, S, "canceled") EXCEPT !.rcaller[nxt] = Nil]
                 ELSE st
          stranded == st1.ts[S] = "ready" /\ CtxOf(st1, S) = Nil
          st2 == [st1 EXCEPT !.serving[S] = Nil]
      IN IF stranded /\ st2.tep[S]
         THEN [st2 EXCEPT !.ts[S] = "fault", !.fk[S] = "withdrawn"]
         ELSE st2

WalkStepEffect(st, w) ==
    LET q   == Head(w)
        nxt == IF Len(w) > 1 THEN w[2] ELSE Nil
        st1 == StepServer(st, q, nxt)
    IN [st1 EXCEPT
          !.rst[q] = "invalid", !.rserver[q] = Nil, !.rsc[q] = Nil,
          !.rcaller[q] = Nil,
          !.walks = (st1.walks \ {w}) \cup (IF Len(w) > 1 THEN {Tail(w)} ELSE {})]

\* Every step of walk w, at once.
RECURSIVE RunWalk(_, _)
RunWalk(st, w) ==
    IF Len(w) = 1 THEN WalkStepEffect(st, w)
    ELSE RunWalk(WalkStepEffect(st, w), Tail(w))

\* Every pending walk, at once: the walks touch disjoint objects, so the
\* order doesn't matter.
RECURSIVE RunAll(_)
RunAll(st) ==
    IF st.walks = {} THEN st
    ELSE RunAll(RunWalk(st, CHOOSE w \in st.walks: TRUE))

(***************************************************************************)
(* The other effects.  TB(st, r, x) is the take-back, which the batched    *)
(* and at-once specs define.                                               *)
(***************************************************************************)
RecvEffect(st, t, r) ==
    [st EXCEPT !.rst[r] = "recv", !.rserver[r] = t, !.rcaller[r] = Nil,
               !.rsc[r] = Nil, !.ts[t] = "recv", !.wr[t] = r, !.res[t] = "none"]

CallEffect(st, cl, v) ==
    LET r   == st.wr[v]
        c   == CtxOf(st, cl)
        don == CtxOf(st, v) = Nil
        st1 == [st EXCEPT !.ts[cl] = "call", !.wr[cl] = r, !.res[cl] = "none",
                          !.ts[v] = "ready", !.wr[v] = Nil, !.res[v] = "none",
                          !.rst[r] = "pending", !.rcaller[r] = cl]
    IN IF don
       THEN [st1 EXCEPT !.rserver[r] = v, !.rsc[r] = c,
                        !.stack[c] = Append(st.stack[c], r),
                        !.holder[c] = v, !.serving[v] = r]
       ELSE [st1 EXCEPT !.rserver[r] = Nil, !.rsc[r] = Nil]

\* Whether a reply by t on r does something.
ReplyApplies(st, t, r) ==
    \/ /\ st.rst[r] = "pending" /\ st.rsc[r] # Nil
       /\ st.holder[st.rsc[r]] = t
       /\ st.stack[st.rsc[r]] # << >>
       /\ st.stack[st.rsc[r]][Len(st.stack[st.rsc[r]])] = r
    \/ st.rst[r] = "pending" /\ st.rsc[r] = Nil
    \/ st.rst[r] = "invalid"

ReplyEffect(st, t, r) ==
    LET clr == st.rcaller[r]
        idle(x) == [x EXCEPT !.rst[r] = "idle", !.rcaller[r] = Nil,
                             !.rserver[r] = Nil, !.rsc[r] = Nil]
    IN
    CASE st.rst[r] = "pending" /\ st.rsc[r] # Nil ->
           LET c == st.rsc[r] IN
           idle([EndWait(st, clr, "replied") EXCEPT
                   !.stack[c] = SubSeq(st.stack[c], 1, Len(st.stack[c]) - 1),
                   !.holder[c] = clr, !.serving[t] = Nil])
      [] st.rst[r] = "pending" ->
           idle(EndWait(st, clr, "replied"))
      [] OTHER -> idle(st)

\* Ending thread t's wait with result x (a cancel, or a deadline).
EndAnyWait(st, t, x, TB(_, _, _)) ==
    LET q == st.wr[t] IN
    CASE st.ts[t] = "call" /\ Live(st, q) -> TB(st, q, x)
      [] st.ts[t] = "call" /\ st.rst[q] = "stale" ->
           [EndWait(st, t, x) EXCEPT !.rcaller[q] = Nil]
      [] st.ts[t] = "call" ->
           [EndWait(st, t, x) EXCEPT !.rst[q] = "invalid", !.rcaller[q] = Nil]
      [] st.ts[t] = "recv" ->
           [EndWait(st, t, x) EXCEPT !.rst[q] = "idle", !.rserver[q] = Nil]
      [] st.ts[t] = "fault" -> EndWait(st, t, "none")
      [] OTHER -> EndWait(st, t, x)

\* Unbinding context c from its home, taking it back first (KS, bindings).
UnbindEffect(st, c, TB(_, _, _)) ==
    LET h   == st.home[c]
        st1 == IF st.stack[c] # << >> THEN TB(st, st.stack[c][1], "canceled")
               ELSE st
    IN [st1 EXCEPT !.home[c] = Nil, !.holder[c] = Nil]

\* Destroying thread t: the donated call it serves is taken back for
\* its caller, then its own wait ends, then its home context is unbound.
DestroyThreadEffect(st, t, TB(_, _, _)) ==
    LET q   == st.serving[t]
        st1 == IF q = Nil THEN st
               ELSE IF Live(st, q)
               THEN [TB(st, q, "canceled") EXCEPT !.rserver[q] = Nil,
                                                  !.serving[t] = Nil]
               ELSE [st EXCEPT !.rserver[q] = Nil, !.serving[t] = Nil]
        st2 == IF st1.ts[t] = "ready" THEN st1
               ELSE EndAnyWait(st1, t, "canceled", TB)
        c   == HomeOf(st2, t)
        st3 == IF c = Nil THEN st2
               ELSE [st2 EXCEPT !.home[c] = Nil, !.holder[c] = Nil]
    IN [st3 EXCEPT !.talive[t] = FALSE, !.ts[t] = "ready", !.wr[t] = Nil,
                   !.fk[t] = "none", !.res[t] = "none", !.serving[t] = Nil,
                   !.tep[t] = FALSE, !.susp[t] = FALSE]

\* Destroying reply r.  A live donating reply is a cut at r, and r's
\* own step follows at once.  A stale one takes its step at once: its
\* caller's wait on it ends, and it leaves its walk.
DestroyReplyEffect(st, r, TB(_, _, _)) ==
    LET gone(x) == [x EXCEPT !.ralive[r] = FALSE, !.rst[r] = "idle",
                             !.rcaller[r] = Nil, !.rserver[r] = Nil,
                             !.rsc[r] = Nil]
        clr == st.rcaller[r]
    IN
    CASE Live(st, r) ->
           LET st1 == TB(st, r, "canceled") IN
           IF ReplyOnWalk(st1, r)
           THEN LET w == WalkOf(st1, r) IN gone(WalkStepEffect(st1, w))
           ELSE gone(st1)
      [] st.rst[r] = "stale" ->
           LET w   == WalkOf(st, r)
               i   == IndexOf(w, r)
               nxt == IF i < Len(w) THEN w[i + 1] ELSE Nil
               st1 == IF clr # Nil
                      THEN [EndWait(st, clr, "canceled") EXCEPT !.rcaller[r] = Nil]
                      ELSE st
               st2 == StepServer(st1, r, nxt)
               rest == SubSeq(w, 1, i - 1) \o SubSeq(w, i + 1, Len(w))
           IN gone([st2 EXCEPT !.walks = (st2.walks \ {w}) \cup
                                          (IF rest = << >> THEN {} ELSE {rest})])
      [] st.rst[r] = "pending" ->
           gone(EndWait(st, clr, "canceled"))
      [] st.rst[r] = "recv" ->
           gone(EndWait(st, st.rserver[r], "canceled"))
      [] OTHER -> gone(st)

\* Destroying context c: unbound first, taken back first if donated.  Its
\* pending walks carry on: they need nothing from it.
DestroySCEffect(st, c, TB(_, _, _)) ==
    LET st1 == IF st.home[c] # Nil THEN UnbindEffect(st, c, TB) ELSE st
    IN [st1 EXCEPT !.scalive[c] = FALSE]

(***************************************************************************)
(* The actions.  Those that a pending walk's step would decide differently *)
(* if they came first are disabled on the walk's objects in the            *)
(* refinement model (Refine); the full model allows them everywhere.       *)
(***************************************************************************)
Free(t) == ~Refine \/ ~OnWalk(s, t)
FreeR(r) == ~Refine \/ ~ReplyOnWalk(s, r)

Recv(t, r) ==
    /\ Runs(s, t) /\ s.ralive[r] /\ s.rst[r] \in {"idle", "invalid"}
    /\ s' = RecvEffect(s, t, r)

Call(cl, v) ==
    /\ Runs(s, cl) /\ v # cl /\ s.talive[v] /\ s.ts[v] = "recv"
    /\ s' = CallEffect(s, cl, v)

Reply(t, r) ==
    /\ Runs(s, t) /\ s.ralive[r] /\ ReplyApplies(s, t, r)
    /\ s' = ReplyEffect(s, t, r)

ReplyRecv(t, r) ==
    /\ Runs(s, t) /\ s.ralive[r]
    /\ LET st1 == IF ReplyApplies(s, t, r) THEN ReplyEffect(s, t, r) ELSE s
       IN /\ st1.rst[r] \in {"idle", "invalid"}
          /\ s' = RecvEffect(st1, t, r)

Wait(t) ==
    /\ Runs(s, t)
    /\ s' = [s EXCEPT !.ts[t] = "other", !.res[t] = "none"]

BudgetOut(t) ==
    /\ Runs(s, t) /\ s.tep[t]
    /\ s' = [s EXCEPT !.ts[t] = "fault", !.fk[t] = "timeout"]

FaultReplied(t) ==
    /\ s.talive[t] /\ s.ts[t] = "fault"
    /\ s' = EndWait(s, t, "none")

Suspend(t) ==
    /\ WithSuspend /\ s.talive[t] /\ ~s.susp[t]
    /\ s' = [s EXCEPT !.susp[t] = TRUE]

Resume(t) ==
    /\ WithSuspend /\ s.talive[t] /\ s.susp[t]
    /\ s' = [s EXCEPT !.susp[t] = FALSE]

\* K08, K50: removing the endpoint withdraws a fault queued on it.
SetTep(t, b) ==
    /\ WithSetTep /\ s.talive[t] /\ s.tep[t] # b /\ Free(t)
    /\ s' = IF ~b /\ s.ts[t] = "fault"
            THEN [EndWait(s, t, "none") EXCEPT !.tep[t] = b]
            ELSE [s EXCEPT !.tep[t] = b]

\* A thread that serves a donated call can't be given a context.
BindSC(c, t) ==
    /\ s.scalive[c] /\ s.talive[t]
    /\ s.home[c] = Nil /\ s.holder[c] = Nil
    /\ HomeOf(s, t) = Nil /\ CtxOf(s, t) = Nil /\ s.serving[t] = Nil
    /\ s' = [s EXCEPT !.home[c] = t, !.holder[c] = t]

=============================================================================
