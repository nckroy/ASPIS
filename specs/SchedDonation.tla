\* SPDX-FileCopyrightText: 2026 Nicole Roy
\* SPDX-License-Identifier: MPL-2.0

------------------------------ MODULE SchedDonation ------------------------------
(***************************************************************************)
(* Scheduling-context donation with take-back in bounded batches (ADR     *)
(* 0051, rule 3; ADR 0052, rule 2; ADR 0068, rule 10).  A take-back       *)
(* starts at once: the caller gets its context back, and the chain's       *)
(* replies become a walk.  The walk then goes one step at a time, at the   *)
(* kernel's preemption points and batches, interleaved with every other    *)
(* action.  The properties are the kernel specification's "Model           *)
(* checking" bullets for C12; specs/README.md maps each to its operator.   *)
(***************************************************************************)
EXTENDS SchedDonationCore

TB(st, r, x) == TakeBackStart(st, r, x)

Cancel(t) ==
    /\ s.talive[t] /\ s.ts[t] \in {"call", "recv", "other", "fault"} /\ Free(t)
    /\ s' = EndAnyWait(s, t, "canceled", TB)

Deadline(t) ==
    /\ s.talive[t] /\ s.ts[t] \in {"call", "recv", "other"} /\ Free(t)
    /\ s' = EndAnyWait(s, t, "timedout", TB)

WalkStep(w) ==
    /\ w \in s.walks
    /\ s' = WalkStepEffect(s, w)

\* The step at reply r, for fairness.
StepAt(r) == \E w \in s.walks: Head(w) = r /\ WalkStep(w)

UnbindSC(c) ==
    /\ s.scalive[c] /\ s.home[c] # Nil
    /\ s' = UnbindEffect(s, c, TB)

DestroyThread(t) ==
    /\ WithDestroy /\ s.talive[t] /\ Free(t)
    /\ s' = DestroyThreadEffect(s, t, TB)

DestroyReply(r) ==
    /\ WithDestroy /\ s.ralive[r] /\ FreeR(r)
    /\ s' = DestroyReplyEffect(s, r, TB)

DestroySC(c) ==
    /\ WithDestroy /\ s.scalive[c]
    /\ s' = DestroySCEffect(s, c, TB)

Next ==
    \/ \E t \in Threads, r \in Replies: Recv(t, r) \/ Reply(t, r) \/ ReplyRecv(t, r)
    \/ \E t, v \in Threads: Call(t, v)
    \/ \E t \in Threads:
         \/ Cancel(t) \/ Deadline(t) \/ Wait(t) \/ BudgetOut(t)
         \/ FaultReplied(t) \/ Suspend(t) \/ Resume(t) \/ DestroyThread(t)
         \/ \E b \in BOOLEAN: SetTep(t, b)
    \/ \E c \in SCs: UnbindSC(c) \/ DestroySC(c) \/ \E t \in Threads: BindSC(c, t)
    \/ \E r \in Replies: DestroyReply(r)
    \/ \E w \in s.walks: WalkStep(w)

\* Walks progress: every reply on a walk is eventually stepped.
Fairness == \A r \in Replies: WF_s(StepAt(r))

Spec == Init /\ [][Next]_s /\ Fairness

(***************************************************************************)
(* Invariants.                                                             *)
(***************************************************************************)

\* Each context is bound to at most one thread, and each thread holds at
\* most one context.
OneContextPerThread ==
    \A c, d \in SCs: c # d /\ s.holder[c] # Nil => s.holder[c] # s.holder[d]

\* A thread runs only on a context it holds; and a context's holder is
\* alive and never blocked in a donating call, so it is where the context
\* is.
HolderIsWhereTheContextIs ==
    \A c \in SCs: s.holder[c] # Nil =>
        /\ s.talive[s.holder[c]] /\ s.scalive[c]
        /\ ~(s.ts[s.holder[c]] = "call" /\ Live(s, s.wr[s.holder[c]]))

\* Along a chain, the replies lead from the home caller to the thread that
\* holds the context; no context is lost or duplicated.
ChainWellFormed ==
    \A c \in SCs:
      LET k == s.stack[c] IN
      /\ s.holder[c] # Nil => s.home[c] # Nil
      /\ s.home[c] # Nil /\ s.scalive[c] => s.holder[c] # Nil
      /\ k # << >> => s.rcaller[k[1]] = s.home[c]
      /\ s.holder[c] # Nil =>
           s.holder[c] = (IF k = << >> THEN s.home[c] ELSE s.rserver[k[Len(k)]])
      /\ \A i \in DOMAIN k:
           /\ s.rst[k[i]] = "pending" /\ s.rsc[k[i]] = c /\ s.ralive[k[i]]
           /\ s.ts[s.rcaller[k[i]]] = "call" /\ s.wr[s.rcaller[k[i]]] = k[i]
           /\ s.serving[s.rserver[k[i]]] = k[i]
           /\ i < Len(k) => s.rcaller[k[i + 1]] = s.rserver[k[i]]
      /\ \A i, j \in DOMAIN k: i # j => k[i] # k[j]

\* Every pending donating reply is on its context's stack, and every stale
\* one on exactly one walk.
RepliesAccountedFor ==
    /\ \A r \in Replies:
         s.rst[r] = "pending" /\ s.rsc[r] # Nil => r \in Range(s.stack[s.rsc[r]])
    /\ \A r \in Replies:
         (s.rst[r] = "stale") <=> (\E w \in s.walks: r \in Range(w))
    /\ \A v, w \in s.walks: v # w => Range(v) \cap Range(w) = {}

\* A canceled caller never receives a reply: a reply's caller is always a
\* thread waiting on that reply.
ReplyReachesOnlyItsCaller ==
    \A r \in Replies: s.rcaller[r] # Nil =>
        /\ s.ts[s.rcaller[r]] = "call" /\ s.wr[s.rcaller[r]] = r

\* A thread serves at most one donated call, and its reply names it.
ServingWellFormed ==
    /\ \A t \in Threads: s.serving[t] # Nil =>
         /\ s.rserver[s.serving[t]] = t
         /\ s.rst[s.serving[t]] \in {"pending", "stale"}
    /\ \A r \in Replies:
         s.rst[r] \in {"pending", "stale"} /\ s.rsc[r] # Nil /\ s.rserver[r] # Nil
           => s.serving[s.rserver[r]] = r

\* A thread waits on its own wait's object.
WaitsWellFormed ==
    \A t \in Threads:
      /\ s.ts[t] \in {"recv", "call"} <=> s.wr[t] # Nil
      /\ s.ts[t] = "recv" => s.rst[s.wr[t]] = "recv" /\ s.rserver[s.wr[t]] = t
      /\ (s.ts[t] = "fault") <=> (s.fk[t] # "none")

\* A thread owed a walk step is stranded or still in its onward call.
OwedAreStranded ==
    \A t \in Threads: Owed(s, t) =>
        /\ CtxOf(s, t) = Nil
        /\ s.ts[t] \in {"ready", "call"}

Invariants ==
    /\ TypeOK /\ OneContextPerThread /\ HolderIsWhereTheContextIs
    /\ ChainWellFormed /\ RepliesAccountedFor /\ ReplyReachesOnlyItsCaller
    /\ ServingWellFormed /\ WaitsWellFormed /\ OwedAreStranded

(***************************************************************************)
(* Action and temporal properties.                                         *)
(***************************************************************************)

\* When a donating call ends, other than by its caller's or context's
\* destruction or the context's unbinding, the context comes back in the
\* same step: to the caller, whose call ends "replied", "canceled" or
\* "timed out", or to a caller below it in the chain, whose own call ended
\* in that step (a cut lower down, which also ends this call).
CallersAtOrBelow(st, c, r) ==
    {st.rcaller[st.stack[c][i]] : i \in 1..IndexOf(st.stack[c], r)}

ContextBackAtOnce ==
    [][\A t \in Threads:
         LET r == s.wr[t]
             c == s.rsc[r] IN
         (/\ s.ts[t] = "call" /\ Live(s, r)
          /\ s'.wr[t] # r
          /\ s'.talive[t] /\ s'.scalive[c] /\ s'.home[c] # Nil)
           => /\ s'.holder[c] \in CallersAtOrBelow(s, c, r)
              /\ s'.holder[c] = t =>
                   s'.res[t] \in {"replied", "canceled", "timedout"}]_s

\* A context-withdrawn fault is sent only at the walk step for a server's
\* donated call, which ends its serving; so each stranded server gets at
\* most one per take-back.
WithdrawnOnlyByItsStep ==
    [][\A t \in Threads:
         (s'.fk[t] = "withdrawn" /\ s.fk[t] # "withdrawn") =>
           /\ s.serving[t] # Nil
           /\ s'.serving[t] = Nil]_s

\* The other half, written apart from StepServer: when the walk steps a
\* server's donated call, a server that is then left alive and without a
\* context, and has a timeout endpoint before and after the step, gets its
\* context-withdrawn fault in that step.  With WithdrawnOnlyByItsStep, each
\* such server gets exactly one.
StrandedGetWithdrawn ==
    [][\A q \in Replies:
         LET S == s.rserver[q] IN
         (/\ s.rst[q] = "stale" /\ s'.rst[q] # "stale" /\ S # Nil
          /\ s'.talive[S] /\ s.tep[S] /\ s'.tep[S] /\ CtxOf(s', S) = Nil
          /\ s.ts[S] \in {"ready", "call"})
           => s'.ts[S] = "fault" /\ s'.fk[S] = "withdrawn"]_s

\* Suspend and resume change nothing but the flag (ADR 0061, rule 3).
SuspendOnlyFlags ==
    [][\A t \in Threads:
         s'.susp[t] # s.susp[t] /\ s'.talive[t] =>
           s' = [s EXCEPT !.susp[t] = s'.susp[t]]]_s

\* Every reply on a walk is stepped in the end.
WalksEnd == \A r \in Replies: (s.rst[r] = "stale") ~> (s.rst[r] # "stale")

(***************************************************************************)
(* The refinement: every pending walk finished at once maps the batched    *)
(* state to the at-once one.  Checked in the model where the actions that *)
(* would interfere with a pending walk are disabled (Refine).              *)
(***************************************************************************)
AO == INSTANCE SchedDonationAtOnce WITH s <- RunAll(s)

Refinement == AO!Spec

=============================================================================
