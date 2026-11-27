\* SPDX-FileCopyrightText: 2026 Nicole Roy
\* SPDX-License-Identifier: MPL-2.0

---------------------------- MODULE SchedDonationAtOnce ----------------------------
(***************************************************************************)
(* Taking a context back as one atomic step, walk included: the protocol  *)
(* as the kernel specification first states it, before batching.  The     *)
(* batched protocol, SchedDonation, refines this one: a long chain         *)
(* followed in bounded batches ends in the same state as one followed at   *)
(* once (kernel specification, "Model checking").  Safety only.            *)
(***************************************************************************)
EXTENDS SchedDonationCore

\* The take-back, at once.
TB(st, r, x) ==
    LET st1 == TakeBackStart(st, r, x)
        c   == st.rsc[r]
        stk == st.stack[c]
        seg == SubSeq(stk, IndexOf(stk, r), Len(stk))
    IN RunWalk(st1, seg)

Cancel(t) ==
    /\ s.talive[t] /\ s.ts[t] \in {"call", "recv", "other", "fault"}
    /\ s' = EndAnyWait(s, t, "canceled", TB)

Deadline(t) ==
    /\ s.talive[t] /\ s.ts[t] \in {"call", "recv", "other"}
    /\ s' = EndAnyWait(s, t, "timedout", TB)

UnbindSC(c) ==
    /\ s.scalive[c] /\ s.home[c] # Nil
    /\ s' = UnbindEffect(s, c, TB)

DestroyThread(t) ==
    /\ WithDestroy /\ s.talive[t]
    /\ s' = DestroyThreadEffect(s, t, TB)

DestroyReply(r) ==
    /\ WithDestroy /\ s.ralive[r]
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

Spec == Init /\ [][Next]_s

=============================================================================
