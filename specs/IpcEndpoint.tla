\* SPDX-FileCopyrightText: 2026 Nicole Roy
\* SPDX-License-Identifier: MPL-2.0

------------------------------ MODULE IpcEndpoint ------------------------------
(***************************************************************************)
(* A synchronous endpoint (ADR 0054; kernel specification, "Endpoint      *)
(* operations and messages" and "IPC deadlines and cancellation"; ADR     *)
(* 0068, rule 10): seL4's send, send without blocking, call, receive, and  *)
(* reply and receive, with a queue served in priority order, first come    *)
(* first served within a priority; deadlines and cancels whose results say *)
(* whether a call was delivered; faults sent as calls; canceling the sends *)
(* queued under a released badge; and destroying the endpoint, which       *)
(* releases one queued thread per step (K30).  The properties are the     *)
(* kernel specification's "Model checking" bullets for C14's endpoints;   *)
(* specs/README.md maps each to its operator.                              *)
(*                                                                         *)
(* Scheduling contexts and donation are SchedDonation.tla's: here every    *)
(* thread runs on its own context, so no call donates.  The whole state is *)
(* one record, s, and every action is written as s' = Effect(s, ...), so  *)
(* that a trace from the Rust (crates/kipc, module endpoint) is one        *)
(* expression.  Objects are numbers: threads 1..NT, reply objects 1..NR,   *)
(* badges 1..NB, and Nil = 0.  The queue is the sequence of its threads in *)
(* the order they are served; a thread joins after every queued thread    *)
(* whose priority is at least its own, which is the Rust's tree order by   *)
(* priority, then arrival, without arrival numbers, so the state stays     *)
(* finite.                                                                 *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    NT,          \* threads
    NR,          \* reply objects
    Prios,       \* the priorities a thread may have
    NB,          \* badges: thread t's capability carries Badge(t)
    WithPrio,    \* whether priorities change while queued (K25)
    WithBadge,   \* whether badges are released (ADR 0049, rule 5)
    WithDestroy  \* whether the endpoint and reply objects are destroyed

Threads == 1..NT
Replies == 1..NR
Badges == 1..NB
Nil == 0

Badge(t) == 1 + ((t - 1) % NB)
MinPrio == CHOOSE p \in Prios: \A x \in Prios: p <= x

Senders == {"sendq", "callq", "faultq"}
TState == {"ready", "recv", "call"} \cup Senders
RState == {"idle", "recv", "pending", "invalid"}
Results == {"none", "replied", "canceled", "timedout", "destroyed"}
\* The results that end a call that may have been delivered.
Ends == {"canceled", "timedout", "destroyed"}

VARIABLE s

(***************************************************************************)
(* ts: a thread's state: ready (running), recv (queued to receive),       *)
(* sendq, callq and faultq (queued senders), call (a call or fault         *)
(* delivered, waiting on reply object wr).  res: how its last wait ended;  *)
(* dbit: whether that wait was a delivered call that ended without its     *)
(* reply (the delivered bit, K30); rw: whether it was a send restarted at  *)
(* its SVC; flt: whether its call is a fault's.                            *)
(***************************************************************************)
InitState ==
    [ ts      |-> [t \in Threads |-> "ready"],
      prio    |-> [t \in Threads |-> MinPrio],
      q       |-> << >>,
      wr      |-> [t \in Threads |-> Nil],
      rst     |-> [r \in Replies |-> "idle"],
      rcaller |-> [r \in Replies |-> Nil],
      res     |-> [t \in Threads |-> "none"],
      dbit    |-> [t \in Threads |-> FALSE],
      flt     |-> [t \in Threads |-> FALSE],
      rw      |-> [t \in Threads |-> FALSE],
      ep      |-> "live",
      revoked |-> {},
      ralive  |-> [r \in Replies |-> TRUE] ]

Init == s = InitState

TypeOK ==
    /\ s.ts      \in [Threads -> TState]
    /\ s.prio    \in [Threads -> Prios]
    /\ s.q       \in Seq(Threads)
    /\ s.wr      \in [Threads -> Replies \cup {Nil}]
    /\ s.rst     \in [Replies -> RState]
    /\ s.rcaller \in [Replies -> Threads \cup {Nil}]
    /\ s.res     \in [Threads -> Results]
    /\ s.dbit    \in [Threads -> BOOLEAN]
    /\ s.flt     \in [Threads -> BOOLEAN]
    /\ s.rw      \in [Threads -> BOOLEAN]
    /\ s.ep      \in {"live", "draining", "gone"}
    /\ s.revoked \subseteq Badges
    /\ s.ralive  \in [Replies -> BOOLEAN]

(***************************************************************************)
(* Helpers.                                                                *)
(***************************************************************************)
Range(q) == {q[i] : i \in DOMAIN q}

\* t joins the queue after every thread whose priority is at least its own.
Insert(st, q, t) ==
    LET k == Cardinality({i \in DOMAIN q: st.prio[q[i]] >= st.prio[t]})
    IN SubSeq(q, 1, k) \o << t >> \o SubSeq(q, k + 1, Len(q))

Remove(q, t) == SelectSeq(q, LAMBDA x: x # t)

ReceiverWaiting(st) == st.q # << >> /\ st.ts[Head(st.q)] = "recv"
SenderWaiting(st) == st.q # << >> /\ st.ts[Head(st.q)] \in Senders

\* A thread that runs: here every thread holds its own context.
Runs(t) == s.ts[t] = "ready"

\* A sender's capability resolves: the endpoint is live, and its badge
\* hasn't been released.
CanSend(t) == s.ep = "live" /\ Badge(t) \notin s.revoked

\* t's wait ends with result x; a delivered fault's call ends with none.
EndWait(st, t, x) ==
    LET y == IF st.flt[t] THEN "none" ELSE x IN
    [st EXCEPT !.ts[t] = "ready", !.wr[t] = Nil, !.flt[t] = FALSE, !.res[t] = y,
               !.dbit[t] = (st.ts[t] = "call" /\ y \in Ends), !.rw[t] = FALSE]

\* A message reaches v, which was receiving: its reply object goes idle.
SendTo(st, v) ==
    [EndWait(st, v, "replied") EXCEPT !.rst[st.wr[v]] = "idle"]

\* t's call, or its fault (f), is delivered to v, which was receiving.
CallTo(st, t, v, f) ==
    LET r == st.wr[v] IN
    [EndWait(st, v, "none") EXCEPT
        !.ts[t] = "call", !.wr[t] = r, !.res[t] = "none", !.flt[t] = f,
        !.rst[r] = "pending", !.rcaller[r] = t]

\* The receive by t with reply object r, after any reply: the head of a
\* queue of senders is delivered, or t waits queued.
RecvPart(st, t, r) ==
    IF SenderWaiting(st)
    THEN LET x == Head(st.q)
             st1 == [st EXCEPT !.q = Tail(st.q)]
         IN IF st.ts[x] = "sendq"
            THEN [EndWait(EndWait(st1, x, "replied"), t, "replied") EXCEPT !.rst[r] = "idle"]
            ELSE CallTo([st1 EXCEPT !.wr[t] = r], x, t, st.ts[x] = "faultq")
    ELSE [st EXCEPT !.ts[t] = "recv", !.wr[t] = r, !.res[t] = "none",
                    !.rst[r] = "recv", !.rcaller[r] = Nil, !.q = Insert(st, st.q, t)]

ReplyEffect(st, r) ==
    IF st.rst[r] = "pending"
    THEN [EndWait(st, st.rcaller[r], "replied") EXCEPT !.rst[r] = "idle", !.rcaller[r] = Nil]
    ELSE [st EXCEPT !.rst[r] = "idle"]

\* Ending t's wait with x: a cancel, a deadline (ADR 0054, rules 5 and 6).
\* Before delivery t leaves the queue, and the server never sees it; after,
\* the reply object becomes invalid, and a later reply fails "no caller".
EndAny(st, t, x) ==
    CASE st.ts[t] \in {"sendq", "callq"} -> [EndWait(st, t, x) EXCEPT !.q = Remove(st.q, t)]
      [] st.ts[t] = "faultq" -> [EndWait(st, t, "none") EXCEPT !.q = Remove(st.q, t)]
      [] st.ts[t] = "recv" ->
           [EndWait(st, t, x) EXCEPT !.q = Remove(st.q, t), !.rst[st.wr[t]] = "idle"]
      [] st.ts[t] = "call" ->
           [EndWait(st, t, x) EXCEPT !.rst[st.wr[t]] = "invalid", !.rcaller[st.wr[t]] = Nil]
      [] OTHER -> st

(***************************************************************************)
(* The actions.                                                            *)
(***************************************************************************)
Send(t) ==
    /\ Runs(t) /\ CanSend(t)
    /\ s' = IF ReceiverWaiting(s)
            THEN [SendTo(s, Head(s.q)) EXCEPT !.q = Tail(s.q)]
            ELSE [s EXCEPT !.ts[t] = "sendq", !.res[t] = "none", !.q = Insert(s, s.q, t)]

\* Without a receiver the message is dropped, which changes nothing.
NBSend(t) ==
    /\ Runs(t) /\ CanSend(t) /\ ReceiverWaiting(s)
    /\ s' = [SendTo(s, Head(s.q)) EXCEPT !.q = Tail(s.q)]

Call(t) ==
    /\ Runs(t) /\ CanSend(t)
    /\ s' = IF ReceiverWaiting(s)
            THEN [CallTo(s, t, Head(s.q), FALSE) EXCEPT !.q = Tail(s.q)]
            ELSE [s EXCEPT !.ts[t] = "callq", !.res[t] = "none", !.q = Insert(s, s.q, t)]

\* A fault on t's fault endpoint, this one, sent as a call (ADR 0056,
\* rule 1).  Its copy of the endpoint carries t's badge.
Fault(t) ==
    /\ Runs(t) /\ CanSend(t)
    /\ s' = IF ReceiverWaiting(s)
            THEN [CallTo(s, t, Head(s.q), TRUE) EXCEPT !.q = Tail(s.q)]
            ELSE [s EXCEPT !.ts[t] = "faultq", !.q = Insert(s, s.q, t)]

Recv(t, r) ==
    /\ Runs(t) /\ s.ep = "live" /\ s.ralive[r] /\ s.rst[r] \in {"idle", "invalid"}
    /\ s' = RecvPart(s, t, r)

Reply(t, r) ==
    /\ Runs(t) /\ s.ralive[r] /\ s.rst[r] \in {"pending", "invalid"}
    /\ s' = ReplyEffect(s, r)

\* Everything is checked before the reply; a reply with no caller doesn't
\* stop the receive.
ReplyRecv(t, r) ==
    /\ Runs(t) /\ s.ep = "live" /\ s.ralive[r]
    /\ s.rst[r] \in {"idle", "invalid", "pending"}
    /\ s' = RecvPart(IF s.rst[r] = "idle" THEN s ELSE ReplyEffect(s, r), t, r)

Cancel(t) ==
    /\ s.ts[t] # "ready"
    /\ s' = EndAny(s, t, "canceled")

\* Faults have no deadline, queued or delivered.
Deadline(t) ==
    /\ s.ts[t] \in {"sendq", "callq", "recv", "call"} /\ ~s.flt[t]
    /\ s' = EndAny(s, t, "timedout")

\* A queued thread whose priority changes rejoins as a new arrival (K25).
SetPrio(t, p) ==
    /\ WithPrio /\ p # s.prio[t]
    /\ LET st == [s EXCEPT !.prio[t] = p] IN
       s' = IF t \in Range(s.q) THEN [st EXCEPT !.q = Insert(st, Remove(s.q, t), t)] ELSE st

\* The manager revokes its kept copy under badge b: no capability with b
\* is left, so no sender joins under it again.
RevokeBadge(b) ==
    /\ WithBadge /\ b \notin s.revoked
    /\ s' = [s EXCEPT !.revoked = @ \cup {b}]

\* One unit of canceling b's queued sends, invoked on the badged copy after
\* the revoke: a send or call restarts at its SVC, with no result; a fault
\* is withdrawn, and goes on as its kind allows.  The Rust takes them first come first;
\* any one is a step here.
CancelBadgedStep(b) ==
    /\ WithBadge /\ s.ep = "live" /\ b \in s.revoked
    /\ \E x \in Range(s.q):
         /\ s.ts[x] \in Senders /\ Badge(x) = b
         /\ s' = [EndWait(s, x, "none") EXCEPT !.q = Remove(s.q, x),
                                               !.rw[x] = (s.ts[x] # "faultq")]

\* The endpoint's last capability becomes a queue zombie: no thread can
\* name it, so none joins its queue.
DestroyEp ==
    /\ WithDestroy /\ s.ep = "live"
    /\ s' = [s EXCEPT !.ep = "draining"]

\* One step of the zombie: the first queued thread ends "destroyed",
\* undelivered, or a fault is withdrawn; when none is left, it is gone.
DrainStep ==
    /\ s.ep = "draining"
    /\ LET st == IF s.q = << >> THEN s
                 ELSE LET x == Head(s.q)
                          st1 == [s EXCEPT !.q = Tail(s.q)] IN
                      CASE s.ts[x] = "faultq" -> EndWait(st1, x, "none")
                        [] s.ts[x] = "recv" ->
                             [EndWait(st1, x, "destroyed") EXCEPT !.rst[s.wr[x]] = "idle"]
                        [] OTHER -> EndWait(st1, x, "destroyed")
       IN s' = IF st.q = << >> THEN [st EXCEPT !.ep = "gone"] ELSE st

\* A call waiting on r ends "destroyed", delivered; a receive with r ends
\* "destroyed", and leaves the queue.
DestroyReply(r) ==
    /\ WithDestroy /\ s.ralive[r]
    /\ LET st == CASE s.rst[r] = "pending" -> EndWait(s, s.rcaller[r], "destroyed")
                   [] s.rst[r] = "recv" ->
                        LET v == CHOOSE v \in Threads: s.ts[v] = "recv" /\ s.wr[v] = r IN
                        [EndWait(s, v, "destroyed") EXCEPT !.q = Remove(s.q, v)]
                   [] OTHER -> s
       IN s' = [st EXCEPT !.ralive[r] = FALSE, !.rst[r] = "idle", !.rcaller[r] = Nil]

Next ==
    \/ \E t \in Threads:
         \/ Send(t) \/ NBSend(t) \/ Call(t) \/ Fault(t) \/ Cancel(t) \/ Deadline(t)
         \/ \E r \in Replies: Recv(t, r) \/ Reply(t, r) \/ ReplyRecv(t, r)
         \/ \E p \in Prios: SetPrio(t, p)
    \/ \E b \in Badges: RevokeBadge(b) \/ CancelBadgedStep(b)
    \/ DestroyEp \/ DrainStep
    \/ \E r \in Replies: DestroyReply(r)

\* The zombie's steps and the badge's cancel progress.
Fairness == WF_s(DrainStep) /\ \A b \in Badges: WF_s(CancelBadgedStep(b))

Spec == Init /\ [][Next]_s /\ Fairness

(***************************************************************************)
(* Invariants.                                                             *)
(***************************************************************************)

\* The queue holds exactly the threads that wait on the endpoint, each
\* once, all senders or all receivers, highest priority first.
QueueWellFormed ==
    /\ Range(s.q) = {t \in Threads: s.ts[t] \in Senders \cup {"recv"}}
    /\ Len(s.q) = Cardinality(Range(s.q))
    /\ \/ \A t \in Range(s.q): s.ts[t] = "recv"
       \/ \A t \in Range(s.q): s.ts[t] \in Senders
    /\ \A i \in 1..(Len(s.q) - 1): s.prio[s.q[i]] >= s.prio[s.q[i + 1]]

\* A reply object answers at most one call, and its caller waits on it; a
\* receiving thread holds its own reply object.
ReplyAnswersOne ==
    /\ \A t \in Threads: s.ts[t] \in {"recv", "call"} <=> s.wr[t] # Nil
    /\ \A t \in Threads: s.ts[t] = "recv" => s.rst[s.wr[t]] = "recv"
    /\ \A t \in Threads: s.ts[t] = "call" =>
         s.rst[s.wr[t]] = "pending" /\ s.rcaller[s.wr[t]] = t
    /\ \A r \in Replies: s.rst[r] = "pending" =>
         s.rcaller[r] # Nil /\ s.ts[s.rcaller[r]] = "call" /\ s.wr[s.rcaller[r]] = r
    /\ \A r \in Replies: s.rst[r] = "recv" =>
         Cardinality({t \in Threads: s.ts[t] = "recv" /\ s.wr[t] = r}) = 1
    /\ \A r \in Replies: s.rst[r] # "pending" => s.rcaller[r] = Nil
    /\ \A t \in Threads: s.flt[t] => s.ts[t] = "call"

\* A gone endpoint holds no thread.
DrainedWhenGone == s.ep = "gone" => s.q = << >>

Invariants == TypeOK /\ QueueWellFormed /\ ReplyAnswersOne /\ DrainedWhenGone

(***************************************************************************)
(* Action and temporal properties.                                        *)
(***************************************************************************)

\* t left the queue with its message, call or fault delivered.
Delivered(t) ==
    \/ s'.ts[t] = "call"
    \/ s'.res[t] = "replied"
    \/ s.ts[t] = "recv" /\ s'.ts[t] = "ready" /\ s'.res[t] = "none"

\* Waiting senders and receivers are served in priority order, first come
\* first served within a priority: every delivery takes the queue's head.
PriorityOrder ==
    [][\A t \in Range(s.q): t \notin Range(s'.q) /\ Delivered(t) => t = Head(s.q)]_s

\* A delivered call ends exactly once, with its reply, canceled, timed out
\* or destroyed, and the delivered bit says whether it had been delivered.
\* (That no reply object names it afterwards follows from ReplyAnswersOne.)
CallEndsOnce ==
    [][\A t \in Threads:
         /\ s.ts[t] = "call" => s'.ts[t] \in {"call", "ready"}
         /\ s.ts[t] = "call" /\ s'.ts[t] = "ready" =>
              /\ s'.res[t] \in {"replied"} \cup Ends \cup (IF s.flt[t] THEN {"none"} ELSE {})
              /\ s'.dbit[t] = (s'.res[t] \in Ends)]_s

\* A reply answers one call: no step ends two delivered calls.  A reply,
\* a cancel, a deadline and a reply object's destruction each end the one
\* call they are about; with ReplyAnswersOne, which ties each pending reply
\* object to its one caller, a reply reaches only the caller its reply
\* object answers.
OneCallEndsPerStep ==
    [][Cardinality({t \in Threads: s.ts[t] = "call" /\ s'.ts[t] # "call"}) <= 1]_s

\* A queued call or send that leaves the queue without being delivered
\* ends "canceled", "timed out" or "destroyed", undelivered, or with no
\* result to restart at its SVC (a released badge's cancel); it never ends
\* "replied" with no reply.  A queued send ends "replied" only as a
\* receive that takes it leaves it: on the live endpoint, with another
\* thread that was running holding "replied" after the step, as the
\* receiver does.  The state doesn't record which action ran, and a
\* receiver's earlier result may already be "replied", so a step that
\* ended the send "replied" otherwise, from a state that a receive would
\* leave just the same, can't be told from that receive here.  (A queued
\* call that a receive takes becomes "call", which CallEndsOnce covers.)
QueuedEndsOnce ==
    [][\A t \in Threads:
         s.ts[t] \in {"sendq", "callq"} /\ s'.ts[t] = "ready" =>
           \/ s'.res[t] \in Ends /\ ~s'.dbit[t]
           \/ s'.res[t] = "none" /\ s'.rw[t]
           \/ /\ s.ts[t] = "sendq" /\ s'.res[t] = "replied" /\ s.ep = "live"
              /\ \E v \in Threads \ {t}: s.ts[v] = "ready" /\ s'.res[v] = "replied"]_s

\* A call or send canceled, timed out or destroyed before delivery was
\* never delivered: the bit is clear, and no reply object names it.
NeverSeenIfEndedFirst ==
    [][\A t \in Threads:
         s.ts[t] \in {"sendq", "callq"} /\ s'.ts[t] = "ready" /\ s'.res[t] \in Ends =>
           ~s'.dbit[t] /\ \A r \in Replies: s'.rcaller[r] # t]_s

\* A fault, queued or delivered, ends with no result, and is never
\* restarted at its SVC: the thread goes on as its fault's kind allows.
FaultSilent ==
    [][\A t \in Threads:
         (s.flt[t] \/ s.ts[t] = "faultq") /\ s'.ts[t] = "ready" =>
           s'.res[t] = "none" /\ ~s'.dbit[t] /\ ~s'.rw[t]]_s

\* No sender joins under a released badge.
NoJoinUnderRevoked ==
    [][\A t \in Threads:
         t \notin Range(s.q) /\ t \in Range(s'.q) /\ s'.ts[t] \in Senders =>
           Badge(t) \notin s.revoked]_s

\* A draining endpoint is gone in the end; after a badge is released, its
\* queued sends are canceled in the end.
DrainEnds == s.ep = "draining" ~> s.ep = "gone"

BadgeCleared(b) == \A t \in Range(s.q): s.ts[t] = "recv" \/ Badge(t) # b
BadgeCancelEnds == \A b \in Badges: b \in s.revoked ~> BadgeCleared(b)

=============================================================================
