<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0066. Capability parameters and server streams

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

The [design backlog, D27](../design/design-backlog.md#m2-kernel-objects) asks how a parameter that carries a capability appears in the IDL and in its ABNF, how it is translated between nodes, and how server streams serve catalog watches, rotation pushes and log tails. ABNF can't express a capability transfer, and raw capabilities never travel between nodes ([0002](0002-capability-security-model.md), rules 1 and 5).

The kernel follows seL4 ([0047](0047-the-kernel-follows-sel4.md)): every transfer is a copy, and no server learns when a client deletes one. A passive server runs on its caller's scheduling context ([0051](0051-scheduling-timers-and-deadlines.md), rule 3), so it can't hold a call open.

On 2026-11-25 the project owner decided:

- **Three real capability transfers per message**, the receiver naming up to three receive slots, where seL4 transfers one ([0047](0047-the-kernel-follows-sel4.md), rule 3; [0054](0054-ipc-endpoints.md), rule 7).
- **Capability parameters cross nodes as proxies**, with object-capability semantics. Durable or direct access uses the object ID and a bind, with an RFC 8693 delegated token where needed.

The owner also accepted defaults that Claude proposed with these records: server streams only; a badge per holder, with `session_dup` to share a session capability; stream pulls that never block; and u32 counts.

This record was proposed with in-place edits of [0002](0002-capability-security-model.md), rule 5 and [0015](0015-jwt-tokens-and-oidc-identity.md), rule 1, which said authority crosses nodes as JWTs. Both now keep JWTs for authority a party uses under its own bind, and say a capability parameter crosses as a proxy (rule 4).

Claude drafted this record from the discussion. The [call-language specification](../design/call-language.md#capability-parameters-and-server-streams) holds the layouts, tables and examples.

## Decision

1. **Capability parameters are typed in the IDL** ([Capability types](../design/call-language.md#capability-types)).
   - `cap<I/M.n>` is a session capability, to a session speaking interface I, major M, minor n or later. It names an interface, never an object ([0050](0050-ids-for-kernel-objects.md), rule 5).
   - `cap<aspis.kernel.X/M, rights>` is a kernel object capability with the listed rights ([0049](0049-capability-spaces-rights-and-revocation.md), rule 2), and memory may require `immutable`. `slot<...>`, in kernel interfaces only, names a slot in the caller's own capability space.
   - A capability is a resource: never copied implicitly, compared or rendered by value, and never in a sequence, an array, a stream item, an error, or a field or arm added in a minor ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rule 13). It may be optional.
   - **Declared rights are a ceiling and a floor.** The sending stub attenuates to them, and the receiving stub checks them with the kernel's identify operation, refusing shortfalls with `capability_rights`. The compiler fixes the rights a session needs ([Rights a session needs](../design/call-language.md#rights-a-session-needs)).
2. **On the wire, a capability parameter is a one-octet index** into the message's capability list: the core rule `cap-ref` ([0062](0062-core-rules-big-endian-fixed-width.md), rule 3; [Capability indexes](../design/call-language.md#capability-indexes)).
   - The body is the same on kernel IPC and on QUIC, so one generated grammar serves both ([0064](0064-the-call-header-and-wire-encoding.md), rule 12).
   - Each index appears exactly once, in ascending order. A decoder rejects any other use. There is no sentinel index for "absent": an optional capability is a tail field or a `presence` octet ([0062](0062-core-rules-big-endian-fixed-width.md), rule 6).
   - In the JSON mapping and the call text, a capability renders as its index, `{"cap":N}`.
3. **A message carries at most three capabilities in each direction**, two when its body may spill ([0064](0064-the-call-header-and-wire-encoding.md), rule 11). The compiler counts the worst case, and more is a compile error. A call that needs more uses a builder session, which takes up to three capabilities per `add` ([More than three capabilities](../design/call-language.md#more-than-three-capabilities)). Native spawn is the first ([0060](0060-processes-native-spawn-and-elf.md), rule 2).
4. **Across nodes, capabilities are proxied** ([Translation between nodes](../design/call-language.md#translation-between-nodes)).
   - The session stays bound to its original channel, and calls through a proxy route back through the exporting node. Raw capabilities never leave a node ([0002](0002-capability-security-model.md), rule 5).
   - Network servers translate capabilities without parsing bodies. Only session and endpoint capabilities with write, and immutable memory objects with read, cross. A proxy sent back to its exporter becomes the original again. A call carrying anything else fails whole, before sending, with `capability_not_remotable`, outcome unreachable ([0065](0065-typed-errors-and-minor-versions-on-the-wire.md), rule 5).
   - **Locality is per method.** A method that passes a capability that can't cross is local, by inference or by `[local]`. An interface is local only when it declares `[local]` or `[kernel]`. A manager refuses either on a remote session with `local_only`, before anything runs.
   - A proxy carries the exporting session's authority, decided once at bind. A party that needs its own authority takes the object ID and binds ([0015](0015-jwt-tokens-and-oidc-identity.md), rules 1 and 4).
5. **Each holder closes only its own badge** ([Sessions, badges and proxies](../design/call-language.md#sessions-badges-and-proxies)).
   - A bind returns a session's first badge, and `session_dup` another, with no greater rights. `session_close` releases only the badge it is sent on. The session ends with its last badge, its token's expiry, its revocation ([0015](0015-jwt-tokens-and-oidc-identity.md), rule 1) or idle rundown.
   - Generated bindings own badges: moving a capability as a parameter gives its badge up, and sharing one sends a new badge from `session_dup`.
   - Proxies follow the same rule, and end with their last local badge, their session or their connection. No call through a proxy outlives its session.
6. **Streams are server streams** ([Server streams in the IDL](../design/call-language.md#server-streams-in-the-idl)).
   - `stream<T>` appears only as a method's result, at top level. `T` is a struct with no capabilities.
   - Every stream method takes `after: u64?`, and the opening reply gives a stream ID and a start position, so any stream can resume.
   - Streams are lossless by default: when history is gone, the stream ends `expired`. `[lossy]` streams report lost items and continue, and `[coalescing]` ones deliver only the newest item.
   - Opening is the authorized action. Pulls ride the session.
7. **Stream messages are batches of length-delimited entries** ([Stream messages](../design/call-language.md#stream-messages); [0064](0064-the-call-header-and-wire-encoding.md), rule 6). An entry is an item, a progress bookmark or a count of lost items, at a u64 position that strictly increases. A stream end's reason is an open enum, and an unknown reason reads as `closed`.
8. **On kernel IPC, a stream is pulled with credit, and a pull never blocks** ([Local pull with credit](../design/call-language.md#local-pull-with-credit)).
   - `stream_next` names `after` and `max_items`, the credit. The server answers at once, with entries, an empty batch or a stream end, and never pushes.
   - A client waits on the stream's readiness eventcount, from `stream_ready` ([0053](0053-eventcounts.md)), reading it before each pull so no wakeup is lost.
   - Pulls are idempotent, so the server keeps no buffer per client.
9. **Between nodes, a stream is pushed within QUIC's credit** ([Remote push within QUIC's credit](../design/call-language.md#remote-push-within-quics-credit)).
   - One ASPIS stream is one QUIC stream, and QUIC's stream credit is its only flow control: ASPIS adds no credit messages.
   - The importing network server's window always fits one whole entry. It answers local pulls and `stream_ready` itself ([0053](0053-eventcounts.md), rule 9).
   - After a lost connection, the binding reopens from the last position it delivered, keeping [0028](0028-discovery-and-realm-catalog.md), rule 6's promise to miss no change and see none twice.
10. **Limits and rundown** ([Stream limits and rundown](../design/call-language.md#stream-limits-and-rundown)).
    - The three capability positions are fixed. The other limits are defaults that C18 and C29 tune, and exceeding one gives `resource_limit`.
    - A server ends every stream of a session when the session ends. A network server ends the local half of every stream when its connection is lost.

## Consequences

- **Capabilities passed between nodes keep object-capability semantics**: revoking a session reaches every proxy. The cost is a route through the exporting node, and proxy chains until three-party handoff ([L26](../design/call-language.md#l26-three-party-handoff)).
- **Writable memory and other kernel objects stay on their node** ([L27](../design/call-language.md#l27-writable-memory-across-nodes)).
- **Sharing a session capability costs one `session_dup` call.** Copies made outside the binding share one badge.
- **D27 is settled.** The IDL form is rule 1, the ABNF rule 2, translation between nodes rules 4 and 5, and streams for catalog watches, rotation pushes and log tails rules 6 to 9 ([Worked fits](../design/call-language.md#worked-fits)). The specification keeps open the bind message, reconnection, HTTPS streams, stream history, default limits, content-hash descriptors, client streams and the identify operation ([L05](../design/call-language.md#l05-the-bind-message), [L07](../design/call-language.md#l07-sessions-across-reconnection), [L16](../design/call-language.md#l16-streams-over-https), [L18](../design/call-language.md#l18-stream-history-and-replicas), [L24](../design/call-language.md#l24-per-session-defaults), [L28](../design/call-language.md#l28-content-hash-descriptors), [L29](../design/call-language.md#l29-client-and-bidirectional-streams), [L41](../design/call-language.md#l41-the-identify-operation)).

## References

- [Call-language specification](../design/call-language.md#capability-parameters-and-server-streams)
- [Cap'n Proto RPC protocol](https://github.com/capnproto/capnproto/blob/v2/c++/src/capnp/rpc.capnp): capability tables and Release
- [OCapN CapTP specification](https://github.com/ocapn/ocapn/blob/main/draft-specifications/CapTP%20Specification.md), a draft with no revision or date
- [Zircon `zx_channel_write_etc`](https://fuchsia.dev/fuchsia-src/reference/syscalls/channel_write_etc)
- [seL4 reference manual, 17.0.0: capability transfer and badges](https://docs.sel4.systems/releases/sel4/17.0.0)
- [DCE 1.1: Remote Procedure Call (The Open Group, C706)](https://pubs.opengroup.org/onlinepubs/9629399/): pipes
- [Kubernetes API concepts: watch bookmarks](https://kubernetes.io/docs/reference/using-api/api-concepts/)
- [RFC 9000, QUIC](https://www.rfc-editor.org/info/rfc9000); [RFC 8693, OAuth 2.0 Token Exchange](https://www.rfc-editor.org/info/rfc8693)
