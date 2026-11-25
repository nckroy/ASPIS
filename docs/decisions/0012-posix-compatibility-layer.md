<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0012. POSIX compatibility: a user-space personality on ASPIS APIs

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

The brief: ASPIS must be able to run a native *NIX compatibility layer on top of its APIs. POSIX assumes several things ASPIS deliberately does differently:

- ambient authority;
- `fork`;
- kernel-delivered signals;
- small-integer identities;
- an all-powerful root;
- local, reliable I/O.

The [POSIX compatibility design note](../design/posix-compatibility.md) maps 21 conflicts and the precedents: Domain/OS's BSD and System V environments, QNX, Hurd, Fuchsia's Starnix, Redox's relibc, and WSL.

## Decision

1. **User space only.** POSIX is a personality made of:
   - libc inside each POSIX process;
   - a POSIX process server;
   - a TTY server;
   - the network stack server.

   The kernel gains no POSIX-specific features. What POSIX needs from it is general-purpose (design note §5).
2. **Source compatibility first.** The target is POSIX.1-2024 system interfaces, shell and utilities, plus widely used Linux and BSD extensions. Running unmodified Linux binaries is a separate, later personality, on the Starnix model.
3. **Instances.** A POSIX instance is a process server with its own pid space, uid/gid map and root directory. Each node runs one by default; more can be started for isolation.
4. **`fork()` is supported.** It uses copy-on-write clones of memory objects and a copy of the capability table. `posix_spawn()` is the fast path.
5. **Files.**
   - Descriptors map to open file descriptions held server-side by object managers.
   - `(st_dev, st_ino)` is the per-authority device number plus the ID's sequence.
   - `//` is the network root, which POSIX permits.
   - Names are byte strings, UTF-8 by convention.
6. **Identity.**
   - The realm registry assigns uids and gids to principals.
   - Mode bits are a view onto ACLs.
   - uid 0 is an administrative principal limited by policy, not an all-powerful superuser.
   - setuid runs a program as the file owner's principal, subject to policy.
7. **Failure.** Each subtree has a policy. By default, libc retries until the deadline and then fails with `EIO` or `ETIMEDOUT`. "Hard" subtrees wait indefinitely but can be interrupted by signals.
8. **Signals, job control and terminals live in the layer.** Pseudo-terminals are backed by dm pads in terminal mode.
9. **Libraries.** relibc is ported as the C library. Rust's standard library targets ASPIS APIs directly, not libc.

## Consequences

- Native programs keep capability semantics, and POSIX programs get Unix behavior inside their namespace.
- The kernel requirements in design note §5 become inputs to the kernel specification.
- POSIX programs using remote files can see `EIO` where a local Unix never would; hard subtrees trade that for waiting.
- With no all-powerful root, admin tools that assume root can do anything need explicit policy grants.
- Full Linux binary compatibility is not promised.

## References

- [POSIX compatibility design note](../design/posix-compatibility.md)
