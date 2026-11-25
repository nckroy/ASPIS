<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->

# Apollo AEGIS / Domain/OS: research notes for ASPIS

*Compiled 2026-11-24 as input to the ASPIS design discussion. Each fact carries a source tag; see [Sources](#sources). Text marked **Analysis** is our interpretation, not something a source states.*

1. [History in brief](#1-history-in-brief)
2. [Architecture](#2-architecture)
3. [What went wrong](#3-what-went-wrong)
4. [Platform facts for ASPIS](#4-platform-facts-for-aspis)
5. [Implications for ASPIS](#5-implications-for-aspis)
6. [Gaps and next sources](#6-gaps-and-next-sources)

---

## 1. History in brief

| Date | Event | Source |
|---|---|---|
| 1980 | Apollo Computer founded | [W-AC] |
| Mar 1981 | AEGIS SR1 ships on the DN100 (Motorola 68000) | [W-DOS], [W-AC] |
| 1988 | Renamed Domain/OS. SR10 offers three selectable environments: Aegis, BSD 4.3, System V.3 | [W-DOS] |
| Dec 1988 to Mar 1992 | SR10.1 through SR10.4 | [W-DOS] |
| 1989 | HP acquires Apollo for US$476 million | [W-AC] |
| 2 Nov 1997 | Clock rollover makes unpatched systems unusable | [W-TB], [FAQ] |
| 1 Jan 2001 | HP ends final support | [W-DOS] |

- The DN100 used two 68000s. The main CPU ran the OS and programs; a "fixer" CPU serviced page faults while the main CPU was held mid-memory-cycle. The 68010 made this unnecessary. [W-AC]
- AEGIS was written in a proprietary Pascal. [W-AC]
- Domain/OS began as a Unix layer over AEGIS. SR10 brought in large parts of Unix, and the backward compatibility made it larger and significantly slower. [W-AC]

## 2. Architecture

### 2.1 Objects and UIDs

- All storage is objects named by 64-bit UIDs, "unique in space and time": uniqueness in space comes from an encoding of the machine serial number, uniqueness in time from the creation time. [ARCH §III.2]
- A system-global address is 96 bits: a 64-bit UID plus a 32-bit byte offset. [ARCH §III.2]
- `uid_$t` layout, as drawn in the 1992 CERN documentation mirror [W3-UID]:

  ```
  word 0 (32 bits): top 32 bits of the system clock
  word 1 (32 bits): [31:28] counter for UIDs made in the same clock interval
                    [27:20] unused
                    [19:0]  node ID (20 bits)
  ```

  UIDs named files, processes, types and traits. [W3-UID]
- Source discrepancy: the mirror labels the clock field "4 mSec units". The system clock counted 4 µs units in 48 bits [W-TB], so its top 32 bits tick every 2^16 × 4 µs ≈ 0.262 s. Only the 0.262 s reading fits the 1997 rollover date (§3.1); a 4 ms field would have overflowed in April 1980. **Analysis.**
- UID calls: `uid_$gen`, `uid_$hash`, `uid_$nil`, `uid_$bind`, `uid_$unbind`. [W3-CALLS]
- Raw UIDs were visible to users: `ctob` and `uctob` add or remove a directory entry for an object given its UID, a hard link that can cross volumes without changing the link count. [FAQ 4.5]

### 2.2 Single-level store

- Objects are network-wide, byte-addressable spaces mapped into a per-process virtual address space (24-bit on the original hardware). Mapping moves no data. Page faults fetch 1 KB pages on demand from local or remote disks. [ARCH §I.6, §III.2–III.4]
- The Active Segment Table caches the location of each page. [ARCH §III.8]
- Page size, network packet and disk sector were all 1 KB. The ring allowed DMA page faulting from any disk on the network. [W-AC]
- I/O layers, top to bottom: language I/O, streams, mapped I/O, page I/O. [ARCH §III.9–III.10]
- Mapping calls include `ms_$mapl`, `ms_$relock`, `ms_$mk_immutable`, `ms_$fw_file` (force write) and `ms_$advice`. [W3-CALLS]
- The file system applied mandatory, implicit locks, which broke Unix mail-spool conventions. [FAQ 4.2]
- Domain/OS took single-level store and dynamic linking from Multics. [W-DOS] Compiled code was position-independent and re-entrant, and paged in on demand. [ARCH §III.14]

### 2.3 Naming

- One slash-separated hierarchy. A leading `//` is the network-wide root; a single `/` is the node's root. Directories map each name to a UID or to a path name (a link substituted during resolution). [ARCH §IV.2, §III.3]
- The namespace discovered itself as nodes joined. [W-AC]
- Symbolic links can embed environment variables, so `/$(SYSTYPE)/usr/lib/...` resolves differently for BSD and System V processes ("variant links"). [W-DOS], [FAQ 5.23]
- `` `node_data `` names per-node data (`node_data/etc`, `node_data/systmp`). [FAQ] On a diskless node it resolves to a directory on the partner node that serves it. [USENET]
- Each process had both a working directory and a naming directory (`name_$get_wdir`, `name_$get_ndir`). The `name_$` family also includes `root_uid`, `canned_root_uid`, `node_uid`, `node_data_uid`, `add_link`, `resolve` and `mount`. [W3-CALLS]

### 2.4 Typed objects: type managers and traits

- The Open System Toolkit (USENIX 1986) combined a typed object system with Extensible Streams. A type database maps type UID, type manager and type name to one another; a stream operation is dispatched to the manager for the object's type. [OST]
- A trait is a set of operations. An object supports a trait if its type manager implements those operations. `trait_$bind` binds an (object, trait) pair to the manager's entry-point vector. [OST], [W3-CALLS]
- Built-in traits: `io`, `io_oc` (open/create), `io_xoc` (extended open/create for structured objects), `ios_dir` (directories), `sio` (serial lines), `prot` (owner, groups, permissions), `attr` (size, timestamps). Others include `socket`, `vstreams` (System V STREAMS), `xdl` and `xpager` (an external user-space pager). [W3-TRAITS]
- Apollo never published how to write traits, so few third-party ones existed. [W3-TRAITS]
- Type calls: `type_$create`, `type_$install`, `type_$install_mgr`, `type_$install_trait_mgr`, `type_$get_mgr`. [W3-CALLS]
- An object's type is recorded in its volume table-of-contents entry. [ARCH §III.9]

### 2.5 Processes, synchronization and errors

- Program invocation: `pgm_$invoke`, `pgm_$exec`, `pgm_$proc_wait`. Level-2 processes: `proc2_$create`, `proc2_$fork`, `proc2_$signal`, `proc2_$suspend`. [W3-CALLS]
- Synchronization: eventcounts (`ec2_$init`, `ec2_$advance`, `ec2_$read`, `ec2_$wait`), mutexes (`mutex_$lock`), and mailboxes (`mbx_$create_server`, `mbx_$put_rec`, `mbx_$get_rec`). [W3-CALLS]
- Errors were status codes with subsystem, module and code fields (`error_$subsys`, `error_$module`, `error_$code`, `error_$fail`). [W3-CALLS]
- Processes could be connected by streams in the Software Tools style. [ARCH §III.11–III.12]

### 2.6 Protection and identity

- Access control lists (`acl_$`, about 130 calls including `check_rights`, `get_sid` and `set_prot`) and a distributed registry (`rgy_$`) of persons, groups and organizations (`pgo_$` calls). [W3-CALLS]
- Principals had three parts: a cron job started without `-p` ran as `user.none.none`. [FAQ 4.16] **Analysis:** this fits a person.project.organization scheme, but none of the sources read documents the format.
- The registry used encryption-based authentication. Breaking into one node did not let an attacker change the registry without an administrator's password. [FAQ 4.16]
- Users valued ACLs, node-owner policy and protected subsystems. [FAQ 5.23]
- MMU page protection had two supervisor and two user levels. [ARCH §III.6]

### 2.7 Storage

- A physical volume holds logical volumes. Each logical volume has a table of contents (VTOC) listing object UIDs with their attributes: type, access control, accounting dates. Block maps hold 35 pointers with up to four levels of indirection. [ARCH §III.9]
- Every data block records its owning UID and page number, so one pass over the data can rebuild the maps after a failure. [ARCH §III.9]

### 2.8 Networking and RPC

- Proprietary token ring: one token; packets carry source and destination node addresses, a CRC and an acknowledgment field. [ARCH §II] It was designed for small offices with "at most dozens of computers" and didn't interoperate with other networks. [W-AC]
- Ethernet and TCP/IP came later. Domain routing was modeled on Xerox Network Systems. [W-AC]
- NCS (Network Computing System) provided transport-independent RPC, an interface definition language and location brokers (`llbd`, `glbd`). The underlying Network Computing Architecture was placed in the public domain. [W-DOS], [FAQ]
- UUIDs originated in NCS and passed from there to OSF DCE and Microsoft Windows. [RFC9562]
- DSEE (Domain Software Engineering Environment) version control inspired IBM ClearCase. [W-AC]

### 2.9 User environment

- The Display Manager integrated window management with "pads": transcripts kept from process birth, a built-in editor, and editing available everywhere. [W-DOS]
- The DM was the system console: by default, root could log in only on a DM pad. [FAQ 2.5]
- Pads weren't terminals. [FAQ 2.1] The DM was written mainly with GPR, Apollo's graphics library, and `pad_$` calls could place GPR graphics in a pad, so text and graphics shared a window. [FAQ 3.11]

## 3. What went wrong

### 3.1 The 2 November 1997 clock rollover

- The clock was a signed 48-bit count of 4 µs units since 1 January 1980. [W-TB]
- The Pascal include files declared the high 32 bits of the clock type as a 31-bit value. The failure took effect at 14:59 GMT on 2 November 1997. [FAQ 4.25, read via summary]
- Check: 2^47 × 4 µs = 562,949,953.4 s after 1980-01-01T00:00:00Z, which is **1997-11-02T14:59:13Z**. **Analysis.**
- Unpatched systems became unusable. [W-TB] HP's first patch (PD96_M0739) was withdrawn after it broke `cal_$encode_time` for some dates and was replaced by PD96_M0748. A one-byte patch to `/lib/kslib` circulated as a risky workaround. [FAQ 4.25, summary]
- Setting the clock back was the other workaround. It came with warnings about wrong timestamps, clock skew between nodes, and **duplicate file UIDs leading to file-system corruption**. [FAQ 4.25, summary]
- The FAA's Enhanced Traffic Management System ran on 450 HP Apollo workstations. HP's OS patch worked, but Pascal applications built on the same clock type still crashed until they were fixed. [FAA]
- **Analysis.** A UID's first word is the top 32 bits of that clock, so every UID minted after the rollover has its top bit set and falls outside the declared 31-bit range.

Lessons (**Analysis**):

1. Wall-clock time was part of identity. Resetting the clock threatened uniqueness; the clock rolling over invalidated identity.
2. A signedness mismatch at a type boundary turned a counter into a time bomb.
3. A fixed tick plus a 4-bit counter capped how many UIDs a node could mint per tick.
4. Node IDs were 20 bits derived from hardware serial numbers: about a million nodes, assigned at the factory, with nothing to prove them.
5. 64 bits and no version field left no room to evolve the format.

### 3.2 Other weaknesses

- The network didn't interoperate and was sized for dozens of nodes. [W-AC]
- Layering Unix onto AEGIS made SR10 larger and slower. [W-AC]
- Mandatory implicit locking conflicted with Unix conventions. [FAQ 4.2]
- Third parties couldn't extend the trait system. [W3-TRAITS]
- **Analysis.** Node identity was a hardware serial number, not a key. The only cryptography in the sources read is the registry's authentication; nothing indicates node-to-node traffic was authenticated or encrypted. This is absence of evidence, not proof.
- **Analysis.** With a single-level store, a remote failure surfaces as a page fault in the middle of an ordinary memory access, where the program has no natural place to handle it. Waldo et al. make the general case: latency, memory access, partial failure and concurrency mean remote objects can't be made indistinguishable from local ones. [WALDO] FAQ user reports include boots hanging when network services were unavailable, and an NFS-exported `//` described as a bottleneck in front of unreliable nodes. [FAQ 4.5, 4.19]

## 4. Platform facts for ASPIS

### 4.1 GRUB on ARM64

- GRUB's build definitions enable `multiboot2` only for `x86`, `i386_xen_pvh` and `mips`, and `multiboot` only for `x86` and `i386_xen_pvh`. ARM64 gets neither. [GRUB-MK] This was checked in Red Hat's GRUB tree, which tracks upstream; the upstream Savannah server refused automated access. A 2019 Debian bug noted multiboot had not been ported to ARM [DEB-940628]. An arm64 Multiboot2 series was posted in October 2020 [GRUB-ML-2020] and is not in the tree.
- On arm64 the `linux` command is GRUB's EFI loader. [GRUB-LINUX]
  - It requires a PE/COFF image (`MZ` signature, PE32+ optional header).
  - It rejects plain images with "plain image kernel not supported - rebuild with CONFIG_(U)EFI_STUB enabled".
  - It starts the image with UEFI `LoadImage`/`StartImage`.
  - If the image's PE major image version is 1 or higher, the initrd is offered through `EFI_LOAD_FILE2_PROTOCOL` on a device path tagged `LINUX_EFI_INITRD_MEDIA_GUID`. Otherwise it goes in the FDT as `/chosen` `linux,initrd-start` and `linux,initrd-end`.
- `chainloader` (module `chain`) loads any image the firmware's `LoadImage` accepts, on any EFI platform. [GRUB-CHAIN]
- GRUB 2.14 (January 2026) adds NX support for EFI, the shim loader protocol, BLS and UKI support, a TPM 2.0 key protector and Argon2. Nothing in it is arm64-specific. [GRUB-NEWS], [PHX]
- **Consequence:** under GRUB on ARM64, ASPIS must be a UEFI PE32+ image. The same image can be booted directly by firmware, and by U-Boot on boards where U-Boot implements UEFI.

### 4.2 Post-quantum cryptography

- The lattice-based NIST standards are **FIPS 203 ML-KEM** (key encapsulation) [FIPS203] and **FIPS 204 ML-DSA** (signatures) [FIPS204], both final since August 2024. FIPS 205 SLH-DSA is hash-based, not lattice-based.
- **FN-DSA** (Falcon, lattice-based, FIPS 206): the draft was submitted for approval in August 2025, and vendors expect the final standard in late 2026 or early 2027. [NIST-206], [EC-206]
- **HQC** (code-based) was selected in March 2025 as a backup KEM. NIST planned a draft about a year later and a final standard in 2027. [NIST-HQC]
- Sizes that drive protocol design, in bytes [FIPS203], [FIPS204]:

  | Parameter set | Public key | Ciphertext or signature |
  |---|---|---|
  | ML-KEM-768 | 1184 | 1088 |
  | ML-KEM-1024 | 1568 | 1568 |
  | ML-DSA-65 | 1952 | 3309 |
  | ML-DSA-87 | 2592 | 4627 |

  A single ML-DSA-65 signature is larger than the 1280-byte IPv6 minimum MTU, so handshakes must fragment. **Analysis.**
- Rust implementations:
  - RustCrypto `ml-kem`: pure Rust, `no_std`; 0.3.0 pre-release in January 2026. [LIBRS-MLKEM]
  - Cryspen `libcrux-ml-kem` and `libcrux-ml-dsa`: ML-KEM is verified with hax as panic-free, functionally correct and secret-independent; `no_std` given a global allocator; every crate is below 0.1. [CRYSPEN], [LIBCRUX]
  - RustCrypto `ml-dsa`: current status not confirmed.

  Choosing a library is a design-session task.

### 4.3 Firmware framebuffers after boot

- UEFI's Graphics Output Protocol (GOP) may expose a linear framebuffer or offer only `Blt()`; a `Blt()`-only GOP conforms to the UEFI spec. [ARD-GOP] GOP is a boot-time protocol, so after `ExitBootServices` only a linear framebuffer stays usable.
- On QEMU aarch64, EDK2's virtio-gpu GOP reports `PixelBltOnly`, meaning no linear framebuffer. [EDK2-VGPU], [SUSE-1219180] virtio-vga isn't available on aarch64. [SUSE-1219180] The `ramfb` device provides a simple framebuffer in guest RAM, driven by EDK2's QemuRamfbDxe. [ERSEK-RAMFB]
- **Analysis.** On the Raspberry Pi 4 with the pftf UEFI firmware, the GOP is expected to provide a linear framebuffer. This needs confirming on hardware.

### 4.4 Prior art: vector imaging models for displays

- Sun's NeWS and Adobe's Display PostScript (used by NeXTSTEP) made PostScript the imaging model of the window system. Neither gained broad acceptance. [W-DPS]
- When NeXTSTEP became Mac OS X, Apple replaced Display PostScript with Quartz, which uses the PDF imaging model. Secondary sources give two reasons: licensing costs, and that PDF is a display format rather than a programming language, so it needs no interpreter. [ECL-PDF], [W-DPS]
- **Analysis.** What lasted was the imaging model, not the language. ASPIS should adopt SVG's imaging model and document format, without scripting.

### 4.5 Vector rendering in Rust

- resvg, a static SVG renderer now maintained by Linebender, is built on usvg (parser and simplifier) and tiny-skia (CPU rasterizer). The latest release is 0.47.0. [RESVG] `no_std` support isn't confirmed.
- Vello's "sparse strips" renderers: vello_cpu is alpha (0.0.x, with breaking changes expected), and vello_hybrid splits work between CPU and GPU (0.0.6, January 2026). [VELLO], [LIBRS-VH]

## 5. Implications for ASPIS

Proposals from the discussion. The ones accepted on 2026-11-24 are recorded as decision records in [docs/decisions](../decisions/README.md).

| AEGIS | Keep or change | ASPIS proposal |
|---|---|---|
| 64-bit time + node UID | Change | An ID with no clock in it: node UUID (globally unique) + per-node monotonic sequence (indexable) + version and class. All fields unsigned; byte order is sort order |
| Single-level store | Keep | Objects mapped by ID; user-space pagers; remote pages over secure RPC; failures delivered as typed faults |
| Type managers and traits | Keep, open up | User-space type managers; traits as IDL interfaces; documented for third parties |
| `//` namespace, variant links, `` `node_data `` | Keep | Realm-rooted namespace; friendly node names over node UUIDs; context-dependent links |
| Eventcounts, mailboxes, `pgm_$invoke` | Keep | 64-bit eventcounts as the async primitive; spawn-only process creation; fork only in the POSIX layer |
| Structured status codes | Keep | Typed errors namespaced by subsystem ID, preserved across RPC |
| Self-describing disk blocks | Keep | Back-references and checksums in the object store |
| Kernel-checked ACLs | Change | Kernel capabilities; ACLs and policy enforced by object managers |
| Hardware-serial node IDs | Change | Node UUID derived from the node's post-quantum identity key |
| Unauthenticated network | Change | Mutually authenticated ML-KEM/ML-DSA transport in a user-space network server |
| Mandatory implicit locks | Change | Leases or tokens with explicit semantics |
| NCS | Keep | ASPIS RPC, IDL and location service |
| Aegis/BSD/SysV environments | Keep | POSIX personality in user space ([0012](../decisions/0012-posix-compatibility-layer.md), [design note](../design/posix-compatibility.md)) |
| Display Manager, pads, GPR graphics in pads | Keep | `dm` built on Display SVG; pads mix text and SVG ([0011](../decisions/0011-dm-window-system.md)) |

## 6. Gaps and next sources

- Not yet read, because both exceed the web-fetch size limit: *Domain/OS Design Principles* (January 1989, 14 MB) [DP] and *AEGIS Overview* (1985, 15 MB) [AO]. They should cover lock modes, how cached remote pages were validated, the hint manager, and behavior when a remote node fails.
- Not read: Leach et al., "UIDs as Internal Names in a Distributed File System" (PODC 1982) [LEACH82]; Leach et al., "The Architecture of an Integrated Local Network" (IEEE JSAC 1983, DOI 10.1109/JSAC.1983.1146002) [LEACH83]; the full 1986 USENIX Open System Toolkit paper; *Apollo DOMAIN Architecture* (February 1981) [ARCH81].
- Unverified: the SID format, the partner-node boot protocol, the token ring bit rate, and whether `ms_$` offered named concurrency modes.

## Sources

- [ARCH] Apollo DOMAIN architecture overview, undated plain-text copy (early 1980s): https://anna.lysator.liu.se/pub/doc/OS/domain/architecture.technical
- [W3-UID] `uid_$t`, 1992 CERN mirror of Domain/OS documentation: https://www.w3.org/History/1992/nfs_dxcern_mirror/web/Apollo/types/uid.html
- [W3-TRAITS] Domain/OS types and traits: https://www.w3.org/History/1992/nfs_dxcern_mirror/web/Apollo/Traits.html
- [W3-CALLS] Domain/OS call index and per-family pages (`uid`, `ms`, `name`, `trait`, `type`, `pgm`, `proc2`, `ec2`, `mutex`, `mbx`, `error`, `acl`, `rgy`): https://www.w3.org/History/1992/nfs_dxcern_mirror/web/Apollo/Domain_calls.html
- [OST] Open System Toolkit / Extensible Streams material, seen as search excerpts: https://bio.nic.funet.fi/pub/unix/apollo/ost
- [W-DOS] Wikipedia, "Domain/OS": https://en.wikipedia.org/wiki/Domain/OS
- [W-AC] Wikipedia, "Apollo Computer": https://en.wikipedia.org/wiki/Apollo_Computer
- [W-TB] Wikipedia, "Time formatting and storage bugs": https://en.wikipedia.org/wiki/Time_formatting_and_storage_bugs
- [FAQ] comp.sys.apollo FAQ, revision 5, December 2001: https://jk.kom.tuwien.ac.at/Software/Apollo/FAQ.html. Items 4.21–4.25 were read through a summary, not verbatim.
- [USENET] comp.sys.apollo posts from 1992–93, seen as search excerpts and not read in full: https://discmaster.textfiles.com/view/28248/NN_1993_1.iso/spool/comp/sys/apollo/4232
- [FAA] "FAA corrects system bug, averts holiday travel crisis", November 1997: https://www.route-fifty.com/digital-government/1997/11/faa-corrects-system-bug-averts-holiday-travel-crisis/307893/
- [RFC9562] RFC 9562, Universally Unique IDentifiers (UUIDs): https://www.rfc-editor.org/rfc/rfc9562
- [WALDO] Waldo, Wyant, Wollrath, Kendall, "A Note on Distributed Computing", Sun Labs SMLI TR-94-29, 1994: https://waldo.scholars.harvard.edu/publications/note-distributed-computing
- [GRUB-MK] GRUB `Makefile.core.def` (rhboot tree): https://raw.githubusercontent.com/rhboot/grub2/master/grub-core/Makefile.core.def
- [GRUB-LINUX] GRUB EFI Linux loader: https://raw.githubusercontent.com/rhboot/grub2/master/grub-core/loader/efi/linux.c
- [GRUB-CHAIN] GRUB EFI chainloader: https://raw.githubusercontent.com/rhboot/grub2/master/grub-core/loader/efi/chainloader.c
- [GRUB-NEWS] GRUB NEWS: https://raw.githubusercontent.com/rhboot/grub2/master/NEWS
- [PHX] Phoronix, "GRUB 2.14 Bootloader Released": https://phoronix.com/news/grub-2.14-released
- [DEB-940628] Debian bug 940628, missing multiboot modules on non-x86 EFI: https://lists.alioth.debian.org/pipermail/pkg-grub-devel/2019-September/016796.html
- [GRUB-ML-2020] grub-devel, "Enable multiboot2 support on arm64-efi target" series, October 2020: https://lists.gnu.org/archive/html/grub-devel/2020-10/msg00175.html
- [FIPS203] FIPS 203, ML-KEM: https://csrc.nist.gov/pubs/fips/203/final
- [FIPS204] FIPS 204, ML-DSA: https://csrc.nist.gov/pubs/fips/204/final
- [NIST-206] NIST, FIPS 206 (FN-DSA) presentation, 2025: https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon
- [EC-206] Encryption Consulting, FN-DSA / FIPS 206 overview: https://www.encryptionconsulting.com/education-center/fn-dsa-fips-206/
- [NIST-HQC] NIST selects HQC, March 2025: https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption
- [LIBRS-MLKEM] RustCrypto `ml-kem`: https://lib.rs/crates/ml-kem
- [CRYSPEN] Cryspen, "Verified ML-KEM (Kyber) in Rust": https://cryspen.com/post/ml-kem-implementation/
- [LIBCRUX] libcrux: https://github.com/cryspen/libcrux
- [DP] *Domain/OS Design Principles*, 014962-A00, January 1989: https://ftp.mirrorservice.org/sites/www.bitsavers.org/pdf/apollo/014962-A00_Domain_OS_Design_Principles_Jan89.pdf
- [AO] *AEGIS Overview*, 1985: https://ftp.mirrorservice.org/sites/www.bitsavers.org/pdf/apollo/AEGIS_Overview_1985.pdf
- [ARCH81] *Apollo DOMAIN Architecture*, February 1981: https://ftp.mirrorservice.org/sites/www.bitsavers.org/pdf/apollo/Apollo_DOMAIN_Architecture_Feb81.pdf
- [LEACH82] Leach, Stumpf, Hamilton, Levine, PODC 1982, pp. 34–41: https://researchr.org/publication/LeachSHL82/bibtex
- [LEACH83] Leach, Levine, Douros, Hamilton, Nelson, Stumpf, IEEE JSAC 1(5), 1983: https://researchr.org/publication/LeachLDHNS83/bibtex
- [ARD-GOP] Ard Biesheuvel on `Blt()`-only GOP conformance (linux-efi): https://lore.kernel.org/all/CAKv+Gu-5CffcgsWwOUpXukVQJaSxRtvHTFiQjf+OmG380iKWaA@mail.gmail.com/
- [EDK2-VGPU] EDK2 `OvmfPkg/VirtioGpuDxe/Gop.c`: https://qemu.googlesource.com/edk2/+/refs/heads/12m23/OvmfPkg/VirtioGpuDxe/Gop.c
- [SUSE-1219180] openSUSE bug 1219180, "Missing framebuffer during boot on aarch64": https://lists.opensuse.org/archives/list/bugs@lists.opensuse.org/thread/DH65VFJ5XTLXQMEACY5POJYHQJUDTYN3
- [ERSEK-RAMFB] Laszlo Ersek on ramfb and virtio-gpu drivers in EDK2: https://lore.kernel.org/all/6fc9f102-0d73-68cc-592b-5d74479c0351@redhat.com/
- [W-DPS] Wikipedia, "Display PostScript": https://en.wikipedia.org/wiki/Display_PostScript
- [ECL-PDF] The Eclectic Light Company, "A brief history of PDF on the Mac", 2025: https://eclecticlight.co/2025/08/09/a-brief-history-of-pdf-on-the-mac/
- [RESVG] resvg: https://github.com/linebender/resvg and https://docs.rs/crate/resvg/latest
- [VELLO] Vello sparse-strips renderers: https://github.com/linebender/vello/tree/main/sparse_strips
- [LIBRS-VH] vello_hybrid on lib.rs: https://lib.rs/crates/vello_hybrid
