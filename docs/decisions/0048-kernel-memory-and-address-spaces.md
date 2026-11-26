<!-- SPDX-FileCopyrightText: 2026 Nicole Roy -->
<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# 0048. Kernel memory: untyped memory, 4 KiB pages, and no access to user addresses

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

The [design backlog, D14](../design/design-backlog.md#m2-kernel-objects) asks how kernel objects get their memory, what the physical frame allocator is, which translation granule the kernel uses, how address spaces are laid out, and whether W^X, PAN and PXN apply from the first page tables (D145).

What is already fixed:

- The kernel is a position-independent ELF linked in the upper half of the address space, and the stub relocates it ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rules 2 to 4). C05 chose the virtual base `0xffff_8000_0000_0000`, with 48-bit halves and 4 KiB granules.
- The boot information's memory map types every range ([0041](0041-boot-abi.md), rule 3).
- The kernel doesn't map the UEFI runtime regions ([0039](0039-no-uefi-runtime-services.md), rule 1), and never reads the seed's page ([0041](0041-boot-abi.md), rule 4).
- The initial image is aligned to 64 KiB until the page size is fixed ([0037](0037-initial-image-format-and-contents.md), rule 1).
- Jobs have memory budgets ([0025](0025-twelve-factor-app-contract.md), rule 12).
- The kernel maps its text and read-only data read-only only after the stub has relocated it ([0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 3).

[0047](0047-the-kernel-follows-sel4.md) adopts seL4's untyped memory, and its rule 4 forbids the kernel to wait for anything outside itself. That rule matters most when the kernel reads user memory. In a single-level store, a user page may be missing, and fetching it may mean a pager asking a remote node. If the kernel waited for that page, a hostile or partitioned node could stall a system call indefinitely, while it held kernel locks. The project owner raised this on 2026-11-25. seL4 already avoids it: its kernel reads only registers and a per-thread IPC buffer that must be mapped, and it takes no page faults on user memory.

This record states what is decided and what is guaranteed. The mechanism behind it is in the [kernel specification](../design/kernel-specification.md), a design note written from these records ([0047](0047-the-kernel-follows-sel4.md), rule 5), which also lists what is still open.

Claude drafted this record from the project owner's choices of 2026-11-25.

## Decision

1. **Memory is untyped until a holder retypes it**, as in seL4. The kernel has no other frame allocator, and no heap.
   - At boot, the kernel keeps what it needs for itself: its image, with the panic symbol table that the stub places after it ([0061](0061-debugging.md), rule 2); its stacks, page tables and log ring ([0042](0042-log-ring-and-panic-path.md), rule 1); on a GICv3, the redistributors' LPI tables ([0055](0055-interrupt-objects.md), rule 4); and the boot objects of rule 2. The [kernel specification](../design/kernel-specification.md#boot-memory) lists the details.
   - It gives the rest of usable RAM to the root server as untyped memory, and the MMIO ranges as device untyped memory, except the devices the kernel drives itself: every frame of the interrupt controller, and the UART.
   - **After boot, the kernel never allocates memory that no job supplied.** Every kernel object, page table, frame and kernel record made after boot is made from untyped memory. So the kernel's own memory never grows, and it can't run out at a bad moment.
   - **An object belongs to the job whose untyped memory it is made from** ([0058](0058-jobs-and-budgets.md), rule 1), as an seL4 object belongs to the untyped region it came from. Making an object needs untyped memory, not the job's capability. The one exception is a child job, which needs its parent's job capability, because it carves the parent's reservation, limit and CPU share ([0058](0058-jobs-and-budgets.md), rule 9).
   - **Memory that no caller supplies comes from the job responsible.** Map's page tables and mapping records come from the address space's job ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 3). The root server's address space belongs to no job (rule 2), so its page tables and mapping records come from the root job. A fault's memory comes from the job [0058](0058-jobs-and-budgets.md), rule 6 names.
   - How a job's memory is divided into pieces, and how the kernel keeps its small records in them, is in the [kernel specification](../design/kernel-specification.md#untyped-memory-and-kernel-records).
2. **The kernel presents boot memory as objects.**
   - The initial image, the device tree and the boot information become resident immutable memory objects ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 1), so the root server can map executables in place ([0037](0037-initial-image-format-and-contents.md), rule 4).
   - The kernel interface library's pages, which the kernel's image carries but never executes, become the library's resident immutable memory object ([0059](0059-the-kernel-interface-library.md), rule 3).
   - The framebuffer becomes a device memory object, beside the framebuffer's kernel object ([0042](0042-log-ring-and-panic-path.md), rule 6).
   - The seed's page becomes a frame that the kernel never maps. D42 decides how it reaches the entropy service ([0041](0041-boot-abi.md), rule 4).
   - All of these go to the root server, with the root job, the root server's first thread and its IPC buffer, its capability space, its address space and the control capabilities.
   - **Boot objects belong to no job, and are never destroyed.** They are made from memory the kernel kept for itself, so none of them is ever untyped memory, and they count against no reservation or limit ([0058](0058-jobs-and-budgets.md), rule 1).
3. **Pages are 4 KiB.** The translation granule is 4 KiB everywhere, with 2 MiB and 1 GiB block mappings where a range allows. Addresses are 48 bits in each half.
4. **The address space is split in two.**
   - **The lower half (`TTBR0`)** belongs to user space. Each address space has its own tables and its own ASID.
   - **No job can use up the node's ASIDs.** The hardware has 65,536 or 256 of them, and memory accounting doesn't bound how many address spaces a job makes. So ASIDs are allocated in a way that one job can't exhaust. How is open in the [kernel specification](../design/kernel-specification.md#address-space-layout).
   - **The upper half (`TTBR1`)** belongs to the kernel, at the base C05 fixed. It holds the kernel's image, its stacks, the devices it drives (rule 1), the boot framebuffer until it is retired ([0042](0042-log-ring-and-panic-path.md), rule 6), and a direct map.
   - **The direct map covers RAM only, and is never executable.** It covers usable RAM and the ranges that hold rule 2's immutable objects. The kernel image's range is mapped read-only there, so the kernel's code has no writable alias. It leaves out the UEFI runtime regions and other firmware-reserved memory ([0039](0039-no-uefi-runtime-services.md), rules 1 and 2), the seed's page ([0041](0041-boot-abi.md), rule 4), the framebuffer and all MMIO.
5. **The kernel never dereferences a user address, and never takes a page fault in kernel mode.**
   - It reads arguments from registers, and messages from the calling thread's IPC buffer through its own direct map.
   - **A thread's IPC buffer is pinned** ([0054](0054-ipc-endpoints.md), rule 3). It is a resident page of RAM in a memory object of the thread's own job or an ancestor's, so it can't outlive the thread. The root server's first thread uses the buffer the kernel gave it at boot (rule 2). The pinned frame is its object's own, never shared copy-on-write. Eviction, decommit and reclaim skip it, and destroying its object, or ending that object's job, unregisters the buffer first ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 8). It stays charged to its memory object's job ([0058](0058-jobs-and-budgets.md), rule 5).
   - **Other user memory is reached by walking the tables in software.** For a word wait ([0053](0053-eventcounts.md), rule 6), or a debugger's read or write ([0061](0061-debugging.md), rule 3), the kernel walks the address space's tables and reaches the frame through its direct map.
     - If the page isn't resident, the call fails at once with "not resident", and holds no lock. The caller touches the page in user mode, which is an ordinary page fault that goes to the pager under a deadline ([0056](0056-faults-and-page-fetch-deadlines.md), rule 4), and retries.
     - If the address is mapped to a device memory object, the call fails at once with "not RAM". So the kernel never touches MMIO on a user's behalf.
   - **The kernel writes only where the process could.** A debugger writes only through a mapping with the write right, except into the private clone that holds software breakpoints ([0061](0061-debugging.md), rules 3 and 4). So code in an immutable object never changes.
   - **The kernel writes only into a frame its object owns.** A page shared copy-on-write is copied first, charged to the written object's job, as any write is ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 4). If that job can't pay, the call fails at once with "no memory". Every kernel write marks the page dirty, as a user write does, so the pager's write-back sees it ([0057](0057-memory-objects-and-the-pager-protocol.md), rule 8).
   - The order of these steps is in the [kernel specification](../design/kernel-specification.md#access-to-user-memory).
   - So no pager or remote node can stall a system call.
6. **Mappings are never both writable and executable**, from the first page tables (C10).
   - In the kernel's half, text is read-only and executable, read-only data is read-only, and everything else is read-write and never executable.
   - The kernel refuses a user mapping that would be both writable and executable.
   - Every user mapping is marked PXN, so the kernel never executes user pages. Every kernel mapping is marked UXN.
   - PAN is turned on where the processor implements it (Armv8.1 and later). The Pi 4's Cortex-A72 doesn't, and rule 5 makes the kernel safe without it. Whether to emulate PAN there is C78's.
   - [0035](0035-toolchain-image-linkage-and-esp-layout.md), rule 3 sets the order: the kernel write-protects its text and read-only data only after the stub has relocated it.

## Consequences

- **A job's memory is the untyped memory it holds**: its reservation, and whatever it has borrowed from the node's pool up to its limit ([0058](0058-jobs-and-budgets.md)). Kernel objects, page tables and capability spaces count against it, because they are made from it.
- **The kernel can't run out of memory at a bad moment.** A call that needs memory is given it by its caller, or fails at once. A fault that needs memory takes it from the responsible job, or asks for more without waiting ([0058](0058-jobs-and-budgets.md), rule 6).
- **IPC buffers can't be evicted, and can't outlive their memory.** A registered buffer costs one resident page, and the kernel never writes a message into a frame that has been reused.
- **Remote nodes can't reach the kernel's locks.** A slow or hostile pager can delay the faulting thread, which its deadline bounds, but never a system call. Words in pages shared between nodes don't work as locks, since a wake on one node can't reach a waiter on another; locks across nodes use leases or tokens ([0005](0005-single-level-store.md), rule 4).
- **The initial image can be aligned to 4 KiB**, as [0037](0037-initial-image-format-and-contents.md), rule 1 anticipates once the page size is fixed. Whether the builder changes is C02's choice.
- **The M1 kernel's early tables are replaced.** M1 maps the kernel's 32 MiB with 2 MiB blocks that share one set of attributes, and identity-maps the first 4 GiB of physical memory in the lower half. C10 replaces both with the layout above, and the lower half is left to user space.
- **D14 is settled, except for mechanism.**
  - How kernel objects get their memory, and the frame allocator: untyped memory, owned by jobs (rule 1).
  - The translation granule: 4 KiB (rule 3).
  - The address-space layout: rule 4.
  - D145 for the first page tables: W^X and PXN from C10, PAN where the hardware has it, and no writable alias of the kernel's code (rule 6). Randomizing the kernel's placement, and the rest of D145, stay with C78.
  - Open in the kernel specification, to be settled with the prototype of C10 to C16: how ASIDs are allocated (rule 4), how a job's small kernel records are kept in its pieces, and how the index of a job's pieces is paid for (rule 1).

## References

- [seL4 reference manual, 17.0.0: untyped memory and the IPC buffer](https://docs.sel4.systems/releases/sel4/17.0.0)
- [Arm Architecture Reference Manual for A-profile architecture (DDI 0487), issue M.d](https://developer.arm.com/documentation/ddi0487/latest): translation granules, ASIDs (`ID_AA64MMFR0_EL1.ASIDBits`), PAN, PXN and UXN
- [Kernel specification](../design/kernel-specification.md): boot memory, untyped memory and kernel records, the address-space layout, and access to user memory
- [0047. The kernel follows seL4](0047-the-kernel-follows-sel4.md); [0041. Boot ABI](0041-boot-abi.md); [0037. Initial image](0037-initial-image-format-and-contents.md); [0039. No UEFI runtime services](0039-no-uefi-runtime-services.md); [0035. Toolchain, image linkage and ESP layout](0035-toolchain-image-linkage-and-esp-layout.md); [0055. Interrupt objects](0055-interrupt-objects.md)
