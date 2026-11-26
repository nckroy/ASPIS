/* SPDX-FileCopyrightText: 2026 Nicole Roy */
/* SPDX-License-Identifier: MPL-2.0 */

/*
 * The kernel is a static, position-independent ELF linked in the upper half
 * of the address space (ADR 0035, rule 2). The stub loads it at a 2 MiB
 * aligned physical address and relocates it for the virtual base it chooses
 * (rules 3 and 4). The bootstrap page tables in entry.rs map the image, and
 * nothing past its end, within 32 MiB of its start, with the boot window
 * right above, so the image must stay smaller than that. They map the first
 * 2 MiB by page, text executable and the rest not, so text must fit in it.
 *
 * The image is laid out in three page-aligned parts, so that the kernel's
 * own tables can map each with its own permissions (ADR 0048, rule 6):
 *
 *   [__text_start, __text_end)      text: read-only, executable
 *   [__rodata_start, __rodata_end)  read-only data: read-only, never
 *                                   executable. It includes the relocated
 *                                   sections, which are read-only once the
 *                                   stub has relocated them (ADR 0035,
 *                                   rule 3), and the test table.
 *   [__data_start, __data_end)      data and .bss: read-write, never
 *                                   executable, except the guard page.
 *
 * The boot stack has a page-aligned section of its own, with a guard page
 * below it that the kernel's tables leave unmapped, so an overflow takes a
 * translation fault, which panics, instead of overwriting .bss. The
 * exception entry's own pushes fault on the guard page too, until the stack
 * pointer has passed it; the frames then land in the bootstrap tables below
 * it, which nothing uses after the switch.
 */

ENTRY(_start)

SECTIONS
{
    . = 0xffff800000000000;
    __kernel_start = .;

    __text_start = .;
    .text : {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }
    . = ALIGN(4096);
    __text_end = .;

    __rodata_start = .;
    .rodata : { *(.rodata .rodata.*) }
    .dynsym : { *(.dynsym) }
    .dynstr : { *(.dynstr) }
    .gnu.hash : { *(.gnu.hash) }
    .hash : { *(.hash) }
    .rela.dyn : { *(.rela.dyn) *(.rela.*) }
    .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) }
    .dynamic : { *(.dynamic) }
    .got : { *(.got) *(.got.plt) }

    /* Test builds only (ADR 0036, rules 5 and 8). */
    .aspis_tests : {
        __tests_start = .;
        KEEP(*(.aspis_tests))
        __tests_end = .;
    }
    .aspis_test_marker : { KEEP(*(.aspis_test_marker)) }
    . = ALIGN(4096);
    __rodata_end = .;

    __data_start = .;
    .data : { *(.data .data.*) }

    . = ALIGN(4096);
    .bss (NOLOAD) : {
        /*
         * The bootstrap tables, which are dead once the kernel has switched
         * to its own. They lie right below the guard page, so an overflow's
         * nested exception frames land in them. The empty table that
         * TTBR0_EL1 holds is live, so it is read-only data instead
         * (.rodata.zero_table), out of their way.
         */
        __boot_pt_start = .;
        *(.bss.boot_pt)
        __boot_pt_end = .;
        . = ALIGN(4096);
        __stack_guard_start = .;
        . += 4096;
        __stack_guard_end = .;
        *(.bss.stack)
        . = ALIGN(4096);
        __stack_end = .;
        *(.bss .bss.*)
        *(COMMON)
    }

    . = ALIGN(4096);
    __data_end = .;
    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
        *(.interp)
    }
}

ASSERT(__kernel_end - __kernel_start <= 32M, "the kernel image must fit the bootstrap 32 MiB mapping")
ASSERT(__text_end - __kernel_start <= 2M, "kernel text must fit the bootstrap tables' level-3 table")
ASSERT(__stack_end - __stack_guard_end == 64K, "the boot stack must sit right above its guard page")
