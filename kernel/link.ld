/* SPDX-FileCopyrightText: 2026 Nicole Roy */
/* SPDX-License-Identifier: MPL-2.0 */

/*
 * The kernel is a static, position-independent ELF linked in the upper half
 * of the address space (ADR 0035, rule 2). The stub loads it at a 2 MiB
 * aligned physical address and relocates it for the virtual base it chooses
 * (rules 3 and 4). The early page tables in entry.rs map 32 MiB from the
 * image's start, so the image must stay smaller than that.
 */

ENTRY(_start)

SECTIONS
{
    . = 0xffff800000000000;
    __kernel_start = .;

    .text : {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }

    . = ALIGN(4096);
    .rodata : { *(.rodata .rodata.*) }
    .dynsym : { *(.dynsym) }
    .dynstr : { *(.dynstr) }
    .gnu.hash : { *(.gnu.hash) }
    .hash : { *(.hash) }
    .rela.dyn : { *(.rela.dyn) *(.rela.*) }

    . = ALIGN(4096);
    .data.rel.ro : { *(.data.rel.ro .data.rel.ro.*) }
    .dynamic : { *(.dynamic) }
    .got : { *(.got) *(.got.plt) }
    .data : { *(.data .data.*) }

    /* Test builds only (ADR 0036, rules 5 and 8). */
    .aspis_tests : {
        __tests_start = .;
        KEEP(*(.aspis_tests))
        __tests_end = .;
    }
    .aspis_test_marker : { KEEP(*(.aspis_test_marker)) }

    . = ALIGN(4096);
    .bss (NOLOAD) : {
        __boot_pt_start = .;
        *(.bss.boot_pt)
        __boot_pt_end = .;
        *(.bss .bss.*)
        *(COMMON)
    }

    . = ALIGN(4096);
    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
        *(.interp)
    }
}

ASSERT(__kernel_end - __kernel_start <= 32M, "the kernel image must fit the early 32 MiB mapping")
