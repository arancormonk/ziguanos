/* Copyright 2025 arancormonk
 * SPDX-License-Identifier: MIT */

/* Ziguanos Kernel Linker Script */
/* Optimized for UEFI x86-64 kernel at 2MB physical address */

ENTRY(_start)
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

SECTIONS
{
    /* Base address - with PIE this becomes a relative offset from the actual load address */
    . = 0x200000;
    __kernel_start = .;

    /* Code section - executable instructions */
    .text ALIGN(4096) : {
        /* Entry point must be first */
        KEEP(*(.text._start))
        *(.text .text.*)
        /* Include compiler-generated sections */
        *(.gnu.linkonce.t*)
    }

    /* Read-only data after code for cache efficiency */
    .rodata ALIGN(4096) : {
        *(.rodata .rodata.*)
        *(.gnu.linkonce.r*)
        
        /* Exception handling data if needed */
        *(.gcc_except_table)
        *(.gcc_except_table.*)
    }

    /* Ensure proper alignment for data sections */
    . = ALIGN(4096);
    __data_start = .;

    /* SMP trampoline code - must be kept together in its own section */
    .trampoline ALIGN(4096) : {
        *(.data.trampoline)
    }
    
    /* Initialized data */
    .data ALIGN(4096) : {
        /* Exclude trampoline section */
        *(.data)
        *(.data.[!t]*)
        *(.data.t[!r]*)
        *(.data.tr[!a]*)
        *(.data.tra[!m]*)
        *(.data.tram[!p]*)
        *(.data.tramp[!o]*)
        *(.data.trampo[!l]*)
        *(.data.trampol[!i]*)
        *(.data.trampoli[!n]*)
        *(.data.trampolin[!e]*)
        *(.gnu.linkonce.d*)
        
        /* Constructor/destructor arrays for C++ support */
        __init_array_start = .;
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array))
        __init_array_end = .;
        
        __fini_array_start = .;
        KEEP(*(SORT(.fini_array.*)))
        KEEP(*(.fini_array))
        __fini_array_end = .;
    }

    /* Small data sections for optimization */
    .sdata ALIGN(16) : {
        *(.sdata .sdata.*)
    }

    /* BSS section for uninitialized data */
    .bss ALIGN(4096) : {
        __bss_start = .;
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(8);
        __bss_end = .;
    }

    /* Boot stack - 64KB for early initialization including error handling */
    /* Real stack will be allocated dynamically after PMM init */
    .boot_stack ALIGN(4096) : {
        __boot_stack_bottom = .;
        . += 0x10000; /* 64KB boot stack */
        __boot_stack_top = .;
    }

    /* End of kernel image */
    . = ALIGN(4096);
    __kernel_end = .;
    __kernel_size = __kernel_end - __kernel_start;

    /* Symbols for physical memory management - these will be set at runtime */
    /* For PIE builds, these are set by the bootloader based on actual load address */

    /* Discard unnecessary sections */
    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.debug*)
        *(.gnu.warning*)
        /* Keep relocations for PIE support - bootloader needs these */
        /* *(.rel*) */
        /* *(.rela*) */
        /* Discard PE/COFF sections from UEFI toolchain */
        *(.pdata*)
        *(.xdata*)
    }
}