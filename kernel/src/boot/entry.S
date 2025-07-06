# Copyright 2025 arancormonk
# SPDX-License-Identifier: MIT

# Assembly entry point for PIE kernel
# This captures the boot info pointer before any relocations

.global _start
.global _zig_start
.global boot_info_ptr

.section .text._start, "ax", @progbits
_start:
    # Disable interrupts
    cli
    
    # Save the boot info pointer (passed in RDI) using RIP-relative addressing
    # This is compatible with PIE/PIC
    movq %rdi, boot_info_ptr(%rip)
    
    # Call the Zig entry point
    jmp _zig_start

.section .data
.align 8
boot_info_ptr:
    .quad 0