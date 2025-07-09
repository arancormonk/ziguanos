# Copyright 2025 arancormonk
# SPDX-License-Identifier: MIT

# Application Processor (AP) startup trampoline
# This code is copied to low memory (0x7000) and executed in real mode
# Compatible with PIE/PIC kernel requirements

.section .data.trampoline, "aw", @progbits
.align 4096

.global ap_trampoline_start
.global ap_trampoline_end
.global ap_startup_data

ap_trampoline_start:

# Real mode startup code (16-bit)
.code16
ap_rm_entry:
    # Intel SDM: APs start execution in real mode with CS:IP from SIPI vector
    # CRITICAL: Do NOT write to any memory locations until segments are properly set up
    # Writing to unmapped or invalid memory in real mode can cause system hangs

    # Intel SDM: Step 1 - Disable interrupts immediately
    cli

    # Intel SDM: Step 2 - Disable NMIs to prevent any interruption
    # This prevents NMIs from interrupting critical startup sequence
    mov $0x70, %dx
    in %dx, %al
    or $0x80, %al
    out %al, %dx

    # Add a delay loop to ensure BSP completes APIC write
    # and to avoid any potential race conditions
    mov $0x20000, %cx
1:  dec %cx
    jnz 1b

    # Intel SDM: Step 3 - Initialize segment registers to known values
    # Load data segment FIRST before any memory accesses
    xor %ax, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss        # Also clear SS
    mov %ax, %fs        # Clear FS
    mov %ax, %gs        # Clear GS

    # Debug markers at start of debug range (0x6FF0...)
    mov $0xDEAD, %ax
    mov %ax, 0x6FF0
    mov $0xBEEF, %ax
    mov %ax, 0x6FF2
    
    # CRITICAL: Ensure stores are globally visible
    # Use serializing instruction to flush store buffer
    xor %eax, %eax
    cpuid

    # Small delay before any memory writes to avoid conflicts
    mov $0x1000, %cx
3:  dec %cx
    jnz 3b

    # Debug writes to track real mode entry
    movl $0x12345678, 0x6000       # Magic
    movl (ap_cpu_id - ap_trampoline_start + 0x8000), %eax  # Load CPU ID from data section
    movl %eax, 0x6004              # CPU ID
    movb $1, 0x6008                # Stage = RealMode16
    movb $0, 0x6009                # Error = 0

    # Intel SDM: Step 4 - Load GDT before switching to protected mode
    # The GDTR is located at a fixed offset from trampoline start
    lgdt (ap_gdtr - ap_trampoline_start + 0x8000)

    # Intel SDM: Serialization after LGDT is recommended
    # Jump to next instruction to serialize
    jmp 1f
1:  nop

    # Debug marker after lgdt
    movw $0x1111, 0x6FF4
    
    # Intel SDM: Step 5 - Switch to protected mode
    # Set PE bit in CR0 to enable protected mode
    mov %cr0, %eax
    or $1, %eax         # CR0.PE = 1
    mov %eax, %cr0

    # Debug marker after enabling protected mode
    movw $0x2222, 0x6FF6

    # Intel SDM: Step 6 - Execute far jump to load CS with protected mode selector
    # This is REQUIRED to complete the transition to protected mode
    # CS = 0x08 (code segment), EIP = 32-bit entry relative to 0x8000
    ljmp $0x08, $(ap_pm_entry - ap_trampoline_start + 0x8000)

# Simple exception handler for 32-bit mode
.code32
ap_exception_handler:
    # Write exception marker
    movl $0xDEADBEEF, 0x6FF8
    # Halt
1:  hlt
    jmp 1b

# Protected mode code (32-bit)
.code32
.align 16
ap_pm_entry:
    # Debug marker for protected mode entry
    movl $0x3333, 0x6FFC

    # Setup segments - CRITICAL: Must be done first in protected mode
    mov $0x10, %ax      # Data segment selector
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    # CRITICAL: Load a minimal IDT to prevent triple fault
    # This prevents exceptions from causing a system hang
    lidt (ap_idtr - ap_trampoline_start + 0x8000)

    # Debug writes for protected mode stage
    movl $0x12345678, 0x6000       # Magic
    movl (ap_cpu_id - ap_trampoline_start + 0x8000), %eax  # Load CPU ID from data section
    movl %eax, 0x6004              # CPU ID
    movb $2, 0x6008                # Stage = ProtectedMode32
    movb $0, 0x6009                # Error = 0

    # Intel SDM: Step 1 - Enable PAE (CR4.PAE) BEFORE any other long mode setup
    mov %cr4, %eax
    or $0x20, %eax      # CR4.PAE = 1
    mov %eax, %cr4

    # Debug marker after PAE enabled
    movl $0x4444, 0x7000

    # Serializing instruction to ensure PAE is enabled
    xor %eax, %eax
    cpuid

    # Intel SDM: Step 2 - Load page table base into CR3
    # The BSP will write the PML4 address to ap_pml4_addr
    mov (ap_pml4_addr - ap_trampoline_start + 0x8000), %eax
    mov %eax, %cr3

    # Debug marker after CR3 loaded
    movl $0x5555, 0x7004

    # Intel SDM: Step 3 - Set long mode enable in EFER MSR
    # This MUST be done AFTER PAE is enabled and BEFORE paging is enabled
    mov $0xC0000080, %ecx
    rdmsr
    or $0x100, %eax     # EFER.LME = 1
    wrmsr

    # Debug marker after EFER.LME set
    movl $0x6666, 0x7008

    # Serializing instruction after WRMSR
    xor %eax, %eax
    cpuid

    # Intel SDM: Step 4 - Enable paging to activate long mode
    # This MUST be the last step - it activates long mode when CR0.PG=1
    mov %cr0, %eax
    or $0x80000000, %eax # CR0.PG = 1
    mov %eax, %cr0

    # Debug marker after paging enabled
    movl $0x7777, 0x700C

    # Far jump to 64-bit long mode
    # Use 64-bit code segment selector (0x18)
    ljmp $0x18, $(ap_lm_entry - ap_trampoline_start + 0x8000)

# Long mode code (64-bit)
.code64
.align 16
ap_lm_entry:
    # Load 64-bit data segment (0x20)
    mov $0x20, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    # Re-enable NMIs now that we're in a stable state
    # Clear bit 7 of CMOS address port
    mov $0x70, %dx
    in %dx, %al
    and $0x7F, %al
    out %al, %dx

    # Write debug info: LongMode64 stage (3)
    movl $0x12345678, 0x6000       # Magic
    movl (ap_cpu_id - ap_trampoline_start + 0x8000), %eax  # Load CPU ID from data section
    movl %eax, 0x6004              # CPU ID
    movb $3, 0x6008                # Stage = LongMode64
    movb $0, 0x6009                # Error = 0

    # Additional synchronization delay before accessing kernel resources
    # This gives BSP time to complete SIPI and release locks
    mov $0x200000, %rcx
2:  pause
    dec %rcx
    jnz 2b

    # Memory barrier to ensure all previous operations are visible
    mfence

    # Get CPU ID from startup data
    movl (ap_cpu_id - ap_trampoline_start + 0x8000), %edi  # Load CPU ID from data section

    # Load stack pointer for this CPU
    # Stack addresses are stored in an array starting at ap_stack_array
    mov %edi, %eax
    shl $3, %eax       # Multiply by 8 (size of pointer)
    lea (ap_stack_array - ap_trampoline_start + 0x8000), %rcx
    mov (%rcx,%rax), %rsp

    # Store stack pointer as debug value
    mov %rsp, 0x6010               # Debug value field

    # Clear base pointer
    xor %rbp, %rbp

    # Jump to kernel's AP entry point with CPU ID in RDI
    # The address is relocated and stored by BSP
    mov (ap_entry_point - ap_trampoline_start + 0x8000), %rax
    jmp *%rax

# Data section for trampoline
.align 16
ap_startup_data:

# GDT for bootstrap
.align 16
ap_gdt:
    .quad 0x0000000000000000  # Null descriptor
    .quad 0x00CF9A000000FFFF  # 32-bit code segment
    .quad 0x00CF92000000FFFF  # 32-bit data segment
    .quad 0x00AF9A000000FFFF  # 64-bit code segment (L=1, D=0)
    .quad 0x00AF92000000FFFF  # 64-bit data segment
ap_gdt_end:

# GDT pointer
.align 16
ap_gdtr:
    .word ap_gdt_end - ap_gdt - 1  # Limit
    .long 0  # Base will be patched by BSP at runtime

# Minimal IDT with simple exception handler
.align 16
ap_idt:
    # First 32 entries point to simple handler (exceptions)
    # The BSP will patch these with the correct offset
    .rept 32
    .word 0  # Offset 15:0 - will be patched by BSP
    .word 0x08                     # Code segment selector
    .byte 0                        # IST (not used in 32-bit)
    .byte 0x8E                     # Type: 32-bit interrupt gate, DPL=0, Present
    .word 0                        # Offset 31:16 - will be patched by BSP
    .endr
    # Remaining entries are null
    .fill 224, 8, 0
ap_idt_end:

# IDT pointer
.align 16
ap_idtr:
    .word ap_idt_end - ap_idt - 1  # Limit
    .long 0  # Base will be patched by BSP at runtime

# Variables populated by BSP
.align 8
ap_pml4_addr:
    .long 0                    # Physical address of PML4

.align 8
ap_entry_point:
    .quad 0                    # Kernel virtual address of AP entry

.align 4
ap_cpu_id:
    .long 0                    # CPU ID for the AP being started

.align 8
ap_stack_array:
    .fill 64, 8, 0            # Array of stack pointers (max 64 CPUs)

ap_trampoline_end:

# Export the size for the kernel
.global ap_trampoline_size
.set ap_trampoline_size, ap_trampoline_end - ap_trampoline_start