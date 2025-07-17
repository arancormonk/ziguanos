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

    # Debug markers at start of debug range (0x510...)
    mov $0xDEAD, %ax
    mov %ax, 0x510
    mov $0xBEEF, %ax
    mov %ax, 0x512

    # CRITICAL: Ensure stores are globally visible
    # Use serializing instruction to flush store buffer
    xor %eax, %eax
    cpuid

    # Small delay before any memory writes to avoid conflicts
    mov $0x1000, %cx
3:  dec %cx
    jnz 3b

    # Debug writes to track real mode entry
    movl $0x12345678, 0x500       # Magic
    movl (ap_cpu_id - ap_trampoline_start + 0x8000), %eax  # Load CPU ID from data section
    movl %eax, 0x504              # CPU ID
    movb $1, 0x508                # Stage = RealMode16
    movb $0, 0x509                # Error = 0

    # Intel SDM: Step 4 - Load GDT before switching to protected mode
    # The GDTR is located at a fixed offset from trampoline start
    lgdt (ap_gdtr - ap_trampoline_start + 0x8000)

    # Intel SDM: Serialization after LGDT is recommended
    # Jump to next instruction to serialize
    jmp 1f
1:  nop

    # Debug marker after lgdt
    movw $0x1111, 0x514

    # Intel SDM: Step 5 - Switch to protected mode
    # Set PE bit in CR0 to enable protected mode
    mov %cr0, %eax
    or $1, %eax         # CR0.PE = 1
    mov %eax, %cr0

    # Debug marker after enabling protected mode
    movw $0x2222, 0x516

    # Intel SDM: Step 6 - Execute far jump to load CS with protected mode selector
    # This is REQUIRED to complete the transition to protected mode
    # CS = 0x08 (code segment), EIP = 32-bit entry relative to 0x8000
    ljmp $0x08, $(ap_pm_entry - ap_trampoline_start + 0x8000)

# Simple exception handler for 32-bit mode
.code32
ap_exception_handler:
    # Write exception marker
    movl $0xDEADBEEF, 0x518
    # Halt
1:  hlt
    jmp 1b

# Protected mode code (32-bit)
.code32
.align 16
ap_pm_entry:
    # Debug marker for protected mode entry
    movl $0x3333, 0x51C

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
    movl $0x12345678, 0x500       # Magic
    movl (ap_cpu_id - ap_trampoline_start + 0x8000), %eax  # Load CPU ID from data section
    movl %eax, 0x504              # CPU ID
    movb $2, 0x508                # Stage = ProtectedMode32
    movb $0, 0x509                # Error = 0

    # Intel SDM: Step 1 - Enable PAE (CR4.PAE) BEFORE any other long mode setup
    mov %cr4, %eax
    or $0x20, %eax      # CR4.PAE = 1
    mov %eax, %cr4

    # Debug marker after PAE enabled
    movl $0x4444, 0x520

    # Serializing instruction to ensure PAE is enabled
    xor %eax, %eax
    cpuid

    # Intel SDM: Step 2 - Load page table base into CR3
    # The BSP will write the PML4 address to ap_pml4_addr
    # CRITICAL: Even though we're in 32-bit mode, ap_pml4_addr is 64-bit
    # We only need the lower 32 bits for CR3 in 32-bit mode
    movl (ap_pml4_addr - ap_trampoline_start + 0x8000), %eax
    mov %eax, %cr3

    # Debug marker after CR3 loaded
    movl $0x5555, 0x524

    # Intel SDM: Step 3 - Set long mode enable in EFER MSR
    # This MUST be done AFTER PAE is enabled and BEFORE paging is enabled
    mov $0xC0000080, %ecx
    rdmsr
    or $0x100, %eax     # EFER.LME = 1
    wrmsr

    # Debug marker after EFER.LME set
    movl $0x6666, 0x528

    # Serializing instruction after WRMSR
    xor %eax, %eax
    cpuid

    # Intel SDM: Step 4 - Enable paging to activate long mode
    # This MUST be the last step - it activates long mode when CR0.PG=1
    mov %cr0, %eax
    or $0x80000000, %eax # CR0.PG = 1
    mov %eax, %cr0

    # Debug marker after paging enabled
    movl $0x7777, 0x52C

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

    # Debug: Mark that we reached 64-bit mode entry
    movl $0x64646464, 0x530

    # Write debug info: LongMode64 stage (3)
    movl $0x12345678, 0x500       # Magic
    movl (ap_cpu_id - ap_trampoline_start + 0x8000), %eax  # Load CPU ID from data section
    movl %eax, 0x504              # CPU ID
    movb $3, 0x508                # Stage = LongMode64
    movb $0, 0x509                # Error = 0

    # Debug: Mark before delay
    movl $0xDE1A1111, 0x534

    # Removed delay loop to test if it's causing the hang

    # Memory barrier to ensure all previous operations are visible
    mfence

    # Debug: Mark after delay
    movl $0xDE1A2222, 0x538

    # Get CPU ID from startup data
    movl (ap_cpu_id - ap_trampoline_start + 0x8000), %edi  # Load CPU ID from data section

    # Debug: Mark after loading CPU ID
    movl $0xDE1A4444, 0x540

    # Debug: Write CPU ID to verify we loaded it correctly
    movl %edi, 0x544

    # Load stack pointer for this CPU
    # Stack addresses are stored in an array starting at ap_stack_array
    mov %edi, %eax
    shl $3, %eax       # Multiply by 8 (size of pointer)
    lea (ap_stack_array - ap_trampoline_start + 0x8000), %rcx

    # Debug: Write the array address
    movq %rcx, 0x548

    # Debug: Write the offset we're using
    movl %eax, 0x550

    # Load the stack pointer
    mov (%rcx,%rax), %rsp

    # Store stack pointer as debug value
    movq %rsp, 0x558               # Debug value field (8-byte aligned)

    # Debug: Mark that we loaded stack (must not overlap with stack pointer!)
    movl $0x8888, 0x560

    # Test if stack is valid (non-zero)
    test %rsp, %rsp
    jz stack_error

    # Clear base pointer
    xor %rbp, %rbp

    # Debug: Mark before loading kernel GDT
    movl $0xBBBB, 0x590

    # Debug: Read and verify the GDTR at 0x8F00 before loading
    movw 0x8F00, %ax      # Read limit (should be 0x17)
    movw %ax, 0x5A8
    movl 0x8F02, %eax     # Read base low 32 bits (should be 0x8E00)
    movl %eax, 0x5AC

    # Load transition GDT from fixed location
    # The BSP has created a minimal GDT at 0x8F00 with copies of kernel segments
    lgdt 0x8F00

    # Debug: Mark after lgdt
    movl $0xCCCC, 0x594

    # Use a temporary stack in low memory for the far jump
    # We'll switch to the real stack after we're in the kernel segments
    movq %rsp, %r15         # Save real RSP
    movq $0x7000, %rsp      # Use temporary stack at 0x7000

    # Perform far jump to reload CS with kernel code segment
    pushq $0x08         # Kernel code segment
    lea 1f(%rip), %rax
    pushq %rax

    # Debug: Mark before lretq
    movl $0xDDDD, 0x5A0

    lretq
1:
    # Debug: Mark after successful lretq
    movl $0xEEEE, 0x5A4

    # Now we're running with kernel code segment, reload data segments
    mov $0x10, %ax      # Kernel data segment
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    # Restore the real stack pointer now that segments are loaded
    movq %r15, %rsp

    # Load kernel IDT from fixed location
    # The BSP has written the kernel IDTR to 0x8F10
    lidt 0x8F10

    # Debug: Mark before loading entry point
    movl $0x9999, 0x564

    # Before jumping to the kernel, write a marker to show we made it this far
    movl $0xCAFEBABE, 0x5B0
    movl %edi, 0x5B4        # Write CPU ID

    # Jump to kernel's AP entry point with CPU ID in RDI
    # The address is relocated and stored by BSP
    movq (ap_entry_point - ap_trampoline_start + 0x8000), %rax

    # Debug: Write entry point address
    movq %rax, 0x568

    # Debug: Mark before jump
    movl $0xAAAA, 0x570

    # Test if entry point is valid (non-zero)
    test %rax, %rax
    jz entry_error

    # Debug: Mark that we're about to jump
    movl $0xDEAD0017, 0x574

    # Write a marker to show we're about to jump
    movl $0x4A4D5021, 0x580  # "JMP!"

    # Ensure interrupts are disabled before jump
    cli

    # Clear direction flag as per ABI
    cld

    # Test if we can read from the target address
    # Try to read the first byte of the target code
    movb (%rax), %bl
    movb %bl, 0x584       # Store what we read

    # If we got here, the address is readable
    movl $0x52454144, 0x588  # "READ"

    # Push dummy return address to satisfy C ABI
    # The Zig function expects stack as if it was called with 'call'
    # Use movq to push a full 64-bit value
    movq $0xDEADBEEF, %rbx
    pushq %rbx
    
    # Jump to kernel entry point
    jmp *%rax

halt:
    # This should never be reached
    movl $0xDEADBEEF, 0x58C
    hlt
    jmp halt

stack_error:
    # Write error marker for invalid stack
    movl $0xBAD57ACC, 0x5C0  # "BAD STACC" at different address (moved to avoid conflict)
    # Also write the bad stack value
    movq %rsp, 0x5C8
    hlt
    jmp stack_error

entry_error:
    # Write error marker for invalid entry point
    movl $0xBADC0DED, 0x5D0  # "BAD CODED" at different address (moved to avoid conflict)
    # Also write the bad entry point value
    movq %rax, 0x5D8
    hlt
    jmp entry_error

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
    .quad 0                    # Physical address of PML4 (changed to quad for 64-bit support)

.align 8
ap_entry_point:
    .quad 0                    # Kernel virtual address of AP entry

.align 4
ap_cpu_id:
    .long 0                    # CPU ID for the AP being started

.align 8
ap_stack_array:
    .fill 256, 8, 0           # Array of stack pointers (max 256 CPUs to match per_cpu.MAX_CPUS)

ap_trampoline_end:

# Export the size for the kernel
.global ap_trampoline_size
.set ap_trampoline_size, ap_trampoline_end - ap_trampoline_start