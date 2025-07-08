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
    # First thing: write a marker to show we're executing
    # Write 0xDEAD to address 0x9FE0 using direct addressing
    mov $0xDEAD, %ax
    mov %ax, 0x9FE0
    
    # Don't write to VGA memory - it may not be mapped and can cause issues
    # Just continue with initialization
    
    cli
    
    # Load data segment
    xor %ax, %ax
    mov %ax, %ds
    
    # Write another marker to show we got past segment setup
    # Write 0xBEEF to address 0x9FF0 to indicate real mode entry
    mov $0xBEEF, %ax
    mov %ax, 0x9FF0
    
    # Write debug info: RealMode16 stage (1)
    # Debug structure at 0x9000: magic(4), cpu_id(4), stage(1), error(1), pad(6), value(8)
    movl $0x12345678, 0x9000       # Magic
    movl (ap_cpu_id - ap_trampoline_start + 0x5000), %eax
    movl %eax, 0x9004              # CPU ID
    movb $1, 0x9008                # Stage = RealMode16
    movb $0, 0x9009                # Error = 0
    
    # Load GDT pointer using absolute addressing
    # GDT descriptor will be placed at 0x5000 + ap_gdtr offset
    lgdt (ap_gdtr - ap_trampoline_start + 0x5000)
    
    # Write marker to show we passed lgdt
    movw $0x1111, 0x9FFC
    
    # Enable protected mode
    mov %cr0, %eax
    or $1, %eax
    mov %eax, %cr0
    
    # Write marker to show we enabled protected mode
    movw $0x2222, 0x9FFA
    
    # Far jump to 32-bit protected mode
    # CS = 0x08 (code segment), EIP = 32-bit entry relative to 0x5000
    ljmp $0x08, $(ap_pm_entry - ap_trampoline_start + 0x5000)

# Protected mode code (32-bit)
.code32
.align 16
ap_pm_entry:
    # Write marker to show we reached 32-bit mode
    movl $0x3333, 0x9FF8
    
    # Setup segments
    mov $0x10, %ax      # Data segment selector
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    
    # Write debug info: ProtectedMode32 stage (2)
    movl $0x12345678, 0x9000       # Magic
    movl (ap_cpu_id - ap_trampoline_start + 0x5000), %eax
    movl %eax, 0x9004              # CPU ID
    movb $2, 0x9008                # Stage = ProtectedMode32
    movb $0, 0x9009                # Error = 0
    
    # Load page table base into CR3
    # The BSP will write the PML4 address to ap_pml4_addr
    mov (ap_pml4_addr - ap_trampoline_start + 0x5000), %eax
    mov %eax, %cr3
    
    # Enable PAE
    mov %cr4, %eax
    or $0x20, %eax      # CR4.PAE = 1
    mov %eax, %cr4
    
    # Set long mode enable in EFER MSR
    mov $0xC0000080, %ecx
    rdmsr
    or $0x100, %eax     # EFER.LME = 1
    wrmsr
    
    # Enable paging and enter long mode
    mov %cr0, %eax
    or $0x80000000, %eax # CR0.PG = 1
    mov %eax, %cr0
    
    # Far jump to 64-bit long mode
    # Use 64-bit code segment selector (0x18)
    ljmp $0x18, $(ap_lm_entry - ap_trampoline_start + 0x5000)

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
    
    # Write debug info: LongMode64 stage (3)
    movl $0x12345678, 0x9000       # Magic
    movl (ap_cpu_id - ap_trampoline_start + 0x5000), %eax
    movl %eax, 0x9004              # CPU ID
    movb $3, 0x9008                # Stage = LongMode64
    movb $0, 0x9009                # Error = 0
    
    # Get CPU ID from startup data
    movl (ap_cpu_id - ap_trampoline_start + 0x5000), %edi
    
    # Load stack pointer for this CPU
    # Stack addresses are stored in an array starting at ap_stack_array
    mov %edi, %eax
    shl $3, %eax       # Multiply by 8 (size of pointer)
    lea (ap_stack_array - ap_trampoline_start + 0x5000), %rbx
    mov (%rbx,%rax), %rsp
    
    # Store stack pointer as debug value
    mov %rsp, 0x9010               # Debug value field
    
    # Clear base pointer
    xor %rbp, %rbp
    
    # Jump to kernel's AP entry point with CPU ID in RDI
    # The address is relocated and stored by BSP
    mov (ap_entry_point - ap_trampoline_start + 0x5000), %rax
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
    .long ap_gdt - ap_trampoline_start + 0x5000  # Base (physical address)

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