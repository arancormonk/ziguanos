// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

.section .text

# Exception handler stubs
.global exception0
.global exception1
.global exception2
.global exception3
.global exception4
.global exception5
.global exception6
.global exception7
.global exception8
.global exception9
.global exception10
.global exception11
.global exception12
.global exception13
.global exception14
.global exception16
.global exception17
.global exception18
.global exception19
.global exception20
.global exception21
.global exception30

# Macro for exceptions without error code
.macro EXCEPTION_NOERRCODE num
exception\num:
    endbr64                 # CET: Mark as valid indirect branch target
    pushq $0                # Dummy error code
    pushq $\num             # Exception number
    jmp exception_common
.endm

# Macro for exceptions with error code
.macro EXCEPTION_ERRCODE num
exception\num:
    endbr64                 # CET: Mark as valid indirect branch target
    pushq $\num             # Exception number
    jmp exception_common
.endm

EXCEPTION_NOERRCODE 0
EXCEPTION_NOERRCODE 1
EXCEPTION_NOERRCODE 2
EXCEPTION_NOERRCODE 3
EXCEPTION_NOERRCODE 4
EXCEPTION_NOERRCODE 5
EXCEPTION_NOERRCODE 6
EXCEPTION_NOERRCODE 7
EXCEPTION_ERRCODE 8
EXCEPTION_NOERRCODE 9
EXCEPTION_ERRCODE 10
EXCEPTION_ERRCODE 11
EXCEPTION_ERRCODE 12
EXCEPTION_ERRCODE 13
EXCEPTION_ERRCODE 14
EXCEPTION_NOERRCODE 16
EXCEPTION_ERRCODE 17
EXCEPTION_NOERRCODE 18
EXCEPTION_NOERRCODE 19
EXCEPTION_NOERRCODE 20
EXCEPTION_ERRCODE 21
EXCEPTION_ERRCODE 30

exception_common:
    endbr64                 # CET: Mark as valid indirect branch target
    # Check if coming from user mode and swap GS if needed
    testq $3, 24(%rsp)      # Check CS (24 bytes up: error, vector, RIP, CS)
    jz 1f                   # Skip if already in kernel mode
    swapgs
    # Speculation barrier after swapgs
    lfence
1:
    # Critical: Clear AC flag if SMAP is enabled
    # This prevents kernel from accessing user memory without proper stac/clac
    clac
    
    # Apply memory barrier on kernel entry
    mfence
    
    # Save all registers
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    
    # Save segment registers
    movw %ds, %ax
    pushq %rax
    movw %es, %ax
    pushq %rax
    movw %fs, %ax
    pushq %rax
    movw %gs, %ax
    pushq %rax
    
    # Load kernel data segments
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    xorw %ax, %ax
    movw %ax, %fs
    movw %ax, %gs
    
    # Apply speculation barrier after segment loads
    lfence
    
    # Clear CPU buffers with VERW if coming from user mode
    testq $3, 168(%rsp)     # Check original CS (adjusted for all pushes)
    jz 2f                   # Skip if was already in kernel mode
    # Execute VERW to clear CPU buffers
    subq $2, %rsp           # Make room for descriptor
    movw $0, (%rsp)         # Null descriptor
    verw (%rsp)             # Clear buffers
    addq $2, %rsp           # Clean up
2:

    # Set up parameters for handler
    movq 152(%rsp), %rdi    # Exception number (adjusted for saved segments)
    movq 160(%rsp), %rsi    # Error code
    movq %rsp, %rdx         # Stack pointer (full context)

    # Call enhanced C handler
    call handleExceptionEnhanced

    # Restore segment registers
    popq %rax
    movw %ax, %gs
    popq %rax
    movw %ax, %fs
    popq %rax
    movw %ax, %es
    popq %rax
    movw %ax, %ds
    
    # Restore registers (might return if recovered)
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    
    # Check if returning to user mode
    testq $3, 24(%rsp)      # Check CS
    jz 3f                   # Skip if staying in kernel mode
    
    # Call comprehensive MDS mitigation function
    # This handles all CPU buffer clearing based on vulnerability status
    call mitigateOnKernelExitAsm
    
    # Memory barrier before swapgs
    mfence
    
    # Swap GS back
    swapgs
    
    # Final speculation barrier
    lfence
3:

    # Remove error code and exception number
    addq $16, %rsp

    # Return from interrupt
    iretq