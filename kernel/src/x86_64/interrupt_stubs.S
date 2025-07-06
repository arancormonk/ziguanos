// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

# Interrupt handler stubs for vectors 32-255
# These are for hardware interrupts and need to call handleInterrupt

.section .text

# Common interrupt handler that calls the new handleInterrupt function
interrupt_common:
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
    
    # Save all registers (15 registers = 120 bytes)
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

    # NOTE: Unlike exceptions, we don't save segment registers for interrupts
    # Stack layout after pushes:
    # RSP+0:   saved R15
    # ...
    # RSP+112: saved RAX 
    # RSP+120: interrupt number (pushed by stub)
    # RSP+128: error code (0, pushed by stub)
    # RSP+136: RIP (pushed by CPU)
    # RSP+144: CS (pushed by CPU)
    # RSP+152: RFLAGS (pushed by CPU)
    # RSP+160: RSP (pushed by CPU)
    # RSP+168: SS (pushed by CPU)
    
    # Apply speculation barrier after register saves
    lfence
    
    # Clear CPU buffers with VERW if coming from user mode
    testq $3, 144(%rsp)     # Check original CS
    jz 2f                   # Skip if was already in kernel mode
    # Execute VERW to clear CPU buffers
    subq $2, %rsp           # Make room for descriptor
    movw $0, (%rsp)         # Null descriptor
    verw (%rsp)             # Clear buffers
    addq $2, %rsp           # Clean up
2:
    
    # Set up parameters for handler
    movq 120(%rsp), %rdi    # Interrupt number
    movq 128(%rsp), %rsi    # Error code (always 0 for interrupts)
    leaq 136(%rsp), %rdx    # Address of interrupt frame (RIP is at offset 136)

    # Call C handler (handleInterrupt instead of handleException)
    call handleInterrupt

    # Restore registers
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

    # Remove error code and interrupt number
    addq $16, %rsp

    # Return from interrupt
    iretq

# Minimal test handler that just sends EOI
.global minimal_interrupt32
minimal_interrupt32:
    endbr64                 # CET: Mark as valid indirect branch target
    # Check if coming from user mode and swap GS if needed
    testq $3, 8(%rsp)       # Check CS (8 bytes up: RIP, CS)
    jz 1f                   # Skip if already in kernel mode
    swapgs
    lfence                  # Speculation barrier after swapgs
1:
    # Critical: Clear AC flag if SMAP is enabled
    clac
    # Memory barrier on entry
    mfence
    
    # Save only what we need
    pushq %rax
    pushq %rdx
    
    # Send EOI to APIC (use 64-bit addressing)
    movq $0xFEE000B0, %rdx
    movl $0, (%rdx)
    
    # Restore and return
    popq %rdx
    popq %rax
    
    # Check if returning to user mode
    testq $3, 8(%rsp)       # Check CS
    jz 2f
    # Call comprehensive MDS mitigation function
    call mitigateOnKernelExitAsm
    mfence                  # Memory barrier before swapgs
    swapgs
    lfence                  # Final speculation barrier
2:
    iretq

# Test handler that just increments a counter and returns
.global test_interrupt32
test_interrupt32:
    endbr64                 # CET: Mark as valid indirect branch target
    # Check if coming from user mode and swap GS if needed
    testq $3, 8(%rsp)       # Check CS (8 bytes up: RIP, CS)
    jz 1f                   # Skip if already in kernel mode
    swapgs
    lfence                  # Speculation barrier after swapgs
1:
    # Critical: Clear AC flag if SMAP is enabled
    clac
    # Memory barrier on entry
    mfence
    
    # Save registers we'll use
    pushq %rax
    pushq %rdx
    
    # Increment a test counter in memory (PIE-compatible with RIP-relative addressing)
    incq test_counter(%rip)
    
    # Send EOI to APIC (0xFEE000B0 = APIC EOI register)
    # Use proper 64-bit addressing
    movq $0xFEE000B0, %rdx
    movl $0, (%rdx)
    
    # Restore registers
    popq %rdx
    popq %rax
    
    # Check if returning to user mode
    testq $3, 8(%rsp)       # Check CS
    jz 2f
    # Call comprehensive MDS mitigation function
    call mitigateOnKernelExitAsm
    mfence                  # Memory barrier before swapgs
    swapgs
    lfence                  # Final speculation barrier
2:
    # Return from interrupt
    iretq

# Test counter
.section .data
.global test_counter
test_counter:
    .quad 0

.section .text

# Macro for interrupt stubs (no error code)
.macro INTERRUPT num
.global interrupt\num
interrupt\num:
    endbr64                 # CET: Mark as valid indirect branch target
    pushq $0                # Dummy error code
    pushq $\num             # Interrupt number
    jmp interrupt_common
.endm

# Generate interrupt stubs for vectors 32-255
# Timer interrupt (vector 32)
INTERRUPT 32

# Additional hardware interrupts (33-47 typically for legacy IRQs)
INTERRUPT 33
INTERRUPT 34
INTERRUPT 35
INTERRUPT 36
INTERRUPT 37
INTERRUPT 38
INTERRUPT 39
INTERRUPT 40
INTERRUPT 41
INTERRUPT 42
INTERRUPT 43
INTERRUPT 44
INTERRUPT 45
INTERRUPT 46
INTERRUPT 47

# User-defined interrupts (48-255)
# We'll generate a few common ones and the spurious interrupt vector
INTERRUPT 48
INTERRUPT 49
INTERRUPT 50

# ... (you can add more as needed)

# Spurious interrupt (vector 255)
INTERRUPT 255

# Export symbols for common interrupt vectors
.global interrupt32   # Timer
.global interrupt255  # Spurious