# Zig x86 Assembly Integration Guide for Ziguanos

## Executive Summary

This guide documents the x86 assembly patterns used in Ziguanos, a security-focused operating system written in Zig. The patterns demonstrate modern security practices including:

- **SWAPGS handling**: Proper kernel/user GS segment switching
- **Speculation barriers**: Intel-recommended mitigations against speculative execution attacks
- **IST support**: Interrupt Stack Table for critical exceptions
- **Stack protection**: CanaryGuard system with shadow stacks
- **I/O security**: Privilege checking and port allowlisting
- **SMAP support**: Supervisor Mode Access Prevention with clac/stac
- **CFI integration**: Control Flow Integrity for indirect calls

## Assembly File Patterns in Ziguanos

### Exception Handling with SWAPGS

Ziguanos uses separate assembly files for exception and interrupt stubs. The exception handler demonstrates proper SWAPGS handling:

```asm
# exception_stubs.S - Exception entry with SWAPGS handling
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
    # ... save all general purpose registers ...
    
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
    
    # Call C handler with proper parameters
    movq 152(%rsp), %rdi    # Exception number (adjusted for saved segments)
    movq 160(%rsp), %rsi    # Error code
    movq %rsp, %rdx         # Stack pointer (full context)
    call handleExceptionEnhanced
```

Key security features:

- **CET Support**: `endbr64` instruction marks valid indirect branch targets
- **SWAPGS Handling**: Only when transitioning from user mode (CPL check)
- **SMAP Protection**: `clac` instruction prevents kernel access to user memory
- **Speculation Barriers**: `lfence` after privilege transitions, `mfence` on entry
- **CPU Buffer Clearing**: VERW instruction for MDS/TAA mitigation
- **Full Context Preservation**: All GPRs and segment registers saved
- **Stack Layout Awareness**: Precise offset calculations for parameters

### Interrupt Handling Patterns

Interrupt handlers are simpler but follow similar patterns:

```asm
# interrupt_stubs.S - Hardware interrupt handling
interrupt_common:
    endbr64                 # CET: Mark as valid indirect branch target
    # Check if coming from user mode and swap GS if needed
    testq $3, 24(%rsp)      # Check CS (24 bytes up: error, vector, RIP, CS)
    jz 1f                   # Skip if already in kernel mode
    swapgs
    # Speculation barrier after swapgs
    lfence
1:
    
    # Apply memory barrier on kernel entry
    mfence
    
    # Save all registers (no segment registers for interrupts)
    pushq %rax
    pushq %rbx
    # ... save registers ...
    
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
    movq 128(%rsp), %rsi    # Error code (always 0)
    leaq 136(%rsp), %rdx    # Address of interrupt frame
    
    # Call C handler
    call handleInterrupt
    
    # Restore and return
    # ... restore registers ...
    addq $16, %rsp          # Remove error code and interrupt number
    iretq
```

## Inline Assembly Patterns in Ziguanos

### I/O Port Operations with Security

Ziguanos implements secure I/O operations with privilege checking and speculation barriers:

```zig
// io_security.zig - Secure I/O port access
const cfi = @import("cfi.zig");  // Control Flow Integrity module

pub fn outb(port: u16, value: u8) void {
    // Check permissions first (fail fast)
    checkIOPermission(port);
    
    // Memory barrier to ensure all prior memory operations complete
    speculation.memoryFence();
    
    // Log the access if security is enabled
    if (security_phase == .Enabled and logging_enabled) {
        logIOAccess(port, value, true);
    }
    
    // Perform the I/O operation
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "N{dx}" (port),
        : "memory" // Intel recommendation: memory clobber for I/O
    );
    
    // Post-operation barrier for ordering
    speculation.storeFence();
}

pub fn inb(port: u16) u8 {
    // Check permissions first
    checkIOPermission(port);
    
    // Pre-operation barrier
    speculation.loadFence();
    
    const value = asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
        : "memory"
    );
    
    // Post-operation barrier to prevent speculative use
    speculation.speculationBarrier();
    
    return value;
}
```

### CPU Control Register Access

```zig
// Reading control registers
fn getCurrentPrivilegeLevel() u2 {
    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );
    return @truncate(cs & 0x3);
}

// CR0 manipulation
var cr0 = asm volatile ("mov %%cr0, %[result]"
    : [result] "=r" (-> u64),
);
cr0 |= CR0_NE; // Enable native FPU error reporting
asm volatile ("mov %[value], %%cr0"
    :
    : [value] "r" (cr0),
    : "memory"
);

// CR4 security features
var cr4 = asm volatile ("mov %%cr4, %[result]"
    : [result] "=r" (-> u64),
);
cr4 |= CR4_UMIP | CR4_FSGSBASE | CR4_CET;
asm volatile ("mov %[value], %%cr4"
    :
    : [value] "r" (cr4),
    : "memory"
);
```

### MSR Operations

```zig
// Read MSR
fn readMSR(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, high) << 32) | low;
}

// Write MSR
fn writeMSR(msr: u32, value: u64) void {
    const low = @as(u32, @truncate(value));
    const high = @as(u32, @truncate(value >> 32));
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (low),
          [high] "{edx}" (high),
    );
}
```

### Time Stamp Counter and Timing

```zig
// Read TSC for timing
fn readTSC() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdtsc"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
    );
    return (@as(u64, high) << 32) | low;
}

// Calibrated delay using TSC
fn delayMicroseconds(us: u64) void {
    if (tsc_frequency == 0) {
        // Fallback to simple loop if TSC not calibrated
        var i: u64 = 0;
        while (i < us * 10) : (i += 1) {
            asm volatile ("pause");
        }
        return;
    }
    
    const start = readTSC();
    const ticks_to_wait = (us * tsc_frequency) / 1_000_000;
    
    while ((readTSC() - start) < ticks_to_wait) {
        asm volatile ("pause"); // CPU hint for spin-wait loops
    }
}
```

### Hardware Random Number Generation

```zig
// RDRAND with retry logic
fn rdrand64() ?u64 {
    var retries: u32 = 0;
    while (retries < MAX_RETRIES) : (retries += 1) {
        var result: u64 = undefined;
        var success: u8 = undefined;
        
        asm volatile (
            \\rdrand %[result]
            \\setc %[success]
            : [result] "=r" (result),
              [success] "=r" (success),
        );
        
        if (success != 0) return result;
        asm volatile ("pause" ::: "memory");
    }
    return null;
}

// RDSEED for true entropy
fn rdseed64() ?u64 {
    var retries: u32 = 0;
    while (retries < MAX_RETRIES) : (retries += 1) {
        var result: u64 = undefined;
        var success: u8 = undefined;
        
        asm volatile (
            \\rdseed %[result]
            \\setc %[success]
            : [result] "=r" (result),
              [success] "=r" (success),
        );
        
        if (success != 0) return result;
        asm volatile ("pause" ::: "memory");
    }
    return null;
}
```

### GDT and IDT Management

```zig
// Load GDT
asm volatile ("lgdt %[ptr]"
    :
    : [ptr] "*p" (&gdt_ptr),
    : "memory"
);

// Load IDT
asm volatile ("lidt %[ptr]"
    :
    : [ptr] "*p" (&idt_ptr),
    : "memory"
);

// Load Task State Segment
asm volatile ("ltr %[sel]"
    :
    : [sel] "r" (TSS_SELECTOR),
);

// Reload segments after GDT change
asm volatile (
    \\mov $0x10, %%ax
    \\mov %%ax, %%ds
    \\mov %%ax, %%es
    \\mov %%ax, %%ss
    \\xor %%ax, %%ax
    \\mov %%ax, %%fs
    \\mov %%ax, %%gs
    ::: "rax", "memory"
);
```

### Virtual Memory Management

```zig
// TLB invalidation
asm volatile ("invlpg (%[addr])"
    :
    : [addr] "r" (virt_addr),
    : "memory"
);

// Read CR3 (page table base)
const cr3 = asm volatile ("mov %%cr3, %[result]"
    : [result] "=r" (-> u64),
);

// XSAVE/XRSTOR for extended state
fn xsaveState(save_area: *align(64) XSaveArea) void {
    const feature_mask: u64 = 0x7; // x87, SSE, AVX
    const edx: u32 = @truncate(feature_mask >> 32);
    const eax: u32 = @truncate(feature_mask);
    
    asm volatile ("xsave %[area]"
        :
        : [area] "m" (save_area.*),
          [eax] "{eax}" (eax),
          [edx] "{edx}" (edx),
        : "memory"
    );
}
```

### PIE/PIC Assembly Entry Point

For Position Independent Code support with KASLR:

```asm
# entry.S - PIE-compatible kernel entry
.global _start
.global _zig_start
.global boot_info_ptr

.section .text._start, "ax", @progbits
_start:
    # Disable interrupts
    cli
    
    # Save boot info pointer using RIP-relative addressing
    # This is compatible with PIE/PIC
    movq %rdi, boot_info_ptr(%rip)
    
    # Call the Zig entry point
    jmp _zig_start

.section .data
.align 8
boot_info_ptr:
    .quad 0
```

Key PIE/PIC considerations:
- Use RIP-relative addressing for data access
- Avoid absolute addresses in assembly
- Let the linker handle relocations

## Security-Focused Assembly Patterns

### Stack Protection with CanaryGuard

Ziguanos implements a shadow stack-based canary system:

```zig
// Stack canary generation using TSC entropy
fn generateCanary() u64 {
    var eax: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("rdtsc"
        : [_] "={eax}" (eax),
          [_] "={edx}" (edx),
    );
    
    const tsc = (@as(u64, edx) << 32) | eax;
    return tsc ^ 0xDEADBEEFCAFEBABE;
}

// Usage pattern with defer
pub fn vulnerableFunction() void {
    var guard = stack_security.protect();
    defer guard.deinit(); // Automatic cleanup
    
    // Function implementation
}
```

### Speculation Barriers

Following Intel's recommendations for speculative execution mitigations:

```zig
// speculation.zig - Barrier implementations
pub inline fn speculationBarrier() void {
    asm volatile ("lfence" ::: "memory");
}

pub inline fn memoryFence() void {
    asm volatile ("mfence" ::: "memory");
}

pub inline fn storeFence() void {
    asm volatile ("sfence" ::: "memory");
}

pub inline fn loadFence() void {
    asm volatile ("lfence" ::: "memory");
}

// Usage in security-critical paths
fn checkIOPermission(port: u16) void {
    const cpl = getCurrentPrivilegeLevel();
    
    // Speculation barrier before privilege check
    speculation.speculationBarrier();
    
    const allowed = isPortAllowed(port);
    
    // Double barrier for critical security decision
    speculation.speculationBarrier();
    
    if (cpl > 0 and !allowed) {
        handleSecurityViolation(port, cpl);
    }
}
```

## Build System Integration

### Ziguanos Build Configuration

```zig
// build.zig - Kernel with assembly files
const kernel = b.addExecutable(.{
    .name = "kernel.elf",
    .root_source_file = b.path("kernel/src/main.zig"),
    .target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
    }),
    .optimize = .ReleaseFast,
    .code_model = .kernel,
    .pic = true, // Position Independent Code for KASLR
});

// Add assembly stubs
kernel.addAssemblyFile(b.path("kernel/src/x86_64/exception_stubs.S"));
kernel.addAssemblyFile(b.path("kernel/src/x86_64/interrupt_stubs.S"));

// Disable incompatible features
kernel.root_module.red_zone = false;
kernel.root_module.stack_check = false;
kernel.root_module.stack_protector = false;

// Keep frame pointer for debugging
kernel.root_module.omit_frame_pointer = false;

// Linker script
kernel.setLinkerScript(b.path("kernel/kernel.ld"));
```

### Assembly File Integration Pattern

When adding assembly files to a Zig project:

1. **Use AT&T syntax** (GNU assembler default)
2. **Declare global symbols** for Zig to access
3. **Follow calling conventions** (System V AMD64 ABI)
4. **Preserve callee-saved registers**
5. **Add CET markers** (`endbr64`) for indirect branch targets
6. **Use PIE-compatible addressing** (RIP-relative) for KASLR support

Example assembly stub pattern:

```asm
.section .text
.global my_function

# Macro for common patterns
.macro SAVE_CONTEXT
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
.endm

.macro RESTORE_CONTEXT
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
.endm

my_function:
    SAVE_CONTEXT
    # Function implementation
    RESTORE_CONTEXT
    ret
```

## IST (Interrupt Stack Table) Support

Ziguanos implements full IST support for critical exceptions:

```zig
// IST stack allocation and setup
pub const IST_STACKS = 7;
pub const IST_STACK_SIZE = 16 * 1024; // 16KB per IST stack

// Critical exceptions that use IST
pub const IST_EXCEPTIONS = [_]struct { vector: u8, ist: u8 }{
    .{ .vector = 1, .ist = 1 },   // Debug
    .{ .vector = 2, .ist = 2 },   // NMI
    .{ .vector = 3, .ist = 3 },   // Breakpoint
    .{ .vector = 8, .ist = 4 },   // Double Fault
    .{ .vector = 18, .ist = 5 },  // Machine Check
    .{ .vector = 12, .ist = 6 },  // Stack Fault
    .{ .vector = 13, .ist = 7 },  // General Protection
};

// Two-phase initialization pattern
pub fn earlyInitIST() void {
    // Phase 1: Use static stacks during early boot
    const static_stacks = &[_][]const u8{
        &static_ist1_stack,
        &static_ist2_stack,
        // ... etc
    };
    
    for (static_stacks, 0..) |stack, i| {
        const stack_top = @intFromPtr(stack.ptr) + stack.len;
        gdt.tss.ist[i] = stack_top;
    }
}

pub fn lateInitIST(allocator: *pmm.PhysicalMemoryManager) !void {
    // Phase 2: Allocate proper stacks with guard pages
    for (0..IST_STACKS) |i| {
        // Allocate guard page + stack + guard page
        const total_size = PAGE_SIZE + IST_STACK_SIZE + PAGE_SIZE;
        const region = try allocator.allocAligned(total_size, PAGE_SIZE);
        
        // Mark guard pages as non-present
        const guard1 = region;
        const stack = region + PAGE_SIZE;
        const guard2 = region + PAGE_SIZE + IST_STACK_SIZE;
        
        try vmm.unmapPage(guard1);
        try vmm.unmapPage(guard2);
        
        // Update TSS with new stack
        gdt.tss.ist[i] = stack + IST_STACK_SIZE;
    }
}
```

## Advanced Security Features

### Control Flow Integrity (CFI)

Ziguanos implements software-based CFI for forward-edge protection:

```zig
// CFI validation before indirect calls
if (cfi.validateIndirectCall(@intFromPtr(handler), .IO_VIOLATION_HANDLER)) {
    handler(port, cpl);
} else {
    serial.println("[IO_SEC] CFI violation: Invalid handler", .{});
}
```

### SMAP (Supervisor Mode Access Prevention)

When SMAP is enabled, the kernel must explicitly allow access to user memory:

```asm
# In exception handlers
clac    # Clear AC flag - prevent kernel access to user memory

# When intentionally accessing user memory
stac    # Set AC flag - allow access
# ... access user memory ...
clac    # Clear AC flag - restore protection
```

### APIC Timer with Security

```zig
// Secure APIC access pattern
fn writeAPICRegister(offset: u32, value: u32) void {
    const addr = APIC_BASE + offset;
    const ptr: *volatile u32 = @ptrFromInt(addr);
    
    // Memory barrier before write
    speculation.memoryFence();
    
    ptr.* = value;
    
    // Ensure write completes
    speculation.storeFence();
}

// Timer interrupt handler with security checks
export fn timerInterruptHandler() callconv(.C) void {
    // Verify we're in kernel mode
    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );
    if ((cs & 3) != 0) {
        @panic("Timer interrupt from userspace!");
    }
    
    // Handle timer tick
    timer_ticks +%= 1;
    
    // Send EOI to APIC
    writeAPICRegister(APIC_EOI, 0);
}
```

### PIT Timer Operations

```zig
// Secure PIT programming
fn configurePIT(divisor: u16) void {
    // Disable interrupts during configuration
    const flags = asm volatile (
        \\pushfq
        \\pop %[result]
        \\cli
        : [result] "=r" (-> u64),
    );
    defer asm volatile (
        \\push %[flags]
        \\popfq
        :
        : [flags] "r" (flags),
    );
    
    // Program PIT
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x36)), // Channel 0, mode 3
          [port] "N{dx}" (@as(u16, 0x43)),
        : "memory"
    );
    
    // Send divisor
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, @truncate(divisor & 0xFF))),
          [port] "N{dx}" (@as(u16, 0x40)),
        : "memory"
    );
    
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, @truncate(divisor >> 8))),
          [port] "N{dx}" (@as(u16, 0x40)),
        : "memory"
    );
}
```

## Best Practices and Patterns

### Assembly Constraint Specifiers

Ziguanos uses specific constraint patterns for different use cases:

```zig
// Fixed register constraints
"{al}"   // AL register for 8-bit I/O
"{ax}"   // AX register for 16-bit I/O
"{eax}"  // EAX for 32-bit operations
"{rax}"  // RAX for 64-bit operations
"{ecx}"  // ECX for loop counters, MSR index
"{edx}"  // EDX for I/O port addressing

// Output constraints
"=r"     // Any general purpose register
"={al}"  // Specific register output
"=m"     // Memory operand

// Input/output constraints
"+r"     // Read-modify-write register
"+m"     // Read-modify-write memory

// Special constraints
"N{dx}"  // Immediate port number (0-255) or DX register
"*p"     // Memory pointer operand
"memory" // Memory clobber for barriers
```

### Security Considerations

1. **Always use speculation barriers** after privilege checks
2. **Validate CPL** before sensitive operations
3. **Use memory barriers** around I/O operations
4. **Implement stack canaries** for functions handling external data
5. **Enable security features** (UMIP, CET, PKU) when available

### Common Pitfalls

1. **Missing SWAPGS**: Always check privilege level before SWAPGS
2. **Incorrect stack offsets**: Account for all pushed values when calculating offsets
3. **Missing memory clobbers**: Add "memory" clobber for operations that affect memory
4. **Speculation vulnerabilities**: Use barriers to prevent speculative execution attacks
5. **I/O timing**: Use appropriate barriers for I/O ordering
6. **CET compatibility**: Add `endbr64` to all indirect branch targets
7. **PIE/PIC violations**: Avoid absolute addresses; use RIP-relative addressing
8. **VERW timing**: Execute VERW before returning to user mode, not after
9. **SMAP violations**: Forgetting `clac` in exception handlers can leave kernel vulnerable
10. **CFI checks**: Always validate function pointers before indirect calls

### Assembly Macro Best Practices

```asm
# Use meaningful macro names
.macro SPECULATION_BARRIER
    lfence
.endm

# Document stack layout changes
.macro SAVE_ALL_REGS
    # Saves 15 general purpose registers (120 bytes)
    pushq %rax
    pushq %rbx
    # ... etc
.endm

# Use local labels (1f, 1b) for jumps within macros
.macro CHECK_USER_MODE
    testq $3, 24(%rsp)
    jz 1f
    swapgs
1:
.endm
```

## Debugging Assembly in Ziguanos

### Serial Output for Debugging

```zig
// Early boot serial output (before full driver init)
fn debugChar(c: u8) void {
    // Wait for transmit ready
    while ((asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (@as(u16, 0x3FD)),
    ) & 0x20) == 0) {
        asm volatile ("pause");
    }
    
    // Send character
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (c),
          [port] "N{dx}" (@as(u16, 0x3F8)),
    );
}
```

### Exception Debugging

```zig
// Print register state on exception
fn dumpRegisters(frame: *const InterruptFrame) void {
    serial.print("RIP: 0x{x:0>16}\n", .{frame.rip});
    serial.print("RSP: 0x{x:0>16}\n", .{frame.rsp});
    serial.print("RFL: 0x{x:0>16}\n", .{frame.rflags});
    serial.print("CS:  0x{x:0>4}\n", .{frame.cs});
    serial.print("SS:  0x{x:0>4}\n", .{frame.ss});
}
```

## Integration with Ziguanos Tools

### Using the Test Infrastructure

```bash
# Build and test with secure boot verification
zig build test    # Run in QEMU (headless)

# Check logs for assembly-related issues
cat serial.log    # Kernel debug output
cat qemu.log      # QEMU diagnostics
```

### Performance Monitoring

```zig
// TSC-based performance measurement
fn measureFunction() void {
    const start = readTSC();
    
    // Function to measure
    someExpensiveOperation();
    
    const elapsed = readTSC() - start;
    serial.print("Cycles: {}\n", .{elapsed});
}
```

## Zig 0.14.1 Inline Assembly Syntax Notes

### Key Syntax Elements

1. **Multi-line Assembly**: Use `\\` for line breaks in assembly strings
2. **Constraint Specifiers**:
   - Output: `"=r"` (any register), `"={reg}"` (specific register)
   - Input: `"r"` (any register), `"{reg}"` (specific register)
   - Memory: `"m"` for memory operands
   - Clobbers: List modified registers/flags after third colon

3. **Return Values**: Use `-> Type` syntax for assembly that returns values:
   ```zig
   const value = asm volatile ("instruction"
       : [result] "=r" (-> u64),
   );
   ```
   
   Note: The named output syntax `[name] "=constraint" (-> Type)` is used when the assembly block returns a value directly, not when assigning to an existing variable.

4. **Volatility**: Always use `asm volatile` for side effects or precise timing

### Security-Critical Patterns

1. **Always use AT&T syntax** (source, destination order)
2. **Add speculation barriers** at security boundaries
3. **Include memory clobbers** for barrier instructions
4. **Use proper constraints** to prevent compiler optimizations
5. **Validate CPUID features** before using advanced instructions

## Summary

This guide reflects the actual assembly patterns used in Ziguanos with Zig 0.14.1, emphasizing:

1. **Security-first design** with speculation barriers and privilege checks
2. **Modern x86-64 features** including SWAPGS, IST, CET, SMAP, and advanced CPU capabilities
3. **Clean integration** between Zig and assembly code
4. **PIE/PIC compatibility** for KASLR support
5. **Comprehensive CPU buffer clearing** with VERW for MDS/TAA mitigation
6. **Control Flow Integrity** for protecting indirect calls
7. **Supervisor Mode Access Prevention** for kernel/user memory isolation
8. **Practical patterns** tested in a real operating system

The patterns shown are production-ready and demonstrate best practices for secure, efficient kernel development with Zig 0.14.1.
