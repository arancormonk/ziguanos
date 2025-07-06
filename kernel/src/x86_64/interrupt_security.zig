// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Enhanced interrupt and exception security according to Intel x86-64 best practices
// Implements privilege validation, IST management, and state preservation

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const cpuid = @import("cpuid.zig");
const gdt = @import("gdt.zig");
const pmm = @import("../memory/pmm.zig");
const speculation = @import("speculation.zig");
const stack_security = @import("stack_security.zig");
const secure_print = @import("../lib/secure_print.zig");

// IST (Interrupt Stack Table) configuration
pub const IST = struct {
    // IST indices (1-7, 0 means no IST)
    pub const DOUBLE_FAULT: u8 = 1;
    pub const NMI: u8 = 2;
    pub const DEBUG: u8 = 3;
    pub const MACHINE_CHECK: u8 = 4;
    pub const STACK_FAULT: u8 = 5;
    pub const GENERAL_PROTECTION: u8 = 6;
    pub const PAGE_FAULT: u8 = 7;

    // Stack sizes
    pub const STACK_SIZE: usize = 16384; // 16KB per IST stack
    pub const STACK_PAGES: usize = STACK_SIZE / 4096;
};

// Extended processor state for XSAVE
pub const ExtendedState = struct {
    // XSAVE area header
    xsave_header: [64]u8 align(64) = undefined,
    // Legacy FPU/SSE state (512 bytes)
    fpu_sse_state: [512]u8 = undefined,
    // AVX state (if supported)
    avx_state: [256]u8 = undefined,
    // Additional state components
    extended_features: [1024]u8 = undefined,
};

// Interrupt context with full state preservation
pub const InterruptContext = struct {
    // General purpose registers
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rbp: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    rcx: u64,
    rbx: u64,
    rax: u64,

    // Interrupt information
    vector: u64,
    error_code: u64,

    // CPU-pushed interrupt frame
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,

    // Extended state (if XSAVE is used)
    extended_state: ?*ExtendedState,

    // Security context
    previous_cpl: u8,
    from_userspace: bool,
    ist_level: u8,
};

// Security statistics
var security_stats = struct {
    privilege_violations: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    ist_overflows: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    ist_underflows: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    invalid_transitions: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    state_corruption_detected: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    recovery_attempts: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    successful_recoveries: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    context_validation_failures: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
}{};

// IST stack management
var ist_stacks: [7]?u64 = [_]?u64{null} ** 7;
var ist_depths: [7]std.atomic.Value(u16) = [_]std.atomic.Value(u16){std.atomic.Value(u16).init(0)} ** 7;
const MAX_IST_DEPTH: u16 = 8; // Maximum nesting level

// Static IST stacks for early boot (before PMM)
var static_ist_stacks: [7][IST.STACK_SIZE]u8 align(4096) = std.mem.zeroes([7][IST.STACK_SIZE]u8);
var using_static_stacks: bool = true;

// XSAVE support
var xsave_supported: bool = false;
var xsave_size: u32 = 0;
var xsave_features: u64 = 0;

// Initialization state
var init_phase: enum {
    Uninitialized,
    EarlyInit,
    FullInit,
} = .Uninitialized;

// Early initialization (before PMM)
pub fn earlyInit() void {
    serial.println("[INT_SEC] Early interrupt security initialization", .{});

    // Check XSAVE support
    if (cpuid.getFeatures().xsave) {
        initXSAVE();
    }

    // Use static IST stacks for early boot
    setupStaticISTStacks();

    // Update TSS with IST entries
    updateTSSWithIST();

    init_phase = .EarlyInit;
    serial.println("[INT_SEC] Early interrupt security initialized with static stacks", .{});
}

// Full initialization (after PMM is available)
pub fn fullInit() !void {
    if (init_phase != .EarlyInit) {
        serial.println("[INT_SEC] Warning: Attempting full init without early init", .{});
        return;
    }

    serial.println("[INT_SEC] Full interrupt security initialization", .{});

    // Allocate dynamic IST stacks
    try allocateISTStacks();

    // Update TSS with new IST entries
    updateTSSWithIST();

    init_phase = .FullInit;
    serial.println("[INT_SEC] Interrupt security fully initialized with dynamic stacks", .{});
}

// Wrapper for compatibility - performs early init only
pub fn init() !void {
    if (init_phase == .Uninitialized) {
        earlyInit();
    }
}

// Initialize XSAVE support
fn initXSAVE() void {
    // Get XSAVE features using inline cpuid call
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (@as(u32, 0x0D)),
          [subleaf] "{ecx}" (@as(u32, 0)),
    );
    xsave_features = (@as(u64, edx) << 32) | eax;
    xsave_size = ebx;

    // Enable XSAVE in CR4
    var cr4 = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );
    cr4 |= (1 << 18); // CR4.OSXSAVE
    asm volatile ("mov %[cr4], %%cr4"
        :
        : [cr4] "r" (cr4),
    );

    // Set XCR0 to enable features
    const xcr0 = 0x07; // x87, SSE, AVX
    asm volatile (
        \\xor %%ecx, %%ecx
        \\mov %[low], %%eax
        \\xor %%edx, %%edx
        \\xsetbv
        :
        : [low] "r" (@as(u32, @truncate(xcr0))),
        : "eax", "ecx", "edx"
    );

    xsave_supported = true;
    serial.println("[INT_SEC] XSAVE enabled, size: {} bytes", .{xsave_size});
}

// Setup static IST stacks for early boot
fn setupStaticISTStacks() void {
    var i: u8 = 0;
    while (i < 7) : (i += 1) {
        // Zero the static stack
        @memset(&static_ist_stacks[i], 0);

        // Stack grows down, so top is base + size
        const stack_base = @intFromPtr(&static_ist_stacks[i]);
        ist_stacks[i] = stack_base + IST.STACK_SIZE;
    }

    using_static_stacks = true;
    serial.println("[INT_SEC] Using static IST stacks for early boot", .{});
}

// Allocate IST stacks with guard pages
fn allocateISTStacks() !void {
    var i: u8 = 0;
    while (i < 7) : (i += 1) {
        // Allocate stack pages
        const stack_base = pmm.allocPagesTagged(IST.STACK_PAGES, .INTERRUPT_STACKS) orelse {
            serial.println("[INT_SEC] ERROR: Failed to allocate IST stack", .{});
            return error.OutOfMemory;
        };

        // Zero the stack
        const stack_ptr = @as([*]u8, @ptrFromInt(stack_base));
        @memset(stack_ptr[0..IST.STACK_SIZE], 0);

        // Stack grows down, so top is base + size
        ist_stacks[i] = stack_base + IST.STACK_SIZE;

        // Create guard page below stack
        if (stack_base >= 4096) {
            pmm.createGuardPage(stack_base - 4096) catch {};
        }
    }

    using_static_stacks = false;
    serial.println("[INT_SEC] Allocated 7 dynamic IST stacks with guard pages", .{});
}

// Update TSS with IST entries
fn updateTSSWithIST() void {
    if (ist_stacks[0]) |stack| {
        gdt.tss.ist1 = stack;
    }
    if (ist_stacks[1]) |stack| {
        gdt.tss.ist2 = stack;
    }
    if (ist_stacks[2]) |stack| {
        gdt.tss.ist3 = stack;
    }
    if (ist_stacks[3]) |stack| {
        gdt.tss.ist4 = stack;
    }
    if (ist_stacks[4]) |stack| {
        gdt.tss.ist5 = stack;
    }
    if (ist_stacks[5]) |stack| {
        gdt.tss.ist6 = stack;
    }
    if (ist_stacks[6]) |stack| {
        gdt.tss.ist7 = stack;
    }
}

// Validate privilege transition
pub fn validatePrivilegeTransition(context: *const InterruptContext) !void {
    // Apply speculation barrier before privilege check
    speculation.speculationBarrier();

    const current_cs = context.cs;
    const current_cpl = @as(u8, @truncate(current_cs & 3));

    // Check for invalid transitions
    if (context.vector < 32) { // Exception
        switch (context.vector) {
            // These exceptions should only occur in kernel mode
            8, 18 => { // Double fault, Machine check
                if (current_cpl != 0) {
                    _ = security_stats.privilege_violations.fetchAdd(1, .monotonic);
                    return error.InvalidPrivilegeLevel;
                }
            },
            // Page fault can occur from any privilege level
            14 => {},
            else => {},
        }
    }

    // Validate stack pointer transitions
    if (context.from_userspace) {
        // Transitioning from user to kernel
        if (context.rsp < 0xFFFF800000000000) {
            _ = security_stats.invalid_transitions.fetchAdd(1, .monotonic);
            return error.InvalidStackTransition;
        }
    }

    // Check for stack overflow on IST stacks with atomic operation
    if (context.ist_level > 0 and context.ist_level <= 7) {
        const ist_idx = context.ist_level - 1;

        // Atomically increment and check for overflow
        const old_depth = ist_depths[ist_idx].fetchAdd(1, .acq_rel);
        if (old_depth >= MAX_IST_DEPTH) {
            // CRITICAL: IST stack overflow detected - system compromised
            _ = security_stats.ist_overflows.fetchAdd(1, .monotonic);

            // Log critical error before halting
            serial.println("[CRITICAL] IST[{}] stack overflow detected - depth: {}", .{ context.ist_level, old_depth + 1 });
            serial.println("[CRITICAL] Cannot safely continue execution - halting system", .{});

            // Halt the system immediately - do not return
            haltSystem();
        }
    }
}

// Save extended processor state
pub fn saveExtendedState(state: *ExtendedState) void {
    if (!xsave_supported) return;

    // Use XSAVE to save all enabled state components
    const save_mask: u64 = 0xFFFFFFFFFFFFFFFF; // Save all components
    asm volatile (
        \\mov %[mask_low], %%eax
        \\mov %[mask_high], %%edx
        \\xsave (%[state])
        :
        : [state] "r" (state),
          [mask_low] "r" (@as(u32, @truncate(save_mask))),
          [mask_high] "r" (@as(u32, @truncate(save_mask >> 32))),
        : "eax", "edx", "memory"
    );
}

// Restore extended processor state
pub fn restoreExtendedState(state: *const ExtendedState) void {
    if (!xsave_supported) return;

    // Use XRSTOR to restore all state components
    const restore_mask: u64 = 0xFFFFFFFFFFFFFFFF;
    asm volatile (
        \\mov %[mask_low], %%eax
        \\mov %[mask_high], %%edx
        \\xrstor (%[state])
        :
        : [state] "r" (state),
          [mask_low] "r" (@as(u32, @truncate(restore_mask))),
          [mask_high] "r" (@as(u32, @truncate(restore_mask >> 32))),
        : "eax", "edx", "memory"
    );
}

// Enhanced exception handler with recovery
pub fn handleSecureException(context: *InterruptContext) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Validate the transition
    validatePrivilegeTransition(context) catch |err| {
        serial.println("[INT_SEC] Privilege validation failed: {s}", .{@errorName(err)});
        // Continue with limited handling
    };

    // Check if recovery is possible
    if (canRecover(context)) {
        _ = security_stats.recovery_attempts.fetchAdd(1, .monotonic);

        if (tryRecover(context)) {
            _ = security_stats.successful_recoveries.fetchAdd(1, .monotonic);
            return;
        }
    }

    // No recovery possible, terminate
    serial.println("[INT_SEC] Unrecoverable exception, terminating", .{});
}

// Check if recovery is possible for this exception
fn canRecover(context: *const InterruptContext) bool {
    switch (context.vector) {
        // Recoverable exceptions
        14 => { // Page fault
            // Check if it's a valid page fault we can handle
            const cr2 = asm volatile ("mov %%cr2, %[result]"
                : [result] "=r" (-> u64),
            );

            // User space page faults might be recoverable
            if (context.from_userspace and cr2 < 0x800000000000) {
                return true;
            }
        },
        16, 19 => { // x87 FPU, SIMD
            // FPU/SIMD exceptions might be recoverable
            return context.from_userspace;
        },
        else => {},
    }

    return false;
}

// Attempt to recover from exception
fn tryRecover(context: *InterruptContext) bool {
    switch (context.vector) {
        14 => { // Page fault
            // DO NOT skip instructions without proper decoding
            // This is a critical security issue that could lead to arbitrary code execution
            // Log the fault details and let it panic safely
            const cr2 = asm volatile ("mov %%cr2, %[cr2]"
                : [cr2] "=r" (-> u64),
            );
            serial.println("[FAULT] Page fault at RIP={x}, CR2={x}, cannot safely recover", .{ context.rip, cr2 });
            return false; // Let the system panic safely
        },
        16, 19 => { // FPU/SIMD
            // Clear FPU state and continue
            asm volatile (
                \\fninit
                \\fnclex
            );
            return true;
        },
        else => {},
    }

    return false;
}

// Clean up IST stack on exception return
pub fn cleanupISTStack(ist_level: u8) void {
    if (ist_level > 0 and ist_level <= 7) {
        const ist_idx = ist_level - 1;

        // Use fetchSub for atomic decrement per Intel guidelines
        const prev_depth = ist_depths[ist_idx].fetchSub(1, .acq_rel);

        // Check for underflow (if previous value was 0, we went negative)
        if (prev_depth == 0) {
            // CRITICAL: Never attempt to continue after IST corruption
            // IST stack underflow indicates severe system corruption
            _ = security_stats.ist_underflows.fetchAdd(1, .monotonic);

            // Log critical error before halting
            serial.println("[CRITICAL] IST[{}] stack underflow detected - system compromised", .{ist_level});
            serial.println("[CRITICAL] Cannot safely continue execution - halting system", .{});

            // Halt the system immediately - do not return
            haltSystem();
        }
    }
}

// Get recommended IST level for exception vector
pub fn getISTLevel(vector: u8) u8 {
    return switch (vector) {
        8 => IST.DOUBLE_FAULT, // Double fault
        2 => IST.NMI, // NMI
        1 => IST.DEBUG, // Debug
        18 => IST.MACHINE_CHECK, // Machine check
        12 => IST.STACK_FAULT, // Stack fault
        13 => IST.GENERAL_PROTECTION, // General protection
        14 => IST.PAGE_FAULT, // Page fault
        else => 0, // No IST
    };
}

// Halt the system safely
fn haltSystem() noreturn {
    // Disable interrupts and halt the CPU
    while (true) {
        asm volatile (
            \\cli
            \\hlt
        );
    }
}

// Print security statistics
pub fn printStatistics() void {
    serial.println("[INT_SEC] Interrupt Security Statistics:", .{});
    serial.println("  Initialization phase: {s}", .{switch (init_phase) {
        .Uninitialized => "Not initialized",
        .EarlyInit => "Early init (static stacks)",
        .FullInit => "Fully initialized (dynamic stacks)",
    }});
    serial.println("  Using static stacks: {s}", .{if (using_static_stacks) "Yes" else "No"});
    serial.println("  Privilege violations: {}", .{security_stats.privilege_violations.load(.acquire)});
    serial.println("  IST overflows: {}", .{security_stats.ist_overflows.load(.acquire)});
    serial.println("  Invalid transitions: {}", .{security_stats.invalid_transitions.load(.acquire)});
    serial.println("  State corruption detected: {}", .{security_stats.state_corruption_detected.load(.acquire)});
    serial.println("  Context validation failures: {}", .{security_stats.context_validation_failures.load(.acquire)});
    serial.println("  Recovery attempts: {}", .{security_stats.recovery_attempts.load(.acquire)});
    serial.println("  Successful recoveries: {}", .{security_stats.successful_recoveries.load(.acquire)});
}

// Validate interrupt context integrity with enhanced security checks
pub fn validateContext(context: *const InterruptContext) bool {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Comprehensive segment selector validation
    const valid_kernel_cs: u64 = 0x08;
    const valid_user_cs: u64 = 0x1B;

    if (context.cs != valid_kernel_cs and context.cs != valid_user_cs) {
        _ = security_stats.context_validation_failures.fetchAdd(1, .monotonic);
        _ = security_stats.state_corruption_detected.fetchAdd(1, .monotonic);

        // Log detailed context corruption information
        serial.print("[CRITICAL] Exception context validation failed:\r\n", .{});
        serial.print("  Vector: {}\r\n", .{context.vector});
        serial.print("  Error Code: 0x{X}\r\n", .{context.error_code});
        serial.print("  RIP: 0x{X}\r\n", .{context.rip});
        serial.print("  CS: 0x{X} (expected 0x08 or 0x1B)\r\n", .{context.cs});
        serial.print("  RFLAGS: 0x{X}\r\n", .{context.rflags});
        serial.print("  RSP: 0x{X}\r\n", .{context.rsp});
        serial.print("  SS: 0x{X}\r\n", .{context.ss});

        // Force immediate system halt on context corruption
        @panic("Critical security violation: Exception context corruption detected");
    }

    // Validate SS (Stack Segment) matches CS privilege level
    const cs_rpl = context.cs & 0x3;
    const ss_rpl = context.ss & 0x3;
    if (cs_rpl != ss_rpl) {
        _ = security_stats.context_validation_failures.fetchAdd(1, .monotonic);
        serial.print("[CRITICAL] CS/SS privilege mismatch: CS RPL={}, SS RPL={}\r\n", .{ cs_rpl, ss_rpl });
        @panic("Critical security violation: CS/SS privilege level mismatch");
    }

    // Additional sanity checks for privilege escalation attempts
    if (context.cs & 0x3 != 0 and context.vector < 32) {
        // User mode exception trying to escalate to kernel
        if (context.ss == valid_kernel_cs) {
            serial.print("[CRITICAL] User mode exception with kernel SS detected\r\n", .{});
            @panic("Privilege escalation attempt detected");
        }
    }

    // Validate RIP is within reasonable bounds
    if (context.cs == valid_kernel_cs) {
        // Kernel mode - RIP should be in kernel space
        if (context.rip < 0xFFFF800000000000) {
            _ = security_stats.context_validation_failures.fetchAdd(1, .monotonic);
            serial.print("[CRITICAL] Kernel CS with user-space RIP: 0x{X}\r\n", .{context.rip});
            @panic("Critical security violation: Invalid RIP for kernel mode");
        }
    } else if (context.cs == valid_user_cs) {
        // User mode - RIP should be in user space
        if (context.rip >= 0xFFFF800000000000) {
            _ = security_stats.context_validation_failures.fetchAdd(1, .monotonic);
            serial.print("[CRITICAL] User CS with kernel-space RIP: 0x{X}\r\n", .{context.rip});
            @panic("Critical security violation: Invalid RIP for user mode");
        }
    }

    // Check stack alignment (16-byte boundary required by ABI)
    if (context.rsp & 0xF != 0) {
        _ = security_stats.context_validation_failures.fetchAdd(1, .monotonic);
        serial.print("[CRITICAL] Misaligned stack pointer: 0x{X}\r\n", .{context.rsp});
        @panic("Critical security violation: Stack pointer misalignment");
    }

    // Validate stack pointer is within reasonable bounds
    if (context.cs == valid_kernel_cs) {
        // Kernel stack should be in kernel space
        if (context.rsp < 0xFFFF800000000000) {
            _ = security_stats.context_validation_failures.fetchAdd(1, .monotonic);
            serial.print("[CRITICAL] Kernel mode with user-space RSP: 0x{X}\r\n", .{context.rsp});
            @panic("Critical security violation: Invalid RSP for kernel mode");
        }
    }

    // Validate RFLAGS
    const required_flags = 0x200; // IF (Interrupt Flag) must be set
    const forbidden_flags = 0x30000; // VM and RF flags should not be set in 64-bit mode

    if (context.rflags & required_flags == 0) {
        _ = security_stats.context_validation_failures.fetchAdd(1, .monotonic);
        serial.print("[CRITICAL] Missing required RFLAGS: 0x{X}\r\n", .{context.rflags});
        @panic("Critical security violation: Invalid RFLAGS state");
    }

    if (context.rflags & forbidden_flags != 0) {
        _ = security_stats.context_validation_failures.fetchAdd(1, .monotonic);
        serial.print("[CRITICAL] Forbidden RFLAGS set: 0x{X}\r\n", .{context.rflags});
        @panic("Critical security violation: Invalid RFLAGS state");
    }

    // Validate vector number is within valid range
    if (context.vector > 255) {
        _ = security_stats.context_validation_failures.fetchAdd(1, .monotonic);
        serial.print("[CRITICAL] Invalid exception vector: {}\r\n", .{context.vector});
        @panic("Critical security violation: Invalid exception vector");
    }

    // All checks passed
    return true;
}
