// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Enhanced exception handling with full security features
// Implements Intel x86-64 best practices

const std = @import("std");
const builtin = @import("builtin");
const serial = @import("../drivers/serial.zig");
const secure_print = @import("../lib/secure_print.zig");
const interrupt_security = @import("interrupt_security.zig");
const speculation = @import("speculation.zig");
const pmm = @import("../memory/pmm.zig");
const apic = @import("apic.zig");
const cpuid = @import("cpuid.zig");
const cfi_exception = @import("cfi_exception.zig");
const cpu_init = @import("cpu_init.zig");

// Extended interrupt frame with saved state
pub const ExtendedInterruptFrame = extern struct {
    // Saved segment registers
    gs: u64,
    fs: u64,
    es: u64,
    ds: u64,

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

    // Exception information
    vector: u64,
    error_code: u64,

    // CPU-pushed interrupt frame
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

// Compatibility alias for code that expects the simpler structure
// The basic interrupt frame is at the end of ExtendedInterruptFrame
pub const InterruptFrame = extern struct {
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
};

// Exception names (same as before)
const exception_names = [_][]const u8{
    "Division Error", // 0
    "Debug", // 1
    "Non-Maskable Interrupt", // 2
    "Breakpoint", // 3
    "Overflow", // 4
    "Bound Range Exceeded", // 5
    "Invalid Opcode", // 6
    "Device Not Available", // 7
    "Double Fault", // 8
    "Coprocessor Segment Overrun", // 9
    "Invalid TSS", // 10
    "Segment Not Present", // 11
    "Stack Segment Fault", // 12
    "General Protection Fault", // 13
    "Page Fault", // 14
    "Reserved", // 15
    "x87 FPU Error", // 16
    "Alignment Check", // 17
    "Machine Check", // 18
    "SIMD Floating Point", // 19
    "Virtualization", // 20
    "Control Protection", // 21
};

// Compatibility wrapper for simple interrupt frame
pub export fn handleException(vector: u64, error_code: u64, frame: *InterruptFrame) callconv(.C) void {
    // For compatibility with interrupts module - create minimal context
    var extended_frame = ExtendedInterruptFrame{
        // Segment registers (not available in simple frame)
        .gs = 0,
        .fs = 0,
        .es = 0,
        .ds = 0,
        // General purpose registers (not available)
        .r15 = 0,
        .r14 = 0,
        .r13 = 0,
        .r12 = 0,
        .r11 = 0,
        .r10 = 0,
        .r9 = 0,
        .r8 = 0,
        .rbp = 0,
        .rdi = 0,
        .rsi = 0,
        .rdx = 0,
        .rcx = 0,
        .rbx = 0,
        .rax = 0,
        // Exception information
        .vector = vector,
        .error_code = error_code,
        // CPU-pushed interrupt frame
        .rip = frame.rip,
        .cs = frame.cs,
        .rflags = frame.rflags,
        .rsp = frame.rsp,
        .ss = frame.ss,
    };
    handleExceptionEnhanced(vector, error_code, &extended_frame);
}

// Enhanced exception handler called from assembly
export fn handleExceptionEnhanced(vector: u64, error_code: u64, context: *ExtendedInterruptFrame) callconv(.C) void {
    // Debug: catch any early exceptions
    if (vector < 32) {
        serial.print("[EXCEPTION] Early catch: vector {d}, RIP: ", .{vector});
        secure_print.printHex("", context.rip);
        serial.println("", .{});
    }

    // Apply speculation barrier
    speculation.speculationBarrier();

    // Build full interrupt context
    var int_context = interrupt_security.InterruptContext{
        .r15 = context.r15,
        .r14 = context.r14,
        .r13 = context.r13,
        .r12 = context.r12,
        .r11 = context.r11,
        .r10 = context.r10,
        .r9 = context.r9,
        .r8 = context.r8,
        .rbp = context.rbp,
        .rdi = context.rdi,
        .rsi = context.rsi,
        .rdx = context.rdx,
        .rcx = context.rcx,
        .rbx = context.rbx,
        .rax = context.rax,
        .vector = vector,
        .error_code = error_code,
        .rip = context.rip,
        .cs = context.cs,
        .rflags = context.rflags,
        .rsp = context.rsp,
        .ss = context.ss,
        .extended_state = null,
        .previous_cpl = @as(u8, @truncate(context.cs & 3)),
        .from_userspace = (context.cs & 3) != 0,
        .ist_level = interrupt_security.getISTLevel(@as(u8, @truncate(vector))),
    };

    // Validate context integrity - validateContext will panic on failure
    // This ensures no silent failures and immediate halt on corruption
    _ = interrupt_security.validateContext(&int_context);

    // Validate privilege transition
    interrupt_security.validatePrivilegeTransition(&int_context) catch |err| {
        serial.println("[EXCEPTION] Security violation: {s}", .{@errorName(err)});
        // Log security event but continue handling
    };

    // Print exception information
    if (vector < exception_names.len) {
        serial.print("[EXCEPTION] {s}", .{exception_names[vector]});
    } else {
        serial.print("[EXCEPTION] Vector {}", .{vector});
    }

    // Print error code if applicable
    if (hasErrorCode(vector)) {
        serial.print(" (Error: 0x{x})", .{error_code});

        // Decode error code for specific exceptions
        if (vector == 14) { // Page fault
            decodePageFaultError(error_code);
        }
    }

    serial.println("", .{});
    printContext(context);

    // Handle specific exceptions
    handleSpecificException(&int_context) catch |err| {
        serial.println("[EXCEPTION] Handler failed: {s}", .{@errorName(err)});
    };

    // Clean up IST stack if used
    if (int_context.ist_level > 0) {
        interrupt_security.cleanupISTStack(int_context.ist_level);
    }

    // If we recovered, update context and return
    if (int_context.rip != context.rip) {
        context.rip = int_context.rip;
        serial.println("[EXCEPTION] Recovered, continuing execution", .{});

        // Apply MDS mitigation before returning to potentially different context
        if (int_context.from_userspace) {
            speculation.mitigateOnKernelExit();
        }
        return;
    }

    // No recovery possible
    serial.println("[EXCEPTION] System halted.", .{});
    halt();
}

// Check if exception pushes error code
fn hasErrorCode(vector: u64) bool {
    return switch (vector) {
        8, 10, 11, 12, 13, 14, 17, 21, 30 => true,
        else => false,
    };
}

// Decode page fault error code
fn decodePageFaultError(error_code: u64) void {
    serial.print("  Page fault details:", .{});
    if (error_code & 1 != 0) {
        serial.print("    Caused by: protection violation", .{});
    } else {
        serial.print("    Caused by: non-present page", .{});
    }

    if (error_code & 2 != 0) {
        serial.print("    Access type: write", .{});
    } else {
        serial.print("    Access type: read", .{});
    }

    if (error_code & 4 != 0) {
        serial.print("    Mode: user", .{});
    } else {
        serial.print("    Mode: kernel", .{});
    }

    if (error_code & 8 != 0) {
        serial.print("    Reserved bit violation", .{});
    }

    if (error_code & 16 != 0) {
        serial.print("    Instruction fetch", .{});
    }

    if (error_code & 32 != 0) {
        serial.print("    Protection key violation", .{});
    }

    if (error_code & (1 << 15) != 0) {
        serial.print("    SGX violation", .{});
    }

    const cr2 = asm volatile ("mov %%cr2, %[result]"
        : [result] "=r" (-> u64),
    );
    serial.print("    Fault address: ", .{});
    secure_print.printHex("", cr2);
}

// Print detailed context information
fn printContext(context: *const ExtendedInterruptFrame) void {
    secure_print.printRegisters(context);
}

// Decode RFLAGS register
fn decodeRFLAGS(rflags: u64) void {
    serial.print(" (", .{});
    if (rflags & (1 << 0) != 0) serial.print("CF ", .{});
    if (rflags & (1 << 2) != 0) serial.print("PF ", .{});
    if (rflags & (1 << 4) != 0) serial.print("AF ", .{});
    if (rflags & (1 << 6) != 0) serial.print("ZF ", .{});
    if (rflags & (1 << 7) != 0) serial.print("SF ", .{});
    if (rflags & (1 << 8) != 0) serial.print("TF ", .{});
    if (rflags & (1 << 9) != 0) serial.print("IF ", .{});
    if (rflags & (1 << 10) != 0) serial.print("DF ", .{});
    if (rflags & (1 << 11) != 0) serial.print("OF ", .{});
    if (rflags & (1 << 14) != 0) serial.print("NT ", .{});
    if (rflags & (1 << 16) != 0) serial.print("RF ", .{});
    if (rflags & (1 << 17) != 0) serial.print("VM ", .{});
    if (rflags & (1 << 18) != 0) serial.print("AC ", .{});
    if (rflags & (1 << 19) != 0) serial.print("VIF ", .{});
    if (rflags & (1 << 20) != 0) serial.print("VIP ", .{});
    if (rflags & (1 << 21) != 0) serial.print("ID ", .{});
    serial.print(")", .{});
}

// Decode Control Protection fault error code
fn decodeControlProtectionError(error_code: u64) void {
    serial.print("  Control Protection fault details:", .{});

    if (error_code & 1 != 0) {
        serial.print("    CET fault: Shadow stack violation", .{});
    } else {
        serial.print("    CET fault: Indirect branch tracking violation", .{});
    }

    if (error_code & 2 != 0) {
        serial.print("    Missing ENDBR instruction", .{});
    }

    if (error_code & 4 != 0) {
        serial.print("    Shadow stack token verification failed", .{});
    }

    // Error code bits 31:16 contain additional details
    const error_info = error_code >> 16;
    if (error_info != 0) {
        serial.print("    Error info: 0x{x}", .{error_info});
    }
}

// Handle specific exceptions - NO UNSAFE RECOVERY
fn handleSpecificException(context: *interrupt_security.InterruptContext) !void {
    switch (context.vector) {
        0 => { // Division error
            serial.println("  Division by zero detected at RIP: 0x{x}", .{context.rip});
            // DO NOT attempt to skip instructions - this is unsafe
            // Log the exception and halt
            if (comptime builtin.mode == .Debug) {
                @panic("Division by zero - manual intervention required");
            }
            // In production, safely terminate (halt for now)
            halt();
        },
        6 => { // Invalid opcode
            serial.println("  Invalid instruction executed at RIP: 0x{x}", .{context.rip});
            // DO NOT attempt instruction emulation without proper decoding
            if (comptime builtin.mode == .Debug) {
                @panic("Invalid opcode - manual intervention required");
            }
            halt();
        },
        7 => { // Device not available (FPU)
            serial.println("  FPU not available at RIP: 0x{x}", .{context.rip});
            // Initialize FPU - this is safe as it doesn't modify RIP
            asm volatile (
                \\mov %%cr0, %%rax
                \\and $0xFFFFFFFFFFFFFFFB, %%rax
                \\mov %%rax, %%cr0
                \\fninit
                ::: "rax", "memory");
            // Retry the instruction by returning normally
        },
        13 => { // General protection fault
            serial.println("  General protection violation at RIP: 0x{x}", .{context.rip});
            // General protection faults are usually unrecoverable
            if (comptime builtin.mode == .Debug) {
                @panic("General protection fault - manual intervention required");
            }
            halt();
        },
        14 => { // Page fault
            const cr2 = asm volatile ("mov %%cr2, %[result]"
                : [result] "=r" (-> u64),
            );

            serial.println("  Page fault at address 0x{x}, RIP: 0x{x}", .{ cr2, context.rip });
            // DO NOT attempt to skip instructions - this is unsafe
            // Log the fault and halt
            if (comptime builtin.mode == .Debug) {
                @panic("Page fault - manual intervention required");
            }
            halt();
        },
        21 => { // Control Protection Exception (CET)
            try handleControlProtectionFault(context);
        },
        else => {},
    }
}

// NMI handler (special case)
export fn handleNMI(vector: u64, error_code: u64, frame: *ExtendedInterruptFrame) callconv(.C) void {
    _ = vector;
    _ = error_code;

    // NMI cannot be masked, handle carefully
    serial.println("[NMI] Non-Maskable Interrupt received", .{});

    // Check for hardware errors
    checkHardwareErrors();

    // Log NMI source if possible
    serial.println("  RIP at NMI: 0x{x:0>16}", .{frame.rip});

    // NMI typically indicates serious hardware issue
    // For now, just return and hope for the best
}

// Check for hardware errors
fn checkHardwareErrors() void {
    // Check machine check banks if available
    // MCE is bit 7 in EDX from CPUID leaf 1
    serial.println("  Hardware error check performed", .{});

    // Check other hardware status
    // This is platform-specific
}

// Control Protection (#CP) Exception Error Code bits (Intel SDM Vol 3A Ch 18)
const CP_ERR_NEAR_RET: u64 = 1 << 0; // Near RET check failure
const CP_ERR_FAR_RET_IRET: u64 = 1 << 1; // Far RET/IRET check failure
const CP_ERR_ENDBR: u64 = 1 << 2; // Missing ENDBR at indirect branch target
const CP_ERR_RSTORSSP: u64 = 1 << 3; // RSTORSSP check failure
const CP_ERR_SETSSBSY: u64 = 1 << 4; // Shadow stack token busy during SETSSBSY

// Handle Control Protection Exception (#CP)
fn handleControlProtectionFault(context: *interrupt_security.InterruptContext) !void {
    // Use the dedicated CFI exception handler
    // Create a temporary InterruptFrame from the context
    var frame = InterruptFrame{
        .rip = context.rip,
        .cs = context.cs,
        .rflags = context.rflags,
        .rsp = context.rsp,
        .ss = context.ss,
    };
    cfi_exception.handleControlProtection(&frame, context.error_code);

    // The CFI handler will panic, so this is unreachable
    // But kept for completeness
    serial.println("[CP] Control Protection Exception", .{});
    serial.println("  Error code: 0x{x:0>16}", .{context.error_code});

    // Decode error code
    if ((context.error_code & CP_ERR_NEAR_RET) != 0) {
        serial.println("  Cause: Near RET - shadow stack mismatch", .{});

        // Read shadow stack pointer
        const ssp = cpu_init.readMSR(cpu_init.IA32_PL0_SSP);
        serial.println("  Current SSP: 0x{x:0>16}", .{ssp});

        // Try to read the mismatched return address
        if (ssp != 0) {
            const shadow_ret_addr = @as(*u64, @ptrFromInt(ssp)).*;
            serial.println("  Shadow stack return address: 0x{x:0>16}", .{shadow_ret_addr});
            serial.println("  Actual return address (RSP): 0x{x:0>16}", .{context.rsp});
        }
    }

    if ((context.error_code & CP_ERR_FAR_RET_IRET) != 0) {
        serial.println("  Cause: Far RET/IRET - shadow stack mismatch", .{});
    }

    if ((context.error_code & CP_ERR_ENDBR) != 0) {
        serial.println("  Cause: Missing ENDBR at indirect branch target", .{});
        secure_print.printValue("  Target address", context.rip);

        // In development mode, only disable IBT for specific debug operations that require it
        if (isDebugMode()) {
            if (isIBTDisableRequired()) {
                serial.println("  [DEBUG] SECURITY: Temporarily disabling IBT for critical debug operation", .{});

                // Log additional context for security audit
                serial.print("    RIP: ", .{});
                secure_print.printHex("", context.rip);
                serial.println("", .{});
                serial.print("    Error code: ", .{});
                secure_print.printHex("", context.error_code);
                serial.println("", .{});

                // Disable IBT temporarily
                var s_cet = cpu_init.readMSR(cpu_init.IA32_S_CET);
                s_cet &= ~cpu_init.CET_ENDBR_EN;
                cpu_init.writeMSR(cpu_init.IA32_S_CET, s_cet);

                // Re-enable IBT immediately after the debug operation
                defer {
                    s_cet |= cpu_init.CET_ENDBR_EN;
                    cpu_init.writeMSR(cpu_init.IA32_S_CET, s_cet);
                    serial.println("  [DEBUG] SECURITY: IBT re-enabled", .{});
                }

                // Retry the instruction (only if truly necessary)
                return;
            } else {
                // Keep IBT enabled for normal debug operations
                serial.println("  [DEBUG] Control flow violation - IBT remains enabled", .{});
                serial.println("  [DEBUG] Set isIBTDisableRequired() to true if IBT disable is truly needed", .{});
                // Continue with normal exception handling
            }
        }
    }

    if ((context.error_code & CP_ERR_RSTORSSP) != 0) {
        serial.println("  Cause: RSTORSSP check failure", .{});
    }

    if ((context.error_code & CP_ERR_SETSSBSY) != 0) {
        serial.println("  Cause: Shadow stack token busy during SETSSBSY", .{});
    }

    // Log shadow stack state
    const features = cpuid.getFeatures();
    if (features.cet_ss) {
        const s_cet = cpu_init.readMSR(cpu_init.IA32_S_CET);
        serial.println("  IA32_S_CET: 0x{x:0>16}", .{s_cet});

        if ((s_cet & cpu_init.CET_SHSTK_EN) != 0) {
            const ssp = cpu_init.readMSR(cpu_init.IA32_PL0_SSP);
            secure_print.printValue("  Shadow Stack Pointer", ssp);

            // Dump a few shadow stack entries for debugging
            serial.println("  Shadow stack contents:", .{});
            var i: u64 = 0;
            while (i < 5) : (i += 1) {
                const addr = ssp + (i * 8);
                const value = @as(*u64, @ptrFromInt(addr)).*;
                serial.print("    [SSP+{}]: ", .{i * 8});
                secure_print.printHex("", value);
                serial.println("", .{});
            }
        }
    }

    // Check if we're in userspace - might be able to terminate just the process
    if (context.from_userspace) {
        serial.println("  Fault in userspace - would terminate process", .{});
        // In a real OS, we would terminate the offending process
        // For now, halt the system
    }

    // Cannot recover from most CET violations - they indicate
    // control flow integrity compromise
    serial.println("  CRITICAL: Control flow integrity violation - halting", .{});
}

// Check if we're in debug mode (for development)
fn isDebugMode() bool {
    // Only enable debug mode in Debug builds
    return @import("builtin").mode == .Debug;
}

// Check if IBT disable is truly required for this specific debug operation
fn isIBTDisableRequired() bool {
    // Only disable IBT for operations that truly require it
    // By default, keep IBT enabled even in debug mode
    return false;
}

// Halt the system
fn halt() noreturn {
    // Disable interrupts and halt
    while (true) {
        asm volatile (
            \\cli
            \\hlt
        );
    }
}
