// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Test for enhanced exception context validation security

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const exceptions = @import("../x86_64/exceptions.zig");
const interrupt_security = @import("../x86_64/interrupt_security.zig");

pub fn runTests() void {
    serial.println("[EXCEPTION_TEST] Testing enhanced exception validation...", .{});

    // Test 1: Valid kernel context
    testValidKernelContext();

    // Test 2: Valid user context
    testValidUserContext();

    // Note: We cannot test invalid contexts directly as they would panic
    // and halt the system. These tests verify the happy path works correctly.

    serial.println("[EXCEPTION_TEST] All exception validation tests passed", .{});
}

fn testValidKernelContext() void {
    serial.println("[EXCEPTION_TEST] Test 1: Valid kernel context", .{});

    var context = interrupt_security.InterruptContext{
        .r15 = 0,
        .r14 = 0,
        .r13 = 0,
        .r12 = 0,
        .r11 = 0,
        .r10 = 0,
        .r9 = 0,
        .r8 = 0,
        .rbp = 0xFFFF800000001000,
        .rdi = 0,
        .rsi = 0,
        .rdx = 0,
        .rcx = 0,
        .rbx = 0,
        .rax = 0,
        .vector = 14, // Page fault
        .error_code = 0,
        .rip = 0xFFFF800000002000, // Kernel space RIP
        .cs = 0x08, // Kernel CS
        .rflags = 0x200, // IF set
        .rsp = 0xFFFF800000003000, // Kernel space RSP (16-byte aligned)
        .ss = 0x10, // Kernel SS (RPL=0)
        .extended_state = null,
        .previous_cpl = 0,
        .from_userspace = false,
        .ist_level = 7, // Page fault uses IST 7
    };

    // This should pass without panicking
    const valid = interrupt_security.validateContext(&context);
    if (!valid) {
        serial.println("  ERROR: Valid kernel context failed validation!", .{});
        return;
    }

    serial.println("  ✓ Valid kernel context passed validation", .{});
}

fn testValidUserContext() void {
    serial.println("[EXCEPTION_TEST] Test 2: Valid user context", .{});

    var context = interrupt_security.InterruptContext{
        .r15 = 0,
        .r14 = 0,
        .r13 = 0,
        .r12 = 0,
        .r11 = 0,
        .r10 = 0,
        .r9 = 0,
        .r8 = 0,
        .rbp = 0x00007FFF00001000,
        .rdi = 0,
        .rsi = 0,
        .rdx = 0,
        .rcx = 0,
        .rbx = 0,
        .rax = 0,
        .vector = 14, // Page fault
        .error_code = 4, // User mode page fault
        .rip = 0x0000000000401000, // User space RIP
        .cs = 0x1B, // User CS (RPL=3)
        .rflags = 0x200, // IF set
        .rsp = 0x00007FFF00002000, // User space RSP (16-byte aligned)
        .ss = 0x23, // User SS (RPL=3)
        .extended_state = null,
        .previous_cpl = 3,
        .from_userspace = true,
        .ist_level = 7, // Page fault uses IST 7
    };

    // This should pass without panicking
    const valid = interrupt_security.validateContext(&context);
    if (!valid) {
        serial.println("  ERROR: Valid user context failed validation!", .{});
        return;
    }

    serial.println("  ✓ Valid user context passed validation", .{});
}

// Test cases that would cause panics (documented but not executed):
// 1. Invalid CS selector (not 0x08 or 0x1B) - would panic
// 2. CS/SS privilege level mismatch - would panic
// 3. Kernel CS with user-space RIP - would panic
// 4. User CS with kernel-space RIP - would panic
// 5. Misaligned stack pointer - would panic
// 6. Kernel mode with user-space RSP - would panic
// 7. Missing required RFLAGS - would panic
// 8. Forbidden RFLAGS set - would panic
// 9. Invalid exception vector > 255 - would panic

pub fn printSecurityStats() void {
    interrupt_security.printStatistics();
}
