// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const stack_canary_test = @import("../x86_64/tests/stack_canary_test.zig");
const vmm = @import("../memory/vmm.zig");
const exception_validation_test = @import("../tests/exception_validation_test.zig");

// Run all diagnostic tests
pub fn runAllTests() void {
    // Test the improved canary implementation
    stack_canary_test.runAllTests();

    // Test serial driver robustness
    testSerial();

    // Test VMM functionality
    testVMM();

    // Test exception validation security
    exception_validation_test.runTests();

    // Print security statistics
    exception_validation_test.printSecurityStats();
}

// Test serial driver
fn testSerial() void {
    serial.println("[KERNEL] Testing serial driver...", .{});

    // Run self-test
    if (serial.selfTest()) {
        serial.println("[KERNEL] ✓ Serial self-test passed", .{});
    } else {
        serial.println("[KERNEL] ✗ Serial self-test failed", .{});
    }

    // Print serial statistics
    serial.printStats();

    serial.println("[KERNEL] Serial driver tests complete", .{});
}

// Test virtual memory manager
fn testVMM() void {
    serial.println("[KERNEL] Testing virtual memory manager...", .{});
    vmm.runTests();
}
