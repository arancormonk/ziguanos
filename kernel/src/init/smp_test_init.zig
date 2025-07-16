// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const smp = @import("../smp.zig");
const serial = @import("../drivers/serial.zig");
const error_utils = @import("../lib/error_utils.zig");

// Run SMP tests during kernel initialization
pub fn runSmpTests() void {
    serial.println("\n[KERNEL] Running SMP test suite...", .{});

    // Only run tests if we have multiple CPUs
    if (smp.per_cpu.getCpuCount() < 2) {
        serial.println("[KERNEL] Skipping SMP tests (single CPU system)", .{});
        return;
    }

    // Run the test suite
    smp.tests.runAllTests() catch |err| {
        serial.println("[KERNEL] SMP tests failed: {s}", .{error_utils.errorToString(err)});
        return;
    };

    serial.println("[KERNEL] SMP test suite complete", .{});
}

// Run specific test based on kernel command line or config
pub fn runSmpTest(test_name: []const u8) void {
    if (std.mem.eql(u8, test_name, "ap_startup")) {
        smp.tests.testApStartup() catch |err| {
            serial.println("[KERNEL] AP startup test failed: {s}", .{error_utils.errorToString(err)});
        };
    } else if (std.mem.eql(u8, test_name, "per_cpu")) {
        smp.tests.testPerCpuData() catch |err| {
            serial.println("[KERNEL] Per-CPU data test failed: {s}", .{error_utils.errorToString(err)});
        };
    } else if (std.mem.eql(u8, test_name, "ipi")) {
        smp.tests.testIpi() catch |err| {
            serial.println("[KERNEL] IPI test failed: {s}", .{error_utils.errorToString(err)});
        };
    } else if (std.mem.eql(u8, test_name, "memory_stress")) {
        smp.tests.stressMemoryAllocation() catch |err| {
            serial.println("[KERNEL] Memory stress test failed: {s}", .{error_utils.errorToString(err)});
        };
    } else if (std.mem.eql(u8, test_name, "all")) {
        runSmpTests();
    } else {
        serial.println("[KERNEL] Unknown SMP test: {s}", .{test_name});
    }
}
