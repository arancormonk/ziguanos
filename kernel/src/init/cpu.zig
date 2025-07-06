// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const cpuid = @import("../x86_64/cpuid.zig");
const cpu_init = @import("../x86_64/cpu_init.zig");
const rng = @import("../x86_64/rng.zig");
const cfi = @import("../x86_64/cfi.zig");
const smap = @import("../x86_64/smap.zig");

/// Initialize CPU features and security mechanisms
pub fn init() void {
    // Detect CPU features
    cpuid.detectFeatures();
    cpuid.printFeatures();

    // Enable CPU security features
    cpu_init.initializeCPU();
    cpu_init.printSecurityFeatures(serial);
    serial.flush(); // Ensure CPU security features are visible

    // Test SMAP functionality
    smap.testSMAP();
    serial.flush(); // Ensure SMAP test results are visible

    // Test hardware RNG if available
    rng.testRNG();
    serial.flush(); // Ensure RNG test results are visible

    // Initialize Control Flow Integrity (CFI)
    cfi.init();
    serial.println("[KERNEL] Control Flow Integrity (CFI) initialized", .{});
}

/// Initialize complete CPU features after memory management is ready
pub fn initComplete() !void {
    // Initialize complete CET support now that memory management is ready
    cpu_init.initializeCETComplete() catch |err| {
        serial.println("[KERNEL] ERROR: Complete CET initialization failed: {s}", .{@errorName(err)});
        serial.flush();
        return err;
    };

    // Test CET functionality
    cpu_init.testCET();
    serial.flush();
}

/// Test CFI functionality
pub fn testCFI() void {
    serial.println("[KERNEL] Testing Control Flow Integrity (CFI)...", .{});
    cfi.selfTest() catch |err| {
        serial.println("[KERNEL] CFI self-test failed: {s}", .{@errorName(err)});
        serial.flush();
    };
}

/// Print CPU-related statistics
pub fn printStatistics() void {
    // Print SMAP statistics
    smap.printStats();

    // Print CFI statistics
    cfi.printStatistics();

    serial.flush();
}
