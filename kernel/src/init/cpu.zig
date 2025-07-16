// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const cpuid = @import("../x86_64/cpuid.zig");
const cpu_init = @import("../x86_64/cpu_init.zig");
const rng = @import("../x86_64/rng.zig");
const cfi = @import("../x86_64/cfi.zig");
const smap = @import("../x86_64/smap.zig");
const ap_cpu_init = @import("../smp/ap_cpu_init.zig");
const ipi = @import("../smp/ipi.zig");
const call_function = @import("../smp/call_function.zig");
const error_utils = @import("../lib/error_utils.zig");

// Initialize CPU features and security mechanisms
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

    // Save BSP features for AP verification (Intel SDM Vol 3A Section 8.4.6)
    ap_cpu_init.saveBspFeatures();
    serial.println("[KERNEL] BSP CPU features saved for AP verification", .{});
}

// Initialize complete CPU features after memory management is ready
pub fn initComplete() !void {
    // Initialize complete CET support now that memory management is ready
    cpu_init.initializeCETComplete() catch |err| {
        serial.println("[KERNEL] ERROR: Complete CET initialization failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
        return err;
    };

    // Test CET functionality
    cpu_init.testCET();
    serial.flush();

    // Initialize IPI infrastructure (Intel SDM Vol 3A Section 10.6)
    ipi.init();
    serial.println("[KERNEL] Inter-Processor Interrupt (IPI) infrastructure initialized", .{});
    serial.flush();

    // Initialize remote function call infrastructure
    call_function.init();
    serial.println("[KERNEL] Remote function call infrastructure initialized", .{});
    serial.flush();
}

// Test CFI functionality
pub fn testCFI() void {
    serial.println("[KERNEL] Testing Control Flow Integrity (CFI)...", .{});
    cfi.selfTest() catch |err| {
        serial.println("[KERNEL] CFI self-test failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
    };
}

// Print CPU-related statistics
pub fn printStatistics() void {
    // Print SMAP statistics
    smap.printStats();

    // Print CFI statistics
    cfi.printStatistics();

    serial.flush();
}
