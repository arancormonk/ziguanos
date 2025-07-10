// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const functional_tests = @import("functional_tests.zig");
const per_cpu_tests = @import("per_cpu_tests.zig");
const ap_debug_tests = @import("ap_debug_tests.zig");
const serial = @import("../../drivers/serial.zig");

/// Run all SMP tests
pub fn runAllTests() !void {
    serial.println("\n========== SMP Test Suite ==========", .{});

    // Run per-CPU infrastructure tests
    try per_cpu_tests.testPerCpuInfrastructure();

    // Run AP debug tests
    try ap_debug_tests.testApDebug();

    // Run functional tests
    try functional_tests.runAll();

    // Note: Stress tests are not yet fully implemented
    // They require more infrastructure like task scheduling

    serial.println("\n========== SMP Test Suite Complete ==========", .{});
}

/// Run only functional tests
pub fn runFunctionalTests() !void {
    try functional_tests.runAll();
}

/// Run per-CPU infrastructure tests
pub fn runPerCpuTests() !void {
    try per_cpu_tests.testPerCpuInfrastructure();
}

/// Run AP debug tests
pub fn runApDebugTests() !void {
    try ap_debug_tests.testApDebug();
}

/// Individual test exports for direct calling
pub const testApStartup = functional_tests.testApStartup;
pub const testPerCpuData = functional_tests.testPerCpuData;
pub const testIpi = functional_tests.testIpi;
pub const testAtomicOps = functional_tests.testAtomicOps;
pub const testRemoteFunctionCalls = functional_tests.testRemoteFunctionCalls;
pub const testPerCpuInfrastructure = per_cpu_tests.testPerCpuInfrastructure;
pub const testApDebug = ap_debug_tests.testApDebug;
