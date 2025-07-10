// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const per_cpu = @import("../per_cpu.zig");
const ap_init = @import("../ap_init.zig");
const ipi = @import("../ipi.zig");
const ap_sync = @import("../ap_sync.zig");
const serial = @import("../../drivers/serial.zig");
const timer = @import("../../x86_64/timer.zig");
const call_function = @import("../call_function.zig");
const test_coordinator = @import("test_coordinator.zig");

// Test results structure
pub const TestResult = struct {
    passed: u32 = 0,
    failed: u32 = 0,
    skipped: u32 = 0,
};

var test_results = TestResult{};

// Test 1: Verify all APs respond to INIT-SIPI-SIPI
pub fn testApStartup() !void {
    serial.println("\n[SMP TEST] Testing AP startup sequence...", .{});

    const start_time = timer.readTSC();
    const initial_cpu_count = per_cpu.getCpuCount();

    // Get expected CPU count from ACPI
    const expected_cpus = ap_init.getDetectedCpuCount();

    // Ensure APs are started
    try test_coordinator.coordinator.ensureAPsStarted();

    // Wait for APs to come online (max 5 seconds)
    const timeout_ms: u64 = 5000;
    const start_uptime = timer.getUptime();

    while ((timer.getUptime() - start_uptime) / 1_000_000 < timeout_ms) {
        if (ap_init.getOnlineCpuCount() >= expected_cpus) {
            break;
        }
        timer.delayMicroseconds(1000); // 1ms delay
    }

    const final_cpu_count = ap_init.getOnlineCpuCount();
    const elapsed_us = if (timer.getTSCFrequency() > 0)
        (timer.readTSC() - start_time) * 1000 / (timer.getTSCFrequency() / 1000)
    else
        0;

    serial.println("  Initial CPUs: {}", .{initial_cpu_count});
    serial.println("  Expected CPUs: {}", .{expected_cpus});
    serial.println("  Final CPUs: {}", .{final_cpu_count});
    if (elapsed_us > 0) {
        serial.println("  Startup time: {} us", .{elapsed_us});
    }

    if (final_cpu_count == expected_cpus) {
        serial.println("  ✓ All APs started successfully", .{});
        test_results.passed += 1;
    } else {
        serial.println("  ✗ Only {}/{} APs started", .{ final_cpu_count - 1, expected_cpus - 1 });
        test_results.failed += 1;
    }
}

// Test 2: Verify per-CPU data access
pub fn testPerCpuData() !void {
    serial.println("\n[SMP TEST] Testing per-CPU data access...", .{});

    const cpu_count = per_cpu.getCpuCount();
    var errors: u32 = 0;

    // Test each CPU's data structure
    for (0..cpu_count) |cpu_id| {
        const cpu_data = per_cpu.getCpuById(@intCast(cpu_id));
        if (cpu_data) |data| {
            // Verify magic number
            if (data.magic != 0xDEADBEEFCAFEBABE) {
                serial.println("  ✗ CPU {} invalid magic: 0x{x}", .{ cpu_id, data.magic });
                errors += 1;
                continue;
            }

            // Verify CPU ID matches
            if (data.cpu_id != cpu_id) {
                serial.println("  ✗ CPU {} ID mismatch: {}", .{ cpu_id, data.cpu_id });
                errors += 1;
                continue;
            }

            // Verify kernel stack is non-null
            if (@intFromPtr(data.kernel_stack) == 0) {
                serial.println("  ✗ CPU {} null kernel stack", .{cpu_id});
                errors += 1;
                continue;
            }

            // Verify IST stacks
            for (data.ist_stacks, 0..) |stack, i| {
                if (@intFromPtr(stack) == 0) {
                    serial.println("  ✗ CPU {} null IST stack {}", .{ cpu_id, i });
                    errors += 1;
                }
            }
        } else {
            serial.println("  ✗ CPU {} data not found", .{cpu_id});
            errors += 1;
        }
    }

    if (errors == 0) {
        serial.println("  ✓ All per-CPU data structures valid", .{});
        test_results.passed += 1;
    } else {
        serial.println("  ✗ {} errors in per-CPU data", .{errors});
        test_results.failed += 1;
    }
}

// Test 3: Verify inter-processor interrupts
pub fn testIpi() !void {
    serial.println("\n[SMP TEST] Testing inter-processor interrupts...", .{});

    const cpu_count = per_cpu.getCpuCount();
    if (cpu_count < 2) {
        serial.println("  ⚠ Skipping IPI test (single CPU system)", .{});
        test_results.skipped += 1;
        return;
    }

    // Get initial IPI stats
    const initial_stats = ipi.getStats();

    // Test 1: Send IPI to specific CPU
    const target_cpu = 1; // Send to first AP
    ipi.requestReschedule(target_cpu);

    // Small delay for IPI delivery
    timer.delayUs(100);

    // Test 2: Broadcast IPI to all CPUs except self
    ipi.tlbShootdownAll();

    // Delay for IPI processing
    timer.delayUs(1000);

    // Get final stats
    const final_stats = ipi.getStats();

    // Verify IPIs were sent
    const reschedule_sent = final_stats.sent[1] - initial_stats.sent[1];
    const tlb_sent = final_stats.sent[0] - initial_stats.sent[0];

    serial.println("  Reschedule IPIs sent: {}", .{reschedule_sent});
    serial.println("  TLB shootdown IPIs sent: {}", .{tlb_sent});

    // We should have sent at least the expected number
    const expected_tlb = cpu_count - 1; // All CPUs except self

    if (reschedule_sent >= 1 and tlb_sent >= expected_tlb) {
        serial.println("  ✓ IPI delivery successful", .{});
        test_results.passed += 1;
    } else {
        serial.println("  ✗ IPI delivery failed", .{});
        test_results.failed += 1;
    }
}

// Test 4: Verify atomic operations
pub fn testAtomicOps() !void {
    serial.println("\n[SMP TEST] Testing atomic operations...", .{});

    // Shared atomic counter
    var counter = std.atomic.Value(u64).init(0);
    var errors: u32 = 0;

    // Test atomic increment
    const initial = counter.load(.seq_cst);
    _ = counter.fetchAdd(1, .seq_cst);
    const after_add = counter.load(.seq_cst);

    if (after_add != initial + 1) {
        serial.println("  ✗ Atomic add failed: {} -> {}", .{ initial, after_add });
        errors += 1;
    }

    // Test compare and swap
    const old_val = counter.load(.seq_cst);
    const new_val = old_val + 10;
    if (counter.cmpxchgStrong(old_val, new_val, .seq_cst, .seq_cst)) |_| {
        serial.println("  ✗ CAS unexpectedly failed", .{});
        errors += 1;
    } else {
        const current = counter.load(.seq_cst);
        if (current != new_val) {
            serial.println("  ✗ CAS value mismatch: expected {}, got {}", .{ new_val, current });
            errors += 1;
        }
    }

    // Test atomic exchange
    const prev = counter.swap(100, .seq_cst);
    const after_swap = counter.load(.seq_cst);

    if (after_swap != 100) {
        serial.println("  ✗ Atomic swap failed: got {}", .{after_swap});
        errors += 1;
    }

    // Verify the previous value was what we expected
    if (prev != new_val) {
        serial.println("  ✗ Atomic swap returned wrong previous value: expected {}, got {}", .{ new_val, prev });
        errors += 1;
    }

    if (errors == 0) {
        serial.println("  ✓ All atomic operations successful", .{});
        test_results.passed += 1;
    } else {
        serial.println("  ✗ {} atomic operation failures", .{errors});
        test_results.failed += 1;
    }
}

// Test 5: Verify remote function calls
pub fn testRemoteFunctionCalls() !void {
    serial.println("\n[SMP TEST] Testing remote function calls...", .{});

    const cpu_count = per_cpu.getCpuCount();
    if (cpu_count < 2) {
        serial.println("  ⚠ Skipping remote function call test (single CPU system)", .{});
        test_results.skipped += 1;
        return;
    }

    // Shared test state
    var test_value = std.atomic.Value(u32).init(0);
    var errors: u32 = 0;

    // Test 1: Call function on specific CPU
    const testFunc = struct {
        fn increment(val: *std.atomic.Value(u32)) void {
            _ = val.fetchAdd(1, .seq_cst);
        }
    }.increment;

    // Call on CPU 1
    call_function.callFunctionSingle(1, @ptrCast(&testFunc)) catch |err| {
        serial.println("  ✗ Failed to call function on CPU 1: {}", .{err});
        errors += 1;
    };

    // Small delay for completion
    timer.delayMicroseconds(100);

    const value_after_single = test_value.load(.seq_cst);
    if (value_after_single != 1) {
        serial.println("  ✗ Remote function call failed: expected 1, got {}", .{value_after_single});
        errors += 1;
    }

    // Test 2: Broadcast function to all CPUs
    test_value.store(0, .seq_cst);

    call_function.callFunctionAll(@ptrCast(&testFunc)) catch |err| {
        serial.println("  ✗ Failed to broadcast function: {}", .{err});
        errors += 1;
    };

    // Small delay for completion
    timer.delayMicroseconds(1000);

    const value_after_broadcast = test_value.load(.seq_cst);
    const expected_broadcast = cpu_count - 1; // All CPUs except current

    if (value_after_broadcast != expected_broadcast) {
        serial.println("  ✗ Broadcast function call failed: expected {}, got {}", .{ expected_broadcast, value_after_broadcast });
        errors += 1;
    }

    // Get statistics
    const stats = call_function.getStats();
    serial.println("  Function calls sent: {}", .{stats.calls_sent});
    serial.println("  Function calls completed: {}", .{stats.calls_completed});
    serial.println("  Function calls failed: {}", .{stats.calls_failed});
    serial.println("  Function call timeouts: {}", .{stats.timeouts});

    if (errors == 0) {
        serial.println("  ✓ Remote function calls successful", .{});
        test_results.passed += 1;
    } else {
        serial.println("  ✗ {} remote function call errors", .{errors});
        test_results.failed += 1;
    }
}

// Run all functional tests
pub fn runAll() !void {
    serial.println("\n=== SMP Functional Tests ===", .{});

    test_results = TestResult{};

    // Run each test
    try testApStartup();
    try testPerCpuData();
    try testIpi();
    try testAtomicOps();
    try testRemoteFunctionCalls();

    // Print summary
    serial.println("\n=== Test Summary ===", .{});
    serial.println("Passed: {}", .{test_results.passed});
    serial.println("Failed: {}", .{test_results.failed});
    serial.println("Skipped: {}", .{test_results.skipped});

    if (test_results.failed == 0) {
        serial.println("\n✓ All functional tests passed!", .{});
    } else {
        serial.println("\n✗ {} tests failed!", .{test_results.failed});
    }
}
