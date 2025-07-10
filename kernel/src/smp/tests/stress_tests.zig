// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// NOTE: Stress tests are temporarily disabled as they require
// scheduler infrastructure that is not yet implemented.
// They will be re-enabled once the task/process management is in place.

const std = @import("std");
const per_cpu = @import("../per_cpu.zig");
const ipi = @import("../ipi.zig");
const ap_sync = @import("../ap_sync.zig");
const serial = @import("../../drivers/serial.zig");
const timer = @import("../../x86_64/timer.zig");
const pmm = @import("../../memory/pmm.zig");
const heap = @import("../../memory/heap.zig");
const spinlock = @import("../../lib/spinlock.zig");
const call_function = @import("../call_function.zig");
const test_utils = @import("test_utils.zig");
const test_coordinator = @import("test_coordinator.zig");

// Shared state for stress tests
var stress_counter = std.atomic.Value(u64).init(0);
var stress_errors = std.atomic.Value(u32).init(0);
var test_lock = spinlock.SpinLock{};
var cache_line_test: [64]u8 align(64) = [_]u8{0} ** 64;

// Test configuration
const STRESS_ITERATIONS = 10000;
const ALLOCATION_SIZE = 4096;
const IPI_BURST_COUNT = 100;

// Test 1: Parallel memory allocation stress test
pub fn stressMemoryAllocation() !void {
    serial.println("\n[SMP STRESS] Testing parallel memory allocation...", .{});

    const cpu_count = per_cpu.getCpuCount();
    if (cpu_count < 2) {
        serial.println("  ⚠ Skipping (single CPU system)", .{});
        return;
    }

    // Reset counters
    stress_counter.store(0, .seq_cst);
    stress_errors.store(0, .seq_cst);

    // Create barrier for synchronized start
    var barrier = test_utils.Barrier.init(@intCast(cpu_count));

    // Function to run on each CPU
    const allocWorker = struct {
        fn work(ctx: *test_utils.TestContext) void {
            // Wait for all CPUs to be ready
            ctx.barrier.wait() catch {
                _ = stress_errors.fetchAdd(1, .seq_cst);
                return;
            };

            // Perform allocations
            var local_allocs: u32 = 0;
            var i: u32 = 0;
            while (i < STRESS_ITERATIONS / per_cpu.getCpuCount()) : (i += 1) {
                // Allocate memory
                const ptr = heap.allocator.alloc(u8, ALLOCATION_SIZE) catch {
                    _ = stress_errors.fetchAdd(1, .seq_cst);
                    continue;
                };
                defer heap.allocator.free(ptr);

                // Write pattern to verify allocation
                for (ptr, 0..) |*byte, idx| {
                    byte.* = @truncate(cpu_id + idx);
                }

                // Verify pattern
                for (ptr, 0..) |byte, idx| {
                    if (byte != @as(u8, @truncate(cpu_id + idx))) {
                        _ = stress_errors.fetchAdd(1, .seq_cst);
                        break;
                    }
                }

                local_allocs += 1;
            }

            _ = stress_counter.fetchAdd(local_allocs, .seq_cst);
        }
    }.work;

    // Run test on all CPUs
    const start_time = timer.readTSC();

    // TODO: Execute allocWorker on each CPU via IPI
    // For now, just run on current CPU
    allocWorker(per_cpu.getCurrentCpuId(), &barrier);

    const elapsed_us = (timer.readTSC() - start_time) / timer.getCpuFrequencyMhz();
    const total_allocs = stress_counter.load(.seq_cst);
    const errors = stress_errors.load(.seq_cst);

    serial.println("  Total allocations: {}", .{total_allocs});
    serial.println("  Errors: {}", .{errors});
    serial.println("  Time: {} us", .{elapsed_us});
    serial.println("  Throughput: {} allocs/sec", .{(total_allocs * 1000000) / elapsed_us});

    if (errors == 0) {
        serial.println("  ✓ Memory allocation stress test passed", .{});
    } else {
        serial.println("  ✗ Memory allocation stress test failed", .{});
    }
}

// Test 2: Lock contention stress test
pub fn stressLockContention() !void {
    serial.println("\n[SMP STRESS] Testing lock contention...", .{});

    const cpu_count = per_cpu.getCpuCount();
    if (cpu_count < 2) {
        serial.println("  ⚠ Skipping (single CPU system)", .{});
        return;
    }

    stress_counter.store(0, .seq_cst);
    stress_errors.store(0, .seq_cst);

    const lockWorker = struct {
        fn work(cpu_id: u32) void {
            _ = cpu_id;
            var i: u32 = 0;
            while (i < STRESS_ITERATIONS) : (i += 1) {
                const flags = test_lock.acquire();
                defer test_lock.release(flags);

                // Critical section: increment counter
                const old_val = stress_counter.load(.monotonic);

                // Small delay to increase contention
                var j: u32 = 0;
                while (j < 10) : (j += 1) {
                    asm volatile ("pause");
                }

                stress_counter.store(old_val + 1, .monotonic);
            }
        }
    }.work;

    const start_time = timer.readTSC();

    // TODO: Run on all CPUs
    lockWorker(per_cpu.getCurrentCpuId());

    const elapsed_us = (timer.readTSC() - start_time) / timer.getCpuFrequencyMhz();
    const final_count = stress_counter.load(.seq_cst);

    serial.println("  Lock acquisitions: {}", .{final_count});
    serial.println("  Time: {} us", .{elapsed_us});
    serial.println("  Throughput: {} locks/sec", .{(final_count * 1000000) / elapsed_us});

    if (final_count == STRESS_ITERATIONS) {
        serial.println("  ✓ Lock contention test passed", .{});
    } else {
        serial.println("  ✗ Lock contention test failed (count mismatch)", .{});
    }
}

// Test 3: IPI flood stress test
pub fn stressIpiFlood() !void {
    serial.println("\n[SMP STRESS] Testing IPI flood...", .{});

    const cpu_count = per_cpu.getCpuCount();
    if (cpu_count < 2) {
        serial.println("  ⚠ Skipping (single CPU system)", .{});
        return;
    }

    const initial_stats = ipi.getStats();
    const start_time = timer.readTSC();

    // Send burst of IPIs
    for (0..IPI_BURST_COUNT) |_| {
        // TLB shootdown to all CPUs
        ipi.tlbShootdownAll();

        // Targeted IPIs to each CPU
        for (1..cpu_count) |target| {
            ipi.requestReschedule(@intCast(target));
        }

        // Small delay between bursts
        timer.delayUs(10);
    }

    // Wait for IPIs to be processed
    timer.delayUs(1000);

    const elapsed_us = (timer.readTSC() - start_time) / timer.getCpuFrequencyMhz();
    const final_stats = ipi.getStats();

    var total_sent: u64 = 0;
    var total_received: u64 = 0;

    for (0..ipi.IPI_VECTOR_COUNT) |i| {
        total_sent += final_stats.sent[i] - initial_stats.sent[i];
        total_received += final_stats.received[i] - initial_stats.received[i];
    }

    serial.println("  IPIs sent: {}", .{total_sent});
    serial.println("  IPIs received: {}", .{total_received});
    serial.println("  Time: {} us", .{elapsed_us});
    serial.println("  Send rate: {} IPIs/sec", .{(total_sent * 1000000) / elapsed_us});

    // Allow some loss due to coalescing
    const loss_rate = if (total_sent > 0)
        @as(f32, @floatFromInt(total_sent - total_received)) / @as(f32, @floatFromInt(total_sent))
    else
        0;

    serial.println("  Loss rate: {d:.2}%", .{loss_rate * 100});

    if (loss_rate < 0.05) { // Allow up to 5% loss
        serial.println("  ✓ IPI flood test passed", .{});
    } else {
        serial.println("  ✗ IPI flood test failed (high loss rate)", .{});
    }
}

// Test 4: Cache coherency validation
pub fn stressCacheCoherency() !void {
    serial.println("\n[SMP STRESS] Testing cache coherency...", .{});

    const cpu_count = per_cpu.getCpuCount();
    if (cpu_count < 2) {
        serial.println("  ⚠ Skipping (single CPU system)", .{});
        return;
    }

    stress_errors.store(0, .seq_cst);

    // Test false sharing scenario
    const cacheWorker = struct {
        fn work(cpu_id: u32) void {
            const offset = (cpu_id % 8) * 8; // Each CPU writes to different 8-byte region

            for (0..STRESS_ITERATIONS) |i| {
                // Write pattern
                const pattern = @as(u64, cpu_id) << 32 | @as(u64, @truncate(i));
                const ptr = @as(*u64, @ptrCast(@alignCast(&cache_line_test[offset])));
                ptr.* = pattern;

                // Memory barrier to ensure write is visible
                asm volatile ("mfence" ::: "memory");

                // Read back and verify
                const read_val = ptr.*;
                if (read_val != pattern) {
                    _ = stress_errors.fetchAdd(1, .seq_cst);
                }

                // Add some work to stress cache coherency protocol
                var sum: u64 = 0;
                for (cache_line_test) |byte| {
                    sum += byte;
                }
                // Prevent optimization
                asm volatile (""
                    :
                    : [val] "r" (sum),
                    : "memory"
                );
            }
        }
    }.work;

    const start_time = timer.readTSC();

    // TODO: Run on all CPUs simultaneously
    cacheWorker(per_cpu.getCurrentCpuId());

    const elapsed_us = (timer.readTSC() - start_time) / timer.getCpuFrequencyMhz();
    const errors = stress_errors.load(.seq_cst);

    serial.println("  Iterations: {}", .{STRESS_ITERATIONS});
    serial.println("  Coherency errors: {}", .{errors});
    serial.println("  Time: {} us", .{elapsed_us});

    if (errors == 0) {
        serial.println("  ✓ Cache coherency test passed", .{});
    } else {
        serial.println("  ✗ Cache coherency test failed", .{});
    }
}

// Run all stress tests
pub fn runAll() !void {
    serial.println("\n=== SMP Stress Tests ===", .{});

    try stressMemoryAllocation();
    try stressLockContention();
    try stressIpiFlood();
    try stressCacheCoherency();

    serial.println("\n=== Stress Test Complete ===", .{});
}
