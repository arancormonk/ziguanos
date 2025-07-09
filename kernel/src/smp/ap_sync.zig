// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// SMP synchronization primitives for AP startup
// This module provides synchronization mechanisms to prevent race conditions
// during Application Processor initialization

const std = @import("std");
const spinlock = @import("../lib/spinlock.zig");

/// Global BSP protection lock
/// Used to ensure BSP doesn't experience faults during SIPI operations
pub var bsp_protection_lock = spinlock.SpinLock{};

/// AP startup synchronization barrier
/// Ensures APs wait before accessing shared resources
pub const ApBarrier = struct {
    /// Number of APs that need to reach the barrier
    expected_count: u32,
    /// Current count of APs at the barrier
    current_count: u32,
    /// Lock protecting the barrier state
    lock: spinlock.SpinLock,
    /// Signal to proceed past the barrier
    proceed: bool,

    pub fn init(expected_aps: u32) ApBarrier {
        return .{
            .expected_count = expected_aps,
            .current_count = 0,
            .lock = spinlock.SpinLock{},
            .proceed = false,
        };
    }

    /// Wait at the barrier until all APs arrive or timeout
    pub fn wait(self: *ApBarrier, timeout_cycles: u64) bool {
        // Increment count atomically
        {
            const flags = self.lock.acquire();
            defer self.lock.release(flags);
            self.current_count += 1;
        }

        // Wait for all APs to arrive or for proceed signal
        var cycles: u64 = 0;
        while (cycles < timeout_cycles) : (cycles += 1) {
            // Check if we can proceed
            const flags = self.lock.acquire();
            const can_proceed = self.proceed or (self.current_count >= self.expected_count);
            self.lock.release(flags);

            if (can_proceed) {
                return true;
            }

            // Pause to reduce bus contention
            asm volatile ("pause" ::: "memory");
        }

        return false; // Timeout
    }

    /// Signal all waiting APs to proceed
    pub fn release(self: *ApBarrier) void {
        const flags = self.lock.acquire();
        defer self.lock.release(flags);
        self.proceed = true;
    }

    /// Reset the barrier for reuse
    pub fn reset(self: *ApBarrier) void {
        const flags = self.lock.acquire();
        defer self.lock.release(flags);
        self.current_count = 0;
        self.proceed = false;
    }
};

/// Memory barrier to ensure all memory operations are visible
pub inline fn memoryBarrier() void {
    asm volatile ("mfence" ::: "memory");
}

/// Read barrier to ensure all reads complete before subsequent operations
pub inline fn readBarrier() void {
    asm volatile ("lfence" ::: "memory");
}

/// Write barrier to ensure all writes complete before subsequent operations
pub inline fn writeBarrier() void {
    asm volatile ("sfence" ::: "memory");
}

/// Full serializing barrier (stronger than memory barrier)
pub inline fn serializingBarrier() void {
    // CPUID is a serializing instruction
    asm volatile ("cpuid" ::: "eax", "ebx", "ecx", "edx", "memory");
}

/// Delay function for AP startup synchronization
/// Uses PAUSE instruction to reduce power consumption and bus contention
pub fn apStartupDelay(iterations: u32) void {
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        asm volatile ("pause" ::: "memory");
    }
}

/// Protected SIPI operation wrapper
/// Ensures BSP stability during SIPI transmission
pub fn protectedSipiOperation(comptime T: type, operation: fn () T) T {
    // Ensure all memory operations are complete
    memoryBarrier();

    // Acquire BSP protection lock
    const flags = bsp_protection_lock.acquire();
    defer bsp_protection_lock.release(flags);

    // Ensure instruction cache coherency
    serializingBarrier();

    // Perform the SIPI operation
    const result = operation();

    // Ensure operation completes
    memoryBarrier();

    return result;
}
