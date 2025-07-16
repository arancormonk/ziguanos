// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Counting semaphore implementation for kernel synchronization
// Allows controlled access to a resource with a specified count

const std = @import("std");
const barriers = @import("barriers.zig");
const spinlock = @import("spinlock.zig");
const interrupts = @import("../x86_64/interrupts.zig");

// Counting semaphore structure
pub const Semaphore = struct {
    // Current count of available resources
    count: i32,
    // Maximum count (for bounded semaphores)
    max_count: i32,
    // Lock protecting the count
    lock: spinlock.SpinLock,

    // Semaphore guard - automatically releases on scope exit
    pub const Guard = struct {
        sem: *Semaphore,

        pub fn deinit(self: Guard) void {
            self.sem.release();
        }
    };

    // Initialize a new semaphore with given initial and maximum count
    pub fn init(initial_count: i32, max_count: i32) Semaphore {
        std.debug.assert(initial_count >= 0);
        std.debug.assert(max_count > 0);
        std.debug.assert(initial_count <= max_count);

        return .{
            .count = initial_count,
            .max_count = max_count,
            .lock = spinlock.SpinLock{},
        };
    }

    // Initialize a binary semaphore (mutex-like, count 0 or 1)
    pub fn initBinary(initially_available: bool) Semaphore {
        return init(if (initially_available) 1 else 0, 1);
    }

    // Wait for the semaphore (P operation)
    // Decrements the count, blocks if count would go negative
    pub fn wait(self: *Semaphore) void {
        while (true) {
            const guard = self.lock.acquire();
            defer _ = guard;

            if (self.count > 0) {
                self.count -= 1;
                return;
            }

            // Release lock and spin
            _ = guard;
            barriers.spinLoopHint();
        }
    }

    // Try to wait for the semaphore without blocking
    // Returns true if acquired, false if would block
    pub fn tryWait(self: *Semaphore) bool {
        const guard = self.lock.acquire();
        defer _ = guard;

        if (self.count > 0) {
            self.count -= 1;
            return true;
        }

        return false;
    }

    // Wait with timeout (in microseconds)
    // Returns true if acquired, false if timed out
    pub fn timedWait(self: *Semaphore, timeout_us: u64) bool {
        const timer = @import("../x86_64/timer.zig");
        const start_time = timer.readUptime();
        const timeout_ns = timeout_us * 1000;

        while (true) {
            if (self.tryWait()) {
                return true;
            }

            // Check timeout
            const elapsed = timer.readUptime() - start_time;
            if (elapsed >= timeout_ns) {
                return false;
            }

            barriers.spinLoopHint();
        }
    }

    // Signal the semaphore (V operation)
    // Increments the count, potentially unblocking waiters
    pub fn signal(self: *Semaphore) void {
        const guard = self.lock.acquire();
        defer _ = guard;

        std.debug.assert(self.count < self.max_count); // Overflow check
        self.count += 1;
    }

    // Signal the semaphore, same as signal() for compatibility
    pub fn release(self: *Semaphore) void {
        self.signal();
    }

    // Try to signal the semaphore
    // Returns false if would exceed max_count
    pub fn trySignal(self: *Semaphore) bool {
        const guard = self.lock.acquire();
        defer _ = guard;

        if (self.count < self.max_count) {
            self.count += 1;
            return true;
        }

        return false;
    }

    // Get the current count (may change immediately after return)
    pub fn getCount(self: *Semaphore) i32 {
        const guard = self.lock.acquire();
        defer _ = guard;

        return self.count;
    }

    // Check if semaphore is available (count > 0)
    pub fn isAvailable(self: *Semaphore) bool {
        return self.getCount() > 0;
    }

    // Wait and return a guard that releases on scope exit
    pub fn acquire(self: *Semaphore) Guard {
        self.wait();
        return .{ .sem = self };
    }

    // Reset the semaphore to a new count
    // Dangerous - use only when no threads are waiting
    pub fn reset(self: *Semaphore, new_count: i32) void {
        std.debug.assert(new_count >= 0);
        std.debug.assert(new_count <= self.max_count);

        const guard = self.lock.acquire();
        defer _ = guard;

        self.count = new_count;
    }
};

// Barrier synchronization primitive
// Allows multiple threads to wait until all have reached a barrier point
pub const Barrier = struct {
    // Number of threads that must reach the barrier
    threshold: u32,
    // Current count of threads at the barrier
    count: u32,
    // Generation counter to handle reuse
    generation: u32,
    // Lock protecting the barrier state
    lock: spinlock.SpinLock,

    // Initialize a new barrier for the specified number of threads
    pub fn init(num_threads: u32) Barrier {
        std.debug.assert(num_threads > 0);

        return .{
            .threshold = num_threads,
            .count = 0,
            .generation = 0,
            .lock = spinlock.SpinLock{},
        };
    }

    // Wait at the barrier until all threads arrive
    // Returns true for exactly one thread (the last to arrive)
    pub fn wait(self: *Barrier) bool {
        const guard = self.lock.acquire();

        const my_generation = self.generation;
        self.count += 1;

        if (self.count >= self.threshold) {
            // Last thread to arrive
            self.count = 0;
            self.generation +%= 1;
            _ = guard; // Release lock
            return true;
        }

        // Not the last thread, wait for generation change
        _ = guard; // Release lock

        while (@atomicLoad(u32, &self.generation, .acquire) == my_generation) {
            barriers.spinLoopHint();
        }

        return false;
    }

    // Reset the barrier (dangerous if threads are waiting)
    pub fn reset(self: *Barrier) void {
        const guard = self.lock.acquire();
        defer _ = guard;

        self.count = 0;
        self.generation +%= 1;
    }

    // Get the number of threads currently waiting
    pub fn getWaitingCount(self: *Barrier) u32 {
        const guard = self.lock.acquire();
        defer _ = guard;

        return self.count;
    }
};

// Test utilities
pub const testing = struct {
    // Test basic semaphore operations
    pub fn testSemaphore() !void {
        // Test counting semaphore
        var sem = Semaphore.init(3, 5);

        // Should be able to acquire 3 times
        try std.testing.expect(sem.tryWait());
        try std.testing.expect(sem.tryWait());
        try std.testing.expect(sem.tryWait());

        // Fourth should fail
        try std.testing.expect(!sem.tryWait());

        // Release one
        sem.signal();

        // Should be able to acquire again
        try std.testing.expect(sem.tryWait());

        // Test with guard
        {
            const guard = sem.acquire();
            defer _ = guard;
            // Semaphore is held
        }
        // Automatically released

        // Test binary semaphore
        var binary = Semaphore.initBinary(true);
        try std.testing.expect(binary.tryWait());
        try std.testing.expect(!binary.tryWait());
        binary.signal();
        try std.testing.expect(binary.tryWait());
    }

    // Test barrier synchronization
    pub fn testBarrier() !void {
        var barrier = Barrier.init(3);

        // Simulate 3 threads arriving
        try std.testing.expect(!barrier.wait()); // First
        try std.testing.expect(!barrier.wait()); // Second
        try std.testing.expect(barrier.wait()); // Third (last)

        // Barrier should be reset for next use
        try std.testing.expect(barrier.getWaitingCount() == 0);
    }
};
