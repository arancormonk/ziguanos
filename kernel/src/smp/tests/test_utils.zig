// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const spinlock = @import("../../lib/spinlock.zig");
const serial = @import("../../drivers/serial.zig");

// Generic barrier for test synchronization
pub const Barrier = struct {
    count: u32,
    generation: u32,
    total_cpus: u32,
    lock: spinlock.SpinLock,

    pub fn init(total_cpus: u32) Barrier {
        return .{
            .count = 0,
            .generation = 0,
            .total_cpus = total_cpus,
            .lock = spinlock.SpinLock{},
        };
    }

    pub fn wait(self: *Barrier) !void {
        const guard = self.lock.acquire();
        defer _ = guard;

        const my_generation = self.generation;
        self.count += 1;

        if (self.count >= self.total_cpus) {
            // Last CPU to arrive, reset for next use
            self.count = 0;
            self.generation += 1;
            return;
        }

        // Release lock and wait for generation change
        _ = guard;

        // Spin wait for generation change
        while (@atomicLoad(u32, &self.generation, .acquire) == my_generation) {
            asm volatile ("pause" ::: "memory");
        }
    }
};

// Test function wrapper for remote execution
pub const TestFunction = struct {
    func: *const fn (*anyopaque) void,
    data: *anyopaque,

    pub fn init(func: *const fn (*anyopaque) void, data: *anyopaque) TestFunction {
        return .{
            .func = func,
            .data = data,
        };
    }

    pub fn execute(self: *const TestFunction) void {
        self.func(self.data);
    }
};

// Per-CPU test context
pub const TestContext = struct {
    cpu_id: u32,
    barrier: *Barrier,
    shared_data: *anyopaque,
    error_count: u32,

    pub fn init(cpu_id: u32, barrier: *Barrier, shared_data: *anyopaque) TestContext {
        return .{
            .cpu_id = cpu_id,
            .barrier = barrier,
            .shared_data = shared_data,
            .error_count = 0,
        };
    }
};
