// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const per_cpu = @import("per_cpu.zig");
const apic_unified = @import("../x86_64/apic_unified.zig");
const spinlock = @import("../lib/spinlock.zig");
const serial = @import("../drivers/serial.zig");
const timer = @import("../x86_64/timer.zig");

/// IPI vector for remote function calls
pub const CALL_FUNCTION_VECTOR: u8 = 0xF2;

/// Maximum number of pending function calls per CPU
const MAX_PENDING_CALLS = 16;

/// Function call request structure
pub const CallRequest = struct {
    func: *const fn () void,
    requester_cpu: u32,
    completed: bool,
    has_error: bool,
};

/// Per-CPU function call queue
pub const CallQueue = struct {
    requests: [MAX_PENDING_CALLS]CallRequest,
    head: u32,
    tail: u32,
    lock: spinlock.SpinLock,

    pub fn init() CallQueue {
        return .{
            .requests = [_]CallRequest{.{
                .func = undefined,
                .requester_cpu = 0,
                .completed = true,
                .has_error = false,
            }} ** MAX_PENDING_CALLS,
            .head = 0,
            .tail = 0,
            .lock = spinlock.SpinLock{},
        };
    }

    /// Add a function call request to the queue
    /// Returns a pointer to the enqueued request
    pub fn enqueue(self: *CallQueue, request: CallRequest) !*CallRequest {
        const guard = self.lock.acquire();
        defer _ = guard;

        const next_tail = (self.tail + 1) % MAX_PENDING_CALLS;
        if (next_tail == self.head) {
            return error.QueueFull;
        }

        self.requests[self.tail] = request;
        const request_ptr = &self.requests[self.tail];
        self.tail = next_tail;
        return request_ptr;
    }

    /// Get the next function call request
    pub fn dequeue(self: *CallQueue) ?*CallRequest {
        const guard = self.lock.acquire();
        defer _ = guard;

        if (self.head == self.tail) {
            return null;
        }

        const request = &self.requests[self.head];
        self.head = (self.head + 1) % MAX_PENDING_CALLS;
        return request;
    }
};

/// Per-CPU call queues
var call_queues: [per_cpu.MAX_CPUS]CallQueue = [_]CallQueue{CallQueue.init()} ** per_cpu.MAX_CPUS;

/// Statistics for function calls
pub var stats = struct {
    calls_sent: u64 = 0,
    calls_completed: u64 = 0,
    calls_failed: u64 = 0,
    timeouts: u64 = 0,
}{};

/// Initialize the call function infrastructure
pub fn init() void {
    // Reset all queues
    for (&call_queues) |*queue| {
        queue.* = CallQueue.init();
    }

    serial.println("[IPI] Call function infrastructure initialized", .{});
}

/// Call a function on a specific CPU
pub fn callFunctionSingle(cpu_id: u32, func: *const fn () void) !void {
    // Validate CPU ID
    if (cpu_id >= per_cpu.getCpuCount()) {
        return error.InvalidCpu;
    }

    // Get current CPU ID
    const current_cpu = per_cpu.getCurrentCpuId();

    // If targeting current CPU, just call directly
    if (cpu_id == current_cpu) {
        func();
        return;
    }

    // Get target CPU data
    const target_cpu_data = per_cpu.getCpuById(cpu_id) orelse return error.InvalidCpu;

    // Create request
    const request = CallRequest{
        .func = func,
        .requester_cpu = current_cpu,
        .completed = false,
        .has_error = false,
    };

    // Enqueue request and get pointer to it
    const request_ptr = try call_queues[cpu_id].enqueue(request);

    // Set IPI pending bit
    const old_pending = @atomicRmw(u32, &target_cpu_data.ipi_pending, .Or, 1 << 2, .acq_rel);

    // Send IPI if not already pending
    if ((old_pending & (1 << 2)) == 0) {
        apic_unified.sendIPI(@intCast(target_cpu_data.apic_id), CALL_FUNCTION_VECTOR, .Fixed, .NoShorthand);
    }

    // Update statistics
    _ = @atomicRmw(u64, &stats.calls_sent, .Add, 1, .monotonic);

    // Wait for completion with timeout (100ms)
    const timeout_ms: u64 = 100;
    const start_time = timer.readUptime();

    while (!@atomicLoad(bool, &request_ptr.completed, .acquire)) {
        // Check timeout
        const elapsed = timer.readUptime() - start_time;
        if (elapsed > timeout_ms * 1_000_000) { // Convert to nanoseconds
            _ = @atomicRmw(u64, &stats.timeouts, .Add, 1, .monotonic);
            return error.Timeout;
        }

        // Pause to reduce bus traffic
        asm volatile ("pause" ::: "memory");
    }

    // Check for error
    if (request_ptr.has_error) {
        _ = @atomicRmw(u64, &stats.calls_failed, .Add, 1, .monotonic);
        return error.RemoteExecutionFailed;
    }

    _ = @atomicRmw(u64, &stats.calls_completed, .Add, 1, .monotonic);
}

/// Call a function on all CPUs except the current one
pub fn callFunctionAll(func: *const fn () void) !void {
    const current_cpu = per_cpu.getCurrentCpuId();
    const cpu_count = per_cpu.getCpuCount();

    // Track pending requests
    var pending_requests: [per_cpu.MAX_CPUS]?*CallRequest = [_]?*CallRequest{null} ** per_cpu.MAX_CPUS;
    var pending_count: u32 = 0;

    // Queue requests for all other CPUs
    for (0..cpu_count) |cpu_id| {
        if (cpu_id == current_cpu) continue;

        const target_cpu_data = per_cpu.getCpuById(@intCast(cpu_id)) orelse continue;

        // Create request
        const request = CallRequest{
            .func = func,
            .requester_cpu = current_cpu,
            .completed = false,
            .has_error = false,
        };

        // Try to enqueue
        const request_ptr = call_queues[cpu_id].enqueue(request) catch |err| {
            serial.println("[IPI] Failed to enqueue call for CPU {}: {}", .{ cpu_id, err });
            continue;
        };

        pending_requests[cpu_id] = request_ptr;
        pending_count += 1;

        // Set IPI pending bit
        const old_pending = @atomicRmw(u32, &target_cpu_data.ipi_pending, .Or, 1 << 2, .acq_rel);

        // Send IPI if not already pending
        if ((old_pending & (1 << 2)) == 0) {
            apic_unified.sendIPI(@intCast(target_cpu_data.apic_id), CALL_FUNCTION_VECTOR, .Fixed, .NoShorthand);
        }
    }

    // Update statistics
    _ = @atomicRmw(u64, &stats.calls_sent, .Add, pending_count, .monotonic);

    // Wait for all to complete with timeout
    const timeout_ms: u64 = 200; // Longer timeout for broadcast
    const start_time = timer.readUptime();
    var completed_count: u32 = 0;

    while (completed_count < pending_count) {
        // Check timeout
        const elapsed = timer.readUptime() - start_time;
        if (elapsed > timeout_ms * 1_000_000) {
            _ = @atomicRmw(u64, &stats.timeouts, .Add, pending_count - completed_count, .monotonic);
            return error.Timeout;
        }

        // Check each pending request
        completed_count = 0;
        for (0..cpu_count) |cpu_id| {
            if (pending_requests[cpu_id]) |request| {
                if (@atomicLoad(bool, &request.completed, .acquire)) {
                    completed_count += 1;

                    // Check for error
                    if (request.has_error) {
                        _ = @atomicRmw(u64, &stats.calls_failed, .Add, 1, .monotonic);
                    } else {
                        _ = @atomicRmw(u64, &stats.calls_completed, .Add, 1, .monotonic);
                    }
                }
            }
        }

        // Pause between checks
        asm volatile ("pause" ::: "memory");
    }
}

/// Process pending function calls on the current CPU
pub fn processPendingCalls() void {
    const cpu_id = per_cpu.getCurrentCpuId();
    var queue = &call_queues[cpu_id];

    // Process all pending calls
    while (queue.dequeue()) |request| {
        // Execute the function with error handling
        const saved_cr0 = asm volatile ("mov %%cr0, %[ret]"
            : [ret] "=r" (-> u64),
        );

        // Try to execute the function
        request.func();

        // Verify CR0 wasn't corrupted
        const current_cr0 = asm volatile ("mov %%cr0, %[ret]"
            : [ret] "=r" (-> u64),
        );

        if (current_cr0 != saved_cr0) {
            request.has_error = true;
            serial.println("[IPI] WARNING: Function call corrupted CR0!", .{});
        }

        // Mark as completed
        @atomicStore(bool, &request.completed, true, .release);
    }
}

/// Get call function statistics
pub fn getStats() @TypeOf(stats) {
    return .{
        .calls_sent = @atomicLoad(u64, &stats.calls_sent, .monotonic),
        .calls_completed = @atomicLoad(u64, &stats.calls_completed, .monotonic),
        .calls_failed = @atomicLoad(u64, &stats.calls_failed, .monotonic),
        .timeouts = @atomicLoad(u64, &stats.timeouts, .monotonic),
    };
}
