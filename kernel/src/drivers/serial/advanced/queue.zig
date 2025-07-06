// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Enhanced queue management for serial driver
// This module provides advanced per-CPU queuing without dependencies on stack security

const std = @import("std");

// Enhanced queue configuration
const QUEUE_SIZE = 4096;
const RECEIVE_BUFFER_SIZE = 2048;
const MAX_CPUS = 64;

/// Enhanced per-CPU queue with better performance characteristics
pub const PerCpuQueue = struct {
    buffer: [QUEUE_SIZE]u8 = [_]u8{0} ** QUEUE_SIZE,
    head: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    tail: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    pub fn init() PerCpuQueue {
        return .{};
    }

    pub fn enqueue(self: *PerCpuQueue, data: []const u8) !usize {
        const head = self.head.load(.monotonic);
        var tail = self.tail.load(.acquire);
        var written: usize = 0;

        for (data) |byte| {
            const next_tail = (tail + 1) % QUEUE_SIZE;
            if (next_tail == head) {
                break; // Queue full
            }
            self.buffer[tail] = byte;
            tail = next_tail;
            written += 1;
        }

        if (written > 0) {
            self.tail.store(tail, .release);
        }
        return written;
    }

    pub fn dequeue(self: *PerCpuQueue, buffer: []u8) usize {
        var head = self.head.load(.acquire);
        const tail = self.tail.load(.monotonic);
        var read: usize = 0;

        while (head != tail and read < buffer.len) {
            buffer[read] = self.buffer[head];
            head = (head + 1) % QUEUE_SIZE;
            read += 1;
        }

        if (read > 0) {
            self.head.store(head, .release);
        }
        return read;
    }

    pub fn isEmpty(self: *const PerCpuQueue) bool {
        return self.head.load(.acquire) == self.tail.load(.acquire);
    }

    pub fn isFull(self: *const PerCpuQueue) bool {
        const head = self.head.load(.acquire);
        const tail = self.tail.load(.acquire);
        return ((tail + 1) % QUEUE_SIZE) == head;
    }

    pub fn getAvailableSpace(self: *const PerCpuQueue) usize {
        const head = self.head.load(.acquire);
        const tail = self.tail.load(.acquire);
        if (tail >= head) {
            return QUEUE_SIZE - (tail - head) - 1;
        } else {
            return head - tail - 1;
        }
    }
};

/// Enhanced queue manager with optional dependencies
pub const QueueManager = struct {
    cpu_queues: [MAX_CPUS]PerCpuQueue,
    num_cpus: u32,
    global_queue: PerCpuQueue,
    global_queue_lock: std.atomic.Value(bool),

    // Receive buffer for interrupt-driven receive
    receive_buffer: [RECEIVE_BUFFER_SIZE]u8,
    receive_head: std.atomic.Value(usize),
    receive_tail: std.atomic.Value(usize),

    pub fn init() QueueManager {
        return .{
            .cpu_queues = init: {
                @setEvalBranchQuota(10000);
                var queues: [MAX_CPUS]PerCpuQueue = undefined;
                for (&queues) |*queue| {
                    queue.* = PerCpuQueue.init();
                }
                break :init queues;
            },
            .num_cpus = 1,
            .global_queue = PerCpuQueue.init(),
            .global_queue_lock = std.atomic.Value(bool).init(false),
            .receive_buffer = [_]u8{0} ** RECEIVE_BUFFER_SIZE,
            .receive_head = std.atomic.Value(usize).init(0),
            .receive_tail = std.atomic.Value(usize).init(0),
        };
    }

    pub fn setNumCpus(self: *QueueManager, num: u32) void {
        self.num_cpus = @min(num, MAX_CPUS);
    }

    pub fn getCurrentCPU(self: *const QueueManager) u32 {
        // Simple CPU ID based on CPUID
        var eax: u32 = undefined;
        var ebx: u32 = undefined;
        var ecx: u32 = undefined;
        var edx: u32 = undefined;

        asm volatile ("cpuid"
            : [eax] "={eax}" (eax),
              [ebx] "={ebx}" (ebx),
              [ecx] "={ecx}" (ecx),
              [edx] "={edx}" (edx),
            : [leaf] "{eax}" (@as(u32, 1)),
              [subleaf] "{ecx}" (@as(u32, 0)),
        );

        const apic_id = (ebx >> 24) & 0xFF;
        return @min(apic_id, self.num_cpus - 1);
    }

    pub fn getCurrentQueue(self: *QueueManager) *PerCpuQueue {
        const cpu = self.getCurrentCPU();
        if (cpu < self.num_cpus) {
            return &self.cpu_queues[cpu];
        }
        return &self.global_queue;
    }

    pub fn acquireGlobalLock(self: *QueueManager) bool {
        const flags = asm volatile (
            \\pushfq
            \\popq %[flags]
            \\cli
            : [flags] "=r" (-> u64),
        );

        while (self.global_queue_lock.swap(true, .acquire)) {
            asm volatile ("pause");
        }

        return (flags & 0x200) != 0;
    }

    pub fn releaseGlobalLock(self: *QueueManager, restore_interrupts: bool) void {
        self.global_queue_lock.store(false, .release);

        if (restore_interrupts) {
            asm volatile ("sti");
        }
    }

    pub fn enqueueReceive(self: *QueueManager, data: []const u8) usize {
        const head = self.receive_head.load(.monotonic);
        var tail = self.receive_tail.load(.acquire);
        var written: usize = 0;

        for (data) |byte| {
            const next_tail = (tail + 1) % RECEIVE_BUFFER_SIZE;
            if (next_tail == head) {
                break;
            }
            self.receive_buffer[tail] = byte;
            tail = next_tail;
            written += 1;
        }

        if (written > 0) {
            self.receive_tail.store(tail, .release);
        }
        return written;
    }

    pub fn dequeueReceive(self: *QueueManager, buffer: []u8) usize {
        var head = self.receive_head.load(.acquire);
        const tail = self.receive_tail.load(.monotonic);
        var read: usize = 0;

        while (head != tail and read < buffer.len) {
            buffer[read] = self.receive_buffer[head];
            head = (head + 1) % RECEIVE_BUFFER_SIZE;
            read += 1;
        }

        if (read > 0) {
            self.receive_head.store(head, .release);
        }
        return read;
    }

    pub fn isReceiveEmpty(self: *const QueueManager) bool {
        return self.receive_head.load(.acquire) == self.receive_tail.load(.acquire);
    }
};
