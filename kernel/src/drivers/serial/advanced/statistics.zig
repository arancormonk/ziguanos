// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Enhanced statistics tracking for serial driver
// This module provides statistics without external dependencies

const std = @import("std");

pub const Statistics = struct {
    // Core metrics
    bytes_written: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    bytes_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    messages_sent: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // Error counters
    queue_overflows: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    transmit_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    fifo_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    receive_errors: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    init_failures: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    // Interrupt statistics
    interrupts_handled: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    spurious_interrupts: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // Performance metrics
    total_wait_time_us: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    max_wait_time_us: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    // Error recovery
    last_error_time: u64 = 0,
    consecutive_errors: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub fn init() Statistics {
        return .{};
    }

    pub fn reset(self: *Statistics) void {
        self.bytes_written.store(0, .monotonic);
        self.bytes_received.store(0, .monotonic);
        self.messages_sent.store(0, .monotonic);
        self.queue_overflows.store(0, .monotonic);
        self.transmit_errors.store(0, .monotonic);
        self.fifo_errors.store(0, .monotonic);
        self.receive_errors.store(0, .monotonic);
        self.init_failures.store(0, .monotonic);
        self.interrupts_handled.store(0, .monotonic);
        self.spurious_interrupts.store(0, .monotonic);
        self.total_wait_time_us.store(0, .monotonic);
        self.max_wait_time_us.store(0, .monotonic);
        self.last_error_time = 0;
        self.consecutive_errors.store(0, .release);
    }

    pub fn incrementBytesWritten(self: *Statistics, count: u64) void {
        _ = self.bytes_written.fetchAdd(count, .monotonic);
    }

    pub fn incrementBytesReceived(self: *Statistics, count: u64) void {
        _ = self.bytes_received.fetchAdd(count, .monotonic);
    }

    pub fn incrementMessagesSent(self: *Statistics) void {
        _ = self.messages_sent.fetchAdd(1, .monotonic);
    }

    pub fn incrementQueueOverflows(self: *Statistics) void {
        _ = self.queue_overflows.fetchAdd(1, .monotonic);
    }

    pub fn incrementTransmitErrors(self: *Statistics) void {
        _ = self.transmit_errors.fetchAdd(1, .monotonic);
    }

    pub fn incrementFifoErrors(self: *Statistics) void {
        _ = self.fifo_errors.fetchAdd(1, .monotonic);
    }

    pub fn incrementReceiveErrors(self: *Statistics) void {
        _ = self.receive_errors.fetchAdd(1, .monotonic);
    }

    pub fn incrementInitFailures(self: *Statistics) void {
        _ = self.init_failures.fetchAdd(1, .monotonic);
    }

    pub fn incrementInterruptsHandled(self: *Statistics) void {
        _ = self.interrupts_handled.fetchAdd(1, .monotonic);
    }

    pub fn incrementSpuriousInterrupts(self: *Statistics) void {
        _ = self.spurious_interrupts.fetchAdd(1, .monotonic);
    }

    pub fn updateWaitTime(self: *Statistics, wait_time_us: u64) void {
        _ = self.total_wait_time_us.fetchAdd(wait_time_us, .monotonic);

        // Update max wait time
        var current_max = self.max_wait_time_us.load(.acquire);
        while (wait_time_us > current_max) {
            const old_value = self.max_wait_time_us.cmpxchgWeak(current_max, wait_time_us, .release, .acquire) orelse break; // Success

            current_max = old_value; // Failed, retry with returned value
        }
    }

    pub fn recordError(self: *Statistics, current_time: u64) void {
        self.last_error_time = current_time;
        _ = self.consecutive_errors.fetchAdd(1, .monotonic);
    }

    pub fn clearConsecutiveErrors(self: *Statistics) void {
        self.consecutive_errors.store(0, .release);
    }

    pub fn getConsecutiveErrors(self: *const Statistics) u32 {
        return self.consecutive_errors.load(.acquire);
    }

    pub fn formatStats(self: *const Statistics, writer: anytype) !void {
        const bytes_written = self.bytes_written.load(.acquire);
        const bytes_received = self.bytes_received.load(.acquire);
        const messages_sent = self.messages_sent.load(.acquire);
        const queue_overflows = self.queue_overflows.load(.acquire);
        const transmit_errors = self.transmit_errors.load(.acquire);
        const fifo_errors = self.fifo_errors.load(.acquire);
        const receive_errors = self.receive_errors.load(.acquire);
        const interrupts_handled = self.interrupts_handled.load(.acquire);
        const spurious_interrupts = self.spurious_interrupts.load(.acquire);
        const total_wait_time = self.total_wait_time_us.load(.acquire);
        const max_wait_time = self.max_wait_time_us.load(.acquire);

        try writer.print("\n=== Serial Driver Statistics ===\n", .{});
        try writer.print("Bytes written:      {d}\n", .{bytes_written});
        try writer.print("Bytes received:     {d}\n", .{bytes_received});
        try writer.print("Messages sent:      {d}\n", .{messages_sent});

        try writer.print("\n--- Errors ---\n", .{});
        try writer.print("Queue overflows:    {d}\n", .{queue_overflows});
        try writer.print("Transmit errors:    {d}\n", .{transmit_errors});
        try writer.print("FIFO errors:        {d}\n", .{fifo_errors});
        try writer.print("Receive errors:     {d}\n", .{receive_errors});

        try writer.print("\n--- Interrupts ---\n", .{});
        try writer.print("Interrupts handled: {d}\n", .{interrupts_handled});
        try writer.print("Spurious interrupts: {d}\n", .{spurious_interrupts});

        try writer.print("\n--- Performance ---\n", .{});
        if (messages_sent > 0) {
            const avg_wait_time = total_wait_time / messages_sent;
            try writer.print("Avg wait time:      {d}us\n", .{avg_wait_time});
        }
        try writer.print("Max wait time:      {d}us\n", .{max_wait_time});

        if (bytes_written > 0) {
            const efficiency = ((bytes_written - queue_overflows) * 100) / bytes_written;
            try writer.print("Queue efficiency:   {d}%\n", .{efficiency});
        }

        try writer.print("================================\n", .{});
    }
};
