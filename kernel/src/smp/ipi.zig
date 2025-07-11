// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const apic_unified = @import("../x86_64/apic_unified.zig");
const interrupts = @import("../x86_64/interrupts.zig");
const per_cpu = @import("per_cpu.zig");
const serial = @import("../drivers/serial.zig");
const call_function = @import("call_function.zig");

// IPI vector allocation (0xF0-0xFF range as per Intel recommendations)
pub const IPI_VECTOR_BASE = 0xF0;
pub const IPI_TLB_SHOOTDOWN = IPI_VECTOR_BASE + 0;
pub const IPI_RESCHEDULE = IPI_VECTOR_BASE + 1;
pub const IPI_CALL_FUNCTION = IPI_VECTOR_BASE + 2;
pub const IPI_PANIC = IPI_VECTOR_BASE + 3;
pub const IPI_VECTOR_COUNT = 4;

// IPI handler function type
pub const IpiHandler = fn () void;

// IPI statistics
var ipi_stats = struct {
    sent: [IPI_VECTOR_COUNT]u64 = [_]u64{0} ** IPI_VECTOR_COUNT,
    received: [IPI_VECTOR_COUNT]u64 = [_]u64{0} ** IPI_VECTOR_COUNT,
}{};

// Initialize IPI infrastructure
pub fn init() void {
    // Install IPI handlers
    interrupts.registerHandler(IPI_TLB_SHOOTDOWN, handleTlbShootdown);
    interrupts.registerHandler(IPI_RESCHEDULE, handleReschedule);
    interrupts.registerHandler(IPI_CALL_FUNCTION, handleCallFunction);
    interrupts.registerHandler(IPI_PANIC, handlePanic);

    serial.println("IPI: Initialized vectors 0x{x:0>2}-0x{x:0>2}", .{ IPI_VECTOR_BASE, IPI_VECTOR_BASE + IPI_VECTOR_COUNT - 1 });
}

// Send IPI to specific CPU
pub fn sendTo(target_cpu: u32, vector: u8) void {
    if (vector < IPI_VECTOR_BASE or vector >= IPI_VECTOR_BASE + IPI_VECTOR_COUNT) {
        @panic("Invalid IPI vector");
    }

    const vector_idx = vector - IPI_VECTOR_BASE;
    _ = @atomicRmw(u64, &ipi_stats.sent[vector_idx], .Add, 1, .monotonic);

    // Get target APIC ID
    const cpu_data = per_cpu.getCpuData(target_cpu) orelse {
        serial.println("IPI: Invalid target CPU", .{});
        return;
    };

    // Send IPI via unified APIC interface
    apic_unified.sendIPI(cpu_data.apic_id, vector, .Fixed, .NoShorthand);
}

// Send IPI to all CPUs except self
pub fn sendToAllButSelf(vector: u8) void {
    if (vector < IPI_VECTOR_BASE or vector >= IPI_VECTOR_BASE + IPI_VECTOR_COUNT) {
        @panic("Invalid IPI vector");
    }

    const vector_idx = vector - IPI_VECTOR_BASE;
    const cpu_count = per_cpu.getCpuCount();

    // Update stats
    _ = @atomicRmw(u64, &ipi_stats.sent[vector_idx], .Add, cpu_count - 1, .monotonic);

    // Send to all other CPUs
    apic_unified.sendIPI(0, vector, .Fixed, .AllExcludingSelf);
}

// Send IPI to all CPUs including self
pub fn sendToAll(vector: u8) void {
    if (vector < IPI_VECTOR_BASE or vector >= IPI_VECTOR_BASE + IPI_VECTOR_COUNT) {
        @panic("Invalid IPI vector");
    }

    const vector_idx = vector - IPI_VECTOR_BASE;
    const cpu_count = per_cpu.getCpuCount();

    // Update stats
    _ = @atomicRmw(u64, &ipi_stats.sent[vector_idx], .Add, cpu_count, .monotonic);

    // Send to all CPUs
    apic_unified.sendIPI(0, vector, .Fixed, .All);
}

// TLB shootdown handler
fn handleTlbShootdown(frame: *interrupts.InterruptFrame) void {
    _ = frame; // Unused
    _ = @atomicRmw(u64, &ipi_stats.received[0], .Add, 1, .monotonic);

    // Flush TLB
    asm volatile ("mov %%cr3, %%rax; mov %%rax, %%cr3" ::: "rax", "memory");

    // Send EOI
    apic_unified.sendEOI();
}

// Reschedule handler
fn handleReschedule(frame: *interrupts.InterruptFrame) void {
    _ = frame;
    _ = @atomicRmw(u64, &ipi_stats.received[1], .Add, 1, .monotonic);

    // TODO: Trigger scheduler when implemented

    // Send EOI
    apic_unified.sendEOI();
}

// Call function handler
fn handleCallFunction(frame: *interrupts.InterruptFrame) void {
    _ = frame;
    _ = @atomicRmw(u64, &ipi_stats.received[2], .Add, 1, .monotonic);

    // Process all pending function calls from the queue
    call_function.processPendingCalls();

    // Send EOI
    apic_unified.sendEOI();
}

// Panic handler - stop this CPU
fn handlePanic(frame: *interrupts.InterruptFrame) void {
    _ = frame;
    _ = @atomicRmw(u64, &ipi_stats.received[3], .Add, 1, .monotonic);

    // Disable interrupts and halt
    asm volatile ("cli");

    serial.println("CPU {}: Received panic IPI, halting", .{per_cpu.getCurrentCpuId()});

    while (true) {
        asm volatile ("hlt");
    }
}

// TLB shootdown for specific address
pub fn tlbShootdown(addr: u64) void {
    // Send IPI to all other CPUs
    sendToAllButSelf(IPI_TLB_SHOOTDOWN);

    // Flush our own TLB for this address
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (addr),
        : "memory"
    );
}

// TLB shootdown for entire TLB
pub fn tlbShootdownAll() void {
    // Send IPI to all other CPUs
    sendToAllButSelf(IPI_TLB_SHOOTDOWN);

    // Flush our own TLB
    asm volatile ("mov %%cr3, %%rax; mov %%rax, %%cr3" ::: "rax", "memory");
}

// Request reschedule on target CPU
pub fn requestReschedule(target_cpu: u32) void {
    sendTo(target_cpu, IPI_RESCHEDULE);
}

// Call function on target CPU (deprecated - use call_function module directly)
pub fn callFunction(target_cpu: u32, func: *const fn () void) void {
    // Forward to the proper call_function module
    call_function.callFunctionSingle(target_cpu, func) catch |err| {
        serial.println("IPI: Failed to call function on CPU {}: {}", .{ target_cpu, err });
    };
}

// Broadcast panic to all CPUs
pub fn broadcastPanic() void {
    sendToAllButSelf(IPI_PANIC);
}

// Get IPI statistics
pub fn getStats() struct {
    sent: [IPI_VECTOR_COUNT]u64,
    received: [IPI_VECTOR_COUNT]u64,
} {
    return .{
        .sent = ipi_stats.sent,
        .received = ipi_stats.received,
    };
}
