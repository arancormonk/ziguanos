// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const per_cpu = @import("per_cpu.zig");
const heap = @import("../memory/heap.zig");
const spinlock = @import("../lib/spinlock.zig");
const cpu_init = @import("../x86_64/cpu_init.zig");

// Per-CPU variable descriptor
pub const PerCpuVar = struct {
    name: []const u8,
    size: usize,
    alignment: usize,
    offset: usize,
};

// Maximum number of per-CPU variables
const MAX_PER_CPU_VARS = 128;

// Registry of per-CPU variables
var per_cpu_vars: [MAX_PER_CPU_VARS]PerCpuVar = undefined;
var per_cpu_var_count: usize = 0;
var per_cpu_lock = spinlock.SpinLock{};

// Per-CPU data area for each CPU
var per_cpu_data_areas: [per_cpu.MAX_CPUS]?[*]u8 = undefined;
var per_cpu_data_size: usize = 0;

// Register a new per-CPU variable
pub fn registerPerCpuVar(name: []const u8, size: usize, alignment: usize) !usize {
    const flags = per_cpu_lock.acquire();
    defer per_cpu_lock.release(flags);

    if (per_cpu_var_count >= MAX_PER_CPU_VARS) {
        return error.TooManyPerCpuVars;
    }

    // Align offset
    const aligned_offset = (per_cpu_data_size + alignment - 1) & ~(alignment - 1);

    per_cpu_vars[per_cpu_var_count] = PerCpuVar{
        .name = name,
        .size = size,
        .alignment = alignment,
        .offset = aligned_offset,
    };

    per_cpu_var_count += 1;
    per_cpu_data_size = aligned_offset + size;

    return aligned_offset;
}

// Allocate per-CPU data area for a CPU
pub fn allocatePerCpuData(cpu_id: u32) !void {
    if (cpu_id >= per_cpu.MAX_CPUS) {
        return error.InvalidCpuId;
    }

    if (per_cpu_data_size == 0) {
        // No per-CPU variables registered
        per_cpu_data_areas[cpu_id] = null;
        return;
    }

    // Allocate memory for this CPU's per-CPU data
    const size = (per_cpu_data_size + 63) & ~@as(usize, 63); // Align to cache line
    const alloc_ptr = try heap.heapAlloc(size);
    const ptr = @as([*]u8, @ptrCast(alloc_ptr));

    // Zero the memory
    @memset(ptr[0..size], 0);

    per_cpu_data_areas[cpu_id] = ptr;
}

// Free per-CPU data area for a CPU
pub fn freePerCpuData(cpu_id: u32) void {
    if (cpu_id >= per_cpu.MAX_CPUS) {
        return;
    }

    if (per_cpu_data_areas[cpu_id]) |ptr| {
        const size = (per_cpu_data_size + 63) & ~@as(usize, 63);
        heap.heapFree(ptr[0..size]);
        per_cpu_data_areas[cpu_id] = null;
    }
}

// Get pointer to per-CPU variable for current CPU
pub inline fn getPerCpuPtr(offset: usize) [*]u8 {
    const cpu = per_cpu.getCurrentCpu();
    const base = per_cpu_data_areas[cpu.cpu_id] orelse @panic("Per-CPU data not allocated");
    return base + offset;
}

// Get pointer to per-CPU variable for specific CPU
pub fn getPerCpuPtrForCpu(cpu_id: u32, offset: usize) ?[*]u8 {
    if (cpu_id >= per_cpu.getCpuCount()) {
        return null;
    }
    const base = per_cpu_data_areas[cpu_id] orelse return null;
    return base + offset;
}

// Access per-CPU variable of type T for current CPU
pub inline fn getPerCpu(comptime T: type, offset: usize) *T {
    const ptr = getPerCpuPtr(offset);
    return @as(*T, @ptrCast(@alignCast(ptr)));
}

// Access per-CPU variable of type T for specific CPU
pub fn getPerCpuForCpu(comptime T: type, cpu_id: u32, offset: usize) ?*T {
    const ptr = getPerCpuPtrForCpu(cpu_id, offset) orelse return null;
    return @as(*T, @ptrCast(@alignCast(ptr)));
}

// Security check: verify current CPU access
pub fn verifyCurrentCpuAccess() bool {
    // Read GSBASE
    const gsbase = cpu_init.readMSR(0xC0000101);
    const cpu_data = @as(*per_cpu.CpuData, @ptrFromInt(gsbase));

    // Verify magic value
    if (cpu_data.magic != 0xDEADBEEFCAFEBABE) {
        return false;
    }

    // Verify CPU ID is valid
    if (cpu_data.cpu_id >= per_cpu.getCpuCount()) {
        return false;
    }

    // Verify this CPU data is in our array
    const expected_ptr = &per_cpu.cpu_data_array[cpu_data.cpu_id];
    if (cpu_data != expected_ptr) {
        return false;
    }

    return true;
}

// Helper macro-like function for defining per-CPU variables
pub fn definePerCpuVar(comptime T: type, name: []const u8) type {
    return struct {
        var offset: usize = 0;
        var initialized = false;

        pub fn init() !void {
            if (!initialized) {
                offset = try registerPerCpuVar(name, @sizeOf(T), @alignOf(T));
                initialized = true;
            }
        }

        pub inline fn get() *T {
            return getPerCpu(T, offset);
        }

        pub fn getForCpu(cpu_id: u32) ?*T {
            return getPerCpuForCpu(T, cpu_id, offset);
        }
    };
}

// Initialize per-CPU subsystem for BSP
pub fn initBsp() !void {
    // Initialize all per-CPU data area pointers to null
    for (&per_cpu_data_areas) |*area| {
        area.* = null;
    }

    // Allocate per-CPU data area for BSP
    try allocatePerCpuData(0);
}

// Initialize per-CPU subsystem for AP
pub fn initAp(cpu_id: u32) !void {
    // Allocate per-CPU data area for this AP
    try allocatePerCpuData(cpu_id);
}

// Example usage of per-CPU variables:
pub const example_per_cpu_counter = definePerCpuVar(u64, "example_counter");
pub const example_per_cpu_flags = definePerCpuVar(u32, "example_flags");

// Test function to demonstrate per-CPU variable usage
pub fn testPerCpuVars() !void {
    // Initialize the variables
    try example_per_cpu_counter.init();
    try example_per_cpu_flags.init();

    // Access current CPU's variables
    const counter = example_per_cpu_counter.get();
    counter.* += 1;

    const flags = example_per_cpu_flags.get();
    flags.* |= 0x1;
}
