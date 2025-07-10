// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const x86_64 = @import("../x86_64.zig");
const gdt = @import("gdt.zig");
const smp = @import("../smp.zig");

// Access byte flags
const KERNEL_CODE_ACCESS = 0x9A; // Present, DPL=0, Code, Execute/Read
const KERNEL_DATA_ACCESS = 0x92; // Present, DPL=0, Data, Read/Write
const USER_CODE_ACCESS = 0xFA; // Present, DPL=3, Code, Execute/Read
const USER_DATA_ACCESS = 0xF2; // Present, DPL=3, Data, Read/Write
const TSS_ACCESS = 0x89; // Present, DPL=0, TSS

// Flags
const FLAGS_L = 0xA; // Long mode, 4K granularity

// Per-CPU GDT structures to avoid race conditions during SMP
pub const MAX_CPUS = 256;

// GDT structure matching the kernel's layout
pub const GDT = packed struct {
    null: u64,
    kernel_code: u64,
    kernel_data: u64,
    user_data: u64,
    user_code: u64,
    tss_low: u64,
    tss_high: u64,
};

// GDT pointer for LGDT instruction
pub const GDTR = packed struct {
    limit: u16,
    base: u64,
};

// Each CPU gets its own GDT and TSS
var per_cpu_gdts: [MAX_CPUS]GDT align(16) = undefined;
var per_cpu_tss: [MAX_CPUS]gdt.TSS align(16) = undefined;

// Create a GDT descriptor
fn createDescriptor(base: u32, limit: u32, access: u8, flags: u8) u64 {
    var desc: u64 = 0;

    // Encode limit
    desc |= @as(u64, limit & 0xFFFF);
    desc |= @as(u64, (limit >> 16) & 0x0F) << 48;

    // Encode base
    desc |= @as(u64, base & 0xFFFF) << 16;
    desc |= @as(u64, (base >> 16) & 0xFF) << 32;
    desc |= @as(u64, (base >> 24) & 0xFF) << 56;

    // Encode access byte
    desc |= @as(u64, access) << 40;

    // Encode flags
    desc |= @as(u64, flags) << 52;

    return desc;
}

// Create a TSS descriptor (takes 2 entries in GDT)
fn createTSSDescriptor(base: u64, limit: u16) struct { low: u64, high: u64 } {
    var low: u64 = 0;
    var high: u64 = 0;

    // Low part
    low |= @as(u64, limit & 0xFFFF);
    low |= (base & 0xFFFF) << 16;
    low |= ((base >> 16) & 0xFF) << 32;
    low |= @as(u64, TSS_ACCESS) << 40;
    // Since limit is u16, no need to shift right by 16
    // TSS limit is typically small enough to fit in 16 bits
    low |= ((base >> 24) & 0xFF) << 56;

    // High part (bits 32-63 of base)
    high = (base >> 32) & 0xFFFFFFFF;

    return .{ .low = low, .high = high };
}

// Initialize GDT for a specific CPU
pub fn initializeForCpu(cpu_id: u32) !void {
    if (cpu_id >= MAX_CPUS) {
        return error.InvalidCpuId;
    }

    // Copy the base GDT template
    per_cpu_gdts[cpu_id] = GDT{
        .null = 0,
        .kernel_code = createDescriptor(0, 0xFFFFF, KERNEL_CODE_ACCESS, FLAGS_L),
        .kernel_data = createDescriptor(0, 0xFFFFF, KERNEL_DATA_ACCESS, FLAGS_L),
        .user_data = createDescriptor(0, 0xFFFFF, USER_DATA_ACCESS, FLAGS_L),
        .user_code = createDescriptor(0, 0xFFFFF, USER_CODE_ACCESS, FLAGS_L),
        .tss_low = 0,
        .tss_high = 0,
    };

    // Initialize TSS for this CPU
    per_cpu_tss[cpu_id] = std.mem.zeroes(gdt.TSS);

    // Set TSS descriptor in GDT
    const tss_addr = @intFromPtr(&per_cpu_tss[cpu_id]);
    const tss_desc = createTSSDescriptor(tss_addr, @sizeOf(gdt.TSS) - 1);
    per_cpu_gdts[cpu_id].tss_low = tss_desc.low;
    per_cpu_gdts[cpu_id].tss_high = tss_desc.high;
}

// Load GDT for current CPU
pub fn loadForCpu(cpu_id: u32) void {
    if (cpu_id >= MAX_CPUS) {
        @panic("Invalid CPU ID");
    }

    const gdtr = GDTR{
        .limit = @sizeOf(GDT) - 1,
        .base = @intFromPtr(&per_cpu_gdts[cpu_id]),
    };

    // Load GDT
    asm volatile ("lgdt %[gdtr]"
        :
        : [gdtr] "*m" (&gdtr),
    );

    // Reload segments
    reloadSegments();

    // Load TSS
    const tss_selector: u16 = 0x28; // TSS is at offset 0x28 in GDT
    asm volatile ("ltr %[sel]"
        :
        : [sel] "r" (tss_selector),
    );
}

// Reload segment registers after GDT change
fn reloadSegments() void {
    // Reload data segments
    asm volatile (
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%ax, %%fs
        \\mov %%ax, %%gs
        \\mov %%ax, %%ss
        ::: "rax");

    // Reload code segment via far return
    asm volatile (
        \\push $0x08
        \\lea 1f(%%rip), %%rax
        \\push %%rax
        \\lretq
        \\1:
        ::: "rax", "memory");
}

// Update TSS for a CPU (safe for concurrent access)
pub fn updateTssForCpu(cpu_id: u32, kernel_stack: u64, ist_stacks: []const u64) void {
    if (cpu_id >= MAX_CPUS) {
        @panic("Invalid CPU ID");
    }

    // Each CPU has its own TSS, so no race condition
    per_cpu_tss[cpu_id].rsp0 = kernel_stack;

    // Set IST stacks
    if (ist_stacks.len >= 1) per_cpu_tss[cpu_id].ist1 = ist_stacks[0];
    if (ist_stacks.len >= 2) per_cpu_tss[cpu_id].ist2 = ist_stacks[1];
    if (ist_stacks.len >= 3) per_cpu_tss[cpu_id].ist3 = ist_stacks[2];
    if (ist_stacks.len >= 4) per_cpu_tss[cpu_id].ist4 = ist_stacks[3];
    if (ist_stacks.len >= 5) per_cpu_tss[cpu_id].ist5 = ist_stacks[4];
    if (ist_stacks.len >= 6) per_cpu_tss[cpu_id].ist6 = ist_stacks[5];
    if (ist_stacks.len >= 7) per_cpu_tss[cpu_id].ist7 = ist_stacks[6];
}

// Get TSS for a specific CPU
pub fn getTssForCpu(cpu_id: u32) *gdt.TSS {
    if (cpu_id >= MAX_CPUS) {
        @panic("Invalid CPU ID");
    }
    return &per_cpu_tss[cpu_id];
}

// Get GDT for a specific CPU
pub fn getGdtForCpu(cpu_id: u32) *gdt.GDT {
    if (cpu_id >= MAX_CPUS) {
        @panic("Invalid CPU ID");
    }
    return &per_cpu_gdts[cpu_id];
}
