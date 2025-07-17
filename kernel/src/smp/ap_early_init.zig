// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const per_cpu_gdt = @import("../x86_64/per_cpu_gdt.zig");
const per_cpu = @import("per_cpu.zig");
const ap_debug = @import("ap_debug.zig");

// Early AP initialization that MUST happen before any complex operations
// This includes GDT/TSS setup which is required for:
// - I/O port access (TSS contains I/O permission bitmap)
// - Proper exception/interrupt handling
// - Stack switching on interrupts
pub fn earlyInit(cpu_id: u32) !void {
    // CRITICAL: This function must be minimal and not perform any operations
    // that require TSS/GDT until after they are set up

    // Write simple debug marker using direct memory write (no I/O)
    const marker_ptr = @as(*volatile u32, @ptrFromInt(0x5C0));
    marker_ptr.* = 0xEAEA0000 | cpu_id;

    // 1. Initialize per-CPU GDT first
    // This allocates and sets up a GDT for this CPU
    per_cpu_gdt.initializeForCpu(cpu_id) catch |err| {
        // Write error marker (no I/O, just memory)
        const err_ptr = @as(*volatile u32, @ptrFromInt(0x5C4));
        err_ptr.* = 0xBAD10000 | @as(u32, @intCast(@intFromError(err)));
        return err;
    };

    // 2. Load the GDT
    per_cpu_gdt.loadForCpu(cpu_id);

    // 3. Setup minimal TSS
    // For now, we just need the TSS loaded so I/O operations don't fault
    // The full TSS setup with IST stacks will happen later in apMain

    // 4. Set GSBASE for per-CPU data access
    // This is needed for many operations
    const cpu_data = &per_cpu.cpu_data_array[cpu_id];
    const gsbase = @intFromPtr(cpu_data);
    asm volatile (
        \\wrmsr
        :
        : [msr] "{ecx}" (@as(u32, 0xC0000101)), // GS.base MSR
          [low] "{eax}" (@as(u32, @truncate(gsbase))),
          [high] "{edx}" (@as(u32, @truncate(gsbase >> 32))),
    );

    // Write success marker
    const success_ptr = @as(*volatile u32, @ptrFromInt(0x5C8));
    success_ptr.* = 0xEAEA1111;
}
