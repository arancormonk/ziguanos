// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const gdt = @import("../x86_64/gdt.zig");
const idt = @import("../x86_64/idt.zig");
const apic = @import("../x86_64/apic.zig");
const apic_unified = @import("../x86_64/apic_unified.zig");
const cpu_init = @import("../x86_64/cpu_init.zig");
const per_cpu = @import("per_cpu.zig");
const cpu_local = @import("cpu_local.zig");
const ap_init = @import("ap_init.zig");
const ap_debug = @import("ap_debug.zig");
const serial = @import("../drivers/serial.zig");
const stack_security = @import("../x86_64/stack_security.zig");
const interrupt_security = @import("../x86_64/interrupt_security.zig");
const paging = @import("../x86_64/paging.zig");
const smap = @import("../x86_64/smap.zig");
const speculation = @import("../x86_64/speculation.zig");
const cfi = @import("../x86_64/cfi.zig");
const per_cpu_gdt = @import("../x86_64/per_cpu_gdt.zig");
const ap_cpu_init = @import("ap_cpu_init.zig");
const ipi = @import("ipi.zig");

// Application Processor main entry point
pub fn apMain(cpu_id: u32, cpu_data: *per_cpu.CpuData) !void {
    // Write a simple debug marker to verify we reached kernel code
    const debug_marker = @as(*volatile u32, @ptrFromInt(0x10000));
    debug_marker.* = 0xCAFEBABE + cpu_id;

    // Mark kernel entry
    ap_debug.updateApStage(cpu_id, .KernelEntry);

    // Intel SDM 10.4.4.2 Step 5: Execute CPUID to verify "GenuineIntel"
    var eax: u32 = 0;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [func] "{eax}" (@as(u32, 0)),
    );
    // Verify "GenuineIntel" signature (optional, we support AMD too)

    // Intel SDM 10.4.4.2 Step 6: Save CPUID values for later use
    // Execute CPUID with EAX=1 to get processor info
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [func] "{eax}" (@as(u32, 1)),
          [zero] "{ecx}" (@as(u32, 0)),
    );
    ap_debug.setDebugValue(cpu_id, 1, @as(u64, eax) | (@as(u64, edx) << 32)); // Store CPUID info

    // 1. Load per-CPU GDT (Intel SDM Vol 3A Section 3.4.5)
    // Each processor must have its own GDT to avoid race conditions when updating TSS
    per_cpu_gdt.initializeForCpu(cpu_id) catch |err| {
        ap_debug.recordApError(cpu_id, @intFromError(err), ap_debug.DebugFlags.MEMORY_ERROR);
        return err;
    };
    per_cpu_gdt.loadForCpu(cpu_id);

    // IDT is shared across all CPUs (Intel SDM Vol 3A Section 6.10)
    // It's already loaded by BSP, no action needed
    ap_debug.updateApStage(cpu_id, .GdtIdtLoaded);

    // 2. Setup GSBASE for per-CPU access
    const gsbase = @intFromPtr(cpu_data);
    asm volatile (
        \\wrmsr
        :
        : [msr] "{ecx}" (@as(u32, 0xC0000101)), // GS.base MSR
          [low] "{eax}" (@as(u32, @truncate(gsbase))),
          [high] "{edx}" (@as(u32, @truncate(gsbase >> 32))),
    );
    ap_debug.updateApStage(cpu_id, .GsBaseSet);
    ap_debug.setDebugValue(cpu_id, 0, gsbase); // Store GSBASE value for debugging

    // 3. Initialize Local APIC
    apic.init() catch |err| {
        ap_debug.recordApError(cpu_id, @intFromError(err), ap_debug.DebugFlags.APIC_ERROR);
        return err;
    };
    ap_debug.updateApStage(cpu_id, .ApicInitialized);

    // 4. Setup TSS and IST stacks
    setupApTss(cpu_data) catch |err| {
        ap_debug.recordApError(cpu_id, @intFromError(err), ap_debug.DebugFlags.STACK_ERROR);
        return err;
    };
    ap_debug.updateApStage(cpu_id, .TssConfigured);

    // 5. Enable CPU security features
    enableApSecurityFeatures(cpu_data);
    ap_debug.updateApStage(cpu_id, .SecurityEnabled);

    // 6. Initialize CPU-specific subsystems
    initApSubsystems(cpu_id) catch |err| {
        ap_debug.recordApError(cpu_id, @intFromError(err), ap_debug.DebugFlags.MEMORY_ERROR);
        return err;
    };
    ap_debug.updateApStage(cpu_id, .SubsystemsInit);

    // 7. Signal ready to BSP
    _ = @atomicRmw(u32, &@import("ap_init.zig").startup_state.ap_ready_count, .Add, 1, .seq_cst);
    ap_debug.updateApStage(cpu_id, .SignaledReady);

    // 8. Wait for proceed signal from BSP
    while (!@atomicLoad(bool, &@import("ap_init.zig").startup_state.proceed_signal, .acquire)) {
        asm volatile ("pause");
    }
    ap_debug.updateApStage(cpu_id, .ProceedReceived);

    // Serial driver is now thread-safe with spinlocks
    serial.println("[SMP] AP {} entering idle loop", .{cpu_id});

    // 9. Enter idle loop
    ap_debug.updateApStage(cpu_id, .IdleLoop);
    idleLoop();
}

// Setup TSS for Application Processor
fn setupApTss(cpu_data: *per_cpu.CpuData) !void {
    // IST stacks are allocated by interrupt_security module
    try interrupt_security.allocateIstStacks(@intCast(cpu_data.cpu_id));

    // Get the allocated stacks
    const ist_stacks = interrupt_security.getIstStacks(@intCast(cpu_data.cpu_id));

    // Copy to per-CPU data
    for (ist_stacks, 0..) |stack, i| {
        cpu_data.ist_stacks[i] = stack;
    }

    // Update per-CPU TSS with this CPU's stacks (Intel SDM Vol 3A Section 7.2.1)
    // Using per-CPU TSS eliminates race conditions
    const kernel_stack_ptr = @intFromPtr(cpu_data.kernel_stack);
    const ist_stack_ptrs = [7]u64{
        @intFromPtr(cpu_data.ist_stacks[0]),
        @intFromPtr(cpu_data.ist_stacks[1]),
        @intFromPtr(cpu_data.ist_stacks[2]),
        @intFromPtr(cpu_data.ist_stacks[3]),
        @intFromPtr(cpu_data.ist_stacks[4]),
        @intFromPtr(cpu_data.ist_stacks[5]),
        @intFromPtr(cpu_data.ist_stacks[6]),
    };

    per_cpu_gdt.updateTssForCpu(@intCast(cpu_data.cpu_id), kernel_stack_ptr, &ist_stack_ptrs);
}

// Enable security features on Application Processor
fn enableApSecurityFeatures(cpu_data: *per_cpu.CpuData) void {
    // Enable SMAP (Supervisor Mode Access Prevention)
    // SMAP needs to be enabled per-CPU by setting CR4.SMAP
    if (smap.isEnabled()) {
        // Re-enable SMAP on this CPU
        const cr4 = asm volatile ("mov %%cr4, %[ret]"
            : [ret] "=r" (-> u64),
        );
        asm volatile ("mov %[cr4], %%cr4"
            :
            : [cr4] "r" (cr4 | (1 << 21)), // CR4.SMAP
        );
    }

    // Initialize AP CPU features to match BSP (Intel SDM Vol 3A Section 8.4.6)
    // This ensures all CPUs have consistent security and feature configuration
    ap_cpu_init.initializeAp(cpu_data.cpu_id) catch |err| {
        ap_debug.recordApError(cpu_data.cpu_id, @intFromError(err), ap_debug.DebugFlags.CPU_FEATURE_MISSING);
        // Continue anyway, some features might still work
    };
}

// Initialize AP-specific subsystems
fn initApSubsystems(cpu_id: u32) !void {
    // Allocate per-CPU data for this AP
    try cpu_local.allocatePerCpuData(cpu_id);

    // Initialize APIC timer
    const timer_freq = try apic.calibrateTimer();
    // Serial driver is now thread-safe with spinlocks
    serial.println("[SMP] AP {} APIC timer frequency: {} Hz", .{ cpu_id, timer_freq });
}

// CPU idle loop
// Intel SDM 10.4.4.2 Step 13: Execute CLI and HLT instructions
fn idleLoop() noreturn {
    // Intel SDM 10.4.3 Step 9: APs remain in halted state
    // They respond only to INIT, NMI, SMI, and STPCLK#
    while (true) {
        // IPIs are now handled via interrupt handlers, not polling
        // The IPI infrastructure (ipi.zig) handles TLB shootdowns,
        // reschedule requests, and function calls directly via interrupts

        // Enter low power state
        asm volatile (
            \\sti  # Enable interrupts
            \\hlt  # Halt until interrupt
            \\cli  # Disable interrupts
        );
    }
}

// Handle pending IPIs
fn handlePendingIpis(cpu_data: *per_cpu.CpuData) void {
    const pending = @atomicLoad(u32, &cpu_data.ipi_pending, .seq_cst);
    @atomicStore(u32, &cpu_data.ipi_pending, 0, .seq_cst);

    // Process each pending IPI type
    if (pending & (1 << 0) != 0) { // Reschedule
        // Future: trigger scheduler
    }

    if (pending & (1 << 1) != 0) { // TLB flush
        paging.flushTLB();
    }

    if (pending & (1 << 2) != 0) { // Call function
        // Future: process function call queue
    }

    if (pending & (1 << 3) != 0) { // Panic
        @panic("Remote panic IPI received");
    }
}

// AP panic handler
pub fn apPanic(msg: []const u8, error_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_trace; // TODO: Use when we have stack trace support

    // Disable interrupts
    asm volatile ("cli");

    // Get current CPU info if possible
    const cpu_id = blk: {
        // Try to get CPU ID from GS base
        const gs_base = asm volatile (
            \\mov %%gs:0, %[ret]
            : [ret] "=r" (-> u64),
        );
        if (gs_base != 0) {
            const cpu_data = @as(*per_cpu.CpuData, @ptrFromInt(gs_base));
            if (cpu_data.magic == 0xDEADBEEFCAFEBABE) {
                break :blk cpu_data.cpu_id;
            }
        }
        break :blk 0xFFFFFFFF; // Unknown CPU
    };

    // Record panic in debug state
    if (cpu_id != 0xFFFFFFFF) {
        ap_debug.recordApError(cpu_id, 0xDEAD, ap_debug.DebugFlags.EXCEPTION);
    }

    // Dump debug info to memory for debugger
    ap_debug.dumpDebugInfo();

    // Write panic info to a fixed memory location
    const panic_info = @as(*volatile PanicInfo, @ptrFromInt(0x11000));
    panic_info.magic = 0xDEADBEEF;
    panic_info.cpu_id = cpu_id;
    panic_info.ret_addr = ret_addr orelse 0;
    panic_info.msg_len = @min(msg.len, 255);
    @memcpy(panic_info.msg[0..panic_info.msg_len], msg);

    // TODO: Serial driver is not thread-safe yet, so we can't print from APs
    // This would cause a triple fault if AP panic occurs

    // Notify BSP of panic (send to CPU 0)
    apic_unified.sendIPIFull(0, 3, .Fixed, apic.IpiLevel.Assert, apic.IpiTriggerMode.Edge, .NoShorthand);

    // Halt forever
    while (true) {
        asm volatile ("hlt");
    }
}

// Panic info structure at fixed address 0x11000
const PanicInfo = extern struct {
    magic: u32,
    cpu_id: u32,
    ret_addr: u64,
    msg_len: u32,
    padding: u32,
    msg: [256]u8,
};
