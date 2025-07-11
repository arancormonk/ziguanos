// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const cpuid = @import("cpuid.zig");
const serial = @import("../drivers/serial.zig");

// x2APIC MSR base address
const X2APIC_MSR_BASE: u32 = 0x800;

// x2APIC MSR offsets (divide by 16 from xAPIC MMIO offsets)
const MSR_APIC_ID = X2APIC_MSR_BASE + 0x02;
const MSR_APIC_VERSION = X2APIC_MSR_BASE + 0x03;
const MSR_APIC_TPR = X2APIC_MSR_BASE + 0x08;
const MSR_APIC_PPR = X2APIC_MSR_BASE + 0x0A;
const MSR_APIC_EOI = X2APIC_MSR_BASE + 0x0B;
const MSR_APIC_LDR = X2APIC_MSR_BASE + 0x0D;
const MSR_APIC_SVR = X2APIC_MSR_BASE + 0x0F;
const MSR_APIC_ISR_BASE = X2APIC_MSR_BASE + 0x10;
const MSR_APIC_TMR_BASE = X2APIC_MSR_BASE + 0x18;
const MSR_APIC_IRR_BASE = X2APIC_MSR_BASE + 0x20;
const MSR_APIC_ESR = X2APIC_MSR_BASE + 0x28;
const MSR_APIC_ICR = X2APIC_MSR_BASE + 0x30;
const MSR_APIC_LVT_TIMER = X2APIC_MSR_BASE + 0x32;
const MSR_APIC_LVT_THERMAL = X2APIC_MSR_BASE + 0x33;
const MSR_APIC_LVT_PERF = X2APIC_MSR_BASE + 0x34;
const MSR_APIC_LVT_LINT0 = X2APIC_MSR_BASE + 0x35;
const MSR_APIC_LVT_LINT1 = X2APIC_MSR_BASE + 0x36;
const MSR_APIC_LVT_ERROR = X2APIC_MSR_BASE + 0x37;
const MSR_APIC_TIMER_INIT_COUNT = X2APIC_MSR_BASE + 0x38;
const MSR_APIC_TIMER_CURRENT_COUNT = X2APIC_MSR_BASE + 0x39;
const MSR_APIC_TIMER_DIVIDE = X2APIC_MSR_BASE + 0x3E;
const MSR_APIC_SELF_IPI = X2APIC_MSR_BASE + 0x3F;

// Other important MSRs
const MSR_IA32_APIC_BASE = 0x1B;
const MSR_IA32_TSC_DEADLINE = 0x6E0;

// APIC Base MSR bits
const APIC_BASE_BSP = 1 << 8;
const APIC_BASE_ENABLE = 1 << 11;
const APIC_BASE_X2APIC_ENABLE = 1 << 10;

// Spurious interrupt vector register bits
const APIC_SVR_ENABLE = 1 << 8;

// Timer modes
pub const TimerMode = enum(u32) {
    OneShot = 0,
    Periodic = 1 << 17,
    TSCDeadline = 2 << 17,
};

// Timer divide values
pub const TimerDivide = enum(u32) {
    Div1 = 0xB,
    Div2 = 0x0,
    Div4 = 0x1,
    Div8 = 0x2,
    Div16 = 0x3,
    Div32 = 0x8,
    Div64 = 0x9,
    Div128 = 0xA,
};

// Delivery modes for IPI
pub const DeliveryMode = enum(u3) {
    Fixed = 0,
    LowestPriority = 1,
    SMI = 2,
    NMI = 4,
    INIT = 5,
    StartUp = 6,
};

// Destination shorthand for IPI
pub const DestinationShorthand = enum(u2) {
    None = 0,
    Self = 1,
    AllIncludingSelf = 2,
    AllExcludingSelf = 3,
};

// Read MSR
fn rdmsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, high) << 32) | low;
}

// Write MSR
fn wrmsr(msr: u32, value: u64) void {
    const low = @as(u32, @truncate(value));
    const high = @as(u32, @truncate(value >> 32));
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (low),
          [high] "{edx}" (high),
    );
}

// x2APIC state
var x2apic_enabled = false;
var bsp_id: u32 = 0;

// Check if x2APIC is supported
pub fn isSupported() bool {
    return cpuid.hasX2APIC();
}

// Check if x2APIC is enabled
pub fn isEnabled() bool {
    return x2apic_enabled;
}

// Enable x2APIC mode
pub fn enable() !void {
    if (!isSupported()) {
        serial.println("[x2APIC] x2APIC not supported by CPU", .{});
        return error.NotSupported;
    }

    // Read APIC base MSR
    var apic_base = rdmsr(MSR_IA32_APIC_BASE);

    // Check if APIC is enabled
    if ((apic_base & APIC_BASE_ENABLE) == 0) {
        serial.println("[x2APIC] APIC not enabled in IA32_APIC_BASE", .{});
        return error.APICNotEnabled;
    }

    // Check if already in x2APIC mode
    if ((apic_base & APIC_BASE_X2APIC_ENABLE) != 0) {
        serial.println("[x2APIC] Already in x2APIC mode", .{});
        x2apic_enabled = true;
        return;
    }

    // Enable x2APIC mode
    // Note: Once x2APIC is enabled, it cannot be disabled without a reset
    apic_base |= APIC_BASE_X2APIC_ENABLE;
    wrmsr(MSR_IA32_APIC_BASE, apic_base);

    // Verify x2APIC is enabled
    apic_base = rdmsr(MSR_IA32_APIC_BASE);
    if ((apic_base & APIC_BASE_X2APIC_ENABLE) == 0) {
        serial.println("[x2APIC] Failed to enable x2APIC mode", .{});
        return error.EnableFailed;
    }

    x2apic_enabled = true;
    serial.println("[x2APIC] Successfully enabled x2APIC mode", .{});

    // Get our APIC ID
    bsp_id = getAPICID();
    serial.print("[x2APIC] BSP APIC ID: {}\r\n", .{bsp_id});
}

// Initialize x2APIC
pub fn init() !void {
    if (!x2apic_enabled) {
        try enable();
    }

    // Clear error status register
    wrmsr(MSR_APIC_ESR, 0);

    // Enable APIC and set spurious interrupt vector
    const spurious_vector: u32 = 0xFF; // Usually the highest vector
    wrmsr(MSR_APIC_SVR, APIC_SVR_ENABLE | spurious_vector);

    // Mask all LVT entries
    wrmsr(MSR_APIC_LVT_TIMER, 1 << 16); // Masked
    wrmsr(MSR_APIC_LVT_THERMAL, 1 << 16); // Masked
    wrmsr(MSR_APIC_LVT_PERF, 1 << 16); // Masked
    wrmsr(MSR_APIC_LVT_LINT0, 1 << 16); // Masked
    wrmsr(MSR_APIC_LVT_LINT1, 1 << 16); // Masked
    wrmsr(MSR_APIC_LVT_ERROR, 1 << 16); // Masked

    // Set task priority to accept all interrupts
    wrmsr(MSR_APIC_TPR, 0);

    serial.println("[x2APIC] Initialization complete", .{});
}

// Get APIC ID
pub fn getAPICID() u32 {
    return @as(u32, @truncate(rdmsr(MSR_APIC_ID)));
}

// Get APIC version
pub fn getVersion() u32 {
    return @as(u32, @truncate(rdmsr(MSR_APIC_VERSION)));
}

// Send End of Interrupt
pub fn sendEOI() void {
    wrmsr(MSR_APIC_EOI, 0);
}

// Send IPI using x2APIC (single 64-bit write to ICR)
pub fn sendIPI(dest: u32, vector: u8, mode: DeliveryMode, shorthand: DestinationShorthand) void {
    const icr_value = (@as(u64, dest) << 32) |
        (@as(u64, @intFromEnum(shorthand)) << 18) |
        (@as(u64, @intFromEnum(mode)) << 8) |
        vector;
    wrmsr(MSR_APIC_ICR, icr_value);
}

// Send self IPI (optimized in x2APIC)
pub fn sendSelfIPI(vector: u8) void {
    wrmsr(MSR_APIC_SELF_IPI, vector);
}

// Timer functions
pub fn initTimer(vector: u8, mode: TimerMode, divide: TimerDivide) void {
    // Set timer divide
    wrmsr(MSR_APIC_TIMER_DIVIDE, @intFromEnum(divide));

    // Configure timer LVT
    const timer_config = @intFromEnum(mode) | vector;
    wrmsr(MSR_APIC_LVT_TIMER, timer_config);
}

pub fn setTimerInitialCount(count: u32) void {
    wrmsr(MSR_APIC_TIMER_INIT_COUNT, count);
}

pub fn getTimerCurrentCount() u32 {
    return @as(u32, @truncate(rdmsr(MSR_APIC_TIMER_CURRENT_COUNT)));
}

pub fn stopTimer() void {
    wrmsr(MSR_APIC_TIMER_INIT_COUNT, 0);
}

// Set timer divider (for compatibility with unified interface)
pub fn setTimerDivider(divider: u32) void {
    // Convert numeric divider to TimerDivide enum
    const divide = switch (divider) {
        1 => TimerDivide.Div1,
        2 => TimerDivide.Div2,
        4 => TimerDivide.Div4,
        8 => TimerDivide.Div8,
        16 => TimerDivide.Div16,
        32 => TimerDivide.Div32,
        64 => TimerDivide.Div64,
        128 => TimerDivide.Div128,
        else => TimerDivide.Div16, // Default to 16 if invalid
    };
    wrmsr(MSR_APIC_TIMER_DIVIDE, @intFromEnum(divide));
}

// TSC-Deadline timer support
pub fn setTSCDeadline(deadline: u64) void {
    wrmsr(MSR_IA32_TSC_DEADLINE, deadline);
}

// Error handling
pub fn getErrorStatus() u32 {
    // Write to ESR to update it
    wrmsr(MSR_APIC_ESR, 0);
    // Read the updated value
    return @as(u32, @truncate(rdmsr(MSR_APIC_ESR)));
}

// Check interrupt pending
pub fn isInterruptPending(vector: u8) bool {
    const reg_index = vector / 32;
    const bit_index = @as(u5, @intCast(vector % 32));
    const isr_value = rdmsr(MSR_APIC_ISR_BASE + reg_index);
    return (isr_value & (@as(u64, 1) << bit_index)) != 0;
}

// Dump x2APIC state for debugging
pub fn dumpState() void {
    serial.println("[x2APIC] State dump:", .{});
    serial.print("  APIC ID: 0x{x}\r\n", .{getAPICID()});
    serial.print("  Version: 0x{x}\r\n", .{getVersion()});
    serial.print("  SVR: 0x{x}\r\n", .{rdmsr(MSR_APIC_SVR)});
    serial.print("  TPR: 0x{x}\r\n", .{rdmsr(MSR_APIC_TPR)});
    serial.print("  PPR: 0x{x}\r\n", .{rdmsr(MSR_APIC_PPR)});
    serial.print("  ESR: 0x{x}\r\n", .{getErrorStatus()});
    serial.print("  Timer Initial: 0x{x}\r\n", .{rdmsr(MSR_APIC_TIMER_INIT_COUNT)});
    serial.print("  Timer Current: 0x{x}\r\n", .{getTimerCurrentCount()});
}
