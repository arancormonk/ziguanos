// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const interrupts = @import("../x86_64/interrupts.zig");
const apic = @import("../x86_64/apic.zig");
const timer = @import("../x86_64/timer.zig");

/// Initialize hardware components
pub fn init() void {
    // Initialize enhanced interrupt handling
    interrupts.init();
    serial.println("[KERNEL] Enhanced interrupt handling initialized", .{});
    serial.flush();

    // Initialize APIC if available
    apic.init() catch |err| {
        serial.println("[KERNEL] APIC init failed: {s}", .{@errorName(err)});
        serial.println("[KERNEL] Falling back to legacy PIC mode", .{});
        serial.flush();
    };

    if (apic.isAvailable()) {
        apic.printInfo();
        serial.println("[KERNEL] APIC initialized successfully", .{});
        serial.flush();

        // Test APIC functionality
        apic.testAPIC() catch |err| {
            serial.println("[KERNEL] APIC test failed: {s}", .{@errorName(err)});
            serial.flush();
        };
    }

    // Initialize timer subsystem (handles both APIC and PIT)
    timer.init();
    timer.printInfo();
    serial.flush(); // Ensure timer initialization is visible
}

/// Prepare for interrupt enabling
pub fn prepareForInterrupts() void {
    // Mask all interrupts except timer before enabling
    serial.println("[KERNEL] Masking spurious interrupts...", .{});
    apic.maskAllInterrupts();
}

/// Enable interrupts
pub fn enableInterrupts() void {
    serial.println("[KERNEL] Enabling interrupts...", .{});
    serial.flush(); // Flush before enabling interrupts to avoid race conditions
    asm volatile ("sti");
}

/// Print hardware statistics
pub fn printStatistics() void {
    // Print interrupt statistics
    interrupts.printStatistics();
}
