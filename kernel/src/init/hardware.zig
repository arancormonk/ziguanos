// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const interrupts = @import("../x86_64/interrupts.zig");
const apic = @import("../x86_64/apic.zig");
const timer = @import("../x86_64/timer.zig");
const acpi = @import("../drivers/acpi/acpi.zig");
const heap = @import("../memory/heap.zig");
const uefi_boot = @import("../boot/uefi_boot.zig");
const allocator = @import("../memory/allocator.zig");

// Store boot info for ACPI initialization
var saved_boot_info: ?*const uefi_boot.UEFIBootInfo = null;

/// Set boot information for hardware initialization
pub fn setBootInfo(boot_info: *const uefi_boot.UEFIBootInfo) void {
    saved_boot_info = boot_info;
}

/// Initialize hardware components
pub fn init() void {
    // Initialize enhanced interrupt handling
    interrupts.init();
    serial.println("[KERNEL] Enhanced interrupt handling initialized", .{});
    serial.flush();

    // Initialize ACPI subsystem if we have boot info
    if (saved_boot_info) |boot_info| {
        if (boot_info.rsdp_addr != 0) {
            serial.println("[KERNEL] Initializing ACPI subsystem...", .{});
            acpi.initSystem(allocator.kernel_allocator, boot_info.rsdp_addr) catch |err| {
                serial.println("[KERNEL] ACPI init failed: {s}", .{@errorName(err)});
                serial.println("[KERNEL] Continuing without ACPI support", .{});
                serial.flush();
            };

            // Print discovered CPU information
            if (acpi.getSystem()) |system| {
                if (system.getTopology()) |topology| {
                    serial.println("[KERNEL] ACPI: Found {d} CPU(s)", .{topology.total_cpus});
                    for (topology.processors, 0..) |proc, i| {
                        serial.println("[KERNEL]   CPU[{d}]: APIC ID {d}, enabled: {}", .{ i, proc.apic_id, proc.isEnabled() });
                    }
                    serial.flush();
                }
            }
        }
    }

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
