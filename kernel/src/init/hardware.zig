// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const interrupts = @import("../x86_64/interrupts.zig");
const apic = @import("../x86_64/apic.zig");
const x2apic = @import("../x86_64/x2apic.zig");
const apic_unified = @import("../x86_64/apic_unified.zig");
const timer = @import("../x86_64/timer.zig");
const acpi = @import("../drivers/acpi/acpi.zig");
const heap = @import("../memory/heap.zig");
const uefi_boot = @import("../boot/uefi_boot.zig");
const allocator = @import("../memory/allocator.zig");
const per_cpu = @import("../smp/per_cpu.zig");
const cpu_local = @import("../smp/cpu_local.zig");
const smp_test = @import("../smp/tests.zig");
const ap_init = @import("../smp/ap_init.zig");
const error_utils = @import("../lib/error_utils.zig");

// Store boot info for ACPI initialization
var saved_boot_info: ?*const uefi_boot.UEFIBootInfo = null;

// Set boot information for hardware initialization
pub fn setBootInfo(boot_info: *const uefi_boot.UEFIBootInfo) void {
    saved_boot_info = boot_info;
}

// Initialize hardware components
pub fn init() void {
    // Initialize per-CPU infrastructure for BSP
    per_cpu.initBsp() catch |err| {
        serial.println("[KERNEL] Per-CPU init failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
        // This is fatal, we need per-CPU infrastructure
        @panic("Failed to initialize per-CPU infrastructure");
    };

    cpu_local.initBsp() catch |err| {
        serial.println("[KERNEL] CPU-local storage init failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
        @panic("Failed to initialize CPU-local storage");
    };

    serial.println("[KERNEL] Per-CPU infrastructure initialized", .{});
    serial.flush();

    // Initialize enhanced interrupt handling
    interrupts.init();
    serial.println("[KERNEL] Enhanced interrupt handling initialized", .{});
    serial.flush();

    // Intel SDM 10.4.4.1 Step 5: BSP creates ACPI table and/or MP table
    // Initialize ACPI subsystem if we have boot info
    if (saved_boot_info) |boot_info| {
        if (boot_info.rsdp_addr != 0) {
            serial.println("[KERNEL] Initializing ACPI subsystem...", .{});
            acpi.initSystem(allocator.kernel_allocator, boot_info.rsdp_addr) catch |err| {
                serial.println("[KERNEL] ACPI init failed: {s}", .{error_utils.errorToString(err)});
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

    // Try x2APIC first if supported
    var using_x2apic = false;
    if (x2apic.isSupported()) {
        serial.println("[KERNEL] x2APIC supported, attempting to enable...", .{});
        x2apic.init() catch |err| {
            serial.println("[KERNEL] x2APIC init failed: {s}", .{error_utils.errorToString(err)});
            serial.println("[KERNEL] Falling back to xAPIC mode", .{});
            serial.flush();
        };

        if (x2apic.isEnabled()) {
            using_x2apic = true;
            serial.println("[KERNEL] x2APIC initialized successfully", .{});

            // Update BSP's APIC ID using x2APIC
            const apic_id = @as(u8, @truncate(x2apic.getAPICID()));
            per_cpu.updateBspApicId(apic_id);
            serial.println("[KERNEL] BSP APIC ID (x2APIC): {d}", .{apic_id});

            // Dump x2APIC state for debugging
            x2apic.dumpState();
            serial.flush();
        }
    }

    // Fall back to xAPIC if x2APIC failed or not supported
    if (!using_x2apic) {
        apic.init() catch |err| {
            serial.println("[KERNEL] APIC init failed: {s}", .{error_utils.errorToString(err)});
            serial.println("[KERNEL] Falling back to legacy PIC mode", .{});
            serial.flush();
        };

        if (apic.isAvailable()) {
            apic.printInfo();
            serial.println("[KERNEL] APIC initialized successfully", .{});

            // Intel SDM 10.4.1: BSP flag is set in IA32_APIC_BASE MSR
            // Update BSP's APIC ID now that APIC is initialized
            const apic_id = @as(u8, @truncate(apic_unified.getAPICID()));
            per_cpu.updateBspApicId(apic_id);
            serial.println("[KERNEL] BSP APIC ID updated: {d}", .{apic_id});
            serial.flush();

            // Test APIC functionality
            apic.testAPIC() catch |err| {
                serial.println("[KERNEL] APIC test failed: {s}", .{error_utils.errorToString(err)});
                serial.flush();
            };
        }
    }

    // Initialize timer subsystem (handles both APIC and PIT)
    timer.init();
    timer.printInfo();
    serial.flush(); // Ensure timer initialization is visible

    // Test per-CPU infrastructure
    serial.println("[KERNEL] Testing per-CPU infrastructure...", .{});
    smp_test.testPerCpuInfrastructure() catch |err| {
        serial.println("[KERNEL] Per-CPU infrastructure test failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
    };

    // Test AP debug functionality
    serial.println("[KERNEL] Testing AP debug mechanism...", .{});
    smp_test.testApDebug() catch |err| {
        serial.println("[KERNEL] AP debug test failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
    };

    serial.println("[KERNEL] AP debug test completed", .{});
    serial.flush();

    // Start Application Processors if we have ACPI topology information
    serial.println("[KERNEL] Checking for ACPI system...", .{});
    serial.flush();

    if (acpi.getSystem()) |system| {
        serial.println("[KERNEL] ACPI system found", .{});
        serial.flush();
        if (system.getTopology()) |topology| {
            if (topology.total_cpus > 1) {
                serial.println("[KERNEL] Starting Application Processors...", .{});
                serial.flush();

                ap_init.startAllAPs(topology.processors) catch |err| {
                    serial.println("[KERNEL] Failed to start APs: {s}", .{error_utils.errorToString(err)});
                    serial.flush();
                    // Continue with single CPU operation
                };
            }
        }
    }
}

// Prepare for interrupt enabling
pub fn prepareForInterrupts() void {
    // Mask all interrupts except timer before enabling
    serial.println("[KERNEL] Masking spurious interrupts...", .{});
    if (x2apic.isEnabled()) {
        // x2APIC handles masking through initialization
        serial.println("[KERNEL] x2APIC mode - interrupts already masked", .{});
    } else {
        apic.maskAllInterrupts();
    }
}

// Enable interrupts
pub fn enableInterrupts() void {
    serial.println("[KERNEL] Enabling interrupts...", .{});
    serial.flush(); // Flush before enabling interrupts to avoid race conditions
    asm volatile ("sti");
}

// Print hardware statistics
pub fn printStatistics() void {
    // Print interrupt statistics
    interrupts.printStatistics();
}
