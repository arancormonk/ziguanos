// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("drivers/serial.zig");
const uefi_boot = @import("boot/uefi_boot.zig");
const runtime_info = @import("boot/runtime_info.zig");
const secure_print = @import("lib/secure_print.zig");
const gdt = @import("x86_64/gdt.zig");
const boot = @import("boot/init.zig");
const spinlock = @import("lib/spinlock.zig");
const pmm = @import("memory/pmm.zig");
const error_utils = @import("lib/error_utils.zig");

// Import initialization modules
const early_init = @import("init/early.zig");
const cpu_init = @import("init/cpu.zig");
const memory_init = @import("init/memory.zig");
const security_init = @import("init/security.zig");
const hardware_init = @import("init/hardware.zig");
const diagnostics = @import("init/diagnostics.zig");
const stack_switch = @import("init/stack_switch.zig");

// UEFI boot info structure
const UEFIBootInfo = uefi_boot.UEFIBootInfo;

// Global state for phase 2 (after stack switch)
var saved_boot_info_ptr: *const UEFIBootInfo = undefined;
var saved_stack_phys: u64 = undefined;
var saved_stack_top: u64 = undefined;

// Main kernel initialization and run loop - Phase 1
pub fn kernelMain(boot_info: *const UEFIBootInfo) noreturn {
    // Set KASLR offset for address sanitization
    const info = runtime_info.getRuntimeInfo();
    serial.setKASLROffset(info.kaslr_offset);

    // Debug: Print boot info
    serial.printAddress("[KERNEL] Boot info ptr", @intFromPtr(boot_info));
    serial.println("[KERNEL] Magic: 0x{x:0>16}", .{boot_info.magic});
    serial.println("[KERNEL] (validated)", .{});

    // Display kernel hash verification status
    if (boot_info.hash_valid) {
        serial.println("[KERNEL] Kernel hash verification: PASSED ✓", .{});
    } else {
        serial.println("[KERNEL] Kernel hash verification: NOT VERIFIED (development mode)", .{});
    }

    // Display kernel hash
    serial.print("[KERNEL] Kernel SHA-256: ", .{});
    for (boot_info.kernel_hash) |byte| {
        serial.print("{X:0>2}", .{byte});
    }
    serial.println("", .{});
    serial.flush(); // Flush after early initialization and hash display

    // Test GDT is working
    if (!gdt.testGDT()) {
        serial.println("[KERNEL] ERROR: GDT test failed!", .{});
        serial.flush();
        @panic("GDT test failed");
    }

    // Initialize basic security features
    security_init.initBasic();

    // Test IDT by triggering an exception (uncomment to test)
    // serial.println("[KERNEL] Testing IDT with divide-by-zero...");
    // idt.testIDT();

    // Initialize CPU features
    cpu_init.init();

    // Initialize memory subsystems phase 1
    serial.println("[KERNEL] Initializing memory subsystems (phase 1)...", .{});
    serial.flush();

    const stack_info = memory_init.initPhase1(boot_info) catch |err| {
        serial.println("[KERNEL] Memory init phase 1 failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
        @panic("Failed to initialize memory");
    };

    // Save info for phase 2
    saved_boot_info_ptr = boot_info;
    saved_stack_phys = stack_info.phys;
    saved_stack_top = stack_info.top;

    // Switch stacks and continue
    serial.println("[KERNEL] Switching to new kernel stack...", .{});
    serial.flush();

    stack_switch.switchStackAndContinue(
        stack_info.top,
        &kernelMainPhase2,
    );
}

// Kernel initialization phase 2 - after stack switch
fn kernelMainPhase2() noreturn {
    // We're now on the new stack
    const boot_info = saved_boot_info_ptr;

    // Complete memory initialization
    memory_init.initPhase2(saved_stack_phys, saved_stack_top, boot_info) catch |err| {
        serial.println("[KERNEL] Memory init phase 2 failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
        @panic("Failed to complete memory initialization");
    };

    // Reclaim boot services memory now that we're done with UEFI
    serial.println("[KERNEL] Reclaiming UEFI boot services memory...", .{});

    // Show memory stats before reclaim
    const stats_before = pmm.getStats();
    serial.println("[KERNEL] Memory before reclaim: {} MB free, {} MB reserved", .{
        (stats_before.free_memory / (1024 * 1024)),
        (stats_before.reserved_memory / (1024 * 1024)),
    });

    // Show reserved regions before reclaim
    // serial.println("[KERNEL] Reserved regions before reclaim:", .{});
    // pmm.printReservedRegions();

    pmm.markBootServicesExited(boot_info);

    // Show memory stats after reclaim
    const stats_after = pmm.getStats();
    serial.println("[KERNEL] Memory after reclaim: {} MB free, {} MB reserved", .{
        (stats_after.free_memory / (1024 * 1024)),
        (stats_after.reserved_memory / (1024 * 1024)),
    });

    const reclaimed_mb = (stats_after.free_memory - stats_before.free_memory) / (1024 * 1024);
    serial.println("[KERNEL] Boot services memory reclaimed: {} MB", .{reclaimed_mb});

    serial.println("[KERNEL] Memory initialization complete", .{});
    serial.flush();

    // Initialize full security features
    security_init.initFull() catch |err| {
        serial.println("[KERNEL] Full security init failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
        @panic("Failed to initialize full security");
    };

    // Initialize complete CPU features
    cpu_init.initComplete() catch |err| {
        serial.println("[KERNEL] Complete CPU init failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
    };

    // Initialize hardware
    hardware_init.setBootInfo(boot_info);
    hardware_init.init();

    // Test NX bit (uncomment to test - will cause page fault if NX is working)
    // NOTE: Now that we have our own page tables, this should trigger a page fault
    // serial.println("[KERNEL] Testing NX bit in high memory...");
    // cpu_init.testNXInHighMemory();  // This correctly triggers a page fault!

    // Boot info already validated at entry, just print confirmation
    serial.println("[KERNEL] Boot validation complete", .{});
    serial.printAddress("[KERNEL] Kernel at", boot_info.kernel_base);
    secure_print.printSize("[KERNEL] Kernel size", boot_info.kernel_size);
    serial.println("", .{});
    serial.flush();

    // Basic memory info
    if (boot_info.memory_map_addr != 0) {
        serial.println("[KERNEL] Memory map provided by bootloader", .{});
        const count = boot_info.memory_map_size / boot_info.memory_map_descriptor_size;
        serial.println("[KERNEL] Memory regions: {}", .{count});
        serial.flush();
    }

    // Report ACPI if available
    if (boot_info.rsdp_addr != 0) {
        secure_print.printValue("[KERNEL] ACPI RSDP at", boot_info.rsdp_addr);
        serial.flush();
    }

    // Run all diagnostic tests
    diagnostics.runAllTests();

    // Test runtime info security system
    runtime_info.testIntegrityProtection();

    // Test spinlock functionality
    serial.println("[KERNEL] Testing spinlock functionality...", .{});
    spinlock.testSpinLock();
    serial.println("[KERNEL] Spinlock test passed", .{});

    // Test CPU features
    cpu_init.testCFI();

    // Test advanced memory features
    memory_init.testAdvancedFeatures();

    // Test memory protection
    memory_init.testProtection();

    // Report all statistics
    memory_init.reportStatistics();
    security_init.printStatistics();
    cpu_init.printStatistics();

    // Prepare for interrupts
    hardware_init.prepareForInterrupts();

    // Enable interrupts
    hardware_init.enableInterrupts();

    // Print final statistics
    hardware_init.printStatistics();

    serial.println("[KERNEL] Kernel complete - entering main loop", .{});

    // Import AP debug module
    const ap_debug = @import("smp/ap_debug.zig");
    const timer = @import("x86_64/timer.zig");

    // Check AP status periodically
    var last_check_time: u64 = 0;
    var check_count: u32 = 0;

    // Main kernel loop
    while (true) {
        // Check AP status every second
        const current_time = timer.getUptime();
        if (current_time > last_check_time + 1_000_000_000) { // 1 second in nanoseconds
            last_check_time = current_time;
            check_count += 1;

            // Get AP summary
            const summary = ap_debug.getApSummary();

            serial.println("[KERNEL] AP Status Check #{} (uptime: {} ms):", .{ check_count, current_time / 1_000_000 });
            serial.println("  Not started: {}", .{summary.not_started});
            serial.println("  In trampoline: {}", .{summary.in_trampoline});
            serial.println("  Initializing: {}", .{summary.initializing});
            serial.println("  Ready: {}", .{summary.ready});
            serial.println("  Running: {}", .{summary.running});
            serial.println("  Failed: {}", .{summary.failed});
            serial.println("  Total errors: {}", .{summary.total_errors});

            // Check individual AP status for more detail
            if (summary.in_trampoline > 0 or summary.failed > 0) {
                serial.println("  Detailed AP status:", .{});
                var cpu_id: u32 = 1;
                while (cpu_id < 8) : (cpu_id += 1) { // Check first 8 CPUs
                    if (ap_debug.getApStatus(cpu_id)) |status| {
                        if (status.stage != .NotStarted) {
                            serial.println("    CPU {}: stage={s}, error=0x{x}, flags=0x{x}", .{
                                cpu_id,
                                @tagName(status.stage),
                                status.error_code,
                                status.flags,
                            });
                        }
                    }
                }
            }

            serial.flush();
        }

        asm volatile ("hlt");
    }
}
