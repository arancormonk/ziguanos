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

/// Main kernel initialization and run loop - Phase 1
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
        serial.println("[KERNEL] Memory init phase 1 failed: {s}", .{@errorName(err)});
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

/// Kernel initialization phase 2 - after stack switch
fn kernelMainPhase2() noreturn {
    // We're now on the new stack
    const boot_info = saved_boot_info_ptr;

    // Complete memory initialization
    memory_init.initPhase2(saved_stack_phys, saved_stack_top, boot_info) catch |err| {
        serial.println("[KERNEL] Memory init phase 2 failed: {s}", .{@errorName(err)});
        serial.flush();
        @panic("Failed to complete memory initialization");
    };

    serial.println("[KERNEL] Memory initialization complete", .{});
    serial.flush();

    // Initialize full security features
    security_init.initFull() catch |err| {
        serial.println("[KERNEL] Full security init failed: {s}", .{@errorName(err)});
        serial.flush();
        @panic("Failed to initialize full security");
    };

    // Initialize complete CPU features
    cpu_init.initComplete() catch |err| {
        serial.println("[KERNEL] Complete CPU init failed: {s}", .{@errorName(err)});
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

    serial.println("[KERNEL] Kernel complete - halting", .{});

    // Main kernel loop
    while (true) {
        asm volatile ("hlt");
    }
}
