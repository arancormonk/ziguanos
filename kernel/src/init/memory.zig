// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const uefi_boot = @import("../boot/uefi_boot.zig");
const paging = @import("../x86_64/paging.zig");
const pmm = @import("../memory/pmm.zig");
const vmm = @import("../memory/vmm.zig");
const stack_security = @import("../x86_64/stack_security.zig");
const secure_print = @import("../lib/secure_print.zig");
const error_utils = @import("../lib/error_utils.zig");

// UEFI boot info structure
const UEFIBootInfo = uefi_boot.UEFIBootInfo;

// Kernel stack configuration
const KERNEL_STACK_SIZE = 32; // pages (128KB)

// Initialize memory subsystems phase 1 - up to stack allocation
pub fn initPhase1(boot_info: *const UEFIBootInfo) !struct { phys: u64, top: u64 } {
    // Initialize paging with proper permissions
    paging.init(boot_info);
    paging.printInfo();
    serial.flush(); // Ensure paging initialization is visible

    // Debug: check boot info is still valid after paging
    serial.printAddress("[KERNEL] After paging - boot info at", @intFromPtr(boot_info));
    serial.println("[KERNEL] Magic: 0x{x:0>16}", .{boot_info.magic});
    secure_print.printValue("[KERNEL] Memory map addr", boot_info.memory_map_addr);
    secure_print.printSize("[KERNEL] Memory map size", boot_info.memory_map_size);
    secure_print.printSize("[KERNEL] Memory map descriptor size", boot_info.memory_map_descriptor_size);
    serial.flush();

    // Initialize physical memory manager
    pmm.init(boot_info);

    // Allocate a proper kernel stack now that PMM is available
    serial.println("[KERNEL] About to allocate kernel stack ({} pages)...", .{KERNEL_STACK_SIZE});
    serial.flush();
    const kernel_stack_phys = pmm.allocPagesTagged(KERNEL_STACK_SIZE, .KERNEL_DATA) orelse {
        serial.println("[KERNEL] FATAL: Failed to allocate kernel stack", .{});
        serial.flush();
        @panic("Failed to allocate kernel stack");
    };

    // Calculate new stack pointer (stack grows down, so point to top)
    const new_stack_top = kernel_stack_phys + (KERNEL_STACK_SIZE * 0x1000);

    secure_print.printValue("[KERNEL] New kernel stack will be at", new_stack_top);
    serial.flush();

    // Return the stack info for the caller to use
    return .{ .phys = kernel_stack_phys, .top = new_stack_top };
}

// Initialize memory subsystems phase 2 - after stack switch
pub fn initPhase2(kernel_stack_phys: u64, new_stack_top: u64, _: *const UEFIBootInfo) !void {
    serial.println("[KERNEL] Successfully switched to new kernel stack", .{});
    serial.flush();

    // Update stack security with new stack info
    stack_security.updateStackInfo(kernel_stack_phys, new_stack_top);
    stack_security.checkStackDepth();
    serial.flush(); // Ensure stack security update is visible

    // Phase 2 removed - bootloader now allocates all page tables
    serial.println("[KERNEL] All memory already mapped by bootloader", .{});
    serial.flush();

    // Initialize virtual memory manager
    vmm.init() catch |err| {
        serial.println("[KERNEL] VMM init failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
        return err;
    };
    vmm.printInfo();
    serial.println("[KERNEL] Virtual memory manager initialized", .{});

    // Enable memory zeroing now that VMM is ready
    // This was disabled during early boot to avoid KVM issues with physical memory access
    pmm.memory_security.setZeroOnAlloc(true);
    serial.println("[KERNEL] Memory zeroing on allocation enabled", .{});
    serial.flush();
}

// Test memory protection features
pub fn testProtection() void {
    serial.println("[KERNEL] Testing memory protection features...", .{});
    pmm.testMemoryProtection();
    paging.testPagingMemoryProtection();
    serial.flush(); // Ensure memory protection test results are visible
}

// Test advanced paging features
pub fn testAdvancedFeatures() void {
    // Run all paging tests
    paging.testAllPagingFeatures();
}

// Report memory usage statistics
pub fn reportStatistics() void {
    pmm.reportSecurityStats();
    pmm.reportTaggedMemoryUsage();
}
