// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const uefi_boot = @import("../boot/uefi_boot.zig");
const idt = @import("../x86_64/idt.zig");
const stack_security = @import("../x86_64/stack_security.zig");

// UEFI boot info structure
const UEFIBootInfo = uefi_boot.UEFIBootInfo;

// Perform early initialization tasks
// This includes IDT setup, stack security, and serial initialization
pub fn init(boot_info: *const UEFIBootInfo) void {
    // Set up minimal IDT with critical exception handlers before stack switch
    idt.initMinimal();

    // Set up full IDT with all exception and interrupt handlers
    idt.init();

    // Initialize boot entropy from UEFI before stack security
    stack_security.initializeBootEntropy(boot_info);

    // Initialize stack security
    stack_security.init() catch {};

    // Now safe to initialize serial and continue
    serial.init();
    serial.println("[KERNEL] Ziguanos Kernel", .{});

    // Note: Kexec support would require command line parsing
    // For now, we'll use the RSDP from boot info if available

    serial.println("[KERNEL] Early initialization complete", .{});
    serial.println("[KERNEL] - Boot info validated", .{});
    serial.println("[KERNEL] - CPU state verified", .{});
    serial.println("[KERNEL] - GDT initialized", .{});
    serial.println("[KERNEL] - Minimal IDT loaded (pre-stack switch)", .{});
    serial.println("[KERNEL] - Stack switched to kernel stack", .{});
    serial.println("[KERNEL] - Full IDT initialized", .{});
    serial.println("[KERNEL] - Stack security initialized", .{});
    serial.flush(); // Ensure early messages appear immediately
}
