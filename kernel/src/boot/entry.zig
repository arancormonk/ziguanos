// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const uefi_boot = @import("../boot/uefi_boot.zig");
const cpu_state = @import("../x86_64/cpu_state.zig");
const secure_print = @import("../lib/secure_print.zig");
const validation = @import("validation.zig");
const bss = @import("bss.zig");
const mode_handler = @import("mode_handler.zig");

// UEFI boot info structure
const UEFIBootInfo = uefi_boot.UEFIBootInfo;

// External symbols from linker script
extern const __boot_stack_top: u8;

// External symbols from assembly entry point
extern var boot_info_ptr: usize;
extern fn _start() void;

// Global to preserve boot info pointer across stack switch
// Make it pub so other modules can access it
pub var saved_boot_info: UEFIBootInfo = undefined;

// Kernel entry point called from assembly
// The assembly stub has already saved the boot info pointer
export fn _zig_start() callconv(.C) noreturn {
    // Disable interrupts immediately for security
    asm volatile ("cli");

    // Initialize serial port early for debugging
    serial.init();
    serial.println("[KERNEL] Entry point reached", .{});
    secure_print.printValue("[KERNEL] Boot info pointer from assembly", boot_info_ptr);

    // Get the boot info pointer that was saved by the assembly entry point
    const real_boot_info = @as(*const UEFIBootInfo, @ptrFromInt(boot_info_ptr));

    // First, switch to our minimal boot stack to avoid using UEFI's stack
    asm volatile (
        \\mov %[stack], %%rsp
        :
        : [stack] "r" (@intFromPtr(&__boot_stack_top)),
    );

    serial.println("[KERNEL] Stack switched", .{});

    // CRITICAL: Validate boot info FIRST before any use
    validation.validateBootInfo(real_boot_info) catch {
        serial.println("[KERNEL] ERROR: Boot info validation failed!", .{});
        serial.flush();
        // Cannot use serial yet, halt immediately
        while (true) {
            asm volatile ("hlt");
        }
    };

    serial.println("[KERNEL] Boot info validated", .{});

    // Save boot info FIRST
    saved_boot_info = real_boot_info.*;

    serial.println("[KERNEL] Boot info saved", .{});
    serial.flush(); // Ensure critical early state is visible

    // NOW clear BSS section EXCEPT for saved_boot_info
    bss.clearBSSPreserving(&saved_boot_info, @sizeOf(UEFIBootInfo));

    // Verify CPU state before anything else
    cpu_state.verifyCPUState();

    serial.println("[KERNEL] CPU state verified", .{});
    serial.flush(); // Ensure CPU state verification is visible

    // Check PIE mode and handle appropriately
    if (real_boot_info.pie_mode) {
        serial.println("[KERNEL] PIE mode detected", .{});
        serial.flush(); // Ensure boot mode is visible before transition
        // PIE mode: We're running at physical addresses
        mode_handler.handlePIEBoot(&saved_boot_info);
    } else {
        serial.println("[KERNEL] Normal mode (identity mapped)", .{});
        serial.flush(); // Ensure boot mode is visible before transition
        // Traditional mode: Already at virtual addresses (identity mapped)
        mode_handler.handleNormalBoot(&saved_boot_info);
    }
}

// Get the saved boot info pointer
pub fn getSavedBootInfo() *const UEFIBootInfo {
    return &saved_boot_info;
}
