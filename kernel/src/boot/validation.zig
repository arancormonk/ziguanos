// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const secure_print = @import("../lib/secure_print.zig");
const uefi_boot = @import("../boot/uefi_boot.zig");

// UEFI boot info structure
const UEFIBootInfo = uefi_boot.UEFIBootInfo;

// Boot magic constant
const BOOT_MAGIC = 0x5A49475541524E53; // "ZIGUANOS"

/// Validates the boot info structure passed from bootloader
/// Must be done before ANY use of boot info
pub fn validateBootInfo(info: *const UEFIBootInfo) !void {
    // Check magic immediately
    if (info.magic != BOOT_MAGIC) {
        serial.println("[KERNEL] Invalid magic: 0x{x:0>16} (expected 0x{x:0>16})", .{ info.magic, BOOT_MAGIC });
        return error.InvalidMagic;
    }

    // Validate kernel base and size
    if (info.kernel_base < 0x100000 or info.kernel_base > 0x100000000) {
        secure_print.printValue("[KERNEL] Invalid kernel base", info.kernel_base);
        return error.InvalidKernelBase;
    }

    if (info.kernel_size == 0 or info.kernel_size > 0x10000000) {
        secure_print.printSize("[KERNEL] Invalid kernel size", info.kernel_size);
        return error.InvalidKernelSize;
    }

    // Check for integer overflow
    const kernel_end = @addWithOverflow(info.kernel_base, info.kernel_size);
    if (kernel_end[1] != 0) { // Overflow occurred
        serial.println("[KERNEL] Kernel range overflow", .{});
        return error.KernelRangeOverflow;
    }

    // Validate memory map pointer if present
    if (info.memory_map_addr != 0) {
        if (info.memory_map_addr < 0x1000 or
            info.memory_map_size == 0 or
            info.memory_map_descriptor_size == 0)
        {
            serial.println("[KERNEL] Invalid memory map:", .{});
            secure_print.printValue("  Address", info.memory_map_addr);
            secure_print.printSize("  Size", info.memory_map_size);
            secure_print.printSize("  Descriptor size", info.memory_map_descriptor_size);
            return error.InvalidMemoryMap;
        }
    }
}
