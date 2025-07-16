// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const uefi_boot = @import("../boot/uefi_boot.zig");

// External symbols from linker script
extern const __bss_start: u8;
extern const __bss_end: u8;

// UEFI boot info structure
const UEFIBootInfo = uefi_boot.UEFIBootInfo;

// Clear BSS section while preserving the given boot info structure
// This is necessary because the BSS section contains uninitialized global variables
// that need to be zeroed, but we must preserve the saved boot info
pub fn clearBSSPreserving(preserved_data: *const anyopaque, preserved_size: usize) void {
    const bss_start = @intFromPtr(&__bss_start);
    const bss_end = @intFromPtr(&__bss_end);
    const preserved_start = @intFromPtr(preserved_data);
    const preserved_end = preserved_start + preserved_size;

    // Clear BSS in two parts to avoid overwriting preserved data
    if (bss_start < preserved_start) {
        // Clear before preserved data
        const size = preserved_start - bss_start;
        const slice = @as([*]u8, @ptrFromInt(bss_start))[0..size];
        @memset(slice, 0);
    }

    if (preserved_end < bss_end) {
        // Clear after preserved data
        const size = bss_end - preserved_end;
        const slice = @as([*]u8, @ptrFromInt(preserved_end))[0..size];
        @memset(slice, 0);
    }

    serial.println("[KERNEL] BSS cleared", .{});
}
