// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const uefi_globals = @import("uefi_globals.zig");

// Helper to create wide string literals
pub fn L(comptime str: []const u8) *const [str.len + 1:0]u16 {
    const result = comptime blk: {
        var r: [str.len + 1:0]u16 = undefined;
        for (str, 0..) |c, i| {
            r[i] = c;
        }
        r[str.len] = 0;
        break :blk r;
    };
    return &result;
}

// Clear screen and print the bootloader banner
pub fn printBanner() void {
    const con_out = uefi_globals.system_table.con_out.?;

    _ = con_out.clearScreen();
    _ = con_out.outputString(L("\r\n\r\n=============================\r\n"));
    _ = con_out.outputString(L("Ziguanos UEFI Bootloader v0.1"));
    _ = con_out.outputString(L("\r\n=============================\r\n\r\n"));
}

// Print system information
pub fn printSystemInfo() void {
    const con_out = uefi_globals.system_table.con_out.?;

    _ = con_out.outputString(L("Firmware: "));
    _ = con_out.outputString(uefi_globals.system_table.firmware_vendor);
    _ = con_out.outputString(L("\r\n"));
}

// Print secure boot status
pub fn printSecureBootStatus(secure_boot_enabled: bool) void {
    const con_out = uefi_globals.system_table.con_out.?;

    if (secure_boot_enabled) {
        _ = con_out.outputString(L("UEFI Firmware Secure Boot: ENABLED\r\n"));
    } else {
        _ = con_out.outputString(L("UEFI Firmware Secure Boot: DISABLED\r\n"));
    }
    _ = con_out.outputString(L("Ziguanos Kernel Verification: ENABLED\r\n"));
    _ = con_out.outputString(L("\r\n"));
}

// Print a simple message
pub fn print(comptime message: []const u8) void {
    const con_out = uefi_globals.system_table.con_out.?;
    _ = con_out.outputString(L(message));
}

// Print a message with newline
pub fn println(comptime message: []const u8) void {
    const con_out = uefi_globals.system_table.con_out.?;
    _ = con_out.outputString(L(message));
    _ = con_out.outputString(L("\r\n"));
}

// Wait for user to press a key
pub fn waitForKeypress() void {
    const con_in = uefi_globals.system_table.con_in.?;
    var key: uefi.protocol.SimpleTextInput.Key.Input = undefined;

    // Clear any pending input
    while (con_in.readKeyStroke(&key) == .success) {}

    _ = uefi_globals.system_table.con_out.?.outputString(L("\r\nPress any key to continue...\r\n"));

    // Wait for a key
    while (con_in.readKeyStroke(&key) != .success) {
        asm volatile ("pause");
    }
}
