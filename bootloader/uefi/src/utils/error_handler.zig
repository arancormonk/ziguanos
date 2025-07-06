// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const uefi_globals = @import("uefi_globals.zig");
const console = @import("console.zig");

/// Error handler that returns to UEFI
pub fn uefiError(status: uefi.Status) noreturn {
    _ = status;
    // Can't use runtime services after ExitBootServices, so just hang
    while (true) {
        asm volatile ("cli");
        asm volatile ("hlt");
    }
}

/// Print an error to the console
pub fn printError(err: anyerror) !void {
    const con_out = uefi_globals.system_table.con_out.?;
    const error_name = @errorName(err);

    // SECURITY: Enforce maximum buffer size to prevent overflow
    const max_error_name_len = 127; // Leave room for null terminator
    const safe_len = @min(error_name.len, max_error_name_len);

    var wide_buffer: [128]u16 = undefined;

    // SECURITY: Use bounded slice operations with explicit bounds checking
    for (error_name[0..safe_len], 0..) |c, i| {
        wide_buffer[i] = c;
    }

    // SECURITY: Ensure null terminator is within bounds
    wide_buffer[safe_len] = 0;

    // If error name was truncated in production mode, append indicator
    if (error_name.len > max_error_name_len) {
        // Add truncation indicator if there's room
        if (safe_len >= 3) {
            wide_buffer[safe_len - 3] = '.';
            wide_buffer[safe_len - 2] = '.';
            wide_buffer[safe_len - 1] = '.';
            wide_buffer[safe_len] = 0;
        }
    }

    _ = con_out.outputString(@ptrCast(&wide_buffer));
}

/// Print error message for kernel hash verification failures
pub fn printHashVerificationError(err: anyerror) void {
    if (err == error.HashMismatch) {
        console.println("\r\nKernel verification failed!");
        console.println("The kernel has been modified or corrupted.");
        console.println("Boot cannot continue for security reasons.");
    } else if (err == error.NoExpectedHash) {
        console.println("\r\nNo expected kernel hash configured!");
        console.println("Secure boot requires a known kernel hash.");
    }
}
