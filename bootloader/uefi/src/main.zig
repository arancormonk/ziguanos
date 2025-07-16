// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const uefi_globals = @import("utils/uefi_globals.zig");
const boot_coordinator = @import("boot/coordinator.zig");
const error_handler = @import("utils/error_handler.zig");
const console = @import("utils/console.zig");

// Main entry point for UEFI application
pub fn main() noreturn {
    // Initialize global UEFI state
    uefi_globals.init(uefi.system_table);

    // Get UEFI handle
    const handle = uefi.handle;

    // Run the boot sequence
    boot_coordinator.boot(handle) catch |err| {
        // Handle fatal boot errors
        console.print("FATAL: Boot failed with error: ");
        error_handler.printError(err) catch {};
        console.println("");
        console.waitForKeypress();
        error_handler.uefiError(.load_error);
    };

    // Should never reach here as boot_coordinator jumps to kernel
    error_handler.uefiError(.aborted);
}
