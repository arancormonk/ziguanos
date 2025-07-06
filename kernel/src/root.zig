// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");

// Re-export panic handler
pub const panic = @import("lib/panic.zig").panic;

// Ensure exceptions module is linked
comptime {
    _ = @import("x86_64/exceptions.zig");
}

// Import boot initialization
const boot = @import("boot/init.zig");

// Import early initialization
const early_init = @import("init/early.zig");

// Import kernel main
const kernel_main = @import("main.zig");

// The entry point is already exported in boot/entry.zig
// We just need to ensure it's linked by importing the module
comptime {
    _ = @import("boot/entry.zig");
}

// Forward declaration required by mode_handler
export fn kernelMain(boot_info: *const @import("boot/uefi_boot.zig").UEFIBootInfo) noreturn {
    _ = boot_info; // Boot info parameter required for interface, but we use saved copy

    // Get the saved boot info from entry module
    const saved_info = @import("boot/entry.zig").getSavedBootInfo();

    // Perform early initialization with saved boot info
    early_init.init(saved_info);

    // Continue with main kernel initialization with saved boot info
    kernel_main.kernelMain(saved_info);
}
