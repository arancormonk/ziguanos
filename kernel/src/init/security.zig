// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const io_security = @import("../x86_64/io_security.zig");
const interrupt_security = @import("../x86_64/interrupt_security.zig");
const stack_security = @import("../x86_64/stack_security.zig");
const spectre_v1 = @import("../x86_64/spectre_v1.zig");
const error_utils = @import("../lib/error_utils.zig");

// Initialize basic security features
pub fn initBasic() void {
    // Initialize I/O port security (must be after GDT)
    io_security.beginInitialization(); // Enter initialization phase
    io_security.init();
    // Enable full security after serial is initialized
    io_security.enableFullSecurity();
    serial.println("[KERNEL] I/O port security initialized", .{});
    serial.flush();

    // Initialize Spectre V1 mitigation system
    spectre_v1.init();
    serial.println("[KERNEL] Spectre V1 mitigation initialized", .{});
    serial.flush();
}

// Initialize full security features after memory management is ready
pub fn initFull() !void {
    serial.println("[SECURITY] Starting full security initialization...", .{});
    serial.flush();

    // Initialize full I/O security now that PMM is available
    io_security.initializeFull() catch |err| {
        serial.println("[KERNEL] WARNING: Full I/O security init failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
        // Continue without full IOPB - basic security still active
    };

    // Test hardware I/O bitmap enforcement
    io_security.testHardwareIOPB() catch |err| {
        serial.println("[KERNEL] WARNING: Hardware IOPB test failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
    };

    // Initialize full interrupt security now that PMM is available
    interrupt_security.fullInit() catch |err| {
        serial.println("[KERNEL] WARNING: Full interrupt security init failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
        // Continue with static IST stacks - basic security still active
    };

    // Initialize advanced stack protection features now that PMM is ready
    stack_security.initializeAdvancedFeatures() catch |err| {
        serial.println("[KERNEL] ERROR: Advanced stack protection init failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
        return err;
    };

    // Set up stack guard pages after paging is initialized
    stack_security.setupStackGuardPages() catch |err| {
        serial.println("[KERNEL] ERROR: Stack guard pages setup failed: {s}", .{error_utils.errorToString(err)});
        serial.flush();
        return err;
    };
}

// Print security statistics
pub fn printStatistics() void {
    // Print I/O access statistics
    io_security.printAccessStats();

    // Print stack security statistics
    stack_security.printStatistics();
}
