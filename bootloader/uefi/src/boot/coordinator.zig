// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const serial = @import("../drivers/serial.zig");
const kernel_loader = @import("kernel_loader.zig");
const verify = @import("../security/verify.zig");
const policy = @import("../security/policy.zig");
const variable_cache = @import("../security/variable_cache.zig");
const hmac = @import("../security/hmac.zig");
const uefi_globals = @import("../utils/uefi_globals.zig");
const console = @import("../utils/console.zig");
const error_handler = @import("../utils/error_handler.zig");
const memory_manager = @import("../utils/memory_manager.zig");
const secure_debug = @import("../security/secure_debug_integration.zig");

/// Main boot coordination function
pub fn boot(handle: uefi.Handle) !void {
    // Phase 1: Initialize console and display banner
    console.printBanner();

    // Initialize secure debug system early
    secure_debug.init();

    // Phase 2: Initialize security subsystems
    try initializeSecurity(handle);

    // Phase 3: Check secure boot and display system info
    const secure_boot_enabled = verify.checkSecureBootStatus(uefi_globals.system_table);
    console.printSystemInfo();
    console.printSecureBootStatus(secure_boot_enabled);

    // Run debug tests if in debug mode and development security level
    const builtin = @import("builtin");
    if (builtin.mode == .Debug and policy.getSecurityLevel() == .Development) {
        runDebugTests();
    }

    // Phase 4: Load and verify kernel
    console.println("Loading kernel...");
    serial.print("[UEFI] Loading kernel\r\n", .{}) catch {};

    const kernel_info = try loadAndVerifyKernel(handle);

    console.println("Kernel loaded successfully");
    secure_debug.printKernelLoad(kernel_info.base_address, kernel_info.entry_point, kernel_info.size);

    // Print security violation summary
    policy.printViolationSummary() catch {};

    // Phase 5: Prepare for kernel handoff
    console.println("Getting memory map...");
    const memory_map = try prepareMemoryMapAndExitBootServices(handle);

    // Phase 6: Jump to kernel
    secure_debug.printJumpToKernel(kernel_info.entry_point);
    const kl_memory_map = memory_manager.convertToKernelLoaderFormat(memory_map);
    kernel_loader.jumpToKernel(kernel_info, kl_memory_map);
}

/// Initialize all security subsystems
fn initializeSecurity(handle: uefi.Handle) !void {
    // Initialize variable cache first to prevent TOCTOU vulnerabilities
    variable_cache.initWithFileSupport(
        uefi_globals.system_table.runtime_services,
        handle,
        uefi_globals.boot_services,
        uefi.pool_allocator,
    ) catch |err| {
        console.print("WARNING: Failed to initialize variable cache: ");
        error_handler.printError(err) catch {};
        console.println("");

        // SECURITY: In non-Development mode, variable cache initialization failure
        // is a critical security issue that can enable TOCTOU attacks
        if (policy.DEFAULT_SECURITY_LEVEL != .Development) {
            console.println("FATAL: Variable cache initialization failed - security policy violation");
            serial.print("[UEFI] FATAL: Variable cache initialization failed in {} mode\r\n", .{policy.DEFAULT_SECURITY_LEVEL}) catch {};
            error_handler.uefiError(.aborted);
        }
        // Continue with defaults only in Development mode
    };

    // Initialize security policy (will use cached variables)
    policy.init(uefi_globals.system_table.runtime_services);

    // Initialize serial port for debugging with policy enforcement
    policy.checkSerialInit(serial.init()) catch {
        console.println("FATAL: Serial initialization failed - security policy violation");
        error_handler.uefiError(.aborted);
    };

    serial.print("[UEFI] Bootloader started\r\n", .{}) catch {};

    // Run HMAC self-test before any cryptographic operations
    hmac.selfTest() catch |err| {
        console.println("FATAL: HMAC self-test failed - cryptographic subsystem compromised");
        serial.print("[UEFI] FATAL: HMAC self-test failed: {}\r\n", .{err}) catch {};
        error_handler.uefiError(.aborted);
    };

    // Try to load expected kernel hash from UEFI variables with policy enforcement
    policy.checkKernelHashLoad(verify.loadExpectedHashFromUEFI(uefi_globals.system_table.runtime_services)) catch {
        console.println("FATAL: Kernel hash load failed - security policy violation");
        error_handler.uefiError(.aborted);
    };

    // Load HMAC key and expected HMAC for kernel authentication
    if (verify.ENABLE_HMAC_VERIFICATION) {
        verify.loadHMACKeyFromUEFI(uefi_globals.system_table.runtime_services) catch |err| {
            serial.print("[UEFI] WARNING: Failed to load HMAC key: {}\r\n", .{err}) catch {};
            // Not fatal - HMAC verification will be skipped if key not available
        };

        verify.loadExpectedHMACFromUEFI(uefi_globals.system_table.runtime_services) catch |err| {
            serial.print("[UEFI] WARNING: Failed to load expected HMAC: {}\r\n", .{err}) catch {};
            // Not fatal - HMAC verification will be skipped if expected HMAC not available
        };
    }
}

/// Run debug tests if in debug mode
fn runDebugTests() void {
    const test_error_sanitizer = @import("../security/tests/error_sanitizer_test.zig");
    test_error_sanitizer.runErrorSanitizerTests() catch |err| {
        serial.print("[TEST] Error sanitizer tests failed: {}\r\n", .{err}) catch {};
    };
}

/// Load and verify the kernel
fn loadAndVerifyKernel(handle: uefi.Handle) !kernel_loader.KernelInfo {
    return kernel_loader.loadKernel(handle, uefi_globals.boot_services, uefi_globals.uefi_allocator) catch |err| {
        console.print("Failed to load kernel: ");
        error_handler.printError(err) catch {};
        console.println("");

        // Provide specific error message for hash verification failures
        error_handler.printHashVerificationError(err);

        console.waitForKeypress();
        error_handler.uefiError(.load_error);
    };
}

/// Get memory map and exit boot services
fn prepareMemoryMapAndExitBootServices(handle: uefi.Handle) !memory_manager.MemoryMap {
    var memory_map = memory_manager.getMemoryMap() catch {
        console.println("Failed to get memory map");
        console.waitForKeypress();
        error_handler.uefiError(.out_of_resources);
    };

    // Exit boot services
    console.println("Exiting boot services...");
    serial.print("[UEFI] Exiting boot services\r\n", .{}) catch {};

    switch (uefi_globals.boot_services.exitBootServices(handle, memory_map.key)) {
        .success => {},
        else => {
            // If failed, we need to get the memory map again
            serial.print("[UEFI] First exit attempt failed, retrying\r\n", .{}) catch {};
            memory_map = memory_manager.getMemoryMap() catch {
                error_handler.uefiError(.load_error);
            };
            switch (uefi_globals.boot_services.exitBootServices(handle, memory_map.key)) {
                .success => {},
                else => error_handler.uefiError(.load_error),
            }
        },
    }

    return memory_map;
}
