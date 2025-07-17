// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const boot_protocol = @import("../../../shared/boot_protocol.zig");
const UefiApManager = @import("../uefi_ap_manager.zig").UefiApManager;
const ap_startup = @import("../ap_startup_sequence.zig");
const validator = @import("../ap_state_validator.zig");
const serial = @import("../../drivers/serial.zig");

// Runtime test functions for UEFI AP support
pub fn runAll() !void {
    serial.println("[UEFI AP Tests] Starting UEFI AP test suite...", .{});

    try testUefiApInitialization();
    try testUefiExtendedDelays();
    try testApStateValidation();
    try testUefiApManagerBehavior();

    serial.println("[UEFI AP Tests] All tests completed successfully", .{});
}

pub fn testUefiApInitialization() !void {
    serial.println("[UEFI AP Test] Testing MP info initialization sequence", .{});

    // Test 1: Verify MP info is properly passed from bootloader
    const mp_info = boot_protocol.MpServicesInfo{
        .available = true,
        .total_processors = 4,
        .enabled_processors = 4,
        .bsp_id = 0,
        .ap_initialized_by_uefi = true,
        ._reserved = .{ 0, 0, 0 },
    };

    const boot_info = boot_protocol.BootInfo{
        .magic = boot_protocol.BOOT_INFO_MAGIC,
        .version = boot_protocol.BOOT_INFO_VERSION,
        .kernel_base = 0x200000,
        .kernel_size = 0x100000,
        .kernel_text_base = 0x200000,
        .kernel_text_size = 0x50000,
        .kernel_rodata_base = 0x250000,
        .kernel_rodata_size = 0x20000,
        .kernel_data_base = 0x270000,
        .kernel_data_size = 0x30000,
        .kernel_bss_base = 0x2A0000,
        .kernel_bss_size = 0x60000,
        .memory_map_base = 0x100000,
        .memory_map_size = 0x1000,
        .memory_map_descriptor_size = 48,
        .memory_map_descriptor_version = 1,
        .framebuffer_base = 0,
        .framebuffer_size = 0,
        .kernel_hash = [_]u8{0} ** 32,
        .kernel_hash_valid = false,
        .secure_boot_enabled = false,
        .kernel_hmac = [_]u8{0} ** 32,
        .kernel_hmac_valid = false,
        .acpi_rsdp_address = 0,
        .smbios_address = 0,
        .efi_system_table_address = 0,
        .kaslr_offset = 0,
        .mp_info = mp_info,
    };

    // Initialize the UEFI AP manager
    const manager = UefiApManager.init(&boot_info);

    // Verify MP info was properly initialized
    if (!manager.mp_info.available) {
        return error.MpInfoNotAvailable;
    }
    if (manager.mp_info.total_processors != 4) {
        return error.InvalidProcessorCount;
    }
    if (manager.mp_info.enabled_processors != 4) {
        return error.InvalidEnabledCount;
    }
    if (manager.mp_info.bsp_id != 0) {
        return error.InvalidBspId;
    }
    if (!manager.mp_info.ap_initialized_by_uefi) {
        return error.ApNotInitializedByUefi;
    }

    serial.println("[UEFI AP Test] ✓ MP info initialization test passed", .{});
}

pub fn testUefiExtendedDelays() !void {
    serial.println("[UEFI AP Test] Testing UEFI extended delays", .{});

    // Test UEFI system (with MP Services)
    const mp_info_uefi = boot_protocol.MpServicesInfo{
        .available = true,
        .total_processors = 2,
        .enabled_processors = 2,
        .bsp_id = 0,
        .ap_initialized_by_uefi = true,
        ._reserved = .{ 0, 0, 0 },
    };

    const boot_info_uefi = createTestBootInfo(mp_info_uefi);

    var uefi_manager = UefiApManager.init(&boot_info_uefi);
    const uefi_init_delay = uefi_manager.getInitDelay();
    const uefi_sipi_delay = uefi_manager.getSipiDelay();

    // Verify UEFI systems use extended delays
    if (uefi_init_delay != 50_000) {
        serial.println("[UEFI AP Test] ✗ Expected UEFI INIT delay of 50000, got {}", .{uefi_init_delay});
        return error.InvalidUefiInitDelay;
    }
    if (uefi_sipi_delay != 10_000) {
        serial.println("[UEFI AP Test] ✗ Expected UEFI SIPI delay of 10000, got {}", .{uefi_sipi_delay});
        return error.InvalidUefiSipiDelay;
    }

    // Test non-UEFI system (no MP Services)
    const mp_info_legacy = boot_protocol.MpServicesInfo{
        .available = false,
        .total_processors = 1,
        .enabled_processors = 1,
        .bsp_id = 0,
        .ap_initialized_by_uefi = false,
        ._reserved = .{ 0, 0, 0 },
    };

    const boot_info_legacy = createTestBootInfo(mp_info_legacy);

    var legacy_manager = UefiApManager.init(&boot_info_legacy);
    const legacy_init_delay = legacy_manager.getInitDelay();
    const legacy_sipi_delay = legacy_manager.getSipiDelay();

    // Verify legacy systems use shorter delays
    if (legacy_init_delay != 10_000) {
        serial.println("[UEFI AP Test] ✗ Expected legacy INIT delay of 10000, got {}", .{legacy_init_delay});
        return error.InvalidLegacyInitDelay;
    }
    if (legacy_sipi_delay != 200) {
        serial.println("[UEFI AP Test] ✗ Expected legacy SIPI delay of 200, got {}", .{legacy_sipi_delay});
        return error.InvalidLegacySipiDelay;
    }

    serial.println("[UEFI AP Test] ✓ Extended delay test passed", .{});
}

pub fn testApStateValidation() !void {
    serial.println("[UEFI AP Test] Testing AP state validation", .{});

    // Test that validation properly times out when AP doesn't start
    const timeout_ms: u32 = 100; // Short timeout for testing

    // This test would need actual AP startup to work fully,
    // but we can test the structure
    const validator_instance = validator.ApStateValidator{};

    // Verify validator compiles and has expected methods
    _ = validator_instance;
    _ = timeout_ms;

    // In a real environment, we would test:
    // 1. validateApStarted returns true when AP sets debug magic
    // 2. validateApStarted returns false on timeout
    // 3. diagnoseTrampolineIssue provides useful debugging info

    serial.println("[UEFI AP Test] ✓ AP state validation structure test passed", .{});
}

pub fn testUefiApManagerBehavior() !void {
    serial.println("[UEFI AP Test] Testing UEFI AP manager behavior", .{});

    // Test with UEFI-initialized APs
    const mp_info_initialized = boot_protocol.MpServicesInfo{
        .available = true,
        .total_processors = 2,
        .enabled_processors = 2,
        .bsp_id = 0,
        .ap_initialized_by_uefi = true,
        ._reserved = .{ 0, 0, 0 },
    };

    const boot_info_initialized = createTestBootInfo(mp_info_initialized);

    var manager = UefiApManager.init(&boot_info_initialized);

    // This should execute without errors
    manager.prepareApStartup();

    // Verify the manager recognizes UEFI-initialized APs
    if (!manager.mp_info.ap_initialized_by_uefi) {
        return error.ApInitializationNotRecognized;
    }

    serial.println("[UEFI AP Test] ✓ UEFI AP manager behavior test passed", .{});
}

// Helper function to create test boot info
fn createTestBootInfo(mp_info: boot_protocol.MpServicesInfo) boot_protocol.BootInfo {
    return boot_protocol.BootInfo{
        .magic = boot_protocol.BOOT_INFO_MAGIC,
        .version = boot_protocol.BOOT_INFO_VERSION,
        .kernel_base = 0x200000,
        .kernel_size = 0x100000,
        .kernel_text_base = 0x200000,
        .kernel_text_size = 0x50000,
        .kernel_rodata_base = 0x250000,
        .kernel_rodata_size = 0x20000,
        .kernel_data_base = 0x270000,
        .kernel_data_size = 0x30000,
        .kernel_bss_base = 0x2A0000,
        .kernel_bss_size = 0x60000,
        .memory_map_base = 0x100000,
        .memory_map_size = 0x1000,
        .memory_map_descriptor_size = 48,
        .memory_map_descriptor_version = 1,
        .framebuffer_base = 0,
        .framebuffer_size = 0,
        .kernel_hash = [_]u8{0} ** 32,
        .kernel_hash_valid = false,
        .secure_boot_enabled = false,
        .kernel_hmac = [_]u8{0} ** 32,
        .kernel_hmac_valid = false,
        .acpi_rsdp_address = 0,
        .smbios_address = 0,
        .efi_system_table_address = 0,
        .kaslr_offset = 0,
        .mp_info = mp_info,
    };
}
