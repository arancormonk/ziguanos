// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const mp_services = @import("protocols/mp_services.zig");
const serial = @import("drivers/serial.zig");

pub const MpInfo = struct {
    total_processors: usize,
    enabled_processors: usize,
    bsp_id: usize,
    ap_initialized_by_uefi: bool = false,
    ap_parking_failed: bool = false,
};

pub fn gatherMpInfo(boot_services: *uefi.tables.BootServices) !MpInfo {
    var info = MpInfo{
        .total_processors = 1, // Default to BSP only
        .enabled_processors = 1,
        .bsp_id = 0,
    };

    // Try to locate MP Services Protocol
    var mp_protocol_ptr: ?*mp_services.Protocol = null;
    const status = boot_services.locateProtocol(&mp_services.guid, null, @ptrCast(&mp_protocol_ptr));

    if (status == .success) {
        serial.print("[MP] Located EFI_MP_SERVICES_PROTOCOL\r\n", .{}) catch {};

        // Get processor count
        var total: usize = 0;
        var enabled: usize = 0;
        const count_status = mp_protocol_ptr.?.get_number_of_processors(mp_protocol_ptr.?, &total, &enabled);

        if (count_status == .success) {
            info.total_processors = total;
            info.enabled_processors = enabled;
            serial.print("[MP] System has {} processors ({} enabled)\r\n", .{ total, enabled }) catch {};
        }

        // Identify BSP
        var current_cpu: usize = 0;
        const who_status = mp_protocol_ptr.?.who_am_i(mp_protocol_ptr.?, &current_cpu);
        if (who_status == .success) {
            info.bsp_id = current_cpu;
            serial.print("[MP] BSP ID: {}\r\n", .{current_cpu}) catch {};
        }

        // If we have multiple processors, assume UEFI might have initialized them
        if (enabled > 1) {
            info.ap_initialized_by_uefi = true;
            serial.print("[MP] Multiple processors detected, assuming UEFI initialization\r\n", .{}) catch {};
        }
    } else {
        serial.print("[MP] EFI_MP_SERVICES_PROTOCOL not available (status: {})\r\n", .{status}) catch {};
        serial.print("[MP] Falling back to ACPI-based AP discovery\r\n", .{}) catch {};
    }

    return info;
}

// AP parking routine - puts AP into halt state
fn apParkingProcedure(parameter: *anyopaque) callconv(.C) void {
    _ = parameter;

    // Disable interrupts and halt
    // This matches the expected "OS compatible CPU state" from UEFI spec
    asm volatile (
        \\cli      # Clear interrupt flag
        \\1:       # Local label
        \\hlt      # Halt processor
        \\jmp 1b   # Jump back to halt (in case of NMI/SMI)
    );
}

// Park all Application Processors in a known halt state before ExitBootServices
pub fn parkAllAPs(boot_services: *uefi.tables.BootServices, mp_info: *MpInfo) void {
    // Try to locate MP Services Protocol
    var mp_protocol_ptr: ?*mp_services.Protocol = null;
    const status = boot_services.locateProtocol(&mp_services.guid, null, @ptrCast(&mp_protocol_ptr));

    if (status != .success) {
        serial.print("[MP] No MP Services Protocol, skipping AP parking\r\n", .{}) catch {};
        return;
    }

    serial.print("[MP] Parking all APs before ExitBootServices...\r\n", .{}) catch {};

    // Get processor count
    var total: usize = 0;
    var enabled: usize = 0;
    const count_status = mp_protocol_ptr.?.get_number_of_processors(mp_protocol_ptr.?, &total, &enabled);

    if (count_status != .success) {
        serial.print("[MP] Failed to get processor count\r\n", .{}) catch {};
        return;
    }

    serial.print("[MP] Total processors: {}, Enabled: {}\r\n", .{ total, enabled }) catch {};

    // If there are enabled APs, park them
    if (enabled > 1) {
        // Use StartupAllAPs to execute parking procedure on all APs
        // timeout_in_microseconds: 50000 = 50ms (should be plenty for parking)
        // wait_for_completion: true - wait for all APs to park
        const startup_status = mp_protocol_ptr.?.startup_all_aps(
            mp_protocol_ptr.?,
            apParkingProcedure,
            true, // single_thread
            null, // wait_event (null = blocking wait)
            50000, // timeout in microseconds
            null, // procedure_argument
            null, // failed_cpu_list
        );

        if (startup_status == .success) {
            serial.print("[MP] Successfully parked {} APs in halt state\r\n", .{enabled - 1}) catch {};
            mp_info.ap_parking_failed = false;
        } else {
            serial.print("[MP] Failed to park APs (status: {})\r\n", .{startup_status}) catch {};
            serial.print("[MP] This is expected if UEFI has already initialized APs\r\n", .{}) catch {};
            mp_info.ap_parking_failed = true;
            // Even if parking failed, continue - kernel will handle it with INIT-SIPI-SIPI
        }
    } else {
        serial.print("[MP] No APs to park (only BSP enabled)\r\n", .{}) catch {};
    }
}

// Legacy function kept for compatibility - creates temporary MpInfo
pub fn disableAllAPs(boot_services: *uefi.tables.BootServices) void {
    var temp_info = MpInfo{
        .total_processors = 0,
        .enabled_processors = 0,
        .bsp_id = 0,
    };
    parkAllAPs(boot_services, &temp_info);
}
