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
    } else {
        serial.print("[MP] EFI_MP_SERVICES_PROTOCOL not available (status: {})\r\n", .{status}) catch {};
        serial.print("[MP] Falling back to ACPI-based AP discovery\r\n", .{}) catch {};
    }

    return info;
}

// Disable all Application Processors before ExitBootServices
pub fn disableAllAPs(boot_services: *uefi.tables.BootServices) void {
    // Try to locate MP Services Protocol
    var mp_protocol_ptr: ?*mp_services.Protocol = null;
    const status = boot_services.locateProtocol(&mp_services.guid, null, @ptrCast(&mp_protocol_ptr));

    if (status != .success) {
        // No MP Services, nothing to do
        return;
    }

    serial.print("[MP] Disabling all APs before ExitBootServices...\r\n", .{}) catch {};

    // Get processor count
    var total: usize = 0;
    var enabled: usize = 0;
    const count_status = mp_protocol_ptr.?.get_number_of_processors(mp_protocol_ptr.?, &total, &enabled);

    if (count_status != .success) {
        serial.print("[MP] Failed to get processor count\r\n", .{}) catch {};
        return;
    }

    // Identify BSP
    var bsp_id: usize = 0;
    const who_status = mp_protocol_ptr.?.who_am_i(mp_protocol_ptr.?, &bsp_id);
    if (who_status != .success) {
        serial.print("[MP] Failed to identify BSP\r\n", .{}) catch {};
        return;
    }

    // Disable each AP
    var disabled_count: usize = 0;
    for (0..total) |cpu_index| {
        if (cpu_index == bsp_id) continue; // Skip BSP

        // Get processor info to check if it's enabled
        var proc_info: mp_services.ProcessorInformation = undefined;
        const info_status = mp_protocol_ptr.?.get_processor_info(mp_protocol_ptr.?, cpu_index, &proc_info);

        if (info_status == .success and (proc_info.status_flag & 0x01) != 0) { // PROCESSOR_ENABLED_BIT
            // Disable this AP
            const disable_status = mp_protocol_ptr.?.enable_disable_ap(mp_protocol_ptr.?, cpu_index, false, null);

            if (disable_status == .success) {
                disabled_count += 1;
                serial.print("[MP] Disabled AP {} (APIC ID {})\r\n", .{ cpu_index, proc_info.processor_id }) catch {};
            } else {
                serial.print("[MP] Failed to disable AP {} (status: {})\r\n", .{ cpu_index, disable_status }) catch {};
            }
        }
    }

    serial.print("[MP] Disabled {} APs\r\n", .{disabled_count}) catch {};
}
