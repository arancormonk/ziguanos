// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const boot_protocol = @import("shared");
const apic = @import("../x86_64/apic.zig");
const serial = @import("../drivers/serial.zig");

pub const UefiApManager = struct {
    mp_info: boot_protocol.MpServicesInfo,

    pub fn init(boot_info: *const boot_protocol.BootInfo) UefiApManager {
        const manager = UefiApManager{
            .mp_info = boot_info.mp_info,
        };

        if (manager.mp_info.available) {
            serial.println("[UEFI AP] MP Services was available during boot", .{});
            serial.println("[UEFI AP] System has {} APs", .{manager.mp_info.enabled_processors - 1});
        }

        return manager;
    }

    pub fn prepareApStartup(self: *UefiApManager) void {
        if (self.mp_info.ap_initialized_by_uefi) {
            serial.println("[UEFI AP] APs were pre-initialized by UEFI", .{});
            serial.println("[UEFI AP] Using extended INIT sequence for proper reset", .{});
        }
    }

    pub fn getInitDelay(self: *UefiApManager) u32 {
        // UEFI systems need longer delays
        return if (self.mp_info.available) 50_000 else 10_000;
    }

    pub fn getSipiDelay(self: *UefiApManager) u32 {
        // Extended SIPI delays for UEFI
        return if (self.mp_info.available) 10_000 else 200;
    }
};
