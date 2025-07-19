// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const paging = @import("../x86_64/paging.zig");
const apic = @import("../x86_64/apic_unified.zig");
const timer = @import("../x86_64/timer.zig");
const madt = @import("../drivers/acpi/madt.zig");

// ACPI Multiprocessor Wakeup mailbox commands
const MP_WAKEUP_COMMAND_NOOP: u16 = 0x0000;
const MP_WAKEUP_COMMAND_WAKEUP: u16 = 0x0001;

pub const ParkingManager = struct {
    mp_wakeup_mailbox: ?*madt.MpWakeupMailbox = null,
    mp_wakeup_phys_addr: u64 = 0,
    uefi_aps_detected: bool = false,

    pub fn init() ParkingManager {
        return ParkingManager{};
    }

    pub fn setupMpWakeupMailbox(self: *ParkingManager, mailbox_phys_addr: u64) !void {
        if (mailbox_phys_addr == 0) {
            serial.println("[PARKING] No MP wakeup mailbox address provided", .{});
            return error.NoMailbox;
        }

        serial.println("[PARKING] Setting up MP wakeup mailbox at physical address 0x{x}", .{mailbox_phys_addr});

        // Ensure the mailbox is in the identity-mapped region
        const max_mapped = paging.getHighestMappedPhysicalAddress();
        if (mailbox_phys_addr >= max_mapped) {
            serial.println("[PARKING] ERROR: MP wakeup mailbox at 0x{x} is beyond identity-mapped region (max: 0x{x})", .{ mailbox_phys_addr, max_mapped });
            return error.MailboxNotMapped;
        }

        // In identity-mapped region, physical address equals virtual address
        self.mp_wakeup_mailbox = @as(*madt.MpWakeupMailbox, @ptrFromInt(mailbox_phys_addr));
        self.mp_wakeup_phys_addr = mailbox_phys_addr;

        // Initialize the mailbox
        self.mp_wakeup_mailbox.?.command = MP_WAKEUP_COMMAND_NOOP;
        self.mp_wakeup_mailbox.?.reserved = 0;
        self.mp_wakeup_mailbox.?.apic_id = 0;
        self.mp_wakeup_mailbox.?.wakeup_vector = 0;

        // Ensure changes are visible
        asm volatile ("mfence" ::: "memory");

        serial.println("[PARKING] MP wakeup mailbox initialized", .{});
    }

    pub fn detectUefiAps(self: *ParkingManager) !bool {
        if (self.mp_wakeup_mailbox == null) {
            serial.println("[PARKING] No MP wakeup mailbox available", .{});
            return false;
        }

        // If we have an MP wakeup mailbox, it means UEFI has initialized APs
        serial.println("[PARKING] MP wakeup mailbox present - UEFI has initialized APs", .{});
        self.uefi_aps_detected = true;
        return true;
    }

    pub fn wakeupAp(self: *ParkingManager, apic_id: u32, wakeup_vector: u64) !void {
        if (self.mp_wakeup_mailbox == null) {
            serial.println("[PARKING] No MP wakeup mailbox available", .{});
            return error.NoMailbox;
        }

        serial.println("[PARKING] Waking up AP with APIC ID {} using vector 0x{x}", .{ apic_id, wakeup_vector });

        // Write the wakeup parameters
        self.mp_wakeup_mailbox.?.apic_id = apic_id;
        self.mp_wakeup_mailbox.?.wakeup_vector = wakeup_vector;

        // Memory barrier to ensure parameters are written before command
        asm volatile ("mfence" ::: "memory");

        // Issue the wakeup command
        self.mp_wakeup_mailbox.?.command = MP_WAKEUP_COMMAND_WAKEUP;

        // Memory barrier to ensure command is visible
        asm volatile ("mfence" ::: "memory");

        // Wait for the command to be processed
        // The firmware should clear the command field when done
        var timeout: u32 = 10000; // 10ms timeout
        while (self.mp_wakeup_mailbox.?.command != MP_WAKEUP_COMMAND_NOOP and timeout > 0) : (timeout -= 1) {
            timer.delayMicroseconds(1);
            asm volatile ("mfence" ::: "memory");
        }

        if (timeout == 0) {
            serial.println("[PARKING] Timeout waiting for AP {} wakeup", .{apic_id});
            return error.WakeupTimeout;
        }

        serial.println("[PARKING] AP {} wakeup command acknowledged", .{apic_id});
    }

    pub fn wakeupAllAps(self: *ParkingManager, wakeup_vector: u64, processor_list: []const u32, bsp_apic_id: u32) !void {
        if (self.mp_wakeup_mailbox == null) {
            serial.println("[PARKING] No MP wakeup mailbox available", .{});
            return error.NoMailbox;
        }

        // Wake up each AP individually
        for (processor_list) |apic_id| {
            if (apic_id == bsp_apic_id) {
                continue; // Skip the BSP
            }

            try self.wakeupAp(apic_id, wakeup_vector);

            // Small delay between APs to avoid overwhelming the system
            timer.delayMicroseconds(100);
        }
    }

    // Legacy methods for non-UEFI systems (using INIT-SIPI-SIPI)
    pub fn sendInitSipiSipi(apic_id: u8, vector: u8) void {
        serial.println("[PARKING] Sending INIT-SIPI-SIPI to AP {} (vector=0x{x})", .{ apic_id, vector });

        // INIT assert
        apic.sendIPIFull(apic_id, 0, .Init, .Assert, .Level, .NoShorthand);
        timer.delayMicroseconds(10000);

        // INIT de-assert
        apic.sendIPIFull(apic_id, 0, .Init, .Deassert, .Level, .NoShorthand);
        timer.delayMicroseconds(10000);

        // First SIPI
        apic.sendIPIFull(apic_id, vector, .Startup, .Assert, .Edge, .NoShorthand);
        timer.delayMicroseconds(200);

        // Second SIPI
        apic.sendIPIFull(apic_id, vector, .Startup, .Assert, .Edge, .NoShorthand);
        timer.delayMicroseconds(200);
    }
};

// Global parking manager instance
var parking_manager: ?ParkingManager = null;

pub fn getParkingManager() *ParkingManager {
    if (parking_manager == null) {
        parking_manager = ParkingManager.init();
    }
    return &parking_manager.?;
}
