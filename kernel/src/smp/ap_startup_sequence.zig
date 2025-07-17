// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const apic = @import("../x86_64/apic.zig");
const timer = @import("../x86_64/timer.zig");
const UefiApManager = @import("uefi_ap_manager.zig").UefiApManager;
const serial = @import("../drivers/serial.zig");

pub fn sendInitSequence(apic_id: u8, uefi_manager: *UefiApManager) !void {
    // Step 1: Send INIT de-assert (clear any pending state)
    apic.sendIPIFull(apic_id, 0, .Init, .Deassert, .Level, .NoShorthand);
    timer.pitPollingDelay(1000);

    // Step 2: Send INIT assert (Level for UEFI compatibility)
    apic.sendIPIFull(apic_id, 0, .Init, .Assert, .Level, .NoShorthand);
    timer.pitPollingDelay(1000);

    // Step 3: Send INIT de-assert
    apic.sendIPIFull(apic_id, 0, .Init, .Deassert, .Level, .NoShorthand);

    // Step 4: Extended delay for UEFI systems
    const init_delay = uefi_manager.getInitDelay();
    serial.println("[AP] Waiting {}ms after INIT for UEFI compatibility", .{init_delay / 1000});
    timer.pitPollingDelay(init_delay);
}

pub fn sendSipiSequence(apic_id: u8, vector: u8, uefi_manager: *UefiApManager) !void {
    const sipi_delay = uefi_manager.getSipiDelay();

    // First SIPI
    apic.sendIPIFull(apic_id, vector, .Startup, .Assert, .Edge, .NoShorthand);
    timer.pitPollingDelay(sipi_delay);

    // Second SIPI
    apic.sendIPIFull(apic_id, vector, .Startup, .Assert, .Edge, .NoShorthand);
    timer.pitPollingDelay(sipi_delay * 5); // Extra delay after second SIPI
}
