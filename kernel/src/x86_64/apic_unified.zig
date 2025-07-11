// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const apic = @import("apic.zig");
const x2apic = @import("x2apic.zig");
const serial = @import("../drivers/serial.zig");

// Unified delivery modes
pub const DeliveryMode = enum {
    Fixed,
    LowestPriority,
    SMI,
    NMI,
    Init,
    Startup,
};

// Destination modes
pub const DestinationMode = enum {
    Physical,
    Logical,
};

// Destination shorthand
pub const DestinationShorthand = enum {
    NoShorthand,
    Self,
    All,
    AllExcludingSelf,
};

// Check if any APIC is available
pub fn isAvailable() bool {
    return x2apic.isEnabled() or apic.isAvailable();
}

// Send End of Interrupt
pub fn sendEOI() void {
    if (x2apic.isEnabled()) {
        x2apic.sendEOI();
    } else if (apic.isAvailable()) {
        apic.sendEOI();
    }
}

// Simplified IPI sending for common cases
pub fn sendIPI(dest: u32, vector: u8, delivery_mode: DeliveryMode, dest_shorthand: DestinationShorthand) void {
    if (x2apic.isEnabled()) {
        // Convert our enum to x2APIC enum
        const x2_mode = switch (delivery_mode) {
            .Fixed => x2apic.DeliveryMode.Fixed,
            .LowestPriority => x2apic.DeliveryMode.LowestPriority,
            .SMI => x2apic.DeliveryMode.SMI,
            .NMI => x2apic.DeliveryMode.NMI,
            .Init => x2apic.DeliveryMode.INIT,
            .Startup => x2apic.DeliveryMode.StartUp,
        };

        const x2_shorthand = switch (dest_shorthand) {
            .NoShorthand => x2apic.DestinationShorthand.None,
            .Self => x2apic.DestinationShorthand.Self,
            .All => x2apic.DestinationShorthand.AllIncludingSelf,
            .AllExcludingSelf => x2apic.DestinationShorthand.AllExcludingSelf,
        };

        // Use self IPI optimization when possible
        if (dest_shorthand == .Self) {
            x2apic.sendSelfIPI(vector);
        } else {
            x2apic.sendIPI(dest, vector, x2_mode, x2_shorthand);
        }
    } else if (apic.isAvailable()) {
        // Convert to xAPIC enums and call with full signature
        const apic_mode = switch (delivery_mode) {
            .Fixed => apic.IpiDeliveryMode.Fixed,
            .LowestPriority => apic.IpiDeliveryMode.LowestPriority,
            .SMI => apic.IpiDeliveryMode.SMI,
            .NMI => apic.IpiDeliveryMode.NMI,
            .Init => apic.IpiDeliveryMode.Init,
            .Startup => apic.IpiDeliveryMode.Startup,
        };

        const apic_shorthand = switch (dest_shorthand) {
            .NoShorthand => apic.IpiDestShorthand.NoShorthand,
            .Self => apic.IpiDestShorthand.Self,
            .All => apic.IpiDestShorthand.AllIncludingSelf,
            .AllExcludingSelf => apic.IpiDestShorthand.AllExcludingSelf,
        };

        // xAPIC requires more parameters - use defaults for simplified case
        apic.sendIPI(@as(u8, @truncate(dest)), vector, apic_mode, .Deassert, .Edge, apic_shorthand) catch |err| {
            serial.println("[APIC] Failed to send IPI: {}", .{err});
        };
    }
}

// Full IPI sending for complex cases (mainly for AP startup)
pub fn sendIPIFull(dest: u32, vector: u8, delivery_mode: DeliveryMode, level: apic.IpiLevel, trigger: apic.IpiTriggerMode, shorthand: DestinationShorthand) void {
    if (x2apic.isEnabled()) {
        // x2APIC doesn't need level/trigger for most cases, just use simplified version
        sendIPI(dest, vector, delivery_mode, shorthand);
    } else if (apic.isAvailable()) {
        // Use full xAPIC interface
        const apic_mode = switch (delivery_mode) {
            .Fixed => apic.IpiDeliveryMode.Fixed,
            .LowestPriority => apic.IpiDeliveryMode.LowestPriority,
            .SMI => apic.IpiDeliveryMode.SMI,
            .NMI => apic.IpiDeliveryMode.NMI,
            .Init => apic.IpiDeliveryMode.Init,
            .Startup => apic.IpiDeliveryMode.Startup,
        };

        const apic_shorthand = switch (shorthand) {
            .NoShorthand => apic.IpiDestShorthand.NoShorthand,
            .Self => apic.IpiDestShorthand.Self,
            .All => apic.IpiDestShorthand.AllIncludingSelf,
            .AllExcludingSelf => apic.IpiDestShorthand.AllExcludingSelf,
        };

        apic.sendIPI(@as(u8, @truncate(dest)), vector, apic_mode, level, trigger, apic_shorthand) catch |err| {
            serial.println("[APIC] Failed to send IPI: {}", .{err});
        };
    }
}

// Get current APIC ID
pub fn getAPICID() u32 {
    if (x2apic.isEnabled()) {
        return x2apic.getAPICID();
    } else if (apic.isAvailable()) {
        const APIC_ID_REG = 0x20;
        return @as(u32, @truncate(apic.readRegister(APIC_ID_REG) >> 24));
    }
    return 0;
}

// Initialize timer
pub fn initTimer(frequency: u32) void {
    if (x2apic.isEnabled()) {
        // x2APIC timer initialization is handled differently
        // This would be called from timer.zig
    } else if (apic.isAvailable()) {
        apic.initTimer(frequency);
    }
}

// Set timer initial count
pub fn setTimerInitialCount(count: u32) void {
    if (x2apic.isEnabled()) {
        x2apic.setTimerInitialCount(count);
    } else if (apic.isAvailable()) {
        apic.setTimerInitialCount(count);
    }
}

// Get timer current count
pub fn getTimerCurrentCount() u32 {
    if (x2apic.isEnabled()) {
        return x2apic.getTimerCurrentCount();
    } else if (apic.isAvailable()) {
        return apic.getTimerCurrentCount();
    }
    return 0;
}

// Stop timer
pub fn stopTimer() void {
    if (x2apic.isEnabled()) {
        x2apic.stopTimer();
    } else if (apic.isAvailable()) {
        apic.stopTimer();
    }
}

// Set timer divider
pub fn setTimerDivider(divider: u32) void {
    if (x2apic.isEnabled()) {
        x2apic.setTimerDivider(divider);
    } else if (apic.isAvailable()) {
        apic.setTimerDivider(divider);
    }
}

// Read APIC register (for compatibility)
pub fn readRegister(offset: u32) u32 {
    if (x2apic.isEnabled()) {
        // x2APIC doesn't support direct register reads by offset
        // This is mainly used for ESR and ICR reads
        switch (offset) {
            0x280 => return x2apic.getErrorStatus(), // ESR
            0x300 => return 0, // ICR low - x2APIC ICR is write-only
            else => {
                serial.println("[APIC] WARNING: Unsupported x2APIC register read at offset 0x{x}", .{offset});
                return 0;
            },
        }
    } else if (apic.isAvailable()) {
        return apic.readRegister(offset);
    }
    return 0;
}

// Write APIC register (for compatibility)
pub fn writeRegister(offset: u32, value: u32) void {
    if (x2apic.isEnabled()) {
        // x2APIC doesn't support direct register writes by offset
        switch (offset) {
            0x280 => {
                // ESR - writing clears it
                _ = x2apic.getErrorStatus();
            },
            else => {
                serial.println("[APIC] WARNING: Unsupported x2APIC register write at offset 0x{x}", .{offset});
            },
        }
    } else if (apic.isAvailable()) {
        apic.writeRegister(offset, value);
    }
}
