// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const apic = @import("../x86_64/apic.zig");
const apic_unified = @import("../x86_64/apic_unified.zig");
const timer = @import("../x86_64/timer.zig");
const serial = @import("../drivers/serial.zig");
const x86_64 = @import("../x86_64/cpu_state.zig");

// Fallback mechanisms for starting APs when standard INIT-SIPI-SIPI fails
pub const ApFallback = struct {
    // Warm reset vector constants
    const WARM_RESET_VECTOR_LOW = 0x467; // BIOS data area: warm reset vector low
    const WARM_RESET_VECTOR_HIGH = 0x469; // BIOS data area: warm reset vector high
    const CMOS_SHUTDOWN_STATUS = 0x0F; // CMOS shutdown status byte
    const CMOS_WARM_RESET = 0x0A; // Warm reset without memory test

    // Track which methods have been tried
    const FallbackMethod = enum {
        nmi,
        warm_reset,
        init_variation,
        skip,
    };

    // Try alternative methods to start an AP
    pub fn tryAlternativeStartup(apic_id: u8, trampoline_addr: u16) !bool {
        serial.println("[AP Fallback] Attempting alternative startup methods for AP {}", .{apic_id});

        // Method 1: Try NMI-based wakeup
        if (try attemptNmiWakeup(apic_id)) {
            serial.println("[AP Fallback] NMI wakeup successful for AP {}", .{apic_id});
            return true;
        }

        // Method 2: Try warm reset vector
        if (try attemptWarmReset(apic_id, trampoline_addr)) {
            serial.println("[AP Fallback] Warm reset successful for AP {}", .{apic_id});
            return true;
        }

        // Method 3: Try variations of INIT timing
        if (try attemptInitVariations(apic_id, trampoline_addr)) {
            serial.println("[AP Fallback] INIT variation successful for AP {}", .{apic_id});
            return true;
        }

        // Method 4: Skip this AP and continue
        serial.println("[AP Fallback] All methods failed for AP {}, marking as failed", .{apic_id});
        return false;
    }

    // Method 1: NMI-based wakeup
    fn attemptNmiWakeup(apic_id: u8) !bool {
        serial.println("[AP Fallback] Trying NMI wakeup...", .{});

        // Send NMI to the target AP
        apic_unified.sendIPIFull(apic_id, 0, .NMI, .Assert, .Edge, .NoShorthand);

        // Wait for response (checking debug region)
        const timeout_ms: u32 = 100;
        const start_time = timer.getUptime();

        while (timer.getUptime() - start_time < timeout_ms * 1_000_000) {
            const debug_magic = @as(*volatile u32, @ptrFromInt(0x500));
            if (debug_magic.* == 0x12345678) {
                return true;
            }
            asm volatile ("pause" ::: "memory");
        }

        return false;
    }

    // Method 2: Warm reset vector method
    fn attemptWarmReset(apic_id: u8, trampoline_addr: u16) !bool {
        serial.println("[AP Fallback] Trying warm reset vector method...", .{});

        // Save current warm reset vector (using byte access for unaligned addresses)
        const low_ptr = @as([*]volatile u8, @ptrFromInt(WARM_RESET_VECTOR_LOW));
        const high_ptr = @as([*]volatile u8, @ptrFromInt(WARM_RESET_VECTOR_HIGH));
        const old_vector_low = @as(u16, low_ptr[0]) | (@as(u16, low_ptr[1]) << 8);
        const old_vector_high = @as(u16, high_ptr[0]) | (@as(u16, high_ptr[1]) << 8);

        // Set warm reset vector to our trampoline (using byte access for unaligned addresses)
        low_ptr[0] = 0; // Offset low byte
        low_ptr[1] = 0; // Offset high byte
        const segment = trampoline_addr >> 4;
        high_ptr[0] = @as(u8, @truncate(segment)); // Segment low byte
        high_ptr[1] = @as(u8, @truncate(segment >> 8)); // Segment high byte

        // Set CMOS shutdown status to warm reset
        outb(0x70, CMOS_SHUTDOWN_STATUS);
        outb(0x71, CMOS_WARM_RESET);

        // Send INIT to trigger warm reset
        apic_unified.sendIPIFull(apic_id, 0, .Init, .Assert, .Level, .NoShorthand);
        timer.delayMicroseconds(10_000);

        // Check if AP started
        const timeout_ms: u32 = 200;
        const start_time = timer.getUptime();
        var started = false;

        while (timer.getUptime() - start_time < timeout_ms * 1_000_000) {
            const debug_magic = @as(*volatile u32, @ptrFromInt(0x500));
            if (debug_magic.* == 0x12345678) {
                started = true;
                break;
            }
            asm volatile ("pause" ::: "memory");
        }

        // Restore original warm reset vector (using byte access for unaligned addresses)
        low_ptr[0] = @as(u8, @truncate(old_vector_low));
        low_ptr[1] = @as(u8, @truncate(old_vector_low >> 8));
        high_ptr[0] = @as(u8, @truncate(old_vector_high));
        high_ptr[1] = @as(u8, @truncate(old_vector_high >> 8));

        // Clear CMOS shutdown status
        outb(0x70, CMOS_SHUTDOWN_STATUS);
        outb(0x71, 0x00);

        return started;
    }

    // Method 3: Try different INIT timing variations
    fn attemptInitVariations(apic_id: u8, trampoline_addr: u16) !bool {
        serial.println("[AP Fallback] Trying INIT timing variations...", .{});

        const variations = [_]struct {
            init_delay_ms: u32,
            sipi_delay_ms: u32,
            use_edge: bool,
            description: []const u8,
        }{
            .{ .init_delay_ms = 100, .sipi_delay_ms = 20, .use_edge = false, .description = "Extended delays with level trigger" },
            .{ .init_delay_ms = 10, .sipi_delay_ms = 1, .use_edge = true, .description = "Short delays with edge trigger" },
            .{ .init_delay_ms = 50, .sipi_delay_ms = 10, .use_edge = true, .description = "Medium delays with edge trigger" },
        };

        for (variations) |variant| {
            serial.println("[AP Fallback] Trying: {s}", .{variant.description});

            // Send INIT sequence
            const trigger_mode = if (variant.use_edge) apic.IpiTriggerMode.Edge else apic.IpiTriggerMode.Level;

            // INIT de-assert
            apic_unified.sendIPIFull(apic_id, 0, .Init, .Deassert, trigger_mode, .NoShorthand);
            timer.delayMicroseconds(1000);

            // INIT assert
            apic_unified.sendIPIFull(apic_id, 0, .Init, .Assert, trigger_mode, .NoShorthand);
            timer.delayMicroseconds(1000);

            // INIT de-assert
            apic_unified.sendIPIFull(apic_id, 0, .Init, .Deassert, trigger_mode, .NoShorthand);
            timer.delayMicroseconds(variant.init_delay_ms * 1000);

            // Send SIPI sequence
            const vector = @as(u8, @intCast(trampoline_addr >> 12));

            // First SIPI
            apic_unified.sendIPIFull(apic_id, vector, .Startup, .Assert, .Edge, .NoShorthand);
            timer.delayMicroseconds(variant.sipi_delay_ms * 1000);

            // Second SIPI
            apic_unified.sendIPIFull(apic_id, vector, .Startup, .Assert, .Edge, .NoShorthand);
            timer.delayMicroseconds(variant.sipi_delay_ms * 5000);

            // Check if AP started
            const timeout_ms: u32 = 100;
            const start_time = timer.getUptime();

            while (timer.getUptime() - start_time < timeout_ms * 1_000_000) {
                const debug_magic = @as(*volatile u32, @ptrFromInt(0x500));
                if (debug_magic.* == 0x12345678) {
                    return true;
                }
                asm volatile ("pause" ::: "memory");
            }
        }

        return false;
    }

    // CMOS I/O helpers
    fn outb(port: u16, value: u8) void {
        asm volatile ("outb %[value], %[port]"
            :
            : [port] "{dx}" (port),
              [value] "{al}" (value),
            : "memory"
        );
    }

    // Diagnose why an AP failed to start
    pub fn diagnoseFailure(apic_id: u8) void {
        serial.println("[AP Fallback] Diagnosing failure for AP {}:", .{apic_id});

        // Check Local APIC state
        const icr_low = apic_unified.readRegister(0x300); // APIC_ICR_LOW
        const icr_high = apic_unified.readRegister(0x310); // APIC_ICR_HIGH
        const esr = apic_unified.readRegister(0x280); // APIC_ESR

        serial.println("  ICR: 0x{x:0>8}{x:0>8}", .{ icr_high, icr_low });
        serial.println("  ESR: 0x{x:0>8}", .{esr});

        // Check if delivery status is still pending
        if ((icr_low & (1 << 12)) != 0) {
            serial.println("  WARNING: IPI delivery still pending!", .{});
        }

        // Check error bits
        if (esr != 0) {
            if ((esr & 0x01) != 0) serial.println("  ERROR: Send CS error", .{});
            if ((esr & 0x02) != 0) serial.println("  ERROR: Receive CS error", .{});
            if ((esr & 0x04) != 0) serial.println("  ERROR: Send accept error", .{});
            if ((esr & 0x08) != 0) serial.println("  ERROR: Receive accept error", .{});
            if ((esr & 0x20) != 0) serial.println("  ERROR: Send illegal vector", .{});
            if ((esr & 0x40) != 0) serial.println("  ERROR: Receive illegal vector", .{});
            if ((esr & 0x80) != 0) serial.println("  ERROR: Illegal register address", .{});
        }

        // Check memory at trampoline location
        serial.println("  Trampoline memory check:", .{});
        const trampoline_ptr = @as([*]const u8, @ptrFromInt(0x8000));
        serial.print("    First 16 bytes: ", .{});
        for (0..16) |i| {
            serial.print("{x:0>2} ", .{trampoline_ptr[i]});
        }
        serial.println("", .{});
    }
};
