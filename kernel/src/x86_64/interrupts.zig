// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Enhanced interrupt handling with APIC support
// Handles both exceptions and external interrupts

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const exceptions = @import("exceptions.zig");
const apic = @import("apic.zig");
const cfi = @import("cfi.zig");
const stack_security = @import("stack_security.zig");
const speculation = @import("speculation.zig");
const secure_print = @import("../lib/secure_print.zig");

// Re-export InterruptFrame for convenience
pub const InterruptFrame = exceptions.InterruptFrame;

// Interrupt handler function type
pub const InterruptHandler = *const fn (frame: *InterruptFrame) void;

// Interrupt handler table
var interrupt_handlers: [256]?InterruptHandler = [_]?InterruptHandler{null} ** 256;

// Interrupt statistics for security monitoring
var interrupt_counts: [256]std.atomic.Value(u64) = blk: {
    var counts: [256]std.atomic.Value(u64) = undefined;
    for (&counts) |*count| {
        count.* = std.atomic.Value(u64).init(0);
    }
    break :blk counts;
};
var spurious_interrupts: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// Register an interrupt handler
pub fn registerHandler(vector: u8, handler: InterruptHandler) void {
    var guard = stack_security.protect();
    defer guard.deinit();

    interrupt_handlers[vector] = handler;

    // Register handler with CFI for validation
    cfi.registerFunction(@intFromPtr(handler), .INTERRUPT_HANDLER, 0x100 // Assume 256 bytes for handler function
    ) catch |err| {
        serial.println("[IRQ] WARNING: Failed to register handler with CFI: {}", .{err});
    };
}

// Unregister an interrupt handler
pub fn unregisterHandler(vector: u8) void {
    interrupt_handlers[vector] = null;
}

// Alias for timer module compatibility
pub const set_handler = registerHandler;

// Common interrupt handler entry point
export fn handleInterrupt(vector: u64, error_code: u64, frame: *exceptions.InterruptFrame) callconv(.C) void {
    // Safety check: validate vector
    if (vector > 255) {
        serial.println("[IRQ] ERROR: Invalid interrupt vector {}", .{vector});
        return;
    }

    // Safety check: validate frame pointer
    const frame_addr = @intFromPtr(frame);
    // Frame should be in reasonable memory range (above 1MB, below 128GB)
    if (frame_addr < 0x100000 or frame_addr > 0x2000000000) {
        serial.print("[IRQ] ERROR: Invalid frame pointer ", .{});
        secure_print.printHex("", frame_addr);
        serial.println("", .{});
        return;
    }

    // Update statistics
    if (vector < 256) {
        _ = interrupt_counts[vector].fetchAdd(1, .monotonic);
    }

    // Check if this is an exception (0-31)
    if (vector < 32) {
        // Call the original exception handler
        exceptions.handleException(vector, error_code, frame);
        // Exceptions don't return, but if they did, no EOI needed
        return;
    }

    // Check for spurious interrupt
    if (vector == 0xFF) {
        _ = spurious_interrupts.fetchAdd(1, .monotonic);
        // Spurious interrupts don't need EOI
        return;
    }

    // Call registered handler if available
    if (vector < 256) {
        if (interrupt_handlers[vector]) |handler| {
            // Validate handler with CFI before calling
            if (cfi.validateIndirectCall(@intFromPtr(handler), .INTERRUPT_HANDLER)) {
                handler(frame);
            } else {
                serial.println("[IRQ] CFI violation: Invalid handler for vector {}", .{vector});
            }
        } else {
            // Unhandled interrupt
            serial.println("[IRQ] Unhandled interrupt vector {}", .{vector});
        }
    }

    // Send EOI to APIC for hardware interrupts
    if (apic.isAvailable() and vector >= 32) {
        apic.sendEOI();
    }

    // Apply MDS mitigation if returning to user mode
    // Check the privilege level in CS to determine if we're returning to user mode
    if ((frame.cs & 3) != 0) {
        speculation.mitigateOnKernelExit();
    }
}

// Timer interrupt handler is registered by timer module
// We don't define one here to avoid conflicts

// Spurious interrupt handler (vector 255)
fn spuriousInterruptHandler(frame: *InterruptFrame) void {
    _ = frame;

    // Just count it, no action needed
    // Note: No EOI needed for spurious interrupts
}

// Initialize interrupt handling
pub fn init() void {

    // Register default handlers
    // Timer handler (32) is registered by timer module
    registerHandler(255, spuriousInterruptHandler); // Spurious

    // Additional handlers can be registered here
}

// Print interrupt statistics
pub fn printStatistics() void {
    serial.println("[IRQ] Interrupt Statistics:", .{});

    var total_interrupts: u64 = 0;
    var printed_vectors: u32 = 0;

    // Print all interrupt vectors that have been triggered
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        const count = interrupt_counts[i].load(.acquire);
        if (count > 0) {
            // Add descriptive names for known interrupt vectors
            if (i < 32) {
                // CPU exceptions (0-31)
                serial.println("  Vector {} (Exception): {} times", .{ i, count });
            } else if (i >= 32 and i < 48) {
                // Hardware IRQs (32-47)
                const irq_num = i - 32;
                switch (irq_num) {
                    0 => serial.println("  Vector {} (IRQ0/Timer): {} times", .{ i, count }),
                    1 => serial.println("  Vector {} (IRQ1/Keyboard): {} times", .{ i, count }),
                    2 => serial.println("  Vector {} (IRQ2/Cascade): {} times", .{ i, count }),
                    3 => serial.println("  Vector {} (IRQ3/COM2): {} times", .{ i, count }),
                    4 => serial.println("  Vector {} (IRQ4/COM1): {} times", .{ i, count }),
                    5 => serial.println("  Vector {} (IRQ5/LPT2): {} times", .{ i, count }),
                    6 => serial.println("  Vector {} (IRQ6/Floppy): {} times", .{ i, count }),
                    7 => serial.println("  Vector {} (IRQ7/LPT1): {} times", .{ i, count }),
                    8 => serial.println("  Vector {} (IRQ8/RTC): {} times", .{ i, count }),
                    9 => serial.println("  Vector {} (IRQ9/Free): {} times", .{ i, count }),
                    10 => serial.println("  Vector {} (IRQ10/Free): {} times", .{ i, count }),
                    11 => serial.println("  Vector {} (IRQ11/Free): {} times", .{ i, count }),
                    12 => serial.println("  Vector {} (IRQ12/PS2 Mouse): {} times", .{ i, count }),
                    13 => serial.println("  Vector {} (IRQ13/FPU): {} times", .{ i, count }),
                    14 => serial.println("  Vector {} (IRQ14/Primary ATA): {} times", .{ i, count }),
                    15 => serial.println("  Vector {} (IRQ15/Secondary ATA): {} times", .{ i, count }),
                    else => serial.println("  Vector {} (IRQ{}): {} times", .{ i, irq_num, count }),
                }
            } else {
                // Software interrupts, IPIs, etc. (48-255)
                serial.println("  Vector {} (Software/IPI): {} times", .{ i, count });
            }
            total_interrupts += count;
            printed_vectors += 1;
        }
    }

    serial.println("  Total interrupts: {} (across {} vectors)", .{ total_interrupts, printed_vectors });
    serial.println("  Spurious interrupts: {}", .{spurious_interrupts.load(.acquire)});
}

// Test interrupt handling
pub fn testInterrupts() !void {

    // Test registering and unregistering handlers
    const test_handler = struct {
        fn handler(frame: *InterruptFrame) void {
            _ = frame;
            serial.println("[TEST] Test interrupt handler called", .{});
        }
    }.handler;

    registerHandler(64, test_handler);

    if (interrupt_handlers[64] != test_handler) {
        return error.HandlerRegistrationFailed;
    }

    unregisterHandler(64);

    if (interrupt_handlers[64] != null) {
        return error.HandlerUnregistrationFailed;
    }
}
