// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");

/// Minimal entry point for Application Processors
/// This function is called directly from assembly code with cpu_id in RDI
pub export fn apEntryWrapper(cpu_id: u32) callconv(.C) noreturn {
    // Write immediate debug marker to verify we reached Zig code
    writeDebugMarker(0xAF00_0001);

    // Simple serial output if available
    if (isSerialInitialized()) {
        serial.directWriteString("[AP] Entry wrapper called for CPU ");
        writeHexByte(@intCast(cpu_id));
        serial.directWriteString("\n");
    }

    // Write another marker to show we're about to call main entry
    writeDebugMarker(0xAF00_0002);

    // Try to call the real AP entry point
    callApMainEntry(cpu_id) catch |err| {
        // Write error marker
        writeDebugMarker(0xAF00_DEAD);

        // Try to report error if serial is available
        if (isSerialInitialized()) {
            serial.directWriteString("[AP] Error in main entry: ");
            writeErrorCode(err);
            serial.directWriteString("\n");
        }

        // Halt this CPU
        haltCpu();
    };

    // Should never reach here
    writeDebugMarker(0xAF00_FFFF);
    haltCpu();
}

/// Check if serial port is initialized (simple check)
fn isSerialInitialized() bool {
    // Check if serial port seems responsive
    // Read Line Status Register
    const lsr = asm volatile ("inb %dx, %al"
        : [ret] "={al}" (-> u8),
        : [port] "{dx}" (@as(u16, 0x3F8 + 5)),
    );
    // If we read 0xFF, port is likely not initialized
    return lsr != 0xFF;
}

/// Write a debug marker to a known memory location
fn writeDebugMarker(value: u32) void {
    // Write to a fixed debug location that we can examine
    const debug_addr = @as(*volatile u32, @ptrFromInt(0x1000_0000));
    debug_addr.* = value;

    // Also write to port 0x80 (POST code)
    asm volatile ("outb %al, %dx"
        :
        : [val] "{al}" (@as(u8, @truncate(value))),
          [port] "{dx}" (@as(u16, 0x80)),
    );
}

/// Write a hex byte to serial (simple implementation)
fn writeHexByte(value: u8) void {
    const hex_chars = "0123456789ABCDEF";
    serial.directWrite(hex_chars[(value >> 4) & 0xF]);
    serial.directWrite(hex_chars[value & 0xF]);
}

/// Write error code to serial
fn writeErrorCode(err: anyerror) void {
    // Just write a simple error indicator for now
    switch (err) {
        error.OutOfMemory => serial.directWriteString("OOM"),
        error.InvalidCpuId => serial.directWriteString("BADCPU"),
        error.StackSetupFailed => serial.directWriteString("STACK"),
        else => serial.directWriteString("UNKNOWN"),
    }
}

// External declaration for the real AP main entry point
extern fn apMainEntry(cpu_id: u32) callconv(.C) noreturn;

/// Call the real AP main entry point
fn callApMainEntry(cpu_id: u32) !void {
    // Validate CPU ID
    if (cpu_id == 0 or cpu_id >= 255) {
        return error.InvalidCpuId;
    }

    // Write marker before calling main entry
    writeDebugMarker(0xAF00_0003);

    // Call the real entry point - it's a noreturn function
    apMainEntry(cpu_id);
}

/// Halt the current CPU
fn haltCpu() noreturn {
    // Disable interrupts
    asm volatile ("cli");

    // Infinite halt loop
    while (true) {
        asm volatile ("hlt");
    }
}

/// Panic handler for AP initialization
pub fn panic(msg: []const u8, error_return_trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    _ = error_return_trace;
    _ = ret_addr;

    // Write panic marker
    writeDebugMarker(0xAF00_DEAD);

    // Try to output panic message if serial is available
    if (isSerialInitialized()) {
        serial.directWriteString("[AP PANIC] ");
        serial.directWriteString(msg);
        serial.directWriteString("\n");
    }

    // Halt this CPU
    haltCpu();
}
