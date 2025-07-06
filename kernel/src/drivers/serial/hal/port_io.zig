// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Hardware abstraction layer for port I/O operations
// This module provides the lowest level hardware access for serial ports

const io = @import("../../../x86_64/io_security.zig");

/// Read a byte from the specified port
pub inline fn inb(port: u16) u8 {
    return io.inb(port);
}

/// Write a byte to the specified port
pub inline fn outb(port: u16, value: u8) void {
    io.outb(port, value);
}

/// Read a word from the specified port
pub inline fn inw(port: u16) u16 {
    return io.inw(port);
}

/// Write a word to the specified port
pub inline fn outw(port: u16, value: u16) void {
    io.outw(port, value);
}

/// Wait for a short period (I/O delay)
pub inline fn ioDelay() void {
    // Use a dummy outb to provide I/O delay
    outb(0x80, 0);
}
