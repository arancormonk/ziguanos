// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Raw UART hardware access layer
// This module provides the minimal hardware interface for UART operations

const io = @import("port_io.zig");
const regs = @import("registers.zig");

/// Initialize a UART port with the specified base port and baud rate
pub fn init(base_port: u16, baud_rate: u32) void {
    // Calculate divisor for baud rate
    const divisor = @as(u16, @intCast(115200 / baud_rate));

    // Disable interrupts
    io.outb(base_port + regs.IER, 0x00);

    // Set baud rate (enable DLAB)
    io.outb(base_port + regs.LCR, regs.LCR_DLAB);
    io.outb(base_port + regs.DLL, @as(u8, @intCast(divisor & 0xFF)));
    io.outb(base_port + regs.DLH, @as(u8, @intCast((divisor >> 8) & 0xFF)));

    // Configure line: 8 bits, no parity, 1 stop bit (8N1)
    io.outb(base_port + regs.LCR, regs.LCR_WORD_LENGTH_8);

    // Enable FIFO with 14-byte trigger level
    io.outb(base_port + regs.FCR, regs.FCR_ENABLE_FIFO |
        regs.FCR_CLEAR_RECEIVE |
        regs.FCR_CLEAR_TRANSMIT |
        regs.FCR_TRIGGER_14);

    // Enable DTR, RTS, and OUT2 (required for interrupts)
    io.outb(base_port + regs.MCR, regs.MCR_DTR | regs.MCR_RTS | regs.MCR_OUT2);

    // Clear any pending data
    _ = io.inb(base_port + regs.DATA);
    _ = io.inb(base_port + regs.LSR);
    _ = io.inb(base_port + regs.MSR);
    _ = io.inb(base_port + regs.IIR);
}

/// Write a single byte to the UART
pub fn writeByte(base_port: u16, byte: u8) void {
    // Wait for transmit buffer to be empty
    var timeout: u32 = 10000;
    while (timeout > 0) : (timeout -= 1) {
        const status = io.inb(base_port + regs.LSR);
        if ((status & regs.LSR_TRANSMIT_HOLDING_EMPTY) != 0) break;
        io.ioDelay();
    }

    // Write the byte if timeout didn't expire
    if (timeout > 0) {
        io.outb(base_port + regs.DATA, byte);
    }
}

/// Write a string to the UART
pub fn writeString(base_port: u16, str: []const u8) void {
    for (str) |byte| {
        writeByte(base_port, byte);
    }
}

/// Read a byte from the UART (non-blocking)
pub fn readByte(base_port: u16) ?u8 {
    const status = io.inb(base_port + regs.LSR);
    if ((status & regs.LSR_DATA_READY) != 0) {
        return io.inb(base_port + regs.DATA);
    }
    return null;
}

/// Check if the UART is ready to transmit
pub fn isTransmitReady(base_port: u16) bool {
    const status = io.inb(base_port + regs.LSR);
    return (status & regs.LSR_TRANSMIT_HOLDING_EMPTY) != 0;
}

/// Check if the UART has received data
pub fn hasReceivedData(base_port: u16) bool {
    const status = io.inb(base_port + regs.LSR);
    return (status & regs.LSR_DATA_READY) != 0;
}

/// Get the line status register
pub fn getLineStatus(base_port: u16) u8 {
    return io.inb(base_port + regs.LSR);
}

/// Get the modem status register
pub fn getModemStatus(base_port: u16) u8 {
    return io.inb(base_port + regs.MSR);
}

/// Enable interrupts on the UART
pub fn enableInterrupts(base_port: u16, interrupts: u8) void {
    io.outb(base_port + regs.IER, interrupts);
}

/// Disable all interrupts on the UART
pub fn disableInterrupts(base_port: u16) void {
    io.outb(base_port + regs.IER, 0x00);
}

/// Basic self-test using scratch register
pub fn selfTest(base_port: u16) bool {
    const test_values = [_]u8{ 0x55, 0xAA, 0x00, 0xFF };
    for (test_values) |value| {
        io.outb(base_port + regs.SCR, value);
        const read_back = io.inb(base_port + regs.SCR);
        if (read_back != value) return false;
    }
    return true;
}
