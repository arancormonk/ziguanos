// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Core serial driver configuration
// This module provides configuration structures and constants for the core driver

const regs = @import("../hal/registers.zig");

/// Serial port enumeration
pub const ComPort = enum(u8) {
    COM1 = 1,
    COM2 = 2,
    COM3 = 3,
    COM4 = 4,

    pub fn getBasePort(self: ComPort) u16 {
        return switch (self) {
            .COM1 => regs.COM1_PORT,
            .COM2 => regs.COM2_PORT,
            .COM3 => regs.COM3_PORT,
            .COM4 => regs.COM4_PORT,
        };
    }
};

/// Baud rate enumeration
pub const BaudRate = enum(u32) {
    B1200 = 1200,
    B2400 = 2400,
    B4800 = 4800,
    B9600 = 9600,
    B19200 = 19200,
    B38400 = 38400,
    B57600 = 57600,
    B115200 = 115200,

    pub fn getDivisor(self: BaudRate) u16 {
        return switch (self) {
            .B1200 => regs.BAUD_1200,
            .B2400 => regs.BAUD_2400,
            .B4800 => regs.BAUD_4800,
            .B9600 => regs.BAUD_9600,
            .B19200 => regs.BAUD_19200,
            .B38400 => regs.BAUD_38400,
            .B57600 => regs.BAUD_57600,
            .B115200 => regs.BAUD_115200,
        };
    }
};

/// Serial configuration structure
pub const SerialConfig = struct {
    port: ComPort,
    baud_rate: BaudRate,
    enable_interrupts: bool = false,
    enable_flow_control: bool = false,
    fifo_trigger_level: u8 = regs.FCR_TRIGGER_14,
};

/// Fixed-size ring buffer for early boot
pub const RingBuffer = struct {
    buffer: [1024]u8,
    read_pos: usize,
    write_pos: usize,

    pub fn init() RingBuffer {
        return RingBuffer{
            .buffer = [_]u8{0} ** 1024,
            .read_pos = 0,
            .write_pos = 0,
        };
    }

    pub fn write(self: *RingBuffer, data: []const u8) usize {
        var written: usize = 0;
        for (data) |byte| {
            const next_pos = (self.write_pos + 1) % self.buffer.len;
            if (next_pos == self.read_pos) break; // Buffer full

            self.buffer[self.write_pos] = byte;
            self.write_pos = next_pos;
            written += 1;
        }
        return written;
    }

    pub fn read(self: *RingBuffer, buffer: []u8) usize {
        var read_count: usize = 0;
        while (read_count < buffer.len and self.read_pos != self.write_pos) {
            buffer[read_count] = self.buffer[self.read_pos];
            self.read_pos = (self.read_pos + 1) % self.buffer.len;
            read_count += 1;
        }
        return read_count;
    }

    pub fn isEmpty(self: *const RingBuffer) bool {
        return self.read_pos == self.write_pos;
    }

    pub fn isFull(self: *const RingBuffer) bool {
        return (self.write_pos + 1) % self.buffer.len == self.read_pos;
    }

    pub fn clear(self: *RingBuffer) void {
        self.read_pos = 0;
        self.write_pos = 0;
    }
};
