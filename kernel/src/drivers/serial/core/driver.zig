// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Core serial driver implementation
// This module provides the main driver logic with phase-aware initialization

const std = @import("std");
const hal = @import("../hal/uart.zig");
const regs = @import("../hal/registers.zig");
const config = @import("config.zig");

/// Driver initialization phases
pub const Phase = enum {
    uninitialized,
    early_boot,
    core_ready,
    advanced_ready,
    fully_initialized,
};

/// Serial port state
pub const SerialPort = struct {
    base_port: u16,
    config: config.SerialConfig,
    initialized: bool,
    buffer: config.RingBuffer,

    pub fn init(cfg: config.SerialConfig) SerialPort {
        return SerialPort{
            .base_port = cfg.port.getBasePort(),
            .config = cfg,
            .initialized = false,
            .buffer = config.RingBuffer.init(),
        };
    }

    pub fn initHardware(self: *SerialPort) void {
        hal.init(self.base_port, @intFromEnum(self.config.baud_rate));
        self.initialized = true;
    }

    pub fn writeByte(self: *SerialPort, byte: u8) void {
        if (!self.initialized) return;
        hal.writeByte(self.base_port, byte);
    }

    pub fn writeString(self: *SerialPort, str: []const u8) void {
        if (!self.initialized) return;
        hal.writeString(self.base_port, str);
    }

    pub fn readByte(self: *SerialPort) ?u8 {
        if (!self.initialized) return null;
        return hal.readByte(self.base_port);
    }

    pub fn isTransmitReady(self: *SerialPort) bool {
        if (!self.initialized) return false;
        return hal.isTransmitReady(self.base_port);
    }

    pub fn hasReceivedData(self: *SerialPort) bool {
        if (!self.initialized) return false;
        return hal.hasReceivedData(self.base_port);
    }
};

/// Main driver state
pub const Driver = struct {
    phase: Phase,
    primary_port: SerialPort,
    active_port: *SerialPort,

    pub fn init() Driver {
        const default_config = config.SerialConfig{
            .port = .COM1,
            .baud_rate = .B115200,
            .enable_interrupts = false,
            .enable_flow_control = false,
        };

        var driver = Driver{
            .phase = .uninitialized,
            .primary_port = SerialPort.init(default_config),
            .active_port = undefined,
        };

        driver.active_port = &driver.primary_port;
        return driver;
    }

    pub fn initEarly(self: *Driver) void {
        if (self.phase != .uninitialized) return;

        self.primary_port.initHardware();
        self.phase = .early_boot;
    }

    pub fn initCore(self: *Driver) void {
        if (self.phase != .early_boot) return;

        // Core initialization doesn't need additional hardware setup
        // since hardware is already initialized in early boot
        self.phase = .core_ready;
    }

    pub fn initEnhanced(self: *Driver) void {
        if (self.phase != .core_ready) return;
        self.phase = .advanced_ready;
    }

    pub fn initFull(self: *Driver) void {
        if (self.phase != .advanced_ready) return;
        self.phase = .fully_initialized;
    }

    pub fn print(self: *Driver, comptime fmt: []const u8, args: anytype) void {
        switch (self.phase) {
            .uninitialized => return,
            .early_boot => self.earlyPrint(fmt, args),
            else => self.bufferedPrint(fmt, args),
        }
    }

    pub fn println(self: *Driver, comptime fmt: []const u8, args: anytype) void {
        self.print(fmt ++ "\r\n", args);
    }

    fn earlyPrint(self: *Driver, comptime fmt: []const u8, args: anytype) void {
        var buffer: [1024]u8 = undefined;
        const output = std.fmt.bufPrint(&buffer, fmt, args) catch {
            self.active_port.writeString("[FMT:ERR]\r\n");
            return;
        };
        self.active_port.writeString(output);
    }

    fn bufferedPrint(self: *Driver, comptime fmt: []const u8, args: anytype) void {
        var buffer: [1024]u8 = undefined;
        const output = std.fmt.bufPrint(&buffer, fmt, args) catch {
            self.active_port.writeString("[FMT:ERR]\r\n");
            return;
        };

        // Try to buffer first
        const written = self.active_port.buffer.write(output);
        if (written < output.len) {
            // Buffer full, flush and try direct write
            self.flush();
            self.active_port.writeString(output[written..]);
        }
    }

    pub fn flush(self: *Driver) void {
        if (self.phase == .uninitialized) return;

        var buffer: [256]u8 = undefined;
        while (!self.active_port.buffer.isEmpty()) {
            const bytes_read = self.active_port.buffer.read(&buffer);
            if (bytes_read == 0) break;
            self.active_port.writeString(buffer[0..bytes_read]);
        }
    }

    pub fn directWrite(self: *Driver, byte: u8) void {
        if (self.phase == .uninitialized) return;
        self.active_port.writeByte(byte);
    }

    pub fn directWriteString(self: *Driver, str: []const u8) void {
        if (self.phase == .uninitialized) return;
        self.active_port.writeString(str);
    }

    pub fn selfTest(self: *Driver) bool {
        if (self.phase == .uninitialized) return false;
        return hal.selfTest(self.active_port.base_port);
    }
};

/// Global driver instance
var global_driver: Driver = undefined;
var driver_initialized: bool = false;

/// Initialize the global driver instance
pub fn initGlobal() void {
    if (driver_initialized) return;
    global_driver = Driver.init();
    driver_initialized = true;
}

/// Get the global driver instance
pub fn getGlobal() *Driver {
    if (!driver_initialized) {
        initGlobal();
    }
    return &global_driver;
}
