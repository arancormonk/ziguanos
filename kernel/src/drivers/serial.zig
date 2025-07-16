// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Layered serial driver for kernel debugging
// This module provides a unified interface to the layered serial driver architecture

const std = @import("std");
const runtime_info = @import("../boot/runtime_info.zig");

// Import the unified API and layer modules
const api = @import("serial/api.zig");
const core = @import("serial/core/config.zig");
const advanced_queue = @import("serial/advanced/queue.zig");
const advanced_stats = @import("serial/advanced/statistics.zig");
const advanced_formatter = @import("serial/advanced/formatter.zig");
const security_sanitizer = @import("serial/security/sanitizer.zig");
const security_policy = @import("serial/security/policy.zig");
const timing_security = @import("serial/security/timing.zig");

// Re-export commonly used types
pub const ComPort = core.ComPort;
pub const SerialConfig = core.SerialConfig;
pub const BaudRate = core.BaudRate;
pub const MessageLevel = security_policy.MessageLevel;

// Global instances for advanced features
var queue_manager: advanced_queue.QueueManager = undefined;
var statistics: advanced_stats.Statistics = undefined;
var formatter: advanced_formatter.Formatter = undefined;
var address_sanitizer: security_sanitizer.AddressSanitizer = undefined;
var security_policy_instance: security_policy.SecurityPolicy = undefined;
var timing_security_instance: timing_security.TimingSecurity = undefined;

// Module state
var initialized: bool = false;
var advanced_initialized: bool = false;
var security_initialized: bool = false;

// Initialize for early boot (minimal hardware access)
pub fn init() void {
    if (initialized) return;

    const serial_api = api.getGlobal();
    serial_api.initEarly();
    initialized = true;
}

// Initialize core driver features
pub fn initCore() void {
    if (!initialized) init();

    const serial_api = api.getGlobal();
    serial_api.initCore();
}

// Initialize advanced features (call after memory management is ready)
pub fn initAdvanced() void {
    if (!initialized) init();
    if (advanced_initialized) return;

    // Initialize advanced components
    queue_manager = advanced_queue.QueueManager.init();
    statistics = advanced_stats.Statistics.init();
    formatter = advanced_formatter.Formatter.init();

    const serial_api = api.getGlobal();
    serial_api.initAdvanced(&queue_manager, &statistics, &formatter);
    advanced_initialized = true;
}

// Initialize security features (call after security subsystems are ready)
pub fn initSecurity() void {
    if (!advanced_initialized) initAdvanced();
    if (security_initialized) return;

    // Initialize security components
    const info = runtime_info.getRuntimeInfo();
    const kaslr_offset = info.kaslr_offset;
    address_sanitizer = security_sanitizer.AddressSanitizer.init(kaslr_offset);
    security_policy_instance = security_policy.SecurityPolicy.init();
    timing_security_instance = timing_security.TimingSecurity.init(security_policy_instance.getTimingConfig());

    const serial_api = api.getGlobal();
    serial_api.initSecurity(&address_sanitizer, &security_policy_instance, &timing_security_instance);
    security_initialized = true;
}

// Initialize full serial driver with all features
pub fn initFull() void {
    initSecurity();
}

// Set KASLR offset for address sanitization (compatibility function)
pub fn setKASLROffset(offset: u64) void {
    _ = offset; // KASLR offset is now handled internally by runtime_info
    // Security initialization will pick up the offset from runtime_info
}

// Flush any buffered output
pub fn flush() void {
    const serial_api = api.getGlobal();
    serial_api.flush();
}

// Main print function with automatic fallback
pub fn print(comptime fmt: []const u8, args: anytype) void {
    const serial_api = api.getGlobal();
    serial_api.print(fmt, args);
}

// Print with newline
pub fn println(comptime fmt: []const u8, args: anytype) void {
    const serial_api = api.getGlobal();
    serial_api.println(fmt, args);
}

// Print with security level checking
pub fn printWithLevel(level: MessageLevel, comptime fmt: []const u8, args: anytype) void {
    const serial_api = api.getGlobal();
    serial_api.printWithLevel(level, fmt, args);
}

// Print address with sanitization if available
pub fn printAddress(name: []const u8, addr: u64) void {
    const serial_api = api.getGlobal();
    serial_api.printAddress(name, addr);
}

// Direct write functions for emergency use
pub fn directWrite(c: u8) void {
    const serial_api = api.getGlobal();
    serial_api.directWrite(c);
}

pub fn directWriteString(str: []const u8) void {
    const serial_api = api.getGlobal();
    serial_api.directWriteString(str);
}

// Print statistics if available
pub fn printStats() void {
    const serial_api = api.getGlobal();
    serial_api.printStats();
}

// Self-test function
pub fn selfTest() bool {
    const serial_api = api.getGlobal();
    return serial_api.selfTest();
}

// Compatibility functions for existing code
pub fn flushPartial(max_bytes: usize) usize {
    _ = max_bytes;
    flush();
    return 0; // Simplified implementation
}

// Custom formatter for sanitized addresses (for compatibility)
pub const SanitizedAddress = struct {
    value: u64,

    pub fn format(
        self: SanitizedAddress,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        if (security_initialized) {
            try address_sanitizer.formatAddress(writer, self.value);
        } else {
            try writer.print("0x{x:0>16}", .{self.value});
        }
    }
};

pub fn sanitizedAddress(value: u64) SanitizedAddress {
    return .{ .value = value };
}

// Early boot compatibility functions (now delegated to API)
pub fn earlyWrite(c: u8) void {
    directWrite(c);
}

pub fn earlyWriteString(str: []const u8) void {
    directWriteString(str);
}

pub fn earlyPrint(comptime fmt: []const u8, args: anytype) void {
    print(fmt, args);
}

pub fn earlyPrintln(comptime fmt: []const u8, args: anytype) void {
    println(fmt, args);
}
