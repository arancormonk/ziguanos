// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Enhanced formatter for serial driver
// This module provides advanced formatting capabilities with optional dependencies

const std = @import("std");

// Enhanced formatter with optional sanitization
pub const Formatter = struct {
    buffer: [4096]u8,
    pos: usize,

    // Optional dependencies (can be null)
    address_sanitizer: ?*const AddressSanitizer = null,

    pub fn init() Formatter {
        return Formatter{
            .buffer = [_]u8{0} ** 4096,
            .pos = 0,
        };
    }

    pub fn reset(self: *Formatter) void {
        self.pos = 0;
    }

    pub fn write(self: *Formatter, data: []const u8) !void {
        if (self.pos + data.len > self.buffer.len) {
            return error.BufferFull;
        }

        @memcpy(self.buffer[self.pos .. self.pos + data.len], data);
        self.pos += data.len;
    }

    pub fn print(self: *Formatter, comptime fmt: []const u8, args: anytype) !void {
        var stream = std.io.fixedBufferStream(self.buffer[self.pos..]);
        const writer = stream.writer();

        try writer.print(fmt, args);
        self.pos += stream.pos;
    }

    pub fn formatSanitized(self: *Formatter, comptime fmt: []const u8, args: anytype) !void {
        // If we have address sanitizer, use it, otherwise use regular formatting
        if (self.address_sanitizer) |_| {
            // For now, just use regular formatting
            // In a full implementation, we'd scan for addresses and sanitize them
            try self.print(fmt, args);
        } else {
            try self.print(fmt, args);
        }
    }

    pub fn formatAddress(self: *Formatter, address: u64) !void {
        if (self.address_sanitizer) |sanitizer| {
            const sanitized = sanitizer.sanitize(address);
            try self.write(sanitized);
        } else {
            try self.print("0x{x:0>16}", .{address});
        }
    }

    pub fn getWritten(self: *const Formatter) []const u8 {
        return self.buffer[0..self.pos];
    }

    pub fn getWriter(self: *Formatter) Writer {
        return Writer{ .formatter = self };
    }

    pub const Writer = struct {
        formatter: *Formatter,

        pub fn writeAll(self: Writer, data: []const u8) !void {
            try self.formatter.write(data);
        }

        pub fn print(self: Writer, comptime fmt: []const u8, args: anytype) !void {
            try self.formatter.print(fmt, args);
        }
    };
};

// Address sanitizer interface (optional dependency)
pub const AddressSanitizer = struct {
    kaslr_offset: u64,

    pub fn init(kaslr_offset: u64) AddressSanitizer {
        return AddressSanitizer{
            .kaslr_offset = kaslr_offset,
        };
    }

    pub fn sanitize(self: *const AddressSanitizer, address: u64) []const u8 {
        _ = self;
        // For now, just return basic format
        // In a full implementation, we'd subtract KASLR offset
        var buffer: [32]u8 = undefined;
        return std.fmt.bufPrint(&buffer, "0x{x:0>16}", .{address}) catch "0x????????????????";
    }
};

// Formatter configuration with optional dependencies
pub const FormatterConfig = struct {
    address_sanitizer: ?*const AddressSanitizer = null,

    pub fn init() FormatterConfig {
        return FormatterConfig{};
    }

    pub fn withAddressSanitizer(_: FormatterConfig, sanitizer: *const AddressSanitizer) FormatterConfig {
        return FormatterConfig{
            .address_sanitizer = sanitizer,
        };
    }
};

// Create a formatter with optional dependencies
pub fn createFormatter(config: FormatterConfig) Formatter {
    return Formatter{
        .buffer = [_]u8{0} ** 4096,
        .pos = 0,
        .address_sanitizer = config.address_sanitizer,
    };
}
