// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Buffer Safety Module
// Provides secure buffer operations with comprehensive overflow protection
// following Intel x86-64 security recommendations and industry best practices

const std = @import("std");

// Safe buffer operations with automatic bounds checking
pub const SafeBuffer = struct {
    // Maximum allowed buffer size for security
    pub const MAX_BUFFER_SIZE = 4096;

    // Safely format a string into a fixed-size buffer
    pub fn format(
        buffer: []u8,
        comptime fmt: []const u8,
        args: anytype,
    ) error{ BufferTooSmall, InvalidFormat }![]const u8 {
        // SECURITY: Validate buffer is not null or empty
        if (buffer.len == 0) {
            return error.BufferTooSmall;
        }

        // SECURITY: Use bounded slice operations
        const result = std.fmt.bufPrint(buffer, fmt, args) catch |err| switch (err) {
            error.NoSpaceLeft => return error.BufferTooSmall,
            else => return error.InvalidFormat,
        };

        return result;
    }

    // Safely format with automatic truncation
    pub fn formatTruncate(
        buffer: []u8,
        comptime fmt: []const u8,
        args: anytype,
    ) ![]const u8 {
        // SECURITY: Reserve space for truncation indicator
        const truncate_suffix = "...";
        const min_size = truncate_suffix.len + 1;

        if (buffer.len < min_size) {
            return error.BufferTooSmall;
        }

        // Try full format first
        const result = std.fmt.bufPrint(buffer, fmt, args) catch |err| {
            if (err == error.NoSpaceLeft) {
                // SECURITY: Truncate safely with indicator
                const safe_size = buffer.len - truncate_suffix.len;
                _ = std.fmt.bufPrint(buffer[0..safe_size], fmt, args) catch {
                    // Even truncated format failed, use minimal message
                    @memcpy(buffer[0..truncate_suffix.len], truncate_suffix);
                    return buffer[0..truncate_suffix.len];
                };

                // Add truncation indicator
                @memcpy(buffer[safe_size..buffer.len], truncate_suffix);
                return buffer[0..buffer.len];
            }
            return err;
        };

        return result;
    }

    // Copy string with bounds checking
    pub fn copyBounded(dest: []u8, src: []const u8) ![]u8 {
        // SECURITY: Validate destination has space
        if (src.len > dest.len) {
            return error.DestinationTooSmall;
        }

        // SECURITY: Use safe memcpy
        @memcpy(dest[0..src.len], src);
        return dest[0..src.len];
    }

    // Copy with automatic null termination
    pub fn copyStringZ(dest: []u8, src: []const u8) ![]u8 {
        // SECURITY: Ensure room for null terminator
        if (src.len >= dest.len) {
            return error.DestinationTooSmall;
        }

        @memcpy(dest[0..src.len], src);
        dest[src.len] = 0;

        return dest[0 .. src.len + 1];
    }

    // Convert narrow string to wide with bounds checking
    pub fn toWideString(dest: []u16, src: []const u8) ![]u16 {
        // SECURITY: Validate destination capacity
        if (src.len >= dest.len) {
            return error.DestinationTooSmall;
        }

        // SECURITY: Use bounded operations
        for (src, 0..) |c, i| {
            dest[i] = c;
        }
        dest[src.len] = 0;

        return dest[0 .. src.len + 1];
    }

    // Validate buffer size at compile time
    pub fn validateSize(comptime size: usize) void {
        if (size > MAX_BUFFER_SIZE) {
            @compileError("Buffer size exceeds maximum safe limit");
        }
    }
};

// Integer overflow safe operations
pub const SafeMath = struct {
    // Add with overflow detection
    pub fn add(comptime T: type, a: T, b: T) !T {
        const result = @addWithOverflow(a, b);
        if (result[1] != 0) {
            return error.IntegerOverflow;
        }
        return result[0];
    }

    // Multiply with overflow detection
    pub fn mul(comptime T: type, a: T, b: T) !T {
        const result = @mulWithOverflow(a, b);
        if (result[1] != 0) {
            return error.IntegerOverflow;
        }
        return result[0];
    }

    // Safe cast with range checking
    pub fn cast(comptime dest_type: type, value: anytype) !dest_type {
        const src_info = @typeInfo(@TypeOf(value));
        const dst_info = @typeInfo(dest_type);

        // Check if value fits in destination type
        if (src_info.Int.bits > dst_info.Int.bits) {
            const max_val = std.math.maxInt(dest_type);
            const min_val = std.math.minInt(dest_type);

            if (value > max_val or value < min_val) {
                return error.IntegerOverflow;
            }
        }

        return @as(dest_type, @intCast(value));
    }
};

// Memory sanitization utilities
pub const MemorySanitizer = struct {
    // Securely zero memory
    pub fn secureZero(comptime T: type, ptr: *T) void {
        const bytes = std.mem.asBytes(ptr);

        // SECURITY: Use volatile to prevent optimization
        @setRuntimeSafety(false);
        const volatile_ptr: *volatile [bytes.len]u8 = @ptrCast(bytes);
        for (volatile_ptr) |*byte| {
            byte.* = 0;
        }
        @setRuntimeSafety(true);
    }

    // Check for potential buffer overflow patterns
    pub fn checkOverflowPattern(buffer: []const u8) bool {
        // Common overflow patterns
        const patterns = [_][]const u8{
            "\x41\x41\x41\x41", // AAAA
            "\x00\x00\x00\x00", // NULL bytes
            "\xff\xff\xff\xff", // All ones
            "\x90\x90\x90\x90", // NOP sled
        };

        if (buffer.len < 4) return false;

        for (patterns) |pattern| {
            if (std.mem.indexOf(u8, buffer, pattern) != null) {
                return true;
            }
        }

        return false;
    }
};

// Compile-time tests for buffer safety
test "SafeBuffer format operations" {
    var buffer: [32]u8 = undefined;

    // Test normal format
    const result = try SafeBuffer.format(&buffer, "Test: {d}", .{42});
    try std.testing.expectEqualStrings("Test: 42", result);

    // Test buffer overflow handling
    const overflow_result = SafeBuffer.format(&buffer, "This is a very long string that will definitely overflow the small buffer", .{});
    try std.testing.expectError(error.BufferTooSmall, overflow_result);

    // Test truncation
    const truncated = try SafeBuffer.formatTruncate(&buffer, "This is a very long string that will be truncated", .{});
    try std.testing.expect(truncated.len == buffer.len);
    try std.testing.expect(std.mem.endsWith(u8, truncated, "..."));
}

test "SafeMath operations" {
    // Test overflow detection
    const max_u32 = std.math.maxInt(u32);
    try std.testing.expectError(error.IntegerOverflow, SafeMath.add(u32, max_u32, 1));

    // Test safe operations
    const result = try SafeMath.add(u32, 100, 200);
    try std.testing.expectEqual(@as(u32, 300), result);

    // Test safe casting
    const large: u32 = 1000;
    const small = try SafeMath.cast(u16, large);
    try std.testing.expectEqual(@as(u16, 1000), small);

    // Test cast overflow
    const too_large: u32 = 70000;
    try std.testing.expectError(error.IntegerOverflow, SafeMath.cast(u16, too_large));
}
