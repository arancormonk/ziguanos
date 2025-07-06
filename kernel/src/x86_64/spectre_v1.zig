// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Spectre V1 Mitigation Module for Ziguanos Kernel
// Provides consistent array bounds masking to prevent speculative execution side-channel attacks

const std = @import("std");
const speculation = @import("speculation.zig");
const serial = @import("../drivers/serial.zig");

// Re-export the core masking function from speculation.zig for backward compatibility
pub const arrayIndexMask = speculation.arrayIndexMask;

// Enhanced array indexing with bounds checking and speculation-safe masking
pub inline fn safeArrayIndex(index: usize, array_size: usize) usize {
    // Apply speculation-safe masking to prevent Spectre V1 attacks
    const masked_index = speculation.arrayIndexMask(index, array_size);

    // Debug assertion in development builds
    if (std.debug.runtime_safety) {
        if (index >= array_size) {
            serial.println("[SPECTRE_V1] WARNING: Array index {} out of bounds (size: {}), masked to {}", .{ index, array_size, masked_index });
        }
    }

    return masked_index;
}

// Safe array access with automatic bounds masking
pub inline fn safeArrayAccess(comptime T: type, array: []const T, index: usize) T {
    const safe_index = safeArrayIndex(index, array.len);
    return array[safe_index];
}

// Safe mutable array access with automatic bounds masking
pub inline fn safeArrayAccessMut(comptime T: type, array: []T, index: usize) *T {
    const safe_index = safeArrayIndex(index, array.len);
    return &array[safe_index];
}

// Safe array write with automatic bounds masking
pub inline fn safeArrayWrite(comptime T: type, array: []T, index: usize, value: T) void {
    const safe_index = safeArrayIndex(index, array.len);
    array[safe_index] = value;
}

// Safe bitmap operations with speculation protection
pub inline fn safeBitmapGet(bitmap: []const u64, bit_index: usize) bool {
    const total_bits = bitmap.len * 64;
    const safe_bit_index = safeArrayIndex(bit_index, total_bits);

    const word_index = safe_bit_index / 64;
    const bit_offset = @as(u6, @truncate(safe_bit_index % 64));

    const safe_word_index = safeArrayIndex(word_index, bitmap.len);
    const word = bitmap[safe_word_index];

    return (word & (@as(u64, 1) << bit_offset)) != 0;
}

// Safe bitmap set with speculation protection
pub inline fn safeBitmapSet(bitmap: []u64, bit_index: usize, value: bool) void {
    const total_bits = bitmap.len * 64;
    const safe_bit_index = safeArrayIndex(bit_index, total_bits);

    const word_index = safe_bit_index / 64;
    const bit_offset = @as(u6, @truncate(safe_bit_index % 64));

    const safe_word_index = safeArrayIndex(word_index, bitmap.len);

    if (value) {
        bitmap[safe_word_index] |= (@as(u64, 1) << bit_offset);
    } else {
        bitmap[safe_word_index] &= ~(@as(u64, 1) << bit_offset);
    }
}

// Safe bitmap clear with speculation protection
pub inline fn safeBitmapClear(bitmap: []u64, bit_index: usize) void {
    safeBitmapSet(bitmap, bit_index, false);
}

// Safe bitmap toggle with speculation protection
pub inline fn safeBitmapToggle(bitmap: []u64, bit_index: usize) void {
    const current = safeBitmapGet(bitmap, bit_index);
    safeBitmapSet(bitmap, bit_index, !current);
}

// Safe memory copy with bounds checking and speculation protection
pub inline fn safeMemoryCopy(dest: []u8, src: []const u8, offset: usize, count: usize) void {
    const safe_offset = safeArrayIndex(offset, dest.len);
    const safe_count = @min(count, dest.len - safe_offset);
    const safe_src_count = @min(safe_count, src.len);

    // Perform bounds-checked copy
    for (0..safe_src_count) |i| {
        const dest_idx = safe_offset + i;
        if (dest_idx >= dest.len) break;
        dest[dest_idx] = src[i];
    }
}

// Safe string operations with speculation protection
pub inline fn safeStringLength(str: []const u8, max_len: usize) usize {
    const safe_max = safeArrayIndex(max_len, str.len + 1);
    var len: usize = 0;

    while (len < safe_max and len < str.len) : (len += 1) {
        if (str[len] == 0) break;
    }

    return len;
}

// Safe buffer operations for kernel use
pub inline fn safeBufferAccess(buffer: []u8, offset: usize, size: usize) []u8 {
    const safe_offset = safeArrayIndex(offset, buffer.len);
    const safe_end = @min(safe_offset + size, buffer.len);
    const safe_size = if (safe_end > safe_offset) safe_end - safe_offset else 0;

    return buffer[safe_offset .. safe_offset + safe_size];
}

// Test function to verify Spectre V1 mitigation implementation
pub fn testSpectreV1Mitigation() void {
    serial.println("[SPECTRE_V1] Testing Spectre V1 mitigation implementation", .{});

    // Test array bounds masking
    var test_array = [_]u32{ 1, 2, 3, 4, 5 };
    const array_len = test_array.len;

    // Test 1: Normal access
    const normal_index = 2;
    const normal_masked = safeArrayIndex(normal_index, array_len);
    if (normal_masked == normal_index) {
        serial.println("[SPECTRE_V1] ✓ Normal array access: index {} -> {}", .{ normal_index, normal_masked });
    } else {
        serial.println("[SPECTRE_V1] ✗ Normal array access failed: index {} -> {}", .{ normal_index, normal_masked });
    }

    // Test 2: Out-of-bounds access (should be masked)
    const oob_index = 10;
    const oob_masked = safeArrayIndex(oob_index, array_len);
    if (oob_masked < array_len) {
        serial.println("[SPECTRE_V1] ✓ Out-of-bounds access masked: index {} -> {}", .{ oob_index, oob_masked });
    } else {
        serial.println("[SPECTRE_V1] ✗ Out-of-bounds access not masked: index {} -> {}", .{ oob_index, oob_masked });
    }

    // Test 3: Safe array access
    const safe_value = safeArrayAccess(u32, &test_array, 2);
    if (safe_value == 3) {
        serial.println("[SPECTRE_V1] ✓ Safe array access: value = {}", .{safe_value});
    } else {
        serial.println("[SPECTRE_V1] ✗ Safe array access failed: value = {}", .{safe_value});
    }

    // Test 4: Safe array write
    safeArrayWrite(u32, &test_array, 1, 42);
    if (test_array[1] == 42) {
        serial.println("[SPECTRE_V1] ✓ Safe array write: test_array[1] = {}", .{test_array[1]});
    } else {
        serial.println("[SPECTRE_V1] ✗ Safe array write failed: test_array[1] = {}", .{test_array[1]});
    }

    // Test 5: Bitmap operations
    var test_bitmap = [_]u64{ 0, 0, 0, 0 };
    const bit_index = 65; // Second word, bit 1

    safeBitmapSet(&test_bitmap, bit_index, true);
    const bit_value = safeBitmapGet(&test_bitmap, bit_index);
    if (bit_value) {
        serial.println("[SPECTRE_V1] ✓ Safe bitmap operations: bit {} set", .{bit_index});
    } else {
        serial.println("[SPECTRE_V1] ✗ Safe bitmap operations failed: bit {} not set", .{bit_index});
    }

    // Test 6: Out-of-bounds bitmap access (should be masked)
    const oob_bit_index = 300; // Way beyond bitmap size
    const oob_bit_masked = safeArrayIndex(oob_bit_index, test_bitmap.len * 64);
    if (oob_bit_masked < test_bitmap.len * 64) {
        serial.println("[SPECTRE_V1] ✓ Out-of-bounds bitmap access masked: bit {} -> {}", .{ oob_bit_index, oob_bit_masked });
    } else {
        serial.println("[SPECTRE_V1] ✗ Out-of-bounds bitmap access not masked: bit {} -> {}", .{ oob_bit_index, oob_bit_masked });
    }

    serial.println("[SPECTRE_V1] Spectre V1 mitigation test completed", .{});
}

// Statistics tracking for Spectre V1 mitigation usage
pub const SpectreV1Stats = struct {
    total_array_accesses: u64 = 0,
    masked_accesses: u64 = 0,
    bitmap_operations: u64 = 0,
    buffer_operations: u64 = 0,

    pub fn recordArrayAccess(self: *SpectreV1Stats, was_masked: bool) void {
        self.total_array_accesses += 1;
        if (was_masked) {
            self.masked_accesses += 1;
        }
    }

    pub fn recordBitmapOperation(self: *SpectreV1Stats) void {
        self.bitmap_operations += 1;
    }

    pub fn recordBufferOperation(self: *SpectreV1Stats) void {
        self.buffer_operations += 1;
    }

    pub fn getMitigationEffectiveness(self: *const SpectreV1Stats) u32 {
        if (self.total_array_accesses == 0) return 100;
        return @as(u32, @intCast((self.masked_accesses * 100) / self.total_array_accesses));
    }

    pub fn printStats(self: *const SpectreV1Stats) void {
        serial.println("[SPECTRE_V1] Statistics:", .{});
        serial.println("  Total array accesses: {}", .{self.total_array_accesses});
        serial.println("  Masked accesses: {}", .{self.masked_accesses});
        serial.println("  Bitmap operations: {}", .{self.bitmap_operations});
        serial.println("  Buffer operations: {}", .{self.buffer_operations});
        serial.println("  Mitigation effectiveness: {}%", .{self.getMitigationEffectiveness()});
    }
};

var spectre_v1_stats = SpectreV1Stats{};

// Get current statistics
pub fn getStats() *const SpectreV1Stats {
    return &spectre_v1_stats;
}

// Initialize Spectre V1 mitigation system
pub fn init() void {
    serial.println("[SPECTRE_V1] Initializing Spectre V1 mitigation system", .{});

    // Test the mitigation implementation
    testSpectreV1Mitigation();

    serial.println("[SPECTRE_V1] Spectre V1 mitigation system initialized", .{});
}
