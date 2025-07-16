// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Address and data sanitization for serial output
// This module provides KASLR-aware address sanitization without external dependencies

const std = @import("std");

// Import hardware RNG and timer for entropy
const rng = @import("../../../x86_64/rng.zig");
const timer = @import("../../../x86_64/timer.zig");

// SipHash round function
inline fn sipRound(v0: *u64, v1: *u64, v2: *u64, v3: *u64) void {
    v0.* +%= v1.*;
    v2.* +%= v3.*;
    v1.* = std.math.rotl(u64, v1.*, 13);
    v3.* = std.math.rotl(u64, v3.*, 16);
    v1.* ^= v0.*;
    v3.* ^= v2.*;
    v0.* = std.math.rotl(u64, v0.*, 32);
    v2.* +%= v1.*;
    v0.* +%= v3.*;
    v1.* = std.math.rotl(u64, v1.*, 17);
    v3.* = std.math.rotl(u64, v3.*, 21);
    v1.* ^= v2.*;
    v3.* ^= v0.*;
    v2.* = std.math.rotl(u64, v2.*, 32);
}

// Address sanitizer for KASLR protection
pub const AddressSanitizer = struct {
    kaslr_offset: u64,
    hash_key0: u64, // First 64-bit key for SipHash
    hash_key1: u64, // Second 64-bit key for SipHash
    enabled: bool,

    pub fn init(kaslr_offset: u64) AddressSanitizer {
        // Generate cryptographically secure keys using hardware RNG
        var key0: u64 = 0x736f6d6570736575; // Default: "somepseu"
        var key1: u64 = 0x646f72616e646f6d; // Default: "dorandom"

        // Try to get hardware RNG entropy
        const rng_result0 = rng.getRandom64();
        const rng_result1 = rng.getRandom64();

        if (rng_result0.success and rng_result1.success) {
            // Use hardware RNG directly
            key0 = rng_result0.value;
            key1 = rng_result1.value;
        } else {
            // Fallback: mix timer ticks with KASLR offset for entropy
            const ticks = timer.getTicks();
            key0 = ticks ^ kaslr_offset ^ 0x736f6d6570736575;
            key1 = (ticks << 32) ^ (kaslr_offset >> 32) ^ 0x646f72616e646f6d;

            // Additional mixing using golden ratio
            key0 = key0 *% 0x9E3779B97F4A7C15;
            key1 = key1 *% 0x9E3779B97F4A7C15;
        }

        return AddressSanitizer{
            .kaslr_offset = kaslr_offset,
            .hash_key0 = key0,
            .hash_key1 = key1,
            .enabled = true,
        };
    }

    pub fn disable(self: *AddressSanitizer) void {
        self.enabled = false;
    }

    pub fn enable(self: *AddressSanitizer) void {
        self.enabled = true;
    }

    fn hashAddress(self: *const AddressSanitizer, addr: u64) u64 {
        // SipHash-2-4 implementation for cryptographically secure hashing
        // This provides strong protection against hash collision attacks

        // Initialize SipHash state
        var v0: u64 = 0x736f6d6570736575 ^ self.hash_key0;
        var v1: u64 = 0x646f72616e646f6d ^ self.hash_key1;
        var v2: u64 = 0x6c7967656e657261 ^ self.hash_key0;
        var v3: u64 = 0x7465646279746573 ^ self.hash_key1;

        // Mix in the address
        v3 ^= addr;

        // 2 compression rounds
        sipRound(&v0, &v1, &v2, &v3);
        sipRound(&v0, &v1, &v2, &v3);

        v0 ^= addr;

        // Mix in length (always 8 bytes for a u64)
        v2 ^= 8;

        // 4 finalization rounds
        sipRound(&v0, &v1, &v2, &v3);
        sipRound(&v0, &v1, &v2, &v3);
        sipRound(&v0, &v1, &v2, &v3);
        sipRound(&v0, &v1, &v2, &v3);

        // Final result
        return v0 ^ v1 ^ v2 ^ v3;
    }

    pub fn sanitizeAddress(self: *const AddressSanitizer, addr: u64) u64 {
        if (!self.enabled) {
            return addr;
        }

        // If the address is within kernel space, apply KASLR offset removal
        if (addr >= 0xFFFF800000000000) {
            const sanitized = addr -% self.kaslr_offset;
            return self.hashAddress(sanitized) & 0xFFFF;
        }

        // For other addresses, just hash them
        return self.hashAddress(addr) & 0xFFFF;
    }

    pub fn formatAddress(self: *const AddressSanitizer, writer: anytype, addr: u64) !void {
        if (self.enabled) {
            try writer.print("0x{x:0>4}", .{self.sanitizeAddress(addr)});
        } else {
            try writer.print("0x{x:0>16}", .{addr});
        }
    }

    pub fn sanitizeBuffer(self: *const AddressSanitizer, buffer: []const u8, output: []u8) void {
        if (!self.enabled or buffer.len == 0 or output.len == 0) {
            @memcpy(output[0..@min(buffer.len, output.len)], buffer[0..@min(buffer.len, output.len)]);
            return;
        }

        // Look for potential addresses (8-byte aligned values that look like kernel addresses)
        var i: usize = 0;
        const copy_len = @min(buffer.len, output.len);

        while (i < copy_len) {
            // Check if we have enough bytes for a potential address
            if (i + 8 <= copy_len and i % 8 == 0) {
                // Read potential address
                const potential_addr = std.mem.readInt(u64, buffer[i..][0..8], .little);

                // Check if it looks like a kernel address
                if (potential_addr >= 0xFFFF800000000000) {
                    // Sanitize it
                    const sanitized = self.sanitizeAddress(potential_addr);
                    std.mem.writeInt(u64, output[i..][0..8], sanitized, .little);
                    i += 8;
                    continue;
                }
            }

            // Not an address, copy as-is
            output[i] = buffer[i];
            i += 1;
        }
    }

    pub fn sanitizeString(self: *const AddressSanitizer, input: []const u8, writer: anytype) !void {
        if (!self.enabled) {
            try writer.writeAll(input);
            return;
        }

        // Simple pattern matching for hex addresses in strings
        var i: usize = 0;
        while (i < input.len) {
            // Look for "0x" prefix
            if (i + 2 < input.len and input[i] == '0' and input[i + 1] == 'x') {
                // Check if followed by hex digits
                const hex_start = i + 2;
                var hex_end = hex_start;

                while (hex_end < input.len and hex_end < hex_start + 16) {
                    const c = input[hex_end];
                    if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F'))) {
                        break;
                    }
                    hex_end += 1;
                }

                // If we found at least 8 hex digits, it might be an address
                if (hex_end - hex_start >= 8) {
                    // Parse the address
                    const hex_str = input[hex_start..hex_end];
                    if (std.fmt.parseInt(u64, hex_str, 16)) |addr| {
                        // Write sanitized version
                        try self.formatAddress(writer, addr);
                        i = hex_end;
                        continue;
                    } else |_| {
                        // Not a valid hex number, write as-is
                        try writer.writeByte(input[i]);
                        i += 1;
                    }
                } else {
                    // Too short to be an address
                    try writer.writeByte(input[i]);
                    i += 1;
                }
            } else {
                // Regular character
                try writer.writeByte(input[i]);
                i += 1;
            }
        }
    }
};
