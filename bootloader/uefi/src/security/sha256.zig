// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// SHA-256 implementation for kernel verification
// Based on FIPS 180-4 specification
// Constant-time implementation to prevent timing attacks

const std = @import("std");

// SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
const K = [64]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

pub const SHA256_SIZE = 32;

pub const SHA256 = struct {
    h: [8]u32,
    buf: [64]u8,
    buf_len: u8,
    total_len: u64,

    pub fn init() SHA256 {
        return SHA256{
            // Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
            .h = [8]u32{
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19,
            },
            .buf = [_]u8{0} ** 64,
            .buf_len = 0,
            .total_len = 0,
        };
    }

    pub fn update(self: *SHA256, data: []const u8) void {
        var remaining = data;

        // Process any buffered data first
        if (self.buf_len > 0) {
            const space = 64 - self.buf_len;
            const to_copy = @min(space, remaining.len);
            @memcpy(self.buf[self.buf_len..][0..to_copy], remaining[0..to_copy]);
            self.buf_len += @as(u8, @intCast(to_copy));
            remaining = remaining[to_copy..];

            if (self.buf_len == 64) {
                self.processBlock(&self.buf);
                self.buf_len = 0;
            }
        }

        // Process complete 512-bit blocks
        while (remaining.len >= 64) {
            var block: [64]u8 = undefined;
            @memcpy(&block, remaining[0..64]);
            self.processBlock(&block);
            remaining = remaining[64..];
        }

        // Buffer any remaining bytes
        if (remaining.len > 0) {
            @memcpy(self.buf[0..remaining.len], remaining);
            self.buf_len = @as(u8, @intCast(remaining.len));
        }

        self.total_len += data.len;
    }

    pub fn final(self: *SHA256) [SHA256_SIZE]u8 {
        // Pad the message
        const msg_len_bits = self.total_len * 8;

        // Add padding bit
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        // If not enough space for length, process this block and start a new one
        if (self.buf_len > 56) {
            @memset(self.buf[self.buf_len..], 0);
            self.processBlock(&self.buf);
            self.buf_len = 0;
        }

        // Pad with zeros
        @memset(self.buf[self.buf_len..56], 0);

        // Append length in bits as 64-bit big-endian
        self.buf[56] = @as(u8, @intCast(msg_len_bits >> 56));
        self.buf[57] = @as(u8, @intCast(msg_len_bits >> 48));
        self.buf[58] = @as(u8, @intCast(msg_len_bits >> 40));
        self.buf[59] = @as(u8, @intCast(msg_len_bits >> 32));
        self.buf[60] = @as(u8, @intCast(msg_len_bits >> 24));
        self.buf[61] = @as(u8, @intCast(msg_len_bits >> 16));
        self.buf[62] = @as(u8, @intCast(msg_len_bits >> 8));
        self.buf[63] = @as(u8, @intCast(msg_len_bits));

        self.processBlock(&self.buf);

        // Convert hash to bytes
        var result: [SHA256_SIZE]u8 = undefined;
        for (0..8) |i| {
            result[i * 4] = @as(u8, @intCast((self.h[i] >> 24) & 0xff));
            result[i * 4 + 1] = @as(u8, @intCast((self.h[i] >> 16) & 0xff));
            result[i * 4 + 2] = @as(u8, @intCast((self.h[i] >> 8) & 0xff));
            result[i * 4 + 3] = @as(u8, @intCast(self.h[i] & 0xff));
        }

        return result;
    }

    fn processBlock(self: *SHA256, block: *const [64]u8) void {
        var w: [64]u32 = undefined;

        // Prepare message schedule - unrolled for constant time
        comptime var i = 0;
        inline while (i < 16) : (i += 1) {
            w[i] = (@as(u32, block[i * 4]) << 24) |
                (@as(u32, block[i * 4 + 1]) << 16) |
                (@as(u32, block[i * 4 + 2]) << 8) |
                @as(u32, block[i * 4 + 3]);
        }

        // Extend message schedule - fully unrolled
        inline while (i < 64) : (i += 1) {
            const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] +% s0 +% w[i - 7] +% s1;
        }

        // Initialize working variables
        var a = self.h[0];
        var b = self.h[1];
        var c = self.h[2];
        var d = self.h[3];
        var e = self.h[4];
        var f = self.h[5];
        var g = self.h[6];
        var h = self.h[7];

        // Main loop - fully unrolled for constant time
        comptime var j = 0;
        inline while (j < 64) : (j += 1) {
            const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = h +% s1 +% ch +% K[j] +% w[j];
            const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = s0 +% maj;

            h = g;
            g = f;
            f = e;
            e = d +% temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 +% temp2;
        }

        // Add to hash values
        self.h[0] +%= a;
        self.h[1] +%= b;
        self.h[2] +%= c;
        self.h[3] +%= d;
        self.h[4] +%= e;
        self.h[5] +%= f;
        self.h[6] +%= g;
        self.h[7] +%= h;

        // Clear sensitive data
        secureZero([64]u32, &w);
    }

    fn rotr(x: u32, n: u5) u32 {
        // True constant-time rotation
        // Modern x86-64 processors have barrel shifters that execute rotations
        // in constant time (1 cycle) regardless of rotation count
        // The shift amount is masked to 5 bits automatically by the hardware
        return (x >> n) | (x << @as(u5, @intCast(32 - @as(u32, n))));
    }
};

// Secure memory zeroing that won't be optimized away
fn secureZero(comptime T: type, data: *T) void {
    const bytes = @as([*]volatile u8, @ptrCast(data));
    const size = @sizeOf(T);

    // Use volatile writes to prevent optimization
    var i: usize = 0;
    while (i < size) : (i += 1) {
        bytes[i] = 0;
    }

    // Memory barrier to ensure completion
    asm volatile ("" ::: "memory");
}

// Convenience function to hash a complete buffer
pub fn sha256(data: []const u8) [SHA256_SIZE]u8 {
    var hasher = SHA256.init();
    hasher.update(data);
    return hasher.final();
}

// Test vectors for verification
test "SHA256 empty string" {
    const result = sha256("");
    const expected = [_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    try std.testing.expectEqual(expected, result);
}

test "SHA256 'abc'" {
    const result = sha256("abc");
    const expected = [_]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    try std.testing.expectEqual(expected, result);
}
