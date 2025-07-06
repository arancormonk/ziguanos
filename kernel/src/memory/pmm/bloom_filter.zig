// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Bloom Filter for comprehensive double-free detection
// Uses multiple hash functions to provide probabilistic detection of all freed pages

const std = @import("std");

pub const BLOOM_FILTER_SIZE: usize = 65536; // 64KB bloom filter (512Kbit) for comprehensive double-free detection
pub const BLOOM_FILTER_HASH_COUNT: u32 = 3; // Number of hash functions for optimal false positive rate

// Bloom filter for comprehensive double-free detection
// With 512Kbit filter and 3 hash functions, false positive rate < 0.1% at 100K freed pages
pub const BloomFilter = struct {
    bits: [BLOOM_FILTER_SIZE]u64 align(8) = [_]u64{0} ** BLOOM_FILTER_SIZE,

    // MurmurHash3 mixer for generating multiple hash functions from a single input
    fn hash(self: *const BloomFilter, page: u64, seed: u32) u32 {
        _ = self;
        var h = page ^ seed;
        h ^= h >> 33;
        h *%= 0xff51afd7ed558ccd;
        h ^= h >> 33;
        h *%= 0xc4ceb9fe1a85ec53;
        h ^= h >> 33;
        return @truncate(h);
    }

    // Check if a page might have been freed (false positives possible)
    pub fn contains(self: *const BloomFilter, page: u64) bool {
        var i: u32 = 0;
        while (i < BLOOM_FILTER_HASH_COUNT) : (i += 1) {
            const hash_val = self.hash(page, i);
            const bit_index = hash_val % (BLOOM_FILTER_SIZE * 64);
            const array_index = bit_index / 64;
            const bit_offset = @as(u6, @truncate(bit_index % 64));

            const mask = @as(u64, 1) << bit_offset;
            if ((self.bits[array_index] & mask) == 0) {
                return false; // Definitely not in set
            }
        }
        return true; // Possibly in set
    }

    // Add a page to the bloom filter
    pub fn add(self: *BloomFilter, page: u64) void {
        var i: u32 = 0;
        while (i < BLOOM_FILTER_HASH_COUNT) : (i += 1) {
            const hash_val = self.hash(page, i);
            const bit_index = hash_val % (BLOOM_FILTER_SIZE * 64);
            const array_index = bit_index / 64;
            const bit_offset = @as(u6, @truncate(bit_index % 64));

            const mask = @as(u64, 1) << bit_offset;
            self.bits[array_index] |= mask;
        }
    }

    // Clear the bloom filter
    pub fn clear(self: *BloomFilter) void {
        @memset(&self.bits, 0);
    }

    // Calculate the current false positive probability based on number of elements
    pub fn falsePositiveRate(self: *const BloomFilter, num_elements: u64) f64 {
        _ = self;
        const m = @as(f64, @floatFromInt(BLOOM_FILTER_SIZE * 64)); // Total bits
        const k = @as(f64, @floatFromInt(BLOOM_FILTER_HASH_COUNT)); // Hash functions
        const n = @as(f64, @floatFromInt(num_elements)); // Elements

        // Formula: (1 - e^(-kn/m))^k
        const exponent = -k * n / m;
        const base = 1.0 - @exp(exponent);
        return std.math.pow(f64, base, k);
    }

    // Get the number of bits set (for statistics)
    pub fn popcount(self: *const BloomFilter) u32 {
        var count: u32 = 0;
        for (self.bits) |word| {
            count += @popCount(word);
        }
        return count;
    }
};
