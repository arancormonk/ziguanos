// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Free page tracker for double-free detection

const serial = @import("../../drivers/serial.zig");
const bloom_filter = @import("bloom_filter.zig");

// Legacy free page tracker for recent frees (kept for debugging)
pub const FreePageTracker = struct {
    bloom: bloom_filter.BloomFilter = bloom_filter.BloomFilter{},
    recent_frees: [32]u64 = [_]u64{0} ** 32, // Keep last 32 for debugging
    index: usize = 0,
    total_frees: u64 = 0,

    pub fn init() FreePageTracker {
        return FreePageTracker{};
    }

    pub fn recordFree(self: *FreePageTracker, page: u64) !void {
        // Check bloom filter first
        if (self.bloom.contains(page)) {
            // Possible double-free, verify with recent list
            for (self.recent_frees) |freed_page| {
                if (freed_page == page and freed_page != 0) {
                    return error.DoubleFree;
                }
            }
            // If not in recent list but in bloom filter, it's likely a double-free
            // of an older allocation (or false positive)
            return error.DoubleFree;
        }

        // Add to bloom filter
        self.bloom.add(page);

        // Record in recent list for debugging
        self.recent_frees[self.index] = page;
        self.index = (self.index + 1) % self.recent_frees.len;
        self.total_frees += 1;
    }

    pub fn clear(self: *FreePageTracker) void {
        self.bloom.clear();
        @memset(&self.recent_frees, 0);
        self.index = 0;
        self.total_frees = 0;
    }

    pub fn getStats(self: *const FreePageTracker) void {
        const bits_set = self.bloom.popcount();
        const false_positive_rate = self.bloom.falsePositiveRate(self.total_frees);

        serial.print("[PMM] Bloom Filter Stats:\n", .{});
        serial.print("  Total frees tracked: {}\n", .{self.total_frees});
        serial.print("  Bits set: {}/{}\n", .{ bits_set, bloom_filter.BLOOM_FILTER_SIZE * 64 });
        serial.print("  Fill ratio: {d:.2}%\n", .{@as(f64, @floatFromInt(bits_set)) * 100.0 / @as(f64, @floatFromInt(bloom_filter.BLOOM_FILTER_SIZE * 64))});
        serial.print("  False positive rate: {d:.4}%\n", .{false_positive_rate * 100.0});
    }
};
