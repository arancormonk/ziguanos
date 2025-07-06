// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const cpuid = @import("cpuid.zig");
const serial = @import("../drivers/serial.zig");
const stack_security = @import("stack_security.zig");

// Hardware RNG result structure
pub const RNGResult = struct {
    value: u64,
    success: bool,
};

// Maximum retry count for RDRAND/RDSEED
const MAX_RETRIES: u32 = 10;

// Fixed iteration count for constant-time operations
const CONSTANT_TIME_ITERATIONS: u32 = 100;

// Cache line size for Intel x86-64 (64 bytes)
const CACHE_LINE_SIZE: usize = 64;

// Flush a cache line to prevent timing attacks
inline fn flushCacheLine(addr: *const u8) void {
    asm volatile (
        \\clflush (%[addr])
        :
        : [addr] "r" (addr),
        : "memory"
    );
}

// Execute data-independent memory accesses to normalize cache state
inline fn normalizeCache() void {
    // Create a dummy buffer aligned to cache line
    var dummy_buffer: [CACHE_LINE_SIZE]u8 align(CACHE_LINE_SIZE) = [_]u8{0} ** CACHE_LINE_SIZE;

    // Access all bytes to warm cache uniformly
    var sum: u8 = 0;
    for (dummy_buffer) |byte| {
        sum ^= byte;
    }

    // Prevent optimization
    asm volatile (""
        :
        : [sum] "r" (sum),
        : "memory"
    );

    // Flush the dummy buffer
    flushCacheLine(&dummy_buffer[0]);
}

// Read a random number using RDRAND instruction
// RDRAND provides cryptographically secure pseudo-random numbers
pub fn rdrand64() RNGResult {
    const features = cpuid.getFeatures();
    if (!features.rdrand) {
        return RNGResult{ .value = 0, .success = false };
    }

    var result: u64 = undefined;
    var success: u8 = undefined;
    var retries: u32 = 0;

    while (retries < MAX_RETRIES) : (retries += 1) {
        asm volatile (
            \\rdrand %[result]
            \\setc %[success]
            : [result] "=r" (result),
              [success] "=r" (success),
        );

        if (success != 0) {
            return RNGResult{ .value = result, .success = true };
        }
    }

    return RNGResult{ .value = 0, .success = false };
}

// Read a random number using RDRAND instruction (32-bit)
pub fn rdrand32() RNGResult {
    const features = cpuid.getFeatures();
    if (!features.rdrand) {
        return RNGResult{ .value = 0, .success = false };
    }

    var result: u32 = undefined;
    var success: u8 = undefined;
    var retries: u32 = 0;

    while (retries < MAX_RETRIES) : (retries += 1) {
        asm volatile (
            \\rdrand %[result]
            \\setc %[success]
            : [result] "=r" (result),
              [success] "=r" (success),
        );

        if (success != 0) {
            return RNGResult{ .value = result, .success = true };
        }
    }

    return RNGResult{ .value = 0, .success = false };
}

// Read a true random seed using RDSEED instruction
// RDSEED provides true random numbers from hardware entropy source
pub fn rdseed64() RNGResult {
    const features = cpuid.getFeatures();
    if (!features.rdseed) {
        return RNGResult{ .value = 0, .success = false };
    }

    var result: u64 = undefined;
    var success: u8 = undefined;
    var retries: u32 = 0;

    while (retries < MAX_RETRIES) : (retries += 1) {
        asm volatile (
            \\rdseed %[result]
            \\setc %[success]
            : [result] "=r" (result),
              [success] "=r" (success),
        );

        if (success != 0) {
            return RNGResult{ .value = result, .success = true };
        }
    }

    return RNGResult{ .value = 0, .success = false };
}

// Read a true random seed using RDSEED instruction (32-bit)
pub fn rdseed32() RNGResult {
    const features = cpuid.getFeatures();
    if (!features.rdseed) {
        return RNGResult{ .value = 0, .success = false };
    }

    var result: u32 = undefined;
    var success: u8 = undefined;
    var retries: u32 = 0;

    while (retries < MAX_RETRIES) : (retries += 1) {
        asm volatile (
            \\rdseed %[result]
            \\setc %[success]
            : [result] "=r" (result),
              [success] "=r" (success),
        );

        if (success != 0) {
            return RNGResult{ .value = result, .success = true };
        }
    }

    return RNGResult{ .value = 0, .success = false };
}

// Get the best available random number
// Tries RDSEED first (true random), falls back to RDRAND (CSPRNG)
pub fn getRandom64() RNGResult {
    // Try true random first
    const seed_result = rdseed64();
    if (seed_result.success) {
        return seed_result;
    }

    // Fall back to CSPRNG
    return rdrand64();
}

// Get the best available random number (32-bit)
pub fn getRandom32() RNGResult {
    // Try true random first
    const seed_result = rdseed32();
    if (seed_result.success) {
        return seed_result;
    }

    // Fall back to CSPRNG
    return rdrand32();
}

// Read a random number using RDRAND with constant-time execution
// Always executes fixed number of iterations regardless of success
pub fn rdrand64ConstantTime() RNGResult {
    const features = cpuid.getFeatures();
    if (!features.rdrand) {
        return RNGResult{ .value = 0, .success = false };
    }

    var result: u64 = 0;
    var any_success: u8 = 0;

    // Normalize cache state to prevent timing attacks
    normalizeCache();

    // Memory barrier to prevent prefetch attacks
    asm volatile ("mfence" ::: "memory");

    // Always execute exactly CONSTANT_TIME_ITERATIONS attempts
    var i: u32 = 0;
    while (i < CONSTANT_TIME_ITERATIONS) : (i += 1) {
        var value: u64 = undefined;
        var success: u8 = undefined;

        // Memory barrier before RDRAND to ensure consistent timing
        asm volatile ("lfence" ::: "memory");

        asm volatile (
            \\rdrand %[value]
            \\setc %[success]
            : [value] "=r" (value),
              [success] "=r" (success),
        );

        // Memory barrier after RDRAND to prevent timing leaks
        asm volatile ("lfence" ::: "memory");

        // Constant-time accumulation using masking
        const mask = @as(u64, 0) -% @as(u64, success);
        result |= (value & mask);
        any_success |= success;

        // Always pause for timing consistency with memory clobber
        asm volatile ("pause" ::: "memory");

        // Normalize cache every 10 iterations
        if ((i + 1) % 10 == 0) {
            normalizeCache();
        }
    }

    // Final memory barrier to ensure completion
    asm volatile ("mfence" ::: "memory");

    // Final cache normalization
    normalizeCache();

    return RNGResult{ .value = result, .success = any_success != 0 };
}

// Read a true random seed using RDSEED with constant-time execution
pub fn rdseed64ConstantTime() RNGResult {
    const features = cpuid.getFeatures();
    if (!features.rdseed) {
        return RNGResult{ .value = 0, .success = false };
    }

    var result: u64 = 0;
    var any_success: u8 = 0;

    // Normalize cache state to prevent timing attacks
    normalizeCache();

    // Memory barrier to prevent prefetch attacks
    asm volatile ("mfence" ::: "memory");

    // Always execute exactly CONSTANT_TIME_ITERATIONS attempts
    var i: u32 = 0;
    while (i < CONSTANT_TIME_ITERATIONS) : (i += 1) {
        var value: u64 = undefined;
        var success: u8 = undefined;

        // Memory barrier before RDSEED to ensure consistent timing
        asm volatile ("lfence" ::: "memory");

        asm volatile (
            \\rdseed %[value]
            \\setc %[success]
            : [value] "=r" (value),
              [success] "=r" (success),
        );

        // Memory barrier after RDSEED to prevent timing leaks
        asm volatile ("lfence" ::: "memory");

        // Constant-time accumulation using masking
        const mask = @as(u64, 0) -% @as(u64, success);
        result |= (value & mask);
        any_success |= success;

        // Always pause for timing consistency with memory clobber
        asm volatile ("pause" ::: "memory");

        // Normalize cache every 10 iterations
        if ((i + 1) % 10 == 0) {
            normalizeCache();
        }
    }

    // Final memory barrier to ensure completion
    asm volatile ("mfence" ::: "memory");

    // Final cache normalization
    normalizeCache();

    return RNGResult{ .value = result, .success = any_success != 0 };
}

// Get the best available random number with constant-time execution
pub fn getRandom64ConstantTime() RNGResult {
    // Try true random first
    const seed_result = rdseed64ConstantTime();
    if (seed_result.success) {
        return seed_result;
    }

    // Fall back to CSPRNG
    return rdrand64ConstantTime();
}

// Fill a buffer with random bytes
pub fn fillRandomBytes(buffer: []u8) bool {
    var guard = stack_security.protect();
    defer guard.deinit();

    const features = cpuid.getFeatures();
    if (!features.rdrand and !features.rdseed) {
        return false;
    }

    var i: usize = 0;

    // Fill 8 bytes at a time
    while (i + 8 <= buffer.len) : (i += 8) {
        const result = getRandom64();
        if (!result.success) return false;

        const bytes = @as(*const [8]u8, @ptrCast(&result.value));
        @memcpy(buffer[i .. i + 8], bytes);
    }

    // Fill remaining bytes
    if (i < buffer.len) {
        const result = getRandom64();
        if (!result.success) return false;

        const bytes = @as(*const [8]u8, @ptrCast(&result.value));
        const remaining = buffer.len - i;
        @memcpy(buffer[i..buffer.len], bytes[0..remaining]);
    }

    return true;
}

// Fill a buffer with random bytes using constant-time operations
pub fn fillRandomBytesConstantTime(buffer: []u8) bool {
    var guard = stack_security.protect();
    defer guard.deinit();

    const features = cpuid.getFeatures();
    if (!features.rdrand and !features.rdseed) {
        return false;
    }

    var i: usize = 0;

    // Fill 8 bytes at a time
    while (i + 8 <= buffer.len) : (i += 8) {
        const result = getRandom64ConstantTime();
        if (!result.success) return false;

        const bytes = @as(*const [8]u8, @ptrCast(&result.value));
        @memcpy(buffer[i .. i + 8], bytes);
    }

    // Fill remaining bytes
    if (i < buffer.len) {
        const result = getRandom64ConstantTime();
        if (!result.success) return false;

        const bytes = @as(*const [8]u8, @ptrCast(&result.value));
        const remaining = buffer.len - i;
        @memcpy(buffer[i..buffer.len], bytes[0..remaining]);
    }

    return true;
}

// Test hardware RNG functionality
pub fn testRNG() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    const features = cpuid.getFeatures();

    serial.println("[RNG] Testing hardware random number generators:", .{});

    if (features.rdrand) {
        serial.print("  RDRAND: ", .{});
        const result = rdrand64();
        if (result.success) {
            serial.println("SUCCESS - Generated: 0x{x:0>16}", .{result.value});
        } else {
            serial.println("FAILED - No entropy available", .{});
        }
    } else {
        serial.println("  RDRAND: Not available", .{});
    }

    if (features.rdseed) {
        serial.print("  RDSEED: ", .{});
        const result = rdseed64();
        if (result.success) {
            serial.println("SUCCESS - Generated: 0x{x:0>16}", .{result.value});
        } else {
            serial.println("FAILED - No entropy available", .{});
        }
    } else {
        serial.println("  RDSEED: Not available", .{});
    }

    // Test buffer fill
    if (features.rdrand or features.rdseed) {
        var buffer: [32]u8 = undefined;
        if (fillRandomBytes(&buffer)) {
            serial.print("  Buffer fill (32 bytes): SUCCESS - ", .{});
            for (buffer) |byte| {
                serial.print("0x{x:0>2} ", .{byte});
            }
            serial.println("", .{});
        } else {
            serial.println("  Buffer fill: FAILED", .{});
        }

        // Test constant-time operations
        serial.println("[RNG] Testing constant-time operations:", .{});

        const ct_result = getRandom64ConstantTime();
        if (ct_result.success) {
            serial.println("  Constant-time RNG: SUCCESS - Generated: 0x{x:0>16}", .{ct_result.value});
        } else {
            serial.println("  Constant-time RNG: FAILED", .{});
        }

        // Test constant-time buffer fill
        var ct_buffer: [32]u8 = undefined;
        if (fillRandomBytesConstantTime(&ct_buffer)) {
            serial.println("  Constant-time buffer fill: SUCCESS", .{});
        } else {
            serial.println("  Constant-time buffer fill: FAILED", .{});
        }
    }
}
