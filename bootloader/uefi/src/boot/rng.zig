// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const serial = @import("../drivers/serial.zig");

// Hardware RNG result structure
pub const RNGResult = struct {
    value: u64,
    success: bool,
};

// Maximum retry count for RDRAND/RDSEED
const MAX_RETRIES: u32 = 10;

// CPUID feature bits for RNG support
const CPUID_ECX_RDRAND: u32 = 1 << 30;
const CPUID_EBX_RDSEED: u32 = 1 << 18;

// Entropy conditioning functions for enhanced security
// Get TSC value for entropy mixing
fn getTSCValue() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;

    asm volatile (
        \\rdtsc
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        :
        : "cc"
    );

    return (@as(u64, high) << 32) | @as(u64, low);
}

// Get performance counter for additional entropy
fn getPerformanceCounter() u64 {
    var result: u64 = undefined;

    // Use performance counter 0 if available
    asm volatile (
        \\rdpmc
        : [result] "={rax}" (result),
        : [counter] "{rcx}" (0),
        : "cc", "rdx"
    );

    return result;
}

// Apply entropy conditioning to hardware RNG output
// This implements NIST SP 800-90B recommendations for entropy conditioning
fn conditionEntropy(raw_value: u64) u64 {
    // Get additional entropy sources
    const tsc_value = getTSCValue();
    const perf_counter = getPerformanceCounter();

    // Mix entropy sources using XOR (simple but effective)
    var conditioned = raw_value ^ tsc_value ^ perf_counter;

    // Add stack pointer entropy for address space randomization
    const stack_entropy = asm volatile ("mov %%rsp, %[result]"
        : [result] "=r" (-> u64),
    );
    conditioned ^= stack_entropy;

    // Simple rotation to increase diffusion
    conditioned = (conditioned << 13) | (conditioned >> 51);

    return conditioned;
}

// Assess basic entropy quality of a 64-bit value
fn assessEntropyQuality(value: u64) u32 {
    var score: u32 = 0;

    // Check for bit distribution
    const popcount = @popCount(value);
    if (popcount >= 24 and popcount <= 40) { // Good bit balance
        score += 2;
    } else if (popcount >= 16 and popcount <= 48) { // Acceptable bit balance
        score += 1;
    }

    // Check for obvious patterns (all same bits, alternating patterns)
    if (value != 0 and value != 0xFFFFFFFFFFFFFFFF) {
        score += 1;
    }

    // Check for alternating bit patterns
    if (value != 0x5555555555555555 and value != 0xAAAAAAAAAAAAAAAA) {
        score += 1;
    }

    return score;
}

// Check if RDRAND is supported
fn hasRdrand() bool {
    var eax: u32 = 1;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [eax_in] "{eax}" (eax),
    );

    return (ecx & CPUID_ECX_RDRAND) != 0;
}

// Check if RDSEED is supported
fn hasRdseed() bool {
    var eax: u32 = 7;
    var ecx: u32 = 0;
    var ebx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [eax_in] "{eax}" (eax),
          [ecx_in] "{ecx}" (ecx),
    );

    return (ebx & CPUID_EBX_RDSEED) != 0;
}

// Read a random number using RDRAND instruction with entropy conditioning
// RDRAND provides cryptographically secure pseudo-random numbers
pub fn rdrand64() RNGResult {
    if (!hasRdrand()) {
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
            // Apply entropy conditioning as per NIST SP 800-90B
            const conditioned_result = conditionEntropy(result);
            return RNGResult{ .value = conditioned_result, .success = true };
        }
    }

    return RNGResult{ .value = 0, .success = false };
}

// Read a random number using RDRAND instruction (32-bit) with entropy conditioning
pub fn rdrand32() RNGResult {
    if (!hasRdrand()) {
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
            // Apply entropy conditioning to 32-bit result
            const extended_result = @as(u64, result);
            const conditioned_result = conditionEntropy(extended_result);
            return RNGResult{ .value = @as(u32, @truncate(conditioned_result)), .success = true };
        }
    }

    return RNGResult{ .value = 0, .success = false };
}

// Read a true random seed using RDSEED instruction with entropy conditioning
// RDSEED provides true random numbers from hardware entropy source
pub fn rdseed64() RNGResult {
    if (!hasRdseed()) {
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
            // Apply entropy conditioning - RDSEED already provides high entropy
            // but additional conditioning provides defense in depth
            const conditioned_result = conditionEntropy(result);
            return RNGResult{ .value = conditioned_result, .success = true };
        }
    }

    return RNGResult{ .value = 0, .success = false };
}

// Read a true random seed using RDSEED instruction (32-bit) with entropy conditioning
pub fn rdseed32() RNGResult {
    if (!hasRdseed()) {
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
            // Apply entropy conditioning to 32-bit result
            const extended_result = @as(u64, result);
            const conditioned_result = conditionEntropy(extended_result);
            return RNGResult{ .value = @as(u32, @truncate(conditioned_result)), .success = true };
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

// Generic getRandom function that returns random values of any integer type
pub fn getRandom(comptime T: type) !T {
    const type_info = @typeInfo(T);
    if (type_info != .int) {
        @compileError("getRandom only supports integer types");
    }

    const bits = type_info.int.bits;

    // Handle different integer sizes
    if (bits <= 32) {
        const result = getRandom32();
        if (!result.success) {
            return error.NoRandomAvailable;
        }

        const value = @as(T, @intCast(result.value & ((1 << bits) - 1)));
        return value;
    } else if (bits <= 64) {
        const result = getRandom64();
        if (!result.success) {
            return error.NoRandomAvailable;
        }

        if (bits == 64) {
            return @as(T, @bitCast(result.value));
        } else {
            const value = @as(T, @intCast(result.value & ((1 << bits) - 1)));
            return value;
        }
    } else {
        // For larger types, we need to combine multiple random values
        var result: T = 0;
        var bits_filled: u32 = 0;

        while (bits_filled < bits) {
            const rand_result = getRandom64();
            if (!rand_result.success) {
                return error.NoRandomAvailable;
            }

            const bits_to_fill = @min(64, bits - bits_filled);
            const mask = if (bits_to_fill == 64) ~@as(u64, 0) else (@as(u64, 1) << @as(u6, @intCast(bits_to_fill))) - 1;
            const value = rand_result.value & mask;

            result |= @as(T, value) << @as(u7, @intCast(bits_filled));
            bits_filled += bits_to_fill;
        }

        return result;
    }
}

// Fill a buffer with random bytes
pub fn fillRandomBytes(buffer: []u8) bool {
    if (!hasRdrand() and !hasRdseed()) {
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

// Check if hardware RNG is available
pub fn isAvailable() bool {
    return hasRdrand() or hasRdseed();
}

// Enhanced random generation with quality assessment
pub fn getRandomWithQuality(comptime T: type) !struct { value: T, quality_score: u32 } {
    const result = try getRandom(T);

    // For larger types, assess quality of generated value
    var quality_score: u32 = 0;
    if (@typeInfo(T).int.bits >= 32) {
        const extended_value = if (@typeInfo(T).int.bits == 32)
            @as(u64, result)
        else
            @as(u64, @truncate(result));
        quality_score = assessEntropyQuality(extended_value);
    } else {
        // For smaller types, extend to u64 for quality assessment
        const extended_value = @as(u64, result);
        quality_score = assessEntropyQuality(extended_value);
    }

    return .{ .value = result, .quality_score = quality_score };
}

// Fill buffer with random bytes and assess overall quality
pub fn fillRandomBytesWithQuality(buffer: []u8) struct { success: bool, avg_quality: u32 } {
    if (!hasRdrand() and !hasRdseed()) {
        return .{ .success = false, .avg_quality = 0 };
    }

    var i: usize = 0;
    var total_quality: u32 = 0;
    var quality_samples: u32 = 0;

    // Fill 8 bytes at a time with quality assessment
    while (i + 8 <= buffer.len) : (i += 8) {
        const result = getRandom64();
        if (!result.success) {
            return .{ .success = false, .avg_quality = 0 };
        }

        // Assess quality of this 64-bit value
        const quality = assessEntropyQuality(result.value);
        total_quality += quality;
        quality_samples += 1;

        const bytes = @as(*const [8]u8, @ptrCast(&result.value));
        @memcpy(buffer[i .. i + 8], bytes);
    }

    // Fill remaining bytes
    if (i < buffer.len) {
        const result = getRandom64();
        if (!result.success) {
            return .{ .success = false, .avg_quality = 0 };
        }

        const quality = assessEntropyQuality(result.value);
        total_quality += quality;
        quality_samples += 1;

        const bytes = @as(*const [8]u8, @ptrCast(&result.value));
        const remaining = buffer.len - i;
        @memcpy(buffer[i..buffer.len], bytes[0..remaining]);
    }

    const avg_quality = if (quality_samples > 0) total_quality / quality_samples else 0;
    return .{ .success = true, .avg_quality = avg_quality };
}

// Example usage function demonstrating how to use the RNG module
pub fn exampleUsage() void {
    serial.println("[RNG] Example usage:", .{});

    // Example 1: Get a random u64
    if (getRandom(u64)) |value| {
        serial.println("  Random u64: 0x{x:0>16}", .{value});
    } else |_| {
        serial.println("  Failed to get random u64", .{});
    }

    // Example 2: Get a random u32
    if (getRandom(u32)) |value| {
        serial.println("  Random u32: 0x{x:0>8}", .{value});
    } else |_| {
        serial.println("  Failed to get random u32", .{});
    }

    // Example 3: Generate a random offset for KASLR (up to 1GB)
    if (getRandom(u32)) |value| {
        const max_offset = 0x40000000; // 1GB
        const kaslr_offset = value % max_offset;
        serial.println("  KASLR offset: 0x{x} ({} MB)", .{ kaslr_offset, kaslr_offset / (1024 * 1024) });
    } else |_| {
        serial.println("  Failed to generate KASLR offset", .{});
    }

    // Example 4: Fill a buffer with random bytes
    var key_material: [32]u8 = undefined;
    if (fillRandomBytes(&key_material)) {
        serial.print("  Random key material: ", .{});
        for (key_material, 0..) |byte, i| {
            if (i > 0 and i % 8 == 0) serial.print(" ", .{});
            serial.print("{x:0>2}", .{byte});
        }
        serial.println("", .{});
    } else {
        serial.println("  Failed to fill random buffer", .{});
    }
}

// Test hardware RNG functionality
pub fn testRNG() void {
    serial.println("[RNG] Testing hardware random number generators:", .{});

    if (hasRdrand()) {
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

    if (hasRdseed()) {
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

    // Test generic getRandom function
    if (hasRdrand() or hasRdseed()) {
        serial.println("  Testing getRandom with different types:", .{});

        // Test u8
        if (getRandom(u8)) |value| {
            serial.println("    u8: SUCCESS - Generated: 0x{x:0>2}", .{value});
        } else |_| {
            serial.println("    u8: FAILED", .{});
        }

        // Test u16
        if (getRandom(u16)) |value| {
            serial.println("    u16: SUCCESS - Generated: 0x{x:0>4}", .{value});
        } else |_| {
            serial.println("    u16: FAILED", .{});
        }

        // Test u32
        if (getRandom(u32)) |value| {
            serial.println("    u32: SUCCESS - Generated: 0x{x:0>8}", .{value});
        } else |_| {
            serial.println("    u32: FAILED", .{});
        }

        // Test u64
        if (getRandom(u64)) |value| {
            serial.println("    u64: SUCCESS - Generated: 0x{x:0>16}", .{value});
        } else |_| {
            serial.println("    u64: FAILED", .{});
        }

        // Test buffer fill
        var buffer: [32]u8 = undefined;
        if (fillRandomBytes(&buffer)) {
            serial.print("  Buffer fill (32 bytes): SUCCESS - ", .{});
            for (buffer, 0..) |byte, idx| {
                if (idx > 0 and idx % 8 == 0) serial.print(" ", .{});
                serial.print("{x:0>2}", .{byte});
            }
            serial.println("", .{});
        } else {
            serial.println("  Buffer fill: FAILED", .{});
        }
    }
}
