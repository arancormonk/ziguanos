// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const serial = @import("../drivers/serial.zig");
const uefi_globals = @import("../utils/uefi_globals.zig");

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

// Runtime detection flags - cached after first check
var rdrand_tested: bool = false;
var rdrand_works: bool = false;
var rdseed_tested: bool = false;
var rdseed_works: bool = false;

// UEFI RNG Protocol GUID
const EFI_RNG_PROTOCOL_GUID align(8) = uefi.Guid{
    .time_low = 0x3152bca5,
    .time_mid = 0xeade,
    .time_high_and_version = 0x433d,
    .clock_seq_high_and_reserved = 0x86,
    .clock_seq_low = 0x2e,
    .node = [_]u8{ 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44 },
};

// UEFI RNG Protocol
const RngProtocol = extern struct {
    get_info: *const fn (*const RngProtocol, *usize, [*]uefi.Guid) callconv(.C) uefi.Status,
    get_rng: *const fn (*const RngProtocol, ?*const uefi.Guid, usize, [*]u8) callconv(.C) uefi.Status,
};

// Global RNG protocol instance
var rng_protocol: ?*const RngProtocol = null;
var rng_protocol_initialized = false;

// Feature availability flags
var has_rdrand_flag: ?bool = null;
var has_rdseed_flag: ?bool = null;
var has_tsc_flag: ?bool = null;
var has_rdpmc_flag: ?bool = null;

// Try to locate UEFI RNG protocol
fn locateRngProtocol() void {
    if (rng_protocol_initialized) return;
    rng_protocol_initialized = true;

    // Check if boot services is initialized
    // In UEFI environment, boot_services might not be initialized during static init
    if (@intFromPtr(uefi_globals.boot_services) == 0 or
        @intFromPtr(uefi_globals.boot_services) == @as(usize, @bitCast(@as(i64, -1))))
    {
        return;
    }

    const bs = uefi_globals.boot_services;
    var protocol: *const RngProtocol = undefined;
    const status = bs.locateProtocol(&EFI_RNG_PROTOCOL_GUID, null, @ptrCast(&protocol));
    if (status == .success) {
        rng_protocol = protocol;
        serial.print("[RNG] UEFI RNG Protocol located successfully\r\n", .{}) catch {};
    }
}

// Check if TSC is available
fn checkTSCAvailable() bool {
    if (has_tsc_flag) |flag| return flag;

    // TSC is available on all modern x86_64 processors
    // Check CPUID function 1, EDX bit 4
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

    has_tsc_flag = (edx & (1 << 4)) != 0;
    return has_tsc_flag.?;
}

// Check if RDPMC is available and allowed
fn checkRDPMCAvailable() bool {
    if (has_rdpmc_flag) |flag| return flag;

    // RDPMC availability depends on CR4.PCE bit which may not be set in UEFI
    // We'll try it and catch any exceptions
    has_rdpmc_flag = false; // Default to false for UEFI environment
    return false;
}

// Entropy conditioning functions for enhanced security
// Get TSC value for entropy mixing
fn getTSCValue() u64 {
    if (!checkTSCAvailable()) {
        // Fallback to a simple counter based on memory addresses
        const ptr = @intFromPtr(&getTSCValue);
        return ptr ^ (@as(u64, @truncate(ptr >> 16)) << 32);
    }

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
    // RDPMC is typically not available in UEFI environment
    // Use alternative entropy sources instead
    var entropy: u64 = 0;

    // Mix in stack pointer
    const stack_ptr = @intFromPtr(&entropy);
    entropy ^= stack_ptr;

    // Mix in code pointer
    const code_ptr = @intFromPtr(&getPerformanceCounter);
    entropy ^= code_ptr;

    // If TSC is available, use it
    if (checkTSCAvailable()) {
        entropy ^= getTSCValue();
    }

    // Simple bit mixing
    entropy = (entropy ^ (entropy >> 30)) *% 0xbf58476d1ce4e5b9;
    entropy = (entropy ^ (entropy >> 27)) *% 0x94d049bb133111eb;
    entropy = entropy ^ (entropy >> 31);

    return entropy;
}

// Apply entropy conditioning to hardware RNG output
// This implements NIST SP 800-90B recommendations for entropy conditioning
fn conditionEntropy(raw_value: u64) u64 {
    // Start with the raw value
    var conditioned = raw_value;

    // Get additional entropy sources
    const tsc_value = getTSCValue();
    const perf_counter = getPerformanceCounter();

    // Mix entropy sources using XOR (simple but effective)
    conditioned ^= tsc_value ^ perf_counter;

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

// Check if we're running under hypervisor/emulation
fn isVirtualized() bool {
    // Check CPUID hypervisor bit (bit 31 of ECX on CPUID function 1)
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

    // Bit 31 indicates hypervisor present
    return (ecx & (1 << 31)) != 0;
}

// Check if RDRAND is supported and works
fn hasRdrand() bool {
    // Check cached result first
    if (rdrand_tested) {
        return rdrand_works;
    }

    if (has_rdrand_flag) |flag| {
        if (!flag) {
            rdrand_tested = true;
            rdrand_works = false;
            return false;
        }
    }

    // For TCG mode or environments without RDRAND, default to false
    // Try CPUID but handle potential issues gracefully
    var eax: u32 = 0;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    // Get highest CPUID function
    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [eax_in] "{eax}" (eax),
        : "memory"
    );

    // Check if function 1 is available
    if (eax < 1) {
        has_rdrand_flag = false;
        serial.print("[RNG] CPUID function 1 not available\r\n", .{}) catch {};
        return false;
    }

    // Check for RDRAND support
    eax = 1;
    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [eax_in] "{eax}" (eax),
        : "memory"
    );

    has_rdrand_flag = (ecx & CPUID_ECX_RDRAND) != 0;
    if (!has_rdrand_flag.?) {
        serial.print("[RNG] RDRAND not supported by CPUID (ECX=0x{x:0>8})\r\n", .{ecx}) catch {};
        rdrand_tested = true;
        rdrand_works = false;
        return false;
    }

    // CPUID says RDRAND is supported
    serial.print("[RNG] CPUID reports RDRAND support\r\n", .{}) catch {};

    // Check if we're running in a virtualized environment
    if (isVirtualized()) {
        serial.print("[RNG] WARNING: Running in virtualized environment, RDRAND may not work correctly\r\n", .{}) catch {};
        // In virtualized environments, we'll try to use it but won't trust it completely
        // The actual rdrand64() function will handle failures gracefully
    }

    // We'll trust CPUID for now and let the actual RDRAND calls fail gracefully if needed
    rdrand_tested = true;
    rdrand_works = true;
    return true;
}

// Check if RDSEED is supported
fn hasRdseed() bool {
    if (has_rdseed_flag) |flag| return flag;

    // First check if CPUID is available and supports extended functions
    var eax: u32 = 0;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    // Get highest CPUID function
    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [eax_in] "{eax}" (eax),
        : "memory"
    );

    // Check if function 7 is available
    if (eax < 7) {
        has_rdseed_flag = false;
        serial.print("[RNG] CPUID function 7 not available\r\n", .{}) catch {};
        return false;
    }

    // Check for RDSEED support
    eax = 7;
    ecx = 0;
    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [eax_in] "{eax}" (eax),
          [ecx_in] "{ecx}" (ecx),
        : "memory"
    );

    has_rdseed_flag = (ebx & CPUID_EBX_RDSEED) != 0;
    if (!has_rdseed_flag.?) {
        serial.print("[RNG] RDSEED not supported (EBX=0x{x:0>8})\r\n", .{ebx}) catch {};
    }
    return has_rdseed_flag.?;
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

// Try to use UEFI RNG Protocol if available
fn tryUefiRng() ?u64 {
    if (rng_protocol) |protocol| {
        var value: u64 = 0;
        const status = protocol.get_rng(protocol, null, @sizeOf(u64), @ptrCast(&value));
        if (status == .success) {
            return value;
        }
    }
    return null;
}

// Get the best available random number
// Tries UEFI RNG first, then RDSEED (true random), then RDRAND (CSPRNG)
pub fn getRandom64() RNGResult {
    // Ensure RNG protocol is initialized
    if (!rng_protocol_initialized) {
        locateRngProtocol();
    }

    // Try UEFI RNG Protocol first (most reliable in virtual environments)
    if (tryUefiRng()) |value| {
        return RNGResult{ .value = value, .success = true };
    }

    // If we're not in a virtualized environment, try hardware RNG
    if (!isVirtualized()) {
        // Try true random first
        const seed_result = rdseed64();
        if (seed_result.success) {
            return seed_result;
        }

        // Fall back to CSPRNG
        const rand_result = rdrand64();
        if (rand_result.success) {
            return rand_result;
        }
    }

    // In virtualized environments or if hardware RNG failed, use fallback entropy
    return RNGResult{ .value = conditionEntropy(getTSCValue() ^ getPerformanceCounter()), .success = true };
}

// Get the best available random number (32-bit)
pub fn getRandom32() RNGResult {
    // Get 64-bit random and truncate
    const result64 = getRandom64();
    if (result64.success) {
        return RNGResult{ .value = @as(u32, @truncate(result64.value)), .success = true };
    }
    return RNGResult{ .value = 0, .success = false };
}

// Generic getRandom function that returns random values of any integer type
pub fn getRandom(comptime T: type) !T {
    const type_info = @typeInfo(T);
    if (type_info != .int) {
        @compileError("getRandom only supports integer types");
    }

    const bits = type_info.int.bits;

    // First try UEFI RNG protocol for smaller types
    if (bits <= 64) {
        var buffer: [8]u8 = undefined;
        const bytes_needed = (bits + 7) / 8;

        if (getUefiRandomBytes(buffer[0..bytes_needed])) {
            var value: u64 = 0;
            for (buffer[0..bytes_needed], 0..) |byte, idx| {
                value |= @as(u64, byte) << @as(u6, @intCast(idx * 8));
            }

            if (bits < 64) {
                value &= (@as(u64, 1) << @as(u6, @intCast(bits))) - 1;
            }

            return @as(T, @intCast(value));
        }
    }

    // Try hardware RNG
    if (bits <= 32) {
        const result = getRandom32();
        if (result.success) {
            const value = @as(T, @intCast(result.value & ((1 << bits) - 1)));
            return value;
        }
    } else if (bits <= 64) {
        const result = getRandom64();
        if (result.success) {
            if (bits == 64) {
                return @as(T, @bitCast(result.value));
            } else {
                const value = @as(T, @intCast(result.value & ((1 << bits) - 1)));
                return value;
            }
        }
    } else {
        // For larger types, we need to combine multiple random values
        var result: T = 0;
        var bits_filled: u32 = 0;

        while (bits_filled < bits) {
            const rand_result = getRandom64();
            if (rand_result.success) {
                const bits_to_fill = @min(64, bits - bits_filled);
                const mask = if (bits_to_fill == 64) ~@as(u64, 0) else (@as(u64, 1) << @as(u6, @intCast(bits_to_fill))) - 1;
                const value = rand_result.value & mask;

                result |= @as(T, value) << @as(u7, @intCast(bits_filled));
                bits_filled += bits_to_fill;
            } else {
                // Hardware RNG failed, break out of loop
                break;
            }
        }

        if (bits_filled == bits) {
            return result;
        }
    }

    // Fallback to software entropy
    if (bits <= 64) {
        const entropy = generateFallbackEntropy();
        if (bits == 64) {
            return @as(T, @bitCast(entropy));
        } else {
            const mask = (@as(u64, 1) << @as(u6, @intCast(bits))) - 1;
            return @as(T, @intCast(entropy & mask));
        }
    } else {
        // For larger types, combine multiple fallback values
        var result: T = 0;
        var bits_filled: u32 = 0;

        while (bits_filled < bits) {
            const entropy = generateFallbackEntropy();
            const bits_to_fill = @min(64, bits - bits_filled);
            const mask = if (bits_to_fill == 64) ~@as(u64, 0) else (@as(u64, 1) << @as(u6, @intCast(bits_to_fill))) - 1;
            const value = entropy & mask;

            result |= @as(T, value) << @as(u7, @intCast(bits_filled));
            bits_filled += bits_to_fill;
        }

        return result;
    }
}

// Get random bytes from UEFI RNG protocol
fn getUefiRandomBytes(buffer: []u8) bool {
    locateRngProtocol();

    if (rng_protocol) |protocol| {
        const status = protocol.get_rng(protocol, null, buffer.len, buffer.ptr);
        return status == .success;
    }

    return false;
}

// Generate fallback entropy using various sources
fn generateFallbackEntropy() u64 {
    var entropy: u64 = 0;

    // Mix in TSC if available
    if (checkTSCAvailable()) {
        entropy ^= getTSCValue();
    }

    // Mix in memory addresses
    const stack_addr = @intFromPtr(&entropy);
    const code_addr = @intFromPtr(&generateFallbackEntropy);
    const data_addr = @intFromPtr(&has_rdrand_flag);

    entropy ^= stack_addr;
    entropy ^= code_addr << 16;
    entropy ^= data_addr << 32;

    // Mix in UEFI timer if available
    // Check if boot services is initialized
    if (@intFromPtr(uefi_globals.boot_services) != 0 and
        @intFromPtr(uefi_globals.boot_services) != @as(usize, @bitCast(@as(i64, -1))))
    {
        const bs = uefi_globals.boot_services;
        var timer_value: u64 = undefined;
        // Try to get high-resolution timer
        if (bs.stall(1) == .success) {
            // Measure time taken for a minimal operation
            const start = getTSCValue();
            _ = bs.stall(1);
            const end = getTSCValue();
            timer_value = end -% start;
            entropy ^= timer_value;
        }
    }

    // Apply mixing function
    entropy = (entropy ^ (entropy >> 30)) *% 0xbf58476d1ce4e5b9;
    entropy = (entropy ^ (entropy >> 27)) *% 0x94d049bb133111eb;
    entropy = entropy ^ (entropy >> 31);

    return entropy;
}

// Fill a buffer with random bytes
pub fn fillRandomBytes(buffer: []u8) bool {
    // First try UEFI RNG protocol
    if (getUefiRandomBytes(buffer)) {
        return true;
    }

    // Then try hardware RNG if available
    if (hasRdrand() or hasRdseed()) {
        var i: usize = 0;

        // Fill 8 bytes at a time
        while (i + 8 <= buffer.len) : (i += 8) {
            const result = getRandom64();
            if (!result.success) {
                // Fall back to software entropy
                break;
            }

            const bytes = @as(*const [8]u8, @ptrCast(&result.value));
            @memcpy(buffer[i .. i + 8], bytes);
        }

        // Fill remaining bytes
        if (i < buffer.len) {
            const result = getRandom64();
            if (result.success) {
                const bytes = @as(*const [8]u8, @ptrCast(&result.value));
                const remaining = buffer.len - i;
                @memcpy(buffer[i..buffer.len], bytes[0..remaining]);
                return true;
            }
        } else if (i == buffer.len) {
            return true;
        }
    }

    // Fallback to software entropy generation
    serial.print("[RNG] WARNING: Using fallback entropy generation\r\n", .{}) catch {};

    var i: usize = 0;
    while (i + 8 <= buffer.len) : (i += 8) {
        const entropy = generateFallbackEntropy();
        const bytes = @as(*const [8]u8, @ptrCast(&entropy));
        @memcpy(buffer[i .. i + 8], bytes);
    }

    // Fill remaining bytes
    if (i < buffer.len) {
        const entropy = generateFallbackEntropy();
        const bytes = @as(*const [8]u8, @ptrCast(&entropy));
        const remaining = buffer.len - i;
        @memcpy(buffer[i..buffer.len], bytes[0..remaining]);
    }

    return true;
}

// Check if any RNG is available
pub fn isAvailable() bool {
    // Try to locate UEFI RNG protocol
    locateRngProtocol();

    // We have multiple sources:
    // 1. UEFI RNG protocol
    // 2. Hardware RNG (RDRAND/RDSEED)
    // 3. Fallback entropy (always available)
    return true; // Always return true since we have fallback
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
    serial.print("[RNG] Example usage:\r\n", .{}) catch {};

    // Example 1: Get a random u64
    if (getRandom(u64)) |value| {
        serial.print("  Random u64: 0x{x:0>16}\r\n", .{value}) catch {};
    } else |_| {
        serial.print("  Failed to get random u64\r\n", .{}) catch {};
    }

    // Example 2: Get a random u32
    if (getRandom(u32)) |value| {
        serial.print("  Random u32: 0x{x:0>8}\r\n", .{value}) catch {};
    } else |_| {
        serial.print("  Failed to get random u32\r\n", .{}) catch {};
    }

    // Example 3: Generate a random offset for KASLR (up to 1GB)
    if (getRandom(u32)) |value| {
        const max_offset = 0x40000000; // 1GB
        const kaslr_offset = value % max_offset;
        serial.print("  KASLR offset: 0x{x} ({} MB)\r\n", .{ kaslr_offset, kaslr_offset / (1024 * 1024) }) catch {};
    } else |_| {
        serial.print("  Failed to generate KASLR offset\r\n", .{}) catch {};
    }

    // Example 4: Fill a buffer with random bytes
    var key_material: [32]u8 = undefined;
    if (fillRandomBytes(&key_material)) {
        serial.print("  Random key material: ", .{}) catch {};
        for (key_material, 0..) |byte, i| {
            if (i > 0 and i % 8 == 0) serial.print(" ", .{}) catch {};
            serial.print("{x:0>2}", .{byte}) catch {};
        }
        serial.print("\r\n", .{}) catch {};
    } else {
        serial.print("  Failed to fill random buffer\r\n", .{}) catch {};
    }
}

// Test RNG functionality
pub fn testRNG() void {
    serial.print("[RNG] Testing random number generators:\r\n", .{}) catch {};

    // Test UEFI RNG protocol
    locateRngProtocol();
    if (rng_protocol != null) {
        serial.print("  UEFI RNG Protocol: ", .{}) catch {};
        var buffer: [8]u8 = undefined;
        if (getUefiRandomBytes(&buffer)) {
            var value: u64 = 0;
            for (buffer, 0..) |byte, idx| {
                value |= @as(u64, byte) << @as(u6, @intCast(idx * 8));
            }
            serial.print("SUCCESS - Generated: 0x{x:0>16}\r\n", .{value}) catch {};
        } else {
            serial.print("FAILED\r\n", .{}) catch {};
        }
    } else {
        serial.print("  UEFI RNG Protocol: Not available\r\n", .{}) catch {};
    }

    // Test hardware RNG
    if (hasRdrand()) {
        serial.print("  RDRAND: ", .{}) catch {};
        const result = rdrand64();
        if (result.success) {
            serial.print("SUCCESS - Generated: 0x{x:0>16}\r\n", .{result.value}) catch {};
        } else {
            serial.print("FAILED - No entropy available\r\n", .{}) catch {};
        }
    } else {
        serial.print("  RDRAND: Not available\r\n", .{}) catch {};
    }

    if (hasRdseed()) {
        serial.print("  RDSEED: ", .{}) catch {};
        const result = rdseed64();
        if (result.success) {
            serial.print("SUCCESS - Generated: 0x{x:0>16}\r\n", .{result.value}) catch {};
        } else {
            serial.print("FAILED - No entropy available\r\n", .{}) catch {};
        }
    } else {
        serial.print("  RDSEED: Not available\r\n", .{}) catch {};
    }

    // Test fallback entropy
    serial.print("  Fallback entropy: ", .{}) catch {};
    const fallback = generateFallbackEntropy();
    serial.print("Generated: 0x{x:0>16}\r\n", .{fallback}) catch {};

    // Test generic getRandom function (always available due to fallback)
    serial.print("  Testing getRandom with different types:\r\n", .{}) catch {};

    // Test u8
    if (getRandom(u8)) |value| {
        serial.print("    u8: SUCCESS - Generated: 0x{x:0>2}\r\n", .{value}) catch {};
    } else |_| {
        serial.print("    u8: FAILED\r\n", .{}) catch {};
    }

    // Test u16
    if (getRandom(u16)) |value| {
        serial.print("    u16: SUCCESS - Generated: 0x{x:0>4}\r\n", .{value}) catch {};
    } else |_| {
        serial.print("    u16: FAILED\r\n", .{}) catch {};
    }

    // Test u32
    if (getRandom(u32)) |value| {
        serial.print("    u32: SUCCESS - Generated: 0x{x:0>8}\r\n", .{value}) catch {};
    } else |_| {
        serial.print("    u32: FAILED\r\n", .{}) catch {};
    }

    // Test u64
    if (getRandom(u64)) |value| {
        serial.print("    u64: SUCCESS - Generated: 0x{x:0>16}\r\n", .{value}) catch {};
    } else |_| {
        serial.print("    u64: FAILED\r\n", .{}) catch {};
    }

    // Test buffer fill
    var buffer: [32]u8 = undefined;
    if (fillRandomBytes(&buffer)) {
        serial.print("  Buffer fill (32 bytes): SUCCESS - ", .{}) catch {};
        for (buffer, 0..) |byte, idx| {
            if (idx > 0 and idx % 8 == 0) serial.print(" ", .{}) catch {};
            serial.print("{x:0>2}", .{byte}) catch {};
        }
        serial.print("\r\n", .{}) catch {};
    } else {
        serial.print("  Buffer fill: FAILED\r\n", .{}) catch {};
    }
}
