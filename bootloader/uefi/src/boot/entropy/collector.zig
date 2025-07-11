// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

/// Hardware RNG and system entropy collection utilities
const std = @import("std");
const uefi = std.os.uefi;
const serial = @import("../../drivers/serial.zig");
const kernel_types = @import("../kernel_types.zig");
const variable_cache = @import("../../security/variable_cache.zig");

// KASLR UEFI variable GUID
const kaslr_guid align(8) = uefi.Guid{
    .time_low = 0x12345678,
    .time_mid = 0x1234,
    .time_high_and_version = 0x1234,
    .clock_seq_high_and_reserved = 0x12,
    .clock_seq_low = 0x34,
    .node = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC },
};

// RNG retry configuration structure
pub const RngRetryConfig = struct {
    rdrand_max_retries: u32,
    rdseed_max_retries: u32,

    // Default Intel-recommended values
    const DEFAULT_RDRAND_RETRIES: u32 = 20;
    const DEFAULT_RDSEED_RETRIES: u32 = 1024;
};

// Global retry configuration (initialized with defaults)
var rng_retry_config: RngRetryConfig = .{
    .rdrand_max_retries = RngRetryConfig.DEFAULT_RDRAND_RETRIES,
    .rdseed_max_retries = RngRetryConfig.DEFAULT_RDSEED_RETRIES,
};

/// Load RNG retry configuration from UEFI variable cache
pub fn loadRngRetryConfig(runtime_services: *uefi.tables.RuntimeServices) void {
    // Initialize cache if not already done
    if (!variable_cache.isInitialized()) {
        variable_cache.init(runtime_services) catch {
            serial.print("[UEFI] Failed to initialize variable cache for RNG config\r\n", .{}) catch {};
            return;
        };
    }

    // Get KASLR configuration from cache
    const kaslr_config = variable_cache.getKASLRConfig();

    // Load RDRAND retry count from cache
    if (kaslr_config.rdrand_retries) |rdrand_retries| {
        // Validate reasonable retry count (10-1000)
        if (rdrand_retries >= 10 and rdrand_retries <= 1000) {
            rng_retry_config.rdrand_max_retries = rdrand_retries;
            serial.print("[UEFI] Loaded RDRAND retry count from cache: {}\r\n", .{rdrand_retries}) catch {};
        }
    }

    // Load RDSEED retry count from cache
    if (kaslr_config.rdseed_retries) |rdseed_retries| {
        // Validate reasonable retry count (100-10000)
        if (rdseed_retries >= 100 and rdseed_retries <= 10000) {
            rng_retry_config.rdseed_max_retries = rdseed_retries;
            serial.print("[UEFI] Loaded RDSEED retry count from cache: {}\r\n", .{rdseed_retries}) catch {};
        }
    }
}

/// Check if CPU supports RDRAND instruction
pub fn cpuHasRdrand() bool {
    // Check CPUID leaf 1, ECX bit 30 for RDRAND support
    var eax: u32 = 1;
    var ebx: u32 = undefined;
    var ecx: u32 = 0;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [eax] "+{eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "+{ecx}" (ecx),
          [edx] "={edx}" (edx),
    );

    return (ecx & (1 << 30)) != 0;
}

/// Check if CPU supports RDSEED instruction
pub fn cpuHasRdseed() bool {
    // Check CPUID leaf 7, EBX bit 18 for RDSEED support
    var eax: u32 = 7;
    var ebx: u32 = undefined;
    var ecx: u32 = 0;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [eax] "+{eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "+{ecx}" (ecx),
          [edx] "={edx}" (edx),
    );

    return (ebx & (1 << 18)) != 0;
}

/// Check if we're running under hypervisor
fn isVirtualized() bool {
    var eax: u32 = 1;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [eax] "+{eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "+{ecx}" (ecx),
          [edx] "={edx}" (edx),
    );

    return (ecx & (1 << 31)) != 0;
}

/// Try to get random value using RDRAND instruction (constant-time)
/// Follows Intel DRNG Software Implementation Guide recommendations
pub fn tryRdrand() ?u64 {
    if (!cpuHasRdrand()) return null;

    // In virtualized environments, prefer safer RNG module
    if (isVirtualized()) {
        const rng = @import("../rng.zig");
        const result = rng.getRandom64();
        return if (result.success) result.value else null;
    }

    var value: u64 = undefined;
    var success: u8 = undefined;
    var result: u64 = 0;
    var any_success: u8 = 0;

    // Use configurable retry count loaded from UEFI variables
    const max_retries: u32 = rng_retry_config.rdrand_max_retries;
    var pause_cycles: u32 = 1;

    var attempts: u32 = 0;
    while (attempts < max_retries) : (attempts += 1) {
        asm volatile ("rdrand %[value]; setc %[success]"
            : [value] "=r" (value),
              [success] "=r" (success),
        );

        // Constant-time accumulation
        const mask = @as(u64, 0) -% @as(u64, success);
        result |= (value & mask);
        any_success |= success;

        // Intel recommended: exponential backoff with PAUSE
        // Execute multiple PAUSE instructions based on attempt number
        var pause_count: u32 = 0;
        while (pause_count < pause_cycles) : (pause_count += 1) {
            asm volatile ("pause" ::: "memory");
        }

        // Exponential backoff: double pause cycles every 5 attempts
        if (attempts % 5 == 4 and pause_cycles < 16) {
            pause_cycles *= 2;
        }
    }

    return if (any_success != 0) result else null;
}

/// Try to get random value using RDSEED instruction (constant-time)
/// Follows Intel DRNG Software Implementation Guide recommendations
pub fn tryRdseed() ?u64 {
    if (!cpuHasRdseed()) return null;

    // In virtualized environments, prefer safer RNG module
    if (isVirtualized()) {
        const rng = @import("../rng.zig");
        const result = rng.getRandom64();
        return if (result.success) result.value else null;
    }

    var value: u64 = undefined;
    var success: u8 = undefined;
    var result: u64 = 0;
    var any_success: u8 = 0;

    // Use configurable retry count loaded from UEFI variables
    const max_retries: u32 = rng_retry_config.rdseed_max_retries;
    var pause_cycles: u32 = 8; // Start with more pauses for RDSEED

    var attempts: u32 = 0;
    while (attempts < max_retries) : (attempts += 1) {
        asm volatile ("rdseed %[value]; setc %[success]"
            : [value] "=r" (value),
              [success] "=r" (success),
        );

        // Constant-time accumulation
        const mask = @as(u64, 0) -% @as(u64, success);
        result |= (value & mask);
        any_success |= success;

        // Intel recommended: more aggressive backoff for RDSEED
        // Execute multiple PAUSE instructions based on attempt number
        var pause_count: u32 = 0;
        while (pause_count < pause_cycles) : (pause_count += 1) {
            asm volatile ("pause" ::: "memory");
        }

        // More aggressive exponential backoff for RDSEED
        // Double pause cycles every 64 attempts, up to 256
        if (attempts % 64 == 63 and pause_cycles < 256) {
            pause_cycles *= 2;
        }
    }

    return if (any_success != 0) result else null;
}

/// Read current TSC value
pub fn readTsc() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;

    asm volatile ("rdtsc"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
    );

    return (@as(u64, high) << 32) | low;
}

/// Rotate left helper function specifically for u64
fn rotl64(value: u64, shift: u6) u64 {
    return (value << shift) | (value >> @as(u6, @intCast(64 - @as(u7, shift))));
}

/// Get entropy from ACPI tables (Intel-recommended)
pub fn getAcpiEntropy() u64 {
    var entropy: u64 = 0;

    // Try to find ACPI tables from UEFI
    const config_table = @import("../../utils/uefi_globals.zig").system_table.configuration_table;
    const acpi_20_guid align(8) = uefi.tables.ConfigurationTable.acpi_20_table_guid;

    for (0..@import("../../utils/uefi_globals.zig").system_table.number_of_table_entries) |i| {
        const entry = &config_table[i];
        if (std.meta.eql(entry.vendor_guid, acpi_20_guid)) {
            // Mix ACPI table address for entropy
            entropy = @intFromPtr(entry.vendor_table);

            // SECURITY: Safe memory access following Intel x86-64 best practices
            // ACPI RSDP structure has a minimum guaranteed size
            // According to ACPI specification, RSDP v1.0 has minimum 20 bytes
            // and v2.0+ has minimum 36 bytes. We'll safely read the first 8 bytes
            // which contains the signature "RSD PTR " that all versions share
            const acpi_ptr = @as([*]const u8, @ptrCast(entry.vendor_table));

            // RSDP structure layout (guaranteed fields):
            // Offset 0-7: Signature "RSD PTR " (8 bytes)
            // Offset 8: Checksum (1 byte)
            // This is guaranteed to be present in any valid ACPI table
            const safe_bytes: usize = 8; // RSDP signature size only

            // Validate ACPI signature for additional safety
            const expected_sig = "RSD PTR ";
            var sig_valid = true;
            var sig_idx: usize = 0;
            while (sig_idx < expected_sig.len) : (sig_idx += 1) {
                if (acpi_ptr[sig_idx] != expected_sig[sig_idx]) {
                    sig_valid = false;
                    break;
                }
            }

            if (!sig_valid) {
                serial.print("[UEFI] Warning: Invalid ACPI RSDP signature\r\n", .{}) catch {};
                continue;
            }

            // Mix in the safely accessible bytes
            var byte_idx: usize = 0;
            while (byte_idx < safe_bytes) : (byte_idx += 1) {
                entropy = rotl64(entropy, 5) ^ acpi_ptr[byte_idx];
            }

            break;
        }
    }

    return entropy;
}

/// Get entropy from PIT timer (Intel-recommended)
pub fn getPitEntropy() u64 {
    var entropy: u64 = 0;

    // Read PIT channel 0 counter
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x00)), // Latch counter 0
          [port] "N{dx}" (@as(u16, 0x43)),
    );

    const low = asm volatile ("inb %[port]"
        : [ret] "={al}" (-> u8),
        : [port] "N{dx}" (@as(u16, 0x40)),
    );

    const high = asm volatile ("inb %[port]"
        : [ret] "={al}" (-> u8),
        : [port] "N{dx}" (@as(u16, 0x40)),
    );

    entropy = (@as(u64, high) << 8) | @as(u64, low);

    // Mix with TSC delta for more entropy
    const tsc1 = readTsc();
    asm volatile ("pause" ::: "memory");
    const tsc2 = readTsc();
    entropy ^= (tsc2 - tsc1) << 16;

    return entropy;
}

/// Get entropy from memory layout (Intel-recommended)
pub fn getMemoryLayoutEntropy(boot_services: *uefi.tables.BootServices) u64 {
    var entropy: u64 = 0;
    var memory_map_size: usize = 0;
    var map_key: usize = undefined;
    var descriptor_size: usize = undefined;
    var descriptor_version: u32 = undefined;

    // Get memory map size
    _ = boot_services.getMemoryMap(&memory_map_size, null, &map_key, &descriptor_size, &descriptor_version);

    // Mix memory map characteristics
    entropy = memory_map_size ^ (map_key << 16) ^ (descriptor_size << 32);

    // Mix with memory type distribution
    var buffer: [2048]u8 align(8) = undefined;
    if (memory_map_size <= buffer.len) {
        var actual_size = buffer.len;
        const memory_map = @as([*]uefi.tables.MemoryDescriptor, @ptrCast(@alignCast(&buffer)));

        if (boot_services.getMemoryMap(&actual_size, memory_map, &map_key, &descriptor_size, &descriptor_version) == .success) {
            const num_entries = actual_size / descriptor_size;
            var type_hash: u64 = 0;

            // Hash memory types and addresses
            var i: usize = 0;
            while (i < num_entries and i < 16) : (i += 1) {
                const desc = @as(*const uefi.tables.MemoryDescriptor, @ptrCast(@alignCast(@as([*]const u8, @ptrCast(memory_map)) + (i * descriptor_size))));
                type_hash = rotl64(type_hash, 7) ^ @intFromEnum(desc.type) ^ (desc.physical_start >> 20);
            }

            entropy ^= type_hash;
        }
    }

    return entropy;
}

/// Read CMOS/RTC time for additional entropy
pub fn readCmosTime() u64 {
    // Read various CMOS registers for entropy
    var entropy: u64 = 0;

    // Read seconds
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0)),
          [port] "N{dx}" (@as(u16, 0x70)),
    );
    const seconds = asm volatile ("inb %[port]"
        : [ret] "={al}" (-> u8),
        : [port] "N{dx}" (@as(u16, 0x71)),
    );
    entropy |= @as(u64, seconds);

    // Read minutes
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 2)),
          [port] "N{dx}" (@as(u16, 0x70)),
    );
    const minutes = asm volatile ("inb %[port]"
        : [ret] "={al}" (-> u8),
        : [port] "N{dx}" (@as(u16, 0x71)),
    );
    entropy |= (@as(u64, minutes) << 8);

    // Read hours
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 4)),
          [port] "N{dx}" (@as(u16, 0x70)),
    );
    const hours = asm volatile ("inb %[port]"
        : [ret] "={al}" (-> u8),
        : [port] "N{dx}" (@as(u16, 0x71)),
    );
    entropy |= (@as(u64, hours) << 16);

    // Read day
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 7)),
          [port] "N{dx}" (@as(u16, 0x70)),
    );
    const day = asm volatile ("inb %[port]"
        : [ret] "={al}" (-> u8),
        : [port] "N{dx}" (@as(u16, 0x71)),
    );
    entropy |= (@as(u64, day) << 24);

    // Mix with low bits of TSC for sub-second precision
    entropy ^= readTsc() & 0xFFFFFFFF;

    return entropy;
}

/// Read CPU performance counters for entropy
pub fn readPerfCounters() u64 {
    // SECURITY: Following Intel x86-64 security best practices for entropy collection
    // This function collects timing-based entropy from multiple TSC reads

    var entropy: u64 = 0;

    // Collect TSC jitter over multiple reads
    // The variations in TSC deltas provide actual entropy from CPU timing
    var prev_tsc = readTsc();
    var jitter_sum: u64 = 0;

    var i: u32 = 0;
    while (i < 16) : (i += 1) {
        // Small delay using PAUSE instruction to allow timing variations
        asm volatile ("pause" ::: "memory");

        const current_tsc = readTsc();
        const delta = current_tsc -% prev_tsc;

        // Use only the low bits of delta which have more variation
        jitter_sum = rotl64(jitter_sum, 5) ^ (delta & 0xFFFF);
        prev_tsc = current_tsc;
    }

    entropy = jitter_sum;

    // SECURITY: Removed CPUID mixing as it provides no actual entropy
    // CPUID returns deterministic values that don't contribute to randomness
    // Intel security guidelines recommend using only true entropy sources

    return entropy;
}
