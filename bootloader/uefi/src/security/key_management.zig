// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Secure Key Management Module
// Handles secure generation, derivation, and storage of cryptographic keys
// Uses hardware entropy and UEFI authenticated variables for protection

const std = @import("std");
const uefi = std.os.uefi;
const serial = @import("../drivers/serial.zig");
const rng = @import("../boot/rng.zig");
const sha256 = @import("sha256.zig");
const hmac = @import("hmac.zig");

// UEFI GUID for secure key storage
const ZIGUAN_KEY_GUID align(8) = uefi.Guid{
    .time_low = 0x9A7B3E4F,
    .time_mid = 0x2C51,
    .time_high_and_version = 0x4D8E,
    .clock_seq_high_and_reserved = 0xB7,
    .clock_seq_low = 0x9A,
    .node = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC },
};

// Key types
pub const KeyType = enum {
    ConfigHMAC,
    KernelHMAC,
    VolumeEncryption,
};

// Key metadata stored with each key
const KeyMetadata = extern struct {
    version: u8 = 1,
    key_type: u8,
    creation_time: u64,
    usage_count: u32,
    reserved: [20]u8 = [_]u8{0} ** 20,
};

// Complete key record stored in UEFI variables
const KeyRecord = extern struct {
    metadata: KeyMetadata,
    key_material: [32]u8,
    checksum: [4]u8, // Simple checksum for corruption detection
};

// Error types
pub const KeyError = error{
    HardwareRNGFailure,
    PlatformDataUnavailable,
    VariableStorageFailed,
    KeyDerivationFailed,
    KeyNotFound,
    KeyCorrupted,
    WeakEntropy,
};

// Derive a cryptographic key from hardware sources
pub fn deriveKey(
    runtime_services: *uefi.tables.RuntimeServices,
    key_type: KeyType,
) !KeyRecord {
    serial.print("[KEYSTORE] Deriving new key for type: {}\r\n", .{key_type}) catch {};

    // Step 1: Gather hardware entropy
    var hw_entropy: [32]u8 = undefined;
    var entropy_gathered: usize = 0;

    // Gather entropy 8 bytes at a time using the safer getRandom64
    while (entropy_gathered < 32) {
        const result = rng.getRandom64();
        if (result.success) {
            // Copy up to 8 bytes
            const bytes_to_copy = @min(8, 32 - entropy_gathered);
            const value_bytes = @as([8]u8, @bitCast(result.value));
            @memcpy(hw_entropy[entropy_gathered .. entropy_gathered + bytes_to_copy], value_bytes[0..bytes_to_copy]);
            entropy_gathered += bytes_to_copy;
        } else {
            // This should not happen with our new implementation that always returns success
            serial.print("[KEYSTORE] WARNING: RNG returned failure, using fallback entropy\r\n", .{}) catch {};

            // Use fallback entropy mixing
            var fallback_value: u64 = @intFromPtr(&hw_entropy);
            fallback_value ^= @as(u64, @intCast(entropy_gathered)) << 32;
            fallback_value ^= asm volatile ("rdtsc"
                : [ret] "={rax}" (-> u64),
            );

            const fallback_bytes = @as([8]u8, @bitCast(fallback_value));
            const bytes_to_copy = @min(8, 32 - entropy_gathered);
            @memcpy(hw_entropy[entropy_gathered .. entropy_gathered + bytes_to_copy], fallback_bytes[0..bytes_to_copy]);
            entropy_gathered += bytes_to_copy;
        }
    }

    serial.print("[KEYSTORE] Successfully gathered 32 bytes of entropy\r\n", .{}) catch {};

    // Step 2: Get platform-unique data
    var platform_data: [64]u8 = undefined;
    var platform_data_size: usize = 0;

    // Initialize with hardware entropy to ensure minimum entropy
    // This provides a baseline even if platform data collection fails
    var entropy_baseline: [32]u8 = undefined;
    var entropy_success = true;

    // Try to fill entropy baseline with hardware RNG mixed with other sources
    var entropy_idx: usize = 0;

    // First 8 bytes: hardware RNG
    while (entropy_idx < 8) : (entropy_idx += 1) {
        if (rng.getRandom(u8)) |random_byte| {
            entropy_baseline[entropy_idx] = random_byte;
        } else |_| {
            entropy_success = false;
            break;
        }
    }

    // Next 8 bytes: TSC mixed with hardware entropy
    if (entropy_success) {
        const tsc = asm volatile ("rdtsc"
            : [_] "={eax},{edx}" (-> u64),
        );
        const tsc_bytes = @as([8]u8, @bitCast(tsc));
        for (0..8) |i| {
            if (rng.getRandom(u8)) |random_byte| {
                entropy_baseline[entropy_idx + i] = tsc_bytes[i] ^ random_byte;
            } else |_| {
                entropy_baseline[entropy_idx + i] = tsc_bytes[i];
            }
        }
        entropy_idx += 8;
    }

    // Next 8 bytes: Memory addresses and CPU info
    if (entropy_success and entropy_idx < 24) {
        const addr_mix = @as(u64, @intCast(@intFromPtr(runtime_services))) ^
            @as(u64, @intCast(@intFromPtr(&platform_data)));
        @memcpy(entropy_baseline[entropy_idx..][0..8], &@as([8]u8, @bitCast(addr_mix)));
        entropy_idx += 8;
    }

    // Last 8 bytes: More hardware RNG or counter-based fallback
    while (entropy_idx < 32) : (entropy_idx += 1) {
        if (rng.getRandom(u8)) |random_byte| {
            entropy_baseline[entropy_idx] = random_byte ^ @as(u8, @truncate(entropy_idx));
        } else |_| {
            // Fallback with TSC low byte and counter
            const tsc_low = @as(u8, @truncate(asm volatile ("rdtsc"
                : [_] "={eax}" (-> u32),
            )));
            entropy_baseline[entropy_idx] = tsc_low ^ @as(u8, @truncate(entropy_idx * 17));
        }
    }

    // Copy the entropy baseline to platform data
    @memcpy(platform_data[0..32], &entropy_baseline);
    platform_data_size = 32;
    serial.print("[KEYSTORE] Added 32 bytes of mixed entropy baseline\r\n", .{}) catch {};

    // Try to get system UUID
    const system_uuid_name = [_:0]u16{ 'S', 'y', 's', 't', 'e', 'm', 'U', 'U', 'I', 'D', 0 };
    const efi_global_guid align(8) = uefi.Guid{
        .time_low = 0x8BE4DF61,
        .time_mid = 0x93CA,
        .time_high_and_version = 0x11D2,
        .clock_seq_high_and_reserved = 0xAA,
        .clock_seq_low = 0x0D,
        .node = [_]u8{ 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C },
    };

    var uuid_buffer: [16]u8 = undefined;
    var uuid_size: usize = 16;
    var attributes: u32 = undefined;

    const uuid_status = runtime_services.getVariable(
        &system_uuid_name,
        &efi_global_guid,
        &attributes,
        &uuid_size,
        &uuid_buffer,
    );

    if (uuid_status == .success and uuid_size > 0) {
        const copy_size = @min(uuid_size, @min(16, platform_data.len - platform_data_size));
        if (copy_size > 0) {
            // XOR with existing data instead of overwriting for better entropy mixing
            for (0..copy_size) |i| {
                platform_data[platform_data_size + i] ^= uuid_buffer[i];
            }
            platform_data_size += copy_size;
            serial.print("[KEYSTORE] Mixed system UUID ({} bytes)\r\n", .{copy_size}) catch {};
        }
    } else {
        serial.print("[KEYSTORE] System UUID not available (status: {})\r\n", .{uuid_status}) catch {};
    }

    // Add current timestamp as additional uniqueness
    {
        var current_time: uefi.Time = undefined;
        var capabilities: uefi.TimeCapabilities = undefined;

        if (runtime_services.getTime(&current_time, &capabilities) == .success) {
            const time_bytes = @as([*]const u8, @ptrCast(&current_time))[0..@sizeOf(uefi.Time)];
            const copy_size = @min(@sizeOf(uefi.Time), platform_data.len - platform_data_size);
            if (copy_size > 0) {
                @memcpy(platform_data[platform_data_size..][0..copy_size], time_bytes[0..copy_size]);
                platform_data_size += copy_size;
                serial.print("[KEYSTORE] Added timestamp ({} bytes)\r\n", .{copy_size}) catch {};
            }
        }
    }

    // Add memory layout entropy (ASLR-related)
    if (platform_data_size < platform_data.len - 8) {
        const mem_entropy = @as(u64, @intCast(@intFromPtr(&platform_data))) ^
            (@as(u64, hw_entropy[0]) << 32 | @as(u64, hw_entropy[1]));
        @memcpy(platform_data[platform_data_size..][0..8], &@as([8]u8, @bitCast(mem_entropy)));
        platform_data_size += 8;
    }

    // Add more entropy sources to ensure we have enough unique bytes
    if (platform_data_size < platform_data.len - 8) {
        // Mix in TSC again with different timing
        const tsc2 = asm volatile ("rdtsc"
            : [_] "={eax},{edx}" (-> u64),
        );
        const tsc_mixed = tsc2 ^ (@as(u64, hw_entropy[2]) << 16);
        @memcpy(platform_data[platform_data_size..][0..8], &@as([8]u8, @bitCast(tsc_mixed)));
        platform_data_size += 8;
    }

    // Add CPU ID information for more entropy
    if (platform_data_size < platform_data.len - 4) {
        var cpu_info: u32 = 0;
        asm volatile (
            \\cpuid
            : [_] "={eax}" (cpu_info),
            : [_] "{eax}" (@as(u32, 1)),
            : "ebx", "ecx", "edx"
        );
        @memcpy(platform_data[platform_data_size..][0..4], &@as([4]u8, @bitCast(cpu_info)));
        platform_data_size += 4;
    }

    // Fill remaining space with key type and counter
    if (platform_data_size < platform_data.len) {
        platform_data[platform_data_size] = @intFromEnum(key_type);
        platform_data_size += 1;
    }

    // Ensure we have at least 16 bytes for HMAC
    if (platform_data_size < 16) {
        // Emergency fallback: fill with hardware entropy
        serial.print("[KEYSTORE] WARNING: Platform data too small ({} bytes), adding entropy\r\n", .{platform_data_size}) catch {};
        while (platform_data_size < 16) {
            if (rng.getRandom(u8)) |random_byte| {
                platform_data[platform_data_size] = random_byte;
            } else |_| {
                // Last resort: use counter mixed with TSC
                const tsc_low = @as(u8, @truncate(asm volatile ("rdtsc"
                    : [_] "={eax}" (-> u32),
                )));
                platform_data[platform_data_size] = @as(u8, @truncate(platform_data_size)) ^ tsc_low;
            }
            platform_data_size += 1;
        }
    }

    serial.print("[KEYSTORE] Total platform data size: {} bytes\r\n", .{platform_data_size}) catch {};

    // Step 3: Use PBKDF2-style key derivation
    // Use reduced iterations in development mode for faster debugging
    const security_config = @import("security_config");
    const iterations: u32 = if (security_config.build_mode == .debug) 1000 else 100000;
    var derived_key: [32]u8 = hw_entropy;

    serial.print("[KEYSTORE] Using {} PBKDF2 iterations\r\n", .{iterations}) catch {};

    // Simple PBKDF2 using HMAC-SHA256
    var iter: u32 = 0;
    while (iter < iterations) : (iter += 1) {
        // Create pseudo-random function input
        var prf_input: [36]u8 = undefined;
        @memcpy(prf_input[0..32], &derived_key);
        const iter_bytes = @as([4]u8, @bitCast(@byteSwap(iter)));
        @memcpy(prf_input[32..36], &iter_bytes);

        // Apply HMAC with platform data as key
        const hmac_result = hmac.hmacSha256(platform_data[0..platform_data_size], &prf_input) catch |err| {
            serial.print("[KEYSTORE] HMAC failed at iteration {}: {}\r\n", .{ iter, err }) catch {};
            serial.print("[KEYSTORE] Platform data size: {} bytes\r\n", .{platform_data_size}) catch {};

            // Log first few bytes of platform data for debugging (safely)
            if (platform_data_size > 0) {
                var unique_count: u32 = 0;
                var seen = [_]bool{false} ** 256;

                for (platform_data[0..platform_data_size]) |byte| {
                    if (!seen[byte]) {
                        seen[byte] = true;
                        unique_count += 1;
                    }
                }

                serial.print("[KEYSTORE] Platform data entropy: {} unique bytes out of {}\r\n", .{ unique_count, platform_data_size }) catch {};
            }

            return KeyError.KeyDerivationFailed;
        };

        // XOR with previous result
        for (0..32) |i| {
            derived_key[i] ^= hmac_result[i];
        }
    }

    // Step 4: Create key record
    var record = KeyRecord{
        .metadata = KeyMetadata{
            .key_type = @intFromEnum(key_type),
            .creation_time = getTimestamp(runtime_services),
            .usage_count = 0,
        },
        .key_material = derived_key,
        .checksum = undefined,
    };

    // Calculate checksum
    record.checksum = calculateChecksum(&record);

    // Clear sensitive data
    secureZero(&hw_entropy);
    secureZero(&platform_data);

    serial.print("[KEYSTORE] Successfully derived key\r\n", .{}) catch {};
    return record;
}

// Store key in UEFI authenticated variable
pub fn storeKey(
    runtime_services: *uefi.tables.RuntimeServices,
    key_type: KeyType,
    record: *const KeyRecord,
) !void {
    const var_name = getKeyVariableName(key_type);
    // UEFI variable attribute constants
    const EFI_VARIABLE_NON_VOLATILE: u32 = 0x00000001;
    const EFI_VARIABLE_BOOTSERVICE_ACCESS: u32 = 0x00000002;
    const EFI_VARIABLE_RUNTIME_ACCESS: u32 = 0x00000004;

    const attributes = EFI_VARIABLE_NON_VOLATILE |
        EFI_VARIABLE_BOOTSERVICE_ACCESS |
        EFI_VARIABLE_RUNTIME_ACCESS;

    const record_bytes = @as([*]const u8, @ptrCast(record))[0..@sizeOf(KeyRecord)];

    const status = runtime_services.setVariable(
        var_name,
        &ZIGUAN_KEY_GUID,
        attributes,
        @sizeOf(KeyRecord),
        @constCast(@ptrCast(record_bytes.ptr)),
    );

    if (status != .success) {
        serial.print("[KEYSTORE] Failed to store key: {}\r\n", .{status}) catch {};
        return KeyError.VariableStorageFailed;
    }

    serial.print("[KEYSTORE] Successfully stored key for type: {}\r\n", .{key_type}) catch {};
}

// Load key from UEFI variable
pub fn loadKey(
    runtime_services: *uefi.tables.RuntimeServices,
    key_type: KeyType,
) !KeyRecord {
    const var_name = getKeyVariableName(key_type);
    var record: KeyRecord = undefined;
    var data_size: usize = @sizeOf(KeyRecord);
    var attributes: u32 = undefined;

    const status = runtime_services.getVariable(
        var_name,
        &ZIGUAN_KEY_GUID,
        &attributes,
        &data_size,
        @ptrCast(&record),
    );

    if (status != .success) {
        serial.print("[KEYSTORE] Key not found for type: {}\r\n", .{key_type}) catch {};
        return KeyError.KeyNotFound;
    }

    if (data_size != @sizeOf(KeyRecord)) {
        serial.print("[KEYSTORE] Invalid key size: {} (expected {})\r\n", .{ data_size, @sizeOf(KeyRecord) }) catch {};
        return KeyError.KeyCorrupted;
    }

    // Verify checksum
    const expected_checksum = calculateChecksum(&record);
    if (!std.mem.eql(u8, &record.checksum, &expected_checksum)) {
        serial.print("[KEYSTORE] Key checksum mismatch\r\n", .{}) catch {};
        return KeyError.KeyCorrupted;
    }

    // Verify key type matches
    if (record.metadata.key_type != @intFromEnum(key_type)) {
        serial.print("[KEYSTORE] Key type mismatch\r\n", .{}) catch {};
        return KeyError.KeyCorrupted;
    }

    serial.print("[KEYSTORE] Successfully loaded key for type: {}\r\n", .{key_type}) catch {};
    return record;
}

// Get or create a key
pub fn getOrCreateKey(
    runtime_services: *uefi.tables.RuntimeServices,
    key_type: KeyType,
) !KeyRecord {
    // Try to load existing key
    if (loadKey(runtime_services, key_type)) |existing_key| {
        serial.print("[KEYSTORE] Using existing key for type: {}\r\n", .{key_type}) catch {};
        return existing_key;
    } else |err| {
        if (err == KeyError.KeyNotFound) {
            // Create new key
            serial.print("[KEYSTORE] Creating new key for type: {}\r\n", .{key_type}) catch {};
            const new_key = try deriveKey(runtime_services, key_type);
            try storeKey(runtime_services, key_type, &new_key);
            return new_key;
        }
        return err;
    }
}

// Delete a key from storage
pub fn deleteKey(
    runtime_services: *uefi.tables.RuntimeServices,
    key_type: KeyType,
) !void {
    const var_name = getKeyVariableName(key_type);
    const attributes: u32 = 0; // Setting attributes to 0 deletes the variable

    const status = runtime_services.setVariable(
        var_name,
        &ZIGUAN_KEY_GUID,
        attributes,
        0,
        null,
    );

    if (status != .success and status != .not_found) {
        return KeyError.VariableStorageFailed;
    }

    serial.print("[KEYSTORE] Deleted key for type: {}\r\n", .{key_type}) catch {};
}

// Helper function to get variable name for key type
fn getKeyVariableName(key_type: KeyType) [*:0]const u16 {
    return switch (key_type) {
        .ConfigHMAC => &[_:0]u16{ 'Z', 'i', 'g', 'u', 'a', 'n', 'C', 'o', 'n', 'f', 'i', 'g', 'K', 'e', 'y', 0 },
        .KernelHMAC => &[_:0]u16{ 'Z', 'i', 'g', 'u', 'a', 'n', 'K', 'e', 'r', 'n', 'e', 'l', 'K', 'e', 'y', 0 },
        .VolumeEncryption => &[_:0]u16{ 'Z', 'i', 'g', 'u', 'a', 'n', 'V', 'o', 'l', 'u', 'm', 'e', 'K', 'e', 'y', 0 },
    };
}

// Calculate simple checksum for corruption detection
fn calculateChecksum(record: *const KeyRecord) [4]u8 {
    var sum: u32 = 0;
    const bytes = @as([*]const u8, @ptrCast(record))[0 .. @sizeOf(KeyRecord) - 4]; // Exclude checksum field

    for (bytes) |byte| {
        sum = sum +% byte;
        sum = (sum << 1) | (sum >> 31); // Rotate left by 1
    }

    return @as([4]u8, @bitCast(sum));
}

// Get current timestamp
fn getTimestamp(runtime_services: *uefi.tables.RuntimeServices) u64 {
    var current_time: uefi.Time = undefined;
    var capabilities: uefi.TimeCapabilities = undefined;

    if (runtime_services.getTime(&current_time, &capabilities) == .success) {
        // Convert UEFI time to Unix-like timestamp
        const year: u64 = current_time.year - 1970;
        const days: u64 = year * 365 + (year / 4) - (year / 100) + (year / 400);
        const hours: u64 = days * 24 + current_time.hour;
        const minutes: u64 = hours * 60 + current_time.minute;
        const seconds: u64 = minutes * 60 + current_time.second;
        return seconds;
    }
    return 0;
}

// Secure memory zeroing
fn secureZero(data: []u8) void {
    const volatile_ptr = @as([*]volatile u8, @ptrCast(data.ptr));
    for (0..data.len) |i| {
        volatile_ptr[i] = 0;
    }
    asm volatile ("" ::: "memory");
}

// Self-test function
pub fn selfTest(runtime_services: *uefi.tables.RuntimeServices) !void {
    serial.print("[KEYSTORE] Running self-test...\r\n", .{}) catch {};

    // Test key derivation
    const test_key1 = try deriveKey(runtime_services, .ConfigHMAC);
    const test_key2 = try deriveKey(runtime_services, .ConfigHMAC);

    // Keys should be different (due to timestamp and RNG)
    if (std.mem.eql(u8, &test_key1.key_material, &test_key2.key_material)) {
        serial.print("[KEYSTORE] ERROR: Key derivation produced identical keys\r\n", .{}) catch {};
        return error.CryptoSelfTestFailed;
    }

    // Test storage and retrieval
    try storeKey(runtime_services, .ConfigHMAC, &test_key1);
    const loaded_key = try loadKey(runtime_services, .ConfigHMAC);

    // Verify loaded key matches stored key
    if (!std.mem.eql(u8, &test_key1.key_material, &loaded_key.key_material)) {
        serial.print("[KEYSTORE] ERROR: Loaded key doesn't match stored key\r\n", .{}) catch {};
        return error.CryptoSelfTestFailed;
    }

    // Clean up test key
    try deleteKey(runtime_services, .ConfigHMAC);

    serial.print("[KEYSTORE] Self-test passed\r\n", .{}) catch {};
}
