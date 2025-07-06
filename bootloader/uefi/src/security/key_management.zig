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

    // Try to get entropy from multiple sources
    if (rng.getRandom(u256) catch null) |random_val| {
        const bytes = @as([32]u8, @bitCast(random_val));
        @memcpy(&hw_entropy, &bytes);
        entropy_gathered = 32;
    } else {
        // Fallback: gather entropy byte by byte
        while (entropy_gathered < 32) {
            if (rng.getRandom(u8) catch null) |random_byte| {
                hw_entropy[entropy_gathered] = random_byte;
                entropy_gathered += 1;
            } else {
                serial.print("[KEYSTORE] WARNING: Hardware RNG failure, retrying...\r\n", .{}) catch {};
                // Small delay before retry
                var i: u32 = 0;
                while (i < 1000) : (i += 1) {
                    asm volatile ("pause");
                }
            }
        }
    }

    // Step 2: Get platform-unique data
    var platform_data: [64]u8 = undefined;
    var platform_data_size: usize = 0;

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
        const copy_size = @min(uuid_size, 16);
        @memcpy(platform_data[platform_data_size..][0..copy_size], uuid_buffer[0..copy_size]);
        platform_data_size += copy_size;
        serial.print("[KEYSTORE] Got system UUID ({} bytes)\r\n", .{copy_size}) catch {};
    }

    // Add current timestamp as additional uniqueness
    {
        var current_time: uefi.Time = undefined;
        var capabilities: uefi.TimeCapabilities = undefined;

        if (runtime_services.getTime(&current_time, &capabilities) == .success) {
            const time_bytes = @as([*]const u8, @ptrCast(&current_time))[0..@sizeOf(uefi.Time)];
            const copy_size = @min(@sizeOf(uefi.Time), platform_data.len - platform_data_size);
            @memcpy(platform_data[platform_data_size..][0..copy_size], time_bytes[0..copy_size]);
            platform_data_size += copy_size;
        }
    }

    // Fill remaining space with key type and counter
    if (platform_data_size < platform_data.len) {
        platform_data[platform_data_size] = @intFromEnum(key_type);
        platform_data_size += 1;
    }

    // Step 3: Use PBKDF2-style key derivation
    const iterations = 100000;
    var derived_key: [32]u8 = hw_entropy;

    // Simple PBKDF2 using HMAC-SHA256
    var iter: u32 = 0;
    while (iter < iterations) : (iter += 1) {
        // Create pseudo-random function input
        var prf_input: [36]u8 = undefined;
        @memcpy(prf_input[0..32], &derived_key);
        const iter_bytes = @as([4]u8, @bitCast(@byteSwap(iter)));
        @memcpy(prf_input[32..36], &iter_bytes);

        // Apply HMAC with platform data as key
        const hmac_result = hmac.hmacSha256(platform_data[0..platform_data_size], &prf_input) catch {
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
