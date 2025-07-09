// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// UEFI Variable Cache Module
// Prevents TOCTOU (Time-Of-Check Time-Of-Use) vulnerabilities by caching
// security-critical UEFI variables at boot time

const std = @import("std");
const uefi = std.os.uefi;
const serial = @import("../drivers/serial.zig");
const boot_protocol = @import("shared");
const hmac = @import("hmac.zig");
const config_parser = @import("config_parser.zig");

// Ziguanos vendor GUID for our variables
const ZIGUANOS_VENDOR_GUID align(8) = uefi.Guid{
    .time_low = 0x5A494755,
    .time_mid = 0x414E,
    .time_high_and_version = 0x4F53,
    .clock_seq_high_and_reserved = 0x48,
    .clock_seq_low = 0x41,
    .node = [_]u8{ 0x53, 0x48, 0x5A, 0x49, 0x47, 0x55 },
};

// UEFI variable attribute constants
const EFI_VARIABLE_NON_VOLATILE: u32 = 0x00000001;
const EFI_VARIABLE_BOOTSERVICE_ACCESS: u32 = 0x00000002;
const EFI_VARIABLE_RUNTIME_ACCESS: u32 = 0x00000004;
const EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS: u32 = 0x00000020;

// Security-critical variable structure
const CachedVariable = struct {
    name: []const u16,
    data: ?[]u8,
    attributes: u32,
    loaded: bool,
};

// Cache for security-critical variables
pub const VariableCache = struct {
    // Kernel verification variables
    kernel_hash: ?[boot_protocol.SHA256_SIZE]u8 = null,
    kernel_hash_attrs: u32 = 0,

    post_relocation_hash: ?[boot_protocol.SHA256_SIZE]u8 = null,
    post_relocation_hash_attrs: u32 = 0,

    // HMAC verification variables
    hmac_key: ?[32]u8 = null,
    hmac_key_attrs: u32 = 0,

    kernel_hmac: ?[hmac.HMAC_SIZE]u8 = null,
    kernel_hmac_attrs: u32 = 0,

    // Policy variables
    security_level: ?u8 = null,
    security_level_attrs: u32 = 0,

    hmac_verification: ?bool = null,
    hmac_verification_attrs: u32 = 0,

    // KASLR configuration
    kaslr_rdrand_retries: ?u32 = null,
    kaslr_rdrand_retries_attrs: u32 = 0,

    kaslr_rdseed_retries: ?u32 = null,
    kaslr_rdseed_retries_attrs: u32 = 0,

    kaslr_enforce: ?bool = null,
    kaslr_enforce_attrs: u32 = 0,

    kaslr_enabled: ?bool = null,
    kaslr_enabled_attrs: u32 = 0,

    // Cache state
    initialized: bool = false,
    runtime_services: ?*uefi.tables.RuntimeServices = null,

    // Configuration state
    config_from_file: bool = false,
    uefi_allocator: ?std.mem.Allocator = null,
    boot_services: ?*uefi.tables.BootServices = null,
    handle: ?uefi.Handle = null,
};

// Global cache instance
var cache: VariableCache = .{};

// Initialize the cache and load all security-critical variables
// Now supports both file-based and UEFI variable configuration
pub fn init(runtime_services: *uefi.tables.RuntimeServices) !void {
    try initWithFileSupport(runtime_services, null, null, null);
}

// Initialize with file support (used by main bootloader)
pub fn initWithFileSupport(
    runtime_services: *uefi.tables.RuntimeServices,
    handle: ?uefi.Handle,
    boot_services: ?*uefi.tables.BootServices,
    allocator: ?std.mem.Allocator,
) !void {
    if (cache.initialized) {
        serial.print("[CACHE] WARNING: Variable cache already initialized\r\n", .{}) catch {};
        return;
    }

    cache.runtime_services = runtime_services;
    cache.handle = handle;
    cache.boot_services = boot_services;
    cache.uefi_allocator = allocator;

    serial.print("[CACHE] Initializing configuration cache...\r\n", .{}) catch {};

    // Try to load configuration from file first
    if (handle != null and boot_services != null and allocator != null) {
        serial.print("[CACHE] Attempting to load configuration from file...\r\n", .{}) catch {};

        if (loadConfigurationFromFile(handle.?, boot_services.?, allocator.?)) {
            cache.config_from_file = true;
            serial.print("[CACHE] Successfully loaded configuration from file\r\n", .{}) catch {};
        } else {
            serial.print("[CACHE] Failed to load configuration from file, falling back to UEFI variables\r\n", .{}) catch {};
            loadConfigurationFromUEFI();
        }
    } else {
        serial.print("[CACHE] File support not available, using UEFI variables\r\n", .{}) catch {};
        loadConfigurationFromUEFI();
    }

    cache.initialized = true;

    serial.print("[CACHE] Configuration cache initialized successfully\r\n", .{}) catch {};
    printCacheStatus();
}

// Load configuration from file
fn loadConfigurationFromFile(
    handle: uefi.Handle,
    boot_services: *uefi.tables.BootServices,
    allocator: std.mem.Allocator,
) bool {
    const config = config_parser.getConfigWithDefaults(handle, boot_services, allocator);

    if (!config.loaded_from_file) {
        return false;
    }

    // Apply configuration values to cache
    if (config.kaslr_enabled) |value| {
        cache.kaslr_enabled = value;
        serial.print("[CACHE] Config: KASLR enabled = {}\r\n", .{value}) catch {};
    }

    if (config.kaslr_rdrand_retries) |value| {
        cache.kaslr_rdrand_retries = value;
        serial.print("[CACHE] Config: KASLR RDRAND retries = {}\r\n", .{value}) catch {};
    }

    if (config.kaslr_rdseed_retries) |value| {
        cache.kaslr_rdseed_retries = value;
        serial.print("[CACHE] Config: KASLR RDSEED retries = {}\r\n", .{value}) catch {};
    }

    if (config.kaslr_enforce) |value| {
        cache.kaslr_enforce = value;
        serial.print("[CACHE] Config: KASLR enforce = {}\r\n", .{value}) catch {};
    }

    if (config.security_level) |level| {
        // Convert security level string to u8
        const security_level_value: u8 = if (std.mem.eql(u8, level, "development")) 0 else if (std.mem.eql(u8, level, "production")) 1 else if (std.mem.eql(u8, level, "strict")) 2 else 0; // default to development

        cache.security_level = security_level_value;
        serial.print("[CACHE] Config: Security level = {} ({s})\r\n", .{ security_level_value, level }) catch {};
    }

    if (config.hmac_verification) |value| {
        cache.hmac_verification = value;
        serial.print("[CACHE] Config: HMAC verification = {}\r\n", .{value}) catch {};
    }

    // Set default attributes for file-based config
    const file_attrs = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
    cache.kaslr_enabled_attrs = file_attrs;
    cache.kaslr_rdrand_retries_attrs = file_attrs;
    cache.kaslr_rdseed_retries_attrs = file_attrs;
    cache.kaslr_enforce_attrs = file_attrs;
    cache.security_level_attrs = file_attrs;
    cache.hmac_verification_attrs = file_attrs;

    return true;
}

// Load configuration from UEFI variables (fallback)
fn loadConfigurationFromUEFI() void {
    // First, try to enumerate available variables for debugging
    enumerateVariables();

    // Load all security-critical variables at once
    loadKernelHash();
    loadPostRelocationHash();
    loadHMACKey();
    loadKernelHMAC();
    loadSecurityLevel();
    loadKASLRConfiguration();
}

// Load kernel hash from UEFI variable
fn loadKernelHash() void {
    const rs = cache.runtime_services orelse return;

    var hash_buffer: [boot_protocol.SHA256_SIZE]u8 = undefined;
    var data_size: usize = boot_protocol.SHA256_SIZE;
    var attributes: u32 = undefined;

    serial.print("[CACHE] DEBUG: Attempting to load ZiguanosHash variable\r\n", .{}) catch {};
    serial.print("[CACHE] DEBUG: Expected size: {}, GUID: {X:0>8}-{X:0>4}-{X:0>4}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}\r\n", .{
        boot_protocol.SHA256_SIZE,
        ZIGUANOS_VENDOR_GUID.time_low,
        ZIGUANOS_VENDOR_GUID.time_mid,
        ZIGUANOS_VENDOR_GUID.time_high_and_version,
        ZIGUANOS_VENDOR_GUID.clock_seq_high_and_reserved,
        ZIGUANOS_VENDOR_GUID.clock_seq_low,
        ZIGUANOS_VENDOR_GUID.node[0],
        ZIGUANOS_VENDOR_GUID.node[1],
        ZIGUANOS_VENDOR_GUID.node[2],
        ZIGUANOS_VENDOR_GUID.node[3],
        ZIGUANOS_VENDOR_GUID.node[4],
        ZIGUANOS_VENDOR_GUID.node[5],
    }) catch {};

    const status = rs.getVariable(
        &[_:0]u16{ 'Z', 'i', 'g', 'u', 'a', 'n', 'H', 'a', 's', 'h', 0 },
        &ZIGUANOS_VENDOR_GUID,
        &attributes,
        &data_size,
        &hash_buffer,
    );

    serial.print("[CACHE] DEBUG: GetVariable returned status: {}, data_size: {}\r\n", .{ status, data_size }) catch {};

    if (status == .success and data_size == boot_protocol.SHA256_SIZE) {
        cache.kernel_hash = hash_buffer;
        cache.kernel_hash_attrs = attributes;
        serial.print("[CACHE] Loaded kernel hash (attrs: 0x{X})\r\n", .{attributes}) catch {};
    } else {
        serial.print("[CACHE] ERROR: Failed to load kernel hash - status: {}, expected size: {}, actual size: {}\r\n", .{ status, boot_protocol.SHA256_SIZE, data_size }) catch {};
    }
}

// Load post-relocation hash from UEFI variable
fn loadPostRelocationHash() void {
    const rs = cache.runtime_services orelse return;

    var hash_buffer: [boot_protocol.SHA256_SIZE]u8 = undefined;
    var data_size: usize = boot_protocol.SHA256_SIZE;
    var attributes: u32 = undefined;

    const status = rs.getVariable(
        &[_:0]u16{ 'Z', 'i', 'g', 'u', 'a', 'n', 'P', 'o', 's', 't', 'H', 'a', 's', 'h', 0 },
        &ZIGUANOS_VENDOR_GUID,
        &attributes,
        &data_size,
        &hash_buffer,
    );

    if (status == .success and data_size == boot_protocol.SHA256_SIZE) {
        cache.post_relocation_hash = hash_buffer;
        cache.post_relocation_hash_attrs = attributes;
        serial.print("[CACHE] Loaded post-relocation hash (attrs: 0x{X})\r\n", .{attributes}) catch {};
    }
}

// Load HMAC key from UEFI variable
fn loadHMACKey() void {
    const rs = cache.runtime_services orelse return;

    var key_buffer: [32]u8 = undefined;
    var data_size: usize = 32;
    var attributes: u32 = undefined;

    const status = rs.getVariable(
        &[_:0]u16{ 'Z', 'i', 'g', 'u', 'a', 'n', 'H', 'M', 'A', 'C', 'K', 'e', 'y', 0 },
        &ZIGUANOS_VENDOR_GUID,
        &attributes,
        &data_size,
        &key_buffer,
    );

    if (status == .success and data_size == 32) {
        cache.hmac_key = key_buffer;
        cache.hmac_key_attrs = attributes;
        serial.print("[CACHE] Loaded HMAC key (attrs: 0x{X})\r\n", .{attributes}) catch {};
    }
}

// Load kernel HMAC from UEFI variable
fn loadKernelHMAC() void {
    const rs = cache.runtime_services orelse return;

    var hmac_buffer: [hmac.HMAC_SIZE]u8 = undefined;
    var data_size: usize = hmac.HMAC_SIZE;
    var attributes: u32 = undefined;

    const status = rs.getVariable(
        &[_:0]u16{ 'Z', 'i', 'g', 'u', 'a', 'n', 'H', 'M', 'A', 'C', 0 },
        &ZIGUANOS_VENDOR_GUID,
        &attributes,
        &data_size,
        &hmac_buffer,
    );

    if (status == .success and data_size == hmac.HMAC_SIZE) {
        cache.kernel_hmac = hmac_buffer;
        cache.kernel_hmac_attrs = attributes;
        serial.print("[CACHE] Loaded kernel HMAC (attrs: 0x{X})\r\n", .{attributes}) catch {};
    }
}

// Load security level from UEFI variable
fn loadSecurityLevel() void {
    const rs = cache.runtime_services orelse return;

    const vendor_guid align(8) = uefi.Guid{
        .time_low = 0x41424344,
        .time_mid = 0x4546,
        .time_high_and_version = 0x4748,
        .clock_seq_high_and_reserved = 0x49,
        .clock_seq_low = 0x4A,
        .node = [_]u8{ 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50 },
    };

    var level_value: u8 = undefined;
    var data_size: usize = @sizeOf(u8);
    var attributes: u32 = undefined;

    serial.print("[CACHE] DEBUG: Attempting to load SecurityLevel variable\r\n", .{}) catch {};
    serial.print("[CACHE] DEBUG: Expected size: {}, GUID: {X:0>8}-{X:0>4}-{X:0>4}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}\r\n", .{
        @sizeOf(u8),
        vendor_guid.time_low,
        vendor_guid.time_mid,
        vendor_guid.time_high_and_version,
        vendor_guid.clock_seq_high_and_reserved,
        vendor_guid.clock_seq_low,
        vendor_guid.node[0],
        vendor_guid.node[1],
        vendor_guid.node[2],
        vendor_guid.node[3],
        vendor_guid.node[4],
        vendor_guid.node[5],
    }) catch {};

    const status = rs.getVariable(
        &[_:0]u16{ 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'L', 'e', 'v', 'e', 'l', 0 },
        &vendor_guid,
        &attributes,
        &data_size,
        &level_value,
    );

    serial.print("[CACHE] DEBUG: GetVariable returned status: {}, data_size: {}\r\n", .{ status, data_size }) catch {};

    if (status == .success and data_size == @sizeOf(u8)) {
        cache.security_level = level_value;
        cache.security_level_attrs = attributes;
        serial.print("[CACHE] Loaded security level: {} (attrs: 0x{X})\r\n", .{ level_value, attributes }) catch {};
    } else {
        serial.print("[CACHE] ERROR: Failed to load security level - status: {}, expected size: {}, actual size: {}\r\n", .{ status, @sizeOf(u8), data_size }) catch {};
    }
}

// Load KASLR configuration from UEFI variables
fn loadKASLRConfiguration() void {
    const rs = cache.runtime_services orelse return;

    // Load RDRAND retry count
    {
        var retries: u32 = undefined;
        var data_size: usize = @sizeOf(u32);
        var attributes: u32 = undefined;

        const status = rs.getVariable(
            &[_:0]u16{ 'K', 'A', 'S', 'L', 'R', 'R', 'd', 'r', 'a', 'n', 'd', 'R', 'e', 't', 'r', 'i', 'e', 's', 0 },
            &ZIGUANOS_VENDOR_GUID,
            &attributes,
            &data_size,
            &retries,
        );

        if (status == .success and data_size == @sizeOf(u32)) {
            cache.kaslr_rdrand_retries = retries;
            cache.kaslr_rdrand_retries_attrs = attributes;
            serial.print("[CACHE] Loaded KASLR RDRAND retries: {} (attrs: 0x{X})\r\n", .{ retries, attributes }) catch {};
        }
    }

    // Load RDSEED retry count
    {
        var retries: u32 = undefined;
        var data_size: usize = @sizeOf(u32);
        var attributes: u32 = undefined;

        const status = rs.getVariable(
            &[_:0]u16{ 'K', 'A', 'S', 'L', 'R', 'R', 'd', 's', 'e', 'e', 'd', 'R', 'e', 't', 'r', 'i', 'e', 's', 0 },
            &ZIGUANOS_VENDOR_GUID,
            &attributes,
            &data_size,
            &retries,
        );

        if (status == .success and data_size == @sizeOf(u32)) {
            cache.kaslr_rdseed_retries = retries;
            cache.kaslr_rdseed_retries_attrs = attributes;
            serial.print("[CACHE] Loaded KASLR RDSEED retries: {} (attrs: 0x{X})\r\n", .{ retries, attributes }) catch {};
        }
    }

    // Load KASLR enforcement flag
    {
        var enforce: u8 = undefined;
        var data_size: usize = @sizeOf(u8);
        var attributes: u32 = undefined;

        const status = rs.getVariable(
            &[_:0]u16{ 'K', 'A', 'S', 'L', 'R', 'E', 'n', 'f', 'o', 'r', 'c', 'e', 0 },
            &ZIGUANOS_VENDOR_GUID,
            &attributes,
            &data_size,
            &enforce,
        );

        if (status == .success and data_size == @sizeOf(u8)) {
            cache.kaslr_enforce = (enforce != 0);
            cache.kaslr_enforce_attrs = attributes;
            serial.print("[CACHE] Loaded KASLR enforcement: {} (attrs: 0x{X})\r\n", .{ enforce != 0, attributes }) catch {};
        }
    }

    // Load KASLR enabled flag
    {
        var enabled: u8 = undefined;
        var data_size: usize = @sizeOf(u8);
        var attributes: u32 = undefined;

        const status = rs.getVariable(
            &[_:0]u16{ 'K', 'A', 'S', 'L', 'R', 'E', 'n', 'a', 'b', 'l', 'e', 'd', 0 },
            &ZIGUANOS_VENDOR_GUID,
            &attributes,
            &data_size,
            &enabled,
        );

        if (status == .success and data_size == @sizeOf(u8)) {
            cache.kaslr_enabled = (enabled != 0);
            cache.kaslr_enabled_attrs = attributes;
            serial.print("[CACHE] Loaded KASLR enabled: {} (attrs: 0x{X})\r\n", .{ enabled != 0, attributes }) catch {};
        }
    }
}

// Print cache status for debugging
fn printCacheStatus() void {
    serial.print("[CACHE] Cache Status:\r\n", .{}) catch {};
    serial.print("[CACHE]   Configuration Source: {s}\r\n", .{if (cache.config_from_file) "FILE" else "UEFI_VARIABLES"}) catch {};
    serial.print("[CACHE]   Kernel Hash: {}\r\n", .{cache.kernel_hash != null}) catch {};
    serial.print("[CACHE]   Post-Relocation Hash: {}\r\n", .{cache.post_relocation_hash != null}) catch {};
    serial.print("[CACHE]   HMAC Key: {}\r\n", .{cache.hmac_key != null}) catch {};
    serial.print("[CACHE]   Kernel HMAC: {}\r\n", .{cache.kernel_hmac != null}) catch {};
    serial.print("[CACHE]   Security Level: {}\r\n", .{cache.security_level != null}) catch {};
    serial.print("[CACHE]   KASLR Config: RDRAND={}, RDSEED={}, Enforce={}, Enabled={}\r\n", .{
        if (cache.kaslr_rdrand_retries) |retries| retries else @as(u32, 0),
        if (cache.kaslr_rdseed_retries) |retries| retries else @as(u32, 0),
        if (cache.kaslr_enforce) |enforce| enforce else false,
        if (cache.kaslr_enabled) |enabled| enabled else false,
    }) catch {};
}

// Get cached kernel hash
pub fn getKernelHash() ?struct { hash: [boot_protocol.SHA256_SIZE]u8, attrs: u32 } {
    if (!cache.initialized) return null;
    if (cache.kernel_hash) |hash| {
        return .{ .hash = hash, .attrs = cache.kernel_hash_attrs };
    }
    return null;
}

// Get cached post-relocation hash
pub fn getPostRelocationHash() ?struct { hash: [boot_protocol.SHA256_SIZE]u8, attrs: u32 } {
    if (!cache.initialized) return null;
    if (cache.post_relocation_hash) |hash| {
        return .{ .hash = hash, .attrs = cache.post_relocation_hash_attrs };
    }
    return null;
}

// Get cached HMAC key
pub fn getHMACKey() ?struct { key: [32]u8, attrs: u32 } {
    if (!cache.initialized) return null;
    if (cache.hmac_key) |key| {
        return .{ .key = key, .attrs = cache.hmac_key_attrs };
    }
    return null;
}

// Get cached kernel HMAC
pub fn getKernelHMAC() ?struct { hmac: [hmac.HMAC_SIZE]u8, attrs: u32 } {
    if (!cache.initialized) return null;
    if (cache.kernel_hmac) |hmac_value| {
        return .{ .hmac = hmac_value, .attrs = cache.kernel_hmac_attrs };
    }
    return null;
}

// Get cached security level
pub fn getSecurityLevel() ?struct { level: u8, attrs: u32 } {
    if (!cache.initialized) return null;
    if (cache.security_level) |level| {
        return .{ .level = level, .attrs = cache.security_level_attrs };
    }
    return null;
}

// Get HMAC verification configuration
pub fn getHMACVerification() ?bool {
    if (!cache.initialized) return null;
    return cache.hmac_verification;
}

// Get KASLR configuration
pub fn getKASLRConfig() struct {
    rdrand_retries: ?u32,
    rdseed_retries: ?u32,
    enforce: ?bool,
    enabled: ?bool,
} {
    if (!cache.initialized) {
        return .{
            .rdrand_retries = null,
            .rdseed_retries = null,
            .enforce = null,
            .enabled = null,
        };
    }

    return .{
        .rdrand_retries = cache.kaslr_rdrand_retries,
        .rdseed_retries = cache.kaslr_rdseed_retries,
        .enforce = cache.kaslr_enforce,
        .enabled = cache.kaslr_enabled,
    };
}

// Check if cache is initialized
pub fn isInitialized() bool {
    return cache.initialized;
}

// Validate cached variable attributes
pub fn validateAttributes(attrs: u32, require_authenticated: bool) bool {
    // Check minimum required attributes
    const required_attrs = EFI_VARIABLE_BOOTSERVICE_ACCESS |
        EFI_VARIABLE_RUNTIME_ACCESS |
        EFI_VARIABLE_NON_VOLATILE;

    if ((attrs & required_attrs) != required_attrs) {
        return false;
    }

    // Check authentication if required
    if (require_authenticated) {
        const auth_attrs = EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
        return (attrs & auth_attrs) != 0;
    }

    return true;
}

// Enumerate available UEFI variables for debugging
fn enumerateVariables() void {
    const rs = cache.runtime_services orelse return;

    serial.print("[CACHE] DEBUG: Enumerating UEFI variables...\r\n", .{}) catch {};

    var variable_name: [256:0]u16 = undefined;
    var name_size: usize = 256 * @sizeOf(u16);
    var vendor_guid: uefi.Guid align(8) = undefined;
    var variable_count: u32 = 0;

    // Clear the variable name buffer
    @memset(&variable_name, 0);

    // Use GetNextVariableName to enumerate variables
    while (true) {
        name_size = 256 * @sizeOf(u16);

        const status = rs.getNextVariableName(&name_size, &variable_name, &vendor_guid);

        if (status == .success) {
            variable_count += 1;

            // Convert name to ASCII for display (simple conversion, may lose characters)
            var ascii_name: [128]u8 = undefined;
            var ascii_len: usize = 0;

            for (variable_name[0..@min(127, name_size / @sizeOf(u16))]) |wide_char| {
                if (wide_char == 0) break;
                if (wide_char <= 127) {
                    ascii_name[ascii_len] = @intCast(wide_char);
                    ascii_len += 1;
                } else {
                    ascii_name[ascii_len] = '?';
                    ascii_len += 1;
                }
            }
            ascii_name[ascii_len] = 0;

            serial.print("[CACHE] DEBUG: Variable #{}: '{s}' GUID: {X:0>8}-{X:0>4}-{X:0>4}-{X:0>2}{X:0>2}-{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}{X:0>2}\r\n", .{
                variable_count,
                ascii_name[0..ascii_len],
                vendor_guid.time_low,
                vendor_guid.time_mid,
                vendor_guid.time_high_and_version,
                vendor_guid.clock_seq_high_and_reserved,
                vendor_guid.clock_seq_low,
                vendor_guid.node[0],
                vendor_guid.node[1],
                vendor_guid.node[2],
                vendor_guid.node[3],
                vendor_guid.node[4],
                vendor_guid.node[5],
            }) catch {};

            // Stop after showing first 20 variables to avoid spam
            if (variable_count >= 20) {
                serial.print("[CACHE] DEBUG: (Truncated after {} variables)\r\n", .{variable_count}) catch {};
                break;
            }
        } else {
            if (status == .not_found) {
                serial.print("[CACHE] DEBUG: End of variable enumeration. Total variables: {}\r\n", .{variable_count}) catch {};
            } else {
                serial.print("[CACHE] DEBUG: GetNextVariableName failed: {}\r\n", .{status}) catch {};
            }
            break;
        }
    }
}
