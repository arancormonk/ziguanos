// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Configuration File Parser Module
// Reads and parses configuration files from the EFI System Partition
// Supports simple key=value pairs for Ziguanos configuration

const std = @import("std");
const uefi = std.os.uefi;
const serial = @import("../drivers/serial.zig");
const verify = @import("verify.zig");

// Configuration structure holding parsed values
pub const Config = struct {
    // KASLR configuration
    kaslr_enabled: ?bool = null,
    kaslr_rdrand_retries: ?u32 = null,
    kaslr_rdseed_retries: ?u32 = null,
    kaslr_enforce: ?bool = null,

    // Security configuration
    security_level: ?[]const u8 = null,
    hmac_verification: ?bool = null,

    // Configuration file status
    loaded_from_file: bool = false,

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        if (self.security_level) |level| {
            allocator.free(level);
        }
    }
};

// Default configuration values
pub const DEFAULT_CONFIG = Config{
    .kaslr_enabled = true,
    .kaslr_rdrand_retries = 20,
    .kaslr_rdseed_retries = 1024,
    .kaslr_enforce = false,
    .security_level = null,
    .hmac_verification = null, // null means use default based on security level
    .loaded_from_file = false,
};

// Parse a boolean value from a string
fn parseBoolValue(value: []const u8) ?bool {
    if (std.mem.eql(u8, value, "enabled") or std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1")) {
        return true;
    } else if (std.mem.eql(u8, value, "disabled") or std.mem.eql(u8, value, "false") or std.mem.eql(u8, value, "0")) {
        return false;
    }
    return null;
}

// Parse a u32 value from a string
fn parseU32Value(value: []const u8) ?u32 {
    return std.fmt.parseInt(u32, value, 10) catch null;
}

// Parse a security level value from a string
fn parseSecurityLevel(value: []const u8, allocator: std.mem.Allocator) ?[]const u8 {
    if (std.mem.eql(u8, value, "development") or
        std.mem.eql(u8, value, "production") or
        std.mem.eql(u8, value, "strict"))
    {
        return allocator.dupe(u8, value) catch null;
    }
    return null;
}

// Parse configuration from file content
pub fn parseConfigContent(content: []const u8, allocator: std.mem.Allocator) !Config {
    var config = DEFAULT_CONFIG;
    config.loaded_from_file = true;

    var lines = std.mem.splitScalar(u8, content, '\n');
    var line_number: u32 = 0;

    while (lines.next()) |line| {
        line_number += 1;

        // Trim whitespace
        var trimmed_line = std.mem.trim(u8, line, " \t\r\n");

        // Skip empty lines and comments
        if (trimmed_line.len == 0 or trimmed_line[0] == '#') {
            continue;
        }

        // Find the '=' separator
        if (std.mem.indexOf(u8, trimmed_line, "=")) |eq_pos| {
            const key = std.mem.trim(u8, trimmed_line[0..eq_pos], " \t");
            const value = std.mem.trim(u8, trimmed_line[eq_pos + 1 ..], " \t");

            if (key.len == 0 or value.len == 0) {
                serial.print("[CONFIG] WARNING: Invalid line {} in config file: '{s}'\r\n", .{ line_number, trimmed_line }) catch {};
                continue;
            }

            // Parse key-value pairs
            if (std.mem.eql(u8, key, "KASLREnabled")) {
                if (parseBoolValue(value)) |parsed_value| {
                    config.kaslr_enabled = parsed_value;
                    serial.print("[CONFIG] Parsed KASLREnabled: {}\r\n", .{parsed_value}) catch {};
                } else {
                    serial.print("[CONFIG] WARNING: Invalid boolean value for KASLREnabled: '{s}'\r\n", .{value}) catch {};
                }
            } else if (std.mem.eql(u8, key, "KASLRRdrandRetries")) {
                if (parseU32Value(value)) |parsed_value| {
                    config.kaslr_rdrand_retries = parsed_value;
                    serial.print("[CONFIG] Parsed KASLRRdrandRetries: {}\r\n", .{parsed_value}) catch {};
                } else {
                    serial.print("[CONFIG] WARNING: Invalid u32 value for KASLRRdrandRetries: '{s}'\r\n", .{value}) catch {};
                }
            } else if (std.mem.eql(u8, key, "KASLRRdseedRetries")) {
                if (parseU32Value(value)) |parsed_value| {
                    config.kaslr_rdseed_retries = parsed_value;
                    serial.print("[CONFIG] Parsed KASLRRdseedRetries: {}\r\n", .{parsed_value}) catch {};
                } else {
                    serial.print("[CONFIG] WARNING: Invalid u32 value for KASLRRdseedRetries: '{s}'\r\n", .{value}) catch {};
                }
            } else if (std.mem.eql(u8, key, "KASLREnforce")) {
                if (parseBoolValue(value)) |parsed_value| {
                    config.kaslr_enforce = parsed_value;
                    serial.print("[CONFIG] Parsed KASLREnforce: {}\r\n", .{parsed_value}) catch {};
                } else {
                    serial.print("[CONFIG] WARNING: Invalid boolean value for KASLREnforce: '{s}'\r\n", .{value}) catch {};
                }
            } else if (std.mem.eql(u8, key, "SecurityLevel")) {
                if (parseSecurityLevel(value, allocator)) |parsed_value| {
                    config.security_level = parsed_value;
                    serial.print("[CONFIG] Parsed SecurityLevel: '{s}'\r\n", .{parsed_value}) catch {};
                } else {
                    serial.print("[CONFIG] WARNING: Invalid security level: '{s}'\r\n", .{value}) catch {};
                }
            } else if (std.mem.eql(u8, key, "HMACVerification")) {
                if (parseBoolValue(value)) |parsed_value| {
                    config.hmac_verification = parsed_value;
                    serial.print("[CONFIG] Parsed HMACVerification: {}\r\n", .{parsed_value}) catch {};
                } else {
                    serial.print("[CONFIG] WARNING: Invalid boolean value for HMACVerification: '{s}'\r\n", .{value}) catch {};
                }
            } else {
                serial.print("[CONFIG] WARNING: Unknown configuration key: '{s}'\r\n", .{key}) catch {};
            }
        } else {
            serial.print("[CONFIG] WARNING: Invalid line {} in config file (no '=' found): '{s}'\r\n", .{ line_number, trimmed_line }) catch {};
        }
    }

    return config;
}

// Read configuration file from EFI System Partition
pub fn readConfigFile(
    handle: uefi.Handle,
    boot_services: *uefi.tables.BootServices,
    allocator: std.mem.Allocator,
) !Config {
    serial.print("[CONFIG] Attempting to read configuration file...\r\n", .{}) catch {};

    // Get loaded image protocol
    const loaded_image_guid align(8) = uefi.protocol.LoadedImage.guid;
    var loaded_image: *uefi.protocol.LoadedImage = undefined;

    switch (boot_services.openProtocol(
        handle,
        &loaded_image_guid,
        @ptrCast(&loaded_image),
        handle,
        null,
        .{ .by_handle_protocol = true },
    )) {
        .success => {},
        else => {
            serial.print("[CONFIG] Failed to get loaded image protocol\r\n", .{}) catch {};
            return error.ProtocolNotFound;
        },
    }

    // Get file system protocol from device handle
    const simple_file_system_guid align(8) = uefi.protocol.SimpleFileSystem.guid;
    var file_system: *uefi.protocol.SimpleFileSystem = undefined;

    switch (boot_services.openProtocol(
        loaded_image.device_handle.?,
        &simple_file_system_guid,
        @ptrCast(&file_system),
        handle,
        null,
        .{ .by_handle_protocol = true },
    )) {
        .success => {},
        else => {
            serial.print("[CONFIG] Failed to get file system protocol\r\n", .{}) catch {};
            return error.FileSystemNotFound;
        },
    }

    // Open root directory
    var root_dir: *const uefi.protocol.File = undefined;
    switch (file_system.openVolume(&root_dir)) {
        .success => {},
        else => {
            serial.print("[CONFIG] Failed to open root directory\r\n", .{}) catch {};
            return error.VolumeOpenFailed;
        },
    }

    // Try to open configuration file
    var config_file: *const uefi.protocol.File = undefined;
    const config_path = [_:0]u16{ 'z', 'i', 'g', 'u', 'a', 'n', 'o', 's', '.', 'c', 'o', 'n', 'f', 0 };

    switch (root_dir.open(&config_file, &config_path, uefi.protocol.File.efi_file_mode_read, 0)) {
        .success => {},
        else => |status| {
            serial.print("[CONFIG] Configuration file not found: {}\r\n", .{status}) catch {};
            return error.ConfigFileNotFound;
        },
    }
    defer _ = config_file.close();

    // Get file size
    const FileInfo = extern struct {
        size: u64,
        file_size: u64,
        physical_size: u64,
        create_time: uefi.Time,
        last_access_time: uefi.Time,
        modification_time: uefi.Time,
        attribute: u64,
        file_name: [1]u16,
    };

    const file_info_guid align(8) = uefi.Guid{
        .time_low = 0x09576e92,
        .time_mid = 0x6d3f,
        .time_high_and_version = 0x11d2,
        .clock_seq_high_and_reserved = 0x8e,
        .clock_seq_low = 0x39,
        .node = [_]u8{ 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
    };

    var file_info_buffer: [512]u8 align(8) = undefined;
    var buffer_size: usize = file_info_buffer.len;

    switch (config_file.getInfo(&file_info_guid, &buffer_size, &file_info_buffer)) {
        .success => {},
        else => {
            serial.print("[CONFIG] Failed to get file info\r\n", .{}) catch {};
            return error.FileInfoFailed;
        },
    }

    const file_info = @as(*FileInfo, @ptrCast(&file_info_buffer));
    const file_size = file_info.file_size;

    // Validate file size
    if (file_size == 0) {
        serial.print("[CONFIG] Configuration file is empty\r\n", .{}) catch {};
        return error.EmptyConfigFile;
    }

    if (file_size > 64 * 1024) { // 64KB max
        serial.print("[CONFIG] Configuration file too large: {} bytes\r\n", .{file_size}) catch {};
        return error.ConfigFileTooLarge;
    }

    serial.print("[CONFIG] Configuration file size: {} bytes\r\n", .{file_size}) catch {};

    // Read file content
    const file_content = try allocator.alloc(u8, file_size);
    defer allocator.free(file_content);

    var bytes_read: usize = file_size;
    switch (config_file.read(&bytes_read, file_content.ptr)) {
        .success => {},
        else => {
            serial.print("[CONFIG] Failed to read configuration file\r\n", .{}) catch {};
            return error.FileReadFailed;
        },
    }

    if (bytes_read != file_size) {
        serial.print("[CONFIG] Partial read: {} of {} bytes\r\n", .{ bytes_read, file_size }) catch {};
        return error.PartialFileRead;
    }

    serial.print("[CONFIG] Successfully read configuration file\r\n", .{}) catch {};

    // First, parse the configuration to get HMACVerification setting
    var config = try parseConfigContent(file_content, allocator);

    // Determine if HMAC verification is required
    var require_hmac: bool = false;

    if (config.hmac_verification) |hmac_setting| {
        // Use explicit configuration setting
        require_hmac = hmac_setting;
        serial.print("[CONFIG] HMAC verification {s} by configuration\r\n", .{if (require_hmac) "enabled" else "disabled"}) catch {};
    } else {
        // Use default based on security policy
        const verification_config = verify.VerificationConfig.getDefault();
        require_hmac = verification_config.require_hmac;
        serial.print("[CONFIG] HMAC verification {s} by default policy\r\n", .{if (require_hmac) "enabled" else "disabled"}) catch {};
    }

    if (require_hmac) {
        // Verify configuration integrity
        const config_filename = "ziguanos.conf";
        const is_config_valid = verify.verifyConfigurationIntegrity(
            handle,
            boot_services,
            config_filename,
            file_content,
        );

        if (!is_config_valid) {
            serial.print("[CONFIG] CRITICAL: Configuration integrity check FAILED. Falling back to secure defaults.\r\n", .{}) catch {};
            config.deinit(allocator);
            return error.ConfigIntegrityFailed;
        }

        serial.print("[CONFIG] Configuration integrity verified.\r\n", .{}) catch {};
    } else {
        serial.print("[CONFIG] HMAC verification skipped\r\n", .{}) catch {};
    }

    return config;
}

// Get configuration with fallback to defaults
pub fn getConfigWithDefaults(
    handle: uefi.Handle,
    boot_services: *uefi.tables.BootServices,
    allocator: std.mem.Allocator,
) Config {
    return readConfigFile(handle, boot_services, allocator) catch |err| {
        serial.print("[CONFIG] Failed to read config file: {}, using defaults\r\n", .{err}) catch {};
        return DEFAULT_CONFIG;
    };
}
