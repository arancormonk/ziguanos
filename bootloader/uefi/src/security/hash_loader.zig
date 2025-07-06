// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Hash file loader module
// Loads kernel hash from file on EFI partition instead of compiled-in value

const std = @import("std");
const uefi = std.os.uefi;
const serial = @import("../drivers/serial.zig");
const boot_protocol = @import("shared");

// UEFI File Information GUID
const file_info_guid align(8) = uefi.Guid{
    .time_low = 0x09576e92,
    .time_mid = 0x6d3f,
    .time_high_and_version = 0x11d2,
    .clock_seq_high_and_reserved = 0x8e,
    .clock_seq_low = 0x39,
    .node = [_]u8{ 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
};

// UEFI File Information structure
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

// Load kernel hash from file on EFI partition
// The hash file should contain a single line with the hex-encoded SHA-256 hash
pub fn loadHashFromFile(boot_services: *uefi.tables.BootServices) ?[boot_protocol.SHA256_SIZE]u8 {
    // Get handle to boot file system
    const image_handle = uefi.handle;

    var loaded_image: *uefi.protocol.LoadedImage = undefined;
    switch (boot_services.handleProtocol(image_handle, &uefi.protocol.LoadedImage.guid, @ptrCast(&loaded_image))) {
        .success => {},
        else => |status| {
            serial.print("[UEFI] Failed to get LoadedImage protocol: {}\r\n", .{status}) catch {};
            return null;
        },
    }

    var file_system: *uefi.protocol.SimpleFileSystem = undefined;
    switch (boot_services.handleProtocol(loaded_image.device_handle.?, &uefi.protocol.SimpleFileSystem.guid, @ptrCast(&file_system))) {
        .success => {},
        else => |status| {
            serial.print("[UEFI] Failed to get SimpleFileSystem protocol: {}\r\n", .{status}) catch {};
            return null;
        },
    }

    var root_dir: *const uefi.protocol.File = undefined;
    switch (file_system.openVolume(&root_dir)) {
        .success => {},
        else => |status| {
            serial.print("[UEFI] Failed to open root directory: {}\r\n", .{status}) catch {};
            return null;
        },
    }
    defer _ = root_dir.close();

    // Open hash file
    var hash_file: *const uefi.protocol.File = undefined;
    const hash_path = [_:0]u16{ 'k', 'e', 'r', 'n', 'e', 'l', '.', 's', 'h', 'a', '2', '5', '6', 0 };

    switch (root_dir.open(&hash_file, &hash_path, uefi.protocol.File.efi_file_mode_read, 0)) {
        .success => {},
        else => |status| {
            serial.print("[UEFI] Failed to open kernel.sha256: {}\r\n", .{status}) catch {};
            return null;
        },
    }
    defer _ = hash_file.close();

    // Get file size
    var file_info_buffer: [512]u8 align(8) = undefined;
    var buffer_size: usize = file_info_buffer.len;

    switch (hash_file.getInfo(&file_info_guid, &buffer_size, &file_info_buffer)) {
        .success => {},
        else => {
            serial.print("[UEFI] Failed to get hash file info\r\n", .{}) catch {};
            return null;
        },
    }

    const file_info = @as(*FileInfo, @ptrCast(&file_info_buffer));
    const file_size = file_info.file_size;

    // The file should contain at least 64 hex characters
    if (file_size < 64) {
        serial.print("[UEFI] Hash file too small: {} bytes\r\n", .{file_size}) catch {};
        return null;
    }

    // Read file contents
    var read_buffer: [128]u8 = undefined; // Should be enough for hash + newline
    var bytes_read: usize = read_buffer.len;

    switch (hash_file.read(&bytes_read, &read_buffer)) {
        .success => {},
        else => {
            serial.print("[UEFI] Failed to read hash file\r\n", .{}) catch {};
            return null;
        },
    }

    if (bytes_read < 64) {
        serial.print("[UEFI] Hash file read only {} bytes\r\n", .{bytes_read}) catch {};
        return null;
    }

    // Parse hex string to binary
    var hash: [boot_protocol.SHA256_SIZE]u8 = undefined;

    for (0..boot_protocol.SHA256_SIZE) |i| {
        const hex_byte = read_buffer[i * 2 .. i * 2 + 2];
        hash[i] = parseHexByte(hex_byte) catch {
            serial.print("[UEFI] Invalid hex in hash file at position {}\r\n", .{i * 2}) catch {};
            return null;
        };
    }

    serial.print("[UEFI] Successfully loaded kernel hash from file\r\n", .{}) catch {};
    serial.print("[UEFI] Hash: ", .{}) catch {};
    for (hash) |byte| {
        serial.print("{X:0>2}", .{byte}) catch {};
    }
    serial.print("\r\n", .{}) catch {};

    return hash;
}

// Parse a two-character hex string to a byte
fn parseHexByte(hex: []const u8) !u8 {
    if (hex.len != 2) return error.InvalidHexLength;

    const high = try parseHexNibble(hex[0]);
    const low = try parseHexNibble(hex[1]);

    return (high << 4) | low;
}

// Parse a single hex character to a nibble (4 bits)
fn parseHexNibble(char: u8) !u8 {
    return switch (char) {
        '0'...'9' => char - '0',
        'a'...'f' => char - 'a' + 10,
        'A'...'F' => char - 'A' + 10,
        else => error.InvalidHexCharacter,
    };
}
