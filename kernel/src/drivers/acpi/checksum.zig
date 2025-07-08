// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

//! ACPI table validation utilities

const std = @import("std");
const tables = @import("tables.zig");

/// Calculate 8-bit checksum for ACPI tables
/// The sum of all bytes should equal 0 for a valid table
pub fn calculate8(bytes: []const u8) u8 {
    var sum: u8 = 0;
    for (bytes) |byte| {
        sum +%= byte;
    }
    return sum;
}

/// Validate checksum for a buffer
pub fn validate(bytes: []const u8) tables.Error!void {
    if (calculate8(bytes) != 0) {
        return tables.Error.InvalidChecksum;
    }
}

/// Validate an ACPI table header and its checksum
pub fn validateTable(header: *const tables.Header) tables.Error!void {
    // Ensure we don't read beyond the table
    if (header.length < @sizeOf(tables.Header)) {
        return tables.Error.InvalidAddress;
    }

    const bytes = @as([*]const u8, @ptrCast(header))[0..header.length];
    try validate(bytes);
}

/// Update checksum field in a table
pub fn updateTableChecksum(header: *tables.Header) void {
    // Zero the checksum field first
    header.checksum = 0;

    // Calculate checksum for entire table
    const bytes = @as([*]u8, @ptrCast(header))[0..header.length];
    var sum: u8 = 0;
    for (bytes) |byte| {
        sum +%= byte;
    }

    // Set checksum to make total sum zero
    header.checksum = ~sum +% 1;
}
