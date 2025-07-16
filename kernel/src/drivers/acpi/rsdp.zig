// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// RSDP/RSDT/XSDT parsing for ACPI table discovery

const std = @import("std");
const tables = @import("tables.zig");

// RSDP descriptor for ACPI 1.0
pub const RSDPDescriptor = extern struct {
    signature: [8]u8,
    checksum: u8,
    oem_id: [6]u8,
    revision: u8,
    rsdt_address: u32,

    pub fn validate(self: *const RSDPDescriptor) tables.Error!void {
        // Check signature
        if (!std.mem.eql(u8, &self.signature, tables.Signature.RSDP)) {
            return tables.Error.InvalidSignature;
        }

        // Validate checksum
        const bytes = @as([*]const u8, @ptrCast(self))[0..@sizeOf(RSDPDescriptor)];
        if (calculateChecksum(bytes) != 0) {
            return tables.Error.InvalidChecksum;
        }
    }
};

// Extended RSDP descriptor for ACPI 2.0+
pub const RSDPDescriptor20 = extern struct {
    // ACPI 1.0 compatible part
    first_part: RSDPDescriptor,

    // ACPI 2.0+ extensions
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [3]u8,

    pub fn validate(self: *const RSDPDescriptor20) tables.Error!void {
        // First validate the 1.0 part
        try self.first_part.validate();

        // For ACPI 2.0+, validate the extended checksum
        if (self.first_part.revision >= tables.Revision.ACPI_2_0) {
            const bytes = @as([*]const u8, @ptrCast(self))[0..self.length];
            if (calculateChecksum(bytes) != 0) {
                return tables.Error.InvalidChecksum;
            }
        }
    }

    pub fn getRevision(self: *const RSDPDescriptor20) u8 {
        return self.first_part.revision;
    }

    pub fn isAcpi20(self: *const RSDPDescriptor20) bool {
        return self.first_part.revision >= tables.Revision.ACPI_2_0;
    }
};

// Root System Description Table (32-bit pointers)
pub const RSDT = extern struct {
    header: tables.Header,
    // Followed by array of 32-bit pointers to other tables

    pub fn getTableCount(self: *const RSDT) usize {
        return (self.header.length - @sizeOf(tables.Header)) / @sizeOf(u32);
    }

    pub fn getTablePointers(self: *const RSDT) []const u32 {
        const count = self.getTableCount();
        const ptr = @as([*]const u32, @ptrCast(@alignCast(@as([*]const u8, @ptrCast(self)) + @sizeOf(tables.Header))));
        return ptr[0..count];
    }
};

// Extended System Description Table (64-bit pointers)
pub const XSDT = extern struct {
    header: tables.Header,
    // Followed by array of 64-bit pointers to other tables

    pub fn getTableCount(self: *const XSDT) usize {
        return (self.header.length - @sizeOf(tables.Header)) / @sizeOf(u64);
    }

    pub fn getTablePointers(self: *const XSDT) []const u64 {
        const count = self.getTableCount();
        const ptr = @as([*]const u64, @ptrCast(@alignCast(@as([*]const u8, @ptrCast(self)) + @sizeOf(tables.Header))));
        return ptr[0..count];
    }
};

// Calculate checksum for ACPI tables
fn calculateChecksum(bytes: []const u8) u8 {
    var sum: u8 = 0;
    for (bytes) |byte| {
        sum +%= byte;
    }
    return sum;
}

// Validate any ACPI table with standard header
pub fn validateTable(header: *const tables.Header) tables.Error!void {
    const bytes = @as([*]const u8, @ptrCast(header))[0..header.length];
    if (calculateChecksum(bytes) != 0) {
        return tables.Error.InvalidChecksum;
    }
}

// Find RSDP in system memory (searches common locations)
pub fn findRSDP(rsdp_address: ?u64) ?*const RSDPDescriptor20 {
    // If we have a UEFI-provided address, try it first
    if (rsdp_address) |addr| {
        const ptr = @as(*const RSDPDescriptor20, @ptrFromInt(addr));
        ptr.validate() catch return null;
        return ptr;
    }

    // Otherwise search EBDA and BIOS ROM areas (legacy fallback)
    // Note: This is typically not needed with UEFI boot
    return null;
}

// Enumerate all tables from RSDT
pub fn enumerateRSDT(rsdt: *const RSDT, signature: []const u8, callback: fn (*const tables.Header) anyerror!void) !void {
    const pointers = rsdt.getTablePointers();

    for (pointers) |ptr| {
        const header = @as(*const tables.Header, @ptrFromInt(ptr));

        // Validate table before processing
        validateTable(header) catch continue;

        if (header.isSignature(signature)) {
            try callback(header);
        }
    }
}

// Enumerate all tables from XSDT
pub fn enumerateXSDT(xsdt: *const XSDT, signature: []const u8, callback: fn (*const tables.Header) anyerror!void) !void {
    const pointers = xsdt.getTablePointers();

    for (pointers) |ptr| {
        const header = @as(*const tables.Header, @ptrFromInt(ptr));

        // Validate table before processing
        validateTable(header) catch continue;

        if (header.isSignature(signature)) {
            try callback(header);
        }
    }
}
