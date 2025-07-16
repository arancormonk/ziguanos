// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Main ACPI interface for system configuration discovery

const std = @import("std");
const tables = @import("tables.zig");
const rsdp = @import("rsdp.zig");
const madt = @import("madt.zig");
const checksum = @import("checksum.zig");

const serial = @import("../../drivers/serial.zig");
const error_utils = @import("../../lib/error_utils.zig");

// ACPI subsystem state
pub const AcpiSystem = struct {
    rsdp_descriptor: ?*const rsdp.RSDPDescriptor20,
    rsdt: ?*const rsdp.RSDT,
    xsdt: ?*const rsdp.XSDT,
    madt_table: ?*const madt.MADT,
    system_topology: ?madt.SystemTopology,
    allocator: std.mem.Allocator,

    // Initialize ACPI subsystem with RSDP address from UEFI
    pub fn init(allocator: std.mem.Allocator, rsdp_address: ?u64) !AcpiSystem {
        var acpi = AcpiSystem{
            .rsdp_descriptor = null,
            .rsdt = null,
            .xsdt = null,
            .madt_table = null,
            .system_topology = null,
            .allocator = allocator,
        };

        // Find and validate RSDP
        acpi.rsdp_descriptor = rsdp.findRSDP(rsdp_address);
        if (acpi.rsdp_descriptor == null) {
            serial.println("ACPI: Failed to find valid RSDP at address 0x{x}", .{rsdp_address orelse 0});
            return tables.Error.InvalidAddress;
        }

        const rsdp_desc = acpi.rsdp_descriptor.?;
        serial.println("ACPI: Found RSDP at 0x{x}, revision {d}", .{ @intFromPtr(rsdp_desc), rsdp_desc.getRevision() });

        // Load RSDT or XSDT based on ACPI version
        if (rsdp_desc.isAcpi20() and rsdp_desc.xsdt_address != 0) {
            acpi.xsdt = @as(*const rsdp.XSDT, @ptrFromInt(rsdp_desc.xsdt_address));
            try checksum.validateTable(&acpi.xsdt.?.header);
            serial.println("ACPI: Using XSDT at 0x{x}", .{rsdp_desc.xsdt_address});
        } else if (rsdp_desc.first_part.rsdt_address != 0) {
            acpi.rsdt = @as(*const rsdp.RSDT, @ptrFromInt(rsdp_desc.first_part.rsdt_address));
            try checksum.validateTable(&acpi.rsdt.?.header);
            serial.println("ACPI: Using RSDT at 0x{x}", .{rsdp_desc.first_part.rsdt_address});
        } else {
            return tables.Error.InvalidAddress;
        }

        // Find and parse MADT
        try acpi.findMADT();

        return acpi;
    }

    // Find and parse the MADT table
    fn findMADT(self: *AcpiSystem) !void {
        if (self.xsdt) |xsdt| {
            try rsdp.enumerateXSDT(xsdt, tables.Signature.MADT, madtCallback);
        } else if (self.rsdt) |rsdt| {
            try rsdp.enumerateRSDT(rsdt, tables.Signature.MADT, madtCallback);
        }

        if (madt_found_table) |madt_table| {
            self.madt_table = @as(*const madt.MADT, @ptrCast(madt_table));
            serial.println("ACPI: Found MADT at 0x{x}", .{@intFromPtr(madt_table)});

            // Skip the quick scan - go directly to parsing

            // Parse system topology
            self.system_topology = madt.parseMADT(self.madt_table.?, self.allocator) catch |err| {
                serial.println("ACPI: Failed to parse MADT: {s}", .{error_utils.errorToString(err)});
                serial.println("ACPI: Continuing without full topology information", .{});
                // Don't return error - let the system continue
                return;
            };

            const topology = &self.system_topology.?;
            serial.println("ACPI: System has {d} CPUs, BSP APIC ID: {d}", .{ topology.total_cpus, topology.boot_cpu_id });
            serial.println("ACPI: Local APIC at 0x{x}, Legacy PIC: {}", .{ topology.local_apic_address, topology.has_legacy_pic });

            // Reset global state
            madt_found_table = null;
        } else {
            serial.println("ACPI: MADT table not found", .{});
            return tables.Error.TableNotFound;
        }
    }

    // Get system topology information
    pub fn getTopology(self: *const AcpiSystem) ?*const madt.SystemTopology {
        if (self.system_topology) |_| {
            return &self.system_topology.?;
        }
        return null;
    }

    // Find a specific ACPI table by signature
    pub fn findTable(self: *const AcpiSystem, signature: []const u8) !?*const tables.Header {
        table_search_result = null;
        table_search_signature = signature;

        if (self.xsdt) |xsdt| {
            try rsdp.enumerateXSDT(xsdt, signature, findTableCallback);
        } else if (self.rsdt) |rsdt| {
            try rsdp.enumerateRSDT(rsdt, signature, findTableCallback);
        }

        return table_search_result;
    }

    // Cleanup ACPI resources
    pub fn deinit(self: *AcpiSystem) void {
        if (self.system_topology) |topology| {
            self.allocator.free(topology.processors);
            self.allocator.free(topology.io_apics);
        }
    }
};

// Global state for callbacks (since we can't capture in function pointers)
var madt_found_table: ?*const tables.Header = null;
var table_search_result: ?*const tables.Header = null;
var table_search_signature: []const u8 = "";

fn madtCallback(header: *const tables.Header) !void {
    madt_found_table = header;
}

fn findTableCallback(header: *const tables.Header) !void {
    if (header.isSignature(table_search_signature)) {
        table_search_result = header;
    }
}

// Global ACPI system instance
var acpi_system: ?AcpiSystem = null;

// Initialize the global ACPI subsystem
pub fn initSystem(allocator: std.mem.Allocator, rsdp_address: ?u64) !void {
    if (acpi_system != null) {
        serial.println("ACPI: System already initialized", .{});
        return;
    }

    acpi_system = try AcpiSystem.init(allocator, rsdp_address);
}

// Get the global ACPI system instance
pub fn getSystem() ?*AcpiSystem {
    if (acpi_system) |*system| {
        return system;
    }
    return null;
}

// Shutdown the ACPI subsystem
pub fn shutdown() void {
    if (acpi_system) |*system| {
        system.deinit();
        acpi_system = null;
    }
}
