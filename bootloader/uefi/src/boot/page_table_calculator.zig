// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const boot_protocol = @import("shared");
const serial = @import("../drivers/serial.zig");

pub const PageTableRequirements = struct {
    highest_physical_addr: u64,
    pd_tables_needed: u32, // For identity mapping all RAM
    pt_tables_needed: u32, // For kernel fine-grain mapping
    total_pages_needed: u32, // Total 4KB pages for all tables
};

// Analyze UEFI memory map to determine page table requirements
pub fn calculateRequirements(memory_map: []const u8, descriptor_size: usize) PageTableRequirements {
    var highest_addr: u64 = 0;
    const descriptor_count = memory_map.len / descriptor_size;

    // Find highest usable physical address
    var offset: usize = 0;
    var i: usize = 0;
    while (i < descriptor_count) : (i += 1) {
        const descriptor = @as(*const uefi.tables.MemoryDescriptor, @ptrCast(@alignCast(&memory_map[offset])));

        // Only consider usable memory types
        const mem_type = descriptor.type;
        if (mem_type == .conventional_memory or
            mem_type == .boot_services_code or
            mem_type == .boot_services_data or
            mem_type == .loader_code or
            mem_type == .loader_data)
        {
            const end_addr = descriptor.physical_start +
                (descriptor.number_of_pages * 4096);
            if (end_addr > highest_addr) {
                highest_addr = end_addr;
            }
        }
        offset += descriptor_size;
    }

    // Round up to next GB boundary
    const highest_gb = (highest_addr + (1 << 30) - 1) / (1 << 30);
    highest_addr = highest_gb * (1 << 30);

    // Calculate requirements
    // Each PD table maps 1GB, so we need highest_gb tables
    var pd_tables = @as(u32, @intCast(highest_gb));

    // CRITICAL: Ensure we have enough tables for MMIO regions
    // APIC is at 0xfee00000 (in 4th GB), so we need at least 4 PD tables
    if (pd_tables < 4) {
        pd_tables = 4;
        serial.print("  NOTE: Increasing PD tables to 4 for MMIO access\r\n", .{}) catch {};
    }

    // For kernel fine-grain mapping, assume we need 16 PT tables (32MB coverage)
    // This matches the current kernel implementation
    const pt_tables = 16;

    // Total pages: 1 PML4 + 1 PDPT + pd_tables + pt_tables
    const total_pages = 1 + 1 + pd_tables + pt_tables;

    serial.print("[UEFI] Page table requirements:\r\n", .{}) catch {};
    serial.print("  Highest physical: 0x{x} ({} GB)\r\n", .{ highest_addr, highest_gb }) catch {};
    serial.print("  PD tables needed: {}\r\n", .{pd_tables}) catch {};
    serial.print("  PT tables needed: {}\r\n", .{pt_tables}) catch {};
    serial.print("  Total pages: {}\r\n", .{total_pages}) catch {};

    return PageTableRequirements{
        .highest_physical_addr = highest_addr,
        .pd_tables_needed = pd_tables,
        .pt_tables_needed = pt_tables,
        .total_pages_needed = total_pages,
    };
}
