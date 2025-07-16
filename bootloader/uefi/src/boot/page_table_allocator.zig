// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const boot_protocol = @import("shared").boot_protocol;
const serial = @import("../drivers/serial.zig");
const memory = @import("memory.zig");
const calculator = @import("page_table_calculator.zig");

pub const AllocatedPageTables = struct {
    pml4_addr: u64,
    pdpt_addr: u64,
    pd_base_addr: u64,
    pd_count: u32,
    pt_base_addr: u64,
    pt_count: u32,
    total_pages: u32,

    // For cleanup tracking
    allocation_base: [*]align(4096) u8,
};

// Allocate all page tables as one contiguous block
pub fn allocatePageTables(boot_services: *uefi.tables.BootServices, requirements: calculator.PageTableRequirements, allocations: *memory.AllocatedMemory) !AllocatedPageTables {
    const total_size = requirements.total_pages_needed * 4096;

    // Allocate as one contiguous block
    var base_addr: [*]align(4096) u8 = undefined;
    switch (boot_services.allocatePages(.allocate_any_pages, .boot_services_data, requirements.total_pages_needed, &base_addr)) {
        .success => {},
        else => |err| {
            serial.print("[UEFI] Failed to allocate page tables: {}\r\n", .{err}) catch {};
            return error.OutOfMemory;
        },
    }

    // Zero all pages
    @memset(base_addr[0..total_size], 0);

    // Calculate addresses within the block
    var current_addr = @intFromPtr(base_addr);

    const pml4_addr = current_addr;
    current_addr += 4096;

    const pdpt_addr = current_addr;
    current_addr += 4096;

    const pd_base = current_addr;
    current_addr += requirements.pd_tables_needed * 4096;

    const pt_base = current_addr;

    // Track allocation
    try allocations.add(@intFromPtr(base_addr), requirements.total_pages_needed);

    serial.print("[UEFI] Allocated page tables:\r\n", .{}) catch {};
    serial.print("  Base: 0x{x}\r\n", .{@intFromPtr(base_addr)}) catch {};
    serial.print("  PML4: 0x{x}\r\n", .{pml4_addr}) catch {};
    serial.print("  PDPT: 0x{x}\r\n", .{pdpt_addr}) catch {};
    serial.print("  PD tables: 0x{x} (count: {})\r\n", .{ pd_base, requirements.pd_tables_needed }) catch {};
    serial.print("  PT tables: 0x{x} (count: {})\r\n", .{ pt_base, requirements.pt_tables_needed }) catch {};

    return AllocatedPageTables{
        .pml4_addr = pml4_addr,
        .pdpt_addr = pdpt_addr,
        .pd_base_addr = pd_base,
        .pd_count = requirements.pd_tables_needed,
        .pt_base_addr = pt_base,
        .pt_count = requirements.pt_tables_needed,
        .total_pages = requirements.total_pages_needed,
        .allocation_base = base_addr,
    };
}
