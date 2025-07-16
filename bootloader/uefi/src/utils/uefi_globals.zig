// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;

// Global UEFI allocator that will be initialized at runtime
pub var uefi_allocator: std.mem.Allocator = undefined;

// Boot services pointer for UEFI operations
pub var boot_services: *uefi.tables.BootServices = undefined;

// System table pointer for UEFI operations
pub var system_table: *uefi.tables.SystemTable = undefined;

// Initialize all global UEFI state
pub fn init(sys_table: *uefi.tables.SystemTable) void {
    system_table = sys_table;
    boot_services = sys_table.boot_services.?;
    uefi_allocator = uefi.pool_allocator;
}
