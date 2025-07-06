// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../../drivers/serial.zig");
const secure_print = @import("../../lib/secure_print.zig");
const pmm = @import("../../memory/pmm.zig");
const constants = @import("constants.zig");

// Type for the unmap function that will be provided by main paging module
pub const UnmapPageFn = fn (virt_addr: u64) anyerror!void;

// Create a guard page at address
pub fn createGuardPageAt(addr: u64, unmapPageFn: UnmapPageFn) !void {
    // Ensure the page is unmapped
    try unmapPageFn(addr);

    // Also mark it as unavailable in the PMM
    try pmm.createGuardPage(addr);

    secure_print.printValue("[PAGING] Created guard page at virtual address", addr);
}

// Type for the createGuardPageAt function that will be used in addGuardPagesAroundVirtualRegion
pub const CreateGuardPageAtFn = fn (addr: u64) anyerror!void;

// Add guard pages around virtual region
pub fn addGuardPagesAroundVirtualRegion(start: u64, size: u64, createGuardPageAtFn: CreateGuardPageAtFn) !void {
    secure_print.printRange("[PAGING] Adding virtual guard pages around region", start, start + size);

    // Guard page before region
    if (start >= constants.PAGE_SIZE_4K) {
        const guard_before = (start - constants.PAGE_SIZE_4K) & ~(constants.PAGE_SIZE_4K - 1);
        createGuardPageAtFn(guard_before) catch |err| {
            serial.print("[PAGING] Warning: Could not create guard page before region: ", .{});
            serial.println("{s}", .{@errorName(err)});
        };
    }

    // Guard page after region
    const end = start + size;
    const guard_after = (end + constants.PAGE_SIZE_4K - 1) & ~(constants.PAGE_SIZE_4K - 1);
    createGuardPageAtFn(guard_after) catch |err| {
        serial.print("[PAGING] Warning: Could not create guard page after region: ", .{});
        serial.println("{s}", .{@errorName(err)});
    };
}
