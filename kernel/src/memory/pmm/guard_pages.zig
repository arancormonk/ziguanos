// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Guard page management for memory protection

const serial = @import("../../drivers/serial.zig");
const secure_print = @import("../../lib/secure_print.zig");
const uefi_boot = @import("../../boot/uefi_boot.zig");
const runtime_info = @import("../../boot/runtime_info.zig");
const error_utils = @import("../../lib/error_utils.zig");

const PAGE_SIZE: u64 = 0x1000; // 4KB pages
const PAGES_PER_BITMAP: u64 = 64; // One u64 bitmap entry tracks 64 pages

var guard_page_violations: u64 = 0;

pub fn incrementViolations() void {
    guard_page_violations += 1;
}

pub fn getViolations() u64 {
    return guard_page_violations;
}

// Setup guard pages around critical memory regions
pub fn setupGuardPages(boot_info: *const uefi_boot.UEFIBootInfo, markPagesAsUsedFn: fn (u64, u64) void, reserved_pages: *u64, _: u64) void {
    serial.print("[PMM] Setting up guard pages around critical regions...\n", .{});

    // Guard pages around kernel - use physical addresses in PIE mode
    const info = runtime_info.getRuntimeInfo();
    const kernel_start = if (info.pie_mode)
        info.kernel_physical_base
    else
        boot_info.kernel_base;

    const kernel_size = boot_info.kernel_size;
    const kernel_end = kernel_start + kernel_size;

    // Add guard page before kernel (if possible)
    if (kernel_start >= PAGE_SIZE) {
        const guard_before = kernel_start - PAGE_SIZE;
        markPagesAsUsedFn(guard_before, 1);
        reserved_pages.* += 1;
        secure_print.printValue("  Guard page before kernel", guard_before);
    }

    // Add guard page after kernel
    const kernel_end_aligned = (kernel_end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    const guard_after = kernel_end_aligned;
    markPagesAsUsedFn(guard_after, 1);
    reserved_pages.* += 1;
    secure_print.printValue("  Guard page after kernel", guard_after);

    serial.print("[PMM] Guard pages setup completed\n", .{});
}

// Create a guard page at a specific address (for paging subsystem)
pub fn createGuardPage(addr: u64, memory_bitmap: []u64, total_pages: u64, free_pages: *u64) !void {
    if (addr % PAGE_SIZE != 0) {
        return error.MisalignedAddress;
    }

    const page_num = addr / PAGE_SIZE;

    // Validate page number
    if (page_num >= total_pages) {
        return error.PageNumberOutOfRange;
    }

    const bitmap_idx = page_num / PAGES_PER_BITMAP;
    const bit_idx = @as(u6, @truncate(page_num % PAGES_PER_BITMAP));

    if (bitmap_idx >= memory_bitmap.len) {
        return error.BitmapIndexOutOfRange;
    }

    // Mark the page as used (which makes it unavailable for allocation)
    memory_bitmap[bitmap_idx] |= (@as(u64, 1) << bit_idx);

    // If it was free, update free page count
    if (page_num * PAGE_SIZE < total_pages * PAGE_SIZE) {
        free_pages.* -= 1;
    }

    // serial.print("[PMM] Created guard page at: 0x{x:0>16}\n", .{addr});
}

// Add guard pages around a memory region
pub fn addGuardPagesAroundRegion(start: u64, size: u64, createGuardPageFn: fn (u64) anyerror!void) !void {
    secure_print.printRange("[PMM] Adding guard pages around region", start, start + size);

    // Guard page before region
    if (start >= PAGE_SIZE) {
        const guard_before = (start - PAGE_SIZE) & ~(PAGE_SIZE - 1);
        createGuardPageFn(guard_before) catch |err| {
            serial.print("[PMM] Warning: Could not create guard page before region: {s}\n", .{error_utils.errorToString(err)});
        };
    }

    // Guard page after region
    const end = start + size;
    const guard_after = (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    createGuardPageFn(guard_after) catch |err| {
        serial.print("[PMM] Warning: Could not create guard page after region: {s}\n", .{error_utils.errorToString(err)});
    };
}
