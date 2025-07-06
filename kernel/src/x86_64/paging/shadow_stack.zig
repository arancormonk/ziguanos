// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const constants = @import("constants.zig");
const pku = @import("pku.zig");

// Shadow stack page bits
pub const PAGE_SHADOW_STACK_DIRTY: u64 = 1 << 6;
pub const PAGE_SHADOW_STACK_ACCESSED: u64 = 1 << 5;

// Type for the map function that will be provided by main paging module
pub const MapPageRawFn = fn (virt_addr: u64, entry: u64) anyerror!void;

// Shadow stack write window for controlled updates
var shadow_stack_write_window: ?u64 = null;
var shadow_stack_write_window_size: usize = 0;

// Map a page as shadow stack (read-only for security)
// According to Intel SDM, shadow stack pages must have:
// - P (bit 0) = 0 (not present)
// - R/W (bit 1) = 1 (writable for shadow stack operations)
// However, for security we map them as read-only to prevent unauthorized writes
pub fn mapShadowStackPage(virt_addr: u64, phys_addr: u64, mapPageRawFn: MapPageRawFn) !void {
    // Shadow stack page format per Intel SDM:
    // Bit 0 (P) = 0: Not present
    // Bit 1 (R/W) = 0: Read-only (for security - prevents kernel writes)
    // Bits 11:3, 51:12: Physical address
    // Bit 5 (A): Accessed
    // Bit 6 (D): Dirty
    // Bit 63 (XD): Must be 0 (shadow stack pages are not executable by design)

    // Ensure physical address is page-aligned
    if ((phys_addr & 0xFFF) != 0) {
        return error.UnalignedAddress;
    }

    // Create shadow stack page entry: P=0, RW=0 (read-only), physical address
    // This prevents kernel from accidentally writing to shadow stack pages
    const shadow_stack_entry = (phys_addr & constants.PHYS_ADDR_MASK);

    // Apply shadow stack protection key for additional security
    const shadow_stack_entry_with_pku = pku.createPageEntryWithKey(0, shadow_stack_entry, pku.ProtectionKeys.shadow_stack);

    // Map the page with special shadow stack format (read-only) and PKU protection
    try mapPageRawFn(virt_addr, shadow_stack_entry_with_pku);
}

// Map a write window for controlled shadow stack updates
pub fn mapShadowStackWriteWindow(shadow_stack_base: u64, size: usize, mapPageRawFn: MapPageRawFn) !u64 {
    const pages = (size + constants.PAGE_SIZE - 1) / constants.PAGE_SIZE;

    // Allocate virtual address space for write window
    // In a real implementation, this would use a virtual memory allocator
    // For now, use a simple offset from the shadow stack base
    const write_window_virt = shadow_stack_base + 0x100000; // 1MB offset

    // Map the same physical pages as writable in the write window
    var i: usize = 0;
    while (i < pages) : (i += 1) {
        const phys_addr = shadow_stack_base + i * constants.PAGE_SIZE;
        const virt_addr = write_window_virt + i * constants.PAGE_SIZE;

        // Map as normal writable page for controlled updates
        const writable_entry = (phys_addr & constants.PHYS_ADDR_MASK) |
            constants.PAGE_PRESENT |
            constants.PAGE_WRITABLE |
            constants.PAGE_NO_EXECUTE;

        try mapPageRawFn(virt_addr, writable_entry);
    }

    shadow_stack_write_window = write_window_virt;
    shadow_stack_write_window_size = size;

    return write_window_virt;
}

// Get write window address for controlled shadow stack updates
pub fn getShadowStackWriteWindow() ?u64 {
    return shadow_stack_write_window;
}

// Safely update shadow stack via write window
pub fn updateShadowStackSafely(offset: usize, value: u64) !void {
    const write_window = shadow_stack_write_window orelse return error.NoWriteWindow;

    if (offset + @sizeOf(u64) > shadow_stack_write_window_size) {
        return error.WriteOutOfBounds;
    }

    const write_ptr = @as(*u64, @ptrFromInt(write_window + offset));
    write_ptr.* = value;
}
