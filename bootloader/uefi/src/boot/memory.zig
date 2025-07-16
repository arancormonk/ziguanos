// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Memory allocation tracking and cleanup utilities
const std = @import("std");
const uefi = std.os.uefi;
const serial = @import("../drivers/serial.zig");
const kernel_types = @import("kernel_types.zig");
const vmm = @import("vmm.zig");

// Structure to track allocated memory for cleanup
pub const AllocatedMemory = struct {
    kernel_buffer: ?[*]align(4096) u8 = null,
    kernel_pages: usize = 0,
    segments: [32]kernel_types.AllocatedSegment = [_]kernel_types.AllocatedSegment{.{}} ** 32,
    segment_count: usize = 0,
    // PIE support: are we using identity mapping or dynamic allocation?
    use_identity_mapping: bool = true,
    // Virtual memory manager for PIE mode
    vmm_instance: ?vmm.VirtualMemoryManager = null,
    // Contiguous allocation for PIE kernels with KASLR
    contiguous_allocation: ?[*]align(4096) u8 = null,
    contiguous_pages: usize = 0,

    // Add a new allocation to track
    pub fn add(self: *AllocatedMemory, addr: u64, pages: usize) !void {
        if (self.segment_count >= self.segments.len) {
            return error.TooManyAllocations;
        }
        self.segments[self.segment_count] = kernel_types.AllocatedSegment{
            .addr = addr,
            .pages = pages,
            .allocated = true,
            .virtual_addr = addr,
            .physical_addr = addr,
            .kaslr_offset = 0,
        };
        self.segment_count += 1;
    }
};

// Clean up all allocated memory during kernel loading
pub fn cleanupAllocations(boot_services: *uefi.tables.BootServices, allocations: *AllocatedMemory) void {
    // In PIE mode, we can't free segments as they contain the actual kernel code!
    if (allocations.use_identity_mapping) {
        // Free contiguous allocation if used
        if (allocations.contiguous_allocation) |addr| {
            _ = boot_services.freePages(addr, allocations.contiguous_pages);
            serial.print("[UEFI] Freed contiguous allocation at 0x{X} ({} pages)\r\n", .{ @intFromPtr(addr), allocations.contiguous_pages }) catch {};
        } else {
            // Free segment allocations in reverse order (LIFO) - only for identity mapped mode
            var i: usize = allocations.segment_count;
            while (i > 0) {
                i -= 1;
                if (allocations.segments[i].allocated) {
                    const segment_addr = @as([*]align(4096) u8, @ptrFromInt(allocations.segments[i].addr));
                    _ = boot_services.freePages(segment_addr, allocations.segments[i].pages);
                    serial.print("[UEFI] Freed segment at 0x{X} ({} pages)\r\n", .{ allocations.segments[i].addr, allocations.segments[i].pages }) catch {};
                }
            }
        }
    } else {
        serial.print("[UEFI] Keeping kernel segments for PIE mode (not freeing)\r\n", .{}) catch {};
    }

    // Free kernel buffer (the ELF file loaded from disk)
    if (allocations.kernel_buffer) |buffer| {
        _ = boot_services.freePages(buffer, allocations.kernel_pages);
        serial.print("[UEFI] Freed kernel buffer ({} pages)\r\n", .{allocations.kernel_pages}) catch {};
    }

    // Cleanup VMM if initialized and not used for PIE
    // VMM will be needed after boot services exit for PIE mode
    if (allocations.vmm_instance) |*virtual_mm| {
        if (allocations.use_identity_mapping) {
            virtual_mm.cleanup();
            serial.print("[UEFI] Freed VMM page tables\r\n", .{}) catch {};
        } else {
            serial.print("[UEFI] Keeping VMM page tables for PIE mode\r\n", .{}) catch {};
        }
    }
}

// Calculate the number of pages needed for a given size
pub fn calculatePages(size: usize) usize {
    return (size + 4095) / 4096;
}

// Allocate memory with proper alignment and tracking
pub fn allocateMemory(boot_services: *uefi.tables.BootServices, allocations: *AllocatedMemory, size: usize, memory_type: uefi.tables.MemoryType) !*anyopaque {
    const pages = calculatePages(size);

    var buffer: [*]align(4096) u8 = undefined;
    switch (boot_services.allocatePages(.allocate_any_pages, memory_type, pages, &buffer)) {
        .success => {},
        else => return error.OutOfMemory,
    }

    // Track the allocation
    if (allocations.segment_count < allocations.segments.len) {
        allocations.segments[allocations.segment_count] = kernel_types.AllocatedSegment{
            .addr = @intFromPtr(buffer),
            .pages = pages,
            .allocated = true,
            .virtual_addr = @intFromPtr(buffer),
            .physical_addr = @intFromPtr(buffer),
            .kaslr_offset = 0,
        };
        allocations.segment_count += 1;
    }

    return buffer;
}

// Free a previously allocated memory block
pub fn freeMemory(boot_services: *uefi.tables.BootServices, allocations: *AllocatedMemory, address: *anyopaque) void {
    const addr = @intFromPtr(address);

    // Find the allocation in our tracking
    for (allocations.segments[0..allocations.segment_count], 0..) |segment, i| {
        if (segment.virtual_address == addr) {
            // Free the memory
            const pages = calculatePages(segment.allocated_size);
            const buffer = @as([*]align(4096) u8, @ptrFromInt(addr));
            _ = boot_services.freePages(buffer, pages);

            // Remove from tracking (shift remaining elements)
            var j = i;
            while (j < allocations.segment_count - 1) {
                allocations.segments[j] = allocations.segments[j + 1];
                j += 1;
            }
            allocations.segment_count -= 1;
            return;
        }
    }

    // If not found in tracking, issue a warning
    serial.print("[MEMORY] Warning: Attempted to free untracked memory at 0x{X}\r\n", .{addr}) catch {};
}

// Check if an address is within the allocated memory range
pub fn isAddressAllocated(allocations: *const AllocatedMemory, address: u64) bool {
    for (allocations.segments[0..allocations.segment_count]) |segment| {
        if (address >= segment.virtual_address and address < segment.virtual_address + segment.size) {
            return true;
        }
    }
    return false;
}

// Get memory statistics
pub fn getMemoryStats(allocations: *const AllocatedMemory) struct {
    total_allocations: usize,
    total_size: usize,
    total_pages: usize,
} {
    var total_size: usize = 0;
    var total_pages: usize = 0;

    for (allocations.segments[0..allocations.segment_count]) |segment| {
        total_size += segment.size;
        total_pages += calculatePages(segment.size);
    }

    if (allocations.kernel_buffer != null) {
        total_size += allocations.kernel_pages * 4096;
        total_pages += allocations.kernel_pages;
    }

    if (allocations.contiguous_allocation != null) {
        total_size += allocations.contiguous_pages * 4096;
        total_pages += allocations.contiguous_pages;
    }

    return .{
        .total_allocations = allocations.segment_count,
        .total_size = total_size,
        .total_pages = total_pages,
    };
}
