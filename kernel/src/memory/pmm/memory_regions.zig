// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Memory region management for sparse physical memory layouts
// This properly handles systems where RAM is not contiguous

const std = @import("std");
const uefi_boot = @import("../../boot/uefi_boot.zig");
const serial = @import("../../drivers/serial.zig");

const PAGE_SIZE: u64 = 0x1000;
const PAGES_PER_BITMAP: u64 = 64;
const MAX_REGIONS = 128; // Increased to handle more fragmented memory layouts

// Memory region descriptor
pub const MemoryRegion = struct {
    base: u64, // Physical base address
    size: u64, // Size in bytes
    pages: u64, // Number of pages
    bitmap_offset: usize, // Offset into global bitmap
    bitmap_size: usize, // Size needed for this region's bitmap (in u64s)
    is_usable: bool, // Whether this is usable RAM
};

// Global region state
var regions: [MAX_REGIONS]MemoryRegion = undefined;
var num_regions: usize = 0;
var total_bitmap_size: usize = 0;

// Initialize regions from UEFI memory map
pub fn init(boot_info: *const uefi_boot.UEFIBootInfo) !struct {
    bitmap_size_needed: usize,
    total_ram_pages: u64,
} {
    const memory_map = @as([*]const u8, @ptrFromInt(boot_info.memory_map_addr));
    const descriptor_count = boot_info.memory_map_size / boot_info.memory_map_descriptor_size;

    num_regions = 0;
    total_bitmap_size = 0;
    var total_ram_pages: u64 = 0;

    // Process memory descriptors and create regions
    var offset: usize = 0;
    for (0..descriptor_count) |_| {
        const descriptor = @as(*const uefi_boot.UEFIMemoryDescriptor, @ptrCast(@alignCast(&memory_map[offset])));

        // Check if this is RAM
        const is_ram = switch (descriptor.type) {
            .Conventional, .BootServicesCode, .BootServicesData, .LoaderCode, .LoaderData, .RuntimeServicesCode, .RuntimeServicesData => true,
            else => false,
        };

        if (is_ram and num_regions < MAX_REGIONS) {
            // Try to merge with previous region if adjacent
            if (num_regions > 0) {
                const prev = &regions[num_regions - 1];
                if (prev.base + prev.size == descriptor.physical_start) {
                    // Merge with previous region
                    prev.size += descriptor.number_of_pages * PAGE_SIZE;
                    prev.pages += descriptor.number_of_pages;

                    // Recalculate bitmap size for merged region
                    const new_bitmap_size = (prev.pages + PAGES_PER_BITMAP - 1) / PAGES_PER_BITMAP;
                    total_bitmap_size = total_bitmap_size - prev.bitmap_size + new_bitmap_size;
                    prev.bitmap_size = new_bitmap_size;

                    offset += boot_info.memory_map_descriptor_size;
                    continue;
                }
            }

            // Create new region
            const region = &regions[num_regions];
            region.base = descriptor.physical_start;
            region.size = descriptor.number_of_pages * PAGE_SIZE;
            region.pages = descriptor.number_of_pages;
            region.bitmap_offset = total_bitmap_size;
            region.bitmap_size = (region.pages + PAGES_PER_BITMAP - 1) / PAGES_PER_BITMAP;
            region.is_usable = (descriptor.type == .Conventional);

            total_bitmap_size += region.bitmap_size;
            total_ram_pages += region.pages;
            num_regions += 1;

            serial.println("[PMM] Region {}: 0x{x:0>16} - 0x{x:0>16} ({} MB)", .{
                num_regions - 1,
                region.base,
                region.base + region.size,
                region.size / (1024 * 1024),
            });
        }

        offset += boot_info.memory_map_descriptor_size;
    }

    serial.println("[PMM] Total regions: {}, bitmap size: {} u64s ({} KB)", .{
        num_regions,
        total_bitmap_size,
        (total_bitmap_size * @sizeOf(u64)) / 1024,
    });

    return .{
        .bitmap_size_needed = total_bitmap_size,
        .total_ram_pages = total_ram_pages,
    };
}

// Convert physical address to bitmap index
pub fn physicalToBitmapIndex(phys_addr: u64) ?struct {
    bitmap_idx: usize,
    bit_idx: u6,
} {
    // Find which region contains this address
    for (regions[0..num_regions]) |*region| {
        if (phys_addr >= region.base and phys_addr < region.base + region.size) {
            const offset_in_region = phys_addr - region.base;
            const page_in_region = offset_in_region / PAGE_SIZE;

            const bitmap_idx = region.bitmap_offset + (page_in_region / PAGES_PER_BITMAP);
            const bit_idx = @as(u6, @truncate(page_in_region % PAGES_PER_BITMAP));

            return .{
                .bitmap_idx = bitmap_idx,
                .bit_idx = bit_idx,
            };
        }
    }

    return null;
}

// Find region containing an address
pub fn findRegion(phys_addr: u64) ?*MemoryRegion {
    for (regions[0..num_regions]) |*region| {
        if (phys_addr >= region.base and phys_addr < region.base + region.size) {
            return region;
        }
    }
    return null;
}

// Get all regions
pub fn getRegions() []MemoryRegion {
    return regions[0..num_regions];
}

// Get required bitmap size
pub fn getBitmapSize() usize {
    return total_bitmap_size;
}
