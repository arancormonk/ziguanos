// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Reserved Regions Tracker for Physical Memory Manager
// Tracks all non-conventional memory regions from UEFI to ensure safe allocation

const std = @import("std");
const serial = @import("../../drivers/serial.zig");
const uefi_boot = @import("../../boot/uefi_boot.zig");
const runtime_info = @import("../../boot/runtime_info.zig");

// Maximum number of reserved regions we can track
const MAX_RESERVED_REGIONS = 256;

// Reserved region types
pub const RegionType = enum {
    UEFI_RESERVED, // Generic UEFI reserved memory
    UEFI_RUNTIME_SERVICES, // Runtime services code/data
    UEFI_ACPI, // ACPI tables
    UEFI_MMIO, // Memory-mapped I/O
    UEFI_BOOT_SERVICES, // Boot services (reclaimable after ExitBootServices)
    KERNEL_CODE, // Kernel code/data
    KERNEL_STACK, // Kernel stack
    PAGE_TABLES, // Page table structures
    PMM_BITMAP, // PMM bitmap itself
    GUARD_PAGE, // Guard pages for security
    AP_TRAMPOLINE, // AP boot trampoline
    LEGACY_RESERVED, // Legacy BIOS areas (below 1MB)

    pub fn toString(self: RegionType) []const u8 {
        return switch (self) {
            .UEFI_RESERVED => "UEFI Reserved",
            .UEFI_RUNTIME_SERVICES => "UEFI Runtime Services",
            .UEFI_ACPI => "UEFI ACPI",
            .UEFI_MMIO => "UEFI MMIO",
            .UEFI_BOOT_SERVICES => "UEFI Boot Services",
            .KERNEL_CODE => "Kernel Code",
            .KERNEL_STACK => "Kernel Stack",
            .PAGE_TABLES => "Page Tables",
            .PMM_BITMAP => "PMM Bitmap",
            .GUARD_PAGE => "Guard Page",
            .AP_TRAMPOLINE => "AP Trampoline",
            .LEGACY_RESERVED => "Legacy Reserved",
        };
    }
};

// Reserved memory region
pub const ReservedRegion = struct {
    start: u64,
    end: u64, // Exclusive end address
    region_type: RegionType,
    reclaimable: bool, // Can be reclaimed later (e.g., BootServices after ExitBootServices)
    description: [64]u8, // Human-readable description

    pub fn overlaps(self: *const ReservedRegion, addr: u64, size: u64) bool {
        const region_end = addr + size;
        return !(region_end <= self.start or addr >= self.end);
    }

    pub fn contains(self: *const ReservedRegion, addr: u64) bool {
        return addr >= self.start and addr < self.end;
    }
};

// Reserved regions tracker
pub const ReservedRegionsTracker = struct {
    regions: [MAX_RESERVED_REGIONS]ReservedRegion = undefined,
    count: usize = 0,
    boot_services_exited: bool = false,

    // Initialize the tracker from UEFI memory map
    pub fn init(self: *ReservedRegionsTracker, boot_info: *const uefi_boot.UEFIBootInfo) void {
        self.count = 0;
        self.boot_services_exited = false;

        serial.print("[Reserved] Initializing reserved regions tracker...\n", .{});

        // First, add legacy reserved regions (below 1MB)
        self.addRegion(0, 0x100000, .LEGACY_RESERVED, false, "Legacy BIOS Area") catch |err| {
            serial.print("[Reserved] Failed to add legacy region: {}\n", .{err});
        };

        // Add AP trampoline region
        self.addRegion(0x8000, 0x9000, .AP_TRAMPOLINE, false, "AP Boot Trampoline") catch |err| {
            serial.print("[Reserved] Failed to add AP trampoline: {}\n", .{err});
        };

        // Process UEFI memory map
        if (boot_info.memory_map_addr == 0 or boot_info.memory_map_descriptor_size == 0) {
            serial.print("[Reserved] ERROR: Invalid UEFI memory map\n", .{});
            return;
        }

        const memory_map = @as([*]const u8, @ptrFromInt(boot_info.memory_map_addr));
        const descriptor_count = boot_info.memory_map_size / boot_info.memory_map_descriptor_size;

        serial.print("[Reserved] Processing {} UEFI memory descriptors\n", .{descriptor_count});

        var offset: usize = 0;
        for (0..descriptor_count) |_| {
            const descriptor = @as(*const uefi_boot.UEFIMemoryDescriptor, @ptrCast(@alignCast(&memory_map[offset])));

            // Track non-conventional memory regions
            switch (descriptor.type) {
                .Conventional => {
                    // Skip conventional memory - it's available for allocation
                },
                .BootServicesCode, .BootServicesData => {
                    // Boot services memory - reclaimable after ExitBootServices
                    const end_addr = descriptor.physical_start + (descriptor.number_of_pages * 0x1000);

                    // Debug: Log boot services regions around 8MB
                    if (descriptor.physical_start <= 0x900000 and end_addr >= 0x800000) {
                        serial.print("[Reserved] Boot services region near 8MB: 0x{x:0>16} - 0x{x:0>16} ({} pages)\n", .{
                            descriptor.physical_start,
                            end_addr,
                            descriptor.number_of_pages,
                        });
                    }

                    self.addRegion(descriptor.physical_start, end_addr, .UEFI_BOOT_SERVICES, true, // Reclaimable
                        "UEFI Boot Services") catch |err| {
                        serial.print("[Reserved] Failed to add boot services region: {}\n", .{err});
                    };
                },
                .RuntimeServicesCode, .RuntimeServicesData => {
                    // Runtime services - never reclaimable
                    const end_addr = descriptor.physical_start + (descriptor.number_of_pages * 0x1000);
                    self.addRegion(descriptor.physical_start, end_addr, .UEFI_RUNTIME_SERVICES, false, "UEFI Runtime Services") catch |err| {
                        serial.print("[Reserved] Failed to add runtime services region: {}\n", .{err});
                    };
                },
                .AcpiReclaim, .AcpiNvs => {
                    // ACPI tables
                    const end_addr = descriptor.physical_start + (descriptor.number_of_pages * 0x1000);
                    self.addRegion(descriptor.physical_start, end_addr, .UEFI_ACPI, descriptor.type == .AcpiReclaim, // AcpiReclaim can be reclaimed
                        "ACPI Tables") catch |err| {
                        serial.print("[Reserved] Failed to add ACPI region: {}\n", .{err});
                    };
                },
                .MemoryMappedIo, .MemoryMappedIoPortSpace => {
                    // MMIO regions
                    const end_addr = descriptor.physical_start + (descriptor.number_of_pages * 0x1000);
                    self.addRegion(descriptor.physical_start, end_addr, .UEFI_MMIO, false, "Memory Mapped I/O") catch |err| {
                        serial.print("[Reserved] Failed to add MMIO region: {}\n", .{err});
                    };
                },
                else => {
                    // Other reserved types
                    const end_addr = descriptor.physical_start + (descriptor.number_of_pages * 0x1000);
                    self.addRegion(descriptor.physical_start, end_addr, .UEFI_RESERVED, false, "UEFI Reserved") catch |err| {
                        serial.print("[Reserved] Failed to add reserved region: {}\n", .{err});
                    };
                },
            }

            offset += boot_info.memory_map_descriptor_size;
        }

        // Add kernel regions
        const info = runtime_info.getRuntimeInfo();
        const kernel_base = if (info.pie_mode) info.kernel_physical_base else boot_info.kernel_base;
        const kernel_end = kernel_base + boot_info.kernel_size;

        self.addRegion(kernel_base, kernel_end, .KERNEL_CODE, false, "Kernel Code/Data") catch |err| {
            serial.print("[Reserved] Failed to add kernel region: {}\n", .{err});
        };

        serial.print("[Reserved] Initialized with {} reserved regions\n", .{self.count});

        // Report summary
        self.reportSummary();
    }

    // Add a reserved region
    pub fn addRegion(self: *ReservedRegionsTracker, start: u64, end: u64, region_type: RegionType, reclaimable: bool, description: []const u8) !void {
        if (self.count >= MAX_RESERVED_REGIONS) {
            return error.TooManyRegions;
        }

        if (end <= start) {
            return error.InvalidRegion;
        }

        // Check for overlaps with existing regions
        for (self.regions[0..self.count]) |*existing| {
            if (existing.overlaps(start, end - start)) {
                // Merge overlapping regions if they're the same type
                if (existing.region_type == region_type) {
                    existing.start = @min(existing.start, start);
                    existing.end = @max(existing.end, end);
                    return;
                }
            }
        }

        // Add new region
        var region = &self.regions[self.count];
        region.start = start;
        region.end = end;
        region.region_type = region_type;
        region.reclaimable = reclaimable;

        // Copy description
        const desc_len = @min(description.len, region.description.len - 1);
        @memcpy(region.description[0..desc_len], description[0..desc_len]);
        region.description[desc_len] = 0;

        self.count += 1;
    }

    // Check if an address range is reserved
    pub fn isReserved(self: *const ReservedRegionsTracker, addr: u64, size: u64) bool {
        for (self.regions[0..self.count]) |*region| {
            // Skip reclaimable regions if boot services have exited
            if (region.reclaimable and self.boot_services_exited) {
                continue;
            }

            if (region.overlaps(addr, size)) {
                return true;
            }
        }
        return false;
    }

    // Check if a specific address is in a reserved region
    pub fn getRegionType(self: *const ReservedRegionsTracker, addr: u64) ?RegionType {
        for (self.regions[0..self.count]) |*region| {
            // Skip reclaimable regions if boot services have exited
            if (region.reclaimable and self.boot_services_exited) {
                continue;
            }

            if (region.contains(addr)) {
                return region.region_type;
            }
        }
        return null;
    }

    // Mark boot services as exited (makes boot services memory available)
    pub fn markBootServicesExited(self: *ReservedRegionsTracker) void {
        self.boot_services_exited = true;
        serial.print("[Reserved] Boot services marked as exited - reclaimable memory now available\n", .{});

        // Count how much memory becomes available
        var reclaimed_pages: u64 = 0;
        for (self.regions[0..self.count]) |*region| {
            if (region.reclaimable) {
                const pages = (region.end - region.start) / 0x1000;
                reclaimed_pages += pages;
            }
        }

        const reclaimed_mb = (reclaimed_pages * 0x1000) / (1024 * 1024);
        serial.print("[Reserved] {} MB of boot services memory now reclaimable\n", .{reclaimed_mb});
    }

    // Get boot services regions for manual reclaim
    pub fn getReclaimableRegions(self: *const ReservedRegionsTracker, out_regions: []ReservedRegion) usize {
        var count: usize = 0;
        for (self.regions[0..self.count]) |*region| {
            if (region.reclaimable and self.boot_services_exited) {
                if (count < out_regions.len) {
                    out_regions[count] = region.*;
                    count += 1;
                }
            }
        }
        return count;
    }

    // Report summary of reserved regions
    pub fn reportSummary(self: *const ReservedRegionsTracker) void {
        serial.print("[Reserved] Memory regions summary:\n", .{});

        // Group by type
        const enum_field_count = @typeInfo(RegionType).@"enum".fields.len;
        var type_counts = [_]u32{0} ** enum_field_count;
        var type_sizes = [_]u64{0} ** enum_field_count;

        for (self.regions[0..self.count]) |*region| {
            const type_index = @intFromEnum(region.region_type);
            type_counts[type_index] += 1;
            type_sizes[type_index] += region.end - region.start;
        }

        // Report each type
        inline for (@typeInfo(RegionType).@"enum".fields, 0..) |_, i| {
            if (type_counts[i] > 0) {
                const region_type: RegionType = @enumFromInt(i);
                const size_mb = type_sizes[i] / (1024 * 1024);
                serial.print("  {s}: {} regions, {} MB\n", .{
                    region_type.toString(),
                    type_counts[i],
                    size_mb,
                });
            }
        }

        // Report total
        var total_reserved: u64 = 0;
        var reclaimable: u64 = 0;

        for (self.regions[0..self.count]) |*region| {
            const size = region.end - region.start;
            total_reserved += size;
            if (region.reclaimable) {
                reclaimable += size;
            }
        }

        const total_mb = total_reserved / (1024 * 1024);
        const reclaimable_mb = reclaimable / (1024 * 1024);

        serial.print("[Reserved] Total reserved: {} MB ({} MB reclaimable)\n", .{
            total_mb,
            reclaimable_mb,
        });
    }

    // Debug: Print detailed region list
    pub fn printDetailedList(self: *const ReservedRegionsTracker) void {
        serial.print("[Reserved] Detailed region list:\n", .{});

        for (self.regions[0..self.count]) |*region| {
            const size_kb = (region.end - region.start) / 1024;
            serial.print("  [0x{x:0>16} - 0x{x:0>16}] {} KB, {s}{s}\n", .{
                region.start,
                region.end,
                size_kb,
                region.region_type.toString(),
                if (region.reclaimable) " (reclaimable)" else "",
            });
        }
    }
};

// Global reserved regions tracker
var reserved_tracker: ReservedRegionsTracker = .{};

// Initialize the global tracker
pub fn init(boot_info: *const uefi_boot.UEFIBootInfo) void {
    reserved_tracker.init(boot_info);
}

// Check if a region is reserved
pub fn isReserved(addr: u64, size: u64) bool {
    return reserved_tracker.isReserved(addr, size);
}

// Get the type of region at an address
pub fn getRegionType(addr: u64) ?RegionType {
    return reserved_tracker.getRegionType(addr);
}

// Mark boot services as exited
pub fn markBootServicesExited() void {
    reserved_tracker.markBootServicesExited();
}

// Get the global tracker (for advanced operations)
pub fn getTracker() *ReservedRegionsTracker {
    return &reserved_tracker;
}

// Get reclaimable regions for manual boot services reclaim
pub fn getReclaimableRegions(out_regions: []ReservedRegion) usize {
    return reserved_tracker.getReclaimableRegions(out_regions);
}
