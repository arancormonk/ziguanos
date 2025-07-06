// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");

// Import shared boot protocol
const boot_protocol = @import("shared");

// Re-export types from shared protocol
pub const UEFIBootInfo = boot_protocol.BootInfo;
pub const UEFIMemoryType = boot_protocol.MemoryType;
pub const UEFIMemoryDescriptor = boot_protocol.MemoryDescriptor;

fn processMemoryMap(uefi_info: *const UEFIBootInfo) void {
    const descriptors = @as([*]const UEFIMemoryDescriptor, @ptrFromInt(uefi_info.memory_map_addr));
    const count = uefi_info.memory_map_size / uefi_info.memory_map_descriptor_size;

    var total_memory: u64 = 0;
    var usable_memory: u64 = 0;

    serial.print("[UEFI] Processing {} memory descriptors\r\n", .{count});

    // Iterate through UEFI memory descriptors
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const desc_ptr = @as([*]const u8, @ptrCast(descriptors)) + (i * uefi_info.memory_map_descriptor_size);
        const desc = @as(*const UEFIMemoryDescriptor, @ptrCast(@alignCast(desc_ptr)));

        const size = desc.number_of_pages * 4096;
        total_memory += size;

        // Count usable memory
        switch (desc.type) {
            .Conventional, .LoaderCode, .LoaderData => {
                usable_memory += size;
            },
            else => {},
        }

        // Log significant memory regions
        if (desc.number_of_pages > 256) { // Only log regions > 1MB
            serial.print("  [{:0>16X}-{:0>16X}] {} ({} MB)\r\n", .{
                desc.physical_start,
                desc.physical_start + size - 1,
                desc.type,
                size / (1024 * 1024),
            });
        }
    }

    serial.print("[UEFI] Total memory: {} MB, Usable: {} MB\r\n", .{
        total_memory / (1024 * 1024),
        usable_memory / (1024 * 1024),
    });
}
