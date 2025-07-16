// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const uefi_globals = @import("uefi_globals.zig");
const serial = @import("../drivers/serial.zig");
const kernel_loader = @import("../boot/kernel_loader.zig");

// Memory map information returned by UEFI
pub const MemoryMap = struct {
    descriptors: [*]uefi.tables.MemoryDescriptor,
    size: usize,
    key: usize,
    descriptor_size: usize,
    descriptor_version: u32,
};

// Get the current memory map from UEFI
pub fn getMemoryMap() !MemoryMap {
    var map_size: usize = 0;
    var map_key: usize = undefined;
    var descriptor_size: usize = undefined;
    var descriptor_version: u32 = undefined;

    // Get required buffer size
    _ = uefi_globals.boot_services.getMemoryMap(&map_size, null, &map_key, &descriptor_size, &descriptor_version);

    // SECURITY: Check for integer overflow when adding extra space
    // We need extra space because memory map can change between calls
    const extra_descriptors: usize = 2;
    const extra_size = std.math.mul(usize, extra_descriptors, descriptor_size) catch {
        serial.print("[UEFI] ERROR: Integer overflow calculating extra memory map space\r\n", .{}) catch {};
        return error.IntegerOverflow;
    };

    // Allocate buffer with extra space
    map_size = std.math.add(usize, map_size, extra_size) catch {
        serial.print("[UEFI] ERROR: Integer overflow calculating total memory map size\r\n", .{}) catch {};
        return error.IntegerOverflow;
    };
    var buffer: [*]align(8) u8 = undefined;
    switch (uefi_globals.boot_services.allocatePool(.loader_data, map_size, &buffer)) {
        .success => {},
        else => return error.AllocationFailed,
    }

    // Get actual memory map
    switch (uefi_globals.boot_services.getMemoryMap(&map_size, @ptrCast(buffer), &map_key, &descriptor_size, &descriptor_version)) {
        .success => {},
        else => return error.MemoryMapFailed,
    }

    // Debug: log the memory map info
    serial.print("[UEFI] Memory map retrieved: size={}, descriptor_size={}, version={}\r\n", .{ map_size, descriptor_size, descriptor_version }) catch {};

    return MemoryMap{
        .descriptors = @ptrCast(@alignCast(buffer)),
        .size = map_size,
        .key = map_key,
        .descriptor_size = descriptor_size,
        .descriptor_version = descriptor_version,
    };
}

// Convert our MemoryMap to kernel_loader.MemoryMap format
pub fn convertToKernelLoaderFormat(memory_map: MemoryMap) kernel_loader.MemoryMap {
    return kernel_loader.MemoryMap{
        .descriptors = memory_map.descriptors,
        .size = memory_map.size,
        .descriptor_size = memory_map.descriptor_size,
        .descriptor_version = memory_map.descriptor_version,
    };
}
