// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../../drivers/serial.zig");
const cpuid = @import("../cpuid.zig");
const error_utils = @import("../../lib/error_utils.zig");

// CR4 bit for LA57
const CR4_LA57: u64 = 1 << 12;

// State tracking
pub var enabled: bool = false;

// Enable 5-level paging
pub fn enable() !void {
    const features = cpuid.getFeatures();
    if (!features.la57) {
        serial.println("[PAGING] LA57 not supported by CPU", .{});
        return error.LA57NotSupported;
    }

    // Set CR4.LA57 bit (bit 12)
    var cr4 = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );

    cr4 |= CR4_LA57;

    asm volatile ("mov %[value], %%cr4"
        :
        : [value] "r" (cr4),
        : "memory"
    );

    enabled = true;
    serial.println("[PAGING] LA57 enabled - 5-level paging active", .{});
}

// Get table index for a given virtual address and level
pub fn getTableIndex(virt_addr: u64, level: u8) u16 {
    var shift: u6 = 0;

    if (enabled) {
        shift = switch (level) {
            5 => 48, // PML5
            4 => 39, // PML4
            3 => 30, // PDPT
            2 => 21, // PD
            1 => 12, // PT
            else => 0,
        };
    } else {
        shift = switch (level) {
            4 => 39, // PML4
            3 => 30, // PDPT
            2 => 21, // PD
            1 => 12, // PT
            else => 0,
        };
    }

    return @truncate((virt_addr >> shift) & 0x1FF);
}

// Test LA57 functionality
pub fn testLA57() void {
    serial.println("[PAGING] Testing 5-level paging (LA57) support...", .{});

    const features = cpuid.getFeatures();

    // Test 1: Check CPU support
    serial.print("  LA57 supported by CPU: ", .{});
    serial.println("{s}", .{if (features.la57) "Yes" else "No"});

    if (!features.la57) {
        serial.println("  Skipping LA57 tests - not supported by CPU", .{});
        return;
    }

    // Test 2: Test getTableIndex with LA57 disabled (4-level paging)
    serial.println("  Testing getTableIndex with 4-level paging:", .{});
    enabled = false;

    // Test address: 0x0000_7FFF_FFFF_F000 (highest canonical address in 4-level)
    const test_addr_4level: u64 = 0x0000_7FFF_FFFF_F000;
    const pml4_idx_4level = getTableIndex(test_addr_4level, 4);
    const pdpt_idx_4level = getTableIndex(test_addr_4level, 3);
    const pd_idx_4level = getTableIndex(test_addr_4level, 2);
    const pt_idx_4level = getTableIndex(test_addr_4level, 1);

    serial.println("    Address: 0x{x:0>16}", .{test_addr_4level});
    serial.print("    PML4 index: ", .{});
    serial.print("0x{x:0>16}", .{pml4_idx_4level});
    serial.print(" (expected 0xFF)", .{});
    serial.println("", .{});
    serial.print("    PDPT index: ", .{});
    serial.print("0x{x:0>16}", .{pdpt_idx_4level});
    serial.print(" (expected 0x1FF)", .{});
    serial.println("", .{});
    serial.print("    PD index: ", .{});
    serial.print("0x{x:0>16}", .{pd_idx_4level});
    serial.print(" (expected 0x1FF)", .{});
    serial.println("", .{});
    serial.print("    PT index: ", .{});
    serial.print("0x{x:0>16}", .{pt_idx_4level});
    serial.print(" (expected 0x1FF)", .{});
    serial.println("", .{});

    // Test 3: Enable LA57 and test getTableIndex with 5-level paging
    serial.println("  Testing LA57 enable and getTableIndex with 5-level paging:", .{});

    // Try to enable LA57
    enable() catch |err| {
        serial.print("    Failed to enable LA57: ", .{});
        serial.println("{s}", .{error_utils.errorToString(err)});
        return;
    };

    // Test address: 0x00FF_FFFF_FFFF_F000 (uses PML5)
    const test_addr_5level: u64 = 0x00FF_FFFF_FFFF_F000;
    const pml5_idx = getTableIndex(test_addr_5level, 5);
    const pml4_idx_5level = getTableIndex(test_addr_5level, 4);
    const pdpt_idx_5level = getTableIndex(test_addr_5level, 3);
    const pd_idx_5level = getTableIndex(test_addr_5level, 2);
    const pt_idx_5level = getTableIndex(test_addr_5level, 1);

    serial.println("    Address: 0x{x:0>16}", .{test_addr_5level});
    serial.print("    PML5 index: ", .{});
    serial.print("0x{x:0>16}", .{pml5_idx});
    serial.print(" (expected 0x1)", .{});
    serial.println("", .{});
    serial.print("    PML4 index: ", .{});
    serial.print("0x{x:0>16}", .{pml4_idx_5level});
    serial.print(" (expected 0x1FF)", .{});
    serial.println("", .{});
    serial.print("    PDPT index: ", .{});
    serial.print("0x{x:0>16}", .{pdpt_idx_5level});
    serial.print(" (expected 0x1FF)", .{});
    serial.println("", .{});
    serial.print("    PD index: ", .{});
    serial.print("0x{x:0>16}", .{pd_idx_5level});
    serial.print(" (expected 0x1FF)", .{});
    serial.println("", .{});
    serial.print("    PT index: ", .{});
    serial.print("0x{x:0>16}", .{pt_idx_5level});
    serial.print(" (expected 0x1FF)", .{});
    serial.println("", .{});

    // Test 4: Verify CR4.LA57 bit is set
    const cr4 = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );
    const la57_bit_set = (cr4 & CR4_LA57) != 0;
    serial.print("    CR4.LA57 bit set: ", .{});
    serial.println("{s}", .{if (la57_bit_set) "Yes" else "No"});

    serial.println("[PAGING] LA57 tests completed", .{});
}
