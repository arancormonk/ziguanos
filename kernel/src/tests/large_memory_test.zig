// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Test large memory support in the Physical Memory Manager

const std = @import("std");
const pmm = @import("../memory/pmm.zig");
const cpuid = @import("../x86_64/cpuid.zig");
const serial = @import("../drivers/serial.zig");

pub fn testLargeMemorySupport() void {
    serial.println("[PMM_TEST] Testing large memory support...", .{});

    // Get CPU physical address capabilities
    const phys_bits = cpuid.getPhysicalAddressBits();
    const max_phys_mem = cpuid.getMaxPhysicalMemory();

    serial.println("[PMM_TEST] CPU Physical Address Support:", .{});
    serial.println("  Physical address bits: {}", .{phys_bits});
    serial.println("  Maximum addressable memory: {} TB", .{max_phys_mem / (1024 * 1024 * 1024 * 1024)});

    // Get current memory statistics
    const stats = pmm.getStats();
    serial.println("[PMM_TEST] Current Memory Statistics:", .{});
    serial.println("  Total memory: {} MB", .{stats.total_memory / (1024 * 1024)});
    serial.println("  Free memory: {} MB", .{stats.free_memory / (1024 * 1024)});
    serial.println("  Reserved memory: {} MB", .{stats.reserved_memory / (1024 * 1024)});

    // Test allocation patterns to verify bitmap handling
    serial.println("[PMM_TEST] Testing allocation patterns...", .{});

    // Test 1: Allocate and free a large block
    const large_pages = 256; // 1MB worth of pages
    if (pmm.allocPages(large_pages)) |addr| {
        serial.println("  ✓ Successfully allocated {} pages at 0x{x}", .{ large_pages, addr });
        pmm.freePages(addr, large_pages);
        serial.println("  ✓ Successfully freed {} pages", .{large_pages});
    } else {
        serial.println("  ✗ Failed to allocate {} pages", .{large_pages});
    }

    // Test 2: Allocate multiple smaller blocks
    var addrs: [10]?u64 = [_]?u64{null} ** 10;
    var allocated: u32 = 0;

    for (&addrs) |*addr| {
        addr.* = pmm.allocPages(16); // 64KB blocks
        if (addr.* != null) {
            allocated += 1;
        }
    }

    serial.println("  ✓ Allocated {}/10 blocks of 16 pages each", .{allocated});

    // Free them
    var freed: u32 = 0;
    for (addrs) |addr| {
        if (addr) |a| {
            pmm.freePages(a, 16);
            freed += 1;
        }
    }

    serial.println("  ✓ Freed {}/{} blocks", .{ freed, allocated });

    // Test 3: Verify high address support
    serial.println("[PMM_TEST] Memory Layout:", .{});

    // Find the highest allocated page to understand memory layout
    var highest_addr: u64 = 0;
    if (pmm.allocPage()) |addr| {
        highest_addr = addr;
        pmm.freePage(addr);

        serial.println("  Allocation returned address: 0x{x:0>16}", .{addr});

        // Check if this is beyond the bootstrap bitmap range
        const bootstrap_max = 8 * 1024 * 1024 * 1024; // 8GB
        if (addr >= bootstrap_max) {
            serial.println("  ✓ System is using extended bitmap (address beyond 8GB limit)", .{});
        } else {
            serial.println("  System is within bootstrap bitmap range (< 8GB)", .{});
        }
    }

    serial.println("[PMM_TEST] Large memory support test complete", .{});
}
