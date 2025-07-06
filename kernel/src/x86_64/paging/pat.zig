// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../../drivers/serial.zig");
const constants = @import("constants.zig");
const cpuid = @import("../cpuid.zig");

// PAT bits
pub const PAGE_PAT_4K: u64 = 1 << 7;
pub const PAGE_PAT_LARGE: u64 = 1 << 12;

// Memory type combinations
pub const MEMORY_TYPE_UC: u64 = 0;
pub const MEMORY_TYPE_WC: u64 = constants.PAGE_WRITE_THROUGH;
pub const MEMORY_TYPE_WT: u64 = constants.PAGE_CACHE_DISABLE;
pub const MEMORY_TYPE_WP: u64 = constants.PAGE_WRITE_THROUGH | constants.PAGE_CACHE_DISABLE;
pub const MEMORY_TYPE_WB: u64 = 0;

// PAT MSR
const IA32_PAT_MSR: u32 = 0x277;

// Memory type encodings
const PAT_UC: u8 = 0x00;
const PAT_WC: u8 = 0x01;
const PAT_WT: u8 = 0x04;
const PAT_WP: u8 = 0x05;
const PAT_WB: u8 = 0x06;
const PAT_UC_MINUS: u8 = 0x07;

// Initialize PAT with default memory types
pub fn init() void {
    const features = cpuid.getFeatures();
    if (!features.pat) {
        serial.println("[PAGING] PAT not supported by CPU", .{});
        return;
    }

    // Default PAT configuration:
    // PAT0 (000b) = WB (Write Back)
    // PAT1 (001b) = WT (Write Through)
    // PAT2 (010b) = UC- (Uncacheable minus)
    // PAT3 (011b) = UC (Uncacheable)
    // PAT4 (100b) = WB (Write Back)
    // PAT5 (101b) = WT (Write Through)
    // PAT6 (110b) = UC- (Uncacheable minus)
    // PAT7 (111b) = UC (Uncacheable)

    // Build the 64-bit PAT value (8 bytes, one per PAT entry)
    const pat_value: u64 = (@as(u64, PAT_UC) << 56) | // PAT7
        (@as(u64, PAT_UC_MINUS) << 48) | // PAT6
        (@as(u64, PAT_WT) << 40) | // PAT5
        (@as(u64, PAT_WB) << 32) | // PAT4
        (@as(u64, PAT_UC) << 24) | // PAT3
        (@as(u64, PAT_UC_MINUS) << 16) | // PAT2
        (@as(u64, PAT_WT) << 8) | // PAT1
        (@as(u64, PAT_WB)); // PAT0

    // Write to PAT MSR
    wrmsr(IA32_PAT_MSR, pat_value);

    serial.println("[PAGING] PAT initialized with default memory types", .{});
}

// Set memory type for a page table entry
pub fn setPageMemoryType(entry: *u64, memory_type: u64, is_large_page: bool) void {
    const pat_bit = if (is_large_page) PAGE_PAT_LARGE else PAGE_PAT_4K;

    // Clear existing memory type bits (PWT, PCD, and PAT)
    entry.* &= ~(constants.PAGE_WRITE_THROUGH | constants.PAGE_CACHE_DISABLE | pat_bit);

    // Set the new memory type
    // For standard memory types, we only need PWT and PCD
    // PAT bit would be used for extended memory types when PAT is fully configured
    entry.* |= (memory_type & (constants.PAGE_WRITE_THROUGH | constants.PAGE_CACHE_DISABLE));
}

// Get memory type from a page table entry
pub fn getPageMemoryType(entry: u64, is_large_page: bool) u64 {
    const pat_bit = if (is_large_page) PAGE_PAT_LARGE else PAGE_PAT_4K;
    return entry & (constants.PAGE_WRITE_THROUGH | constants.PAGE_CACHE_DISABLE | pat_bit);
}

// Test PAT functionality
pub fn testPAT() void {
    serial.println("[PAGING] Testing PAT memory type configuration...", .{});

    // Example: Map a hypothetical device memory region as uncacheable
    // In a real OS, this would be the physical address of a device
    const device_phys_addr: u64 = 0xFEE00000; // Example: Local APIC base

    // Find the page table entry for this address
    // This is a simplified example - in practice you'd walk the page tables

    // For demonstration, let's show how to set up an uncacheable mapping
    // when creating a new page table entry
    var test_entry: u64 = device_phys_addr | constants.PAGE_PRESENT | constants.PAGE_WRITABLE | constants.PAGE_NO_EXECUTE;

    // Set as uncacheable using PAT
    setPageMemoryType(&test_entry, MEMORY_TYPE_UC, false);

    serial.println("[PAGING] Test entry for device memory: 0x{x:0>16}", .{test_entry});

    // Verify the memory type
    const mem_type = getPageMemoryType(test_entry, false);
    serial.print("[PAGING] Memory type bits: 0x", .{});
    serial.print("0x{x:0>16}", .{mem_type});
    serial.println("{s}", .{if (mem_type == MEMORY_TYPE_UC) " (Uncacheable)" else " (Other)"});

    serial.println("[PAGING] PAT test completed", .{});
}

// MSR access functions (local to this module)
fn rdmsr(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;

    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );

    return (@as(u64, high) << 32) | low;
}

fn wrmsr(msr: u32, value: u64) void {
    const low = @as(u32, @truncate(value));
    const high = @as(u32, @truncate(value >> 32));

    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (low),
          [high] "{edx}" (high),
    );
}
