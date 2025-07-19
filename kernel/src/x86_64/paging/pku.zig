// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../../drivers/serial.zig");
const constants = @import("constants.zig");
const cpuid = @import("../cpuid.zig");

// Protection Key bits
pub const PAGE_PKEY_MASK: u64 = 0xF << 59;
pub const PAGE_PKEY_SHIFT: u6 = 59;

// CR4 bit for PKU
const CR4_PKE: u64 = 1 << 22;

// PKRU access rights structure
pub const PKRUAccessRights = struct {
    access_disable: bool,
    write_disable: bool,
};

// Protection key assignments for different memory regions
pub const ProtectionKeys = enum(u4) {
    kernel_code = 0, // Most restrictive - execute only
    kernel_data = 1, // Kernel data - read/write
    kernel_heap = 2, // Kernel heap - read/write
    kernel_stack = 3, // Kernel stack - read/write
    shadow_stack = 4, // Shadow stack - read-only (written via write window)
    page_tables = 5, // Page table pages - read/write
    guard_pages = 6, // Guard pages - no access
    user_accessible = 7, // User-accessible kernel data
    // Keys 8-15 reserved for future use

    pub fn toU4(self: ProtectionKeys) u4 {
        return @intFromEnum(self);
    }
};

// Enable PKU in CR4
pub fn enable() !void {
    const features = cpuid.getFeatures();
    if (!features.pku) {
        serial.println("[PAGING] PKU not supported by CPU", .{});
        return error.PKUNotSupported;
    }

    // Set CR4.PKE bit (bit 22)
    var cr4 = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );

    cr4 |= CR4_PKE;

    asm volatile ("mov %[value], %%cr4"
        :
        : [value] "r" (cr4),
        : "memory"
    );

    // Add memory barrier to ensure CR4 write completes
    asm volatile ("mfence" ::: "memory");

    // Verify CR4.PKE was actually set
    const cr4_verify = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );

    if ((cr4_verify & CR4_PKE) == 0) {
        serial.println("[PAGING] Failed to enable PKU - CR4.PKE not set", .{});
        return error.PKUEnableFailed;
    }

    // Test PKRU access before declaring success
    const test_pkru = asm volatile (
        \\xor %%ecx, %%ecx
        \\xor %%edx, %%edx
        \\rdpkru
        : [ret] "={eax}" (-> u32),
        :
        : "ecx", "edx"
    );

    serial.println("[PAGING] PKU enabled (test PKRU: 0x{x})", .{test_pkru});
}

// Initialize protection keys with proper access rights
pub fn init() void {
    if (!cpuid.getFeatures().pku) return;

    // Configure protection keys with appropriate access rights
    serial.println("[PKU] Configuring protection keys...", .{});

    // First, ensure PKRU is accessible by reading it
    const initial_pkru = readPKRU();
    serial.println("[PKU] Initial PKRU value: 0x{x}", .{initial_pkru});

    // Key 0 (kernel_code): Allow read/execute, deny write
    // Note: PKU doesn't control execute permissions, only read/write
    setPKRU(ProtectionKeys.kernel_code.toU4(), false, true);
    serial.println("[PKU] Key 0 (kernel_code): read-only", .{});

    // Key 1 (kernel_data): Allow read/write
    setPKRU(ProtectionKeys.kernel_data.toU4(), false, false);
    serial.println("[PKU] Key 1 (kernel_data): read/write", .{});

    // Key 2 (kernel_heap): Allow read/write
    setPKRU(ProtectionKeys.kernel_heap.toU4(), false, false);
    serial.println("[PKU] Key 2 (kernel_heap): read/write", .{});

    // Key 3 (kernel_stack): Allow read/write
    setPKRU(ProtectionKeys.kernel_stack.toU4(), false, false);
    serial.println("[PKU] Key 3 (kernel_stack): read/write", .{});

    // Key 4 (shadow_stack): Allow read, deny write (written via write window)
    setPKRU(ProtectionKeys.shadow_stack.toU4(), false, true);
    serial.println("[PKU] Key 4 (shadow_stack): read-only", .{});

    // Key 5 (page_tables): Allow read/write
    setPKRU(ProtectionKeys.page_tables.toU4(), false, false);
    serial.println("[PKU] Key 5 (page_tables): read/write", .{});

    // Key 6 (guard_pages): Deny all access
    setPKRU(ProtectionKeys.guard_pages.toU4(), true, true);
    serial.println("[PKU] Key 6 (guard_pages): no access", .{});

    // Key 7 (user_accessible): Allow read/write
    setPKRU(ProtectionKeys.user_accessible.toU4(), false, false);
    serial.println("[PKU] Key 7 (user_accessible): read/write", .{});

    serial.println("[PKU] Protection keys initialized with security policies", .{});
}

// Set protection key for a page table entry
pub fn setProtectionKey(entry: *u64, key: u4) void {
    entry.* = (entry.* & ~PAGE_PKEY_MASK) | (@as(u64, key) << PAGE_PKEY_SHIFT);
}

// Get protection key from a page table entry
pub fn getProtectionKey(entry: u64) u4 {
    return @truncate((entry & PAGE_PKEY_MASK) >> PAGE_PKEY_SHIFT);
}

// Read PKRU register
pub fn readPKRU() u32 {
    if (!cpuid.getFeatures().pku) return 0;

    // RDPKRU instruction: reads PKRU into EAX, zeroes EDX
    // ECX must also be zero for RDPKRU
    return asm volatile (
        \\xor %%ecx, %%ecx
        \\xor %%edx, %%edx
        \\rdpkru
        : [ret] "={eax}" (-> u32),
        :
        : "ecx", "edx"
    );
}

// Write PKRU register
pub fn writePKRU(value: u32) void {
    if (!cpuid.getFeatures().pku) return;

    // WRPKRU instruction: writes EAX to PKRU, ECX and EDX must be zero
    asm volatile (
        \\xor %%ecx, %%ecx
        \\xor %%edx, %%edx
        \\wrpkru
        :
        : [eax] "{eax}" (value),
        : "ecx", "edx", "memory"
    );
}

// Set access rights for a specific key
pub fn setPKRU(key: u4, disable_access: bool, disable_write: bool) void {
    if (!cpuid.getFeatures().pku) return;

    var pkru = readPKRU();
    const shift: u5 = @as(u5, key) * 2;

    // Clear the two bits for this key
    pkru &= ~(@as(u32, 0b11) << shift);

    // Set new rights
    if (disable_access) pkru |= (@as(u32, 1) << shift);
    if (disable_write) pkru |= (@as(u32, 2) << shift);

    writePKRU(pkru);
}

// Get access rights for a specific key
pub fn getPKRU(key: u4) PKRUAccessRights {
    if (!cpuid.getFeatures().pku) {
        return .{ .access_disable = false, .write_disable = false };
    }

    const pkru = readPKRU();
    const shift: u5 = @as(u5, key) * 2;
    const bits = (pkru >> shift) & 0b11;

    return .{
        .access_disable = (bits & 1) != 0,
        .write_disable = (bits & 2) != 0,
    };
}

// Apply protection key to a page table entry
pub fn applyProtectionKey(entry: *u64, key: ProtectionKeys) void {
    if (!cpuid.getFeatures().pku) return;

    setProtectionKey(entry, key.toU4());
}

// Create a page table entry with protection key
pub fn createPageEntryWithKey(phys_addr: u64, flags: u64, key: ProtectionKeys) u64 {
    const features = cpuid.getFeatures();
    if (features.pku) {
        return phys_addr | flags | (@as(u64, @intFromEnum(key)) << 59);
    } else {
        return phys_addr | flags;
    }
}

// Get appropriate protection key for a memory region type
pub fn getKeyForMemoryType(memory_type: enum { code, data, heap, stack, shadow_stack, page_tables, guard_pages, user_accessible }) ProtectionKeys {
    return switch (memory_type) {
        .code => ProtectionKeys.kernel_code,
        .data => ProtectionKeys.kernel_data,
        .heap => ProtectionKeys.kernel_heap,
        .stack => ProtectionKeys.kernel_stack,
        .shadow_stack => ProtectionKeys.shadow_stack,
        .page_tables => ProtectionKeys.page_tables,
        .guard_pages => ProtectionKeys.guard_pages,
        .user_accessible => ProtectionKeys.user_accessible,
    };
}

// Test PKU functionality
pub fn testPKU() void {
    serial.println("[PAGING] Testing Protection Keys (PKU)...", .{});

    const features = cpuid.getFeatures();
    if (!features.pku) {
        serial.println("[PAGING] PKU not supported, skipping test", .{});
        return;
    }

    // Test 1: Read initial PKRU value
    const initial_pkru = readPKRU();
    serial.print("[PAGING] Initial PKRU value: 0x", .{});
    serial.print("0x{x:0>16}", .{initial_pkru});
    serial.println(" (should be 0x0 after init)", .{});

    // Test 2: Set protection key 1 to deny all access
    serial.println("[PAGING] Setting protection key 1 to deny all access...", .{});
    setPKRU(1, true, true);

    const pkru_after_set = readPKRU();
    serial.print("[PAGING] PKRU after setting key 1: 0x", .{});
    serial.print("0x{x:0>16}", .{pkru_after_set});
    serial.println(" (should have bits 2-3 set)", .{});

    // Test 3: Verify the rights were set correctly
    const rights = getPKRU(1);
    serial.print("[PAGING] Key 1 rights: access_disable=", .{});
    serial.print("{s}", .{if (rights.access_disable) "true" else "false"});
    serial.print(", write_disable=", .{});
    serial.println("{s}", .{if (rights.write_disable) "true" else "false"});

    // Test 4: Set protection key 2 to allow read but deny write
    serial.println("[PAGING] Setting protection key 2 to read-only...", .{});
    setPKRU(2, false, true);

    const rights2 = getPKRU(2);
    serial.print("[PAGING] Key 2 rights: access_disable=", .{});
    serial.print("{s}", .{if (rights2.access_disable) "true" else "false"});
    serial.print(", write_disable=", .{});
    serial.println("{s}", .{if (rights2.write_disable) "true" else "false"});

    // Test 5: Create a test page table entry with protection key
    var test_entry: u64 = 0x1000 | constants.PAGE_PRESENT | constants.PAGE_USER | constants.PAGE_WRITABLE;
    serial.println("[PAGING] Test PTE before setting key: 0x{x:0>16}", .{test_entry});

    // Set protection key 2 on the entry
    setProtectionKey(&test_entry, 2);
    serial.println("[PAGING] Test PTE after setting key 2: 0x{x:0>16}", .{test_entry});

    // Verify we can read back the key
    const read_key = getProtectionKey(test_entry);
    serial.print("[PAGING] Protection key read from PTE: ", .{});
    serial.print("{}", .{read_key});
    serial.println(" (should be 2)", .{});

    // Reset PKRU to allow all access
    serial.println("[PAGING] Resetting PKRU to allow all access...", .{});
    writePKRU(0);

    const final_pkru = readPKRU();
    serial.print("[PAGING] Final PKRU value: 0x", .{});
    serial.print("0x{x:0>16}", .{final_pkru});
    serial.println(" (should be 0x0)", .{});

    serial.println("[PAGING] Protection Keys test completed", .{});
}
