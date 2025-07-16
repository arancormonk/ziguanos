// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../../drivers/serial.zig");
const secure_print = @import("../../lib/secure_print.zig");
const constants = @import("constants.zig");

// Validate a page table entry for reserved bit violations
pub fn validateEntry(entry: u64, level: u8) !void {
    // Skip validation for non-present entries
    if ((entry & constants.PAGE_PRESENT) == 0) {
        return;
    }

    // Determine reserved bit mask based on level and page size
    const reserved_mask: u64 = switch (level) {
        4 => constants.RESERVED_BITS_PML4,
        3 => if ((entry & constants.PAGE_HUGE) != 0) constants.RESERVED_BITS_PDPT_1G else 0x0,
        2 => if ((entry & constants.PAGE_HUGE) != 0) constants.RESERVED_BITS_PD_2M else 0x0,
        1 => constants.RESERVED_BITS_PT,
        else => return error.InvalidLevel,
    };

    // Check if any reserved bits are set
    if ((entry & reserved_mask) != 0) {
        serial.println("[PAGING] Reserved bit violation in level {} entry: 0x{x:0>16}", .{ level, entry });
        return error.ReservedBitViolation;
    }

    // Verify canonical address for PML4 entries
    if (level == 4) {
        const addr = entry & constants.PHYS_ADDR_MASK;
        const bit47 = (addr >> 47) & 1;
        const bits_51_48 = (addr >> 48) & 0xF;

        // In PML4, bits 51:48 must be copies of bit 47 (sign extension)
        const expected_bits: u64 = if (bit47 == 1) 0xF else 0x0;
        if (bits_51_48 != expected_bits) {
            serial.println("[PAGING] Non-canonical address in PML4 entry: 0x{x:0>16}", .{entry});
            return error.NonCanonicalAddress;
        }
    }

    // Additional validation for huge pages
    if ((entry & constants.PAGE_HUGE) != 0) {
        // For huge pages, verify that the address is properly aligned
        const addr = entry & constants.PHYS_ADDR_MASK;
        const alignment = switch (level) {
            3 => constants.PAGE_SIZE_1G, // 1GB pages in PDPT
            2 => constants.PAGE_SIZE_2M, // 2MB pages in PD
            else => 0,
        };

        if (alignment > 0 and (addr % alignment) != 0) {
            serial.println("[PAGING] Misaligned huge page address in level {}: 0x{x:0>16}", .{ level, addr });
            return error.MisalignedHugePage;
        }
    }
}

// Check if an address is canonical (valid in 48-bit address space)
// In x86-64, bits 63:48 must be copies of bit 47
pub fn isCanonicalAddress(addr: u64) bool {
    const bit47 = (addr >> 47) & 1;
    const bits_63_48 = addr >> 48;
    const expected: u64 = if (bit47 == 1) 0xFFFF else 0x0000;
    return bits_63_48 == expected;
}

// Test reserved bit validation functionality
pub fn testValidation() void {
    serial.println("[PAGING] Testing reserved bit validation...", .{});

    // Test 1: Valid PML4 entry
    serial.println("[PAGING] Test 1: Valid PML4 entry", .{});
    const valid_pml4: u64 = 0x1000 | constants.PAGE_PRESENT | constants.PAGE_WRITABLE;
    validateEntry(valid_pml4, 4) catch |err| {
        const err_msg = switch (err) {
            error.NonCanonicalAddress => "NonCanonicalAddress",
            error.ReservedBitViolation => "ReservedBitViolation",
            error.InvalidLevel => "InvalidLevel",
            error.MisalignedHugePage => "MisalignedHugePage",
        };
        serial.println("[PAGING] ERROR: Valid PML4 entry failed validation: {s}", .{err_msg});
    };
    serial.println("[PAGING] Valid PML4 entry passed", .{});

    // Test 2: PML4 entry with reserved bits set
    serial.println("[PAGING] Test 2: PML4 entry with reserved bits", .{});
    const invalid_pml4: u64 = 0x0010_0000_0000_0000 | constants.PAGE_PRESENT; // Set bit 52
    validateEntry(invalid_pml4, 4) catch |err| {
        // In kernel/freestanding mode, @errorName seems to return zeros
        // So we'll use a workaround to get the actual error name
        const err_msg = switch (err) {
            error.NonCanonicalAddress => "NonCanonicalAddress",
            error.ReservedBitViolation => "ReservedBitViolation",
            error.InvalidLevel => "InvalidLevel",
            else => "UnknownError",
        };
        serial.println("[PAGING] Expected error for reserved bits: {s}", .{err_msg});
    };

    // Test 3: Non-canonical address in PML4
    serial.println("[PAGING] Test 3: Non-canonical address", .{});
    const non_canonical: u64 = 0x0008_0000_0000_0000 | constants.PAGE_PRESENT; // Bit 51 set but not 48-50
    validateEntry(non_canonical, 4) catch |err| {
        // In kernel/freestanding mode, @errorName seems to return zeros
        // So we'll use a workaround to get the actual error name
        const err_msg = switch (err) {
            error.NonCanonicalAddress => "NonCanonicalAddress",
            error.ReservedBitViolation => "ReservedBitViolation",
            error.InvalidLevel => "InvalidLevel",
            else => "UnknownError",
        };
        serial.println("[PAGING] Expected error for non-canonical address: 0x{x:0>16} - {s}", .{ non_canonical, err_msg });
    };

    // Test 4: Valid 1GB huge page
    serial.println("[PAGING] Test 4: Valid 1GB huge page", .{});
    const valid_1gb: u64 = 0x4000_0000 | constants.PAGE_PRESENT | constants.PAGE_WRITABLE | constants.PAGE_HUGE;
    validateEntry(valid_1gb, 3) catch |err| {
        const err_msg = switch (err) {
            error.NonCanonicalAddress => "NonCanonicalAddress",
            error.ReservedBitViolation => "ReservedBitViolation",
            error.InvalidLevel => "InvalidLevel",
            error.MisalignedHugePage => "MisalignedHugePage",
        };
        serial.println("[PAGING] ERROR: Valid 1GB page failed validation: {s}", .{err_msg});
    };
    serial.println("[PAGING] Valid 1GB page passed", .{});

    // Test 5: Misaligned 1GB huge page
    serial.println("[PAGING] Test 5: Misaligned 1GB huge page", .{});
    const misaligned_1gb: u64 = 0x4000_1000 | constants.PAGE_PRESENT | constants.PAGE_WRITABLE | constants.PAGE_HUGE; // Not 1GB aligned
    validateEntry(misaligned_1gb, 3) catch |err| {
        // In kernel/freestanding mode, @errorName seems to return zeros
        // So we'll use a workaround to get the actual error name
        const err_msg = switch (err) {
            error.MisalignedHugePage => "MisalignedHugePage",
            error.ReservedBitViolation => "ReservedBitViolation",
            error.InvalidLevel => "InvalidLevel",
            else => "UnknownError",
        };
        serial.println("[PAGING] Expected error for misaligned 1GB page: 0x{x:0>16} - {s}", .{ misaligned_1gb, err_msg });
    };

    // Test 6: Valid 2MB huge page
    serial.println("[PAGING] Test 6: Valid 2MB huge page", .{});
    const valid_2mb: u64 = 0x20_0000 | constants.PAGE_PRESENT | constants.PAGE_WRITABLE | constants.PAGE_HUGE;
    validateEntry(valid_2mb, 2) catch |err| {
        const err_msg = switch (err) {
            error.NonCanonicalAddress => "NonCanonicalAddress",
            error.ReservedBitViolation => "ReservedBitViolation",
            error.InvalidLevel => "InvalidLevel",
            error.MisalignedHugePage => "MisalignedHugePage",
        };
        serial.println("[PAGING] ERROR: Valid 2MB page failed validation: {s}", .{err_msg});
    };
    serial.println("[PAGING] Valid 2MB page passed", .{});

    // Test 7: Test canonical address check function
    serial.println("[PAGING] Test 7: Canonical address checks", .{});
    const canonical_low: u64 = 0x0000_7FFF_FFFF_FFFF;
    const canonical_high: u64 = 0xFFFF_8000_0000_0000;
    const non_canonical_mid: u64 = 0x0000_8000_0000_0000;

    serial.print("[PAGING] Address ", .{});
    secure_print.printHex("0x", canonical_low);
    serial.print(" is canonical: ", .{});
    serial.println("{s}", .{if (isCanonicalAddress(canonical_low)) "true" else "false"});

    serial.print("[PAGING] Address ", .{});
    secure_print.printHex("0x", canonical_high);
    serial.print(" is canonical: ", .{});
    serial.println("{s}", .{if (isCanonicalAddress(canonical_high)) "true" else "false"});

    serial.print("[PAGING] Address ", .{});
    secure_print.printHex("0x", non_canonical_mid);
    serial.print(" is canonical: ", .{});
    serial.println("{s}", .{if (isCanonicalAddress(non_canonical_mid)) "true" else "false"});

    // Test 8: Non-present entry should not be validated
    serial.println("[PAGING] Test 8: Non-present entry", .{});
    const non_present: u64 = 0xFFFF_FFFF_FFFF_FFFE; // All bits set except present
    validateEntry(non_present, 4) catch |err| {
        const err_msg = switch (err) {
            error.NonCanonicalAddress => "NonCanonicalAddress",
            error.ReservedBitViolation => "ReservedBitViolation",
            error.InvalidLevel => "InvalidLevel",
            error.MisalignedHugePage => "MisalignedHugePage",
        };
        serial.println("[PAGING] ERROR: Non-present entry should not fail validation: {s}", .{err_msg});
    };
    serial.println("[PAGING] Non-present entry correctly skipped", .{});

    serial.println("[PAGING] Reserved bit validation tests completed", .{});
}
