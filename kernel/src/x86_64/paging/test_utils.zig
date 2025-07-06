// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../../drivers/serial.zig");
const runtime_info = @import("../../boot/runtime_info.zig");
const constants = @import("constants.zig");
const pat = @import("pat.zig");
const pku = @import("pku.zig");
const la57 = @import("la57.zig");
const validation = @import("validation.zig");

// Type for getPageTableEntry function from main paging module
pub const GetPageTableEntryFn = fn (virt_addr: u64) anyerror!u64;

// Test all paging features
pub fn testAll() void {
    serial.println("[PAGING] Running comprehensive tests...", .{});

    pat.testPAT();
    pku.testPKU();
    la57.testLA57();
    validation.testValidation();

    serial.println("[PAGING] All tests completed", .{});
}

// Test memory protection (W^X)
pub fn testPagingMemoryProtection(getPageTableEntryFn: GetPageTableEntryFn) void {
    serial.println("[PAGING] Testing paging-level memory protection...", .{});

    // Test 1: Check W^X enforcement
    serial.println("[PAGING] Test 1: W^X enforcement verification", .{});

    // Find a code page in the kernel
    const info = runtime_info.getRuntimeInfo();
    const kernel_start = info.kernel_virtual_base;
    const code_page = kernel_start & ~(constants.PAGE_SIZE_4K - 1);

    if (getPageTableEntryFn(code_page) catch null) |pte| {
        const is_writable = (pte & constants.PAGE_WRITABLE) != 0;
        const is_executable = (pte & constants.PAGE_NO_EXECUTE) == 0;

        if (is_executable and !is_writable) {
            serial.println("  ✓ Code page correctly marked as executable but not writable", .{});
        } else {
            serial.print("  ✗ Code page has incorrect permissions: writable=", .{});
            serial.print("{s}", .{if (is_writable) "true" else "false"});
            serial.print(", executable=", .{});
            serial.println("{s}", .{if (is_executable) "true" else "false"});
        }
    } else {
        serial.println("  ? Could not find code page mapping", .{});
    }

    // Test 2: Data page verification
    serial.println("[PAGING] Test 2: Data page W^X verification", .{});

    // Find a data page (stack area)
    const stack_addr = asm volatile (
        \\mov %%rsp, %[result]
        : [result] "=r" (-> u64),
    );
    const data_page = stack_addr & ~(constants.PAGE_SIZE_4K - 1);

    if (getPageTableEntryFn(data_page) catch null) |pte| {
        const is_writable = (pte & constants.PAGE_WRITABLE) != 0;
        const is_non_executable = (pte & constants.PAGE_NO_EXECUTE) != 0;

        if (is_writable and is_non_executable) {
            serial.println("  ✓ Data page correctly marked as writable but not executable", .{});
        } else {
            serial.print("  ✗ Data page has incorrect permissions: writable=", .{});
            serial.print("{s}", .{if (is_writable) "true" else "false"});
            serial.print(", non-executable=", .{});
            serial.println("{s}", .{if (is_non_executable) "true" else "false"});
        }
    } else {
        serial.println("  ? Could not find data page mapping", .{});
    }

    serial.println("[PAGING] Paging memory protection tests completed", .{});
}
