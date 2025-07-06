// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Statistics tracking and reporting for the Physical Memory Manager

const serial = @import("../../drivers/serial.zig");

// Memory statistics
pub const MemoryStats = struct {
    total_memory: u64,
    free_memory: u64,
    reserved_memory: u64,
    used_memory: u64,
    allocations: u64,
    deallocations: u64,
    double_free_attempts: u64,
    guard_page_violations: u64,
};

pub const Statistics = struct {
    allocation_count: u64 = 0,
    deallocation_count: u64 = 0,
    double_free_attempts: u64 = 0,
    guard_page_violations: u64 = 0,

    pub fn init() Statistics {
        return Statistics{};
    }

    pub fn recordAllocation(self: *Statistics) void {
        self.allocation_count += 1;
    }

    pub fn recordDeallocation(self: *Statistics) void {
        self.deallocation_count += 1;
    }

    pub fn recordDoubleFreeAttempt(self: *Statistics) void {
        self.double_free_attempts += 1;
    }

    pub fn recordGuardPageViolation(self: *Statistics) void {
        self.guard_page_violations += 1;
    }

    pub fn getStats(self: *const Statistics, total_pages: u64, free_pages: u64, reserved_pages: u64, page_size: u64) MemoryStats {
        const used_pages = total_pages - free_pages - reserved_pages;
        return MemoryStats{
            .total_memory = total_pages * page_size,
            .free_memory = free_pages * page_size,
            .reserved_memory = reserved_pages * page_size,
            .used_memory = used_pages * page_size,
            .allocations = self.allocation_count,
            .deallocations = self.deallocation_count,
            .double_free_attempts = self.double_free_attempts,
            .guard_page_violations = self.guard_page_violations,
        };
    }

    pub fn reportSecurityStats(self: *const Statistics, zero_on_alloc: bool) void {
        serial.print("[PMM] Security Statistics:\n", .{});
        serial.print("  Total allocations: {}\n", .{self.allocation_count});
        serial.print("  Total deallocations: {}\n", .{self.deallocation_count});
        serial.print("  Double-free attempts blocked: {}\n", .{self.double_free_attempts});
        serial.print("  Guard page violations: {}\n", .{self.guard_page_violations});
        serial.print("  Memory zeroing: {s}\n", .{if (zero_on_alloc) "enabled" else "disabled"});
    }

    pub fn clear(self: *Statistics) void {
        self.allocation_count = 0;
        self.deallocation_count = 0;
        self.double_free_attempts = 0;
        self.guard_page_violations = 0;
    }
};
