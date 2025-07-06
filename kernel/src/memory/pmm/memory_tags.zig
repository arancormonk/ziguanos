// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Memory tagging system for allocation tracking

pub const MAX_MEMORY_TAGS: usize = 16; // Support for 16 different memory tags

// Memory tagging system for allocation tracking
pub const MemoryTag = enum(u8) {
    KERNEL_CODE = 0,
    KERNEL_DATA = 1,
    PAGE_TABLES = 2,
    DEVICE_DRIVERS = 3,
    BUFFER_CACHE = 4,
    NETWORK_BUFFERS = 5,
    FILE_SYSTEM = 6,
    USER_PROCESS = 7,
    INTERRUPT_STACKS = 8,
    DMA_BUFFERS = 9,
    TEMPORARY = 10,
    DEBUG = 11,
    SECURITY = 12,
    GUARD_PAGES = 13,
    RESERVED_14 = 14,
    UNKNOWN = 15,

    pub fn toString(self: MemoryTag) []const u8 {
        return switch (self) {
            .KERNEL_CODE => "KERNEL_CODE",
            .KERNEL_DATA => "KERNEL_DATA",
            .PAGE_TABLES => "PAGE_TABLES",
            .DEVICE_DRIVERS => "DEVICE_DRIVERS",
            .BUFFER_CACHE => "BUFFER_CACHE",
            .NETWORK_BUFFERS => "NETWORK_BUFFERS",
            .FILE_SYSTEM => "FILE_SYSTEM",
            .USER_PROCESS => "USER_PROCESS",
            .INTERRUPT_STACKS => "INTERRUPT_STACKS",
            .DMA_BUFFERS => "DMA_BUFFERS",
            .TEMPORARY => "TEMPORARY",
            .DEBUG => "DEBUG",
            .SECURITY => "SECURITY",
            .GUARD_PAGES => "GUARD_PAGES",
            .RESERVED_14 => "RESERVED_14",
            .UNKNOWN => "UNKNOWN",
        };
    }
};

// Memory tagging tracking
pub const MemoryTagTracker = struct {
    allocations: [MAX_MEMORY_TAGS]u64 = [_]u64{0} ** MAX_MEMORY_TAGS,
    deallocations: [MAX_MEMORY_TAGS]u64 = [_]u64{0} ** MAX_MEMORY_TAGS,
    bytes_allocated: [MAX_MEMORY_TAGS]u64 = [_]u64{0} ** MAX_MEMORY_TAGS,
    bytes_freed: [MAX_MEMORY_TAGS]u64 = [_]u64{0} ** MAX_MEMORY_TAGS,

    pub fn init() MemoryTagTracker {
        return MemoryTagTracker{};
    }

    pub fn recordAllocation(self: *MemoryTagTracker, tag: MemoryTag, bytes: u64) void {
        const idx = @intFromEnum(tag);
        self.allocations[idx] += 1;
        self.bytes_allocated[idx] += bytes;
    }

    pub fn recordDeallocation(self: *MemoryTagTracker, tag: MemoryTag, bytes: u64) void {
        const idx = @intFromEnum(tag);
        self.deallocations[idx] += 1;
        self.bytes_freed[idx] += bytes;
    }

    pub fn getActiveBytes(self: *const MemoryTagTracker, tag: MemoryTag) u64 {
        const idx = @intFromEnum(tag);
        return self.bytes_allocated[idx] - self.bytes_freed[idx];
    }

    pub fn clear(self: *MemoryTagTracker) void {
        @memset(&self.allocations, 0);
        @memset(&self.deallocations, 0);
        @memset(&self.bytes_allocated, 0);
        @memset(&self.bytes_freed, 0);
    }
};
