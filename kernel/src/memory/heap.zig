// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const pmm = @import("pmm.zig");
const paging = @import("../x86_64/paging.zig");
const stack_security = @import("../x86_64/stack_security.zig");
const serial = @import("../drivers/serial.zig");
const memory_security = @import("pmm/memory_security.zig");

const HEAP_MAGIC: u64 = 0x48454150424C4F43; // "HEAPALOC"
const HEAP_FREED_MAGIC: u64 = 0x46524545424C4F43; // "FREEBLOC"
const MAX_ALLOCATION_SIZE: u64 = 256 * 1024 * 1024; // 256MB max single allocation
const MIN_SPLIT_SIZE: u64 = 64; // Don't split blocks smaller than this

pub const HeapHeader = struct {
    magic: u64,
    size: u64, // Size of usable memory (excluding header)
    next: ?*HeapHeader,
    prev: ?*HeapHeader,
    is_free: bool,
    pad: [7]u8 = undefined, // Padding to make header 48 bytes
};

pub const HeapStats = struct {
    total_allocated: u64,
    total_free: u64,
    allocation_count: u64,
    free_count: u64,
    largest_free_block: u64,
    fragmentation_ratio: f32,
};

var heap_start: u64 = 0;
var heap_end: u64 = 0;
var free_list_head: ?*HeapHeader = null;
var heap_stats: HeapStats = .{
    .total_allocated = 0,
    .total_free = 0,
    .allocation_count = 0,
    .free_count = 0,
    .largest_free_block = 0,
    .fragmentation_ratio = 0.0,
};
var heap_initialized: bool = false;

pub fn init(start: u64, size: u64) !void {
    if (heap_initialized) return;

    var guard = stack_security.protect();
    defer guard.deinit();

    heap_start = start;
    heap_end = start + size;

    // Ensure the heap region is accessible by writing a test value
    const test_ptr = @as(*u64, @ptrFromInt(start));
    test_ptr.* = 0xDEADBEEF;
    if (test_ptr.* != 0xDEADBEEF) {
        serial.print("[HEAP] ERROR: Heap memory at {X} is not accessible!\n", .{start});
        return error.HeapNotAccessible;
    }

    // Create initial free block
    const initial_header = @as(*HeapHeader, @ptrFromInt(start));
    initial_header.* = .{
        .magic = HEAP_MAGIC,
        .size = size - @sizeOf(HeapHeader),
        .next = null,
        .prev = null,
        .is_free = true,
    };

    free_list_head = initial_header;
    heap_stats.total_free = size - @sizeOf(HeapHeader);
    heap_stats.largest_free_block = heap_stats.total_free;
    heap_initialized = true;

    serial.print("[HEAP] Initialized heap at {X} with size {} bytes\n", .{ start, size });
}

pub fn heapAlloc(size: u64) !*anyopaque {
    if (!heap_initialized) return error.HeapNotInitialized;
    if (size == 0) return error.InvalidSize;
    if (size > MAX_ALLOCATION_SIZE) return error.SizeTooLarge;

    var guard = stack_security.protect();
    defer guard.deinit();

    // Align size to 8 bytes
    const aligned_size = (size + 7) & ~@as(u64, 7);

    // Find a suitable free block
    var current = free_list_head;
    while (current) |block| {
        if (!validateHeapHeader(block)) {
            serial.print("[HEAP] ERROR: Heap corruption detected during allocation\n", .{});
            return error.HeapCorruption;
        }

        if (block.is_free and block.size >= aligned_size) {
            // Found a suitable block
            allocateBlock(block, aligned_size);
            updateHeapStats();

            const user_ptr = @as([*]u8, @ptrFromInt(@intFromPtr(block))) + @sizeOf(HeapHeader);

            // Zero the allocated memory for security
            if (memory_security.isZeroOnAllocEnabled()) {
                memory_security.zeroMemoryRange(@intFromPtr(user_ptr), aligned_size);
            }

            return @as(*anyopaque, @ptrCast(user_ptr));
        }
        current = block.next;
    }

    return error.OutOfMemory;
}

pub fn heapFree(ptr: ?*anyopaque) void {
    if (ptr == null) return;

    var guard = stack_security.protect();
    defer guard.deinit();

    // Validate pointer is within heap bounds
    if (!isValidHeapPointer(ptr)) {
        handleHeapCorruption(ptr);
        return;
    }

    // Get allocation header
    const header_ptr = @as([*]u8, @ptrFromInt(@intFromPtr(ptr.?))) - @sizeOf(HeapHeader);
    const header = @as(*HeapHeader, @ptrFromInt(@intFromPtr(header_ptr)));

    if (!validateHeapHeader(header)) {
        handleHeapCorruption(ptr);
        return;
    }

    if (header.is_free) {
        serial.print("[HEAP] ERROR: Double free detected at {X}\n", .{@intFromPtr(ptr)});
        return;
    }

    // Poison freed memory
    memory_security.poisonMemoryRange(@intFromPtr(ptr.?), header.size);

    // Mark as free
    header.is_free = true;
    header.magic = HEAP_FREED_MAGIC;

    // Update statistics
    heap_stats.total_free += header.size;
    heap_stats.total_allocated -= header.size;
    heap_stats.free_count += 1;

    // Add to free list with coalescing
    addToFreeList(header);

    // Trigger garbage collection if needed
    if (shouldTriggerGC()) {
        triggerGarbageCollection();
    }
}

fn allocateBlock(block: *HeapHeader, size: u64) void {
    const remaining_size = block.size - size;

    // Split block if remainder is large enough
    if (remaining_size >= @sizeOf(HeapHeader) + MIN_SPLIT_SIZE) {
        // Create new free block
        const new_block_addr = @intFromPtr(block) + @sizeOf(HeapHeader) + size;
        const new_block = @as(*HeapHeader, @ptrFromInt(new_block_addr));

        new_block.* = .{
            .magic = HEAP_MAGIC,
            .size = remaining_size - @sizeOf(HeapHeader),
            .next = block.next,
            .prev = block,
            .is_free = true,
        };

        if (block.next) |next| {
            next.prev = new_block;
        }

        block.next = new_block;
        block.size = size;
    }

    block.is_free = false;
    heap_stats.total_allocated += block.size;
    heap_stats.total_free -= block.size;
    heap_stats.allocation_count += 1;

    // Remove from free list
    removeFromFreeList(block);
}

fn addToFreeList(header: *HeapHeader) void {
    // Try to coalesce with adjacent free blocks
    coalesceBlock(header);

    // Add to free list (sorted by address for better locality)
    if (free_list_head == null or @intFromPtr(header) < @intFromPtr(free_list_head.?)) {
        header.next = free_list_head;
        header.prev = null;
        if (free_list_head) |head| {
            head.prev = header;
        }
        free_list_head = header;
    } else {
        var current = free_list_head.?;
        while (current.next) |next| {
            if (@intFromPtr(header) < @intFromPtr(next)) break;
            current = next;
        }
        header.next = current.next;
        header.prev = current;
        if (current.next) |next| {
            next.prev = header;
        }
        current.next = header;
    }
}

fn removeFromFreeList(header: *HeapHeader) void {
    if (header.prev) |prev| {
        prev.next = header.next;
    } else {
        free_list_head = header.next;
    }

    if (header.next) |next| {
        next.prev = header.prev;
    }

    header.next = null;
    header.prev = null;
}

fn coalesceBlock(header: *HeapHeader) void {
    // Check if we can merge with next block
    const next_addr = @intFromPtr(header) + @sizeOf(HeapHeader) + header.size;
    if (next_addr < heap_end) {
        const next_header = @as(*HeapHeader, @ptrFromInt(next_addr));
        if (validateHeapHeader(next_header) and next_header.is_free) {
            // Merge with next block
            header.size += @sizeOf(HeapHeader) + next_header.size;
            header.next = next_header.next;
            if (next_header.next) |next_next| {
                next_next.prev = header;
            }
            heap_stats.free_count -= 1;
        }
    }

    // Check if we can merge with previous block
    // This requires walking the heap to find the previous block
    var current: ?*HeapHeader = @as(*HeapHeader, @ptrFromInt(heap_start));
    while (current) |block| {
        const block_end = @intFromPtr(block) + @sizeOf(HeapHeader) + block.size;
        if (block_end == @intFromPtr(header) and block.is_free) {
            // Merge with previous block
            block.size += @sizeOf(HeapHeader) + header.size;
            block.next = header.next;
            if (header.next) |next| {
                next.prev = block;
            }
            heap_stats.free_count -= 1;
            break;
        }

        // Move to next block in memory (not free list)
        if (block_end >= heap_end) break;
        current = @as(*HeapHeader, @ptrFromInt(block_end));
    }
}

fn isValidHeapPointer(ptr: ?*anyopaque) bool {
    if (ptr == null) return false;

    const addr = @intFromPtr(ptr.?);
    // For higher-half kernel addresses, check if within heap bounds
    const header_size = @sizeOf(HeapHeader);
    return addr >= heap_start + header_size and
        addr < heap_end and
        (addr & 0x7) == 0; // 8-byte aligned
}

fn validateHeapHeader(header: *HeapHeader) bool {
    const header_addr = @intFromPtr(header);
    if (header_addr < heap_start or header_addr >= heap_end) {
        serial.print("[HEAP] Header {X} outside bounds [{X}, {X})\n", .{ header_addr, heap_start, heap_end });
        return false;
    }

    // Check magic number
    if (header.magic != HEAP_MAGIC and header.magic != HEAP_FREED_MAGIC) {
        serial.print("[HEAP] Invalid magic {X} at {X}, expected {X} or {X}\n", .{ header.magic, header_addr, HEAP_MAGIC, HEAP_FREED_MAGIC });
        return false;
    }

    // Check size is reasonable
    if (header.size == 0 or header.size > heap_end - heap_start) {
        serial.print("[HEAP] Invalid size {} at {X}, heap size is {}\n", .{ header.size, header_addr, heap_end - heap_start });
        return false;
    }

    return true;
}

fn handleHeapCorruption(ptr: ?*anyopaque) void {
    serial.print("[HEAP] CRITICAL: Heap corruption detected!\n", .{});
    if (ptr) |p| {
        serial.print("[HEAP] Invalid pointer: {X}\n", .{@intFromPtr(p)});
    }
    serial.print("[HEAP] Heap range: {X} - {X}\n", .{ heap_start, heap_end });

    // In a production system, this should trigger a kernel panic
    // For now, we just log the error
}

fn updateHeapStats() void {
    // Find largest free block
    heap_stats.largest_free_block = 0;
    var current = free_list_head;
    var free_block_count: u64 = 0;

    while (current) |block| {
        if (block.size > heap_stats.largest_free_block) {
            heap_stats.largest_free_block = block.size;
        }
        free_block_count += 1;
        current = block.next;
    }

    // Calculate fragmentation ratio
    if (heap_stats.total_free > 0 and heap_stats.largest_free_block > 0) {
        heap_stats.fragmentation_ratio = 1.0 - @as(f32, @floatFromInt(heap_stats.largest_free_block)) / @as(f32, @floatFromInt(heap_stats.total_free));
    } else {
        heap_stats.fragmentation_ratio = 0.0;
    }
}

fn shouldTriggerGC() bool {
    // Trigger GC if:
    // 1. Fragmentation is too high (> 50%)
    // 2. Free count is too high (> 1000 free blocks)
    // 3. Free memory is low (< 10% of heap)
    const total_heap_size = heap_end - heap_start;
    const free_percentage = (heap_stats.total_free * 100) / total_heap_size;

    return heap_stats.fragmentation_ratio > 0.5 or
        heap_stats.free_count > 1000 or
        free_percentage < 10;
}

fn triggerGarbageCollection() void {
    // Simple garbage collection: compact free blocks
    serial.print("[HEAP] Triggering garbage collection...\n", .{});

    // In a real implementation, this would:
    // 1. Defragment the heap by moving allocations
    // 2. Update all pointers to moved allocations
    // 3. Coalesce all free space

    // For now, we just try aggressive coalescing
    var current = free_list_head;
    while (current) |block| {
        coalesceBlock(block);
        current = block.next;
    }

    updateHeapStats();
    serial.print("[HEAP] GC complete. Fragmentation: {}%\n", .{@as(u32, @intFromFloat(heap_stats.fragmentation_ratio * 100))});
}

pub fn getStats() HeapStats {
    updateHeapStats();
    return heap_stats;
}

pub fn printStats() void {
    const stats = getStats();
    serial.print("[HEAP] Statistics:\n", .{});
    serial.print("  Total allocated: {} bytes\n", .{stats.total_allocated});
    serial.print("  Total free: {} bytes\n", .{stats.total_free});
    serial.print("  Allocation count: {}\n", .{stats.allocation_count});
    serial.print("  Free count: {}\n", .{stats.free_count});
    serial.print("  Largest free block: {} bytes\n", .{stats.largest_free_block});
    serial.print("  Fragmentation: {}%\n", .{@as(u32, @intFromFloat(stats.fragmentation_ratio * 100))});
}
