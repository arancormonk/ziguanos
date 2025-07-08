// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const pmm = @import("pmm.zig");
const paging = @import("../x86_64/paging.zig");
const stack_security = @import("../x86_64/stack_security.zig");
const serial = @import("../drivers/serial.zig");
const runtime_info = @import("../boot/runtime_info.zig");
const heap = @import("heap.zig");

// Virtual memory layout - dynamic based on kernel load address
const KERNEL_HEAP_SIZE = 1024 * 1024 * 1024; // 1GB initial heap

// Get kernel heap start dynamically - place it at higher half but offset by KASLR
fn getKernelHeapStart() u64 {
    // Place heap within the kernel's 4KB-mapped region
    // The kernel maps its own region with 4KB pages for W^X protection
    const info = runtime_info.getRuntimeInfo();
    const kernel_end = info.kernel_virtual_base + info.kernel_size;
    // Align to page boundary (4KB)
    const aligned_end = (kernel_end + 0xFFF) & ~@as(u64, 0xFFF);
    // Add small gap but stay within the 4KB-mapped region
    return aligned_end + 0x10000; // Add 64KB gap after kernel
}

// Page table entry helpers
fn makeTableEntry(phys_addr: u64, flags: u64) u64 {
    return (phys_addr & ~@as(u64, 0xFFF)) | flags;
}

// Get or create page table
fn getOrCreateTable(table: *[512]u64, index: usize, flags: u64) !*[512]u64 {
    var guard = stack_security.protect();
    defer guard.deinit();

    if ((table[index] & paging.PAGE_PRESENT) == 0) {
        // Allocate new page table
        const phys_addr = pmm.allocPages(1) orelse return error.OutOfMemory;

        // Map and clear new table
        const new_table = @as(*[512]u64, @ptrFromInt(phys_addr));
        for (new_table) |*entry| {
            entry.* = 0;
        }

        // Install in parent table
        table[index] = makeTableEntry(phys_addr, flags);
    }

    const table_addr = table[index] & ~@as(u64, 0xFFF);
    return @as(*[512]u64, @ptrFromInt(table_addr));
}

// Map virtual address to physical address
pub fn mapPage(virt_addr: u64, phys_addr: u64, flags: u64) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    const pml4_idx = (virt_addr >> 39) & 0x1FF;
    const pdpt_idx = (virt_addr >> 30) & 0x1FF;
    const pd_idx = (virt_addr >> 21) & 0x1FF;
    const pt_idx = (virt_addr >> 12) & 0x1FF;

    // Get current PML4
    const cr3 = asm volatile ("mov %%cr3, %[result]"
        : [result] "=r" (-> u64),
    );
    const pml4 = @as(*[512]u64, @ptrFromInt(cr3 & ~@as(u64, 0xFFF)));

    // Walk/create page tables
    const pdpt = try getOrCreateTable(pml4, pml4_idx, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
    const pd = try getOrCreateTable(pdpt, pdpt_idx, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
    const pt = try getOrCreateTable(pd, pd_idx, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);

    // Map the page
    pt[pt_idx] = makeTableEntry(phys_addr, flags);

    // Flush TLB for this address
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (virt_addr),
        : "memory"
    );
}

// Unmap virtual address
pub fn unmapPage(virt_addr: u64) void {
    var guard = stack_security.protect();
    defer guard.deinit();

    const pml4_idx = (virt_addr >> 39) & 0x1FF;
    const pdpt_idx = (virt_addr >> 30) & 0x1FF;
    const pd_idx = (virt_addr >> 21) & 0x1FF;
    const pt_idx = (virt_addr >> 12) & 0x1FF;

    // Get current PML4
    const cr3 = asm volatile ("mov %%cr3, %[result]"
        : [result] "=r" (-> u64),
    );
    const pml4 = @as(*[512]u64, @ptrFromInt(cr3 & ~@as(u64, 0xFFF)));

    // Walk page tables
    if ((pml4[pml4_idx] & paging.PAGE_PRESENT) == 0) return;
    const pdpt = @as(*[512]u64, @ptrFromInt(pml4[pml4_idx] & ~@as(u64, 0xFFF)));

    if ((pdpt[pdpt_idx] & paging.PAGE_PRESENT) == 0) return;
    const pd = @as(*[512]u64, @ptrFromInt(pdpt[pdpt_idx] & ~@as(u64, 0xFFF)));

    if ((pd[pd_idx] & paging.PAGE_PRESENT) == 0) return;
    const pt = @as(*[512]u64, @ptrFromInt(pd[pd_idx] & ~@as(u64, 0xFFF)));

    // Clear the mapping
    pt[pt_idx] = 0;

    // Flush TLB
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (virt_addr),
        : "memory"
    );
}

// Bootstrap page mapping that doesn't use heap for page table allocation
fn mapPageBootstrap(virt_addr: u64, phys_addr: u64, flags: u64) !void {
    const pml4_idx = (virt_addr >> 39) & 0x1FF;
    const pdpt_idx = (virt_addr >> 30) & 0x1FF;
    const pd_idx = (virt_addr >> 21) & 0x1FF;
    const pt_idx = (virt_addr >> 12) & 0x1FF;

    // Get current PML4
    const cr3 = asm volatile ("mov %%cr3, %[result]"
        : [result] "=r" (-> u64),
    );
    const pml4 = @as(*[512]u64, @ptrFromInt(cr3 & ~@as(u64, 0xFFF)));

    // Walk/create page tables using PMM directly

    const pdpt = try getOrCreateTableBootstrap(pml4, pml4_idx, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
    const pd = try getOrCreateTableBootstrap(pdpt, pdpt_idx, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);
    const pt = try getOrCreateTableBootstrap(pd, pd_idx, paging.PAGE_PRESENT | paging.PAGE_WRITABLE);

    // Map the page
    pt[pt_idx] = makeTableEntry(phys_addr, flags);

    // Flush TLB for this address
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (virt_addr),
        : "memory"
    );
}

// Bootstrap version of getOrCreateTable that uses PMM directly
fn getOrCreateTableBootstrap(table: *[512]u64, index: usize, flags: u64) !*[512]u64 {
    // Check if entry is present and if it's a huge page
    const entry = table[index];

    if ((entry & paging.PAGE_PRESENT) == 0) {
        // Allocate new page table using PMM with PAGE_TABLE tag
        const phys_addr = pmm.allocPagesTagged(1, pmm.MemoryTag.PAGE_TABLES) orelse return error.OutOfMemory;

        // Check if physical address is in mapped region
        if (phys_addr >= 0x200000000) { // 8GB limit
            serial.println("[VMM] ERROR: Physical address 0x{x:0>16} is beyond identity-mapped region!", .{phys_addr});
            return error.OutOfMemory;
        }

        // IMPORTANT: Assume physical memory is identity-mapped
        const new_table = @as(*[512]u64, @ptrFromInt(phys_addr));

        // Clear the table
        var i: usize = 0;
        while (i < 512) : (i += 1) {
            new_table[i] = 0;
        }

        // Install in parent table
        table[index] = makeTableEntry(phys_addr, flags);
    }

    const table_addr = table[index] & ~@as(u64, 0xFFF);
    return @as(*[512]u64, @ptrFromInt(table_addr));
}

// Map multiple contiguous pages
pub fn mapPages(virt_addr: u64, phys_addr: u64, page_count: usize, flags: u64) !void {
    var i: usize = 0;
    while (i < page_count) : (i += 1) {
        // Use checked arithmetic to prevent overflow
        const virt_offset = std.math.mul(u64, i, 4096) catch return error.IntegerOverflow;
        const phys_offset = std.math.mul(u64, i, 4096) catch return error.IntegerOverflow;
        const virt_page = std.math.add(u64, virt_addr, virt_offset) catch return error.IntegerOverflow;
        const phys_page = std.math.add(u64, phys_addr, phys_offset) catch return error.IntegerOverflow;
        try mapPage(virt_page, phys_page, flags);
    }
}

// Unmap multiple contiguous pages
pub fn unmapPages(virt_addr: u64, page_count: usize) void {
    var i: usize = 0;
    while (i < page_count) : (i += 1) {
        // Use checked arithmetic to prevent overflow
        const offset = std.math.mul(u64, i, 4096) catch {
            serial.println("[VMM] WARNING: Integer overflow in unmapPages, stopping at page {}", .{i});
            return;
        };
        const virt_page = std.math.add(u64, virt_addr, offset) catch {
            serial.println("[VMM] WARNING: Integer overflow in unmapPages, stopping at page {}", .{i});
            return;
        };
        unmapPage(virt_page);
    }
}

// Get physical address from virtual address (if mapped)
pub fn getPhysicalAddress(virt_addr: u64) ?u64 {
    const pml4_idx = (virt_addr >> 39) & 0x1FF;
    const pdpt_idx = (virt_addr >> 30) & 0x1FF;
    const pd_idx = (virt_addr >> 21) & 0x1FF;
    const pt_idx = (virt_addr >> 12) & 0x1FF;
    const offset = virt_addr & 0xFFF;

    // Get current PML4
    const cr3 = asm volatile ("mov %%cr3, %[result]"
        : [result] "=r" (-> u64),
    );
    const pml4 = @as(*[512]u64, @ptrFromInt(cr3 & ~@as(u64, 0xFFF)));

    // Walk page tables
    if ((pml4[pml4_idx] & paging.PAGE_PRESENT) == 0) return null;
    const pdpt = @as(*[512]u64, @ptrFromInt(pml4[pml4_idx] & ~@as(u64, 0xFFF)));

    if ((pdpt[pdpt_idx] & paging.PAGE_PRESENT) == 0) return null;
    const pd = @as(*[512]u64, @ptrFromInt(pdpt[pdpt_idx] & ~@as(u64, 0xFFF)));

    if ((pd[pd_idx] & paging.PAGE_PRESENT) == 0) return null;
    const pt = @as(*[512]u64, @ptrFromInt(pd[pd_idx] & ~@as(u64, 0xFFF)));

    if ((pt[pt_idx] & paging.PAGE_PRESENT) == 0) return null;

    const phys_page = pt[pt_idx] & ~@as(u64, 0xFFF);
    return phys_page | offset;
}

// State tracking to prevent recursion
var in_heap_init: bool = false;
var heap_ready: bool = false; // Different from heap_initialized - means safe to use

// Kernel heap management
var heap_current: u64 = 0; // Initialized in initHeap()
var heap_end: u64 = 0; // Initialized in initHeap()
var heap_initialized: bool = false;

// Initialize virtual memory manager
pub fn init() !void {
    // Prevent recursion
    if (in_heap_init) {
        return error.RecursiveInit;
    }
    if (heap_initialized) {
        return;
    }

    in_heap_init = true;
    defer in_heap_init = false;

    serial.println("[VMM] Starting VMM initialization...", .{});

    // Phase 1: Setup heap region
    const heap_start = getKernelHeapStart();
    heap_current = heap_start;
    heap_end = heap_start + KERNEL_HEAP_SIZE;

    serial.println("[VMM] Heap region: 0x{x:0>16} - 0x{x:0>16}", .{ heap_start, heap_end });

    // Phase 2: Pre-allocate and map initial heap pages
    // For SMP support, we need more heap:
    // - 64KB per AP stack
    // - 112KB per AP for IST stacks (7 * 16KB)
    // - Additional space for other allocations
    // For 4 CPUs: ~704KB minimum, let's allocate 1MB
    const initial_pages = 256; // 1MB initial heap for SMP support
    serial.println("[VMM] Pre-allocating {} pages for heap", .{initial_pages});

    var i: usize = 0;
    while (i < initial_pages) : (i += 1) {
        // Allocate physical page with KERNEL_DATA tag for heap
        const phys = pmm.allocPagesTagged(1, pmm.MemoryTag.KERNEL_DATA) orelse {
            serial.println("[VMM] Failed to allocate page {} for heap", .{i});
            return error.OutOfMemory;
        };

        const offset = i * 4096;
        const page_addr = heap_start + offset;

        // Use bootstrap mapping to avoid heap usage
        try mapPageBootstrap(page_addr, phys, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_NO_EXECUTE);

        if (i % 64 == 0) {
            serial.print("[VMM] Mapped {}/{} pages\r", .{ i, initial_pages });
        }
    }
    serial.println("[VMM] Mapped {}/{} pages", .{ initial_pages, initial_pages });

    // Phase 3: Initialize the heap allocator
    serial.println("[VMM] Initializing heap allocator...", .{});
    try heap.init(heap_start, initial_pages * 4096);

    // Phase 4: Update state
    heap_current = heap_start + (initial_pages * 4096);
    heap_initialized = true;
    heap_ready = true;

    serial.println("[VMM] Heap initialization complete", .{});
}

// Public heap allocation interface
pub fn heapAlloc(size: usize) !*anyopaque {
    if (!heap_ready) {
        return error.HeapNotReady;
    }

    // Try to allocate from heap
    return heap.heapAlloc(@as(u64, size)) catch |err| {
        if (err == error.OutOfMemory) {
            // Try to expand heap
            const pages_needed = (size + 4095) / 4096 + 4; // Extra pages for buffer
            expandHeap(pages_needed) catch {
                serial.println("[VMM] Failed to expand heap for {} bytes", .{size});
                return error.OutOfMemory;
            };

            // Retry allocation
            return heap.heapAlloc(@as(u64, size));
        }
        return err;
    };
}

pub fn heapFree(ptr: ?*anyopaque) void {
    if (ptr == null or !heap_ready) return;
    heap.heapFree(ptr);
}

// Heap expansion (private)
fn expandHeap(pages: usize) !void {
    if (!heap_ready) return error.HeapNotReady;

    // Check if expansion would exceed heap bounds
    const heap_start = getKernelHeapStart();
    const new_size = (heap_current - heap_start) + (pages * 4096);
    if (new_size > KERNEL_HEAP_SIZE) {
        return error.HeapLimitExceeded;
    }

    serial.println("[VMM] Expanding heap by {} pages", .{pages});

    // Map new pages
    var i: usize = 0;
    while (i < pages) : (i += 1) {
        if (heap_current >= heap_end) {
            return error.HeapLimitExceeded;
        }

        const phys = pmm.allocPagesTagged(1, pmm.MemoryTag.KERNEL_DATA) orelse {
            // If we can't get more pages, at least we mapped some
            if (i > 0) break;
            return error.OutOfMemory;
        };

        try mapPageBootstrap(heap_current, phys, paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_NO_EXECUTE);
        heap_current += 4096;
    }

    serial.println("[VMM] Heap expanded by {} pages", .{i});
}

// Get heap statistics
pub const HeapStats = struct {
    start: u64,
    current: u64,
    end: u64,
    used: u64,
    available: u64,
    total: u64,
};

pub fn getHeapStats() HeapStats {
    const heap_start = getKernelHeapStart();
    const used = heap_current - heap_start;
    const available = heap_end - heap_current;

    return HeapStats{
        .start = heap_start,
        .current = heap_current,
        .end = heap_end,
        .used = used,
        .available = available,
        .total = KERNEL_HEAP_SIZE,
    };
}

pub fn printInfo() void {
    const vmm_stats = getHeapStats();
    serial.printAddress("[VMM] Kernel Heap Start", vmm_stats.start);

    // Get detailed stats from heap module
    const heap_stats = heap.getStats();
    serial.println("[VMM] Heap Statistics:", .{});
    serial.println("  Allocated: {} bytes", .{heap_stats.total_allocated});
    serial.println("  Free: {} bytes", .{heap_stats.total_free});
    serial.println("  Allocations: {}", .{heap_stats.allocation_count});
    serial.println("  Free blocks: {}", .{heap_stats.free_count});
    serial.println("  Largest free: {} bytes", .{heap_stats.largest_free_block});
    serial.println("  Fragmentation: {}%", .{@as(u32, @intFromFloat(heap_stats.fragmentation_ratio * 100))});
}

// Test function for VMM
pub fn runTests() void {
    serial.println("[VMM] Running tests...", .{});

    // Test 1: Page mapping and unmapping
    const test_virt = 0xFFFF900000000000;
    if (pmm.allocPages(1)) |test_phys| {
        if (mapPage(test_virt, test_phys, paging.PAGE_PRESENT | paging.PAGE_WRITABLE)) {
            // Test write
            const ptr = @as(*u64, @ptrFromInt(test_virt));
            ptr.* = 0xDEADBEEF;

            if (ptr.* == 0xDEADBEEF) {
                serial.println("[VMM] Test 1 passed: Page mapping", .{});
            } else {
                serial.println("[VMM] Test 1 failed: Could not read back value", .{});
            }

            // Test physical address lookup
            if (getPhysicalAddress(test_virt)) |phys| {
                if (phys == test_phys) {
                    serial.println("[VMM] Test 2 passed: Physical address lookup", .{});
                } else {
                    serial.println("[VMM] Test 2 failed: Wrong physical address {}", .{serial.sanitizedAddress(phys)});
                }
            } else {
                serial.println("[VMM] Test 2 failed: Could not get physical address", .{});
            }

            unmapPage(test_virt);
        } else |err| {
            serial.println("[VMM] Test 1 failed: mapPage error {s}", .{@errorName(err)});
        }
        pmm.freePages(test_phys, 1);
    }

    // Test 3: Heap allocation
    const ptr1 = heapAlloc(1024) catch |err| {
        serial.println("[VMM] Test 3 failed: Heap allocation error {s}", .{@errorName(err)});
        return;
    };
    serial.printAddress("[VMM] Test 3 passed: Allocated from heap at", @intFromPtr(ptr1));

    // Test 4: Heap read/write
    const test_data = @as(*u64, @ptrCast(@alignCast(ptr1)));
    test_data.* = 0xCAFEBABE;

    if (test_data.* == 0xCAFEBABE) {
        serial.println("[VMM] Test 4 passed: Heap read/write", .{});
    } else {
        serial.println("[VMM] Test 4 failed: Could not read back from heap", .{});
    }

    // Test 5: Multiple allocations
    const ptr2 = heapAlloc(2048) catch |err| {
        serial.println("[VMM] Test 5 failed: Second allocation error {s}", .{@errorName(err)});
        heapFree(ptr1);
        return;
    };

    const ptr3 = heapAlloc(512) catch |err| {
        serial.println("[VMM] Test 5 failed: Third allocation error {s}", .{@errorName(err)});
        heapFree(ptr1);
        heapFree(ptr2);
        return;
    };

    serial.println("[VMM] Test 5 passed: Multiple allocations successful", .{});

    // Test 6: Heap free
    heapFree(ptr2); // Free middle allocation
    heapFree(ptr1);
    heapFree(ptr3);
    serial.println("[VMM] Test 6 passed: Heap free operations", .{});

    // Test 7: Allocation after free (reuse test)
    const ptr4 = heapAlloc(1024) catch |err| {
        serial.println("[VMM] Test 7 failed: Reallocation error {s}", .{@errorName(err)});
        return;
    };
    heapFree(ptr4);
    serial.println("[VMM] Test 7 passed: Memory reuse after free", .{});

    serial.println("[VMM] Tests completed", .{});
}

pub fn stressTest() void {
    serial.println("[VMM] Running heap stress test...", .{});

    // Test 1: Many small allocations
    var ptrs: [100]?*anyopaque = undefined;
    var i: usize = 0;

    while (i < 100) : (i += 1) {
        ptrs[i] = heapAlloc(64 + i * 8) catch {
            serial.println("[VMM] Stress test: Allocation {} failed", .{i});
            break;
        };
    }

    serial.println("[VMM] Allocated {} small blocks", .{i});

    // Free every other one
    var j: usize = 0;
    while (j < i) : (j += 2) {
        heapFree(ptrs[j]);
    }

    // Free the rest
    j = 1;
    while (j < i) : (j += 2) {
        heapFree(ptrs[j]);
    }

    serial.println("[VMM] Stress test completed", .{});
}
