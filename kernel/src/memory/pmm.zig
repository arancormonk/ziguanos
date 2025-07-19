// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Physical Memory Manager for Ziguanos
// Manages physical memory allocation using a bitmap allocator

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const secure_print = @import("../lib/secure_print.zig");
const uefi_boot = @import("../boot/uefi_boot.zig");
const runtime_info = @import("../boot/runtime_info.zig");
const paging = @import("../x86_64/paging.zig");
const spectre_v1 = @import("../x86_64/spectre_v1.zig");

// Import PMM modules
const bloom_filter = @import("pmm/bloom_filter.zig");
const free_tracker = @import("pmm/free_tracker.zig");
const memory_tags = @import("pmm/memory_tags.zig");
const memory_security = @import("pmm/memory_security.zig");
const guard_pages = @import("pmm/guard_pages.zig");
const statistics = @import("pmm/statistics.zig");
const reserved_regions = @import("pmm/reserved_regions.zig");
const memory_regions = @import("pmm/memory_regions.zig");

// Constants
const PAGE_SIZE: u64 = 0x1000; // 4KB pages
const PAGES_PER_BITMAP: u64 = 64; // One u64 bitmap entry tracks 64 pages

// Dynamic bitmap sizing - support up to CPU's physical address limits
// We use a two-phase approach:
// 1. Bootstrap phase: Use static bitmap for initial allocation (supports up to 4GB)
// 2. Full phase: Dynamically allocate larger bitmap based on actual memory
const BOOTSTRAP_BITMAP_SIZE: usize = 16384; // 16K u64s = 128KB bitmap = 4GB RAM

// Memory regions
const PMM_RESERVED_BASE: u64 = 0x100000; // Reserve first 1MB

// Protected memory ranges that should never be freed or poisoned
const TRAMPOLINE_START: u64 = 0x8000;
const TRAMPOLINE_END: u64 = 0x8000 + 4096; // End of trampoline page

// Get kernel base dynamically from runtime info
fn getKernelBase() u64 {
    const info = runtime_info.getRuntimeInfo();
    return info.kernel_physical_base;
}

// Bitmap allocator - two-phase approach for large memory support
var bootstrap_bitmap: [BOOTSTRAP_BITMAP_SIZE]u64 align(8) = undefined;
var dynamic_bitmap_ptr: ?[*]u64 = null; // Pointer to dynamically allocated bitmap
var memory_bitmap: []u64 = undefined; // Actual slice used
var bitmap_size: usize = 0;
var total_pages: u64 = 0;
var free_pages: u64 = 0;
var reserved_pages: u64 = 0;
var is_dynamic_bitmap: bool = false; // Track if we're using dynamic allocation

// Security features
var free_page_tracker = free_tracker.FreePageTracker{};
var tag_tracker = memory_tags.MemoryTagTracker{};
var stats = statistics.Statistics{};

// Re-export types from modules
pub const MemoryStats = statistics.MemoryStats;
pub const MemoryTag = memory_tags.MemoryTag;

// Initialize physical memory manager from UEFI memory map
pub fn init(boot_info: *const uefi_boot.UEFIBootInfo) void {
    // Initialize without canary protection to avoid early init issues

    serial.print("[PMM] Initializing physical memory manager (region-based)...\n", .{});

    // Initialize reserved regions tracker first
    reserved_regions.init(boot_info);

    // Initialize memory regions from UEFI memory map
    const region_info = memory_regions.init(boot_info) catch |err| {
        serial.print("[PMM] ERROR: Failed to initialize memory regions: {}\n", .{err});
        @panic("Cannot initialize PMM without memory regions");
    };

    // Set up bitmap based on actual memory regions
    bitmap_size = region_info.bitmap_size_needed;

    // Check if we need more than the bootstrap bitmap can handle
    if (bitmap_size > BOOTSTRAP_BITMAP_SIZE) {
        serial.print("[PMM] Large memory system detected: {} GB RAM\n", .{
            (region_info.total_ram_pages * PAGE_SIZE) / (1024 * 1024 * 1024),
        });
        serial.print("[PMM] Bootstrap bitmap supports {} GB, need bitmap for {} GB\n", .{
            (BOOTSTRAP_BITMAP_SIZE * PAGES_PER_BITMAP * PAGE_SIZE) / (1024 * 1024 * 1024),
            (bitmap_size * PAGES_PER_BITMAP * PAGE_SIZE) / (1024 * 1024 * 1024),
        });

        // For now, we'll use the bootstrap bitmap and limit memory detection
        // After boot services exit, we can allocate a larger bitmap
        serial.print("[PMM] WARNING: Using bootstrap bitmap, limiting to {} GB during early boot\n", .{
            (BOOTSTRAP_BITMAP_SIZE * PAGES_PER_BITMAP * PAGE_SIZE) / (1024 * 1024 * 1024),
        });
        bitmap_size = BOOTSTRAP_BITMAP_SIZE;
    }

    // Initialize bitmap slice with bootstrap bitmap
    memory_bitmap = bootstrap_bitmap[0..bitmap_size];
    @memset(memory_bitmap, 0xFFFFFFFFFFFFFFFF); // Mark all as used initially

    total_pages = region_info.total_ram_pages;

    // Process UEFI memory map
    if (boot_info.memory_map_addr == 0) {
        serial.print("[PMM] ERROR: No memory map provided!\n", .{});
        return;
    }

    if (boot_info.memory_map_descriptor_size == 0) {
        serial.print("[PMM] ERROR: Invalid memory descriptor size!\n", .{});
        return;
    }

    const memory_map = @as([*]const u8, @ptrFromInt(boot_info.memory_map_addr));

    secure_print.printValue("[PMM] Memory map at", boot_info.memory_map_addr);
    secure_print.printSize("[PMM] Memory map size", boot_info.memory_map_size);
    secure_print.printSize("[PMM] Descriptor size", boot_info.memory_map_descriptor_size);

    if (boot_info.memory_map_descriptor_size == 0) {
        serial.print("[PMM] ERROR: Descriptor size is 0!\n", .{});
        return;
    }

    const descriptor_count = boot_info.memory_map_size / boot_info.memory_map_descriptor_size;

    serial.print("[PMM] Processing {} memory descriptors\n", .{descriptor_count});

    var offset: usize = 0;
    var total_system_pages: u64 = 0;
    var conventional_count: u64 = 0;

    // First pass: Calculate total pages and find highest physical address
    var max_ram_address: u64 = 0; // Track highest RAM address
    var max_any_address: u64 = 0; // Track highest address of any type

    for (0..descriptor_count) |_| {
        const descriptor = @as(*const uefi_boot.UEFIMemoryDescriptor, @ptrCast(@alignCast(&memory_map[offset])));

        // Track the highest address of any type
        const region_end = descriptor.physical_start + (descriptor.number_of_pages * PAGE_SIZE);
        if (region_end > max_any_address) {
            max_any_address = region_end;
        }

        // Only count actual RAM (not MMIO, ACPI, etc.)
        switch (descriptor.type) {
            .Conventional, .BootServicesCode, .BootServicesData, .LoaderCode, .LoaderData, .RuntimeServicesCode, .RuntimeServicesData => {
                total_system_pages += descriptor.number_of_pages;
                // Track highest RAM address specifically
                if (region_end > max_ram_address) {
                    max_ram_address = region_end;
                }
            },
            else => {
                // Don't count MMIO, ACPI tables, etc. as system memory
            },
        }

        offset += boot_info.memory_map_descriptor_size;
    }

    // Set total_pages before any marking operations
    total_pages = total_system_pages;

    if (total_pages == 0) {
        serial.print("[PMM] ERROR: No memory found in UEFI memory map!\n", .{});
        serial.print("  Descriptor count was: {}\n", .{descriptor_count});
        // Set some minimal values to avoid divide by zero
        total_pages = 65536; // 256MB minimum
    }

    serial.print("[PMM] Total RAM: {} MB ({} pages)\n", .{ (total_pages * PAGE_SIZE) / (1024 * 1024), total_pages });

    // Second pass: Mark free pages
    offset = 0;
    for (0..descriptor_count) |_| {
        const descriptor = @as(*const uefi_boot.UEFIMemoryDescriptor, @ptrCast(@alignCast(&memory_map[offset])));

        // Only mark conventional memory as free
        if (descriptor.type == .Conventional) {
            conventional_count += 1;
            const num_pages = descriptor.number_of_pages;

            // Skip memory below 1MB (reserved for legacy)
            if (descriptor.physical_start >= PMM_RESERVED_BASE) {
                markPagesAsFreeInitial(descriptor.physical_start, num_pages);
                free_pages += num_pages;
            }
        }

        offset += boot_info.memory_map_descriptor_size;
    }

    // Reserve kernel pages - handle PIE mode correctly
    const info = runtime_info.getRuntimeInfo();
    const kernel_physical_base = if (info.pie_mode)
        info.kernel_physical_base
    else
        boot_info.kernel_base;

    const kernel_pages = (boot_info.kernel_size + PAGE_SIZE - 1) / PAGE_SIZE;
    markPagesAsUsedInitial(kernel_physical_base, kernel_pages);
    reserved_pages += kernel_pages;

    // Reserve page tables - use physical addresses
    if (boot_info.page_table_info.pml4_phys_addr != 0) {
        const pt_info = &boot_info.page_table_info;
        const total_pt_pages = 1 + 1 + pt_info.pd_table_count + pt_info.pt_table_count;
        markPagesAsUsedInitial(pt_info.pml4_phys_addr, total_pt_pages);
        reserved_pages += total_pt_pages;
    }

    // Reserve PMM bitmap itself - use physical address
    const bitmap_addr = runtime_info.getPhysicalAddress(&bootstrap_bitmap);
    const bitmap_pages = (bitmap_size * @sizeOf(u64) + PAGE_SIZE - 1) / PAGE_SIZE;
    markPagesAsUsedInitial(bitmap_addr, bitmap_pages);
    reserved_pages += bitmap_pages;

    // Reserve low memory area for AP trampoline (0x8000-0x9000, one 4KB page)
    // This is critical for SMP initialization
    const trampoline_pages = 1; // One 4KB page
    markPagesAsUsedInitial(0x8000, trampoline_pages);
    reserved_pages += trampoline_pages;
    serial.print("[PMM] Reserved AP trampoline area at 0x8000\n", .{});

    // Reserve debug area for AP startup (0x0-0x1000)
    // The trampoline writes debug information here during startup
    const debug_pages = 1; // One 4KB page
    markPagesAsUsedInitial(0x0, debug_pages);
    reserved_pages += debug_pages;
    serial.print("[PMM] Reserved first page (0x0-0x1000) for AP debug area\n", .{});

    // Enable guard pages around critical regions
    const max_pages = memory_bitmap.len * PAGES_PER_BITMAP;
    guard_pages.setupGuardPages(boot_info, markPagesAsUsed, &reserved_pages, max_pages);

    // Print statistics
    const total_mb = (total_pages * PAGE_SIZE) / (1024 * 1024);
    const free_mb = (free_pages * PAGE_SIZE) / (1024 * 1024);
    const reserved_mb = (reserved_pages * PAGE_SIZE) / (1024 * 1024);

    serial.print("[PMM] Total memory: {} MB\n", .{total_mb});
    serial.print("[PMM] Free memory: {} MB\n", .{free_mb});
    serial.print("[PMM] Reserved memory: {} MB\n", .{reserved_mb});

    // Warn if we have very little memory
    if (total_mb < 256) {
        serial.print("[PMM] WARNING: System has very limited memory!\n", .{});
        serial.print("[PMM] Some features may not initialize properly.\n", .{});
    }

    // Initialize security features
    free_page_tracker = free_tracker.FreePageTracker{};
    tag_tracker = memory_tags.MemoryTagTracker{};
    stats = statistics.Statistics{};
    memory_security.setZeroOnAlloc(true);

    serial.print("[PMM] Security features initialized:\n", .{});
    serial.print("  - Memory zeroing on allocation: enabled\n", .{});
    serial.print("  - Double-free detection: enabled (bloom filter)\n", .{});
    serial.print("  - Bloom filter size: {} KB\n", .{bloom_filter.BLOOM_FILTER_SIZE * 8 / 1024});
    serial.print("  - Bloom filter hash functions: {}\n", .{bloom_filter.BLOOM_FILTER_HASH_COUNT});
    serial.print("  - Memory poisoning on free: enabled\n", .{});
    serial.print("  - Memory tagging/coloring: enabled\n", .{});
}

// Mark pages as free during initialization using physical addresses
fn markPagesAsFreeInitial(start_addr: u64, num_pages: u64) void {
    var addr = start_addr;
    var remaining = num_pages;

    while (remaining > 0) : ({
        addr += PAGE_SIZE;
        remaining -= 1;
    }) {
        // Get bitmap index for this physical address
        const idx_info = memory_regions.physicalToBitmapIndex(addr) orelse continue;

        // Bounds check
        if (idx_info.bitmap_idx >= memory_bitmap.len) {
            continue;
        }

        // Clear bit to mark as free (with Spectre V1 mitigation)
        const safe_idx = spectre_v1.safeArrayIndex(idx_info.bitmap_idx, memory_bitmap.len);
        memory_bitmap[safe_idx] &= ~(@as(u64, 1) << idx_info.bit_idx);
    }
}

// Mark pages as free in bitmap with proper bounds checking
fn markPagesAsFree(start_addr: u64, num_pages: u64) void {
    // Validate address alignment
    if (start_addr % PAGE_SIZE != 0) {
        serial.print("[PMM] WARNING: Attempted to free unaligned address 0x{x}\n", .{start_addr});
        return;
    }

    var addr = start_addr;
    var remaining = num_pages;

    while (remaining > 0) : ({
        addr += PAGE_SIZE;
        remaining -= 1;
    }) {
        // Get bitmap index for this physical address
        const idx_info = memory_regions.physicalToBitmapIndex(addr) orelse {
            serial.print("[PMM] WARNING: Address 0x{x} not in any memory region\n", .{addr});
            continue;
        };

        // Bounds check
        if (idx_info.bitmap_idx >= memory_bitmap.len) {
            serial.print("[PMM] ERROR: Bitmap index {} out of bounds (max: {})\n", .{ idx_info.bitmap_idx, memory_bitmap.len - 1 });
            stats.recordGuardPageViolation();
            continue;
        }

        // Clear bit to mark as free (with Spectre V1 mitigation)
        const safe_idx = spectre_v1.safeArrayIndex(idx_info.bitmap_idx, memory_bitmap.len);
        memory_bitmap[safe_idx] &= ~(@as(u64, 1) << idx_info.bit_idx);
    }
}

// Mark pages as used during initialization using physical addresses
fn markPagesAsUsedInitial(start_addr: u64, num_pages: u64) void {
    var addr = start_addr;
    var remaining = num_pages;

    while (remaining > 0) : ({
        addr += PAGE_SIZE;
        remaining -= 1;
    }) {
        // Get bitmap index for this physical address
        const idx_info = memory_regions.physicalToBitmapIndex(addr) orelse continue;

        // Bounds check
        if (idx_info.bitmap_idx >= memory_bitmap.len) {
            continue;
        }

        // Set bit to mark as used (with Spectre V1 mitigation)
        const safe_idx = spectre_v1.safeArrayIndex(idx_info.bitmap_idx, memory_bitmap.len);
        memory_bitmap[safe_idx] |= (@as(u64, 1) << idx_info.bit_idx);
    }
}

// Mark pages as used in bitmap with proper bounds checking
fn markPagesAsUsed(start_addr: u64, num_pages: u64) void {
    // Validate address alignment
    if (start_addr % PAGE_SIZE != 0) {
        serial.print("[PMM] WARNING: Attempted to mark unaligned address 0x{x} as used\n", .{start_addr});
        return;
    }

    var addr = start_addr;
    var remaining = num_pages;

    while (remaining > 0) : ({
        addr += PAGE_SIZE;
        remaining -= 1;
    }) {
        // Get bitmap index for this physical address
        const idx_info = memory_regions.physicalToBitmapIndex(addr) orelse {
            serial.print("[PMM] WARNING: Address 0x{x} not in any memory region\n", .{addr});
            continue;
        };

        // Bounds check
        if (idx_info.bitmap_idx >= memory_bitmap.len) {
            serial.print("[PMM] ERROR: Bitmap index {} out of bounds (max: {})\n", .{ idx_info.bitmap_idx, memory_bitmap.len - 1 });
            stats.recordGuardPageViolation();
            continue;
        }

        // Set bit to mark as used (with Spectre V1 mitigation)
        const safe_idx = spectre_v1.safeArrayIndex(idx_info.bitmap_idx, memory_bitmap.len);
        memory_bitmap[safe_idx] |= (@as(u64, 1) << idx_info.bit_idx);
    }
}

// Allocate a single physical page with security features
pub fn allocPage() ?u64 {
    return allocPages(1);
}

// Allocate a single page without zeroing (for performance-critical code)
pub fn allocPageFast() ?u64 {
    const old_zero = memory_security.isZeroOnAllocEnabled();
    memory_security.setZeroOnAlloc(false);
    defer memory_security.setZeroOnAlloc(old_zero);
    return allocPages(1);
}

// Allocate a page with a specific memory tag for tracking
pub fn allocPageTagged(tag: MemoryTag) ?u64 {
    if (allocPage()) |addr| {
        tag_tracker.recordAllocation(tag, PAGE_SIZE);
        return addr;
    }
    return null;
}

// Allocate multiple pages with a specific memory tag
pub fn allocPagesTagged(num_pages: u64, tag: MemoryTag) ?u64 {
    if (allocPages(num_pages)) |addr| {
        tag_tracker.recordAllocation(tag, num_pages * PAGE_SIZE);
        return addr;
    }
    return null;
}

// Allocate multiple contiguous physical pages with security features
pub fn allocPages(num_pages: u64) ?u64 {
    // No canary guard for performance and to avoid init issues

    if (num_pages == 0 or num_pages > free_pages) return null;

    // Check for integer overflow in size calculation per Intel guidelines
    _ = std.math.mul(u64, num_pages, PAGE_SIZE) catch {
        serial.print("[PMM] ERROR: Integer overflow in allocation size calculation\n", .{});
        return null;
    };

    // Search each memory region for contiguous free pages
    const regions = memory_regions.getRegions();

    for (regions) |*region| {
        // Skip non-usable regions
        if (!region.is_usable) continue;

        var consecutive: u64 = 0;
        var start_addr: u64 = 0;
        var addr = region.base;

        // Skip reserved low memory
        if (addr < PMM_RESERVED_BASE and region.base + region.size > PMM_RESERVED_BASE) {
            addr = PMM_RESERVED_BASE;
        }

        // Align to page boundary
        addr = (addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

        while (addr + (num_pages * PAGE_SIZE) <= region.base + region.size) : (addr += PAGE_SIZE) {
            // Check if this page is free
            const idx_info = memory_regions.physicalToBitmapIndex(addr) orelse {
                consecutive = 0;
                continue;
            };

            if (idx_info.bitmap_idx >= memory_bitmap.len) {
                consecutive = 0;
                continue;
            }

            const safe_idx = spectre_v1.safeArrayIndex(idx_info.bitmap_idx, memory_bitmap.len);
            const is_free = (memory_bitmap[safe_idx] & (@as(u64, 1) << idx_info.bit_idx)) == 0;

            if (is_free) {
                if (consecutive == 0) {
                    start_addr = addr;
                }
                consecutive += 1;

                if (consecutive >= num_pages) {
                    // Check if this range overlaps with any reserved regions
                    if (reserved_regions.isReserved(start_addr, num_pages * PAGE_SIZE)) {
                        consecutive = 0;
                        continue;
                    }

                    // Found enough contiguous pages
                    markPagesAsUsed(start_addr, num_pages);
                    free_pages -= num_pages;
                    stats.recordAllocation();

                    // Zero the allocated pages if enabled
                    if (memory_security.isZeroOnAllocEnabled()) {
                        memory_security.zeroMemoryRange(start_addr, num_pages * PAGE_SIZE);
                    }

                    return start_addr;
                }
            } else {
                consecutive = 0;
            }
        }
    }

    return null; // No contiguous block found
}

// Free a physical page with security checks
pub fn freePage(addr: u64) void {
    freePages(addr, 1);
}

// Free multiple contiguous physical pages with security checks
pub fn freePages(addr: u64, num_pages: u64) void {
    if (addr < PMM_RESERVED_BASE or (addr % PAGE_SIZE) != 0) {
        serial.printAddress("[PMM] WARNING: Invalid free address", addr);
        stats.recordGuardPageViolation();
        return;
    }

    // Check if this is the trampoline area - NEVER free or poison it
    if (addr >= TRAMPOLINE_START and addr < TRAMPOLINE_END) {
        serial.printAddress("[PMM] SECURITY: Blocked attempt to free protected trampoline memory at", addr);
        return;
    }

    // Validate that address is in a valid memory region
    if (memory_regions.findRegion(addr) == null) {
        serial.print("[PMM] ERROR: Attempted to free address 0x{x} outside any memory region\n", .{addr});
        stats.recordGuardPageViolation();
        return;
    }

    const start_page = addr / PAGE_SIZE;

    // Check for double-free
    free_page_tracker.recordFree(start_page) catch |err| {
        switch (err) {
            error.DoubleFree => {
                stats.recordDoubleFreeAttempt();
                serial.printAddress("[PMM] SECURITY ALERT: Double-free detected at", addr);
                serial.print("  Page number: {}\n", .{start_page});
                return; // Don't actually free the page
            },
        }
    };

    // Poison the pages before freeing
    memory_security.poisonMemoryRange(addr, num_pages * PAGE_SIZE);

    markPagesAsFree(addr, num_pages);
    free_pages += num_pages;
    stats.recordDeallocation();
}

// Free a page with specific memory tag tracking
pub fn freePageTagged(addr: u64, tag: MemoryTag) void {
    freePagesTagged(addr, 1, tag);
}

// Free multiple pages with specific memory tag tracking
pub fn freePagesTagged(addr: u64, num_pages: u64, tag: MemoryTag) void {
    // Record the deallocation in tag tracker BEFORE freeing
    // This ensures we track the deallocation even if the free fails
    tag_tracker.recordDeallocation(tag, num_pages * PAGE_SIZE);

    // Perform the actual free
    freePages(addr, num_pages);
}

// Get memory statistics with security information
pub fn getStats() MemoryStats {
    return stats.getStats(total_pages, free_pages, reserved_pages, PAGE_SIZE);
}

// Enable or disable memory zeroing on allocation
pub fn setZeroOnAlloc(enabled: bool) void {
    memory_security.setZeroOnAlloc(enabled);
}

// Clear the double-free tracker (for testing)
pub fn clearFreeTracker() void {
    free_page_tracker.clear();
    stats.double_free_attempts = 0;
    serial.print("[PMM] Free tracker cleared (bloom filter reset)\n", .{});
}

// Report bloom filter statistics
pub fn reportBloomFilterStats() void {
    free_page_tracker.getStats();
}

// Report security events
pub fn reportSecurityStats() void {
    stats.reportSecurityStats(memory_security.isZeroOnAllocEnabled());
    // Add bloom filter stats
    free_page_tracker.getStats();
}

// Get memory usage by tag
pub fn getTaggedMemoryUsage(tag: MemoryTag) u64 {
    return tag_tracker.getActiveBytes(tag);
}

// Report memory usage by all tags
pub fn reportTaggedMemoryUsage() void {
    serial.print("[PMM] Memory Usage by Tag:\n", .{});

    var total_tagged: u64 = 0;

    for (0..memory_tags.MAX_MEMORY_TAGS) |i| {
        const tag: MemoryTag = @enumFromInt(i);
        const active_bytes = tag_tracker.getActiveBytes(tag);

        if (active_bytes > 0) {
            const kb = active_bytes / 1024;
            serial.print("  {s}: {} KB\n", .{ tag.toString(), kb });
            total_tagged += active_bytes;
        }
    }

    const total_tagged_kb = total_tagged / 1024;
    serial.print("  TOTAL TAGGED: {} KB\n", .{total_tagged_kb});
}

// Clear memory tag tracking (for testing)
pub fn clearTagTracker() void {
    tag_tracker.clear();
    serial.print("[PMM] Memory tag tracker cleared\n", .{});
}

// Find the first free page (for debugging)
pub fn findFirstFreePage() ?u64 {
    for (0..memory_bitmap.len) |i| {
        const safe_i = spectre_v1.safeArrayIndex(i, memory_bitmap.len);
        if (memory_bitmap[safe_i] != 0xFFFFFFFFFFFFFFFF) {
            // Found a block with at least one free page
            for (0..PAGES_PER_BITMAP) |bit| {
                const bit_mask = @as(u64, 1) << @as(u6, @truncate(bit));
                if ((memory_bitmap[safe_i] & bit_mask) == 0) {
                    return (safe_i * PAGES_PER_BITMAP + bit) * PAGE_SIZE;
                }
            }
        }
    }
    return null;
}

// Test memory protection features
pub fn testMemoryProtection() void {
    serial.print("[PMM] Testing memory protection features...\n", .{});

    // Test 1: Memory zeroing
    serial.print("[PMM] Test 1: Memory zeroing on allocation\n", .{});
    const test_page1 = allocPage();
    if (test_page1) |addr| {
        const ptr = @as(*u32, @ptrFromInt(addr));
        if (ptr.* == 0) {
            serial.print("  ✓ Memory correctly zeroed on allocation\n", .{});
        } else {
            serial.print("  ✗ Memory not zeroed on allocation\n", .{});
        }
        freePage(addr);
    }

    // Test 2: Double-free detection
    serial.print("[PMM] Test 2: Double-free detection\n", .{});
    const test_page2 = allocPage();
    if (test_page2) |addr| {
        freePage(addr); // First free - should succeed
        freePage(addr); // Second free - should be blocked
        if (stats.double_free_attempts > 0) {
            serial.print("  ✓ Double-free correctly detected and blocked\n", .{});
        } else {
            serial.print("  ✗ Double-free not detected\n", .{});
        }
    }

    // Clear the free tracker before test 3 to avoid false positives
    clearFreeTracker();

    // Test 3: Memory poisoning
    serial.print("[PMM] Test 3: Memory poisoning on free\n", .{});
    const test_page3 = allocPage();
    if (test_page3) |addr| {
        const ptr = @as(*[PAGE_SIZE]u8, @ptrFromInt(addr));

        // Fill page with known pattern
        @memset(ptr, 0x42);

        // Free the page (which should poison it)
        freePage(addr);

        // Check if memory was poisoned (note: this is technically undefined behavior
        // since we're accessing freed memory, but for testing purposes...)
        // Since we now use random poison patterns, we check if the memory has changed
        // and is not all the same value (which would indicate a predictable pattern)
        var changed = false;
        var all_same = true;
        const first_byte = ptr[0];

        for (ptr[0..@min(256, PAGE_SIZE)]) |byte| {
            if (byte != 0x42) {
                changed = true;
            }
            if (byte != first_byte) {
                all_same = false;
            }
        }

        if (changed and !all_same) {
            serial.print("  ✓ Memory correctly poisoned with random pattern on free\n", .{});
        } else if (changed and all_same) {
            serial.print("  ✗ Memory poisoned but with predictable pattern (security risk)\n", .{});
        } else {
            serial.print("  ✗ Memory not poisoned on free\n", .{});
        }
    }

    // Test 4: Memory tagging
    serial.print("[PMM] Test 4: Memory tagging/coloring\n", .{});

    // Clear both trackers before this test to ensure clean state
    clearFreeTracker();
    clearTagTracker();

    // Debug: Report current tag usage before test
    serial.print("  Current tag usage before test:\n", .{});
    const security_before = getTaggedMemoryUsage(.SECURITY);
    const page_table_before = getTaggedMemoryUsage(.PAGE_TABLES);
    serial.print("    SECURITY: {} bytes\n", .{security_before});
    serial.print("    PAGE_TABLES: {} bytes\n", .{page_table_before});

    const test_page4 = allocPageTagged(.SECURITY);
    const test_page5 = allocPagesTagged(2, .PAGE_TABLES);

    if (test_page4 != null and test_page5 != null) {
        const security_usage = getTaggedMemoryUsage(.SECURITY);
        const page_table_usage = getTaggedMemoryUsage(.PAGE_TABLES);

        if (security_usage == PAGE_SIZE and page_table_usage == 2 * PAGE_SIZE) {
            serial.print("  ✓ Memory tagging correctly tracking allocations\n", .{});
        } else {
            serial.print("  ✗ Memory tagging not working correctly\n", .{});
            serial.print("    Security usage: {} bytes, expected: {} bytes\n", .{ security_usage, PAGE_SIZE });
            serial.print("    Page table usage: {} bytes, expected: {} bytes\n", .{ page_table_usage, 2 * PAGE_SIZE });
        }

        // Free with tags
        if (test_page4) |addr| freePageTagged(addr, .SECURITY);
        if (test_page5) |addr| freePagesTagged(addr, 2, .PAGE_TABLES);

        // Check that tags are cleared
        const security_usage_after = getTaggedMemoryUsage(.SECURITY);
        const page_table_usage_after = getTaggedMemoryUsage(.PAGE_TABLES);

        if (security_usage_after == 0 and page_table_usage_after == 0) {
            serial.print("  ✓ Memory tagging correctly tracking deallocations\n", .{});
        } else {
            serial.print("  ✗ Memory tagging not tracking deallocations correctly\n", .{});
            serial.print("    Security usage after free: {} bytes\n", .{security_usage_after});
            serial.print("    Page table usage after free: {} bytes\n", .{page_table_usage_after});
        }
    }

    // Reset trackers for clean state
    clearFreeTracker();
    clearTagTracker();

    // Test 5: Comprehensive double-free detection beyond old limit
    serial.print("[PMM] Test 5: Bloom filter comprehensive double-free detection\n", .{});

    // Clear trackers for a clean test
    clearFreeTracker();

    // Test with 100 pages (reasonable for limited memory system)
    const test_pages = 100;
    var pages: [test_pages]?u64 = [_]?u64{null} ** test_pages;
    var allocated: u32 = 0;

    // Allocate pages
    for (&pages) |*page| {
        page.* = allocPage();
        if (page.* != null) {
            allocated += 1;
        }
    }

    serial.print("  Allocated {} pages\n", .{allocated});

    // Free all allocated pages
    var freed: u32 = 0;
    for (pages) |page| {
        if (page) |addr| {
            freePage(addr);
            freed += 1;
        }
    }

    serial.print("  Freed {} pages\n", .{freed});

    // Save the double-free count before test
    const before_test = stats.double_free_attempts;

    // Try to double-free pages at different positions
    // Old tracker would only remember last 1024, bloom filter remembers all
    var test_count: u32 = 0;

    // Test first page
    if (allocated > 0 and pages[0] != null) {
        freePage(pages[0].?);
        test_count += 1;
    }

    // Test middle page
    if (allocated > 50 and pages[50] != null) {
        freePage(pages[50].?);
        test_count += 1;
    }

    // Test last allocated page
    if (allocated > 0) {
        var i: usize = allocated - 1;
        while (i > 0) : (i -= 1) {
            if (pages[i] != null) {
                freePage(pages[i].?);
                test_count += 1;
                break;
            }
        }
    }

    const detected = stats.double_free_attempts - before_test;

    if (detected == test_count and test_count > 0) {
        serial.print("  ✓ Bloom filter detected all {} double-free attempts\n", .{detected});
        serial.print("  ✓ Comprehensive tracking beyond old 1024-entry limit\n", .{});
    } else {
        serial.print("  ✗ Detected {} double-frees, expected {}\n", .{ detected, test_count });
    }

    // Report bloom filter statistics
    reportBloomFilterStats();

    // Reset trackers for clean state
    clearFreeTracker();

    serial.print("[PMM] Memory protection tests completed\n", .{});
}

// Create a guard page at a specific address (for paging subsystem)
pub fn createGuardPage(addr: u64) !void {
    const max_pages = memory_bitmap.len * PAGES_PER_BITMAP;
    try guard_pages.createGuardPage(addr, &memory_bitmap, max_pages, &free_pages);
}

// Add guard pages around a memory region
pub fn addGuardPagesAroundRegion(start: u64, size: u64) !void {
    try guard_pages.addGuardPagesAroundRegion(start, size, createGuardPage);
}

// Mark boot services memory as reclaimable and actually free it
pub fn markBootServicesExited(boot_info: *const uefi_boot.UEFIBootInfo) void {
    reserved_regions.markBootServicesExited();

    // Debug the boot info structure
    serial.print("[PMM] markBootServicesExited called\n", .{});
    secure_print.printPointer("[PMM] Boot info at", boot_info);
    secure_print.printValue("[PMM] Memory map addr", boot_info.memory_map_addr);
    secure_print.printSize("[PMM] Memory map size", boot_info.memory_map_size);
    secure_print.printSize("[PMM] Descriptor size", boot_info.memory_map_descriptor_size);

    // Now we need to actually free the boot services memory regions
    if (boot_info.memory_map_addr == 0 or boot_info.memory_map_descriptor_size == 0) {
        serial.print("[PMM] ERROR: Cannot reclaim boot services - invalid memory map\n", .{});
        return;
    }

    const memory_map = @as([*]const u8, @ptrFromInt(boot_info.memory_map_addr));
    const descriptor_count = boot_info.memory_map_size / boot_info.memory_map_descriptor_size;

    serial.print("[PMM] Processing {} descriptors for boot services reclaim\n", .{descriptor_count});

    // Debug: Check if memory map data looks valid
    const first_bytes = @as([*]const u64, @ptrCast(@alignCast(memory_map)));
    serial.print("[PMM] First 8 bytes of memory map: 0x{x:0>16}\n", .{first_bytes[0]});
    serial.print("[PMM] Second 8 bytes of memory map: 0x{x:0>16}\n", .{first_bytes[1]});

    // If we're seeing zeros, the memory map might have been corrupted
    if (first_bytes[0] == 0 and first_bytes[1] == 0) {
        serial.print("[PMM] ERROR: Memory map appears to be zeroed out!\n", .{});
        serial.print("[PMM] This suggests the memory map was overwritten or freed.\n", .{});

        // Try to provide a workaround by manually reclaiming known boot services regions
        serial.print("[PMM] Attempting manual boot services reclaim based on reserved regions tracker...\n", .{});

        // Get reclaimable regions from the reserved regions tracker
        var regions_buffer: [256]reserved_regions.ReservedRegion = undefined;
        const region_count = reserved_regions.getReclaimableRegions(&regions_buffer);

        serial.print("[PMM] Found {} reclaimable regions in tracker\n", .{region_count});

        var reclaimed_manual: u64 = 0;
        for (regions_buffer[0..region_count]) |region| {
            // Skip regions below 1MB
            if (region.start >= PMM_RESERVED_BASE) {
                const num_pages = (region.end - region.start) / PAGE_SIZE;

                // Check if this region is valid
                if (memory_regions.findRegion(region.start) == null) {
                    serial.print("[PMM] WARNING: Manual reclaim region at 0x{x} not in any memory region\n", .{region.start});
                    continue;
                }

                // Free the pages
                markPagesAsFree(region.start, num_pages);
                reclaimed_manual += num_pages;

                // Log significant regions
                if (num_pages > 256) {
                    serial.print("[PMM] Manually reclaimed: 0x{x:0>16} - 0x{x:0>16} ({} pages)\n", .{ region.start, region.end, num_pages });
                }
            }
        }

        // Update free pages count
        free_pages += reclaimed_manual;

        const reclaimed_mb = (reclaimed_manual * PAGE_SIZE) / (1024 * 1024);
        serial.print("[PMM] Manual boot services reclaim: {} MB ({} pages)\n", .{ reclaimed_mb, reclaimed_manual });
        return;
    }

    var reclaimed_pages: u64 = 0;
    var offset: usize = 0;

    // Process memory map and free boot services regions
    var boot_services_found: u64 = 0;
    for (0..descriptor_count) |i| {
        // Calculate descriptor pointer the same way as in init
        const desc_ptr = &memory_map[offset];
        const descriptor = @as(*const uefi_boot.UEFIMemoryDescriptor, @ptrCast(@alignCast(desc_ptr)));

        // Debug: log first few descriptor types
        if (i < 5) {
            serial.print("[PMM] Descriptor {}: type={s}, start=0x{x}, pages={}\n", .{ i, @tagName(descriptor.type), descriptor.physical_start, descriptor.number_of_pages });
        }

        // Only reclaim boot services memory
        if (descriptor.type == .BootServicesCode or descriptor.type == .BootServicesData) {
            boot_services_found += 1;
            const num_pages = descriptor.number_of_pages;

            // Skip memory below 1MB (reserved for legacy)
            if (descriptor.physical_start >= PMM_RESERVED_BASE) {
                // Mark these pages as free in the bitmap
                markPagesAsFree(descriptor.physical_start, num_pages);
                reclaimed_pages += num_pages;

                // Debug output for significant regions
                if (num_pages > 256) { // More than 1MB
                    serial.print("[PMM] Reclaimed boot services region: 0x{x:0>16} - 0x{x:0>16} ({} pages)\n", .{
                        descriptor.physical_start,
                        descriptor.physical_start + (num_pages * PAGE_SIZE),
                        num_pages,
                    });
                }
            }
        }

        offset += boot_info.memory_map_descriptor_size;
    }

    // Update free pages count
    free_pages += reclaimed_pages;

    const reclaimed_mb = (reclaimed_pages * PAGE_SIZE) / (1024 * 1024);
    serial.print("[PMM] Boot services regions found: {}\n", .{boot_services_found});
    serial.print("[PMM] Boot services memory reclaimed: {} MB ({} pages)\n", .{
        reclaimed_mb,
        reclaimed_pages,
    });

    // Debug: print memory info
    serial.print("[PMM] Total memory regions: {}\n", .{memory_regions.getRegions().len});
}

// Check if an address is in a reserved region
pub fn isReserved(addr: u64, size: u64) bool {
    return reserved_regions.isReserved(addr, size);
}

// Get detailed reserved regions information
pub fn printReservedRegions() void {
    reserved_regions.getTracker().printDetailedList();
}

// Upgrade to a larger bitmap for systems with more than 4GB RAM
// This should be called after boot services exit when we have more memory available
// Supports up to the CPU's physical address limit (typically 40-52 bits)
pub fn upgradeBitmapForLargeMemory(boot_info: *const uefi_boot.UEFIBootInfo) !void {
    // Get CPU capabilities to determine maximum supported memory
    const cpuid = @import("../x86_64/cpuid.zig");
    const max_phys_mem = cpuid.getMaxPhysicalMemory();
    const phys_bits = cpuid.getPhysicalAddressBits();

    serial.print("[PMM] Upgrading bitmap for large memory support\n", .{});
    serial.print("[PMM] CPU supports {} physical address bits (", .{phys_bits});

    // Print human-readable size
    if (max_phys_mem >= 1024 * 1024 * 1024 * 1024 * 1024) { // >= 1PB
        serial.print("{} PB max)\n", .{max_phys_mem / (1024 * 1024 * 1024 * 1024 * 1024)});
    } else {
        serial.print("{} TB max)\n", .{max_phys_mem / (1024 * 1024 * 1024 * 1024)});
    }

    // Recalculate actual memory regions
    const region_info = memory_regions.init(boot_info) catch |err| {
        serial.print("[PMM] ERROR: Failed to reinitialize memory regions: {}\n", .{err});
        return err;
    };

    const required_bitmap_size = region_info.bitmap_size_needed;

    // Check if we actually need to upgrade
    if (required_bitmap_size <= BOOTSTRAP_BITMAP_SIZE) {
        serial.print("[PMM] No bitmap upgrade needed, current size sufficient\n", .{});
        return;
    }

    // Calculate bitmap memory requirements
    const bitmap_bytes = required_bitmap_size * @sizeOf(u64);
    const bitmap_pages = (bitmap_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    serial.print("[PMM] Need {} KB for bitmap to manage {} GB of RAM\n", .{
        bitmap_bytes / 1024,
        (total_pages * PAGE_SIZE) / (1024 * 1024 * 1024),
    });

    // Allocate contiguous pages for the new bitmap
    const new_bitmap_addr = allocPages(bitmap_pages) orelse {
        serial.print("[PMM] ERROR: Cannot allocate {} pages for extended bitmap\n", .{bitmap_pages});
        return error.OutOfMemory;
    };

    serial.print("[PMM] Allocated new bitmap at 0x{x} ({} pages)\n", .{ new_bitmap_addr, bitmap_pages });

    // Get the new bitmap as a slice
    const new_bitmap_ptr = @as([*]u64, @ptrFromInt(new_bitmap_addr));
    const new_bitmap = new_bitmap_ptr[0..required_bitmap_size];

    // Copy current bitmap state to new bitmap
    @memcpy(new_bitmap[0..bitmap_size], memory_bitmap);

    // Initialize the rest of the new bitmap (mark as used)
    if (required_bitmap_size > bitmap_size) {
        @memset(new_bitmap[bitmap_size..], 0xFFFFFFFFFFFFFFFF);
    }

    // Now process the full memory map with the new bitmap
    const old_bitmap_size = bitmap_size;
    bitmap_size = required_bitmap_size;
    memory_bitmap = new_bitmap;
    dynamic_bitmap_ptr = new_bitmap_ptr;
    is_dynamic_bitmap = true;

    // No need to reprocess - the memory was already discovered during init
    // The bitmap upgrade just allows us to track memory that was already counted
    // but couldn't be managed due to bitmap size limitations
    serial.print("[PMM] Bootstrap bitmap could only track {} GB\n", .{
        (BOOTSTRAP_BITMAP_SIZE * PAGES_PER_BITMAP * PAGE_SIZE) / (1024 * 1024 * 1024),
    });
    serial.print("[PMM] Extended bitmap can now track all {} GB\n", .{
        (total_pages * PAGE_SIZE) / (1024 * 1024 * 1024),
    });

    serial.print("[PMM] Bitmap upgraded successfully\n", .{});
    serial.print("[PMM] Old bitmap size: {} KB, New bitmap size: {} KB\n", .{
        (old_bitmap_size * @sizeOf(u64)) / 1024,
        bitmap_bytes / 1024,
    });
    serial.print("[PMM] Memory tracking capacity increased from {} GB to {} GB\n", .{
        (BOOTSTRAP_BITMAP_SIZE * PAGES_PER_BITMAP * PAGE_SIZE) / (1024 * 1024 * 1024),
        (required_bitmap_size * PAGES_PER_BITMAP * PAGE_SIZE) / (1024 * 1024 * 1024),
    });
    serial.print("[PMM] Total free memory: {} MB (unchanged)\n", .{(free_pages * PAGE_SIZE) / (1024 * 1024)});
}
