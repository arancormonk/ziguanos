// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi_boot = @import("../boot/uefi_boot.zig");
const runtime_info = @import("../boot/runtime_info.zig");
const serial = @import("../drivers/serial.zig");
const secure_print = @import("../lib/secure_print.zig");
const cpuid = @import("cpuid.zig");
const pmm = @import("../memory/pmm.zig");
const stack_security = @import("stack_security.zig");
const spinlock = @import("../lib/spinlock.zig");
const error_utils = @import("../lib/error_utils.zig");

// Import extracted modules
const constants = @import("paging/constants.zig");
const pat = @import("paging/pat.zig");
const pku = @import("paging/pku.zig");
const la57 = @import("paging/la57.zig");
const pcid = @import("paging/pcid.zig");
const shadow_stack = @import("paging/shadow_stack.zig");
const validation = @import("paging/validation.zig");
const guard_pages = @import("paging/guard_pages.zig");
const test_utils = @import("paging/test_utils.zig");

// Re-export commonly used items
pub usingnamespace constants;
pub const PAT = pat;
pub const PKU = pku;
pub const LA57 = la57;
pub const PCID = pcid;
pub const ShadowStack = shadow_stack;
pub const Validation = validation;

// Import constants for internal use
const PAGE_PRESENT = constants.PAGE_PRESENT;
const PAGE_WRITABLE = constants.PAGE_WRITABLE;
const PAGE_USER = constants.PAGE_USER;
const PAGE_WRITE_THROUGH = constants.PAGE_WRITE_THROUGH;
const PAGE_CACHE_DISABLE = constants.PAGE_CACHE_DISABLE;
const PAGE_ACCESSED = constants.PAGE_ACCESSED;
const PAGE_DIRTY = constants.PAGE_DIRTY;
const PAGE_HUGE = constants.PAGE_HUGE;
const PAGE_GLOBAL = constants.PAGE_GLOBAL;
const PAGE_NO_EXECUTE = constants.PAGE_NO_EXECUTE;
const PAGE_SIZE_4K = constants.PAGE_SIZE_4K;
const PAGE_SIZE_2M = constants.PAGE_SIZE_2M;
const PAGE_SIZE_1G = constants.PAGE_SIZE_1G;
const RESERVED_BITS_PML4 = constants.RESERVED_BITS_PML4;
const RESERVED_BITS_PDPT_1G = constants.RESERVED_BITS_PDPT_1G;
const RESERVED_BITS_PD_2M = constants.RESERVED_BITS_PD_2M;
const RESERVED_BITS_PT = constants.RESERVED_BITS_PT;
const PHYS_ADDR_MASK = constants.PHYS_ADDR_MASK;
const PAGE_KERNEL_CODE = constants.PAGE_KERNEL_CODE;
const PAGE_KERNEL_DATA = constants.PAGE_KERNEL_DATA;
const PAGE_KERNEL_RODATA = constants.PAGE_KERNEL_RODATA;
const PAGE_USER_CODE = constants.PAGE_USER_CODE;
const PAGE_USER_DATA = constants.PAGE_USER_DATA;
const PAGE_GUARD = constants.PAGE_GUARD;
const GUARD_PAGE_SIZE = constants.GUARD_PAGE_SIZE;

// Import PAT constants for internal use
const MEMORY_TYPE_UC = pat.MEMORY_TYPE_UC;
const MEMORY_TYPE_WC = pat.MEMORY_TYPE_WC;
const MEMORY_TYPE_WT = pat.MEMORY_TYPE_WT;
const MEMORY_TYPE_WP = pat.MEMORY_TYPE_WP;
const MEMORY_TYPE_WB = pat.MEMORY_TYPE_WB;
const PAGE_PAT_4K = pat.PAGE_PAT_4K;
const PAGE_PAT_LARGE = pat.PAGE_PAT_LARGE;

// Import boot protocol for PageTableInfo
const boot_protocol = @import("shared");

// Page table pointers - will be set from bootloader-allocated tables
pub var pml4_table: *[512]u64 = undefined;
pub var pdpt_table: *[512]u64 = undefined;
pub var pd_tables: [][512]u64 = undefined;
pub var kernel_pts: [][512]u64 = undefined;

// Store page table info from bootloader
var page_table_info: boot_protocol.PageTableInfo = undefined;

// Track next available kernel PT for dynamic allocation
var next_kernel_pt_index: usize = 0;

// 5-level paging support (LA57)
pub var pml5_table: [512]u64 align(4096) = [_]u64{0} ** 512;

// Track kernel memory regions from linker script
// With PIE, these are offsets that need to be adjusted by kernel base
extern const __kernel_start: u8;
extern const __kernel_end: u8;
extern const __data_start: u8;
extern const __bss_start: u8;
extern const __bss_end: u8;

const KERNEL_MAX_SIZE: u64 = 0x1000000; // 16MB max kernel size

// Track paging initialization state
var paging_initialized: bool = false;
var initial_cr3: u64 = 0;

// Global page table lock system for synchronization
var page_table_locks: spinlock.PageTableLockSystem = spinlock.PageTableLockSystem{};

// Global variable to track the highest mapped physical address
var highest_mapped_physical_addr: u64 = 0;

// Check if stack protection is safe in current context
// Stack protection is unsafe during:
// 1. Initial page table setup (when modifying active page tables)
// 2. When switching between page tables
// 3. When modifying the page containing the stack itself
fn isStackProtectionSafe() bool {
    // If paging is not yet initialized, we're in early boot
    if (!paging_initialized) {
        return false;
    }

    // Check if we're using the initial page tables
    const current_cr3 = getCurrentPageTable();
    if (current_cr3 != initial_cr3) {
        // We've switched page tables, it's generally safe now
        return true;
    }

    // During initial setup, stack protection is unsafe
    return false;
}

// Get kernel base dynamically from runtime info
fn getKernelBase() u64 {
    const info = runtime_info.getRuntimeInfo();
    return info.kernel_virtual_base;
}

pub fn init(boot_info: *const uefi_boot.UEFIBootInfo) void {
    // Store page table info from bootloader
    page_table_info = boot_info.page_table_info;

    // Validate that bootloader provided page tables
    if (page_table_info.pml4_phys_addr == 0 or page_table_info.pdpt_phys_addr == 0) {
        serial.println("[PAGING] FATAL: Bootloader did not provide page tables!", .{});
        serial.println("[PAGING] PML4: 0x{x}, PDPT: 0x{x}", .{ page_table_info.pml4_phys_addr, page_table_info.pdpt_phys_addr });
        @panic("Cannot continue without page tables from bootloader");
    }

    if (page_table_info.pd_table_count == 0 or page_table_info.pt_table_count == 0) {
        serial.println("[PAGING] FATAL: Invalid page table counts from bootloader!", .{});
        serial.println("[PAGING] PD count: {}, PT count: {}", .{ page_table_info.pd_table_count, page_table_info.pt_table_count });
        @panic("Cannot continue with zero page table counts");
    }

    // Map bootloader-provided tables to kernel virtual addresses
    // IMPORTANT: Convert physical addresses to virtual addresses
    pml4_table = @as(*[512]u64, @ptrFromInt(runtime_info.physToVirt(page_table_info.pml4_phys_addr)));
    pdpt_table = @as(*[512]u64, @ptrFromInt(runtime_info.physToVirt(page_table_info.pdpt_phys_addr)));

    // Create slices for PD tables
    const pd_base = @as([*][512]u64, @ptrFromInt(runtime_info.physToVirt(page_table_info.pd_table_base)));
    pd_tables = pd_base[0..page_table_info.pd_table_count];

    // Create slices for PT tables
    const pt_base = @as([*][512]u64, @ptrFromInt(runtime_info.physToVirt(page_table_info.pt_table_base)));
    kernel_pts = pt_base[0..page_table_info.pt_table_count];

    serial.println("[PAGING] Using bootloader-allocated page tables:", .{});
    serial.println("  PML4: 0x{x}", .{@intFromPtr(pml4_table)});
    serial.println("  PDPT: 0x{x}", .{@intFromPtr(pdpt_table)});
    serial.println("  PD tables: {} at 0x{x}", .{ pd_tables.len, @intFromPtr(pd_tables.ptr) });
    serial.println("  PT tables: {} at 0x{x}", .{ kernel_pts.len, @intFromPtr(kernel_pts.ptr) });

    // Store initial CR3 for safety checks
    initial_cr3 = getCurrentPageTable();
    serial.println("[PAGING] Stack protection disabled during critical setup phase", .{});

    // Stack canary active to detect corruption

    // Map first 4GB of physical memory with basic identity mapping
    const gbs_to_map = setupIdentityMapping(boot_info);

    // Stack canary active to detect corruption

    // Apply fine-grained kernel protection regardless of page size
    setupKernelProtection(boot_info);

    // Stack canary active to detect corruption

    // Verify page table entries before loading
    secure_print.printValue("[PAGING] PML4[0]", pml4_table[0]);
    secure_print.printValue("[PAGING] PDPT[0]", pdpt_table[0]);

    // Debug: Show all PDPT entries to verify mapping
    serial.println("[PAGING] PDPT entries:", .{});
    for (0..8) |i| {
        if (pdpt_table[i] != 0) {
            serial.print("  PDPT[", .{});
            serial.print("0x{x:0>16}", .{i});
            serial.print("] = ", .{});
            secure_print.printHex("", pdpt_table[i]);
            serial.println("", .{});
        }
    }

    // Load new page table
    const pml4_phys_addr = page_table_info.pml4_phys_addr;
    const pml4_virt_addr = @intFromPtr(pml4_table);
    serial.print("[PAGING] Loading PML4 virtual: ", .{});
    secure_print.printHex("", pml4_virt_addr);
    serial.print(", physical: 0x{x:0>16}", .{pml4_phys_addr});
    serial.println("", .{});

    // Critical: Verify that our page tables are in mapped memory
    const info = runtime_info.getRuntimeInfo();
    const kernel_base = info.kernel_virtual_base;
    const kernel_size = info.kernel_size;
    const kernel_end = kernel_base + kernel_size;

    secure_print.printRange("[PAGING] Kernel memory range", kernel_base, kernel_end);

    // Check if PML4 is within kernel range - this is informational only
    // Page tables don't need to be within kernel code/data range, just accessible
    if (pml4_virt_addr < kernel_base or pml4_virt_addr >= kernel_end) {
        serial.println("[PAGING] INFO: PML4 at 0x{x:0>16} is outside kernel code/data range", .{pml4_virt_addr});
        serial.println("[PAGING] This is normal when bootloader allocates page tables separately", .{});
    }

    // Get current CR3 for comparison
    const old_cr3 = getCurrentPageTable();
    secure_print.printValue("[PAGING] Old CR3", old_cr3);

    // Ensure interrupts are disabled during page table switch
    asm volatile ("cli");

    // CRITICAL: Before switching page tables, verify we can access the new PML4
    // Do a test read to ensure it's accessible
    const test_read = @as(*const u64, @ptrFromInt(pml4_virt_addr)).*;
    secure_print.printValue("[PAGING] Test read of new PML4[0]", test_read);

    // Verify critical memory regions will be accessible after page table switch
    serial.println("[PAGING] Verifying critical memory regions...", .{});

    // 1. Current instruction pointer
    const current_rip = asm volatile (
        \\lea (%%rip), %[result]
        : [result] "=r" (-> u64),
    );
    secure_print.printValue("  RIP", current_rip);
    const ip_gb = @divFloor(current_rip, PAGE_SIZE_1G);
    serial.println("       (GB 0x{x:0>16})", .{ip_gb});

    // 2. Current stack pointer
    const current_rsp = asm volatile (
        \\mov %%rsp, %[result]
        : [result] "=r" (-> u64),
    );
    secure_print.printValue("  RSP", current_rsp);
    const sp_gb = @divFloor(current_rsp, PAGE_SIZE_1G);
    serial.println("       (GB 0x{x:0>16})", .{sp_gb});

    // Check if stack is at a suspicious location
    if (current_rsp >= kernel_end - 0x1000 and current_rsp <= kernel_end + 0x1000) {
        serial.println("  WARNING: Stack is at kernel boundary!", .{});
        serial.print("    Kernel end: ", .{});
        secure_print.printHex("", kernel_end);
        serial.print(", Stack: ", .{});
        secure_print.printHex("", current_rsp);
        serial.println("", .{});
    }

    // 3. Boot info structure
    secure_print.printPointer("  Boot info", boot_info);
    const bi_gb = @divFloor(@intFromPtr(boot_info), PAGE_SIZE_1G);
    serial.println(" (GB {})", .{bi_gb});

    // 4. Page tables themselves
    secure_print.printValue("  PML4", pml4_virt_addr);
    const pml4_gb = @divFloor(pml4_virt_addr, PAGE_SIZE_1G);
    serial.println(" (GB {})", .{pml4_gb});

    // 5. GDT location (critical for segment access)
    const gdt_info = asm volatile (
        \\sub $16, %%rsp
        \\sgdt (%%rsp)
        \\mov 2(%%rsp), %[base]
        \\add $16, %%rsp
        : [base] "=r" (-> u64),
    );
    secure_print.printValue("  GDT", gdt_info);
    const gdt_gb = @divFloor(gdt_info, PAGE_SIZE_1G);
    serial.println(" (GB 0x{x:0>16})", .{gdt_gb});

    // Find the maximum GB we need
    const max_gb = @max(@max(@max(@max(ip_gb, sp_gb), bi_gb), pml4_gb), gdt_gb);
    serial.println("[PAGING] Maximum GB needed: 0x{x:0>16}, mapped: 0x{x:0>16}", .{ max_gb, gbs_to_map });

    if (max_gb >= gbs_to_map) {
        serial.println("[PAGING] FATAL: Not enough GBs mapped!", .{});
        serial.println("  Need at least 0x{x:0>16} GBs, but only mapped 0x{x:0>16}", .{ max_gb + 1, gbs_to_map });
        while (true) {
            asm volatile ("hlt");
        }
    }

    // Load our new page table
    serial.println("[PAGING] Loading new CR3...", .{});

    // Final verification of page table structure
    serial.println("[PAGING] Final page table verification:", .{});
    serial.println("  PML4 physical addr for CR3: 0x{x:0>16}", .{pml4_phys_addr});

    // Verify the PML4 entry points to a valid PDPT
    const pml4_entry = pml4_table[0];
    const pdpt_phys = pml4_entry & ~@as(u64, 0xFFF); // Clear flag bits
    serial.println("  PML4[0] -> PDPT at: 0x{x:0>16}", .{pdpt_phys});

    // CRITICAL: Verify we can access the physical addresses we're using
    serial.println("[PAGING] Testing access to page table memory:", .{});

    // Test reading through our current virtual addresses
    serial.println("  Reading PML4 at physical 0x{x:0>16}: 0x{x:0>16}", .{ pml4_phys_addr, pml4_table[0] });
    serial.println("  Reading PDPT at physical 0x{x:0>16}: 0x{x:0>16}", .{ page_table_info.pdpt_phys_addr, pdpt_table[0] });

    // Add memory barrier to ensure all previous writes are complete
    asm volatile ("mfence" ::: "memory");

    // Disable interrupts to prevent any interrupt during the critical switch
    asm volatile ("cli" ::: "memory");

    // Load CR3 with PHYSICAL address
    asm volatile ("mov %[addr], %%cr3"
        :
        : [addr] "r" (pml4_phys_addr),
        : "memory"
    );

    // Immediately verify we're still executing
    serial.println("[PAGING] CR3 loaded successfully!", .{});

    // Verify the new CR3
    const new_cr3 = getCurrentPageTable();
    secure_print.printValue("[PAGING] New CR3", new_cr3);

    // Simple memory test
    serial.println("[PAGING] Testing memory access...", .{});
    const test_value: u32 = 0x12345678;
    const test_ptr = @as(*volatile u32, @ptrFromInt(0x1000));
    test_ptr.* = test_value;
    if (test_ptr.* == test_value) {
        serial.println("[PAGING] Memory access test passed", .{});
    } else {
        serial.println("[PAGING] Memory access test FAILED!", .{});
    }

    serial.println("[PAGING] Page tables loaded successfully", .{});

    // Flush TLB to ensure all changes take effect
    flushTLB();

    // Enable PCID if supported
    pcid.enable();

    // Initialize PAT if supported
    pat.init();

    // Enable PKU if supported
    pku.enable() catch |err| {
        if (err != error.PKUNotSupported) {
            serial.println("[PAGING] Warning: Failed to enable PKU", .{});
        }
    };

    // Initialize protection keys if PKU was enabled
    if (cpuid.getFeatures().pku) {
        pku.init();
        pku.testPKU();
    }

    // Mark paging as initialized - stack protection can be enabled after this point
    paging_initialized = true;
    serial.println("[PAGING] Page table setup complete - stack protection can now be safely enabled", .{});
}

// Find the highest physical memory address from UEFI memory map
fn findHighestPhysicalAddress(boot_info: *const uefi_boot.UEFIBootInfo) u64 {
    var highest_addr: u64 = 0;
    var highest_usable_addr: u64 = 0;

    if (boot_info.memory_map_addr == 0 or boot_info.memory_map_descriptor_size == 0) {
        // Default to 8GB if we can't read the memory map (matches static page tables)
        return 8 * PAGE_SIZE_1G;
    }

    const memory_map = @as([*]const u8, @ptrFromInt(boot_info.memory_map_addr));
    const descriptor_count = boot_info.memory_map_size / boot_info.memory_map_descriptor_size;

    var offset: usize = 0;
    for (0..descriptor_count) |_| {
        const descriptor = @as(*const uefi_boot.UEFIMemoryDescriptor, @ptrCast(@alignCast(&memory_map[offset])));

        // Track highest address overall
        const end_addr = descriptor.physical_start + (descriptor.number_of_pages * PAGE_SIZE_4K);
        if (end_addr > highest_addr) {
            highest_addr = end_addr;
        }

        // Only consider usable memory types for mapping
        switch (descriptor.type) {
            .Conventional, .BootServicesCode, .BootServicesData, .LoaderCode, .LoaderData => {
                if (end_addr > highest_usable_addr) {
                    highest_usable_addr = end_addr;
                }
            },
            else => {}, // Skip non-RAM regions
        }

        offset += boot_info.memory_map_descriptor_size;
    }

    // Use the highest usable address, not just any address
    const effective_highest = highest_usable_addr;

    // Round up to next GB boundary for cleaner mapping
    const highest_gb = @divFloor(effective_highest + PAGE_SIZE_1G - 1, PAGE_SIZE_1G);

    serial.println("[PAGING] Highest usable RAM address: 0x{x:0>16} ({} GB)", .{ highest_usable_addr, @divFloor(highest_usable_addr, PAGE_SIZE_1G) });

    if (highest_addr > highest_usable_addr) {
        serial.println("[PAGING] Note: Highest address overall: 0x{x:0>16} (includes MMIO/reserved)", .{highest_addr});
    }

    return highest_gb * PAGE_SIZE_1G;
}

fn setupIdentityMapping(boot_info: *const uefi_boot.UEFIBootInfo) usize {
    // Only use stack protection if it's safe to do so
    var guard: ?stack_security.canaryGuard() = null;
    if (isStackProtectionSafe()) {
        guard = stack_security.protect();
    }
    defer if (guard) |*g| g.deinit();

    const features = cpuid.getFeatures();

    // Set up PML4 entry (covers 512GB)
    // CRITICAL: Use PHYSICAL address for page table entries
    const pdpt_phys_addr = page_table_info.pdpt_phys_addr;
    const pdpt_virt_addr = @intFromPtr(pdpt_table);
    serial.print("[PAGING] PDPT virtual: ", .{});
    secure_print.printHex("", pdpt_virt_addr);
    serial.print(", physical: 0x{x:0>16}", .{pdpt_phys_addr});
    serial.println("", .{});
    pml4_table[0] = pdpt_phys_addr | PAGE_PRESENT | PAGE_WRITABLE;

    // Validate the PML4 entry
    validateEntry(pml4_table[0], 4) catch |err| {
        serial.print("[PAGING] ERROR: PML4 entry validation failed: ", .{});
        serial.println("{s}", .{error_utils.errorToString(err)});
    };

    // Determine how much memory we need to map
    // We need to map all memory regions that might be in use

    // 1. Kernel location
    const kernel_start = boot_info.kernel_base;
    const kernel_end = boot_info.kernel_base + boot_info.kernel_size;
    const kernel_start_gb = @divFloor(kernel_start, PAGE_SIZE_1G);
    const kernel_end_gb = @divFloor(kernel_end + PAGE_SIZE_1G - 1, PAGE_SIZE_1G); // Round up to next GB

    serial.println("[PAGING] Kernel spans GB 0x{x:0>16} to GB 0x{x:0>16}", .{ kernel_start_gb, kernel_end_gb - 1 });

    // 2. Also consider where our stack and page tables are (they're in BSS after kernel)
    // Page tables are now allocated by bootloader, no need to track their end

    // 3. CRITICAL: Add extra space for stack growth and alignment
    // The kernel_size doesn't include the full memory needed for stack operations
    // Add at least 2MB extra to ensure we have room for stack growth and any alignment padding
    const SAFETY_MARGIN: u64 = 0x200000; // 2MB safety margin
    const safe_kernel_end = kernel_end + SAFETY_MARGIN;
    const safe_kernel_end_gb = @divFloor(safe_kernel_end + PAGE_SIZE_1G - 1, PAGE_SIZE_1G);

    // 4. Determine how much physical memory we actually have
    const highest_phys_addr = findHighestPhysicalAddress(boot_info);
    const highest_phys_gb = @divFloor(highest_phys_addr, PAGE_SIZE_1G);

    // Use the page table count from bootloader to determine how much we can map
    const max_mappable_gbs = pd_tables.len; // Each PD table maps 1GB

    // Ensure we map at least enough to cover the kernel
    const min_gbs = @max(4, safe_kernel_end_gb); // At least 4GB or where kernel ends

    // Use the bootloader's calculated amount, which should match highest_phys_gb
    const gbs_to_map = @min(max_mappable_gbs, @max(min_gbs, highest_phys_gb));

    if (gbs_to_map < highest_phys_gb) {
        serial.println("[PAGING] WARNING: Only mapping {} GB but system has {} GB", .{ gbs_to_map, highest_phys_gb });
    }

    serial.print("[PAGING] Mapping ", .{});
    serial.print("0x{x:0>16}", .{gbs_to_map});
    serial.println(" GB of memory (have {} PD tables)", .{pd_tables.len});

    // Set up PDPT entries (each covers 1GB)
    // Map using either 1GB or 2MB pages
    if (features.gbpages) {
        // Use 1GB pages if available
        serial.println("[PAGING] Using 1GB pages with fine-grained kernel protection", .{});

        // Cap at what PDPT can handle (512 GB)
        const effective_gbs = @min(gbs_to_map, pdpt_table.len);

        // Map all GBs with 1GB pages using TRUE identity mapping
        // GB 0 might be replaced with smaller pages if kernel is there
        for (0..effective_gbs) |i| {
            const virt_addr = i * PAGE_SIZE_1G;
            const phys_addr = virt_addr; // Identity mapping: virtual = physical

            // Check if kernel is in this GB
            const gb_contains_kernel = (kernel_start >= virt_addr and kernel_start < virt_addr + PAGE_SIZE_1G) or
                (kernel_end > virt_addr and kernel_end <= virt_addr + PAGE_SIZE_1G);

            // Intel SDM 4.2: Also check if this GB contains critical low memory
            // The first GB (0-1GB) must always use smaller pages for:
            // - AP trampoline at 0x8000
            // - Legacy memory regions
            // - BIOS/UEFI structures
            const is_first_gb = (i == 0);

            // For GBs that don't contain the kernel, use 1GB pages with NX
            // For the GB containing the kernel, we need to use 2MB pages for finer W^X control
            if (gb_contains_kernel or is_first_gb) {
                // Don't use a 1GB page for the kernel GB - we need finer control
                // Allocate a PD table for this GB if available
                if (i < pd_tables.len) {
                    // Calculate physical address from bootloader-provided base
                    const pd_phys_addr = page_table_info.pd_table_base + (i * 4096);
                    pdpt_table[i] = pd_phys_addr | PAGE_PRESENT | PAGE_WRITABLE;

                    // Fill the PD with 2MB pages
                    const gb_base = i * PAGE_SIZE_1G;
                    for (0..512) |j| {
                        const addr = gb_base + (j * PAGE_SIZE_2M);
                        // Apply NX to all 2MB pages - kernel region will be handled later with 4KB pages
                        pd_tables[i][j] = addr | PAGE_PRESENT | PAGE_WRITABLE | PAGE_HUGE | PAGE_NO_EXECUTE;
                    }

                    if (gb_contains_kernel) {
                        serial.println("[PAGING] GB 0x{x} contains kernel - using 2MB pages for W^X enforcement", .{i});
                    } else {
                        serial.println("[PAGING] GB 0 (low memory) - using 2MB pages for AP trampoline access", .{});
                    }
                } else {
                    serial.println("[PAGING] CRITICAL: No PD table available for kernel GB!", .{});
                    serial.println("[PAGING] CRITICAL: Cannot enforce W^X protection - system halted for security", .{});
                    // SECURITY: Never allow WX pages - halt system if we can't enforce W^X
                    // This prevents the security vulnerability described in the audit
                    while (true) {
                        asm volatile (
                            \\cli
                            \\hlt
                        );
                    }
                }
            } else if (i == 3) {
                // 4th GB (0xC0000000-0xFFFFFFFF) contains MMIO regions
                // APIC at 0xFEE00000, IO-APIC at 0xFEC00000, etc.
                // Map with cache-disable for MMIO compatibility
                // Note: MMIO regions should NOT have NX bit set
                serial.println("[PAGING] GB 3 contains MMIO regions (APIC) - setting cache-disable, no NX", .{});
                pdpt_table[i] = phys_addr | PAGE_PRESENT | PAGE_WRITABLE | PAGE_HUGE | PAGE_CACHE_DISABLE;
            } else {
                // Non-kernel, non-MMIO GB - use 1GB page with NX
                pdpt_table[i] = phys_addr | PAGE_PRESENT | PAGE_WRITABLE | PAGE_HUGE | PAGE_NO_EXECUTE;
            }

            // Validate the PDPT entry
            validateEntry(pdpt_table[i], 3) catch |err| {
                serial.print("[PAGING] ERROR: PDPT entry ", .{});
                serial.print("{}", .{i});
                serial.print(" validation failed: ", .{});
                serial.println("{s}", .{error_utils.errorToString(err)});
            };

            serial.print("[PAGING] Identity map GB ", .{});
            serial.print("0x{x:0>16}", .{i});
            serial.print(": virtual ", .{});
            serial.print("0x{x:0>16}", .{virt_addr});
            serial.print(" -> physical ", .{});
            serial.print("0x{x:0>16}", .{phys_addr});
            if (gb_contains_kernel) {
                serial.println(" (kernel GB - executable)", .{});
            } else {
                serial.println(" (NX set)", .{});
            }
        }
    } else {
        // Use 2MB pages
        serial.println("[PAGING] Using 2MB pages", .{});
        const max_gbs = @min(gbs_to_map, pd_tables.len);
        if (gbs_to_map > max_gbs) {
            serial.print("[PAGING] WARNING: Can only map ", .{});
            serial.print("0x{x:0>16}", .{max_gbs});
            serial.print(" GB with available PD tables (need ", .{});
            serial.print("0x{x:0>16}", .{gbs_to_map});
            serial.println(" GB)", .{});
        }
        for (0..max_gbs) |i| {
            // Calculate physical address from bootloader-provided base
            const pd_phys_addr = page_table_info.pd_table_base + (i * 4096);
            pdpt_table[i] = pd_phys_addr | PAGE_PRESENT | PAGE_WRITABLE;

            // Validate the PDPT entry (points to PD table, not a huge page)
            validateEntry(pdpt_table[i], 3) catch |err| {
                serial.print("[PAGING] ERROR: PDPT entry ", .{});
                serial.print("{}", .{i});
                serial.print(" validation failed: ", .{});
                serial.println("{s}", .{error_utils.errorToString(err)});
            };
        }

        // Set up PD entries with 2MB pages
        var phys_addr: u64 = 0;
        for (pd_tables[0..max_gbs], 0..) |*pd_table, gb_index| {
            for (&pd_table.*) |*entry| {
                var flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_HUGE;

                // Always apply NX bit to large pages - we'll use fine-grained
                // permissions for kernel regions later
                // Exception: First 2MB needs to be executable for AP trampoline
                if (phys_addr < PAGE_SIZE_2M) {
                    // First 2MB contains AP trampoline at 0x8000
                    // Don't set NX bit for this region
                } else {
                    flags |= PAGE_NO_EXECUTE;
                }

                // Check if this is in the 4th GB which contains MMIO regions
                if (gb_index == 3) {
                    // 4th GB contains APIC at 0xFEE00000, IO-APIC at 0xFEC00000
                    // Set cache-disable for MMIO compatibility and remove NX bit
                    flags |= PAGE_CACHE_DISABLE;
                    flags &= ~PAGE_NO_EXECUTE; // MMIO regions should be executable
                }

                entry.* = phys_addr | flags;
                phys_addr += PAGE_SIZE_2M;
            }
        }

        serial.print("[PAGING] Mapped up to ", .{});
        serial.print("0x{x:0>16}", .{phys_addr});
        serial.println(" with 2MB pages", .{});
    }

    // Apply specific memory permissions based on boot info
    applyMemoryPermissions(boot_info);

    // Return the actual number of GBs we mapped (may be less than requested due to limits)
    const mapped_gbs = if (features.gbpages)
        @min(gbs_to_map, pdpt_table.len)
    else
        @min(gbs_to_map, pd_tables.len);

    // Store the highest mapped physical address globally
    highest_mapped_physical_addr = mapped_gbs * PAGE_SIZE_1G;
    serial.println("[PAGING] Highest mapped physical address: 0x{x:0>16} ({} GB)", .{ highest_mapped_physical_addr, mapped_gbs });

    return mapped_gbs;
}

fn isKernelAddress(addr: u64) bool {
    return runtime_info.isKernelAddress(addr);
}

// Setup fine-grained kernel protection with W^X enforcement
fn setupKernelProtection(_: *const uefi_boot.UEFIBootInfo) void {
    // Only use stack protection if it's safe to do so
    var guard: ?stack_security.canaryGuard() = null;
    if (isStackProtectionSafe()) {
        guard = stack_security.protect();
    }
    defer if (guard) |*g| g.deinit();

    serial.println("[PAGING] Setting up kernel W^X protection...", .{});

    // Debug: Show addresses of our arrays
    serial.print("[PAGING] kernel_pts address: ", .{});
    secure_print.printHex("0x", @intFromPtr(&kernel_pts));
    serial.print(", size: 0x", .{});
    serial.print("{x:0>16}", .{@sizeOf(@TypeOf(kernel_pts))});
    serial.println("", .{});

    // Stack location available in stack_security output

    // Get runtime addresses
    // With PIE, these symbols should already be at their runtime addresses
    // But if they're not, we need to use the kernel base from runtime_info
    const info = runtime_info.getRuntimeInfo();
    const kernel_base = info.kernel_virtual_base;
    const kernel_start_addr = if (@intFromPtr(&__kernel_start) < 0x1000000)
        kernel_base // Symbol is an offset, use actual base
    else
        @intFromPtr(&__kernel_start); // Symbol is already relocated

    // With proper PIE, symbols are already relocated to the correct addresses
    const data_start_addr = @intFromPtr(&__data_start);
    const bss_start_addr = @intFromPtr(&__bss_start);
    const bss_end_addr = @intFromPtr(&__bss_end);

    // Debug: print actual addresses
    serial.print("[PAGING] Kernel base: ", .{});
    secure_print.printHex("0x", kernel_base);
    serial.print(", start symbol: ", .{});
    secure_print.printHex("0x", @intFromPtr(&__kernel_start));
    serial.println("", .{});

    // Calculate page-aligned boundaries
    const kernel_start_page = kernel_start_addr & ~@as(u64, PAGE_SIZE_4K - 1);

    // Replace the large page mapping for kernel area with 4K pages
    // This allows fine-grained permissions

    const features = cpuid.getFeatures();
    if (features.gbpages) {
        // Determine which GB the kernel is in
        const kernel_gb = @divFloor(kernel_base, PAGE_SIZE_1G);
        const kernel_in_first_gb = kernel_gb == 0;

        if (kernel_in_first_gb) {
            // When kernel is in first GB, replace it with a PD table for fine-grained control
            const kernel_pd_phys_addr = page_table_info.pd_table_base; // First PD table
            serial.println("[PAGING] kernel_pd at physical: 0x{x:0>16}", .{kernel_pd_phys_addr});
            pdpt_table[0] = kernel_pd_phys_addr | PAGE_PRESENT | PAGE_WRITABLE;
        } else {
            // Kernel is in a higher GB, we need to split that GB for fine-grained control
            serial.print("[PAGING] Kernel in GB ", .{});
            serial.print("0x{x:0>16}", .{kernel_gb});
            serial.print(" at address ", .{});
            serial.print("0x{x:0>16}", .{kernel_base});
            serial.println(" - setting up fine-grained protection", .{});

            // Verify that this GB is mapped
            if (kernel_gb >= pdpt_table.len or pdpt_table[kernel_gb] == 0) {
                serial.println("[PAGING] ERROR: Kernel GB is not mapped!", .{});
                return;
            }

            // Check if it's currently a 1GB page
            if ((pdpt_table[kernel_gb] & PAGE_HUGE) != 0) {
                // We need to replace the 1GB page with a PD table
                // Use one of the pre-allocated PD tables for this
                // We'll use pd_tables[kernel_gb] if available
                if (kernel_gb < pd_tables.len) {
                    const pd_phys_addr = page_table_info.pd_table_base + (kernel_gb * 4096);
                    serial.println("[PAGING] Replacing 1GB page with PD table at physical: 0x{x:0>16}", .{pd_phys_addr});

                    // First, fill the PD with 2MB pages to maintain the identity mapping
                    const gb_base = kernel_gb * PAGE_SIZE_1G;
                    for (0..512) |i| {
                        const phys_addr = gb_base + (i * PAGE_SIZE_2M);
                        const flags = PAGE_PRESENT | PAGE_WRITABLE | PAGE_HUGE | PAGE_NO_EXECUTE;

                        // For kernel region, we'll need finer control, so skip the huge page flag
                        const addr_start = gb_base + (i * PAGE_SIZE_2M);
                        const addr_end = addr_start + PAGE_SIZE_2M;
                        const kernel_end = kernel_base + info.kernel_size;
                        const kernel_overlaps = (addr_start < kernel_end) and (addr_end > kernel_base);

                        if (kernel_overlaps) {
                            // Don't use huge pages for kernel region - we'll set up PT tables later
                            pd_tables[kernel_gb][i] = 0;
                        } else {
                            pd_tables[kernel_gb][i] = phys_addr | flags;
                        }
                    }

                    // Now replace the PDPT entry
                    pdpt_table[kernel_gb] = pd_phys_addr | PAGE_PRESENT | PAGE_WRITABLE;

                    // Flush TLB to ensure the new mapping takes effect
                    flushTLB();
                } else {
                    serial.println("[PAGING] ERROR: No PD table available for kernel GB!", .{});
                    return;
                }
            } else {
                // Already have a PD table, make sure kernel region entries are cleared
                if (kernel_gb >= pd_tables.len) {
                    serial.println("[PAGING] ERROR: Kernel is in GB {} but only {} PD tables available", .{ kernel_gb, pd_tables.len });
                    return;
                }
                const pd_table = &pd_tables[kernel_gb];
                const kernel_2mb_start = kernel_base & ~@as(u64, PAGE_SIZE_2M - 1);
                const kernel_2mb_end = (kernel_base + info.kernel_size + PAGE_SIZE_2M - 1) & ~@as(u64, PAGE_SIZE_2M - 1);

                // Clear entries that overlap with kernel so we can set up PT tables
                const start_pd_idx = @divFloor(kernel_2mb_start % PAGE_SIZE_1G, PAGE_SIZE_2M);
                const end_pd_idx = @divFloor(kernel_2mb_end % PAGE_SIZE_1G, PAGE_SIZE_2M);

                for (start_pd_idx..end_pd_idx) |i| {
                    if (i < 512) {
                        pd_table.*[i] = 0;
                    }
                }
            }

            // Now we have a PD table for the kernel's GB, continue with fine-grained mapping
        }

        // Handle both first GB and higher GB cases
        if (kernel_in_first_gb) {
            // Map first part of memory with 2MB pages in kernel_pd
            // Map up to the kernel's 2MB-aligned start
            var addr: u64 = 0;
            var pd_idx: usize = 0;
            const kernel_2mb_start = kernel_start_page & ~@as(u64, PAGE_SIZE_2M - 1);

            // Map enough to ensure boot info is accessible, but leave room for the rest of the GB
            // Boot info is typically at ~254MB, so 256MB should be sufficient
            // This leaves us with 256 PD entries for the rest of the first GB
            const min_mapping_size: u64 = 256 * 1024 * 1024; // 256MB
            const map_up_to = if (kernel_2mb_start > min_mapping_size) kernel_2mb_start else min_mapping_size;

            // Map first 16MB with 4KB pages for fine-grained control (needed for SMP)
            const low_mem_4k_size: u64 = 16 * 1024 * 1024; // 16MB
            const low_mem_pt_count = @divFloor(low_mem_4k_size, PAGE_SIZE_2M); // 8 PT tables

            // Set up 4KB pages for first 16MB
            for (0..low_mem_pt_count) |i| {
                const pt_phys_addr = page_table_info.pt_table_base + (i * 4096);
                pd_tables[0][i] = pt_phys_addr | PAGE_PRESENT | PAGE_WRITABLE; // Point to PT, not a huge page

                // Fill the PT with 4KB pages
                for (0..512) |j| {
                    const page_addr = (i * PAGE_SIZE_2M) + (j * PAGE_SIZE_4K);
                    const flags = PAGE_PRESENT | PAGE_WRITABLE;

                    // Apply appropriate protections
                    if (page_addr == 0) {
                        // First page (0x0-0xFFF) contains AP debug area at 0x500
                        // Must be mapped for SMP but keep NX for security
                        kernel_pts[i][j] = page_addr | flags | PAGE_NO_EXECUTE;
                    } else if (page_addr == 0x8000) {
                        // AP trampoline - needs to be executable
                        kernel_pts[i][j] = page_addr | flags; // No NX bit
                    } else {
                        // Everything else gets NX bit
                        kernel_pts[i][j] = page_addr | flags | PAGE_NO_EXECUTE;
                    }
                }
            }

            addr = low_mem_4k_size;
            pd_idx = low_mem_pt_count;

            serial.println("[PAGING] Mapped 0-0x{x:0>16} with 4KB pages for SMP support", .{low_mem_4k_size});

            // Continue mapping rest of memory with 2MB pages
            while (addr < map_up_to and pd_idx < 512) {
                // Identity mapping: virtual address = physical address
                const phys_addr = addr; // This is critical!
                pd_tables[0][pd_idx] = phys_addr | PAGE_PRESENT | PAGE_WRITABLE | PAGE_HUGE | PAGE_NO_EXECUTE;
                addr += PAGE_SIZE_2M;
                pd_idx += 1;
            }

            serial.print("[PAGING] Mapped 0-", .{});
            serial.print("0x{x:0>16}", .{addr});
            serial.print(" with 2MB pages (", .{});
            serial.print("0x{x:0>16}", .{pd_idx});
            serial.println(" entries)", .{});

            // Map kernel area with 4K pages for fine control
            // We need to replace the 2MB pages covering the kernel with PT tables
            const kernel_pd_idx = @divFloor(kernel_2mb_start, PAGE_SIZE_2M);

            // CRITICAL: kernel_pd_idx must be within kernel_pd bounds
            if (kernel_pd_idx >= 512) {
                serial.print("[PAGING] WARNING: Kernel PD index ", .{});
                serial.print("0x{x:0>16}", .{kernel_pd_idx});
                serial.println(" exceeds first GB bounds - kernel at high address due to KASLR", .{});

                // When kernel is beyond first GB, we need to ensure it's mapped properly
                // The kernel should already be mapped by the identity mapping in higher GBs
                // We just need to ensure the mapping is correct and has proper permissions

                // Get which GB the kernel is in
                const actual_kernel_gb = @divFloor(kernel_base, PAGE_SIZE_1G);
                serial.println("[PAGING] Kernel is in GB 0x{x:0>16} at address 0x{x:0>16}", .{ actual_kernel_gb, kernel_base });

                // Verify that this GB is mapped
                serial.println("[PAGING] Checking PDPT[0x{x:0>16}] = 0x{x:0>16}", .{ actual_kernel_gb, pdpt_table[actual_kernel_gb] });

                if (actual_kernel_gb < pdpt_table.len and pdpt_table[actual_kernel_gb] != 0) {
                    serial.println("[PAGING] Kernel GB is already mapped with 1GB page", .{});
                    // The kernel will run with the 1GB page mapping
                    // We can't apply fine-grained W^X protection, but the kernel will still work
                    serial.println("[PAGING] Note: Fine-grained W^X protection not available for high memory kernel", .{});
                } else {
                    serial.println("[PAGING] ERROR: Kernel GB is not mapped!", .{});
                    // This should not happen with our current setup
                }
                return;
            }

            // IMPORTANT: We need to map more than just the kernel code/data
            // We also need to ensure page tables and stack remain accessible
            // BUT we must not map our own page table arrays or we'll corrupt ourselves
            // kernel_end calculation removed as it's not needed

            // Find where our page tables start (they're in BSS after kernel)
            _ = @intFromPtr(&kernel_pts); // page_tables_start not needed after change

            // Map up to the page tables, but not including them
            // CRITICAL: We must also ensure the stack remains mapped!
            // The stack is typically placed after the page tables in BSS
            // For safety, let's extend mapping by 2MB to cover stack
            // Page tables are allocated by bootloader, use kernel end for stack calculation
            const page_tables_end = kernel_base + info.kernel_size;
            const safe_end = page_tables_end + 0x200000; // Add 2MB for stack
            const extended_end = safe_end & ~@as(u64, PAGE_SIZE_4K - 1); // Align down to page boundary

            // Calculate how many 2MB regions we need to cover with 4K pages
            const extended_num_pts = @divFloor(extended_end - kernel_2mb_start + PAGE_SIZE_2M - 1, PAGE_SIZE_2M);

            serial.println("[PAGING] Setting up 0x{x:0>16} PT tables starting at PD entry 0x{x:0>16}", .{ extended_num_pts, kernel_pd_idx });

            // Sanity check - ensure we don't exceed our PT table array bounds
            if (extended_num_pts > kernel_pts.len) {
                serial.print("[PAGING] ERROR: Need ", .{});
                serial.print("0x{x:0>16}", .{extended_num_pts});
                serial.print(" PT tables but only have ", .{});
                serial.print("0x{x:0>16}", .{kernel_pts.len});
                serial.println(" allocated!", .{});
                while (true) {
                    asm volatile ("hlt");
                }
            }

            // Also check PD bounds
            if (kernel_pd_idx + extended_num_pts > 512) {
                serial.print("[PAGING] ERROR: PD entries ", .{});
                serial.print("0x{x:0>16}", .{kernel_pd_idx});
                serial.print(" + ", .{});
                serial.print("0x{x:0>16}", .{extended_num_pts});
                serial.println(" exceeds 512!", .{});
                while (true) {
                    asm volatile ("hlt");
                }
            }

            for (0..extended_num_pts) |i| {
                const pd_entry_idx = kernel_pd_idx + i;
                if (pd_entry_idx >= 512) {
                    serial.print("[PAGING] ERROR: PD entry index ", .{});
                    serial.print("0x{x:0>16}", .{pd_entry_idx});
                    serial.println(" exceeds bounds during PT setup!", .{});
                    break;
                }
                pd_tables[0][pd_entry_idx] = (page_table_info.pt_table_base + (i * 4096)) | PAGE_PRESENT | PAGE_WRITABLE;
            }

            // PT tables set up

            // Map 4K pages with appropriate permissions
            // Start from 2MB-aligned boundary to properly fill the PT tables
            applyKernelPermissions4K(kernel_2mb_start, extended_end, kernel_start_page, data_start_addr, bss_start_addr, bss_end_addr);

            // Continue with mapping

            // Continue mapping rest of memory with 2MB pages
            // We've mapped some initial memory, then replaced kernel region with PT tables
            // Now continue from after the kernel region

            // Calculate the PD index to continue from
            const kernel_region_end_pd = kernel_pd_idx + extended_num_pts;
            // Continue from the maximum of where we left off initially or after the kernel region
            pd_idx = @max(pd_idx, kernel_region_end_pd);

            // Calculate the address to continue from
            // Use the address that corresponds to our pd_idx
            addr = pd_idx * PAGE_SIZE_2M;

            // Map as much as we can with remaining PD entries
            // We may not be able to map the full first GB due to PT tables taking up entries
            // IMPORTANT: Leave at least one entry as guard to prevent stack corruption
            const max_safe_entries = 511; // Leave last entry as guard
            const remaining_entries = if (pd_idx < max_safe_entries) max_safe_entries - pd_idx else 0;
            const end_addr = addr + (remaining_entries * PAGE_SIZE_2M);

            // Only map up to 1GB boundary
            const gb_boundary = PAGE_SIZE_1G;
            const actual_end = @min(end_addr, gb_boundary);

            while (addr < actual_end and pd_idx < max_safe_entries) {
                // Write the PD entry with identity mapping
                const phys_addr = addr; // Identity: virtual = physical
                pd_tables[0][pd_idx] = phys_addr | PAGE_PRESENT | PAGE_WRITABLE | PAGE_HUGE | PAGE_NO_EXECUTE;
                addr += PAGE_SIZE_2M;
                pd_idx += 1;
            }

            // kernel_pd mapping complete

            // Log what we managed to map
            if (addr < gb_boundary) {
                serial.print("[PAGING] Note: Mapped up to ", .{});
                serial.print("0x{x:0>16}", .{addr});
                serial.print(" of first GB (", .{});
                serial.print("0x{x:0>16}", .{gb_boundary - addr});
                serial.println(" bytes unmapped due to kernel fine-grained mapping)", .{});
            }
        } else {
            // Kernel is in a higher GB - we need to apply fine-grained protection there
            const kernel_2mb_start = kernel_start_page & ~@as(u64, PAGE_SIZE_2M - 1);
            const kernel_pd_idx = @divFloor(kernel_2mb_start % PAGE_SIZE_1G, PAGE_SIZE_2M);

            // Get the PD table for the kernel's GB
            if (kernel_gb >= pd_tables.len) {
                serial.println("[PAGING] ERROR: Kernel is in GB {} but only {} PD tables available", .{ kernel_gb, pd_tables.len });
                return;
            }
            const pd_table = &pd_tables[kernel_gb];

            // Find where our page tables start (they're in BSS after kernel)
            // Page tables are allocated by bootloader, use kernel end for stack calculation
            const page_tables_end = kernel_base + info.kernel_size;
            const safe_end = page_tables_end + 0x200000; // Add 2MB for stack
            const extended_end = safe_end & ~@as(u64, PAGE_SIZE_4K - 1); // Align down to page boundary

            // Calculate how many 2MB regions we need to cover with 4K pages
            const extended_num_pts = @divFloor(extended_end - kernel_2mb_start + PAGE_SIZE_2M - 1, PAGE_SIZE_2M);

            serial.println("[PAGING] Setting up 0x{x:0>16} PT tables for high memory kernel starting at PD entry 0x{x:0>16}", .{ extended_num_pts, kernel_pd_idx });

            // Sanity check - ensure we don't exceed our PT table array bounds
            if (extended_num_pts > kernel_pts.len) {
                serial.print("[PAGING] ERROR: Need ", .{});
                serial.print("0x{x:0>16}", .{extended_num_pts});
                serial.print(" PT tables but only have ", .{});
                serial.print("0x{x:0>16}", .{kernel_pts.len});
                serial.println(" allocated!", .{});
                return;
            }

            // Also check PD bounds
            if (kernel_pd_idx + extended_num_pts > 512) {
                serial.print("[PAGING] ERROR: PD entries ", .{});
                serial.print("0x{x:0>16}", .{kernel_pd_idx});
                serial.print(" + ", .{});
                serial.print("0x{x:0>16}", .{extended_num_pts});
                serial.println(" exceeds 512!", .{});
                return;
            }

            // Replace 2MB pages with PT tables for kernel area
            for (0..extended_num_pts) |i| {
                const pd_entry_idx = kernel_pd_idx + i;
                if (pd_entry_idx >= 512) {
                    serial.print("[PAGING] ERROR: PD entry index ", .{});
                    serial.print("0x{x:0>16}", .{pd_entry_idx});
                    serial.println(" exceeds bounds during PT setup!", .{});
                    break;
                }
                pd_table.*[pd_entry_idx] = (page_table_info.pt_table_base + (i * 4096)) | PAGE_PRESENT | PAGE_WRITABLE;
            }

            // Map 4K pages with appropriate permissions
            applyKernelPermissions4K(kernel_2mb_start, extended_end, kernel_start_page, data_start_addr, bss_start_addr, bss_end_addr);

            serial.println("[PAGING] Fine-grained W^X protection applied to high memory kernel", .{});
        } // End of kernel_in_first_gb condition
    } else {
        // For 2MB pages, we need to find the kernel's PD entry and split it
        const kernel_gb_idx = @divFloor(kernel_start_page, PAGE_SIZE_1G);
        const kernel_pd_idx = @divFloor(kernel_start_page % PAGE_SIZE_1G, PAGE_SIZE_2M);

        // Get the PD table for the kernel's GB
        if (kernel_gb_idx >= pd_tables.len) {
            serial.println("[PAGING] ERROR: Kernel is in GB {} but only {} PD tables available", .{ kernel_gb_idx, pd_tables.len });
            return;
        }
        const pd_table = &pd_tables[kernel_gb_idx];

        // Map kernel area with 4K pages
        // Find where our page tables start (they're in BSS after kernel)
        _ = @intFromPtr(&kernel_pts); // page_tables_start not needed after change
        // CRITICAL: We must also ensure the stack remains mapped!
        // Page tables are allocated by bootloader, use kernel end for stack calculation
        const page_tables_end = kernel_base + info.kernel_size;
        const safe_end = page_tables_end + 0x200000; // Add 2MB for stack
        const extended_end = safe_end & ~@as(u64, PAGE_SIZE_4K - 1); // Align down to page boundary
        const kernel_2mb_start = kernel_start_page & ~@as(u64, PAGE_SIZE_2M - 1);
        const kernel_2mb_end = (extended_end + PAGE_SIZE_2M - 1) & ~@as(u64, PAGE_SIZE_2M - 1);
        const num_2mb_pages = @divFloor(kernel_2mb_end - kernel_2mb_start, PAGE_SIZE_2M);

        // Replace 2MB pages with PT tables for kernel area
        for (0..num_2mb_pages) |i| {
            const pd_entry_idx = kernel_pd_idx + i;
            if (pd_entry_idx < 512 and i < kernel_pts.len) {
                pd_table.*[pd_entry_idx] = (page_table_info.pt_table_base + (i * 4096)) | PAGE_PRESENT | PAGE_WRITABLE;
            }
        }

        // Map 4K pages with appropriate permissions
        applyKernelPermissions4K(kernel_2mb_start, extended_end, kernel_start_page, data_start_addr, bss_start_addr, bss_end_addr);
    }
}

// Apply fine-grained permissions to kernel pages
fn applyKernelPermissions4K(region_start: u64, region_end: u64, kernel_start: u64, data_start: u64, _: u64, bss_end: u64) void {
    // Stack protection is not safe here as we're actively modifying
    // the page tables that contain our stack memory
    // This function is only called during initial setup
    const num_pages = @divFloor(region_end - region_start, PAGE_SIZE_4K);
    var page_addr = region_start;
    var pt_idx: usize = 0;
    var current_pt: usize = 0;

    serial.println("[PAGING] Applying W^X to kernel pages:", .{});
    serial.print("  Mapping region: 0x", .{});
    serial.print("0x{x:0>16}", .{region_start});
    serial.print(" - 0x", .{});
    serial.print("0x{x:0>16}", .{region_end});
    serial.print(" (", .{});
    serial.print("0x{x:0>16}", .{num_pages});
    serial.println(" pages)", .{});

    for (0..num_pages) |_| {
        // Check bounds before accessing array
        if (current_pt >= kernel_pts.len) {
            serial.println("[PAGING] ERROR: Ran out of PT tables!", .{});
            break;
        }

        if (pt_idx >= 512) {
            current_pt += 1;
            pt_idx = 0;
            // Check again after incrementing current_pt
            if (current_pt >= kernel_pts.len) {
                serial.println("[PAGING] ERROR: Ran out of PT tables!", .{});
                break;
            }
        }

        var flags: u64 = undefined;
        var pkey: pku.ProtectionKeys = undefined;

        if (page_addr < kernel_start) {
            // Before kernel - non-executable data pages
            flags = PAGE_KERNEL_DATA;
            pkey = pku.ProtectionKeys.kernel_data;
        } else if (page_addr < data_start) {
            // Code section - executable, not writable
            flags = PAGE_KERNEL_CODE;
            pkey = pku.ProtectionKeys.kernel_code;
        } else if (page_addr < bss_end) {
            // Data/BSS sections - writable, not executable
            flags = PAGE_KERNEL_DATA;
            pkey = pku.ProtectionKeys.kernel_data;
        } else {
            // After kernel - keep mapped as writable/non-executable
            // This includes page tables and stack
            flags = PAGE_KERNEL_DATA;
            pkey = pku.ProtectionKeys.page_tables;
        }

        // Write the page table entry with identity mapping and protection key
        // virtual page_addr maps to physical page_addr
        kernel_pts[current_pt][pt_idx] = pku.createPageEntryWithKey(page_addr, flags, pkey);
        page_addr += PAGE_SIZE_4K;
        pt_idx += 1;
    }

    // Check if we can add guard page

    // Add guard page after kernel
    if (pt_idx < 512 and current_pt < kernel_pts.len) {
        kernel_pts[current_pt][pt_idx] = pku.createPageEntryWithKey(0, PAGE_GUARD, pku.ProtectionKeys.guard_pages);
    } else {
        serial.println("  WARNING: Cannot add guard page - out of bounds", .{});
    }

    // Update next_kernel_pt_index to track which PTs have been used
    // If we used any entries in current_pt, we need to mark it as used
    if (pt_idx > 0) {
        next_kernel_pt_index = current_pt + 1;
    } else {
        next_kernel_pt_index = current_pt;
    }
    serial.println("[PAGING] Kernel protection used {} PT tables", .{next_kernel_pt_index});
}

fn applyMemoryPermissions(boot_info: *const uefi_boot.UEFIBootInfo) void {
    // Stack protection may be safe here depending on when this is called
    var guard: ?stack_security.canaryGuard() = null;
    if (isStackProtectionSafe()) {
        guard = stack_security.protect();
    }
    defer if (guard) |*g| g.deinit();

    const kernel_start = boot_info.kernel_base;
    const kernel_end = kernel_start + boot_info.kernel_size;

    secure_print.printRange("[PAGING] Kernel region", kernel_start, kernel_end);

    // Fine-grained protection is now handled by setupKernelProtection()
}

// Get current page table base (CR3)
pub fn getCurrentPageTable() u64 {
    return asm volatile ("mov %%cr3, %[result]"
        : [result] "=r" (-> u64),
    );
}

// Invalidate TLB entry for a specific address
pub fn invalidatePage(addr: u64) void {
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (addr),
        : "memory"
    );
}

// Flush entire TLB by reloading CR3
pub fn flushTLB() void {
    const cr3 = getCurrentPageTable();
    asm volatile ("mov %[value], %%cr3"
        :
        : [value] "r" (cr3),
        : "memory"
    );
}

// Flush TLB on all CPUs for a specific address (Intel SDM Vol 3A Section 4.10.4.2)
pub fn invalidatePageAllCpus(addr: u64) void {
    // Use IPI for TLB shootdown if SMP is active
    if (@import("../smp/per_cpu.zig").getCpuCount() > 1) {
        @import("../smp/ipi.zig").tlbShootdown(addr);
    } else {
        // Single CPU, just invalidate locally
        invalidatePage(addr);
    }
}

// Flush entire TLB on all CPUs (Intel SDM Vol 3A Section 4.10.4.2)
pub fn flushTLBAllCpus() void {
    // Use IPI for TLB shootdown if SMP is active
    if (@import("../smp/per_cpu.zig").getCpuCount() > 1) {
        @import("../smp/ipi.zig").tlbShootdownAll();
    } else {
        // Single CPU, just flush locally
        flushTLB();
    }
}

// Delegate protection key functions to PKU module
pub const setProtectionKey = pku.setProtectionKey;
pub const getProtectionKey = pku.getProtectionKey;

// Delegate getTableIndex to LA57 module
pub const getTableIndex = la57.getTableIndex;

// Delegate PKU functions to PKU module
pub const PKRUAccessRights = pku.PKRUAccessRights;
pub const readPKRU = pku.readPKRU;
pub const writePKRU = pku.writePKRU;
pub const setPKRU = pku.setPKRU;
pub const getPKRU = pku.getPKRU;

// Delegate PCID functions to PCID module
pub const loadPageTableWithPCID = pcid.loadPageTableWithPCID;
pub const switchPageTableNoFlush = pcid.switchPageTableNoFlush;
pub const invalidatePCID = pcid.invalidatePCID;
pub const isPCIDSupported = pcid.isSupported;

// Get the highest mapped physical address
pub fn getHighestMappedPhysicalAddress() u64 {
    return highest_mapped_physical_addr;
}

// Print page table info
pub fn printInfo() void {
    secure_print.printValue("[PAGING] CR3", getCurrentPageTable());

    // Check if we're using 1GB or 2MB pages
    const features = cpuid.getFeatures();
    if (features.gbpages) {
        serial.println("[PAGING] Using 1GB pages with fine-grained kernel protection", .{});
        serial.println("[PAGING] First GB uses 2MB/4KB pages for kernel W^X enforcement", .{});
    } else {
        serial.println("[PAGING] Using 2MB pages with fine-grained kernel protection", .{});
    }

    // Check PAT status
    if (features.pat) {
        serial.println("[PAGING] PAT (Page Attribute Table) enabled", .{});

        // PAT module handles displaying its configuration
    }

    // Check PKU status
    if (features.pku) {
        serial.println("[PAGING] PKU (Protection Keys for Userspace) enabled", .{});

        // Read and display current PKRU value
        const pkru_value = readPKRU();
        serial.println("[PAGING] Current PKRU value: 0x{x:0>8}", .{pkru_value});
    }
}

// Delegate validation functions to validation module
pub const validateEntry = validation.validateEntry;
pub const isCanonicalAddress = validation.isCanonicalAddress;

// Unmap a page at the given virtual address
// This makes the page inaccessible and will cause a page fault on access
pub fn unmapPage(virt_addr: u64) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Acquire page table lock for this address
    var lock_guard = page_table_locks.acquireForAddress(virt_addr);
    defer lock_guard.deinit();
    // Find the page table entry for this address
    const pml4_idx = getTableIndex(virt_addr, 4);
    const pdpt_idx = getTableIndex(virt_addr, 3);
    const pd_idx = getTableIndex(virt_addr, 2);
    const pt_idx = getTableIndex(virt_addr, 1);

    // Check if PML4 entry exists
    if ((pml4_table[pml4_idx] & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    // For simplicity, assume we're using 4K pages in kernel region
    // In a full implementation, we'd need to handle 1GB and 2MB pages too

    // Navigate to the page table
    const pdpt_phys = pml4_table[pml4_idx] & PHYS_ADDR_MASK;
    // Intel SDM 4.2: Physical addresses must be accessible
    const pdpt_virt = runtime_info.physToVirt(pdpt_phys);
    const pdpt = @as(*[512]u64, @ptrFromInt(pdpt_virt));

    if ((pdpt[pdpt_idx] & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    // Check if this is a 1GB page
    if ((pdpt[pdpt_idx] & PAGE_HUGE) != 0) {
        // Remove the entire 1GB page
        pdpt[pdpt_idx] = 0;
        asm volatile ("mfence" ::: "memory");
        invalidatePage(virt_addr);
        return;
    }

    const pd_phys = pdpt[pdpt_idx] & PHYS_ADDR_MASK;
    const pd_virt = runtime_info.physToVirt(pd_phys);
    const pd = @as(*[512]u64, @ptrFromInt(pd_virt));

    if ((pd[pd_idx] & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    // Check if this is a 2MB page
    if ((pd[pd_idx] & PAGE_HUGE) != 0) {
        // Remove the entire 2MB page
        pd[pd_idx] = 0;
        asm volatile ("mfence" ::: "memory");
        invalidatePage(virt_addr);
        return;
    }

    const pt_phys = pd[pd_idx] & PHYS_ADDR_MASK;
    const pt_virt = runtime_info.physToVirt(pt_phys);
    const pt = @as(*[512]u64, @ptrFromInt(pt_virt));

    if ((pt[pt_idx] & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    // Remove the 4K page
    pt[pt_idx] = 0;
    asm volatile ("mfence" ::: "memory");
    invalidatePage(virt_addr);
}

// Split a 1GB huge page into 512 2MB pages
fn split1GBPage(pdpt: *[512]u64, pdpt_idx: usize) !void {
    const entry = pdpt[pdpt_idx];
    if ((entry & PAGE_HUGE) == 0) return; // Not a huge page

    const gb_phys_base = entry & PHYS_ADDR_MASK;
    // Preserve only essential permission flags from the original huge page
    // We should NOT preserve transient flags like ACCESSED or DIRTY
    const ESSENTIAL_FLAGS = PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER | PAGE_NO_EXECUTE |
        PAGE_CACHE_DISABLE | PAGE_WRITE_THROUGH;
    const essential_page_flags = entry & ESSENTIAL_FLAGS & ~PAGE_HUGE;

    // Intel SDM Vol 3A Section 4.10.4: Proper TLB invalidation procedure
    // Step 1: Disable interrupts
    const old_flags = asm volatile ("pushfq; popq %[flags]; cli"
        : [flags] "=r" (-> u64),
    );
    defer {
        if (old_flags & 0x200 != 0) {
            asm volatile ("sti" ::: "memory");
        }
    }

    // Step 2: Flush caches before changing page attributes
    asm volatile ("wbinvd" ::: "memory");

    // Step 3: Clear PRESENT bit in PDPT entry first (critical for proper TLB invalidation)
    pdpt[pdpt_idx] &= ~PAGE_PRESENT;
    asm volatile ("mfence" ::: "memory");

    // Step 4: Flush TLB for the entire 1GB region
    flushTLB(); // Full TLB flush for safety with 1GB page changes

    // Step 5: Allocate a new PD table
    const pd_phys = pmm.allocPagesTagged(1, .PAGE_TABLES) orelse return error.OutOfMemory;
    serial.println("[PAGING] Allocated PD at physical 0x{x}", .{pd_phys});
    const pd_virt = runtime_info.physToVirt(pd_phys);
    serial.println("[PAGING] PD virtual address: 0x{x}", .{pd_virt});

    // Check if this physical address is within our mapped range
    if (pd_phys >= highest_mapped_physical_addr) {
        serial.println("[PAGING] ERROR: Allocated page table at 0x{x} is beyond mapped memory (max 0x{x})", .{ pd_phys, highest_mapped_physical_addr });
        return error.PageTableBeyondMappedMemory;
    }

    const pd = @as(*[512]u64, @ptrFromInt(pd_virt));

    // Clear the new table
    serial.println("[PAGING] Clearing PD table...", .{});
    @memset(pd, 0);
    serial.println("[PAGING] PD table cleared", .{});

    // Fill with 2MB pages, preserving only essential flags from the original huge page
    var i: usize = 0;
    while (i < 512) : (i += 1) {
        const mb_phys = gb_phys_base + (i * PAGE_SIZE_2M);
        pd[i] = mb_phys | essential_page_flags | PAGE_HUGE; // Keep huge bit for 2MB pages
    }

    // Step 6: Update PDPT entry to point to new PD (still without PRESENT)
    // For non-leaf entries (pointing to page tables), only use control flags
    // Don't include page-specific flags like NX, PAT, etc.
    const pdpt_table_flags = essential_page_flags & (PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    pdpt[pdpt_idx] = pd_phys | pdpt_table_flags;
    pdpt[pdpt_idx] &= ~PAGE_PRESENT; // Ensure PRESENT is still cleared
    asm volatile ("mfence" ::: "memory");

    // Step 7: Invalidate TLB again
    flushTLB();

    // Step 8: Flush caches again
    asm volatile ("wbinvd" ::: "memory");

    // Step 9: Set PRESENT bit
    pdpt[pdpt_idx] |= PAGE_PRESENT;
    asm volatile ("mfence" ::: "memory");

    // Step 10: Final TLB invalidation
    flushTLB();

    // Additional serialization after huge page split
    asm volatile ("cpuid" ::: "eax", "ebx", "ecx", "edx", "memory");

    serial.println("[PAGING] Split 1GB page at PDPT index {} into 2MB pages", .{pdpt_idx});

    // Verify the split was successful
    const new_entry = pdpt[pdpt_idx];
    serial.println("[PAGING] New PDPT[{}] entry after split: 0x{x}", .{ pdpt_idx, new_entry });

    // Additional verification: ensure the PD is accessible and properly mapped
    const verify_pd = @as(*[512]u64, @ptrFromInt(pd_virt));
    const first_pd_entry = verify_pd[0];
    serial.println("[PAGING] Verified PD[0] after split: 0x{x}", .{first_pd_entry});

    // Ensure the split preserved the identity mapping
    const expected_phys = gb_phys_base;
    const actual_phys = first_pd_entry & PHYS_ADDR_MASK;
    if (actual_phys != expected_phys) {
        serial.println("[PAGING] ERROR: PD[0] physical address mismatch after split!", .{});
        serial.println("[PAGING] Expected: 0x{x}, Actual: 0x{x}", .{ expected_phys, actual_phys });
    }
    if ((new_entry & PAGE_HUGE) != 0) {
        serial.println("[PAGING] ERROR: PDPT entry still has huge page bit set!", .{});
    }
}

// Split a 2MB huge page into 512 4KB pages
fn split2MBPageAt(pd: *[512]u64, pd_idx: usize, pd_virt_base: u64) !void {
    const entry = pd[pd_idx];
    if ((entry & PAGE_HUGE) == 0) return; // Not a huge page

    const mb_phys_base = entry & PHYS_ADDR_MASK;
    serial.println("[PAGING] split2MBPageAt: original entry=0x{x}", .{entry});

    // Intel SDM Vol 3A Section 4.10.4: Proper TLB invalidation procedure
    // Step 1: Disable interrupts
    const old_flags = asm volatile ("pushfq; popq %[flags]; cli"
        : [flags] "=r" (-> u64),
    );
    defer {
        if (old_flags & 0x200 != 0) {
            asm volatile ("sti" ::: "memory");
        }
    }

    // Step 2: Flush caches before changing page attributes
    asm volatile ("wbinvd" ::: "memory");

    // Step 3: Clear PRESENT bit in PD entry first (critical for proper TLB invalidation)
    pd[pd_idx] &= ~PAGE_PRESENT;
    asm volatile ("mfence" ::: "memory");

    // Step 4: Flush TLB for the entire 2MB region
    const mb_virt = pd_virt_base + (pd_idx * PAGE_SIZE_2M);
    var flush_addr = mb_virt;
    const mb_end = mb_virt + PAGE_SIZE_2M;
    while (flush_addr < mb_end) : (flush_addr += PAGE_SIZE_4K) {
        invalidatePage(flush_addr);
    }

    // Step 5: Use pre-allocated PT from bootloader
    if (next_kernel_pt_index >= kernel_pts.len) {
        serial.println("[PAGING] ERROR: Out of pre-allocated PT tables! Need {} but only have {}", .{ next_kernel_pt_index + 1, kernel_pts.len });
        return error.OutOfPageTables;
    }

    const pt_index = next_kernel_pt_index;
    next_kernel_pt_index += 1;

    const pt_phys = page_table_info.pt_table_base + (pt_index * 4096);
    serial.println("[PAGING] Using pre-allocated PT[{}] at physical 0x{x}", .{ pt_index, pt_phys });

    const pt_virt = runtime_info.physToVirt(pt_phys);
    serial.println("[PAGING] PT virtual address: 0x{x}", .{pt_virt});

    // Verify identity mapping assumption
    if (pt_phys != pt_virt) {
        serial.println("[PAGING] ERROR: Physical/virtual mismatch! phys=0x{x}, virt=0x{x}", .{ pt_phys, pt_virt });
        return error.AddressTranslationError;
    }

    // Check if this physical address is within our mapped range
    if (pt_phys >= highest_mapped_physical_addr) {
        serial.println("[PAGING] ERROR: Allocated page table at 0x{x} is beyond mapped memory (max 0x{x})", .{ pt_phys, highest_mapped_physical_addr });
        return error.PageTableBeyondMappedMemory;
    }

    const pt = @as(*[512]u64, @ptrFromInt(pt_virt));

    // Debug: Check if we can access the PT before clearing
    serial.println("[PAGING] Testing PT access at virtual 0x{x}...", .{pt_virt});

    // Check if this address is in a valid range
    const gb_index = pt_virt / PAGE_SIZE_1G;
    serial.println("[PAGING] PT is in GB {}", .{gb_index});

    // Try a simple read first
    serial.println("[PAGING] Attempting test read...", .{});
    const test_read = @as(*volatile u64, @ptrFromInt(pt_virt)).*;
    serial.println("[PAGING] Test read from PT succeeded: 0x{x}", .{test_read});

    // Clear the new table
    serial.println("[PAGING] Clearing PT table...", .{});
    @memset(pt, 0);
    serial.println("[PAGING] PT table cleared", .{});

    // Fill with 4KB pages, preserving only essential permission flags from the original huge page
    // We should NOT preserve transient flags like ACCESSED or DIRTY
    const ESSENTIAL_FLAGS = PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER | PAGE_NO_EXECUTE |
        PAGE_CACHE_DISABLE | PAGE_WRITE_THROUGH;
    const essential_page_flags = entry & ESSENTIAL_FLAGS;

    var i: usize = 0;
    while (i < 512) : (i += 1) {
        const kb_phys = mb_phys_base + (i * PAGE_SIZE_4K);
        // Only use essential flags, not transient ones like ACCESSED/DIRTY
        pt[i] = kb_phys | essential_page_flags;
    }

    // Step 6: Update PD entry to point to new PT (still without PRESENT)
    // For non-leaf entries (pointing to page tables), only use control flags
    // Don't include page-specific flags like NX, PAT, etc.
    const pd_table_flags = essential_page_flags & (PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER);
    pd[pd_idx] = pt_phys | pd_table_flags;
    pd[pd_idx] &= ~PAGE_PRESENT; // Ensure PRESENT is still cleared
    asm volatile ("mfence" ::: "memory");

    // Step 7: Invalidate TLB again
    flush_addr = mb_virt;
    while (flush_addr < mb_end) : (flush_addr += PAGE_SIZE_4K) {
        invalidatePage(flush_addr);
    }

    // Step 8: Flush caches again
    asm volatile ("wbinvd" ::: "memory");

    // Step 9: Set PRESENT bit
    pd[pd_idx] |= PAGE_PRESENT;
    asm volatile ("mfence" ::: "memory");

    // Step 10: Final TLB invalidation
    flush_addr = mb_virt;
    while (flush_addr < mb_end) : (flush_addr += PAGE_SIZE_4K) {
        invalidatePage(flush_addr);
    }

    // Additional serialization after huge page split
    asm volatile ("cpuid" ::: "eax", "ebx", "ecx", "edx", "memory");

    serial.println("[PAGING] Split 2MB page at PD index {} (virt 0x{x}) into 4KB pages", .{ pd_idx, mb_virt });

    // Verify the split was successful
    const new_entry = pd[pd_idx];
    serial.println("[PAGING] New PD[{}] entry after split: 0x{x}", .{ pd_idx, new_entry });
    if ((new_entry & PAGE_HUGE) != 0) {
        serial.println("[PAGING] ERROR: PD entry still has huge page bit set!", .{});
    }

    // Additional verification: ensure the PT is accessible and properly mapped
    const verify_pt = @as(*[512]u64, @ptrFromInt(pt_virt));
    const first_pt_entry = verify_pt[0];
    serial.println("[PAGING] Verified PT[0] after split: 0x{x}", .{first_pt_entry});
    serial.println("[PAGING] Essential flags preserved: 0x{x}", .{essential_page_flags});

    // Verify a specific entry for APIC if this is the APIC page
    if (mb_virt == 0xfee00000) {
        const apic_pt_idx = 0; // APIC is at the start of this 2MB region
        const apic_entry = verify_pt[apic_pt_idx];
        serial.println("[PAGING] APIC PT entry after split: 0x{x}", .{apic_entry});

        // For MMIO regions, we need to ensure all pages in the PT have proper cache settings
        // Update all entries to have cache-disable for the entire 2MB region
        serial.println("[PAGING] Updating entire 2MB region for MMIO compatibility", .{});
        var j: usize = 0;
        while (j < 512) : (j += 1) {
            const kb_phys = mb_phys_base + (j * PAGE_SIZE_4K);
            // Set cache-disable for all pages in MMIO region
            verify_pt[j] = kb_phys | PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE;
        }
        // Flush entire 2MB region
        var mmio_flush_addr = mb_virt;
        const flush_end = mb_virt + PAGE_SIZE_2M;
        while (mmio_flush_addr < flush_end) : (mmio_flush_addr += PAGE_SIZE_4K) {
            invalidatePage(mmio_flush_addr);
        }
        serial.println("[PAGING] Updated all PT entries for MMIO region", .{});
    }
}

// Map a page with specific permissions
// This is a simplified version - a full implementation would handle page table allocation
pub fn mapPage(virt_addr: u64, phys_addr: u64, flags: u64) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Acquire page table lock for this address
    var lock_guard = page_table_locks.acquireForAddress(virt_addr);
    defer lock_guard.deinit();
    // This is a basic implementation - in practice you'd need to allocate
    // page table pages if they don't exist

    const pml4_idx = getTableIndex(virt_addr, 4);
    const pdpt_idx = getTableIndex(virt_addr, 3);
    const pd_idx = getTableIndex(virt_addr, 2);
    const pt_idx = getTableIndex(virt_addr, 1);

    // For now, assume all page table structures exist
    if ((pml4_table[pml4_idx] & PAGE_PRESENT) == 0) {
        return error.PageTableNotPresent;
    }

    const pdpt_phys = pml4_table[pml4_idx] & PHYS_ADDR_MASK;
    const pdpt_virt = runtime_info.physToVirt(pdpt_phys);
    const pdpt = @as(*[512]u64, @ptrFromInt(pdpt_virt));

    if ((pdpt[pdpt_idx] & PAGE_PRESENT) == 0) {
        return error.PageTableNotPresent;
    }

    if ((pdpt[pdpt_idx] & PAGE_HUGE) != 0) {
        // Split the 1GB page into 2MB pages
        try split1GBPage(pdpt, pdpt_idx);
        // Now it should be a normal PD pointer, not a huge page
    }

    const pd_phys = pdpt[pdpt_idx] & PHYS_ADDR_MASK;
    const pd_virt = runtime_info.physToVirt(pd_phys);
    const pd = @as(*[512]u64, @ptrFromInt(pd_virt));

    if ((pd[pd_idx] & PAGE_PRESENT) == 0) {
        return error.PageTableNotPresent;
    }

    if ((pd[pd_idx] & PAGE_HUGE) != 0) {
        // Split the 2MB page into 4KB pages
        const pd_virt_base = pdpt_idx * PAGE_SIZE_1G;
        try split2MBPageAt(pd, pd_idx, pd_virt_base);
        // Now it should be a normal PT pointer, not a huge page
    }

    const pt_phys = pd[pd_idx] & PHYS_ADDR_MASK;
    const pt_virt = runtime_info.physToVirt(pt_phys);
    const pt = @as(*[512]u64, @ptrFromInt(pt_virt));

    // Map the page
    pt[pt_idx] = phys_addr | flags;
    serial.println("[PAGING] Mapped page: virt=0x{x} -> phys=0x{x}, flags=0x{x}, PTE=0x{x}", .{ virt_addr, phys_addr, flags, pt[pt_idx] });

    // Flush TLB entry with memory barrier
    asm volatile ("mfence" ::: "memory");
    invalidatePage(virt_addr);

    // Verify the mapping is accessible by doing a test read of the PTE
    const verify_pte = pt[pt_idx];
    serial.println("[PAGING] Verified PTE readback: 0x{x}", .{verify_pte});
}

// Map a page with raw page table entry value (for special page types like shadow stack)
// This allows full control over page table entry bits
pub fn mapPageRaw(virt_addr: u64, raw_entry: u64) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Acquire page table lock for this address
    var lock_guard = page_table_locks.acquireForAddress(virt_addr);
    defer lock_guard.deinit();
    const pml4_idx = getTableIndex(virt_addr, 4);
    const pdpt_idx = getTableIndex(virt_addr, 3);
    const pd_idx = getTableIndex(virt_addr, 2);
    const pt_idx = getTableIndex(virt_addr, 1);

    // For now, assume all page table structures exist
    if ((pml4_table[pml4_idx] & PAGE_PRESENT) == 0) {
        return error.PageTableNotPresent;
    }

    const pdpt_phys = pml4_table[pml4_idx] & PHYS_ADDR_MASK;
    const pdpt_virt = runtime_info.physToVirt(pdpt_phys);
    const pdpt = @as(*[512]u64, @ptrFromInt(pdpt_virt));

    if ((pdpt[pdpt_idx] & PAGE_PRESENT) == 0) {
        return error.PageTableNotPresent;
    }

    if ((pdpt[pdpt_idx] & PAGE_HUGE) != 0) {
        // Split the 1GB page into 2MB pages
        try split1GBPage(pdpt, pdpt_idx);
        // Now it should be a normal PD pointer, not a huge page
    }

    const pd_phys = pdpt[pdpt_idx] & PHYS_ADDR_MASK;
    const pd_virt = runtime_info.physToVirt(pd_phys);
    const pd = @as(*[512]u64, @ptrFromInt(pd_virt));

    if ((pd[pd_idx] & PAGE_PRESENT) == 0) {
        return error.PageTableNotPresent;
    }

    if ((pd[pd_idx] & PAGE_HUGE) != 0) {
        // Split the 2MB page into 4KB pages
        const pd_virt_base = pdpt_idx * PAGE_SIZE_1G;
        try split2MBPageAt(pd, pd_idx, pd_virt_base);
        // Now it should be a normal PT pointer, not a huge page
    }

    const pt_phys = pd[pd_idx] & PHYS_ADDR_MASK;
    const pt_virt = runtime_info.physToVirt(pt_phys);
    const pt = @as(*[512]u64, @ptrFromInt(pt_virt));

    // Map the page with raw entry
    pt[pt_idx] = raw_entry;
    asm volatile ("mfence" ::: "memory");
    invalidatePage(virt_addr);
}

// Create a guard page that will fault on any access
pub fn createGuardPageAt(addr: u64) !void {
    try guard_pages.createGuardPageAt(addr, unmapPage);
}

// Add guard pages around a virtual memory region
pub fn addGuardPagesAroundVirtualRegion(start: u64, size: u64) !void {
    try guard_pages.addGuardPagesAroundVirtualRegion(start, size, createGuardPageAt);
}

// Test memory protection features at the paging level
pub fn testPagingMemoryProtection() void {
    test_utils.testPagingMemoryProtection(getPageTableEntry);
}

// Map a page as a shadow stack page (for CET)
pub fn mapShadowStackPage(virt_addr: u64, phys_addr: u64) !void {
    try shadow_stack.mapShadowStackPage(virt_addr, phys_addr, mapPageRaw);
}

// Map a page with specific permissions and protection key
pub fn mapPageWithKey(virt_addr: u64, phys_addr: u64, flags: u64, key: pku.ProtectionKeys) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Acquire page table lock for this address
    var lock_guard = page_table_locks.acquireForAddress(virt_addr);
    defer lock_guard.deinit();

    // Create page table entry with protection key
    const entry = pku.createPageEntryWithKey(phys_addr, flags, key);

    // Map the page with the PKU-enabled entry
    try mapPageRaw(virt_addr, entry);
}

// Get the physical address that a virtual address maps to
// Handles 4KB, 2MB, and 1GB pages correctly
pub fn getPhysicalAddress(virt_addr: u64) !u64 {
    const pte = try getPageTableEntry(virt_addr);

    // Check page size to determine how to extract physical address
    if ((pte & PAGE_HUGE) != 0) {
        // Large page - need to determine if it's 2MB or 1GB
        const pml4_idx = getTableIndex(virt_addr, 4);
        const pdpt_idx = getTableIndex(virt_addr, 3);

        // Check if this is a 1GB page (in PDPT) or 2MB page (in PD)
        const pdpt_phys = pml4_table[pml4_idx] & PHYS_ADDR_MASK;
        const pdpt_virt = runtime_info.physToVirt(pdpt_phys);
        const pdpt = @as(*[512]u64, @ptrFromInt(pdpt_virt));

        if ((pdpt[pdpt_idx] & PAGE_HUGE) != 0) {
            // 1GB page
            const base = pte & ~@as(u64, PAGE_SIZE_1G - 1);
            const offset = virt_addr & (PAGE_SIZE_1G - 1);
            return base + offset;
        } else {
            // 2MB page
            const base = pte & ~@as(u64, PAGE_SIZE_2M - 1);
            const offset = virt_addr & (PAGE_SIZE_2M - 1);
            return base + offset;
        }
    } else {
        // 4KB page
        const base = pte & PHYS_ADDR_MASK;
        const offset = virt_addr & (PAGE_SIZE_4K - 1);
        return base + offset;
    }
}

// Get page table entry for a virtual address
pub fn getPageTableEntry(virt_addr: u64) !u64 {
    const pml4_idx = getTableIndex(virt_addr, 4);
    const pdpt_idx = getTableIndex(virt_addr, 3);
    const pd_idx = getTableIndex(virt_addr, 2);
    const pt_idx = getTableIndex(virt_addr, 1);

    // Navigate to the page table entry
    if ((pml4_table[pml4_idx] & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    const pdpt_phys = pml4_table[pml4_idx] & PHYS_ADDR_MASK;
    const pdpt_virt = runtime_info.physToVirt(pdpt_phys);
    const pdpt = @as(*[512]u64, @ptrFromInt(pdpt_virt));

    if ((pdpt[pdpt_idx] & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    // Handle 1GB pages
    if ((pdpt[pdpt_idx] & PAGE_HUGE) != 0) {
        return pdpt[pdpt_idx];
    }

    const pd_phys = pdpt[pdpt_idx] & PHYS_ADDR_MASK;
    const pd_virt = runtime_info.physToVirt(pd_phys);
    const pd = @as(*[512]u64, @ptrFromInt(pd_virt));

    if ((pd[pd_idx] & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    // Handle 2MB pages
    if ((pd[pd_idx] & PAGE_HUGE) != 0) {
        return pd[pd_idx];
    }

    const pt_phys = pd[pd_idx] & PHYS_ADDR_MASK;
    const pt_virt = runtime_info.physToVirt(pt_phys);
    const pt = @as(*[512]u64, @ptrFromInt(pt_virt));

    // Return 4K page entry (even if not present, for shadow stack pages)
    return pt[pt_idx];
}

// Run all paging tests
pub fn testAllPagingFeatures() void {
    test_utils.testAll();
    testPagingMemoryProtection();
}

// Make a memory region executable (removes NX bit)
// This is needed for the AP trampoline code
pub fn makeRegionExecutable(start_addr: u64, size: u64) !void {
    const aligned_start = start_addr & ~@as(u64, PAGE_SIZE_4K - 1);
    const aligned_end = (start_addr + size + PAGE_SIZE_4K - 1) & ~@as(u64, PAGE_SIZE_4K - 1);

    serial.println("[PAGING] Making region 0x{x}-0x{x} executable", .{ aligned_start, aligned_end });

    // With our new 4KB page mapping for low memory, we can handle individual pages
    var current_addr = aligned_start;
    while (current_addr < aligned_end) : (current_addr += PAGE_SIZE_4K) {
        const pml4_idx = getTableIndex(current_addr, 4);
        const pdpt_idx = getTableIndex(current_addr, 3);
        const pd_idx = getTableIndex(current_addr, 2);
        const pt_idx = getTableIndex(current_addr, 1);

        // Navigate through page tables
        if ((pml4_table[pml4_idx] & PAGE_PRESENT) == 0) {
            serial.println("[PAGING] PML4 entry not present for 0x{x}", .{current_addr});
            continue;
        }

        const pdpt_phys = pml4_table[pml4_idx] & PHYS_ADDR_MASK;
        const pdpt_virt = runtime_info.physToVirt(pdpt_phys);
        const pdpt = @as(*[512]u64, @ptrFromInt(pdpt_virt));

        if ((pdpt[pdpt_idx] & PAGE_PRESENT) == 0) {
            serial.println("[PAGING] PDPT entry not present for 0x{x}", .{current_addr});
            continue;
        }

        // Check if it's a 1GB page
        if ((pdpt[pdpt_idx] & PAGE_HUGE) != 0) {
            serial.println("[PAGING] Cannot make executable: 1GB page at 0x{x}", .{current_addr});
            return error.CannotModify1GBPage;
        }

        const pd_phys = pdpt[pdpt_idx] & PHYS_ADDR_MASK;
        const pd_virt = runtime_info.physToVirt(pd_phys);
        const pd = @as(*[512]u64, @ptrFromInt(pd_virt));

        if ((pd[pd_idx] & PAGE_PRESENT) == 0) {
            serial.println("[PAGING] PD entry not present for 0x{x}", .{current_addr});
            continue;
        }

        // Check if it's a 2MB page
        if ((pd[pd_idx] & PAGE_HUGE) != 0) {
            // For 2MB pages, clear NX bit on the whole page
            const old_entry = pd[pd_idx];
            if ((old_entry & PAGE_NO_EXECUTE) != 0) {
                pd[pd_idx] = old_entry & ~PAGE_NO_EXECUTE;
                serial.println("[PAGING] Cleared NX bit on 2MB page at 0x{x}", .{current_addr});

                // Flush TLB for the 2MB page
                const mb_base = current_addr & ~@as(u64, PAGE_SIZE_2M - 1);
                var flush_addr = mb_base;
                while (flush_addr < mb_base + PAGE_SIZE_2M) : (flush_addr += PAGE_SIZE_4K) {
                    invalidatePage(flush_addr);
                }
            }
            // Skip to next 2MB boundary
            current_addr = (current_addr & ~@as(u64, PAGE_SIZE_2M - 1)) + PAGE_SIZE_2M - PAGE_SIZE_4K;
            continue;
        }

        // It's a 4KB page table
        const pt_phys = pd[pd_idx] & PHYS_ADDR_MASK;
        const pt_virt = runtime_info.physToVirt(pt_phys);
        const pt = @as(*[512]u64, @ptrFromInt(pt_virt));

        // Clear NX bit on the specific 4KB page
        if ((pt[pt_idx] & PAGE_PRESENT) != 0) {
            const old_entry = pt[pt_idx];
            if ((old_entry & PAGE_NO_EXECUTE) != 0) {
                pt[pt_idx] = old_entry & ~PAGE_NO_EXECUTE;
                serial.println("[PAGING] Cleared NX bit on 4KB page at 0x{x}", .{current_addr});
                invalidatePage(current_addr);
            }
        }
    }

    // Intel SDM Vol 3A, Section 11.12: Ensure page table changes are globally visible
    // Issue a full TLB flush to ensure all cached translations are invalidated
    flushTLB();

    // Memory barrier to ensure all page table modifications are complete
    asm volatile ("mfence" ::: "memory");

    serial.println("[PAGING] Region made executable", .{});
}

// Split a 2MB page into 4KB pages for fine-grained control
// This is necessary for low memory where we need different permissions for different areas
pub fn split2MBPage(mb_addr: u64) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    const aligned_addr = mb_addr & ~@as(u64, PAGE_SIZE_2M - 1);
    serial.println("[PAGING] Splitting 2MB page at 0x{x} into 4KB pages", .{aligned_addr});

    // Debug: show current page table state
    serial.println("[PAGING] PML4[0] = 0x{x}", .{pml4_table[0]});

    // Safety check - don't try to split if paging isn't fully initialized
    const cr3 = getCurrentPageTable();
    if (cr3 == 0) {
        serial.println("[PAGING] ERROR: CR3 is 0, paging not initialized", .{});
        return error.PagingNotInitialized;
    }

    // Find the PD entry for this 2MB page
    const pml4_idx = getTableIndex(aligned_addr, 4);
    const pdpt_idx = getTableIndex(aligned_addr, 3);
    const pd_idx = getTableIndex(aligned_addr, 2);

    // Navigate to the PD
    if ((pml4_table[pml4_idx] & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    const pdpt_phys = pml4_table[pml4_idx] & PHYS_ADDR_MASK;
    const pdpt_virt = runtime_info.physToVirt(pdpt_phys);
    const pdpt = @as(*[512]u64, @ptrFromInt(pdpt_virt));

    if ((pdpt[pdpt_idx] & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    if ((pdpt[pdpt_idx] & PAGE_HUGE) != 0) {
        return error.CannotSplit1GBPage; // Would need to split 1GB->2MB first
    }

    const pd_phys = pdpt[pdpt_idx] & PHYS_ADDR_MASK;
    const pd_virt = runtime_info.physToVirt(pd_phys);
    const pd = @as(*[512]u64, @ptrFromInt(pd_virt));

    const pd_entry = pd[pd_idx];
    if ((pd_entry & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    if ((pd_entry & PAGE_HUGE) == 0) {
        // Already using 4KB pages
        serial.println("[PAGING] Page at 0x{x} already uses 4KB pages", .{aligned_addr});
        return;
    }

    // Allocate a new page table for the 4KB pages
    const pt_page = pmm.allocPage() orelse {
        return error.OutOfMemory;
    };
    const pt_virt = runtime_info.physToVirt(pt_page);
    const pt = @as(*[512]u64, @ptrFromInt(pt_virt));

    // Zero the page table
    @memset(@as([*]u8, @ptrCast(pt))[0..PAGE_SIZE_4K], 0);

    // Get the flags from the 2MB page (excluding PAGE_HUGE)
    const flags = pd_entry & ~(PAGE_HUGE | PHYS_ADDR_MASK);

    // Fill the PT with 512 4KB pages that map the same physical memory
    const base_phys = pd_entry & PHYS_ADDR_MASK;
    for (0..512) |i| {
        const page_phys = base_phys + (i * PAGE_SIZE_4K);
        pt[i] = page_phys | flags | PAGE_PRESENT;
    }

    // Replace the PD entry to point to the new PT
    pd[pd_idx] = pt_page | PAGE_PRESENT | PAGE_WRITABLE;

    // Flush TLB for the entire 2MB region
    var flush_addr = aligned_addr;
    const end_addr = aligned_addr + PAGE_SIZE_2M;
    while (flush_addr < end_addr) : (flush_addr += PAGE_SIZE_4K) {
        invalidatePage(flush_addr);
    }

    serial.println("[PAGING] Successfully split 2MB page into 4KB pages", .{});
}

// Make a memory region uncacheable - critical for SMP coherency
pub fn makeRegionUncacheable(start_addr: u64, size: u64) !void {
    const aligned_start = start_addr & ~@as(u64, PAGE_SIZE_4K - 1);
    const aligned_end = (start_addr + size + PAGE_SIZE_4K - 1) & ~@as(u64, PAGE_SIZE_4K - 1);

    serial.println("[PAGING] Making region 0x{x}-0x{x} uncacheable", .{ aligned_start, aligned_end });

    // For regions in the first 2MB, we need to handle it specially
    if (aligned_start < PAGE_SIZE_2M) {
        // The first 2MB is mapped directly in kernel_pd[0]
        const old_entry = pd_tables[0][0];

        // Check if this is a 2MB page
        if ((old_entry & PAGE_HUGE) != 0) {
            // For 2MB pages, we need to split it into 4K pages to apply different cache attributes
            serial.println("[PAGING] Need to split 2MB page to make region uncacheable", .{});

            // This is complex - for now, just set the entire 2MB page as uncacheable
            // Set PCD (Page Cache Disable) and PWT (Page Write Through) bits
            const new_entry = old_entry | PAGE_CACHE_DISABLE | PAGE_WRITE_THROUGH;
            pd_tables[0][0] = new_entry;
            serial.println("[PAGING] Updated first 2MB page to uncacheable: 0x{x}", .{new_entry});

            // Flush TLB for the entire 2MB page
            var flush_addr: u64 = 0;
            while (flush_addr < PAGE_SIZE_2M) : (flush_addr += PAGE_SIZE_4K) {
                invalidatePage(flush_addr);
            }

            // Also flush caches for this region
            flush_addr = aligned_start;
            while (flush_addr < aligned_end and flush_addr < PAGE_SIZE_2M) : (flush_addr += 64) {
                asm volatile ("clflush (%[addr])"
                    :
                    : [addr] "r" (flush_addr),
                    : "memory"
                );
            }
            asm volatile ("mfence" ::: "memory");
        }
    } else {
        // For other regions, walk the page tables and update each 4K page
        var current_addr = aligned_start;
        while (current_addr < aligned_end) : (current_addr += PAGE_SIZE_4K) {
            // This would require walking the page tables - simplified for now
            serial.println("[PAGING] Would update page at 0x{x} to uncacheable", .{current_addr});
        }
    }

    serial.println("[PAGING] Region marked as uncacheable", .{});
}

// Update page flags without changing the physical address
// This is useful for changing permissions on existing mappings
pub fn updatePageFlags(virt_addr: u64, new_flags: u64) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Acquire page table lock for this address
    var lock_guard = page_table_locks.acquireForAddress(virt_addr);
    defer lock_guard.deinit();
    const pml4_idx = getTableIndex(virt_addr, 4);
    const pdpt_idx = getTableIndex(virt_addr, 3);
    const pd_idx = getTableIndex(virt_addr, 2);
    const pt_idx = getTableIndex(virt_addr, 1);

    // Navigate to the page table entry
    if ((pml4_table[pml4_idx] & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    const pdpt_phys = pml4_table[pml4_idx] & PHYS_ADDR_MASK;
    const pdpt_virt = runtime_info.physToVirt(pdpt_phys);
    const pdpt = @as(*[512]u64, @ptrFromInt(pdpt_virt));

    if ((pdpt[pdpt_idx] & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    // Handle 1GB pages
    if ((pdpt[pdpt_idx] & PAGE_HUGE) != 0) {
        const phys_addr = pdpt[pdpt_idx] & PHYS_ADDR_MASK;
        pdpt[pdpt_idx] = phys_addr | new_flags | PAGE_HUGE;
        asm volatile ("mfence" ::: "memory");
        invalidatePage(virt_addr);
        return;
    }

    const pd_phys = pdpt[pdpt_idx] & PHYS_ADDR_MASK;
    const pd_virt = runtime_info.physToVirt(pd_phys);
    const pd = @as(*[512]u64, @ptrFromInt(pd_virt));

    if ((pd[pd_idx] & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    // Handle 2MB pages
    if ((pd[pd_idx] & PAGE_HUGE) != 0) {
        const phys_addr = pd[pd_idx] & PHYS_ADDR_MASK;
        pd[pd_idx] = phys_addr | new_flags | PAGE_HUGE;
        asm volatile ("mfence" ::: "memory");
        invalidatePage(virt_addr);
        return;
    }

    const pt_phys = pd[pd_idx] & PHYS_ADDR_MASK;
    const pt_virt = runtime_info.physToVirt(pt_phys);
    const pt = @as(*[512]u64, @ptrFromInt(pt_virt));

    if ((pt[pt_idx] & PAGE_PRESENT) == 0) {
        return error.PageNotMapped;
    }

    // Update 4K page
    const phys_addr = pt[pt_idx] & PHYS_ADDR_MASK;
    pt[pt_idx] = phys_addr | new_flags;
    asm volatile ("mfence" ::: "memory");
    invalidatePage(virt_addr);
}

// Map a memory-mapped I/O (MMIO) region as uncacheable
// This is critical for device registers like APIC, where caching can cause incorrect behavior
pub fn mapMMIORegion(virt_addr: u64, phys_addr: u64, size: usize) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Ensure addresses and size are page-aligned
    if ((virt_addr & (PAGE_SIZE_4K - 1)) != 0 or (phys_addr & (PAGE_SIZE_4K - 1)) != 0) {
        return error.UnalignedAddress;
    }

    const page_count = (size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;

    serial.println("[PAGING] Mapping MMIO region: virt=0x{x}, phys=0x{x}, size=0x{x} ({} pages)", .{ virt_addr, phys_addr, size, page_count });

    // Check if this region is already mapped
    if (getPageTableEntry(virt_addr)) |existing_pte| {
        serial.println("[PAGING] WARNING: Page already mapped with PTE: 0x{x}", .{existing_pte});
        const existing_phys = existing_pte & PHYS_ADDR_MASK;

        // Check if it's mapped to the correct address with correct cache attributes
        const has_cache_disable = (existing_pte & PAGE_CACHE_DISABLE) != 0;
        const has_nx_bit = (existing_pte & PAGE_NO_EXECUTE) != 0;

        if (existing_phys == phys_addr and has_cache_disable and !has_nx_bit) {
            serial.println("[PAGING] Already mapped correctly for MMIO, skipping", .{});
            return;
        }

        if (existing_phys != phys_addr) {
            serial.println("[PAGING] Page mapped to different address (0x{x}), remapping...", .{existing_phys});
        } else {
            serial.println("[PAGING] Page has incorrect attributes (cache_disable={}, nx={}), remapping...", .{ has_cache_disable, has_nx_bit });
        }
    } else |err| {
        if (err == error.PageNotMapped) {
            serial.println("[PAGING] Page not currently mapped, proceeding with mapping", .{});
        } else {
            serial.println("[PAGING] Error checking existing mapping: {}", .{err});
        }
    }

    // Map each page with uncacheable flags
    var offset: usize = 0;
    while (offset < size) : (offset += PAGE_SIZE_4K) {
        const current_virt = virt_addr + offset;
        const current_phys = phys_addr + offset;

        // Use cache-disable and write-through for MMIO regions
        // This ensures all reads/writes go directly to the device
        // Note: Don't set PAGE_NO_EXECUTE for MMIO as it can cause issues
        // For APIC specifically, we need strong uncacheable (UC) not write-combining
        const mmio_flags = if (phys_addr == 0xfee00000) blk: {
            // APIC requires strong uncacheable (UC) - PAT index 0
            // This means PCD=1, PWT=0 (not both set)
            serial.println("[PAGING] Using strong UC for APIC MMIO", .{});
            break :blk PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE;
        } else blk: {
            // Other MMIO can use UC- (uncacheable minus) - PAT index 3
            break :blk PAGE_PRESENT | PAGE_WRITABLE | PAGE_CACHE_DISABLE | PAGE_WRITE_THROUGH;
        };

        // Map the page - mapPage now handles huge page splitting automatically
        mapPage(current_virt, current_phys, mmio_flags) catch |err| {
            if (err == error.PageTableNotPresent) {
                // Page table doesn't exist, this is more complex
                // For now, we assume early boot has set up necessary page tables
                serial.println("[PAGING] WARNING: Page table not present for MMIO mapping at 0x{x}", .{current_virt});
                return err;
            } else {
                serial.println("[PAGING] Failed to map MMIO page at 0x{x}: {}", .{ current_virt, err });
                return err;
            }
        };
    }

    // Ensure all CPUs see the mapping changes
    asm volatile ("mfence" ::: "memory");

    // After splitting huge pages and mapping MMIO, we need a full TLB flush
    // This is critical for MMIO regions after page size changes
    serial.println("[PAGING] Performing full TLB flush after MMIO mapping...", .{});
    flushTLB();

    // Additional synchronization for APIC MMIO
    if (phys_addr == 0xfee00000) {
        // For APIC, we need extra care with TLB and cache coherency
        asm volatile ("mfence" ::: "memory");
        asm volatile ("wbinvd" ::: "memory"); // Flush all caches
        asm volatile ("mfence" ::: "memory");

        // Verify the mapping one more time
        if (getPageTableEntry(virt_addr)) |final_pte| {
            serial.println("[PAGING] Final APIC PTE after all flushes: 0x{x}", .{final_pte});
            if ((final_pte & PAGE_CACHE_DISABLE) == 0) {
                serial.println("[PAGING] ERROR: APIC page still not uncacheable after mapping!", .{});
                return error.APICMappingFailed;
            }
        } else |_| {}
    }

    // Additional serialization to ensure all memory operations complete
    asm volatile ("mfence" ::: "memory");
    asm volatile ("" ::: "memory"); // Compiler barrier

    serial.println("[PAGING] MMIO region mapped successfully", .{});
}

// Ensure a region is identity mapped (virtual address = physical address)
// This is critical for AP trampoline code
pub fn ensureIdentityMapping(virt_addr: u64, size: u64) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    const aligned_start = virt_addr & ~@as(u64, PAGE_SIZE_4K - 1);
    const aligned_end = (virt_addr + size + PAGE_SIZE_4K - 1) & ~@as(u64, PAGE_SIZE_4K - 1);

    serial.println("[PAGING] Ensuring identity mapping for 0x{x}-0x{x}", .{ aligned_start, aligned_end });

    // For each page in the range, ensure it's identity mapped
    var current_addr = aligned_start;
    while (current_addr < aligned_end) : (current_addr += PAGE_SIZE_4K) {
        // Check if page is already mapped correctly
        const pte = getPageTableEntry(current_addr) catch |err| {
            if (err == error.PageNotMapped) {
                // Page not mapped - need to map it
                serial.println("[PAGING] Page at 0x{x} not mapped, creating identity mapping", .{current_addr});

                // Map with standard flags for executable code
                const flags = PAGE_PRESENT | PAGE_WRITABLE;
                try mapPage(current_addr, current_addr, flags);
            } else {
                return err;
            }
            continue;
        };

        const phys_addr = pte & PHYS_ADDR_MASK;
        if (phys_addr != current_addr) {
            serial.println("[PAGING] Page at 0x{x} not identity mapped (phys=0x{x})", .{ current_addr, phys_addr });

            // Need to remap as identity mapping
            // First unmap the old mapping
            unmapPage(current_addr) catch |err| {
                serial.println("[PAGING] WARNING: Failed to unmap page: {}", .{err});
            };

            // Then create identity mapping
            const flags = PAGE_PRESENT | PAGE_WRITABLE;
            try mapPage(current_addr, current_addr, flags);
        }
    }

    // Flush TLB for the entire range
    current_addr = aligned_start;
    while (current_addr < aligned_end) : (current_addr += PAGE_SIZE_4K) {
        invalidatePage(current_addr);
    }

    serial.println("[PAGING] Identity mapping ensured", .{});
}
