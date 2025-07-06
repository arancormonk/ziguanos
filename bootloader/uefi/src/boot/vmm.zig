// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const serial = @import("../drivers/serial.zig");

// MSR addresses and bits for NX enable
const IA32_EFER: u32 = 0xC0000080;
const EFER_NXE: u64 = 1 << 11; // No-Execute Enable

// Read MSR
fn readMSR(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, high) << 32) | low;
}

// Write MSR
fn writeMSR(msr: u32, value: u64) void {
    const low = @as(u32, @truncate(value));
    const high = @as(u32, @truncate(value >> 32));
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (low),
          [high] "{edx}" (high),
        : "memory"
    );
}

// Check if NX is supported and enable it
fn enableNXBit() bool {
    // Check if NX is supported via CPUID
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    // CPUID function 0x80000001 - Extended feature information
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [input] "{eax}" (@as(u32, 0x80000001)),
    );

    // Check bit 20 in EDX for NX support
    const nx_supported = (edx & (1 << 20)) != 0;

    if (!nx_supported) {
        serial.print("[VMM] WARNING: NX bit not supported by CPU\n", .{}) catch {};
        return false;
    }

    // Enable NX bit in EFER
    var efer = readMSR(IA32_EFER);
    if ((efer & EFER_NXE) == 0) {
        efer |= EFER_NXE;
        writeMSR(IA32_EFER, efer);
        serial.print("[VMM] ✓ NX (No-Execute) bit enabled for W^X enforcement\n", .{}) catch {};
    } else {
        serial.print("[VMM] ✓ NX (No-Execute) bit already enabled\n", .{}) catch {};
    }

    return true;
}

// Page size and entry flags
pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_PRESENT: u64 = 1 << 0;
pub const PAGE_WRITE: u64 = 1 << 1;
pub const PAGE_USER: u64 = 1 << 2;
pub const PAGE_WRITE_THROUGH: u64 = 1 << 3;
pub const PAGE_CACHE_DISABLE: u64 = 1 << 4;
pub const PAGE_ACCESSED: u64 = 1 << 5;
pub const PAGE_DIRTY: u64 = 1 << 6;
pub const PAGE_SIZE_BIT: u64 = 1 << 7; // 2MB pages for PD entries
pub const PAGE_GLOBAL: u64 = 1 << 8;
pub const PAGE_NX: u64 = 1 << 63; // No execute

// Page table structure
const PageTable = extern struct {
    entries: [512]u64 align(4096) = [_]u64{0} ** 512,
};

// Virtual Memory Manager for bootloader
pub const VirtualMemoryManager = struct {
    boot_services: *uefi.tables.BootServices,
    pml4: *PageTable,
    pdpt_pool: []PageTable,
    pd_pool: []PageTable,
    pt_pool: []PageTable,
    next_pdpt: usize = 0,
    next_pd: usize = 0,
    next_pt: usize = 0,

    // Track allocations for cleanup
    allocations: struct {
        pml4_addr: ?[*]align(4096) u8 = null,
        pdpt_pool_addr: ?[*]align(4096) u8 = null,
        pd_pool_addr: ?[*]align(4096) u8 = null,
        pt_pool_addr: ?[*]align(4096) u8 = null,
        pml4_pages: usize = 0,
        pdpt_pages: usize = 0,
        pd_pages: usize = 0,
        pt_pages: usize = 0,
    } = .{},

    // Initialize VMM with page table pools
    pub fn init(boot_services: *uefi.tables.BootServices) !VirtualMemoryManager {
        // Enable NX bit before setting up page tables for W^X enforcement
        _ = enableNXBit();

        var vmm = VirtualMemoryManager{
            .boot_services = boot_services,
            .pml4 = undefined,
            .pdpt_pool = undefined,
            .pd_pool = undefined,
            .pt_pool = undefined,
        };

        // Allocate PML4
        var pml4_addr: [*]align(4096) u8 = undefined;
        switch (boot_services.allocatePages(
            .allocate_any_pages,
            .loader_data,
            1,
            &pml4_addr,
        )) {
            .success => {},
            else => return error.AllocationFailed,
        }
        vmm.allocations.pml4_addr = pml4_addr;
        vmm.allocations.pml4_pages = 1;
        vmm.pml4 = @ptrCast(pml4_addr);
        @memset(@as([*]u8, @ptrCast(vmm.pml4))[0..@sizeOf(PageTable)], 0);

        // Allocate PDPT pool (4 tables = 16KB)
        var pdpt_pool_addr: [*]align(4096) u8 = undefined;
        const pdpt_pages = 4;
        switch (boot_services.allocatePages(
            .allocate_any_pages,
            .loader_data,
            pdpt_pages,
            &pdpt_pool_addr,
        )) {
            .success => {},
            else => {
                vmm.cleanup();
                return error.AllocationFailed;
            },
        }
        vmm.allocations.pdpt_pool_addr = pdpt_pool_addr;
        vmm.allocations.pdpt_pages = pdpt_pages;
        vmm.pdpt_pool = @as([*]PageTable, @ptrCast(pdpt_pool_addr))[0..pdpt_pages];
        @memset(@as([*]u8, @ptrCast(pdpt_pool_addr))[0 .. pdpt_pages * PAGE_SIZE], 0);

        // Allocate PD pool (16 tables = 64KB)
        var pd_pool_addr: [*]align(4096) u8 = undefined;
        const pd_pages = 16;
        switch (boot_services.allocatePages(
            .allocate_any_pages,
            .loader_data,
            pd_pages,
            &pd_pool_addr,
        )) {
            .success => {},
            else => {
                vmm.cleanup();
                return error.AllocationFailed;
            },
        }
        vmm.allocations.pd_pool_addr = pd_pool_addr;
        vmm.allocations.pd_pages = pd_pages;
        vmm.pd_pool = @as([*]PageTable, @ptrCast(pd_pool_addr))[0..pd_pages];
        @memset(@as([*]u8, @ptrCast(pd_pool_addr))[0 .. pd_pages * PAGE_SIZE], 0);

        // Allocate PT pool (256 tables = 1MB for larger kernels)
        var pt_pool_addr: [*]align(4096) u8 = undefined;
        const pt_pages = 256;
        switch (boot_services.allocatePages(
            .allocate_any_pages,
            .loader_data,
            pt_pages,
            &pt_pool_addr,
        )) {
            .success => {},
            else => {
                vmm.cleanup();
                return error.AllocationFailed;
            },
        }
        vmm.allocations.pt_pool_addr = pt_pool_addr;
        vmm.allocations.pt_pages = pt_pages;
        vmm.pt_pool = @as([*]PageTable, @ptrCast(pt_pool_addr))[0..pt_pages];
        @memset(@as([*]u8, @ptrCast(pt_pool_addr))[0 .. pt_pages * PAGE_SIZE], 0);

        serial.print("[VMM] Initialized with {} PDPT, {} PD, {} PT entries\n", .{ pdpt_pages, pd_pages, pt_pages }) catch {};

        return vmm;
    }

    // Cleanup all allocations
    pub fn cleanup(self: *VirtualMemoryManager) void {
        if (self.allocations.pt_pool_addr) |addr| {
            _ = self.boot_services.freePages(addr, self.allocations.pt_pages);
        }
        if (self.allocations.pd_pool_addr) |addr| {
            _ = self.boot_services.freePages(addr, self.allocations.pd_pages);
        }
        if (self.allocations.pdpt_pool_addr) |addr| {
            _ = self.boot_services.freePages(addr, self.allocations.pdpt_pages);
        }
        if (self.allocations.pml4_addr) |addr| {
            _ = self.boot_services.freePages(addr, self.allocations.pml4_pages);
        }
    }

    // Map a 4KB page
    pub fn mapPage(self: *VirtualMemoryManager, virt_addr: u64, phys_addr: u64, flags: u64) !void {
        // Ensure addresses are page-aligned
        if ((virt_addr & 0xFFF) != 0 or (phys_addr & 0xFFF) != 0) {
            return error.UnalignedAddress;
        }

        // Extract page table indices
        const pml4_idx = (virt_addr >> 39) & 0x1FF;
        const pdpt_idx = (virt_addr >> 30) & 0x1FF;
        const pd_idx = (virt_addr >> 21) & 0x1FF;
        const pt_idx = (virt_addr >> 12) & 0x1FF;

        // Get or create PDPT
        if (self.pml4.entries[pml4_idx] == 0) {
            if (self.next_pdpt >= self.pdpt_pool.len) {
                return error.OutOfPageTables;
            }
            const pdpt = &self.pdpt_pool[self.next_pdpt];
            self.next_pdpt += 1;
            self.pml4.entries[pml4_idx] = @intFromPtr(pdpt) | PAGE_PRESENT | PAGE_WRITE;
        }

        const pdpt = @as(*PageTable, @ptrFromInt(self.pml4.entries[pml4_idx] & ~@as(u64, 0xFFF)));

        // Get or create PD
        if (pdpt.entries[pdpt_idx] == 0) {
            if (self.next_pd >= self.pd_pool.len) {
                return error.OutOfPageTables;
            }
            const pd = &self.pd_pool[self.next_pd];
            self.next_pd += 1;
            pdpt.entries[pdpt_idx] = @intFromPtr(pd) | PAGE_PRESENT | PAGE_WRITE;
        }

        const pd = @as(*PageTable, @ptrFromInt(pdpt.entries[pdpt_idx] & ~@as(u64, 0xFFF)));

        // Get or create PT
        if (pd.entries[pd_idx] == 0) {
            if (self.next_pt >= self.pt_pool.len) {
                return error.OutOfPageTables;
            }
            const pt = &self.pt_pool[self.next_pt];
            self.next_pt += 1;
            pd.entries[pd_idx] = @intFromPtr(pt) | PAGE_PRESENT | PAGE_WRITE;
        }

        const pt = @as(*PageTable, @ptrFromInt(pd.entries[pd_idx] & ~@as(u64, 0xFFF)));

        // Map the page
        pt.entries[pt_idx] = phys_addr | flags;
    }

    // Map a memory range
    pub fn mapRange(self: *VirtualMemoryManager, virt_start: u64, phys_start: u64, size: u64, flags: u64) !void {
        const pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
        var i: u64 = 0;
        while (i < pages) : (i += 1) {
            try self.mapPage(virt_start + i * PAGE_SIZE, phys_start + i * PAGE_SIZE, flags);
        }
    }

    // Identity map a range (virtual = physical)
    pub fn identityMap(self: *VirtualMemoryManager, start: u64, size: u64, flags: u64) !void {
        try self.mapRange(start, start, size, flags);
    }

    // Set up identity mapping for critical regions
    pub fn setupIdentityMapping(self: *VirtualMemoryManager) !void {
        // Identity map first 256MB for UEFI/firmware (reduce from 1GB to save page tables)
        serial.print("[VMM] Identity mapping first 256MB for UEFI\n", .{}) catch {};
        try self.identityMap(0, 0x10000000, PAGE_PRESENT | PAGE_WRITE);

        // Identity map APIC region
        const apic_base: u64 = 0xFEE00000;
        serial.print("[VMM] Identity mapping APIC at 0x{X}\n", .{apic_base}) catch {};
        try self.identityMap(apic_base, PAGE_SIZE, PAGE_PRESENT | PAGE_WRITE | PAGE_CACHE_DISABLE);

        // Identity map I/O APIC region
        const io_apic_base: u64 = 0xFEC00000;
        serial.print("[VMM] Identity mapping I/O APIC at 0x{X}\n", .{io_apic_base}) catch {};
        try self.identityMap(io_apic_base, PAGE_SIZE, PAGE_PRESENT | PAGE_WRITE | PAGE_CACHE_DISABLE);
    }

    // Enable paging with new page tables
    pub fn enablePaging(self: *VirtualMemoryManager) void {
        // Disable interrupts
        asm volatile ("cli");

        // Load new page tables
        const cr3_value = @intFromPtr(self.pml4);
        asm volatile ("movq %[cr3], %%cr3"
            :
            : [cr3] "r" (cr3_value),
            : "memory"
        );

        // Enable required features
        var cr4: u64 = undefined;
        asm volatile ("movq %%cr4, %[cr4]"
            : [cr4] "=r" (cr4),
        );
        cr4 |= (1 << 5); // PAE
        cr4 |= (1 << 7); // PGE
        asm volatile ("movq %[cr4], %%cr4"
            :
            : [cr4] "r" (cr4),
            : "memory"
        );

        serial.print("[VMM] Paging enabled with PML4 at 0x{X}\n", .{cr3_value}) catch {};
    }
};

// Helper to calculate required page flags based on segment flags
// Enforces W^X principle per Intel x86-64 security guidelines
pub fn segmentFlagsToPageFlags(segment_flags: u32) u64 {
    var flags: u64 = PAGE_PRESENT;

    // Check ELF segment flags
    const PF_W = 0x2; // Write
    const PF_X = 0x1; // Execute

    if (segment_flags & PF_W != 0) {
        flags |= PAGE_WRITE;
    }

    // Set NX bit for data pages (non-executable pages)
    // This enforces W^X: if a page is writable, it cannot be executable
    if ((segment_flags & PF_X) == 0) {
        flags |= PAGE_NX; // Mark data pages as non-executable
    }

    // Additional validation: ensure W^X compliance
    const has_write = (segment_flags & PF_W) != 0;
    const has_exec = (segment_flags & PF_X) != 0;

    // This should never happen due to earlier validation, but double-check
    if (has_write and has_exec) {
        @panic("FATAL: W^X violation in page flag conversion - should have been caught earlier");
    }

    return flags;
}
