// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");

// Page table entry flags
pub const PAGE_PRESENT: u64 = 1 << 0;
pub const PAGE_WRITABLE: u64 = 1 << 1;
pub const PAGE_USER: u64 = 1 << 2;
pub const PAGE_WRITE_THROUGH: u64 = 1 << 3;
pub const PAGE_CACHE_DISABLE: u64 = 1 << 4;
pub const PAGE_ACCESSED: u64 = 1 << 5;
pub const PAGE_DIRTY: u64 = 1 << 6;
pub const PAGE_HUGE: u64 = 1 << 7;
pub const PAGE_GLOBAL: u64 = 1 << 8;
pub const PAGE_NO_EXECUTE: u64 = 1 << 63;

// Page sizes
pub const PAGE_SIZE_4K: u64 = 0x1000;
pub const PAGE_SIZE_2M: u64 = 0x200000;
pub const PAGE_SIZE_1G: u64 = 0x40000000;

// Reserved bit masks - Intel SDM 4.5
// Note: These depend on MAXPHYADDR from CPUID
// For 48-bit physical addresses (common case):
// - Bits 51:MAXPHYADDR must be 0 in all entries
// - For PML4E/PDPTE/PDE: bits 62:52, 11:9 (for 4KB aligned entries)
// - For 1GB pages: bits 29:13 must be 0 in PDPTE
// - For 2MB pages: bits 20:13 must be 0 in PDE
pub const RESERVED_BITS_MASK_HIGH: u64 = 0x7FF0_0000_0000_0000; // Bits 62:52
pub const RESERVED_BITS_PML4: u64 = RESERVED_BITS_MASK_HIGH;
pub const RESERVED_BITS_PDPT: u64 = RESERVED_BITS_MASK_HIGH;
pub const RESERVED_BITS_PDPT_1G: u64 = RESERVED_BITS_MASK_HIGH | 0x3FFF_E000; // Also bits 29:13
pub const RESERVED_BITS_PD: u64 = RESERVED_BITS_MASK_HIGH;
pub const RESERVED_BITS_PD_2M: u64 = RESERVED_BITS_MASK_HIGH | 0x1F_E000; // Also bits 20:13
pub const RESERVED_BITS_PT: u64 = RESERVED_BITS_MASK_HIGH;

// Address masks - we support up to 52 physical address bits (max for x86-64)
// The actual mask should be based on CPUID MAXPHYADDR, but we use the max here
// Individual page table entry handlers should apply the appropriate mask
pub const PHYS_ADDR_MASK_4K: u64 = 0x000F_FFFF_FFFF_F000; // Bits 51:12 for 4KB pages
pub const PHYS_ADDR_MASK_2M: u64 = 0x000F_FFFF_FFE0_0000; // Bits 51:21 for 2MB pages
pub const PHYS_ADDR_MASK_1G: u64 = 0x000F_FFFC_0000_0000; // Bits 51:30 for 1GB pages

// Legacy compatibility
pub const PHYS_ADDR_MASK: u64 = PHYS_ADDR_MASK_4K;

// Page permission combinations
pub const PAGE_KERNEL_CODE: u64 = PAGE_PRESENT | PAGE_GLOBAL;
pub const PAGE_KERNEL_DATA: u64 = PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE | PAGE_GLOBAL;
pub const PAGE_KERNEL_RODATA: u64 = PAGE_PRESENT | PAGE_NO_EXECUTE | PAGE_GLOBAL;
pub const PAGE_USER_CODE: u64 = PAGE_PRESENT | PAGE_USER;
pub const PAGE_USER_DATA: u64 = PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER | PAGE_NO_EXECUTE;
pub const PAGE_GUARD: u64 = PAGE_NO_EXECUTE;

// Guard page size
pub const GUARD_PAGE_SIZE: u64 = PAGE_SIZE_4K;
