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

// Reserved bit masks
pub const RESERVED_BITS_PML4: u64 = 0x0000_FF00_0000_0000;
pub const RESERVED_BITS_PDPT_1G: u64 = 0x0000_0000_3FFF_E000;
pub const RESERVED_BITS_PD_2M: u64 = 0x0000_0000_001F_E000;
pub const RESERVED_BITS_PT: u64 = 0x0;

// Address masks
pub const PHYS_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// Page permission combinations
pub const PAGE_KERNEL_CODE: u64 = PAGE_PRESENT | PAGE_GLOBAL;
pub const PAGE_KERNEL_DATA: u64 = PAGE_PRESENT | PAGE_WRITABLE | PAGE_NO_EXECUTE | PAGE_GLOBAL;
pub const PAGE_KERNEL_RODATA: u64 = PAGE_PRESENT | PAGE_NO_EXECUTE | PAGE_GLOBAL;
pub const PAGE_USER_CODE: u64 = PAGE_PRESENT | PAGE_USER;
pub const PAGE_USER_DATA: u64 = PAGE_PRESENT | PAGE_WRITABLE | PAGE_USER | PAGE_NO_EXECUTE;
pub const PAGE_GUARD: u64 = PAGE_NO_EXECUTE;

// Guard page size
pub const GUARD_PAGE_SIZE: u64 = PAGE_SIZE_4K;
