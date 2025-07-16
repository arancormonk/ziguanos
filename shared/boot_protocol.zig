// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Shared boot protocol between UEFI bootloader and kernel
// This file defines the interface between bootloader and kernel

const std = @import("std");

// Boot info magic number
pub const BOOT_MAGIC = 0x5A49475541524E53; // "ZIGUANOS" in hex

// UEFI Memory Types (subset used by kernel)
pub const MemoryType = enum(u32) {
    Reserved = 0,
    LoaderCode = 1,
    LoaderData = 2,
    BootServicesCode = 3,
    BootServicesData = 4,
    RuntimeServicesCode = 5,
    RuntimeServicesData = 6,
    Conventional = 7,
    Unusable = 8,
    AcpiReclaim = 9,
    AcpiNvs = 10,
    MemoryMappedIo = 11,
    MemoryMappedIoPortSpace = 12,
    PalCode = 13,
    PersistentMemory = 14,
};

// UEFI Memory Descriptor (must match UEFI spec exactly)
pub const MemoryDescriptor = extern struct {
    type: MemoryType,
    pad: u32, // Padding for 8-byte alignment
    physical_start: u64,
    virtual_start: u64,
    number_of_pages: u64,
    attribute: u64,
};

// SHA-256 hash size
pub const SHA256_SIZE = 32;

// Page table information passed from bootloader to kernel
pub const PageTableInfo = extern struct {
    // Pre-allocated page table addresses (physical)
    pml4_phys_addr: u64, // PML4 table (always 1)
    pdpt_phys_addr: u64, // PDPT table (always 1)
    pd_table_base: u64, // Base address of PD table array
    pd_table_count: u32, // Number of PD tables allocated
    pt_table_base: u64, // Base address of PT table array (for kernel fine-grain)
    pt_table_count: u32, // Number of PT tables allocated

    // Memory mapping information
    highest_mapped_addr: u64, // Highest physical address that will be mapped
    total_pages_allocated: u32, // Total 4KB pages allocated for all tables
    _padding: u32, // Alignment padding
};

// Boot information passed from bootloader to kernel
pub const BootInfo = extern struct {
    magic: u64, // Magic number for validation
    memory_map_addr: u64, // Physical address of memory map
    memory_map_size: u64, // Total size of memory map
    memory_map_descriptor_size: u64, // Size of each descriptor
    memory_map_descriptor_version: u32, // UEFI descriptor version
    _padding: u32, // Padding for alignment
    kernel_base: u64, // Where kernel was loaded
    kernel_size: u64, // Size of loaded kernel
    rsdp_addr: u64, // ACPI RSDP address (0 if not found)

    // Security fields
    kernel_hash: [SHA256_SIZE]u8, // SHA-256 hash of kernel image
    hash_valid: bool, // Whether hash was verified
    pie_mode: bool, // Whether segments were loaded with allocate_any_pages
    _padding2: [6]u8, // Padding for alignment

    // Enhanced entropy fields for boot-time security
    boot_entropy: [32]u8, // 256 bits of boot-time entropy from UEFI
    entropy_quality: u8, // Entropy quality assessment (0-100)
    entropy_sources: u8, // Number of entropy sources used
    has_hardware_rng: bool, // Whether hardware RNG was available
    _padding3: [5]u8, // Padding for alignment

    // Page table information from bootloader
    page_table_info: PageTableInfo,

    // Reserved for future use
    reserved: [21]u64, // Reduced from 24 to accommodate page table info
};
