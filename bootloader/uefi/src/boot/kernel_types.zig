// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

/// Shared data structures and constants for kernel loading
const std = @import("std");
const uefi = std.os.uefi;
const boot_protocol = @import("shared");
const vmm = @import("vmm.zig");

// KASLR security error for when enforcement is enabled
pub const KASLRError = error{
    InsufficientMemoryForKASLR,
    KASLRRequiredButFailed,
};

/// Per-segment KASLR info
pub const SegmentKASLR = struct {
    base_offset: u64, // Base KASLR offset for the kernel
    segment_offsets: [32]u64 = [_]u64{0} ** 32, // Additional per-segment offsets
    segment_count: usize = 0,
    section_randomization_enabled: bool = false,
};

/// Boot entropy data to pass to kernel for enhanced security
pub const BootEntropyData = struct {
    entropy_bytes: [32]u8 = [_]u8{0} ** 32, // 256 bits of entropy
    quality: u8 = 0, // 0-100 quality score
    sources_used: u8 = 0, // Number of entropy sources
    has_hardware_rng: bool = false, // Whether hardware RNG was available
    collected: bool = false, // Whether entropy has been collected
};

/// Memory map descriptor information
pub const MemoryMap = struct {
    descriptors: [*]uefi.tables.MemoryDescriptor,
    size: usize,
    descriptor_size: usize,
    descriptor_version: u32,
};

/// Allocated segment information for PIE support
pub const AllocatedSegment = struct {
    addr: u64 = 0,
    pages: u64 = 0,
    allocated: bool = false,
    // For PIE support: track virtual-to-physical mapping
    virtual_addr: u64 = 0,
    physical_addr: u64 = 0,
    // Additional fields for kernel loading
    kaslr_offset: u64 = 0,
};

/// Allocated memory tracking for cleanup
pub const AllocatedMemory = struct {
    address: u64,
    size: u64,
    pages: usize,
    boot_services_type: uefi.tables.MemoryType,
    needs_cleanup: bool = true,
};

/// Main kernel information structure
pub const KernelInfo = struct {
    base_address: u64,
    entry_point: u64,
    size: usize,
    memory_map: MemoryMap,
    hash: [boot_protocol.SHA256_SIZE]u8,
    hash_verified: bool,
    // PIE support: VMM instance and segment mappings
    vmm_instance: ?vmm.VirtualMemoryManager = null,
    segment_mappings: ?[]const AllocatedSegment = null,
    use_identity_mapping: bool = true,
    // Pre-allocated boot info
    boot_info: ?*boot_protocol.BootInfo = null,
};

// ELF64 Header structure
pub const Elf64Header = extern struct {
    e_ident: [16]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

// ELF64 Program Header
pub const Elf64ProgramHeader = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

// ELF64 Section Header
pub const Elf64SectionHeader = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

// ELF64 Relocation with addend
pub const Elf64Rela = extern struct {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,
};

// ELF64 Dynamic entry
pub const Elf64Dyn = extern struct {
    d_tag: i64,
    d_un: extern union {
        d_val: u64,
        d_ptr: u64,
    },
};

// EFI File Info structure and GUID
pub const FileInfo = extern struct {
    size: u64,
    file_size: u64,
    physical_size: u64,
    create_time: uefi.Time,
    last_access_time: uefi.Time,
    modification_time: uefi.Time,
    attribute: u64,
    file_name: [1]u16, // Variable length, null-terminated
};

// ELF types - Intel recommends only accepting these for kernel loading
pub const ET_NONE = 0;
pub const ET_REL = 1;
pub const ET_EXEC = 2; // Executable file
pub const ET_DYN = 3; // Shared object file (PIE executables)
pub const ET_CORE = 4;

// Program header types
pub const PT_LOAD = 1;
pub const PT_DYNAMIC = 2;
pub const PT_INTERP = 3;
pub const PT_NOTE = 4;
pub const PT_SHLIB = 5;
pub const PT_PHDR = 6;

// Program header flags - Intel x86-64 ABI
pub const PF_X = 0x1; // Execute
pub const PF_W = 0x2; // Write
pub const PF_R = 0x4; // Read

// Dynamic table entries
pub const DT_NULL = 0;
pub const DT_RELA = 7;
pub const DT_RELASZ = 8;
pub const DT_RELAENT = 9;

// Section header types
pub const SHT_RELA = 4;

// ELF magic number
pub const ELF_MAGIC = "\x7fELF";

// x86-64 relocation types
pub const R_X86_64_NONE = 0;
pub const R_X86_64_64 = 1;
pub const R_X86_64_PC32 = 2;
pub const R_X86_64_GOT32 = 3;
pub const R_X86_64_PLT32 = 4;
pub const R_X86_64_COPY = 5;
pub const R_X86_64_GLOB_DAT = 6;
pub const R_X86_64_JUMP_SLOT = 7;
pub const R_X86_64_RELATIVE = 8;
pub const R_X86_64_GOTPCREL = 9;
pub const R_X86_64_32 = 10;
pub const R_X86_64_32S = 11;
pub const R_X86_64_16 = 12;
pub const R_X86_64_PC16 = 13;
pub const R_X86_64_8 = 14;
pub const R_X86_64_PC8 = 15;

/// Extract symbol index from relocation info
pub fn ELF64_R_SYM(i: u64) u32 {
    return @as(u32, @truncate(i >> 32));
}

/// Extract relocation type from relocation info
pub fn ELF64_R_TYPE(i: u64) u32 {
    return @as(u32, @truncate(i));
}
