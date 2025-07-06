// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// This file provides integration helpers for migrating existing debug prints
// to the new secure debug system. It includes wrapper functions that maintain
// the same interface while adding security sanitization.

const std = @import("std");
const debug_sanitizer = @import("debug_sanitizer.zig");
const serial = @import("../drivers/serial.zig");

// Re-export commonly used types and functions
pub const DebugLevel = debug_sanitizer.DebugLevel;
pub const print = debug_sanitizer.print;
pub const println = debug_sanitizer.println;
pub const printKernelLoad = debug_sanitizer.printKernelLoad;
pub const printKASLROffset = debug_sanitizer.printKASLROffset;
pub const printEntropy = debug_sanitizer.printEntropy;
pub const printMemoryMap = debug_sanitizer.printMemoryMap;
pub const printHashVerification = debug_sanitizer.printHashVerification;
pub const printSecureBootStatus = debug_sanitizer.printSecureBootStatus;
pub const printError = debug_sanitizer.printError;
pub const printStackTrace = debug_sanitizer.printStackTrace;

// Initialize the debug system
pub fn init() void {
    debug_sanitizer.init();
}

// Additional wrapper functions for common patterns

pub fn printElfInfo(elf_type: u16, entry_point: u64) void {
    if (debug_sanitizer.debug_sanitizer.sanitize_addresses) {
        println(.Info, "[UEFI] ELF type: {}", .{elf_type});
    } else {
        println(.Info, "[UEFI] ELF type: {}, entry point: 0x{X}", .{ elf_type, entry_point });
    }
}

pub fn printSegmentLoad(segment_num: usize, addr: u64, size: u64, flags: u32) void {
    if (debug_sanitizer.debug_sanitizer.sanitize_addresses) {
        println(.Debug, "[UEFI] Loading segment {} (size: 0x{X}, flags: 0x{X})", .{ segment_num, size, flags });
    } else {
        println(.Debug, "[UEFI] Loading segment {} at 0x{X} (size: 0x{X}, flags: 0x{X})", .{ segment_num, addr, size, flags });
    }
}

pub fn printAllocation(comptime what: []const u8, addr: u64, size: u64) void {
    if (debug_sanitizer.debug_sanitizer.sanitize_addresses) {
        if (size < 1024 * 1024) {
            println(.Debug, "[UEFI] Allocated {s} ({} KB)", .{ what, size / 1024 });
        } else {
            println(.Debug, "[UEFI] Allocated {s} ({} MB)", .{ what, size / (1024 * 1024) });
        }
    } else {
        println(.Debug, "[UEFI] Allocated {s} at 0x{X} ({} bytes)", .{ what, addr, size });
    }
}

pub fn printMemoryRegion(start: u64, end: u64, size_mb: u64) void {
    if (debug_sanitizer.debug_sanitizer.sanitize_addresses) {
        println(.Debug, "[UEFI] Memory region: {} MB", .{size_mb});
    } else {
        println(.Debug, "[UEFI] Memory region: 0x{X}-0x{X} ({} MB)", .{ start, end, size_mb });
    }
}

pub fn printBootInfo(boot_info_addr: u64, magic: u64) void {
    if (debug_sanitizer.debug_sanitizer.sanitize_addresses) {
        println(.Info, "[UEFI] Boot info prepared, magic=0x{X}", .{magic});
    } else {
        println(.Info, "[UEFI] Boot info at 0x{X}, magic=0x{X}", .{ boot_info_addr, magic });
    }
}

pub fn printJumpToKernel(entry_point: u64) void {
    if (debug_sanitizer.debug_sanitizer.sanitize_addresses) {
        println(.Info, "[UEFI] Jumping to kernel", .{});
    } else {
        println(.Info, "[UEFI] Jumping to kernel at 0x{X}", .{entry_point});
    }
}

pub fn printVmmMapping(comptime what: []const u8, addr: u64) void {
    if (debug_sanitizer.debug_sanitizer.sanitize_addresses) {
        println(.Debug, "[VMM] Identity mapping {s}", .{what});
    } else {
        println(.Debug, "[VMM] Identity mapping {s} at 0x{X}", .{ what, addr });
    }
}

pub fn printPagingEnabled(cr3: u64) void {
    if (debug_sanitizer.debug_sanitizer.sanitize_addresses) {
        println(.Info, "[VMM] Paging enabled", .{});
    } else {
        println(.Info, "[VMM] Paging enabled with PML4 at 0x{X}", .{cr3});
    }
}

pub fn printRelocationWarning(addr: u64, reloc_type: u32) void {
    if (debug_sanitizer.debug_sanitizer.sanitize_addresses) {
        println(.Warning, "[UEFI] PIE: Unsupported relocation type {}", .{reloc_type});
    } else {
        println(.Warning, "[UEFI] PIE: Unsupported relocation type {} at 0x{X}", .{ reloc_type, addr });
    }
}

// Entropy quality reporting (safe to show)
pub fn printEntropyQuality(sources_used: u32, estimated_bits: f64) void {
    println(.Info, "[UEFI] KASLR: Entropy quality - {} sources, ~{d:.1} bits estimated entropy", .{ sources_used, estimated_bits });
}

// Memory statistics (safe to show sizes)
pub fn printMemoryStats(total_mb: u64) void {
    println(.Debug, "[UEFI] Total conventional memory: {} MB", .{total_mb});
}

// Helper to check if we should show addresses
pub fn shouldShowAddresses() bool {
    return !debug_sanitizer.debug_sanitizer.sanitize_addresses;
}
