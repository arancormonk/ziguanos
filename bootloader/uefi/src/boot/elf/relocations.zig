// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2024 Ziguanos. All rights reserved.

// ELF Relocations Module
//
// This module handles ELF relocation processing for Position Independent
// Executables (PIE) and KASLR support. It includes comprehensive bounds
// checking and security validation for all relocation types.

const std = @import("std");
const kernel_types = @import("../kernel_types.zig");
const memory = @import("../memory.zig");
const serial = @import("../../drivers/serial.zig");

/// Apply ELF relocations for KASLR with segment mapping support
pub fn applyElfRelocationsWithMapping(
    elf_buffer: [*]u8,
    elf_header: *const kernel_types.Elf64Header,
    kaslr_offset: u64,
    kernel_base: u64,
    kernel_size: u64,
    allocations: *const memory.AllocatedMemory,
) void {
    _ = kernel_base;
    _ = kernel_size;

    serial.print("[UEFI] PIE: Processing relocations with segment mappings\r\n", .{}) catch {};

    // For PIE mode, we need to process relocations based on physical addresses
    // since segments are not at their virtual addresses yet

    // First, find all rela sections
    const section_headers = @as([*]const kernel_types.Elf64SectionHeader, @ptrCast(@alignCast(elf_buffer + elf_header.e_shoff)));

    for (0..elf_header.e_shnum) |i| {
        const sh = &section_headers[i];
        if (sh.sh_type != kernel_types.SHT_RELA) continue;

        const relocations = @as([*]const kernel_types.Elf64Rela, @ptrCast(@alignCast(elf_buffer + sh.sh_offset)));
        const num_relocations = sh.sh_size / @sizeOf(kernel_types.Elf64Rela);

        serial.print("[UEFI] PIE: Processing {} relocations in section {}\r\n", .{ num_relocations, i }) catch {};

        for (0..num_relocations) |j| {
            const rela = &relocations[j];
            const reloc_type = kernel_types.ELF64_R_TYPE(rela.r_info);

            // Find which segment contains this relocation
            const target_vaddr = rela.r_offset + kaslr_offset;
            var physical_addr: ?u64 = null;

            for (0..allocations.segment_count) |k| {
                const seg = &allocations.segments[k];
                if (target_vaddr >= seg.virtual_addr and
                    target_vaddr < seg.virtual_addr + (seg.pages * 4096))
                {
                    // Found the segment - calculate physical address
                    const offset_in_segment = target_vaddr - seg.virtual_addr;
                    physical_addr = seg.physical_addr + offset_in_segment;
                    break;
                }
            }

            if (physical_addr == null) {
                serial.print("[UEFI] PIE: WARNING: Relocation at 0x{X} not in any segment\r\n", .{target_vaddr}) catch {};
                continue;
            }

            // Apply relocation at physical address
            switch (reloc_type) {
                kernel_types.R_X86_64_RELATIVE => {
                    const ptr = @as(*u64, @ptrFromInt(physical_addr.?));
                    ptr.* = kaslr_offset + @as(u64, @bitCast(rela.r_addend));
                },
                kernel_types.R_X86_64_64 => {
                    const ptr = @as(*u64, @ptrFromInt(physical_addr.?));
                    ptr.* += kaslr_offset;
                },
                else => {
                    serial.print("[UEFI] PIE: Unsupported relocation type {} at 0x{X}\r\n", .{ reloc_type, target_vaddr }) catch {};
                },
            }
        }
    }

    serial.print("[UEFI] PIE: Relocation processing completed\r\n", .{}) catch {};
}

/// Apply ELF relocations for KASLR - standard identity-mapped mode
pub fn applyElfRelocations(
    elf_buffer: [*]u8,
    elf_header: *const kernel_types.Elf64Header,
    kaslr_offset: u64,
    kernel_base: u64,
    kernel_size: u64,
) void {
    // Check for dynamic relocations (.rela.dyn section)
    const section_headers = @as([*]const kernel_types.Elf64SectionHeader, @ptrCast(@alignCast(elf_buffer + elf_header.e_shoff)));

    for (0..elf_header.e_shnum) |i| {
        const sh = &section_headers[i];
        if (sh.sh_type != kernel_types.SHT_RELA) continue;

        serial.print("[UEFI] Found relocation section {} at offset 0x{X}\r\n", .{ i, sh.sh_offset }) catch {};

        applySectionRelocations(sh, elf_buffer, kaslr_offset, kernel_base, kernel_size);
    }
}

/// Apply relocations from a single section
pub fn applySectionRelocations(
    sh: *const kernel_types.Elf64SectionHeader,
    elf_buffer: [*]u8,
    kaslr_offset: u64,
    kernel_base: u64,
    kernel_size: u64,
) void {
    const num_rela = sh.sh_size / @sizeOf(kernel_types.Elf64Rela);
    if (num_rela == 0) return;

    const rela_entries = @as([*]const kernel_types.Elf64Rela, @ptrCast(@alignCast(elf_buffer + sh.sh_offset)));

    serial.print("[UEFI] Processing {} relocations from section\r\n", .{num_rela}) catch {};

    for (0..num_rela) |j| {
        processRelocationSafe(&rela_entries[j], kaslr_offset, kernel_base, kernel_size) catch |err| {
            serial.print("[UEFI] Section relocation error: {} at offset 0x{X}\r\n", .{ err, rela_entries[j].r_offset }) catch {};
        };
    }
}

/// Enhanced relocation processing with comprehensive bounds checking
pub fn processRelocationSafe(
    rela: *const kernel_types.Elf64Rela,
    kaslr_offset: u64,
    kernel_base: u64,
    kernel_size: u64,
) !void {
    const reloc_type = kernel_types.ELF64_R_TYPE(rela.r_info);

    // SECURITY: Validate relocation offset is within kernel bounds
    if (rela.r_offset >= kernel_size) {
        serial.print("[UEFI] ERROR: Relocation offset 0x{X} exceeds kernel size 0x{X}\r\n", .{ rela.r_offset, kernel_size }) catch {};
        return error.RelocationOutOfBounds;
    }

    // SECURITY: Ensure relocation won't write past kernel bounds
    const reloc_size = getRelocationSize(reloc_type) catch {
        serial.print("[UEFI] ERROR: Unknown relocation type {} size\r\n", .{reloc_type}) catch {};
        return error.UnknownRelocationType;
    };

    if (rela.r_offset + reloc_size > kernel_size) {
        serial.print("[UEFI] ERROR: Relocation at 0x{X} would write past kernel end\r\n", .{rela.r_offset}) catch {};
        return error.RelocationWriteOutOfBounds;
    }

    // SECURITY: Validate alignment requirements
    const required_align = getRelocationAlignment(reloc_type);
    if (rela.r_offset & (required_align - 1) != 0) {
        serial.print("[UEFI] ERROR: Relocation at 0x{X} misaligned for type {}\r\n", .{ rela.r_offset, reloc_type }) catch {};
        return error.RelocationMisaligned;
    }

    const target_addr = kernel_base + rela.r_offset;

    switch (reloc_type) {
        kernel_types.R_X86_64_NONE => {
            // No operation needed
        },
        kernel_types.R_X86_64_RELATIVE => {
            // SECURITY: Validate addend doesn't cause overflow
            const new_value = std.math.add(u64, kernel_base, @as(u64, @bitCast(rela.r_addend))) catch {
                serial.print("[UEFI] ERROR: RELATIVE relocation addend overflow\r\n", .{}) catch {};
                return error.RelocationAddendOverflow;
            };

            // SECURITY: Ensure relocated address is within reasonable bounds
            // Allow 16MB slack for runtime allocations beyond kernel
            const max_addr = kernel_base + kernel_size + (16 << 20);
            if (new_value < kernel_base or new_value >= max_addr) {
                serial.print("[UEFI] ERROR: RELATIVE relocation target 0x{X} out of bounds\r\n", .{new_value}) catch {};
                return error.RelocationTargetOutOfBounds;
            }

            @as(*u64, @ptrFromInt(target_addr)).* = new_value;
        },
        kernel_types.R_X86_64_64 => {
            // SECURITY: Read current value safely
            const current = @as(*u64, @ptrFromInt(target_addr)).*;

            // SECURITY: Check for overflow when applying KASLR offset
            const new_value = std.math.add(u64, current, kaslr_offset) catch {
                serial.print("[UEFI] ERROR: R_X86_64_64 relocation overflow\r\n", .{}) catch {};
                return error.RelocationOverflow;
            };

            @as(*u64, @ptrFromInt(target_addr)).* = new_value;
        },
        kernel_types.R_X86_64_32 => {
            // SECURITY: Ensure value fits in unsigned 32-bit
            const current = @as(*u64, @ptrFromInt(target_addr)).*;
            const new_value = std.math.add(u64, current, kaslr_offset) catch {
                return error.Relocation32Overflow;
            };

            if (new_value > 0xFFFFFFFF) {
                serial.print("[UEFI] ERROR: R_X86_64_32 value 0x{X} exceeds 32-bit\r\n", .{new_value}) catch {};
                return error.Relocation32Overflow;
            }

            @as(*u32, @ptrFromInt(target_addr)).* = @truncate(new_value);
        },
        kernel_types.R_X86_64_32S => {
            // SECURITY: Ensure value fits in signed 32-bit
            const current = @as(*u64, @ptrFromInt(target_addr)).*;
            const new_value = std.math.add(u64, current, kaslr_offset) catch {
                return error.Relocation32SOverflow;
            };

            const signed_value = @as(i64, @bitCast(new_value));
            if (signed_value < -0x80000000 or signed_value > 0x7FFFFFFF) {
                serial.print("[UEFI] ERROR: R_X86_64_32S value 0x{X} out of signed 32-bit range\r\n", .{new_value}) catch {};
                return error.Relocation32SOverflow;
            }

            @as(*u32, @ptrFromInt(target_addr)).* = @truncate(new_value);
        },
        kernel_types.R_X86_64_PC32, kernel_types.R_X86_64_PLT32 => {
            // SECURITY: PC-relative relocations - validate target is reachable
            const current = @as(*u32, @ptrFromInt(target_addr)).*;
            const pc_offset = @as(i32, @bitCast(current));

            // Calculate absolute target address (PC + 4 + offset)
            const pc_addr = @as(i64, @intCast(target_addr + 4));
            const abs_target = std.math.add(i64, pc_addr, pc_offset) catch {
                serial.print("[UEFI] ERROR: PC32 target calculation overflow\r\n", .{}) catch {};
                return error.RelocationPCOverflow;
            };

            // SECURITY: Verify target is within kernel or reasonable range
            if (abs_target < 0) {
                serial.print("[UEFI] ERROR: PC32 target 0x{X} is negative\r\n", .{abs_target}) catch {};
                return error.RelocationPCNegative;
            }

            const abs_target_u64 = @as(u64, @intCast(abs_target));
            const max_pc_range = kernel_base + kernel_size + (16 << 20); // 16MB slack
            if (abs_target_u64 < kernel_base or abs_target_u64 >= max_pc_range) {
                // Log but don't fail - PC32 relocations might reference external symbols
                serial.print("[UEFI] WARNING: PC32 relocation target 0x{X} outside kernel range\r\n", .{abs_target_u64}) catch {};
            }
        },
        kernel_types.R_X86_64_16 => {
            // SECURITY: 16-bit relocation
            const current = @as(*u16, @ptrFromInt(target_addr)).*;
            const new_value = std.math.add(u16, current, @truncate(kaslr_offset)) catch {
                serial.print("[UEFI] ERROR: R_X86_64_16 overflow\r\n", .{}) catch {};
                return error.Relocation16Overflow;
            };

            @as(*u16, @ptrFromInt(target_addr)).* = new_value;
        },
        kernel_types.R_X86_64_PC16 => {
            // SECURITY: 16-bit PC-relative relocation
            const current = @as(*u16, @ptrFromInt(target_addr)).*;
            const pc_offset = @as(i16, @bitCast(current));

            // Calculate absolute target address (PC + 2 + offset)
            const pc_addr = @as(i64, @intCast(target_addr + 2));
            const abs_target = std.math.add(i64, pc_addr, pc_offset) catch {
                serial.print("[UEFI] ERROR: PC16 target calculation overflow\r\n", .{}) catch {};
                return error.RelocationPC16Overflow;
            };

            // SECURITY: Verify target is within kernel range
            if (abs_target < 0) {
                serial.print("[UEFI] ERROR: PC16 target 0x{X} is negative\r\n", .{abs_target}) catch {};
                return error.RelocationPC16Negative;
            }

            const abs_target_u64 = @as(u64, @intCast(abs_target));

            // Apply KASLR offset to the absolute target
            const new_abs_target = std.math.add(u64, abs_target_u64, kaslr_offset) catch {
                serial.print("[UEFI] ERROR: PC16 KASLR adjustment overflow\r\n", .{}) catch {};
                return error.RelocationPC16KASLROverflow;
            };

            // Calculate new PC-relative offset
            const new_pc_offset = @as(i64, @intCast(new_abs_target)) - @as(i64, @intCast(target_addr + 2));

            // SECURITY: Ensure the new offset fits in 16 bits
            if (new_pc_offset < -32768 or new_pc_offset > 32767) {
                serial.print("[UEFI] ERROR: PC16 offset 0x{X} out of 16-bit range\r\n", .{new_pc_offset}) catch {};
                return error.RelocationPC16OutOfRange;
            }

            @as(*u16, @ptrFromInt(target_addr)).* = @bitCast(@as(i16, @intCast(new_pc_offset)));
        },
        kernel_types.R_X86_64_8 => {
            // SECURITY: 8-bit relocation
            const current = @as(*u8, @ptrFromInt(target_addr)).*;
            const offset_u8 = @as(u8, @truncate(kaslr_offset));
            const new_value = std.math.add(u8, current, offset_u8) catch {
                serial.print("[UEFI] ERROR: R_X86_64_8 overflow\r\n", .{}) catch {};
                return error.Relocation8Overflow;
            };

            @as(*u8, @ptrFromInt(target_addr)).* = new_value;
        },
        kernel_types.R_X86_64_PC8 => {
            // SECURITY: 8-bit PC-relative relocation
            const current = @as(*u8, @ptrFromInt(target_addr)).*;
            const pc_offset = @as(i8, @bitCast(current));

            // Calculate absolute target address (PC + 1 + offset)
            const pc_addr = @as(i64, @intCast(target_addr + 1));
            const abs_target = std.math.add(i64, pc_addr, pc_offset) catch {
                serial.print("[UEFI] ERROR: PC8 target calculation overflow\r\n", .{}) catch {};
                return error.RelocationPC8Overflow;
            };

            // SECURITY: Verify target is within kernel range
            if (abs_target < 0) {
                serial.print("[UEFI] ERROR: PC8 target 0x{X} is negative\r\n", .{abs_target}) catch {};
                return error.RelocationPC8Negative;
            }

            const abs_target_u64 = @as(u64, @intCast(abs_target));

            // Apply KASLR offset to the absolute target
            const new_abs_target = std.math.add(u64, abs_target_u64, kaslr_offset) catch {
                serial.print("[UEFI] ERROR: PC8 KASLR adjustment overflow\r\n", .{}) catch {};
                return error.RelocationPC8KASLROverflow;
            };

            // Calculate new PC-relative offset
            const new_pc_offset = @as(i64, @intCast(new_abs_target)) - @as(i64, @intCast(target_addr + 1));

            // SECURITY: Ensure the new offset fits in 8 bits
            if (new_pc_offset < -128 or new_pc_offset > 127) {
                serial.print("[UEFI] ERROR: PC8 offset 0x{X} out of 8-bit range\r\n", .{new_pc_offset}) catch {};
                return error.RelocationPC8OutOfRange;
            }

            @as(*u8, @ptrFromInt(target_addr)).* = @bitCast(@as(i8, @intCast(new_pc_offset)));
        },
        kernel_types.R_X86_64_GOT32, kernel_types.R_X86_64_GOTPCREL => {
            // SECURITY: GOT relocations should not appear in static kernel
            serial.print("[UEFI] ERROR: GOT relocation type {} in kernel\r\n", .{reloc_type}) catch {};
            return error.UnexpectedGOTRelocation;
        },
        kernel_types.R_X86_64_COPY, kernel_types.R_X86_64_GLOB_DAT, kernel_types.R_X86_64_JUMP_SLOT => {
            // SECURITY: Dynamic linking relocations should not appear in kernel
            serial.print("[UEFI] ERROR: Dynamic relocation type {} in kernel\r\n", .{reloc_type}) catch {};
            return error.UnexpectedDynamicRelocation;
        },
        else => {
            // SECURITY: Unknown relocation type
            serial.print("[UEFI] ERROR: Unknown relocation type {}\r\n", .{reloc_type}) catch {};
            return error.UnsupportedRelocation;
        },
    }
}

/// Get size of relocation based on type
pub fn getRelocationSize(reloc_type: u32) !usize {
    return switch (reloc_type) {
        kernel_types.R_X86_64_NONE => 0,
        kernel_types.R_X86_64_64, kernel_types.R_X86_64_RELATIVE, kernel_types.R_X86_64_GLOB_DAT, kernel_types.R_X86_64_JUMP_SLOT => 8,
        kernel_types.R_X86_64_32, kernel_types.R_X86_64_32S, kernel_types.R_X86_64_PC32, kernel_types.R_X86_64_PLT32, kernel_types.R_X86_64_GOT32, kernel_types.R_X86_64_GOTPCREL => 4,
        kernel_types.R_X86_64_16, kernel_types.R_X86_64_PC16 => 2,
        kernel_types.R_X86_64_8, kernel_types.R_X86_64_PC8 => 1,
        kernel_types.R_X86_64_COPY => 0, // Size depends on symbol
        else => error.UnknownRelocationType,
    };
}

/// Get required alignment for relocation type
pub fn getRelocationAlignment(reloc_type: u32) usize {
    return switch (reloc_type) {
        kernel_types.R_X86_64_64, kernel_types.R_X86_64_RELATIVE, kernel_types.R_X86_64_GLOB_DAT, kernel_types.R_X86_64_JUMP_SLOT => 8,
        kernel_types.R_X86_64_32, kernel_types.R_X86_64_32S, kernel_types.R_X86_64_PC32, kernel_types.R_X86_64_PLT32, kernel_types.R_X86_64_GOT32, kernel_types.R_X86_64_GOTPCREL => 4,
        kernel_types.R_X86_64_16, kernel_types.R_X86_64_PC16 => 2,
        kernel_types.R_X86_64_8, kernel_types.R_X86_64_PC8, kernel_types.R_X86_64_NONE, kernel_types.R_X86_64_COPY => 1,
        else => 1,
    };
}
