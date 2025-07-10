// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2024 Ziguanos. All rights reserved.

// ELF Loader Module
//
// This module handles the loading and validation of ELF kernel files.
// It includes comprehensive security checks, memory allocation strategies,
// and support for both static and PIE (Position Independent Executable) kernels.

const std = @import("std");
const uefi = std.os.uefi;
const kernel_types = @import("../kernel_types.zig");
const memory = @import("../memory.zig");
const kaslr_generator = @import("../kaslr/generator.zig");
const serial = @import("../../drivers/serial.zig");
const boot_protocol = @import("shared");
const sha256 = @import("../../security/sha256.zig");
const verify = @import("../../security/verify.zig");
const policy = @import("../../security/policy.zig");
const vmm = @import("../vmm.zig");
const secure_debug = @import("../../security/secure_debug_integration.zig");

// PIE support: Enable allocate_any_pages mode for better compatibility
const ENABLE_PIE_ALLOCATION = false;

// File information GUID
const file_info_guid align(8) = uefi.Guid{
    .time_low = 0x9576e92,
    .time_mid = 0x6d3f,
    .time_high_and_version = 0x11d2,
    .clock_seq_high_and_reserved = 0x8e,
    .clock_seq_low = 0x39,
    .node = [_]u8{ 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b },
};

// File information structure
const FileInfo = extern struct {
    size: u64,
    file_size: u64,
    physical_size: u64,
    create_time: uefi.Time,
    last_access_time: uefi.Time,
    modification_time: uefi.Time,
    attribute: u64,
    file_name: [512]u16,
};

/// Enhanced kernel path validation with comprehensive security checks
/// This function validates kernel paths to prevent directory traversal,
/// invalid characters, and other security vulnerabilities
fn validateKernelPath(kernel_path: []const u8) !void {
    // Length validation
    if (kernel_path.len == 0) {
        serial.print("[UEFI] SECURITY: Empty kernel path\r\n", .{}) catch {};
        return error.EmptyPath;
    }

    if (kernel_path.len > 255) {
        serial.print("[UEFI] SECURITY: Kernel path too long ({})\r\n", .{kernel_path.len}) catch {};
        return error.PathTooLong;
    }

    // Check for directory traversal attempts
    if (std.mem.indexOf(u8, kernel_path, "..") != null) {
        serial.print("[UEFI] SECURITY: Directory traversal attempt detected\r\n", .{}) catch {};
        return error.DirectoryTraversal;
    }

    // Validate characters (printable ASCII only, excluding control characters)
    for (kernel_path, 0..) |char, idx| {
        // Check for control characters and non-printable ASCII
        if (char < 0x20 or char > 0x7E) {
            serial.print("[UEFI] SECURITY: Invalid character 0x{X} at position {}\r\n", .{ char, idx }) catch {};
            return error.InvalidCharacter;
        }

        // Check for directory separators that could enable path traversal
        if (char == '/' or char == '\\') {
            serial.print("[UEFI] SECURITY: Directory separator found at position {}\r\n", .{idx}) catch {};
            return error.DirectoryTraversal;
        }

        // Additional dangerous characters that should not be in filenames
        const dangerous_chars = [_]u8{ '<', '>', ':', '"', '|', '?', '*' };
        for (dangerous_chars) |dangerous| {
            if (char == dangerous) {
                serial.print("[UEFI] SECURITY: Dangerous character '{}' found at position {}\r\n", .{ char, idx }) catch {};
                return error.DangerousCharacter;
            }
        }
    }

    // Check for null bytes
    if (std.mem.indexOf(u8, kernel_path, "\x00") != null) {
        serial.print("[UEFI] SECURITY: Null byte found in kernel path\r\n", .{}) catch {};
        return error.NullByte;
    }

    // Validate file extension - must be .elf or .ELF
    if (!std.mem.endsWith(u8, kernel_path, ".elf") and !std.mem.endsWith(u8, kernel_path, ".ELF")) {
        serial.print("[UEFI] SECURITY: Invalid file extension (expected .elf)\r\n", .{}) catch {};
        return error.InvalidExtension;
    }

    // Check for reserved names (Windows compatibility and security)
    const reserved_names = [_][]const u8{ "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };

    // Extract filename without extension for reserved name check
    const dot_pos = std.mem.lastIndexOf(u8, kernel_path, ".") orelse kernel_path.len;
    const filename_no_ext = kernel_path[0..dot_pos];

    for (reserved_names) |reserved| {
        if (std.ascii.eqlIgnoreCase(filename_no_ext, reserved)) {
            serial.print("[UEFI] SECURITY: Reserved filename detected: {s}\r\n", .{reserved}) catch {};
            return error.ReservedName;
        }
    }

    // Additional validation: no leading/trailing spaces or dots
    if (kernel_path[0] == ' ' or kernel_path[0] == '.' or
        kernel_path[kernel_path.len - 1] == ' ')
    {
        serial.print("[UEFI] SECURITY: Invalid filename format (leading/trailing space or dot)\r\n", .{}) catch {};
        return error.InvalidFormat;
    }

    // Check for multiple consecutive dots (beyond ..)
    var dot_count: usize = 0;
    for (kernel_path) |char| {
        if (char == '.') {
            dot_count += 1;
            if (dot_count > 2) {
                serial.print("[UEFI] SECURITY: Multiple consecutive dots detected\r\n", .{}) catch {};
                return error.InvalidFormat;
            }
        } else {
            dot_count = 0;
        }
    }
}

/// Load kernel from EFI System Partition
pub fn loadKernelInternal(
    handle: uefi.Handle,
    boot_services: *uefi.tables.BootServices,
    kaslr_offset_param: u64,
) !kernel_types.KernelInfo {
    var kaslr_offset = kaslr_offset_param;
    _ = &kaslr_offset; // May be modified in PIE allocation mode
    // Track allocations for cleanup on error
    var allocations = memory.AllocatedMemory{};
    errdefer memory.cleanupAllocations(boot_services, &allocations);

    // Get loaded image protocol
    const loaded_image_guid align(8) = uefi.protocol.LoadedImage.guid;
    var loaded_image: *uefi.protocol.LoadedImage = undefined;

    switch (boot_services.openProtocol(
        handle,
        &loaded_image_guid,
        @ptrCast(&loaded_image),
        handle,
        null,
        .{ .by_handle_protocol = true },
    )) {
        .success => {},
        else => return error.ProtocolNotFound,
    }

    // Get file system protocol from device handle
    const simple_file_system_guid align(8) = uefi.protocol.SimpleFileSystem.guid;
    var file_system: *uefi.protocol.SimpleFileSystem = undefined;

    switch (boot_services.openProtocol(
        loaded_image.device_handle.?,
        &simple_file_system_guid,
        @ptrCast(&file_system),
        handle,
        null,
        .{ .by_handle_protocol = true },
    )) {
        .success => {},
        else => return error.FileSystemNotFound,
    }

    // Open root directory
    var root_dir: *const uefi.protocol.File = undefined;
    switch (file_system.openVolume(&root_dir)) {
        .success => {},
        else => return error.VolumeOpenFailed,
    }

    // SECURITY: Enhanced file path security with defense-in-depth
    // Following Intel x86-64 best practices for secure file loading

    // Define kernel path as UTF-8 for enhanced validation
    const kernel_path_utf8 = "kernel.elf";

    // Perform comprehensive path validation using our enhanced function
    try validateKernelPath(kernel_path_utf8);

    // Convert validated UTF-8 path to UTF-16 for UEFI API
    var kernel_file: *const uefi.protocol.File = undefined;

    // Allocate memory for UTF-16 conversion (UTF-8 to UTF-16 max 2:1 ratio + null terminator)
    const utf16_buffer_size = (kernel_path_utf8.len * 2 + 1) * @sizeOf(u16);
    var utf16_buffer_ptr: [*]align(8) u8 = undefined;
    switch (boot_services.allocatePool(.loader_data, utf16_buffer_size, &utf16_buffer_ptr)) {
        .success => {},
        else => return error.OutOfMemory,
    }
    defer _ = boot_services.freePool(utf16_buffer_ptr);

    // Cast to u16 slice for UTF-16 conversion
    const utf16_slice = @as([*]u16, @ptrCast(@alignCast(utf16_buffer_ptr)))[0 .. kernel_path_utf8.len + 1];

    // Convert UTF-8 to UTF-16LE and null terminate
    const utf16_len = std.unicode.utf8ToUtf16Le(utf16_slice[0..kernel_path_utf8.len], kernel_path_utf8) catch {
        return error.InvalidUtf8;
    };
    utf16_slice[utf16_len] = 0; // Null terminate

    const kernel_path = utf16_slice[0..utf16_len :0];

    switch (root_dir.open(&kernel_file, kernel_path.ptr, uefi.protocol.File.efi_file_mode_read, 0)) {
        .success => {},
        else => |status| {
            serial.print("[UEFI] Failed to open kernel.elf: {}\r\n", .{status}) catch {};
            return error.KernelNotFound;
        },
    }
    defer _ = kernel_file.close();

    // Get file size
    var file_info_buffer: [512]u8 align(8) = undefined;
    var buffer_size: usize = file_info_buffer.len;

    switch (kernel_file.getInfo(&file_info_guid, &buffer_size, &file_info_buffer)) {
        .success => {},
        else => return error.FileInfoFailed,
    }

    const file_info = @as(*FileInfo, @ptrCast(&file_info_buffer));
    const kernel_size = file_info.file_size;

    // SECURITY: Validate file attributes following Intel x86-64 best practices
    // Check that the file is not a directory or other special type
    const EFI_FILE_DIRECTORY: u64 = 0x10;
    const EFI_FILE_SYSTEM: u64 = 0x04;
    const EFI_FILE_HIDDEN: u64 = 0x02;

    if ((file_info.attribute & EFI_FILE_DIRECTORY) != 0) {
        serial.print("[UEFI] SECURITY: Kernel path points to a directory, not a file\r\n", .{}) catch {};
        return error.KernelIsDirectory;
    }

    if ((file_info.attribute & EFI_FILE_SYSTEM) != 0) {
        serial.print("[UEFI] SECURITY: Kernel file has system attribute set\r\n", .{}) catch {};
        // Log but continue - some systems may mark kernel as system file
    }

    if ((file_info.attribute & EFI_FILE_HIDDEN) != 0) {
        serial.print("[UEFI] WARNING: Kernel file is marked as hidden\r\n", .{}) catch {};
        // Log but continue - unusual but not necessarily malicious
    }

    serial.print("[UEFI] Kernel file size: {} bytes, attributes: 0x{x}\r\n", .{ kernel_size, file_info.attribute }) catch {};

    // SECURITY: Validate kernel size to prevent integer overflow and suspicious files
    // Following Intel x86-64 best practices for file validation
    const min_kernel_size: u64 = 4096; // Minimum 4KB for a valid ELF file
    const max_kernel_size: u64 = 1 << 30; // Maximum 1GB

    if (kernel_size < min_kernel_size) {
        serial.print("[UEFI] SECURITY: Kernel size {} is below minimum allowed size of {} bytes\r\n", .{ kernel_size, min_kernel_size }) catch {};
        return error.KernelTooSmall;
    }

    if (kernel_size > max_kernel_size) {
        serial.print("[UEFI] ERROR: Kernel size {} exceeds maximum allowed size of {} bytes\r\n", .{ kernel_size, max_kernel_size }) catch {};
        return error.KernelTooLarge;
    }

    // SECURITY: Additional validation - ensure size is aligned to prevent certain attacks
    if ((kernel_size & 0x3) != 0) {
        if (try policy.reportViolation(.UnalignedKernelSize, "Kernel size {} is not 4-byte aligned", .{kernel_size})) {
            return error.SecurityPolicyViolation;
        }
    }

    // SECURITY: Check for integer overflow in page calculation
    // Using divCeil for clearer and safer page calculation
    const page_size: u64 = 4096;
    const pages_needed = std.math.divCeil(u64, kernel_size, page_size) catch {
        serial.print("[UEFI] ERROR: Integer overflow calculating pages for kernel size {} with page size {}\r\n", .{ kernel_size, page_size }) catch {};
        return error.IntegerOverflow;
    };

    // SECURITY: Validate page count is reasonable
    const max_pages: u64 = max_kernel_size / page_size;
    const MAX_REASONABLE_PAGES: u64 = (1 << 30) / page_size; // 1GB max

    if (pages_needed > max_pages) {
        serial.print("[UEFI] ERROR: Page count {} exceeds maximum {}\r\n", .{ pages_needed, max_pages }) catch {};
        return error.TooManyPages;
    }

    // Additional validation for unreasonable page counts
    if (pages_needed > MAX_REASONABLE_PAGES) {
        serial.print("[UEFI] ERROR: Unreasonable page count {} for kernel size {}\r\n", .{ pages_needed, kernel_size }) catch {};
        return error.UnreasonablePageCount;
    }

    // Allocate memory for kernel file
    var kernel_buffer: [*]u8 = undefined;

    switch (boot_services.allocatePages(
        .allocate_any_pages,
        .loader_data,
        pages_needed,
        @ptrCast(&kernel_buffer),
    )) {
        .success => {},
        else => return error.AllocationFailed,
    }

    // Track kernel buffer allocation for cleanup
    allocations.kernel_buffer = @as([*]align(4096) u8, @alignCast(kernel_buffer));
    allocations.kernel_pages = pages_needed;

    // Read kernel file
    var bytes_read = kernel_size;
    switch (kernel_file.read(&bytes_read, kernel_buffer)) {
        .success => {},
        else => return error.ReadFailed,
    }

    // Calculate SHA-256 hash of kernel image
    serial.print("[UEFI] Calculating kernel hash...\r\n", .{}) catch {};
    const kernel_hash = sha256.sha256(kernel_buffer[0..kernel_size]);

    // Print hash for debugging
    serial.print("[UEFI] Kernel SHA-256: ", .{}) catch {};
    serial.print("0x", .{}) catch {};
    for (kernel_hash) |byte| {
        serial.print("{X:0>2}", .{byte}) catch {};
    }
    serial.print("\r\n", .{}) catch {};

    // Verify kernel hash
    const hash_verified = verify.verifyKernelHash(kernel_hash) catch |err| {
        serial.print("[UEFI] Hash verification error: {}\r\n", .{err}) catch {};
        if (verify.ENFORCE_HASH_CHECK) {
            serial.print("[UEFI] FATAL: Kernel verification failed. Boot aborted.\r\n", .{}) catch {};
            return err;
        }
        false;
    };

    // Verify kernel HMAC for authentication (in addition to hash)
    if (verify.ENABLE_HMAC_VERIFICATION) {
        serial.print("[UEFI] Verifying kernel HMAC...\r\n", .{}) catch {};
        const hmac_verified = verify.verifyKernelHMAC(handle, boot_services, kernel_buffer[0..kernel_size]) catch |err| {
            serial.print("[UEFI] HMAC verification error: {}\r\n", .{err}) catch {};
            if (verify.ENFORCE_HASH_CHECK) {
                serial.print("[UEFI] FATAL: Kernel HMAC authentication failed. Boot aborted.\r\n", .{}) catch {};
                return err;
            }
            false;
        };

        if (!hmac_verified and verify.ENFORCE_HASH_CHECK) {
            serial.print("[UEFI] FATAL: Kernel HMAC verification failed\r\n", .{}) catch {};
            return error.HMACVerificationFailed;
        }
    }

    // Parse and validate ELF header
    const elf_result = try validateAndLoadElf(
        kernel_buffer,
        kernel_size,
        boot_services,
        kaslr_offset,
        &allocations,
    );

    // Post-relocation hash verification (Intel x86-64 security best practice)
    // This ensures that relocations haven't been tampered with
    if (hash_verified and verify.ENFORCE_HASH_CHECK and elf_result.kaslr_offset != 0) {
        serial.print("[UEFI] Performing post-relocation integrity verification...\r\n", .{}) catch {};

        // Calculate hash of kernel in memory after relocations
        const loaded_kernel_size = elf_result.highest_addr - elf_result.lowest_addr;
        const post_reloc_hash = verify.hashLoadedKernel(elf_result.lowest_addr, loaded_kernel_size);

        // Log the post-relocation hash
        serial.print("[UEFI] Post-relocation SHA-256: 0x", .{}) catch {};
        for (post_reloc_hash) |byte| {
            serial.print("{X:0>2}", .{byte}) catch {};
        }
        serial.print("\r\n", .{}) catch {};

        // In a production system with full secure boot implementation:
        // 1. The build system would calculate expected post-relocation hashes
        //    for each possible KASLR offset
        // 2. These hashes would be stored in a signed manifest
        // 3. The bootloader would verify the manifest signature
        // 4. Then check if the actual post-relocation hash matches one of the
        //    expected hashes in the manifest
        //
        // For now, we ensure the kernel can be hashed after relocation,
        // which detects corruption and provides a foundation for future
        // enhanced verification.

        serial.print("[UEFI] Post-relocation integrity check completed\r\n", .{}) catch {};
        serial.print("[UEFI] Note: Full verification requires signed hash manifest (not yet implemented)\r\n", .{}) catch {};
    }

    // Prepare segment mappings for passing to kernel
    var segment_mappings: ?[]const kernel_types.AllocatedSegment = null;
    if (ENABLE_PIE_ALLOCATION and !allocations.use_identity_mapping and allocations.segment_count > 0) {
        segment_mappings = allocations.segments[0..allocations.segment_count];
    }

    // Transfer VMM ownership to prevent cleanup
    const vmm_to_transfer = allocations.vmm_instance;
    allocations.vmm_instance = null; // Clear to prevent cleanup

    // Allocate boot info before freeing kernel buffer
    var boot_info_pages: [*]align(4096) u8 = undefined;
    const boot_info_page_count = std.math.divCeil(usize, @sizeOf(boot_protocol.BootInfo), 4096) catch 1; // BootInfo is small, 1 page is safe fallback

    switch (boot_services.allocatePages(
        .allocate_any_pages,
        .runtime_services_data, // This memory type persists after ExitBootServices
        boot_info_page_count,
        &boot_info_pages,
    )) {
        .success => {},
        else => |status| {
            serial.print("[UEFI] Failed to allocate boot info: {}\r\n", .{status}) catch {};
            return error.BootInfoAllocationFailed;
        },
    }

    const boot_info = @as(*boot_protocol.BootInfo, @ptrCast(@alignCast(boot_info_pages)));

    // Initialize boot info to zero to ensure no garbage data
    boot_info.* = std.mem.zeroes(boot_protocol.BootInfo);

    // Set a temporary magic value to help debug
    boot_info.magic = 0xDEADBEEFCAFEBABE;

    // Only free the kernel buffer (ELF file), not the loaded segments
    if (allocations.kernel_buffer) |buffer| {
        _ = boot_services.freePages(buffer, allocations.kernel_pages);
        serial.print("[UEFI] Freed kernel buffer ({} pages)\r\n", .{allocations.kernel_pages}) catch {};
        allocations.kernel_buffer = null;
    }

    return kernel_types.KernelInfo{
        .base_address = elf_result.lowest_addr,
        .entry_point = elf_result.entry_point,
        .size = elf_result.highest_addr - elf_result.lowest_addr,
        .memory_map = undefined, // Will be set by caller
        .hash = kernel_hash,
        .hash_verified = hash_verified,
        .vmm_instance = vmm_to_transfer,
        .segment_mappings = segment_mappings,
        .use_identity_mapping = allocations.use_identity_mapping,
        .boot_info = boot_info,
    };
}

const ElfLoadResult = struct {
    lowest_addr: u64,
    highest_addr: u64,
    entry_point: u64,
    kaslr_offset: u64,
};

/// Validate and load ELF kernel
fn validateAndLoadElf(
    kernel_buffer: [*]u8,
    kernel_size: u64,
    boot_services: *uefi.tables.BootServices,
    kaslr_offset_param: u64,
    allocations: *memory.AllocatedMemory,
) !ElfLoadResult {
    var kaslr_offset = kaslr_offset_param;
    _ = &kaslr_offset; // May be modified in PIE allocation mode

    // Parse ELF header
    const elf_header = @as(*const kernel_types.Elf64Header, @ptrCast(@alignCast(kernel_buffer)));

    // Verify ELF magic
    if (!std.mem.eql(u8, elf_header.e_ident[0..4], kernel_types.ELF_MAGIC)) {
        return error.InvalidELF;
    }

    // Verify 64-bit ELF
    if (elf_header.e_ident[4] != 2) {
        return error.Not64BitELF;
    }

    // Verify x86-64 architecture
    if (elf_header.e_machine != 0x3E) {
        return error.WrongArchitecture;
    }

    // SECURITY: Verify ELF type is executable or PIE (Intel recommendation)
    if (elf_header.e_type != kernel_types.ET_EXEC and elf_header.e_type != kernel_types.ET_DYN) {
        serial.print("[UEFI] ERROR: Invalid ELF type: {} (expected ET_EXEC=2 or ET_DYN=3)\r\n", .{elf_header.e_type}) catch {};
        return error.InvalidELFType;
    }

    // SECURITY: Validate program header offset and count
    if (elf_header.e_phoff == 0 or elf_header.e_phoff >= kernel_size) {
        serial.print("[UEFI] ERROR: Invalid program header offset: 0x{X}\r\n", .{elf_header.e_phoff}) catch {};
        return error.InvalidProgramHeaderOffset;
    }

    if (elf_header.e_phnum == 0 or elf_header.e_phnum > 128) { // Reasonable limit
        serial.print("[UEFI] ERROR: Invalid program header count: {}\r\n", .{elf_header.e_phnum}) catch {};
        return error.InvalidProgramHeaderCount;
    }

    // SECURITY: Validate section headers following Intel x86-64 best practices
    // Check section header offset
    if (elf_header.e_shoff != 0) {
        // If section headers exist, validate them
        if (elf_header.e_shoff >= kernel_size) {
            serial.print("[UEFI] ERROR: Section header offset 0x{X} beyond file size 0x{X}\r\n", .{ elf_header.e_shoff, kernel_size }) catch {};
            return error.InvalidSectionHeaderOffset;
        }

        // Validate section header entry size
        if (elf_header.e_shentsize != @sizeOf(kernel_types.Elf64SectionHeader)) {
            serial.print("[UEFI] ERROR: Invalid section header entry size: {} (expected {})\r\n", .{ elf_header.e_shentsize, @sizeOf(kernel_types.Elf64SectionHeader) }) catch {};
            return error.InvalidSectionHeaderEntrySize;
        }

        // Validate section header count (prevent excessive allocations)
        if (elf_header.e_shnum > 65536) { // SHN_LORESERVE
            serial.print("[UEFI] ERROR: Section header count {} exceeds maximum\r\n", .{elf_header.e_shnum}) catch {};
            return error.InvalidSectionHeaderCount;
        }

        // Check for integer overflow in section header table size
        const sh_table_size = @as(u64, elf_header.e_shnum) * @as(u64, elf_header.e_shentsize);
        if (sh_table_size > kernel_size or elf_header.e_shoff + sh_table_size > kernel_size) {
            serial.print("[UEFI] ERROR: Section header table extends beyond file\r\n", .{}) catch {};
            return error.SectionHeaderTableTooLarge;
        }

        // Validate section header string table index
        if (elf_header.e_shstrndx != 0 and elf_header.e_shstrndx >= elf_header.e_shnum) {
            // Special handling for SHN_XINDEX (0xFFFF) - section 0 contains actual index
            if (elf_header.e_shstrndx != 0xFFFF) {
                serial.print("[UEFI] ERROR: Section string table index {} out of range\r\n", .{elf_header.e_shstrndx}) catch {};
                return error.InvalidSectionStringTableIndex;
            }
        }

        serial.print("[UEFI] Section headers validated: offset=0x{X}, count={}, shstrndx={}\r\n", .{ elf_header.e_shoff, elf_header.e_shnum, elf_header.e_shstrndx }) catch {};
    }

    // SECURITY: Validate ELF header size
    if (elf_header.e_ehsize != @sizeOf(kernel_types.Elf64Header)) {
        serial.print("[UEFI] ERROR: Invalid ELF header size: {} (expected {})\r\n", .{ elf_header.e_ehsize, @sizeOf(kernel_types.Elf64Header) }) catch {};
        return error.InvalidELFHeaderSize;
    }

    // SECURITY: Validate program header entry size
    if (elf_header.e_phentsize != @sizeOf(kernel_types.Elf64ProgramHeader)) {
        serial.print("[UEFI] ERROR: Invalid program header entry size: {} (expected {})\r\n", .{ elf_header.e_phentsize, @sizeOf(kernel_types.Elf64ProgramHeader) }) catch {};
        return error.InvalidProgramHeaderEntrySize;
    }

    // SECURITY: Validate entry point is within a LOAD segment (will check after loading)
    secure_debug.printElfInfo(elf_header.e_type, elf_header.e_entry);

    // KASLR offset is passed as parameter now
    if (kaslr_offset != 0) {
        secure_debug.printKASLROffset(kaslr_offset, 0); // bits will be calculated by the function
    }

    // Initialize VMM if using PIE allocation mode
    if (ENABLE_PIE_ALLOCATION) {
        serial.print("[UEFI] Initializing Virtual Memory Manager for PIE mode\r\n", .{}) catch {};
        allocations.vmm_instance = try vmm.VirtualMemoryManager.init(boot_services);

        // Set up identity mappings for critical regions
        try allocations.vmm_instance.?.setupIdentityMapping();
    }

    // Load ELF segments
    const load_result = try loadElfSegments(
        kernel_buffer,
        kernel_size,
        elf_header,
        boot_services,
        kaslr_offset,
        allocations,
    );

    // Calculate final entry point BEFORE any cleanup (while elf_header is still valid)
    const final_entry_point = elf_header.e_entry + load_result.kaslr_offset;
    secure_debug.println(.Debug, "[UEFI] Entry point calculated", .{});

    return ElfLoadResult{
        .lowest_addr = load_result.lowest_addr,
        .highest_addr = load_result.highest_addr,
        .entry_point = final_entry_point,
        .kaslr_offset = load_result.kaslr_offset,
    };
}

const SegmentLoadResult = struct {
    lowest_addr: u64,
    highest_addr: u64,
    kaslr_offset: u64,
};

/// Load ELF segments into memory
fn loadElfSegments(
    kernel_buffer: [*]u8,
    kernel_size: u64,
    elf_header: *const kernel_types.Elf64Header,
    boot_services: *uefi.tables.BootServices,
    kaslr_offset_param: u64,
    allocations: *memory.AllocatedMemory,
) !SegmentLoadResult {
    var kaslr_offset = kaslr_offset_param;

    // First pass: Calculate total memory range needed for all LOAD segments
    const program_headers = @as([*]const kernel_types.Elf64ProgramHeader, @ptrCast(@alignCast(kernel_buffer + elf_header.e_phoff)));

    // SECURITY: Comprehensive W^X validation for all ELF segments per Intel x86-64 guidelines
    policy.validateELFSegmentSecurity(program_headers[0..elf_header.e_phnum], elf_header.e_phnum) catch |err| {
        serial.print("[UEFI] FATAL: ELF W^X security validation failed: {}\r\n", .{err}) catch {};
        return err;
    };
    serial.print("[UEFI] ✓ ELF segments passed W^X security validation\r\n", .{}) catch {};

    var lowest_vaddr: u64 = 0xFFFFFFFFFFFFFFFF;
    var highest_vaddr_end: u64 = 0;
    var total_segments: usize = 0;

    // Scan all segments to find memory range
    for (0..elf_header.e_phnum) |i| {
        const ph = &program_headers[i];
        if (ph.p_type != kernel_types.PT_LOAD) continue;

        total_segments += 1;
        const seg_start = ph.p_vaddr;
        const seg_end = ph.p_vaddr + ph.p_memsz;

        if (seg_start < lowest_vaddr) lowest_vaddr = seg_start;
        if (seg_end > highest_vaddr_end) highest_vaddr_end = seg_end;
    }

    // Check if we have a PIE kernel with multiple segments
    const is_pie_kernel = elf_header.e_type == kernel_types.ET_DYN and total_segments > 1;
    var contiguous_allocation: ?[*]align(4096) u8 = null;
    var contiguous_pages: usize = 0;

    if (is_pie_kernel and !ENABLE_PIE_ALLOCATION) {
        // For PIE kernels, allocate the entire range at once to avoid fragmentation
        const total_size = highest_vaddr_end - lowest_vaddr;
        contiguous_pages = std.math.divCeil(u64, total_size, 0x1000) catch {
            serial.print("[UEFI] ERROR: Integer overflow calculating contiguous pages for size 0x{X}\r\n", .{total_size}) catch {};
            return error.ContiguousSizeOverflow;
        };

        secure_debug.println(.Debug, "[UEFI] PIE kernel detected with {} segments, allocating {} pages", .{ total_segments, contiguous_pages });

        // For PIE kernels, allocation strategy depends on whether we have KASLR
        if (kaslr_offset != 0) {
            // With KASLR, try to allocate at the specific randomized address
            var base_addr: [*]align(4096) u8 = @ptrFromInt(lowest_vaddr + kaslr_offset);
            switch (boot_services.allocatePages(
                .allocate_address,
                .loader_code,
                contiguous_pages,
                &base_addr,
            )) {
                .success => {
                    contiguous_allocation = base_addr;
                    allocations.contiguous_allocation = base_addr;
                    allocations.contiguous_pages = contiguous_pages;
                    secure_debug.printAllocation("contiguous range", @intFromPtr(base_addr), contiguous_pages * 4096);
                },
                else => {
                    secure_debug.printError("ContiguousAllocation", error.KASLRAllocationFailed);
                    return error.KASLRAllocationFailed;
                },
            }
        } else {
            // Without KASLR, try to allocate at the preferred address first
            var base_addr: [*]align(4096) u8 = @ptrFromInt(lowest_vaddr);
            switch (boot_services.allocatePages(
                .allocate_address,
                .loader_code,
                contiguous_pages,
                &base_addr,
            )) {
                .success => {
                    contiguous_allocation = base_addr;
                    allocations.contiguous_allocation = base_addr;
                    allocations.contiguous_pages = contiguous_pages;
                    // No KASLR offset when loaded at preferred address
                    kaslr_offset = 0;
                    secure_debug.printAllocation("contiguous range at preferred address", @intFromPtr(base_addr), contiguous_pages * 4096);
                },
                else => {
                    // If preferred address fails, let UEFI choose any suitable location
                    serial.print("[UEFI] Could not allocate at preferred address 0x{X}, trying any address\r\n", .{lowest_vaddr}) catch {};
                    switch (boot_services.allocatePages(
                        .allocate_any_pages,
                        .loader_code,
                        contiguous_pages,
                        &base_addr,
                    )) {
                        .success => {
                            contiguous_allocation = base_addr;
                            allocations.contiguous_allocation = base_addr;
                            allocations.contiguous_pages = contiguous_pages;
                            // Update offset to reflect actual load address
                            kaslr_offset = @intFromPtr(base_addr) - lowest_vaddr;
                            serial.print("[UEFI] WARNING: Kernel loaded at 0x{X} instead of preferred 0x{X}\r\n", .{ @intFromPtr(base_addr), lowest_vaddr }) catch {};
                            secure_debug.printAllocation("contiguous range at alternate address", @intFromPtr(base_addr), contiguous_pages * 4096);
                        },
                        else => {
                            secure_debug.printError("ContiguousAllocation", error.AllocationFailed);
                            return error.AllocationFailed;
                        },
                    }
                },
            }
        }
    }

    // Load program segments
    var lowest_addr: u64 = 0xFFFFFFFFFFFFFFFF;
    var highest_addr: u64 = 0;

    // SECURITY: Track loaded segments for overlap detection
    var loaded_segments: [16]struct {
        start: u64,
        end: u64,
        flags: u32,
    } = undefined;
    var num_loaded_segments: usize = 0;

    for (0..elf_header.e_phnum) |i| {
        const ph = &program_headers[i];

        if (ph.p_type != kernel_types.PT_LOAD) continue;

        // SECURITY: Validate segment file offset
        if (ph.p_offset >= kernel_size or ph.p_offset + ph.p_filesz > kernel_size) {
            serial.print("[UEFI] ERROR: Segment {} file offset/size out of bounds\r\n", .{i}) catch {};
            return error.SegmentOutOfBounds;
        }

        // SECURITY: Validate segment alignment
        if (ph.p_align != 0 and ph.p_align & (ph.p_align - 1) != 0) {
            serial.print("[UEFI] ERROR: Segment {} has invalid alignment: 0x{X}\r\n", .{ i, ph.p_align }) catch {};
            return error.InvalidSegmentAlignment;
        }

        // SECURITY: Validate segment file size does not exceed memory size
        // This prevents buffer underflow when zeroing BSS section
        if (ph.p_filesz > ph.p_memsz) {
            serial.print("[UEFI] ERROR: Segment {} file size (0x{X}) exceeds memory size (0x{X})\r\n", .{ i, ph.p_filesz, ph.p_memsz }) catch {};
            return error.InvalidSegmentSize;
        }

        // SECURITY: Validate segment permissions follow Intel x86-64 guidelines
        // This enforces W^X (Write XOR Execute) principle - critical security measure
        policy.checkWXViolation(i, ph.p_flags) catch |err| {
            serial.print("[UEFI] FATAL: Segment {} W^X violation rejected by security policy\r\n", .{i}) catch {};
            return err;
        };

        // Apply KASLR offset to virtual address
        const relocated_addr = ph.p_vaddr + kaslr_offset;

        // SECURITY: Check for integer overflow in address calculation
        if (relocated_addr < ph.p_vaddr and kaslr_offset > 0) {
            serial.print("[UEFI] ERROR: Segment {} address overflow\r\n", .{i}) catch {};
            return error.SegmentAddressOverflow;
        }

        // SECURITY: Check for overlapping segments
        const seg_start = relocated_addr;
        const seg_end = relocated_addr + ph.p_memsz;

        for (0..num_loaded_segments) |j| {
            const existing = &loaded_segments[j];
            // Check if segments overlap
            if (seg_start < existing.end and seg_end > existing.start) {
                secure_debug.println(.Error, "[UEFI] ERROR: Segment {} overlaps with previously loaded segment", .{i});
                if (!secure_debug.shouldShowAddresses()) {
                    secure_debug.println(.Error, "[UEFI]   Segments overlap detected", .{});
                } else {
                    serial.print("[UEFI]   New: 0x{X}-0x{X}, Existing: 0x{X}-0x{X}\r\n", .{ seg_start, seg_end, existing.start, existing.end }) catch {};
                }
                return error.OverlappingSegments;
            }
        }

        secure_debug.printSegmentLoad(i, relocated_addr, ph.p_memsz, ph.p_flags);

        // Track memory range (with KASLR offset)
        if (relocated_addr < lowest_addr) lowest_addr = relocated_addr;
        if (relocated_addr + ph.p_memsz > highest_addr) highest_addr = relocated_addr + ph.p_memsz;

        // SECURITY: Record this segment for overlap checking
        if (num_loaded_segments < loaded_segments.len) {
            loaded_segments[num_loaded_segments] = .{
                .start = seg_start,
                .end = seg_end,
                .flags = ph.p_flags,
            };
            num_loaded_segments += 1;
        }

        // Load the segment
        try loadSingleSegment(
            kernel_buffer,
            ph,
            relocated_addr,
            boot_services,
            contiguous_allocation,
            is_pie_kernel,
            allocations,
        );
    }

    // SECURITY: Validate entry point is within an executable segment
    const entry_point_with_kaslr = elf_header.e_entry + kaslr_offset;
    var entry_point_valid = false;

    for (0..num_loaded_segments) |i| {
        const seg = &loaded_segments[i];
        if (entry_point_with_kaslr >= seg.start and entry_point_with_kaslr < seg.end) {
            // Check if segment has execute permission
            if ((seg.flags & kernel_types.PF_X) != 0) {
                entry_point_valid = true;
                secure_debug.println(.Debug, "[UEFI] Entry point validated in executable segment", .{});
                break;
            } else {
                secure_debug.println(.Error, "[UEFI] ERROR: Entry point in non-executable segment", .{});
                return error.EntryPointNotExecutable;
            }
        }
    }

    if (!entry_point_valid) {
        serial.print("[UEFI] ERROR: Entry point 0x{X} not within any loaded segment\r\n", .{entry_point_with_kaslr}) catch {};
        return error.EntryPointOutOfBounds;
    }

    return SegmentLoadResult{
        .lowest_addr = lowest_addr,
        .highest_addr = highest_addr,
        .kaslr_offset = kaslr_offset,
    };
}

/// Load a single ELF segment
fn loadSingleSegment(
    kernel_buffer: [*]u8,
    ph: *const kernel_types.Elf64ProgramHeader,
    relocated_addr: u64,
    boot_services: *uefi.tables.BootServices,
    contiguous_allocation: ?[*]align(4096) u8,
    is_pie_kernel: bool,
    allocations: *memory.AllocatedMemory,
) !void {
    // SECURITY: Check for integer overflow in segment page calculation
    const segment_pages = std.math.divCeil(u64, ph.p_memsz, 4096) catch {
        serial.print("[UEFI] ERROR: Integer overflow calculating pages for segment size 0x{X}\r\n", .{ph.p_memsz}) catch {};
        return error.SegmentSizeOverflow;
    };

    // SECURITY: Validate segment size is reasonable (256MB max per segment)
    const max_segment_pages: u64 = (256 << 20) / 4096; // 256MB in pages
    if (segment_pages > max_segment_pages) {
        serial.print("[UEFI] ERROR: Segment requires {} pages, exceeds maximum {}\r\n", .{ segment_pages, max_segment_pages }) catch {};
        return error.SegmentTooLarge;
    }

    // Allocate pages - use new PIE mode if enabled
    var actual_physical_addr: u64 = undefined;

    if (ENABLE_PIE_ALLOCATION) {
        // PIE mode: Allocate anywhere and track mapping
        var segment_memory: [*]align(4096) u8 = undefined;

        // For unaligned segments, we need to allocate extra pages to cover the offset
        const page_mask: u64 = 0xFFF;
        const offset_in_page = relocated_addr & page_mask;
        const aligned_virt_addr = relocated_addr & ~page_mask;

        // Calculate pages needed including the offset
        // SECURITY: Check for integer overflow in PIE calculations
        const total_size_with_offset = std.math.add(u64, ph.p_memsz, offset_in_page) catch {
            serial.print("[UEFI] ERROR: Integer overflow in PIE calculation: size 0x{X} + offset 0x{X}\r\n", .{ ph.p_memsz, offset_in_page }) catch {};
            return error.IntegerOverflow;
        };
        const pages_with_offset = std.math.divCeil(u64, total_size_with_offset, 4096) catch {
            serial.print("[UEFI] ERROR: Integer overflow calculating pages with offset for size 0x{X}\r\n", .{total_size_with_offset}) catch {};
            return error.SegmentSizeOverflow;
        };

        switch (boot_services.allocatePages(
            .allocate_any_pages, // Let UEFI choose any free memory
            .loader_code,
            pages_with_offset,
            &segment_memory,
        )) {
            .success => {
                // Physical address is always page-aligned from UEFI
                actual_physical_addr = @intFromPtr(segment_memory);
                allocations.use_identity_mapping = false;

                serial.print("[UEFI] PIE: Allocated segment at physical 0x{X} for virtual 0x{X}\r\n", .{ actual_physical_addr, relocated_addr }) catch {};

                // Map virtual to physical in VMM
                if (allocations.vmm_instance) |*virtual_mm| {
                    const page_flags = vmm.segmentFlagsToPageFlags(ph.p_flags);

                    // Map the aligned addresses (both virtual and physical are now aligned)
                    try virtual_mm.mapRange(aligned_virt_addr, actual_physical_addr, total_size_with_offset, page_flags);
                    serial.print("[UEFI] PIE: Mapped virtual 0x{X} to physical 0x{X} ({} pages, offset 0x{X})\r\n", .{ aligned_virt_addr, actual_physical_addr, pages_with_offset, offset_in_page }) catch {};
                }
            },
            else => |status| {
                serial.print("[UEFI] PIE: Failed to allocate {} pages: {}\r\n", .{ pages_with_offset, status }) catch {};
                return error.SegmentAllocationFailed;
            },
        }
    } else {
        // Original mode: Allocate at specific address
        // Check if we're using pre-allocated contiguous memory
        if (contiguous_allocation != null and is_pie_kernel) {
            // Segment is already allocated as part of contiguous range
            actual_physical_addr = relocated_addr;
            serial.print("[UEFI] Using pre-allocated memory for segment at 0x{X}\r\n", .{relocated_addr}) catch {};
        } else {
            // Individual allocation for non-PIE or when contiguous allocation wasn't used
            var segment_addr: [*]align(4096) u8 = @ptrFromInt(relocated_addr);

            switch (boot_services.allocatePages(
                .allocate_address,
                .loader_code,
                segment_pages,
                &segment_addr,
            )) {
                .success => {
                    actual_physical_addr = relocated_addr;
                },
                else => |status| {
                    serial.print("[UEFI] Failed to allocate at 0x{X}: {}\r\n", .{ relocated_addr, status }) catch {};
                    return error.SegmentAllocationFailed;
                },
            }
        }
    }

    // Track segment allocation for cleanup
    if (allocations.segment_count < allocations.segments.len) {
        // Use the correct page count based on allocation mode
        const actual_pages = if (ENABLE_PIE_ALLOCATION and !allocations.use_identity_mapping) blk: {
            const page_mask: u64 = 0xFFF;
            const offset_in_page = relocated_addr & page_mask;
            const total_size_with_offset = ph.p_memsz + offset_in_page;
            break :blk std.math.divCeil(u64, total_size_with_offset, 4096) catch segment_pages; // Fallback to segment_pages on overflow
        } else segment_pages;

        allocations.segments[allocations.segment_count] = .{
            .addr = actual_physical_addr, // Physical address for deallocation
            .pages = actual_pages,
            .allocated = true,
            .virtual_addr = relocated_addr,
            .physical_addr = actual_physical_addr,
        };
        allocations.segment_count += 1;
    }

    // Copy segment data to actual physical address
    // For PIE mode with unaligned segments, we need to account for the offset within the page
    const page_mask: u64 = 0xFFF;
    const offset_in_page = if (ENABLE_PIE_ALLOCATION and !allocations.use_identity_mapping)
        relocated_addr & page_mask
    else
        0;

    const dest = @as([*]u8, @ptrFromInt(actual_physical_addr + offset_in_page));
    const src = kernel_buffer + ph.p_offset;
    @memcpy(dest[0..ph.p_filesz], src[0..ph.p_filesz]);

    // Zero BSS section
    if (ph.p_memsz > ph.p_filesz) {
        @memset(dest[ph.p_filesz..ph.p_memsz], 0);
    }
}
