// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const serial = @import("../drivers/serial.zig");
const boot_protocol = @import("shared");

// Import extracted modules
const kernel_types = @import("kernel_types.zig");
const memory = @import("memory.zig");
const entropy_collector = @import("entropy/collector.zig");
const entropy_crypto = @import("entropy/crypto.zig");
const kaslr_config = @import("kaslr/config.zig");
const kaslr_generator = @import("kaslr/generator.zig");
const elf_loader = @import("elf/loader.zig");
const vmm = @import("vmm.zig");
const page_table_calculator = @import("page_table_calculator.zig");
const page_table_allocator = @import("page_table_allocator.zig");

// Re-export types for public API compatibility
pub const KernelInfo = kernel_types.KernelInfo;
pub const MemoryMap = kernel_types.MemoryMap;
pub const KASLRError = kernel_types.KASLRError;

// Main kernel loading function
pub fn loadKernel(handle: uefi.Handle, boot_services: *uefi.tables.BootServices, allocator: std.mem.Allocator) !KernelInfo {
    _ = allocator; // Maintain API compatibility

    serial.print("[kernel_loader] Starting kernel load process\n", .{}) catch {};

    // Test SipHash implementation before using it for KASLR
    if (!entropy_crypto.testSipHash24()) {
        serial.print("[UEFI] FATAL: SipHash-2-4 self-test failed\r\n", .{}) catch {};
        return error.CryptoSelfTestFailed;
    }

    // Load RNG retry configuration from UEFI variables
    // Access runtime services through the system table
    entropy_collector.loadRngRetryConfig(uefi.system_table.runtime_services);

    // Initialize memory tracking
    var allocated_memory = memory.AllocatedMemory{};
    errdefer memory.cleanupAllocations(boot_services, &allocated_memory);

    // Collect entropy sources for the kernel
    var entropy_sources = [_]u64{
        entropy_collector.readTsc(),
        entropy_collector.getAcpiEntropy(),
        entropy_collector.getPitEntropy(),
        entropy_collector.getMemoryLayoutEntropy(boot_services),
        entropy_collector.readCmosTime(),
        entropy_collector.readPerfCounters(),
    };

    // Check if hardware RNG is available
    const hardware_rng_used = entropy_collector.cpuHasRdseed() or entropy_collector.cpuHasRdrand();

    // Collect boot entropy for the kernel
    entropy_crypto.collectBootEntropy(&entropy_sources, hardware_rng_used);
    const boot_entropy = entropy_crypto.getBootEntropyData().*;

    // Try loading with KASLR - with proper error handling
    const kaslr_offset = kaslr_generator.getRandomOffset(boot_services) catch |err| {
        switch (err) {
            error.InsufficientMemoryForKASLR, error.KASLRRequiredButFailed => {
                // KASLR enforcement errors - cannot continue
                serial.print("[UEFI] FATAL: KASLR security requirement failed\r\n", .{}) catch {};
                serial.print("[UEFI] Boot halted for security reasons\r\n", .{}) catch {};
                return err;
            },
            else => return err,
        }
    };

    // Load the kernel with KASLR and PIE support
    const kernel_info = try elf_loader.loadKernelInternal(
        handle,
        boot_services,
        kaslr_offset,
    );

    // Store boot entropy in the already-allocated boot info
    if (kernel_info.boot_info) |boot_info| {
        @memcpy(&boot_info.boot_entropy, &boot_entropy.entropy_bytes);
        boot_info.entropy_quality = boot_entropy.quality;
        boot_info.entropy_sources = boot_entropy.sources_used;
        boot_info.has_hardware_rng = boot_entropy.has_hardware_rng;
    }

    // Note: PIE relocations and hash verification are handled inside elf_loader.loadKernelInternal

    serial.print("[kernel_loader] Kernel loaded successfully at 0x{x}\n", .{kernel_info.base_address}) catch {};
    return kernel_info;
}

// Find ACPI RSDP
fn findRSDP() u64 {
    // Search for RSDP in UEFI configuration table
    const config_table = @import("../utils/uefi_globals.zig").system_table.configuration_table;
    const acpi_20_guid align(8) = uefi.tables.ConfigurationTable.acpi_20_table_guid;
    const acpi_10_guid align(8) = uefi.tables.ConfigurationTable.acpi_10_table_guid;

    // SECURITY: Add bounds validation to prevent out-of-bounds reads
    // Limit configuration table entries to a reasonable maximum
    const max_tables = 128; // Reasonable limit for UEFI configuration tables
    const table_count = @min(@import("../utils/uefi_globals.zig").system_table.number_of_table_entries, max_tables);

    for (0..table_count) |i| {
        const entry = &config_table[i];

        if (std.meta.eql(entry.vendor_guid, acpi_20_guid)) {
            return @intFromPtr(entry.vendor_table);
        } else if (std.meta.eql(entry.vendor_guid, acpi_10_guid)) {
            return @intFromPtr(entry.vendor_table);
        }
    }

    return 0; // Not found
}

// PIE support: Enable allocate_any_pages mode for better compatibility
const ENABLE_PIE_ALLOCATION = false;

// Jump to the loaded kernel
pub fn jumpToKernel(kernel_info: KernelInfo, memory_map: MemoryMap) noreturn {
    // Use pre-allocated boot info
    const boot_info = kernel_info.boot_info orelse {
        serial.print("[UEFI] FATAL: Boot info not allocated!\r\n", .{}) catch {};
        while (true) {
            asm volatile ("hlt");
        }
    };

    // Prepare kernel boot information structure
    boot_info.* = boot_protocol.BootInfo{
        .magic = boot_protocol.BOOT_MAGIC,
        .memory_map_addr = @intFromPtr(memory_map.descriptors),
        .memory_map_size = memory_map.size,
        .memory_map_descriptor_size = memory_map.descriptor_size,
        .memory_map_descriptor_version = memory_map.descriptor_version,
        ._padding = 0,
        .kernel_base = kernel_info.base_address,
        .kernel_size = kernel_info.size,
        .rsdp_addr = findRSDP(),
        .kernel_hash = kernel_info.hash,
        .hash_valid = kernel_info.hash_verified,
        .pie_mode = ENABLE_PIE_ALLOCATION and !kernel_info.use_identity_mapping,
        ._padding2 = [_]u8{0} ** 6,
        // Enhanced entropy fields (already set in loadKernel)
        .boot_entropy = boot_info.boot_entropy,
        .entropy_quality = boot_info.entropy_quality,
        .entropy_sources = boot_info.entropy_sources,
        .has_hardware_rng = boot_info.has_hardware_rng,
        ._padding3 = [_]u8{0} ** 5,
        .page_table_info = boot_info.page_table_info, // Will be set by coordinator
        .mp_info = boot_info.mp_info, // Will be set by coordinator
        .reserved = [_]u64{0} ** 13,
    };

    // Debug: Print boot info address and magic
    serial.print("[UEFI] Boot info at 0x{X}, magic=0x{X}\r\n", .{ @intFromPtr(boot_info), boot_info.magic }) catch {};
    serial.print("[UEFI] Memory map addr: 0x{X}, size: 0x{X}, descriptor_size: 0x{X}\r\n", .{ boot_info.memory_map_addr, boot_info.memory_map_size, boot_info.memory_map_descriptor_size }) catch {};
    serial.print("[UEFI] PIE mode: {}, use_identity_mapping: {}\r\n", .{ boot_info.pie_mode, kernel_info.use_identity_mapping }) catch {};

    // Enable paging if using PIE mode with VMM
    if (kernel_info.vmm_instance) |virtual_mm| {
        serial.print("[UEFI] PIE: Enabling paging before kernel jump\r\n", .{}) catch {};

        // Map the boot info structure
        const boot_info_addr = @intFromPtr(boot_info);
        const boot_info_pages_to_map = (@sizeOf(boot_protocol.BootInfo) + 4095) / 4096;

        serial.print("[UEFI] PIE: Mapping boot info at 0x{X} ({} pages)\r\n", .{ boot_info_addr, boot_info_pages_to_map }) catch {};

        // Make a mutable copy of the VMM for the final mapping
        var vmm_copy = virtual_mm;
        vmm_copy.mapRange(boot_info_addr, boot_info_addr, boot_info_pages_to_map * 4096, vmm.PAGE_PRESENT | vmm.PAGE_WRITE) catch |err| {
            serial.print("[UEFI] FATAL: Failed to map boot info structure: {}\r\n", .{err}) catch {};
            while (true) {
                asm volatile ("hlt");
            }
        };

        // Enable paging with new page tables
        vmm_copy.enablePaging();
        serial.print("[UEFI] PIE: Paging enabled, jumping to kernel\r\n", .{}) catch {};
    }

    // Final debug print before jump
    serial.print("[UEFI] Boot info at 0x{X}, jumping to kernel at 0x{X}\r\n", .{ @intFromPtr(boot_info), kernel_info.entry_point }) catch {};

    // Ensure boot info pointer will be in RDI
    const boot_info_ptr = @intFromPtr(boot_info);

    // Ensure writes are committed
    asm volatile ("wbinvd");
    asm volatile ("mfence");

    // Disable interrupts for the jump
    asm volatile ("cli");

    // Jump to kernel with explicit register setup
    asm volatile (
        \\mov %[boot_info], %%rdi
        \\jmp *%[entry]
        :
        : [boot_info] "r" (boot_info_ptr),
          [entry] "r" (kernel_info.entry_point),
        : "rdi"
    );

    unreachable;
}
