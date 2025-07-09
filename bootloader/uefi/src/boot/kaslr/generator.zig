// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2024 Ziguanos. All rights reserved.

// KASLR Offset Generation Module
//
// This module contains the core KASLR offset generation logic, including
// alignment selection, entropy calculation, and segment randomization.

const std = @import("std");
const uefi = std.os.uefi;
const config = @import("config.zig");
const kernel_types = @import("../kernel_types.zig");
const collector = @import("../entropy/collector.zig");
const crypto = @import("../entropy/crypto.zig");
const serial = @import("../../drivers/serial.zig");
const variable_cache = @import("../../security/variable_cache.zig");
const rng = @import("../rng.zig");
const secure_debug = @import("../../security/secure_debug_integration.zig");

// KASLR alignment constants
pub const KASLR_ALIGNMENT_ULTRA_FINE: u64 = 0x1000; // 4KB page granularity for maximum entropy
pub const KASLR_ALIGNMENT_FINE: u64 = 0x10000; // 64KB for high entropy
pub const KASLR_ALIGNMENT_NORMAL: u64 = 0x200000; // 2MB for TLB efficiency (default)
pub const KASLR_ALIGNMENT_COARSE: u64 = 0x1000000; // 16MB for huge TLB

/// Helper function to calculate entropy bits from number of positions
pub fn calculateEntropyBits(num_positions: u64) u32 {
    if (num_positions <= 1) return 0;

    var bits: u32 = 0;
    var n = num_positions;
    while (n > 1) : (n >>= 1) {
        bits += 1;
    }
    return bits;
}

/// Select KASLR alignment based on available memory - Enhanced for higher entropy
pub fn selectKASLRAlignment(available_range: u64) u64 {
    // Check for user preference via UEFI variable
    const runtime_services = @import("../../utils/uefi_globals.zig").system_table.runtime_services;
    var alignment_pref: u8 = 0; // 0=auto, 1=ultra_fine, 2=fine, 3=normal, 4=coarse
    var data_size: usize = @sizeOf(u8);
    var attributes: u32 = undefined;

    const var_name = [_:0]u16{ 'K', 'A', 'S', 'L', 'R', 'A', 'l', 'i', 'g', 'n', 0 };

    const status = runtime_services.getVariable(
        @constCast(&var_name),
        @constCast(&config.kaslr_guid),
        &attributes,
        &data_size,
        @ptrCast(&alignment_pref),
    );

    // If user has set a preference, use it
    if (status == .success) {
        switch (alignment_pref) {
            1 => {
                serial.print("[UEFI] KASLR: Using ultra-fine alignment (4KB) per user preference\r\n", .{}) catch {};
                return KASLR_ALIGNMENT_ULTRA_FINE;
            },
            2 => {
                serial.print("[UEFI] KASLR: Using fine alignment (64KB) per user preference\r\n", .{}) catch {};
                return KASLR_ALIGNMENT_FINE;
            },
            3 => {
                serial.print("[UEFI] KASLR: Using normal alignment (2MB) per user preference\r\n", .{}) catch {};
                return KASLR_ALIGNMENT_NORMAL;
            },
            4 => {
                serial.print("[UEFI] KASLR: Using coarse alignment (16MB) per user preference\r\n", .{}) catch {};
                return KASLR_ALIGNMENT_COARSE;
            },
            else => {}, // Fall through to auto selection
        }
    }

    // Enhanced auto-selection to achieve 12+ bits of entropy per Intel guidelines
    // Calculate potential entropy for each alignment option
    const ultra_fine_entropy = calculateEntropyBits(available_range / KASLR_ALIGNMENT_ULTRA_FINE);
    const fine_entropy = calculateEntropyBits(available_range / KASLR_ALIGNMENT_FINE);
    const normal_entropy = calculateEntropyBits(available_range / KASLR_ALIGNMENT_NORMAL);

    // Select finest alignment that achieves recommended entropy while considering performance
    if (available_range >= 0x100000000) { // >= 4GB range
        // With 4GB+ range, even 2MB alignment gives 11+ bits of entropy
        // Use ultra-fine for maximum security on large systems
        if (ultra_fine_entropy >= config.KASLR_OPTIMAL_ENTROPY_BITS) {
            secure_debug.println(.Debug, "[UEFI] KASLR: Auto-selected ultra-fine alignment (4KB) for optimal entropy ({} bits)", .{ultra_fine_entropy});
            return KASLR_ALIGNMENT_ULTRA_FINE;
        } else {
            secure_debug.println(.Debug, "[UEFI] KASLR: Auto-selected fine alignment (64KB) for high entropy ({} bits)", .{fine_entropy});
            return KASLR_ALIGNMENT_FINE;
        }
    } else if (available_range >= 0x40000000) { // >= 1GB range
        // With 1GB range, need finer alignment to achieve 12+ bits
        if (fine_entropy >= config.KASLR_RECOMMENDED_ENTROPY_BITS) {
            serial.print("[UEFI] KASLR: Auto-selected fine alignment (64KB) for recommended entropy ({} bits)\r\n", .{fine_entropy}) catch {};
            return KASLR_ALIGNMENT_FINE;
        } else {
            // If even fine alignment doesn't give enough entropy, use ultra-fine
            serial.print("[UEFI] KASLR: Auto-selected ultra-fine alignment (4KB) to achieve {} bits entropy\r\n", .{ultra_fine_entropy}) catch {};
            return KASLR_ALIGNMENT_ULTRA_FINE;
        }
    } else if (available_range >= 0x10000000) { // >= 256MB range
        // For smaller memory, prioritize achieving minimum recommended entropy
        if (normal_entropy >= config.KASLR_RECOMMENDED_ENTROPY_BITS) {
            serial.print("[UEFI] KASLR: Auto-selected normal alignment (2MB) with {} bits entropy\r\n", .{normal_entropy}) catch {};
            return KASLR_ALIGNMENT_NORMAL;
        } else if (fine_entropy >= config.KASLR_RECOMMENDED_ENTROPY_BITS) {
            serial.print("[UEFI] KASLR: Auto-selected fine alignment (64KB) to achieve {} bits entropy\r\n", .{fine_entropy}) catch {};
            return KASLR_ALIGNMENT_FINE;
        } else {
            // Use ultra-fine to maximize entropy on constrained systems
            serial.print("[UEFI] KASLR: Auto-selected ultra-fine alignment (4KB) for maximum entropy ({} bits)\r\n", .{ultra_fine_entropy}) catch {};
            return KASLR_ALIGNMENT_ULTRA_FINE;
        }
    } else {
        // For very small memory (<256MB), always use ultra-fine alignment
        serial.print("[UEFI] KASLR: Auto-selected ultra-fine alignment (4KB) for constrained memory ({} bits entropy)\r\n", .{ultra_fine_entropy}) catch {};
        return KASLR_ALIGNMENT_ULTRA_FINE;
    }
}

/// Generate per-segment randomization offsets for section-level KASLR
pub fn generateSegmentOffsets(num_segments: usize, available_range: u64, hardware_rng: bool) !kernel_types.SegmentKASLR {
    var segment_kaslr = kernel_types.SegmentKASLR{
        .base_offset = 0,
        .segment_count = num_segments,
        .section_randomization_enabled = config.ENABLE_SECTION_KASLR and num_segments > 1,
    };

    if (!segment_kaslr.section_randomization_enabled) {
        return segment_kaslr;
    }

    serial.print("[UEFI] Section-level KASLR: Generating offsets for {} segments\r\n", .{num_segments}) catch {};

    // Calculate available space for section randomization
    const guard_space = config.SECTION_KASLR_GUARD_SIZE * (num_segments - 1);
    if (available_range <= guard_space) {
        serial.print("[UEFI] Section-level KASLR: Insufficient space for guard pages\r\n", .{}) catch {};
        segment_kaslr.section_randomization_enabled = false;
        return segment_kaslr;
    }

    const randomization_range = available_range - guard_space;
    const per_segment_range = randomization_range / num_segments;

    // Use fine-grained alignment for section randomization
    const section_alignment = KASLR_ALIGNMENT_ULTRA_FINE; // 4KB for maximum entropy
    const positions_per_segment = per_segment_range / section_alignment;
    const section_entropy_bits = calculateEntropyBits(positions_per_segment);

    serial.print("[UEFI] Section KASLR: {} bits entropy per section ({} positions)\r\n", .{ section_entropy_bits, positions_per_segment }) catch {};

    // Generate random offset for each segment
    for (0..num_segments) |i| {
        if (i == 0) {
            // First segment uses base offset
            segment_kaslr.segment_offsets[i] = 0;
        } else {
            // Generate random offset within the segment's range
            var random_value: u64 = undefined;

            if (hardware_rng) {
                // Try hardware RNG first
                if (collector.tryRdseed()) |seed| {
                    random_value = seed;
                } else if (collector.tryRdrand()) |rand| {
                    random_value = rand;
                } else {
                    random_value = collector.readTsc();
                }
            } else {
                // Use mixed entropy sources
                const entropy_sources = [_]u64{
                    collector.readTsc(),
                    collector.readTsc() >> 16,
                    @as(u64, @intCast(i)) * 0xDEADBEEF, // Segment-specific salt
                    collector.readPerfCounters(),
                };
                random_value = try crypto.mixEntropySources(&entropy_sources);
            }

            // Calculate offset within segment's allocated range
            const segment_base = i * (randomization_range / num_segments);
            const offset_in_range = (random_value % positions_per_segment) * section_alignment;
            segment_kaslr.segment_offsets[i] = segment_base + offset_in_range;

            if (secure_debug.shouldShowAddresses()) {
                serial.print("[UEFI] Section KASLR: Segment {} offset: 0x{X}\r\n", .{ i, segment_kaslr.segment_offsets[i] }) catch {};
            } else {
                serial.print("[UEFI] Section KASLR: Segment {} offset applied\r\n", .{i}) catch {};
            }
        }
    }

    // Calculate total entropy from section randomization
    const total_section_combinations = std.math.pow(u64, positions_per_segment, num_segments - 1);
    const total_section_entropy = calculateEntropyBits(total_section_combinations);

    serial.print("[UEFI] Section KASLR: Total section entropy: ~{} bits\r\n", .{total_section_entropy}) catch {};

    return segment_kaslr;
}

/// Check if KASLR enforcement is enabled (fail if KASLR cannot be applied)
pub fn isKASLREnforcementEnabled() bool {
    // Access runtime services through system table
    const runtime_services = @import("../../utils/uefi_globals.zig").system_table.runtime_services;
    const policy = @import("../../security/policy.zig");

    // Initialize security policy if not already done
    policy.init(runtime_services);

    // In development mode, never enforce KASLR (allow boot to continue even if KASLR fails)
    if (policy.getSecurityLevel() == .Development) {
        serial.print("[UEFI] KASLR enforcement disabled in Development mode\r\n", .{}) catch {};
        return false;
    }

    // Initialize cache if not already done
    if (!variable_cache.isInitialized()) {
        variable_cache.init(runtime_services) catch {
            // If cache init fails, use compile-time default for non-development modes
            if (config.ENFORCE_KASLR_ON_FAILURE) {
                serial.print("[UEFI] KASLR enforcement enabled by default (cache init failed)\r\n", .{}) catch {};
            }
            return config.ENFORCE_KASLR_ON_FAILURE;
        };
    }

    // Get KASLR configuration from cache
    const kaslr_config = variable_cache.getKASLRConfig();

    if (kaslr_config.enforce) |enforce| {
        if (enforce) {
            serial.print("[UEFI] KASLR enforcement enabled by UEFI variable (cached)\r\n", .{}) catch {};
            return true;
        } else {
            serial.print("[UEFI] KASLR enforcement disabled by UEFI variable (cached)\r\n", .{}) catch {};
            return false;
        }
    }

    // Return compile-time default if variable not found
    if (config.ENFORCE_KASLR_ON_FAILURE) {
        serial.print("[UEFI] KASLR enforcement enabled by default (Intel security best practice)\r\n", .{}) catch {};
    }
    return config.ENFORCE_KASLR_ON_FAILURE;
}

/// Check if KASLR is enabled at runtime
pub fn isKASLREnabled(boot_services: *uefi.tables.BootServices) bool {
    _ = boot_services; // Will be used for command line parsing in future

    // Access runtime services through system table
    const runtime_services = @import("../../utils/uefi_globals.zig").system_table.runtime_services;

    // Initialize cache if not already done
    if (!variable_cache.isInitialized()) {
        serial.print("[UEFI] KASLR: Variable cache not initialized, attempting init\r\n", .{}) catch {};
        variable_cache.init(runtime_services) catch |err| {
            // If cache init fails, default to enabled for security
            serial.print("[UEFI] KASLR: Variable cache init failed: {}, defaulting to enabled\r\n", .{err}) catch {};
            return true;
        };
    }

    // Check KASLR enabled status from cache
    const kaslr_config = variable_cache.getKASLRConfig();
    serial.print("[UEFI] KASLR config from cache: enabled={?}\r\n", .{kaslr_config.enabled}) catch {};

    // Check if KASLR is explicitly configured
    if (kaslr_config.enabled) |enabled| {
        if (!enabled) {
            serial.print("[UEFI] KASLR disabled by configuration (cached value: false)\r\n", .{}) catch {};
            return false;
        } else {
            serial.print("[UEFI] KASLR enabled by configuration (cached value: true)\r\n", .{}) catch {};
            return true;
        }
    }

    // Default to enabled if no explicit configuration
    serial.print("[UEFI] KASLR: No explicit configuration found, defaulting to enabled\r\n", .{}) catch {};
    return true;
}

/// Get safe memory range for KASLR from UEFI memory map
pub fn getSafeKASLRRange(boot_services: *uefi.tables.BootServices) struct { min: u64, max: u64 } {
    var memory_map_size: usize = 0;
    var map_key: usize = undefined;
    var descriptor_size: usize = undefined;
    var descriptor_version: u32 = undefined;

    // First call to get the size needed
    _ = boot_services.getMemoryMap(&memory_map_size, null, &map_key, &descriptor_size, &descriptor_version);

    // Allocate buffer for memory map (add generous padding for descriptor changes)
    // UEFI spec recommends adding extra space as memory map can change between calls
    const buffer_size = memory_map_size + (8 * descriptor_size);

    // Allocate dynamic buffer using UEFI pool allocator
    const buffer = uefi.pool_allocator.alloc(u8, buffer_size) catch {
        serial.print("[UEFI] Failed to allocate memory for KASLR memory map (needed {} bytes)\r\n", .{buffer_size}) catch {};
        // Default to 16MB-256MB range if we can't get memory map
        return .{ .min = 0x1000000, .max = 0x10000000 };
    };
    defer uefi.pool_allocator.free(buffer);

    memory_map_size = buffer_size;
    const memory_map = @as([*]uefi.tables.MemoryDescriptor, @ptrCast(@alignCast(buffer.ptr)));

    // Get the actual memory map
    switch (boot_services.getMemoryMap(&memory_map_size, memory_map, &map_key, &descriptor_size, &descriptor_version)) {
        .success => {},
        else => {
            serial.print("[UEFI] Failed to get memory map for KASLR\r\n", .{}) catch {};
            return .{ .min = 0x1000000, .max = 0x10000000 };
        },
    }

    // Find the largest contiguous usable memory region above 16MB
    var best_start: u64 = 0x1000000; // Default to 16MB minimum
    var best_end: u64 = 0x10000000; // Default to 256MB
    var best_size: u64 = 0;

    // Track total conventional memory below 4GB to detect systems with only 4GB RAM
    var total_low_memory: u64 = 0;
    const FOUR_GB = 0x100000000;

    const num_entries = memory_map_size / descriptor_size;

    // First pass: count total conventional memory below 4GB
    var i: usize = 0;
    while (i < num_entries) : (i += 1) {
        const desc = @as(*const uefi.tables.MemoryDescriptor, @ptrCast(@alignCast(@as([*]const u8, @ptrCast(memory_map)) + (i * descriptor_size))));

        switch (desc.type) {
            .conventional_memory => {
                const start = desc.physical_start;
                const end = start + (desc.number_of_pages * 4096);

                if (start < FOUR_GB) {
                    const low_end = @min(end, FOUR_GB);
                    total_low_memory += (low_end - start);
                }
            },
            else => {},
        }
    }

    serial.print("[UEFI] Total conventional memory below 4GB: {} MB\r\n", .{total_low_memory / (1024 * 1024)}) catch {};

    // Second pass: find best region for KASLR
    i = 0;
    while (i < num_entries) : (i += 1) {
        const desc = @as(*const uefi.tables.MemoryDescriptor, @ptrCast(@alignCast(@as([*]const u8, @ptrCast(memory_map)) + (i * descriptor_size))));

        // Check if this is usable memory above 16MB
        switch (desc.type) {
            .conventional_memory => {
                const start = desc.physical_start;
                const end = start + (desc.number_of_pages * 4096);

                // Skip regions below 16MB (often reserved)
                if (end <= 0x1000000) continue;

                // CRITICAL: Skip regions at or above 4GB on systems with 4GB or less total RAM
                // Systems with exactly 4GB often report memory above 4GB due to PCI hole remapping
                // Only use high memory if we have significantly more than 4GB total
                if (start >= FOUR_GB) {
                    // More accurate check: Systems with 4GB or less typically have < 2GB usable below 4GB
                    // due to PCI hole and other reserved regions. Systems with 8GB+ typically have
                    // ~2GB usable below 4GB with the rest remapped above.
                    // QEMU specifically gives ~2002MB below 4GB for 8GB systems.
                    if (total_low_memory < 0x70000000) { // Less than 1.75GB below 4GB
                        if (secure_debug.shouldShowAddresses()) {
                            serial.print("[UEFI] Skipping high memory region at 0x{X} (system likely has only 4GB total)\r\n", .{start}) catch {};
                        } else {
                            serial.print("[UEFI] Skipping high memory region (system likely has only 4GB total)\r\n", .{}) catch {};
                        }
                        continue;
                    }
                }

                // Adjust start if it's below 16MB
                const adjusted_start = if (start < 0x1000000) 0x1000000 else start;
                const adjusted_size = end - adjusted_start;

                // Prefer regions below 4GB for better compatibility
                const is_low_region = end <= FOUR_GB;
                const is_better = if (is_low_region and best_end > FOUR_GB)
                    true // Always prefer low memory over high memory
                else if (!is_low_region and best_end <= FOUR_GB)
                    false // Don't replace low memory with high memory
                else
                    adjusted_size > best_size; // Same category, pick larger

                if (is_better) {
                    best_start = adjusted_start;
                    best_end = end;
                    best_size = adjusted_size;
                }
            },
            else => {},
        }
    }

    if (secure_debug.shouldShowAddresses()) {
        serial.print("[UEFI] Best KASLR region: 0x{X}-0x{X} ({} MB)\r\n", .{ best_start, best_end, best_size / (1024 * 1024) }) catch {};
    } else {
        serial.print("[UEFI] Best KASLR region: {} MB\r\n", .{best_size / (1024 * 1024)}) catch {};
    }

    return .{ .min = best_start, .max = best_end };
}

/// Get random offset for KASLR
pub fn getRandomOffset(boot_services: *uefi.tables.BootServices) !u64 {
    // Check if KASLR is enabled at runtime
    if (!isKASLREnabled(boot_services)) {
        serial.print("[UEFI] KASLR disabled by configuration\r\n", .{}) catch {};
        return 0;
    }

    serial.print("[UEFI] KASLR enabled, calculating random offset\r\n", .{}) catch {};

    // Get safe memory range for KASLR
    const safe_range = getSafeKASLRRange(boot_services);

    // Reserve space for kernel (assume max 16MB kernel) and some buffer
    const kernel_reserve = 0x1000000; // 16MB
    const safety_buffer = 0x1000000; // 16MB

    // Calculate the range for KASLR within the safe region
    // The kernel will be loaded at safe_range.min + offset
    const min_addr = safe_range.min;
    const max_addr = if (safe_range.max > (kernel_reserve + safety_buffer))
        safe_range.max - kernel_reserve - safety_buffer
    else
        safe_range.max;

    if (max_addr <= min_addr) {
        serial.print("[UEFI] CRITICAL: Insufficient memory for KASLR\r\n", .{}) catch {};
        if (isKASLREnforcementEnabled()) {
            serial.print("[UEFI] SECURITY: Failing boot due to KASLR enforcement policy\r\n", .{}) catch {};
            return kernel_types.KASLRError.InsufficientMemoryForKASLR;
        }
        serial.print("[UEFI] WARNING: Continuing without KASLR (security degraded)\r\n", .{}) catch {};
        return 0;
    }

    const kaslr_range = max_addr - min_addr;

    // Ensure we have at least some randomization space
    if (kaslr_range < 0x2000000) { // Less than 32MB available
        serial.print("[UEFI] CRITICAL: Insufficient memory for KASLR (need at least 32MB range, have {} MB)\r\n", .{kaslr_range / (1024 * 1024)}) catch {};
        if (isKASLREnforcementEnabled()) {
            serial.print("[UEFI] SECURITY: Failing boot due to KASLR enforcement policy\r\n", .{}) catch {};
            return kernel_types.KASLRError.InsufficientMemoryForKASLR;
        }
        serial.print("[UEFI] WARNING: Continuing without KASLR (security degraded)\r\n", .{}) catch {};
        return 0;
    }

    // Select alignment based on available range
    var alignment = selectKASLRAlignment(kaslr_range);

    // Calculate entropy bits: log2(number of possible positions)
    var num_positions = kaslr_range / alignment;
    var entropy_bits: u32 = 0;
    var n = num_positions;
    while (n > 1) : (n >>= 1) {
        entropy_bits += 1;
    }

    // SECURITY: Check minimum entropy requirement
    if (entropy_bits < config.KASLR_MIN_ENTROPY_BITS) {
        serial.print("[UEFI] KASLR: Initial entropy too low ({} bits < {} minimum)\r\n", .{ entropy_bits, config.KASLR_MIN_ENTROPY_BITS }) catch {};

        // Try to increase entropy by using finer alignment
        const min_positions = @as(u64, 1) << config.KASLR_MIN_ENTROPY_BITS; // 2^4 = 16 positions minimum
        const required_alignment = kaslr_range / min_positions;

        // Use the finest alignment that still meets the minimum positions requirement
        const adjusted_alignment = if (required_alignment >= KASLR_ALIGNMENT_COARSE)
            KASLR_ALIGNMENT_COARSE
        else if (required_alignment >= KASLR_ALIGNMENT_NORMAL)
            KASLR_ALIGNMENT_NORMAL
        else if (required_alignment >= KASLR_ALIGNMENT_FINE)
            KASLR_ALIGNMENT_FINE
        else if (required_alignment >= KASLR_ALIGNMENT_ULTRA_FINE)
            KASLR_ALIGNMENT_ULTRA_FINE
        else
            required_alignment; // Use calculated alignment for very small ranges

        // Recalculate with adjusted alignment
        num_positions = kaslr_range / adjusted_alignment;
        entropy_bits = 0;
        n = num_positions;
        while (n > 1) : (n >>= 1) {
            entropy_bits += 1;
        }

        serial.print("[UEFI] KASLR: Adjusted alignment to {} KB for minimum entropy\r\n", .{adjusted_alignment / 1024}) catch {};

        // Final check - if we still can't meet minimum entropy, fail
        if (entropy_bits < config.KASLR_MIN_ENTROPY_BITS) {
            serial.print("[UEFI] CRITICAL: Cannot achieve minimum KASLR entropy ({} bits < {} required)\r\n", .{ entropy_bits, config.KASLR_MIN_ENTROPY_BITS }) catch {};
            if (isKASLREnforcementEnabled()) {
                serial.print("[UEFI] SECURITY: Failing boot due to insufficient KASLR entropy\r\n", .{}) catch {};
                return kernel_types.KASLRError.InsufficientMemoryForKASLR;
            }
            serial.print("[UEFI] WARNING: Continuing with degraded KASLR security\r\n", .{}) catch {};
        }

        // Update alignment for final use
        alignment = adjusted_alignment;
    }

    if (secure_debug.shouldShowAddresses()) {
        serial.print("[UEFI] KASLR range: 0x{X} ({} MB), alignment: {} KB, ~{} bits of entropy ({} possible positions)\r\n", .{ kaslr_range, kaslr_range / (1024 * 1024), alignment / 1024, entropy_bits, num_positions }) catch {};
    } else {
        serial.print("[UEFI] KASLR range: {} MB, alignment: {} KB, ~{} bits of entropy ({} possible positions)\r\n", .{ kaslr_range / (1024 * 1024), alignment / 1024, entropy_bits, num_positions }) catch {};
    }

    // Warn if below recommended entropy
    if (entropy_bits < config.KASLR_RECOMMENDED_ENTROPY_BITS) {
        serial.print("[UEFI] WARNING: KASLR entropy below recommended level ({} bits < {} recommended)\r\n", .{ entropy_bits, config.KASLR_RECOMMENDED_ENTROPY_BITS }) catch {};
    }

    // SECURITY: Add additional entropy for constrained systems (4GB or less)
    // Systems with limited memory ranges provide less KASLR entropy, so we need to
    // mix in additional entropy sources to maintain security
    var extra_entropy_value: u64 = 0;
    const is_constrained_system = entropy_bits < config.KASLR_RECOMMENDED_ENTROPY_BITS;
    if (is_constrained_system) {
        serial.print("[UEFI] KASLR: Adding extra entropy for constrained system\r\n", .{}) catch {};

        // Mix in additional entropy sources for systems with limited memory
        const extra_entropy_sources = [_]u64{
            collector.readTsc(), // Current TSC value
            collector.readPerfCounters(), // CPU performance counters with jitter
            collector.readCmosTime(), // CMOS/RTC time for timing variation
            collector.getPitEntropy(), // PIT timer entropy
            collector.getAcpiEntropy(), // ACPI table entropy
            @intFromPtr(boot_services), // UEFI memory address entropy
            collector.getMemoryLayoutEntropy(boot_services), // Memory layout entropy
        };

        // Mix all entropy sources using a simple but effective approach
        for (extra_entropy_sources) |source| {
            extra_entropy_value = crypto.rotl64(extra_entropy_value, 7) ^ source;
        }

        // Apply timing-based entropy mixing
        const start_tsc = collector.readTsc();
        asm volatile ("pause" ::: "memory");
        const end_tsc = collector.readTsc();
        extra_entropy_value ^= (end_tsc -% start_tsc);

        serial.print("[UEFI] KASLR: Mixed {} additional entropy sources for constrained system\r\n", .{extra_entropy_sources.len}) catch {};
    }

    // Try to use UEFI RNG protocol
    const rng_guid align(8) = uefi.Guid{
        .time_low = 0x3152bca5,
        .time_mid = 0xeade,
        .time_high_and_version = 0x433d,
        .clock_seq_high_and_reserved = 0x86,
        .clock_seq_low = 0x2e,
        .node = [_]u8{ 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44 },
    };

    var rng_protocol: *anyopaque = undefined;
    var random_value: u64 = 0;
    var hardware_rng_used = false;

    // Try to get RNG protocol
    switch (boot_services.locateProtocol(&rng_guid, null, @ptrCast(&rng_protocol))) {
        .success => {
            // RNG protocol available, get random number
            const get_random = @as(*const fn (*anyopaque, usize, [*]u8) callconv(.C) uefi.Status, @ptrCast(@alignCast(rng_protocol)));
            _ = get_random(rng_protocol, 8, @ptrCast(&random_value));
            hardware_rng_used = true;
            serial.print("[UEFI] KASLR: Using UEFI RNG protocol\r\n", .{}) catch {};

            // Still collect multiple entropy sources for boot entropy
            const entropy_sources = [_]u64{
                random_value, // UEFI RNG value
                collector.readTsc(), // TSC for additional entropy
                @intFromPtr(boot_services), // Memory address
                collector.readCmosTime(), // CMOS/RTC time
                collector.readPerfCounters(), // Performance counters
            };

            // Collect boot entropy for kernel
            crypto.collectBootEntropy(&entropy_sources, hardware_rng_used);
        },
        else => {
            // Fallback: try hardware RNG instructions first
            // Use our RNG module which tries RDSEED first, then RDRAND
            if (rng.getRandom(u64)) |value| {
                random_value = value;
                hardware_rng_used = true;
                serial.print("[UEFI] KASLR: Using hardware RNG\r\n", .{}) catch {};
            } else |_| {
                // Final fallback: use TSC and other entropy sources
                random_value = collector.readTsc();
                serial.print("[UEFI] KASLR: Using TSC as entropy source\r\n", .{}) catch {};
            }

            // Collect multiple entropy sources (Intel-recommended)
            const entropy_sources = [_]u64{
                random_value, // Base entropy (TSC or hardware RNG)
                @intFromPtr(boot_services), // Memory address (ASLR of UEFI)
                collector.readCmosTime(), // CMOS/RTC time
                collector.readPerfCounters(), // Performance counters with CPUID mix
                collector.readTsc() >> 8, // High-resolution timer (shifted for variety)
                collector.getAcpiEntropy(), // ACPI tables entropy
                collector.getPitEntropy(), // PIT timer entropy
                collector.getMemoryLayoutEntropy(boot_services), // Memory layout entropy
            };

            // Collect boot entropy for kernel before assessment
            crypto.collectBootEntropy(&entropy_sources, hardware_rng_used);

            // Assess entropy quality
            const quality = crypto.assessEntropyQuality(&entropy_sources, hardware_rng_used);
            secure_debug.printEntropyQuality(quality.sources_used, quality.estimated_entropy);

            // Enforce minimum entropy requirements (Intel recommends at least 32 bits)
            if (!hardware_rng_used and quality.estimated_entropy < 32.0) {
                const policy = @import("../../security/policy.zig");
                policy.checkLowEntropy(quality.estimated_entropy) catch |err| {
                    serial.print("[UEFI] FATAL: Low entropy rejected by security policy\r\n", .{}) catch {};
                    return err;
                };
            }

            // Use cryptographically strong mixing
            random_value = try crypto.mixEntropySources(&entropy_sources);
            serial.print("[UEFI] KASLR: Mixed {} entropy sources with NIST SP 800-90A CTR_DRBG\r\n", .{entropy_sources.len}) catch {};
        },
    }

    // Apply additional entropy mixing for constrained systems
    if (is_constrained_system and extra_entropy_value != 0) {
        // Mix the extra entropy with the random value using cryptographic mixing
        random_value = crypto.rotl64(random_value, 13) ^ extra_entropy_value;
        random_value = crypto.rotl64(random_value, 7) ^ collector.readTsc();

        serial.print("[UEFI] KASLR: Applied additional entropy mixing for constrained system\r\n", .{}) catch {};
    }

    // Generate offset within the safe range
    const offset_within_range = (random_value % num_positions) * alignment;

    // The actual offset is from the original kernel base (0x200000) to the new location
    const actual_offset = (safe_range.min - 0x200000) + offset_within_range;

    // Calculate entropy bits based on number of possible positions
    const calculated_entropy_bits: u8 = @intFromFloat(@log2(@as(f64, @floatFromInt(num_positions))));
    secure_debug.printKASLROffset(actual_offset, calculated_entropy_bits);

    return actual_offset;
}
