// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2024 Ziguanos. All rights reserved.

// KASLR Configuration Module
//
// This module contains all KASLR-related configuration constants, structures,
// and configuration loading functions extracted from the kernel loader.

const std = @import("std");
const uefi = std.os.uefi;
const variable_cache = @import("../../security/variable_cache.zig");
const serial = @import("../../drivers/serial.zig");
const kernel_types = @import("../kernel_types.zig");

// KASLR entropy configuration constants
pub const KASLR_MIN_ENTROPY_BITS: u32 = 4;
pub const KASLR_RECOMMENDED_ENTROPY_BITS: u32 = 12; // Increased from 6 to 12 per Intel guidelines
pub const KASLR_OPTIMAL_ENTROPY_BITS: u32 = 16; // Optimal target for maximum security

// KASLR security configuration
pub const ENFORCE_KASLR_ON_FAILURE = true;

// Section-level KASLR support for enhanced entropy
pub const ENABLE_SECTION_KASLR = true; // Enable per-section randomization
pub const SECTION_KASLR_GUARD_SIZE: u64 = 0x100000; // 1MB guard between sections

// PIE support: Enable allocate_any_pages mode for better compatibility
pub const ENABLE_PIE_ALLOCATION = false;

// KASLR UEFI variable GUID
pub const kaslr_guid align(8) = uefi.Guid{
    .time_low = 0x12345678,
    .time_mid = 0x1234,
    .time_high_and_version = 0x1234,
    .clock_seq_high_and_reserved = 0x12,
    .clock_seq_low = 0x34,
    .node = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC },
};

/// RNG retry configuration structure
pub const RngRetryConfig = struct {
    rdrand_max_retries: u32,
    rdseed_max_retries: u32,

    // Default Intel-recommended values
    pub const DEFAULT_RDRAND_RETRIES: u32 = 20;
    pub const DEFAULT_RDSEED_RETRIES: u32 = 1024;
};

// Global retry configuration (initialized with defaults)
var rng_retry_config: RngRetryConfig = .{
    .rdrand_max_retries = RngRetryConfig.DEFAULT_RDRAND_RETRIES,
    .rdseed_max_retries = RngRetryConfig.DEFAULT_RDSEED_RETRIES,
};

/// Get the current RNG retry configuration
pub fn getRngRetryConfig() RngRetryConfig {
    return rng_retry_config;
}

/// Load RNG retry configuration from UEFI variable cache
pub fn loadRngRetryConfig(runtime_services: *uefi.tables.RuntimeServices) void {
    // Initialize cache if not already done
    if (!variable_cache.isInitialized()) {
        variable_cache.init(runtime_services) catch {
            serial.print("[UEFI] Failed to initialize variable cache for RNG config\r\n", .{}) catch {};
            return;
        };
    }

    // Get KASLR configuration from cache
    const kaslr_config = variable_cache.getKASLRConfig();

    // Load RDRAND retry count from cache
    if (kaslr_config.rdrand_retries) |rdrand_retries| {
        // Validate reasonable retry count (10-1000)
        if (rdrand_retries >= 10 and rdrand_retries <= 1000) {
            rng_retry_config.rdrand_max_retries = rdrand_retries;
            serial.print("[UEFI] Loaded RDRAND retry count from cache: {}\r\n", .{rdrand_retries}) catch {};
        }
    }

    // Load RDSEED retry count from cache
    if (kaslr_config.rdseed_retries) |rdseed_retries| {
        // Validate reasonable retry count (100-10000)
        if (rdseed_retries >= 100 and rdseed_retries <= 10000) {
            rng_retry_config.rdseed_max_retries = rdseed_retries;
            serial.print("[UEFI] Loaded RDSEED retry count from cache: {}\r\n", .{rdseed_retries}) catch {};
        }
    }
}
