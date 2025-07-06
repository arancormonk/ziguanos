// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Security policy enforcement for serial output
// This module manages what can be output based on security levels

const std = @import("std");
const timing = @import("timing.zig");

/// Message level enumeration
pub const MessageLevel = enum(u8) {
    critical = 0,
    err = 1,
    warning = 2,
    info = 3,
    debug = 4,
    trace = 5,
};

/// Security policy configuration
pub const SecurityPolicy = struct {
    enable_serial: bool,
    sanitize_addresses: bool,
    enable_memory_info: bool,
    min_message_level: MessageLevel,
    timing_config: timing.TimingConfig,

    pub fn init() SecurityPolicy {
        return SecurityPolicy{
            .enable_serial = true,
            .sanitize_addresses = true,
            .enable_memory_info = false,
            .min_message_level = .info,
            .timing_config = timing.TimingConfig{},
        };
    }

    pub fn development() SecurityPolicy {
        return SecurityPolicy{
            .enable_serial = true,
            .sanitize_addresses = false,
            .enable_memory_info = true,
            .min_message_level = .trace,
            .timing_config = timing.TimingConfig.development(),
        };
    }

    pub fn production() SecurityPolicy {
        return SecurityPolicy{
            .enable_serial = true,
            .sanitize_addresses = true,
            .enable_memory_info = false,
            .min_message_level = .warning,
            .timing_config = timing.TimingConfig.production(),
        };
    }

    pub fn strict() SecurityPolicy {
        return SecurityPolicy{
            .enable_serial = false,
            .sanitize_addresses = true,
            .enable_memory_info = false,
            .min_message_level = .critical,
            .timing_config = timing.TimingConfig.strict(),
        };
    }

    pub fn isOutputAllowed(self: *const SecurityPolicy, level: MessageLevel) bool {
        if (!self.enable_serial) return false;

        const level_value = @intFromEnum(level);
        const min_level_value = @intFromEnum(self.min_message_level);

        // Lower numeric values = higher priority (critical = 0, trace = 5)
        return level_value <= min_level_value;
    }

    pub fn isMemoryInfoAllowed(self: *const SecurityPolicy) bool {
        return self.enable_memory_info;
    }

    pub fn shouldSanitizeAddresses(self: *const SecurityPolicy) bool {
        return self.sanitize_addresses;
    }

    pub fn getTimingConfig(self: *const SecurityPolicy) timing.TimingConfig {
        return self.timing_config;
    }
};
