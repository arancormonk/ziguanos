// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Security configuration for compile-time control of debug output
// Following Intel x86-64 security best practices for information leakage prevention

const std = @import("std");

// Build mode configuration
pub const BuildMode = enum {
    debug,
    release,
    production,
};

// Get build mode from compile-time options
pub const build_mode: BuildMode = if (@hasDecl(@import("build_options"), "build_mode"))
    @field(BuildMode, @import("build_options").build_mode)
else
    .debug; // Default to debug if not specified

// Serial output security configuration
pub const SerialSecurity = struct {
    // Enable serial output at all
    pub const enable_serial: bool = switch (build_mode) {
        .debug => true,
        .release => true,
        .production => false, // Completely disable in production
    };

    // Enable debug messages (detailed system information)
    pub const enable_debug_output: bool = switch (build_mode) {
        .debug => true,
        .release => false,
        .production => false,
    };

    // Enable error messages (security-relevant errors)
    pub const enable_error_output: bool = switch (build_mode) {
        .debug => true,
        .release => true,
        .production => false, // Even errors are disabled in production
    };

    // Enable address sanitization (hide KASLR offsets)
    pub const sanitize_addresses: bool = switch (build_mode) {
        .debug => false, // Show full addresses in debug
        .release => true,
        .production => true,
    };

    // Enable performance statistics
    pub const enable_statistics: bool = switch (build_mode) {
        .debug => true,
        .release => true,
        .production => false,
    };

    // Enable timing information (could leak through timing attacks)
    pub const enable_timing_info: bool = switch (build_mode) {
        .debug => true,
        .release => false,
        .production => false,
    };

    // Enable memory information (could leak layout)
    pub const enable_memory_info: bool = switch (build_mode) {
        .debug => true,
        .release => false,
        .production => false,
    };

    // Maximum message buffer size (prevent memory exhaustion)
    pub const max_message_size: usize = switch (build_mode) {
        .debug => 4096,
        .release => 1024,
        .production => 0,
    };
};

// Message filtering levels
pub const MessageLevel = enum(u8) {
    critical = 0, // System failures
    @"error" = 1, // Errors that may continue
    warning = 2, // Warnings
    info = 3, // Informational messages
    debug = 4, // Debug details
    trace = 5, // Detailed tracing
};

// Get minimum message level for output
pub fn getMinMessageLevel() MessageLevel {
    return switch (build_mode) {
        .debug => .trace,
        .release => .warning,
        .production => .critical,
    };
}

// Check if a message level should be output
pub inline fn shouldOutput(level: MessageLevel) bool {
    if (!SerialSecurity.enable_serial) return false;
    return @intFromEnum(level) <= @intFromEnum(getMinMessageLevel());
}

// Secure message filtering
pub inline fn filterMessage(comptime level: MessageLevel, comptime fmt: []const u8) ?[]const u8 {
    if (!comptime shouldOutput(level)) return null;

    // Additional compile-time filtering for sensitive patterns
    if (comptime build_mode == .production) {
        // Check for potentially sensitive information patterns
        if (comptime std.mem.indexOf(u8, fmt, "0x") != null and !SerialSecurity.sanitize_addresses) {
            return null; // Block raw addresses
        }
        if (comptime std.mem.indexOf(u8, fmt, "offset") != null) {
            return null; // Block offset information
        }
        if (comptime std.mem.indexOf(u8, fmt, "address") != null) {
            return null; // Block address information
        }
    }

    return fmt;
}

// Timing attack mitigation
pub const TimingSecurity = struct {
    // Add random delays to operations in production
    pub const add_timing_jitter: bool = switch (build_mode) {
        .debug => false,
        .release => false,
        .production => true,
    };

    // Minimum jitter in CPU cycles
    pub const min_jitter_cycles: u32 = 100;
    pub const max_jitter_cycles: u32 = 1000;
};

// Memory security
pub const MemorySecurity = struct {
    // Zero memory on allocation/free
    pub const zero_on_alloc: bool = switch (build_mode) {
        .debug => false,
        .release => true,
        .production => true,
    };

    pub const zero_on_free: bool = switch (build_mode) {
        .debug => false,
        .release => true,
        .production => true,
    };

    // Scrub sensitive data patterns
    pub const scrub_pattern: u8 = switch (build_mode) {
        .debug => 0x00,
        .release => 0xAA,
        .production => 0xFF,
    };
};

// Assert configuration
pub const AssertSecurity = struct {
    // Enable runtime assertions
    pub const enable_asserts: bool = switch (build_mode) {
        .debug => true,
        .release => true,
        .production => false, // No asserts in production
    };

    // Enable assert messages (could leak information)
    pub const enable_assert_messages: bool = switch (build_mode) {
        .debug => true,
        .release => false,
        .production => false,
    };
};

// Panic configuration
pub const PanicSecurity = struct {
    // Enable detailed panic information
    pub const detailed_panic: bool = switch (build_mode) {
        .debug => true,
        .release => true,
        .production => false,
    };

    // Enable stack traces in panic
    pub const panic_stack_trace: bool = switch (build_mode) {
        .debug => true,
        .release => false,
        .production => false,
    };

    // Panic message for production
    pub const production_panic_msg: []const u8 = "System Error";
};

// Helper functions for secure output
pub const SecureOutput = struct {
    // Compile-time no-op function for production
    pub inline fn print(comptime level: MessageLevel, comptime fmt: []const u8, args: anytype) void {
        if (comptime !SerialSecurity.enable_serial) return;
        if (comptime !shouldOutput(level)) return;

        const filtered_fmt = comptime filterMessage(level, fmt) orelse return;
        _ = filtered_fmt;
        _ = args;
        // Actual implementation will be in serial drivers
    }

    // Runtime check for dynamic content
    pub fn printRuntime(level: MessageLevel, fmt: []const u8, args: anytype) void {
        if (!SerialSecurity.enable_serial) return;
        if (!shouldOutput(level)) return;
        _ = fmt;
        _ = args;
        // Actual implementation will be in serial drivers
    }
};

// Export build mode for runtime checks
pub fn getBuildModeString() []const u8 {
    return switch (build_mode) {
        .debug => "debug",
        .release => "release",
        .production => "production",
    };
}

// Compile-time assertions to ensure security
comptime {
    if (build_mode == .production) {
        // Ensure production mode has all security features enabled
        std.debug.assert(!SerialSecurity.enable_serial);
        std.debug.assert(!SerialSecurity.enable_debug_output);
        std.debug.assert(!SerialSecurity.enable_timing_info);
        std.debug.assert(!SerialSecurity.enable_memory_info);
        std.debug.assert(SerialSecurity.sanitize_addresses);
        std.debug.assert(MemorySecurity.zero_on_alloc);
        std.debug.assert(MemorySecurity.zero_on_free);
    }
}
