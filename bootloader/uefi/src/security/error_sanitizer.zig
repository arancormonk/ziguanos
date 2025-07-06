// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = @import("std").os.uefi;
const policy = @import("policy.zig");

// Error message sanitization for production builds
// Prevents information leakage through detailed error messages
pub const ErrorSanitizer = struct {
    // Sensitive patterns that should be redacted in production
    const SensitivePatterns = struct {
        // Memory address patterns (0x followed by hex digits)
        const address_pattern = "0x";

        // Offset information patterns
        const offset_patterns = [_][]const u8{
            "offset",
            "OFFSET",
            "Offset",
        };

        // Size information patterns
        const size_patterns = [_][]const u8{
            "size=",
            "SIZE=",
            "bytes",
            "BYTES",
            "KB",
            "MB",
            "GB",
        };

        // Path information patterns
        const path_patterns = [_][]const u8{
            "\\EFI\\",
            "/EFI/",
            "path:",
            "PATH:",
            "file:",
            "FILE:",
        };

        // Technical details patterns
        const technical_patterns = [_][]const u8{
            "failed at",
            "error at line",
            "function:",
            "module:",
            "stack:",
            "register:",
        };
    };

    // Generic error messages for production mode
    const GenericMessages = struct {
        const boot_failure = "Boot process failed";
        const verification_failure = "Security verification failed";
        const loading_failure = "System loading failed";
        const configuration_error = "Configuration error";
        const hardware_error = "Hardware initialization failed";
        const memory_error = "Memory operation failed";
        const security_violation = "Security policy violation";
    };

    // Sanitize an error message based on security policy
    pub fn sanitize(message: []const u8, error_code: anyerror) []const u8 {
        const security_level = policy.getSecurityLevel();

        // In development mode, return original message
        if (security_level == .Development) {
            return message;
        }

        // In production/strict mode, return generic message based on error type
        if (security_level == .Production or security_level == .Strict) {
            return getGenericMessage(error_code);
        }

        // In other modes, redact sensitive information
        return redactSensitiveInfo(message);
    }

    // Get a generic error message for production mode
    fn getGenericMessage(error_code: anyerror) []const u8 {
        // Map specific errors to generic messages
        return switch (error_code) {
            error.FileNotFound, error.InvalidPath => GenericMessages.loading_failure,
            error.HashMismatch, error.HMACMismatch => GenericMessages.verification_failure,
            error.SecurityViolation, error.PolicyViolation => GenericMessages.security_violation,
            error.OutOfMemory, error.AllocationFailed => GenericMessages.memory_error,
            error.InvalidParameter, error.InvalidConfiguration => GenericMessages.configuration_error,
            error.DeviceError, error.HardwareFailure => GenericMessages.hardware_error,
            else => GenericMessages.boot_failure,
        };
    }

    // Check if a message contains sensitive information
    pub fn containsSensitiveInfo(message: []const u8) bool {
        // Check for memory addresses
        if (std.mem.indexOf(u8, message, SensitivePatterns.address_pattern) != null) {
            return true;
        }

        // Check for offset patterns
        for (SensitivePatterns.offset_patterns) |pattern| {
            if (std.mem.indexOf(u8, message, pattern) != null) {
                return true;
            }
        }

        // Check for size patterns
        for (SensitivePatterns.size_patterns) |pattern| {
            if (std.mem.indexOf(u8, message, pattern) != null) {
                return true;
            }
        }

        // Check for path patterns
        for (SensitivePatterns.path_patterns) |pattern| {
            if (std.mem.indexOf(u8, message, pattern) != null) {
                return true;
            }
        }

        // Check for technical patterns
        for (SensitivePatterns.technical_patterns) |pattern| {
            if (std.mem.indexOf(u8, message, pattern) != null) {
                return true;
            }
        }

        return false;
    }

    // Redact sensitive information from a message
    fn redactSensitiveInfo(message: []const u8) []const u8 {
        // For now, if message contains sensitive info, return generic message
        // In a more sophisticated implementation, we could selectively redact
        if (containsSensitiveInfo(message)) {
            return "Operation failed. Check system configuration.";
        }
        return message;
    }

    // Create a safe error context without leaking details
    pub fn createSafeContext(
        comptime error_type: []const u8,
        details: anytype,
    ) []const u8 {
        const security_level = policy.getSecurityLevel();

        // In production mode, return minimal context
        if (security_level == .Production or security_level == .Strict) {
            return error_type;
        }

        // In development mode, include full details
        if (security_level == .Development) {
            return std.fmt.comptimePrint("{s}: {any}", .{ error_type, details });
        }

        // Otherwise, include type but not details
        return error_type;
    }
};

// Wrapper for serial output with automatic sanitization
pub const SanitizedSerial = struct {
    const serial = @import("../drivers/serial.zig");

    // Print an error message with automatic sanitization
    pub fn printError(comptime fmt: []const u8, args: anytype) void {
        const security_level = policy.getSecurityLevel();

        // In production/strict mode, check if serial output is allowed
        if (security_level == .Production or security_level == .Strict) {
            // Check if this is a critical security message that should always be shown
            if (!isCriticalSecurityMessage(fmt)) {
                return; // Suppress non-critical messages
            }
        }

        // Sanitize format string
        const sanitized_fmt = sanitizeFormatString(fmt);

        // Print with sanitized format
        serial.printError(sanitized_fmt, args);
    }

    // Print a warning message with automatic sanitization
    pub fn printWarning(comptime fmt: []const u8, args: anytype) void {
        const security_level = policy.getSecurityLevel();

        // In production/strict mode, suppress warnings
        if (security_level == .Production or security_level == .Strict) {
            return;
        }

        // Sanitize and print
        const sanitized_fmt = sanitizeFormatString(fmt);
        serial.printWarning(sanitized_fmt, args);
    }

    // Print an info message with automatic sanitization
    pub fn printInfo(comptime fmt: []const u8, args: anytype) void {
        const security_level = policy.getSecurityLevel();

        // Only show info in development mode
        if (security_level != .Development) {
            return;
        }

        serial.printInfo(fmt, args);
    }

    // Check if a message is critical security information
    fn isCriticalSecurityMessage(comptime fmt: []const u8) bool {
        return std.mem.indexOf(u8, fmt, "[SECURITY]") != null or
            std.mem.indexOf(u8, fmt, "FATAL") != null or
            std.mem.indexOf(u8, fmt, "CRITICAL") != null;
    }

    // Sanitize a format string at compile time
    fn sanitizeFormatString(comptime fmt: []const u8) []const u8 {
        // Check for patterns that might leak information
        if (comptime std.mem.indexOf(u8, fmt, "0x{x}") != null) {
            return std.mem.replaceOwned(u8, fmt, "0x{x}", "[REDACTED]") catch fmt;
        }
        if (comptime std.mem.indexOf(u8, fmt, "offset") != null) {
            return std.mem.replaceOwned(u8, fmt, "offset", "[offset]") catch fmt;
        }
        if (comptime std.mem.indexOf(u8, fmt, "address") != null) {
            return std.mem.replaceOwned(u8, fmt, "address", "[addr]") catch fmt;
        }
        return fmt;
    }
};

// Test error sanitization
pub fn testErrorSanitization() !void {
    const test_messages = [_]struct {
        message: []const u8,
        has_sensitive: bool,
    }{
        .{ .message = "Boot completed successfully", .has_sensitive = false },
        .{ .message = "Failed to load at 0x1234ABCD", .has_sensitive = true },
        .{ .message = "Memory allocation failed at offset 0x1000", .has_sensitive = true },
        .{ .message = "File not found: \\EFI\\BOOT\\kernel.elf", .has_sensitive = true },
        .{ .message = "Verification complete", .has_sensitive = false },
        .{ .message = "Size mismatch: expected 4096 bytes", .has_sensitive = true },
    };

    for (test_messages) |test_case| {
        const result = ErrorSanitizer.containsSensitiveInfo(test_case.message);
        if (result != test_case.has_sensitive) {
            return error.TestFailed;
        }
    }
}
