// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const error_sanitizer = @import("error_sanitizer.zig");
const ErrorSanitizer = error_sanitizer.ErrorSanitizer;
const policy = @import("policy.zig");

// Secure logging wrapper that automatically applies error sanitization
// based on security policy. Use this instead of direct serial output
// for all error and warning messages.
pub const SecureLog = struct {
    // Log an error with automatic sanitization
    pub fn logError(comptime context: []const u8, err: anyerror, comptime details: []const u8, args: anytype) void {
        const security_level = policy.getSecurityLevel();

        // In production/strict mode, use generic error messages
        if (security_level == .Production or security_level == .Strict) {
            const generic_msg = ErrorSanitizer.sanitize(details, err);
            serial.print("[ERROR] {s}: {s}\r\n", .{ context, generic_msg }) catch {};
            return;
        }

        // In development mode, provide full details
        if (security_level == .Development) {
            serial.print("[ERROR] {s}: ", .{context}) catch {};
            serial.print(details, args) catch {};
            serial.print(" (error: {s})\r\n", .{@errorName(err)}) catch {};
            return;
        }

        // In other modes, provide context but sanitized details
        var buffer: [512]u8 = undefined;

        // SECURITY: Handle buffer overflow with explicit error handling
        const formatted = std.fmt.bufPrint(&buffer, details, args) catch |fmt_err| {
            // On buffer overflow, log sanitized error
            if (fmt_err == error.NoSpaceLeft) {
                serial.print("[ERROR] {s}: Message too long for buffer (>512 bytes)\r\n", .{context}) catch {};
            } else {
                serial.print("[ERROR] {s}: Failed to format error details\r\n", .{context}) catch {};
            }
            return;
        };

        if (ErrorSanitizer.containsSensitiveInfo(formatted)) {
            serial.print("[ERROR] {s}: {s}\r\n", .{ context, ErrorSanitizer.sanitize(formatted, err) }) catch {};
        } else {
            serial.print("[ERROR] {s}: {s}\r\n", .{ context, formatted }) catch {};
        }
    }

    // Log a warning with automatic sanitization
    pub fn logWarning(comptime context: []const u8, comptime details: []const u8, args: anytype) void {
        const security_level = policy.getSecurityLevel();

        // In production/strict mode, suppress warnings
        if (security_level == .Production or security_level == .Strict) {
            return;
        }

        // Check if details contain sensitive information
        var buffer: [512]u8 = undefined;

        // SECURITY: Properly handle buffer overflow cases
        const formatted = std.fmt.bufPrint(&buffer, details, args) catch |fmt_err| {
            if (fmt_err == error.NoSpaceLeft) {
                // SECURITY: Don't expose that message was too long in production
                serial.print("[WARNING] {s}: Unable to log complete details\r\n", .{context}) catch {};
            } else {
                serial.print("[WARNING] {s}: Format error occurred\r\n", .{context}) catch {};
            }
            return;
        };

        if (ErrorSanitizer.containsSensitiveInfo(formatted)) {
            serial.print("[WARNING] {s}: Operation encountered non-critical issue\r\n", .{context}) catch {};
        } else {
            serial.print("[WARNING] {s}: {s}\r\n", .{ context, formatted }) catch {};
        }
    }

    // Log informational message with automatic filtering
    pub fn logInfo(comptime context: []const u8, comptime details: []const u8, args: anytype) void {
        const security_level = policy.getSecurityLevel();

        // Only show info in development mode
        if (security_level != .Development) {
            return;
        }

        serial.print("[INFO] {s}: ", .{context}) catch {};
        serial.print(details, args) catch {};
        serial.print("\r\n", .{}) catch {};
    }

    // Log debug message (development only)
    pub fn logDebug(comptime context: []const u8, comptime details: []const u8, args: anytype) void {
        const security_level = policy.getSecurityLevel();

        // Only show debug in development mode
        if (security_level != .Development) {
            return;
        }

        serial.printDebug("[DEBUG] {s}: ", .{context}) catch {};
        serial.printDebug(details, args) catch {};
        serial.printDebug("\r\n", .{}) catch {};
    }

    // Log critical security message (always shown unless serial is disabled)
    pub fn logCritical(comptime context: []const u8, comptime details: []const u8, args: anytype) void {
        // Critical messages use minimal details in production
        const security_level = policy.getSecurityLevel();

        if (security_level == .Production or security_level == .Strict) {
            serial.printCritical("[CRITICAL] Security violation detected\r\n", .{}) catch {};
        } else {
            serial.printCritical("[CRITICAL] {s}: ", .{context}) catch {};
            serial.printCritical(details, args) catch {};
            serial.printCritical("\r\n", .{}) catch {};
        }
    }

    // Log a file operation error with path sanitization
    pub fn logFileError(comptime operation: []const u8, path: []const u16, err: anyerror) void {
        const security_level = policy.getSecurityLevel();

        if (security_level == .Production or security_level == .Strict) {
            // Don't reveal file paths in production
            logError("FileSystem", err, "{s} operation failed", .{operation});
        } else {
            // In development, show the path but limit length
            const max_path_len = 64;
            const path_len = std.mem.len(path);

            if (path_len <= max_path_len) {
                logError("FileSystem", err, "{s} failed for path: {}", .{ operation, std.unicode.fmtUtf16le(path) });
            } else {
                // Truncate long paths
                logError("FileSystem", err, "{s} failed for path: {}...", .{ operation, std.unicode.fmtUtf16le(path[0..max_path_len]) });
            }
        }
    }

    // Log a memory operation error with address sanitization
    pub fn logMemoryError(comptime operation: []const u8, address: usize, size: usize, err: anyerror) void {
        const security_level = policy.getSecurityLevel();

        if (security_level == .Production or security_level == .Strict) {
            // Don't reveal memory addresses in production
            logError("Memory", err, "{s} operation failed", .{operation});
        } else if (security_level == .Development) {
            // Show full details in development
            logError("Memory", err, "{s} failed at 0x{x:0>16} size=0x{x}", .{ operation, address, size });
        } else {
            // Show size but not address in other modes
            logError("Memory", err, "{s} failed for size=0x{x}", .{ operation, size });
        }
    }
};

// Example usage patterns for secure logging
pub fn exampleUsage() void {
    // Log a file error
    SecureLog.logFileError("open", &[_]u16{ 'k', 'e', 'r', 'n', 'e', 'l', '.', 'e', 'l', 'f', 0 }, error.FileNotFound);

    // Log a memory error
    SecureLog.logMemoryError("allocate", 0x200000, 0x1000, error.OutOfMemory);

    // Log a generic error
    SecureLog.logError("KernelLoader", error.HashMismatch, "Kernel integrity check failed", .{});

    // Log a warning
    SecureLog.logWarning("KASLR", "Entropy below recommended level: {} bits", .{5});

    // Log info
    SecureLog.logInfo("Boot", "Starting kernel load process", .{});

    // Log critical security violation
    SecureLog.logCritical("SecureBoot", "Unsigned kernel detected", .{});
}
