// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../../drivers/serial.zig");
const policy = @import("../policy.zig");
const secure_log = @import("../secure_log.zig");
const SecureLog = secure_log.SecureLog;
const error_sanitizer = @import("../error_sanitizer.zig");
const ErrorSanitizer = error_sanitizer.ErrorSanitizer;

// Test error sanitization functionality
pub fn runErrorSanitizerTests() !void {
    serial.print("\r\n[TEST] Starting error sanitizer tests...\r\n", .{}) catch {};

    // Test 1: Test sensitive pattern detection
    testSensitivePatternDetection();

    // Test 2: Test error message sanitization
    testErrorMessageSanitization();

    // Test 3: Test secure logging with different security levels
    testSecureLogging();

    serial.print("[TEST] Error sanitizer tests completed\r\n", .{}) catch {};
}

fn testSensitivePatternDetection() void {
    serial.print("[TEST] Testing sensitive pattern detection...\r\n", .{}) catch {};

    const test_cases = [_]struct {
        message: []const u8,
        expected: bool,
        desc: []const u8,
    }{
        .{ .message = "Simple message", .expected = false, .desc = "no sensitive info" },
        .{ .message = "Error at 0x1234ABCD", .expected = true, .desc = "memory address" },
        .{ .message = "Failed at offset 0x1000", .expected = true, .desc = "offset info" },
        .{ .message = "\\EFI\\BOOT\\kernel.elf not found", .expected = true, .desc = "file path" },
        .{ .message = "Allocated 4096 bytes", .expected = true, .desc = "size info" },
        .{ .message = "Function: loadKernel failed", .expected = true, .desc = "technical details" },
    };

    for (test_cases) |tc| {
        const result = ErrorSanitizer.containsSensitiveInfo(tc.message);
        if (result == tc.expected) {
            serial.print("  ✓ {s}: {s}\r\n", .{ tc.desc, if (result) "detected" else "clean" }) catch {};
        } else {
            serial.print("  ✗ {s}: expected {}, got {}\r\n", .{ tc.desc, tc.expected, result }) catch {};
        }
    }
}

fn testErrorMessageSanitization() void {
    serial.print("[TEST] Testing error message sanitization...\r\n", .{}) catch {};

    // Save current security level
    const current_level = policy.getSecurityLevel();

    // Test in Development mode
    policy.testSetSecurityLevel(.Development);
    var msg = ErrorSanitizer.sanitize("Failed to load at 0x1234ABCD", error.FileNotFound);
    serial.print("  Development mode: \"{s}\"\r\n", .{msg}) catch {};

    // Test in Production mode
    policy.testSetSecurityLevel(.Production);
    msg = ErrorSanitizer.sanitize("Failed to load at 0x1234ABCD", error.FileNotFound);
    serial.print("  Production mode: \"{s}\"\r\n", .{msg}) catch {};

    // Restore original security level
    policy.testSetSecurityLevel(current_level);
}

fn testSecureLogging() void {
    serial.print("[TEST] Testing secure logging...\r\n", .{}) catch {};

    // Save current security level
    const current_level = policy.getSecurityLevel();

    serial.print("  Testing in Development mode:\r\n", .{}) catch {};
    policy.testSetSecurityLevel(.Development);

    // These should show full details in development mode
    SecureLog.logError("TestModule", error.OutOfMemory, "Failed to allocate {} bytes at 0x{x}", .{ 4096, 0x200000 });
    SecureLog.logWarning("TestModule", "Memory usage at {}%", .{85});
    SecureLog.logInfo("TestModule", "Test info message", .{});

    serial.print("  Testing in Production mode:\r\n", .{}) catch {};
    policy.testSetSecurityLevel(.Production);

    // These should be sanitized or suppressed in production mode
    SecureLog.logError("TestModule", error.OutOfMemory, "Failed to allocate {} bytes at 0x{x}", .{ 4096, 0x200000 });
    SecureLog.logWarning("TestModule", "Memory usage at {}%", .{85}); // Should be suppressed
    SecureLog.logInfo("TestModule", "Test info message", .{}); // Should be suppressed

    // Restore original security level
    policy.testSetSecurityLevel(current_level);
}
