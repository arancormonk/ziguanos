// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const security_config = @import("security_config");
const SerialSecurity = security_config.SerialSecurity;
const MessageLevel = security_config.MessageLevel;
const error_sanitizer = @import("../security/error_sanitizer.zig");
const ErrorSanitizer = error_sanitizer.ErrorSanitizer;

// Serial port I/O addresses
const COM1_BASE: u16 = 0x3F8;
const COM1_DATA = COM1_BASE + 0;
const COM1_IER = COM1_BASE + 1;
const COM1_FCR = COM1_BASE + 2;
const COM1_LCR = COM1_BASE + 3;
const COM1_MCR = COM1_BASE + 4;
const COM1_LSR = COM1_BASE + 5;
const COM1_SCR = COM1_BASE + 7; // Scratch register

// Timeout value for write operations (in pause loops)
const WRITE_TIMEOUT_LOOPS: u32 = 100000;

// Simple I/O port operations using minimal inline assembly
pub fn outb(port: u16, value: u8) void {
    asm volatile ("outb %al, %dx"
        :
        : [value] "{al}" (value),
          [port] "{dx}" (port),
    );
}

pub fn inb(port: u16) u8 {
    return asm volatile ("inb %dx, %al"
        : [result] "={al}" (-> u8),
        : [port] "{dx}" (port),
    );
}

pub fn init() !void {
    // Check if serial output is enabled for this build mode
    if (!SerialSecurity.enable_serial) {
        return; // Serial output disabled in production
    }
    // First check if serial port exists using scratch register
    const saved_scratch = inb(COM1_SCR);

    // Write test patterns to scratch register
    outb(COM1_SCR, 0x55);
    if (inb(COM1_SCR) != 0x55) {
        return error.SerialPortNotFound;
    }

    outb(COM1_SCR, 0xAA);
    if (inb(COM1_SCR) != 0xAA) {
        return error.SerialPortNotFound;
    }

    // Restore original scratch value
    outb(COM1_SCR, saved_scratch);

    // Disable interrupts
    outb(COM1_IER, 0x00);

    // Enable DLAB (set baud rate divisor)
    outb(COM1_LCR, 0x80);

    // Set divisor to 1 (115200 baud)
    outb(COM1_DATA, 0x01);
    outb(COM1_IER, 0x00);

    // 8 bits, no parity, 1 stop bit
    outb(COM1_LCR, 0x03);

    // Enable FIFO, clear them, with 14-byte threshold
    outb(COM1_FCR, 0xC7);

    // IRQs enabled, RTS/DSR set
    outb(COM1_MCR, 0x0B);

    // Test serial port in loopback mode
    const saved_mcr = inb(COM1_MCR);
    outb(COM1_MCR, saved_mcr | 0x10); // Enable loopback

    // Send test byte
    outb(COM1_DATA, 0xAE);

    // Wait a bit for loopback
    var wait_loops: u32 = 0;
    while (wait_loops < 1000) : (wait_loops += 1) {
        asm volatile ("pause");
    }

    // Check if we received it
    if ((inb(COM1_LSR) & 0x01) == 0 or inb(COM1_DATA) != 0xAE) {
        outb(COM1_MCR, saved_mcr); // Restore MCR
        return error.SerialPortFailed;
    }

    // Restore MCR
    outb(COM1_MCR, saved_mcr);

    // Clear FIFOs and ready to go
    outb(COM1_FCR, 0xC7);
}

// Write character with timeout protection
pub fn writeCharWithTimeout(char: u8) bool {
    var loops: u32 = 0;

    // Wait for transmit buffer to be empty
    while ((inb(COM1_LSR) & 0x20) == 0) {
        if (loops >= WRITE_TIMEOUT_LOOPS) {
            return false; // Timeout
        }
        loops += 1;
        asm volatile ("pause");
    }

    outb(COM1_DATA, char);
    return true;
}

// Original writeChar for compatibility - now with timeout protection
pub fn writeChar(char: u8) void {
    if (!SerialSecurity.enable_serial) return;
    _ = writeCharWithTimeout(char);
}

pub fn writeString(str: []const u8) void {
    if (!SerialSecurity.enable_serial) return;
    for (str) |char| {
        writeChar(char);
    }
}

// Write string with timeout protection - returns number of chars written
pub fn writeStringWithTimeout(str: []const u8) usize {
    if (!SerialSecurity.enable_serial) return 0;
    var written: usize = 0;
    for (str) |char| {
        if (!writeCharWithTimeout(char)) {
            break; // Stop on timeout
        }
        written += 1;
    }
    return written;
}

pub fn print(comptime fmt: []const u8, args: anytype) !void {
    if (!SerialSecurity.enable_serial) return;

    // SECURITY: Limit buffer size based on security configuration
    const buffer_size = @min(1024, SerialSecurity.max_message_size);
    if (buffer_size == 0) return;

    var buffer: [1024]u8 = undefined;

    // SECURITY: Use bounded slice and handle overflow explicitly
    const formatted = std.fmt.bufPrint(buffer[0..buffer_size], fmt, args) catch |err| switch (err) {
        error.NoSpaceLeft => {
            // SECURITY: Handle buffer overflow gracefully
            // Truncate the message and add overflow indicator
            const truncated_size = buffer_size - 5; // Room for "...\r\n"
            _ = std.fmt.bufPrint(buffer[0..truncated_size], fmt, args) catch {};
            buffer[truncated_size] = '.';
            buffer[truncated_size + 1] = '.';
            buffer[truncated_size + 2] = '.';
            buffer[truncated_size + 3] = '\r';
            buffer[truncated_size + 4] = '\n';
            writeString(buffer[0..buffer_size]);
            return error.BufferOverflow;
        },
        else => return err,
    };

    writeString(formatted);
}

// Security-aware print functions for different message levels
pub fn printDebug(comptime fmt: []const u8, args: anytype) void {
    if (!SerialSecurity.enable_debug_output) return;
    print(fmt, args) catch {};
}

pub fn printInfo(comptime fmt: []const u8, args: anytype) void {
    if (!security_config.shouldOutput(.info)) return;
    print(fmt, args) catch {};
}

pub fn printWarning(comptime fmt: []const u8, args: anytype) void {
    if (!security_config.shouldOutput(.warning)) return;
    print(fmt, args) catch {};
}

pub fn printError(comptime fmt: []const u8, args: anytype) void {
    if (!SerialSecurity.enable_error_output) return;
    print(fmt, args) catch {};
}

// Critical print function that tries harder on errors
pub fn printCritical(comptime fmt: []const u8, args: anytype) void {
    // Critical messages only output if error output is enabled
    if (!SerialSecurity.enable_error_output) return;

    // SECURITY: Ensure buffer size is safe
    const buffer_size = @min(1024, SerialSecurity.max_message_size);
    if (buffer_size == 0) return;

    var buffer: [1024]u8 = undefined;

    // SECURITY: Use bounded slice operations with proper error handling
    const formatted = std.fmt.bufPrint(buffer[0..buffer_size], fmt, args) catch |err| {
        // If formatting fails, at least try to output an error indicator
        const error_msg = switch (err) {
            error.NoSpaceLeft => {
                // SECURITY: Try to preserve as much of the message as possible
                // Attempt partial format with smaller buffer
                const small_size = @min(buffer_size, 256);
                const partial = std.fmt.bufPrint(buffer[0..small_size], fmt, args) catch {
                    // Even partial format failed, use generic error
                    writeString("[CRITICAL:FMT_OVERFLOW]\r\n");
                    return;
                };
                writeString(partial);
                writeString("...[TRUNCATED]\r\n");
                return;
            },
            else => "[FMT_ERR]\r\n",
        };
        writeString(error_msg);
        return;
    };

    // Try to write with timeout protection
    const written = writeStringWithTimeout(formatted);

    // If we didn't write everything, try to indicate truncation
    if (written < formatted.len) {
        writeString("...[TRUNC]\r\n");
    }
}

// Sanitized print functions that apply error message sanitization
pub fn printErrorSanitized(comptime fmt: []const u8, args: anytype, error_code: anyerror) void {
    if (!SerialSecurity.enable_error_output) return;

    // Check if the format string contains sensitive information
    if (comptime ErrorSanitizer.containsSensitiveInfo(fmt)) {
        // Use sanitized version
        const sanitized = ErrorSanitizer.sanitize(fmt, error_code);
        print(sanitized, .{}) catch {};
    } else {
        printError(fmt, args);
    }
}

pub fn printWarningSanitized(comptime fmt: []const u8, args: anytype) void {
    if (!security_config.shouldOutput(.warning)) return;

    // Apply sanitization for warning messages
    const buffer_size = @min(1024, SerialSecurity.max_message_size);
    if (buffer_size == 0) return;

    var buffer: [1024]u8 = undefined;

    // SECURITY: Handle buffer overflow properly
    const formatted = std.fmt.bufPrint(buffer[0..buffer_size], fmt, args) catch |err| {
        // On overflow, print truncated indicator
        if (err == error.NoSpaceLeft) {
            writeString("[WARNING:TRUNCATED]\r\n");
        }
        return;
    };

    // Check if formatted message contains sensitive info
    if (ErrorSanitizer.containsSensitiveInfo(formatted)) {
        // Print generic warning instead
        print("Warning: Operation encountered issues\r\n", .{}) catch {};
    } else {
        print(fmt, args) catch {};
    }
}

pub fn printInfoSanitized(comptime fmt: []const u8, args: anytype) void {
    if (!security_config.shouldOutput(.info)) return;

    // In production mode, suppress detailed info messages
    const policy = @import("../security/policy.zig");
    const security_level = policy.getSecurityLevel() catch .Development;

    if (security_level == .Production or security_level == .Strict) {
        return; // No info messages in production
    }

    printInfo(fmt, args);
}
