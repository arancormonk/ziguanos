// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Debug output sanitization for UEFI bootloader
// This module provides comprehensive debug output control to prevent
// sensitive information leakage while maintaining useful debugging capabilities

const std = @import("std");
const uefi = std.os.uefi;
const serial = @import("../drivers/serial.zig");
const policy = @import("policy.zig");
const builtin = @import("builtin");

/// Debug levels for controlling output verbosity
pub const DebugLevel = enum(u8) {
    None = 0, // No debug output at all
    Critical = 1, // Only critical security messages
    Error = 2, // Errors and critical messages
    Warning = 3, // Warnings, errors, and critical
    Info = 4, // General information messages
    Debug = 5, // Detailed debug information
    Trace = 6, // Verbose trace-level output

    pub fn fromSecurityLevel(level: policy.SecurityLevel) DebugLevel {
        return switch (level) {
            .Strict => .Critical,
            .Production => .Warning,
            .Development => .Debug,
        };
    }
};

/// Sensitive data types that need sanitization
const SensitiveDataType = enum {
    KernelAddress,
    KASLROffset,
    EntropyValue,
    CryptoKey,
    MemoryAddress,
    StackPointer,
    None,
};

/// Debug output sanitizer configuration
pub const DebugSanitizer = struct {
    debug_level: DebugLevel,
    sanitize_addresses: bool,
    sanitize_entropy: bool,
    hash_key: u64,

    pub fn init() DebugSanitizer {
        const security_level = policy.getSecurityLevel();
        const is_production = security_level != .Development;

        // Generate a random hash key for address sanitization
        const hash_key = if (builtin.mode == .Debug)
            0xDEADBEEFCAFEBABE
        else blk: {
            // Try to get random value for hash key
            var key: u64 = 0x5A49475541524E53; // "ZIGUANOS" as fallback

            // Use TSC for additional entropy
            var low: u32 = undefined;
            var high: u32 = undefined;
            asm volatile (
                \\rdtsc
                : [low] "={eax}" (low),
                  [high] "={edx}" (high),
            );
            key ^= (@as(u64, high) << 32) | low;

            break :blk key;
        };

        return DebugSanitizer{
            .debug_level = DebugLevel.fromSecurityLevel(security_level),
            .sanitize_addresses = is_production,
            .sanitize_entropy = is_production,
            .hash_key = hash_key,
        };
    }

    /// Check if output is allowed for given level
    pub fn isAllowed(self: *const DebugSanitizer, level: DebugLevel) bool {
        return @intFromEnum(level) <= @intFromEnum(self.debug_level);
    }

    /// Classify data type for sanitization
    fn classifyData(value: u64) SensitiveDataType {
        // Kernel addresses (typically loaded at 0x200000 or with KASLR offset)
        if (value >= 0x100000 and value < 0x10000000) {
            return .KernelAddress;
        }

        // KASLR offsets are typically smaller values
        if (value > 0 and value < 0x1000000) {
            return .KASLROffset;
        }

        // Stack pointers and higher kernel addresses
        if (value >= 0xFFFF800000000000) {
            return .StackPointer;
        }

        // Memory addresses in general
        if (value >= 0x1000) {
            return .MemoryAddress;
        }

        return .None;
    }

    /// Hash a value for sanitization
    fn hashValue(self: *const DebugSanitizer, value: u64) u64 {
        var hash = value ^ self.hash_key;
        hash = (hash ^ (hash >> 30)) *% 0xBF58476D1CE4E5B9;
        hash = (hash ^ (hash >> 27)) *% 0x94D049BB133111EB;
        hash = hash ^ (hash >> 31);
        return hash & 0xFFFF; // Return only lower 16 bits
    }

    /// Sanitize a potentially sensitive value
    pub fn sanitizeValue(self: *const DebugSanitizer, value: u64, data_type: SensitiveDataType) u64 {
        if (!self.sanitize_addresses) {
            return value;
        }

        return switch (data_type) {
            .KernelAddress, .KASLROffset, .StackPointer => self.hashValue(value),
            .EntropyValue => if (self.sanitize_entropy) 0xDEAD else value,
            .CryptoKey => 0xDEADDEAD, // REDACTED
            .MemoryAddress => value & 0xFFFFF000, // Mask lower bits
            .None => value,
        };
    }

    /// Format an address for safe output
    pub fn formatAddress(self: *const DebugSanitizer, writer: anytype, addr: u64) !void {
        const data_type = classifyData(addr);

        if (self.sanitize_addresses and data_type != .None) {
            const sanitized = self.sanitizeValue(addr, data_type);
            try writer.print("0x{x:0>4}****", .{sanitized});
        } else {
            try writer.print("0x{x:0>16}", .{addr});
        }
    }

    /// Sanitize a format string and its arguments
    pub fn sanitizeFormat(self: *const DebugSanitizer, comptime fmt: []const u8, args: anytype) void {
        // For now, we'll implement specific print functions instead
        // of trying to parse and sanitize arbitrary format strings
        _ = self;
        _ = fmt;
        _ = args;
    }
};

/// Global debug sanitizer instance
pub var debug_sanitizer: DebugSanitizer = undefined;
var initialized = false;

/// Initialize the debug sanitizer
pub fn init() void {
    debug_sanitizer = DebugSanitizer.init();
    initialized = true;
}

/// Ensure sanitizer is initialized
fn ensureInitialized() void {
    if (!initialized) {
        init();
    }
}

/// Secure debug print functions
pub fn print(level: DebugLevel, comptime fmt: []const u8, args: anytype) void {
    ensureInitialized();

    if (!debug_sanitizer.isAllowed(level)) {
        return;
    }

    serial.print(fmt, args) catch {};
}

pub fn println(level: DebugLevel, comptime fmt: []const u8, args: anytype) void {
    ensureInitialized();

    if (!debug_sanitizer.isAllowed(level)) {
        return;
    }

    serial.print(fmt, args) catch {};
    serial.print("\r\n", .{}) catch {};
}

/// Specialized print functions for sensitive data
pub fn printKernelLoad(physical_addr: u64, virtual_addr: u64, size: u64) void {
    ensureInitialized();

    if (!debug_sanitizer.isAllowed(.Info)) {
        return;
    }

    if (debug_sanitizer.sanitize_addresses) {
        println(.Info, "[UEFI] Kernel loaded successfully (size: 0x{x})", .{size});
    } else {
        println(.Info, "[UEFI] Kernel loaded at physical: 0x{x:0>16}, virtual: 0x{x:0>16}, size: 0x{x}", .{ physical_addr, virtual_addr, size });
    }
}

pub fn printKASLROffset(offset: u64, entropy_bits: u8) void {
    ensureInitialized();

    if (!debug_sanitizer.isAllowed(.Debug)) {
        return;
    }

    if (debug_sanitizer.sanitize_addresses) {
        println(.Debug, "[UEFI] KASLR enabled with {} bits of entropy", .{entropy_bits});
    } else {
        println(.Debug, "[UEFI] KASLR offset: 0x{x:0>16} ({} bits of entropy)", .{ offset, entropy_bits });
    }
}

pub fn printEntropy(comptime source: []const u8, value: u64) void {
    ensureInitialized();

    if (!debug_sanitizer.isAllowed(.Trace)) {
        return;
    }

    if (debug_sanitizer.sanitize_entropy) {
        println(.Trace, "[UEFI] {s} entropy collected", .{source});
    } else {
        println(.Trace, "[UEFI] {s} entropy: 0x{x:0>16}", .{ source, value });
    }
}

pub fn printMemoryMap(start: u64, end: u64, mem_type: []const u8) void {
    ensureInitialized();

    if (!debug_sanitizer.isAllowed(.Debug)) {
        return;
    }

    const size = end - start;

    if (debug_sanitizer.sanitize_addresses) {
        // Show size and type but not addresses
        if (size < 1024 * 1024) {
            println(.Debug, "[UEFI] Memory region: {s} ({} KB)", .{ mem_type, size / 1024 });
        } else {
            println(.Debug, "[UEFI] Memory region: {s} ({} MB)", .{ mem_type, size / (1024 * 1024) });
        }
    } else {
        println(.Debug, "[UEFI] Memory: 0x{x:0>16} - 0x{x:0>16} {s} ({} KB)", .{ start, end, mem_type, size / 1024 });
    }
}

pub fn printHashVerification(success: bool) void {
    ensureInitialized();

    if (!debug_sanitizer.isAllowed(.Info)) {
        return;
    }

    if (success) {
        println(.Info, "[UEFI] Kernel integrity verification: PASSED", .{});
    } else {
        println(.Error, "[UEFI] Kernel integrity verification: FAILED", .{});
    }
}

pub fn printSecureBootStatus(enabled: bool) void {
    ensureInitialized();

    if (!debug_sanitizer.isAllowed(.Info)) {
        return;
    }

    if (enabled) {
        println(.Info, "[UEFI] Secure Boot: ENABLED", .{});
    } else {
        println(.Warning, "[UEFI] Secure Boot: DISABLED", .{});
    }
}

pub fn printError(comptime context: []const u8, err: anyerror) void {
    ensureInitialized();

    if (!debug_sanitizer.isAllowed(.Error)) {
        return;
    }

    if (debug_sanitizer.debug_level == .Critical) {
        // Minimal error output in strict mode
        println(.Error, "[UEFI] {s} failed", .{context});
    } else {
        println(.Error, "[UEFI] {s} error: {s}", .{ context, @errorName(err) });
    }
}

pub fn printStackTrace(rip: u64, rsp: u64, rbp: u64) void {
    ensureInitialized();

    if (!debug_sanitizer.isAllowed(.Debug)) {
        return;
    }

    if (debug_sanitizer.sanitize_addresses) {
        println(.Debug, "[UEFI] Stack trace available (sanitized)", .{});
    } else {
        println(.Debug, "[UEFI] Stack: RIP=0x{x:0>16} RSP=0x{x:0>16} RBP=0x{x:0>16}", .{ rip, rsp, rbp });
    }
}

/// Test function to verify sanitization
pub fn runSelfTest() void {
    init();

    println(.Info, "[UEFI] Debug sanitizer self-test", .{});

    // Test different data types
    const kernel_addr: u64 = 0x200000;
    const kaslr_offset: u64 = 0x123000;
    const entropy: u64 = 0xDEADBEEFCAFEBABE;
    const stack_ptr: u64 = 0xFFFF800000001000;

    printKernelLoad(kernel_addr, kernel_addr + kaslr_offset, 0x100000);
    printKASLROffset(kaslr_offset, 6);
    printEntropy("RDRAND", entropy);
    printStackTrace(kernel_addr + 0x1234, stack_ptr, stack_ptr + 0x20);

    println(.Info, "[UEFI] Debug sanitizer test complete", .{});
}
