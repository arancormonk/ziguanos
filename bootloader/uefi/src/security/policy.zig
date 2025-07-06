// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;
const serial = @import("../drivers/serial.zig");
const variable_cache = @import("variable_cache.zig");
const security_config = @import("security_config");

// Security policy configuration
// Following Intel x86-64 security best practices for secure boot

// Security policy levels
pub const SecurityLevel = enum(u8) {
    // Development mode - warnings only, boot continues
    Development = 0,

    // Production mode - critical errors halt boot, some warnings allowed
    Production = 1,

    // Strict mode - any security violation halts boot
    Strict = 2,
};

// Default security level (can be overridden at compile time)
// Use the build mode from security_config which respects the --mode build option
pub const DEFAULT_SECURITY_LEVEL: SecurityLevel = switch (security_config.build_mode) {
    .debug => SecurityLevel.Development,
    .release => SecurityLevel.Production,
    .production => SecurityLevel.Strict,
};

// Security violation types
pub const ViolationType = enum {
    // Boot security violations
    SerialInitFailure,
    KernelHashLoadFailure,
    UnsignedKernel,
    HashMismatch,
    UnauthenticatedVariable,

    // KASLR violations
    KASLRFailure,
    LowEntropy,
    DRBGFailure,

    // ELF loading violations
    InvalidFileAttributes,
    UnalignedKernelSize,
    InvalidELFSection,
    WXViolation,
    UnsupportedRelocation,
    OutOfRangeRelocation,

    // System integrity violations
    InvalidACPISignature,
    MemoryMapFailure,

    // Generic violations
    SecurityCheckFailed,
};

// Security policy configuration loaded from UEFI variables
var security_level: SecurityLevel = DEFAULT_SECURITY_LEVEL;
var policy_initialized: bool = false;

// Security violation statistics
var violation_counts: [std.meta.fields(ViolationType).len]u32 = [_]u32{0} ** std.meta.fields(ViolationType).len;
var total_violations: u32 = 0;

// Initialize security policy from UEFI variable cache
pub fn init(runtime_services: ?*uefi.tables.RuntimeServices) void {
    if (policy_initialized) return;
    policy_initialized = true;

    // Try to load security level from cache
    if (runtime_services) |rs| {
        // Initialize cache if not already done
        if (!variable_cache.isInitialized()) {
            variable_cache.init(rs) catch {
                serial.print("[SECURITY] Failed to initialize variable cache, using default policy\r\n", .{}) catch {};
                return;
            };
        }

        // Get security level from cache
        if (variable_cache.getSecurityLevel()) |cached| {
            if (cached.level <= @intFromEnum(SecurityLevel.Strict)) {
                security_level = @enumFromInt(cached.level);
                serial.print("[SECURITY] Security level set to: {} (from cache)\r\n", .{security_level}) catch {};
            } else {
                serial.print("[SECURITY] Invalid security level in cache: {}, using default\r\n", .{cached.level}) catch {};
            }
        } else {
            // Variable not found in cache - use default
            serial.print("[SECURITY] Using default security level: {}\r\n", .{security_level}) catch {};
        }
    }

    // Log security policy configuration
    serial.print("[SECURITY] Security Policy Initialized\r\n", .{}) catch {};
    serial.print("[SECURITY] Level: {}\r\n", .{security_level}) catch {};
    serial.print("[SECURITY] Strict mode: {}\r\n", .{security_level == .Strict}) catch {};
}

// Check if a violation should halt boot based on current policy
pub fn shouldHalt(violation: ViolationType) bool {
    // Track violation
    const violation_index = @intFromEnum(violation);
    violation_counts[violation_index] += 1;
    total_violations += 1;

    // In strict mode, any violation halts boot
    if (security_level == .Strict) {
        return true;
    }

    // In production mode, determine based on violation severity
    if (security_level == .Production) {
        return switch (violation) {
            // Critical violations always halt in production
            .KernelHashLoadFailure,
            .UnsignedKernel,
            .HashMismatch,
            .UnauthenticatedVariable,
            .KASLRFailure,
            .SecurityCheckFailed,
            .WXViolation, // W^X violations are now critical per Intel x86-64 guidelines
            => true,

            // Warnings in production mode
            .SerialInitFailure,
            .LowEntropy,
            .DRBGFailure,
            .InvalidFileAttributes,
            .UnalignedKernelSize,
            .InvalidELFSection,
            .UnsupportedRelocation,
            .OutOfRangeRelocation,
            .InvalidACPISignature,
            .MemoryMapFailure,
            => false,
        };
    }

    // In development mode, never halt
    return false;
}

// Report a security violation
pub fn reportViolation(violation: ViolationType, comptime message: []const u8, args: anytype) !bool {
    const should_halt = shouldHalt(violation);

    if (should_halt) {
        try serial.print("[SECURITY] FATAL: ", .{});
    } else {
        try serial.print("[SECURITY] WARNING: ", .{});
    }

    try serial.print(message, args);
    try serial.print("\r\n", .{});

    if (should_halt) {
        try serial.print("[SECURITY] Boot halted due to security policy ({})\r\n", .{security_level});
        try serial.print("[SECURITY] Violation type: {}\r\n", .{violation});
        try printViolationSummary();
    }

    return should_halt;
}

// Print summary of all violations
pub fn printViolationSummary() !void {
    if (total_violations == 0) {
        try serial.print("[SECURITY] No security violations detected\r\n", .{});
        return;
    }

    try serial.print("[SECURITY] Security Violation Summary:\r\n", .{});
    try serial.print("[SECURITY] Total violations: {}\r\n", .{total_violations});

    const violation_types = std.meta.fields(ViolationType);
    inline for (violation_types, 0..) |field, i| {
        if (violation_counts[i] > 0) {
            try serial.print("[SECURITY]   {s}: {} times\r\n", .{ field.name, violation_counts[i] });
        }
    }
}

// Check if strict mode is enabled
pub fn isStrictMode() bool {
    return security_level == .Strict;
}

// Get current security level
pub fn getSecurityLevel() SecurityLevel {
    return security_level;
}

// Test-only function to set security level (for testing error sanitization)
pub fn testSetSecurityLevel(level: SecurityLevel) void {
    // Only allow in development builds to prevent misuse
    const builtin = @import("builtin");
    if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) {
        security_level = level;
    }
}

// Security policy enforcement helpers

// Check serial initialization with policy enforcement
pub fn checkSerialInit(init_result: anyerror!void) !void {
    init_result catch |err| {
        if (try reportViolation(.SerialInitFailure, "Failed to initialize serial port: {}", .{err})) {
            return error.SecurityPolicyViolation;
        }
    };
}

// Check kernel hash loading with policy enforcement
pub fn checkKernelHashLoad(load_result: anyerror!void) !void {
    load_result catch |err| {
        if (try reportViolation(.KernelHashLoadFailure, "Failed to load kernel hash from UEFI variables: {}", .{err})) {
            return error.SecurityPolicyViolation;
        }
    };
}

// Check unsigned kernel with policy enforcement
pub fn checkUnsignedKernel() !void {
    if (try reportViolation(.UnsignedKernel, "Running unsigned kernel (no expected hash configured)", .{})) {
        return error.SecurityPolicyViolation;
    }
}

// Check hash mismatch with policy enforcement
pub fn checkHashMismatch() !void {
    if (try reportViolation(.HashMismatch, "Kernel hash verification failed", .{})) {
        return error.SecurityPolicyViolation;
    }
}

// Check UEFI variable authentication with policy enforcement
pub fn checkVariableAuthentication(variable_name: []const u8, is_authenticated: bool) !void {
    if (!is_authenticated) {
        if (try reportViolation(.UnauthenticatedVariable, "UEFI variable '{s}' is not authenticated", .{variable_name})) {
            return error.SecurityPolicyViolation;
        }
    }
}

// Check KASLR failure with policy enforcement
pub fn checkKASLRFailure(reason: []const u8) !void {
    if (try reportViolation(.KASLRFailure, "KASLR failed: {s}", .{reason})) {
        return error.SecurityPolicyViolation;
    }
}

// Check low entropy with policy enforcement
pub fn checkLowEntropy(entropy_bits: f64) !void {
    if (try reportViolation(.LowEntropy, "Low entropy for KASLR: {d:.1} bits", .{entropy_bits})) {
        return error.SecurityPolicyViolation;
    }
}

// Check file attributes with policy enforcement
pub fn checkFileAttributes(is_system: bool, is_hidden: bool) !void {
    if (is_system or is_hidden) {
        const attrs = if (is_system and is_hidden) "system and hidden" else if (is_system) "system" else "hidden";
        if (try reportViolation(.InvalidFileAttributes, "Kernel file has unusual attributes: {s}", .{attrs})) {
            return error.SecurityPolicyViolation;
        }
    }
}

// Check W^X violation with policy enforcement (Intel x86-64 security guidelines)
// Per Intel Software Developer Manual and security best practices:
// - Code segments should be R+X (readable and executable, not writable)
// - Data segments should be R+W (readable and writable, not executable)
// - No memory region should be both writable and executable (W^X principle)
pub fn checkWXViolation(segment_index: usize, flags: u32) !void {
    const PF_W = 0x2; // Write permission
    const PF_X = 0x1; // Execute permission
    const PF_R = 0x4; // Read permission

    const has_write = (flags & PF_W) != 0;
    const has_exec = (flags & PF_X) != 0;
    const has_read = (flags & PF_R) != 0;

    // W^X violation check - fundamental security principle
    if (has_write and has_exec) {
        if (try reportViolation(.WXViolation, "Segment {} violates W^X: has both write (W) and execute (X) permissions (flags: 0x{X})", .{ segment_index, flags })) {
            return error.WXViolation;
        }
    }

    // Additional Intel x86-64 security validations
    if (has_exec and !has_read) {
        if (try reportViolation(.InvalidELFSection, "Segment {} has execute but no read permission (unusual, flags: 0x{X})", .{ segment_index, flags })) {
            return error.InvalidSegmentPermissions;
        }
    }

    // Segments with no permissions are suspicious
    if (!has_read and !has_write and !has_exec) {
        if (try reportViolation(.InvalidELFSection, "Segment {} has no permissions set (flags: 0x{X})", .{ segment_index, flags })) {
            return error.InvalidSegmentPermissions;
        }
    }
}

// Check ELF section validity with policy enforcement
pub fn checkInvalidELFSection(section_index: usize, reason: []const u8) !void {
    if (try reportViolation(.InvalidELFSection, "Section {} is invalid: {s}", .{ section_index, reason })) {
        return error.SecurityPolicyViolation;
    }
}

// Security audit mode - log all checks even if they pass
pub var audit_mode: bool = false;

pub fn enableAuditMode() void {
    audit_mode = true;
    serial.print("[SECURITY] Audit mode enabled - all security checks will be logged\r\n", .{}) catch {};
}

// Log successful security check (only in audit mode)
pub fn auditCheckPassed(comptime check_name: []const u8) void {
    if (audit_mode) {
        serial.print("[SECURITY] AUDIT: {s} - PASSED\r\n", .{check_name}) catch {};
    }
}

// Enhanced W^X validation for comprehensive ELF security
// This function validates all segments in an ELF file for W^X compliance
pub fn validateELFSegmentSecurity(program_headers: anytype, num_segments: usize) !void {
    var code_segments: usize = 0;
    var data_segments: usize = 0;
    var violations: usize = 0;

    const PF_W = 0x2; // Write permission
    const PF_X = 0x1; // Execute permission

    for (0..num_segments) |i| {
        const ph = &program_headers[i];
        if (ph.p_type != 1) continue; // Only check PT_LOAD segments

        const has_write = (ph.p_flags & PF_W) != 0;
        const has_exec = (ph.p_flags & PF_X) != 0;

        // Classify segment type
        if (has_exec) {
            code_segments += 1;
        } else if (has_write) {
            data_segments += 1;
        }

        // Individual segment validation
        checkWXViolation(i, ph.p_flags) catch |err| {
            violations += 1;
            if (err == error.WXViolation) {
                // Critical W^X violation - bail out immediately
                return err;
            }
            // Continue for other errors to collect all issues
        };
    }

    // Log segment analysis
    if (audit_mode or violations > 0) {
        try serial.print("[SECURITY] ELF Segment Analysis: {} code segments, {} data segments, {} violations\r\n", .{ code_segments, data_segments, violations });
    }

    // Validate overall ELF structure follows Intel guidelines
    if (code_segments == 0) {
        if (try reportViolation(.InvalidELFSection, "ELF has no executable segments (unusual for kernel)", .{})) {
            return error.NoExecutableSegments;
        }
    }

    if (violations > 0) {
        if (try reportViolation(.SecurityCheckFailed, "ELF failed security validation with {} violations", .{violations})) {
            return error.ELFSecurityViolations;
        }
    }

    auditCheckPassed("ELF W^X validation");
}
