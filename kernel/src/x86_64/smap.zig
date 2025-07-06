// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// SMAP (Supervisor Mode Access Prevention) management
// Provides wrappers for safe user memory access with clac/stac instructions
// Following Intel x86-64 security guidelines
const std = @import("std");
const serial = @import("../drivers/serial.zig");
const cpuid = @import("cpuid.zig");
const stack_security = @import("stack_security.zig");

// SMAP violation statistics
var smap_violations: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var user_access_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var nested_access_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// Per-CPU nested access counter for safety (no threadlocal in kernel)
var nested_depth: u32 = 0;

// SMAP support flag
var smap_enabled: bool = false;

// Error types for SMAP operations
pub const SmapError = error{
    SmapNotSupported,
    NestedAccessDepthExceeded,
    InvalidUserPointer,
};

// Maximum nested user access depth
const MAX_NESTED_DEPTH: u32 = 8;

// Initialize SMAP support detection
pub fn init() void {
    const features = cpuid.getFeatures();
    smap_enabled = features.smap;

    if (smap_enabled) {
        serial.println("[SMAP] Supervisor Mode Access Prevention enabled", .{});
    } else {
        serial.println("[SMAP] WARNING: SMAP not supported on this CPU", .{});
    }
}

// Check if SMAP is enabled
pub fn isEnabled() bool {
    return smap_enabled;
}

// Clear AC flag (enable SMAP protection)
// This prevents kernel from accessing user memory
inline fn clac() void {
    if (smap_enabled) {
        asm volatile ("clac" ::: "memory", "cc");
    }
}

// Set AC flag (disable SMAP protection temporarily)
// This allows kernel to access user memory
inline fn stac() void {
    if (smap_enabled) {
        asm volatile ("stac" ::: "memory", "cc");
    }
}

// RAII guard for safe user memory access
pub const UserAccessGuard = struct {
    depth_on_entry: u32,
    enabled: bool,

    // Create a new user access guard
    pub fn init() !UserAccessGuard {
        var guard = stack_security.protect();
        defer guard.deinit();

        if (!smap_enabled) {
            return UserAccessGuard{
                .depth_on_entry = 0,
                .enabled = false,
            };
        }

        // Check nested depth
        if (nested_depth >= MAX_NESTED_DEPTH) {
            _ = smap_violations.fetchAdd(1, .monotonic);
            return SmapError.NestedAccessDepthExceeded;
        }

        const current_depth = nested_depth;
        nested_depth += 1;
        _ = user_access_count.fetchAdd(1, .monotonic);

        if (current_depth > 0) {
            _ = nested_access_count.fetchAdd(1, .monotonic);
        }

        // Disable SMAP protection
        stac();

        return UserAccessGuard{
            .depth_on_entry = current_depth,
            .enabled = true,
        };
    }

    // Cleanup - re-enable SMAP protection
    pub fn deinit(self: *UserAccessGuard) void {
        if (!self.enabled) return;

        // Re-enable SMAP protection
        clac();

        // Restore nested depth
        nested_depth = self.depth_on_entry;
    }
};

// Validate user pointer before access
pub fn validateUserPointer(ptr: usize, size: usize) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Check if pointer is in user space (below kernel base)
    const KERNEL_BASE = 0xFFFF800000000000; // x86-64 canonical kernel space

    if (ptr >= KERNEL_BASE or ptr + size >= KERNEL_BASE) {
        _ = smap_violations.fetchAdd(1, .monotonic);
        return SmapError.InvalidUserPointer;
    }

    // Check for integer overflow
    if (ptr + size < ptr) {
        _ = smap_violations.fetchAdd(1, .monotonic);
        return SmapError.InvalidUserPointer;
    }
}

// Copy data from user space to kernel space
pub fn copyFromUser(dest: []u8, user_ptr: usize) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Validate user pointer
    try validateUserPointer(user_ptr, dest.len);

    // Create SMAP guard
    var access_guard = try UserAccessGuard.init();
    defer access_guard.deinit();

    // Perform the copy with SMAP disabled
    const user_slice = @as([*]const u8, @ptrFromInt(user_ptr))[0..dest.len];
    @memcpy(dest, user_slice);
}

// Copy data from kernel space to user space
pub fn copyToUser(user_ptr: usize, src: []const u8) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Validate user pointer
    try validateUserPointer(user_ptr, src.len);

    // Create SMAP guard
    var access_guard = try UserAccessGuard.init();
    defer access_guard.deinit();

    // Perform the copy with SMAP disabled
    const user_slice = @as([*]u8, @ptrFromInt(user_ptr))[0..src.len];
    @memcpy(user_slice, src);
}

// Read a single value from user space
pub fn readUser(comptime T: type, user_ptr: usize) !T {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Validate user pointer
    try validateUserPointer(user_ptr, @sizeOf(T));

    // Create SMAP guard
    var access_guard = try UserAccessGuard.init();
    defer access_guard.deinit();

    // Read the value with SMAP disabled
    const ptr = @as(*const T, @ptrFromInt(user_ptr));
    return ptr.*;
}

// Write a single value to user space
pub fn writeUser(comptime T: type, user_ptr: usize, value: T) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Validate user pointer
    try validateUserPointer(user_ptr, @sizeOf(T));

    // Create SMAP guard
    var access_guard = try UserAccessGuard.init();
    defer access_guard.deinit();

    // Write the value with SMAP disabled
    const ptr = @as(*T, @ptrFromInt(user_ptr));
    ptr.* = value;
}

// Zero user memory
pub fn zeroUser(user_ptr: usize, size: usize) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Validate user pointer
    try validateUserPointer(user_ptr, size);

    // Create SMAP guard
    var access_guard = try UserAccessGuard.init();
    defer access_guard.deinit();

    // Zero the memory with SMAP disabled
    const user_slice = @as([*]u8, @ptrFromInt(user_ptr))[0..size];
    @memset(user_slice, 0);
}

// String operations with user memory
pub fn strlenUser(user_ptr: usize, max_len: usize) !usize {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Validate at least one byte can be read
    try validateUserPointer(user_ptr, 1);

    // Create SMAP guard
    var access_guard = try UserAccessGuard.init();
    defer access_guard.deinit();

    // Find string length with SMAP disabled
    const user_str = @as([*]const u8, @ptrFromInt(user_ptr));
    var len: usize = 0;

    while (len < max_len) : (len += 1) {
        // Validate each page boundary crossing
        if ((user_ptr + len) & 0xFFF == 0) {
            // Re-validate on page boundary
            try validateUserPointer(user_ptr + len, 1);
        }

        if (user_str[len] == 0) {
            return len;
        }
    }

    return max_len;
}

// Copy string from user space
pub fn copyStringFromUser(dest: []u8, user_ptr: usize) ![]u8 {
    var guard = stack_security.protect();
    defer guard.deinit();

    const max_len = dest.len - 1; // Leave room for null terminator
    const str_len = try strlenUser(user_ptr, max_len);

    // Copy the string
    try copyFromUser(dest[0..str_len], user_ptr);
    dest[str_len] = 0; // Null terminate

    return dest[0..str_len];
}

// Execute a function with user memory access
pub fn withUserAccess(comptime func: anytype, args: anytype) !@typeInfo(@TypeOf(func)).Fn.return_type.? {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Create SMAP guard
    var access_guard = try UserAccessGuard.init();
    defer access_guard.deinit();

    // Execute the function with SMAP disabled
    return @call(.auto, func, args);
}

// Get SMAP statistics
pub fn getStats() struct {
    violations: u64,
    user_accesses: u64,
    nested_accesses: u64,
    smap_enabled: bool,
} {
    return .{
        .violations = smap_violations.load(.monotonic),
        .user_accesses = user_access_count.load(.monotonic),
        .nested_accesses = nested_access_count.load(.monotonic),
        .smap_enabled = smap_enabled,
    };
}

// Print SMAP statistics
pub fn printStats() void {
    const stats = getStats();

    serial.println("\n=== SMAP Security Statistics ===", .{});
    serial.println("SMAP Enabled: {}", .{stats.smap_enabled});
    serial.println("User Memory Accesses: {}", .{stats.user_accesses});
    serial.println("Nested User Accesses: {}", .{stats.nested_accesses});
    serial.println("SMAP Violations: {}", .{stats.violations});
}

// Test SMAP functionality (for debugging)
pub fn testSMAP() void {
    if (!smap_enabled) {
        serial.println("[SMAP] Test skipped - SMAP not supported", .{});
        return;
    }

    serial.println("[SMAP] Running SMAP functionality test...", .{});

    // Test basic clac/stac instructions
    serial.println("[SMAP] Testing clac/stac instructions...", .{});

    // Enable SMAP protection (clac)
    clac();
    serial.println("[SMAP] Executed clac (SMAP protection enabled)", .{});

    // Disable SMAP protection (stac)
    stac();
    serial.println("[SMAP] Executed stac (SMAP protection temporarily disabled)", .{});

    // Re-enable SMAP protection (clac)
    clac();
    serial.println("[SMAP] Executed clac (SMAP protection re-enabled)", .{});

    serial.println("[SMAP] Basic clac/stac test completed successfully", .{});

    // Test access guard
    serial.println("[SMAP] Testing UserAccessGuard...", .{});
    if (UserAccessGuard.init()) |guard| {
        var mutable_guard = guard;
        defer mutable_guard.deinit();

        serial.println("[SMAP] UserAccessGuard created successfully", .{});
    } else |err| {
        serial.println("[SMAP] UserAccessGuard creation failed: {s}", .{@errorName(err)});
    }

    printStats();
}
