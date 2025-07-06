// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Control Flow Integrity (CFI) implementation
//
// This module provides forward-edge and backward-edge control flow integrity
// following Intel x86 security guidelines and industry best practices.
//
// Features:
// - Forward-edge CFI for indirect calls (software-based)
// - Backward-edge CFI integration with Intel CET
// - Type-based function set validation
// - Runtime violation detection and reporting
// - Statistics tracking for security monitoring

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const speculation = @import("speculation.zig");
const stack_security = @import("stack_security.zig");
const cpu_init = @import("cpu_init.zig");
const cpuid = @import("cpuid.zig");

// CFI configuration
const CFI_ENABLED = true;
const CFI_STRICT_MODE = false; // If true, violations cause panic
const CFI_SHADOW_MEMORY_SIZE = 0x100000; // 1MB shadow memory for CFI metadata

// CET state for backward-edge CFI
var cet_enabled: bool = false;
var shadow_stack_enabled: bool = false;

// Function type signatures for validation
pub const FunctionType = enum(u32) {
    INVALID = 0,
    INTERRUPT_HANDLER = 0x49525148, // "IRQH"
    EXCEPTION_HANDLER = 0x45584348, // "EXCH"
    IO_VIOLATION_HANDLER = 0x494F5648, // "IOVH"
    TIMER_CALLBACK = 0x54494D48, // "TIMH"
    GENERIC_CALLBACK = 0x43414C4C, // "CALL"
    KERNEL_FUNCTION = 0x4B45524E, // "KERN"
};

// CFI metadata for functions
pub const FunctionMetadata = packed struct {
    magic: u32 = 0x43464921, // "CFI!"
    type: FunctionType,
    entry_point: u64,
    min_addr: u64,
    max_addr: u64,
    flags: u32,
};

// CFI violation types
pub const ViolationType = enum {
    INVALID_TARGET,
    TYPE_MISMATCH,
    OUT_OF_BOUNDS,
    CORRUPTED_METADATA,
    SHADOW_STACK_MISMATCH,
};

// CFI statistics
const CFIStats = struct {
    forward_checks: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    forward_violations: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    backward_checks: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    backward_violations: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    metadata_corruptions: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

var cfi_stats = CFIStats{};

// Shadow memory for CFI metadata (aligned to page boundary)
var cfi_shadow_memory: [CFI_SHADOW_MEMORY_SIZE]u8 align(0x1000) = [_]u8{0} ** CFI_SHADOW_MEMORY_SIZE;
var shadow_memory_offset: usize = 0;

// Function set registry for type-based CFI
const MAX_FUNCTION_SETS = 64;
const FunctionSet = struct {
    type: FunctionType,
    count: u32,
    functions: [256]u64, // Function addresses
};

var function_sets: [MAX_FUNCTION_SETS]FunctionSet = undefined;
var function_set_count: u32 = 0;

// Initialize CFI subsystem
pub fn init() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    serial.println("[CFI] Initializing Control Flow Integrity", .{});

    // Initialize function sets
    function_set_count = 0;
    for (&function_sets) |*set| {
        set.type = .INVALID;
        set.count = 0;
    }

    // Initialize shadow memory
    shadow_memory_offset = 0;
    @memset(&cfi_shadow_memory, 0);

    // Register kernel function types
    createFunctionSet(.INTERRUPT_HANDLER);
    createFunctionSet(.EXCEPTION_HANDLER);
    createFunctionSet(.IO_VIOLATION_HANDLER);
    createFunctionSet(.TIMER_CALLBACK);
    createFunctionSet(.KERNEL_FUNCTION);

    // Check for CET support and integrate with backward-edge CFI
    const features = cpuid.getFeatures();
    if (features.cet_ss) {
        cet_enabled = true;
        shadow_stack_enabled = true;
        serial.println("[CFI] Intel CET shadow stack detected - integrating with backward-edge CFI", .{});

        // Verify CET is actually enabled in CR4
        const cr4 = asm volatile ("mov %%cr4, %[ret]"
            : [ret] "=r" (-> u64),
        );
        if (cr4 & cpu_init.CR4_CET != 0) {
            serial.println("[CFI] CET enabled in CR4 - shadow stack protection active", .{});
        } else {
            serial.println("[CFI] WARNING: CET supported but not enabled in CR4", .{});
            cet_enabled = false;
            shadow_stack_enabled = false;
        }
    } else {
        serial.println("[CFI] Intel CET not available - using software-only CFI", .{});
    }

    serial.println("[CFI] Control Flow Integrity initialized", .{});
}

// Create a new function set for a specific type
fn createFunctionSet(func_type: FunctionType) void {
    if (function_set_count >= MAX_FUNCTION_SETS) {
        serial.println("[CFI] ERROR: Function set limit reached", .{});
        return;
    }

    var set = &function_sets[function_set_count];
    set.type = func_type;
    set.count = 0;
    function_set_count += 1;
}

// Register a function in the CFI system
pub fn registerFunction(
    entry_point: u64,
    func_type: FunctionType,
    size: u64,
) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Find the appropriate function set
    var set: ?*FunctionSet = null;
    for (function_sets[0..function_set_count]) |*s| {
        if (s.type == func_type) {
            set = s;
            break;
        }
    }

    if (set == null) {
        serial.println("[CFI] ERROR: Unknown function type: {}", .{@intFromEnum(func_type)});
        return error.UnknownFunctionType;
    }

    // Add to function set
    if (set.?.count >= 256) {
        return error.FunctionSetFull;
    }

    set.?.functions[set.?.count] = entry_point;
    set.?.count += 1;

    // Create metadata in shadow memory
    if (shadow_memory_offset + @sizeOf(FunctionMetadata) > CFI_SHADOW_MEMORY_SIZE) {
        return error.ShadowMemoryFull;
    }

    const metadata = @as(*FunctionMetadata, @ptrCast(@alignCast(&cfi_shadow_memory[shadow_memory_offset])));
    metadata.* = FunctionMetadata{
        .type = func_type,
        .entry_point = entry_point,
        .min_addr = entry_point,
        .max_addr = entry_point + size,
        .flags = 0,
    };

    shadow_memory_offset += @sizeOf(FunctionMetadata);

    serial.println("[CFI] Registered function at 0x{x:0>16} type: {}", .{ entry_point, @intFromEnum(func_type) });
}

// Validate an indirect call target (forward-edge CFI)
pub fn validateIndirectCall(
    target: u64,
    expected_type: FunctionType,
) bool {
    if (!CFI_ENABLED) return true;

    _ = cfi_stats.forward_checks.fetchAdd(1, .monotonic);

    // Add speculation barrier to prevent speculative bypass
    speculation.speculationBarrier();

    // Check if target is in the valid function set
    for (function_sets[0..function_set_count]) |*set| {
        if (set.type != expected_type) continue;

        for (set.functions[0..set.count]) |func_addr| {
            if (func_addr == target) {
                // Valid target found
                return true;
            }
        }
    }

    // Target not found in expected function set
    handleViolation(.TYPE_MISMATCH, target, expected_type);
    return false;
}

// Enhanced validation with bounds checking
pub fn validateIndirectCallEnhanced(
    target: u64,
    expected_type: FunctionType,
) bool {
    if (!CFI_ENABLED) return true;

    _ = cfi_stats.forward_checks.fetchAdd(1, .monotonic);

    // Add speculation barrier
    speculation.speculationBarrier();

    // Search shadow memory for metadata
    var offset: usize = 0;
    while (offset + @sizeOf(FunctionMetadata) <= shadow_memory_offset) : (offset += @sizeOf(FunctionMetadata)) {
        const metadata = @as(*const FunctionMetadata, @ptrCast(@alignCast(&cfi_shadow_memory[offset])));

        // Validate metadata magic
        if (metadata.magic != 0x43464921) {
            _ = cfi_stats.metadata_corruptions.fetchAdd(1, .monotonic);
            continue;
        }

        // Check if target matches
        if (target >= metadata.min_addr and target < metadata.max_addr) {
            if (metadata.type == expected_type) {
                return true;
            } else {
                handleViolation(.TYPE_MISMATCH, target, expected_type);
                return false;
            }
        }
    }

    // No metadata found for target
    handleViolation(.INVALID_TARGET, target, expected_type);
    return false;
}

// Handle CFI violation
fn handleViolation(
    violation_type: ViolationType,
    target: u64,
    expected_type: FunctionType,
) void {
    _ = cfi_stats.forward_violations.fetchAdd(1, .monotonic);

    serial.println(
        "[CFI] VIOLATION: {s} at target 0x{x:0>16}, expected type: {}",
        .{ @tagName(violation_type), target, @intFromEnum(expected_type) },
    );

    if (CFI_STRICT_MODE) {
        @panic("CFI violation detected");
    }
}

// Wrapper for safe indirect calls with CFI validation
pub fn safeIndirectCall(
    comptime ReturnType: type,
    target: anytype,
    expected_type: FunctionType,
    args: anytype,
) ReturnType {
    const target_addr = @intFromPtr(target);

    if (!validateIndirectCallEnhanced(target_addr, expected_type)) {
        if (CFI_STRICT_MODE) {
            @panic("CFI validation failed");
        }
        // Return zero-initialized value on failure
        return std.mem.zeroes(ReturnType);
    }

    // Perform the call
    return @call(.auto, target, args);
}

// Validate backward-edge control flow (integrated with CET)
pub fn validateReturnAddress(expected_return: u64) bool {
    if (!CFI_ENABLED) return true;

    _ = cfi_stats.backward_checks.fetchAdd(1, .monotonic);

    // If CET is enabled, the hardware provides backward-edge protection
    // We can still perform additional software validation
    if (shadow_stack_enabled) {
        // With CET, a mismatch would have already caused a #CP exception
        // This is an additional software check for defense in depth

        // Get shadow stack pointer (SSP)
        const ssp = cpu_init.readMSR(cpu_init.IA32_PL0_SSP);

        // The shadow stack grows down, so the return address is at SSP - 8
        if (ssp > 8) {
            const shadow_return = @as(*const u64, @ptrFromInt(ssp - 8)).*;
            if (shadow_return != expected_return) {
                _ = cfi_stats.backward_violations.fetchAdd(1, .monotonic);
                serial.println(
                    "[CFI] CET shadow stack mismatch: expected 0x{x:0>16}, got 0x{x:0>16}",
                    .{ expected_return, shadow_return },
                );
                return false;
            }
        }
    }

    // Traditional stack-based validation (always performed)
    const current_rsp = asm volatile ("mov %%rsp, %[rsp]"
        : [rsp] "=r" (-> u64),
    );
    const return_addr = @as(*const u64, @ptrFromInt(current_rsp)).*;

    if (return_addr != expected_return) {
        _ = cfi_stats.backward_violations.fetchAdd(1, .monotonic);
        serial.println(
            "[CFI] Return address mismatch: expected 0x{x:0>16}, got 0x{x:0>16}",
            .{ expected_return, return_addr },
        );
        return false;
    }

    return true;
}

// Get CFI statistics
pub fn getStatistics() CFIStats {
    return CFIStats{
        .forward_checks = std.atomic.Value(u64).init(cfi_stats.forward_checks.load(.monotonic)),
        .forward_violations = std.atomic.Value(u64).init(cfi_stats.forward_violations.load(.monotonic)),
        .backward_checks = std.atomic.Value(u64).init(cfi_stats.backward_checks.load(.monotonic)),
        .backward_violations = std.atomic.Value(u64).init(cfi_stats.backward_violations.load(.monotonic)),
        .metadata_corruptions = std.atomic.Value(u64).init(cfi_stats.metadata_corruptions.load(.monotonic)),
    };
}

// Print CFI statistics
pub fn printStatistics() void {
    const stats = getStatistics();
    serial.println("[CFI] Statistics:", .{});
    serial.println("  Forward-edge checks: {}", .{stats.forward_checks.raw});
    serial.println("  Forward-edge violations: {}", .{stats.forward_violations.raw});
    serial.println("  Backward-edge checks: {}", .{stats.backward_checks.raw});
    serial.println("  Backward-edge violations: {}", .{stats.backward_violations.raw});
    serial.println("  Metadata corruptions: {}", .{stats.metadata_corruptions.raw});
    serial.println("  CET enabled: {}", .{cet_enabled});
    serial.println("  Shadow stack enabled: {}", .{shadow_stack_enabled});
}

// Check if target has valid ENDBR64 instruction (for CET IBT)
fn hasValidENDBR64(target: u64) bool {
    // ENDBR64 is F3 0F 1E FA
    const endbr64_bytes = [_]u8{ 0xF3, 0x0F, 0x1E, 0xFA };

    // Read 4 bytes at target address
    const target_ptr = @as([*]const u8, @ptrFromInt(target));

    // Safely check if we can read the memory
    // In a real implementation, this would need proper bounds checking
    for (endbr64_bytes, 0..) |expected_byte, i| {
        if (target_ptr[i] != expected_byte) {
            return false;
        }
    }

    return true;
}

// Self-test for CFI
pub fn selfTest() !void {
    serial.println("[CFI] Running self-test...", .{});

    // Test function registration
    try registerFunction(0x1000, .KERNEL_FUNCTION, 0x100);
    try registerFunction(0x2000, .INTERRUPT_HANDLER, 0x200);

    // Test valid call
    if (!validateIndirectCall(0x1000, .KERNEL_FUNCTION)) {
        return error.CFISelfTestFailed;
    }

    // Test invalid type
    if (validateIndirectCall(0x1000, .INTERRUPT_HANDLER)) {
        return error.CFISelfTestFailed;
    }

    // Test invalid target
    if (validateIndirectCall(0x3000, .KERNEL_FUNCTION)) {
        return error.CFISelfTestFailed;
    }

    serial.println("[CFI] Self-test passed", .{});
}
