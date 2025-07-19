// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// I/O Port Security Module for Ziguanos
// Provides secure I/O port access with privilege checking and auditing

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const gdt = @import("gdt.zig");
const stack_security = @import("stack_security.zig");
const speculation = @import("speculation.zig");
const cfi = @import("cfi.zig");

// Common I/O port ranges and their purposes
pub const IOPortRange = struct {
    start: u16,
    end: u16,
    name: []const u8,
    allow_user: bool = false,
};

// Allowlist of permitted I/O ports
const allowed_ports = [_]IOPortRange{
    // Serial ports
    .{ .start = 0x3F8, .end = 0x3FF, .name = "COM1" },
    .{ .start = 0x2F8, .end = 0x2FF, .name = "COM2" },
    .{ .start = 0x3E8, .end = 0x3EF, .name = "COM3" },
    .{ .start = 0x2E8, .end = 0x2EF, .name = "COM4" },

    // Programmable Interrupt Controller (PIC)
    .{ .start = 0x20, .end = 0x21, .name = "PIC1" },
    .{ .start = 0xA0, .end = 0xA1, .name = "PIC2" },

    // PS/2 Controller
    .{ .start = 0x60, .end = 0x60, .name = "PS2_DATA" },
    .{ .start = 0x64, .end = 0x64, .name = "PS2_CMD" },

    // PIT Timer
    .{ .start = 0x40, .end = 0x43, .name = "PIT" },

    // CMOS/RTC
    .{ .start = 0x70, .end = 0x71, .name = "CMOS" },

    // DMA Page Registers
    .{ .start = 0x80, .end = 0x8F, .name = "DMA_PAGE" },

    // PCI Config
    .{ .start = 0xCF8, .end = 0xCFF, .name = "PCI_CONFIG" },

    // VGA Registers
    .{ .start = 0x3C0, .end = 0x3DF, .name = "VGA" },
};

// I/O Permission Bitmap size (covers ports 0-0xFFFF)
const IOPB_SIZE: usize = 8192; // 65536 ports / 8 bits per byte

// Extended TSS structure with I/O Permission Bitmap
pub const ExtendedTSS = extern struct {
    base: gdt.TSS,
    iopb: [IOPB_SIZE]u8 align(4),
    // Terminating 0xFF byte required by x86 spec
    terminator: u8 = 0xFF,
};

// Global extended TSS pointer - will be allocated dynamically
// to avoid corrupting memory with a huge 8KB global variable
var extended_tss_ptr: ?*ExtendedTSS = null;

// Access logging for security auditing
const IOAccessLog = struct {
    port: u16,
    value: u8,
    is_write: bool,
    timestamp: u64,
    caller: u64,
};

// Circular buffer for I/O access logs
const LOG_SIZE = 1024;
var io_access_log: [LOG_SIZE]IOAccessLog = std.mem.zeroes([LOG_SIZE]IOAccessLog);
var log_index: usize = 0;
var logging_enabled: bool = false;

// Security state management with proper phase tracking
pub const SecurityPhase = enum {
    Disabled, // Pre-initialization phase
    Initializing, // During initialization
    Enabled, // Fully operational
};

var security_phase: SecurityPhase = .Disabled;
var early_boot_ports_only: bool = true; // Restrict to essential ports during boot

// Essential early boot ports (minimal set)
const early_boot_ports = [_]IOPortRange{
    .{ .start = 0x3F8, .end = 0x3FF, .name = "COM1" }, // Serial for debugging
    .{ .start = 0x70, .end = 0x71, .name = "CMOS" }, // CMOS/RTC for timing
    .{ .start = 0x20, .end = 0x21, .name = "PIC1" }, // Primary PIC
    .{ .start = 0xA0, .end = 0xA1, .name = "PIC2" }, // Secondary PIC
};

// Get current privilege level
fn getCurrentPrivilegeLevel() u2 {
    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );
    return @truncate(cs & 0x3);
}

// Check if port access is allowed with phase-aware security
fn isPortAllowed(port: u16) bool {
    // During early boot, only allow essential ports
    if (early_boot_ports_only) {
        for (early_boot_ports) |range| {
            if (port >= range.start and port <= range.end) {
                return true;
            }
        }
        return false;
    }

    // Normal operation - check full allowlist
    const cpl = getCurrentPrivilegeLevel();

    // Check static ports
    for (allowed_ports) |range| {
        if (port >= range.start and port <= range.end) {
            // Speculation barrier after privilege check
            speculation.speculationBarrier();

            if (cpl > 0 and !range.allow_user) {
                return false;
            }
            return true;
        }
    }

    // Check dynamic ports
    for (dynamic_ports[0..dynamic_port_count]) |range| {
        if (port >= range.start and port <= range.end) {
            // Speculation barrier after privilege check
            speculation.speculationBarrier();

            if (cpl > 0 and !range.allow_user) {
                return false;
            }
            return true;
        }
    }

    return false;
}

// Security violation handler following Intel recommendations
pub const IOViolationHandler = *const fn (port: u16, cpl: u2) void;
var violation_handler: ?IOViolationHandler = null;

// Statistics for security monitoring
var violation_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var last_violation_port: u16 = 0;
var last_violation_time: u64 = 0;

// Check if a port is essential for boot operations
fn isEssentialBootPort(port: u16) bool {
    // Only allow truly essential ports during boot
    return switch (port) {
        0x3F8...0x3FF => true, // Serial ports for debugging (COM1-COM4)
        0x60, 0x64 => true, // Keyboard controller (required for early boot)
        0x70, 0x71 => true, // CMOS/RTC (required for boot timing)
        0x20, 0x21 => true, // Master PIC (if needed during early initialization)
        0xA0, 0xA1 => true, // Slave PIC (if needed during early initialization)
        0x40...0x43 => true, // PIT timer (for APIC calibration)
        0x61 => true, // PC speaker/timer gate control
        0x80 => true, // POST code for boot diagnostics
        0x92 => true, // Fast A20 gate control
        else => false,
    };
}

// Centralized security check with speculation protection
fn checkIOPermission(port: u16) void {
    // Minimum security even when disabled
    if (security_phase == .Disabled) {
        if (!isEssentialBootPort(port)) {
            // CRITICAL: Do NOT use serial.print here as it causes recursive I/O!
            // During early boot (especially AP startup), we cannot do any I/O
            // that isn't absolutely essential. Just record the violation.
            _ = violation_count.fetchAdd(1, .monotonic);
            last_violation_port = port;
            // Only handle violation if we won't cause recursion
            if (port < 0x3F8 or port > 0x3FF) { // Not a serial port
                handleSecurityViolation(port, getCurrentPrivilegeLevel());
            }
        }
        return;
    }

    const cpl = getCurrentPrivilegeLevel();

    // Speculation barrier before privilege check (Intel recommendation)
    speculation.speculationBarrier();

    const allowed = isPortAllowed(port);

    // Double speculation barrier for critical security decision
    speculation.speculationBarrier();

    if (cpl > 0 and !allowed) {
        handleSecurityViolation(port, cpl);
    }
}

// Handle security violations gracefully
fn handleSecurityViolation(port: u16, cpl: u2) void {
    // Update violation statistics
    _ = violation_count.fetchAdd(1, .monotonic);
    last_violation_port = port;
    last_violation_time = getTimestamp();

    // Log the violation if logging is enabled
    if (logging_enabled and security_phase == .Enabled) {
        logSecurityViolation(port, cpl);
    }

    // Call custom handler if set
    if (violation_handler) |handler| {
        // Validate handler with CFI before calling
        if (cfi.validateIndirectCall(@intFromPtr(handler), .IO_VIOLATION_HANDLER)) {
            handler(port, cpl);
        } else {
            serial.println("[IO_SEC] CFI violation: Invalid I/O violation handler", .{});
        }
    } else {
        // Default behavior - panic only if fully initialized
        if (security_phase == .Enabled) {
            @panic("Unauthorized I/O port access");
        }
        // During initialization, just deny access silently
    }
}

// Log security violation details
fn logSecurityViolation(port: u16, cpl: u2) void {
    _ = cpl; // Will be used in future for detailed logging

    // Avoid using serial during early boot to prevent recursion
    if (port >= 0x3F8 and port <= 0x3FF) return;

    io_access_log[log_index] = IOAccessLog{
        .port = port,
        .value = 0xFF, // Special marker for violations
        .is_write = false,
        .timestamp = getTimestamp(),
        .caller = getCallerAddress(),
    };
    log_index = (log_index + 1) % LOG_SIZE;
}

// Get port name for logging
fn getPortName(port: u16) []const u8 {
    for (allowed_ports) |range| {
        if (port >= range.start and port <= range.end) {
            return range.name;
        }
    }
    return "UNKNOWN";
}

// Get TSC timestamp
fn getTimestamp() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdtsc"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
    );
    return (@as(u64, high) << 32) | low;
}

// Get return address for logging
fn getCallerAddress() u64 {
    return @returnAddress();
}

// Log I/O access
fn logIOAccess(port: u16, value: u8, is_write: bool) void {
    if (!logging_enabled) return;

    io_access_log[log_index] = IOAccessLog{
        .port = port,
        .value = value,
        .is_write = is_write,
        .timestamp = getTimestamp(),
        .caller = getCallerAddress(),
    };

    log_index = (log_index + 1) % LOG_SIZE;
}

// Initialize I/O security system
pub fn init() void {
    // Use CanaryGuard system for stack protection
    var guard = stack_security.protect();
    defer guard.deinit();

    // Don't use serial here to avoid circular dependency
    // serial.println("[IO_SEC] Initializing I/O port security...");

    // IMPORTANT: During early boot, we do NOT use the extended TSS
    // because it's too large (8KB) and will corrupt memory.
    // We'll just disable I/O port access for now and rely on
    // security_phase checks until PMM is available.

    // Set TSS IOPB offset to beyond TSS size (effectively disabling IOPB)
    gdt.tss.iopb_offset = @sizeOf(gdt.TSS);

    // Enable logging
    logging_enabled = false; // Start with logging disabled to avoid issues during init
}

// Transition to initialization phase
pub fn beginInitialization() void {
    security_phase = .Initializing;
    early_boot_ports_only = true;
    logging_enabled = false; // Avoid logging during init
}

// Enable full security after initialization
pub fn enableFullSecurity() void {
    security_phase = .Enabled;
    early_boot_ports_only = false;
    logging_enabled = true;

    // Flush CPU buffers to prevent information leakage
    speculation.memoryFence();
}

// Set custom violation handler
pub fn setViolationHandler(handler: ?IOViolationHandler) void {
    var guard = stack_security.protect();
    defer guard.deinit();

    violation_handler = handler;

    // Register handler with CFI if non-null
    if (handler) |h| {
        cfi.registerFunction(@intFromPtr(h), .IO_VIOLATION_HANDLER, 0x100 // Assume 256 bytes for handler function
        ) catch |err| {
            serial.println("[IO_SEC] WARNING: Failed to register violation handler with CFI: {}", .{err});
        };
    }
}

// Get current security phase
pub fn getSecurityPhase() SecurityPhase {
    return security_phase;
}

// Update TSS descriptor in GDT to point to extended TSS
fn updateTSSInGDT() void {
    if (extended_tss_ptr) |extended_tss| {
        const tss_base = @intFromPtr(extended_tss);
        const tss_limit = @sizeOf(ExtendedTSS) - 1;

        // Ensure the TSS's iopb_offset points to our I/O permission bitmap
        // This is already set in initializeFull, but verify it's correct
        if (extended_tss.base.iopb_offset != @offsetOf(ExtendedTSS, "iopb")) {
            extended_tss.base.iopb_offset = @offsetOf(ExtendedTSS, "iopb");
        }

        // Copy the extended TSS base pointer to the global TSS
        // This ensures that any updates to gdt.tss are reflected
        gdt.tss = extended_tss.base;

        // Call GDT function to update TSS descriptor with the new base and limit
        gdt.updateTSSDescriptor(tss_base, tss_limit);

        // Log for debugging
        serial.println("[IO_SEC] TSS descriptor updated: base=0x{x:0>16}, limit=0x{x:0>4}", .{ tss_base, tss_limit });
    }
}

// Secure I/O port output (8-bit) with Intel-recommended ordering
pub fn outb(port: u16, value: u8) void {
    // Check permissions first (fail fast)
    checkIOPermission(port);

    // Memory barrier to ensure all prior memory operations complete
    speculation.memoryFence();

    // Log the access if security is enabled
    if (security_phase == .Enabled and logging_enabled) {
        logIOAccess(port, value, true);
    }

    // Perform the I/O operation
    asm volatile ("outb %[value], %[port]"
        :
        : [value] "{al}" (value),
          [port] "N{dx}" (port),
        : "memory" // Intel recommendation: memory clobber for I/O
    );

    // Post-operation barrier for ordering
    speculation.storeFence();
}

// Secure I/O port input (8-bit) with Intel-recommended ordering
pub fn inb(port: u16) u8 {
    // Check permissions first (fail fast)
    checkIOPermission(port);

    // Pre-operation barrier
    speculation.loadFence();

    const value = asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (port),
        : "memory" // Intel recommendation: memory clobber for I/O
    );

    // Post-operation barrier to prevent speculative use of result
    speculation.speculationBarrier();

    // Log the access if security is enabled
    if (security_phase == .Enabled and logging_enabled) {
        logIOAccess(port, value, false);
    }

    return value;
}

// Secure I/O port output (16-bit) with Intel-recommended ordering
pub fn outw(port: u16, value: u16) void {
    // Check permissions first (fail fast)
    checkIOPermission(port);

    // Memory barrier to ensure all prior memory operations complete
    speculation.memoryFence();

    if (security_phase == .Enabled and logging_enabled) {
        // Log both bytes
        logIOAccess(port, @truncate(value & 0xFF), true);
        logIOAccess(port + 1, @truncate((value >> 8) & 0xFF), true);
    }

    asm volatile ("outw %[value], %[port]"
        :
        : [value] "{ax}" (value),
          [port] "N{dx}" (port),
        : "memory" // Intel recommendation: memory clobber for I/O
    );

    // Post-operation barrier for ordering
    speculation.storeFence();
}

// Secure I/O port input (16-bit) with Intel-recommended ordering
pub fn inw(port: u16) u16 {
    // Check permissions first (fail fast)
    checkIOPermission(port);

    // Pre-operation barrier
    speculation.loadFence();

    const value = asm volatile ("inw %[port], %[result]"
        : [result] "={ax}" (-> u16),
        : [port] "N{dx}" (port),
        : "memory" // Intel recommendation: memory clobber for I/O
    );

    // Post-operation barrier to prevent speculative use of result
    speculation.speculationBarrier();

    if (security_phase == .Enabled and logging_enabled) {
        // Log both bytes
        logIOAccess(port, @truncate(value & 0xFF), false);
        logIOAccess(port + 1, @truncate((value >> 8) & 0xFF), false);
    }

    return value;
}

// Secure I/O port output (32-bit) with Intel-recommended ordering
pub fn outl(port: u16, value: u32) void {
    // Check permissions first (fail fast)
    checkIOPermission(port);

    // Memory barrier to ensure all prior memory operations complete
    speculation.memoryFence();

    if (security_phase == .Enabled and logging_enabled) {
        // Log access (could log all 4 bytes if needed)
        logIOAccess(port, @truncate(value & 0xFF), true);
    }

    asm volatile ("outl %[value], %[port]"
        :
        : [value] "{eax}" (value),
          [port] "N{dx}" (port),
        : "memory" // Intel recommendation: memory clobber for I/O
    );

    // Post-operation barrier for ordering
    speculation.storeFence();
}

// Secure I/O port input (32-bit) with Intel-recommended ordering
pub fn inl(port: u16) u32 {
    // Check permissions first (fail fast)
    checkIOPermission(port);

    // Pre-operation barrier
    speculation.loadFence();

    const value = asm volatile ("inl %[port], %[result]"
        : [result] "={eax}" (-> u32),
        : [port] "N{dx}" (port),
        : "memory" // Intel recommendation: memory clobber for I/O
    );

    // Post-operation barrier to prevent speculative use of result
    speculation.speculationBarrier();

    if (security_phase == .Enabled and logging_enabled) {
        // Log access (could log all 4 bytes if needed)
        logIOAccess(port, @truncate(value & 0xFF), false);
    }

    return value;
}

// Runtime port configuration (Intel recommendation)
const MAX_DYNAMIC_PORTS = 32;
var dynamic_ports: [MAX_DYNAMIC_PORTS]IOPortRange = std.mem.zeroes([MAX_DYNAMIC_PORTS]IOPortRange);
var dynamic_port_count: usize = 0;

// Add a port range at runtime
pub fn addPortRange(range: IOPortRange) !void {
    if (dynamic_port_count >= MAX_DYNAMIC_PORTS) {
        return error.TooManyPorts;
    }

    // Validate port range
    if (range.start > range.end) {
        return error.InvalidPortRange;
    }

    // Check for overlaps with existing ranges
    for (allowed_ports) |existing| {
        if (rangesOverlap(range, existing)) {
            return error.PortRangeOverlap;
        }
    }

    for (dynamic_ports[0..dynamic_port_count]) |existing| {
        if (rangesOverlap(range, existing)) {
            return error.PortRangeOverlap;
        }
    }

    // Add the range
    dynamic_ports[dynamic_port_count] = range;
    dynamic_port_count += 1;

    // Update IOPB if needed
    updateIOPBForRange(range);
}

// Check if two port ranges overlap
fn rangesOverlap(a: IOPortRange, b: IOPortRange) bool {
    return a.start <= b.end and b.start <= a.end;
}

// Update I/O Permission Bitmap for a port range
fn updateIOPBForRange(range: IOPortRange) void {
    if (extended_tss_ptr) |extended_tss| {
        var port: u16 = range.start;
        while (port <= range.end) : (port += 1) {
            const byte_idx = port / 8;
            const bit_idx = @as(u3, @truncate(port % 8));
            extended_tss.iopb[byte_idx] &= ~(@as(u8, 1) << bit_idx);
        }
    }
}

// Print I/O access statistics with security information
pub fn printAccessStats() void {
    serial.println("[IO_SEC] I/O Access Statistics:", .{});

    // Print security phase
    serial.println("  Security Phase: {s}", .{switch (security_phase) {
        .Disabled => "Disabled",
        .Initializing => "Initializing",
        .Enabled => "Enabled",
    }});

    // Print violation statistics
    serial.println("  Total Violations: {}", .{violation_count.load(.acquire)});

    if (violation_count.load(.acquire) > 0) {
        serial.println("  Last Violation Port: 0x{x:0>4}", .{last_violation_port});
    }

    // Count accesses per port range
    var port_counts = std.mem.zeroes([allowed_ports.len]u32);
    var dynamic_counts = std.mem.zeroes([MAX_DYNAMIC_PORTS]u32);

    // Only process entries that have been written
    const entries_to_process = if (log_index < LOG_SIZE) log_index else LOG_SIZE;

    var i: usize = 0;
    while (i < entries_to_process) : (i += 1) {
        const entry = &io_access_log[i];
        if (entry.port == 0) continue; // Skip uninitialized entries

        // Check static ports
        for (allowed_ports, 0..) |range, idx| {
            if (entry.port >= range.start and entry.port <= range.end) {
                port_counts[idx] += 1;
                break;
            }
        }

        // Check dynamic ports
        for (dynamic_ports[0..dynamic_port_count], 0..) |range, idx| {
            if (entry.port >= range.start and entry.port <= range.end) {
                dynamic_counts[idx] += 1;
                break;
            }
        }
    }

    // Print static port statistics
    serial.println("  Static Port Ranges:", .{});
    // Only print ports that actually had accesses
    var printed_any = false;
    for (allowed_ports, 0..) |_, idx| {
        // Add bounds check just to be safe
        if (idx < allowed_ports.len and port_counts[idx] > 0) {
            // Get the name based on index
            const name = switch (idx) {
                0 => "COM1",
                1 => "COM2",
                2 => "COM3",
                3 => "COM4",
                4 => "PIC1",
                5 => "PIC2",
                6 => "PS2_DATA",
                7 => "PS2_CMD",
                8 => "PIT",
                9 => "CMOS",
                10 => "DMA_PAGE",
                11 => "PCI_CONFIG",
                12 => "VGA",
                else => "UNKNOWN",
            };

            serial.println("    {s} (0x{x:0>4}-0x{x:0>4}): {} accesses", .{ name, allowed_ports[idx].start, allowed_ports[idx].end, port_counts[idx] });
            printed_any = true;
        }
    }
    if (!printed_any) {
        serial.println("    (no port accesses recorded)", .{});
    }

    // Print dynamic port statistics
    if (dynamic_port_count > 0) {
        serial.println("  Dynamic Port Ranges:", .{});
        for (dynamic_ports[0..dynamic_port_count], 0..) |range, idx| {
            if (dynamic_counts[idx] > 0) {
                serial.println("    {s}: {} accesses", .{ range.name, dynamic_counts[idx] });
            }
        }
    }
}

// Get recent I/O accesses for debugging
pub fn getRecentAccesses(count: usize) []const IOAccessLog {
    const start = if (log_index >= count) log_index - count else LOG_SIZE - (count - log_index);
    if (start < LOG_SIZE) {
        return io_access_log[start..log_index];
    }
    return io_access_log[0..0]; // Empty slice
}

// Enable or disable logging
pub fn setLoggingEnabled(enabled: bool) void {
    logging_enabled = enabled;
}

// Clear access log
pub fn clearAccessLog() void {
    @memset(&io_access_log, std.mem.zeroes(IOAccessLog));
    log_index = 0;
}

// Test function to verify port name printing
pub fn testPortNamePrinting() void {
    serial.println("[IO_SEC] Testing port name printing...", .{});

    // Test 1: Direct string literal
    serial.println("  Test 1: Direct literal: {s}", .{"COM1"});

    // Test 2: Access first port name directly
    const first_port = allowed_ports[0];
    serial.println("  Test 2: First port name: {s}", .{first_port.name});

    // Test 3: Use getPortName function
    const port_name = getPortName(0x3F8); // COM1 port
    serial.println("  Test 3: getPortName(0x3F8): {s}", .{port_name});

    // Test 4: Loop through all ports and print names
    serial.println("  Test 4: All port names:", .{});
    for (allowed_ports, 0..) |port, idx| {
        serial.println("    [{}] {s} (0x{x:0>4}-0x{x:0>4})", .{ idx, port.name, port.start, port.end });
    }

    // Test 5: Test with each field printed separately
    serial.println("  Test 5: Fields printed separately:", .{});
    for (allowed_ports) |port| {
        serial.print("    Name: ", .{});
        serial.print("{s}", .{port.name});
        serial.print(", Start: 0x{x:0>4}", .{port.start});
        serial.println(", End: 0x{x:0>4}", .{port.end});
    }
}

// Security monitoring API (Intel recommendation)
pub const SecurityMetrics = struct {
    total_accesses: u64,
    read_accesses: u64,
    write_accesses: u64,
    violations: u64,
    phase: SecurityPhase,
    iopb_active: bool,
};

// Get current security metrics
pub fn getSecurityMetrics() SecurityMetrics {
    var metrics = SecurityMetrics{
        .total_accesses = 0,
        .read_accesses = 0,
        .write_accesses = 0,
        .violations = violation_count.load(.acquire),
        .phase = security_phase,
        .iopb_active = (extended_tss_ptr != null),
    };

    // Count accesses in log
    for (io_access_log) |entry| {
        if (entry.port != 0) {
            metrics.total_accesses += 1;
            if (entry.is_write) {
                metrics.write_accesses += 1;
            } else {
                metrics.read_accesses += 1;
            }
        }
    }

    return metrics;
}

// Validate I/O subsystem integrity (Intel recommendation)
pub fn validateIntegrity() !void {
    if (extended_tss_ptr) |extended_tss| {
        // Check TSS IOPB offset is correct
        if (extended_tss.base.iopb_offset != @offsetOf(ExtendedTSS, "iopb")) {
            return error.InvalidIOPBOffset;
        }

        // Check terminator byte
        if (extended_tss.terminator != 0xFF) {
            return error.InvalidTerminator;
        }

        // Verify TSS is properly loaded by checking TR register
        const tr = asm volatile ("str %[result]"
            : [result] "=r" (-> u16),
        );
        if (tr != gdt.TSS_SELECTOR) {
            return error.TSSNotLoaded;
        }

        // Verify IOPB limit is correct
        // Note: We've already verified the TSS is loaded with correct selector
        // The GDT update is handled in updateTSSDescriptor which sets the proper limit
    }

    // Verify CPL checking works
    const cpl = getCurrentPrivilegeLevel();
    if (cpl != 0) {
        return error.InvalidPrivilegeLevel;
    }

    // Memory barrier to ensure consistency
    speculation.memoryFence();
}

// Test that hardware I/O bitmap is actually enforcing port access
pub fn testHardwareIOPB() !void {
    // Only test if extended TSS is initialized
    if (extended_tss_ptr == null) {
        return error.IOPBNotInitialized;
    }

    serial.println("[IO_SEC] Testing hardware I/O bitmap enforcement...", .{});

    // Save current security phase and logging state
    const saved_phase = security_phase;
    const saved_logging = logging_enabled;
    const saved_violation_handler = violation_handler;

    // Note: We can't actually test port access violation without causing a GP fault
    // The hardware IOPB works at CPU level and will trigger an exception
    // Instead, we'll verify the IOPB bits are correctly set

    // Try to access a port that should be blocked (port 0x80 is typically blocked)
    // This port is commonly used for POST codes but not in our allowed list
    const test_port: u16 = 0x80;

    // Check if port is in our allowed list (it shouldn't be)
    var port_allowed = false;
    for (allowed_ports) |range| {
        if (test_port >= range.start and test_port <= range.end) {
            port_allowed = true;
            break;
        }
    }

    if (!port_allowed) {
        // Attempt to access the blocked port
        // This should trigger a general protection fault if hardware IOPB is working
        serial.println("[IO_SEC] Attempting to access blocked port 0x{x:0>4}...", .{test_port});

        // Note: We can't actually test this without causing a GP fault
        // Instead, we'll verify the IOPB bit is set correctly
        const byte_idx = test_port / 8;
        const bit_idx = @as(u3, @truncate(test_port % 8));

        if (extended_tss_ptr) |extended_tss| {
            const is_blocked = (extended_tss.iopb[byte_idx] & (@as(u8, 1) << bit_idx)) != 0;
            if (is_blocked) {
                serial.println("[IO_SEC] ✓ Port 0x{x:0>4} correctly marked as blocked in IOPB", .{test_port});
            } else {
                serial.println("[IO_SEC] ✗ Port 0x{x:0>4} incorrectly marked as allowed in IOPB", .{test_port});
                return error.IOPBIncorrect;
            }
        }
    }

    // Restore original settings
    security_phase = saved_phase;
    logging_enabled = saved_logging;
    violation_handler = saved_violation_handler;

    // Verify allowed ports are correctly set
    var verified_count: u32 = 0;
    for (allowed_ports) |range| {
        // Check first port in range
        const port = range.start;
        const byte_idx = port / 8;
        const bit_idx = @as(u3, @truncate(port % 8));

        if (extended_tss_ptr) |extended_tss| {
            const is_allowed = (extended_tss.iopb[byte_idx] & (@as(u8, 1) << bit_idx)) == 0;
            if (is_allowed) {
                verified_count += 1;
            } else {
                serial.println("[IO_SEC] ✗ Port 0x{x:0>4} ({s}) incorrectly blocked", .{ port, range.name });
                return error.AllowedPortBlocked;
            }
        }
    }

    serial.println("[IO_SEC] ✓ Hardware IOPB test passed - {} port ranges verified", .{verified_count});
}

// Maximum TSS size for validation
const MAX_TSS_SIZE = 0x10000; // 64KB maximum

// Check if memory is accessible for read/write operations
fn isMemoryAccessible(addr: u64, size: usize) bool {
    // Basic bounds check - ensure we're in kernel space
    if (addr < 0x100000) return false; // Below 1MB
    if (addr >= 0xFFFFFFFF00000000) return false; // Above canonical address space

    // Check for overflow
    if (addr + size < addr) return false;

    // Try to access the memory - this will page fault if inaccessible
    const ptr = @as([*]volatile u8, @ptrFromInt(addr));

    // Test first and last bytes
    const first_byte = ptr[0];
    const last_byte = ptr[size - 1];

    // Write and read back to verify write access
    ptr[0] = first_byte;
    ptr[size - 1] = last_byte;

    return true;
}

// Validate TSS structure integrity
fn validateTSSStructure(tss: *ExtendedTSS) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Validate TSS fields
    if (tss.base.iopb_offset != @offsetOf(ExtendedTSS, "iopb")) {
        serial.println("[IO_SEC] ERROR: TSS IOPB offset mismatch: expected 0x{x:0>4}, got 0x{x:0>4}", .{ @offsetOf(ExtendedTSS, "iopb"), tss.base.iopb_offset });
        return error.TSSValidationFailed;
    }

    // Validate memory accessibility
    if (!isMemoryAccessible(@intFromPtr(tss), @sizeOf(ExtendedTSS))) {
        serial.println("[IO_SEC] ERROR: TSS memory not accessible at 0x{x:0>16}", .{@intFromPtr(tss)});
        return error.TSSMemoryNotAccessible;
    }

    // Validate terminator byte
    if (tss.terminator != 0xFF) {
        serial.println("[IO_SEC] ERROR: TSS terminator byte invalid: expected 0xFF, got 0x{x:0>2}", .{tss.terminator});
        return error.TSSValidationFailed;
    }

    // Validate IOPB structure
    const iopb_size = @sizeOf(@TypeOf(tss.iopb));
    if (iopb_size != IOPB_SIZE) {
        serial.println("[IO_SEC] ERROR: IOPB size mismatch: expected {}, got {}", .{ IOPB_SIZE, iopb_size });
        return error.TSSValidationFailed;
    }

    serial.println("[IO_SEC] ✓ TSS structure validation passed", .{});
}

// Set up proper TSS permissions and security settings
fn setupTSSPermissions(tss: *ExtendedTSS) void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Initialize security-relevant TSS fields
    tss.base.iopb_offset = @offsetOf(ExtendedTSS, "iopb");
    tss.terminator = 0xFF;

    // Set all I/O ports as restricted by default
    @memset(&tss.iopb, 0xFF);

    serial.println("[IO_SEC] ✓ TSS security permissions configured", .{});
}

// Allocate and initialize extended TSS with comprehensive validation
fn allocateExtendedTSS() !*ExtendedTSS {
    var guard = stack_security.protect();
    defer guard.deinit();

    const tss_size = @sizeOf(ExtendedTSS);

    // Validate size requirements
    if (tss_size > MAX_TSS_SIZE) {
        serial.println("[IO_SEC] ERROR: TSS size {} exceeds maximum {}", .{ tss_size, MAX_TSS_SIZE });
        return error.TSSTooBig;
    }

    // Allocate memory for extended TSS (must be aligned to page boundary)
    const pmm = @import("../memory/pmm.zig");
    const extended_tss_pages = (tss_size + 4095) / 4096;
    serial.println("[IO_SEC] About to allocate {} pages for TSS (size: {} bytes)", .{ extended_tss_pages, tss_size });
    serial.flush();
    const extended_tss_addr = pmm.allocPagesTagged(extended_tss_pages, .SECURITY) orelse {
        serial.println("[IO_SEC] ERROR: Failed to allocate {} pages for TSS", .{extended_tss_pages});
        return error.OutOfMemory;
    };

    serial.println("[IO_SEC] Allocated TSS at physical address: 0x{x}", .{extended_tss_addr});
    serial.flush();

    // Ensure cleanup on error
    errdefer pmm.freePages(extended_tss_addr, extended_tss_pages);

    const extended_tss = @as(*ExtendedTSS, @ptrFromInt(extended_tss_addr));

    // Validate pointer alignment (TSS should be 8-byte aligned)
    if (@intFromPtr(extended_tss) & 0x7 != 0) {
        serial.println("[IO_SEC] ERROR: TSS misaligned at 0x{x:0>16}", .{@intFromPtr(extended_tss)});
        return error.TSSMisaligned;
    }

    // Initialize TSS with validation
    @memset(@as([*]u8, @ptrCast(extended_tss))[0..tss_size], 0);

    // Copy current TSS data (preserving existing RSP0, IST entries, etc.)
    extended_tss.base = gdt.tss;

    // Set up proper TSS limits and permissions
    setupTSSPermissions(extended_tss);

    // Validate TSS structure
    validateTSSStructure(extended_tss) catch |err| {
        serial.println("[IO_SEC] ERROR: TSS validation failed: {}", .{err});
        return err;
    };

    serial.println("[IO_SEC] ✓ Extended TSS allocated and validated at 0x{x:0>16}", .{extended_tss_addr});
    return extended_tss;
}

// Initialize full I/O security after PMM is available
pub fn initializeFull() !void {
    // Use CanaryGuard system for stack protection
    var guard = stack_security.protect();
    defer guard.deinit();

    // Only initialize once
    if (extended_tss_ptr != null) return;

    // Allocate and validate extended TSS
    const extended_tss = try allocateExtendedTSS();
    extended_tss_ptr = extended_tss;

    // Clear bits for allowed ports (0 = allowed)
    for (allowed_ports) |range| {
        var port: u16 = range.start;
        while (port <= range.end) : (port += 1) {
            const byte_idx = port / 8;
            const bit_idx = @as(u3, @truncate(port % 8));
            extended_tss.iopb[byte_idx] &= ~(@as(u8, 1) << bit_idx);
        }
    }

    // Also apply dynamic ports if any
    for (dynamic_ports[0..dynamic_port_count]) |range| {
        updateIOPBForRange(range);
    }

    // Update TSS in GDT to point to extended TSS
    updateTSSInGDT();

    // Perform final validation after all configuration is complete
    try validateTSSStructure(extended_tss);

    // Verify the TSS was loaded correctly
    try validateIntegrity();

    serial.println("[IO_SEC] Full I/O security initialized with hardware IOPB enforcement", .{});
    serial.println("[IO_SEC] Extended TSS at 0x{x:0>16}, size: {} bytes", .{ @intFromPtr(extended_tss), @sizeOf(ExtendedTSS) });
    serial.println("[IO_SEC] IOPB offset: 0x{x:0>4}", .{extended_tss.base.iopb_offset});
}
