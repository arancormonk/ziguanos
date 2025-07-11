// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const rng = @import("../x86_64/rng.zig");
const stack_security = @import("../x86_64/stack_security.zig");
const serial = @import("../drivers/serial.zig");
const secure_print = @import("../lib/secure_print.zig");

// Runtime information about kernel load address
// This is populated early in kernel startup to handle KASLR and PIE
pub const RuntimeInfo = struct {
    // Physical address where kernel is actually loaded
    kernel_physical_base: u64,
    // Virtual address where kernel expects to be
    kernel_virtual_base: u64,
    // Offset between virtual and physical
    virtual_to_physical_offset: i64,
    // Size of kernel
    kernel_size: u64,
    // Whether we're in PIE mode
    pie_mode: bool,
    // KASLR offset from expected base
    kaslr_offset: u64,
    // Virtual memory enabled flag
    virtual_memory_enabled: bool,
};

// Security features for runtime info protection
const RUNTIME_INFO_MAGIC: u64 = 0x5A49475552494E46; // "ZIGURINF"
const RUNTIME_INFO_FREED_MAGIC: u64 = 0xDEADBEEFCAFEBABE;
const MAX_RUNTIME_INFO_INITIALIZATIONS: u32 = 1;

// Protected runtime info structure with integrity checking
const SecureRuntimeInfo = struct {
    magic: u64,
    info: RuntimeInfo,
    integrity_hash: u64,
    initialization_count: u32,
    is_protected: bool,
    checksum: u64,
};

// Global runtime info - protected and set once during early boot
var secure_runtime_info: SecureRuntimeInfo = SecureRuntimeInfo{
    .magic = RUNTIME_INFO_MAGIC,
    .info = RuntimeInfo{
        .kernel_physical_base = 0x200000, // Default expected base
        .kernel_virtual_base = 0x200000, // Identity mapped by default
        .virtual_to_physical_offset = 0,
        .kernel_size = 0,
        .pie_mode = false,
        .kaslr_offset = 0,
        .virtual_memory_enabled = false,
    },
    .integrity_hash = 0,
    .initialization_count = 0,
    .is_protected = false,
    .checksum = 0,
};

// Security statistics
var runtime_info_access_count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var runtime_info_violations: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// Calculate integrity hash for runtime info
fn calculateIntegrityHash(info: *const RuntimeInfo) u64 {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Use deterministic entropy based on struct content
    const struct_ptr = @as([*]const u8, @ptrCast(info));
    var entropy: u64 = 0x5A49475552494E46; // ZIGURINF magic

    // XOR all bytes of the struct for deterministic entropy
    for (0..@sizeOf(RuntimeInfo)) |i| {
        entropy ^= @as(u64, struct_ptr[i]) << @as(u6, @truncate((i * 8) % 64));
    }

    // Calculate hash using multiple fields with deterministic mixing
    var hash: u64 = entropy;
    hash ^= info.kernel_physical_base;
    hash = (hash << 13) | (hash >> 51); // Rotate left 13 bits
    hash ^= info.kernel_virtual_base;
    hash = (hash << 7) | (hash >> 57); // Rotate left 7 bits
    hash ^= info.kernel_size;
    hash = (hash << 17) | (hash >> 47); // Rotate left 17 bits
    hash ^= info.kaslr_offset;
    hash = (hash << 23) | (hash >> 41); // Rotate left 23 bits
    hash ^= @as(u64, if (info.pie_mode) 1 else 0);
    hash ^= @as(u64, if (info.virtual_memory_enabled) 1 else 0);
    hash ^= @as(u64, @bitCast(info.virtual_to_physical_offset));

    // Final mix with golden ratio constant
    hash ^= 0x9E3779B97F4A7C15; // φ * 2^64

    return hash;
}

// Validate runtime info integrity
fn validateRuntimeInfoIntegrity() bool {
    var guard = stack_security.protect();
    defer guard.deinit();

    // If not yet initialized, skip integrity checks but allow access to defaults
    if (secure_runtime_info.initialization_count == 0) {
        return true;
    }

    // Check magic number
    if (secure_runtime_info.magic != RUNTIME_INFO_MAGIC) {
        _ = runtime_info_violations.fetchAdd(1, .monotonic);
        serial.print("[SECURITY] Runtime info magic corruption detected: 0x{X}\n", .{secure_runtime_info.magic});
        return false;
    }

    // Check if already freed
    if (secure_runtime_info.magic == RUNTIME_INFO_FREED_MAGIC) {
        _ = runtime_info_violations.fetchAdd(1, .monotonic);
        serial.print("[SECURITY] Access to freed runtime info detected\n", .{});
        return false;
    }

    // Validate integrity hash
    const expected_hash = calculateIntegrityHash(&secure_runtime_info.info);
    if (secure_runtime_info.integrity_hash != expected_hash) {
        _ = runtime_info_violations.fetchAdd(1, .monotonic);
        serial.print("[SECURITY] Runtime info integrity hash mismatch: expected 0x{X}, got 0x{X}\n", .{ expected_hash, secure_runtime_info.integrity_hash });
        return false;
    }

    // Calculate and validate checksum
    const info_ptr = @as([*]const u8, @ptrCast(&secure_runtime_info.info));
    var checksum: u64 = 0;
    for (0..@sizeOf(RuntimeInfo)) |i| {
        checksum ^= @as(u64, info_ptr[i]) << @as(u6, @truncate(i % 64));
    }

    if (secure_runtime_info.checksum != checksum) {
        _ = runtime_info_violations.fetchAdd(1, .monotonic);
        serial.print("[SECURITY] Runtime info checksum mismatch: expected 0x{X}, got 0x{X}\n", .{ checksum, secure_runtime_info.checksum });
        return false;
    }

    return true;
}

// Update integrity hash and checksum after modification
fn updateIntegrityProtection() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    secure_runtime_info.integrity_hash = calculateIntegrityHash(&secure_runtime_info.info);

    // Calculate checksum
    const info_ptr = @as([*]const u8, @ptrCast(&secure_runtime_info.info));
    var checksum: u64 = 0;
    for (0..@sizeOf(RuntimeInfo)) |i| {
        checksum ^= @as(u64, info_ptr[i]) << @as(u6, @truncate(i % 64));
    }
    secure_runtime_info.checksum = checksum;
}

// Handle security violations
fn handleSecurityViolation(operation: []const u8) void {
    var guard = stack_security.protect();
    defer guard.deinit();

    serial.print("[SECURITY] CRITICAL: Runtime info security violation during {s}\n", .{operation});
    serial.print("[SECURITY] Magic: 0x{X}\n", .{secure_runtime_info.magic});
    serial.print("[SECURITY] Initialization count: {}\n", .{secure_runtime_info.initialization_count});
    serial.print("[SECURITY] Protected: {}\n", .{secure_runtime_info.is_protected});
    serial.print("[SECURITY] Total violations: {}\n", .{runtime_info_violations.load(.monotonic)});

    // Log forensic information
    serial.print("[SECURITY] Kernel physical base: ", .{});
    secure_print.printHex("", secure_runtime_info.info.kernel_physical_base);
    serial.print("\n[SECURITY] Kernel virtual base: ", .{});
    secure_print.printHex("", secure_runtime_info.info.kernel_virtual_base);
    serial.print("\n[SECURITY] KASLR offset: ", .{});
    secure_print.printHex("", secure_runtime_info.info.kaslr_offset);
    serial.print("\n", .{});

    @panic("Runtime info security violation - system compromised");
}

// Initialize runtime info from boot parameters (identity mapped mode)
pub fn init(kernel_base: u64, kernel_size: u64) void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Check if already initialized
    if (secure_runtime_info.initialization_count >= MAX_RUNTIME_INFO_INITIALIZATIONS) {
        serial.print("[SECURITY] ERROR: Attempt to re-initialize runtime info (count: {})\n", .{secure_runtime_info.initialization_count});
        handleSecurityViolation("init");
        return;
    }

    // Validate parameters
    if (kernel_size == 0 or kernel_size > 0x10000000) { // Max 256MB
        serial.print("[SECURITY] ERROR: Invalid kernel size: 0x{X}\n", .{kernel_size});
        handleSecurityViolation("init");
        return;
    }

    if (kernel_base & 0xFFF != 0) { // Must be page-aligned
        serial.print("[SECURITY] ERROR: Kernel base not page-aligned: 0x{X}\n", .{kernel_base});
        handleSecurityViolation("init");
        return;
    }

    const expected_base: u64 = 0x200000; // From linker script

    secure_runtime_info.info = RuntimeInfo{
        .kernel_physical_base = kernel_base,
        .kernel_virtual_base = kernel_base, // Identity mapped
        .virtual_to_physical_offset = 0,
        .kernel_size = kernel_size,
        .pie_mode = false,
        .kaslr_offset = kernel_base -% expected_base,
        .virtual_memory_enabled = true, // Already in virtual mode for identity mapping
    };

    secure_runtime_info.initialization_count += 1;
    updateIntegrityProtection();

    serial.print("[SECURITY] Runtime info initialized (count: {})\n", .{secure_runtime_info.initialization_count});
    serial.print("[SECURITY] Kernel base: ", .{});
    secure_print.printHex("", kernel_base);
    serial.print(", size: ", .{});
    secure_print.printHex("", kernel_size);
    serial.print("\n", .{});
}

// Initialize for PIE mode
pub fn initPIE(physical_base: u64, kernel_size: u64, virtual_memory_enabled: bool) void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Check if already initialized
    if (secure_runtime_info.initialization_count >= MAX_RUNTIME_INFO_INITIALIZATIONS) {
        serial.print("[SECURITY] ERROR: Attempt to re-initialize runtime info in PIE mode (count: {})\n", .{secure_runtime_info.initialization_count});
        handleSecurityViolation("initPIE");
        return;
    }

    // Validate parameters
    if (kernel_size == 0 or kernel_size > 0x10000000) { // Max 256MB
        serial.print("[SECURITY] ERROR: Invalid kernel size in PIE mode: 0x{X}\n", .{kernel_size});
        handleSecurityViolation("initPIE");
        return;
    }

    if (physical_base & 0xFFF != 0) { // Must be page-aligned
        serial.print("[SECURITY] ERROR: Physical base not page-aligned in PIE mode: 0x{X}\n", .{physical_base});
        handleSecurityViolation("initPIE");
        return;
    }

    const expected_virtual_base: u64 = 0x200000; // From linker script

    secure_runtime_info.info = RuntimeInfo{
        .kernel_physical_base = physical_base,
        .kernel_virtual_base = expected_virtual_base,
        .virtual_to_physical_offset = @as(i64, @intCast(physical_base)) - @as(i64, @intCast(expected_virtual_base)),
        .kernel_size = kernel_size,
        .pie_mode = true,
        .kaslr_offset = physical_base -% expected_virtual_base,
        .virtual_memory_enabled = virtual_memory_enabled,
    };

    secure_runtime_info.initialization_count += 1;
    updateIntegrityProtection();

    serial.print("[SECURITY] Runtime info initialized in PIE mode (count: {})\n", .{secure_runtime_info.initialization_count});
    serial.print("[SECURITY] Physical base: ", .{});
    secure_print.printHex("", physical_base);
    serial.print(", virtual base: ", .{});
    secure_print.printHex("", expected_virtual_base);
    serial.print("\n", .{});
}

// Set virtual memory enabled flag
pub fn setVirtualMemoryEnabled() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    if (!validateRuntimeInfoIntegrity()) {
        handleSecurityViolation("setVirtualMemoryEnabled");
        return;
    }

    if (secure_runtime_info.is_protected) {
        serial.print("[SECURITY] ERROR: Attempt to modify protected runtime info\n", .{});
        handleSecurityViolation("setVirtualMemoryEnabled");
        return;
    }

    secure_runtime_info.info.virtual_memory_enabled = true;
    updateIntegrityProtection();

    serial.print("[SECURITY] Virtual memory enabled flag set\n", .{});
}

// Check if virtual memory is enabled
pub fn isVirtualMemoryEnabled() bool {
    var guard = stack_security.protect();
    defer guard.deinit();

    _ = runtime_info_access_count.fetchAdd(1, .monotonic);

    if (!validateRuntimeInfoIntegrity()) {
        handleSecurityViolation("isVirtualMemoryEnabled");
        return false;
    }

    return secure_runtime_info.info.virtual_memory_enabled;
}

// Convert virtual address to physical for PIE mode
pub fn virtualToPhysical(virt_addr: u64) u64 {
    var guard = stack_security.protect();
    defer guard.deinit();

    _ = runtime_info_access_count.fetchAdd(1, .monotonic);

    if (!validateRuntimeInfoIntegrity()) {
        handleSecurityViolation("virtualToPhysical");
        return virt_addr; // Fallback to identity mapping
    }

    if (!secure_runtime_info.info.pie_mode) {
        // Identity mapped in non-PIE mode
        return virt_addr;
    }

    // Check if address is in kernel range
    if (virt_addr >= secure_runtime_info.info.kernel_virtual_base and
        virt_addr < secure_runtime_info.info.kernel_virtual_base + secure_runtime_info.info.kernel_size)
    {
        // Apply offset
        const signed_addr = @as(i64, @intCast(virt_addr));
        const phys_signed = signed_addr + secure_runtime_info.info.virtual_to_physical_offset;
        return @as(u64, @intCast(phys_signed));
    }

    // Outside kernel range - might be identity mapped (like MMIO)
    return virt_addr;
}

// Convert physical address to virtual for PIE mode
pub fn physicalToVirtual(phys_addr: u64) u64 {
    var guard = stack_security.protect();
    defer guard.deinit();

    _ = runtime_info_access_count.fetchAdd(1, .monotonic);

    if (!validateRuntimeInfoIntegrity()) {
        handleSecurityViolation("physicalToVirtual");
        return phys_addr; // Fallback to identity mapping
    }

    if (!secure_runtime_info.info.pie_mode) {
        return phys_addr;
    }

    // Check if address is in kernel physical range
    if (phys_addr >= secure_runtime_info.info.kernel_physical_base and
        phys_addr < secure_runtime_info.info.kernel_physical_base + secure_runtime_info.info.kernel_size)
    {
        // Apply reverse offset
        const signed_addr = @as(i64, @intCast(phys_addr));
        const virt_signed = signed_addr - secure_runtime_info.info.virtual_to_physical_offset;
        return @as(u64, @intCast(virt_signed));
    }

    // Outside kernel range
    return phys_addr;
}

// Alias for physicalToVirtual for convenience
pub fn physToVirt(phys_addr: u64) u64 {
    return physicalToVirtual(phys_addr);
}

// Get runtime address considering PIE mode
pub fn getRuntimeAddress(ptr: anytype) u64 {
    var guard = stack_security.protect();
    defer guard.deinit();

    _ = runtime_info_access_count.fetchAdd(1, .monotonic);

    if (!validateRuntimeInfoIntegrity()) {
        handleSecurityViolation("getRuntimeAddress");
        return @intFromPtr(ptr); // Fallback to direct address
    }

    const addr = @intFromPtr(ptr);

    // If we're in PIE mode and virtual memory isn't enabled yet,
    // we need to use physical addresses
    if (secure_runtime_info.info.pie_mode and !secure_runtime_info.info.virtual_memory_enabled) {
        return virtualToPhysical(addr);
    }

    return addr;
}

// Get physical address from a pointer
pub fn getPhysicalAddress(ptr: anytype) u64 {
    var guard = stack_security.protect();
    defer guard.deinit();

    _ = runtime_info_access_count.fetchAdd(1, .monotonic);

    if (!validateRuntimeInfoIntegrity()) {
        handleSecurityViolation("getPhysicalAddress");
        return @intFromPtr(ptr); // Fallback to direct address
    }

    const virt_addr = @intFromPtr(ptr);
    return virtualToPhysical(virt_addr);
}

// Helper to check if an address is within kernel range
pub fn isKernelAddress(addr: u64) bool {
    var guard = stack_security.protect();
    defer guard.deinit();

    _ = runtime_info_access_count.fetchAdd(1, .monotonic);

    if (!validateRuntimeInfoIntegrity()) {
        handleSecurityViolation("isKernelAddress");
        return false; // Secure default
    }

    if (secure_runtime_info.info.pie_mode) {
        // Check virtual range
        return addr >= secure_runtime_info.info.kernel_virtual_base and
            addr < secure_runtime_info.info.kernel_virtual_base + secure_runtime_info.info.kernel_size;
    } else {
        // Check physical/identity mapped range
        return addr >= secure_runtime_info.info.kernel_physical_base and
            addr < secure_runtime_info.info.kernel_physical_base + secure_runtime_info.info.kernel_size;
    }
}

// Get secure copy of runtime info for read-only access
pub fn getRuntimeInfo() RuntimeInfo {
    var guard = stack_security.protect();
    defer guard.deinit();

    _ = runtime_info_access_count.fetchAdd(1, .monotonic);

    if (!validateRuntimeInfoIntegrity()) {
        handleSecurityViolation("getRuntimeInfo");
        // Return safe defaults
        return RuntimeInfo{
            .kernel_physical_base = 0x200000,
            .kernel_virtual_base = 0x200000,
            .virtual_to_physical_offset = 0,
            .kernel_size = 0,
            .pie_mode = false,
            .kaslr_offset = 0,
            .virtual_memory_enabled = false,
        };
    }

    return secure_runtime_info.info;
}

// Protect runtime info from further modification
pub fn protectRuntimeInfo() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    if (!validateRuntimeInfoIntegrity()) {
        handleSecurityViolation("protectRuntimeInfo");
        return;
    }

    secure_runtime_info.is_protected = true;
    updateIntegrityProtection();

    serial.print("[SECURITY] Runtime info protected from modification\n", .{});
}

// Check if runtime info is protected
pub fn isRuntimeInfoProtected() bool {
    var guard = stack_security.protect();
    defer guard.deinit();

    if (!validateRuntimeInfoIntegrity()) {
        handleSecurityViolation("isRuntimeInfoProtected");
        return true; // Secure default
    }

    return secure_runtime_info.is_protected;
}

// Get security statistics
pub fn getSecurityStatistics() struct {
    access_count: u64,
    violations: u64,
    initialization_count: u32,
    is_protected: bool,
} {
    var guard = stack_security.protect();
    defer guard.deinit();

    return .{
        .access_count = runtime_info_access_count.load(.monotonic),
        .violations = runtime_info_violations.load(.monotonic),
        .initialization_count = secure_runtime_info.initialization_count,
        .is_protected = secure_runtime_info.is_protected,
    };
}

// Test address translation (for debugging)
pub fn testAddressTranslation() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    if (!validateRuntimeInfoIntegrity()) {
        handleSecurityViolation("testAddressTranslation");
        return;
    }

    const test_virt = secure_runtime_info.info.kernel_virtual_base;
    const test_phys = virtualToPhysical(test_virt);
    const back_virt = physicalToVirtual(test_phys);

    if (test_virt != back_virt) {
        serial.print("[SECURITY] Address translation test failed!\n", .{});
        serial.print("[SECURITY] Original virt: ", .{});
        secure_print.printHex("", test_virt);
        serial.print(", phys: ", .{});
        secure_print.printHex("", test_phys);
        serial.print(", back virt: ", .{});
        secure_print.printHex("", back_virt);
        serial.print("\n", .{});
        @panic("Address translation test failed!");
    }

    serial.print("[SECURITY] ✓ Address translation test passed\n", .{});
}

// Test integrity protection system
pub fn testIntegrityProtection() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    serial.print("[TEST] Testing runtime info integrity protection...\n", .{});

    // Test 1: Validate current state
    if (!validateRuntimeInfoIntegrity()) {
        serial.print("[TEST] ✗ Initial integrity validation failed\n", .{});
        return;
    }
    serial.print("[TEST] ✓ Initial integrity validation passed\n", .{});

    // Test 2: Test access counting
    const initial_count = runtime_info_access_count.load(.monotonic);
    _ = getRuntimeInfo();
    const after_count = runtime_info_access_count.load(.monotonic);

    if (after_count != initial_count + 1) {
        serial.print("[TEST] ✗ Access counting failed: {} -> {}\n", .{ initial_count, after_count });
        return;
    }
    serial.print("[TEST] ✓ Access counting works correctly\n", .{});

    // Test 3: Test protection state
    if (!isRuntimeInfoProtected()) {
        protectRuntimeInfo();
        if (!isRuntimeInfoProtected()) {
            serial.print("[TEST] ✗ Protection state setting failed\n", .{});
            return;
        }
    }
    serial.print("[TEST] ✓ Protection state works correctly\n", .{});

    // Test 4: Test statistics
    const stats = getSecurityStatistics();
    serial.print("[TEST] Security statistics: {} accesses, {} violations, {} inits\n", .{
        stats.access_count,
        stats.violations,
        stats.initialization_count,
    });

    serial.print("[TEST] ✓ Runtime info integrity protection system working correctly\n", .{});
}
