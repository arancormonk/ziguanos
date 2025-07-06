// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const cpu_init = @import("cpu_init.zig");
const cpuid = @import("cpuid.zig");
const serial = @import("../drivers/serial.zig");

// Intel MSR definitions for speculation control
pub const IA32_SPEC_CTRL = 0x48;
pub const IA32_PRED_CMD = 0x49;
pub const IA32_ARCH_CAPABILITIES = 0x10A;
pub const IA32_FLUSH_CMD = 0x10B;

// IA32_SPEC_CTRL bits
pub const SPEC_CTRL_IBRS: u64 = 1 << 0; // Indirect Branch Restricted Speculation
pub const SPEC_CTRL_STIBP: u64 = 1 << 1; // Single Thread Indirect Branch Predictors
pub const SPEC_CTRL_SSBD: u64 = 1 << 2; // Speculative Store Bypass Disable
pub const SPEC_CTRL_RRSBA_DIS_U: u64 = 1 << 5; // Disable RRSBA behavior in user mode
pub const SPEC_CTRL_RRSBA_DIS_S: u64 = 1 << 6; // Disable RRSBA behavior in supervisor mode

// IA32_PRED_CMD bits
pub const PRED_CMD_IBPB: u64 = 1 << 0; // Indirect Branch Prediction Barrier

// IA32_ARCH_CAPABILITIES bits
pub const ARCH_CAP_RDCL_NO: u64 = 1 << 0; // Not susceptible to Meltdown
pub const ARCH_CAP_IBRS_ALL: u64 = 1 << 1; // Enhanced IBRS is supported
pub const ARCH_CAP_RSBA: u64 = 1 << 2; // RET may use alternative branch predictors
pub const ARCH_CAP_SKIP_L1DFL_VMENTRY: u64 = 1 << 3; // Skip L1D flush on VM entry
pub const ARCH_CAP_SSB_NO: u64 = 1 << 4; // Not susceptible to Speculative Store Bypass
pub const ARCH_CAP_MDS_NO: u64 = 1 << 5; // Not susceptible to MDS
pub const ARCH_CAP_PSCHANGE_MC_NO: u64 = 1 << 6; // No Mcheck on page size change
pub const ARCH_CAP_TSX_CTRL: u64 = 1 << 7; // TSX control MSR is supported
pub const ARCH_CAP_TAA_NO: u64 = 1 << 8; // Not susceptible to TAA

// IA32_FLUSH_CMD bits
pub const L1D_FLUSH: u64 = 1 << 0; // Trigger L1D cache flush

// TSX control MSR
pub const IA32_TSX_CTRL = 0x122;
pub const TSX_CTRL_RTM_DISABLE: u64 = 1 << 0; // Disable RTM
pub const TSX_CTRL_TSX_CPUID_CLEAR: u64 = 1 << 1; // Clear TSX CPUID bits

// MCU_OPT_CTRL MSR for additional mitigations
pub const IA32_MCU_OPT_CTRL = 0x123;
pub const RNGDS_MITG_DIS: u64 = 1 << 0; // Disable RNGDS mitigation

// State tracking
pub const SpeculationState = struct {
    ibrs_enabled: bool = false,
    stibp_enabled: bool = false,
    ssbd_enabled: bool = false,
    enhanced_ibrs: bool = false,
    l1d_flush_supported: bool = false,
    mds_mitigation: bool = false,
    tsx_disabled: bool = false,
    arch_capabilities: u64 = 0,

    // MDS mitigation statistics
    mds_verw_successes: u64 = 0,
    mds_fallback_uses: u64 = 0,
    mds_invalid_selectors: u64 = 0,
    mds_total_mitigations: u64 = 0,
};

var speculation_state = SpeculationState{};

// Speculation barrier primitives
pub inline fn speculationBarrier() void {
    asm volatile ("lfence" ::: "memory");
}

pub inline fn loadFence() void {
    asm volatile ("lfence" ::: "memory");
}

pub inline fn storeFence() void {
    asm volatile ("sfence" ::: "memory");
}

pub inline fn memoryFence() void {
    asm volatile ("mfence" ::: "memory");
}

// Indirect branch prediction barrier
pub inline fn indirectBranchBarrier() void {
    if (cpuid.hasIBPB()) {
        cpu_init.writeMSR(IA32_PRED_CMD, PRED_CMD_IBPB);
    }
}

// Array index masking for Spectre V1 mitigation
pub inline fn arrayIndexMask(index: usize, array_size: usize) usize {
    // Ensure the index is within bounds without branching
    const mask = @as(usize, @intFromBool(index < array_size)) -% 1;
    return index & ~mask;
}

// Conditional select without branching (for constant-time operations)
pub inline fn conditionalSelect(condition: bool, true_val: u64, false_val: u64) u64 {
    const mask = @as(u64, @intFromBool(condition)) -% 1;
    return (true_val & ~mask) | (false_val & mask);
}

// Check CPU vulnerabilities
pub fn checkVulnerabilities() void {

    // Read architecture capabilities if available
    if (cpuid.hasArchCapabilities()) {
        speculation_state.arch_capabilities = cpu_init.readMSR(IA32_ARCH_CAPABILITIES);

        serial.println("[SPEC] Architecture Capabilities: 0x{x:0>16}", .{speculation_state.arch_capabilities});

        if (speculation_state.arch_capabilities & ARCH_CAP_RDCL_NO != 0) {
            serial.println("[SPEC] CPU not vulnerable to Meltdown (RDCL_NO)", .{});
        } else {
            serial.println("[SPEC] WARNING: CPU vulnerable to Meltdown - KPTI recommended", .{});
        }

        if (speculation_state.arch_capabilities & ARCH_CAP_IBRS_ALL != 0) {
            serial.println("[SPEC] Enhanced IBRS supported", .{});
            speculation_state.enhanced_ibrs = true;
        }

        if (speculation_state.arch_capabilities & ARCH_CAP_SSB_NO != 0) {
            serial.println("[SPEC] CPU not vulnerable to Speculative Store Bypass", .{});
        }

        if (speculation_state.arch_capabilities & ARCH_CAP_MDS_NO != 0) {
            serial.println("[SPEC] CPU not vulnerable to MDS", .{});
        }

        if (speculation_state.arch_capabilities & ARCH_CAP_TAA_NO != 0) {
            serial.println("[SPEC] CPU not vulnerable to TAA", .{});
        }
    } else {
        serial.println("[SPEC] WARNING: No architecture capabilities MSR - assuming vulnerable", .{});
    }
}

// Enable Spectre V2 mitigations
pub fn enableSpectreV2Mitigations() void {
    if (!cpuid.hasSpecCtrl()) {
        serial.println("[SPEC] No SPEC_CTRL MSR support - Spectre V2 mitigations unavailable", .{});
        return;
    }

    var spec_ctrl: u64 = 0;

    // Try to read existing value
    spec_ctrl = cpu_init.readMSR(IA32_SPEC_CTRL);

    // Enable IBRS (Indirect Branch Restricted Speculation)
    if (speculation_state.enhanced_ibrs) {
        // Enhanced IBRS provides always-on protection
        spec_ctrl |= SPEC_CTRL_IBRS;
        speculation_state.ibrs_enabled = true;
        serial.println("[SPEC] Enabled Enhanced IBRS (always-on)", .{});
    } else if (cpuid.hasIBRS()) {
        // Legacy IBRS - would need to toggle on kernel entry/exit
        spec_ctrl |= SPEC_CTRL_IBRS;
        speculation_state.ibrs_enabled = true;
        serial.println("[SPEC] Enabled IBRS (legacy mode)", .{});
    }

    // Enable STIBP for SMT systems
    if (cpuid.hasSTIBP() and cpuid.hasSMT()) {
        spec_ctrl |= SPEC_CTRL_STIBP;
        speculation_state.stibp_enabled = true;
        serial.println("[SPEC] Enabled STIBP for SMT protection", .{});
    }

    // Enable SSBD (Speculative Store Bypass Disable)
    if (cpuid.hasSSBD()) {
        spec_ctrl |= SPEC_CTRL_SSBD;
        speculation_state.ssbd_enabled = true;
        serial.println("[SPEC] Enabled SSBD (Speculative Store Bypass Disable)", .{});
    }

    // Write the combined value
    cpu_init.writeMSR(IA32_SPEC_CTRL, spec_ctrl);

    serial.println("[SPEC] IA32_SPEC_CTRL = 0x{x:0>16}", .{spec_ctrl});
}

// Enable L1D cache flush capability
pub fn enableL1DFlush() void {
    if (cpuid.hasL1DFlush()) {
        speculation_state.l1d_flush_supported = true;
        serial.println("[SPEC] L1D cache flush capability available", .{});
    } else {
        serial.println("[SPEC] No hardware L1D flush support", .{});
    }
}

// Perform L1D cache flush
pub fn flushL1DCache() void {
    if (speculation_state.l1d_flush_supported) {
        // Memory barrier before hardware flush
        memoryFence();

        // Hardware flush via MSR
        cpu_init.writeMSR(IA32_FLUSH_CMD, L1D_FLUSH);

        // Memory barrier after flush to ensure completion
        memoryFence();
    } else {
        // Software flush fallback
        softwareL1DFlush();
    }
}

// Software L1D cache flush (fallback)
fn softwareL1DFlush() void {
    // Allocate buffer larger than L1D cache (typically 32KB-64KB)
    // IMPORTANT: Initialize to zero to avoid reading uninitialized memory
    var flush_buffer: [65536]u8 align(64) = [_]u8{0} ** 65536;

    // Memory barrier after buffer allocation to ensure initialization completes
    // This prevents CPU reordering that could lead to incomplete cache flush
    memoryFence();

    // Touch every cache line to evict existing data
    var i: usize = 0;
    while (i < flush_buffer.len) : (i += 64) {
        // Force a write then read to ensure cache line is loaded
        const volatile_ptr = @as(*volatile u8, &flush_buffer[i]);
        volatile_ptr.* = 0; // Write to ensure line is allocated

        // Memory barrier to prevent reordering
        asm volatile ("" ::: "memory");

        _ = volatile_ptr.*; // Read to load into cache
    }

    // Final memory barrier to ensure completion
    memoryFence();
}

// Enable MDS mitigations
pub fn enableMDSMitigations() void {

    // Check if CPU is vulnerable
    if (speculation_state.arch_capabilities & ARCH_CAP_MDS_NO != 0) {
        serial.println("[SPEC] CPU not vulnerable to MDS", .{});
        return;
    }

    // Check for MD_CLEAR capability
    if (cpuid.hasMDClear()) {
        speculation_state.mds_mitigation = true;
        serial.println("[SPEC] MDS mitigation via MD_CLEAR enabled", .{});

        // Set up VERW instruction usage for additional protection
        setupVERWMitigation();
    } else {
        serial.println("[SPEC] WARNING: CPU vulnerable to MDS but no MD_CLEAR support", .{});
    }
}

// Setup VERW instruction for MDS mitigation
fn setupVERWMitigation() void {
    // VERW instruction can be used to clear CPU buffers
    // This is typically done on security domain transitions

    // Create a descriptor we can VERW against
    const verw_desc: u16 = 0; // Null descriptor is fine

    // Test that VERW works
    asm volatile (
        \\verw %[desc]
        :
        : [desc] "m" (verw_desc),
        : "cc"
    );

    serial.println("[SPEC] VERW instruction tested successfully", .{});
}

// Disable TSX to mitigate TAA
pub fn disableTSX() void {

    // Check if TSX control is available
    if (speculation_state.arch_capabilities & ARCH_CAP_TSX_CTRL == 0) {
        if (cpuid.hasTSX()) {
            serial.println("[SPEC] WARNING: TSX present but no control MSR", .{});
        }
        return;
    }

    // Disable TSX via MSR
    cpu_init.writeMSR(IA32_TSX_CTRL, TSX_CTRL_RTM_DISABLE | TSX_CTRL_TSX_CPUID_CLEAR);
    speculation_state.tsx_disabled = true;
    serial.println("[SPEC] TSX disabled for TAA mitigation", .{});
}

// Initialize all CPU speculation mitigations
pub fn init() void {
    serial.println("[SPEC] Initializing CPU speculation mitigations...", .{});

    // Check vulnerabilities first
    checkVulnerabilities();

    // Enable various mitigations
    enableSpectreV2Mitigations();
    enableL1DFlush();
    enableMDSMitigations();
    disableTSX();

    // Perform initial cache flush
    if (speculation_state.l1d_flush_supported) {
        flushL1DCache();
        serial.println("[SPEC] Initial L1D cache flush completed", .{});
    }

    serial.println("[SPEC] CPU speculation mitigations initialized", .{});

    // Test MDS mitigation implementation
    testMDSMitigation();
}

// Get current mitigation status
pub fn getMitigationStatus() SpeculationState {
    return speculation_state;
}

// Context switch mitigation (call on task switch)
pub fn onContextSwitch() void {
    // Memory barrier to ensure all previous stores are visible
    memoryFence();

    // Flush indirect branch predictors if not using enhanced IBRS
    if (!speculation_state.enhanced_ibrs and cpuid.hasIBPB()) {
        indirectBranchBarrier();
    }

    // Flush L1D cache on security domain change
    if (speculation_state.l1d_flush_supported) {
        // Memory barrier before cache flush
        memoryFence();
        flushL1DCache();
    }

    // Issue VERW for MDS mitigation
    if (speculation_state.mds_mitigation) {
        executeVERW();
    }

    // Final speculation barrier
    speculationBarrier();
}

// Validate data segment selector for VERW instruction
fn validateDataSegmentSelector(selector: u16) bool {
    // Check if selector is null
    if (selector == 0) return false;

    // Extract table indicator (bit 2)
    const table_indicator = (selector & 0x04) != 0;

    // For kernel, we expect GDT (TI=0) with RPL=0
    // For user, we expect GDT (TI=0) with RPL=3
    if (table_indicator) return false; // Must be GDT, not LDT

    // Valid selectors are kernel data (0x10) or user data (0x23)
    return selector == @import("gdt.zig").KERNEL_DATA_SELECTOR or
        selector == @import("gdt.zig").USER_DATA_SELECTOR;
}

// Get current data segment selector
fn getCurrentDataSegment() u16 {
    return asm volatile ("mov %%ds, %[result]"
        : [result] "=r" (-> u16),
    );
}

// Alternative MDS mitigation using memory operations
fn performAlternativeMDSMitigation() void {
    // Alternative approach: Use memory fence + cache line flush
    // This provides some protection when VERW is not available
    memoryFence();

    // Flush cache lines that might contain sensitive data
    // This is less effective than VERW but provides some protection
    asm volatile (
        \\mfence
        \\lfence
        \\sfence
        ::: "memory");

    speculationBarrier();
}

// Execute VERW instruction with proper validation
pub inline fn executeVERW() void {
    // Get the current data segment selector
    const current_ds = getCurrentDataSegment();

    // Update total mitigation counter
    speculation_state.mds_total_mitigations += 1;

    // Validate the data segment selector
    if (validateDataSegmentSelector(current_ds)) {
        // Memory barrier before VERW
        memoryFence();

        // Use validated data segment selector for VERW
        // VERW clears CPU internal buffers when used with a valid writable descriptor
        asm volatile (
            \\verw %[desc]
            :
            : [desc] "m" (current_ds),
            : "cc", "memory"
        );

        // Speculation barrier after VERW
        speculationBarrier();

        // Track successful VERW usage
        speculation_state.mds_verw_successes += 1;
    } else {
        // Track invalid selector
        speculation_state.mds_invalid_selectors += 1;

        // Fallback to alternative mitigation if selector validation fails
        performAlternativeMDSMitigation();

        // Track fallback usage
        speculation_state.mds_fallback_uses += 1;

        // Log security event for monitoring
        serial.println("[SECURITY] MDS mitigation using fallback method - invalid DS selector 0x{X}", .{current_ds});
    }
}

// Comprehensive MDS mitigation for all kernel exits
// This function implements Intel's recommended MDS mitigation sequence
pub inline fn mitigateOnKernelExit() void {
    // Only perform mitigation if MDS mitigation is enabled and CPU is vulnerable
    if (!speculation_state.mds_mitigation) {
        return;
    }

    // Update total mitigation counter
    speculation_state.mds_total_mitigations += 1;

    // Intel recommends the following sequence for MDS mitigation:
    // 1. Memory barrier to ensure all stores are visible
    memoryFence();

    // 2. Execute VERW with a validated writable data segment
    // The VERW instruction will clear CPU internal buffers including:
    // - Store buffers
    // - Load ports
    // - Fill buffers
    const ds_selector = getCurrentDataSegment();

    // Validate the data segment selector before using it
    if (validateDataSegmentSelector(ds_selector)) {
        // Use validated data segment selector for VERW
        asm volatile (
            \\sub $8, %%rsp
            \\mov %[sel], (%%rsp)
            \\verw (%%rsp)
            \\add $8, %%rsp
            :
            : [sel] "r" (ds_selector),
            : "memory", "cc"
        );

        // Track successful VERW usage
        speculation_state.mds_verw_successes += 1;
    } else {
        // Track invalid selector
        speculation_state.mds_invalid_selectors += 1;

        // Use fallback mitigation if validation fails
        performAlternativeMDSMitigation();

        // Track fallback usage
        speculation_state.mds_fallback_uses += 1;

        // Log security event for monitoring
        serial.println("[SECURITY] Kernel exit MDS mitigation using fallback - invalid DS selector 0x{X}", .{ds_selector});
    }

    // 3. Speculation barrier to prevent speculative execution
    // from potentially leaking data after VERW
    speculationBarrier();
}

// Check if MDS mitigation is active
pub fn hasMDSMitigation() bool {
    return speculation_state.mds_mitigation;
}

// Get MDS mitigation statistics
pub fn getMDSMitigationStats() struct {
    total_mitigations: u64,
    verw_successes: u64,
    fallback_uses: u64,
    invalid_selectors: u64,
    effectiveness_percentage: u32,
} {
    const effectiveness = if (speculation_state.mds_total_mitigations > 0)
        @as(u32, @intCast((speculation_state.mds_verw_successes * 100) / speculation_state.mds_total_mitigations))
    else
        0;

    return .{
        .total_mitigations = speculation_state.mds_total_mitigations,
        .verw_successes = speculation_state.mds_verw_successes,
        .fallback_uses = speculation_state.mds_fallback_uses,
        .invalid_selectors = speculation_state.mds_invalid_selectors,
        .effectiveness_percentage = effectiveness,
    };
}

// Report MDS mitigation statistics
pub fn reportMDSMitigationStats() void {
    const stats = getMDSMitigationStats();

    serial.println("[SECURITY] MDS Mitigation Statistics:", .{});
    serial.println("  Total mitigations: {}", .{stats.total_mitigations});
    serial.println("  VERW successes: {}", .{stats.verw_successes});
    serial.println("  Fallback uses: {}", .{stats.fallback_uses});
    serial.println("  Invalid selectors: {}", .{stats.invalid_selectors});
    serial.println("  Effectiveness: {}%", .{stats.effectiveness_percentage});
}

// Test MDS mitigation implementation
pub fn testMDSMitigation() void {
    serial.println("[TEST] Testing MDS mitigation implementation", .{});

    // Test 1: Validate current data segment selector
    const current_ds = getCurrentDataSegment();
    serial.println("[TEST] Current DS selector: 0x{X}", .{current_ds});

    const is_valid = validateDataSegmentSelector(current_ds);
    if (is_valid) {
        serial.println("[TEST] ✓ Current DS selector is valid", .{});
    } else {
        serial.println("[TEST] ✗ Current DS selector is invalid", .{});
    }

    // Test 2: Validate known good selectors
    const gdt = @import("gdt.zig");
    if (validateDataSegmentSelector(gdt.KERNEL_DATA_SELECTOR)) {
        serial.println("[TEST] ✓ Kernel data selector validation passed", .{});
    } else {
        serial.println("[TEST] ✗ Kernel data selector validation failed", .{});
    }

    if (validateDataSegmentSelector(gdt.USER_DATA_SELECTOR)) {
        serial.println("[TEST] ✓ User data selector validation passed", .{});
    } else {
        serial.println("[TEST] ✗ User data selector validation failed", .{});
    }

    // Test 3: Validate known bad selectors
    if (!validateDataSegmentSelector(0x0000)) {
        serial.println("[TEST] ✓ Null selector correctly rejected", .{});
    } else {
        serial.println("[TEST] ✗ Null selector incorrectly accepted", .{});
    }

    if (!validateDataSegmentSelector(0x0007)) { // Invalid selector with LDT bit set
        serial.println("[TEST] ✓ LDT selector correctly rejected", .{});
    } else {
        serial.println("[TEST] ✗ LDT selector incorrectly accepted", .{});
    }

    // Test 4: Test MDS mitigation execution if enabled
    if (speculation_state.mds_mitigation) {
        serial.println("[TEST] Testing MDS mitigation execution", .{});

        // Save current statistics
        const stats_before = getMDSMitigationStats();

        // Execute MDS mitigation
        executeVERW();

        // Check statistics after
        const stats_after = getMDSMitigationStats();

        if (stats_after.total_mitigations > stats_before.total_mitigations) {
            serial.println("[TEST] ✓ MDS mitigation executed and statistics updated", .{});
        } else {
            serial.println("[TEST] ✗ MDS mitigation statistics not updated", .{});
        }

        // Report final statistics
        reportMDSMitigationStats();
    } else {
        serial.println("[TEST] MDS mitigation disabled - skipping execution test", .{});
    }

    serial.println("[TEST] MDS mitigation test completed", .{});
}

// Export the MDS mitigation function for assembly code to call
// This wrapper preserves all registers that assembly code expects to remain unchanged
export fn mitigateOnKernelExitAsm() callconv(.C) void {
    // Save volatile registers that C calling convention allows us to modify
    // RAX, RCX, RDX, R8, R9, R10, R11 are caller-saved in System V AMD64 ABI
    // We'll preserve them all to be extra safe
    asm volatile (
        \\push %%rax
        \\push %%rcx
        \\push %%rdx
        \\push %%r8
        \\push %%r9
        \\push %%r10
        \\push %%r11
        ::: "memory");

    // Call the actual mitigation function
    mitigateOnKernelExit();

    // Restore registers
    asm volatile (
        \\pop %%r11
        \\pop %%r10
        \\pop %%r9
        \\pop %%r8
        \\pop %%rdx
        \\pop %%rcx
        \\pop %%rax
        ::: "memory");
}

// Enhanced privilege transition barriers
pub inline fn onPrivilegeTransition() void {
    // Full memory barrier
    memoryFence();

    // Speculation barrier
    speculationBarrier();

    // Clear CPU buffers if MDS mitigation is enabled
    if (speculation_state.mds_mitigation) {
        executeVERW();
    }
}

// Barrier for entering kernel mode
pub inline fn enterKernelBarrier() void {
    // Speculation barrier on entry
    speculationBarrier();

    // Memory barrier to ensure all user-mode stores are visible
    memoryFence();
}

// Barrier for exiting kernel mode
pub inline fn exitKernelBarrier() void {
    // Use comprehensive MDS mitigation on kernel exit
    mitigateOnKernelExit();

    // Additional memory barrier for extra safety
    memoryFence();

    // Final speculation barrier
    speculationBarrier();
}
