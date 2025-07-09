// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const per_cpu = @import("per_cpu.zig");
const timer = @import("../x86_64/timer.zig");
const spinlock = @import("../lib/spinlock.zig");

/// AP initialization stages for debugging
pub const ApStage = enum(u8) {
    /// AP has not started yet
    NotStarted = 0,
    /// AP entered 16-bit real mode code
    RealMode16 = 1,
    /// AP transitioned to 32-bit protected mode
    ProtectedMode32 = 2,
    /// AP enabled paging and entered long mode
    LongMode64 = 3,
    /// AP jumped to 64-bit kernel code
    KernelEntry = 4,
    /// AP loaded GDT/IDT
    GdtIdtLoaded = 5,
    /// AP set up GSBASE for per-CPU data
    GsBaseSet = 6,
    /// AP initialized Local APIC
    ApicInitialized = 7,
    /// AP set up TSS and IST stacks
    TssConfigured = 8,
    /// AP enabled security features
    SecurityEnabled = 9,
    /// AP initialized subsystems
    SubsystemsInit = 10,
    /// AP signaled ready to BSP
    SignaledReady = 11,
    /// AP received proceed signal
    ProceedReceived = 12,
    /// AP entered idle loop
    IdleLoop = 13,
    /// AP encountered an error
    Error = 255,
};

/// Detailed AP status information
pub const ApStatus = struct {
    /// Current stage of initialization
    stage: ApStage = .NotStarted,
    /// Error code if stage is Error
    error_code: u32 = 0,
    /// Timestamp when stage was entered (TSC value)
    stage_timestamp: u64 = 0,
    /// Number of times this AP has been started
    start_attempts: u32 = 0,
    /// Flags for additional debugging
    flags: u32 = 0,
    /// Last known good stage before error
    last_good_stage: ApStage = .NotStarted,
    /// Additional debug values (stage-specific)
    debug_values: [4]u64 = [_]u64{0} ** 4,
};

/// Debug flags
pub const DebugFlags = struct {
    pub const APIC_ERROR: u32 = 1 << 0;
    pub const MEMORY_ERROR: u32 = 1 << 1;
    pub const TIMEOUT: u32 = 1 << 2;
    pub const EXCEPTION: u32 = 1 << 3;
    pub const IPI_FAILED: u32 = 1 << 4;
    pub const STACK_ERROR: u32 = 1 << 5;
    pub const CPU_FEATURE_MISSING: u32 = 1 << 6;
    pub const INVALID_CPU_ID: u32 = 1 << 7;
};

/// Global AP debug state
pub const ApDebugState = struct {
    /// Status for each AP (indexed by CPU ID)
    ap_status: [per_cpu.MAX_CPUS]ApStatus = [_]ApStatus{.{}} ** per_cpu.MAX_CPUS,
    /// Total number of APs that should start
    expected_ap_count: u32 = 0,
    /// Number of APs currently in each stage
    stage_counts: [16]u32 = [_]u32{0} ** 16,
    /// Global error counter
    total_errors: u32 = 0,
    /// Lock for updating shared state
    lock: spinlock.SpinLock = .{},
    /// Magic value to verify structure integrity
    magic: u64 = 0xABCDEF1234567890,
};

/// Global debug state instance
pub var debug_state: ApDebugState = .{};

/// Memory location for trampoline to update stages
/// Located at a fixed address that trampoline can write to
pub const TRAMPOLINE_DEBUG_ADDR: u64 = 0x9004;

/// Structure at TRAMPOLINE_DEBUG_ADDR for trampoline communication
pub const TrampolineDebug = extern struct {
    magic: u32, // 0x12345678 to verify structure (at 0x9004)
    cpu_id: u32, // CPU being initialized (at 0x9008)
    stage: u8, // Current stage (ApStage enum value) (at 0x900C)
    error_code: u8, // Error code if any (at 0x900D)
    padding: [6]u8, // Alignment padding
    debug_value: u64, // Additional debug value (at 0x9020)
};

/// Check and process trampoline debug updates
pub fn checkTrampolineDebug() void {
    const debug_ptr = @as(*align(1) volatile TrampolineDebug, @ptrFromInt(TRAMPOLINE_DEBUG_ADDR));

    // Check magic value
    if (debug_ptr.magic != 0x12345678) return;

    const cpu_id = debug_ptr.cpu_id;
    const stage = @as(ApStage, @enumFromInt(debug_ptr.stage));

    // Update our debug state
    updateApStage(cpu_id, stage);

    // Store any debug value
    if (debug_ptr.debug_value != 0) {
        setDebugValue(cpu_id, 0, debug_ptr.debug_value);
    }

    // Clear magic to indicate we've processed it
    debug_ptr.magic = 0;
}

/// Update AP stage with atomic operations
pub fn updateApStage(cpu_id: u32, stage: ApStage) void {
    if (cpu_id >= per_cpu.MAX_CPUS) return;

    const flags = debug_state.lock.acquire();
    defer debug_state.lock.release(flags);

    const status = &debug_state.ap_status[cpu_id];
    const old_stage = status.stage;

    // Update stage counts
    if (@intFromEnum(old_stage) < debug_state.stage_counts.len) {
        debug_state.stage_counts[@intFromEnum(old_stage)] -|= 1;
    }
    if (@intFromEnum(stage) < debug_state.stage_counts.len) {
        debug_state.stage_counts[@intFromEnum(stage)] += 1;
    }

    // Update status
    status.stage = stage;
    status.stage_timestamp = readTscSafe();

    // Track last good stage
    if (stage != .Error) {
        status.last_good_stage = stage;
    }
}

/// Record an error for an AP
pub fn recordApError(cpu_id: u32, error_code: u32, flags: u32) void {
    if (cpu_id >= per_cpu.MAX_CPUS) return;

    const lock_flags = debug_state.lock.acquire();
    defer debug_state.lock.release(lock_flags);

    const status = &debug_state.ap_status[cpu_id];
    status.stage = .Error;
    status.error_code = error_code;
    status.flags |= flags;
    status.stage_timestamp = readTscSafe();

    debug_state.total_errors += 1;
}

/// Set a debug value for current stage
pub fn setDebugValue(cpu_id: u32, index: usize, value: u64) void {
    if (cpu_id >= per_cpu.MAX_CPUS or index >= 4) return;

    const flags = debug_state.lock.acquire();
    defer debug_state.lock.release(flags);

    debug_state.ap_status[cpu_id].debug_values[index] = value;
}

/// Get current status for an AP
pub fn getApStatus(cpu_id: u32) ?ApStatus {
    if (cpu_id >= per_cpu.MAX_CPUS) return null;

    const flags = debug_state.lock.acquire();
    defer debug_state.lock.release(flags);

    return debug_state.ap_status[cpu_id];
}

/// Get summary of all AP states
pub fn getApSummary() ApSummary {
    const flags = debug_state.lock.acquire();
    defer debug_state.lock.release(flags);

    var summary = ApSummary{};

    // Count APs in each major phase
    for (debug_state.ap_status[1..], 1..) |status, cpu_id| {
        _ = cpu_id;
        switch (status.stage) {
            .NotStarted => summary.not_started += 1,
            .RealMode16, .ProtectedMode32, .LongMode64 => summary.in_trampoline += 1,
            .KernelEntry, .GdtIdtLoaded, .GsBaseSet, .ApicInitialized, .TssConfigured, .SecurityEnabled, .SubsystemsInit => summary.initializing += 1,
            .SignaledReady, .ProceedReceived => summary.ready += 1,
            .IdleLoop => summary.running += 1,
            .Error => summary.failed += 1,
        }
    }

    summary.total_errors = debug_state.total_errors;
    return summary;
}

/// Summary structure for quick status check
pub const ApSummary = struct {
    not_started: u32 = 0,
    in_trampoline: u32 = 0,
    initializing: u32 = 0,
    ready: u32 = 0,
    running: u32 = 0,
    failed: u32 = 0,
    total_errors: u32 = 0,
};

/// Initialize debug state
pub fn init(expected_aps: u32) void {
    const flags = debug_state.lock.acquire();
    defer debug_state.lock.release(flags);

    debug_state.expected_ap_count = expected_aps;
    debug_state.total_errors = 0;

    // Reset all AP status
    for (&debug_state.ap_status) |*status| {
        status.* = .{};
    }

    // Reset stage counts
    debug_state.stage_counts = [_]u32{0} ** 16;
    debug_state.stage_counts[@intFromEnum(ApStage.NotStarted)] = expected_aps;
}

/// Check if all APs have reached a minimum stage
pub fn allApsReachedStage(min_stage: ApStage) bool {
    const flags = debug_state.lock.acquire();
    defer debug_state.lock.release(flags);

    var count: u32 = 0;
    for (debug_state.ap_status[1 .. debug_state.expected_ap_count + 1]) |status| {
        if (@intFromEnum(status.stage) >= @intFromEnum(min_stage)) {
            count += 1;
        }
    }

    return count == debug_state.expected_ap_count;
}

/// Wait for all APs to reach a stage with timeout
pub fn waitForStage(min_stage: ApStage, timeout_ms: u64) bool {
    const start_time = timer.getUptime();

    while (timer.getUptime() - start_time < timeout_ms) {
        if (allApsReachedStage(min_stage)) {
            return true;
        }
        asm volatile ("pause");
    }

    return false;
}

/// Read TSC safely (handle case where TSC might not be available)
fn readTscSafe() u64 {
    // Check if RDTSC is available
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (@as(u32, 1)),
        : "memory"
    );

    // Check for TSC support (bit 4 of EDX)
    if (edx & (1 << 4) != 0) {
        return asm volatile (
            \\rdtsc
            \\shl $32, %%rdx
            \\or %%rdx, %%rax
            : [ret] "={rax}" (-> u64),
            :
            : "rdx"
        );
    }

    return 0;
}

/// Format stage name for display
pub fn stageName(stage: ApStage) []const u8 {
    return switch (stage) {
        .NotStarted => "Not Started",
        .RealMode16 => "Real Mode (16-bit)",
        .ProtectedMode32 => "Protected Mode (32-bit)",
        .LongMode64 => "Long Mode (64-bit)",
        .KernelEntry => "Kernel Entry",
        .GdtIdtLoaded => "GDT/IDT Loaded",
        .GsBaseSet => "GS Base Set",
        .ApicInitialized => "APIC Initialized",
        .TssConfigured => "TSS Configured",
        .SecurityEnabled => "Security Enabled",
        .SubsystemsInit => "Subsystems Initialized",
        .SignaledReady => "Signaled Ready",
        .ProceedReceived => "Proceed Received",
        .IdleLoop => "Idle Loop",
        .Error => "Error",
    };
}

/// Dump debug information (can be called from panic handler)
pub fn dumpDebugInfo() void {
    // This function should work even without serial output
    // It just updates a memory structure that can be examined in debugger

    const flags = debug_state.lock.acquire();
    defer debug_state.lock.release(flags);

    // Create a summary in a known memory location
    const summary_ptr = @as(*volatile ApDebugDump, @ptrFromInt(0x10000));
    summary_ptr.magic = 0xDEADBEEF;
    summary_ptr.expected_aps = debug_state.expected_ap_count;
    summary_ptr.total_errors = debug_state.total_errors;

    // Copy AP status
    for (debug_state.ap_status[0..@min(16, per_cpu.MAX_CPUS)], 0..) |status, i| {
        summary_ptr.ap_stages[i] = @intFromEnum(status.stage);
        summary_ptr.ap_errors[i] = status.error_code;
    }

    // Copy stage counts
    for (debug_state.stage_counts[0..16], 0..) |count, i| {
        summary_ptr.stage_counts[i] = count;
    }
}

/// Structure for debug dump at fixed address
const ApDebugDump = extern struct {
    magic: u32,
    expected_aps: u32,
    total_errors: u32,
    ap_stages: [16]u8,
    ap_errors: [16]u32,
    stage_counts: [16]u32,
};
