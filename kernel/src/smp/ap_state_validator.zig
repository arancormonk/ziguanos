// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const timer = @import("../x86_64/timer.zig");
const serial = @import("../drivers/serial.zig");
const ap_init = @import("ap_init.zig");
const ap_debug = @import("ap_debug.zig");
const per_cpu = @import("per_cpu.zig");

pub const ApStateValidator = struct {
    pub fn validateApStarted(_: u32, timeout_ms: u32) !bool {
        const start_time = timer.getUptime();

        // Check multiple indicators of AP startup
        while (timer.getUptime() - start_time < timeout_ms) {
            // Check debug region
            const debug_magic = @as(*volatile u32, @ptrFromInt(0x500));
            if (debug_magic.* == 0x12345678) {
                return true;
            }

            // Check AP alive counter
            const alive_count = @atomicLoad(u32, &ap_init.ap_alive_counter, .acquire);
            if (alive_count > 0) {
                return true;
            }

            // Brief pause
            asm volatile ("pause" ::: "memory");
        }

        return false;
    }

    pub fn diagnoseTrampolineIssue() void {
        // Read key memory locations for debugging
        const locations = [_]struct { addr: usize, name: []const u8 }{
            .{ .addr = 0x8000, .name = "Trampoline start" },
            .{ .addr = 0x8100, .name = "Early marker" },
            .{ .addr = 0x500, .name = "Debug region" },
            .{ .addr = 0x510, .name = "Debug value" },
        };

        for (locations) |loc| {
            const ptr = @as([*]const u8, @ptrFromInt(loc.addr));
            serial.print("[DIAG] {s} (0x{x}): ", .{ loc.name, loc.addr });
            for (0..16) |i| {
                serial.print("{x:0>2} ", .{ptr[i]});
            }
            serial.println("", .{});
        }
    }

    // Check if APs have reached specific stages
    pub fn checkApProgress(expected_stage: ap_debug.ApStage, timeout_ms: u32) bool {
        const start_time = timer.getUptime();

        while (timer.getUptime() - start_time < timeout_ms) {
            _ = ap_debug.getApSummary();

            // Check if all APs have reached at least the expected stage
            var all_reached = true;
            // Check each AP's status
            for (1..per_cpu.MAX_CPUS) |cpu_id| {
                const status = ap_debug.getApStatus(@intCast(cpu_id));
                if (status) |s| {
                    if (s.stage != .NotStarted and @intFromEnum(s.stage) < @intFromEnum(expected_stage)) {
                        all_reached = false;
                        break;
                    }
                }
            }

            if (all_reached) {
                return true;
            }

            // Brief pause
            asm volatile ("pause" ::: "memory");
        }

        return false;
    }

    // Validate specific AP state
    pub fn validateApState(cpu_id: u32) struct { valid: bool, stage: ap_debug.ApStage, error_code: u32 } {
        // Get status for this AP
        const status = ap_debug.getApStatus(cpu_id) orelse return .{ .valid = false, .stage = .NotStarted, .error_code = 0 };

        // Check for errors
        if (status.error_code != 0) {
            return .{ .valid = false, .stage = status.stage, .error_code = status.error_code };
        }

        // Check if AP is in a valid state
        const valid_stages = [_]ap_debug.ApStage{
            .SignaledReady,
            .ProceedReceived,
            .IdleLoop,
        };

        for (valid_stages) |stage| {
            if (status.stage == stage) {
                return .{ .valid = true, .stage = status.stage, .error_code = 0 };
            }
        }

        return .{ .valid = false, .stage = status.stage, .error_code = 0 };
    }

    // Diagnose why an AP failed to start
    pub fn diagnoseApFailure(cpu_id: u32) void {
        serial.println("[DIAG] Diagnosing AP {} failure:", .{cpu_id});

        // Check AP status
        if (ap_debug.getApStatus(cpu_id)) |status| {
            serial.println("[DIAG]   Stage reached: {}", .{status.stage});
            serial.println("[DIAG]   Flags: 0x{x}", .{status.flags});
            if (status.error_code != 0) {
                serial.println("[DIAG]   Error code: 0x{x}", .{status.error_code});
                serial.println("[DIAG]   Start attempts: {}", .{status.start_attempts});
            }
            // Print debug values if any
            for (status.debug_values, 0..) |value, i| {
                if (value != 0) {
                    serial.println("[DIAG]   Debug[{}]: 0x{x}", .{ i, value });
                }
            }
        } else {
            serial.println("[DIAG]   No status recorded for AP {}", .{cpu_id});
        }

        // Check if trampoline is intact
        const tramp_start = @as(*const u8, @ptrFromInt(0x8000));
        if (tramp_start.* != 0xFA) { // Should start with cli
            serial.println("[DIAG]   Trampoline corrupted! First byte: 0x{x} (expected 0xFA)", .{tramp_start.*});
        }

        // Dump key memory regions
        diagnoseTrampolineIssue();
    }

    // Validate all APs have started successfully
    pub fn validateAllAPs(expected_count: u32, timeout_ms: u32) !void {
        const start_time = timer.getUptime();

        // Wait for all APs to signal ready
        while (timer.getUptime() - start_time < timeout_ms) {
            const ready_count = @atomicLoad(u32, &ap_init.startup_state.ap_ready_count, .acquire);
            if (ready_count >= expected_count) {
                serial.println("[VAL] All {} APs signaled ready", .{expected_count});
                return;
            }

            // Brief pause
            asm volatile ("pause" ::: "memory");
        }

        // Timeout - diagnose failures
        const ready_count = @atomicLoad(u32, &ap_init.startup_state.ap_ready_count, .acquire);
        serial.println("[VAL] Timeout! Only {} of {} APs ready", .{ ready_count, expected_count });

        // Diagnose each AP
        for (1..expected_count + 1) |i| {
            const state = validateApState(@intCast(i));
            if (!state.valid) {
                diagnoseApFailure(@intCast(i));
            }
        }

        return error.ApStartupTimeout;
    }
};
