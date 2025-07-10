// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const acpi = @import("../../drivers/acpi/acpi.zig");
const serial = @import("../../drivers/serial.zig");
const ap_init = @import("../ap_init.zig");
const per_cpu = @import("../per_cpu.zig");

/// Test coordinator for SMP tests
pub const TestCoordinator = struct {
    processor_info: ?[]const per_cpu.ProcessorInfo = null,
    aps_started: bool = false,

    /// Initialize test coordinator
    pub fn init() TestCoordinator {
        return .{};
    }

    /// Get processor information from ACPI
    pub fn getProcessorInfo(self: *TestCoordinator) ![]const per_cpu.ProcessorInfo {
        if (self.processor_info) |info| {
            return info;
        }

        // Get ACPI system info
        const system = acpi.getSystem() orelse {
            serial.println("[TEST] ERROR: ACPI system not initialized", .{});
            return error.AcpiNotInitialized;
        };

        // Get topology info
        const topology = system.getTopology() orelse {
            serial.println("[TEST] ERROR: No CPU topology found", .{});
            return error.NoTopology;
        };

        self.processor_info = topology.processors;
        return topology.processors;
    }

    /// Start all APs if not already started
    pub fn ensureAPsStarted(self: *TestCoordinator) !void {
        if (self.aps_started) {
            return;
        }

        const processors = try self.getProcessorInfo();
        if (processors.len <= 1) {
            serial.println("[TEST] Single CPU system, no APs to start", .{});
            self.aps_started = true;
            return;
        }

        // Check if APs are already online
        const online_count = ap_init.getOnlineCpuCount();
        if (online_count >= processors.len) {
            serial.println("[TEST] APs already online: {}", .{online_count});
            self.aps_started = true;
            return;
        }

        // Start the APs
        serial.println("[TEST] Starting {} APs...", .{processors.len - 1});
        try ap_init.startAllAPs(processors);
        self.aps_started = true;
    }

    /// Get CPU count
    pub fn getCpuCount(self: *TestCoordinator) u32 {
        _ = self;
        return per_cpu.getCpuCount();
    }
};

/// Global test coordinator instance
pub var coordinator = TestCoordinator.init();
