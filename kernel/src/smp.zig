// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Re-export all SMP components
pub const per_cpu = @import("smp/per_cpu.zig");
pub const cpu_local = @import("smp/cpu_local.zig");
pub const ap_init = @import("smp/ap_init.zig");
pub const ap_entry = @import("smp/ap_entry.zig");
pub const ap_sync = @import("smp/ap_sync.zig");
pub const ap_debug = @import("smp/ap_debug.zig");
pub const ipi = @import("smp/ipi.zig");
pub const ap_cpu_init = @import("smp/ap_cpu_init.zig");
pub const smp_test = @import("smp/tests.zig");
pub const ap_state_validator = @import("smp/ap_state_validator.zig");

// Test modules
pub const tests = @import("smp/tests/tests.zig");
// pub const stress_tests = @import("smp/tests/stress_tests.zig"); // TODO: Re-enable when scheduler is implemented
