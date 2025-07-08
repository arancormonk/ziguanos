const std = @import("std");
const per_cpu = @import("per_cpu.zig");
const cpu_local = @import("cpu_local.zig");
const serial = @import("../drivers/serial.zig");

/// Test per-CPU infrastructure functionality
pub fn testPerCpuInfrastructure() !void {
    serial.println("[SMP TEST] Starting per-CPU infrastructure tests...", .{});

    // Test 1: Get current CPU data
    const cpu = per_cpu.getCurrentCpu();
    serial.println("[SMP TEST] Current CPU ID: {d}, APIC ID: {d}", .{ cpu.cpu_id, cpu.apic_id });

    // Test 2: CPU data lookup by ID
    if (per_cpu.getCpuById(0)) |bsp| {
        serial.println("[SMP TEST] BSP lookup successful: CPU ID {d}, APIC ID {d}", .{ bsp.cpu_id, bsp.apic_id });
    } else {
        return error.BspLookupFailed;
    }

    // Test 3: CPU data lookup by APIC ID
    if (per_cpu.getCpuByApicId(cpu.apic_id)) |found| {
        if (found == cpu) {
            serial.println("[SMP TEST] APIC ID lookup successful", .{});
        } else {
            return error.ApicIdLookupMismatch;
        }
    } else {
        return error.ApicIdLookupFailed;
    }

    // Test 4: Statistics counters
    const initial_interrupts = cpu.interrupts_handled;
    per_cpu.incrementInterrupts();
    if (cpu.interrupts_handled != initial_interrupts + 1) {
        return error.InterruptCounterFailed;
    }
    serial.println("[SMP TEST] Interrupt counter incremented successfully", .{});

    // Test 5: TLB flush pending flag
    per_cpu.setTlbFlushPending();
    if (!per_cpu.isTlbFlushPending()) {
        return error.TlbFlagSetFailed;
    }
    per_cpu.clearTlbFlushPending();
    if (per_cpu.isTlbFlushPending()) {
        return error.TlbFlagClearFailed;
    }
    serial.println("[SMP TEST] TLB flush flag operations successful", .{});

    // Test 6: IPI pending bits
    per_cpu.setIpiPending(0x1);
    if (per_cpu.getIpiPending() != 0x1) {
        return error.IpiPendingSetFailed;
    }
    per_cpu.setIpiPending(0x2);
    if (per_cpu.getIpiPending() != 0x3) { // Should be OR'd
        return error.IpiPendingOrFailed;
    }
    per_cpu.clearIpiPending(0x1);
    if (per_cpu.getIpiPending() != 0x2) {
        return error.IpiPendingClearFailed;
    }
    per_cpu.clearIpiPending(0x2);
    if (per_cpu.getIpiPending() != 0) {
        return error.IpiPendingClearAllFailed;
    }
    serial.println("[SMP TEST] IPI pending bits operations successful", .{});

    // Test 7: Per-CPU variables (skipped for now - requires allocation)
    serial.println("[SMP TEST] Per-CPU variables test skipped (requires allocation)", .{});

    // Test 8: CPU local storage security check
    if (!cpu_local.verifyCurrentCpuAccess()) {
        return error.CpuAccessVerificationFailed;
    }
    serial.println("[SMP TEST] CPU access verification successful", .{});

    serial.println("[SMP TEST] All per-CPU infrastructure tests passed!", .{});
}
