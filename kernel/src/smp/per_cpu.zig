const std = @import("std");
const cpu_init = @import("../x86_64/cpu_init.zig");
const heap = @import("../memory/heap.zig");
const spinlock = @import("../lib/spinlock.zig");

/// Per-CPU data structure containing all CPU-specific information
pub const CpuData = struct {
    // Identification
    cpu_id: u32, // Logical CPU ID (0, 1, 2...)
    apic_id: u8, // Physical APIC ID

    // Stacks
    kernel_stack: [*]u8, // Top of kernel stack
    ist_stacks: [7][*]u8, // Interrupt stack table

    // State
    magic: u64, // Magic value for validation (0xDEADBEEFCAFEBABE)
    current_task: ?*anyopaque, // Current running task (Task type not yet defined)
    idle_task: ?*anyopaque, // CPU idle task (Task type not yet defined)

    // Statistics
    context_switches: u64,
    interrupts_handled: u64,

    // Synchronization
    tlb_flush_pending: bool,
    ipi_pending: u32,
};

/// Maximum number of CPUs supported
pub const MAX_CPUS = 256;

/// Magic value for CPU data validation
const CPU_DATA_MAGIC: u64 = 0xDEADBEEFCAFEBABE;

/// Global array of CPU data structures
pub var cpu_data_array: [MAX_CPUS]CpuData align(64) = undefined;

/// Number of CPUs detected
var cpu_count: u32 = 0;

/// Lock for CPU initialization
var init_lock = spinlock.SpinLock{};

/// Initialize per-CPU data for the bootstrap processor
pub fn initBsp() !void {
    const flags = init_lock.acquire();
    defer init_lock.release(flags);

    // BSP is always CPU 0
    cpu_count = 1;

    const bsp_data = &cpu_data_array[0];
    bsp_data.* = CpuData{
        .cpu_id = 0,
        .apic_id = 0, // Will be updated after APIC initialization
        .kernel_stack = undefined, // Will be set by caller
        .ist_stacks = undefined, // Will be set by IST initialization
        .magic = CPU_DATA_MAGIC,
        .current_task = null,
        .idle_task = null, // Will be set when scheduler initializes
        .context_switches = 0,
        .interrupts_handled = 0,
        .tlb_flush_pending = false,
        .ipi_pending = 0,
    };

    // Set GSBASE to point to BSP's per-CPU data
    cpu_init.writeMSR(0xC0000101, @intFromPtr(bsp_data));
}

/// Update BSP's APIC ID after APIC initialization
pub fn updateBspApicId(apic_id: u8) void {
    const flags = init_lock.acquire();
    defer init_lock.release(flags);

    if (cpu_count > 0) {
        cpu_data_array[0].apic_id = apic_id;
    }
}

/// Allocate and initialize per-CPU data for an application processor
pub fn allocateApData(apic_id: u8) !*CpuData {
    const flags = init_lock.acquire();
    defer init_lock.release(flags);

    if (cpu_count >= MAX_CPUS) {
        return error.TooManyCpus;
    }

    const cpu_id = cpu_count;
    cpu_count += 1;

    const ap_data = &cpu_data_array[cpu_id];
    ap_data.* = CpuData{
        .cpu_id = cpu_id,
        .apic_id = apic_id,
        .kernel_stack = undefined, // Will be allocated by AP startup
        .ist_stacks = undefined, // Will be allocated by AP startup
        .magic = CPU_DATA_MAGIC,
        .current_task = null,
        .idle_task = null, // Will be set when scheduler initializes
        .context_switches = 0,
        .interrupts_handled = 0,
        .tlb_flush_pending = false,
        .ipi_pending = 0,
    };

    return ap_data;
}

/// Get the current CPU's data structure (must be called with GSBASE set)
pub inline fn getCurrentCpu() *CpuData {
    // GSBASE points directly to the CpuData structure
    const gsbase = cpu_init.readMSR(0xC0000101);
    return @as(*CpuData, @ptrFromInt(gsbase));
}

/// Get CPU data by logical CPU ID
pub fn getCpuById(cpu_id: u32) ?*CpuData {
    if (cpu_id >= cpu_count) {
        return null;
    }
    return &cpu_data_array[cpu_id];
}

/// Get CPU data by APIC ID
pub fn getCpuByApicId(apic_id: u8) ?*CpuData {
    for (cpu_data_array[0..cpu_count]) |*cpu| {
        if (cpu.apic_id == apic_id) {
            return cpu;
        }
    }
    return null;
}

/// Get total number of CPUs
pub fn getCpuCount() u32 {
    return cpu_count;
}

/// Update current task for this CPU
pub fn setCurrentTask(task: *anyopaque) void {
    const cpu = getCurrentCpu();
    cpu.current_task = task;
}

/// Get current task for this CPU
pub fn getCurrentTask() ?*anyopaque {
    const cpu = getCurrentCpu();
    return cpu.current_task;
}

/// Increment context switch counter
pub fn incrementContextSwitches() void {
    const cpu = getCurrentCpu();
    cpu.context_switches += 1;
}

/// Increment interrupt counter
pub fn incrementInterrupts() void {
    const cpu = getCurrentCpu();
    cpu.interrupts_handled += 1;
}

/// Set TLB flush pending flag
pub fn setTlbFlushPending() void {
    const cpu = getCurrentCpu();
    @atomicStore(bool, &cpu.tlb_flush_pending, true, .release);
}

/// Clear TLB flush pending flag
pub fn clearTlbFlushPending() void {
    const cpu = getCurrentCpu();
    @atomicStore(bool, &cpu.tlb_flush_pending, false, .release);
}

/// Check if TLB flush is pending
pub fn isTlbFlushPending() bool {
    const cpu = getCurrentCpu();
    return @atomicLoad(bool, &cpu.tlb_flush_pending, .acquire);
}

/// Set IPI pending bits
pub fn setIpiPending(ipi_mask: u32) void {
    const cpu = getCurrentCpu();
    _ = @atomicRmw(u32, &cpu.ipi_pending, .Or, ipi_mask, .acq_rel);
}

/// Clear IPI pending bits
pub fn clearIpiPending(ipi_mask: u32) void {
    const cpu = getCurrentCpu();
    _ = @atomicRmw(u32, &cpu.ipi_pending, .And, ~ipi_mask, .acq_rel);
}

/// Get IPI pending bits
pub fn getIpiPending() u32 {
    const cpu = getCurrentCpu();
    return @atomicLoad(u32, &cpu.ipi_pending, .acquire);
}
