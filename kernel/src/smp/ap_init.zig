// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const apic = @import("../x86_64/apic.zig");
const paging = @import("../x86_64/paging.zig");
const pmm = @import("../memory/pmm.zig");
const per_cpu = @import("per_cpu.zig");
const cpu_local = @import("cpu_local.zig");
const ap_debug = @import("ap_debug.zig");
const ap_sync = @import("ap_sync.zig");
const spinlock = @import("../lib/spinlock.zig");
const serial = @import("../drivers/serial.zig");
const timer = @import("../x86_64/timer.zig");
const heap = @import("../memory/heap.zig");
const runtime_info = @import("../boot/runtime_info.zig");
const error_utils = @import("../lib/error_utils.zig");

// Import the trampoline symbols
// These are defined in trampoline.S in the .data.trampoline section
// For linker symbols, we need to declare them differently
extern var ap_trampoline_start: u8;
extern var ap_trampoline_end: u8;
// Note: ap_trampoline_size is an absolute symbol set by .set directive
extern const ap_trampoline_size: usize;

// AP startup synchronization state
pub const ApStartupState = struct {
    ap_ready_count: u32 = 0,
    ap_boot_error: u32 = 0,
    ap_stack_top: [*]u8 = undefined,
    ap_cpu_data: *per_cpu.CpuData = undefined,
    proceed_signal: bool = false,
};

// Global startup state
pub var startup_state: ApStartupState = .{};
var startup_lock = spinlock.SpinLock{};

// Simple verification counter that APs increment
pub var ap_alive_counter: u32 = 0;

// AP startup barrier for synchronization
var ap_startup_barrier: ap_sync.ApBarrier = undefined;
var barrier_initialized: bool = false;

// Trampoline location in low memory
// Note: Some systems clear memory during INIT-SIPI-SIPI
// Try 0x8000 which is in conventional memory
const TRAMPOLINE_ADDR: u64 = 0x8000;

// Stack size per CPU (64KB)
const AP_STACK_SIZE: usize = 64 * 1024;

// Timeout for AP startup (in milliseconds)
const AP_STARTUP_TIMEOUT_MS: u64 = 1_000; // 1 second

// AP startup error codes
pub const ApError = enum(u32) {
    None = 0,
    TrampolineAllocFailed = 1,
    StackAllocFailed = 2,
    InitIPIFailed = 3,
    StartupTimeout = 4,
    InvalidCpuId = 5,
};

// Offsets in trampoline data section (from trampoline.S)
// These are relative to ap_startup_data label (calculated from symbol table)
const TrampolineOffsets = struct {
    // ap_gdt starts at ap_startup_data + 0 (with .align 16)
    const gdt_offset: usize = 0;
    // ap_gdtr starts after GDT (5 entries * 8 bytes = 40 bytes) + alignment
    const gdtr_offset: usize = 0x30; // 48 bytes from ap_startup_data
    // ap_idt starts after gdtr (6 bytes) + alignment
    const idt_offset: usize = 0x40; // 64 bytes from ap_startup_data
    // ap_idtr starts after IDT (256 entries * 8 bytes = 2048 bytes)
    const idtr_offset: usize = 0x840; // 2112 bytes from ap_startup_data
    // ap_pml4_addr starts after idtr (6 bytes) + alignment to 8
    const pml4_addr_offset: usize = 0x848; // 2120 bytes from ap_startup_data
    // ap_entry_point starts after pml4_addr (4 bytes) + alignment to 8
    const entry_point_offset: usize = 0x850; // 2128 bytes from ap_startup_data
    // ap_cpu_id starts after entry_point (8 bytes) + alignment to 4
    const cpu_id_offset: usize = 0x858; // 2136 bytes from ap_startup_data
    // ap_stack_array starts after cpu_id (4 bytes) + alignment to 8
    const stack_array_offset: usize = 0x860; // 2144 bytes from ap_startup_data
};

/// Initialize an Application Processor
pub fn initAP(cpu_id: u32, apic_id: u8) !void {
    serial.println("[SMP] Starting AP: CPU {} (APIC ID {})", .{ cpu_id, apic_id });

    // Validate CPU ID
    if (cpu_id >= per_cpu.MAX_CPUS) {
        ap_debug.recordApError(cpu_id, @intFromEnum(ApError.InvalidCpuId), ap_debug.DebugFlags.INVALID_CPU_ID);
        return error.InvalidCpuId;
    }

    // Also check against trampoline limit
    if (cpu_id >= 64) {
        serial.println("[SMP] ERROR: CPU ID {} exceeds trampoline limit of 64", .{cpu_id});
        ap_debug.recordApError(cpu_id, @intFromEnum(ApError.InvalidCpuId), ap_debug.DebugFlags.INVALID_CPU_ID);
        return error.InvalidCpuId;
    }

    // Allocate stack for AP
    serial.println("[SMP] Allocating {} KB stack for CPU {}", .{ AP_STACK_SIZE / 1024, cpu_id });
    const stack_bottom = heap.heapAlloc(AP_STACK_SIZE) catch |err| {
        serial.println("[SMP] Failed to allocate stack for CPU {}: {s}", .{ cpu_id, error_utils.errorToString(err) });
        ap_debug.recordApError(cpu_id, @intFromEnum(ApError.StackAllocFailed), ap_debug.DebugFlags.STACK_ERROR);
        return error.StackAllocFailed;
    };
    const stack_top = @as([*]u8, @ptrCast(stack_bottom)) + AP_STACK_SIZE;
    serial.println("[SMP] Stack allocated at 0x{x} - 0x{x}", .{ @intFromPtr(stack_bottom), @intFromPtr(stack_top) });

    // Prepare per-CPU data
    const cpu_data = &per_cpu.cpu_data_array[cpu_id];

    // Initialize the per-CPU data structure
    cpu_data.* = per_cpu.CpuData{
        .cpu_id = cpu_id,
        .apic_id = apic_id,
        .kernel_stack = stack_top,
        .ist_stacks = undefined, // Will be set during AP initialization
        .magic = 0xDEADBEEFCAFEBABE,
        .current_task = null,
        .idle_task = null,
        .context_switches = 0,
        .interrupts_handled = 0,
        .tlb_flush_pending = false,
        .ipi_pending = 0,
    };

    // Setup trampoline if not already done
    serial.println("[SMP] Setting up trampoline...", .{});
    try setupTrampoline();

    // Update trampoline data for this CPU
    serial.println("[SMP] Updating trampoline data for CPU {}...", .{cpu_id});
    const ap_startup_data_offset = updateTrampolineData(cpu_id, stack_top, cpu_data);

    // Verify trampoline integrity before sending IPI
    const verify_ptr = @as([*]const u8, @ptrFromInt(TRAMPOLINE_ADDR));
    serial.print("[SMP] Trampoline check before IPI: ", .{});
    for (0..16) |i| {
        serial.print("{x:0>2} ", .{verify_ptr[i]});
    }
    serial.println("", .{});
    if (verify_ptr[0] != 0xFA) { // Should start with cli
        serial.println("[SMP] ERROR: Trampoline corrupted before sending IPI!", .{});
        // Try to recover by re-copying the trampoline
        serial.println("[SMP] Attempting to recover by re-copying trampoline...", .{});
        try setupTrampoline();
    }

    // Add a debug dump of the critical trampoline values before sending IPI
    serial.println("[SMP] Dumping critical trampoline data before INIT-SIPI-SIPI:", .{});
    const dump_base = TRAMPOLINE_ADDR + ap_startup_data_offset;
    const dump_ptr = @as([*]const u8, @ptrFromInt(dump_base));
    serial.print("[SMP]   GDT[0]: ", .{});
    for (0..8) |i| {
        serial.print("{x:0>2} ", .{dump_ptr[i]});
    }
    serial.println("", .{});
    serial.print("[SMP]   GDTR @ +0x{x}: ", .{TrampolineOffsets.gdtr_offset});
    const gdtr_ptr = dump_ptr + TrampolineOffsets.gdtr_offset;
    for (0..6) |i| {
        serial.print("{x:0>2} ", .{gdtr_ptr[i]});
    }
    serial.println("", .{});
    serial.print("[SMP]   PML4 @ +0x{x}: ", .{TrampolineOffsets.pml4_addr_offset});
    const pml4_ptr = @as(*const u32, @ptrFromInt(@intFromPtr(dump_ptr) + TrampolineOffsets.pml4_addr_offset));
    serial.println("0x{x}", .{pml4_ptr.*});
    serial.print("[SMP]   Entry @ +0x{x}: ", .{TrampolineOffsets.entry_point_offset});
    const entry_ptr = @as(*const u64, @ptrFromInt(@intFromPtr(dump_ptr) + TrampolineOffsets.entry_point_offset));
    serial.println("0x{x}", .{entry_ptr.*});
    serial.print("[SMP]   CPU ID @ +0x{x}: ", .{TrampolineOffsets.cpu_id_offset});
    const cpuid_ptr = @as(*const u32, @ptrFromInt(@intFromPtr(dump_ptr) + TrampolineOffsets.cpu_id_offset));
    serial.println("{}", .{cpuid_ptr.*});

    // Verify the trampoline memory is properly mapped and accessible
    serial.println("[SMP] Verifying trampoline memory mapping before INIT-SIPI-SIPI...", .{});

    // Test write and read to trampoline memory
    const test_addr = TRAMPOLINE_ADDR + 0x100; // Test address within trampoline
    const test_ptr = @as(*volatile u32, @ptrFromInt(test_addr));
    const test_value: u32 = 0xCAFEBABE;
    test_ptr.* = test_value;
    asm volatile ("mfence" ::: "memory");
    const read_value = test_ptr.*;
    if (read_value != test_value) {
        serial.println("[SMP] ERROR: Trampoline memory test failed! Wrote 0x{x}, read 0x{x}", .{ test_value, read_value });
        return error.TrampolineMemoryNotAccessible;
    }
    serial.println("[SMP] Trampoline memory test passed", .{});

    // Ensure the first page (0x0-0xFFF) is mapped since real mode starts at 0x8000
    // The AP will access memory in real mode which needs identity mapping
    serial.println("[SMP] Checking low memory identity mapping...", .{});

    // CRITICAL: Ensure the trampoline memory region is mapped and accessible
    // The AP will start in real mode at physical address 0x8000
    // We need to ensure this memory is:
    // 1. Identity mapped (virtual 0x8000 = physical 0x8000)
    // 2. Executable (no NX bit)
    // 3. Not cached in a way that causes coherency issues

    // Flush TLB entries for the trampoline region to ensure coherency
    const trampoline_page = TRAMPOLINE_ADDR & ~@as(u64, 0xFFF);
    asm volatile ("invlpg (%[addr])"
        :
        : [addr] "r" (trampoline_page),
        : "memory"
    );

    // Add a full memory barrier to ensure all memory writes are visible to other CPUs
    ap_sync.memoryBarrier();

    // Clear the debug memory region (0x6000) before sending INIT-SIPI-SIPI
    // This ensures we can detect if the AP actually writes to it
    serial.println("[SMP] Clearing debug memory region at 0x6000...", .{});
    const debug_region_ptr = @as([*]volatile u8, @ptrFromInt(0x6000));
    @memset(debug_region_ptr[0..0x100], 0); // Clear 256 bytes
    asm volatile ("mfence" ::: "memory");

    // Verify the memory was cleared
    serial.print("[SMP] Debug region after clear: ", .{});
    for (0..16) |i| {
        serial.print("{x:0>2} ", .{debug_region_ptr[i]});
    }
    serial.println("", .{});

    // Debug: Check what's at the trampoline location right before SIPI
    serial.println("[SMP] Checking trampoline memory right before INIT-SIPI-SIPI...", .{});
    const pre_sipi_dump = @as([*]const volatile u8, @ptrFromInt(TRAMPOLINE_ADDR));
    serial.print("[SMP] Trampoline at 0x8000: ", .{});
    for (0..16) |i| {
        serial.print("{x:0>2} ", .{pre_sipi_dump[i]});
    }
    serial.println("", .{});

    // Also dump the area that's showing the pattern
    serial.println("[SMP] Memory dump of pattern area:", .{});
    const pattern_start = TRAMPOLINE_ADDR;
    const pattern_dump = @as([*]const volatile u8, @ptrFromInt(pattern_start));
    for (0..4) |row| {
        serial.print("[SMP]   0x{x:0>4}: ", .{row * 16});
        for (0..16) |col| {
            serial.print("{x:0>2} ", .{pattern_dump[row * 16 + col]});
        }
        serial.println("", .{});
    }

    // Send INIT-SIPI-SIPI sequence
    serial.println("[SMP] Sending INIT-SIPI-SIPI to APIC ID {}...", .{apic_id});
    sendInitSipiSipi(apic_id) catch |err| {
        ap_debug.recordApError(cpu_id, @intFromEnum(ApError.InitIPIFailed), ap_debug.DebugFlags.IPI_FAILED);
        return err;
    };

    // Wait for AP to signal ready
    // Use TSC directly since interrupts are disabled
    const tsc_freq = timer.getTSCFrequency();
    if (tsc_freq == 0) {
        serial.println("[SMP] ERROR: TSC not calibrated, using busy wait", .{});
        // Fallback to simple busy wait
        var wait_count: u32 = 0;
        while (@atomicLoad(u32, &startup_state.ap_ready_count, .acquire) < cpu_id and wait_count < 100_000_000) {
            asm volatile ("pause");
            wait_count += 1;
        }
        if (wait_count >= 100_000_000) {
            serial.println("[SMP] AP {} startup timeout (busy wait)", .{cpu_id});
            ap_debug.recordApError(cpu_id, @intFromEnum(ApError.StartupTimeout), ap_debug.DebugFlags.TIMEOUT);
            @atomicStore(u32, &startup_state.ap_boot_error, @intFromEnum(ApError.StartupTimeout), .release);
            return error.StartupTimeout;
        }
        serial.println("[SMP] AP {} started successfully", .{cpu_id});
        return;
    }

    const start_tsc = timer.readTSC();
    var last_check_tsc = start_tsc;
    var debug_checks: u32 = 0;

    // Calculate TSC ticks for timeouts
    const tsc_per_ms = tsc_freq / 1000;
    const check_interval_ticks = tsc_per_ms * 10; // 10ms
    const timeout_ticks = tsc_per_ms * AP_STARTUP_TIMEOUT_MS;

    while (@atomicLoad(u32, &startup_state.ap_ready_count, .acquire) < cpu_id) {
        // Check for trampoline debug updates every 10ms
        const current_tsc = timer.readTSC();
        if (current_tsc - last_check_tsc >= check_interval_ticks) {
            ap_debug.checkTrampolineDebug();
            last_check_tsc = current_tsc;
            debug_checks += 1;

            // Also check the debug location directly every 100ms
            if (debug_checks % 10 == 0) {
                const debug_ptr = @as(*align(1) volatile ap_debug.TrampolineDebug, @ptrFromInt(ap_debug.TRAMPOLINE_DEBUG_ADDR));
                const early_marker = @as(*volatile u16, @ptrFromInt(0x6FF0)).*;
                const marker = @as(*volatile u16, @ptrFromInt(0x6FF2)).*;
                const lgdt_marker = @as(*volatile u16, @ptrFromInt(0x6FF4)).*;
                const cr0_marker = @as(*volatile u16, @ptrFromInt(0x6FF6)).*;
                const pm_marker = @as(*volatile u32, @ptrFromInt(0x6FFC)).*;

                if (debug_ptr.magic == 0x12345678 or early_marker != 0 or marker != 0 or lgdt_marker != 0 or cr0_marker != 0 or pm_marker != 0) {
                    serial.println("[SMP] Direct debug check: magic=0x{x}, early=0x{x}, marker=0x{x}, lgdt=0x{x}, cr0=0x{x}, pm=0x{x}, CPU={}, stage={}", .{
                        debug_ptr.magic,
                        early_marker,
                        marker,
                        lgdt_marker,
                        cr0_marker,
                        pm_marker,
                        debug_ptr.cpu_id,
                        debug_ptr.stage,
                    });
                }
            }
        }

        if (current_tsc - start_tsc > timeout_ticks) {
            // Check debug state for more detailed info
            const status = ap_debug.getApStatus(cpu_id);
            serial.println("[SMP] AP {} startup timeout at stage: {s}", .{ cpu_id, if (status) |s| ap_debug.stageName(s.stage) else "Unknown" });

            // Print debug values if available
            if (status) |s| {
                if (s.debug_values[0] != 0) {
                    serial.println("[SMP]   Debug value: 0x{x}", .{s.debug_values[0]});
                }
                if (s.error_code != 0) {
                    serial.println("[SMP]   Error code: 0x{x}", .{s.error_code});
                }
            }

            ap_debug.recordApError(cpu_id, @intFromEnum(ApError.StartupTimeout), ap_debug.DebugFlags.TIMEOUT);
            @atomicStore(u32, &startup_state.ap_boot_error, @intFromEnum(ApError.StartupTimeout), .release);
            return error.StartupTimeout;
        }
        asm volatile ("pause");
    }

    serial.println("[SMP] AP {} started successfully", .{cpu_id});
}

// Check if memory contains suspicious pattern
fn checkMemoryPattern(addr: u64, size: usize) void {
    const ptr = @as([*]const u8, @ptrFromInt(addr));
    var all_same = true;
    const pattern_value: u8 = ptr[0];

    for (1..size) |i| {
        if (ptr[i] != pattern_value) {
            all_same = false;
            break;
        }
    }

    if (all_same and pattern_value != 0x00 and pattern_value != 0xFF) {
        serial.println("[SMP] WARNING: Memory at 0x{x} contains repeating pattern 0x{x}", .{ addr, pattern_value });
    }
}

/// Setup the trampoline code in low memory
fn setupTrampoline() !void {
    const flags = startup_lock.acquire();
    defer startup_lock.release(flags);

    // Check if the memory has a suspicious pattern before setup
    checkMemoryPattern(TRAMPOLINE_ADDR, 256);

    // Also check the debug region
    serial.println("[SMP] Checking debug region at 0x6000...", .{});
    checkMemoryPattern(0x6000, 256);

    // Try to ensure debug region is mapped and writable
    const debug_test = @as(*volatile u32, @ptrFromInt(0x6000));
    debug_test.* = 0xDEADBEEF;
    asm volatile ("mfence" ::: "memory");
    if (debug_test.* != 0xDEADBEEF) {
        serial.println("[SMP] ERROR: Debug region at 0x6000 is not writable!", .{});
        serial.println("[SMP]   Wrote 0xDEADBEEF, read back 0x{x}", .{debug_test.*});
    } else {
        serial.println("[SMP] Debug region at 0x6000 is writable", .{});
        debug_test.* = 0; // Clear it
    }

    // Also verify this memory is accessible
    const test_ptr = @as(*volatile u8, @ptrFromInt(TRAMPOLINE_ADDR));
    const original_value = test_ptr.*;
    test_ptr.* = 0xAA;
    if (test_ptr.* != 0xAA) {
        serial.println("[SMP] ERROR: Cannot write to trampoline memory at 0x{x}!", .{TRAMPOLINE_ADDR});
        return error.TrampolineMemoryNotWritable;
    }
    test_ptr.* = original_value; // Restore original value

    // Check if already setup
    const trampoline_ptr = @as([*]const u8, @ptrFromInt(TRAMPOLINE_ADDR));

    // Check if the trampoline looks valid (has our code pattern)
    // The first instruction is now cli (0xFA) after our fix
    if (trampoline_ptr[0] == 0xFA) {
        serial.println("[SMP] Trampoline already setup at 0x{x}", .{TRAMPOLINE_ADDR});
        return; // Already setup
    }

    // First, let's check if the symbols are properly linked
    serial.println("[SMP] Checking trampoline symbols...", .{});

    // Get the addresses of the trampoline symbols
    // These are linker symbols that mark the start and end of the trampoline
    const start_addr = @intFromPtr(&ap_trampoline_start);
    const end_addr = @intFromPtr(&ap_trampoline_end);

    serial.println("[SMP] Trampoline addresses: start=0x{x}, end=0x{x}", .{ start_addr, end_addr });

    // Also try to use the absolute size symbol
    serial.println("[SMP] ap_trampoline_size from assembly: {} bytes", .{ap_trampoline_size});

    // Try different approaches to get the size
    var trampoline_size: usize = 0;

    // Calculate size from runtime addresses
    if (end_addr > start_addr and (end_addr - start_addr) <= 4096) {
        trampoline_size = end_addr - start_addr;
        serial.println("[SMP] Calculated size from addresses: {} bytes", .{trampoline_size});
    } else {
        // Fallback to known size
        serial.println("[SMP] WARNING: Cannot calculate size from addresses, using known size", .{});
        trampoline_size = 0xbd0; // 3024 bytes - from nm output
    }

    serial.println("[SMP] Final trampoline size: {} bytes", .{trampoline_size});

    // Sanity check - trampoline should be reasonable size
    if (trampoline_size == 0 or trampoline_size > 4096) {
        serial.println("[SMP] ERROR: Invalid trampoline size: {} bytes", .{trampoline_size});
        return error.InvalidTrampolineSize;
    }

    // Ensure it fits in one page
    if (trampoline_size > paging.PAGE_SIZE_4K) {
        serial.println("[SMP] ERROR: Trampoline too large! Need {} bytes but only have {} bytes", .{ trampoline_size, paging.PAGE_SIZE_4K });
        return error.TrampolineTooLarge;
    }

    // Map low memory page if needed (identity mapped in early boot)
    // For now, we assume 0x8000 is accessible

    // Copy trampoline code from the calculated runtime address
    const src = @as([*]const u8, @ptrFromInt(start_addr));
    const dst = @as([*]volatile u8, @ptrFromInt(TRAMPOLINE_ADDR));

    // Use volatile copy to prevent optimization issues
    for (0..trampoline_size) |i| {
        dst[i] = src[i];
    }

    // Memory barrier to ensure copy completes
    asm volatile ("mfence" ::: "memory");

    // Flush the data cache and instruction cache for the trampoline area
    // This is critical - the CPU might have stale instruction cache entries
    var cache_addr: u64 = TRAMPOLINE_ADDR;
    while (cache_addr < TRAMPOLINE_ADDR + trampoline_size) : (cache_addr += 64) {
        // clflush flushes the cache line containing the linear address
        asm volatile ("clflush (%[addr])"
            :
            : [addr] "r" (cache_addr),
            : "memory"
        );
    }

    // Ensure all cache flushes complete
    asm volatile ("mfence" ::: "memory");

    // On some CPUs, we also need to serialize to ensure instruction cache coherency
    asm volatile ("cpuid" ::: "eax", "ebx", "ecx", "edx", "memory");

    serial.println("[SMP] Trampoline code copied to 0x{x} ({} bytes), caches flushed", .{ TRAMPOLINE_ADDR, trampoline_size });

    // Verify the copy was successful
    const first_bytes = dst[0..16];
    serial.print("[SMP] First 16 bytes at 0x{x}: ", .{TRAMPOLINE_ADDR});
    for (first_bytes) |byte| {
        serial.print("{x:0>2} ", .{byte});
    }
    serial.println("", .{});

    // The first instruction should be cli (0xFA) after our fix
    if (dst[0] != 0xFA) {
        serial.println("[SMP] WARNING: First byte is not CLI (0xFA), got 0x{x}", .{dst[0]});
    }

    // Find the ap_startup_data offset first
    const ap_startup_data_offset = findStartupDataOffsetStatic(@as([*]const u8, @ptrCast(@volatileCast(dst))), trampoline_size);

    // Look for the lgdt instruction (0x0F 0x01 0x16) to verify the offset is correct
    serial.println("[SMP] Searching for lgdt instruction in trampoline...", .{});
    var lgdt_offset: ?usize = null;
    for (0..trampoline_size - 6) |i| {
        if (dst[i] == 0x0F and dst[i + 1] == 0x01 and dst[i + 2] == 0x16) {
            lgdt_offset = i;
            serial.println("[SMP] Found lgdt at offset 0x{x}", .{i});
            // The next 4 bytes should be the address of the GDTR
            const lgdt_addr = @as(u32, dst[i + 3]) |
                (@as(u32, dst[i + 4]) << 8) |
                (@as(u32, dst[i + 5]) << 16) |
                (@as(u32, dst[i + 6]) << 24);
            serial.println("[SMP] lgdt operand address: 0x{x} (should be ~0x{x} for correct relocation)", .{ lgdt_addr, TRAMPOLINE_ADDR + 0x170 + 0x30 });

            // Fix the lgdt operand to use the correct address
            const correct_gdtr_addr = TRAMPOLINE_ADDR + ap_startup_data_offset + TrampolineOffsets.gdtr_offset;
            dst[i + 3] = @truncate(correct_gdtr_addr & 0xFF);
            dst[i + 4] = @truncate((correct_gdtr_addr >> 8) & 0xFF);
            dst[i + 5] = @truncate((correct_gdtr_addr >> 16) & 0xFF);
            dst[i + 6] = @truncate((correct_gdtr_addr >> 24) & 0xFF);
            serial.println("[SMP] Fixed lgdt operand to: 0x{x}", .{correct_gdtr_addr});
            break;
        }
    }
    if (lgdt_offset == null) {
        serial.println("[SMP] WARNING: Could not find lgdt instruction!", .{});
    }

    // Look for the lidt instruction (0x0F 0x01 0x1D) to fix its operand too
    serial.println("[SMP] Searching for lidt instruction in trampoline...", .{});
    var lidt_offset: ?usize = null;
    for (0..trampoline_size - 6) |i| {
        if (dst[i] == 0x0F and dst[i + 1] == 0x01 and dst[i + 2] == 0x1D) {
            lidt_offset = i;
            serial.println("[SMP] Found lidt at offset 0x{x}", .{i});
            // The next 4 bytes should be the address of the IDTR
            const lidt_addr = @as(u32, dst[i + 3]) |
                (@as(u32, dst[i + 4]) << 8) |
                (@as(u32, dst[i + 5]) << 16) |
                (@as(u32, dst[i + 6]) << 24);
            serial.println("[SMP] lidt operand address: 0x{x}", .{lidt_addr});

            // Fix the lidt operand to use the correct address
            const correct_idtr_addr = TRAMPOLINE_ADDR + ap_startup_data_offset + TrampolineOffsets.idtr_offset;
            dst[i + 3] = @truncate(correct_idtr_addr & 0xFF);
            dst[i + 4] = @truncate((correct_idtr_addr >> 8) & 0xFF);
            dst[i + 5] = @truncate((correct_idtr_addr >> 16) & 0xFF);
            dst[i + 6] = @truncate((correct_idtr_addr >> 24) & 0xFF);
            serial.println("[SMP] Fixed lidt operand to: 0x{x}", .{correct_idtr_addr});
            break;
        }
    }
    if (lidt_offset == null) {
        serial.println("[SMP] WARNING: Could not find lidt instruction!", .{});
    }

    // Verify the lgdt fix by reading it back
    if (lgdt_offset) |off| {
        const verify_addr = @as(u32, dst[off + 3]) |
            (@as(u32, dst[off + 4]) << 8) |
            (@as(u32, dst[off + 5]) << 16) |
            (@as(u32, dst[off + 6]) << 24);
        serial.println("[SMP] Verified lgdt operand: 0x{x}", .{verify_addr});
    }

    // Make the trampoline area executable (remove NX bit)
    paging.makeRegionExecutable(TRAMPOLINE_ADDR, trampoline_size) catch |err| {
        serial.println("[SMP] Failed to make trampoline executable: {s}", .{error_utils.errorToString(err)});
        return err;
    };

    // Fix up the GDTR base address in the trampoline
    // The GDTR in the trampoline has a relative base that needs to be adjusted
    // (we already found ap_startup_data_offset above)
    const gdtr_offset = ap_startup_data_offset + TrampolineOffsets.gdtr_offset;
    const gdtr_ptr = @as(*[6]u8, @ptrFromInt(TRAMPOLINE_ADDR + gdtr_offset));

    // The GDTR should point to the GDT at TRAMPOLINE_ADDR + ap_startup_data_offset
    const gdt_physical_addr = TRAMPOLINE_ADDR + ap_startup_data_offset;
    const gdt_limit: u16 = 39; // 5 entries * 8 bytes - 1 = 0x27

    // Write the correct GDTR (limit=0x27, base=physical address of GDT)
    gdtr_ptr[0] = @truncate(gdt_limit & 0xFF);
    gdtr_ptr[1] = @truncate((gdt_limit >> 8) & 0xFF);
    gdtr_ptr[2] = @truncate(gdt_physical_addr & 0xFF);
    gdtr_ptr[3] = @truncate((gdt_physical_addr >> 8) & 0xFF);
    gdtr_ptr[4] = @truncate((gdt_physical_addr >> 16) & 0xFF);
    gdtr_ptr[5] = @truncate((gdt_physical_addr >> 24) & 0xFF);

    serial.println("[SMP] Fixed GDTR: limit=0x{x}, base=0x{x}", .{ gdt_limit, gdt_physical_addr });

    // Fix up the IDTR base address in the trampoline
    const idtr_offset = ap_startup_data_offset + TrampolineOffsets.idtr_offset;
    const idtr_ptr = @as(*[6]u8, @ptrFromInt(TRAMPOLINE_ADDR + idtr_offset));

    // The IDTR should point to the IDT at TRAMPOLINE_ADDR + ap_startup_data_offset + idt_offset
    const idt_physical_addr = TRAMPOLINE_ADDR + ap_startup_data_offset + TrampolineOffsets.idt_offset;
    const idt_limit: u16 = 2047; // 256 entries * 8 bytes - 1 = 0x7FF

    // Write the correct IDTR (limit=0x7FF, base=physical address of IDT)
    idtr_ptr[0] = @truncate(idt_limit & 0xFF);
    idtr_ptr[1] = @truncate((idt_limit >> 8) & 0xFF);
    idtr_ptr[2] = @truncate(idt_physical_addr & 0xFF);
    idtr_ptr[3] = @truncate((idt_physical_addr >> 8) & 0xFF);
    idtr_ptr[4] = @truncate((idt_physical_addr >> 16) & 0xFF);
    idtr_ptr[5] = @truncate((idt_physical_addr >> 24) & 0xFF);

    serial.println("[SMP] Fixed IDTR: limit=0x{x}, base=0x{x}", .{ idt_limit, idt_physical_addr });

    // Ensure all CPUs see the changes (memory barrier)
    asm volatile ("mfence" ::: "memory");

    // Verify trampoline is still intact after setup
    const verify_ptr = @as([*]const u8, @ptrFromInt(TRAMPOLINE_ADDR));
    serial.print("[SMP] Trampoline verification after setup: ", .{});
    for (0..16) |i| {
        serial.print("{x:0>2} ", .{verify_ptr[i]});
    }
    serial.println("", .{});
    if (verify_ptr[0] != 0xFA) { // Should start with cli
        serial.println("[SMP] ERROR: Trampoline corrupted immediately after setup!", .{});
    }
}

/// Find the ap_startup_data offset in a buffer
fn findStartupDataOffsetStatic(buffer: [*]const u8, size: usize) usize {
    // The ap_startup_data section starts with the GDT which has a known pattern:
    // - Null descriptor: 0x0000000000000000
    // - Code segment: 0x00CF9A000000FFFF
    // - Data segment: 0x00CF92000000FFFF

    // Search for the GDT pattern
    var offset: usize = 0;
    while (offset + 24 <= size) : (offset += 8) {
        const ptr = @as(*const [3]u64, @ptrFromInt(@intFromPtr(buffer) + offset));
        if (ptr[0] == 0x0000000000000000 and
            ptr[1] == 0x00CF9A000000FFFF and
            ptr[2] == 0x00CF92000000FFFF)
        {
            serial.println("[SMP] Found GDT at offset 0x{x}", .{offset});
            return offset;
        }
    }

    // If not found, use the expected offset (from symbol table)
    serial.println("[SMP] WARNING: Could not find GDT pattern, using default offset 0x170", .{});
    return 0x170; // 368 bytes from trampoline start
}

/// Find the ap_startup_data offset in the trampoline
fn findStartupDataOffset() usize {
    // The ap_startup_data section starts with the GDT which has a known pattern:
    // - Null descriptor: 0x0000000000000000
    // - Code segment: 0x00CF9A000000FFFF
    // - Data segment: 0x00CF92000000FFFF
    const trampoline_ptr = @as([*]const u8, @ptrFromInt(TRAMPOLINE_ADDR));
    const trampoline_size = 3024; // Total trampoline size including IDT

    // Search for the GDT pattern
    var offset: usize = 0;
    while (offset + 24 <= trampoline_size) : (offset += 8) {
        const ptr = @as(*const [3]u64, @ptrFromInt(@intFromPtr(trampoline_ptr) + offset));
        if (ptr[0] == 0x0000000000000000 and
            ptr[1] == 0x00CF9A000000FFFF and
            ptr[2] == 0x00CF92000000FFFF)
        {
            serial.println("[SMP] Found GDT at offset 0x{x}", .{offset});
            return offset;
        }
    }

    // If not found, use the expected offset (from symbol table)
    serial.println("[SMP] WARNING: Could not find GDT pattern, using default offset 0x170", .{});
    return 0x170; // 368 bytes from trampoline start
}

/// Update trampoline data for specific CPU
fn updateTrampolineData(cpu_id: u32, stack_top: [*]u8, cpu_data: *per_cpu.CpuData) usize {
    // Find the actual offset of ap_startup_data
    const ap_startup_data_offset = findStartupDataOffset();

    const trampoline_base = TRAMPOLINE_ADDR;

    // Calculate addresses of each field
    const pml4_addr_ptr = @as(*u32, @ptrFromInt(trampoline_base + ap_startup_data_offset + TrampolineOffsets.pml4_addr_offset));
    const entry_point_ptr = @as(*u64, @ptrFromInt(trampoline_base + ap_startup_data_offset + TrampolineOffsets.entry_point_offset));
    const cpu_id_ptr = @as(*u32, @ptrFromInt(trampoline_base + ap_startup_data_offset + TrampolineOffsets.cpu_id_offset));
    const stack_array_ptr = @as(*[64]u64, @ptrFromInt(trampoline_base + ap_startup_data_offset + TrampolineOffsets.stack_array_offset));

    // Get current CR3 (physical address of PML4)
    const cr3 = asm volatile ("mov %%cr3, %[cr3]"
        : [cr3] "=r" (-> u64),
    );

    // Update PML4 address (32-bit physical address)
    pml4_addr_ptr.* = @truncate(cr3);
    serial.println("[SMP] Set ap_pml4_addr to 0x{x}", .{pml4_addr_ptr.*});

    // Update entry point (64-bit virtual address)
    const entry_addr = @intFromPtr(&apMainEntry);
    entry_point_ptr.* = entry_addr;
    serial.println("[SMP] Set ap_entry_point to 0x{x}", .{entry_addr});

    // Update CPU ID
    cpu_id_ptr.* = cpu_id;
    serial.println("[SMP] Set ap_cpu_id to {}", .{cpu_id});

    // Update stack pointer for this CPU
    stack_array_ptr[cpu_id] = @intFromPtr(stack_top);
    serial.println("[SMP] Set ap_stack_array[{}] to 0x{x}", .{ cpu_id, @intFromPtr(stack_top) });

    // Verify the GDT hasn't been corrupted
    // GDTR is 6 bytes: 2 bytes limit + 4 bytes base
    const gdtr_ptr = @as(*const [6]u8, @ptrFromInt(trampoline_base + ap_startup_data_offset + TrampolineOffsets.gdtr_offset));
    const gdtr_bytes = gdtr_ptr.*;

    // Debug: show what's actually at the GDTR location
    serial.print("[SMP] GDTR bytes at offset 0x{x}: ", .{TrampolineOffsets.gdtr_offset});
    for (gdtr_bytes) |byte| {
        serial.print("{x:0>2} ", .{byte});
    }
    serial.println("", .{});

    const gdtr_limit = @as(u16, gdtr_bytes[0]) | (@as(u16, gdtr_bytes[1]) << 8);
    const gdtr_base = @as(u32, gdtr_bytes[2]) |
        (@as(u32, gdtr_bytes[3]) << 8) |
        (@as(u32, gdtr_bytes[4]) << 16) |
        (@as(u32, gdtr_bytes[5]) << 24);
    // The GDTR base should point to the GDT at the start of ap_startup_data
    const expected_base = @as(u32, @truncate(trampoline_base + ap_startup_data_offset));
    serial.println("[SMP] GDTR: limit=0x{x}, base=0x{x} (expected: 0x27, 0x{x})", .{ gdtr_limit, gdtr_base, expected_base });

    if (gdtr_limit != 0x27 or gdtr_base != expected_base) {
        serial.println("[SMP] WARNING: GDTR values don't match expected values!", .{});

        // Let's search for the actual GDTR pattern
        serial.println("[SMP] Searching for GDTR pattern...", .{});
        var search_offset: usize = 0;
        while (search_offset + 6 <= 200) : (search_offset += 1) {
            const search_ptr = @as(*const [6]u8, @ptrFromInt(trampoline_base + ap_startup_data_offset + search_offset));
            const search_bytes = search_ptr.*;
            const search_limit = @as(u16, search_bytes[0]) | (@as(u16, search_bytes[1]) << 8);
            const search_base = @as(u32, search_bytes[2]) |
                (@as(u32, search_bytes[3]) << 8) |
                (@as(u32, search_bytes[4]) << 16) |
                (@as(u32, search_bytes[5]) << 24);
            if (search_limit == 0x27 and search_base == expected_base) {
                serial.println("[SMP] Found GDTR at offset 0x{x}!", .{search_offset});
                break;
            }
        }
    }

    // Store in startup state
    startup_state.ap_stack_top = stack_top;
    startup_state.ap_cpu_data = cpu_data;

    // Ensure all writes are visible with full memory barrier
    ap_sync.memoryBarrier();

    return ap_startup_data_offset;
}

/// Simple busy wait for AP startup (doesn't require interrupts or TSC)
fn busyWait(iterations: u32) void {
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        asm volatile ("pause" ::: "memory");
    }
}

/// PIT-based delay using polling (no interrupts required)
/// Uses PIT channel 2 which is typically used for PC speaker
fn pitPollingDelay(microseconds: u64) void {
    // PIT frequency is 1193182 Hz
    const PIT_FREQUENCY: u64 = 1193182;

    // Calculate ticks needed (with bounds checking)
    const ticks_needed = (PIT_FREQUENCY * microseconds) / 1_000_000;
    if (ticks_needed == 0) return; // Too short to measure
    if (ticks_needed > 0xFFFF) {
        // Too long for one PIT cycle, break into chunks
        const chunks = ticks_needed / 0xFFFF;
        const remainder = ticks_needed % 0xFFFF;

        var i: u64 = 0;
        while (i < chunks) : (i += 1) {
            pitPollingDelayTicks(0xFFFF);
        }
        if (remainder > 0) {
            pitPollingDelayTicks(@intCast(remainder));
        }
        return;
    }

    pitPollingDelayTicks(@intCast(ticks_needed));
}

/// Helper to delay for a specific number of PIT ticks
fn pitPollingDelayTicks(ticks: u16) void {
    const PIT_CHANNEL2: u16 = 0x42;
    const PIT_COMMAND: u16 = 0x43;
    const PIT_CONTROL: u16 = 0x61;

    // Save current state of port 0x61
    const saved_state = asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (PIT_CONTROL),
    );

    // Configure PIT channel 2 for one-shot mode
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0xB0)), // Channel 2, LSB/MSB, mode 0
          [port] "N{dx}" (PIT_COMMAND),
    );

    // Load counter value
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, @truncate(ticks & 0xFF))),
          [port] "N{dx}" (PIT_CHANNEL2),
    );
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, @truncate(ticks >> 8))),
          [port] "N{dx}" (PIT_CHANNEL2),
    );

    // Enable gate and disable speaker
    const new_state = (saved_state & 0xFC) | 0x01;
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (new_state),
          [port] "N{dx}" (PIT_CONTROL),
    );

    // Poll until counter reaches 0 (OUT2 goes high)
    while (true) {
        const status = asm volatile ("inb %[port], %[result]"
            : [result] "={al}" (-> u8),
            : [port] "N{dx}" (PIT_CONTROL),
        );
        if ((status & 0x20) != 0) break; // Check OUT2 bit
        asm volatile ("pause" ::: "memory");
    }

    // Restore original state
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (saved_state),
          [port] "N{dx}" (PIT_CONTROL),
    );
}

/// Send INIT-SIPI-SIPI sequence to start AP
fn sendInitSipiSipi(apic_id: u8) !void {
    // Disable interrupts for the entire sequence
    asm volatile ("cli" ::: "memory");
    defer asm volatile ("sti" ::: "memory");

    // Also disable NMIs to prevent any interruption during SIPI
    // Save current CMOS address register state
    const saved_cmos = asm volatile ("inb $0x70, %[result]"
        : [result] "={al}" (-> u8),
    );
    // Set bit 7 to disable NMIs
    asm volatile ("outb %[val], $0x70"
        :
        : [val] "{al}" (saved_cmos | 0x80),
    );
    defer {
        // Re-enable NMIs on exit
        asm volatile ("outb %[val], $0x70"
            :
            : [val] "{al}" (saved_cmos & 0x7F),
        );
    }

    // Clear debug marker locations before starting
    // Important: Don't clear the trampoline area (0x8000), only debug areas
    // NOTE: These addresses must be within mapped memory regions
    // Make sure these locations are accessible before writing
    const debug_addr_3 = @as(*volatile u32, @ptrFromInt(0x7000));

    // Clear debug markers at beginning of debug range
    const early_marker_1 = @as(*volatile u16, @ptrFromInt(0x6FF0));
    const early_marker_2 = @as(*volatile u16, @ptrFromInt(0x6FF2));
    const clear_lgdt_marker = @as(*volatile u16, @ptrFromInt(0x6FF4));
    const clear_cr0_marker = @as(*volatile u16, @ptrFromInt(0x6FF6));
    const clear_exception_marker = @as(*volatile u32, @ptrFromInt(0x6FF8));
    const clear_pm_marker = @as(*volatile u32, @ptrFromInt(0x6FFC));
    const clear_stack_debug = @as(*volatile u64, @ptrFromInt(0x7010));

    // Try to clear them, but don't fail if they're not accessible
    early_marker_1.* = 0;
    early_marker_2.* = 0;
    debug_addr_3.* = 0; // Clear magic at 0x7000
    clear_lgdt_marker.* = 0;
    clear_cr0_marker.* = 0;
    clear_exception_marker.* = 0;
    clear_pm_marker.* = 0;
    clear_stack_debug.* = 0;

    // Ensure writes are visible
    asm volatile ("mfence" ::: "memory");

    // Immediately verify the clear worked
    const verify_region = @as([*]const volatile u8, @ptrFromInt(0x6FF0));
    var all_zero = true;
    for (0..32) |i| {
        if (verify_region[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (!all_zero) {
        serial.println("[SMP] WARNING: Debug region not properly cleared!", .{});
        serial.print("[SMP]   Region content: ", .{});
        for (0..16) |i| {
            serial.print("{x:0>2} ", .{verify_region[i]});
        }
        serial.println("", .{});
    }

    // Ensure the trampoline is still intact
    const tramp_ptr = @as([*]const volatile u8, @ptrFromInt(TRAMPOLINE_ADDR));
    if (tramp_ptr[0] != 0xFA) { // Should start with cli
        serial.println("[SMP] ERROR: Trampoline corrupted before SIPI! First byte: 0x{x} (expected 0xFA)", .{tramp_ptr[0]});

        // Dump more info about the corruption
        serial.print("[SMP] Trampoline area corrupted to: ", .{});
        const corrupt_bytes = @as([*]const volatile u8, @ptrFromInt(TRAMPOLINE_ADDR));
        for (0..16) |i| {
            serial.print("{x:0>2} ", .{corrupt_bytes[i]});
        }
        serial.println("", .{});

        return error.TrampolineCorrupted;
    }

    // Verify this CPU's APIC ID
    const bsp_apic_id = apic.getID();
    serial.println("[SMP] BSP APIC ID: {}, Target AP APIC ID: {}", .{ bsp_apic_id, apic_id });
    if (bsp_apic_id == apic_id) {
        serial.println("[SMP] ERROR: Trying to send IPI to self!", .{});
        return error.InvalidAPICID;
    }

    // Check APIC state before sending INIT
    const esr_before = apic.readRegister(0x280); // APIC_ESR
    if (esr_before != 0) {
        serial.println("[SMP] WARNING: APIC ESR=0x{x} before INIT", .{esr_before});
        // Clear ESR
        apic.writeRegister(0x280, 0);
        _ = apic.readRegister(0x280);
    }

    // Send INIT IPI
    serial.println("[SMP] Sending INIT IPI to APIC ID {}", .{apic_id});

    // CRITICAL: For modern CPUs, send INIT-deassert first (legacy compatibility)
    // This ensures the AP is in a known state
    try apic.sendIPI(apic_id, 0, .Init, .Deassert, .Level, .NoShorthand);
    busyWait(10000); // Short delay

    // Now send the actual INIT assert
    try apic.sendIPI(apic_id, 0, .Init, .Assert, .Edge, .NoShorthand);

    // Wait 10ms using PIT polling (Intel SDM requirement)
    serial.println("[SMP] Waiting 10ms after INIT...", .{});
    pitPollingDelay(10_000); // 10ms = 10,000 microseconds

    // Additional synchronization delay
    ap_sync.apStartupDelay(10_000);

    // Check ICR status after INIT
    const icr_after_init = apic.readRegister(0x300); // APIC_ICR_LOW
    serial.println("[SMP] ICR after INIT wait: 0x{x}", .{icr_after_init});

    // Wait for delivery status to clear
    var wait_count: u32 = 0;
    while ((apic.readRegister(0x300) & (1 << 12)) != 0 and wait_count < 1000) {
        busyWait(1000);
        wait_count += 1;
    }
    if (wait_count > 0) {
        serial.println("[SMP] Waited {} iterations for INIT delivery status to clear", .{wait_count});
    }

    // Dump memory to check if it's been overwritten during INIT
    serial.print("[SMP] Trampoline after INIT: ", .{});
    const init_check = @as([*]const u8, @ptrFromInt(TRAMPOLINE_ADDR));
    for (0..16) |i| {
        serial.print("{x:0>2} ", .{init_check[i]});
    }
    serial.println("", .{});

    // Verify trampoline is still intact after INIT
    const check_ptr = @as([*]const u8, @ptrFromInt(TRAMPOLINE_ADDR));
    if (check_ptr[0] != 0xFA) { // Should start with cli
        serial.println("[SMP] WARNING: Trampoline corrupted after INIT! First byte: 0x{x} (expected 0xFA)", .{check_ptr[0]});
    }

    // Check interrupt flag status
    const flags = asm volatile ("pushfq; popq %[flags]"
        : [flags] "=r" (-> u64),
    );
    const if_enabled = (flags & 0x200) != 0; // IF is bit 9
    serial.println("[SMP] Interrupt flag status before SIPI: {} (flags=0x{x})", .{ if_enabled, flags });

    // Final verification before SIPI
    const pre_sipi_check = @as([*]const u8, @ptrFromInt(TRAMPOLINE_ADDR));
    if (pre_sipi_check[0] != 0xFA) { // Should start with cli
        serial.println("[SMP] CRITICAL: Trampoline corrupted right before SIPI!", .{});
        serial.print("[SMP] First bytes: ", .{});
        for (0..16) |i| {
            serial.print("{x:0>2} ", .{pre_sipi_check[i]});
        }
        serial.println("", .{});
        return error.TrampolineCorrupted;
    }

    // CRITICAL: Before sending SIPI, ensure the BSP is in a stable state
    // Some systems hang if SIPI is sent while certain operations are pending
    asm volatile ("mfence; lfence" ::: "memory");

    // Send first SIPI with vector 0x08 (0x8000 >> 12)
    // SIPI vector is the page number (address >> 12), so 0x08 = 0x8000
    serial.println("[SMP] Sending first SIPI with vector 0x08 (starts at 0x8000)", .{});

    // WORKAROUND: Some systems require a small delay before SIPI
    busyWait(1000);

    try apic.sendIPI(apic_id, 0x08, .Startup, .Assert, .Edge, .NoShorthand);

    // Wait 200us (0.2ms) between SIPIs as per Intel SDM
    serial.println("[SMP] Waiting 200us between SIPIs...", .{});
    pitPollingDelay(200); // Wait 200 microseconds

    // Additional synchronization delay
    ap_sync.apStartupDelay(5_000);

    // Send second SIPI
    serial.println("[SMP] Sending second SIPI with vector 0x08", .{});
    try apic.sendIPI(apic_id, 0x08, .Startup, .Assert, .Edge, .NoShorthand);

    // Add a delay after second SIPI to ensure it completes and avoid race
    ap_sync.apStartupDelay(50_000); // 50k pause cycles

    serial.println("[SMP] INIT-SIPI-SIPI sequence complete", .{});

    // Clear debug memory region before checking
    const debug_region = @as([*]volatile u8, @ptrFromInt(0x6FF0));
    for (0..0x30) |i| {
        debug_region[i] = 0;
    }
    ap_sync.memoryBarrier();

    // Give AP a moment to start and check debug location immediately
    ap_sync.apStartupDelay(10_000); // Short wait
    const debug_ptr = @as(*align(1) volatile ap_debug.TrampolineDebug, @ptrFromInt(ap_debug.TRAMPOLINE_DEBUG_ADDR));
    serial.println("[SMP] Immediate debug check at 0x7000:", .{});
    serial.print("[SMP]   First 16 bytes at 0x6FF0: ", .{});
    const debug_bytes = @as([*]const u8, @ptrFromInt(0x6FF0));
    for (0..16) |i| {
        serial.print("{x:0>2} ", .{debug_bytes[i]});
    }
    serial.println("", .{});
    if (debug_ptr.magic == 0x12345678) {
        serial.println("[SMP]   AP wrote debug info! CPU={}, stage={}", .{ debug_ptr.cpu_id, debug_ptr.stage });
    } else {
        serial.println("[SMP]   No debug info written yet (magic=0x{x})", .{debug_ptr.magic});
    }

    // Check for simple markers
    const early_marker_ptr = @as(*volatile u16, @ptrFromInt(0x6FF0));
    const marker_ptr = @as(*volatile u16, @ptrFromInt(0x6FF2));
    const lgdt_marker = @as(*volatile u16, @ptrFromInt(0x6FF4));
    const cr0_marker = @as(*volatile u16, @ptrFromInt(0x6FF6));
    const exception_marker = @as(*volatile u32, @ptrFromInt(0x6FF8));
    const pm_marker = @as(*volatile u32, @ptrFromInt(0x6FFC));
    const stack_value = @as(*volatile u64, @ptrFromInt(0x7010));
    serial.println("[SMP]   Early marker at 0x6FF0: 0x{x} (should be 0xDEAD if AP executed)", .{early_marker_ptr.*});
    serial.println("[SMP]   Marker at 0x6FF2: 0x{x} (should be 0xBEEF if AP started)", .{marker_ptr.*});
    serial.println("[SMP]   Post-lgdt marker at 0x6FF4: 0x{x} (should be 0x1111 if lgdt succeeded)", .{lgdt_marker.*});
    serial.println("[SMP]   Post-CR0 marker at 0x6FF6: 0x{x} (should be 0x2222 if CR0 modified)", .{cr0_marker.*});
    serial.println("[SMP]   Exception marker at 0x6FF8: 0x{x} (should be 0 if no exception)", .{exception_marker.*});
    serial.println("[SMP]   PM entry marker at 0x6FFC: 0x{x} (should be 0x3333 if reached 32-bit mode)", .{pm_marker.*});
    serial.println("[SMP]   Stack value at 0x7010: 0x{x} (stack pointer in long mode)", .{stack_value.*});

    // Also dump the first part of the trampoline to verify it looks correct
    serial.println("[SMP] Trampoline first 64 bytes:", .{});
    const tramp_bytes = @as([*]const u8, @ptrFromInt(TRAMPOLINE_ADDR));
    var j: usize = 0;
    while (j < 64) : (j += 16) {
        serial.print("[SMP]   0x{x:0>4}: ", .{j});
        var k: usize = 0;
        while (k < 16 and j + k < 64) : (k += 1) {
            serial.print("{x:0>2} ", .{tramp_bytes[j + k]});
        }
        serial.println("", .{});
    }
}

/// Start all Application Processors
pub fn startAllAPs(processor_info: []const per_cpu.ProcessorInfo) !void {
    serial.println("[SMP] Starting {} Application Processors", .{processor_info.len - 1});

    // Initialize debug state
    ap_debug.init(@intCast(processor_info.len - 1));

    // Initialize AP startup barrier
    const ap_count = @as(u32, @intCast(processor_info.len - 1));
    ap_startup_barrier = ap_sync.ApBarrier.init(ap_count);
    barrier_initialized = true;

    // Reset startup state
    @atomicStore(u32, &startup_state.ap_ready_count, 0, .release);
    @atomicStore(u32, &startup_state.ap_boot_error, 0, .release);
    @atomicStore(bool, &startup_state.proceed_signal, false, .release);

    // Start each AP (skip BSP which is CPU 0)
    for (processor_info[1..], 1..) |proc, cpu_id| {
        if (proc.flags & 1 != 0) { // Check if processor is enabled
            try initAP(@intCast(cpu_id), @intCast(proc.apic_id));
        }
    }

    // Wait for all APs to reach ready state
    if (!ap_debug.waitForStage(.SignaledReady, 2000)) { // 2 second timeout
        // Print detailed debug info
        const summary = ap_debug.getApSummary();
        serial.println("[SMP] AP startup incomplete. Summary:", .{});
        serial.println("  Not started: {}", .{summary.not_started});
        serial.println("  In trampoline: {}", .{summary.in_trampoline});
        serial.println("  Initializing: {}", .{summary.initializing});
        serial.println("  Ready: {}", .{summary.ready});
        serial.println("  Failed: {}", .{summary.failed});

        // Dump debug info to memory for debugger
        ap_debug.dumpDebugInfo();
    }

    // Release the startup barrier to let APs proceed
    ap_startup_barrier.release();

    // Signal all APs to proceed
    @atomicStore(bool, &startup_state.proceed_signal, true, .release);

    // Report AP alive counter
    const alive_count = @atomicLoad(u32, &ap_alive_counter, .acquire);
    serial.println("[SMP] All APs started and ready", .{});
    serial.println("[SMP] AP alive counter: {} (expected: {})", .{ alive_count, processor_info.len - 1 });

    // Show debug summary
    const summary = ap_debug.getApSummary();
    serial.println("[SMP] Debug Summary:", .{});
    serial.println("  Not started: {}", .{summary.not_started});
    serial.println("  In trampoline: {}", .{summary.in_trampoline});
    serial.println("  Initializing: {}", .{summary.initializing});
    serial.println("  Ready: {}", .{summary.ready});
    serial.println("  Running: {}", .{summary.running});
    serial.println("  Failed: {}", .{summary.failed});
    serial.println("  Total errors: {}", .{summary.total_errors});
}

/// Entry point for APs (called from assembly trampoline)
export fn apMainEntry(cpu_id: u32) callconv(.C) noreturn {
    // This is called with interrupts disabled

    // Add a small delay to ensure BSP has completed SIPI and released locks
    ap_sync.apStartupDelay(100_000); // 100k pause cycles

    // Increment alive counter to verify AP is executing
    _ = @atomicRmw(u32, &ap_alive_counter, .Add, 1, .seq_cst);

    // Update debug state
    ap_debug.updateApStage(cpu_id, .KernelEntry);

    // Wait at startup barrier before accessing shared resources
    if (barrier_initialized) {
        const wait_result = ap_startup_barrier.wait(10_000_000); // ~10M cycles timeout
        if (!wait_result) {
            // Timeout waiting at barrier
            ap_debug.recordApError(cpu_id, 0xBAD1, ap_debug.DebugFlags.TIMEOUT);
            while (true) {
                asm volatile ("hlt");
            }
        }
    }

    // Get the correct per-CPU data for this CPU
    const cpu_data = &per_cpu.cpu_data_array[cpu_id];

    // Call the real AP main function
    @import("ap_entry.zig").apMain(cpu_id, cpu_data) catch {
        // Record error and halt
        @atomicStore(u32, &startup_state.ap_boot_error, 1, .release);
        ap_debug.recordApError(cpu_id, 1, ap_debug.DebugFlags.EXCEPTION);
        while (true) {
            asm volatile ("hlt");
        }
    };

    // This point should never be reached, but ensure we don't return
    while (true) {
        asm volatile ("hlt");
    }
}

/// Get AP startup state for debugging
pub fn getStartupState() *const ApStartupState {
    return &startup_state;
}
