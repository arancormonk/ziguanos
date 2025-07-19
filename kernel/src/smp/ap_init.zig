// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const apic = @import("../x86_64/apic.zig");
const apic_unified = @import("../x86_64/apic_unified.zig");
const paging = @import("../x86_64/paging.zig");
const paging_constants = @import("../x86_64/paging/constants.zig");
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
const cpu_init = @import("../x86_64/cpu_init.zig");
const gdt = @import("../x86_64/gdt.zig");
const idt = @import("../x86_64/idt.zig");
const UefiApManager = @import("uefi_ap_manager.zig").UefiApManager;
const ap_startup_sequence = @import("ap_startup_sequence.zig");
const boot_protocol = @import("shared");
const ap_state_validator = @import("ap_state_validator.zig");

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

// UEFI AP manager (initialized from boot info)
var uefi_ap_manager: ?UefiApManager = null;

// Simple verification counter that APs increment
pub var ap_alive_counter: u32 = 0;

// Initialize UEFI AP manager from boot info
pub fn initUefiApManager(boot_info: *const boot_protocol.BootInfo) void {
    uefi_ap_manager = UefiApManager.init(boot_info);
    if (uefi_ap_manager) |*manager| {
        manager.prepareApStartup();
    }
}

// Intel SDM 10.4.4: Lock Semaphore for AP initialization
var lock_semaphore: std.atomic.Value(u32) = std.atomic.Value(u32).init(0); // 0 = VACANT

// AP startup barrier for synchronization
var ap_startup_barrier: ap_sync.ApBarrier = undefined;
var barrier_initialized: bool = false;

// Trampoline location in low memory
// Intel SDM 10.4.4: Startup IPI vector specifies 4KB page number
// Note: Some systems clear memory during INIT-SIPI-SIPI
// Try 0x8000 which is in conventional memory (page 8)
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
    // ap_entry_point starts after pml4_addr (8 bytes now) - no alignment needed
    const entry_point_offset: usize = 0x850; // 2128 bytes from ap_startup_data
    // ap_cpu_id starts after entry_point (8 bytes)
    const cpu_id_offset: usize = 0x858; // 2136 bytes from ap_startup_data
    // ap_stack_array starts after cpu_id (4 bytes) + alignment to 8
    const stack_array_offset: usize = 0x860; // 2144 bytes from ap_startup_data
    // ap_kernel_gdtr starts after stack array (256 * 8 = 2048 bytes) + alignment to 16
    // NOTE: This is beyond the current trampoline size!
    const kernel_gdtr_offset: usize = 0x1070; // 4208 bytes from ap_startup_data
    // ap_kernel_idtr starts after gdtr (2 + 8 = 10 bytes) + alignment to 16
    const kernel_idtr_offset: usize = 0x1080; // 4224 bytes from ap_startup_data
};

// MSR constants for MTRRs
pub const MTRR_DEF_TYPE = 0x2FF;
pub const MTRR_FIX_64K_00000 = 0x250;
pub const MTRR_FIX_16K_80000 = 0x258;
pub const MTRR_FIX_16K_A0000 = 0x259;
pub const MTRR_FIX_4K_C0000 = 0x268;
pub const MTRR_FIX_4K_C8000 = 0x269;
pub const MTRR_FIX_4K_D0000 = 0x26A;
pub const MTRR_FIX_4K_D8000 = 0x26B;
pub const MTRR_FIX_4K_E0000 = 0x26C;
pub const MTRR_FIX_4K_E8000 = 0x26D;
pub const MTRR_FIX_4K_F0000 = 0x26E;
pub const MTRR_FIX_4K_F8000 = 0x26F;
pub const MTRR_PHYSBASE0 = 0x200;
pub const MTRR_PHYSMASK0 = 0x201;
pub const MTRRCAP = 0xFE;

// Memory types
pub const MEM_TYPE_UC = 0;
pub const MEM_TYPE_WC = 1;
pub const MEM_TYPE_WT = 4;
pub const MEM_TYPE_WP = 5;
pub const MEM_TYPE_WB = 6;

fn getMemoryType(phys_addr: u64) u8 {
    const cap = cpu_init.readMSR(MTRRCAP);
    const var_count = @as(u8, @truncate(cap & 0xFF));
    const fixed_support = (cap & (1 << 8)) != 0;
    const wc_support = (cap & (1 << 10)) != 0;
    // Ignore wc_support for now
    _ = wc_support;

    const def_type_msr = cpu_init.readMSR(MTRR_DEF_TYPE);
    const mtrr_enable = (def_type_msr & (1 << 11)) != 0;
    const fixed_enable = (def_type_msr & (1 << 10)) != 0;
    var effective_type: u8 = @truncate(def_type_msr & 0xFF);

    if (!mtrr_enable) return effective_type;

    // Check fixed MTRRs if enabled and address < 1MB
    if (fixed_enable and fixed_support and phys_addr < 0x100000) {
        var fixed_msr: u32 = undefined;
        var offset: u64 = undefined;

        if (phys_addr < 0x80000) {
            fixed_msr = MTRR_FIX_64K_00000;
            offset = phys_addr / 0x10000;
        } else if (phys_addr < 0xC0000) {
            fixed_msr = MTRR_FIX_16K_80000 + @as(u32, @truncate((phys_addr - 0x80000) / 0x4000));
            offset = (phys_addr % 0x4000) / 0x800;
        } else {
            fixed_msr = MTRR_FIX_4K_C0000 + @as(u32, @truncate((phys_addr - 0xC0000) / 0x1000));
            offset = (phys_addr % 0x1000) / 0x200;
        }

        const fixed_value = cpu_init.readMSR(fixed_msr);
        const shift: u6 = @intCast(offset * 8);
        effective_type = @as(u8, @truncate((fixed_value >> shift) & 0xFF));
    }

    // Apply variable MTRRs (they override fixed)
    var i: u32 = 0;
    while (i < var_count) : (i += 1) {
        const mask = cpu_init.readMSR(MTRR_PHYSMASK0 + 2 * i);
        if ((mask & (1 << 11)) == 0) continue; // Invalid

        const base = cpu_init.readMSR(MTRR_PHYSBASE0 + 2 * i);
        if ((phys_addr & mask & paging_constants.PHYS_ADDR_MASK) == (base & mask & paging_constants.PHYS_ADDR_MASK)) {
            effective_type = @as(u8, @truncate(base & 0xFF));
        }
    }

    return effective_type;
}

fn setVariableMTRR(base_addr: u64, size: u64, mem_type: u8) !void {
    if (size != 4096) return error.InvalidSize; // Only support 4KB for now

    const cap = cpu_init.readMSR(MTRRCAP);
    const var_count: u8 = @truncate(cap & 0xFF);

    // Find free slot
    var slot: ?u32 = null;
    var i: u32 = 0;
    while (i < var_count) : (i += 1) {
        const mask = cpu_init.readMSR(MTRR_PHYSMASK0 + 2 * i);
        if ((mask & (1 << 11)) == 0) {
            slot = i;
            break;
        }
    }
    if (slot == null) return error.NoFreeMTRR;

    // Sequence to change MTRR
    asm volatile ("cli" ::: "memory");
    asm volatile ("wbinvd" ::: "memory");
    var cr0 = asm volatile ("mov %%cr0, %[cr0]"
        : [cr0] "=r" (-> u64),
    );
    cr0 |= @as(u64, 1 << 30); // CD=1
    cr0 &= ~@as(u64, 1 << 29); // NW=0
    asm volatile ("mov %[cr0], %%cr0"
        :
        : [cr0] "r" (cr0),
        : "memory"
    );
    asm volatile ("wbinvd" ::: "memory");

    var def = cpu_init.readMSR(MTRR_DEF_TYPE);
    def &= ~@as(u64, 1 << 11); // Disable MTRRs
    cpu_init.writeMSR(MTRR_DEF_TYPE, def);

    // Set the variable MTRR
    const mtrr_base = (base_addr & ~@as(u64, 0xFFF)) | mem_type;
    const mtrr_mask = 0xFFFFF000 | @as(u64, 1 << 11);
    cpu_init.writeMSR(MTRR_PHYSBASE0 + 2 * slot.?, mtrr_base);
    cpu_init.writeMSR(MTRR_PHYSMASK0 + 2 * slot.?, mtrr_mask);

    asm volatile ("wbinvd" ::: "memory");
    def |= @as(u64, 1 << 11); // Enable MTRRs
    cpu_init.writeMSR(MTRR_DEF_TYPE, def);
    asm volatile ("wbinvd" ::: "memory");
    cr0 &= ~@as(u64, 1 << 30); // CD=0
    cr0 &= ~@as(u64, 1 << 29); // NW=0
    asm volatile ("mov %[cr0], %%cr0"
        :
        : [cr0] "r" (cr0),
        : "memory"
    );
    asm volatile ("wbinvd" ::: "memory");
    asm volatile ("sti" ::: "memory");

    serial.println("[SMP] Set MTRR slot {} for 0x{x}-0x{x} to type {}", .{ slot.?, base_addr, base_addr + size - 1, mem_type });
}

// Initialize an Application Processor
pub fn initAP(cpu_id: u32, apic_id: u8) !void {
    serial.println("[SMP] Starting AP: CPU {} (APIC ID {})", .{ cpu_id, apic_id });

    // Validate CPU ID
    if (cpu_id >= per_cpu.MAX_CPUS) {
        ap_debug.recordApError(cpu_id, @intFromEnum(ApError.InvalidCpuId), ap_debug.DebugFlags.INVALID_CPU_ID);
        return error.InvalidCpuId;
    }

    // Also check against trampoline limit
    if (cpu_id >= 256) {
        serial.println("[SMP] ERROR: CPU ID {} exceeds trampoline limit of 256", .{cpu_id});
        ap_debug.recordApError(cpu_id, @intFromEnum(ApError.InvalidCpuId), ap_debug.DebugFlags.INVALID_CPU_ID);
        return error.InvalidCpuId;
    }

    // Allocate stack for AP
    // Intel SDM Vol 3A Section 8.4.5: Stack must be 16-byte aligned
    serial.println("[SMP] Allocating {} KB stack for CPU {}", .{ AP_STACK_SIZE / 1024, cpu_id });

    // Allocate extra space to ensure we can align to 16 bytes
    const alloc_size = AP_STACK_SIZE + 16;
    const raw_stack = heap.heapAlloc(alloc_size) catch |err| {
        serial.println("[SMP] Failed to allocate stack for CPU {}: {s}", .{ cpu_id, error_utils.errorToString(err) });
        ap_debug.recordApError(cpu_id, @intFromEnum(ApError.StackAllocFailed), ap_debug.DebugFlags.STACK_ERROR);
        return error.StackAllocFailed;
    };

    // Align the stack bottom to 16 bytes
    const raw_addr = @intFromPtr(raw_stack);
    const aligned_bottom = (raw_addr + 15) & ~@as(usize, 15);
    const stack_bottom = @as([*]u8, @ptrFromInt(aligned_bottom));

    // Calculate aligned stack top
    // Intel SDM: RSP should be 16-byte aligned before CALL
    // We'll make it (16n - 8) so after CALL it becomes 16n
    const stack_top_aligned = aligned_bottom + AP_STACK_SIZE;
    const stack_top = @as([*]u8, @ptrFromInt((stack_top_aligned & ~@as(usize, 15)) - 8));

    serial.println("[SMP] Stack allocated at 0x{x} - 0x{x} (aligned from 0x{x})", .{ aligned_bottom, @intFromPtr(stack_top), raw_addr });

    // Verify alignment
    if (@intFromPtr(stack_bottom) & 15 != 0) {
        serial.println("[SMP] ERROR: Stack bottom not 16-byte aligned!", .{});
        return error.StackAlignmentError;
    }
    if ((@intFromPtr(stack_top) + 8) & 15 != 0) {
        serial.println("[SMP] ERROR: Stack top not properly aligned for calls!", .{});
        return error.StackAlignmentError;
    }

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
        .call_function = null,
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

    // Clear the debug memory region (0x500) before sending INIT-SIPI-SIPI
    // This ensures we can detect if the AP actually writes to it
    serial.println("[SMP] Clearing debug memory region at 0x500...", .{});
    const debug_region_ptr = @as([*]volatile u8, @ptrFromInt(0x500));
    @memset(debug_region_ptr[0..0x100], 0); // Clear 256 bytes
    asm volatile ("mfence" ::: "memory");

    // Verify the memory was cleared
    serial.print("[SMP] Debug region after clear: ", .{});
    for (0..16) |i| {
        serial.print("{x:0>2} ", .{debug_region_ptr[i]});
    }
    serial.println("", .{});

    // Intel SDM 11.12: Final cache coherency check before INIT-SIPI-SIPI
    // Ensure all memory operations are complete and visible to all processors
    asm volatile ("mfence" ::: "memory");

    // Flush the trampoline area one more time to ensure coherency
    var final_flush_addr: u64 = TRAMPOLINE_ADDR;
    while (final_flush_addr < TRAMPOLINE_ADDR + 4096) : (final_flush_addr += 64) {
        asm volatile ("clflush (%[addr])"
            :
            : [addr] "r" (final_flush_addr),
            : "memory"
        );
    }

    // Also flush the debug region
    var debug_flush_addr: u64 = 0x500;
    while (debug_flush_addr < 0x600) : (debug_flush_addr += 64) {
        asm volatile ("clflush (%[addr])"
            :
            : [addr] "r" (debug_flush_addr),
            : "memory"
        );
    }

    asm volatile ("mfence" ::: "memory");

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

    // Use validator to check if AP actually started
    const validator = ap_state_validator.ApStateValidator;
    var ap_started = validator.validateApStarted(cpu_id, 500) catch false; // 500ms initial check

    if (!ap_started) {
        serial.println("[SMP] AP {} did not start after INIT-SIPI-SIPI, diagnosing...", .{cpu_id});
        validator.diagnoseApFailure(cpu_id);

        // Try fallback mechanisms
        const ApFallback = @import("ap_fallback.zig").ApFallback;
        serial.println("[SMP] Attempting fallback startup methods for AP {}...", .{cpu_id});

        const trampoline_addr = @as(u16, @intCast(TRAMPOLINE_ADDR));
        ap_started = ApFallback.tryAlternativeStartup(apic_id, trampoline_addr) catch false;

        if (!ap_started) {
            serial.println("[SMP] All fallback methods failed for AP {}", .{cpu_id});
            ApFallback.diagnoseFailure(apic_id);
            ap_debug.recordApError(cpu_id, @intFromEnum(ApError.StartupTimeout), ap_debug.DebugFlags.TIMEOUT);
            // Continue without this AP
        } else {
            serial.println("[SMP] AP {} started using fallback method!", .{cpu_id});
        }
    } else {
        serial.println("[SMP] AP {} responded to INIT-SIPI-SIPI", .{cpu_id});
    }

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
                // Add memory barrier before reading to ensure coherency
                asm volatile ("mfence" ::: "memory");

                const debug_ptr = @as(*align(1) volatile ap_debug.TrampolineDebug, @ptrFromInt(ap_debug.TRAMPOLINE_DEBUG_ADDR));
                const early_marker = @as(*volatile u16, @ptrFromInt(0x510)).*;
                const marker = @as(*volatile u16, @ptrFromInt(0x512)).*;
                // Read lgdt_marker as volatile to avoid interference
                const lgdt_marker = @as(*volatile u16, @ptrFromInt(0x514)).*;
                const cr0_marker = @as(*volatile u16, @ptrFromInt(0x516)).*;
                const pm_marker = @as(*volatile u32, @ptrFromInt(0x51C)).*;
                const pae_marker = @as(*volatile u32, @ptrFromInt(0x520)).*;
                const cr3_marker = @as(*volatile u32, @ptrFromInt(0x524)).*;
                const lme_marker = @as(*volatile u32, @ptrFromInt(0x528)).*;
                const pg_marker = @as(*volatile u32, @ptrFromInt(0x52C)).*;

                if (debug_ptr.magic == 0x12345678 or early_marker != 0 or marker != 0 or lgdt_marker != 0 or cr0_marker != 0 or pm_marker != 0 or pae_marker != 0 or cr3_marker != 0 or lme_marker != 0 or pg_marker != 0) {
                    serial.println("[SMP] Direct debug check: magic=0x{x}, early=0x{x}, marker=0x{x}, lgdt=0x{x}, cr0=0x{x}, pm=0x{x}", .{
                        debug_ptr.magic,
                        early_marker,
                        marker,
                        lgdt_marker,
                        cr0_marker,
                        pm_marker,
                    });
                    if (pae_marker != 0 or cr3_marker != 0 or lme_marker != 0 or pg_marker != 0) {
                        serial.println("[SMP]   Long mode: pae=0x{x}, cr3=0x{x}, lme=0x{x}, pg=0x{x}", .{
                            pae_marker,
                            cr3_marker,
                            lme_marker,
                            pg_marker,
                        });
                    }
                    serial.println("[SMP]   CPU={}, stage={}", .{ debug_ptr.cpu_id, debug_ptr.stage });

                    // Also check for Zig entry marker at correct addresses
                    const zig_marker = @as(*volatile u32, @ptrFromInt(0x5B0)).*;
                    const zig_cpu_id = @as(*volatile u32, @ptrFromInt(0x5B4)).*;
                    if (zig_marker == 0xDEADC0DE) {
                        serial.println("[SMP]   ZIG ENTRY DETECTED! Marker=0x{x}, CPU={}", .{ zig_marker, zig_cpu_id });
                    } else if (zig_marker == 0xCAFEBABE) {
                        serial.println("[SMP]   Assembly pre-jump marker detected! CPU={}", .{zig_cpu_id});
                    }
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

// Setup the trampoline code in low memory
fn setupTrampoline() !void {
    const flags = startup_lock.acquire();
    defer startup_lock.release(flags);

    // Check if the memory has a suspicious pattern before setup
    checkMemoryPattern(TRAMPOLINE_ADDR, 256);

    // Also check the debug region
    serial.println("[SMP] Checking debug region at 0x500...", .{});
    checkMemoryPattern(0x500, 256);

    // CRITICAL: Ensure debug regions are properly accessible with correct memory type
    // These regions must be accessible to both BSP and AP with cache coherency
    serial.println("[SMP] Verifying debug region accessibility and coherency...", .{});

    // NOTE: We previously made the debug region uncacheable to avoid coherency issues,
    // but this causes problems with AP writes during CPU mode transitions.
    // The uncacheable memory semantics can corrupt writes when the CPU is switching
    // between real mode, protected mode, and long mode.
    // Instead, we'll rely on memory barriers and cache flushes for coherency.
    //
    // DO NOT make the debug region uncacheable - it causes AP startup failures!
    serial.println("[SMP] Debug region remains cacheable (using barriers for coherency)", .{});

    // Test the region is accessible
    const debug_test = @as(*volatile u32, @ptrFromInt(0x500));
    debug_test.* = 0xDEADBEEF;
    asm volatile ("mfence" ::: "memory");
    if (debug_test.* != 0xDEADBEEF) {
        serial.println("[SMP] ERROR: Debug region at 0x500 is not writable!", .{});
        serial.println("[SMP]   Wrote 0xDEADBEEF, read back 0x{x}", .{debug_test.*});
    } else {
        serial.println("[SMP] Debug region at 0x500 is writable and coherent", .{});
        debug_test.* = 0; // Clear it
        asm volatile ("mfence" ::: "memory");
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

    // Intel SDM 4.2: Ensure trampoline page is identity mapped
    // CRITICAL: The AP starts in real mode and needs identity mapping
    ensureTrampolineIdentityMapped() catch |err| {
        serial.println("[SMP] ERROR: Failed to ensure trampoline identity mapping: {s}", .{error_utils.errorToString(err)});
        return err;
    };

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

    // No need to patch lgdt instruction anymore since we'll patch the GDTR directly
    serial.println("[SMP] GDTR and IDTR will be patched directly in the data section", .{});

    // Also patch the IDT entries to point to the exception handler
    const exception_handler_addr = TRAMPOLINE_ADDR + findExceptionHandlerOffset(@as([*]const u8, @ptrCast(@volatileCast(dst))), trampoline_size);
    const idt_offset = ap_startup_data_offset + TrampolineOffsets.idt_offset;

    // Patch all 32 exception entries in the IDT
    for (0..32) |i| {
        const entry_offset = idt_offset + (i * 8);
        const entry_ptr = @as(*[8]u8, @ptrFromInt(TRAMPOLINE_ADDR + entry_offset));
        // Set offset 15:0
        entry_ptr[0] = @as(u8, @truncate(exception_handler_addr & 0xFF));
        entry_ptr[1] = @as(u8, @truncate((exception_handler_addr >> 8) & 0xFF));
        // Selector and flags are already set
        // Set offset 31:16 (for 32-bit mode, upper 16 bits of offset)
        entry_ptr[6] = @as(u8, @truncate((exception_handler_addr >> 16) & 0xFF));
        entry_ptr[7] = @as(u8, @truncate((exception_handler_addr >> 24) & 0xFF));
    }
    serial.println("[SMP] Patched IDT entries to point to exception handler at 0x{x}", .{exception_handler_addr});

    // Intel SDM 11.12: Memory type changes must be done carefully
    // For code regions, it's better to set cache attributes before copying code

    // Make the trampoline area executable (remove NX bit)
    paging.makeRegionExecutable(TRAMPOLINE_ADDR, trampoline_size) catch |err| {
        serial.println("[SMP] Failed to make trampoline executable: {s}", .{error_utils.errorToString(err)});
        return err;
    };

    // Intel SDM 11.12: Ensure page table changes are globally visible
    // Issue memory barrier to ensure all page table writes complete
    asm volatile ("mfence" ::: "memory");

    // Intel SDM 11.12.8: Flush cache lines containing modified page tables
    // This ensures the AP sees the updated page table entries
    // Flush the page table entries that map the trampoline area
    asm volatile ("clflush (%[addr])"
        :
        : [addr] "r" (@intFromPtr(&paging.pml4_table[0])),
        : "memory"
    );

    // Also flush any other relevant page table structures
    // The exact addresses depend on the page table hierarchy
    asm volatile ("mfence" ::: "memory");

    // Intel SDM 11.12.4: Don't change cache attributes of active code
    // The trampoline memory should remain cacheable for proper execution
    // Cache coherency is maintained via WBINVD in sendInitSipiSipi
    serial.println("[SMP] Trampoline area remains cacheable for execution", .{});

    // Fix up the GDTR base address in the trampoline
    // The GDTR in the trampoline has a relative base that needs to be adjusted
    // (we already found ap_startup_data_offset above)
    const gdtr_offset = ap_startup_data_offset + TrampolineOffsets.gdtr_offset;
    const gdtr_ptr = @as(*[6]u8, @ptrFromInt(TRAMPOLINE_ADDR + gdtr_offset));

    // The GDTR should point to the GDT at TRAMPOLINE_ADDR + ap_startup_data_offset
    const gdt_physical_addr = TRAMPOLINE_ADDR + ap_startup_data_offset;
    const gdt_limit: u16 = 39; // 5 entries * 8 bytes - 1 = 0x27

    // Write the correct GDTR (limit=0x27, base=physical address of GDT)
    gdtr_ptr[0] = @as(u8, @truncate(gdt_limit & 0xFF));
    gdtr_ptr[1] = @as(u8, @truncate((gdt_limit >> 8) & 0xFF));
    gdtr_ptr[2] = @as(u8, @truncate(gdt_physical_addr & 0xFF));
    gdtr_ptr[3] = @as(u8, @truncate((gdt_physical_addr >> 8) & 0xFF));
    gdtr_ptr[4] = @as(u8, @truncate((gdt_physical_addr >> 16) & 0xFF));
    gdtr_ptr[5] = @as(u8, @truncate((gdt_physical_addr >> 24) & 0xFF));

    serial.println("[SMP] Fixed GDTR: limit=0x{x}, base=0x{x}", .{ gdt_limit, gdt_physical_addr });

    // Fix up the IDTR base address in the trampoline
    const idtr_offset = ap_startup_data_offset + TrampolineOffsets.idtr_offset;
    const idtr_ptr = @as(*[6]u8, @ptrFromInt(TRAMPOLINE_ADDR + idtr_offset));

    // The IDTR should point to the IDT at TRAMPOLINE_ADDR + ap_startup_data_offset + idt_offset
    const idt_physical_addr = TRAMPOLINE_ADDR + ap_startup_data_offset + TrampolineOffsets.idt_offset;
    const idt_limit: u16 = 2047; // 256 entries * 8 bytes - 1 = 0x7FF

    // Write the correct IDTR (limit=0x7FF, base=physical address of IDT)
    idtr_ptr[0] = @as(u8, @truncate(idt_limit & 0xFF));
    idtr_ptr[1] = @as(u8, @truncate((idt_limit >> 8) & 0xFF));
    idtr_ptr[2] = @as(u8, @truncate(idt_physical_addr & 0xFF));
    idtr_ptr[3] = @as(u8, @truncate((idt_physical_addr >> 8) & 0xFF));
    idtr_ptr[4] = @as(u8, @truncate((idt_physical_addr >> 16) & 0xFF));
    idtr_ptr[5] = @as(u8, @truncate((idt_physical_addr >> 24) & 0xFF));

    serial.println("[SMP] Fixed IDTR: limit=0x{x}, base=0x{x}", .{ idt_limit, idt_physical_addr });

    // Verify the GDTR and IDTR are correctly set
    serial.println("[SMP] Verifying GDTR at offset 0x{x}:", .{gdtr_offset});
    serial.print("[SMP]   GDTR bytes: ", .{});
    for (gdtr_ptr.*) |byte| {
        serial.print("{x:0>2} ", .{byte});
    }
    serial.println("", .{});

    serial.println("[SMP] Verifying IDTR at offset 0x{x}:", .{idtr_offset});
    serial.print("[SMP]   IDTR bytes: ", .{});
    for (idtr_ptr.*) |byte| {
        serial.print("{x:0>2} ", .{byte});
    }
    serial.println("", .{});

    // CRITICAL: Also flush the debug memory regions that AP will write to
    // This prevents cache coherency issues between BSP and AP
    serial.println("[SMP] Flushing debug memory regions for cache coherency", .{});

    // Flush 0x500-0x520 region (debug area)
    var debug_addr: u64 = 0x500;
    while (debug_addr <= 0x558) : (debug_addr += 64) {
        asm volatile ("clflush (%[addr])"
            :
            : [addr] "r" (debug_addr),
            : "memory"
        );
    }

    // Ensure all cache flushes complete before proceeding
    asm volatile ("mfence" ::: "memory");

    // Additional serialization to ensure all pending stores are globally visible
    asm volatile ("cpuid" ::: "eax", "ebx", "ecx", "edx", "memory");

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

    // Add to setupTrampoline after ensureTrampolineIdentityMapped
    const tramp_mem_type = getMemoryType(TRAMPOLINE_ADDR);
    serial.println("[SMP] Trampoline at 0x{x} memory type: 0x{x}", .{ TRAMPOLINE_ADDR, tramp_mem_type });
    if (tramp_mem_type != MEM_TYPE_WB) {
        serial.println("[SMP] Overriding trampoline memory type to WB", .{});
        try setVariableMTRR(TRAMPOLINE_ADDR, 4096, MEM_TYPE_WB);
    }
}

// Ensure the trampoline memory is identity mapped
// Intel SDM 4.2: Identity mapping means virtual address = physical address
fn ensureTrampolineIdentityMapped() !void {
    // Intel SDM 10.4.4: The AP starts in real mode at the physical address
    // specified by the SIPI vector. This requires identity mapping.

    // CRITICAL: The low memory area (0x0 - 0x100000) needs to be accessible
    // for real mode operation. The AP will start at physical address 0x8000.

    // First, check if the page table exists for low memory
    // If not, we need to create the necessary page table hierarchy
    serial.println("[SMP] Ensuring identity mapping for trampoline at 0x{x}", .{TRAMPOLINE_ADDR});

    // The first GB should already be mapped with 2MB pages during paging initialization
    // Let's verify that the 2MB page covering our trampoline area is present
    serial.println("[SMP] Verifying low memory mapping...", .{});

    // Check if we can access the trampoline area
    const test_access = paging.getPhysicalAddress(TRAMPOLINE_ADDR) catch |err| {
        serial.println("[SMP] ERROR: Trampoline area at 0x{x} is not accessible: {s}", .{ TRAMPOLINE_ADDR, error_utils.errorToString(err) });

        // The first GB should be mapped with 2MB pages. If it's not accessible,
        // there's a fundamental issue with the page tables
        serial.println("[SMP] CRITICAL: Low memory is not mapped! This should have been done during paging init.", .{});

        // Try to diagnose the issue
        // Check if the PDPT entry for the first GB exists
        const pml4_entry = paging.pml4_table[0];
        serial.println("[SMP] PML4[0] = 0x{x}", .{pml4_entry});

        if ((pml4_entry & paging.PAGE_PRESENT) != 0) {
            // PML4 entry exists, check PDPT
            const pdpt_phys = pml4_entry & paging.PHYS_ADDR_MASK;
            const pdpt = @as(*[512]u64, @ptrFromInt(pdpt_phys));
            const pdpt_entry = pdpt[0];
            serial.println("[SMP] PDPT[0] = 0x{x}", .{pdpt_entry});

            if ((pdpt_entry & paging.PAGE_PRESENT) != 0) {
                // Check if it's a 1GB page or points to a PD
                if ((pdpt_entry & paging.PAGE_HUGE) != 0) {
                    serial.println("[SMP] First GB is mapped as a 1GB page", .{});
                } else {
                    // It points to a PD, check the PD entry
                    const pd_phys = pdpt_entry & paging.PHYS_ADDR_MASK;
                    const pd = @as(*[512]u64, @ptrFromInt(pd_phys));
                    const pd_entry_idx = (TRAMPOLINE_ADDR >> 21) & 0x1FF; // Index for 2MB page
                    const pd_entry = pd[pd_entry_idx];
                    serial.println("[SMP] PD[{}] (for address 0x{x}) = 0x{x}", .{ pd_entry_idx, TRAMPOLINE_ADDR, pd_entry });

                    if ((pd_entry & paging.PAGE_PRESENT) == 0) {
                        serial.println("[SMP] ERROR: The 2MB page containing trampoline is not present!", .{});
                    }
                }
            } else {
                serial.println("[SMP] ERROR: PDPT[0] is not present!", .{});
            }
        } else {
            serial.println("[SMP] ERROR: PML4[0] is not present!", .{});
        }

        return err;
    };

    // Mask off the NX bit to get the actual physical address
    const actual_phys = test_access & 0x000FFFFFFFFFF000;
    serial.println("[SMP] Trampoline area is accessible at physical address 0x{x} (raw: 0x{x})", .{ actual_phys, test_access });

    if (actual_phys != TRAMPOLINE_ADDR) {
        serial.println("[SMP] ERROR: Trampoline is not identity mapped! Phys 0x{x} != Virt 0x{x}", .{ actual_phys, TRAMPOLINE_ADDR });
        return error.IdentityMappingFailed;
    }

    // The area is already mapped correctly as part of a 2MB page
    serial.println("[SMP] Trampoline area is already identity mapped as part of 2MB page", .{});

    // For now, skip splitting the page - that seems to cause issues
    // We'll just make sure the trampoline area is executable later
    serial.println("[SMP] Using existing 2MB page mapping for trampoline", .{});

    // Verify debug region mapping
    _ = paging.getPhysicalAddress(0x500) catch |err| {
        serial.println("[SMP] WARNING: Debug region at 0x500 not mapped: {s}", .{error_utils.errorToString(err)});
        // This is OK - the debug region is in the first page which we skip for null protection
        // The important thing is that the trampoline at 0x8000 is accessible
    };

    serial.println("[SMP] Low memory mapping verification complete", .{});
    serial.println("[SMP] Trampoline at 0x{x} is identity mapped and ready", .{TRAMPOLINE_ADDR});
}

// Find the exception handler offset in the trampoline
fn findExceptionHandlerOffset(buffer: [*]const u8, size: usize) usize {
    // Look for the exception handler pattern:
    // movl $0xDEADBEEF, 0x518
    // This is: C7 05 18 05 00 00 EF BE AD DE
    const pattern = [_]u8{ 0xC7, 0x05, 0x18, 0x05, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE };

    var offset: usize = 0;
    while (offset + pattern.len <= size) : (offset += 1) {
        var match = true;
        for (pattern, 0..) |byte, i| {
            if (buffer[offset + i] != byte) {
                match = false;
                break;
            }
        }
        if (match) {
            serial.println("[SMP] Found exception handler at offset 0x{x}", .{offset});
            return offset;
        }
    }

    // If not found, assume it's near the beginning of protected mode section
    // The handler is defined right before ap_pm_entry
    serial.println("[SMP] WARNING: Could not find exception handler pattern, using estimated offset", .{});
    return 0x6F; // Approximate offset based on assembly listing
}

// Find the ap_startup_data offset in a buffer
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

// Find the ap_startup_data offset in the trampoline
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

// Update trampoline data for specific CPU
fn updateTrampolineData(cpu_id: u32, stack_top: [*]u8, cpu_data: *per_cpu.CpuData) usize {
    // Find the actual offset of ap_startup_data
    const ap_startup_data_offset = findStartupDataOffset();

    const trampoline_base = TRAMPOLINE_ADDR;

    // Calculate addresses of each field
    // CRITICAL: ap_pml4_addr is now 64-bit to support high memory
    const pml4_addr_ptr = @as(*u64, @ptrFromInt(trampoline_base + ap_startup_data_offset + TrampolineOffsets.pml4_addr_offset));
    const entry_point_ptr = @as(*u64, @ptrFromInt(trampoline_base + ap_startup_data_offset + TrampolineOffsets.entry_point_offset));
    const cpu_id_ptr = @as(*u32, @ptrFromInt(trampoline_base + ap_startup_data_offset + TrampolineOffsets.cpu_id_offset));
    const stack_array_ptr = @as(*[256]u64, @ptrFromInt(trampoline_base + ap_startup_data_offset + TrampolineOffsets.stack_array_offset));

    // Get current CR3 (physical address of PML4)
    const cr3 = asm volatile ("mov %%cr3, %[cr3]"
        : [cr3] "=r" (-> u64),
    );

    // Intel SDM 4.5: Update PML4 address (full 64-bit physical address)
    pml4_addr_ptr.* = cr3;
    serial.println("[SMP] Set ap_pml4_addr to 0x{x}", .{cr3});

    // Verify PML4 is below 4GB for 32-bit mode compatibility
    if (cr3 > 0xFFFFFFFF) {
        serial.println("[SMP] WARNING: PML4 at 0x{x} is above 4GB!", .{cr3});
        serial.println("[SMP] This will cause issues in 32-bit protected mode", .{});
    }

    // Update entry point (64-bit virtual address)
    // In a PIE kernel, @intFromPtr already gives us the runtime address
    // The trampoline will jump to this address after setting up paging
    // Use the wrapper function for better debugging
    const ap_entry_wrapper = @import("ap_entry_wrapper.zig");
    const entry_addr = @intFromPtr(&ap_entry_wrapper.apEntryWrapper);
    entry_point_ptr.* = entry_addr;
    serial.println("[SMP] Set ap_entry_point to 0x{x} (wrapper)", .{entry_addr});

    // Update CPU ID
    cpu_id_ptr.* = cpu_id;
    serial.println("[SMP] Set ap_cpu_id to {}", .{cpu_id});

    // Update stack pointer for this CPU
    stack_array_ptr[cpu_id] = @intFromPtr(stack_top);
    serial.println("[SMP] Set ap_stack_array[{}] to 0x{x}", .{ cpu_id, @intFromPtr(stack_top) });

    // Intel SDM: Verify the stack is accessible and properly mapped
    // Write a test pattern to the stack to ensure it's writable
    const stack_test_ptr = @as(*volatile u64, @ptrFromInt(@intFromPtr(stack_top) - 8));
    const test_pattern: u64 = 0xDEADBEEF00000000 | @as(u64, cpu_id);
    stack_test_ptr.* = test_pattern;
    asm volatile ("mfence" ::: "memory");

    if (stack_test_ptr.* != test_pattern) {
        serial.println("[SMP] ERROR: Stack test failed! Wrote 0x{x}, read 0x{x}", .{ test_pattern, stack_test_ptr.* });
        return 0; // Return error
    }
    serial.println("[SMP] Stack test passed for CPU {}", .{cpu_id});

    // Intel SDM 11.12: Flush the cache line containing the stack array entry
    // This ensures the AP sees the updated stack pointer
    const stack_array_entry_addr = @intFromPtr(&stack_array_ptr[cpu_id]);
    asm volatile ("clflush (%[addr])"
        :
        : [addr] "r" (stack_array_entry_addr),
        : "memory"
    );
    asm volatile ("mfence" ::: "memory");

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

    // Set up kernel GDT and IDT pointers for the AP
    setupKernelDescriptorPointers(trampoline_base + ap_startup_data_offset);

    // Ensure all writes are visible with full memory barrier
    ap_sync.memoryBarrier();

    return ap_startup_data_offset;
}

fn setupKernelDescriptorPointers(ap_startup_data_base: u64) void {
    _ = ap_startup_data_base; // Not used anymore

    // Use fixed locations within the already-mapped trampoline region
    // The trampoline is at 0x8000 and is about 3KB (0xBD0), ending around 0x8BD0
    // Place the transition GDT at the end of the trampoline region but before 0x9000
    const TRANSITION_GDT_ADDR: u64 = 0x8E00; // Near end of trampoline region
    const TRANSITION_GDTR_ADDR: u64 = 0x8F00; // 256 bytes after GDT
    const KERNEL_IDTR_ADDR: u64 = 0x8F10; // Right after GDTR

    // First, verify this memory region is accessible
    const test_ptr = @as(*volatile u64, @ptrFromInt(TRANSITION_GDT_ADDR));
    test_ptr.* = 0x1234567890ABCDEF;
    if (test_ptr.* != 0x1234567890ABCDEF) {
        serial.println("[SMP] ERROR: Cannot access transition GDT memory at 0x{x}!", .{TRANSITION_GDT_ADDR});
        @panic("Transition GDT memory not accessible");
    }
    test_ptr.* = 0; // Clear test value

    // Get the current GDT and IDT from the BSP
    var kernel_gdt_info: gdt.GDTPointer = undefined;
    var kernel_idt_info: idt.IDTPointer = undefined;

    // Get current GDT
    asm volatile ("sgdt (%[ptr])"
        :
        : [ptr] "r" (&kernel_gdt_info),
        : "memory"
    );

    // Get current IDT
    asm volatile ("sidt (%[ptr])"
        :
        : [ptr] "r" (&kernel_idt_info),
        : "memory"
    );

    // Create a minimal transition GDT in low memory with just the essential segments
    // This avoids needing to access the kernel's GDT at a high virtual address
    const gdt_entries = @as([*]volatile u64, @ptrFromInt(TRANSITION_GDT_ADDR));

    // Copy the first 3 essential entries from kernel GDT
    // 0x00: Null descriptor
    // 0x08: Kernel code segment
    // 0x10: Kernel data segment
    const kernel_gdt_entries = @as([*]const u64, @ptrFromInt(kernel_gdt_info.base));
    gdt_entries[0] = kernel_gdt_entries[0]; // Null
    gdt_entries[1] = kernel_gdt_entries[1]; // Kernel code
    gdt_entries[2] = kernel_gdt_entries[2]; // Kernel data

    serial.println("[SMP] Kernel GDT entries: null=0x{x}, code=0x{x}, data=0x{x}", .{ gdt_entries[0], gdt_entries[1], gdt_entries[2] });

    // Write transition GDTR
    const gdtr_ptr = @as(*volatile u16, @ptrFromInt(TRANSITION_GDTR_ADDR));
    gdtr_ptr.* = 23; // Limit for 3 entries (3*8 - 1)

    // Write base address
    const gdtr_base_bytes = @as([*]volatile u8, @ptrFromInt(TRANSITION_GDTR_ADDR + 2));
    for (0..8) |i| {
        gdtr_base_bytes[i] = @as(u8, @truncate(TRANSITION_GDT_ADDR >> @as(u6, @intCast(i * 8))));
    }

    serial.println("[SMP] Created transition GDT at 0x{x} with kernel segments", .{TRANSITION_GDT_ADDR});

    // Verify the GDTR structure at 0x9100
    const verify_limit = @as(*const u16, @ptrFromInt(TRANSITION_GDTR_ADDR)).*;
    const verify_base_ptr = @as([*]const u8, @ptrFromInt(TRANSITION_GDTR_ADDR + 2));
    var verify_base: u64 = 0;
    for (0..8) |i| {
        verify_base |= @as(u64, verify_base_ptr[i]) << @as(u6, @intCast(i * 8));
    }
    serial.println("[SMP] Transition GDTR at 0x{x}: limit=0x{x}, base=0x{x}", .{ TRANSITION_GDTR_ADDR, verify_limit, verify_base });
    if (verify_base != TRANSITION_GDT_ADDR) {
        serial.println("[SMP] ERROR: GDTR base mismatch! Expected 0x{x}, got 0x{x}", .{ TRANSITION_GDT_ADDR, verify_base });
    }

    // Write kernel IDT pointer to fixed location
    const kernel_idtr_ptr = @as(*volatile u16, @ptrFromInt(KERNEL_IDTR_ADDR));
    kernel_idtr_ptr.* = kernel_idt_info.limit;

    // Write base address byte by byte to avoid alignment issues
    const idt_base_bytes = @as([*]volatile u8, @ptrFromInt(KERNEL_IDTR_ADDR + 2));
    const idt_base_value = kernel_idt_info.base;
    for (0..8) |i| {
        idt_base_bytes[i] = @as(u8, @truncate(idt_base_value >> @as(u6, @intCast(i * 8))));
    }

    serial.println("[SMP] Set kernel IDTR at 0x{x}: limit=0x{x}, base=0x{x}", .{ KERNEL_IDTR_ADDR, kernel_idt_info.limit, kernel_idt_info.base });

    // Flush cache lines for the descriptor pointers
    asm volatile ("clflush (%[addr])"
        :
        : [addr] "r" (TRANSITION_GDT_ADDR),
        : "memory"
    );
    asm volatile ("clflush (%[addr])"
        :
        : [addr] "r" (TRANSITION_GDTR_ADDR),
        : "memory"
    );
    asm volatile ("clflush (%[addr])"
        :
        : [addr] "r" (KERNEL_IDTR_ADDR),
        : "memory"
    );
    // Also flush the GDT entries themselves
    for (0..3) |i| {
        const entry_addr = TRANSITION_GDT_ADDR + i * 8;
        asm volatile ("clflush (%[addr])"
            :
            : [addr] "r" (entry_addr),
            : "memory"
        );
    }
    asm volatile ("mfence" ::: "memory");

    serial.println("[SMP] Transition GDT and descriptors flushed for cache coherency", .{});
}

// Simple busy wait for AP startup (doesn't require interrupts or TSC)
fn busyWait(iterations: u32) void {
    var i: u32 = 0;
    while (i < iterations) : (i += 1) {
        asm volatile ("pause" ::: "memory");
    }
}

// PIT-based delay using polling (no interrupts required)
// Uses PIT channel 2 which is typically used for PC speaker
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

// Helper to delay for a specific number of PIT ticks
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

// Send INIT-SIPI-SIPI sequence to start AP
// Intel SDM 10.4.4: MP Initialization Example
fn sendInitSipiSipi(apic_id: u8) !void {
    // Intel SDM 10.4.2: All devices capable of delivering interrupts must be inhibited
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

    // Clear debug markers at beginning of debug range
    const early_marker_1 = @as(*volatile u16, @ptrFromInt(0x510));
    const early_marker_2 = @as(*volatile u16, @ptrFromInt(0x512));
    // const clear_lgdt_marker = @as(*volatile u16, @ptrFromInt(0x514));
    const clear_cr0_marker = @as(*volatile u16, @ptrFromInt(0x516));
    const clear_exception_marker = @as(*volatile u32, @ptrFromInt(0x518));
    const clear_pm_marker = @as(*volatile u32, @ptrFromInt(0x51C));
    const clear_pae_marker = @as(*volatile u32, @ptrFromInt(0x520));
    const clear_cr3_marker = @as(*volatile u32, @ptrFromInt(0x524));
    const clear_lme_marker = @as(*volatile u32, @ptrFromInt(0x528));
    const clear_pg_marker = @as(*volatile u32, @ptrFromInt(0x52C));
    const clear_stack_debug = @as(*volatile u64, @ptrFromInt(0x558));

    // NOTE: Clear debug regions but avoid 0x514 to prevent conflicts
    // The AP will write to 0x514 after lgdt, and we don't want to interfere
    early_marker_1.* = 0;
    early_marker_2.* = 0;
    // Skip clearing 0x514 (lgdt marker) to avoid race condition
    clear_cr0_marker.* = 0;
    clear_exception_marker.* = 0;
    clear_pm_marker.* = 0;
    clear_pae_marker.* = 0;
    clear_cr3_marker.* = 0;
    clear_lme_marker.* = 0;
    clear_pg_marker.* = 0;
    clear_stack_debug.* = 0;

    // Ensure writes are visible and prevent reordering
    asm volatile ("mfence; lfence" ::: "memory");

    // Flush cache lines for the debug area to ensure AP sees clean memory
    // This is critical now that we're keeping the memory cacheable
    var flush_addr: u64 = 0x500;
    while (flush_addr <= 0x5C0) : (flush_addr += 64) {
        asm volatile ("clflush (%[addr])"
            :
            : [addr] "r" (flush_addr),
            : "memory"
        );
    }
    // Ensure all cache flushes complete
    asm volatile ("mfence" ::: "memory");

    // Immediately verify the clear worked
    const verify_region = @as([*]const volatile u8, @ptrFromInt(0x510));
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

    // Intel SDM 8.7.5: Cache coherency in MP systems
    // Intel SDM 11.12: WBINVD flushes and invalidates all caches
    // CRITICAL: Ensure complete cache coherency before starting AP
    serial.println("[SMP] Ensuring cache coherency before SIPI...", .{});

    // Flush all modified cache lines and invalidate caches
    // This ensures the AP sees the trampoline code we just copied
    asm volatile ("wbinvd" ::: "memory");

    // Intel SDM 8.3: Serializing instructions
    // Additional memory barrier for complete serialization
    asm volatile ("mfence" ::: "memory");

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
    const bsp_apic_id = @as(u8, @truncate(apic_unified.getAPICID()));
    serial.println("[SMP] BSP APIC ID: {}, Target AP APIC ID: {}", .{ bsp_apic_id, apic_id });
    if (bsp_apic_id == apic_id) {
        serial.println("[SMP] ERROR: Trying to send IPI to self!", .{});
        return error.InvalidAPICID;
    }

    // Check APIC state before sending INIT
    const esr_before = apic_unified.readRegister(0x280); // APIC_ESR
    if (esr_before != 0) {
        serial.println("[SMP] WARNING: APIC ESR=0x{x} before INIT", .{esr_before});
        // Clear ESR
        apic_unified.writeRegister(0x280, 0);
        _ = apic_unified.readRegister(0x280);
    }

    // Intel SDM Table 10-1: Send INIT IPI
    serial.println("[SMP] Sending INIT IPI to APIC ID {}", .{apic_id});

    // Intel SDM 10.4.3: Send INIT-deassert first for legacy compatibility
    // This ensures the AP is in a known state
    apic_unified.sendIPIFull(apic_id, 0, .Init, .Deassert, .Level, .NoShorthand);
    busyWait(10000); // Short delay

    // CRITICAL FOR UEFI: Send INIT assert with Level trigger
    // This provides a stronger reset signal for APs that UEFI has initialized
    // Some UEFI systems need Level-triggered INIT to properly reset APs
    apic_unified.sendIPIFull(apic_id, 0, .Init, .Assert, .Level, .NoShorthand);

    // Wait for INIT to take effect
    pitPollingDelay(1000); // 1ms

    // Send INIT de-assert to complete the sequence
    apic_unified.sendIPIFull(apic_id, 0, .Init, .Deassert, .Level, .NoShorthand);

    // Intel SDM 10.4.4: Wait 10ms after INIT IPI
    // Use UEFI-aware delay if available
    const init_delay = if (uefi_ap_manager) |*manager| manager.getInitDelay() else 10_000;
    serial.println("[SMP] Waiting {}ms after INIT...", .{init_delay / 1000});
    pitPollingDelay(init_delay);

    // Additional synchronization delay
    ap_sync.apStartupDelay(10_000);

    // Check ICR status after INIT
    const icr_after_init = apic_unified.readRegister(0x300); // APIC_ICR_LOW
    serial.println("[SMP] ICR after INIT wait: 0x{x}", .{icr_after_init});

    // Wait for delivery status to clear
    var wait_count: u32 = 0;
    while ((apic_unified.readRegister(0x300) & (1 << 12)) != 0 and wait_count < 1000) {
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
    var flags = asm volatile ("pushfq; popq %[flags]"
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

    // Intel SDM Table 10-1: Send first SIPI with vector
    // Format: 000C46XXH where XX is the vector (0x08 for 0x8000)
    // SIPI vector is the page number (address >> 12), so 0x08 = 0x8000
    serial.println("[SMP] Sending first SIPI with vector 0x08 (starts at 0x8000)", .{});

    // WORKAROUND: Some systems require a small delay before SIPI
    busyWait(1000);

    apic_unified.sendIPIFull(apic_id, 0x08, .Startup, .Assert, .Edge, .NoShorthand);

    // Intel SDM 10.4.4: Wait 200us between SIPIs
    // Use UEFI-aware delay if available
    const sipi_delay = if (uefi_ap_manager) |*manager| manager.getSipiDelay() else 200;
    serial.println("[SMP] Waiting {}us between SIPIs...", .{sipi_delay});
    pitPollingDelay(sipi_delay);

    // Intel SDM 10.4.4: Send second SIPI
    serial.println("[SMP] Sending second SIPI with vector 0x08", .{});

    // Intel SDM 10.4.2: Ensure interrupts stay disabled during AP startup
    // Some systems have issues if interrupts fire during AP startup
    flags = asm volatile ("pushfq; popq %[flags]; cli"
        : [flags] "=r" (-> u64),
    );
    defer {
        // Restore interrupt flag after AP has had time to start
        if (flags & 0x200 != 0) {
            asm volatile ("sti" ::: "memory");
        }
    }

    apic_unified.sendIPIFull(apic_id, 0x08, .Startup, .Assert, .Edge, .NoShorthand);

    // Add a delay after second SIPI to ensure it completes and avoid race
    // Use extended delay for UEFI systems
    const post_sipi_delay = if (uefi_ap_manager) |*manager| manager.getSipiDelay() * 5 else 1000;
    serial.println("[SMP] Waiting {}ms after second SIPI for AP to start...", .{post_sipi_delay / 1000});
    pitPollingDelay(post_sipi_delay);

    // Add memory barrier to ensure all writes are visible
    ap_sync.memoryBarrier();

    // Check if AP has written to debug region immediately
    const immediate_debug = @as(*volatile u32, @ptrFromInt(0x500));
    if (immediate_debug.* == 0x12345678) {
        serial.println("[SMP] AP has written magic to debug region!", .{});
    }

    // Also check the very early marker at 0x8100
    const early_marker = @as(*volatile u16, @ptrFromInt(0x8100));
    if (early_marker.* == 0xABCD) {
        serial.println("[SMP] AP executed first instruction! Early marker found at 0x8100", .{});
    } else {
        serial.println("[SMP] No early marker found at 0x8100 (value: 0x{x})", .{early_marker.*});
    }

    serial.println("[SMP] INIT-SIPI-SIPI sequence complete", .{});

    // CRITICAL: Do NOT clear debug memory after SIPI!
    // The AP is already running and writing to these locations.
    // Clearing them now causes a race condition and cache coherency issues.

    // Give AP a moment to start and check debug location immediately
    ap_sync.apStartupDelay(10_000); // Short wait

    // CRITICAL: Ensure we read fresh values from memory, not stale cache
    // Use MFENCE to ensure all previous memory operations are complete
    asm volatile ("mfence" ::: "memory");

    // Additionally, use LFENCE to prevent speculative reads
    asm volatile ("lfence" ::: "memory");

    const debug_ptr = @as(*align(1) volatile ap_debug.TrampolineDebug, @ptrFromInt(ap_debug.TRAMPOLINE_DEBUG_ADDR));
    serial.println("[SMP] Immediate debug check at 0x500:", .{});
    serial.print("[SMP]   First 16 bytes at 0x510: ", .{});
    const debug_bytes = @as([*]const volatile u8, @ptrFromInt(0x510));
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
    const early_marker_ptr = @as(*volatile u16, @ptrFromInt(0x510));
    const marker_ptr = @as(*volatile u16, @ptrFromInt(0x512));
    const lgdt_marker = @as(*volatile u16, @ptrFromInt(0x514));
    const cr0_marker = @as(*volatile u16, @ptrFromInt(0x516));
    const exception_marker = @as(*volatile u32, @ptrFromInt(0x518));
    const pm_marker = @as(*volatile u32, @ptrFromInt(0x51C));
    const pae_marker = @as(*volatile u32, @ptrFromInt(0x520));
    const cr3_marker = @as(*volatile u32, @ptrFromInt(0x524));
    const lme_marker = @as(*volatile u32, @ptrFromInt(0x528));
    const pg_marker = @as(*volatile u32, @ptrFromInt(0x52C));
    const stack_value = @as(*volatile u64, @ptrFromInt(0x558));
    serial.println("[SMP]   Early marker at 0x510: 0x{x} (should be 0xDEAD if AP executed)", .{early_marker_ptr.*});
    serial.println("[SMP]   Marker at 0x512: 0x{x} (should be 0xBEEF if AP started)", .{marker_ptr.*});
    serial.println("[SMP]   Post-lgdt marker at 0x514: 0x{x} (should be 0x1111 if lgdt succeeded)", .{lgdt_marker.*});
    serial.println("[SMP]   Post-CR0 marker at 0x516: 0x{x} (should be 0x2222 if CR0 modified)", .{cr0_marker.*});
    serial.println("[SMP]   Exception marker at 0x518: 0x{x} (should be 0 if no exception)", .{exception_marker.*});
    serial.println("[SMP]   PM entry marker at 0x51C: 0x{x} (should be 0x3333 if reached 32-bit mode)", .{pm_marker.*});
    serial.println("[SMP]   PAE enabled marker at 0x520: 0x{x} (should be 0x4444 if PAE set)", .{pae_marker.*});
    serial.println("[SMP]   CR3 loaded marker at 0x524: 0x{x} (should be 0x5555 if CR3 loaded)", .{cr3_marker.*});
    serial.println("[SMP]   EFER.LME marker at 0x528: 0x{x} (should be 0x6666 if LME set)", .{lme_marker.*});
    serial.println("[SMP]   Paging enabled marker at 0x52C: 0x{x} (should be 0x7777 if paging on)", .{pg_marker.*});
    serial.println("[SMP]   Stack value at 0x558: 0x{x} (stack pointer in long mode)", .{stack_value.*});

    // Check 64-bit entry marker
    const lm64_entry = @as(*volatile u32, @ptrFromInt(0x530)).*;
    serial.println("[SMP]   64-bit entry marker at 0x530: 0x{x} (should be 0x64646464 if reached 64-bit mode)", .{lm64_entry});

    // Check debug markers from assembly
    const loaded_cpu_id = @as(*volatile u32, @ptrFromInt(0x544)).*;
    const array_addr = @as(*volatile u64, @ptrFromInt(0x548)).*;
    const array_offset = @as(*volatile u32, @ptrFromInt(0x550)).*;
    const stack_loaded = @as(*volatile u32, @ptrFromInt(0x560)).*;
    const before_entry = @as(*volatile u32, @ptrFromInt(0x564)).*;
    const entry_addr = @as(*volatile u64, @ptrFromInt(0x568)).*;
    const before_jump = @as(*volatile u32, @ptrFromInt(0x570)).*;

    serial.println("[SMP]   Debug markers from assembly:", .{});
    serial.println("[SMP]     CPU ID loaded: {} (at 0x544)", .{loaded_cpu_id});
    serial.println("[SMP]     Stack array addr: 0x{x} (at 0x548)", .{array_addr});
    serial.println("[SMP]     Array offset: {} (at 0x550)", .{array_offset});
    serial.println("[SMP]     Stack loaded marker: 0x{x} (at 0x560, should be 0x8888)", .{stack_loaded});
    serial.println("[SMP]     Before entry marker: 0x{x} (at 0x564, should be 0x9999)", .{before_entry});
    serial.println("[SMP]     Entry point addr: 0x{x} (at 0x568)", .{entry_addr});
    serial.println("[SMP]     Before jump marker: 0x{x} (at 0x570, should be 0xAAAA)", .{before_jump});

    // Check for normal path markers that might conflict with error markers
    const before_gdt_marker = @as(*volatile u32, @ptrFromInt(0x590)).*;
    const after_gdt_marker = @as(*volatile u32, @ptrFromInt(0x594)).*;
    serial.println("[SMP]     Before kernel GDT marker: 0x{x} (at 0x590, should be 0xBBBB)", .{before_gdt_marker});
    serial.println("[SMP]     After kernel GDT marker: 0x{x} (at 0x594, should be 0xCCCC)", .{after_gdt_marker});

    // Check for error markers at non-conflicting addresses
    const new_stack_error = @as(*volatile u32, @ptrFromInt(0x5C0)).*;
    const bad_stack_value = @as(*volatile u64, @ptrFromInt(0x5C8)).*;
    const new_entry_error = @as(*volatile u32, @ptrFromInt(0x5D0)).*;
    const bad_entry_value = @as(*volatile u64, @ptrFromInt(0x5D8)).*;

    if (new_stack_error == 0xBAD57ACC) {
        serial.println("[SMP]     ERROR: Stack error at 0x5C0: 0x{x}, bad stack value: 0x{x}", .{ new_stack_error, bad_stack_value });
    }
    if (new_entry_error == 0xBADC0DED) {
        serial.println("[SMP]     ERROR: Entry error at 0x5D0: 0x{x}, bad entry value: 0x{x}", .{ new_entry_error, bad_entry_value });
    }

    // Check halt marker
    const halt_marker = @as(*volatile u32, @ptrFromInt(0x574)).*;
    if (halt_marker != 0) {
        serial.println("[SMP]     Halt marker: 0x{x} (AP reached halt before jump)", .{halt_marker});
    }

    // Check GDTR verification values
    const gdtr_limit = @as(*volatile u16, @ptrFromInt(0x5A8)).*;
    const gdtr_base = @as(*volatile u32, @ptrFromInt(0x5AC)).*;
    serial.println("[SMP]     GDTR verification - limit: 0x{x}, base: 0x{x}", .{ gdtr_limit, gdtr_base });

    // Check lretq markers
    const before_lretq = @as(*volatile u32, @ptrFromInt(0x5A0)).*;
    const after_lretq = @as(*volatile u32, @ptrFromInt(0x5A4)).*;
    serial.println("[SMP]     Before lretq marker: 0x{x} (at 0x5A0, should be 0xDDDD)", .{before_lretq});
    serial.println("[SMP]     After lretq marker: 0x{x} (at 0x5A4, should be 0xEEEE)", .{after_lretq});

    // Check debug flow markers
    const before_delay = @as(*volatile u32, @ptrFromInt(0x534)).*;
    const after_delay = @as(*volatile u32, @ptrFromInt(0x538)).*;
    const after_mfence = @as(*volatile u32, @ptrFromInt(0x53C)).*;
    const after_cpu_load = @as(*volatile u32, @ptrFromInt(0x540)).*;
    serial.println("[SMP]   Debug flow markers:", .{});
    serial.println("[SMP]     Before delay: 0x{x} (should be 0xDE1A1111)", .{before_delay});
    serial.println("[SMP]     After delay: 0x{x} (should be 0xDE1A2222)", .{after_delay});
    serial.println("[SMP]     After mfence: 0x{x} (should be 0xDE1A3333)", .{after_mfence});
    serial.println("[SMP]     After CPU load: 0x{x} (should be 0xDE1A4444)", .{after_cpu_load});

    // Check test markers
    const test_marker = @as(*volatile u32, @ptrFromInt(0x580)).*;
    const loop_marker = @as(*volatile u32, @ptrFromInt(0x58C)).*;
    const read_byte = @as(*volatile u8, @ptrFromInt(0x584)).*;
    const read_marker = @as(*volatile u32, @ptrFromInt(0x588)).*;
    // Check for actual Zig entry markers (at different addresses)
    const zig_marker = @as(*volatile u32, @ptrFromInt(0x5B0)).*;
    const zig_cpu_id = @as(*volatile u32, @ptrFromInt(0x5B4)).*;
    if (test_marker != 0) {
        serial.println("[SMP]     Test jump marker: 0x{x} (attempting jump)", .{test_marker});
    }
    if (read_byte != 0 or read_marker != 0) {
        serial.println("[SMP]     Read test: byte=0x{x}, marker=0x{x} (target address is readable!)", .{ read_byte, read_marker });
        // The first byte should be 0x55 (push %rbp)
        if (read_byte == 0x55) {
            serial.println("[SMP]     First instruction is correct (push %%rbp)", .{});
        }
    }
    if (loop_marker != 0) {
        serial.println("[SMP]     Unreachable marker: 0x{x} (should not see this)", .{loop_marker});
    }

    serial.println("[SMP]   Jump target markers:", .{});
    if (zig_marker == 0xDEADC0DE) {
        serial.println("[SMP]     ✓ AP REACHED ZIG CODE! Marker=0x{x}, CPU={}", .{ zig_marker, zig_cpu_id });
    } else if (zig_marker == 0xCAFEBABE) {
        serial.println("[SMP]     AP wrote pre-jump marker (0xCAFEBABE) but did NOT reach Zig code", .{});
        serial.println("[SMP]     CPU ID from assembly: {}", .{zig_cpu_id});
    } else {
        serial.println("[SMP]     Marker at 0x5B0: 0x{x} (expecting 0xCAFEBABE from asm or 0xDEADC0DE from Zig)", .{zig_marker});
        serial.println("[SMP]     CPU ID at 0x5B4: {}", .{zig_cpu_id});
    }

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

// Start all Application Processors
pub fn startAllAPs(processor_info: []const per_cpu.ProcessorInfo) !void {
    serial.println("[SMP] Starting {} Application Processors", .{processor_info.len - 1});

    // Intel SDM 10.4.4.1 Step 13: Initialize Lock Semaphore to VACANT (0)
    lock_semaphore.store(0, .release);

    // Intel SDM 10.4.4.1 Step 14: Set COUNT variable to 1 (BSP)
    @atomicStore(u32, &startup_state.ap_ready_count, 1, .release);

    // Initialize debug state
    ap_debug.init(@intCast(processor_info.len - 1));

    // Initialize AP startup barrier
    const ap_count = @as(u32, @intCast(processor_info.len - 1));
    ap_startup_barrier = ap_sync.ApBarrier.init(ap_count);
    barrier_initialized = true;

    // Reset other startup state
    @atomicStore(u32, &startup_state.ap_boot_error, 0, .release);
    @atomicStore(bool, &startup_state.proceed_signal, false, .release);

    // Start each AP (skip BSP which is CPU 0)
    for (processor_info[1..], 1..) |proc, cpu_id| {
        if (proc.flags & 1 != 0) { // Check if processor is enabled
            try initAP(@intCast(cpu_id), @intCast(proc.apic_id));
        }
    }

    // Use the new validator to check AP startup
    const validator = ap_state_validator.ApStateValidator;

    // Validate all APs have started
    validator.validateAllAPs(ap_count, 2000) catch |err| {
        serial.println("[SMP] AP validation failed: {s}", .{@errorName(err)});

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

        // Continue with partial APs rather than failing completely
    };

    // Release the startup barrier to let APs proceed
    ap_startup_barrier.release();

    // Signal all APs to proceed
    @atomicStore(bool, &startup_state.proceed_signal, true, .release);

    // Intel SDM 10.4.4.1 Step 16: Read and evaluate COUNT variable
    const final_count = @atomicLoad(u32, &startup_state.ap_ready_count, .acquire);
    const alive_count = @atomicLoad(u32, &ap_alive_counter, .acquire);
    serial.println("[SMP] All APs started and ready", .{});
    serial.println("[SMP] Processor count: {} (BSP + {} APs)", .{ final_count, final_count - 1 });
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

// Entry point for APs (called from assembly trampoline)
export fn apMainEntry(cpu_id: u32) callconv(.C) noreturn {
    // This is called with interrupts disabled

    // Write immediate debug marker to verify we reached Zig code
    // Use addresses that don't conflict with assembly debug markers
    const marker_ptr = @as(*volatile u32, @ptrFromInt(0x5B0));
    marker_ptr.* = 0xDEADC0DE;

    // Write CPU ID to next location
    const id_ptr = @as(*volatile u32, @ptrFromInt(0x5B4));
    id_ptr.* = cpu_id;

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

// Get AP startup state for debugging
pub fn getStartupState() *const ApStartupState {
    return &startup_state;
}

// Get detected CPU count from ACPI
pub fn getDetectedCpuCount() u32 {
    return per_cpu.getCpuCount();
}

// Get online CPU count (BSP + ready APs)
pub fn getOnlineCpuCount() u32 {
    return 1 + @atomicLoad(u32, &startup_state.ap_ready_count, .acquire);
}
