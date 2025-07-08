// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Advanced Peripheral Interrupt Controller (APIC) driver
// Provides modern interrupt handling and inter-processor communication

const std = @import("std");
const cpuid = @import("cpuid.zig");
const paging = @import("paging.zig");
const io_security = @import("io_security.zig");
const serial = @import("../drivers/serial.zig");
const stack_security = @import("stack_security.zig");
const secure_print = @import("../lib/secure_print.zig");

// APIC register offsets
const APIC_ID = 0x20;
const APIC_VERSION = 0x30;
const APIC_TPR = 0x80; // Task Priority Register
const APIC_APR = 0x90; // Arbitration Priority Register
const APIC_PPR = 0xA0; // Processor Priority Register
const APIC_EOI = 0xB0; // End of Interrupt
const APIC_RRD = 0xC0; // Remote Read Register
const APIC_LDR = 0xD0; // Logical Destination Register
const APIC_DFR = 0xE0; // Destination Format Register
const APIC_SPURIOUS = 0xF0; // Spurious Interrupt Vector
const APIC_ISR = 0x100; // In-Service Register (8 registers)
const APIC_TMR = 0x180; // Trigger Mode Register (8 registers)
const APIC_IRR = 0x200; // Interrupt Request Register (8 registers)
const APIC_ESR = 0x280; // Error Status Register
const APIC_ICR_LOW = 0x300; // Interrupt Command Register (low)
const APIC_ICR_HIGH = 0x310; // Interrupt Command Register (high)
const APIC_TIMER_LVT = 0x320; // Timer Local Vector Table
const APIC_THERMAL_LVT = 0x330; // Thermal Local Vector Table
const APIC_PERF_LVT = 0x340; // Performance Counter Local Vector Table
const APIC_LINT0_LVT = 0x350; // Local Interrupt 0 Local Vector Table
const APIC_LINT1_LVT = 0x360; // Local Interrupt 1 Local Vector Table
const APIC_ERROR_LVT = 0x370; // Error Local Vector Table
pub const APIC_TIMER_INITIAL = 0x380;
pub const APIC_TIMER_CURRENT = 0x390;
const APIC_TIMER_DIVIDE = 0x3E0;

// MSR addresses
const IA32_APIC_BASE_MSR: u32 = 0x1B;

// APIC base MSR bits
const APIC_BASE_BSP: u64 = 1 << 8; // Bootstrap processor
const APIC_BASE_ENABLE: u64 = 1 << 11; // APIC enable
const APIC_BASE_X2APIC: u64 = 1 << 10; // x2APIC mode (if supported)
const APIC_BASE_ADDR_MASK: u64 = 0xFFFFF000;

// Spurious interrupt vector register bits
const APIC_SPURIOUS_ENABLE: u32 = 1 << 8;
const APIC_SPURIOUS_FOCUS_CHECK: u32 = 1 << 9;

// Local Vector Table bits
const APIC_LVT_MASKED: u32 = 1 << 16;
const APIC_LVT_TRIGGER_LEVEL: u32 = 1 << 15;
const APIC_LVT_REMOTE_IRR: u32 = 1 << 14;
const APIC_LVT_PIN_POLARITY: u32 = 1 << 13;
const APIC_LVT_DELIVERY_STATUS: u32 = 1 << 12;

// Timer modes
const APIC_TIMER_ONE_SHOT: u32 = 0 << 17;
const APIC_TIMER_PERIODIC: u32 = 1 << 17;
const APIC_TIMER_TSC_DEADLINE: u32 = 2 << 17;

// Error bits
const APIC_ERROR_SEND_CHECKSUM: u32 = 1 << 0;
const APIC_ERROR_RECV_CHECKSUM: u32 = 1 << 1;
const APIC_ERROR_SEND_ACCEPT: u32 = 1 << 2;
const APIC_ERROR_RECV_ACCEPT: u32 = 1 << 3;
const APIC_ERROR_REDIRECTABLE_IPI: u32 = 1 << 4;
const APIC_ERROR_SEND_ILLEGAL_VECTOR: u32 = 1 << 5;
const APIC_ERROR_RECV_ILLEGAL_VECTOR: u32 = 1 << 6;
const APIC_ERROR_ILLEGAL_REG_ADDR: u32 = 1 << 7;

// ICR delivery modes
const APIC_ICR_DELIVERY_FIXED: u32 = 0 << 8;
const APIC_ICR_DELIVERY_LOWEST: u32 = 1 << 8;
const APIC_ICR_DELIVERY_SMI: u32 = 2 << 8;
const APIC_ICR_DELIVERY_NMI: u32 = 4 << 8;
const APIC_ICR_DELIVERY_INIT: u32 = 5 << 8;
const APIC_ICR_DELIVERY_STARTUP: u32 = 6 << 8;

// ICR destination modes
const APIC_ICR_DEST_PHYSICAL: u32 = 0 << 11;
const APIC_ICR_DEST_LOGICAL: u32 = 1 << 11;

// ICR level
const APIC_ICR_LEVEL_DEASSERT: u32 = 0 << 14;
const APIC_ICR_LEVEL_ASSERT: u32 = 1 << 14;

// ICR trigger mode
const APIC_ICR_TRIGGER_EDGE: u32 = 0 << 15;
const APIC_ICR_TRIGGER_LEVEL: u32 = 1 << 15;

// ICR destination shorthand
const APIC_ICR_DEST_SPECIFIC: u32 = 0 << 18;
const APIC_ICR_DEST_SELF: u32 = 1 << 18;
const APIC_ICR_DEST_ALL: u32 = 2 << 18;
const APIC_ICR_DEST_ALL_BUT_SELF: u32 = 3 << 18;

// Timer divide values
const APIC_TIMER_DIV_1: u32 = 0xB;
const APIC_TIMER_DIV_2: u32 = 0x0;
const APIC_TIMER_DIV_4: u32 = 0x1;
const APIC_TIMER_DIV_8: u32 = 0x2;
const APIC_TIMER_DIV_16: u32 = 0x3;
const APIC_TIMER_DIV_32: u32 = 0x8;
const APIC_TIMER_DIV_64: u32 = 0x9;
const APIC_TIMER_DIV_128: u32 = 0xA;

// APIC register bounds
const MAX_APIC_OFFSET: u32 = 0x3F0;
const APIC_REGISTER_SIZE: u32 = 4;

// Global APIC state
var apic_base: u64 = 0;
var lapic_addr: ?[*]volatile u32 = null;
var is_bsp: bool = false;
var apic_available: bool = false;
var x2apic_available: bool = false;
var timer_calibrated: bool = false;
var timer_frequency: u64 = 0;

// Security: Track APIC access for audit
var apic_reads: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var apic_writes: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var apic_bounds_violations: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// Check if APIC is available
pub fn isAvailable() bool {
    return apic_available;
}

// Check if this is the bootstrap processor
pub fn isBSP() bool {
    return is_bsp;
}

// Read APIC base address from MSR
fn readAPICBase() u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (IA32_APIC_BASE_MSR),
    );
    return (@as(u64, high) << 32) | low;
}

// Write APIC base address to MSR
fn writeAPICBase(value: u64) void {
    const low = @as(u32, @truncate(value));
    const high = @as(u32, @truncate(value >> 32));
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (IA32_APIC_BASE_MSR),
          [low] "{eax}" (low),
          [high] "{edx}" (high),
        : "memory"
    );
}

// Validate APIC register offset
fn validateAPICOffset(offset: u32) !void {
    // Check if offset is within valid APIC register range
    if (offset > MAX_APIC_OFFSET) {
        _ = apic_bounds_violations.fetchAdd(1, .monotonic);
        serial.print("[APIC] SECURITY: Invalid register offset 0x{X} (max 0x{X})\r\n", .{ offset, MAX_APIC_OFFSET });
        return error.InvalidAPICOffset;
    }

    // Check if offset is properly aligned (APIC registers are 4-byte aligned)
    if (offset & 0x3 != 0) {
        _ = apic_bounds_violations.fetchAdd(1, .monotonic);
        serial.print("[APIC] SECURITY: Misaligned register offset 0x{X} (must be 4-byte aligned)\r\n", .{offset});
        return error.MisalignedAPICOffset;
    }

    // Additional validation for known register offsets
    if (!isValidAPICRegister(offset)) {
        _ = apic_bounds_violations.fetchAdd(1, .monotonic);
        serial.print("[APIC] SECURITY: Access to unknown register offset 0x{X}\r\n", .{offset});
        return error.UnknownAPICRegister;
    }
}

// Check if register offset corresponds to a known APIC register
fn isValidAPICRegister(offset: u32) bool {
    return switch (offset) {
        APIC_ID, APIC_VERSION, APIC_TPR, APIC_APR, APIC_PPR, APIC_EOI, APIC_RRD, APIC_LDR, APIC_DFR, APIC_SPURIOUS, APIC_ESR, APIC_ICR_LOW, APIC_ICR_HIGH, APIC_TIMER_LVT, APIC_THERMAL_LVT, APIC_PERF_LVT, APIC_LINT0_LVT, APIC_LINT1_LVT, APIC_ERROR_LVT, APIC_TIMER_INITIAL, APIC_TIMER_CURRENT, APIC_TIMER_DIVIDE => true,
        // ISR registers (8 consecutive registers)
        APIC_ISR...APIC_ISR + 0x70 => (offset - APIC_ISR) % 0x10 == 0,
        // TMR registers (8 consecutive registers)
        APIC_TMR...APIC_TMR + 0x70 => (offset - APIC_TMR) % 0x10 == 0,
        // IRR registers (8 consecutive registers)
        APIC_IRR...APIC_IRR + 0x70 => (offset - APIC_IRR) % 0x10 == 0,
        else => false,
    };
}

// Get APIC base address with validation
fn getAPICBase() u64 {
    if (apic_base == 0) {
        serial.print("[APIC] SECURITY: APIC base address not initialized\r\n", .{});
        @panic("APIC base address not initialized");
    }
    return apic_base & APIC_BASE_ADDR_MASK;
}

// Read from APIC register with comprehensive validation
pub fn readRegister(offset: u32) u32 {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Validate offset before accessing
    validateAPICOffset(offset) catch |err| {
        serial.print("[APIC] SECURITY: Register read validation failed: {}\r\n", .{err});
        @panic("Invalid APIC register access");
    };

    _ = apic_reads.fetchAdd(1, .monotonic);

    if (lapic_addr) |addr| {
        // Double-check bounds to prevent speculation attacks
        if (offset > MAX_APIC_OFFSET) {
            @panic("APIC offset bounds check failed");
        }

        const reg_ptr = @as([*]volatile u32, @ptrFromInt(@intFromPtr(addr) + offset));
        return reg_ptr[0];
    }

    serial.print("[APIC] SECURITY: APIC not initialized for register read\r\n", .{});
    @panic("APIC not initialized");
}

// Write to APIC register with comprehensive validation
pub fn writeRegister(offset: u32, value: u32) void {
    // Debug for ICR writes
    if (offset == APIC_ICR_LOW or offset == APIC_ICR_HIGH) {
        serial.println("[APIC] writeRegister: offset=0x{x}, value=0x{x}", .{ offset, value });
    }

    var guard = stack_security.protect();
    defer guard.deinit();

    // Validate offset before accessing
    validateAPICOffset(offset) catch |err| {
        serial.print("[APIC] SECURITY: Register write validation failed: {}\r\n", .{err});
        @panic("Invalid APIC register access");
    };

    // Additional validation for write-only registers
    if (isReadOnlyAPICRegister(offset)) {
        _ = apic_bounds_violations.fetchAdd(1, .monotonic);
        serial.print("[APIC] SECURITY: Attempted write to read-only register 0x{X}\r\n", .{offset});
        @panic("Write to read-only APIC register");
    }

    // Validate critical register values
    validateAPICRegisterValue(offset, value) catch |err| {
        serial.print("[APIC] SECURITY: Register value validation failed: {}\r\n", .{err});
        @panic("Invalid APIC register value");
    };

    _ = apic_writes.fetchAdd(1, .monotonic);

    if (lapic_addr) |addr| {
        // Double-check bounds to prevent speculation attacks
        if (offset > MAX_APIC_OFFSET) {
            @panic("APIC offset bounds check failed");
        }

        const reg_ptr = @as([*]volatile u32, @ptrFromInt(@intFromPtr(addr) + offset));

        // Debug for ICR
        if (offset == APIC_ICR_LOW or offset == APIC_ICR_HIGH) {
            serial.println("[APIC] About to write value 0x{x} to address 0x{x}", .{ value, @intFromPtr(reg_ptr) });
        }

        // Memory barrier before write
        asm volatile ("mfence" ::: "memory");

        // For SIPI, add pre-write delay and serialization
        if (offset == APIC_ICR_LOW and (value & 0x700) == 0x600) { // Check for Startup IPI
            serial.println("[APIC] About to write SIPI, serializing...", .{});

            // Ensure interrupts are disabled
            const flags = asm volatile ("pushfq; popq %[result]; cli"
                : [result] "=r" (-> u64),
            );
            const interrupts_were_enabled = (flags & 0x200) != 0;
            if (interrupts_were_enabled) {
                serial.println("[APIC] WARNING: Interrupts were enabled during SIPI, now disabled", .{});
            }

            // Serialize execution to ensure all previous operations complete
            asm volatile ("cpuid" ::: "eax", "ebx", "ecx", "edx", "memory");
        }

        // Write the value to the APIC register
        reg_ptr[0] = value;

        // For SIPI specifically, add extra synchronization
        if (offset == APIC_ICR_LOW and (value & 0x700) == 0x600) {
            // Strong memory barriers to ensure write completes
            asm volatile ("mfence; lfence; sfence" ::: "memory");

            // Read back to ensure write completed
            const readback = reg_ptr[0];
            serial.println("[APIC] SIPI write completed, readback: 0x{x}", .{readback});
        }

        // Memory barrier after write
        asm volatile ("mfence" ::: "memory");

        // For SIPI, handle special requirements
        if (offset == APIC_ICR_LOW and (value & 0x700) == 0x600) { // Check for Startup IPI
            serial.println("[APIC] SIPI write completed, adding delay...", .{});

            // Small delay loop to give AP time to start
            var delay_count: u32 = 0;
            while (delay_count < 1000) : (delay_count += 1) {
                asm volatile ("pause" ::: "memory");
            }

            // Direct ESR check without recursion
            if (lapic_addr) |lapic| {
                const esr_ptr = @as([*]volatile u32, @ptrFromInt(@intFromPtr(lapic) + APIC_ESR));
                _ = esr_ptr[0]; // Read ESR
                esr_ptr[0] = 0; // Write to update ESR
                asm volatile ("mfence" ::: "memory");
                const esr_after = esr_ptr[0];
                if (esr_after != 0) {
                    serial.println("[APIC] ERROR: ESR=0x{x} after SIPI write!", .{esr_after});
                }
            }

            // Debug for SIPI
            serial.println("[APIC] SIPI handling complete", .{});
        } else {
            // Normal readback for non-SIPI writes
            const readback = reg_ptr[0];

            // Debug for ICR
            if (offset == APIC_ICR_LOW or offset == APIC_ICR_HIGH) {
                serial.println("[APIC] Write completed, readback: 0x{x}", .{readback});
            }
        }
    } else {
        serial.print("[APIC] SECURITY: APIC not initialized for register write\r\n", .{});
        @panic("APIC not initialized");
    }
}

// Check if register is read-only
fn isReadOnlyAPICRegister(offset: u32) bool {
    return switch (offset) {
        APIC_ID, APIC_VERSION, APIC_APR, APIC_PPR, APIC_RRD, APIC_TIMER_CURRENT => true,
        // ISR, TMR, IRR registers are read-only
        APIC_ISR...APIC_ISR + 0x70 => (offset - APIC_ISR) % 0x10 == 0,
        APIC_TMR...APIC_TMR + 0x70 => (offset - APIC_TMR) % 0x10 == 0,
        APIC_IRR...APIC_IRR + 0x70 => (offset - APIC_IRR) % 0x10 == 0,
        else => false,
    };
}

// Validate register values for security
fn validateAPICRegisterValue(offset: u32, value: u32) !void {
    switch (offset) {
        APIC_TPR => {
            // Task Priority Register: only bits 7:4 are valid
            if (value & ~@as(u32, 0xFF) != 0) {
                return error.InvalidTPRValue;
            }
        },
        APIC_SPURIOUS => {
            // Spurious Interrupt Vector: vector must be in range 32-255
            const vector = value & 0xFF;
            if (vector < 32) {
                return error.InvalidSpuriousVector;
            }
        },
        APIC_TIMER_LVT, APIC_THERMAL_LVT, APIC_PERF_LVT, APIC_LINT0_LVT, APIC_LINT1_LVT, APIC_ERROR_LVT => {
            // LVT entries: vector must be in range 32-255 if not masked
            if ((value & APIC_LVT_MASKED) == 0) {
                const vector = value & 0xFF;
                if (vector < 32) {
                    return error.InvalidLVTVector;
                }
            }
        },
        APIC_ICR_LOW => {
            // ICR: vector must be in range 32-255 for normal interrupts
            const delivery_mode = (value >> 8) & 0x7;
            if (delivery_mode == 0) { // Fixed delivery mode
                const vector = value & 0xFF;
                if (vector < 32) {
                    return error.InvalidICRVector;
                }
            }
        },
        else => {},
    }
}

// Initialize APIC
pub fn init() !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Check if APIC is available via CPUID
    const features = cpuid.getFeatures();
    if (!features.apic) {
        return error.APICNotAvailable;
    }
    apic_available = true;

    // Get APIC base address and status
    apic_base = readAPICBase();
    is_bsp = (apic_base & APIC_BASE_BSP) != 0;
    const physical_base = apic_base & APIC_BASE_ADDR_MASK;

    // Map APIC MMIO region as uncacheable (critical for proper operation)
    // APIC registers occupy 4KB at the base address
    paging.mapMMIORegion(physical_base, physical_base, paging.PAGE_SIZE_4K) catch |err| {
        serial.print("[APIC] Failed to map MMIO region: {}\r\n", .{err});
        return err;
    };

    // Map APIC registers to virtual memory (identity mapped for now)
    lapic_addr = @as([*]volatile u32, @ptrFromInt(physical_base));

    // Enable APIC in MSR if not already enabled
    if ((apic_base & APIC_BASE_ENABLE) == 0) {
        writeAPICBase(apic_base | APIC_BASE_ENABLE);
        apic_base = readAPICBase(); // Re-read to confirm
    }

    // Security: Clear any pending errors
    writeRegister(APIC_ESR, 0);
    _ = readRegister(APIC_ESR);

    // Enable APIC by setting spurious interrupt vector
    // Use vector 255 for spurious interrupts (highest priority, usually ignored)
    const spurious_vec = 0xFF;
    writeRegister(APIC_SPURIOUS, spurious_vec | APIC_SPURIOUS_ENABLE);

    // Set task priority to accept all interrupts
    writeRegister(APIC_TPR, 0);

    // Initialize Local Vector Table entries
    // Mask all local interrupts initially for security
    writeRegister(APIC_TIMER_LVT, APIC_LVT_MASKED);
    writeRegister(APIC_THERMAL_LVT, APIC_LVT_MASKED);
    writeRegister(APIC_PERF_LVT, APIC_LVT_MASKED);
    writeRegister(APIC_LINT0_LVT, APIC_LVT_MASKED);
    writeRegister(APIC_LINT1_LVT, APIC_LVT_MASKED);
    writeRegister(APIC_ERROR_LVT, APIC_LVT_MASKED);

    // Security: Disable logical mode (use physical addressing only)
    writeRegister(APIC_DFR, 0xFFFFFFFF); // Flat model
    writeRegister(APIC_LDR, 0x00000000); // Logical ID = 0

    // Clear any pending interrupts
    for (0..8) |i| {
        const isr_offset = APIC_ISR + @as(u32, @intCast(i * 0x10));
        if (readRegister(isr_offset) != 0) {
            // Send EOI to clear
            sendEOI();
        }
    }

    // Disable legacy PIC if present (security: prevent dual interrupt sources)
    disablePIC();
}

// Send End of Interrupt signal
pub fn sendEOI() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    writeRegister(APIC_EOI, 0);
}

// IPI delivery modes
pub const IpiDeliveryMode = enum(u3) {
    Fixed = 0,
    LowestPriority = 1,
    SMI = 2,
    Reserved = 3,
    NMI = 4,
    Init = 5,
    Startup = 6,
    ExtINT = 7,
};

// IPI destination shorthand
pub const IpiDestShorthand = enum(u2) {
    NoShorthand = 0,
    Self = 1,
    AllIncludingSelf = 2,
    AllExcludingSelf = 3,
};

// IPI level
pub const IpiLevel = enum(u1) {
    Deassert = 0,
    Assert = 1,
};

// IPI trigger mode
pub const IpiTriggerMode = enum(u1) {
    Edge = 0,
    Level = 1,
};

// Send Inter-Processor Interrupt
pub fn sendIPI(dest_apic_id: u8, vector: u8, delivery_mode: IpiDeliveryMode, level: IpiLevel, trigger_mode: IpiTriggerMode, dest_shorthand: IpiDestShorthand) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    if (!isAvailable()) {
        return error.APICNotAvailable;
    }

    // Build ICR value
    var icr_low: u32 = 0;
    icr_low |= @as(u32, vector); // Vector (bits 0-7)
    icr_low |= @as(u32, @intFromEnum(delivery_mode)) << 8; // Delivery mode (bits 8-10)
    icr_low |= @as(u32, @intFromEnum(level)) << 14; // Level (bit 14)
    icr_low |= @as(u32, @intFromEnum(trigger_mode)) << 15; // Trigger mode (bit 15)
    icr_low |= @as(u32, @intFromEnum(dest_shorthand)) << 18; // Destination shorthand (bits 18-19)

    // Debug the ICR value being built
    if (delivery_mode == .Startup or delivery_mode == .Init) {
        serial.println("[APIC] Building IPI: mode={}, vector=0x{x}, level={}, trigger={}, ICR=0x{x}", .{
            @intFromEnum(delivery_mode),
            vector,
            @intFromEnum(level),
            @intFromEnum(trigger_mode),
            icr_low,
        });
    }

    // For physical destination mode (we don't use logical mode)
    // Destination mode = 0 (physical) is bit 11, already 0

    // Wait for any previous IPI to complete
    // Note: For Startup IPIs, the delivery status bit may not be reliable
    if (delivery_mode != .Startup) {
        var retries: u32 = 0;
        const icr_value = readRegister(APIC_ICR_LOW);
        if ((icr_value & (1 << 12)) != 0) {
            serial.println("[APIC] WARNING: ICR delivery status bit is set before IPI (ICR=0x{x})", .{icr_value});
        }
        while ((readRegister(APIC_ICR_LOW) & (1 << 12)) != 0) {
            asm volatile ("pause");
            retries += 1;
            if (retries == 100000) {
                serial.println("[APIC] IPI delivery stuck after 100k retries, ICR=0x{x}", .{readRegister(APIC_ICR_LOW)});
            }
            if (retries > 1000000) {
                serial.println("[APIC] ERROR: IPI delivery timeout! ICR=0x{x}", .{readRegister(APIC_ICR_LOW)});
                return error.IPIBusy;
            }
        }
    } else {
        // For Startup IPIs, just ensure ICR is not busy before writing
        // Some CPUs don't clear the delivery status bit properly for SIPI
        const icr_before = readRegister(APIC_ICR_LOW);
        serial.println("[APIC] Before SIPI: ICR=0x{x}", .{icr_before});
    }

    // Write destination (high 32 bits) if not using shorthand
    if (dest_shorthand == .NoShorthand) {
        const icr_high = @as(u32, dest_apic_id) << 24;
        serial.println("[APIC] Writing ICR_HIGH: 0x{x} (dest APIC ID {})", .{ icr_high, dest_apic_id });
        writeRegister(APIC_ICR_HIGH, icr_high);

        // Memory barrier to ensure ICR_HIGH write completes before ICR_LOW
        asm volatile ("mfence" ::: "memory");
    }

    // For INIT and SIPI, add extra serialization as per Intel SDM
    if (delivery_mode == .Init or delivery_mode == .Startup) {
        // Ensure all previous memory operations are complete
        asm volatile ("mfence; lfence" ::: "memory");
    }

    // Write command (low 32 bits) - this sends the IPI
    serial.println("[APIC] Writing ICR_LOW: 0x{x}", .{icr_low});

    // CRITICAL: For SIPI, add an extra check to ensure we're not sending to ourselves
    if (delivery_mode == .Startup) {
        serial.println("[APIC] About to write SIPI, serializing...", .{});
        // Extra serialization before SIPI
        asm volatile ("mfence; lfence; mfence" ::: "memory");
    }

    writeRegister(APIC_ICR_LOW, icr_low);

    // For INIT and SIPI, add serialization after write as well
    if (delivery_mode == .Init or delivery_mode == .Startup) {
        // Ensure the IPI write is fully committed
        asm volatile ("mfence" ::: "memory");
        serial.println("[APIC] Post-IPI serialization complete", .{});
    }

    // Immediate debug after write to see if we get here
    serial.println("[APIC] ICR write completed, checking status...", .{});

    // For SIPI, add extra delay to ensure AP doesn't interfere
    if (delivery_mode == .Startup) {
        // Small busy wait to let AP get past initial real mode
        var delay: u32 = 0;
        while (delay < 100000) : (delay += 1) {
            asm volatile ("pause" ::: "memory");
        }
        serial.println("[APIC] Post-SIPI delay completed", .{});
    }

    // Debug: Check if IPI was sent
    if (delivery_mode == .Startup or delivery_mode == .Init) {
        const final_icr = readRegister(APIC_ICR_LOW);
        serial.println("[APIC] After IPI write: vector=0x{x}, dest={}, ICR now=0x{x}", .{ vector, dest_apic_id, final_icr });
    }
}

// Mask all interrupts except timer
pub fn maskAllInterrupts() void {
    // Mask thermal sensor interrupts
    writeRegister(APIC_THERMAL_LVT, APIC_LVT_MASKED);

    // Mask performance counter interrupts
    writeRegister(APIC_PERF_LVT, APIC_LVT_MASKED);

    // Mask LINT0 (usually connected to 8259 PIC)
    writeRegister(APIC_LINT0_LVT, APIC_LVT_MASKED);

    // Mask LINT1 (usually NMI)
    writeRegister(APIC_LINT1_LVT, APIC_LVT_MASKED);

    // Mask error interrupts
    writeRegister(APIC_ERROR_LVT, APIC_LVT_MASKED);

    // Keep timer unmasked as we need it
}

// Get LAPIC ID (useful for multi-core)
pub fn getID() u32 {
    return readRegister(APIC_ID) >> 24;
}

// Get APIC version info
pub fn getVersion() u32 {
    return readRegister(APIC_VERSION);
}

// Check for errors
pub fn checkErrors() u32 {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Write to ESR to update it
    writeRegister(APIC_ESR, 0);
    return readRegister(APIC_ESR);
}

// Initialize APIC timer with given frequency
pub fn initTimer(frequency_hz: u32) void {
    _ = frequency_hz; // Timer module handles actual frequency setup

    // Timer is configured by the timer module which handles calibration
    // This simplified version uses vector 32 by default
    const vector: u32 = 32;

    // Set up periodic timer on vector 32 (unmasked)
    // Note: We explicitly clear the mask bit (bit 16) to enable the timer
    writeRegister(APIC_TIMER_LVT, vector | APIC_TIMER_PERIODIC);
}

// Stop APIC timer
pub fn stopTimer() void {
    writeRegister(APIC_TIMER_LVT, APIC_LVT_MASKED);
    writeRegister(APIC_TIMER_INITIAL, 0);
}

// Set APIC timer divider
pub fn setTimerDivider(divider: u32) void {
    var div_val: u32 = APIC_TIMER_DIV_1;
    switch (divider) {
        1 => div_val = APIC_TIMER_DIV_1,
        2 => div_val = APIC_TIMER_DIV_2,
        4 => div_val = APIC_TIMER_DIV_4,
        8 => div_val = APIC_TIMER_DIV_8,
        16 => div_val = APIC_TIMER_DIV_16,
        32 => div_val = APIC_TIMER_DIV_32,
        64 => div_val = APIC_TIMER_DIV_64,
        128 => div_val = APIC_TIMER_DIV_128,
        else => div_val = APIC_TIMER_DIV_16, // Default to 16
    }
    writeRegister(APIC_TIMER_DIVIDE, div_val);
}

// Set APIC timer initial count
pub fn setTimerInitialCount(count: u32) void {
    serial.println("[APIC] Setting timer initial count to: 0x{x:0>8} ({})", .{ count, count });
    writeRegister(APIC_TIMER_INITIAL, count);
}

// Get APIC timer current count
pub fn getTimerCurrentCount() u32 {
    return readRegister(APIC_TIMER_CURRENT);
}

// Broadcast IPI to all CPUs
pub fn broadcastIPI(vector: u8, include_self: bool) !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    if (vector < 32) {
        return error.InvalidVector;
    }

    const dest_shorthand = if (include_self) APIC_ICR_DEST_ALL else APIC_ICR_DEST_ALL_BUT_SELF;

    // Wait for any pending IPI
    var timeout: u32 = 1000000;
    while ((readRegister(APIC_ICR_LOW) & (1 << 12)) != 0 and timeout > 0) : (timeout -= 1) {
        asm volatile ("pause");
    }

    if (timeout == 0) {
        return error.IPITimeout;
    }

    // No need to set ICR_HIGH for broadcast
    const icr_low = @as(u32, vector) | APIC_ICR_DELIVERY_FIXED | dest_shorthand | APIC_ICR_LEVEL_ASSERT;
    writeRegister(APIC_ICR_LOW, icr_low);
}

// Calibrate APIC timer using PIT
pub fn calibrateTimer() !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Use PIT channel 2 for calibration
    const calibration_ms = 10;
    const pit_frequency = 1193182; // Hz
    const pit_ticks = (pit_frequency * calibration_ms) / 1000;

    // Configure PIT channel 2
    io_security.outb(0x43, 0xB0); // Channel 2, LSB/MSB, mode 0

    // Set count
    const count = @as(u16, @truncate(pit_ticks));
    io_security.outb(0x42, @as(u8, @truncate(count)));
    io_security.outb(0x42, @as(u8, @truncate(count >> 8)));

    // Set APIC timer to maximum count
    writeRegister(APIC_TIMER_DIVIDE, APIC_TIMER_DIV_16);
    writeRegister(APIC_TIMER_INITIAL, 0xFFFFFFFF);

    // Enable gate for PIT channel 2 and start timing
    var port61 = io_security.inb(0x61);
    port61 = (port61 & 0xFC) | 0x01;
    io_security.outb(0x61, port61);

    // Read initial APIC timer value
    const start_apic = readRegister(APIC_TIMER_CURRENT);

    // Wait for PIT to count down
    while (true) {
        port61 = io_security.inb(0x61);
        if ((port61 & 0x20) != 0) break;
    }

    // Read final APIC timer value
    const end_apic = readRegister(APIC_TIMER_CURRENT);

    // Stop APIC timer
    writeRegister(APIC_TIMER_INITIAL, 0);

    // Calculate ticks elapsed
    const apic_ticks = start_apic - end_apic;

    // Calculate APIC timer frequency
    // apic_ticks occurred in calibration_ms milliseconds
    // So frequency = (apic_ticks * 1000 * divider) / calibration_ms
    timer_frequency = (@as(u64, apic_ticks) * 1000 * 16) / calibration_ms;
    timer_calibrated = true;
}

// Disable legacy 8259 PIC
fn disablePIC() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Mask all interrupts on both PICs
    io_security.outb(0xA1, 0xFF); // Slave PIC
    io_security.outb(0x21, 0xFF); // Master PIC

    // Send initialization command to both PICs
    io_security.outb(0x20, 0x11); // Master PIC
    io_security.outb(0xA0, 0x11); // Slave PIC

    // Set vector offsets (we won't use them, but set them high)
    io_security.outb(0x21, 0xF0); // Master starts at 240
    io_security.outb(0xA1, 0xF8); // Slave starts at 248

    // Set up cascading
    io_security.outb(0x21, 0x04); // Master has slave on IRQ2
    io_security.outb(0xA1, 0x02); // Slave cascade identity

    // Set 8086 mode
    io_security.outb(0x21, 0x01);
    io_security.outb(0xA1, 0x01);

    // Mask all interrupts again
    io_security.outb(0x21, 0xFF);
    io_security.outb(0xA1, 0xFF);
}

// Print APIC information
pub fn printInfo() void {
    if (!isAvailable()) {
        serial.println("[APIC] Not available on this CPU", .{});
        return;
    }

    secure_print.printValue("[APIC] Base", apic_base & APIC_BASE_ADDR_MASK);
    serial.println("[APIC] BSP: {s}", .{if (is_bsp) "true" else "false"});
    serial.println("[APIC] Enabled: {s}", .{if ((apic_base & APIC_BASE_ENABLE) != 0) "true" else "false"});

    serial.println("[APIC] ID: {}", .{getID()});

    const version = getVersion();
    const version_num = version & 0xFF;
    const max_lvt = (version >> 16) & 0xFF;
    serial.println("[APIC] Version: 0x{x:0>2}, Max LVT: {}", .{ version_num, max_lvt });

    if (timer_calibrated) {
        serial.println("[APIC] Timer frequency: {} MHz", .{timer_frequency / 1_000_000});
    } else {
        serial.println("[APIC] Timer not calibrated", .{});
    }

    // Print timer register values
    const timer_lvt = readRegister(APIC_TIMER_LVT);
    const timer_initial = readRegister(APIC_TIMER_INITIAL);
    const timer_current = readRegister(APIC_TIMER_CURRENT);
    const timer_divide = readRegister(APIC_TIMER_DIVIDE);

    serial.println("[APIC] Timer LVT: 0x{x:0>8} (vector={}, mask={s}, mode={s})", .{ timer_lvt, timer_lvt & 0xFF, if ((timer_lvt & APIC_LVT_MASKED) != 0) "YES" else "NO", if ((timer_lvt & APIC_TIMER_PERIODIC) != 0) "periodic" else "one-shot" });
    serial.println("[APIC] Timer Initial Count: 0x{x:0>8} ({})", .{ timer_initial, timer_initial });
    serial.println("[APIC] Timer Current Count: 0x{x:0>8} ({})", .{ timer_current, timer_current });
    serial.println("[APIC] Timer Divide: 0x{x:0>8}", .{timer_divide});

    const errors = checkErrors();
    if (errors != 0) {
        serial.println("[APIC] Errors: 0x{x:0>8}", .{errors});
    }

    // Security audit info
    const total_reads = apic_reads.load(.acquire);
    const total_writes = apic_writes.load(.acquire);
    const bounds_violations = apic_bounds_violations.load(.acquire);

    serial.println("[APIC] Security: {} reads, {} writes", .{ total_reads, total_writes });

    if (bounds_violations > 0) {
        serial.println("[APIC] SECURITY WARNING: {} bounds violations detected!", .{bounds_violations});
    } else {
        serial.println("[APIC] Security: No bounds violations detected", .{});
    }
}

// Test APIC functionality
pub fn testAPIC() !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    if (!isAvailable()) {
        return error.APICNotAvailable;
    }

    // Test 1: Verify we can read/write registers
    const original_tpr = readRegister(APIC_TPR);
    writeRegister(APIC_TPR, 0x10);
    const new_tpr = readRegister(APIC_TPR);
    writeRegister(APIC_TPR, original_tpr); // Restore

    if ((new_tpr & 0xFF) != 0x10) {
        return error.APICRegisterTestFailed;
    }

    // Test 2: Check error register is clear
    const errors = checkErrors();
    if (errors != 0) {
        return error.APICHasErrors;
    }

    // Test 3: Verify timer can be configured
    initTimer(100); // 100Hz
    const timer_lvt = readRegister(APIC_TIMER_LVT);
    stopTimer();

    if ((timer_lvt & 0xFF) != 32) {
        return error.APICTimerTestFailed;
    }
}
