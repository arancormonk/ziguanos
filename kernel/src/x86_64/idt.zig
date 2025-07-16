// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const gdt = @import("gdt.zig");
const exceptions = @import("exceptions.zig");
const interrupt_security = @import("interrupt_security.zig");
const serial = @import("../drivers/serial.zig");
const runtime_info = @import("../boot/runtime_info.zig");
const spectre_v1 = @import("spectre_v1.zig");
const error_utils = @import("../lib/error_utils.zig");

// IDT entry structure (16 bytes)
const IDTEntry = packed struct {
    offset_low: u16,
    selector: u16,
    ist: u8, // Bits 0-2: IST, 3-7: Reserved (0)
    type_attr: u8, // Type and attributes
    offset_mid: u16,
    offset_high: u32,
    reserved: u32 = 0,
};

// IDT pointer for LIDT instruction
pub const IDTPointer = packed struct {
    limit: u16,
    base: u64,
};

// IDT storage
var idt_entries: [256]IDTEntry align(16) = std.mem.zeroes([256]IDTEntry);
var idt_ptr: IDTPointer = std.mem.zeroes(IDTPointer);

// Gate types
const INTERRUPT_GATE: u8 = 0x8E; // Present, DPL=0, 64-bit interrupt gate
const TRAP_GATE: u8 = 0x8F; // Present, DPL=0, 64-bit trap gate

// Create an IDT entry
fn makeIDTEntry(handler: u64, selector: u16, type_attr: u8, ist: u8) IDTEntry {
    return IDTEntry{
        .offset_low = @truncate(handler & 0xFFFF),
        .selector = selector,
        .ist = ist & 0x7,
        .type_attr = type_attr,
        .offset_mid = @truncate((handler >> 16) & 0xFFFF),
        .offset_high = @truncate(handler >> 32),
        .reserved = 0,
    };
}

// Assembly exception handler stubs
// These save CPU state and call the common handler
extern fn exception0() void;
extern fn exception1() void;
extern fn exception2() void;
extern fn exception3() void;
extern fn exception4() void;
extern fn exception5() void;
extern fn exception6() void;
extern fn exception7() void;
extern fn exception8() void;
extern fn exception9() void;
extern fn exception10() void;
extern fn exception11() void;
extern fn exception12() void;
extern fn exception13() void;
extern fn exception14() void;
extern fn exception16() void;
extern fn exception17() void;
extern fn exception18() void;
extern fn exception19() void;
extern fn exception20() void;
extern fn exception21() void;
extern fn exception30() void;

// Minimal IDT initialization for early boot
// Sets up only critical exception handlers needed before stack switch
// NOTE: This function runs before stack security is initialized, so it cannot use
// CanaryGuard protection. This is an architectural requirement as IDT must be set up
// very early in the boot process before any advanced security features can be enabled.
pub fn initMinimal() void {
    // Initialize all entries as not present
    for (&idt_entries) |*entry| {
        entry.* = std.mem.zeroes(IDTEntry);
    }

    // Install only the most critical exception handlers
    // These are the ones most likely to occur during early boot

    // Double Fault (#DF) - Critical for catching cascading exceptions
    idt_entries[8] = makeIDTEntry(@intFromPtr(&exception8), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);

    // Stack Fault (#SS) - Critical during stack operations
    idt_entries[12] = makeIDTEntry(@intFromPtr(&exception12), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);

    // General Protection Fault (#GP) - Critical for segment violations
    idt_entries[13] = makeIDTEntry(@intFromPtr(&exception13), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);

    // Page Fault (#PF) - Critical for memory access violations
    idt_entries[14] = makeIDTEntry(@intFromPtr(&exception14), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);

    // Machine Check (#MC) - Critical for hardware errors
    idt_entries[18] = makeIDTEntry(@intFromPtr(&exception18), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);

    // Set up IDT pointer
    idt_ptr = IDTPointer{
        .limit = @sizeOf(@TypeOf(idt_entries)) - 1,
        .base = @intFromPtr(&idt_entries),
    };

    // Load IDT
    asm volatile ("lidt %[ptr]"
        :
        : [ptr] "*p" (&idt_ptr),
        : "memory"
    );

    // Note: We don't initialize interrupt security or print messages here
    // because serial/stack security may not be ready yet
}

// Initialize the complete Interrupt Descriptor Table (IDT)
// NOTE: This function runs before stack security is initialized, so it cannot use
// CanaryGuard protection. This is an architectural requirement as IDT must be set up
// very early in the boot process before any advanced security features can be enabled.
pub fn init() void {

    // Initialize all entries as not present
    for (&idt_entries) |*entry| {
        entry.* = std.mem.zeroes(IDTEntry);
    }

    // Initialize interrupt security first
    interrupt_security.init() catch |err| {
        serial.println("[IDT] Failed to initialize interrupt security: {s}", .{error_utils.errorToString(err)});
    };

    // Install exception handlers
    installExceptionHandlers();

    // Install interrupt handlers
    installInterruptHandlers();

    // Load IDT
    loadIDT();

    serial.println("[IDT] Initialized with enhanced security features", .{});
}

// Load IDT with proper address handling for PIE mode
fn loadIDT() void {
    const info = runtime_info.getRuntimeInfo();
    idt_ptr = IDTPointer{
        .limit = @sizeOf(@TypeOf(idt_entries)) - 1,
        .base = if (info.pie_mode and !runtime_info.isVirtualMemoryEnabled())
            runtime_info.virtualToPhysical(@intFromPtr(&idt_entries))
        else
            @intFromPtr(&idt_entries),
    };

    asm volatile ("lidt %[ptr]"
        :
        : [ptr] "*p" (&idt_ptr),
        : "memory"
    );
}

fn installExceptionHandlers() void {
    // CPU exceptions (0-31) with proper IST assignments
    idt_entries[0] = makeIDTEntry(@intFromPtr(&exception0), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);
    idt_entries[1] = makeIDTEntry(@intFromPtr(&exception1), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, interrupt_security.IST.DEBUG);
    idt_entries[2] = makeIDTEntry(@intFromPtr(&exception2), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, interrupt_security.IST.NMI);
    idt_entries[3] = makeIDTEntry(@intFromPtr(&exception3), gdt.KERNEL_CODE_SELECTOR, TRAP_GATE, 0);
    idt_entries[4] = makeIDTEntry(@intFromPtr(&exception4), gdt.KERNEL_CODE_SELECTOR, TRAP_GATE, 0);
    idt_entries[5] = makeIDTEntry(@intFromPtr(&exception5), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);
    idt_entries[6] = makeIDTEntry(@intFromPtr(&exception6), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);
    idt_entries[7] = makeIDTEntry(@intFromPtr(&exception7), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);
    idt_entries[8] = makeIDTEntry(@intFromPtr(&exception8), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, interrupt_security.IST.DOUBLE_FAULT);
    idt_entries[9] = makeIDTEntry(@intFromPtr(&exception9), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);
    idt_entries[10] = makeIDTEntry(@intFromPtr(&exception10), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);
    idt_entries[11] = makeIDTEntry(@intFromPtr(&exception11), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);
    idt_entries[12] = makeIDTEntry(@intFromPtr(&exception12), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, interrupt_security.IST.STACK_FAULT);
    idt_entries[13] = makeIDTEntry(@intFromPtr(&exception13), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, interrupt_security.IST.GENERAL_PROTECTION);
    idt_entries[14] = makeIDTEntry(@intFromPtr(&exception14), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, interrupt_security.IST.PAGE_FAULT);
    // 15 is reserved
    idt_entries[16] = makeIDTEntry(@intFromPtr(&exception16), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);
    idt_entries[17] = makeIDTEntry(@intFromPtr(&exception17), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);
    idt_entries[18] = makeIDTEntry(@intFromPtr(&exception18), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, interrupt_security.IST.MACHINE_CHECK);
    idt_entries[19] = makeIDTEntry(@intFromPtr(&exception19), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);
    idt_entries[20] = makeIDTEntry(@intFromPtr(&exception20), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);
    idt_entries[21] = makeIDTEntry(@intFromPtr(&exception21), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);
    // 22-29 are reserved
    idt_entries[30] = makeIDTEntry(@intFromPtr(&exception30), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);
}

// Install interrupt handler for a specific vector
pub fn installHandler(vector: u8, handler: u64, ist: u8) void {
    const safe_vector = spectre_v1.safeArrayIndex(vector, idt_entries.len);
    idt_entries[safe_vector] = makeIDTEntry(handler, gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, ist);
}

// Get IDT entry for debugging
pub fn getEntry(vector: u8) IDTEntry {
    const safe_vector = spectre_v1.safeArrayIndex(vector, idt_entries.len);
    return idt_entries[safe_vector];
}

// Get raw IDT entry bytes for detailed debugging
pub fn getEntryBytes(vector: u8) [16]u8 {
    const safe_vector = spectre_v1.safeArrayIndex(vector, idt_entries.len);
    const entry = &idt_entries[safe_vector];
    return @bitCast(entry.*);
}

// Reconstruct the full offset from an IDT entry
pub fn reconstructOffset(entry: IDTEntry) u64 {
    return @as(u64, entry.offset_low) |
        (@as(u64, entry.offset_mid) << 16) |
        (@as(u64, entry.offset_high) << 32);
}

// Import interrupt stubs
extern fn interrupt32() void;
extern fn interrupt255() void;
pub extern fn testInterrupt32() void;
pub extern fn minimalInterrupt32() void;
pub extern var test_counter: u64;

// Install interrupt handlers
fn installInterruptHandlers() void {
    // Timer interrupt (vector 32) - re-enabled
    idt_entries[32] = makeIDTEntry(@intFromPtr(&interrupt32), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);

    // Spurious interrupt (vector 255)
    idt_entries[255] = makeIDTEntry(@intFromPtr(&interrupt255), gdt.KERNEL_CODE_SELECTOR, INTERRUPT_GATE, 0);

    // Additional interrupts can be installed as needed
}

// Get the current IDTR value
pub fn getIDTR() IDTPointer {
    var idtr: IDTPointer = undefined;
    asm volatile ("sidt %[idtr]"
        : [idtr] "=m" (idtr),
    );
    return idtr;
}

// Test IDT by triggering a divide-by-zero exception
pub fn testIDT() void {
    // This will trigger exception 0 (Division Error) using inline assembly
    // to avoid compile-time checks
    asm volatile (
        \\xor %%eax, %%eax
        \\xor %%edx, %%edx
        \\mov $1, %%ecx
        \\div %%eax
        ::: "eax", "edx", "ecx");
}
