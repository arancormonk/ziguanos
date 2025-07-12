// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const runtime_info = @import("../boot/runtime_info.zig");

// GDT entry structure (8 bytes)
const GDTEntry = packed struct {
    limit_low: u16,
    base_low: u16,
    base_middle: u8,
    access: u8,
    flags_limit_high: u8,
    base_high: u8,
};

// GDT pointer for LGDT instruction
pub const GDTPointer = packed struct {
    limit: u16,
    base: u64,
};

// Task State Segment for x86-64
pub const TSS = extern struct {
    reserved0: u32 = 0,
    rsp0: u64 = 0, // Stack pointer for privilege level 0
    rsp1: u64 = 0, // Stack pointer for privilege level 1
    rsp2: u64 = 0, // Stack pointer for privilege level 2
    reserved1: u64 = 0,
    ist1: u64 = 0, // Interrupt Stack Table entry 1
    ist2: u64 = 0,
    ist3: u64 = 0,
    ist4: u64 = 0,
    ist5: u64 = 0,
    ist6: u64 = 0,
    ist7: u64 = 0,
    reserved2: u64 = 0,
    reserved3: u16 = 0,
    iopb_offset: u16 = @sizeOf(TSS),
};

// Export tss for io_security module
pub var tss: TSS align(16) = std.mem.zeroes(TSS);

// Static GDT storage (must be aligned)
var gdt_entries: [7]GDTEntry align(16) = std.mem.zeroes([7]GDTEntry);
var gdt_ptr: GDTPointer = std.mem.zeroes(GDTPointer);

// Kernel stack for interrupts (16KB)
var kernel_interrupt_stack: [4096]u64 align(16) = std.mem.zeroes([4096]u64);

// Segment selectors
pub const NULL_SELECTOR: u16 = 0x00;
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;
pub const USER_CODE_SELECTOR: u16 = 0x18 | 3; // RPL=3
pub const USER_DATA_SELECTOR: u16 = 0x20 | 3; // RPL=3
pub const TSS_SELECTOR: u16 = 0x28;

fn makeGDTEntry(base: u32, limit: u32, access: u8, flags: u8) GDTEntry {
    return GDTEntry{
        .limit_low = @truncate(limit & 0xFFFF),
        .base_low = @truncate(base & 0xFFFF),
        .base_middle = @truncate((base >> 16) & 0xFF),
        .access = access,
        .flags_limit_high = @truncate(((limit >> 16) & 0x0F) | (flags << 4)),
        .base_high = @truncate((base >> 24) & 0xFF),
    };
}

// Initialize GDT for early boot in PIE mode (using physical addresses)
pub fn initEarly() void {
    // Set up GDT entries
    setupGDTEntries();

    // Load GDT with physical address
    loadGDTEarly();
}

// Initialize the Global Descriptor Table (GDT)
// NOTE: This function runs before stack security is initialized, so it cannot use
// CanaryGuard protection. This is an architectural requirement as GDT must be set up
// very early in the boot process before any advanced security features can be enabled.
pub fn init() void {
    // Set up GDT entries
    setupGDTEntries();

    // Load GDT normally
    loadGDT();
}

// Set up GDT entries (shared between init and initEarly)
fn setupGDTEntries() void {

    // 1. Null descriptor (required)
    gdt_entries[0] = std.mem.zeroes(GDTEntry);

    // 2. Kernel code segment
    // Access: Present=1, DPL=0, Type=Code, Execute/Read
    gdt_entries[1] = makeGDTEntry(0, 0xFFFFF, 0x9A, 0xA);

    // 3. Kernel data segment
    // Access: Present=1, DPL=0, Type=Data, Read/Write
    gdt_entries[2] = makeGDTEntry(0, 0xFFFFF, 0x92, 0xC);

    // 4. User code segment
    // Access: Present=1, DPL=3, Type=Code, Execute/Read
    gdt_entries[3] = makeGDTEntry(0, 0xFFFFF, 0xFA, 0xA);

    // 5. User data segment
    // Access: Present=1, DPL=3, Type=Data, Read/Write
    gdt_entries[4] = makeGDTEntry(0, 0xFFFFF, 0xF2, 0xC);

    // 6-7. TSS descriptor (16 bytes in long mode)
    setupTSS();
}

// Load GDT normally (with virtual addresses)
fn loadGDT() void {
    gdt_ptr = GDTPointer{
        .limit = @sizeOf(@TypeOf(gdt_entries)) - 1,
        .base = @intFromPtr(&gdt_entries),
    };

    asm volatile ("lgdt %[ptr]"
        :
        : [ptr] "*p" (&gdt_ptr),
        : "memory"
    );

    // Reload segments with far jump
    reloadSegments();

    // Load TSS
    asm volatile ("ltr %[sel]"
        :
        : [sel] "r" (TSS_SELECTOR),
        : "memory"
    );
}

// Load GDT for early boot (using physical addresses)
fn loadGDTEarly() void {
    const info = runtime_info.getRuntimeInfo();
    gdt_ptr = GDTPointer{
        .limit = @sizeOf(@TypeOf(gdt_entries)) - 1,
        .base = if (info.pie_mode and !runtime_info.isVirtualMemoryEnabled())
            runtime_info.virtualToPhysical(@intFromPtr(&gdt_entries))
        else
            @intFromPtr(&gdt_entries),
    };

    asm volatile ("lgdt %[ptr]"
        :
        : [ptr] "*p" (&gdt_ptr),
        : "memory"
    );

    // Reload segments with far jump
    reloadSegments();

    // Load TSS
    asm volatile ("ltr %[sel]"
        :
        : [sel] "r" (TSS_SELECTOR),
        : "memory"
    );
}

// Test that GDT is loaded correctly
pub fn testGDT() bool {
    // Read current code segment selector
    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );

    // Verify it matches our kernel code selector
    return cs == KERNEL_CODE_SELECTOR;
}

fn setupTSS() void {

    // Initialize TSS with interrupt stack
    tss.rsp0 = @intFromPtr(&kernel_interrupt_stack) + kernel_interrupt_stack.len * 8;
    tss.ist1 = tss.rsp0; // Use same stack for IST1 (double fault handler)

    const tss_base = @intFromPtr(&tss);
    const tss_limit = @sizeOf(TSS) - 1;

    // TSS descriptor is special - spans two GDT entries
    // Low 8 bytes
    gdt_entries[5] = makeGDTEntry(@truncate(tss_base), tss_limit, 0x89, 0x0);

    // High 8 bytes (base bits 32-63)
    const high_base = tss_base >> 32;
    gdt_entries[6] = GDTEntry{
        .limit_low = @truncate(high_base & 0xFFFF),
        .base_low = @truncate((high_base >> 16) & 0xFFFF),
        .base_middle = 0,
        .access = 0,
        .flags_limit_high = 0,
        .base_high = 0,
    };
}

fn reloadSegments() void {
    // Use inline assembly to reload all segments
    asm volatile (
        \\mov $0x10, %%ax
        \\mov %%ax, %%ds
        \\mov %%ax, %%es
        \\mov %%ax, %%fs
        \\mov %%ax, %%gs
        \\mov %%ax, %%ss
        \\pushq $0x08
        \\lea 1f(%%rip), %%rax
        \\pushq %%rax
        \\lretq
        \\1:
        ::: "rax", "memory");
}

// Update TSS descriptor in GDT (for I/O permission bitmap)
pub fn updateTSSDescriptor(base: u64, limit: u32) void {
    // TSS descriptor is a 16-byte system descriptor in long mode
    const tss_idx = 5; // TSS starts at GDT entry 5

    // Low 8 bytes
    gdt_entries[tss_idx] = GDTEntry{
        .limit_low = @truncate(limit & 0xFFFF),
        .base_low = @truncate(base & 0xFFFF),
        .base_middle = @truncate((base >> 16) & 0xFF),
        .access = 0x89, // Present=1, Type=TSS Available (0x9)
        .flags_limit_high = @truncate(((limit >> 16) & 0x0F) | 0x00), // 32-bit TSS
        .base_high = @truncate((base >> 24) & 0xFF),
    };

    // High 8 bytes (upper 32 bits of base address)
    const high_base = base >> 32;
    gdt_entries[tss_idx + 1] = GDTEntry{
        .limit_low = @truncate(high_base & 0xFFFF),
        .base_low = @truncate((high_base >> 16) & 0xFFFF),
        .base_middle = 0,
        .access = 0,
        .flags_limit_high = 0,
        .base_high = 0,
    };

    // Reload TSS
    asm volatile ("ltr %[sel]"
        :
        : [sel] "r" (TSS_SELECTOR),
        : "memory"
    );
}
