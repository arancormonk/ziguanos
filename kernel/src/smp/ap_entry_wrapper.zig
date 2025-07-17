// SPDX-License-Identifier: MIT

const std = @import("std");
const ap_early_init = @import("ap_early_init.zig");

// Minimal entry point for Application Processors
// This function is called directly from assembly code with cpu_id in RDI
pub export fn apEntryWrapper(cpu_id: u32) callconv(.C) noreturn {
    // CRITICAL: Do NOT perform any I/O operations here!
    // The AP doesn't have TSS/IOPL set up yet.
    // Any I/O will cause a #GP fault that crashes the system.

    // Write simple memory marker to verify we reached Zig code
    // Use the established debug area at 0x5B0
    const marker_ptr = @as(*volatile u32, @ptrFromInt(0x5B0));
    marker_ptr.* = 0xDEADC0DE;

    // Write CPU ID
    const id_ptr = @as(*volatile u32, @ptrFromInt(0x5B4));
    id_ptr.* = cpu_id;

    // CRITICAL: Setup GDT/TSS before any complex operations
    // This MUST happen before calling apMainEntry which does atomic ops, I/O, etc.
    ap_early_init.earlyInit(cpu_id) catch {
        // Early init failed - write error marker and halt
        const err_ptr = @as(*volatile u32, @ptrFromInt(0x5B8));
        err_ptr.* = 0xEAEADEAD;
        while (true) {
            asm volatile ("hlt");
        }
    };

    // Memory fence to ensure GDT/TSS setup is complete
    asm volatile ("mfence" ::: "memory");

    // Now it's safe to call the main entry point which can do I/O and atomic ops
    apMainEntry(cpu_id);

    // Should never reach here since apMainEntry is noreturn
    unreachable;
}

// External declaration for the real AP main entry point
extern fn apMainEntry(cpu_id: u32) callconv(.C) noreturn;
