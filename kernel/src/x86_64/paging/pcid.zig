// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../../drivers/serial.zig");
const cpuid = @import("../cpuid.zig");

// CR4 bit for PCID
const CR4_PCIDE: u64 = 1 << 17;

// PCID constants
pub const PCID_KERNEL: u64 = 0;
pub const PCID_USER_BASE: u64 = 1;

// Check if PCID is supported
pub fn isSupported() bool {
    const features = cpuid.getFeatures();
    // PCID requires both the PCID feature and CR4.PCIDE to be supported
    return features.pcid;
}

// Enable PCID in CR4
pub fn enable() void {
    if (!isSupported()) {
        serial.println("[PAGING] PCID not supported by CPU", .{});
        return;
    }

    // Set CR4.PCIDE bit (bit 17)
    var cr4 = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );

    cr4 |= CR4_PCIDE;

    asm volatile ("mov %[value], %%cr4"
        :
        : [value] "r" (cr4),
        : "memory"
    );

    serial.println("[PAGING] PCID enabled", .{});
}

// Load page table with PCID
pub fn loadPageTableWithPCID(pml4_addr: u64, pcid: u12) void {
    // PCID is in bits 0-11 of CR3
    // Bit 63 controls whether to flush TLB (0 = flush, 1 = no flush)
    const cr3_value = pml4_addr | pcid;

    asm volatile ("mov %[value], %%cr3"
        :
        : [value] "r" (cr3_value),
        : "memory"
    );
}

// Switch page table without flushing
pub fn switchPageTableNoFlush(pml4_addr: u64, pcid: u12) void {
    // Set bit 63 to preserve TLB entries for other PCIDs
    const cr3_value = pml4_addr | pcid | (1 << 63);

    asm volatile ("mov %[value], %%cr3"
        :
        : [value] "r" (cr3_value),
        : "memory"
    );
}

// Invalidate all TLB entries for a specific PCID
pub fn invalidatePCID(pcid: u12) void {
    if (!isSupported()) return;

    // INVPCID instruction type 0: invalidate single PCID
    const descriptor = struct {
        pcid: u64,
        addr: u64,
    }{
        .pcid = pcid,
        .addr = 0,
    };

    asm volatile (
        \\invpcid (%[desc]), %[type]
        :
        : [desc] "r" (&descriptor),
          [type] "r" (@as(u64, 1)), // Type 1: Invalidate all entries for PCID
        : "memory"
    );
}
