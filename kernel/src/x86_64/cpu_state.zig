// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");

// Verify that the CPU is in the expected state after UEFI handoff
pub fn verifyCPUState() void {
    // Check we're in long mode by reading the EFER MSR
    const efer = readEFER();

    // Bit 10 = LMA (Long Mode Active)
    if ((efer & (1 << 10)) == 0) {
        @panic("CPU not in long mode!");
    }

    // Verify paging is enabled by reading CR0
    const cr0 = readCR0();

    // Bit 31 = PG (Paging)
    if ((cr0 & (1 << 31)) == 0) {
        @panic("Paging not enabled!");
    }
}

// Read the Extended Feature Enable Register (EFER) MSR
fn readEFER() u64 {
    var low: u32 = 0;
    var high: u32 = 0;

    // IA32_EFER MSR address is 0xC0000080
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (@as(u32, 0xC0000080)),
        : "memory"
    );

    return (@as(u64, high) << 32) | @as(u64, low);
}

// Read Control Register 0 (CR0)
fn readCR0() u64 {
    return asm volatile ("mov %%cr0, %[result]"
        : [result] "=r" (-> u64),
    );
}
