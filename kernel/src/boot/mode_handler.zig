// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi_boot = @import("../boot/uefi_boot.zig");
const runtime_info = @import("../boot/runtime_info.zig");
const gdt = @import("../x86_64/gdt.zig");
const cpu_init = @import("../x86_64/cpu_init.zig");

// UEFI boot info structure
const UEFIBootInfo = uefi_boot.UEFIBootInfo;

// External symbols
extern fn _start() void;

// Forward declaration of kernel main
extern fn kernelMain(boot_info: *const UEFIBootInfo) noreturn;

/// Handle PIE (Position Independent Executable) boot mode
pub fn handlePIEBoot(boot_info: *const UEFIBootInfo) noreturn {
    // We're currently executing at physical addresses
    // The bootloader has set up page tables but they're not active yet

    // Get our physical base address (where we're actually loaded)
    const physical_base = @intFromPtr(&_start) & ~@as(u64, 0xFFF);

    // Initialize runtime info with physical addresses, virtual memory not yet enabled
    runtime_info.initPIE(physical_base, boot_info.kernel_size, false);

    // Set up early CPU features that don't require virtual memory
    cpu_init.initEarlyFeatures();

    // Set up minimal GDT with physical addresses
    gdt.initEarly();

    // Enable the page tables set up by bootloader
    enableBootloaderPageTables(boot_info);

    // Now we're running with virtual memory enabled
    runtime_info.setVirtualMemoryEnabled();

    // Continue with normal initialization
    continueKernelInit(boot_info);
}

/// Handle normal (identity-mapped) boot mode
pub fn handleNormalBoot(boot_info: *const UEFIBootInfo) noreturn {
    // Traditional mode: Already at virtual addresses

    // Initialize runtime info for identity-mapped mode first
    runtime_info.init(boot_info.kernel_base, boot_info.kernel_size);

    // Set up GDT immediately for known good segments
    gdt.init();

    // Continue with normal initialization
    continueKernelInit(boot_info);
}

/// Enable page tables from bootloader
fn enableBootloaderPageTables(_: *const UEFIBootInfo) void {
    // The bootloader should pass us the CR3 value to use
    // For now, we need to coordinate with the bootloader's VMM structure

    // Enable required CPU features for paging
    var cr4 = asm volatile ("mov %%cr4, %[ret]"
        : [ret] "=r" (-> u64),
    );
    cr4 |= (1 << 5); // PAE (Physical Address Extension)
    cr4 |= (1 << 7); // PGE (Page Global Enable)
    asm volatile ("mov %[cr4], %%cr4"
        :
        : [cr4] "r" (cr4),
        : "memory"
    );

    // For PIE mode, we need the bootloader to pass the PML4 physical address
    // This would typically be in the boot info structure
    // For now, we'll panic as this needs coordination with bootloader
    @panic("PIE mode page table activation not yet implemented - needs bootloader coordination");
}

/// Continue kernel initialization after boot mode handling
pub fn continueKernelInit(boot_info: *const UEFIBootInfo) noreturn {
    // Jump directly to kernelMain which will handle all initialization
    kernelMain(boot_info);
}
