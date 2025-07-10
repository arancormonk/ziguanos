// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Memory security features including zeroing and poisoning

const serial = @import("../../drivers/serial.zig");
const rng = @import("../../x86_64/rng.zig");
const timer = @import("../../x86_64/timer.zig");
const stack_security = @import("../../x86_64/stack_security.zig");

pub const POISON_VALUE: u8 = 0xDE; // "Dead" marker for freed pages (legacy - not used anymore)

var zero_on_alloc: bool = true; // Enable memory zeroing by default

// Zero a memory range securely
pub fn zeroMemoryRange(addr: u64, size: u64) void {
    if (addr == 0 or size == 0) return;

    // NEVER zero the AP trampoline area (0x8000-0x9000)
    const TRAMPOLINE_START: u64 = 0x8000;
    const TRAMPOLINE_END: u64 = 0x8000 + 4096; // End of trampoline page
    if (addr >= TRAMPOLINE_START and addr < TRAMPOLINE_END) {
        return; // Silently skip zeroing protected memory
    }

    // Also protect the AP debug area (0x0-0x1000) during SMP initialization
    // Using safe conventional memory area (0x500-0x7BFF)
    const DEBUG_START: u64 = 0x0;
    const DEBUG_END: u64 = 0x1000; // End of first page
    if (addr >= DEBUG_START and addr < DEBUG_END) {
        return; // Silently skip zeroing debug memory
    }

    const ptr = @as([*]u8, @ptrFromInt(addr));
    @memset(ptr[0..size], 0);

    // Memory barrier to ensure zeroing completes
    asm volatile ("mfence" ::: "memory");
}

// Poison a memory range with cryptographically secure random patterns
pub fn poisonMemoryRange(addr: u64, size: u64) void {
    if (addr == 0 or size == 0) return;

    // NEVER poison the AP trampoline area (0x8000-0x9000)
    const TRAMPOLINE_START: u64 = 0x8000;
    const TRAMPOLINE_END: u64 = 0x8000 + 4096; // End of trampoline page
    if (addr >= TRAMPOLINE_START and addr < TRAMPOLINE_END) {
        return; // Silently skip poisoning protected memory
    }

    // Also protect the AP debug area (0x0-0x1000) during SMP initialization
    // Using safe conventional memory area (0x500-0x7BFF)
    const DEBUG_START: u64 = 0x0;
    const DEBUG_END: u64 = 0x1000; // End of first page
    if (addr >= DEBUG_START and addr < DEBUG_END) {
        return; // Silently skip poisoning debug memory
    }

    var guard = stack_security.protect();
    defer guard.deinit();

    const ptr = @as([*]u8, @ptrFromInt(addr));

    // Generate initial random poison pattern
    const rng_result = rng.getRandom64();
    var poison_pattern = if (rng_result.success)
        @as(u32, @truncate(rng_result.value))
    else
        // Fallback: mix timer ticks with address for entropy
        @as(u32, @truncate(timer.getTicks() ^ addr));

    // Fill memory with varying poison patterns
    var offset: u64 = 0;
    while (offset + 4 <= size) : (offset += 4) {
        // Vary the pattern using a simple hash function to prevent predictability
        // Using the golden ratio constant (φ - 1) * 2^32 for good bit mixing
        poison_pattern = poison_pattern ^ (@as(u32, @truncate(addr + offset)) +% 0x9E3779B9);

        const poison_ptr = @as(*u32, @ptrFromInt(addr + offset));
        poison_ptr.* = poison_pattern;
    }

    // Handle remaining bytes
    while (offset < size) : (offset += 1) {
        // Use lower byte of pattern for remaining bytes
        ptr[offset] = @as(u8, @truncate(poison_pattern));
        poison_pattern = poison_pattern >> 8;
    }

    // Memory barrier to ensure poisoning completes
    asm volatile ("mfence" ::: "memory");
}

// Enable or disable memory zeroing on allocation
pub fn setZeroOnAlloc(enabled: bool) void {
    zero_on_alloc = enabled;
    serial.print("[PMM] Memory zeroing on allocation: {s}\n", .{if (enabled) "enabled" else "disabled"});
}

// Check if zero on alloc is enabled
pub fn isZeroOnAllocEnabled() bool {
    return zero_on_alloc;
}
