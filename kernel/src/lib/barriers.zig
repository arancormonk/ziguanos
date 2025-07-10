// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

//! Memory barriers and synchronization primitives for x86-64
//! Provides various memory ordering guarantees for concurrent operations

const std = @import("std");

/// Full memory barrier - prevents all memory reordering
/// Ensures all memory operations before the barrier complete before any after
pub inline fn memoryBarrier() void {
    asm volatile ("mfence" ::: "memory");
}

/// Read memory barrier - prevents read reordering
/// Ensures all reads before the barrier complete before any reads after
pub inline fn readBarrier() void {
    asm volatile ("lfence" ::: "memory");
}

/// Write memory barrier - prevents write reordering
/// Ensures all writes before the barrier complete before any writes after
pub inline fn writeBarrier() void {
    asm volatile ("sfence" ::: "memory");
}

/// Compiler barrier - prevents compiler reordering only
/// Does not emit any CPU instructions
pub inline fn compilerBarrier() void {
    asm volatile ("" ::: "memory");
}

/// Serializing barrier - fully serializes instruction execution
/// Uses CPUID as a serializing instruction
pub inline fn serializingBarrier() void {
    asm volatile (
        \\cpuid
        :
        : [_] "{eax}" (@as(u32, 0)),
        : "eax", "ebx", "ecx", "edx", "memory"
    );
}

/// Acquire barrier - ensures subsequent reads see all previous writes
/// Used after acquiring a lock or reading a synchronization variable
pub inline fn acquireBarrier() void {
    // On x86-64, loads have acquire semantics by default
    // Compiler barrier is sufficient
    compilerBarrier();
}

/// Release barrier - ensures previous writes are visible before release
/// Used before releasing a lock or writing a synchronization variable
pub inline fn releaseBarrier() void {
    // On x86-64, stores have release semantics by default
    // Compiler barrier is sufficient
    compilerBarrier();
}

/// Store-Load barrier - prevents store-load reordering
/// The only reordering x86-64 allows, so mfence is needed
pub inline fn storeLoadBarrier() void {
    memoryBarrier();
}

/// Pause instruction - hints CPU we're in a spin loop
/// Improves performance and reduces power consumption
pub inline fn spinLoopHint() void {
    asm volatile ("pause" ::: "memory");
}

/// Monitor an address for changes (used with mwait)
/// Sets up address monitoring for efficient waiting
pub inline fn monitor(address: *const u8) void {
    asm volatile (
        \\monitor
        :
        : [_] "{rax}" (address),
          [_] "{ecx}" (@as(u32, 0)),
          [_] "{edx}" (@as(u32, 0)),
        : "memory"
    );
}

/// Wait for a monitored address to change or interrupt
/// Must be preceded by monitor() call
pub inline fn mwait(extensions: u32, hints: u32) void {
    asm volatile (
        \\mwait
        :
        : [_] "{ecx}" (extensions),
          [_] "{eax}" (hints),
        : "memory"
    );
}

/// Prefetch data into cache for reading
/// Hint to CPU to load data into cache before it's needed
pub inline fn prefetchRead(address: *const u8) void {
    asm volatile (
        \\prefetcht0 (%[addr])
        :
        : [addr] "r" (address),
        : "memory"
    );
}

/// Prefetch data into cache for writing
/// Hint to CPU to load data into cache in exclusive state
pub inline fn prefetchWrite(address: *const u8) void {
    asm volatile (
        \\prefetchw (%[addr])
        :
        : [addr] "r" (address),
        : "memory"
    );
}

/// Non-temporal store hint - bypass cache for streaming writes
/// Use for data that won't be accessed soon
pub inline fn streamingStore(comptime T: type, dst: *T, value: T) void {
    switch (@sizeOf(T)) {
        4 => asm volatile (
            \\movnti %[val], (%[dst])
            :
            : [dst] "r" (dst),
              [val] "r" (@as(u32, @bitCast(value))),
            : "memory"
        ),
        8 => asm volatile (
            \\movnti %[val], (%[dst])
            :
            : [dst] "r" (dst),
              [val] "r" (@as(u64, @bitCast(value))),
            : "memory"
        ),
        else => @compileError("streamingStore only supports 32 and 64-bit values"),
    }
}

/// Flush cache line containing the given address
/// Forces write-back of modified data to memory
pub inline fn cacheLineFlush(address: *const u8) void {
    asm volatile (
        \\clflush (%[addr])
        :
        : [addr] "r" (address),
        : "memory"
    );
}

/// Optimized cache line flush (does not serialize)
/// More efficient than clflush when available
pub inline fn cacheLineFlushOpt(address: *const u8) void {
    asm volatile (
        \\clflushopt (%[addr])
        :
        : [addr] "r" (address),
        : "memory"
    );
}

/// Write-back invalidate cache line
/// Writes back and invalidates the cache line
pub inline fn cacheLineWriteBackInvalidate(address: *const u8) void {
    asm volatile (
        \\clwb (%[addr])
        :
        : [addr] "r" (address),
        : "memory"
    );
}

/// Test utilities for barriers
pub const testing = struct {
    /// Test that barriers compile and execute without errors
    pub fn testBarriers() !void {
        // Test all barrier types
        memoryBarrier();
        readBarrier();
        writeBarrier();
        compilerBarrier();
        serializingBarrier();
        acquireBarrier();
        releaseBarrier();
        storeLoadBarrier();
        spinLoopHint();

        // Test cache operations
        var data: u64 = 0x123456789ABCDEF0;
        prefetchRead(@ptrCast(&data));
        prefetchWrite(@ptrCast(&data));
        cacheLineFlush(@ptrCast(&data));
    }

    /// Test streaming stores
    pub fn testStreamingStores() !void {
        var data32: u32 = 0x12345678;
        var data64: u64 = 0x123456789ABCDEF0;

        streamingStore(u32, &data32, 0x87654321);
        streamingStore(u64, &data64, 0x0FEDCBA987654321);

        // Ensure stores are visible
        writeBarrier();
    }
};
