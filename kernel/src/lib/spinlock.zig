// Copyright 2025 ziguanos
// SPDX-License-Identifier: MIT

const std = @import("std");

/// A spinlock implementation for protecting shared resources in multicore environments
/// Uses atomic operations and interrupt disabling for proper synchronization
pub const SpinLock = struct {
    /// Atomic boolean indicating whether the lock is held
    locked: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Acquire the spinlock
    /// Returns the previous interrupt flags that should be restored on release
    pub fn acquire(self: *SpinLock) u64 {
        // Disable interrupts first to prevent deadlock
        const flags = asm volatile (
            \\pushfq
            \\popq %[flags]
            \\cli
            : [flags] "=r" (-> u64),
        );

        // Spin until we acquire the lock
        while (self.locked.swap(true, .acquire)) {
            // Use pause instruction to be nicer to the CPU
            asm volatile ("pause");
        }

        // Return the previous interrupt flags
        return flags;
    }

    /// Release the spinlock and restore interrupt flags
    pub fn release(self: *SpinLock, flags: u64) void {
        // Release the lock
        self.locked.store(false, .release);

        // Restore interrupts if they were enabled before
        if ((flags & 0x200) != 0) {
            asm volatile ("sti");
        }
    }

    /// Check if the lock is currently held (without acquiring)
    pub fn isLocked(self: *const SpinLock) bool {
        return self.locked.load(.monotonic);
    }
};

/// RAII-style spinlock guard that automatically releases the lock
pub const SpinLockGuard = struct {
    lock: *SpinLock,
    flags: u64,

    /// Initialize the guard and acquire the lock
    pub fn init(lock: *SpinLock) SpinLockGuard {
        const flags = lock.acquire();
        return SpinLockGuard{
            .lock = lock,
            .flags = flags,
        };
    }

    /// Release the lock and restore interrupt flags
    pub fn deinit(self: *SpinLockGuard) void {
        self.lock.release(self.flags);
    }
};

/// Per-table spinlock system for page table operations
/// Provides fine-grained locking for different page table levels
pub const PageTableLockSystem = struct {
    /// Lock for PML4 table modifications
    pml4_lock: SpinLock = SpinLock{},

    /// Locks for PDPT table modifications (up to 512 entries)
    pdpt_locks: [512]SpinLock = [_]SpinLock{SpinLock{}} ** 512,

    /// Global lock for page table structure changes
    global_lock: SpinLock = SpinLock{},

    /// Acquire lock for modifying a specific page table entry
    /// Returns a guard that will automatically release the lock
    pub fn acquireForAddress(self: *PageTableLockSystem, virt_addr: u64) SpinLockGuard {
        _ = virt_addr; // Future use for fine-grained locking
        // For page table operations, we need the global lock to ensure
        // consistent page table structure
        return SpinLockGuard.init(&self.global_lock);
    }

    /// Acquire lock for PML4 modifications
    pub fn acquirePML4Lock(self: *PageTableLockSystem) SpinLockGuard {
        return SpinLockGuard.init(&self.pml4_lock);
    }

    /// Acquire lock for PDPT modifications
    pub fn acquirePDPTLock(self: *PageTableLockSystem, pdpt_index: usize) SpinLockGuard {
        if (pdpt_index >= self.pdpt_locks.len) {
            // Fall back to global lock for out-of-bounds access
            return SpinLockGuard.init(&self.global_lock);
        }
        return SpinLockGuard.init(&self.pdpt_locks[pdpt_index]);
    }

    /// Acquire global lock for major page table operations
    pub fn acquireGlobalLock(self: *PageTableLockSystem) SpinLockGuard {
        return SpinLockGuard.init(&self.global_lock);
    }
};

/// Global page table lock system instance
pub var page_table_locks: PageTableLockSystem = PageTableLockSystem{};

/// Test spinlock functionality
pub fn testSpinLock() void {
    var test_lock = SpinLock{};

    // Test basic acquire/release
    const flags = test_lock.acquire();
    test_lock.release(flags);

    // Test RAII guard
    {
        var guard = SpinLockGuard.init(&test_lock);
        defer guard.deinit();
        // Lock is held during this scope
    }
    // Lock is automatically released here
}
