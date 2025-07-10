// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

//! Read-Write Lock implementation for kernel synchronization
//! Allows multiple concurrent readers or a single exclusive writer

const std = @import("std");
const barriers = @import("barriers.zig");
const interrupts = @import("../x86_64/interrupts.zig");

/// Read-Write Lock structure
/// Uses a single atomic counter:
/// - 0: Unlocked
/// - >0: Number of active readers
/// - <0: Writer active (WRITER_ACTIVE)
pub const RwLock = struct {
    /// The lock state counter
    state: i32 = 0,

    /// Special value indicating a writer is active
    const WRITER_ACTIVE: i32 = -1;

    /// Maximum number of concurrent readers (prevent overflow)
    const MAX_READERS: i32 = 0x7FFFFFFF - 1;

    /// Reader lock guard - automatically releases on scope exit
    pub const ReaderGuard = struct {
        lock: *RwLock,

        pub fn deinit(self: ReaderGuard) void {
            self.lock.readUnlock();
        }
    };

    /// Writer lock guard - automatically releases on scope exit
    pub const WriterGuard = struct {
        lock: *RwLock,
        saved_flags: u64,

        pub fn deinit(self: WriterGuard) void {
            self.lock.writeUnlock(self.saved_flags);
        }
    };

    /// Initialize a new read-write lock
    pub fn init() RwLock {
        return .{ .state = 0 };
    }

    /// Acquire a read lock
    /// Multiple readers can hold the lock simultaneously
    pub fn readLock(self: *RwLock) void {
        while (true) {
            const current = @atomicLoad(i32, &self.state, .acquire);

            // If a writer is active or waiting, spin
            if (current < 0) {
                barriers.spinLoopHint();
                continue;
            }

            // Check for reader overflow
            if (current >= MAX_READERS) {
                barriers.spinLoopHint();
                continue;
            }

            // Try to increment reader count
            if (@cmpxchgWeak(
                i32,
                &self.state,
                current,
                current + 1,
                .acq_rel,
                .acquire,
            ) == null) {
                // Success
                return;
            }

            // Failed, retry
            barriers.spinLoopHint();
        }
    }

    /// Try to acquire a read lock without blocking
    /// Returns true if successful, false if would block
    pub fn tryReadLock(self: *RwLock) bool {
        const current = @atomicLoad(i32, &self.state, .acquire);

        // Check if writer active or too many readers
        if (current < 0 or current >= MAX_READERS) {
            return false;
        }

        // Try to increment reader count
        return @cmpxchgWeak(
            i32,
            &self.state,
            current,
            current + 1,
            .acq_rel,
            .acquire,
        ) == null;
    }

    /// Release a read lock
    pub fn readUnlock(self: *RwLock) void {
        const prev = @atomicRmw(i32, &self.state, .Sub, 1, .release);
        std.debug.assert(prev > 0); // Must have been a reader
    }

    /// Acquire a write lock
    /// Exclusive access - waits for all readers to finish
    pub fn writeLock(self: *RwLock) u64 {
        // Disable interrupts for exclusive access
        const saved_flags = interrupts.disable();

        // First, atomically set to WRITER_ACTIVE
        while (true) {
            const current = @atomicLoad(i32, &self.state, .acquire);

            // If unlocked, try to acquire
            if (current == 0) {
                if (@cmpxchgWeak(
                    i32,
                    &self.state,
                    0,
                    WRITER_ACTIVE,
                    .acq_rel,
                    .acquire,
                ) == null) {
                    // Success
                    return saved_flags;
                }
            }

            // Otherwise, spin
            barriers.spinLoopHint();
        }
    }

    /// Try to acquire a write lock without blocking
    /// Returns saved interrupt flags if successful, null if would block
    pub fn tryWriteLock(self: *RwLock) ?u64 {
        const saved_flags = interrupts.disable();

        // Try to atomically transition from unlocked to writer active
        if (@cmpxchgStrong(
            i32,
            &self.state,
            0,
            WRITER_ACTIVE,
            .acq_rel,
            .acquire,
        ) == null) {
            // Success
            return saved_flags;
        }

        // Failed, restore interrupts
        interrupts.restore(saved_flags);
        return null;
    }

    /// Release a write lock
    pub fn writeUnlock(self: *RwLock, saved_flags: u64) void {
        const prev = @atomicRmw(i32, &self.state, .Xchg, 0, .release);
        std.debug.assert(prev == WRITER_ACTIVE); // Must have been the writer

        // Restore interrupts
        interrupts.restore(saved_flags);
    }

    /// Acquire a read lock with guard
    pub fn acquireRead(self: *RwLock) ReaderGuard {
        self.readLock();
        return .{ .lock = self };
    }

    /// Acquire a write lock with guard
    pub fn acquireWrite(self: *RwLock) WriterGuard {
        const saved_flags = self.writeLock();
        return .{ .lock = self, .saved_flags = saved_flags };
    }

    /// Check if the lock is currently held by any reader or writer
    pub fn isLocked(self: *const RwLock) bool {
        return @atomicLoad(i32, &self.state, .acquire) != 0;
    }

    /// Check if the lock is currently held by a writer
    pub fn isWriteLocked(self: *const RwLock) bool {
        return @atomicLoad(i32, &self.state, .acquire) < 0;
    }

    /// Get the current number of readers (0 if writer active)
    pub fn getReaderCount(self: *const RwLock) u32 {
        const state = @atomicLoad(i32, &self.state, .acquire);
        return if (state > 0) @intCast(state) else 0;
    }

    /// Downgrade a write lock to a read lock
    /// Must be called while holding the write lock
    pub fn downgrade(self: *RwLock) void {
        const prev = @atomicRmw(i32, &self.state, .Xchg, 1, .acq_rel);
        std.debug.assert(prev == WRITER_ACTIVE); // Must have been the writer
        // Note: Caller must handle interrupt restoration appropriately
    }
};

/// Test utilities
pub const testing = struct {
    /// Basic functionality test
    pub fn testBasicRwLock() !void {
        var lock = RwLock.init();

        // Test read lock
        {
            const guard = lock.acquireRead();
            defer _ = guard;

            // Should be able to acquire multiple read locks
            const guard2 = lock.acquireRead();
            defer _ = guard2;

            try std.testing.expect(lock.getReaderCount() == 2);
            try std.testing.expect(!lock.isWriteLocked());
        }

        // Lock should be released
        try std.testing.expect(!lock.isLocked());

        // Test write lock
        {
            const guard = lock.acquireWrite();
            defer _ = guard;

            try std.testing.expect(lock.isWriteLocked());
            try std.testing.expect(lock.getReaderCount() == 0);
        }

        // Lock should be released
        try std.testing.expect(!lock.isLocked());
    }

    /// Test try-lock operations
    pub fn testTryLock() !void {
        var lock = RwLock.init();

        // Try read should succeed on unlocked
        try std.testing.expect(lock.tryReadLock());
        lock.readUnlock();

        // Hold write lock
        const saved_flags = lock.writeLock();
        defer lock.writeUnlock(saved_flags);

        // Try read should fail
        try std.testing.expect(!lock.tryReadLock());

        // Try write should fail
        try std.testing.expect(lock.tryWriteLock() == null);
    }
};
