// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");

// Convert an error to a string representation safely
// In freestanding environments, @errorName can fail or return non-string types
pub fn errorToString(err: anyerror) []const u8 {
    // Try to use @errorName, but catch any issues
    const name = @errorName(err);

    // Check if we got a valid string
    if (@TypeOf(name) == []const u8) {
        return name;
    }

    // If @errorName didn't return a string, return a generic message
    return switch (err) {
        error.OutOfMemory => "OutOfMemory",
        error.InvalidSize => "InvalidSize",
        error.HeapNotInitialized => "HeapNotInitialized",
        error.HeapCorruption => "HeapCorruption",
        error.StackAllocFailed => "StackAllocFailed",
        error.StartupTimeout => "StartupTimeout",
        error.InvalidCpuId => "InvalidCpuId",
        error.TrampolineTooLarge => "TrampolineTooLarge",
        error.InitIPIFailed => "InitIPIFailed",
        // Paging errors
        error.PageNotMapped => "PageNotMapped",
        error.PageTableNotPresent => "PageTableNotPresent",
        error.PageTableBeyondMappedMemory => "PageTableBeyondMappedMemory",
        error.OutOfPageTables => "OutOfPageTables",
        error.AddressTranslationError => "AddressTranslationError",
        error.CannotModify1GBPage => "CannotModify1GBPage",
        error.PagingNotInitialized => "PagingNotInitialized",
        else => "UnknownError",
    };
}

// Format an error for printing
pub fn formatError(err: anyerror, writer: anytype) !void {
    const err_str = errorToString(err);
    try writer.print("{s}", .{err_str});
}
