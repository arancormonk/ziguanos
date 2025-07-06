// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");

// Export all boot modules for easy access
pub const validation = @import("validation.zig");
pub const bss = @import("bss.zig");
pub const mode_handler = @import("mode_handler.zig");
pub const entry = @import("entry.zig");

// Re-export key functions
pub const validateBootInfo = validation.validateBootInfo;
pub const clearBSSPreserving = bss.clearBSSPreserving;
pub const handlePIEBoot = mode_handler.handlePIEBoot;
pub const handleNormalBoot = mode_handler.handleNormalBoot;
pub const getSavedBootInfo = entry.getSavedBootInfo;

// The entry point is already exported in entry.zig, so we don't re-export it here
