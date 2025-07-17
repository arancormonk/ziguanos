// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const uefi = std.os.uefi;

// EFI_MP_SERVICES_PROTOCOL_GUID
pub const guid align(8) = uefi.Guid{
    .time_low = 0x3fdda605,
    .time_mid = 0xa76e,
    .time_high_and_version = 0x4f46,
    .clock_seq_high_and_reserved = 0xad,
    .clock_seq_low = 0x29,
    .node = [_]u8{ 0x12, 0xf4, 0x53, 0x1b, 0x3d, 0x08 },
};

pub const ProcessorInformation = extern struct {
    processor_id: u64,
    status_flag: u32,
    location: ProcessorLocation,
    extended_information: ProcessorExtendedInformation,
};

pub const ProcessorLocation = extern struct {
    package: u32,
    core: u32,
    thread: u32,
};

pub const ProcessorExtendedInformation = extern struct {
    reserved: [4]u32,
};

pub const Protocol = extern struct {
    get_number_of_processors: *const fn (*Protocol, *usize, *usize) callconv(.C) uefi.Status,
    get_processor_info: *const fn (*Protocol, usize, *ProcessorInformation) callconv(.C) uefi.Status,
    startup_all_aps: *const fn (*Protocol, ?*const fn (*anyopaque) callconv(.C) void, bool, ?*uefi.Event, usize, ?*anyopaque, ?*[*]usize) callconv(.C) uefi.Status,
    startup_this_ap: *const fn (*Protocol, ?*const fn (*anyopaque) callconv(.C) void, usize, ?*uefi.Event, usize, ?*anyopaque, ?*bool) callconv(.C) uefi.Status,
    switch_bsp: *const fn (*Protocol, usize, bool) callconv(.C) uefi.Status,
    enable_disable_ap: *const fn (*Protocol, usize, bool, ?*u32) callconv(.C) uefi.Status,
    who_am_i: *const fn (*Protocol, *usize) callconv(.C) uefi.Status,
};
