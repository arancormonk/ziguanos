// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");

// VGA text buffer for panic display
const VGA_BUFFER_ADDR: usize = 0xB8000;
const VGA_BUFFER = @as(*volatile [25][80]u16, @ptrFromInt(VGA_BUFFER_ADDR));

// VGA colors
const VGAColor = enum(u8) {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Brown = 6,
    LightGray = 7,
    DarkGray = 8,
    LightBlue = 9,
    LightGreen = 10,
    LightCyan = 11,
    LightRed = 12,
    LightMagenta = 13,
    Yellow = 14,
    White = 15,
};

fn makeVGAColor(fg: VGAColor, bg: VGAColor) u8 {
    return @intFromEnum(fg) | (@intFromEnum(bg) << 4);
}

fn makeVGAEntry(char: u8, color: u8) u16 {
    return @as(u16, char) | (@as(u16, color) << 8);
}

// Panic handler
pub fn panic(message: []const u8, _: ?*std.builtin.StackTrace, _: ?usize) noreturn {
    serial.println("[KERNEL PANIC] {s}", .{message});

    // Also display on VGA
    const panic_color = makeVGAColor(.White, .Red);

    // Clear a few lines for panic message
    for (10..15) |y| {
        for (0..80) |x| {
            VGA_BUFFER[y][x] = makeVGAEntry(' ', panic_color);
        }
    }

    // Display panic header
    const header = "!!! KERNEL PANIC !!!";
    const header_start = (80 - header.len) / 2;
    for (header, 0..) |char, i| {
        VGA_BUFFER[11][header_start + i] = makeVGAEntry(char, panic_color);
    }

    // Display message (truncate if too long)
    const msg_start = (80 - @min(message.len, 78)) / 2;
    for (0..@min(message.len, 78)) |i| {
        VGA_BUFFER[13][msg_start + i] = makeVGAEntry(message[i], panic_color);
    }

    while (true) {
        asm volatile ("cli");
        asm volatile ("hlt");
    }
}
