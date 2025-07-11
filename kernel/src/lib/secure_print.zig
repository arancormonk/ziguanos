// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Secure printing utilities that automatically sanitize memory addresses
// to prevent KASLR bypass through information disclosure

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const runtime_info = @import("../boot/runtime_info.zig");

// Print a value that might be an address with automatic sanitization
pub fn printValue(comptime name: []const u8, value: u64) void {
    const info = runtime_info.getRuntimeInfo();
    const kernel_base = info.kernel_virtual_base;
    const kernel_size = info.kernel_size;

    // Check if value looks like a kernel address
    if (value >= kernel_base and value < kernel_base + kernel_size) {
        serial.printAddress(name, value);
    } else if (value >= 0xFFFF800000000000) {
        // Higher half kernel space address
        serial.printAddress(name, value);
    } else {
        // Non-kernel address, safe to print
        serial.println("{s}: 0x{x:0>16}", .{ name, value });
    }
}

// Print hex value with sanitization
pub fn printHex(comptime prefix: []const u8, value: u64) void {
    const info = runtime_info.getRuntimeInfo();
    const kernel_base = info.kernel_virtual_base;
    const kernel_size = info.kernel_size;

    if (value >= kernel_base and value < kernel_base + kernel_size) {
        serial.print("{s}{}", .{ prefix, serial.sanitizedAddress(value) });
    } else if (value >= 0xFFFF800000000000) {
        serial.print("{s}{}", .{ prefix, serial.sanitizedAddress(value) });
    } else {
        serial.print("{s}0x{x:0>16}", .{ prefix, value });
    }
}

// Print register dump with automatic sanitization
pub fn printRegisters(frame: anytype) void {
    serial.println("  Registers:", .{});
    printValue("    RIP", frame.rip);
    printValue("    RSP", frame.rsp);
    printValue("    RBP", @field(frame, "rbp"));
    serial.println("    RFLAGS: 0x{x:0>16}", .{frame.rflags});

    // General purpose registers
    printValue("    RAX", @field(frame, "rax"));
    printValue("    RBX", @field(frame, "rbx"));
    printValue("    RCX", @field(frame, "rcx"));
    printValue("    RDX", @field(frame, "rdx"));
    printValue("    RSI", @field(frame, "rsi"));
    printValue("    RDI", @field(frame, "rdi"));
    printValue("    R8 ", @field(frame, "r8"));
    printValue("    R9 ", @field(frame, "r9"));
    printValue("    R10", @field(frame, "r10"));
    printValue("    R11", @field(frame, "r11"));
    printValue("    R12", @field(frame, "r12"));
    printValue("    R13", @field(frame, "r13"));
    printValue("    R14", @field(frame, "r14"));
    printValue("    R15", @field(frame, "r15"));
}

// Print pointer with sanitization
pub fn printPointer(comptime name: []const u8, ptr: anytype) void {
    const addr = @intFromPtr(ptr);
    printValue(name, addr);
}

// Safe print for boot info addresses
pub fn printBootAddress(comptime name: []const u8, addr: u64) void {
    // Boot info addresses might contain kernel addresses
    if (addr != 0) {
        printValue(name, addr);
    } else {
        serial.println("{s}: null", .{name});
    }
}

// Print size value (always safe)
pub fn printSize(comptime name: []const u8, size: u64) void {
    if (size < 1024) {
        serial.print("{s}: {} bytes", .{ name, size });
    } else if (size < 1024 * 1024) {
        serial.print("{s}: {} KB", .{ name, size / 1024 });
    } else if (size < 1024 * 1024 * 1024) {
        serial.print("{s}: {} MB", .{ name, size / (1024 * 1024) });
    } else {
        serial.print("{s}: {} GB", .{ name, size / (1024 * 1024 * 1024) });
    }
}

// Print memory range with sanitization
pub fn printRange(comptime name: []const u8, start: u64, end: u64) void {
    serial.print("{s}: ", .{name});
    printHex("", start);
    serial.print(" - ", .{});
    printHex("", end);
    serial.print(" (", .{});
    printSize("", end - start);
    serial.print(")", .{});
    serial.println("", .{});
}

// Check if address should be sanitized
pub fn shouldSanitize(addr: u64) bool {
    const info = runtime_info.getRuntimeInfo();
    const kernel_base = info.kernel_virtual_base;
    const kernel_size = info.kernel_size;

    // Kernel addresses
    if (addr >= kernel_base and addr < kernel_base + kernel_size) return true;

    // Higher half kernel space
    if (addr >= 0xFFFF800000000000) return true;

    // Stack addresses (typically in higher half)
    if (addr >= 0xFFFF000000000000) return true;

    return false;
}
