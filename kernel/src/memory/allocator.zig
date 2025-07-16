// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Kernel allocator interface for heap allocation

const std = @import("std");
const heap = @import("heap.zig");

// Kernel allocator using heap allocation
pub const kernel_allocator = std.mem.Allocator{
    .ptr = undefined,
    .vtable = &kernel_allocator_vtable,
};

const kernel_allocator_vtable = std.mem.Allocator.VTable{
    .alloc = alloc,
    .resize = resize,
    .free = free,
    .remap = remap,
};

fn alloc(
    ctx: *anyopaque,
    len: usize,
    ptr_align: std.mem.Alignment,
    ret_addr: usize,
) ?[*]u8 {
    _ = ctx;
    _ = ret_addr;

    const alignment: usize = @as(usize, 1) << @intFromEnum(ptr_align);
    const size = std.mem.alignForward(usize, len, alignment);

    const ptr = heap.heapAlloc(size) catch return null;
    return @as([*]u8, @ptrCast(ptr));
}

fn resize(
    ctx: *anyopaque,
    buf: []u8,
    buf_align: std.mem.Alignment,
    new_len: usize,
    ret_addr: usize,
) bool {
    _ = ctx;
    _ = buf_align;
    _ = ret_addr;

    // Simple implementation: can't resize
    return new_len <= buf.len;
}

fn free(
    ctx: *anyopaque,
    buf: []u8,
    buf_align: std.mem.Alignment,
    ret_addr: usize,
) void {
    _ = ctx;
    _ = buf_align;
    _ = ret_addr;

    heap.heapFree(buf.ptr);
}

fn remap(
    ctx: *anyopaque,
    old_buf: []u8,
    old_buf_align: std.mem.Alignment,
    new_len: usize,
    ret_addr: usize,
) ?[*]u8 {
    // For now, we don't support remapping - allocate new and copy
    if (new_len == 0) {
        heap.heapFree(old_buf.ptr);
        return null;
    }

    const new_ptr = alloc(ctx, new_len, old_buf_align, ret_addr) orelse return null;
    const copy_len = @min(old_buf.len, new_len);
    @memcpy(new_ptr[0..copy_len], old_buf[0..copy_len]);
    heap.heapFree(old_buf.ptr);

    return new_ptr;
}
