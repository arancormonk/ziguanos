// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Test module for the improved stack canary implementation

const std = @import("std");
const serial = @import("../../drivers/serial.zig");
const stack_security = @import("../stack_security.zig");

// Test basic canary protection using new CanaryGuard
fn testBasicCanary() !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    serial.println("[CANARY TEST] Basic CanaryGuard test passed", .{});
}

// Test canary with some stack usage
fn testCanaryWithStackUsage() !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Use some stack space
    var buffer: [128]u8 = undefined;
    for (&buffer, 0..) |*byte, i| {
        byte.* = @as(u8, @truncate(i));
    }

    // Do some computation
    var sum: u64 = 0;
    for (buffer) |byte| {
        sum += byte;
    }

    if (sum != 8128) { // Sum of 0..127
        return error.UnexpectedSum;
    }

    serial.println("[CANARY TEST] CanaryGuard with stack usage test passed", .{});
}

// Test nested function calls with canaries
fn innerFunction() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    var local: u64 = 0xDEADBEEF;
    local += 1;
    if (local != 0xDEADBEF0) {
        @panic("Unexpected value in inner function");
    }
}

fn outerFunction() !void {
    var guard = stack_security.protect();
    defer guard.deinit();

    innerFunction();

    serial.println("[CANARY TEST] Nested CanaryGuard test passed", .{});
}

// Run all canary tests
pub fn runAllTests() void {
    // Test 1: Basic CanaryGuard
    testBasicCanary() catch |err| {
        serial.println("[CANARY TEST] Basic CanaryGuard test failed: {s}", .{@errorName(err)});
    };

    // Test 2: CanaryGuard with stack usage
    testCanaryWithStackUsage() catch |err| {
        serial.println("[CANARY TEST] Stack usage test failed: {s}", .{@errorName(err)});
    };

    // Test 3: Nested CanaryGuards
    outerFunction() catch |err| {
        serial.println("[CANARY TEST] Nested function test failed: {s}", .{@errorName(err)});
    };

    // Test 4: Shadow stack integrity
    testShadowStackIntegrity() catch |err| {
        serial.println("[CANARY TEST] Shadow stack integrity test failed: {s}", .{@errorName(err)});
    };
}

// Test shadow stack integrity
fn testShadowStackIntegrity() !void {
    serial.println("[CANARY TEST] Testing shadow stack integrity...", .{});

    // Verify shadow stack is clean initially
    if (!stack_security.verifyShadowStack()) {
        return error.InitialShadowStackCorrupted;
    }

    // Test multiple nested guards
    {
        var guard1 = stack_security.protect();
        defer guard1.deinit();

        {
            var guard2 = stack_security.protect();
            defer guard2.deinit();

            {
                var guard3 = stack_security.protect();
                defer guard3.deinit();

                // Verify stack integrity with nested guards
                if (!stack_security.verifyShadowStack()) {
                    return error.NestedShadowStackCorrupted;
                }
            }
        }
    }

    // Verify shadow stack is clean after all guards are released
    if (!stack_security.verifyShadowStack()) {
        return error.FinalShadowStackCorrupted;
    }

    serial.println("[CANARY TEST] Shadow stack integrity test passed", .{});
}

// Intentionally corrupt the shadow stack to test detection
// WARNING: This will panic the system!
pub fn testCanaryCorruption() void {
    serial.println("[CANARY TEST] Testing canary corruption detection...", .{});

    var guard = stack_security.protect();

    // Directly corrupt the canary value in the guard
    guard.local_canary = 0xBADBADBADBADBAD;

    // This should trigger a panic when deinit is called
    guard.deinit();

    serial.println("[CANARY TEST] This message should not appear!", .{});
}
