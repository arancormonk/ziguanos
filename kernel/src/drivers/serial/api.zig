// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Unified API for the layered serial driver
// This module provides a single interface that gracefully degrades based on initialization phase

const std = @import("std");
const hal = @import("hal/uart.zig");
const regs = @import("hal/registers.zig");
const core = @import("core/driver.zig");
const advanced_queue = @import("advanced/queue.zig");
const advanced_stats = @import("advanced/statistics.zig");
const advanced_formatter = @import("advanced/formatter.zig");
const security_sanitizer = @import("security/sanitizer.zig");
const security_policy = @import("security/policy.zig");
const timing_security = @import("security/timing.zig");

/// Initialization phases
pub const Phase = enum {
    uninitialized,
    early_boot,
    core_ready,
    advanced_ready,
    fully_initialized,
};

/// Unified serial API
pub const SerialAPI = struct {
    phase: Phase,
    core_driver: ?*core.Driver,
    advanced_queue: ?*advanced_queue.QueueManager,
    advanced_stats: ?*advanced_stats.Statistics,
    advanced_formatter: ?*advanced_formatter.Formatter,
    security_sanitizer: ?*security_sanitizer.AddressSanitizer,
    security_policy: ?*security_policy.SecurityPolicy,
    timing_security: ?*timing_security.TimingSecurity,

    pub fn init() SerialAPI {
        return SerialAPI{
            .phase = .uninitialized,
            .core_driver = null,
            .advanced_queue = null,
            .advanced_stats = null,
            .advanced_formatter = null,
            .security_sanitizer = null,
            .security_policy = null,
            .timing_security = null,
        };
    }

    /// Initialize early boot phase (minimal hardware access)
    pub fn initEarly(self: *SerialAPI) void {
        if (self.phase != .uninitialized) return;

        // Initialize hardware directly via HAL
        hal.init(regs.COM1_PORT, 115200);
        self.phase = .early_boot;
    }

    /// Initialize core phase (basic driver with buffering)
    pub fn initCore(self: *SerialAPI) void {
        if (self.phase != .early_boot) return;

        self.core_driver = core.getGlobal();
        self.core_driver.?.initCore();
        self.phase = .core_ready;
    }

    /// Initialize advanced phase (advanced features)
    pub fn initAdvanced(self: *SerialAPI, queue_mgr: *advanced_queue.QueueManager, stats: *advanced_stats.Statistics, formatter: *advanced_formatter.Formatter) void {
        if (self.phase != .core_ready) return;

        self.advanced_queue = queue_mgr;
        self.advanced_stats = stats;
        self.advanced_formatter = formatter;

        if (self.core_driver) |driver| {
            driver.initEnhanced();
        }

        self.phase = .advanced_ready;
    }

    /// Initialize security phase (full security features)
    pub fn initSecurity(self: *SerialAPI, sanitizer: *security_sanitizer.AddressSanitizer, policy: *security_policy.SecurityPolicy, timing: *timing_security.TimingSecurity) void {
        if (self.phase != .advanced_ready) return;

        self.security_sanitizer = sanitizer;
        self.security_policy = policy;
        self.timing_security = timing;

        if (self.core_driver) |driver| {
            driver.initFull();
        }

        self.phase = .fully_initialized;
    }

    /// Print with automatic fallback based on current phase
    pub fn print(self: *SerialAPI, comptime fmt: []const u8, args: anytype) void {
        switch (self.phase) {
            .uninitialized => return,
            .early_boot => self.earlyPrint(fmt, args),
            .core_ready => self.corePrint(fmt, args),
            .advanced_ready => self.advancedPrint(fmt, args),
            .fully_initialized => self.securityPrint(fmt, args),
        }
    }

    /// Print with newline
    pub fn println(self: *SerialAPI, comptime fmt: []const u8, args: anytype) void {
        self.print(fmt ++ "\r\n", args);
    }

    /// Print with security level checking
    pub fn printWithLevel(self: *SerialAPI, level: security_policy.MessageLevel, comptime fmt: []const u8, args: anytype) void {
        // Check security policy if available
        if (self.security_policy) |policy| {
            if (!policy.isOutputAllowed(level)) return;
        }

        self.print(fmt, args);
    }

    /// Direct write functions for emergency use
    pub fn directWrite(self: *SerialAPI, byte: u8) void {
        switch (self.phase) {
            .uninitialized => return,
            .early_boot => hal.writeByte(regs.COM1_PORT, byte),
            else => {
                if (self.core_driver) |driver| {
                    driver.directWrite(byte);
                } else {
                    hal.writeByte(regs.COM1_PORT, byte);
                }
            },
        }
    }

    pub fn directWriteString(self: *SerialAPI, str: []const u8) void {
        switch (self.phase) {
            .uninitialized => return,
            .early_boot => hal.writeString(regs.COM1_PORT, str),
            else => {
                if (self.core_driver) |driver| {
                    driver.directWriteString(str);
                } else {
                    hal.writeString(regs.COM1_PORT, str);
                }
            },
        }
    }

    /// Flush any buffered output
    pub fn flush(self: *SerialAPI) void {
        switch (self.phase) {
            .uninitialized, .early_boot => return, // No buffering
            .fully_initialized => {
                // Flush timing security buffers first
                if (self.timing_security) |timing| {
                    const TimedWriter = struct {
                        api: *SerialAPI,

                        pub fn writeFunction(writer_self: @This(), data: []const u8) !void {
                            if (writer_self.api.core_driver) |driver| {
                                driver.directWriteString(data);
                            }
                        }
                    };

                    const timed_writer = TimedWriter{ .api = self };
                    timing.flushBuffered(TimedWriter.writeFunction, timed_writer) catch {};
                }

                // Then flush regular buffers
                if (self.core_driver) |driver| {
                    driver.flush();
                }
            },
            else => {
                if (self.core_driver) |driver| {
                    driver.flush();
                }
            },
        }
    }

    /// Format and print an address (with sanitization if available)
    pub fn printAddress(self: *SerialAPI, name: []const u8, addr: u64) void {
        if (self.security_sanitizer) |sanitizer| {
            var buffer: [128]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buffer);
            const writer = stream.writer();

            writer.print("{s}: ", .{name}) catch return;
            sanitizer.formatAddress(writer, addr) catch return;
            writer.writeAll("\r\n") catch return;

            self.directWriteString(stream.getWritten());
        } else {
            self.print("{s}: 0x{x:0>16}\r\n", .{ name, addr });
        }
    }

    /// Print statistics if available
    pub fn printStats(self: *SerialAPI) void {
        if (self.advanced_stats) |stats| {
            var buffer: [2048]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buffer);
            const writer = stream.writer();

            stats.formatStats(writer) catch return;
            self.directWriteString(stream.getWritten());
        } else {
            self.println("Statistics not available", .{});
        }
    }

    /// Self-test function
    pub fn selfTest(self: *SerialAPI) bool {
        switch (self.phase) {
            .uninitialized => return false,
            .early_boot => return hal.selfTest(regs.COM1_PORT),
            else => {
                if (self.core_driver) |driver| {
                    return driver.selfTest();
                } else {
                    return hal.selfTest(regs.COM1_PORT);
                }
            },
        }
    }

    // Private implementation functions

    fn earlyPrint(self: *SerialAPI, comptime fmt: []const u8, args: anytype) void {
        _ = self;
        var buffer: [1024]u8 = undefined;
        const output = std.fmt.bufPrint(&buffer, fmt, args) catch {
            hal.writeString(regs.COM1_PORT, "[FMT:ERR]\r\n");
            return;
        };
        hal.writeString(regs.COM1_PORT, output);
    }

    fn corePrint(self: *SerialAPI, comptime fmt: []const u8, args: anytype) void {
        if (self.core_driver) |driver| {
            driver.print(fmt, args);
        } else {
            self.earlyPrint(fmt, args);
        }
    }

    fn advancedPrint(self: *SerialAPI, comptime fmt: []const u8, args: anytype) void {
        if (self.advanced_formatter) |formatter| {
            formatter.reset();
            formatter.print(fmt, args) catch {
                self.corePrint("[FMT:ERR]", .{});
                return;
            };

            const output = formatter.getWritten();
            if (self.advanced_queue) |queue| {
                // Try to queue the output
                const cpu_queue = queue.getCurrentQueue();
                const written = cpu_queue.enqueue(output) catch 0;

                if (written < output.len) {
                    // Queue full, try direct output
                    self.corePrint("{s}", .{output[written..]});
                }
            } else {
                self.corePrint("{s}", .{output});
            }
        } else {
            self.corePrint(fmt, args);
        }
    }

    fn securityPrint(self: *SerialAPI, comptime fmt: []const u8, args: anytype) void {
        // Check timing security first
        if (self.timing_security) |timing| {
            if (!timing.isOutputAllowed()) {
                return; // Serial output disabled by timing security
            }
        }

        // Use advanced print but with address sanitization
        if (self.security_sanitizer) |sanitizer| {
            if (self.advanced_formatter) |formatter| {
                formatter.reset();
                formatter.formatSanitized(fmt, args) catch {
                    self.advancedPrint("[FMT:ERR]", .{});
                    return;
                };

                const output = formatter.getWritten();

                // Apply string sanitization
                var sanitized_buffer: [4096]u8 = undefined;
                var sanitized_stream = std.io.fixedBufferStream(&sanitized_buffer);
                const sanitized_writer = sanitized_stream.writer();

                sanitizer.sanitizeString(output, sanitized_writer) catch {
                    self.advancedPrint("{s}", .{output});
                    return;
                };

                const final_output = sanitized_stream.getWritten();

                // Apply timing security
                if (self.timing_security) |timing| {
                    const TimedWriter = struct {
                        api: *SerialAPI,

                        pub fn writeFunction(writer_self: @This(), data: []const u8) !void {
                            if (writer_self.api.advanced_queue) |queue| {
                                const cpu_queue = queue.getCurrentQueue();
                                const written = cpu_queue.enqueue(data) catch 0;

                                if (written < data.len) {
                                    writer_self.api.corePrint("{s}", .{data[written..]});
                                }
                            } else {
                                writer_self.api.corePrint("{s}", .{data});
                            }
                        }
                    };

                    const timed_writer = TimedWriter{ .api = self };
                    timing.secureWrite(final_output, TimedWriter.writeFunction, timed_writer) catch {
                        self.advancedPrint("{s}", .{final_output});
                        return;
                    };
                } else {
                    // Fallback to regular output
                    if (self.advanced_queue) |queue| {
                        const cpu_queue = queue.getCurrentQueue();
                        const written = cpu_queue.enqueue(final_output) catch 0;

                        if (written < final_output.len) {
                            self.corePrint("{s}", .{final_output[written..]});
                        }
                    } else {
                        self.corePrint("{s}", .{final_output});
                    }
                }

                // Update statistics
                if (self.advanced_stats) |stats| {
                    stats.incrementMessagesSent();
                    stats.incrementBytesWritten(final_output.len);
                }
            } else {
                self.advancedPrint(fmt, args);
            }
        } else {
            self.advancedPrint(fmt, args);
        }
    }
};

/// Global API instance
var global_api: SerialAPI = undefined;
var api_initialized: bool = false;

/// Get the global API instance
pub fn getGlobal() *SerialAPI {
    if (!api_initialized) {
        global_api = SerialAPI.init();
        api_initialized = true;
    }
    return &global_api;
}
