// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// Timing security module for serial output
// This module implements rate limiting and fixed-interval buffering to prevent
// timing side-channel attacks through serial output analysis

const std = @import("std");
const timer = @import("../../../x86_64/timer.zig");

// Timing security configuration
pub const TimingConfig = struct {
    // Enable rate limiting
    enable_rate_limiting: bool = true,

    // Maximum bytes per second for rate limiting
    max_bytes_per_second: u32 = 1024,

    // Enable fixed interval buffering
    enable_fixed_interval: bool = true,

    // Fixed interval in microseconds (default: 10ms)
    fixed_interval_us: u64 = 10_000,

    // Maximum burst size before rate limiting kicks in
    burst_size: u32 = 256,

    // Disable all serial output (for production)
    disable_serial: bool = false,

    // Add artificial delays to normalize timing
    enable_timing_normalization: bool = true,

    // Base delay in microseconds for timing normalization
    base_delay_us: u64 = 100,

    pub fn development() TimingConfig {
        return TimingConfig{
            .enable_rate_limiting = false,
            .enable_fixed_interval = false,
            .disable_serial = false,
            .enable_timing_normalization = false,
            .max_bytes_per_second = 10240, // Higher rate for development
            .fixed_interval_us = 1000, // Faster intervals for development
        };
    }

    pub fn production() TimingConfig {
        return TimingConfig{
            .enable_rate_limiting = true,
            .enable_fixed_interval = true,
            .disable_serial = true,
            .enable_timing_normalization = true,
            .max_bytes_per_second = 512, // Lower rate for production
            .fixed_interval_us = 50_000, // Slower intervals for production
        };
    }

    pub fn strict() TimingConfig {
        return TimingConfig{
            .enable_rate_limiting = true,
            .enable_fixed_interval = true,
            .disable_serial = true,
            .enable_timing_normalization = true,
            .max_bytes_per_second = 0, // No output allowed
            .fixed_interval_us = 100_000, // Very slow intervals
        };
    }
};

// Rate limiter using token bucket algorithm
pub const RateLimiter = struct {
    config: TimingConfig,
    tokens: u32,
    last_refill_time: u64,
    bytes_in_current_burst: u32,

    pub fn init(config: TimingConfig) RateLimiter {
        return RateLimiter{
            .config = config,
            .tokens = config.burst_size,
            .last_refill_time = timer.getUptime() * 1000, // Convert ms to us
            .bytes_in_current_burst = 0,
        };
    }

    pub fn canSend(self: *RateLimiter, bytes: u32) bool {
        if (self.config.disable_serial) return false;
        if (!self.config.enable_rate_limiting) return true;
        if (self.config.max_bytes_per_second == 0) return false;

        self.refillTokens();

        // Check if we have enough tokens
        if (self.tokens >= bytes) {
            self.tokens -= bytes;
            self.bytes_in_current_burst += bytes;
            return true;
        }

        return false;
    }

    pub fn waitForTokens(self: *RateLimiter, bytes: u32) void {
        if (self.config.disable_serial) return;
        if (!self.config.enable_rate_limiting) return;
        if (self.config.max_bytes_per_second == 0) return;

        // Calculate how long to wait for tokens
        const tokens_needed = if (bytes > self.tokens) bytes - self.tokens else 0;
        if (tokens_needed > 0) {
            const wait_time_us = (tokens_needed * 1_000_000) / self.config.max_bytes_per_second;
            timer.delayMicroseconds(wait_time_us);
            self.refillTokens();
        }
    }

    fn refillTokens(self: *RateLimiter) void {
        const now = timer.getUptime() * 1000; // Convert ms to us
        const time_passed_us = if (now > self.last_refill_time) now - self.last_refill_time else 0;

        if (time_passed_us > 0) {
            const new_tokens = @as(u32, @intCast((time_passed_us * self.config.max_bytes_per_second) / 1_000_000));
            self.tokens = @min(self.tokens + new_tokens, self.config.burst_size);
            self.last_refill_time = now;
        }
    }

    pub fn reset(self: *RateLimiter) void {
        self.tokens = self.config.burst_size;
        self.last_refill_time = timer.getUptime() * 1000; // Convert ms to us
        self.bytes_in_current_burst = 0;
    }
};

// Fixed interval buffer for timing normalization
pub const FixedIntervalBuffer = struct {
    const BUFFER_SIZE = 4096;

    config: TimingConfig,
    buffer: [BUFFER_SIZE]u8,
    buffer_pos: usize,
    last_flush_time: u64,

    pub fn init(config: TimingConfig) FixedIntervalBuffer {
        return FixedIntervalBuffer{
            .config = config,
            .buffer = [_]u8{0} ** BUFFER_SIZE,
            .buffer_pos = 0,
            .last_flush_time = timer.getUptime() * 1000, // Convert ms to us
        };
    }

    pub fn write(self: *FixedIntervalBuffer, data: []const u8) usize {
        if (self.config.disable_serial) return 0;
        if (!self.config.enable_fixed_interval) return 0;

        // Check if it's time to flush
        const now = timer.getUptime() * 1000; // Convert ms to us
        const time_since_flush = if (now > self.last_flush_time) now - self.last_flush_time else 0;

        if (time_since_flush >= self.config.fixed_interval_us) {
            return 0; // Signal that buffer should be flushed
        }

        // Try to buffer the data
        var written: usize = 0;
        for (data) |byte| {
            if (self.buffer_pos >= BUFFER_SIZE) break;
            self.buffer[self.buffer_pos] = byte;
            self.buffer_pos += 1;
            written += 1;
        }

        return written;
    }

    pub fn shouldFlush(self: *const FixedIntervalBuffer) bool {
        if (self.config.disable_serial) return false;
        if (!self.config.enable_fixed_interval) return false;

        const now = timer.getUptime() * 1000; // Convert ms to us
        const time_since_flush = if (now > self.last_flush_time) now - self.last_flush_time else 0;

        return time_since_flush >= self.config.fixed_interval_us;
    }

    pub fn flush(self: *FixedIntervalBuffer) []const u8 {
        if (self.buffer_pos == 0) return &[_]u8{};

        const result = self.buffer[0..self.buffer_pos];
        self.buffer_pos = 0;
        self.last_flush_time = timer.getUptime() * 1000; // Convert ms to us

        return result;
    }

    pub fn isEmpty(self: *const FixedIntervalBuffer) bool {
        return self.buffer_pos == 0;
    }

    pub fn isFull(self: *const FixedIntervalBuffer) bool {
        return self.buffer_pos >= BUFFER_SIZE;
    }

    pub fn clear(self: *FixedIntervalBuffer) void {
        self.buffer_pos = 0;
        self.last_flush_time = timer.getUptime() * 1000; // Convert ms to us
    }
};

// Timing normalizer to add consistent delays
pub const TimingNormalizer = struct {
    config: TimingConfig,
    last_operation_time: u64,

    pub fn init(config: TimingConfig) TimingNormalizer {
        return TimingNormalizer{
            .config = config,
            .last_operation_time = timer.getUptime() * 1000, // Convert ms to us
        };
    }

    pub fn normalizeWrite(self: *TimingNormalizer, bytes_written: usize) void {
        if (self.config.disable_serial) return;
        if (!self.config.enable_timing_normalization) return;

        const now = timer.getUptime() * 1000; // Convert ms to us
        const time_since_last = if (now > self.last_operation_time) now - self.last_operation_time else 0;

        // Calculate target delay based on data size
        const target_delay_us = self.config.base_delay_us + (bytes_written * 10);

        if (time_since_last < target_delay_us) {
            const additional_delay = target_delay_us - time_since_last;
            timer.delayMicroseconds(additional_delay);
        }

        self.last_operation_time = timer.getUptime() * 1000; // Convert ms to us
    }

    pub fn normalizeRead(self: *TimingNormalizer) void {
        if (self.config.disable_serial) return;
        if (!self.config.enable_timing_normalization) return;

        // Add consistent delay for read operations
        timer.delayMicroseconds(self.config.base_delay_us);
        self.last_operation_time = timer.getUptime() * 1000; // Convert ms to us
    }
};

// Main timing security manager
pub const TimingSecurity = struct {
    config: TimingConfig,
    rate_limiter: RateLimiter,
    interval_buffer: FixedIntervalBuffer,
    normalizer: TimingNormalizer,

    pub fn init(config: TimingConfig) TimingSecurity {
        return TimingSecurity{
            .config = config,
            .rate_limiter = RateLimiter.init(config),
            .interval_buffer = FixedIntervalBuffer.init(config),
            .normalizer = TimingNormalizer.init(config),
        };
    }

    pub fn secureWrite(self: *TimingSecurity, data: []const u8, writerFunc: anytype, context: anytype) !void {
        if (self.config.disable_serial) return;

        // Apply rate limiting
        if (self.config.enable_rate_limiting) {
            if (!self.rate_limiter.canSend(@intCast(data.len))) {
                self.rate_limiter.waitForTokens(@intCast(data.len));
            }
        }

        // Apply fixed interval buffering
        if (self.config.enable_fixed_interval) {
            const buffered = self.interval_buffer.write(data);
            if (buffered < data.len) {
                // Buffer full or time to flush
                if (self.interval_buffer.shouldFlush()) {
                    const buffered_data = self.interval_buffer.flush();
                    if (buffered_data.len > 0) {
                        try writerFunc(context, buffered_data);
                        self.normalizer.normalizeWrite(buffered_data.len);
                    }
                }

                // Write remaining data directly
                if (buffered < data.len) {
                    try writerFunc(context, data[buffered..]);
                    self.normalizer.normalizeWrite(data.len - buffered);
                }
            }
        } else {
            // Direct write with normalization
            try writerFunc(context, data);
            self.normalizer.normalizeWrite(data.len);
        }
    }

    pub fn flushBuffered(self: *TimingSecurity, writerFunc: anytype, context: anytype) !void {
        if (self.config.disable_serial) return;

        if (self.config.enable_fixed_interval) {
            const buffered_data = self.interval_buffer.flush();
            if (buffered_data.len > 0) {
                try writerFunc(context, buffered_data);
                self.normalizer.normalizeWrite(buffered_data.len);
            }
        }
    }

    pub fn shouldFlush(self: *const TimingSecurity) bool {
        if (self.config.disable_serial) return false;

        if (self.config.enable_fixed_interval) {
            return self.interval_buffer.shouldFlush();
        }

        return false;
    }

    pub fn isOutputAllowed(self: *const TimingSecurity) bool {
        return !self.config.disable_serial;
    }

    pub fn updateConfig(self: *TimingSecurity, new_config: TimingConfig) void {
        self.config = new_config;
        self.rate_limiter = RateLimiter.init(new_config);
        self.interval_buffer = FixedIntervalBuffer.init(new_config);
        self.normalizer = TimingNormalizer.init(new_config);
    }
};
