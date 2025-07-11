// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const apic = @import("apic.zig");
const x2apic = @import("x2apic.zig");
const apic_unified = @import("apic_unified.zig");
const cpuid = @import("cpuid.zig");
const interrupts = @import("interrupts.zig");
const serial = @import("../drivers/serial.zig");
const stack_security = @import("stack_security.zig");

// Timer frequencies
const PIT_FREQUENCY: u32 = 1193182; // Hz
const TIMER_FREQUENCY: u32 = 100; // Desired timer interrupt frequency (Hz)

// Compile-time validation of timer frequency
comptime {
    if (TIMER_FREQUENCY > MAX_TIMER_RATE or TIMER_FREQUENCY < MIN_TIMER_RATE) {
        @compileError("TIMER_FREQUENCY must be between 1 Hz and 10 KHz for security");
    }
}

// PIT I/O ports
const PIT_CHANNEL0: u16 = 0x40;
const PIT_CHANNEL2: u16 = 0x42;
const PIT_COMMAND: u16 = 0x43;
const PIT_CONTROL: u16 = 0x61;

// TSC calibration
var tsc_frequency: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var timer_ticks: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var apic_timer_divisor: u32 = 16;

// Timer source - use u8 for atomic compatibility
const TIMER_SOURCE_PIT: u8 = 0;
const TIMER_SOURCE_APIC: u8 = 1;
var timer_source: std.atomic.Value(u8) = std.atomic.Value(u8).init(TIMER_SOURCE_PIT);

// Intel x86 security: Timer interrupt rate limiting to prevent DoS
const MAX_TIMER_RATE: u32 = 10000; // Maximum 10KHz to prevent CPU starvation
const MIN_TIMER_RATE: u32 = 1; // Minimum 1Hz to ensure system responsiveness

// Timer security statistics
var timer_overflows: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);
var timer_calibration_failures: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

// Read Time Stamp Counter
pub fn readTSC() u64 {
    // Add memory barrier before reading TSC to ensure consistent ordering
    asm volatile ("mfence" ::: "memory");

    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdtsc"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
    );
    return (@as(u64, high) << 32) | low;
}

// Timer interrupt handler
fn timerInterruptHandler(frame: *interrupts.InterruptFrame) void {
    _ = frame; // Not used

    // Use atomic increment for multicore safety
    _ = timer_ticks.fetchAdd(1, .monotonic);

    // Flush serial queue periodically (every 2 ticks = 50 Hz)
    // This ensures output is flushed regularly even if main code is blocked
    const current_ticks = timer_ticks.load(.monotonic);
    if (current_ticks % 2 == 0) {
        // Flush up to 128 bytes per timer tick to avoid spending too much time in interrupt
        _ = serial.flushPartial(128);
    }

    // Check stack depth periodically (every 10 ticks = 10 Hz)
    if (current_ticks % 10 == 0) {
        stack_security.checkStackDepth();
    }

    // EOI is now sent by the general interrupt handler in interrupts.zig
    // Don't send it here to avoid double EOI
}

// Initialize timer subsystem
pub fn init() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Verify we're running at ring 0
    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );
    const cpl: u2 = @truncate(cs & 0x3);
    if (cpl != 0) {
        serial.println("[TIMER] ERROR: Timer init requires ring 0, current CPL={}", .{cpl});
        return;
    }

    serial.println("[TIMER] Initializing timer subsystem...", .{});

    // First calibrate TSC if available
    if (cpuid.getFeatures().rdtscp or cpuid.getFeatures().rdrand) {
        calibrateTSC();
        const freq = tsc_frequency.load(.acquire);
        serial.println("[TIMER] TSC calibrated to {} MHz", .{freq / 1_000_000});
    }

    // Try to use APIC timer if available
    if (x2apic.isEnabled()) {
        initX2APICTimer();
        timer_source.store(TIMER_SOURCE_APIC, .release);
        serial.println("[TIMER] Using x2APIC timer", .{});
    } else if (apic.isAvailable()) {
        initAPICTimer();
        timer_source.store(TIMER_SOURCE_APIC, .release);
        serial.println("[TIMER] Using APIC timer", .{});
    } else {
        initPIT();
        timer_source.store(TIMER_SOURCE_PIT, .release);
        serial.println("[TIMER] Using PIT (8254) timer", .{});
    }

    serial.println("[TIMER] Timer frequency: {} Hz", .{TIMER_FREQUENCY});
}

// Calibrate TSC using PIT
fn calibrateTSC() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Verify we're running at ring 0
    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );
    const cpl: u2 = @truncate(cs & 0x3);
    if (cpl != 0) {
        serial.println("[TIMER] ERROR: TSC calibration requires ring 0, current CPL={}", .{cpl});
        return;
    }

    const calibration_ms: u32 = 50; // Use longer calibration period for accuracy
    const pit_ticks = (PIT_FREQUENCY * calibration_ms) / 1000;

    // Disable interrupts during calibration
    const flags = asm volatile (
        \\pushfq
        \\pop %[result]
        \\cli
        : [result] "=r" (-> u64),
    );
    defer asm volatile (
        \\push %[flags]
        \\popfq
        :
        : [flags] "r" (flags),
    );

    // Configure PIT channel 2 for one-shot mode
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0xB0)), // Channel 2, LSB/MSB, mode 0
          [port] "N{dx}" (PIT_COMMAND),
    );

    // Set count value
    const count = @as(u16, @intCast(pit_ticks & 0xFFFF));
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, @truncate(count & 0xFF))),
          [port] "N{dx}" (PIT_CHANNEL2),
    );
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, @truncate(count >> 8))),
          [port] "N{dx}" (PIT_CHANNEL2),
    );

    // Enable gate for channel 2 and start timer
    var port61 = asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (PIT_CONTROL),
    );
    port61 = (port61 & 0xFC) | 0x01; // Enable gate, disable speaker
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (port61),
          [port] "N{dx}" (PIT_CONTROL),
    );

    // Start TSC measurement
    const start_tsc = readTSC();

    // Wait for PIT to count down
    while (true) {
        port61 = asm volatile ("inb %[port], %[result]"
            : [result] "={al}" (-> u8),
            : [port] "N{dx}" (PIT_CONTROL),
        );
        if ((port61 & 0x20) != 0) break; // Check OUT2 status bit
    }

    // End TSC measurement
    const end_tsc = readTSC();
    const tsc_ticks = end_tsc - start_tsc;

    // Calculate TSC frequency with overflow protection
    // Convert to Hz: ticks_per_ms = tsc_ticks / calibration_ms, then * 1000 for Hz
    // To avoid overflow, calculate as: (tsc_ticks / calibration_ms) * 1000
    const ticks_per_ms = tsc_ticks / calibration_ms;
    const calculated_freq = std.math.mul(u64, ticks_per_ms, 1000) catch {
        // On overflow, indicate TSC is too fast to measure accurately
        serial.println("[TIMER] WARNING: TSC frequency overflow during calibration", .{});
        _ = timer_calibration_failures.fetchAdd(1, .monotonic);
        return;
    };

    // Intel x86 security guideline: Validate frequency is reasonable
    // Modern CPUs typically run between 1-5 GHz
    const min_freq: u64 = 100_000_000; // 100 MHz minimum
    const max_freq: u64 = 10_000_000_000; // 10 GHz maximum

    if (calculated_freq < min_freq or calculated_freq > max_freq) {
        serial.println("[TIMER] WARNING: TSC frequency {} Hz outside reasonable range", .{calculated_freq});
        _ = timer_calibration_failures.fetchAdd(1, .monotonic);
        return;
    }

    tsc_frequency.store(calculated_freq, .release);
}

// Initialize APIC timer
fn initAPICTimer() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Verify we're running at ring 0
    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );
    const cpl: u2 = @truncate(cs & 0x3);
    if (cpl != 0) {
        serial.println("[TIMER] ERROR: APIC timer init requires ring 0, current CPL={}", .{cpl});
        return;
    }

    // Install interrupt handler for APIC timer (vector 32)
    interrupts.set_handler(32, timerInterruptHandler);

    // Ensure timer is stopped before calibration
    apic.stopTimer();

    // Calibrate the APIC timer first to get the correct initial count
    const initial_count = calibrateAPICTimer();

    // Configure APIC timer for periodic mode with the calibrated count
    apic.initTimer(TIMER_FREQUENCY);
    apic.setTimerInitialCount(initial_count);
}

// Initialize x2APIC timer
fn initX2APICTimer() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Verify we're running at ring 0
    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );
    const cpl: u2 = @truncate(cs & 0x3);
    if (cpl != 0) {
        serial.println("[TIMER] ERROR: x2APIC timer init requires ring 0, current CPL={}", .{cpl});
        return;
    }

    serial.println("[TIMER] Initializing x2APIC timer...", .{});

    // Install interrupt handler for timer (vector 32)
    interrupts.set_handler(32, timerInterruptHandler);

    // Calibrate the x2APIC timer
    const initial_count = calibrateX2APICTimer();

    // Configure x2APIC timer for periodic mode
    x2apic.initTimer(32, x2apic.TimerMode.Periodic, x2apic.TimerDivide.Div16);
    x2apic.setTimerInitialCount(initial_count);

    serial.println("[TIMER] x2APIC timer initialized with count: {}", .{initial_count});
}

// Calibrate APIC timer against PIT
fn calibrateAPICTimer() u32 {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Verify we're running at ring 0
    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );
    const cpl: u2 = @truncate(cs & 0x3);
    if (cpl != 0) {
        serial.println("[TIMER] ERROR: APIC calibration requires ring 0, current CPL={}", .{cpl});
        return 0;
    }

    // Use a short calibration period
    const calibration_ms: u32 = 10;
    const pit_ticks = (PIT_FREQUENCY * calibration_ms) / 1000;
    serial.println("[TIMER] PIT calibration: {} ms, {} PIT ticks", .{ calibration_ms, pit_ticks });

    // Set APIC timer to maximum count with divisor but MASKED during calibration
    apic_unified.setTimerDivider(apic_timer_divisor);

    // Debug: Check what divisor was actually set
    const APIC_TIMER_DIVIDE = 0x3E0;
    const actual_divisor = apic_unified.readRegister(APIC_TIMER_DIVIDE);
    serial.println("[TIMER] Set divisor {}, actual register value: 0x{x}", .{ apic_timer_divisor, actual_divisor });

    // Temporarily mask the timer during calibration to prevent interrupts
    const apic_timer_masked = 32 | (1 << 16); // Vector 32 + masked bit
    const APIC_TIMER_LVT = 0x320; // APIC Timer Local Vector Table offset
    apic_unified.writeRegister(APIC_TIMER_LVT, apic_timer_masked);
    apic_unified.setTimerInitialCount(0xFFFFFFFF);

    // Configure PIT for calibration
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0xB0)),
          [port] "N{dx}" (PIT_COMMAND),
    );

    const count = @as(u16, @intCast(pit_ticks & 0xFFFF));
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, @truncate(count & 0xFF))),
          [port] "N{dx}" (PIT_CHANNEL2),
    );
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, @truncate(count >> 8))),
          [port] "N{dx}" (PIT_CHANNEL2),
    );

    // Start PIT
    var port61 = asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (PIT_CONTROL),
    );
    port61 = (port61 & 0xFC) | 0x01;
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (port61),
          [port] "N{dx}" (PIT_CONTROL),
    );

    // Record APIC timer start
    const apic_start = apic.getTimerCurrentCount();

    // Wait for PIT
    var pit_loops: u32 = 0;
    while (true) {
        port61 = asm volatile ("inb %[port], %[result]"
            : [result] "={al}" (-> u8),
            : [port] "N{dx}" (PIT_CONTROL),
        );
        pit_loops += 1;
        if ((port61 & 0x20) != 0) break;

        // Safety check - prevent infinite loop
        if (pit_loops > 10000000) {
            serial.println("[TIMER] ERROR: PIT calibration timeout!", .{});
            break;
        }
    }
    serial.println("[TIMER] PIT calibration loops: {}", .{pit_loops});

    // Record APIC timer end
    const apic_end = apic.getTimerCurrentCount();

    // Calculate how many APIC ticks occurred
    const apic_ticks = apic_start - apic_end;

    serial.println("[TIMER] Calibration: start={}, end={}, ticks={}", .{ apic_start, apic_end, apic_ticks });

    // Calculate APIC timer frequency with overflow protection
    // Convert to Hz: ticks_per_ms = apic_ticks / calibration_ms, then * 1000 for Hz
    // To avoid overflow, calculate as: (apic_ticks / calibration_ms) * 1000
    const ticks_per_ms = apic_ticks / calibration_ms;
    const apic_freq = std.math.mul(u64, ticks_per_ms, 1000) catch {
        serial.println("[TIMER] ERROR: APIC frequency overflow during calibration", .{});
        return 0;
    };

    // Intel x86 security guideline: Validate APIC frequency is reasonable
    const min_apic_freq: u64 = 1_000_000; // 1 MHz minimum
    const max_apic_freq: u64 = 1_000_000_000; // 1 GHz maximum

    if (apic_freq < min_apic_freq or apic_freq > max_apic_freq) {
        serial.println("[TIMER] ERROR: APIC frequency {} Hz outside reasonable range", .{apic_freq});
        return 0;
    }

    serial.println("[TIMER] APIC frequency: {} Hz", .{apic_freq});

    // Store the calculated initial count for desired frequency
    const initial_count = apic_freq / TIMER_FREQUENCY;

    // Validate initial count is within 32-bit range
    if (initial_count > std.math.maxInt(u32)) {
        serial.println("[TIMER] ERROR: APIC initial count {} exceeds 32-bit limit", .{initial_count});
        return std.math.maxInt(u32);
    }

    // Stop the timer after calibration
    apic.setTimerInitialCount(0);

    serial.println("[TIMER] APIC timer calibrated: {} ticks for {}Hz", .{ initial_count, TIMER_FREQUENCY });

    // Return the calculated initial count
    return @intCast(initial_count);
}

// Calibrate x2APIC timer against PIT
fn calibrateX2APICTimer() u32 {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Verify we're running at ring 0
    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );
    const cpl: u2 = @truncate(cs & 0x3);
    if (cpl != 0) {
        serial.println("[TIMER] ERROR: x2APIC calibration requires ring 0, current CPL={}", .{cpl});
        return 0;
    }

    const calibration_ms: u32 = 10;
    const pit_ticks = (PIT_FREQUENCY * calibration_ms) / 1000;
    serial.println("[TIMER] x2APIC calibration: {} ms, {} PIT ticks", .{ calibration_ms, pit_ticks });

    // Set x2APIC timer to maximum count with divisor
    x2apic.initTimer(32, x2apic.TimerMode.OneShot, x2apic.TimerDivide.Div16);
    x2apic.setTimerInitialCount(0xFFFFFFFF);

    // Configure PIT for calibration
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0xB0)),
          [port] "N{dx}" (PIT_COMMAND),
    );

    const count = @as(u16, @intCast(pit_ticks & 0xFFFF));
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, @truncate(count & 0xFF))),
          [port] "N{dx}" (PIT_CHANNEL2),
    );
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, @truncate(count >> 8))),
          [port] "N{dx}" (PIT_CHANNEL2),
    );

    // Start PIT
    var port61 = asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "N{dx}" (PIT_CONTROL),
    );
    port61 = (port61 & 0xFC) | 0x01;
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (port61),
          [port] "N{dx}" (PIT_CONTROL),
    );

    // Record x2APIC timer start
    const apic_start = x2apic.getTimerCurrentCount();

    // Wait for PIT
    var pit_loops: u32 = 0;
    while (true) {
        port61 = asm volatile ("inb %[port], %[result]"
            : [result] "={al}" (-> u8),
            : [port] "N{dx}" (PIT_CONTROL),
        );
        pit_loops += 1;
        if ((port61 & 0x20) != 0) break;

        // Safety check
        if (pit_loops > 10000000) {
            serial.println("[TIMER] ERROR: PIT calibration timeout!", .{});
            break;
        }
    }
    serial.println("[TIMER] PIT calibration loops: {}", .{pit_loops});

    // Record x2APIC timer end
    const apic_end = x2apic.getTimerCurrentCount();

    // Calculate ticks
    const apic_ticks = apic_start - apic_end;
    serial.println("[TIMER] x2APIC calibration: start={}, end={}, ticks={}", .{ apic_start, apic_end, apic_ticks });

    // Calculate frequency
    const ticks_per_ms = apic_ticks / calibration_ms;
    const apic_freq = std.math.mul(u64, ticks_per_ms, 1000) catch {
        serial.println("[TIMER] ERROR: x2APIC frequency overflow during calibration", .{});
        return 0;
    };

    // Validate frequency
    const min_apic_freq: u64 = 1_000_000; // 1 MHz minimum
    const max_apic_freq: u64 = 1_000_000_000; // 1 GHz maximum

    if (apic_freq < min_apic_freq or apic_freq > max_apic_freq) {
        serial.println("[TIMER] ERROR: x2APIC frequency {} Hz outside reasonable range", .{apic_freq});
        return 0;
    }

    serial.println("[TIMER] x2APIC frequency: {} Hz", .{apic_freq});

    // Calculate initial count
    const initial_count = apic_freq / TIMER_FREQUENCY;

    // Validate initial count
    if (initial_count > std.math.maxInt(u32)) {
        serial.println("[TIMER] ERROR: x2APIC initial count {} exceeds 32-bit limit", .{initial_count});
        return std.math.maxInt(u32);
    }

    // Stop the timer after calibration
    x2apic.setTimerInitialCount(0);

    serial.println("[TIMER] x2APIC timer calibrated: {} ticks for {}Hz", .{ initial_count, TIMER_FREQUENCY });

    return @intCast(initial_count);
}

// Initialize legacy PIT as fallback
fn initPIT() void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Verify we're running at ring 0
    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );
    const cpl: u2 = @truncate(cs & 0x3);
    if (cpl != 0) {
        serial.println("[TIMER] ERROR: PIT init requires ring 0, current CPL={}", .{cpl});
        return;
    }

    const divisor = PIT_FREQUENCY / TIMER_FREQUENCY;

    // Install interrupt handler for PIT (IRQ0 = vector 32)
    interrupts.set_handler(32, timerInterruptHandler);

    // Channel 0, LSB/MSB, mode 3 (square wave generator)
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x36)),
          [port] "N{dx}" (PIT_COMMAND),
    );

    // Set frequency divisor
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, @truncate(divisor & 0xFF))),
          [port] "N{dx}" (PIT_CHANNEL0),
    );
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, @truncate(divisor >> 8))),
          [port] "N{dx}" (PIT_CHANNEL0),
    );
}

// Get system uptime in milliseconds with overflow protection
pub fn getUptime() u64 {
    const ticks = getTicks();

    // Intel x86 security guideline: Prevent integer overflow
    // For a 100Hz timer, this protects against overflow for ~585 million years
    // TIMER_FREQUENCY = 100Hz means each tick is 10ms
    const uptime_ms = std.math.mul(u64, ticks, 1000) catch {
        // On overflow, return maximum safe value
        serial.println("[TIMER] WARNING: Uptime overflow detected after {} ticks", .{ticks});
        _ = timer_overflows.fetchAdd(1, .monotonic);
        return std.math.maxInt(u64);
    };

    // Return actual milliseconds (ticks * 1000 / 100)
    return @divFloor(uptime_ms, @as(u64, TIMER_FREQUENCY));
}

// Get timer tick count
pub fn getTicks() u64 {
    // Use atomic load for multicore safety
    return timer_ticks.load(.acquire);
}

// Get TSC frequency in Hz
pub fn getTSCFrequency() u64 {
    return tsc_frequency.load(.acquire);
}

// High-precision delay using TSC with overflow protection
pub fn delayMicroseconds(us: u64) void {
    const freq = tsc_frequency.load(.acquire);
    if (freq == 0) {
        // Fallback to PIT-based delay
        pitDelay(us);
        return;
    }

    const start = readTSC();

    // Intel x86 security guideline: Prevent overflow in delay calculation
    const ticks_to_wait = std.math.mul(u64, freq, us) catch {
        // On overflow, cap to maximum reasonable delay (1 hour)
        const max_us: u64 = 3_600_000_000; // 1 hour in microseconds
        return delayMicroseconds(max_us);
    } / 1_000_000;

    while ((readTSC() - start) < ticks_to_wait) {
        asm volatile ("pause" ::: "memory"); // CPU hint for spin-wait loops with memory barrier
    }
}

// Delay in milliseconds with overflow protection
pub fn delayMilliseconds(ms: u64) void {
    // Intel x86 security guideline: Prevent overflow when converting to microseconds
    const us = std.math.mul(u64, ms, 1000) catch {
        // On overflow, process in chunks
        const chunk_ms: u64 = std.math.maxInt(u64) / 1000;
        var remaining = ms;
        while (remaining > 0) {
            const delay = @min(remaining, chunk_ms);
            delayMicroseconds(delay * 1000);
            remaining -= delay;
        }
        return;
    };
    delayMicroseconds(us);
}

// PIT-based delay for systems without TSC
fn pitDelay(us: u64) void {
    var guard = stack_security.protect();
    defer guard.deinit();

    // Verify we're running at ring 0
    const cs = asm volatile ("mov %%cs, %[result]"
        : [result] "=r" (-> u16),
    );
    const cpl: u2 = @truncate(cs & 0x3);
    if (cpl != 0) {
        serial.println("[TIMER] ERROR: pitDelay requires ring 0, current CPL={}", .{cpl});
        return;
    }

    // For very short delays, just busy wait
    if (us < 1000) {
        var i: u64 = 0;
        while (i < us * 10) : (i += 1) {
            asm volatile ("pause" ::: "memory");
        }
        return;
    }

    // For longer delays, use timer ticks with overflow protection
    const start_ticks = timer_ticks.load(.acquire);

    // Intel x86 security guideline: Prevent overflow in tick calculation
    const ticks_to_wait = std.math.mul(u64, us, TIMER_FREQUENCY) catch {
        // On overflow, use maximum safe delay (1 hour)
        return pitDelay(3_600_000_000); // 1 hour in microseconds
    } / 1_000_000;

    while ((timer_ticks.load(.acquire) - start_ticks) < ticks_to_wait) {
        asm volatile ("pause" ::: "memory");
    }
}

// Print timer information
pub fn printInfo() void {
    const source = timer_source.load(.acquire);
    const source_name = if (source == TIMER_SOURCE_APIC) "apic" else "pit";
    serial.println("[TIMER] Timer source: {s}", .{source_name});

    const freq = tsc_frequency.load(.acquire);
    if (freq > 0) {
        serial.println("[TIMER] TSC frequency: {} MHz", .{freq / 1_000_000});
    }

    serial.println("[TIMER] Timer frequency: {} Hz", .{TIMER_FREQUENCY});
    serial.println("[TIMER] Current uptime: {} ms", .{getUptime()});
}

// Print timer security statistics
pub fn printSecurityStats() void {
    serial.println("[TIMER SECURITY] Timer Security Statistics:", .{});
    serial.println("  - Timer overflows: {}", .{timer_overflows.load(.acquire)});
    serial.println("  - Calibration failures: {}", .{timer_calibration_failures.load(.acquire)});
    serial.println("  - Timer frequency validated: {} Hz (range: {}-{} Hz)", .{ TIMER_FREQUENCY, MIN_TIMER_RATE, MAX_TIMER_RATE });

    const freq = tsc_frequency.load(.acquire);
    if (freq > 0) {
        serial.println("  - TSC frequency validated: {} MHz", .{freq / 1_000_000});
    }
}
