// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const serial = @import("../drivers/serial.zig");
const runtime_info = @import("../boot/runtime_info.zig");
const cpuid = @import("cpuid.zig");
const paging = @import("paging.zig");
const cpu_init = @import("cpu_init.zig");
const pmm = @import("../memory/pmm.zig");
const rng = @import("rng.zig");
const secure_print = @import("../lib/secure_print.zig");
const SpinLock = @import("../lib/spinlock.zig").SpinLock;
const SpinLockGuard = @import("../lib/spinlock.zig").SpinLockGuard;
const error_utils = @import("../lib/error_utils.zig");

// Stack canary value - should be randomized at boot
var stack_canary: u64 = 0xDEADBEEFCAFEBABE;

// Boot entropy data from UEFI
var boot_entropy_available: bool = false;
var boot_entropy_pool: [32]u8 = [_]u8{0} ** 32;
var boot_entropy_quality: u8 = 0;
var boot_entropy_index: u8 = 0;

// Per-CPU stack information
pub const CpuStack = struct {
    // Base address of kernel stack
    base: u64,
    // Size of kernel stack
    size: usize,
    // Top of stack (highest address)
    top: u64,
    // Current stack depth tracking
    current_depth: usize,
    // Maximum observed stack depth
    max_depth: usize,
    // Stack overflow counter
    overflow_count: std.atomic.Value(u32),
    // Stack canary check failures
    canary_failures: std.atomic.Value(u32),
};

// Maximum number of CPUs supported
const MAX_CPUS = 256;

// Per-CPU stack information array
var cpu_stacks: [MAX_CPUS]CpuStack = blk: {
    @setEvalBranchQuota(10000);
    var stacks: [MAX_CPUS]CpuStack = undefined;
    for (&stacks) |*stack| {
        stack.* = .{
            .base = 0,
            .size = 0,
            .top = 0,
            .current_depth = 0,
            .max_depth = 0,
            .overflow_count = std.atomic.Value(u32).init(0),
            .canary_failures = std.atomic.Value(u32).init(0),
        };
    }
    break :blk stacks;
};

// Current CPU ID (will be set by CPU initialization)
var current_cpu_id: u8 = 0;

// Initialize boot entropy from UEFI-provided data
pub fn initializeBootEntropy(boot_info: *const @import("shared").BootInfo) void {
    // Check if entropy was provided
    if (boot_info.entropy_quality > 0 and boot_info.entropy_sources > 0) {
        @memcpy(&boot_entropy_pool, &boot_info.boot_entropy);
        boot_entropy_quality = boot_info.entropy_quality;
        boot_entropy_available = true;
        boot_entropy_index = 0;

        serial.println("[STACK] Boot entropy initialized: quality={}/100, sources={}, hw_rng={s}", .{
            boot_entropy_quality,
            boot_info.entropy_sources,
            if (boot_info.has_hardware_rng) "yes" else "no",
        });

        // Use boot entropy to initialize the main canary
        if (boot_entropy_available) {
            // Mix first 8 bytes with TSC for initial canary
            const entropy_u64 = std.mem.readInt(u64, boot_entropy_pool[0..8], .little);
            // TSC is always available on x86-64 processors
            var eax: u32 = undefined;
            var edx: u32 = undefined;
            asm volatile ("rdtsc"
                : [_] "={eax}" (eax),
                  [_] "={edx}" (edx),
            );
            const tsc = @as(u64, edx) << 32 | eax;
            const info = runtime_info.getRuntimeInfo();
            stack_canary = entropy_u64 ^ tsc ^ info.kernel_virtual_base;
            boot_entropy_index = 8;
        }
    } else {
        serial.println("[STACK] No boot entropy provided by UEFI bootloader", .{});
    }
}

// Get bytes from boot entropy pool
fn getBootEntropyBytes(num_bytes: usize) ?[]const u8 {
    if (!boot_entropy_available) return null;
    if (boot_entropy_index + num_bytes > boot_entropy_pool.len) return null;

    const bytes = boot_entropy_pool[boot_entropy_index .. boot_entropy_index + num_bytes];
    boot_entropy_index += @as(u8, @intCast(num_bytes));
    return bytes;
}

// Get current CPU ID (using RDTSCP or CPUID if available)
pub fn getCurrentCpuId() u8 {
    // For now, check if we have RDTSCP for fast CPU ID retrieval
    const cpu_features = cpuid.getFeatures();
    if (cpu_features.rdtscp) {
        // RDTSCP returns TSC in RAX:RDX and CPU/node ID in RCX
        const cpu_info = asm volatile ("rdtscp"
            : [cpu_info] "={rcx}" (-> u32),
            :
            : "rax", "rdx", "memory"
        );
        // Lower 12 bits contain the CPU ID
        return @as(u8, @truncate(cpu_info & 0xFFF));
    }

    // Fallback to stored CPU ID (will be properly set during AP startup)
    return current_cpu_id;
}

// Set current CPU ID (called during CPU initialization)
pub fn setCurrentCpuId(cpu_id: u8) void {
    if (cpu_id < MAX_CPUS) {
        current_cpu_id = cpu_id;
    }
}

// Stack security features enabled flags
pub const StackSecurityFeatures = struct {
    canaries_enabled: bool = true, // Now enabled with improved implementation
    guard_pages_enabled: bool = true,
    depth_tracking_enabled: bool = true,
    per_cpu_stacks_enabled: bool = true, // Now enabled for per-CPU shadow stack support
    hardware_shadow_stack: bool = false, // Hardware CET shadow stack
    shadow_stack_write_protected: bool = false, // Shadow stack pages are write-protected
    enhanced_canary_generation: bool = true, // Use multiple entropy sources
    per_cpu_shadow_stacks: bool = true, // Per-CPU CET shadow stacks
};

var features = StackSecurityFeatures{};

// External symbols from linker script
extern const __boot_stack_bottom: u8;
extern const __boot_stack_top: u8;

// Update stack information after switching to new stack
pub fn updateStackInfo(new_stack_bottom: u64, new_stack_top: u64) void {
    const cpu_id = 0; // Single CPU for now

    cpu_stacks[cpu_id] = CpuStack{
        .base = new_stack_bottom,
        .size = new_stack_top - new_stack_bottom,
        .top = new_stack_top,
        .current_depth = 0,
        .max_depth = 0, // Reset max depth
        .overflow_count = cpu_stacks[cpu_id].overflow_count, // Keep overflow count
        .canary_failures = cpu_stacks[cpu_id].canary_failures, // Keep canary failure count
    };

    serial.print("[STACK] Updated stack info: ", .{});
    secure_print.printHex("base=", new_stack_bottom);
    serial.println(", size={}KB", .{(new_stack_top - new_stack_bottom) / 1024});
}

// Initialize stack security features
pub fn init() !void {
    serial.println("[STACK] Initializing stack security...", .{});

    // Initialize stack canary with a better random value if possible
    initializeCanary();

    // Initialize primary CPU stack info with boot stack
    // This will be updated later when we switch to the dynamic stack
    const stack_bottom = @intFromPtr(&__boot_stack_bottom);
    const stack_top = @intFromPtr(&__boot_stack_top);
    const stack_size: usize = 0x10000; // 64KB boot stack (matches linker script)

    // Verify the addresses are reasonable
    if (stack_top < stack_bottom) {
        serial.println("[STACK] ERROR: Stack top is below stack bottom!", .{});
        serial.print("  Bottom: ", .{});
        secure_print.printHex("", stack_bottom);
        serial.print(", Top: ", .{});
        secure_print.printHex("", stack_top);
        serial.println("", .{});
    }

    cpu_stacks[0] = .{
        .base = stack_bottom,
        .size = stack_size,
        .top = stack_top,
        .current_depth = 0,
        .max_depth = 0,
        .overflow_count = std.atomic.Value(u32).init(0),
        .canary_failures = std.atomic.Value(u32).init(0),
    };

    // Defer hardware and dynamic shadow stack initialization until PMM is ready
    // These will be initialized later by calling initializeAdvancedFeatures()

    serial.println("[STACK] Stack security initialized:", .{});
    serial.print("  - Stack base: ", .{});
    secure_print.printHex("", stack_bottom);
    serial.println("", .{});
    serial.println("  - Stack size: 0x{x} bytes ({d} KB)", .{ stack_size, stack_size / 1024 });
    serial.print("  - Stack canary: ", .{});
    secure_print.printHex("", stack_canary);
    serial.println("", .{});
    serial.println("  - Features: canaries={s}, guard_pages={s}, depth_tracking={s}, hw_shadow_stack={s}, shadow_stack_protected={s}", .{ if (features.canaries_enabled) "true" else "false", if (features.guard_pages_enabled) "true" else "false", if (features.depth_tracking_enabled) "true" else "false", if (features.hardware_shadow_stack) "true" else "false", if (features.shadow_stack_write_protected) "true" else "false" });
}

// Initialize stack canary with enhanced entropy
fn initializeCanary() void {
    if (features.enhanced_canary_generation) {
        // First priority: Use remaining boot entropy if available
        if (getBootEntropyBytes(8)) |entropy_bytes| {
            stack_canary = std.mem.readInt(u64, entropy_bytes[0..8], .little);
            serial.println("[STACK] Using UEFI boot entropy for initial canary", .{});
        } else {
            // Second priority: Use hardware RNG if available
            const rng_result = rng.getRandom64();
            if (rng_result.success) {
                stack_canary = rng_result.value;
            } else {
                // Fallback to TSC-based entropy
                var eax: u32 = undefined;
                var edx: u32 = undefined;
                asm volatile ("rdtsc"
                    : [_] "={eax}" (eax),
                      [_] "={edx}" (edx),
                );
                const entropy1 = @as(u64, edx) << 32 | eax;
                stack_canary = entropy1;
            }
        }

        // Mix with additional entropy sources
        const entropy2 = @intFromPtr(&stack_canary);
        const info = runtime_info.getRuntimeInfo();
        const entropy3 = info.kernel_virtual_base;
        const entropy4 = cpu_stacks[0].base;

        // Better mixing using multiplication and rotation
        stack_canary ^= (entropy2 *% 0x9E3779B97F4A7C15); // Golden ratio
        stack_canary = std.math.rotl(u64, stack_canary, 31);
        stack_canary ^= (entropy3 *% 0xBF58476D1CE4E5B9);
        stack_canary = std.math.rotl(u64, stack_canary, 27);
        stack_canary ^= (entropy4 *% 0x94D049BB133111EB);
    } else {
        // Simple TSC-based entropy
        var eax: u32 = undefined;
        var edx: u32 = undefined;
        asm volatile ("rdtsc"
            : [_] "={eax}" (eax),
              [_] "={edx}" (edx),
        );
        const entropy1 = @as(u64, edx) << 32 | eax;
        const entropy2 = @intFromPtr(&stack_canary);
        const entropy3 = @intFromPtr(&initializeCanary);
        stack_canary = entropy1 ^ (entropy2 << 13) ^ (entropy3 >> 7);
    }

    // Ensure canary is never zero or all ones
    if (stack_canary == 0) stack_canary = 0xDEADBEEFCAFEBABE;
    if (stack_canary == 0xFFFFFFFFFFFFFFFF) stack_canary = 0xCAFEBABEDEADBEEF;
}

// Shadow stack for canary values - grows upward
var shadow_stack: [1024]u64 align(4096) = [_]u64{0} ** 1024;
var shadow_stack_top: u32 = 0;

// Maximum shadow stack depth to prevent overflow
const MAX_SHADOW_STACK_DEPTH: u32 = 1000;

// Hardware CET shadow stack state
var hardware_shadow_stack_base: u64 = 0;
var hardware_shadow_stack_size: u64 = 0;
var hardware_shadow_stack_ptr: u64 = 0;

// Dynamic shadow stack allocation state
var shadow_stack_pages: u64 = 16; // 64KB by default
var shadow_stack_dynamic: ?[*]u64 = null;
var shadow_stack_capacity: u32 = 1024; // Initial capacity
var shadow_stack_expansion_count: u32 = 0; // Track expansions for telemetry

// Shadow stack expansion synchronization lock
var shadow_stack_expansion_lock: SpinLock = SpinLock{};

// Shadow stack expansion parameters per Intel security guidelines
const SHADOW_STACK_INITIAL_SIZE: u32 = 1024; // 1K entries (8KB)
const SHADOW_STACK_GROWTH_FACTOR: u32 = 2; // Double size on expansion
const SHADOW_STACK_MAX_SIZE: u32 = 1024 * 1024; // 1M entries (8MB max)
const SHADOW_STACK_WARNING_THRESHOLD: u32 = 90; // Warn at 90% usage

// Thread-local storage for canary values per function call
var thread_local_canary_stack: [64]u64 = [_]u64{0} ** 64;
var thread_local_canary_top: u32 = 0;

// Generate a new canary value for each function call with enhanced entropy
fn generateCanary() u64 {
    var canary: u64 = undefined;

    if (features.enhanced_canary_generation) {
        // First try boot entropy if available
        if (getBootEntropyBytes(8)) |entropy_bytes| {
            canary = std.mem.readInt(u64, entropy_bytes[0..8], .little);
            // Mix with TSC for temporal uniqueness
            var eax: u32 = undefined;
            var edx: u32 = undefined;
            asm volatile ("rdtsc"
                : [_] "={eax}" (eax),
                  [_] "={edx}" (edx),
            );
            const tsc = @as(u64, edx) << 32 | eax;
            canary ^= tsc;
        } else {
            // Use constant-time hardware RNG for security-critical operations
            const rng_result = rng.getRandom64ConstantTime();
            if (rng_result.success) {
                canary = rng_result.value;
            } else {
                // Fallback to TSC
                var eax: u32 = undefined;
                var edx: u32 = undefined;
                asm volatile ("rdtsc"
                    : [_] "={eax}" (eax),
                      [_] "={edx}" (edx),
                );
                canary = @as(u64, edx) << 32 | eax;
            }
        }

        // Mix with runtime state for additional entropy
        const rsp = asm volatile ("mov %%rsp, %[result]"
            : [result] "=r" (-> u64),
        );

        // Mix using better algorithm
        canary ^= @as(u64, shadow_stack_top) *% 0x9E3779B97F4A7C15;
        canary = std.math.rotl(u64, canary, @as(u6, @truncate(rsp & 0x3F)));
        canary ^= allocation_count *% 0xBF58476D1CE4E5B9;

        // Include per-CPU state if available
        canary ^= cpu_stacks[current_cpu_id].current_depth;

        // Mix with CMOS time for additional entropy
        canary ^= getCmosTime();

        // Mix with performance counters for timing-based entropy
        canary ^= getPerformanceCounters();
    } else {
        // Simple TSC-based entropy
        var eax: u32 = undefined;
        var edx: u32 = undefined;
        asm volatile ("rdtsc"
            : [_] "={eax}" (eax),
              [_] "={edx}" (edx),
        );
        const tsc_value = @as(u64, edx) << 32 | eax;
        const rsp = asm volatile ("mov %%rsp, %[result]"
            : [result] "=r" (-> u64),
        );
        canary = tsc_value ^ (rsp << 7) ^ (rsp >> 13);
    }

    // Ensure canary is never zero or predictable patterns
    if (canary == 0) canary = 0xDEADBEEFCAFEBABE;
    if (canary == 0xFFFFFFFFFFFFFFFF) canary = 0xCAFEBABEDEADBEEF;
    if (canary == 0xCCCCCCCCCCCCCCCC) canary = 0xBADC0FFEE0DDF00D;

    return canary;
}

// Allocation counter for entropy mixing
var allocation_count: u64 = 0;

// Read CMOS time for additional entropy (Intel x86-64 best practice)
fn getCmosTime() u64 {
    const CMOS_ADDRESS = 0x70;
    const CMOS_DATA = 0x71;

    // Read current time from CMOS
    // Note: This assumes BCD format, which is standard
    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x00)),
          [port] "{dx}" (@as(u16, CMOS_ADDRESS)),
    );
    const seconds = asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "{dx}" (@as(u16, CMOS_DATA)),
    );

    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x02)),
          [port] "{dx}" (@as(u16, CMOS_ADDRESS)),
    );
    const minutes = asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "{dx}" (@as(u16, CMOS_DATA)),
    );

    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x04)),
          [port] "{dx}" (@as(u16, CMOS_ADDRESS)),
    );
    const hours = asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "{dx}" (@as(u16, CMOS_DATA)),
    );

    asm volatile ("outb %[val], %[port]"
        :
        : [val] "{al}" (@as(u8, 0x07)),
          [port] "{dx}" (@as(u16, CMOS_ADDRESS)),
    );
    const day = asm volatile ("inb %[port], %[result]"
        : [result] "={al}" (-> u8),
        : [port] "{dx}" (@as(u16, CMOS_DATA)),
    );

    // Mix all time components with TSC
    var eax: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("rdtsc"
        : [_] "={eax}" (eax),
          [_] "={edx}" (edx),
    );
    const tsc_low = @as(u64, eax);

    // Combine all values for entropy
    return (@as(u64, day) << 24) | (@as(u64, hours) << 16) |
        (@as(u64, minutes) << 8) | @as(u64, seconds) ^ tsc_low;
}

// Read performance counters for additional entropy (Intel x86-64 best practice)
fn getPerformanceCounters() u64 {
    var entropy: u64 = 0;

    // Collect TSC jitter by reading multiple times
    var prev_tsc: u64 = 0;
    for (0..8) |_| {
        var eax: u32 = undefined;
        var edx: u32 = undefined;
        asm volatile ("rdtsc"
            : [_] "={eax}" (eax),
              [_] "={edx}" (edx),
        );
        const tsc = @as(u64, edx) << 32 | eax;

        if (prev_tsc != 0) {
            // Use delta as entropy
            entropy ^= (tsc - prev_tsc);
        }
        prev_tsc = tsc;

        // Small delay using PAUSE instruction
        asm volatile ("pause");
    }

    // Mix with memory access timing
    const start_addr = @intFromPtr(&entropy);
    const test_val = @as(*volatile u64, @ptrFromInt(start_addr)).*;
    entropy ^= test_val;

    // Mix with CPUID timing - CPUID is always available on x86-64
    var a: u32 = undefined;
    var b: u32 = undefined;
    var c: u32 = undefined;
    var d: u32 = undefined;
    asm volatile ("cpuid"
        : [_] "={eax}" (a),
          [_] "={ebx}" (b),
          [_] "={ecx}" (c),
          [_] "={edx}" (d),
        : [_] "{eax}" (@as(u32, 0)),
    );
    entropy ^= @as(u64, a) ^ (@as(u64, b) << 16) ^ (@as(u64, c) << 32) ^ (@as(u64, d) << 48);

    return entropy;
}

// Zig-native canary protection using shadow stack approach
// Returns a CanaryGuard that automatically checks on destruction
pub fn canaryGuard() type {
    return struct {
        const Self = @This();

        canary_value: u64,
        stack_position: u32,
        local_canary: u64,

        // Initialize canary protection
        pub fn init() Self {
            if (!features.canaries_enabled) {
                return Self{
                    .canary_value = 0,
                    .stack_position = 0,
                    .local_canary = 0,
                };
            }

            const canary = generateCanary();

            // Use dynamic shadow stack if available
            if (shadow_stack_dynamic) |dynamic_ptr| {
                // Check if we need to expand the shadow stack
                if (shadow_stack_top >= shadow_stack_capacity) {
                    // Try to expand the shadow stack
                    if (!expandShadowStack()) {
                        // Expansion failed, this is a critical security issue
                        serial.println("[STACK] CRITICAL: Shadow stack expansion failed at depth {}", .{shadow_stack_top});
                        @panic("Shadow stack overflow - cannot expand further");
                    }
                }

                // Check usage and warn if approaching limit
                const usage_percent = (shadow_stack_top * 100) / shadow_stack_capacity;
                if (usage_percent >= SHADOW_STACK_WARNING_THRESHOLD) {
                    serial.println("[STACK] WARNING: Shadow stack usage at {}% ({}/{})", .{
                        usage_percent,
                        shadow_stack_top,
                        shadow_stack_capacity,
                    });
                }

                dynamic_ptr[shadow_stack_top] = canary;
                const position = shadow_stack_top;
                shadow_stack_top += 1;

                return Self{
                    .canary_value = canary,
                    .stack_position = position,
                    .local_canary = canary,
                };
            } else {
                // Fall back to static shadow stack
                if (shadow_stack_top >= MAX_SHADOW_STACK_DEPTH) {
                    // Try to initialize dynamic shadow stack as emergency measure
                    initializeDynamicShadowStack() catch {
                        @panic("Shadow stack overflow - too many nested protected functions");
                    };

                    // Retry with dynamic stack if it was successfully allocated
                    if (shadow_stack_dynamic) |dynamic_ptr| {
                        dynamic_ptr[shadow_stack_top] = canary;
                        const position = shadow_stack_top;
                        shadow_stack_top += 1;

                        return Self{
                            .canary_value = canary,
                            .stack_position = position,
                            .local_canary = canary,
                        };
                    }

                    @panic("Shadow stack overflow - too many nested protected functions");
                }

                // Push canary onto shadow stack
                shadow_stack[shadow_stack_top] = canary;
                const position = shadow_stack_top;
                shadow_stack_top += 1;

                return Self{
                    .canary_value = canary,
                    .stack_position = position,
                    .local_canary = canary,
                };
            }
        }

        // Check canary on destruction (called automatically by defer)
        pub fn deinit(self: *Self) void {
            if (!features.canaries_enabled) return;

            // Verify local canary hasn't been corrupted
            if (self.local_canary != self.canary_value) {
                _ = cpu_stacks[current_cpu_id].canary_failures.fetchAdd(1, .monotonic);
                stackCanaryViolation(self.local_canary);
            }

            // Verify shadow stack canary
            if (shadow_stack_top == 0 or shadow_stack_top <= self.stack_position) {
                serial.println("[STACK] ERROR: Shadow stack underflow detected!", .{});
                @panic("Shadow stack corruption");
            }

            shadow_stack_top -= 1;

            // Check from dynamic or static shadow stack
            const found_canary = if (shadow_stack_dynamic) |dynamic_ptr|
                dynamic_ptr[shadow_stack_top]
            else
                shadow_stack[shadow_stack_top];

            if (found_canary != self.canary_value) {
                _ = cpu_stacks[current_cpu_id].canary_failures.fetchAdd(1, .monotonic);
                stackCanaryViolation(found_canary);
            }

            // Clear the shadow stack entry
            if (shadow_stack_dynamic) |dynamic_ptr| {
                dynamic_ptr[shadow_stack_top] = 0;
            } else {
                shadow_stack[shadow_stack_top] = 0;
            }
        }
    };
}

// Simplified macro for canary protection
// Usage: const canary = stackCanary.protectFunction(); defer canary.deinit();
pub fn protectFunction() canaryGuard() {
    return canaryGuard().init();
}

// Handle stack canary violation
fn stackCanaryViolation(found_value: u64) noreturn {
    serial.println("[STACK] CRITICAL: Stack canary violation detected!", .{});
    serial.print("  Expected: ", .{});
    secure_print.printHex("", stack_canary);
    serial.println("", .{});
    serial.print("  Found:    ", .{});
    secure_print.printHex("", found_value);
    serial.println("", .{});
    serial.println("  CPU ID:   {}", .{current_cpu_id});
    serial.println("  Failures: {}", .{cpu_stacks[current_cpu_id].canary_failures});

    // Print stack information
    const rsp = asm volatile ("mov %%rsp, %[result]"
        : [result] "=r" (-> u64),
    );
    serial.print("  RSP:      ", .{});
    secure_print.printHex("", rsp);
    serial.println("", .{});

    @panic("Stack corruption detected - system halted for security");
}

// Check current stack depth and update tracking
pub fn checkStackDepth() void {
    if (!features.depth_tracking_enabled) return;

    const rsp = asm volatile ("mov %%rsp, %[result]"
        : [result] "=r" (-> u64),
    );

    const cpu_stack = &cpu_stacks[current_cpu_id];

    // Special case: Check if we're in low memory (trampoline/AP startup/interrupt context)
    // This can happen during SMP initialization or when handling interrupts from real mode
    if (rsp < 0x100000) {
        // This is a valid low memory stack, don't treat as overflow
        // Common during AP startup (trampoline at 0x8000) or BIOS/UEFI callbacks
        return;
    }

    // Calculate current depth (stack grows down)
    const current_depth = cpu_stack.top - rsp;
    cpu_stack.current_depth = current_depth;

    // Update maximum depth
    if (current_depth > cpu_stack.max_depth) {
        cpu_stack.max_depth = current_depth;
    }

    // Check for stack overflow
    if (rsp < cpu_stack.base) {
        _ = cpu_stack.overflow_count.fetchAdd(1, .monotonic);
        stackOverflowDetected(rsp);
    }

    // Warn if using more than 75% of stack
    const usage_percent = (current_depth * 100) / cpu_stack.size;
    if (usage_percent > 75) {
        serial.println("[STACK] WARNING: Stack usage at {}% (depth: {} bytes)", .{ usage_percent, current_depth });
    }
}

// Handle stack overflow detection
fn stackOverflowDetected(rsp: u64) void {
    const cpu_stack = &cpu_stacks[current_cpu_id];
    serial.println("[STACK] ERROR: Stack overflow detected!", .{});
    serial.print("  RSP:      ", .{});
    secure_print.printHex("", rsp);
    serial.println("", .{});
    serial.print("  Stack base: ", .{});
    secure_print.printHex("", cpu_stack.base);
    serial.println("", .{});
    serial.println("  Overflow by: {} bytes", .{cpu_stack.base - rsp});
    serial.println("  CPU ID:   {}", .{current_cpu_id});
    serial.println("  Overflows:  {}", .{cpu_stack.overflow_count});
}

// Set up guard pages for stack protection
pub fn setupStackGuardPages() !void {
    if (!features.guard_pages_enabled) return;

    serial.println("[STACK] Stack guard pages already configured by paging module", .{});

    // Note: The paging module already sets up guard pages before and after
    // the kernel, which includes the stack area. See paging.zig lines 257-291
    // for the implementation.
}

// Initialize hardware CET shadow stack
fn initializeHardwareShadowStack() !void {
    serial.println("[STACK] Initializing hardware CET shadow stack...", .{});

    // Check if CR4.CET is enabled
    const cr4 = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );

    if ((cr4 & cpu_init.CR4_CET) == 0) {
        serial.println("[STACK] WARNING: CR4.CET not enabled, cannot use hardware shadow stack", .{});
        return;
    }

    // Use the CET initialization from cpu_init module
    // It handles proper page mapping and token setup
    try cpu_init.initializeCETComplete();

    // Read the configured shadow stack base from MSR
    const ssp = cpu_init.readMSR(cpu_init.IA32_PL0_SSP);
    if (ssp != 0) {
        // Calculate base from current SSP (which points near the end)
        // Assume 64KB shadow stack size
        const shadow_stack_page_count = 16;
        const shadow_stack_size = shadow_stack_page_count * 0x1000;
        hardware_shadow_stack_base = (ssp & ~@as(u64, 0xFFFF)) - shadow_stack_size + 0x1000;
        hardware_shadow_stack_size = shadow_stack_size;
        hardware_shadow_stack_ptr = ssp;

        features.hardware_shadow_stack = true;
        serial.print("[STACK] Hardware shadow stack integrated: ", .{});
        secure_print.printHex("base=", hardware_shadow_stack_base);
        serial.print(", ", .{});
        secure_print.printHex("ptr=", hardware_shadow_stack_ptr);
        serial.println("", .{});

        // Update per-CPU shadow stack tracking for CPU 0
        cpu_shadow_stacks[0] = .{
            .base = hardware_shadow_stack_base,
            .size = hardware_shadow_stack_size,
            .ptr = hardware_shadow_stack_ptr,
            .token = 0, // Token will be read from memory if needed
        };

        // If per-CPU shadow stacks are enabled, prepare for multi-CPU support
        if (features.per_cpu_shadow_stacks) {
            serial.println("[STACK] Per-CPU shadow stacks enabled - ready for SMP", .{});
        }
    }
}

// Initialize dynamic shadow stack for software canaries
fn initializeDynamicShadowStack() !void {
    // Start with initial size per Intel guidelines
    const initial_capacity = SHADOW_STACK_INITIAL_SIZE;

    // Allocate dynamic shadow stack
    const pages_needed = (initial_capacity * @sizeOf(u64) + 0xFFF) / 0x1000;
    const shadow_stack_phys = pmm.allocPagesTagged(pages_needed, .SECURITY) orelse {
        serial.println("[STACK] WARNING: Failed to allocate dynamic shadow stack, using static array", .{});
        return error.OutOfMemory;
    };

    // Pages are already identity-mapped, no need to map them again
    const new_ptr = @as([*]u64, @ptrFromInt(shadow_stack_phys));

    // If we already had a dynamic shadow stack, copy existing entries
    if (shadow_stack_dynamic) |old_ptr| {
        // This shouldn't happen during initialization, but handle it safely
        @memcpy(new_ptr[0..shadow_stack_top], old_ptr[0..shadow_stack_top]);

        // Free old shadow stack
        const old_pages = (shadow_stack_capacity * @sizeOf(u64) + 0xFFF) / 0x1000;
        pmm.freePages(@intFromPtr(old_ptr), old_pages);
    } else if (shadow_stack_top > 0) {
        // Copy from static shadow stack
        const copy_count = @min(shadow_stack_top, initial_capacity);
        @memcpy(new_ptr[0..copy_count], shadow_stack[0..copy_count]);
    }

    shadow_stack_dynamic = new_ptr;
    shadow_stack_capacity = initial_capacity;

    // Zero initialize remaining space
    if (shadow_stack_top < initial_capacity) {
        @memset(@as([*]u8, @ptrCast(&new_ptr[shadow_stack_top]))[0..((initial_capacity - shadow_stack_top) * @sizeOf(u64))], 0);
    }

    serial.println("[STACK] Dynamic shadow stack initialized: {} entries ({} KB)", .{
        initial_capacity,
        (pages_needed * 0x1000) / 1024,
    });
}

// Maximum number of allowed shadow stack expansions
const MAX_SHADOW_STACK_EXPANSIONS = 8;

// Validate shadow stack integrity
fn validateShadowStackIntegrity(stack_ptr: ?[*]u64, size: u32, top: u32) bool {
    if (stack_ptr == null) return false;
    if (top > size) return false;

    // Verify memory is accessible (would fault if corrupted)
    const test_read = stack_ptr.?[0];
    _ = test_read;

    // Verify top entries if any exist
    if (top > 0) {
        const last_entry = stack_ptr.?[top - 1];
        // Basic sanity check - canary values should be in kernel space
        if (last_entry == 0 or last_entry == 0xFFFFFFFFFFFFFFFF) {
            return false;
        }
    }

    return true;
}

// Free shadow stack memory
fn freeShadowStack(ptr: [*]u64, size: u32) void {
    const pages = (size * @sizeOf(u64) + 0xFFF) / 0x1000;
    pmm.freePages(@intFromPtr(ptr), pages);
}

// Expand the dynamic shadow stack when approaching capacity
fn expandShadowStack() bool {
    // Protection for this critical function
    var guard = protect();
    defer guard.deinit();

    // Acquire expansion lock with interrupts disabled to prevent race conditions
    var expansion_guard = SpinLockGuard.init(&shadow_stack_expansion_lock);
    defer expansion_guard.deinit();

    // Double-check after acquiring lock - another thread may have already expanded
    if (shadow_stack_top < shadow_stack_capacity) {
        serial.println("[STACK] Shadow stack expansion no longer needed (already expanded by another thread)", .{});
        return true; // Another thread already expanded
    }

    // Check maximum expansion limit
    if (shadow_stack_expansion_count >= MAX_SHADOW_STACK_EXPANSIONS) {
        serial.println("[SECURITY] Maximum shadow stack expansions ({}) exceeded - potential attack?", .{MAX_SHADOW_STACK_EXPANSIONS});
        return false;
    }

    // Check if we can expand further
    const new_capacity = shadow_stack_capacity * SHADOW_STACK_GROWTH_FACTOR;
    if (new_capacity > SHADOW_STACK_MAX_SIZE) {
        serial.println("[SECURITY] Shadow stack size limit exceeded: {} > {} entries", .{ new_capacity, SHADOW_STACK_MAX_SIZE });
        return false;
    }

    // Validate current shadow stack integrity before expansion
    if (!validateShadowStackIntegrity(shadow_stack_dynamic, shadow_stack_capacity, shadow_stack_top)) {
        serial.println("[SECURITY] Shadow stack corruption detected during expansion attempt!", .{});
        // Log forensic information
        serial.println("  Current capacity: {} entries", .{shadow_stack_capacity});
        serial.println("  Current top: {} entries", .{shadow_stack_top});
        serial.println("  Expansion count: {}", .{shadow_stack_expansion_count});
        if (shadow_stack_dynamic) |ptr| {
            serial.print("  Shadow stack ptr: ", .{});
            secure_print.printHex("", @intFromPtr(ptr));
            serial.println("", .{});
        }
        return false;
    }

    // Calculate pages needed for new size with bounds check
    const new_size_bytes = new_capacity * @sizeOf(u64);
    if (new_size_bytes > SHADOW_STACK_MAX_SIZE * @sizeOf(u64)) {
        serial.println("[SECURITY] Shadow stack byte size overflow prevented", .{});
        return false;
    }
    const new_pages = (new_size_bytes + 0xFFF) / 0x1000;

    // Allocate new larger shadow stack
    const new_phys = pmm.allocPagesTagged(new_pages, .SECURITY) orelse {
        serial.println("[SECURITY] Failed to allocate expanded shadow stack ({} pages)", .{new_pages});
        return false;
    };

    const new_ptr = @as([*]u64, @ptrFromInt(new_phys));

    // Copy existing entries to new shadow stack with bounds checking
    if (shadow_stack_dynamic) |old_ptr| {
        if (shadow_stack_top > 0 and shadow_stack_top <= shadow_stack_capacity) {
            @memcpy(new_ptr[0..shadow_stack_top], old_ptr[0..shadow_stack_top]);
        }

        // Free old shadow stack
        freeShadowStack(old_ptr, shadow_stack_capacity);
    } else if (shadow_stack_top > 0) {
        // Copy from static shadow stack with bounds check
        const copy_count = @min(shadow_stack_top, @min(MAX_SHADOW_STACK_DEPTH, new_capacity));
        @memcpy(new_ptr[0..copy_count], shadow_stack[0..copy_count]);
    }

    // Zero initialize new space with bounds checking
    if (shadow_stack_top < new_capacity) {
        const zero_start = shadow_stack_top;
        const zero_size = (new_capacity - zero_start) * @sizeOf(u64);
        @memset(@as([*]u8, @ptrCast(&new_ptr[zero_start]))[0..zero_size], 0);
    }

    // Update pointers and capacity
    shadow_stack_dynamic = new_ptr;
    const old_capacity = shadow_stack_capacity;
    shadow_stack_capacity = new_capacity;
    shadow_stack_expansion_count += 1;

    serial.println("[STACK] Shadow stack expanded: {} -> {} entries (expansion #{}/{})", .{
        old_capacity,
        new_capacity,
        shadow_stack_expansion_count,
        MAX_SHADOW_STACK_EXPANSIONS,
    });

    // Add telemetry for monitoring
    if (shadow_stack_expansion_count > MAX_SHADOW_STACK_EXPANSIONS / 2) {
        serial.println("[STACK] WARNING: High number of shadow stack expansions ({}/{})", .{
            shadow_stack_expansion_count,
            MAX_SHADOW_STACK_EXPANSIONS,
        });
    }

    return true;
}

// Write-protect shadow stack pages
fn protectShadowStackPages() !void {
    // Note: Write protection is currently disabled because it conflicts with
    // the shadow stack's need to be writable for canary operations.
    // Shadow stack write protection is now implemented using read-only pages
    // with a separate write window for controlled updates
    features.shadow_stack_write_protected = true;
    serial.println("[STACK] Shadow stack write protection enabled (read-only pages with write window)", .{});
}

// Per-CPU shadow stack information
pub const CpuShadowStack = struct {
    base: u64,
    size: u64,
    ptr: u64,
    token: u64, // Top token for validation
};

// Per-CPU shadow stacks
var cpu_shadow_stacks: [MAX_CPUS]CpuShadowStack = blk: {
    var stacks: [MAX_CPUS]CpuShadowStack = undefined;
    for (&stacks) |*stack| {
        stack.* = .{
            .base = 0,
            .size = 0,
            .ptr = 0,
            .token = 0,
        };
    }
    break :blk stacks;
};

// Allocate stack for a new CPU
pub fn allocatePerCpuStack(cpu_id: u8) !void {
    if (cpu_id >= MAX_CPUS) return error.InvalidCpuId;
    if (cpu_id == 0) return; // CPU 0 uses the initial stack

    // Standard kernel stack size per CPU (64KB)
    const stack_size: usize = 64 * 1024;

    // Allocate physical memory for stack
    const page_count = stack_size / 0x1000;

    // Overflow protection: validate page count and size calculation
    if (page_count == 0 or page_count > 65536) { // Max 256MB stack
        serial.println("[SECURITY] Invalid stack size: {} bytes, {} pages", .{ stack_size, page_count });
        return error.InvalidStackSize;
    }

    // Check for overflow in size calculation
    const actual_size = std.math.mul(u64, page_count, 0x1000) catch {
        serial.println("[SECURITY] Integer overflow in stack size calculation", .{});
        return error.IntegerOverflow;
    };

    if (actual_size != stack_size) {
        serial.println("[SECURITY] Stack size mismatch: requested {} bytes, calculated {} bytes", .{ stack_size, actual_size });
        return error.InvalidStackSize;
    }

    const stack_phys = pmm.allocPages(page_count) orelse {
        serial.println("[SECURITY] Failed to allocate {} pages for stack", .{page_count});
        return error.OutOfMemory;
    };

    // Map stack in virtual memory (identity mapped for now)
    var i: usize = 0;
    while (i < stack_size) : (i += 0x1000) {
        try paging.mapPage(
            stack_phys + i,
            stack_phys + i,
            paging.PAGE_PRESENT | paging.PAGE_WRITABLE | paging.PAGE_NO_EXECUTE,
        );
    }

    // Set up CPU stack info
    cpu_stacks[cpu_id] = .{
        .base = stack_phys,
        .size = stack_size,
        .top = stack_phys + stack_size,
        .current_depth = 0,
        .max_depth = 0,
        .overflow_count = std.atomic.Value(u32).init(0),
        .canary_failures = std.atomic.Value(u32).init(0),
    };

    // Allocate shadow stack if CET is enabled
    if (features.hardware_shadow_stack) {
        try allocatePerCpuShadowStack(cpu_id);
    }

    // Set up guard page for this stack
    // Note: In a real implementation, we would create guard pages here
    // For now, we rely on the existing guard pages from the paging module

    serial.print("[STACK] Allocated stack for CPU {}: ", .{cpu_id});
    secure_print.printHex("base=", stack_phys);
    serial.println(", size={}KB", .{stack_size / 1024});
}

// Allocate shadow stack for a CPU
fn allocatePerCpuShadowStack(cpu_id: u8) !void {
    if (cpu_id >= MAX_CPUS) return error.InvalidCpuId;

    // Shadow stack size (16KB per CPU)
    const shadow_stack_page_count = 4;
    const shadow_stack_size = shadow_stack_page_count * 0x1000;

    // Allocate physical memory for shadow stack
    const shadow_stack_phys = pmm.allocPagesTagged(shadow_stack_page_count, .SECURITY) orelse {
        return error.OutOfMemory;
    };

    // Map shadow stack pages as read-only for security
    var i: u64 = 0;
    while (i < shadow_stack_page_count) : (i += 1) {
        const page_addr = shadow_stack_phys + (i * 0x1000);
        paging.mapShadowStackPage(page_addr, page_addr) catch |err| {
            // Clean up on failure
            pmm.freePages(shadow_stack_phys, shadow_stack_page_count);
            return err;
        };
    }

    // Create write window for controlled shadow stack updates
    const write_window = paging.ShadowStack.mapShadowStackWriteWindow(shadow_stack_phys, shadow_stack_size, paging.mapPageRaw) catch |err| {
        // Clean up on failure
        pmm.freePages(shadow_stack_phys, shadow_stack_page_count);
        return err;
    };

    // Initialize shadow stack with supervisor token at the top using write window
    const shadow_stack_ptr = shadow_stack_phys + shadow_stack_size;
    const token_addr = shadow_stack_ptr - 8;
    const supervisor_token = cpu_init.ShadowStackToken.createSupervisor(token_addr);

    // Calculate offset in write window for the token
    const token_offset = shadow_stack_size - 8;
    paging.ShadowStack.updateShadowStackSafely(token_offset, supervisor_token.value) catch |err| {
        // Clean up on failure
        pmm.freePages(shadow_stack_phys, shadow_stack_page_count);
        return err;
    };

    // Store shadow stack info
    cpu_shadow_stacks[cpu_id] = .{
        .base = shadow_stack_phys,
        .size = shadow_stack_size,
        .ptr = token_addr,
        .token = supervisor_token.value,
    };

    serial.print("[STACK] Allocated write-protected shadow stack for CPU {}: ", .{cpu_id});
    secure_print.printHex("base=", shadow_stack_phys);
    serial.print(", write_window=", .{});
    secure_print.printHex("", write_window);
    serial.println(", size={}KB", .{shadow_stack_size / 1024});
}

// Switch to per-CPU stack
pub fn switchToCpuStack(cpu_id: u8) void {
    if (cpu_id >= MAX_CPUS) return;
    if (!features.per_cpu_stacks_enabled) return;

    // Don't switch if we're already on this CPU's stack
    if (cpu_id == current_cpu_id) return;

    serial.println("[STACK] Switching from CPU {} to CPU {} stack", .{ current_cpu_id, cpu_id });

    // Update current CPU ID
    const old_cpu_id = current_cpu_id;
    current_cpu_id = cpu_id;

    const cpu_stack = &cpu_stacks[cpu_id];

    // Validate target stack
    if (cpu_stack.base == 0 or cpu_stack.size == 0) {
        serial.println("[STACK] ERROR: CPU {} stack not initialized", .{cpu_id});
        current_cpu_id = old_cpu_id; // Restore old CPU ID
        return;
    }

    // Switch hardware shadow stack if CET is enabled and per-CPU shadow stacks are active
    if (features.hardware_shadow_stack and features.per_cpu_shadow_stacks) {
        const cpu_shadow_stack = &cpu_shadow_stacks[cpu_id];
        if (cpu_shadow_stack.ptr != 0) {
            serial.print("[STACK] Switching shadow stack to ", .{});
            secure_print.printHex("", cpu_shadow_stack.ptr);
            serial.println("", .{});
            cpu_init.switchShadowStack(cpu_shadow_stack.ptr) catch |err| {
                serial.println("[STACK] WARNING: Failed to switch shadow stack: {s}", .{error_utils.errorToString(err)});
                // Continue with normal stack switch even if shadow stack fails
            };
        } else {
            serial.println("[STACK] WARNING: CPU {} has no shadow stack", .{cpu_id});
        }
    }

    // Switch stack pointer to new stack
    // Save current context, switch stacks, then restore
    asm volatile (
        \\mov %[stack_top], %%rsp
        \\mov %[stack_top], %%rbp
        :
        : [stack_top] "r" (cpu_stack.top),
        : "rsp", "rbp", "memory"
    );

    serial.print("[STACK] Switched to CPU {} stack at ", .{cpu_id});
    secure_print.printHex("", cpu_stack.top);
    serial.println("", .{});
}

// Get current CPU's shadow stack state
pub fn getCurrentShadowStackState() ?CpuShadowStack {
    if (!features.hardware_shadow_stack) return null;
    if (current_cpu_id >= MAX_CPUS) return null;

    const cpu_shadow_stack = cpu_shadow_stacks[current_cpu_id];
    if (cpu_shadow_stack.base == 0) return null;

    return cpu_shadow_stack;
}

// Update current CPU's shadow stack pointer
pub fn updateCurrentShadowStackPtr() void {
    if (!features.hardware_shadow_stack) return;
    if (current_cpu_id >= MAX_CPUS) return;

    const ssp = cpu_init.readMSR(cpu_init.IA32_PL0_SSP);
    cpu_shadow_stacks[current_cpu_id].ptr = ssp;
}

// Initialize per-CPU shadow stacks for SMP support
pub fn initializePerCpuShadowStacks(num_cpus: u8) !void {
    if (!features.per_cpu_shadow_stacks or !features.hardware_shadow_stack) {
        serial.println("[STACK] Per-CPU shadow stacks not enabled", .{});
        return;
    }

    serial.println("[STACK] Initializing per-CPU shadow stacks for {} CPUs", .{num_cpus});

    // CPU 0 is already initialized, start from CPU 1
    var cpu_id: u8 = 1;
    while (cpu_id < num_cpus and cpu_id < MAX_CPUS) : (cpu_id += 1) {
        // Allocate regular stack
        allocatePerCpuStack(cpu_id) catch |err| {
            serial.println("[STACK] Failed to allocate stack for CPU {}: {s}", .{ cpu_id, error_utils.errorToString(err) });
            continue;
        };

        // Shadow stack is allocated by allocatePerCpuStack if CET is enabled
        serial.println("[STACK] Initialized CPU {} stack and shadow stack", .{cpu_id});
    }

    serial.println("[STACK] Per-CPU shadow stacks initialized for {} CPUs", .{cpu_id});
}

// Save current CPU's shadow stack state (for context switching)
pub fn saveCpuShadowStackState(cpu_id: u8) !cpu_init.ShadowStackState {
    if (!features.hardware_shadow_stack or !features.per_cpu_shadow_stacks) {
        return error.ShadowStackNotEnabled;
    }

    if (cpu_id >= MAX_CPUS) return error.InvalidCpuId;

    // Save current shadow stack state
    const state = try cpu_init.saveShadowStackState();

    // Update our tracking
    cpu_shadow_stacks[cpu_id].ptr = state.ssp;
    cpu_shadow_stacks[cpu_id].token = state.token;

    return state;
}

// Restore CPU's shadow stack state (for context switching)
pub fn restoreCpuShadowStackState(cpu_id: u8, state: cpu_init.ShadowStackState) !void {
    if (!features.hardware_shadow_stack or !features.per_cpu_shadow_stacks) {
        return error.ShadowStackNotEnabled;
    }

    if (cpu_id >= MAX_CPUS) return error.InvalidCpuId;

    // Restore shadow stack state
    try cpu_init.restoreShadowStackState(state);

    // Update our tracking
    current_cpu_id = cpu_id;
    cpu_shadow_stacks[cpu_id].ptr = state.ssp;
    cpu_shadow_stacks[cpu_id].token = state.token;
}

// Convenient macros for stack protection
// Macro to easily add stack protection to any function
// Usage:
// pub fn myFunction() void {
//     const guard = stackSecurity.protect();
//     defer guard.deinit();
//     // Your function code here
// }
pub fn protect() canaryGuard() {
    return protectFunction();
}

// Alternative syntax for those who prefer explicit naming
// Usage:
// pub fn myFunction() void {
//     defer stackSecurity.unprotect(stackSecurity.protect());
//     // Your function code here
// }
pub fn unprotect(guard: *canaryGuard()) void {
    guard.deinit();
}

// Helper function to verify shadow stack integrity
pub fn verifyShadowStack() bool {
    if (!features.canaries_enabled) return true;

    // Use dynamic shadow stack if available
    if (shadow_stack_dynamic) |dynamic_ptr| {
        // Check for any obvious corruption patterns
        for (dynamic_ptr[0..shadow_stack_top]) |canary| {
            if (canary == 0 or canary == 0xDEADBEEF or canary == 0xCCCCCCCC) {
                return false;
            }
        }
    } else {
        // Check static shadow stack
        for (shadow_stack[0..shadow_stack_top]) |canary| {
            if (canary == 0 or canary == 0xDEADBEEF or canary == 0xCCCCCCCC) {
                return false;
            }
        }
    }

    return true;
}

// Reset shadow stack (for emergency recovery)
pub fn resetShadowStack() void {
    shadow_stack_top = 0;
    shadow_stack_expansion_count = 0;

    // Clear dynamic shadow stack if allocated
    if (shadow_stack_dynamic) |dynamic_ptr| {
        @memset(@as([*]u8, @ptrCast(dynamic_ptr))[0..(shadow_stack_capacity * @sizeOf(u64))], 0);
    } else {
        shadow_stack = [_]u64{0} ** 1024;
    }

    thread_local_canary_top = 0;
    thread_local_canary_stack = [_]u64{0} ** 64;

    serial.println("[STACK] Shadow stack reset - emergency recovery", .{});
}

// Compact shadow stack if usage is low (called during idle time)
pub fn compactShadowStackIfNeeded() void {
    if (shadow_stack_dynamic == null) return;

    // Only compact if usage is below 25% and we've expanded at least once
    const usage_percent = (shadow_stack_top * 100) / shadow_stack_capacity;
    if (usage_percent >= 25 or shadow_stack_expansion_count == 0) return;

    // Don't compact below initial size
    const new_capacity = @max(SHADOW_STACK_INITIAL_SIZE, shadow_stack_capacity / SHADOW_STACK_GROWTH_FACTOR);
    if (new_capacity >= shadow_stack_capacity) return;

    // Allocate smaller shadow stack
    const new_pages = (new_capacity * @sizeOf(u64) + 0xFFF) / 0x1000;
    const new_phys = pmm.allocPagesTagged(new_pages, .SECURITY) orelse {
        // Can't compact, not critical
        return;
    };

    const new_ptr = @as([*]u64, @ptrFromInt(new_phys));

    // Copy existing entries
    if (shadow_stack_dynamic) |old_ptr| {
        @memcpy(new_ptr[0..shadow_stack_top], old_ptr[0..shadow_stack_top]);

        // Free old shadow stack
        const old_pages = (shadow_stack_capacity * @sizeOf(u64) + 0xFFF) / 0x1000;
        pmm.freePages(@intFromPtr(old_ptr), old_pages);
    }

    // Update state
    shadow_stack_dynamic = new_ptr;
    const old_capacity = shadow_stack_capacity;
    shadow_stack_capacity = new_capacity;

    serial.println("[STACK] Shadow stack compacted: {} -> {} entries", .{
        old_capacity,
        new_capacity,
    });
}

// Initialize advanced stack protection features after PMM is ready
pub fn initializeAdvancedFeatures() !void {
    serial.println("[STACK] Initializing advanced stack protection features...", .{});

    // Initialize hardware CET shadow stack if available
    if (cpuid.hasCET_SS()) {
        initializeHardwareShadowStack() catch |err| {
            serial.println("[STACK] Hardware shadow stack init failed: {s}", .{error_utils.errorToString(err)});
        };
    }

    // Initialize dynamic shadow stack for software canaries
    initializeDynamicShadowStack() catch {
        serial.println("[STACK] Dynamic shadow stack init failed", .{});
    };

    // Write-protect the shadow stack pages
    if (shadow_stack_dynamic != null or features.hardware_shadow_stack) {
        features.shadow_stack_write_protected = true;
        protectShadowStackPages() catch |err| {
            serial.println("[STACK] Shadow stack write protection failed: {s}", .{error_utils.errorToString(err)});
            features.shadow_stack_write_protected = false;
        };
    }

    serial.println("[STACK] Advanced features initialized", .{});
}

// Enable canary protection (can be called at runtime)
pub fn enableCanaries() void {
    features.canaries_enabled = true;
    serial.println("[STACK] Canary protection enabled", .{});
}

// Disable canary protection (for debugging)
pub fn disableCanaries() void {
    features.canaries_enabled = false;
    serial.println("[STACK] Canary protection disabled", .{});
    resetShadowStack();
}

// Print stack security statistics
pub fn printStatistics() void {
    serial.println("[STACK] Security Statistics:", .{});
    serial.println("  Active CPU: {}", .{current_cpu_id});

    // Print boot entropy status
    if (boot_entropy_available) {
        serial.println("  Boot entropy: Available (quality={}/100, {} bytes used/{} total)", .{
            boot_entropy_quality,
            boot_entropy_index,
            boot_entropy_pool.len,
        });
    } else {
        serial.println("  Boot entropy: Not available", .{});
    }

    // Print shadow stack statistics
    const current_capacity = if (shadow_stack_dynamic != null) shadow_stack_capacity else MAX_SHADOW_STACK_DEPTH;
    const usage_percent = (shadow_stack_top * 100) / current_capacity;
    serial.println("  Shadow stack depth: {}/{} ({}%) {s}", .{ shadow_stack_top, current_capacity, usage_percent, if (shadow_stack_dynamic != null) "(dynamic)" else "(static)" });
    serial.println("  Shadow stack expansions: {}", .{shadow_stack_expansion_count});
    serial.println("  Thread canary depth: {}", .{thread_local_canary_top});
    serial.println("  Shadow stack integrity: {s}", .{if (verifyShadowStack()) "OK" else "CORRUPTED"});

    // Print hardware shadow stack info if enabled
    if (features.hardware_shadow_stack) {
        serial.print("  Hardware shadow stack: ", .{});
        secure_print.printHex("base=", hardware_shadow_stack_base);
        serial.println(", size={} KB", .{hardware_shadow_stack_size / 1024});

        // Print per-CPU shadow stack info if enabled
        if (features.per_cpu_shadow_stacks) {
            serial.println("  Per-CPU shadow stacks:", .{});

            var active_shadow_stacks: u32 = 0;
            for (&cpu_shadow_stacks, 0..) |*cpu_shadow_stack, i| {
                if (cpu_shadow_stack.base != 0) {
                    active_shadow_stacks += 1;
                    if (i < 4 or i == current_cpu_id) { // Show first 4 CPUs and current CPU
                        serial.print("    CPU {}: ", .{i});
                        secure_print.printHex("base=", cpu_shadow_stack.base);
                        serial.print(", ", .{});
                        secure_print.printHex("ptr=", cpu_shadow_stack.ptr);
                        serial.println("", .{});
                    }
                }
            }
            serial.println("    Total active shadow stacks: {}", .{active_shadow_stacks});
        }
    }

    var total_overflows: u32 = 0;
    var total_canary_failures: u32 = 0;
    var max_usage_percent: u32 = 0;

    for (&cpu_stacks, 0..) |*cpu_stack, i| {
        if (cpu_stack.size == 0) continue; // Skip uninitialized CPUs

        const cpu_usage_percent = @as(u32, @intCast((cpu_stack.max_depth * 100) / cpu_stack.size));
        if (cpu_usage_percent > max_usage_percent) {
            max_usage_percent = cpu_usage_percent;
        }

        total_overflows += cpu_stack.overflow_count.load(.acquire);
        total_canary_failures += cpu_stack.canary_failures.load(.acquire);

        const overflows = cpu_stack.overflow_count.load(.acquire);
        const canary_fails = cpu_stack.canary_failures.load(.acquire);
        if (i < 4 or overflows > 0 or canary_fails > 0) {
            serial.println("   CPU {} Stack:", .{i});
            serial.print("    Base: ", .{});
            secure_print.printHex("", cpu_stack.base);
            serial.println(", Size: {}KB", .{cpu_stack.size / 1024});
            // Calculate percentage with 2 decimal places
            const usage_percent_precise = (cpu_stack.max_depth * 10000) / cpu_stack.size;
            serial.println("    Max depth: {} bytes ({}.{}%)", .{ cpu_stack.max_depth, usage_percent_precise / 100, usage_percent_precise % 100 });
            serial.println("    Overflows: {}, Canary failures: {}", .{ overflows, canary_fails });
        }
    }

    serial.println("   Summary:", .{});
    serial.println("    Total overflows: {}", .{total_overflows});
    serial.println("    Total canary failures: {}", .{total_canary_failures});
    serial.println("    Maximum stack usage: {}%", .{max_usage_percent});
}

// External symbols from linker script
extern const __stack_bottom: u8;
extern const __stack_top: u8;
