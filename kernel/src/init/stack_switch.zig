// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");

// Switch to a new stack and continue execution
// This function never returns - it jumps directly to the continuation
// Must be noinline to ensure proper stack frame handling
pub noinline fn switchStackAndContinue(
    new_stack_top: u64,
    continuation: *const fn () noreturn,
) noreturn {
    // Switch to new stack and jump to continuation
    // This uses inline assembly to ensure atomic switch
    asm volatile (
        \\mov %[stack], %%rsp
        \\jmp *%[cont]
        :
        : [stack] "r" (new_stack_top),
          [cont] "r" (continuation),
        : "memory"
    );
    unreachable;
}
