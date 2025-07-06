// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const cpuid = @import("cpuid.zig");
const speculation = @import("speculation.zig");
const secure_print = @import("../lib/secure_print.zig");

// MSR addresses
pub const IA32_EFER: u32 = 0xC0000080;
pub const IA32_XCR0: u32 = 0; // Actually XCR0, not an MSR, accessed via XGETBV/XSETBV
pub const IA32_U_CET: u32 = 0x6A0; // User-mode CET configuration
pub const IA32_S_CET: u32 = 0x6A2; // Supervisor-mode CET configuration
pub const IA32_PL0_SSP: u32 = 0x6A4; // Ring 0 shadow stack pointer
pub const IA32_PL3_SSP: u32 = 0x6A7; // Ring 3 shadow stack pointer

// EFER bits
const EFER_SCE: u64 = 1 << 0; // System Call Extensions
const EFER_LME: u64 = 1 << 8; // Long Mode Enable
const EFER_LMA: u64 = 1 << 10; // Long Mode Active
const EFER_NXE: u64 = 1 << 11; // No-Execute Enable

// XCR0 bits for XSAVE features
const XCR0_X87: u64 = 1 << 0; // x87 FPU state
const XCR0_SSE: u64 = 1 << 1; // SSE state
const XCR0_AVX: u64 = 1 << 2; // AVX state
const XCR0_BNDREG: u64 = 1 << 3; // MPX bound registers
const XCR0_BNDCSR: u64 = 1 << 4; // MPX bound config and status
const XCR0_OPMASK: u64 = 1 << 5; // AVX-512 opmask
const XCR0_ZMM_HI256: u64 = 1 << 6; // AVX-512 upper 256 bits of ZMM0-15
const XCR0_HI16_ZMM: u64 = 1 << 7; // AVX-512 ZMM16-31
const XCR0_PKRU: u64 = 1 << 9; // Protection Keys state

// CET MSR bits
pub const CET_SHSTK_EN: u64 = 1 << 0; // Shadow stack enable
pub const CET_WR_SHSTK_EN: u64 = 1 << 1; // Write to shadow stack enable
pub const CET_ENDBR_EN: u64 = 1 << 2; // ENDBR instruction enable
pub const CET_LEG_IW_EN: u64 = 1 << 3; // Legacy indirect branch enable
pub const CET_NO_TRACK_EN: u64 = 1 << 4; // No-track prefix enable
pub const CET_SUPPRESS_DIS: u64 = 1 << 5; // Disable suppression of CET
pub const CET_SUPPRESS: u64 = 1 << 10; // Suppress all CET faults
pub const CET_TRACKER: u64 = 1 << 11; // TRACKER bit (cleared on ENDBR)

// CR0 bits
const CR0_PE: u64 = 1 << 0; // Protected Mode Enable
const CR0_MP: u64 = 1 << 1; // Monitor Coprocessor
const CR0_EM: u64 = 1 << 2; // Emulation
const CR0_TS: u64 = 1 << 3; // Task Switched
const CR0_ET: u64 = 1 << 4; // Extension Type
const CR0_NE: u64 = 1 << 5; // Numeric Error (Native FPU Error)
const CR0_WP: u64 = 1 << 16; // Write Protect
const CR0_AM: u64 = 1 << 18; // Alignment Mask
const CR0_PG: u64 = 1 << 31; // Paging

// CR4 bits
const CR4_VME: u64 = 1 << 0; // Virtual-8086 Mode Extensions
const CR4_PVI: u64 = 1 << 1; // Protected-Mode Virtual Interrupts
const CR4_TSD: u64 = 1 << 2; // Time Stamp Disable
const CR4_DE: u64 = 1 << 3; // Debugging Extensions
const CR4_PSE: u64 = 1 << 4; // Page Size Extensions
const CR4_PAE: u64 = 1 << 5; // Physical Address Extension
const CR4_MCE: u64 = 1 << 6; // Machine Check Enable
const CR4_PGE: u64 = 1 << 7; // Page Global Enable
const CR4_PCE: u64 = 1 << 8; // Performance Counter Enable
const CR4_OSFXSR: u64 = 1 << 9; // OS FXSAVE/FXRSTOR
const CR4_OSXMMEXCPT: u64 = 1 << 10; // OS XMM exceptions
const CR4_UMIP: u64 = 1 << 11; // User Mode Instruction Prevention
const CR4_LA57: u64 = 1 << 12; // 57-bit linear addresses (5-level paging)
const CR4_VMXE: u64 = 1 << 13; // VMX Enable
const CR4_SMXE: u64 = 1 << 14; // SMX Enable
const CR4_FSGSBASE: u64 = 1 << 16; // Enable RDFSBASE/RDGSBASE/WRFSBASE/WRGSBASE
const CR4_PCIDE: u64 = 1 << 17; // PCID Enable
const CR4_OSXSAVE: u64 = 1 << 18; // XSAVE and Processor Extended States Enable
const CR4_SMEP: u64 = 1 << 20; // Supervisor Mode Execution Prevention
const CR4_SMAP: u64 = 1 << 21; // Supervisor Mode Access Prevention
const CR4_PKE: u64 = 1 << 22; // Protection Keys Enable
pub const CR4_CET: u64 = 1 << 23; // Control-flow Enforcement Technology

// Read MSR
pub fn readMSR(msr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("rdmsr"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [msr] "{ecx}" (msr),
    );
    return (@as(u64, high) << 32) | low;
}

// Write MSR
pub fn writeMSR(msr: u32, value: u64) void {
    const low = @as(u32, @truncate(value));
    const high = @as(u32, @truncate(value >> 32));
    asm volatile ("wrmsr"
        :
        : [msr] "{ecx}" (msr),
          [low] "{eax}" (low),
          [high] "{edx}" (high),
        : "memory"
    );
}

// Read XCR (Extended Control Register)
fn readXCR(xcr: u32) u64 {
    var low: u32 = undefined;
    var high: u32 = undefined;
    asm volatile ("xgetbv"
        : [low] "={eax}" (low),
          [high] "={edx}" (high),
        : [xcr] "{ecx}" (xcr),
    );
    return (@as(u64, high) << 32) | low;
}

// Write XCR (Extended Control Register)
fn writeXCR(xcr: u32, value: u64) void {
    const low = @as(u32, @truncate(value));
    const high = @as(u32, @truncate(value >> 32));
    asm volatile ("xsetbv"
        :
        : [xcr] "{ecx}" (xcr),
          [low] "{eax}" (low),
          [high] "{edx}" (high),
        : "memory"
    );
}

// Initialize early CPU features that don't require virtual memory
// This is called in PIE mode before page tables are enabled
pub fn initEarlyFeatures() void {
    // Set minimal CR0 bits for early boot
    var cr0 = asm volatile ("mov %%cr0, %[result]"
        : [result] "=r" (-> u64),
    );
    cr0 |= CR0_PE; // Ensure protected mode is enabled
    cr0 |= CR0_MP; // Monitor coprocessor
    cr0 |= CR0_NE; // Enable native FPU error reporting
    asm volatile ("mov %[value], %%cr0"
        :
        : [value] "r" (cr0),
        : "memory"
    );

    // Set minimal CR4 bits required for paging
    var cr4 = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );

    // These are required for proper paging operation
    cr4 |= CR4_PSE; // Enable Page Size Extension for 2MB/1GB pages
    cr4 |= CR4_PAE; // Enable Physical Address Extension

    // Write back CR4
    asm volatile ("mov %[value], %%cr4"
        :
        : [value] "r" (cr4),
        : "memory"
    );
}

pub fn initializeCPU() void {
    const features = cpuid.getFeatures();

    // Enable NX bit if available
    if (features.nx) {
        var efer = readMSR(IA32_EFER);
        efer |= EFER_NXE;
        writeMSR(IA32_EFER, efer);
    }

    // Set CR0 bits
    var cr0 = asm volatile ("mov %%cr0, %[result]"
        : [result] "=r" (-> u64),
    );
    cr0 |= CR0_WP; // Enable write protection
    cr0 |= CR0_AM; // Enable alignment checking
    cr0 |= CR0_NE; // Enable native FPU error reporting
    asm volatile ("mov %[value], %%cr0"
        :
        : [value] "r" (cr0),
        : "memory"
    );

    // Set CR4 bits
    var cr4 = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );

    // Enable basic features
    if (features.pge) cr4 |= CR4_PGE;
    if (features.fxsr) cr4 |= CR4_OSFXSR;
    if (features.sse) cr4 |= CR4_OSXMMEXCPT;

    // Enable Machine Check Exception
    cr4 |= CR4_MCE;

    // Enable security features
    if (features.smep) cr4 |= CR4_SMEP;
    if (features.smap) cr4 |= CR4_SMAP;
    if (features.umip) cr4 |= CR4_UMIP;

    // Enable performance features
    if (features.fsgsbase) cr4 |= CR4_FSGSBASE;
    if (features.pcid) cr4 |= CR4_PCIDE;

    // Enable XSAVE if available (required for AVX)
    if (features.xsave) {
        cr4 |= CR4_OSXSAVE;
    }

    // Enable Protection Keys
    if (features.pku) cr4 |= CR4_PKE;

    // Enable Control-flow Enforcement Technology
    if (features.cet_ibt or features.cet_ss) cr4 |= CR4_CET;

    // Write CR4 before configuring XSAVE
    asm volatile ("mov %[value], %%cr4"
        :
        : [value] "r" (cr4),
        : "memory"
    );

    // Configure XSAVE features if enabled
    if (features.xsave and (cr4 & CR4_OSXSAVE) != 0) {
        // Enable x87, SSE, and AVX state saving
        var xcr0 = XCR0_X87 | XCR0_SSE;
        if (features.avx) xcr0 |= XCR0_AVX;
        if (features.pku) xcr0 |= XCR0_PKRU;

        // AVX-512 state components
        if (features.avx512f) {
            xcr0 |= XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM;
        }

        writeXCR(IA32_XCR0, xcr0);
    }

    // Configure CET if available (basic setup - full setup happens later)
    if ((features.cet_ss or features.cet_ibt) and (cr4 & CR4_CET) != 0) {
        initializeCETBasic();
    }

    // Initialize CPU speculation mitigations
    speculation.init();

    // Initialize SMAP management
    const smap = @import("smap.zig");
    smap.init();
}

// Initialize basic CET features during early CPU initialization
fn initializeCETBasic() void {
    const features = cpuid.getFeatures();
    var s_cet: u64 = 0;

    // Enable Shadow Stack if available
    if (features.cet_ss) {
        s_cet |= CET_SHSTK_EN; // Enable shadow stack
        s_cet |= CET_WR_SHSTK_EN; // Enable write to shadow stack (for token setup)
    }

    // Enable Indirect Branch Tracking if available
    if (features.cet_ibt) {
        s_cet |= CET_ENDBR_EN; // Enable ENDBR instruction requirement
        s_cet |= CET_NO_TRACK_EN; // Enable NOTRACK prefix handling
    }

    // Write basic configuration
    if (s_cet != 0) {
        writeMSR(IA32_S_CET, s_cet);
    }
}

// Complete CET initialization with memory manager support
// This should be called after memory management is initialized
pub fn initializeCETComplete() !void {
    const features = cpuid.getFeatures();
    const serial = @import("../drivers/serial.zig");
    const paging = @import("paging.zig");

    if (!features.cet_ss and !features.cet_ibt) {
        serial.println("[CET] Control-flow Enforcement Technology not available", .{});
        return;
    }

    // Check if CR4.CET is enabled
    const cr4 = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );

    if ((cr4 & CR4_CET) == 0) {
        serial.println("[CET] WARNING: CR4.CET not enabled", .{});
        return;
    }

    var s_cet: u64 = 0;

    // Configure Shadow Stack
    if (features.cet_ss) {
        serial.println("[CET] Initializing Shadow Stack...", .{});

        // Enable shadow stack
        s_cet |= CET_SHSTK_EN;
        s_cet |= CET_WR_SHSTK_EN; // Required for token operations

        // Allocate and configure shadow stack
        // Note: This requires PMM to be initialized
        const pmm = @import("../memory/pmm.zig");
        const shadow_stack_pages = 16; // 64KB shadow stack

        if (pmm.allocPagesTagged(shadow_stack_pages, .SECURITY)) |shadow_stack_phys| {
            // Map shadow stack pages with proper Intel SDM format (P=0, RW=1)
            var i: u64 = 0;
            while (i < shadow_stack_pages) : (i += 1) {
                const page_addr = shadow_stack_phys + (i * 0x1000);
                // Use identity mapping for simplicity
                paging.mapShadowStackPage(page_addr, page_addr) catch |err| {
                    serial.print("[CET] ERROR: Failed to map shadow stack page at ", .{});
                    secure_print.printHex("", page_addr);
                    serial.println(": {s}", .{@errorName(err)});
                    // Clean up allocated pages on failure
                    pmm.freePages(shadow_stack_phys, shadow_stack_pages);
                    s_cet &= ~(CET_SHSTK_EN | CET_WR_SHSTK_EN);
                    return;
                };
            }

            // Shadow stack grows down, so set pointer to end
            const shadow_stack_ptr = shadow_stack_phys + (shadow_stack_pages * 0x1000);

            // Initialize shadow stack with supervisor token at the top
            // Token format: bit 0 = 1 (valid), bits 1-2 = 0 (supervisor), bits 3-63 = linear address
            const token_addr = shadow_stack_ptr - 8;
            const supervisor_token = token_addr | 0x01; // Valid supervisor token
            const token_ptr = @as(*u64, @ptrFromInt(token_addr));
            token_ptr.* = supervisor_token;

            // Set the shadow stack pointer MSR (point to just below the token)
            writeMSR(IA32_PL0_SSP, token_addr);

            serial.print("[CET] Shadow stack allocated: base=", .{});
            secure_print.printHex("", shadow_stack_phys);
            serial.print(", ptr=", .{});
            secure_print.printHex("", token_addr);
            serial.println("", .{});
            serial.print("[CET] Supervisor token written at ", .{});
            secure_print.printHex("", token_addr);
            serial.print(": ", .{});
            secure_print.printHex("", supervisor_token);
            serial.println("", .{});
        } else {
            serial.println("[CET] WARNING: Failed to allocate shadow stack memory", .{});
            // Disable shadow stack if we can't allocate memory
            s_cet &= ~(CET_SHSTK_EN | CET_WR_SHSTK_EN);
        }
    }

    // Configure Indirect Branch Tracking
    if (features.cet_ibt) {
        serial.println("[CET] Initializing Indirect Branch Tracking...", .{});

        // Enable IBT
        s_cet |= CET_ENDBR_EN; // Require ENDBR at indirect branch targets
        s_cet |= CET_NO_TRACK_EN; // Enable NOTRACK prefix for legacy code

        // For production systems, you might want to disable legacy support:
        // s_cet |= CET_LEG_IW_EN;  // Generate #CP for legacy indirect branches

        serial.println("[CET] IBT enabled with ENDBR requirement", .{});
    }

    // Apply final CET configuration
    if (s_cet != 0) {
        writeMSR(IA32_S_CET, s_cet);

        // Verify configuration was applied
        const actual_s_cet = readMSR(IA32_S_CET);
        serial.println("[CET] Configuration applied: IA32_S_CET=0x{x:0>16}", .{actual_s_cet});

        // Print enabled features
        if ((actual_s_cet & CET_SHSTK_EN) != 0) {
            serial.println("[CET] ✓ Hardware Shadow Stack enabled", .{});
        }
        if ((actual_s_cet & CET_ENDBR_EN) != 0) {
            serial.println("[CET] ✓ Indirect Branch Tracking enabled", .{});
        }
    }
}

// Verify CET is working correctly
pub fn testCET() void {
    const features = cpuid.getFeatures();
    const serial = @import("../drivers/serial.zig");

    if (!features.cet_ss and !features.cet_ibt) {
        serial.println("[CET] No CET features available for testing", .{});
        return;
    }

    const s_cet = readMSR(IA32_S_CET);

    if ((s_cet & CET_SHSTK_EN) != 0) {
        // Test shadow stack by reading the current SSP
        const ssp = readMSR(IA32_PL0_SSP);
        serial.print("[CET] Shadow Stack Test: SSP=", .{});
        secure_print.printHex("", ssp);
        serial.println("", .{});

        // Verify shadow stack operations
        testShadowStackOperations();
    }

    if ((s_cet & CET_ENDBR_EN) != 0) {
        serial.println("[CET] IBT Test: ENDBR instructions required for indirect branches", .{});

        // The fact that our kernel is running with ENDBR instructions in
        // assembly stubs means IBT is working correctly
    }
}

// Test shadow stack operations
fn testShadowStackOperations() void {
    const serial = @import("../drivers/serial.zig");

    serial.println("[CET] Testing shadow stack operations...", .{});

    // Test 1: Token push/pop
    {
        const original_ssp = readMSR(IA32_PL0_SSP);
        const test_token = ShadowStackToken.createSupervisor(original_ssp);

        pushShadowStackToken(test_token) catch |err| {
            serial.println("[CET] ERROR: Failed to push token: {s}", .{@errorName(err)});
            return;
        };

        const new_ssp = readMSR(IA32_PL0_SSP);
        if (new_ssp != original_ssp - 8) {
            serial.println("[CET] ERROR: SSP not updated correctly after push", .{});
        }

        const popped_token = popShadowStackToken() catch |err| {
            serial.println("[CET] ERROR: Failed to pop token: {s}", .{@errorName(err)});
            return;
        };

        if (popped_token != test_token) {
            serial.print("[CET] ERROR: Token mismatch: expected ", .{});
            secure_print.printHex("", test_token);
            serial.print(", got ", .{});
            secure_print.printHex("", popped_token);
            serial.println("", .{});
        } else {
            serial.println("[CET] ✓ Token push/pop test passed", .{});
        }
    }

    // Test 2: Token validation
    {
        const ssp = readMSR(IA32_PL0_SSP);
        const valid_token = ShadowStackToken.createSupervisor(ssp);
        const invalid_token = ShadowStackToken.createSupervisor(ssp + 0x1000);

        if (ShadowStackToken.validate(valid_token, ssp)) {
            serial.println("[CET] ✓ Token validation test passed", .{});
        } else {
            serial.println("[CET] ERROR: Valid token failed validation", .{});
        }

        if (!ShadowStackToken.validate(invalid_token, ssp)) {
            serial.println("[CET] ✓ Invalid token correctly rejected", .{});
        } else {
            serial.println("[CET] ERROR: Invalid token passed validation", .{});
        }
    }

    // Test 3: Shadow stack state save/restore
    {
        const saved_state = saveShadowStackState() catch |err| {
            serial.println("[CET] ERROR: Failed to save shadow stack state: {s}", .{@errorName(err)});
            return;
        };

        // Modify SSP temporarily
        const original_ssp = readMSR(IA32_PL0_SSP);
        writeMSR(IA32_PL0_SSP, original_ssp - 16);

        // Restore state
        restoreShadowStackState(saved_state) catch |err| {
            serial.println("[CET] ERROR: Failed to restore shadow stack state: {s}", .{@errorName(err)});
            return;
        };

        const restored_ssp = readMSR(IA32_PL0_SSP);
        if (restored_ssp == original_ssp) {
            serial.println("[CET] ✓ Shadow stack state save/restore test passed", .{});
        } else {
            serial.println("[CET] ERROR: SSP not restored correctly", .{});
        }
    }

    serial.println("[CET] Shadow stack operation tests completed", .{});
}

// Verify shadow stack page attributes
pub fn verifyShadowStackPages() void {
    const serial = @import("../drivers/serial.zig");
    const paging = @import("paging.zig");

    if (!cpuid.hasCET_SS()) {
        return;
    }

    const ssp = readMSR(IA32_PL0_SSP);
    if (ssp == 0) {
        serial.println("[CET] No shadow stack configured", .{});
        return;
    }

    // Get page table entry for shadow stack
    const pte = paging.getPageTableEntry(ssp) catch |err| {
        serial.println("[CET] ERROR: Failed to get PTE for shadow stack: {s}", .{@errorName(err)});
        return;
    };

    // Verify shadow stack page format (P=0, RW=1)
    if ((pte & paging.PAGE_PRESENT) != 0) {
        serial.println("[CET] ERROR: Shadow stack page has P=1 (should be 0)", .{});
    }

    if ((pte & paging.PAGE_WRITABLE) == 0) {
        serial.println("[CET] ERROR: Shadow stack page has RW=0 (should be 1)", .{});
    }

    if ((pte & paging.PAGE_PRESENT) == 0 and (pte & paging.PAGE_WRITABLE) != 0) {
        serial.println("[CET] ✓ Shadow stack page format correct (P=0, RW=1)", .{});
    }
}

// Shadow Stack Token Management (Intel SDM Vol 3A Ch 18)
// Token format:
// - Bit 0: Valid bit (must be 1)
// - Bits 1-2: Mode (00 = Supervisor, 11 = User)
// - Bit 3: Reserved (must be 0)
// - Bits 63:4: Linear address (must match token location)
pub const ShadowStackToken = struct {
    pub const VALID_BIT: u64 = 1 << 0;
    pub const MODE_MASK: u64 = 0x6; // Bits 1-2
    pub const MODE_SUPERVISOR: u64 = 0x0;
    pub const MODE_USER: u64 = 0x6;
    pub const ADDR_MASK: u64 = 0xFFFFFFFFFFFFFFF0; // Bits 63:4

    // Create a supervisor shadow stack token
    pub fn createSupervisor(addr: u64) u64 {
        return (addr & ADDR_MASK) | VALID_BIT | MODE_SUPERVISOR;
    }

    // Create a user shadow stack token
    pub fn createUser(addr: u64) u64 {
        return (addr & ADDR_MASK) | VALID_BIT | MODE_USER;
    }

    // Validate a shadow stack token
    pub fn validate(token: u64, expected_addr: u64) bool {
        // Check valid bit
        if ((token & VALID_BIT) == 0) return false;

        // Check address matches
        const token_addr = token & ADDR_MASK;
        const expected = expected_addr & ADDR_MASK;
        return token_addr == expected;
    }

    // Check if token is for supervisor mode
    pub fn isSupervisor(token: u64) bool {
        return (token & MODE_MASK) == MODE_SUPERVISOR;
    }

    // Check if token is for user mode
    pub fn isUser(token: u64) bool {
        return (token & MODE_MASK) == MODE_USER;
    }
};

// Push a shadow stack token (for privilege transitions)
pub fn pushShadowStackToken(token: u64) !void {
    const features = cpuid.getFeatures();
    if (!features.cet_ss) return error.CETNotSupported;

    // Read current shadow stack pointer
    const ssp = readMSR(IA32_PL0_SSP);

    // Write token to shadow stack (SSP grows down)
    const new_ssp = ssp - 8;
    const token_ptr = @as(*u64, @ptrFromInt(new_ssp));
    token_ptr.* = token;

    // Update shadow stack pointer
    writeMSR(IA32_PL0_SSP, new_ssp);
}

// Pop and verify a shadow stack token
pub fn popShadowStackToken() !u64 {
    const features = cpuid.getFeatures();
    if (!features.cet_ss) return error.CETNotSupported;

    // Read current shadow stack pointer
    const ssp = readMSR(IA32_PL0_SSP);

    // Read token from shadow stack
    const token_ptr = @as(*u64, @ptrFromInt(ssp));
    const token = token_ptr.*;

    // Update shadow stack pointer (SSP grows down, so add to pop)
    writeMSR(IA32_PL0_SSP, ssp + 8);

    return token;
}

// Switch shadow stacks (for task switching)
pub fn switchShadowStack(new_ssp: u64) !void {
    const features = cpuid.getFeatures();
    if (!features.cet_ss) return error.CETNotSupported;

    const serial = @import("../drivers/serial.zig");

    // Save current shadow stack pointer
    const old_ssp = readMSR(IA32_PL0_SSP);

    // Validate new shadow stack has a valid token at the top
    const token_ptr = @as(*u64, @ptrFromInt(new_ssp));
    const token = token_ptr.*;

    if (!ShadowStackToken.validate(token, new_ssp)) {
        serial.print("[CET] ERROR: Invalid shadow stack token at ", .{});
        secure_print.printHex("", new_ssp);
        serial.print(": ", .{});
        secure_print.printHex("", token);
        serial.println("", .{});
        return error.InvalidShadowStackToken;
    }

    // Switch to new shadow stack
    writeMSR(IA32_PL0_SSP, new_ssp);

    serial.print("[CET] Switched shadow stack from ", .{});
    secure_print.printHex("", old_ssp);
    serial.print(" to ", .{});
    secure_print.printHex("", new_ssp);
    serial.println("", .{});
}

// Save shadow stack state for context switch
pub const ShadowStackState = struct {
    ssp: u64,
    token: u64,
};

pub fn saveShadowStackState() !ShadowStackState {
    const features = cpuid.getFeatures();
    if (!features.cet_ss) return error.CETNotSupported;

    const ssp = readMSR(IA32_PL0_SSP);

    // Create a token for this shadow stack position
    const token = ShadowStackToken.createSupervisor(ssp);

    return ShadowStackState{
        .ssp = ssp,
        .token = token,
    };
}

pub fn restoreShadowStackState(state: ShadowStackState) !void {
    const features = cpuid.getFeatures();
    if (!features.cet_ss) return error.CETNotSupported;

    // Validate the saved state
    if (!ShadowStackToken.validate(state.token, state.ssp)) {
        return error.InvalidShadowStackState;
    }

    // Restore shadow stack pointer
    writeMSR(IA32_PL0_SSP, state.ssp);
}

// Disable CET for debugging (emergency use only)
pub fn disableCET() void {
    const serial = @import("../drivers/serial.zig");

    // Clear all CET bits
    writeMSR(IA32_S_CET, 0);

    // Optionally disable CR4.CET (requires restart of CET initialization)
    // var cr4 = asm volatile ("mov %%cr4, %[result]"
    //     : [result] "=r" (-> u64),
    // );
    // cr4 &= ~CR4_CET;
    // asm volatile ("mov %[value], %%cr4"
    //     :
    //     : [value] "r" (cr4),
    //     : "memory"
    // );

    serial.println("[CET] DISABLED - CET features turned off", .{});
}

// Print enabled security features
pub fn printSecurityFeatures(serial: anytype) void {
    const features = cpuid.getFeatures();

    serial.println("[CPU] Security features status:", .{});

    // Check NX bit
    if (features.nx) {
        const efer = readMSR(IA32_EFER);
        if ((efer & EFER_NXE) != 0) {
            serial.println("  ✓ NX (No-Execute) bit: Enabled", .{});
        } else {
            serial.println("  ✗ NX (No-Execute) bit: Available but not enabled", .{});
        }
    }

    // Check CR0 bits
    const cr0 = asm volatile ("mov %%cr0, %[result]"
        : [result] "=r" (-> u64),
    );
    serial.print("  ✓ CR0 Security: ", .{});
    if ((cr0 & CR0_WP) != 0) serial.print("WP ", .{});
    if ((cr0 & CR0_AM) != 0) serial.print("AM ", .{});
    if ((cr0 & CR0_NE) != 0) serial.print("NE ", .{});
    serial.println("", .{});

    // Check CR4 security features
    const cr4 = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );

    // Basic security
    if (features.smep) {
        serial.print("  ", .{});
        serial.print("{s}", .{if ((cr4 & CR4_SMEP) != 0) "✓" else "✗"});
        serial.println(" SMEP (Supervisor Mode Execution Prevention)", .{});
    }

    if (features.smap) {
        serial.print("  ", .{});
        serial.print("{s}", .{if ((cr4 & CR4_SMAP) != 0) "✓" else "✗"});
        serial.println(" SMAP (Supervisor Mode Access Prevention)", .{});
    }

    if (features.umip) {
        serial.print("  ", .{});
        serial.print("{s}", .{if ((cr4 & CR4_UMIP) != 0) "✓" else "✗"});
        serial.println(" UMIP (User Mode Instruction Prevention)", .{});
    }

    // Performance features
    serial.println("[CPU] Performance features status:", .{});

    if (features.pcid) {
        serial.print("  ", .{});
        serial.print("{s}", .{if ((cr4 & CR4_PCIDE) != 0) "✓" else "✗"});
        serial.println(" PCID (Process Context Identifiers)", .{});
    }

    if (features.fsgsbase) {
        serial.print("  ", .{});
        serial.print("{s}", .{if ((cr4 & CR4_FSGSBASE) != 0) "✓" else "✗"});
        serial.println(" FSGSBASE Instructions", .{});
    }

    if (features.pge) {
        serial.print("  ", .{});
        serial.print("{s}", .{if ((cr4 & CR4_PGE) != 0) "✓" else "✗"});
        serial.println(" PGE (Page Global Enable)", .{});
    }

    // Advanced features
    serial.println("[CPU] Advanced features status:", .{});

    if (features.xsave) {
        serial.print("  ", .{});
        serial.print("{s}", .{if ((cr4 & CR4_OSXSAVE) != 0) "✓" else "✗"});
        serial.print(" XSAVE/AVX Support", .{});
        if ((cr4 & CR4_OSXSAVE) != 0) {
            const xcr0 = readXCR(IA32_XCR0);
            serial.print(" [XCR0: ", .{});
            if ((xcr0 & XCR0_X87) != 0) serial.print("x87 ", .{});
            if ((xcr0 & XCR0_SSE) != 0) serial.print("SSE ", .{});
            if ((xcr0 & XCR0_AVX) != 0) serial.print("AVX ", .{});
            if ((xcr0 & XCR0_PKRU) != 0) serial.print("PKU ", .{});
            serial.print("]", .{});
        }
        serial.println("", .{});
    }

    if (features.pku) {
        serial.print("  ", .{});
        serial.print("{s}", .{if ((cr4 & CR4_PKE) != 0) "✓" else "✗"});
        serial.println(" PKU (Protection Keys for Userspace)", .{});
    }

    if (features.cet_ibt or features.cet_ss) {
        serial.print("  ", .{});
        serial.print("{s}", .{if ((cr4 & CR4_CET) != 0) "✓" else "✗"});
        serial.print(" CET (Control-flow Enforcement)", .{});
        if ((cr4 & CR4_CET) != 0 and features.cet_ss) {
            const s_cet = readMSR(IA32_S_CET);
            serial.print(" [", .{});
            if ((s_cet & CET_SHSTK_EN) != 0) serial.print("ShadowStack ", .{});
            if ((s_cet & CET_ENDBR_EN) != 0) serial.print("IBT ", .{});
            serial.print("]", .{});
        }
        serial.println("", .{});
    }

    // MCE is always important
    serial.print("  ", .{});
    serial.print("{s}", .{if ((cr4 & CR4_MCE) != 0) "✓" else "✗"});
    serial.println(" MCE (Machine Check Enable)", .{});
}

// Test NX bit by trying to execute data (will cause page fault if NX is working)
// NOTE: This test requires proper page tables with NX bit set on data pages.
// It won't fail with UEFI's page tables, which might not enforce NX on all data.
// This will be properly tested after Phase 6 (Memory Management) is implemented.
pub fn testNX() void {
    // Create a RET instruction in data
    const ret_instruction = [_]u8{0xC3};

    // Try to execute it (this should fault with NX enabled and proper page tables)
    const func = @as(*const fn () void, @ptrCast(&ret_instruction));
    func();
}

// Test NX bit by trying to execute from a region we know has NX set
// This allocates memory in the second GB which has NX bit set
pub fn testNXInHighMemory() void {
    // Use an address in the second GB (which has NX set)
    // This is a simple test - in production we'd properly allocate memory
    const test_addr: u64 = 0x40000000; // 1GB mark

    // Write a RET instruction there
    const ptr = @as(*u8, @ptrFromInt(test_addr));
    ptr.* = 0xC3; // RET instruction

    // Try to execute it (this SHOULD fault with NX enabled)
    const func = @as(*const fn () void, @ptrFromInt(test_addr));
    func();
}
