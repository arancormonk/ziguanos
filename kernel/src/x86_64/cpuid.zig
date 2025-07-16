// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");

// CPUID result structure
pub const CPUIDResult = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

// CPU features structure
pub const CPUFeatures = struct {
    // Basic features (EDX from leaf 1)
    fpu: bool = false, // x87 FPU
    pse: bool = false, // Page Size Extension
    tsc: bool = false, // Time Stamp Counter
    pae: bool = false, // Physical Address Extension
    msr: bool = false, // Model Specific Registers
    apic: bool = false, // APIC
    mtrr: bool = false, // Memory Type Range Registers
    pge: bool = false, // Page Global Enable
    pat: bool = false, // Page Attribute Table
    pse36: bool = false, // 36-bit Page Size Extension
    mmx: bool = false, // MMX
    fxsr: bool = false, // FXSAVE/FXRSTOR
    sse: bool = false, // SSE
    sse2: bool = false, // SSE2

    // Extended features (ECX from leaf 1)
    sse3: bool = false, // SSE3
    ssse3: bool = false, // SSSE3
    sse41: bool = false, // SSE4.1
    sse42: bool = false, // SSE4.2
    avx: bool = false, // AVX
    rdrand: bool = false, // RDRAND instruction
    pcid: bool = false, // Process Context Identifiers
    x2apic: bool = false, // x2APIC support
    xsave: bool = false, // XSAVE/XRSTOR support
    osxsave: bool = false, // OS has enabled XSAVE
    rdseed: bool = false, // RDSEED instruction

    // Extended features (EBX from leaf 7, subleaf 0)
    fsgsbase: bool = false, // FSGSBASE instructions
    smep: bool = false, // Supervisor Mode Execution Prevention
    invpcid: bool = false, // INVPCID instruction
    avx2: bool = false, // AVX2
    bmi2: bool = false, // Bit Manipulation Instructions 2
    rdseed_ebx: bool = false, // RDSEED (from EBX)
    smap: bool = false, // Supervisor Mode Access Prevention
    avx512f: bool = false, // AVX-512 Foundation
    avx512dq: bool = false, // AVX-512 Doubleword and Quadword
    avx512cd: bool = false, // AVX-512 Conflict Detection
    avx512bw: bool = false, // AVX-512 Byte and Word
    avx512vl: bool = false, // AVX-512 Vector Length Extensions

    // Extended features (ECX from leaf 7, subleaf 0)
    pku: bool = false, // Protection Keys for Userspace
    umip: bool = false, // User Mode Instruction Prevention
    la57: bool = false, // 5-level paging (57-bit linear addresses)
    rdpid: bool = false, // RDPID instruction

    // Extended features (EDX from leaf 7, subleaf 0)
    tsx_ctrl: bool = false, // TSX Control MSR
    pconfig: bool = false, // Platform configuration
    cet_ibt: bool = false, // Control-flow Enforcement: Indirect Branch Tracking
    cet_ss: bool = false, // Control-flow Enforcement: Shadow Stack
    spec_ctrl: bool = false, // IA32_SPEC_CTRL MSR available
    arch_capabilities: bool = false, // IA32_ARCH_CAPABILITIES MSR
    ibrs_ibpb: bool = false, // IBRS and IBPB supported
    stibp: bool = false, // STIBP supported
    ssbd: bool = false, // SSBD supported
    l1d_flush: bool = false, // IA32_FLUSH_CMD MSR
    md_clear: bool = false, // MD_CLEAR functionality

    // Extended processor info (EDX from leaf 0x80000001)
    nx: bool = false, // No-Execute bit
    gbpages: bool = false, // 1GB pages
    rdtscp: bool = false, // RDTSCP instruction
    lm: bool = false, // Long Mode (64-bit)
};

var cpu_features: CPUFeatures = .{};

// Execute CPUID instruction
fn cpuid(leaf: u32, subleaf: u32) CPUIDResult {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [subleaf] "{ecx}" (subleaf),
    );

    return CPUIDResult{
        .eax = eax,
        .ebx = ebx,
        .ecx = ecx,
        .edx = edx,
    };
}

pub fn detectFeatures() void {
    // Basic features (leaf 1)
    const basic = cpuid(1, 0);

    // Parse EDX
    cpu_features.fpu = (basic.edx & (1 << 0)) != 0;
    cpu_features.pse = (basic.edx & (1 << 3)) != 0;
    cpu_features.tsc = (basic.edx & (1 << 4)) != 0;
    cpu_features.pae = (basic.edx & (1 << 6)) != 0;
    cpu_features.msr = (basic.edx & (1 << 5)) != 0;
    cpu_features.apic = (basic.edx & (1 << 9)) != 0;
    cpu_features.mtrr = (basic.edx & (1 << 12)) != 0;
    cpu_features.pge = (basic.edx & (1 << 13)) != 0;
    cpu_features.pat = (basic.edx & (1 << 16)) != 0;
    cpu_features.pse36 = (basic.edx & (1 << 17)) != 0;
    cpu_features.mmx = (basic.edx & (1 << 23)) != 0;
    cpu_features.fxsr = (basic.edx & (1 << 24)) != 0;
    cpu_features.sse = (basic.edx & (1 << 25)) != 0;
    cpu_features.sse2 = (basic.edx & (1 << 26)) != 0;

    // Parse ECX
    cpu_features.sse3 = (basic.ecx & (1 << 0)) != 0;
    cpu_features.ssse3 = (basic.ecx & (1 << 9)) != 0;
    cpu_features.pcid = (basic.ecx & (1 << 17)) != 0;
    cpu_features.sse41 = (basic.ecx & (1 << 19)) != 0;
    cpu_features.sse42 = (basic.ecx & (1 << 20)) != 0;
    cpu_features.x2apic = (basic.ecx & (1 << 21)) != 0;
    cpu_features.xsave = (basic.ecx & (1 << 26)) != 0;
    cpu_features.osxsave = (basic.ecx & (1 << 27)) != 0;
    cpu_features.avx = (basic.ecx & (1 << 28)) != 0;
    cpu_features.rdrand = (basic.ecx & (1 << 30)) != 0;

    // Extended features (leaf 7, subleaf 0)
    const extended = cpuid(7, 0);

    // Parse EBX
    cpu_features.fsgsbase = (extended.ebx & (1 << 0)) != 0;
    cpu_features.smep = (extended.ebx & (1 << 7)) != 0;
    cpu_features.bmi2 = (extended.ebx & (1 << 8)) != 0;
    cpu_features.invpcid = (extended.ebx & (1 << 10)) != 0;
    cpu_features.avx2 = (extended.ebx & (1 << 5)) != 0;
    cpu_features.rdseed_ebx = (extended.ebx & (1 << 18)) != 0;
    cpu_features.smap = (extended.ebx & (1 << 20)) != 0;
    cpu_features.avx512f = (extended.ebx & (1 << 16)) != 0;
    cpu_features.avx512dq = (extended.ebx & (1 << 17)) != 0;
    cpu_features.avx512cd = (extended.ebx & (1 << 28)) != 0;
    cpu_features.avx512bw = (extended.ebx & (1 << 30)) != 0;
    cpu_features.avx512vl = (extended.ebx & (1 << 31)) != 0;

    // Parse ECX
    cpu_features.pku = (extended.ecx & (1 << 3)) != 0;
    cpu_features.umip = (extended.ecx & (1 << 2)) != 0;
    cpu_features.la57 = (extended.ecx & (1 << 16)) != 0;
    cpu_features.rdpid = (extended.ecx & (1 << 22)) != 0;

    // Parse EDX
    cpu_features.tsx_ctrl = (extended.edx & (1 << 7)) != 0;
    cpu_features.pconfig = (extended.edx & (1 << 18)) != 0;
    cpu_features.cet_ibt = (extended.edx & (1 << 20)) != 0;
    // CET Shadow Stack is bit 7 in ECX (not EDX)
    cpu_features.cet_ss = (extended.ecx & (1 << 7)) != 0;

    // Speculation control features (EDX bits)
    cpu_features.spec_ctrl = (extended.edx & (1 << 26)) != 0; // IA32_SPEC_CTRL MSR
    cpu_features.ibrs_ibpb = (extended.edx & (1 << 26)) != 0; // IBRS and IBPB
    cpu_features.stibp = (extended.edx & (1 << 27)) != 0; // STIBP
    cpu_features.ssbd = (extended.edx & (1 << 31)) != 0; // SSBD
    cpu_features.l1d_flush = (extended.edx & (1 << 28)) != 0; // L1D_FLUSH
    cpu_features.arch_capabilities = (extended.edx & (1 << 29)) != 0; // IA32_ARCH_CAPABILITIES
    cpu_features.md_clear = (extended.edx & (1 << 10)) != 0; // MD_CLEAR

    // Extended processor info
    const ext_info = cpuid(0x80000001, 0);
    cpu_features.nx = (ext_info.edx & (1 << 20)) != 0;
    cpu_features.gbpages = (ext_info.edx & (1 << 26)) != 0;
    cpu_features.rdtscp = (ext_info.edx & (1 << 27)) != 0;
    cpu_features.lm = (ext_info.edx & (1 << 29)) != 0;

    // RDSEED feature can be in either ECX leaf 1 or EBX leaf 7
    cpu_features.rdseed = (basic.ecx & (1 << 18)) != 0 or cpu_features.rdseed_ebx;
}

pub fn getFeatures() *const CPUFeatures {
    return &cpu_features;
}

// Get CPU vendor string
pub fn getVendorString() [12]u8 {
    const vendor_info = cpuid(0, 0);
    var vendor: [12]u8 = undefined;

    // EBX, EDX, ECX contain the vendor string
    @memcpy(vendor[0..4], @as(*const [4]u8, @ptrCast(&vendor_info.ebx)));
    @memcpy(vendor[4..8], @as(*const [4]u8, @ptrCast(&vendor_info.edx)));
    @memcpy(vendor[8..12], @as(*const [4]u8, @ptrCast(&vendor_info.ecx)));

    return vendor;
}

// Get physical address bits supported by the CPU
pub fn getPhysicalAddressBits() u8 {
    // Check if extended function 0x80000008 is supported
    const max_extended = cpuid(0x80000000, 0);
    if (max_extended.eax < 0x80000008) {
        // Default to 36 bits (64GB) for old CPUs
        return 36;
    }

    // Get physical and linear address sizes
    const addr_sizes = cpuid(0x80000008, 0);
    const phys_bits = @as(u8, @truncate(addr_sizes.eax & 0xFF));

    // Sanity check - x86-64 requires at least 36 bits, max is 52 bits
    if (phys_bits < 36) return 36;
    if (phys_bits > 52) return 52;

    return phys_bits;
}

// Get linear (virtual) address bits supported by the CPU
pub fn getLinearAddressBits() u8 {
    // Check if extended function 0x80000008 is supported
    const max_extended = cpuid(0x80000000, 0);
    if (max_extended.eax < 0x80000008) {
        // Default to 48 bits for 4-level paging
        return 48;
    }

    // Get physical and linear address sizes
    const addr_sizes = cpuid(0x80000008, 0);
    const linear_bits = @as(u8, @truncate((addr_sizes.eax >> 8) & 0xFF));

    // Sanity check
    if (linear_bits < 48) return 48;
    if (linear_bits > 57) return 57; // LA57 max

    return linear_bits;
}

// Get maximum physical memory supported
pub fn getMaxPhysicalMemory() u64 {
    const phys_bits = getPhysicalAddressBits();
    return @as(u64, 1) << @as(u6, @truncate(phys_bits));
}

pub fn printFeatures() void {
    const serial = @import("../drivers/serial.zig");
    const stack_security = @import("stack_security.zig");

    var guard = stack_security.protect();
    defer guard.deinit();

    // Print CPU vendor
    const vendor = getVendorString();
    serial.print("[CPU] Vendor: {s}\r\n", .{vendor[0..]});

    serial.println("[CPU] Basic Features:", .{});
    serial.print("  64-bit: {s}\r\n", .{if (cpu_features.lm) "Yes" else "No"});
    serial.print("  NX bit: {s}\r\n", .{if (cpu_features.nx) "Yes" else "No"});
    serial.print("  1GB pages: {s}\r\n", .{if (cpu_features.gbpages) "Yes" else "No"});
    serial.print("  LA57 (5-level paging): {s}\r\n", .{if (cpu_features.la57) "Yes" else "No"});

    // Print address size information
    const phys_bits = getPhysicalAddressBits();
    const linear_bits = getLinearAddressBits();
    const max_phys_mem = getMaxPhysicalMemory();
    serial.print("  Physical address bits: {}\r\n", .{phys_bits});
    serial.print("  Linear address bits: {}\r\n", .{linear_bits});
    serial.print("  Max physical memory: {} TB\r\n", .{max_phys_mem / (1024 * 1024 * 1024 * 1024)});

    serial.println("[CPU] Security Features:", .{});
    serial.print("  SMEP: {s}\r\n", .{if (cpu_features.smep) "Yes" else "No"});
    serial.print("  SMAP: {s}\r\n", .{if (cpu_features.smap) "Yes" else "No"});
    serial.print("  UMIP: {s}\r\n", .{if (cpu_features.umip) "Yes" else "No"});
    serial.print("  CET IBT: {s}\r\n", .{if (cpu_features.cet_ibt) "Yes" else "No"});
    serial.print("  CET SS: {s}\r\n", .{if (cpu_features.cet_ss) "Yes" else "No"});
    serial.print("  PKU: {s}\r\n", .{if (cpu_features.pku) "Yes" else "No"});

    serial.println("[CPU] Performance Features:", .{});
    serial.print("  FSGSBASE: {s}\r\n", .{if (cpu_features.fsgsbase) "Yes" else "No"});
    serial.print("  PCID: {s}\r\n", .{if (cpu_features.pcid) "Yes" else "No"});
    serial.print("  INVPCID: {s}\r\n", .{if (cpu_features.invpcid) "Yes" else "No"});

    serial.println("[CPU] SIMD Features:", .{});
    serial.print("  SSE/SSE2: {s}\r\n", .{if (cpu_features.sse and cpu_features.sse2) "Yes" else "No"});
    serial.print("  AVX: {s}\r\n", .{if (cpu_features.avx) "Yes" else "No"});
    serial.print("  AVX2: {s}\r\n", .{if (cpu_features.avx2) "Yes" else "No"});
    serial.print("  XSAVE: {s}\r\n", .{if (cpu_features.xsave) "Yes" else "No"});
    serial.print("  OSXSAVE: {s}\r\n", .{if (cpu_features.osxsave) "Yes" else "No"});

    serial.println("[CPU] RNG Features:", .{});
    serial.print("  RDRAND: {s}\r\n", .{if (cpu_features.rdrand) "Yes" else "No"});
    serial.print("  RDSEED: {s}\r\n", .{if (cpu_features.rdseed) "Yes" else "No"});

    serial.println("[CPU] Speculation Control:", .{});
    serial.print("  SPEC_CTRL MSR: {s}\r\n", .{if (cpu_features.spec_ctrl) "Yes" else "No"});
    serial.print("  IBRS/IBPB: {s}\r\n", .{if (cpu_features.ibrs_ibpb) "Yes" else "No"});
    serial.print("  STIBP: {s}\r\n", .{if (cpu_features.stibp) "Yes" else "No"});
    serial.print("  SSBD: {s}\r\n", .{if (cpu_features.ssbd) "Yes" else "No"});
    serial.print("  L1D_FLUSH: {s}\r\n", .{if (cpu_features.l1d_flush) "Yes" else "No"});
    serial.print("  ARCH_CAPABILITIES: {s}\r\n", .{if (cpu_features.arch_capabilities) "Yes" else "No"});
    serial.print("  MD_CLEAR: {s}\r\n", .{if (cpu_features.md_clear) "Yes" else "No"});
}

// Speculation control feature checks
pub fn hasSpecCtrl() bool {
    return cpu_features.spec_ctrl;
}

pub fn hasIBRS() bool {
    return cpu_features.ibrs_ibpb;
}

pub fn hasIBPB() bool {
    return cpu_features.ibrs_ibpb;
}

pub fn hasSTIBP() bool {
    return cpu_features.stibp;
}

pub fn hasSSBD() bool {
    return cpu_features.ssbd;
}

pub fn hasL1DFlush() bool {
    return cpu_features.l1d_flush;
}

pub fn hasArchCapabilities() bool {
    return cpu_features.arch_capabilities;
}

pub fn hasMDClear() bool {
    return cpu_features.md_clear;
}

pub fn hasSMT() bool {
    // Check if SMT/HyperThreading is enabled
    // This is a simplified check - in production you'd want more thorough detection
    const info = cpuid(0x1, 0);
    const logical_processors = (info.ebx >> 16) & 0xFF;
    return logical_processors > 1;
}

pub fn hasTSX() bool {
    // Check for TSX support (RTM and HLE)
    const info = cpuid(0x7, 0);
    const rtm = (info.ebx & (1 << 11)) != 0;
    const hle = (info.ebx & (1 << 4)) != 0;
    return rtm or hle;
}

pub fn hasCET_SS() bool {
    return cpu_features.cet_ss;
}

pub fn hasCET_IBT() bool {
    return cpu_features.cet_ibt;
}

// Check if the system has complete CET support (both SS and IBT)
pub fn hasCETComplete() bool {
    return cpu_features.cet_ss and cpu_features.cet_ibt;
}

// Get CET capability details
pub fn getCETCapabilities() struct { shadow_stack: bool, indirect_branch_tracking: bool, available: bool } {
    return .{
        .shadow_stack = cpu_features.cet_ss,
        .indirect_branch_tracking = cpu_features.cet_ibt,
        .available = cpu_features.cet_ss or cpu_features.cet_ibt,
    };
}

// Check if CET is supported and properly configured in the system
pub fn verifyCETConfiguration() bool {
    // Check hardware support
    if (!cpu_features.cet_ss and !cpu_features.cet_ibt) {
        return false;
    }

    // Check if CR4.CET is enabled
    const cr4 = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );

    if ((cr4 & (1 << 23)) == 0) { // CR4.CET bit
        return false;
    }

    return true;
}

// x2APIC support functions
pub fn hasX2APIC() bool {
    return cpu_features.x2apic;
}

pub fn hasAPIC() bool {
    return cpu_features.apic;
}
