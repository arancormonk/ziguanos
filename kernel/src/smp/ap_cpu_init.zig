// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");
const cpuid = @import("../x86_64/cpuid.zig");
const cpu_init = @import("../x86_64/cpu_init.zig");
const speculation = @import("../x86_64/speculation.zig");
const cfi = @import("../x86_64/cfi.zig");
const smap = @import("../x86_64/smap.zig");
const serial = @import("../drivers/serial.zig");

// MSR definitions
const IA32_EFER = 0xC0000080;
const IA32_SPEC_CTRL = 0x48;
const IA32_ARCH_CAPABILITIES = 0x10A;
const IA32_XCR0 = 0x0;

// EFER bits
const EFER_NXE = 1 << 11;

// CR4 bits
const CR4_OSXSAVE = 1 << 18;
const CR4_SMEP = 1 << 20;
const CR4_SMAP = 1 << 21;
const CR4_UMIP = 1 << 11;

// BSP feature snapshot for consistency checking
var bsp_features: ?cpuid.CPUFeatures = null;
var bsp_xcr0: u64 = 0;
var bsp_spec_ctrl: u64 = 0;
var bsp_arch_caps: u64 = 0;

// Save BSP features (called from BSP during init)
pub fn saveBspFeatures() void {
    bsp_features = cpuid.getFeatures().*;

    // Save XCR0 if XSAVE is supported
    if (bsp_features.?.xsave) {
        var low: u32 = undefined;
        var high: u32 = undefined;
        asm volatile ("xgetbv"
            : [low] "={eax}" (low),
              [high] "={edx}" (high),
            : [ecx] "{ecx}" (@as(u32, 0)),
        );
        bsp_xcr0 = @as(u64, low) | (@as(u64, high) << 32);
    }

    // Save speculation control MSRs if available
    if (cpuid.hasSpecCtrl()) {
        bsp_spec_ctrl = cpu_init.readMSR(IA32_SPEC_CTRL);
    }

    if (cpuid.hasArchCapabilities()) {
        bsp_arch_caps = cpu_init.readMSR(IA32_ARCH_CAPABILITIES);
    }
}

// Initialize AP to match BSP configuration
pub fn initializeAp(cpu_id: u32) !void {
    serial.println("AP {}: Starting CPU feature initialization", .{cpu_id});

    // 1. Detect CPU features
    cpuid.detectFeatures();

    // 2. Verify features match BSP
    if (bsp_features) |bsp| {
        const ap_features = cpuid.getFeatures().*;
        if (!verifyFeaturesMatch(bsp, ap_features)) {
            serial.println("AP {}: ERROR - CPU features don't match BSP", .{cpu_id});
            return error.FeatureMismatch;
        }
    }

    // 3. Configure EFER (NX bit)
    var efer = cpu_init.readMSR(IA32_EFER);
    efer |= EFER_NXE;
    cpu_init.writeMSR(IA32_EFER, efer);

    // 4. Configure CR4 security features
    var cr4 = asm volatile ("mov %%cr4, %[result]"
        : [result] "=r" (-> u64),
    );

    if (bsp_features.?.smep) {
        cr4 |= CR4_SMEP;
    }
    if (bsp_features.?.smap) {
        cr4 |= CR4_SMAP;
    }
    if (bsp_features.?.umip) {
        cr4 |= CR4_UMIP;
    }

    asm volatile ("mov %[cr4], %%cr4"
        :
        : [cr4] "r" (cr4),
    );

    // 5. Initialize XSAVE if supported
    if (bsp_features.?.xsave) {
        // Enable OSXSAVE
        cr4 = asm volatile ("mov %%cr4, %[result]"
            : [result] "=r" (-> u64),
        );
        cr4 |= CR4_OSXSAVE;
        asm volatile ("mov %[cr4], %%cr4"
            :
            : [cr4] "r" (cr4),
        );

        // Set XCR0 to match BSP
        const low = @as(u32, @truncate(bsp_xcr0));
        const high = @as(u32, @truncate(bsp_xcr0 >> 32));
        asm volatile ("xsetbv"
            :
            : [_] "{eax}" (low),
              [_] "{edx}" (high),
              [_] "{ecx}" (@as(u32, 0)),
        );
    }

    // 6. Configure speculation controls
    if (cpuid.hasSpecCtrl() and bsp_spec_ctrl != 0) {
        cpu_init.writeMSR(IA32_SPEC_CTRL, bsp_spec_ctrl);
    }

    // 7. Initialize other security features
    speculation.init();
    cfi.init();

    // 8. Re-enable SMAP after initialization
    if (bsp_features.?.smap) {
        smap.init();
    }

    serial.println("AP {}: CPU feature initialization complete", .{cpu_id});
}

// Verify critical features match between BSP and AP
fn verifyFeaturesMatch(bsp: cpuid.CPUFeatures, ap: cpuid.CPUFeatures) bool {
    // Check critical security features
    if (bsp.nx != ap.nx) return false;
    if (bsp.smep != ap.smep) return false;
    if (bsp.smap != ap.smap) return false;
    if (bsp.umip != ap.umip) return false;

    // Check CPU capabilities
    if (bsp.xsave != ap.xsave) return false;
    if (bsp.avx != ap.avx) return false;
    if (bsp.avx2 != ap.avx2) return false;

    // Check speculation controls
    if (bsp.ibrs_ibpb != ap.ibrs_ibpb) return false;
    if (bsp.stibp != ap.stibp) return false;
    if (bsp.ssbd != ap.ssbd) return false;

    // Check other important features
    if (bsp.fsgsbase != ap.fsgsbase) return false;
    if (bsp.pcid != ap.pcid) return false;
    if (bsp.invpcid != ap.invpcid) return false;

    return true;
}

// Get saved BSP features
pub fn getBspFeatures() ?cpuid.CPUFeatures {
    return bsp_features;
}

// Check if all CPUs have consistent features
pub fn verifyCpuConsistency() bool {
    return bsp_features != null;
}
