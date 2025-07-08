// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

const std = @import("std");

pub fn build(b: *std.Build) void {
    // Build mode option
    const build_mode = b.option([]const u8, "mode", "Build mode: debug, release, or production") orelse "debug";

    // Validate build mode
    if (!std.mem.eql(u8, build_mode, "debug") and
        !std.mem.eql(u8, build_mode, "release") and
        !std.mem.eql(u8, build_mode, "production"))
    {
        std.debug.panic("Invalid build mode: {s}. Must be debug, release, or production\n", .{build_mode});
    }

    // Create build options module
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "build_mode", build_mode);

    // Kernel: 64-bit freestanding binary
    // Disable floating-point and SIMD features for kernel
    var disabled_features = std.Target.Cpu.Feature.Set.empty;
    var enabled_features = std.Target.Cpu.Feature.Set.empty;

    // Disable floating-point and SIMD features
    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.mmx));
    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.sse));
    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.sse2));
    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.avx));
    disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.avx2));

    // Enable soft float for kernel arithmetic
    enabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.soft_float));

    const kernel_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
        .cpu_features_sub = disabled_features,
        .cpu_features_add = enabled_features,
    });

    const kernel = b.addExecutable(.{
        .name = "kernel",
        .root_source_file = b.path("kernel/src/root.zig"),
        .target = kernel_target,
        .optimize = .ReleaseFast,
        .code_model = .kernel,
        .pic = true,
    });

    kernel.pie = true;

    kernel.entry = .{ .symbol_name = "_start" };

    // Kernel-specific settings
    kernel.root_module.red_zone = false;
    kernel.root_module.omit_frame_pointer = !std.mem.eql(u8, build_mode, "debug"); // Keep frame pointers only in debug
    kernel.root_module.stack_check = false;
    kernel.root_module.stack_protector = false;
    kernel.root_module.single_threaded = true; // Kernel runs in single-threaded mode
    kernel.root_module.error_tracing = std.mem.eql(u8, build_mode, "debug"); // Error tracing only in debug
    kernel.root_module.unwind_tables = if (std.mem.eql(u8, build_mode, "production")) .none else .sync;
    kernel.root_module.strip = std.mem.eql(u8, build_mode, "production"); // Strip symbols in production

    kernel.setLinkerScript(b.path("kernel/kernel.ld"));

    // Add assembly files
    kernel.addAssemblyFile(b.path("kernel/src/boot/entry.S"));
    kernel.addAssemblyFile(b.path("kernel/src/x86_64/exception_stubs.S"));
    kernel.addAssemblyFile(b.path("kernel/src/x86_64/interrupt_stubs.S"));

    // Add shared module
    kernel.root_module.addImport("shared", b.createModule(.{
        .root_source_file = b.path("shared/boot_protocol.zig"),
    }));

    // Add build options first
    kernel.root_module.addOptions("build_options", build_options);

    // Add security config module with build options dependency
    const security_config_module = b.createModule(.{
        .root_source_file = b.path("shared/security_config.zig"),
    });
    security_config_module.addOptions("build_options", build_options);
    kernel.root_module.addImport("security_config", security_config_module);

    // UEFI Bootloader
    // Also disable floating-point features for UEFI compatibility
    var uefi_disabled_features = std.Target.Cpu.Feature.Set.empty;
    var uefi_enabled_features = std.Target.Cpu.Feature.Set.empty;

    // Disable floating-point and SIMD features for UEFI
    uefi_disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.mmx));
    uefi_disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.sse));
    uefi_disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.sse2));
    uefi_disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.avx));
    uefi_disabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.avx2));

    // Enable soft float for UEFI arithmetic
    uefi_enabled_features.addFeature(@intFromEnum(std.Target.x86.Feature.soft_float));

    const uefi_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .uefi,
        .abi = .msvc,
        .cpu_features_sub = uefi_disabled_features,
        .cpu_features_add = uefi_enabled_features,
    });

    const uefi_bootloader = b.addExecutable(.{
        .name = "BOOTX64",
        .root_source_file = b.path("bootloader/uefi/src/main.zig"),
        .target = uefi_target,
        .optimize = .ReleaseSmall,
        .linkage = .static,
    });

    // UEFI-specific settings
    uefi_bootloader.root_module.red_zone = false; // Critical for UEFI - Microsoft ABI has no red zone
    uefi_bootloader.root_module.stack_protector = false;
    uefi_bootloader.root_module.single_threaded = true; // UEFI bootloader is single-threaded
    uefi_bootloader.root_module.omit_frame_pointer = !std.mem.eql(u8, build_mode, "debug");
    uefi_bootloader.root_module.strip = std.mem.eql(u8, build_mode, "production");
    uefi_bootloader.root_module.unwind_tables = if (std.mem.eql(u8, build_mode, "production")) .none else .sync;
    uefi_bootloader.subsystem = .EfiApplication;

    // Add shared module
    uefi_bootloader.root_module.addImport("shared", b.createModule(.{
        .root_source_file = b.path("shared/boot_protocol.zig"),
    }));

    // Add build options first
    uefi_bootloader.root_module.addOptions("build_options", build_options);

    // Add security config module with build options dependency
    const uefi_security_config_module = b.createModule(.{
        .root_source_file = b.path("shared/security_config.zig"),
    });
    uefi_security_config_module.addOptions("build_options", build_options);
    uefi_bootloader.root_module.addImport("security_config", uefi_security_config_module);

    // Install artifacts
    const kernel_install = b.addInstallArtifact(kernel, .{
        .dest_sub_path = "kernel.elf",
    });
    const uefi_install = b.addInstallArtifact(uefi_bootloader, .{
        .dest_sub_path = "EFI/BOOT/BOOTX64.EFI",
    });

    // Create kernel binary for embedding in UEFI image
    const kernel_objcopy = kernel.addObjCopy(.{
        .format = .bin,
    });
    const kernel_copy_step = b.addInstallBinFile(kernel_objcopy.getOutput(), "kernel.bin");

    // Build steps
    const kernel_build_step = b.step("kernel", "Build kernel");
    kernel_build_step.dependOn(&kernel_copy_step.step);
    kernel_build_step.dependOn(&kernel_install.step);

    const uefi_build_step = b.step("uefi", "Build UEFI bootloader");
    uefi_build_step.dependOn(&uefi_install.step);

    // Default build step - builds everything
    b.getInstallStep().dependOn(&kernel_install.step);
    b.getInstallStep().dependOn(&uefi_install.step);

    // Generate kernel hash (must happen after kernel build but before bootloader)
    const hash_cmd = b.addSystemCommand(&[_][]const u8{
        "bash", "scripts/generate_kernel_hash.sh",
    });
    hash_cmd.step.dependOn(&kernel_install.step);

    // Generate kernel HMAC placeholder (actual HMAC uses runtime keys from UEFI variables)
    const hmac_cmd = b.addSystemCommand(&[_][]const u8{
        "bash", "scripts/generate_kernel_hmac.sh",
    });
    hmac_cmd.step.dependOn(&kernel_install.step);

    // Make UEFI bootloader depend on hash and HMAC generation
    uefi_bootloader.step.dependOn(&hash_cmd.step);
    uefi_bootloader.step.dependOn(&hmac_cmd.step);

    // Create UEFI disk image
    const create_disk_cmd = b.addSystemCommand(&[_][]const u8{
        "bash", "scripts/create_disk.sh",
    });
    create_disk_cmd.step.dependOn(&uefi_install.step);
    create_disk_cmd.step.dependOn(&kernel_install.step);

    const disk_step = b.step("disk", "Create UEFI bootable disk image");
    disk_step.dependOn(&create_disk_cmd.step);

    // Test step (hash generation happens automatically via dependency chain)
    const test_cmd = b.addSystemCommand(&[_][]const u8{
        "bash", "scripts/test.sh", "2", "1024",
    });
    test_cmd.step.dependOn(&create_disk_cmd.step);

    const test_step = b.step("test", "Test Ziguanos with UEFI in QEMU");
    test_step.dependOn(&test_cmd.step);

    // Run step (GUI mode) - hash generation happens automatically via dependency chain
    const run_cmd = b.addSystemCommand(&[_][]const u8{
        "bash", "scripts/run.sh", "2", "1024",
    });
    run_cmd.step.dependOn(&create_disk_cmd.step);

    const run_step = b.step("run", "Run Ziguanos with UEFI in QEMU (GUI mode)");
    run_step.dependOn(&run_cmd.step);

    // Clean step
    const clean_cmd = b.addSystemCommand(&[_][]const u8{
        "rm", "-rf", "zig-out", "zig-cache", "serial.log", "qemu.log",
    });

    const clean_step = b.step("clean", "Clean build artifacts");
    clean_step.dependOn(&clean_cmd.step);
}
