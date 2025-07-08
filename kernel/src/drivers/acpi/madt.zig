// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

//! MADT (Multiple APIC Description Table) parsing for CPU and interrupt controller discovery

const std = @import("std");
const tables = @import("tables.zig");

/// MADT structure types
pub const MadtEntryType = enum(u8) {
    ProcessorLocalApic = 0,
    IoApic = 1,
    InterruptSourceOverride = 2,
    NmiSource = 3,
    LocalApicNmi = 4,
    LocalApicAddressOverride = 5,
    IoSapic = 6,
    LocalSapic = 7,
    PlatformInterruptSources = 8,
    ProcessorLocalX2Apic = 9,
    LocalX2ApicNmi = 10,
    GicCpu = 11,
    GicDistributor = 12,
    GicMsiFrame = 13,
    GicRedistributor = 14,
    GicIts = 15,
    _,
};

/// MADT header structure
pub const MADT = extern struct {
    header: tables.Header,
    local_apic_address: u32,
    flags: u32,
    // Followed by variable length entries

    pub fn hasLegacyPic(self: *const MADT) bool {
        return (self.flags & 0x01) != 0;
    }

    pub fn getEntries(self: *const MADT) MadtEntryIterator {
        return MadtEntryIterator.init(self);
    }
};

/// Common header for all MADT entries
pub const MadtEntryHeader = extern struct {
    entry_type: u8,
    length: u8,
};

/// Processor Local APIC structure
pub const ProcessorLocalApic = extern struct {
    header: MadtEntryHeader,
    acpi_processor_id: u8,
    apic_id: u8,
    flags: u32,

    pub fn isEnabled(self: *const ProcessorLocalApic) bool {
        return (self.flags & 0x01) != 0;
    }

    pub fn isOnlineCapable(self: *const ProcessorLocalApic) bool {
        return (self.flags & 0x02) != 0;
    }
};

/// I/O APIC structure
pub const IoApic = extern struct {
    header: MadtEntryHeader,
    io_apic_id: u8,
    reserved: u8,
    io_apic_address: u32,
    global_system_interrupt_base: u32,
};

/// Interrupt Source Override structure
pub const InterruptSourceOverride = extern struct {
    header: MadtEntryHeader,
    bus: u8,
    source: u8,
    global_system_interrupt: u32,
    flags: u16,

    pub fn getPolarity(self: *const InterruptSourceOverride) Polarity {
        return @enumFromInt(self.flags & 0x03);
    }

    pub fn getTriggerMode(self: *const InterruptSourceOverride) TriggerMode {
        return @enumFromInt((self.flags >> 2) & 0x03);
    }
};

/// NMI Source structure
pub const NmiSource = extern struct {
    header: MadtEntryHeader,
    flags: u16,
    global_system_interrupt: u32,
};

/// Local APIC NMI structure
pub const LocalApicNmi = extern struct {
    header: MadtEntryHeader,
    acpi_processor_id: u8, // 0xFF means all processors
    flags: u16,
    lint: u8, // 0 or 1
};

/// Local APIC Address Override structure
pub const LocalApicAddressOverride = extern struct {
    header: MadtEntryHeader,
    reserved: u16,
    local_apic_address: u64,
};

/// Processor Local x2APIC structure (for > 255 CPUs)
pub const ProcessorLocalX2Apic = extern struct {
    header: MadtEntryHeader,
    reserved: u16,
    x2apic_id: u32,
    flags: u32,
    acpi_processor_uid: u32,

    pub fn isEnabled(self: *const ProcessorLocalX2Apic) bool {
        return (self.flags & 0x01) != 0;
    }
};

/// Interrupt polarity
pub const Polarity = enum(u2) {
    ConformToSpec = 0,
    ActiveHigh = 1,
    Reserved = 2,
    ActiveLow = 3,
};

/// Interrupt trigger mode
pub const TriggerMode = enum(u2) {
    ConformToSpec = 0,
    Edge = 1,
    Reserved = 2,
    Level = 3,
};

/// Iterator for MADT entries
pub const MadtEntryIterator = struct {
    current: [*]const u8,
    end: [*]const u8,

    pub fn init(madt: *const MADT) MadtEntryIterator {
        const start = @as([*]const u8, @ptrCast(madt)) + @sizeOf(MADT);
        const end = @as([*]const u8, @ptrCast(madt)) + madt.header.length;
        return .{
            .current = start,
            .end = end,
        };
    }

    pub fn next(self: *MadtEntryIterator) ?*const MadtEntryHeader {
        if (@intFromPtr(self.current) >= @intFromPtr(self.end)) {
            return null;
        }

        const header = @as(*const MadtEntryHeader, @ptrCast(@alignCast(self.current)));

        // Validate entry doesn't exceed table bounds
        if (@intFromPtr(self.current) + header.length > @intFromPtr(self.end)) {
            return null;
        }

        // Move to next entry
        self.current += header.length;

        return header;
    }
};

/// Processor information extracted from MADT
pub const ProcessorInfo = struct {
    processor_id: u8,
    apic_id: u32, // u32 to support x2APIC
    flags: u32,
    is_x2apic: bool,

    pub fn isEnabled(self: ProcessorInfo) bool {
        return (self.flags & 0x01) != 0;
    }
};

/// System topology information
pub const SystemTopology = struct {
    processors: []ProcessorInfo,
    io_apics: []IoApicInfo,
    boot_cpu_id: u32,
    total_cpus: u32,
    local_apic_address: u64,
    has_legacy_pic: bool,
};

/// I/O APIC information
pub const IoApicInfo = struct {
    io_apic_id: u8,
    io_apic_address: u32,
    global_system_interrupt_base: u32,
};

const MAX_PROCESSORS = 256;
const MAX_IO_APICS = 16;

/// Parse MADT and extract system topology
pub fn parseMADT(madt: *const MADT, allocator: std.mem.Allocator) !SystemTopology {
    // Use fixed-size arrays instead of ArrayList
    var processors_buffer: [MAX_PROCESSORS]ProcessorInfo = undefined;
    var io_apics_buffer: [MAX_IO_APICS]IoApicInfo = undefined;
    var processor_count: usize = 0;
    var io_apic_count: usize = 0;

    var local_apic_address: u64 = madt.local_apic_address;
    var boot_cpu_id: u32 = 0;
    var found_boot_cpu = false;

    var iter = madt.getEntries();
    while (iter.next()) |entry| {
        switch (@as(MadtEntryType, @enumFromInt(entry.entry_type))) {
            .ProcessorLocalApic => {
                const proc = @as(*const ProcessorLocalApic, @ptrCast(@alignCast(entry)));
                if (proc.isEnabled() and processor_count < MAX_PROCESSORS) {
                    processors_buffer[processor_count] = .{
                        .processor_id = proc.acpi_processor_id,
                        .apic_id = proc.apic_id,
                        .flags = proc.flags,
                        .is_x2apic = false,
                    };
                    processor_count += 1;

                    // First enabled processor is typically BSP
                    if (!found_boot_cpu) {
                        boot_cpu_id = proc.apic_id;
                        found_boot_cpu = true;
                    }
                }
            },

            .ProcessorLocalX2Apic => {
                const proc = @as(*const ProcessorLocalX2Apic, @ptrCast(@alignCast(entry)));
                if (proc.isEnabled() and processor_count < MAX_PROCESSORS) {
                    processors_buffer[processor_count] = .{
                        .processor_id = @intCast(proc.acpi_processor_uid),
                        .apic_id = proc.x2apic_id,
                        .flags = proc.flags,
                        .is_x2apic = true,
                    };
                    processor_count += 1;
                }
            },

            .IoApic => {
                const io_apic = @as(*const IoApic, @ptrCast(@alignCast(entry)));
                if (io_apic_count < MAX_IO_APICS) {
                    io_apics_buffer[io_apic_count] = .{
                        .io_apic_id = io_apic.io_apic_id,
                        .io_apic_address = io_apic.io_apic_address,
                        .global_system_interrupt_base = io_apic.global_system_interrupt_base,
                    };
                    io_apic_count += 1;
                }
            },

            .LocalApicAddressOverride => {
                const override = @as(*const LocalApicAddressOverride, @ptrCast(@alignCast(entry)));
                local_apic_address = override.local_apic_address;
            },

            else => {
                // Other entry types can be processed as needed
            },
        }
    }

    // Allocate exact-sized arrays for the results
    const processors_slice = try allocator.alloc(ProcessorInfo, processor_count);
    errdefer allocator.free(processors_slice);

    const io_apics_slice = try allocator.alloc(IoApicInfo, io_apic_count);
    errdefer allocator.free(io_apics_slice);

    // Copy the data
    @memcpy(processors_slice, processors_buffer[0..processor_count]);
    @memcpy(io_apics_slice, io_apics_buffer[0..io_apic_count]);

    return SystemTopology{
        .processors = processors_slice,
        .io_apics = io_apics_slice,
        .boot_cpu_id = boot_cpu_id,
        .total_cpus = @intCast(processor_count),
        .local_apic_address = local_apic_address,
        .has_legacy_pic = madt.hasLegacyPic(),
    };
}
