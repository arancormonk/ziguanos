// Copyright 2025 arancormonk
// SPDX-License-Identifier: MIT

// ACPI table structure definitions following the ACPI specification

const std = @import("std");

// ACPI table signature length
pub const SIGNATURE_LENGTH = 4;

// Common ACPI table header used by all tables
pub const Header = extern struct {
    signature: [SIGNATURE_LENGTH]u8,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [6]u8,
    oem_table_id: [8]u8,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,

    pub fn getSignature(self: *const Header) []const u8 {
        return self.signature[0..SIGNATURE_LENGTH];
    }

    pub fn isSignature(self: *const Header, sig: []const u8) bool {
        if (sig.len != SIGNATURE_LENGTH) return false;
        return std.mem.eql(u8, self.getSignature(), sig);
    }
};

// Generic Address Structure (GAS)
pub const GenericAddress = extern struct {
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    access_size: u8,
    address: u64,
};

// Known ACPI table signatures
pub const Signature = struct {
    pub const RSDP = "RSD PTR "; // Note: 8 bytes with space
    pub const RSDT = "RSDT";
    pub const XSDT = "XSDT";
    pub const MADT = "APIC";
    pub const FADT = "FACP";
    pub const HPET = "HPET";
    pub const MCFG = "MCFG";
    pub const SSDT = "SSDT";
    pub const DSDT = "DSDT";
};

// ACPI revision numbers
pub const Revision = struct {
    pub const ACPI_1_0 = 0;
    pub const ACPI_2_0 = 2;
};

// Address space IDs for Generic Address Structure
pub const AddressSpace = enum(u8) {
    SystemMemory = 0,
    SystemIO = 1,
    PCIConfig = 2,
    EmbeddedController = 3,
    SMBus = 4,
    SystemCMOS = 5,
    PCIBARTarget = 6,
    IPMI = 7,
    GeneralPurposeIO = 8,
    GenericSerialBus = 9,
    PCC = 10,
    _,
};

// ACPI error types
pub const Error = error{
    InvalidSignature,
    InvalidChecksum,
    InvalidRevision,
    TableNotFound,
    InvalidAddress,
    UnsupportedVersion,
};
