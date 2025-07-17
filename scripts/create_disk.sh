# Copyright 2025 arancormonk
# SPDX-License-Identifier: MIT

#!/bin/bash
set -e

# Script to create UEFI bootable disk image for Ziguanos
# Creates a FAT32 image file directly using mtools (no sudo required)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/zig-out"
OUTPUT_IMAGE="$BUILD_DIR/ziguanos-uefi.img"
DISK_SIZE_MB=64

echo "Creating UEFI disk image..."

# Ensure build directory exists
mkdir -p "$BUILD_DIR"

# Check for required files
if [ ! -f "$BUILD_DIR/bin/EFI/BOOT/BOOTX64.EFI" ]; then
    echo "Error: BOOTX64.EFI not found. Run 'zig build uefi' first."
    exit 1
fi

if [ ! -f "$BUILD_DIR/bin/kernel.elf" ]; then
    echo "Error: kernel not found. Run 'zig build kernel' first."
    exit 1
fi

# Create temporary directory for disk contents
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Create EFI directory structure
mkdir -p "$TEMP_DIR/EFI/BOOT"

# Copy files
cp "$BUILD_DIR/bin/EFI/BOOT/BOOTX64.EFI" "$TEMP_DIR/EFI/BOOT/"
cp "$BUILD_DIR/bin/kernel.elf" "$TEMP_DIR/kernel.elf"

# Copy configuration file if it exists
if [ -f "$BUILD_DIR/ziguanos.conf" ]; then
    cp "$BUILD_DIR/ziguanos.conf" "$TEMP_DIR/"
    echo "Configuration file included: ziguanos.conf"
    
    # Copy HMAC signature if it exists
    if [ -f "$BUILD_DIR/ziguanos.conf.hmac" ]; then
        cp "$BUILD_DIR/ziguanos.conf.hmac" "$TEMP_DIR/"
        echo "Configuration HMAC included: ziguanos.conf.hmac"
    else
        echo "WARNING: No HMAC signature found for configuration file"
    fi
else
    echo "No configuration file found - using defaults"
fi

# HMAC keys are now stored securely in UEFI variables
# Never store cryptographic keys on disk
echo "HMAC keys will be generated and stored in UEFI variables at runtime"

# Create startup.nsh
echo "echo Ziguanos UEFI Boot" > "$TEMP_DIR/startup.nsh"
echo "\EFI\BOOT\BOOTX64.EFI" >> "$TEMP_DIR/startup.nsh"

# Create the disk image using mtools (no sudo required)
# First check if mtools is available
if ! command -v mformat &> /dev/null; then
    echo "Error: mtools not installed. Please install mtools package."
    echo "  Ubuntu/Debian: apt install mtools"
    echo "  Fedora: dnf install mtools"
    echo "  Arch: pacman -S mtools"
    exit 1
fi

# Create disk image
dd if=/dev/zero of="$OUTPUT_IMAGE" bs=1M count=$DISK_SIZE_MB status=none

# Format as FAT32
mformat -i "$OUTPUT_IMAGE" -F ::

# Copy files using mcopy
mcopy -s -i "$OUTPUT_IMAGE" "$TEMP_DIR"/* ::

echo "UEFI disk image created: $OUTPUT_IMAGE"
echo ""
echo "To test with QEMU:"
echo "  qemu-system-x86_64 -bios /usr/share/ovmf/OVMF.fd -drive file=$OUTPUT_IMAGE,format=raw"