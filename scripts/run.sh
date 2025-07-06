# Copyright 2025 arancormonk
# SPDX-License-Identifier: MIT

#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/zig-out"
UEFI_IMAGE="$BUILD_DIR/ziguanos-uefi.img"
SERIAL_LOG="$PROJECT_ROOT/serial.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Running Ziguanos with UEFI (GUI mode)...${NC}"

# Check if UEFI image exists
if [ ! -f "$UEFI_IMAGE" ]; then
    echo -e "${YELLOW}UEFI image not found. Building...${NC}"
    cd "$PROJECT_ROOT"
    zig build disk
fi

# Find OVMF firmware
OVMF_CODE=""
OVMF_VARS=""

# Check common OVMF locations
if [ -f "/usr/share/ovmf/OVMF.fd" ]; then
    OVMF_CODE="/usr/share/ovmf/OVMF.fd"
elif [ -f "/usr/share/qemu/OVMF.fd" ]; then
    OVMF_CODE="/usr/share/qemu/OVMF.fd"
elif [ -f "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd" ]; then
    OVMF_CODE="/usr/share/edk2-ovmf/x64/OVMF_CODE.fd"
    OVMF_VARS="/usr/share/edk2-ovmf/x64/OVMF_VARS.fd"
elif [ -f "/usr/share/OVMF/OVMF_CODE.fd" ]; then
    OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
    OVMF_VARS="/usr/share/OVMF/OVMF_VARS.fd"
else
    echo -e "${RED}Error: OVMF firmware not found. Please install OVMF/edk2-ovmf package.${NC}"
    echo "On Ubuntu/Debian: sudo apt install ovmf"
    echo "On Fedora: sudo dnf install edk2-ovmf"
    echo "On Arch: sudo pacman -S edk2-ovmf"
    exit 1
fi

# Clean up old serial log
rm -f "$SERIAL_LOG"

# Prepare QEMU arguments
QEMU_ARGS=(
    -machine q35
    -cpu host,+invtsc
    -smp 4
    -m 8192M
    -no-reboot
    -no-shutdown
    -serial file:"$SERIAL_LOG"
    -drive file="$UEFI_IMAGE",format=raw,if=none,id=boot
    -device ahci,id=ahci
    -device ide-hd,drive=boot,bus=ahci.0,bootindex=1
    # RTC with host time
    -rtc base=localtime,clock=host
    # Network device
    -device e1000e,netdev=net0
    -netdev user,id=net0
    # USB controller
    -device qemu-xhci,id=xhci
    -device usb-tablet
    # Better display
    -device virtio-vga-gl
    -display gtk,gl=on
)

# Add OVMF firmware arguments
if [ -n "$OVMF_VARS" ]; then
    # Use split CODE/VARS (more modern approach)
    TEMP_VARS=$(mktemp --suffix=.fd)
    cp "$OVMF_VARS" "$TEMP_VARS"
    QEMU_ARGS+=(
        -drive if=pflash,format=raw,unit=0,file="$OVMF_CODE",readonly=on
        -drive if=pflash,format=raw,unit=1,file="$TEMP_VARS"
    )
else
    # Use combined firmware file
    QEMU_ARGS+=(-bios "$OVMF_CODE")
fi

# Check if we need to disable HMAC verification for testing
if [ "$DISABLE_HMAC" = "1" ] || [ ! -f "$BUILD_DIR/ziguanos.conf" ]; then
    echo -e "${YELLOW}Note: Running without HMAC verification${NC}"
    # Create a minimal config that disables HMAC
    mkdir -p "$BUILD_DIR"
    echo "HMACVerification=false" > "$BUILD_DIR/ziguanos.conf"
    # Rebuild disk image with new config
    bash "$SCRIPT_DIR/create_disk.sh" > /dev/null 2>&1
fi

# Check if KVM is available
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    echo -e "${GREEN}KVM acceleration available${NC}"
    QEMU_ARGS+=(-enable-kvm)
else
    echo -e "${YELLOW}KVM not available, using TCG (slower)${NC}"
fi

# Run QEMU with GUI
echo -e "${GREEN}Starting QEMU with UEFI (GUI mode)...${NC}"
echo -e "${YELLOW}Serial output will be saved to: $SERIAL_LOG${NC}"
echo ""

qemu-system-x86_64 "${QEMU_ARGS[@]}"

# Clean up temp vars file if created
if [ -n "$TEMP_VARS" ] && [ -f "$TEMP_VARS" ]; then
    rm -f "$TEMP_VARS"
fi

# Show serial output after QEMU exits
echo ""
echo -e "${GREEN}=== Serial Output ===${NC}"
if [ -f "$SERIAL_LOG" ]; then
    cat "$SERIAL_LOG"
else
    echo -e "${YELLOW}No serial output captured${NC}"
fi