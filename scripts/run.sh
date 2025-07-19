# Copyright 2025 arancormonk
# SPDX-License-Identifier: MIT

#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/zig-out"
UEFI_IMAGE="$BUILD_DIR/ziguanos-uefi.img"
SERIAL_LOG="$PROJECT_ROOT/serial.log"
QEMU_LOG="$PROJECT_ROOT/qemu.log"

# Parse command line arguments
SMP_CORES="2"
MEMORY_MB="1024"
ACCEL_MODE=""

# Process arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --kvm)
            ACCEL_MODE="kvm"
            shift
            ;;
        --tcg)
            ACCEL_MODE="tcg"
            shift
            ;;
        *)
            # First non-option argument is SMP_CORES
            if [[ -z "$SMP_CORES_SET" ]]; then
                SMP_CORES=$1
                SMP_CORES_SET=1
            # Second non-option argument is MEMORY_MB
            elif [[ -z "$MEMORY_MB_SET" ]]; then
                MEMORY_MB=$1
                MEMORY_MB_SET=1
            fi
            shift
            ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Running Ziguanos with UEFI (GUI mode)...${NC}"
echo -e "${GREEN}Configuration: ${SMP_CORES} CPUs, ${MEMORY_MB}MB RAM${NC}"

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

# Clean up old logs
rm -f "$SERIAL_LOG" "$QEMU_LOG"

# Prepare QEMU arguments
QEMU_ARGS=(
    -machine q35,kernel-irqchip=split,smm=on,vmport=off,hpet=off,mem-merge=off,dump-guest-core=on
    -smp "$SMP_CORES",maxcpus="$SMP_CORES"
    -m "${MEMORY_MB}M"
    -device intel-iommu,intremap=on,caching-mode=on,aw-bits=48,device-iotlb=on,dma-drain=on
    -global ICH9-LPC.disable_s3=1
    -global ICH9-LPC.disable_s4=1
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
    # Hardware RNG support
    -object rng-random,filename=/dev/urandom,id=rng0
    -device virtio-rng-pci,rng=rng0
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

# Configure acceleration based on user preference or availability
if [[ "$ACCEL_MODE" == "kvm" ]]; then
    # User explicitly requested KVM
    if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        echo -e "${GREEN}Using KVM acceleration (explicitly requested)${NC}"
        QEMU_ARGS+=(
            -cpu host,+ssse3,+sse4.1,+sse4.2,+popcnt,+avx,+aes,+xsave,+xsaveopt,+smep,+smap,+nx,check=on,enforce=on
            -accel kvm
            -rtc base=utc,driftfix=slew
            # Enable guest error reporting
            -d cpu_reset,guest_errors,unimp
            -D "$QEMU_LOG"
        )
    else
        echo -e "${RED}ERROR: KVM requested but not available${NC}"
        exit 1
    fi
elif [[ "$ACCEL_MODE" == "tcg" ]]; then
    # User explicitly requested TCG
    echo -e "${GREEN}Using TCG acceleration (explicitly requested)${NC}"
    QEMU_ARGS+=(
        -cpu max
        -accel tcg,thread=multi,tb-size=512,split-wx=on
        -rtc base=utc,driftfix=slew
        -global kvm-pit.lost_tick_policy=delay
        # Enable guest error reporting
        -d cpu_reset,guest_errors,unimp
        -D "$QEMU_LOG"
    )
else
    # Auto-detect (default behavior)
    if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        echo -e "${GREEN}Using KVM acceleration${NC}"
        QEMU_ARGS+=(
            -cpu host,+ssse3,+sse4.1,+sse4.2,+popcnt,+avx,+aes,+xsave,+xsaveopt,+smep,+smap,+nx,check=on,enforce=on
            -accel kvm
            -rtc base=utc,driftfix=slew
            # Enable guest error reporting
            -d cpu_reset,guest_errors,unimp
            -D "$QEMU_LOG"
        )
    else
        echo -e "${YELLOW}KVM not available, falling back to TCG${NC}"
        echo -e "${YELLOW}For better performance, ensure KVM is enabled and you have access to /dev/kvm${NC}"
        QEMU_ARGS+=(
            -cpu max
            -accel tcg,thread=multi,tb-size=512,split-wx=on
            -rtc base=utc,driftfix=slew
            -global kvm-pit.lost_tick_policy=delay
            # Enable guest error reporting
            -d cpu_reset,guest_errors,unimp
            -D "$QEMU_LOG"
        )
    fi
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