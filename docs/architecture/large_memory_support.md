# Large Memory Support in Ziguanos PMM

## Overview

The Physical Memory Manager (PMM) has been updated to support much larger memory configurations up to x86-64 architectural limits. The implementation uses a two-phase approach to handle systems with varying amounts of RAM efficiently.

## Key Changes

### 1. CPU Physical Address Detection

Added functions to `cpuid.zig` to detect the CPU's physical address capabilities:

- `getPhysicalAddressBits()` - Returns the number of physical address bits (36-52)
- `getLinearAddressBits()` - Returns the number of linear/virtual address bits (48-57)
- `getMaxPhysicalMemory()` - Returns the maximum addressable physical memory

Modern x86-64 CPUs support:

- Minimum: 36 bits (64 GB)
- Common: 40-48 bits (1 TB - 256 TB)
- Maximum: 52 bits (4 PB)

### 2. Two-Phase Bitmap Approach

The PMM now uses a two-phase approach for bitmap allocation:

**Phase 1: Bootstrap Bitmap**

- Static 128KB bitmap supporting up to 4GB RAM
- Used during early boot when memory is limited
- All system memory is discovered but only first 4GB can be allocated

**Phase 2: Dynamic Bitmap** (if needed)

- Allocated after boot services exit
- Sized based on actual system memory
- Extends tracking capability without discovering new memory
- Supports up to CPU's physical address limit (40-52 bits, 1TB-4PB)

### 3. Physical Address Masking

Updated paging constants to properly mask physical addresses:

- `PHYS_ADDR_MASK_4K`: Bits 51:12 for 4KB pages
- `PHYS_ADDR_MASK_2M`: Bits 51:21 for 2MB pages
- `PHYS_ADDR_MASK_1G`: Bits 51:30 for 1GB pages

The VMM now uses these constants instead of hardcoded values.

### 4. Memory Region Support

Increased maximum memory regions from 32 to 128 to handle more fragmented memory layouts common in large memory systems.

### 5. Bitmap Upgrade Function

Added `upgradeBitmapForLargeMemory()` function that:

- Detects if system has more than 4GB RAM
- Allocates a larger bitmap dynamically
- Copies existing bitmap state
- Enables tracking of all system memory (not just first 4GB)

## Usage

The PMM automatically detects and adapts to the system's memory configuration:

1. During early boot, it uses the bootstrap bitmap (tracks first 4GB)
2. All system RAM is discovered but only first 4GB can be allocated
3. After boot services exit, `main.zig` calls `upgradeBitmapForLargeMemory()`
4. If the system has >4GB RAM, the bitmap is upgraded transparently
5. Memory above 4GB becomes available for allocation
6. No new memory is discovered - just tracking capability is extended

## Testing

A comprehensive test (`large_memory_test.zig`) verifies:

- CPU physical address detection
- Memory statistics reporting
- Allocation patterns with large blocks
- Support for high memory addresses

## Scalability

The implementation dynamically scales based on CPU capabilities:

- **Consumer CPUs** (40-bit): Up to 1TB RAM
- **Server CPUs** (46-bit): Up to 64TB RAM  
- **Future CPUs** (52-bit): Up to 4PB RAM

The bitmap size scales linearly with memory:
- 1TB RAM requires 32MB bitmap
- 64TB RAM requires 2GB bitmap
- 4PB RAM requires 128GB bitmap

As long as there's enough free memory for the bitmap after boot services exit, the system can track any amount of RAM up to the CPU's physical address limit.

## Security Considerations

- All security features (double-free detection, memory tagging, etc.) work with large memory
- Bloom filter scales automatically with memory size
- Guard pages and protection mechanisms remain active

## Future Enhancements

1. **NUMA Support**: Detect and optimize for Non-Uniform Memory Access
2. **Hot-plug Memory**: Support for dynamic memory addition
3. **Huge Page Optimization**: Better support for 1GB huge pages in large memory systems
4. **Compressed Bitmaps**: Use compression for sparse memory layouts
