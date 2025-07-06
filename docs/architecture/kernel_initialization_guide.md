# Ziguanos Kernel Initialization Guide

This document provides a comprehensive technical reference for the Ziguanos kernel initialization process. It documents the exact sequence of initialization steps as implemented in the kernel source code.

## Overview

Ziguanos is a security-focused x86-64 operating system that boots via UEFI. The kernel initialization process transforms the UEFI-provided environment into a fully-featured kernel environment with comprehensive security features. The kernel uses a modular initialization system with separate modules for different subsystems.

## Initialization Flow

```
UEFI Bootloader
    ↓
Assembly Entry (_start in boot/entry.S)
    ↓
Zig Entry (_zig_start in boot/entry.zig)
    ├── Serial initialization
    ├── Stack switch to boot stack
    ├── Boot info validation
    ├── BSS clearing
    └── CPU state verification
         ↓
Boot Mode Selection
    ├── PIE Mode → mode_handler.handlePIEBoot()
    └── Normal Mode → mode_handler.handleNormalBoot()
         ↓
Kernel Main Phase 1 (main.zig:kernelMain)
    ├── KASLR offset setup
    ├── Boot info display
    ├── GDT test
    ├── security_init.initBasic()
    ├── cpu_init.init()
    ├── memory_init.initPhase1()
    └── Stack switch to kernel stack
         ↓
Kernel Main Phase 2 (main.zig:kernelMainPhase2)
    ├── memory_init.initPhase2()
    ├── security_init.initFull()
    ├── cpu_init.initComplete()
    ├── hardware_init.init()
    ├── diagnostics.runAllTests()
    ├── Statistics reporting
    ├── hardware_init.enableInterrupts()
    └── Main loop (HLT)
```

## Boot Protocol

The kernel follows a structured boot protocol with the UEFI bootloader:

### Boot Information Structure

The bootloader passes a `UEFIBootInfo` structure containing:

- **Magic Number**: `0x5A49475541524E53` ("ZIGUANOS")
- **Kernel Information**: Base address, size, and hash
- **Memory Map**: UEFI memory map from bootloader
- **ACPI Information**: RSDP address if available
- **Boot Flags**: PIE mode, hash validation status
- **Security Info**: Hash validation results
- **Kernel Hash**: SHA-256 hash for secure boot verification

### Boot Entry Process

The kernel uses a three-stage entry process:

1. **Assembly Entry Point** (`_start` in `boot/entry.S`)
   - Disables interrupts with CLI instruction
   - Receives boot info pointer from UEFI bootloader (in RDI)
   - Saves pointer to global variable using RIP-relative addressing (PIE-compatible)
   - Jumps to Zig entry point `_zig_start`

2. **Zig Entry Point** (`_zig_start` in `boot/entry.zig:29`)
   - Disables interrupts immediately (redundant but safe)
   - Initializes serial port for early debugging
   - Switches to minimal boot stack using `__boot_stack_top`
   - Validates boot info before any use
   - Saves boot info to global variable
   - Clears BSS section (preserving saved boot info)
   - Verifies CPU state (long mode and paging)
   - Handles boot modes (PIE vs normal)

3. **Mode-Specific Handlers** (`boot/mode_handler.zig`)
   - PIE mode: Sets up runtime info, early CPU features, minimal GDT
   - Normal mode: Sets up runtime info, full GDT immediately
   - Both modes continue to `kernelMain`

## Initialization Sequence

The kernel initialization follows a precise order using a modular system. Each module handles specific subsystems, ensuring clear separation of concerns and maintainability.

### Phase 1: Assembly Entry Point

**Location:** `kernel/src/boot/entry.S`  
**Purpose:** Capture boot info pointer in PIE-compatible way

1. **Interrupt Disable** (`entry.S:14`)
   - CLI instruction to prevent interrupts

2. **Save Boot Info** (`entry.S:17`)
   - Saves RDI (boot info pointer) using RIP-relative addressing
   - Compatible with Position Independent Code

3. **Jump to Zig** (`entry.S:21`)
   - Transfers control to `_zig_start`

### Phase 2: Early Boot and Validation

**Location:** `kernel/src/boot/entry.zig:29-89`  
**Purpose:** Establish minimal safe environment and validate boot info

1. **Initial Setup** (`entry.zig:31-36`)
   - Disables interrupts (redundant safety)
   - Initializes serial port for debugging
   - Prints boot info pointer

2. **Stack Switch** (`entry.zig:42-48`)
   - Switches to kernel boot stack
   - Uses inline assembly to set RSP

3. **Boot Info Validation** (`boot/validation.zig`)
   - Magic number check: `0x5A49475541524E53`
   - Kernel range validation (1MB to 4GB, size < 256MB)
   - Memory map validation if present
   - Halt on validation failure

4. **BSS Clearing** (`boot/bss.zig`)
   - Saves boot info first
   - Clears BSS section preserving saved data
   - Uses memory exclusion region for preservation

5. **CPU State Verification** (`x86_64/cpu_state.zig`)
   - Verifies long mode is active (EFER.LMA)
   - Verifies paging is enabled (CR0.PG)

6. **Boot Mode Selection** (`entry.zig:78-88`)
   - Checks PIE mode flag
   - Routes to appropriate handler

### Phase 3: Boot Mode Handling

**Location:** `kernel/src/boot/mode_handler.zig`  
**Purpose:** Handle PIE (Position Independent Executable) vs normal boot

1. **PIE Mode Handler** (`mode_handler.zig:20-44`)
   - Calculates physical base address
   - Initializes runtime info with physical addresses
   - Sets up early CPU features
   - Initializes minimal GDT
   - Attempts to enable bootloader page tables (not implemented)
   - Sets virtual memory enabled flag
   - Continues to kernel main

2. **Normal Mode Handler** (`mode_handler.zig:47-58`)
   - Initializes runtime info for identity-mapped mode
   - Sets up full GDT immediately
   - Continues to kernel main

3. **Common Continuation** (`mode_handler.zig:84-87`)
   - Both modes jump to `kernelMain`

### Phase 4: Global Descriptor Table (GDT)

**Location:** `kernel/src/x86_64/gdt.zig`  
**Purpose:** Establish kernel-controlled segmentation

The GDT is set up differently based on boot mode:
- PIE mode: `gdt.initEarly()` in mode handler
- Normal mode: `gdt.init()` in mode handler

1. **GDT Structure** (`gdt.zig`)
   - Creates 64-bit flat segmentation model
   - Null descriptor at index 0
   - Kernel code segment (0x08): DPL=0, executable, 64-bit
   - Kernel data segment (0x10): DPL=0, writable
   - User code segment (0x18): DPL=3, executable
   - User data segment (0x20): DPL=3, writable
   - TSS descriptor (0x28): 16-byte descriptor for Task State Segment

2. **TSS Configuration**
   - Sets up Task State Segment for interrupt handling
   - Configures RSP0 for kernel stack on interrupts
   - Sets IO permission bitmap offset

3. **Segment Reload**
   - Loads new GDT with LGDT instruction
   - Reloads all segment registers
   - Tests GDT functionality

### Phase 5: Kernel Main Entry

**Location:** `kernel/src/main.zig:31-96`  
**Purpose:** Main kernel initialization phase 1 (before stack switch)

1. **Initial Setup** (`main.zig:32-55`)
   - Sets KASLR offset for address sanitization
   - Prints boot info and validation status
   - Displays kernel hash verification result
   - Shows kernel SHA-256 hash
   - Tests GDT functionality

2. **Basic Security** (`main.zig:64`)
   - Calls `security_init.initBasic()`
   - Initializes I/O port security
   - Enables Spectre V1 mitigations

3. **CPU Initialization** (`main.zig:71`)
   - Calls `cpu_init.init()`
   - Detects CPU features via CPUID
   - Enables CPU security features
   - Tests SMAP, RNG, and initializes CFI

4. **Memory Phase 1** (`main.zig:77-81`)
   - Calls `memory_init.initPhase1()`
   - Initializes paging with W^X enforcement
   - Initializes physical memory manager
   - Allocates 128KB kernel stack

5. **Stack Switch** (`main.zig:92-95`)
   - Saves boot info and stack info for phase 2
   - Calls `stack_switch.switchStackAndContinue()`
   - Continues at `kernelMainPhase2`

### Phase 6: Kernel Main Phase 2

**Location:** `kernel/src/main.zig:99-194`  
**Purpose:** Main kernel initialization phase 2 (after stack switch)

1. **Memory Phase 2** (`main.zig:104-108`)
   - Calls `memory_init.initPhase2()`
   - Updates stack security with new stack info
   - Initializes virtual memory manager (VMM)
   - Sets up kernel heap and slab allocators

2. **Full Security** (`main.zig:114-118`)
   - Calls `security_init.initFull()`
   - Full I/O security with TSS I/O bitmap
   - Full interrupt security with dynamic IST stacks
   - Advanced stack protection features
   - Stack guard pages setup

3. **Complete CPU Features** (`main.zig:121-124`)
   - Calls `cpu_init.initComplete()`
   - Complete CET initialization with shadow stacks
   - Tests CET functionality

4. **Hardware Initialization** (`main.zig:127`)
   - Calls `hardware_init.init()`
   - Enhanced interrupt handling
   - APIC initialization and testing
   - Timer subsystem setup

5. **System Information** (`main.zig:135-152`)
   - Prints boot validation status
   - Shows kernel base and size
   - Reports memory map regions
   - Displays ACPI RSDP if available

6. **Diagnostic Tests** (`main.zig:155-173`)
   - Runs all diagnostic tests
   - Tests runtime info integrity
   - Tests spinlock functionality
   - Tests CFI functionality
   - Tests advanced memory features
   - Tests memory protection

7. **Statistics and Final Setup** (`main.zig:175-187`)
   - Reports memory, security, and CPU statistics
   - Prepares for interrupts (masks spurious)
   - Enables interrupts with STI
   - Prints final hardware statistics

8. **Main Loop** (`main.zig:191-193`)
   - Enters HLT loop waiting for interrupts

## Modular Initialization Details

The kernel uses a modular initialization system with dedicated modules for each subsystem:

### Early Initialization Module (`init/early.zig`)

**Purpose:** Early system setup including IDT and stack security

1. **Minimal IDT** (`early.zig:17`)
   - Sets up critical exception handlers
   - Essential for catching early boot failures

2. **Full IDT** (`early.zig:20`)
   - Installs all exception and interrupt handlers
   - Configures IST entries for critical exceptions

3. **Boot Entropy** (`early.zig:23`)
   - Initializes entropy from UEFI boot info
   - Prepares for stack security

4. **Stack Security** (`early.zig:26`)
   - Initializes canary system
   - TSC-based entropy generation
   - Shadow stack for canary storage

### Security Initialization Module (`init/security.zig`)

**Purpose:** Coordinate all security subsystem initialization

1. **Basic Security** (`security.zig:12-25`)
   - I/O port security with privilege checking
   - Trusted port allowlist configuration
   - Spectre V1 mitigation initialization

2. **Full Security** (`security.zig:28-65`)
   - Full I/O security with TSS I/O bitmap (8KB)
   - Hardware IOPB enforcement testing
   - Full interrupt security with dynamic IST stacks
   - Advanced stack protection features
   - Stack guard pages setup

### CPU Initialization Module (`init/cpu.zig`)

**Purpose:** Manage CPU feature detection and security

1. **CPU Detection** (`cpu.zig:15-16`)
   - Detects features via CPUID
   - Reports available capabilities

2. **Security Features** (`cpu.zig:19-21`)
   - Enables NX, SMEP, SMAP, UMIP
   - Configures XSAVE, FSGSBASE, PCID
   - Enables CET, PKU if available
   - Initializes speculation mitigations

3. **Testing** (`cpu.zig:24-29`)
   - Tests SMAP functionality
   - Verifies hardware RNG
   - Initializes Control Flow Integrity

4. **Complete Initialization** (`cpu.zig:37-48`)
   - Full CET support with memory management
   - Shadow stack allocation
   - Indirect branch tracking

### Memory Initialization Module (`init/memory.zig`)

**Purpose:** Two-phase memory subsystem initialization

1. **Phase 1** (`memory.zig:20-52`)
   - Initializes paging with W^X enforcement
   - Sets up physical memory manager (PMM)
   - Allocates 128KB kernel stack
   - Returns stack info for phase 2

2. **Phase 2** (`memory.zig:55-75`)
   - Updates stack security with new stack
   - Initializes virtual memory manager (VMM)
   - Sets up kernel heap
   - Configures slab allocators

3. **Testing** (`memory.zig:78-89`)
   - Memory protection verification
   - Advanced paging features
   - PAT, PKU, reserved bits, LA57

### Hardware Initialization Module (`init/hardware.zig`)

**Purpose:** Initialize hardware components

1. **Interrupt System** (`hardware.zig:13-15`)
   - Enhanced interrupt handling
   - Statistics tracking

2. **APIC** (`hardware.zig:18-34`)
   - Local APIC initialization
   - Functionality testing
   - Fallback to legacy PIC

3. **Timer** (`hardware.zig:37-39`)
   - Timer subsystem setup
   - APIC timer calibration
   - PIT fallback support

4. **Interrupt Control** (`hardware.zig:43-54`)
   - Masks spurious interrupts
   - Enables interrupts with STI

### Diagnostics Module (`init/diagnostics.zig`)

**Purpose:** Comprehensive system testing

The diagnostics module runs all system tests to verify proper initialization.

### Stack Switch Module (`init/stack_switch.zig`)

**Purpose:** Safely switch from boot stack to kernel stack

Provides assembly routine to switch stacks while preserving execution flow.

## Key Subsystem Details

### Interrupt Descriptor Table (IDT)

The IDT is configured in multiple stages:

1. **Minimal IDT** (via `early_init`)
   - Critical exception handlers only
   - Used before stack switch

2. **Full IDT** (via `early_init`)
   - All 256 interrupt vectors
   - Exception handlers (0-31) with IST support
   - Interrupt handlers (32-255)
   - IST assignments:
     - IST 1: Double Fault (#DF)
     - IST 2: NMI
     - IST 3: Machine Check (#MC)
     - IST 4: Stack Fault (#SS)
     - IST 5: General Protection (#GP)
     - IST 6: Page Fault (#PF)
     - IST 7: Debug (#DB)

### Virtual Memory Management

1. **Paging** (via `memory_init`)
   - Identity mapping for first 64MB (2MB pages)
   - Kernel mapping with 4KB pages
   - W^X enforcement
   - PAT configuration
   - Protection keys support

2. **Physical Memory Manager**
   - Bitmap-based allocation
   - Memory tagging system
   - Security features (double-free detection, poisoning)

3. **Virtual Memory Manager**
   - Kernel heap management
   - Slab allocators
   - Dynamic allocation support

### CPU Security Features

1. **Basic Features** (via `cpu_init`)
   - NX/DEP: Data Execution Prevention
   - SMEP/SMAP: Supervisor mode protections
   - UMIP: User-mode instruction prevention
   - XSAVE: Extended state management
   - FSGSBASE: Fast segment access
   - PCID: Process context identifiers

2. **Advanced Features** (via `cpu_init.initComplete`)
   - CET: Control-flow Enforcement Technology
   - Shadow stack and IBT
   - PKU: Protection Keys for Userspace
   - Speculation mitigations

### Hardware Components

1. **APIC** (via `hardware_init`)
   - Local APIC initialization
   - Interrupt routing
   - Timer support
   - Legacy PIC masking

2. **Timer Subsystem**
   - PIT for calibration
   - APIC timer for primary timing
   - TSC for high-resolution timestamps

### Security Systems

1. **Stack Security**
   - CanaryGuard system with TSC entropy
   - Shadow stack for canary storage
   - Guard pages for overflow detection
   - Per-CPU support ready

2. **I/O Security**
   - Privilege level checking
   - TSS I/O bitmap (8KB)
   - Port allowlist system
   - Access logging

3. **Interrupt Security**
   - Dynamic IST stacks with guard pages
   - Context validation
   - XSAVE integration
   - Privilege transition monitoring

## Security Features Summary

### Memory Protection

- **W^X Enforcement**: No pages are both writable and executable
- **KASLR**: Dynamic kernel relocation with 6-9 bits of entropy
- **Guard Pages**: Detect buffer overflows and stack corruption
- **PAT Support**: Fine-grained memory type control
- **Protection Keys**: Hardware-enforced memory protection domains

### CPU Security

- **NX/DEP**: Data Execution Prevention
- **SMEP/SMAP**: Ring 0 protection from ring 3
- **UMIP**: User-mode instruction prevention
- **CET**: Control-flow integrity (shadow stack + IBT)
- **PCID**: TLB isolation between processes

### Control Flow Integrity

- **Forward-Edge CFI**: Software-based indirect call validation
- **Function Type Validation**: Type-based function set checking
- **Intel CET Integration**: Hardware shadow stack and IBT
- **Violation Detection**: Runtime CFI violation reporting

### Stack Security

- **CanaryGuard**: TSC-based stack canaries
- **Shadow Stack**: Hardware-enforced return address protection
- **Guard Pages**: Detect stack overflows
- **IST**: Separate stacks for critical exceptions with guard pages

### I/O Security

- **Privilege Checking**: All I/O requires ring 0
- **TSS I/O Bitmap**: Per-port access control
- **Access Logging**: Audit trail for I/O operations
- **Port Allowlist**: Only trusted ports accessible

### Interrupt Security

- **IST Stacks**: Dedicated stacks for critical exceptions
- **Context Validation**: Full CPU state preservation
- **Privilege Transitions**: Secure user/kernel transitions
- **Extended State**: XSAVE integration for AVX/FPU state

## Modular Architecture Benefits

The kernel's modular initialization system provides several advantages:

1. **Clear Separation of Concerns**
   - Each module handles a specific subsystem
   - Dependencies are explicit and manageable
   - Easy to understand initialization flow

2. **Phased Initialization**
   - Basic features before advanced ones
   - Stack switch handled cleanly
   - Memory dependencies respected

3. **Error Isolation**
   - Failures contained within modules
   - Graceful degradation possible
   - Clear error reporting

4. **Testability**
   - Each module can include self-tests
   - Integration tests via diagnostics module
   - Statistics and reporting per module

## Error Handling

The kernel implements comprehensive error handling:

1. **Boot Validation Failure**: Immediate halt
2. **CPU State Mismatch**: Panic with diagnostic
3. **Memory Allocation Failure**: Graceful degradation
4. **Feature Unavailable**: Fallback to legacy mode
5. **Security Violation**: Log and halt/recover based on severity

## Testing and Verification

Each initialization phase includes self-tests:

- **GDT**: Segment register verification
- **IDT**: Exception handler testing
- **Paging**: Memory protection verification, PAT, PKU, reserved bits, LA57
- **PMM**: Security features, tagging, double-free detection
- **VMM**: Heap allocation, slab allocators
- **APIC**: Register access and interrupt delivery
- **Timer**: Calibration and accuracy tests
- **Stack Security**: Canary implementation, guard pages
- **I/O Security**: IOPB enforcement, access control
- **CFI**: Forward-edge control flow validation
- **CET**: Shadow stack and IBT functionality
- **Spinlock**: Concurrency primitives
- **Runtime Info**: Integrity protection

## Future Enhancements

- SMP support (per-CPU structures ready)
- IOMMU integration
- Secure boot chain verification
- Hardware virtualization support
- Advanced power management
- PIE mode page table activation (bootloader coordination needed)
