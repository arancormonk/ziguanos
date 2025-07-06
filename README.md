# Ziguanos

A security-focused x86-64 operating system written in Zig, designed with comprehensive hardware security features and modern architectural practices.

## Overview

Ziguanos is an experimental operating system that demonstrates how to build a secure, modern OS kernel using the Zig programming language. It boots via UEFI and implements extensive security features including KASLR, stack protection, I/O port security, and leverages advanced x86-64 CPU capabilities.

### Key Features

- **UEFI Boot**: Modern UEFI-only boot process with secure boot support
- **Security-First Design**: Multiple layers of protection from boot to runtime
- **Written in Zig**: Leverages Zig's safety features and compile-time capabilities
- **Minimal Assembly**: Limited to interrupt/exception stubs
- **Hardware Security**: Extensive use of modern CPU security features
- **Advanced CPU Support**: XSAVE, AVX/AVX2, FSGSBASE, LA57, PKU, CET
- **Control Flow Integrity**: Forward-edge and backward-edge CFI with Intel CET
- **Modern Interrupt Handling**: APIC with high-precision timer support

## Security Features

### Boot-Time Security

- **SHA-256 Kernel Verification**: Cryptographic verification of kernel integrity
- **HMAC-SHA256 Authentication**: Key-based message authentication for enhanced security
- **KASLR (Kernel Address Space Layout Randomization)**:
  - Dynamic memory-aware randomization based on available contiguous memory
  - Intel-compliant hardware RNG using RDSEED/RDRAND with fallbacks
  - Entropy mixing from multiple sources using SipHash-1-2
  - Full ELF relocation support for Position Independent Executables
  - Configurable alignment modes (64KB/2MB/16MB) for different entropy levels
  - Runtime configuration via UEFI variables
- **Secure Boot Integration**: Hash and HMAC verification enforced in secure mode
- **Buffer Overflow Protection**: Safe memory operations in bootloader
- **Runtime Address Sanitization**: Automatic masking of kernel addresses in logs
- **Security Policy Framework**: Configurable security enforcement levels
- **Secure Debugging**: Sanitized error messages and debug output

### Runtime Security

#### Stack Protection

- **CanaryGuard System**: TSC-based canary protection with automatic verification
- **CET Shadow Stacks**: Hardware-enforced return address protection (Intel CET)
- **Per-CPU Shadow Stacks**: Isolated shadow stacks for each CPU core
- **Dynamic Shadow Stack Growth**: Automatic expansion with guard pages
- **Dynamic Entropy**: TSC + hardware RNG for canary generation
- **RAII Pattern**: Automatic cleanup via Zig's defer mechanism
- **Stack Guard Pages**: Protection boundaries with PMM integration

#### I/O Port Security

- **Privilege Verification**: All I/O operations verify CPL=0
- **TSS I/O Bitmap**: 8KB bitmap for fine-grained port control
- **Port Allowlisting**: Configurable trusted port ranges
- **Access Statistics**: Real-time tracking and security monitoring

#### CPU Security Features

- **W^X Enforcement**: Strict separation of writable and executable pages
- **NX Bit**: Full support including 1GB huge pages
- **SMEP/SMAP**: Supervisor Mode Execution/Access Prevention
- **UMIP**: User-Mode Instruction Prevention
- **CET**: Control-flow Enforcement Technology with shadow stacks
- **CFI**: Control Flow Integrity for indirect calls
- **PKU**: Protection Keys with 16 configurable domains
- **XSAVE/XRSTOR**: Extended CPU state management
- **FSGSBASE**: Fast segment register operations
- **LA57**: 5-level paging (57-bit virtual addresses)

#### Memory Protection

- **Physical Memory Manager**:
  - Secure bitmap allocator with canary protection
  - Memory tagging and tracking (16 tags)
  - Double-free detection
  - Poison-on-free security feature
- **Virtual Memory Manager**:
  - Multi-level paging (4KB, 2MB, 1GB pages)
  - Higher-half kernel mapping
  - Reserved bit validation
  - PAT support for cache control
- **Guard Pages**: Automatic allocation boundaries
- **IST**: 7-level Interrupt Stack Table with guard pages

#### CPU Speculation Mitigations

- **Spectre V2**: IBRS/Enhanced IBRS, STIBP for SMT, IBPB on context switch
- **Speculative Store Bypass**: SSBD via IA32_SPEC_CTRL
- **Meltdown**: Detection and warnings (KPTI ready when needed)
- **MDS/TAA**: VERW-based buffer clearing, TSX disable
- **L1D Cache**: Hardware and software flush capabilities
- **Spectre V1**: Array bounds masking helpers

## Hardware Support

### APIC (Advanced Programmable Interrupt Controller)

- Local APIC with modern interrupt handling
- High-precision timer with automatic calibration
- Flexible interrupt routing and prioritization
- Comprehensive error detection and reporting
- Future multi-core IPI support ready

### Timer Subsystem

- **Primary**: APIC timer with microsecond precision
- **Fallback**: 8254 PIT for calibration
- **TSC**: Time Stamp Counter for high-resolution timing
- **Features**: Precise delays, uptime tracking, interrupt-driven
- **Protection**: Overflow protection for long-running systems

### Interrupt and Exception Handling

- Full IDT with all 256 vectors configured
- Detailed exception diagnostics with register dumps
- Enhanced assembly stubs with SWAPGS and speculation barriers
- IST support for critical exceptions
- Privilege transition validation
- Comprehensive security statistics

## System Requirements

### Build Requirements

- **Zig**: Version 0.14.1 (required - other versions may not be compatible)
- **QEMU**: Version 6.0+ with KVM support recommended
- **OVMF**: UEFI firmware for QEMU
- **mtools**: For FAT32 disk image creation (no sudo required)
- **POSIX Tools**: bash, dd, sha256sum
- **Optional**: efibootmgr for UEFI variable configuration

### Runtime Requirements

- **Architecture**: x86-64 processor with SSE2 minimum
- **Boot**: UEFI firmware (no legacy BIOS)
- **Memory**: Minimum 64MB RAM (1GB+ for full KASLR)

## Building

```bash
# Clone the repository
git clone https://github.com/arancormonk/ziguanos.git
cd ziguanos

# Build everything (kernel and bootloader)
zig build

# Build and test in QEMU (headless mode)
zig build test

# Build and run in QEMU with GUI
zig build run

# Create bootable disk image
zig build disk
```

### Build Commands

| Command | Description |
|---------|-------------|
| `zig build` | Build kernel and UEFI bootloader |
| `zig build test` | Build and test in QEMU (headless) |
| `zig build run` | Build and run in QEMU with GUI |
| `zig build disk` | Create bootable UEFI disk image |
| `zig build kernel` | Build kernel only |
| `zig build uefi` | Build UEFI bootloader only |
| `zig build clean` | Clean all build artifacts |

## Project Structure

```text
ziguanos/
├── bootloader/
│   └── uefi/                       # UEFI bootloader
│       └── src/
│           ├── main.zig            # UEFI entry point
│           ├── boot/               # Kernel loading and KASLR
│           │   ├── coordinator.zig # Boot process orchestration
│           │   ├── elf/            # ELF loading and relocation
│           │   ├── entropy/        # Entropy collection and mixing
│           │   ├── kaslr/          # KASLR configuration and generation
│           │   ├── kernel_loader.zig
│           │   ├── memory.zig
│           │   └── vmm.zig
│           ├── drivers/            # Serial output
│           ├── security/           # Security components
│           │   ├── buffer_safety.zig
│           │   ├── hmac.zig        # HMAC-SHA256 implementation
│           │   ├── sha256.zig
│           │   ├── verify.zig
│           │   ├── key_management.zig
│           │   ├── policy.zig      # Security policy framework
│           │   ├── secure_log.zig  # Secure logging
│           │   └── variable_cache.zig # UEFI variable caching
│           └── utils/              # Utility modules
│               ├── console.zig
│               ├── error_handler.zig
│               └── memory_manager.zig
├── kernel/
│   ├── kernel.ld                   # Linker script (PIE-enabled)
│   └── src/
│       ├── main.zig                # Kernel main entry
│       ├── boot/                   # Boot protocol handling
│       │   ├── entry.S             # Assembly entry point
│       │   ├── entry.zig           # Zig entry wrapper
│       │   ├── init.zig            # Initialization orchestration
│       │   ├── runtime_info.zig    # KASLR offset management
│       │   └── validation.zig      # Boot validation
│       ├── drivers/                # Device drivers
│       │   ├── serial.zig          # Serial driver main
│       │   └── serial/             # Modular serial components
│       │       ├── api.zig         # Public API
│       │       ├── core/           # Core driver functionality
│       │       ├── hal/            # Hardware abstraction layer
│       │       ├── security/       # Security features
│       │       └── advanced/       # Advanced features
│       ├── init/                   # Modular initialization
│       │   ├── early.zig           # Early boot setup
│       │   ├── cpu.zig             # CPU initialization
│       │   ├── memory.zig          # Memory setup
│       │   ├── hardware.zig        # Hardware initialization
│       │   └── security.zig        # Security initialization
│       ├── lib/                    # Core utilities
│       │   ├── panic.zig           # Panic handler
│       │   ├── secure_print.zig    # Secure printing utilities
│       │   └── spinlock.zig        # Synchronization primitives
│       ├── memory/                 # Memory management
│       │   ├── pmm.zig             # Physical memory manager
│       │   ├── pmm/                # PMM components
│       │   │   ├── bloom_filter.zig
│       │   │   ├── free_tracker.zig
│       │   │   ├── guard_pages.zig
│       │   │   ├── memory_security.zig
│       │   │   └── statistics.zig
│       │   ├── vmm.zig             # Virtual memory manager
│       │   └── heap.zig            # Heap allocator
│       └── x86_64/                 # Architecture code
│           ├── apic.zig            # APIC controller
│           ├── cpu_init.zig        # CPU feature setup
│           ├── cpu_state.zig       # State verification
│           ├── cpuid.zig           # Feature detection
│           ├── exception_stubs.S   # Exception entry (asm)
│           ├── exceptions.zig      # Exception handlers
│           ├── gdt.zig             # Global Descriptor Table
│           ├── idt.zig             # Interrupt Descriptor Table
│           ├── interrupt_security.zig # IST stack management
│           ├── interrupt_stubs.S   # Interrupt entry (asm)
│           ├── interrupts.zig      # Interrupt handlers
│           ├── io_security.zig     # I/O port protection
│           ├── paging.zig          # Page tables
│           ├── paging/             # Paging components
│           │   ├── constants.zig
│           │   ├── guard_pages.zig
│           │   ├── la57.zig        # 5-level paging
│           │   ├── pat.zig         # Page Attribute Table
│           │   ├── pcid.zig        # Process Context IDs
│           │   ├── pku.zig         # Protection Keys
│           │   └── shadow_stack.zig # CET shadow stacks
│           ├── rng.zig             # Hardware RNG
│           ├── smap.zig            # SMAP support
│           ├── spectre_v1.zig      # Spectre V1 mitigations
│           ├── speculation.zig     # CPU speculation mitigations
│           ├── stack_security.zig  # Stack canaries
│           ├── cfi.zig             # Control Flow Integrity
│           ├── cfi_exception.zig   # CFI exception handler
│           └── timer.zig           # Timer subsystem
├── shared/
│   ├── boot_protocol.zig          # Boot info protocol
│   └── security_config.zig        # Shared security configuration
├── scripts/                        # Build and utility scripts
│   ├── generate_kernel_hash.sh
│   ├── generate_kernel_hmac.sh     # HMAC generation
│   └── configure_ziguanos.sh       # Configuration utility
├── docs/              # Documentation
│   └── architecture/   # Architecture and design guides
│       ├── kernel_initialization_guide.md
│       └── zig_x86_assembly_guide.md
└── build.zig                       # Build configuration
```

## Boot Process

1. **UEFI Firmware** loads BOOTX64.EFI from `/EFI/BOOT/` on ESP
2. **UEFI Bootloader** (`bootloader/uefi/`):
   - Initializes serial console for debugging
   - Checks UEFI Secure Boot status
   - Loads kernel ELF from `/kernel.elf`
   - Verifies kernel SHA-256 hash and HMAC-SHA256 authentication
   - Implements KASLR with hardware RNG
   - Collects entropy from multiple sources (TSC, RNG, memory layout)
   - Processes ELF relocations for PIE support
   - Manages security policy enforcement
   - Gets UEFI memory map
   - Exits boot services
   - Jumps to kernel entry with boot info
3. **Kernel Initialization** (`kernel/`):
   - Assembly entry point validates environment
   - Modular initialization system:
     - **Early Init**: Basic CPU state and stack setup
     - **CPU Init**: Feature detection and security configuration
     - **Memory Init**: Page tables, PMM, VMM setup
     - **Hardware Init**: APIC, timers, interrupts
     - **Security Init**: Stack protection, I/O security, mitigations
   - Sets up early CPU state:
     - GDT with kernel segments
     - IDT with exception handlers
     - Stack switch to kernel stack
   - Initializes core subsystems:
     - Stack security (CanaryGuard)
     - Modular serial console with security features
     - I/O port security framework
   - Detects and enables CPU features:
     - CPUID feature detection
     - Security features (NX, SMEP, SMAP, etc.)
     - Extended features (XSAVE, AVX, etc.)
   - Sets up memory management:
     - Identity maps first 16GB
     - Creates kernel page tables
     - Initializes PMM with security features
     - Sets up VMM with guard pages
   - Initializes hardware:
     - APIC with timer calibration
     - Enhanced interrupt handling
     - IST for critical exceptions
   - Runs self-tests and enters idle

## Development

### Testing

```bash
# Run automated tests
zig build test

# Run with GUI for debugging
zig build run

# Check logs after testing
cat serial.log  # Kernel debug output
cat qemu.log    # QEMU diagnostics
```

### Configuration

Ziguanos supports runtime configuration through UEFI variables and a configuration file:

```bash
# Configure build options via config file
./scripts/configure_ziguanos.sh show     # Show current configuration
./scripts/configure_ziguanos.sh defaults  # Reset to defaults
./scripts/configure_ziguanos.sh set KASLR_ENTROPY 8

# Generate kernel authentication keys
./scripts/generate_kernel_hash.sh  # Generate SHA-256 hash
./scripts/generate_kernel_hmac.sh  # Generate HMAC key and tag

# View UEFI configuration (if UEFI variables are used)
efibootmgr -v | grep ZIGUANOS
```

### Security Guidelines

When implementing security-sensitive code:

```zig
fn sensitiveFunction() void {
    // Add stack protection for functions handling external data
    var guard = stack_security.protect();
    defer guard.deinit();

    // Verify I/O privilege for port access
    const port_allowed = io_security.checkPortAccess(port);
    if (!port_allowed) return error.AccessDenied;

    // Your implementation here
}
```

### Memory Allocation

```zig
// Physical memory allocation
const pages = pmm.allocPages(4) orelse return error.OutOfMemory;
defer pmm.freePages(pages, 4);

// Tagged allocation for tracking
const driver_mem = pmm.allocPagesTagged(1, pmm.MemoryTag.DRIVER) orelse return error.OutOfMemory;
```

### Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Implement with security best practices
4. Run tests (`zig build test`)
5. Commit your changes
6. Push to the branch
7. Open a Pull Request

## Documentation

### Architecture Documentation

- [Kernel Initialization Guide](docs/architecture/kernel_initialization_guide.md) - Detailed boot sequence
- [Zig x86 Assembly Guide](docs/architecture/zig_x86_assembly_guide.md) - Assembly integration patterns

### Refactoring Documentation

- [Refactoring Recommendations](docs/refactoring/refactoring_recommendations.md) - Code improvement suggestions

## Current Status

Ziguanos is actively developed as a research OS focusing on security. Currently implemented:

### Boot and Core

- ✅ UEFI bootloader with SHA-256 and HMAC-SHA256 verification
- ✅ Advanced KASLR with hardware RNG and dynamic memory adaptation
- ✅ Modular boot process with security policy framework
- ✅ Position Independent Executable kernel
- ✅ Full x86-64 initialization (GDT, IDT, TSS)
- ✅ Comprehensive exception and interrupt handling with IST
- ✅ Modular kernel initialization system

### Memory Management

- ✅ Physical Memory Manager with security features:
  - Bitmap allocator with canary protection
  - Memory tagging (16 tags)
  - Double-free detection
  - Poison-on-free
  - Bloom filter for fast lookups
  - Guard page management
  - Comprehensive statistics tracking
- ✅ Virtual Memory Manager:
  - 4KB, 2MB, 1GB page support
  - 5-level paging (LA57) support
  - PAT for cache control
  - Protection Keys (PKU)
  - Reserved bit validation
  - PCID support for TLB optimization
  - Shadow stack page management

### Security Features

- ✅ Stack protection (CanaryGuard with TSC entropy)
- ✅ CET Shadow Stacks (per-CPU with dynamic growth)
- ✅ Control Flow Integrity (CFI) for indirect calls
- ✅ I/O port security with TSS bitmap
- ✅ W^X enforcement across all memory
- ✅ SMEP/SMAP (when available)
- ✅ UMIP (User-Mode Instruction Prevention)
- ✅ CET (Control-flow Enforcement Technology)
- ✅ XSAVE/XRSTOR for extended states
- ✅ FSGSBASE support
- ✅ Hardware RNG (RDRAND/RDSEED)
- ✅ CPU speculation mitigations (Spectre/Meltdown variants)
- ✅ Spectre V1 specific mitigations with array bounds masking
- ✅ HMAC-based key derivation (NIST SP 800-108)
- ✅ Secure error handling and sanitization
- ✅ Spinlock synchronization primitives

### Hardware Support

- ✅ Local APIC with timer
- ✅ PIT for calibration
- ✅ TSC for high-resolution timing
- ✅ Modular serial console with:
  - Hardware abstraction layer (HAL)
  - Security features (address sanitization, timing attack mitigation)
  - Advanced formatting and statistics
  - Per-CPU and global queuing
- ✅ IST with 7 levels
- ⚠️  VGA text mode (minimal - panic handler only)

### Roadmap

- [ ] SMP (Multi-core support)
- [ ] IOMMU support
- [ ] UEFI runtime services
- [ ] ACPI parsing
- [ ] User-space and syscalls
- [ ] Process management
- [ ] File systems (ext4, FAT32)
- [ ] Network stack
- [ ] Device driver framework
- [ ] Virtualization extensions
- [ ] TPM integration
- [ ] Measured boot

## Architecture Philosophy

Ziguanos follows several key design principles:

1. **Security by Default**: Every component is designed with security as the primary concern
2. **Zero Trust**: All inputs are validated, all operations are verified
3. **Defense in Depth**: Multiple layers of protection at every level
4. **Fail Secure**: Security failures result in denial rather than compromise
5. **Minimal Trust Base**: Reduce attack surface by minimizing privileged code

## Performance Characteristics

- **Boot Time**: ~1-2 seconds from UEFI to kernel idle
- **Memory Overhead**: ~16MB for core kernel structures
- **Interrupt Latency**: <1μs with APIC timer
- **Context Switch**: Not yet implemented (no processes)
- **KASLR Overhead**: <10ms during boot

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Zig programming language team for excellent systems programming support
- UEFI Forum for comprehensive boot specifications
- Intel and AMD for detailed processor manuals
- The OS development community for invaluable resources

## Contact

For questions, issues, or contributions, please open an issue on GitHub.

---

**Note**: Ziguanos is an experimental operating system intended for educational and research purposes. It demonstrates modern OS security concepts but is not suitable for production use.
