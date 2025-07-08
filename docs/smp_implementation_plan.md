# Symmetric Multi-Processing (SMP) Implementation Plan for Ziguanos

## Overview

This document provides a detailed, step-by-step plan for implementing Symmetric Multi-Processing (SMP) support in the Ziguanos operating system. The plan follows Intel x86-64 architecture recommendations and industry-standard practices for multi-processor systems.

## Prerequisites

Before beginning SMP implementation, ensure the following components are working correctly:

- ✅ Local APIC driver (`kernel/src/x86_64/apic.zig`)
- ✅ Interrupt handling with IDT
- ✅ Physical and virtual memory management
- ✅ Spinlock implementation
- ✅ UEFI boot protocol with RSDP address

## Phase 1: ACPI Table Infrastructure

### Step 1.1: ACPI Table Parser Module ✅ COMPLETED

**Location**: `kernel/src/drivers/acpi/`

Create a modular ACPI subsystem:

```
kernel/src/drivers/acpi/
├── acpi.zig          # Main ACPI interface
├── tables.zig        # Table structure definitions
├── rsdp.zig          # RSDP/RSDT/XSDT parsing
├── madt.zig          # MADT (APIC) table parsing
└── checksum.zig     # Table validation utilities
```

**Implementation Details** ✅:

1. ✅ Define ACPI table structures following the ACPI specification
2. ✅ Implement RSDP validation (check signature "RSD PTR ", checksum)
3. ✅ Support both ACPI 1.0 (RSDT) and 2.0+ (XSDT) tables
4. ✅ Create table enumeration functions to find specific tables by signature
5. ✅ Implement comprehensive error handling for malformed tables

**Completed Features**:

- ACPI table structure definitions (`tables.zig`)
- RSDP/RSDT/XSDT parsing (`rsdp.zig`)
- Checksum validation utilities (`checksum.zig`)
- Main ACPI subsystem interface (`acpi.zig`)
- Integration with kernel initialization in `hardware_init.zig`
- Global kernel allocator wrapper for heap allocation
- Successfully finds and validates ACPI tables in QEMU

### Step 1.2: MADT Parser Implementation ✅ COMPLETED

**Location**: `kernel/src/drivers/acpi/madt.zig`

Parse the Multiple APIC Description Table to discover:

- ✅ Processor Local APICs (type 0)
- ✅ I/O APICs (type 1)
- ✅ Interrupt Source Overrides (type 2)
- ✅ NMI sources (type 3/4)
- ✅ Local APIC address override (type 5)
- ✅ Processor Local x2APIC (type 9) for systems with >255 CPUs

**Data Structures**:

```zig
pub const ProcessorInfo = struct {
    processor_id: u8,
    apic_id: u8,
    flags: u32,  // bit 0: processor enabled
};

pub const SystemTopology = struct {
    processors: []ProcessorInfo,
    io_apics: []IoApicInfo,
    boot_cpu_id: u8,
    total_cpus: u32,
};
```

**Completed Features**:

- Full MADT table parsing with iterator support
- Support for all common MADT entry types
- x2APIC support for large systems (>255 CPUs)
- System topology extraction with processor and I/O APIC information
- Integration with main ACPI subsystem
- Comprehensive error handling and validation
- Successfully detects CPUs in QEMU virtual machine

## Phase 2: Per-CPU Infrastructure

### Step 2.1: Per-CPU Data Structures

**Location**: `kernel/src/smp/per_cpu.zig`

Design per-CPU structures:

```zig
pub const CpuData = struct {
    // Identification
    cpu_id: u32,              // Logical CPU ID (0, 1, 2...)
    apic_id: u8,              // Physical APIC ID

    // Stacks
    kernel_stack: [*]u8,      // Top of kernel stack
    ist_stacks: [7][*]u8,     // Interrupt stack table

    // State
    self_ptr: *CpuData,       // Self-reference for GSBASE
    current_task: ?*Task,     // Current running task
    idle_task: *Task,         // CPU idle task

    // Statistics
    context_switches: u64,
    interrupts_handled: u64,

    // Synchronization
    tlb_flush_pending: bool,
    ipi_pending: u32,
};
```

### Step 2.2: CPU Local Storage

**Location**: `kernel/src/smp/cpu_local.zig`

Implement fast per-CPU variable access:

1. Use GSBASE to point to current CPU's data structure
2. Provide inline functions for accessing current CPU data
3. Implement per-CPU allocator for dynamic per-CPU variables
   - **Note**: Use kernel's heap allocator directly (`heap.heapAlloc`/`heap.heapFree`)
   - Do NOT use `std.mem.Allocator` interface
4. Add security checks to prevent cross-CPU access violations

## Phase 3: AP Startup Sequence

### Step 3.1: Trampoline Code

**Location**: `kernel/src/smp/trampoline.S`

Create 16-bit real mode trampoline:

```assembly
.code16
.global ap_trampoline_start
ap_trampoline_start:
    cli
    # Load GDT
    lgdt ap_gdtr - ap_trampoline_start + 0x8000

    # Enable protected mode
    mov %cr0, %eax
    or $1, %eax
    mov %eax, %cr0

    # Far jump to 32-bit code
    ljmp $0x08, $ap_32bit_entry - ap_trampoline_start + 0x8000

.code32
ap_32bit_entry:
    # Setup segments
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss

    # Enable PAE and long mode
    # ... (standard x86-64 initialization)

    # Jump to 64-bit kernel code
    ljmp $0x08, $ap_64bit_entry
```

### Step 3.2: AP Initialization Manager

**Location**: `kernel/src/smp/ap_init.zig`

Implement AP startup coordinator:

1. Allocate low memory page (< 1MB) for trampoline
2. Copy trampoline code and data structures
3. Prepare per-CPU stacks and data
4. Send INIT-SIPI-SIPI sequence
5. Wait for AP to signal readiness
6. Synchronize all CPUs before proceeding

**Synchronization Protocol**:

```zig
// Note: Use atomic primitives directly, not std.atomic types
pub const ApStartupState = struct {
    ap_ready_count: u32,  // Use @atomicLoad/@atomicStore
    ap_boot_error: u32,   // Use @atomicLoad/@atomicStore
    ap_stack_top: [*]u8,
    ap_cpu_data: *CpuData,
    proceed_signal: bool, // Use @atomicLoad/@atomicStore
};
```

### Step 3.3: AP Entry Point

**Location**: `kernel/src/smp/ap_entry.zig`

64-bit AP initialization code:

```zig
pub fn apMain(cpu_data: *CpuData) noreturn {
    // 1. Load GDT and IDT
    gdt.load();
    idt.load();

    // 2. Setup GSBASE for per-CPU access
    x86_64.wrmsr(0xC0000101, @intFromPtr(cpu_data));

    // 3. Initialize Local APIC
    apic.initLocalApic();

    // 4. Setup TSS and IST stacks
    setupTss(cpu_data);

    // 5. Enable CPU features (SMAP, SMEP, etc.)
    cpu_init.enableSecurityFeatures();

    // 6. Signal ready to BSP
    _ = @atomicRmw(u32, &startup_state.ap_ready_count, .Add, 1, .seq_cst);

    // 7. Wait for proceed signal
    while (!@atomicLoad(bool, &startup_state.proceed_signal, .acquire)) {
        x86_64.pause();
    }

    // 8. Enter scheduler
    scheduler.idleLoop();
}
```

## Phase 4: Inter-Processor Communication

### Step 4.1: IPI Management

**Location**: `kernel/src/smp/ipi.zig`

Enhance IPI handling:

```zig
pub const IpiType = enum(u8) {
    Reschedule = 0,
    TlbFlush = 1,
    CallFunction = 2,
    Panic = 3,
    Timer = 4,
};

pub const IpiHandler = struct {
    pub fn handle(vector: u8) void {
        const ipi_type = @enumFromInt(IpiType, vector - IPI_VECTOR_BASE);
        switch (ipi_type) {
            .Reschedule => scheduler.reschedule(),
            .TlbFlush => vmm.flushTlb(),
            .CallFunction => runPendingFunctions(),
            .Panic => handleRemotePanic(),
            .Timer => timer.handleIpi(),
        }
    }
};
```

### Step 4.2: TLB Shootdown

**Location**: `kernel/src/smp/tlb_shootdown.zig`

Implement TLB coherency:

1. Track CPUs using each address space
2. Send TLB flush IPIs when page tables change
3. Wait for acknowledgment from all CPUs
4. Optimize with targeted flushes (single page vs full)

### Step 4.3: Remote Function Calls

**Location**: `kernel/src/smp/call_function.zig`

Enable running functions on other CPUs:

```zig
pub fn callFunctionSingle(cpu_id: u32, func: *const fn() void) !void {
    // Queue function for target CPU
    // Send IPI
    // Wait for completion
}

pub fn callFunctionAll(func: *const fn() void) !void {
    // Broadcast to all CPUs except self
    // Wait for all to complete
}
```

## Phase 5: CPU Synchronization Primitives

### Step 5.1: Barriers

**Location**: `kernel/src/smp/barriers.zig`

Implement synchronization barriers:

```zig
pub const Barrier = struct {
    count: u32,      // Use atomic operations
    generation: u32, // Use atomic operations
    total_cpus: u32,

    pub fn wait(self: *Barrier) void {
        const gen = @atomicLoad(u32, &self.generation, .acquire);

        if (@atomicRmw(u32, &self.count, .Add, 1, .acq_rel) == self.total_cpus - 1) {
            // Last CPU to arrive, reset and release others
            @atomicStore(u32, &self.count, 0, .release);
            _ = @atomicRmw(u32, &self.generation, .Add, 1, .release);
        } else {
            // Wait for generation to change
            while (@atomicLoad(u32, &self.generation, .acquire) == gen) {
                x86_64.pause();
            }
        }
    }
};
```

### Step 5.2: Read-Write Locks

**Location**: `kernel/src/smp/rwlock.zig`

Implement reader-writer locks for better concurrency:

1. Multiple readers, single writer
2. Writer priority to prevent starvation
3. Interrupt-safe variants
4. Debug mode with ownership tracking

## Phase 6: Scheduler Foundation

### Step 6.1: Run Queue Management

**Location**: `kernel/src/scheduler/run_queue.zig`

Per-CPU run queues:

```zig
// Note: DoublyLinkedList must be implemented in kernel, not from std
pub const RunQueue = struct {
    ready_list: DoublyLinkedList(Task), // Kernel's own linked list implementation
    lock: SpinLock,
    load: u32,  // Use atomic operations

    pub fn enqueue(self: *RunQueue, task: *Task) void {
        const guard = self.lock.acquire();
        defer guard.release();

        self.ready_list.append(&task.sched_node);
        _ = @atomicRmw(u32, &self.load, .Add, 1, .release);
    }
};
```

### Step 6.2: CPU Selection

**Location**: `kernel/src/scheduler/cpu_select.zig`

Implement CPU selection algorithms:

1. Prefer previous CPU (cache affinity)
2. Load balancing across CPUs
3. NUMA awareness (future)
4. Power efficiency considerations

### Step 6.3: Context Switching

**Location**: `kernel/src/scheduler/context.zig`

Multi-CPU context switch:

1. Save current task state
2. Update per-CPU current task
3. Switch page tables if needed
4. Load new task state
5. Update performance counters

## Phase 7: Testing and Validation

### Step 7.1: SMP Boot Test

Create comprehensive boot tests:

1. Verify all CPUs start successfully
2. Check APIC ID consistency
3. Validate per-CPU data access
4. Test IPI delivery to each CPU

### Step 7.2: Synchronization Tests

Test synchronization primitives:

1. Spinlock contention tests
2. Barrier correctness
3. TLB shootdown verification
4. Atomic operation coherency

### Step 7.3: Stress Testing

Implement stress tests:

1. High-frequency IPI storms
2. Concurrent memory allocation
3. Page table modifications under load
4. CPU hotplug scenarios (future)

## Phase 8: Performance Optimization

### Step 8.1: Cache Line Optimization

1. Align per-CPU data to cache lines
2. Separate read-mostly and write-often data
3. Use percpu allocator for frequently accessed data

### Step 8.2: Lock Contention Reduction

1. Identify hot locks with statistics
2. Convert to per-CPU or lockless where possible
3. Implement MCS locks for high-contention areas

### Step 8.3: NUMA Optimization (Future)

1. NUMA node discovery via ACPI SRAT
2. Node-local memory allocation
3. CPU affinity for memory locality

## Implementation Order

1. **Week 1-2**: ACPI infrastructure and MADT parsing
2. **Week 3-4**: Per-CPU infrastructure and GS base setup
3. **Week 5-6**: AP trampoline and startup sequence
4. **Week 7-8**: IPI handling and TLB shootdown
5. **Week 9-10**: Synchronization primitives
6. **Week 11-12**: Basic scheduler with per-CPU queues
7. **Week 13-14**: Testing and validation
8. **Week 15-16**: Performance optimization

## Security Considerations

1. **AP Startup Security**:
   - Verify trampoline integrity before execution
   - Clear sensitive data from low memory after use
   - Validate CPU features match BSP

2. **Per-CPU Isolation**:
   - Prevent unauthorized cross-CPU access
   - Separate kernel stacks with guard pages
   - CPU-private mappings where appropriate

3. **IPI Security**:
   - Validate IPI sources
   - Rate-limit IPIs to prevent DoS
   - Audit privileged operations

## Success Criteria

1. All CPUs successfully initialize and enter idle loop
2. IPIs delivered reliably between all CPU pairs
3. TLB coherency maintained across all operations
4. No race conditions in synchronization primitives
5. Performance scales with CPU count
6. All security policies enforced on all CPUs

## References

1. Intel® 64 and IA-32 Architectures Software Developer's Manual Volume 3A: System Programming Guide
2. ACPI Specification Version 6.4
3. Intel MultiProcessor Specification Version 1.4
4. AMD64 Architecture Programmer's Manual Volume 2: System Programming

## Notes for AI Implementation

When implementing each phase:

1. Always check existing code for integration points
2. Maintain compatibility with current security features
3. Add comprehensive error handling and logging
4. Update CLAUDE.md with new build/test procedures
5. Create unit tests for each new component
6. Document all new public APIs with Zig doc comments
7. Follow existing code style and naming conventions
8. Ensure all changes compile with `zig build test`

## Important: Freestanding Kernel Constraints

**DO NOT use these standard library features in kernel code:**

- `std.ArrayList` - Use fixed-size arrays or direct allocator calls
- `std.HashMap` - Implement simple hash tables or use arrays
- `std.mem.Allocator` interface - Use kernel's heap allocator directly
- `std.io` - Kernel has its own I/O routines
- `std.fmt` - Use kernel's own formatting/printing functions
- `std.Thread` - Kernel manages its own threading
- `std.debug` - Use kernel's panic/debug facilities
- Any `std` features that allocate memory dynamically

**Safe to use:**

- Basic type definitions (`u8`, `u32`, etc.)
- Compile-time features (`comptime`, `inline`)
- Basic memory operations (`@memcpy`, `@memset`)
- Atomic operations (`@atomicLoad`, `@atomicStore`, etc.)
- Bitwise operations
- Type introspection (`@TypeOf`, `@sizeOf`, etc.)
- Error types and error handling
- Basic math operations
