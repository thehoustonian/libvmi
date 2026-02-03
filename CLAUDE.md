# CLAUDE.md - LibVMI Development Guide

## Project Overview

LibVMI is a C library for virtual machine introspection (VMI). It provides an abstraction layer over hypervisor-specific introspection APIs, enabling programs to read and write memory of running virtual machines or analyze physical memory dump files.

**Core capabilities:**
- Memory access (read/write) using physical addresses, virtual addresses, or kernel symbols
- Virtual-to-physical address translation via page table parsing
- Guest OS semantic extraction (process lists, module lists, etc.)
- Memory event monitoring (read/write/execute traps)
- Support for multiple hypervisors (Xen, KVM, Bareflank) and memory dump files

## Build System

LibVMI uses **CMake** (recommended) with autotools as a fallback.

### Quick Build

```bash
mkdir build && cd build
cmake ..
make
```

### Common Build Options

```bash
cmake .. -DENABLE_XEN=ON              # Xen driver (default: ON)
cmake .. -DENABLE_KVM=ON              # KVM driver (requires json-c)
cmake .. -DENABLE_FILE=ON             # File/memory dump driver (default: ON)
cmake .. -DENABLE_BAREFLANK=ON        # Bareflank driver
cmake .. -DENABLE_WINDOWS=ON          # Windows guest support
cmake .. -DENABLE_LINUX=ON            # Linux guest support
cmake .. -DENABLE_TESTING=ON          # Build test suite
cmake .. -DVMI_DEBUG='(VMI_DEBUG_XEN | VMI_DEBUG_CORE)'  # Debug output
cmake .. -DCMAKE_INSTALL_PREFIX=/usr  # Install location
```

Use `ccmake ..` for interactive configuration.

### Dependencies

- GLib 2.22+
- CMake 3.1+
- flex/bison (for config file parsing)
- libjson-c (for KVM, Bareflank, JSON profiles)
- libvirt (for KVM)
- Xen development libraries (for Xen driver)

Ubuntu: `sudo apt-get install cmake flex bison libglib2.0-dev libvirt-dev libjson-c-dev`

## Repository Structure

```
libvmi/
├── libvmi/                 # Main library source
│   ├── arch/               # CPU architecture page translation
│   │   ├── amd64.c         # x86-64 IA32E paging
│   │   ├── intel.c         # x86 legacy/PAE paging
│   │   ├── arm_aarch64.c   # ARM64 MMU translation
│   │   └── ept.c           # Extended Page Tables (nested paging)
│   ├── config/             # Configuration file parsing (lex/yacc)
│   ├── driver/             # Hypervisor driver implementations
│   │   ├── xen/            # Xen driver (libxc-based)
│   │   ├── kvm/            # KVM driver (libkvmi/libvirt)
│   │   ├── file/           # Memory dump file driver
│   │   └── bareflank/      # Bareflank hypervisor driver
│   ├── os/                 # Guest OS-specific code
│   │   ├── windows/        # Windows kernel parsing (KDBG, PEB, PE)
│   │   ├── linux/          # Linux kernel parsing (task_struct, ELF)
│   │   ├── freebsd/        # FreeBSD support
│   │   └── osx/            # macOS support
│   ├── json_profiles/      # Rekall/Volatility profile support
│   ├── libvmi.h            # Main public API header
│   ├── events.h            # Event API definitions
│   ├── private.h           # Internal data structures
│   ├── core.c              # Initialization and teardown
│   ├── read.c              # Memory read operations
│   ├── write.c             # Memory write operations
│   ├── accessors.c         # High-level API functions
│   └── cache.c             # Address/page caching
├── examples/               # Example programs demonstrating API usage
├── tests/                  # Test suite (GNU Check framework)
├── tools/                  # Utility scripts and helpers
└── doc/                    # Doxygen documentation
```

## Architecture

### Driver Abstraction

Each hypervisor driver implements `driver_interface_t` (see `libvmi/driver/driver_interface.h`):

```c
typedef struct driver_interface {
    status_t (*init_ptr)();
    void* (*read_page_ptr)(vmi_instance_t, addr_t);
    status_t (*write_ptr)();
    status_t (*get_vcpureg_ptr)();
    status_t (*events_listen_ptr)();
    // ... ~40 function pointers
} driver_interface_t;
```

Driver implementations:
- **File**: Simple seek/read or mmap access to memory dump files
- **Xen**: Uses libxenctrl for memory access, full event support
- **KVM**: Uses libkvmi (KVM-VMI project) or legacy GDB stub
- **Bareflank**: Hypercall-based introspection

### OS Abstraction

Guest OS modules implement `os_interface_t` (see `libvmi/os/os_interface.h`):

```c
typedef struct os_interface {
    os_pgd_to_pid_t os_pgd_to_pid;
    os_pid_to_pgd_t os_pid_to_pgd;
    os_kernel_symbol_to_address_t os_ksym2v;
    os_read_unicode_struct_t os_read_unicode_struct;
    // ...
} os_interface_t;
```

### Page Translation

Architecture-specific page table walkers in `libvmi/arch/`:
- Legacy 32-bit paging
- PAE (Physical Address Extension)
- IA32E (x86-64 4-level paging)
- ARM AARCH32/AARCH64
- EPT (Extended Page Tables for nested virtualization)

### Memory Access Flow

```
API call (vmi_read_va, vmi_read_ksym, etc.)
    ↓
Access context interpretation (symbol→addr, PID→DTB)
    ↓
Cache lookup (v2p, PID, symbol caches)
    ↓
Page table walk (architecture-specific)
    ↓
Driver memory access (read_page, mmap)
    ↓
Hypervisor I/O
```

## Key Data Structures

### access_context_t

Used for all memory access operations:

```c
access_context_t ctx = {
    .translate_mechanism = VMI_TM_PROCESS_PID,
    .pid = target_pid,
    .addr = virtual_address
};
vmi_read_32(vmi, &ctx, &value);
```

Translation mechanisms:
- `VMI_TM_NONE` - Address is physical
- `VMI_TM_PROCESS_DTB` - Translate via specified page table base
- `VMI_TM_PROCESS_PID` - Look up process DTB by PID
- `VMI_TM_KERNEL_SYMBOL` - Resolve kernel symbol to address

### vmi_instance_t

Opaque handle to a VMI session (internal structure in `private.h`).

## Code Style

Style configuration in `.astylerc`:
- K&R style with braces on new line for functions
- 4-space indentation (no tabs)
- Function names: `vmi_` prefix for public API
- Types: `_t` suffix (e.g., `status_t`, `vmi_instance_t`)
- Constants: `UPPERCASE` (e.g., `VMI_SUCCESS`, `VMI_PM_IA32E`)

### Error Handling Pattern

```c
status_t ret = VMI_FAILURE;

if (VMI_FAILURE == vmi_read_32(vmi, &ctx, &value)) {
    errprint("Failed to read value\n");
    goto done;
}

// success path
ret = VMI_SUCCESS;

done:
    return ret;
```

Common macros in `debug.h`:
- `dbprint(category, format, ...)` - Debug output by category
- `errprint(format, ...)` - Error output

## Testing

```bash
cmake .. -DENABLE_TESTING=ON
make
make test
# or
ctest --verbose
```

Tests use the GNU Check framework. Test files in `tests/`:
- `test_init.c` - Initialization tests
- `test_read.c` / `test_write.c` - Memory operations
- `test_translate.c` - Address translation
- `test_cache.c` - Caching layer

## Configuration

LibVMI reads VM configuration from `libvmi.conf`:

```
my_vm {
    ostype = "Windows";
    rekall_profile = "/path/to/profile.json";
}

linux_vm {
    ostype = "Linux";
    sysmap = "/boot/System.map";
}
```

Search path: `./libvmi.conf` → `~/etc/libvmi.conf` → `/etc/libvmi.conf`

Alternative: Use Volatility3 IST or Rekall JSON profiles for automatic offset discovery.

## Common Development Tasks

### Adding a New Driver

1. Create directory under `libvmi/driver/`
2. Implement `driver_interface_t` functions
3. Add detection/initialization in `driver_interface.c`
4. Add CMake option in `CMakeLists.txt`

### Adding Guest OS Support

1. Create directory under `libvmi/os/`
2. Implement `os_interface_t` functions
3. Add OS detection in `os_interface.c`
4. Add CMake option for the OS

### Adding Architecture Support

1. Create file in `libvmi/arch/`
2. Implement `arch_interface_t` for the page mode
3. Register in `arch_interface.c`

## Debugging

Enable debug output at build time:
```bash
cmake .. -DVMI_DEBUG=__VMI_DEBUG_ALL
```

Or selective categories:
```bash
cmake .. -DVMI_DEBUG='(VMI_DEBUG_XEN | VMI_DEBUG_CORE | VMI_DEBUG_PTLOOKUP)'
```

Available categories (see `libvmi/debug.h`):
- `VMI_DEBUG_XEN`, `VMI_DEBUG_KVM`, `VMI_DEBUG_FILE`
- `VMI_DEBUG_CORE`, `VMI_DEBUG_PTLOOKUP`
- `VMI_DEBUG_EVENTS`, `VMI_DEBUG_DRIVER`

Runtime toggle via `LIBVMI_DEBUG` environment variable (if `ENV_DEBUG` enabled).

## Examples

The `examples/` directory contains working programs:
- `process-list.c` - Enumerate processes
- `module-list.c` - List loaded modules
- `dump-memory.c` - Dump VM memory
- `event-example.c` - Memory event monitoring
- `map-addr.c` - Address translation demo

Run examples without installing:
```bash
cd build
./examples/vmi-process-list <vm_name>
```

## Resources

- Documentation: https://libvmi.com/docs/
- Python bindings: https://github.com/libvmi/python
- KVM-VMI setup: https://kvm-vmi.github.io/kvm-vmi/
- Volatility3 profiles: https://volatility3.readthedocs.io/en/latest/symbol-tables.html
