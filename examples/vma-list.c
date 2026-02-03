/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file vma-list.c
 * @brief Example demonstrating VMA (Virtual Memory Area) enumeration for
 *        Linux 6.1+ kernels using maple tree traversal.
 *
 * This example shows how to enumerate a process's virtual memory areas,
 * similar to what /proc/<pid>/maps shows. It specifically targets Linux 6.1+
 * which replaced the VMA linked list with a maple tree data structure.
 *
 * Required JSON profile fields:
 *   - task_struct: tasks, mm, pid, comm
 *   - mm_struct: mm_mt, start_code, end_code, start_data, end_data,
 *                start_brk, brk, start_stack
 *   - maple_tree: ma_root
 *   - maple_node: parent, mr64 (or specific node type fields)
 *   - vm_area_struct: vm_start, vm_end, vm_flags, vm_file
 *
 * Usage:
 *   vmi-vma-list -n <domain_name> -p <pid> -j <json_profile>
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdbool.h>
#include <limits.h>

#include <libvmi/libvmi.h>

/*
 * Maple tree constants from Linux kernel (include/linux/maple_tree.h)
 *
 * The maple tree uses tagged pointers where the low bits indicate the type.
 * Node pointers are aligned, so low bits can be used for metadata.
 */

/* Maple tree node types - encoded in low bits of pointers */
#define MAPLE_DENSE          0
#define MAPLE_LEAF_64        1
#define MAPLE_RANGE_64       2
#define MAPLE_ARANGE_64      3

/* Masks for extracting node type and pointer from tagged values */
#define MAPLE_NODE_TYPE_MASK    0x0F
#define MAPLE_NODE_TYPE_SHIFT   0x00
#define MAPLE_NODE_POINTER_MASK (~(addr_t)0x7F)

/* Special values */
#define MAPLE_RESERVED_RANGE    256
#define MA_ROOT_PARENT          1

/* Number of slots in maple tree nodes */
#define MAPLE_RANGE64_SLOTS     16
#define MAPLE_ARANGE64_SLOTS    10

/* Bit to check if a pointer is a value vs node pointer */
#define XA_ZERO_ENTRY           0x02

/* VM flags for permission display */
#define VM_READ         0x00000001
#define VM_WRITE        0x00000002
#define VM_EXEC         0x00000004
#define VM_SHARED       0x00000008
#define VM_MAYREAD      0x00000010
#define VM_MAYWRITE     0x00000020
#define VM_MAYEXEC      0x00000040
#define VM_GROWSDOWN    0x00000100
#define VM_GROWSUP      0x00000200

/* Maximum depth for maple tree traversal (safety limit) */
#define MAX_TREE_DEPTH  20

/* Maximum VMAs to enumerate (safety limit) */
#define MAX_VMAS        65536

/*
 * Offset cache structure - holds all the struct member offsets we need
 */
struct offset_cache {
    /* task_struct offsets */
    addr_t tasks;
    addr_t mm;
    addr_t pid;
    addr_t name;

    /* mm_struct offsets */
    addr_t mm_mt;           /* maple tree root (Linux 6.1+) */
    addr_t start_code;
    addr_t end_code;
    addr_t start_data;
    addr_t end_data;
    addr_t start_brk;
    addr_t brk;
    addr_t start_stack;
    addr_t mmap;            /* legacy linked list head (pre-6.1) */

    /* maple_tree offsets */
    addr_t ma_root;

    /* maple_node offsets */
    addr_t mn_parent;
    addr_t mr64_pivot;      /* maple_range_64.pivot array */
    addr_t mr64_slot;       /* maple_range_64.slot array */
    addr_t ma64_pivot;      /* maple_arange_64.pivot array */
    addr_t ma64_slot;       /* maple_arange_64.slot array */

    /* vm_area_struct offsets */
    addr_t vm_start;
    addr_t vm_end;
    addr_t vm_flags;
    addr_t vm_file;
    addr_t vm_next;         /* legacy (pre-6.1) */

    /* Computed values */
    size_t pointer_size;
    bool use_maple_tree;    /* true for 6.1+, false for older */
};

/*
 * VMA information structure
 */
struct vma_info {
    addr_t start;
    addr_t end;
    uint64_t flags;
    addr_t file;        /* vm_file pointer (0 if anonymous) */
};

/*
 * Global state for cleaner code
 */
static vmi_instance_t vmi = NULL;
static struct offset_cache offsets = {0};

/**
 * Load all required offsets from the JSON profile.
 * Returns VMI_SUCCESS if all critical offsets were found.
 */
static status_t
load_offsets(void)
{
    status_t ret = VMI_FAILURE;

    /* Determine pointer size based on page mode */
    page_mode_t pm = vmi_get_page_mode(vmi, 0);
    offsets.pointer_size = (pm == VMI_PM_IA32E || pm == VMI_PM_AARCH64) ? 8 : 4;

    printf("[*] Detected %zu-bit guest\n", offsets.pointer_size * 8);

    /* Get standard task_struct offsets via vmi_get_offset */
    if (VMI_FAILURE == vmi_get_offset(vmi, "linux_tasks", &offsets.tasks)) {
        fprintf(stderr, "[-] Failed to get linux_tasks offset\n");
        goto done;
    }
    if (VMI_FAILURE == vmi_get_offset(vmi, "linux_mm", &offsets.mm)) {
        fprintf(stderr, "[-] Failed to get linux_mm offset\n");
        goto done;
    }
    if (VMI_FAILURE == vmi_get_offset(vmi, "linux_pid", &offsets.pid)) {
        fprintf(stderr, "[-] Failed to get linux_pid offset\n");
        goto done;
    }
    if (VMI_FAILURE == vmi_get_offset(vmi, "linux_name", &offsets.name)) {
        fprintf(stderr, "[-] Failed to get linux_name offset\n");
        goto done;
    }

    /* Try to get maple tree offset (mm_struct.mm_mt) - present in 6.1+ */
    if (VMI_SUCCESS == vmi_get_kernel_struct_offset(vmi, "mm_struct", "mm_mt", &offsets.mm_mt)) {
        printf("[*] Detected Linux 6.1+ (maple tree VMAs)\n");
        offsets.use_maple_tree = true;

        /* Get maple_tree.ma_root offset */
        if (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "maple_tree", "ma_root", &offsets.ma_root)) {
            fprintf(stderr, "[-] Failed to get maple_tree.ma_root offset\n");
            goto done;
        }

        /*
         * Maple node offsets - these vary by kernel config, but we need at minimum
         * the parent field and the slot/pivot arrays for range64 nodes.
         *
         * Note: The actual structure layout depends on CONFIG_64BIT and other options.
         * These offsets should come from the JSON profile for the specific kernel.
         */
        if (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "maple_node", "parent", &offsets.mn_parent)) {
            /* Try alternate name */
            offsets.mn_parent = 0; /* parent is typically at offset 0 */
        }

        /* For maple_range_64 nodes (most common for VMAs) */
        if (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "maple_range_64", "pivot", &offsets.mr64_pivot)) {
            /* Default offset for 64-bit systems: after parent pointer */
            offsets.mr64_pivot = offsets.pointer_size;
        }
        if (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "maple_range_64", "slot", &offsets.mr64_slot)) {
            /* Slots come after pivots: parent + (SLOTS-1) * sizeof(pivot) */
            offsets.mr64_slot = offsets.mr64_pivot + (MAPLE_RANGE64_SLOTS - 1) * sizeof(uint64_t);
        }

    } else {
        /* Fall back to legacy linked list (pre-6.1) */
        printf("[*] Detected pre-6.1 Linux (linked list VMAs)\n");
        offsets.use_maple_tree = false;

        if (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "mm_struct", "mmap", &offsets.mmap)) {
            fprintf(stderr, "[-] Failed to get mm_struct.mmap offset\n");
            goto done;
        }
        if (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "vm_area_struct", "vm_next", &offsets.vm_next)) {
            fprintf(stderr, "[-] Failed to get vm_area_struct.vm_next offset\n");
            goto done;
        }
    }

    /* Get mm_struct memory range offsets (same for all versions) */
    vmi_get_kernel_struct_offset(vmi, "mm_struct", "start_code", &offsets.start_code);
    vmi_get_kernel_struct_offset(vmi, "mm_struct", "end_code", &offsets.end_code);
    vmi_get_kernel_struct_offset(vmi, "mm_struct", "start_data", &offsets.start_data);
    vmi_get_kernel_struct_offset(vmi, "mm_struct", "end_data", &offsets.end_data);
    vmi_get_kernel_struct_offset(vmi, "mm_struct", "start_brk", &offsets.start_brk);
    vmi_get_kernel_struct_offset(vmi, "mm_struct", "brk", &offsets.brk);
    vmi_get_kernel_struct_offset(vmi, "mm_struct", "start_stack", &offsets.start_stack);

    /* Get vm_area_struct offsets */
    if (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "vm_area_struct", "vm_start", &offsets.vm_start)) {
        fprintf(stderr, "[-] Failed to get vm_area_struct.vm_start offset\n");
        goto done;
    }
    if (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "vm_area_struct", "vm_end", &offsets.vm_end)) {
        fprintf(stderr, "[-] Failed to get vm_area_struct.vm_end offset\n");
        goto done;
    }
    if (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "vm_area_struct", "vm_flags", &offsets.vm_flags)) {
        fprintf(stderr, "[-] Failed to get vm_area_struct.vm_flags offset\n");
        goto done;
    }
    /* vm_file is optional - anonymous mappings don't have it */
    vmi_get_kernel_struct_offset(vmi, "vm_area_struct", "vm_file", &offsets.vm_file);

    ret = VMI_SUCCESS;

done:
    return ret;
}

/**
 * Find a process by PID and return its task_struct address.
 */
static addr_t
find_process_by_pid(vmi_pid_t target_pid)
{
    addr_t list_head = 0, cur_list_entry = 0;
    addr_t current_process = 0;
    vmi_pid_t pid = 0;

    /* Get init_task as starting point */
    if (VMI_FAILURE == vmi_translate_ksym2v(vmi, "init_task", &list_head)) {
        fprintf(stderr, "[-] Failed to find init_task symbol\n");
        return 0;
    }

    list_head += offsets.tasks;
    cur_list_entry = list_head;

    /* Walk the task list */
    do {
        current_process = cur_list_entry - offsets.tasks;

        if (VMI_FAILURE == vmi_read_32_va(vmi, current_process + offsets.pid, 0, (uint32_t*)&pid)) {
            fprintf(stderr, "[-] Failed to read PID at 0x%"PRIx64"\n", current_process + offsets.pid);
            return 0;
        }

        if (pid == target_pid) {
            return current_process;
        }

        if (VMI_FAILURE == vmi_read_addr_va(vmi, cur_list_entry, 0, &cur_list_entry)) {
            fprintf(stderr, "[-] Failed to read next task pointer\n");
            return 0;
        }

    } while (cur_list_entry != list_head);

    return 0; /* Not found */
}

/**
 * Read a VMA's information given its address.
 */
static status_t
read_vma_info(addr_t vma_addr, struct vma_info *info)
{
    if (VMI_FAILURE == vmi_read_addr_va(vmi, vma_addr + offsets.vm_start, 0, &info->start)) {
        return VMI_FAILURE;
    }
    if (VMI_FAILURE == vmi_read_addr_va(vmi, vma_addr + offsets.vm_end, 0, &info->end)) {
        return VMI_FAILURE;
    }
    if (VMI_FAILURE == vmi_read_64_va(vmi, vma_addr + offsets.vm_flags, 0, &info->flags)) {
        /* Try 32-bit flags on 32-bit systems */
        uint32_t flags32 = 0;
        if (VMI_FAILURE == vmi_read_32_va(vmi, vma_addr + offsets.vm_flags, 0, &flags32)) {
            return VMI_FAILURE;
        }
        info->flags = flags32;
    }

    info->file = 0;
    if (offsets.vm_file) {
        vmi_read_addr_va(vmi, vma_addr + offsets.vm_file, 0, &info->file);
    }

    return VMI_SUCCESS;
}

/**
 * Print a VMA in /proc/pid/maps-like format.
 */
static void
print_vma(const struct vma_info *info)
{
    char perms[5] = "----";

    if (info->flags & VM_READ)
        perms[0] = 'r';
    if (info->flags & VM_WRITE)
        perms[1] = 'w';
    if (info->flags & VM_EXEC)
        perms[2] = 'x';
    if (info->flags & VM_SHARED)
        perms[3] = 's';
    else
        perms[3] = 'p';

    printf("  %016"PRIx64"-%016"PRIx64" %s %s\n",
           info->start, info->end, perms,
           info->file ? "[file]" : "[anon]");
}

/**
 * Check if a maple tree entry is a leaf (VMA pointer) vs internal node.
 * In maple trees, leaf entries have specific tag bits cleared.
 */
static inline bool
is_maple_leaf_entry(addr_t entry)
{
    /*
     * A leaf entry (VMA pointer) is distinguished from internal node pointers
     * by examining the low bits. VMA pointers are aligned, so they have
     * low bits clear. The XA_ZERO_ENTRY is a special marker.
     */
    if (entry == 0 || entry == XA_ZERO_ENTRY)
        return false;

    /* If it looks like an aligned pointer in kernel space, it's likely a VMA */
    return (entry & 0x3) == 0;
}

/**
 * Extract the node pointer from a maple tree node entry.
 */
static inline addr_t
maple_node_ptr(addr_t entry)
{
    return entry & MAPLE_NODE_POINTER_MASK;
}

/**
 * Get the maple node type from a node pointer.
 */
static inline int
maple_node_type(addr_t entry)
{
    return (entry >> MAPLE_NODE_TYPE_SHIFT) & MAPLE_NODE_TYPE_MASK;
}

/**
 * Recursively walk a maple tree node to find all VMAs.
 *
 * @param node_ptr  Address of the maple_node in guest memory
 * @param depth     Current recursion depth (for safety)
 * @param vma_count Pointer to count of VMAs found
 * @return VMI_SUCCESS or VMI_FAILURE
 */
static status_t
walk_maple_node(addr_t node_ptr, int depth, int *vma_count)
{
    addr_t slots[MAPLE_RANGE64_SLOTS] = {0};
    uint64_t pivots[MAPLE_RANGE64_SLOTS - 1] = {0};
    int i;

    if (depth > MAX_TREE_DEPTH) {
        fprintf(stderr, "[-] Max tree depth exceeded\n");
        return VMI_FAILURE;
    }

    if (*vma_count >= MAX_VMAS) {
        fprintf(stderr, "[-] Max VMA count exceeded\n");
        return VMI_FAILURE;
    }

    /*
     * Read the slots from the node. For maple_range_64 nodes:
     * - pivots[0..14] define the range boundaries
     * - slots[0..15] contain either child node pointers or VMA pointers
     *
     * The structure is:
     *   struct maple_range_64 {
     *       struct maple_pnode *parent;
     *       unsigned long pivot[MAPLE_RANGE64_SLOTS - 1];  // 15 pivots
     *       union {
     *           void __rcu *slot[MAPLE_RANGE64_SLOTS];     // 16 slots
     *           ...
     *       };
     *   };
     */

    /* Read pivots */
    for (i = 0; i < MAPLE_RANGE64_SLOTS - 1; i++) {
        addr_t pivot_addr = node_ptr + offsets.mr64_pivot + (i * sizeof(uint64_t));
        if (VMI_FAILURE == vmi_read_64_va(vmi, pivot_addr, 0, &pivots[i])) {
            /* Pivot read failure might just mean we've gone past valid entries */
            break;
        }
    }

    /* Read slots */
    for (i = 0; i < MAPLE_RANGE64_SLOTS; i++) {
        addr_t slot_addr = node_ptr + offsets.mr64_slot + (i * offsets.pointer_size);
        if (VMI_FAILURE == vmi_read_addr_va(vmi, slot_addr, 0, &slots[i])) {
            break;
        }
    }

    /* Process each slot */
    for (i = 0; i < MAPLE_RANGE64_SLOTS && *vma_count < MAX_VMAS; i++) {
        addr_t entry = slots[i];

        if (entry == 0)
            continue;

        /* Check if this is a leaf entry (VMA) or internal node */
        if (is_maple_leaf_entry(entry)) {
            /* This is a VMA pointer */
            struct vma_info info = {0};

            if (VMI_SUCCESS == read_vma_info(entry, &info)) {
                print_vma(&info);
                (*vma_count)++;
            }
        } else {
            /* This is an internal node - recurse */
            addr_t child = maple_node_ptr(entry);
            if (child) {
                walk_maple_node(child, depth + 1, vma_count);
            }
        }

        /* Check pivot to see if we've covered the whole range */
        if (i < MAPLE_RANGE64_SLOTS - 1 && pivots[i] == ULONG_MAX) {
            break;
        }
    }

    return VMI_SUCCESS;
}

/**
 * Enumerate VMAs using the maple tree (Linux 6.1+).
 */
static status_t
enumerate_vmas_maple_tree(addr_t mm_ptr)
{
    addr_t mm_mt_addr;
    addr_t ma_root = 0;
    int vma_count = 0;

    /* mm_mt is embedded in mm_struct, not a pointer */
    mm_mt_addr = mm_ptr + offsets.mm_mt;

    /* Read the ma_root from the maple_tree structure */
    if (VMI_FAILURE == vmi_read_addr_va(vmi, mm_mt_addr + offsets.ma_root, 0, &ma_root)) {
        fprintf(stderr, "[-] Failed to read maple tree root\n");
        return VMI_FAILURE;
    }

    printf("[*] Maple tree root: 0x%"PRIx64"\n", ma_root);

    if (ma_root == 0) {
        printf("[*] Empty maple tree (no VMAs)\n");
        return VMI_SUCCESS;
    }

    /*
     * The ma_root can be:
     * 1. A single entry (tagged pointer to VMA) if tree has one entry
     * 2. A pointer to the root maple_node
     *
     * Single entries have the XA entry bits set differently than node pointers.
     * For simplicity, we check if it looks like a VMA first.
     */

    if (is_maple_leaf_entry(ma_root)) {
        /* Single VMA in the tree */
        struct vma_info info = {0};
        if (VMI_SUCCESS == read_vma_info(ma_root, &info)) {
            print_vma(&info);
            vma_count = 1;
        }
    } else {
        /* Root is a node pointer - walk the tree */
        addr_t root_node = maple_node_ptr(ma_root);
        if (root_node) {
            printf("[*] Walking maple tree from node 0x%"PRIx64"\n", root_node);
            walk_maple_node(root_node, 0, &vma_count);
        }
    }

    printf("[*] Total VMAs found: %d\n", vma_count);
    return VMI_SUCCESS;
}

/**
 * Enumerate VMAs using the linked list (pre-6.1 Linux).
 */
static status_t
enumerate_vmas_linked_list(addr_t mm_ptr)
{
    addr_t vma_ptr = 0;
    int vma_count = 0;

    /* Read the head of the VMA linked list */
    if (VMI_FAILURE == vmi_read_addr_va(vmi, mm_ptr + offsets.mmap, 0, &vma_ptr)) {
        fprintf(stderr, "[-] Failed to read mm_struct.mmap\n");
        return VMI_FAILURE;
    }

    printf("[*] VMA list head: 0x%"PRIx64"\n", vma_ptr);

    /* Walk the linked list */
    while (vma_ptr && vma_count < MAX_VMAS) {
        struct vma_info info = {0};

        if (VMI_SUCCESS == read_vma_info(vma_ptr, &info)) {
            print_vma(&info);
            vma_count++;
        }

        /* Read vm_next pointer */
        if (VMI_FAILURE == vmi_read_addr_va(vmi, vma_ptr + offsets.vm_next, 0, &vma_ptr)) {
            break;
        }
    }

    printf("[*] Total VMAs found: %d\n", vma_count);
    return VMI_SUCCESS;
}

/**
 * Print mm_struct summary information.
 */
static void
print_mm_summary(addr_t mm_ptr)
{
    addr_t start_code = 0, end_code = 0;
    addr_t start_data = 0, end_data = 0;
    addr_t start_brk = 0, brk = 0;
    addr_t start_stack = 0;

    printf("\n[*] Memory layout summary:\n");

    if (offsets.start_code) {
        vmi_read_addr_va(vmi, mm_ptr + offsets.start_code, 0, &start_code);
        vmi_read_addr_va(vmi, mm_ptr + offsets.end_code, 0, &end_code);
        printf("    Code:  0x%016"PRIx64" - 0x%016"PRIx64" (%"PRIu64" KB)\n",
               start_code, end_code, (end_code - start_code) / 1024);
    }

    if (offsets.start_data) {
        vmi_read_addr_va(vmi, mm_ptr + offsets.start_data, 0, &start_data);
        vmi_read_addr_va(vmi, mm_ptr + offsets.end_data, 0, &end_data);
        printf("    Data:  0x%016"PRIx64" - 0x%016"PRIx64" (%"PRIu64" KB)\n",
               start_data, end_data, (end_data - start_data) / 1024);
    }

    if (offsets.start_brk) {
        vmi_read_addr_va(vmi, mm_ptr + offsets.start_brk, 0, &start_brk);
        vmi_read_addr_va(vmi, mm_ptr + offsets.brk, 0, &brk);
        printf("    Heap:  0x%016"PRIx64" - 0x%016"PRIx64" (%"PRIu64" KB)\n",
               start_brk, brk, (brk - start_brk) / 1024);
    }

    if (offsets.start_stack) {
        vmi_read_addr_va(vmi, mm_ptr + offsets.start_stack, 0, &start_stack);
        printf("    Stack: 0x%016"PRIx64"\n", start_stack);
    }

    printf("\n");
}

static void
print_usage(const char *progname)
{
    printf("Usage: %s [options]\n", progname);
    printf("\nRequired:\n");
    printf("  -n, --name <domain>     Domain name\n");
    printf("  -p, --pid <pid>         Target process ID\n");
    printf("\nOptional:\n");
    printf("  -d, --domid <id>        Domain ID (alternative to -n)\n");
    printf("  -j, --json <path>       Path to kernel JSON profile\n");
    printf("  -s, --socket <path>     Path to KVMI socket\n");
    printf("  -h, --help              Show this help\n");
    printf("\nExample:\n");
    printf("  %s -n myvm -p 1234 -j /path/to/linux.json\n", progname);
}

int
main(int argc, char **argv)
{
    vmi_init_data_t *init_data = NULL;
    uint64_t domid = 0;
    uint8_t init = VMI_INIT_DOMAINNAME;
    uint8_t config_type = VMI_CONFIG_GLOBAL_FILE_ENTRY;
    void *input = NULL, *config = NULL;
    vmi_pid_t target_pid = -1;
    int retcode = 1;
    addr_t task_addr = 0, mm_ptr = 0;
    char *procname = NULL;

    const struct option long_opts[] = {
        {"name", required_argument, NULL, 'n'},
        {"domid", required_argument, NULL, 'd'},
        {"pid", required_argument, NULL, 'p'},
        {"json", required_argument, NULL, 'j'},
        {"socket", required_argument, NULL, 's'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    const char *opts = "n:d:p:j:s:h";
    int c;

    while ((c = getopt_long(argc, argv, opts, long_opts, NULL)) != -1) {
        switch (c) {
        case 'n':
            input = optarg;
            break;
        case 'd':
            init = VMI_INIT_DOMAINID;
            domid = strtoull(optarg, NULL, 0);
            input = (void *)&domid;
            break;
        case 'p':
            target_pid = (vmi_pid_t)atoi(optarg);
            break;
        case 'j':
            config_type = VMI_CONFIG_JSON_PATH;
            config = (void *)optarg;
            break;
        case 's':
            if (init_data) {
                free(init_data->entry[0].data);
            } else {
                init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
            }
            init_data->count = 1;
            init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
            init_data->entry[0].data = strdup(optarg);
            break;
        case 'h':
            print_usage(argv[0]);
            retcode = 0;
            goto cleanup;
        default:
            print_usage(argv[0]);
            goto cleanup;
        }
    }

    if (!input || target_pid < 0) {
        fprintf(stderr, "[-] Domain name/id and PID are required\n");
        print_usage(argv[0]);
        goto cleanup;
    }

    printf("[*] VMA Enumeration Example for Linux 6.1+\n");
    printf("[*] Target PID: %d\n\n", target_pid);

    /* Initialize LibVMI */
    printf("[*] Initializing LibVMI...\n");
    if (VMI_FAILURE == vmi_init_complete(&vmi, input, init, init_data, config_type, config, NULL)) {
        fprintf(stderr, "[-] Failed to initialize LibVMI\n");
        goto cleanup;
    }

    /* Verify we're looking at Linux */
    if (VMI_OS_LINUX != vmi_get_ostype(vmi)) {
        fprintf(stderr, "[-] This example only supports Linux guests\n");
        goto cleanup;
    }

    /* Load all the struct offsets we need */
    printf("[*] Loading struct offsets from profile...\n");
    if (VMI_FAILURE == load_offsets()) {
        fprintf(stderr, "[-] Failed to load required offsets\n");
        goto cleanup;
    }

    /* Pause VM for consistent memory access */
    printf("[*] Pausing VM...\n");
    if (VMI_FAILURE == vmi_pause_vm(vmi)) {
        fprintf(stderr, "[-] Failed to pause VM\n");
        goto cleanup;
    }

    /* Find the target process */
    printf("[*] Searching for process with PID %d...\n", target_pid);
    task_addr = find_process_by_pid(target_pid);
    if (!task_addr) {
        fprintf(stderr, "[-] Process with PID %d not found\n", target_pid);
        goto resume;
    }

    /* Read process name */
    procname = vmi_read_str_va(vmi, task_addr + offsets.name, 0);
    printf("[+] Found process: %s (task_struct at 0x%"PRIx64")\n",
           procname ? procname : "<unknown>", task_addr);

    /* Get mm_struct pointer */
    if (VMI_FAILURE == vmi_read_addr_va(vmi, task_addr + offsets.mm, 0, &mm_ptr)) {
        fprintf(stderr, "[-] Failed to read mm pointer\n");
        goto resume;
    }

    if (!mm_ptr) {
        printf("[!] Process has no mm_struct (kernel thread?)\n");
        goto resume;
    }

    printf("[*] mm_struct at 0x%"PRIx64"\n", mm_ptr);

    /* Print summary information */
    print_mm_summary(mm_ptr);

    /* Enumerate VMAs */
    printf("[*] Virtual Memory Areas:\n");
    printf("    %-34s %s %s\n", "Address Range", "Perm", "Type");
    printf("    %s\n", "------------------------------------------------------------");

    if (offsets.use_maple_tree) {
        enumerate_vmas_maple_tree(mm_ptr);
    } else {
        enumerate_vmas_linked_list(mm_ptr);
    }

    retcode = 0;

resume:
    vmi_resume_vm(vmi);

cleanup:
    if (procname)
        free(procname);
    if (vmi)
        vmi_destroy(vmi);
    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}
