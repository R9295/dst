#ifndef DETHV_INTERNAL_H
#define DETHV_INTERNAL_H

#include "dethv.h"
#include "guest_shared.h"
#include <linux/kvm.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PAGE_SIZE           4096ULL
#define PAGE_MASK           (~(PAGE_SIZE - 1ULL))
#define PAGE_ALIGN_UP(x)    (((x) + PAGE_SIZE - 1ULL) & PAGE_MASK)
#define PAGE_ALIGN_DOWN(x)  ((x) & PAGE_MASK)

/* Page table entry flags */
#define PTE_P               (1ULL << 0)
#define PTE_W               (1ULL << 1)
#define PTE_U               (1ULL << 2)
#define PTE_PWT             (1ULL << 3)
#define PTE_PCD             (1ULL << 4)
#define PTE_A               (1ULL << 5)
#define PTE_D               (1ULL << 6)
#define PTE_PS              (1ULL << 7)
#define PTE_NX              (1ULL << 63)
#define PTE_ADDR_MASK       0x000FFFFFFFFFF000ULL

/* Limits */
#define DETHV_MAX_VMAS          512
#define DETHV_MAX_THREADS       64
#define DETHV_MAX_FDS           128
#define DETHV_MAX_VFILES        64
#define DETHV_MAX_PIPES         32
#define DETHV_MAX_PATCHES       4096
#define DETHV_MAX_SYMBOLS       4096
#define DETHV_MAX_SIGNALS       64
#define DETHV_OUT_CAP           (1024 * 1024) /* 1 MB captured stdout/stderr */
#define DETHV_PIPE_BUF_SIZE     65536
#define DETHV_DIRTY_RING_BYTES  (256 * 1024)  /* 16384 dirty entries */
#define DETHV_MAX_HOST_DIRTY    16384

/* Fixed deterministic virtual addresses */
#define GUEST_PIE_BASE          0x0000555555554000ULL
#define GUEST_INTERP_BASE       0x00007FFFF7DC0000ULL
#define GUEST_MMAP_TOP          0x00007FFFF0000000ULL
#define GUEST_STACK_TOP         0x00007FFFFFF00000ULL
#define GUEST_STACK_SIZE        (8ULL * 1024 * 1024)
#define GUEST_STACK_INIT_PAGES  32  /* 128 KB initially mapped */

/* ================= Deterministic PRNG & Virtual Clock ================= */

typedef struct {
    uint64_t s[4];              /* xoshiro256** state */
    uint64_t seed;
    uint64_t vtime_ns;          /* Deterministic virtual clock (nanoseconds since epoch) */
    uint64_t vmono_ns;          /* Deterministic monotonic clock (ns) */
    uint64_t total_branches;    /* Accumulated deterministic branches */
    uint64_t syscall_count;
    uint64_t preempt_count;
    uint64_t rdrand_count;
    uint64_t getrandom_count;
} det_state_t;

void     det_init(det_state_t *det, uint64_t seed, uint64_t start_time_ns);
uint64_t det_rand64(det_state_t *det);
void     det_rand_bytes(det_state_t *det, void *buf, size_t len);
void     det_advance_time(det_state_t *det, uint64_t delta_ns);
uint64_t det_hash_bytes(uint64_t h, const void *data, size_t len);
uint64_t det_hash_u64(uint64_t h, uint64_t v);

/* ================= Guest MMU & VMA Tracking ================= */

typedef struct {
    uint64_t start;
    uint64_t end;
    uint32_t prot;              /* PROT_READ | PROT_WRITE | PROT_EXEC */
    uint32_t flags;             /* MAP_ANONYMOUS, MAP_STACK, etc. */
} vma_t;

typedef struct {
    uint64_t pml4_phys;
    uint64_t next_phys;         /* Bump allocator for guest physical frames */
    uint64_t ram_size;
    uint64_t brk_start;
    uint64_t brk_curr;
    uint64_t mmap_cursor;       /* Deterministic top-down mmap allocator */
    uint64_t stack_bottom;      /* Lowest currently-mapped main stack address */
    uint64_t stack_limit;       /* Minimum allowed main stack growth */
    uint32_t num_vmas;
    vma_t    vmas[DETHV_MAX_VMAS];
} mmu_state_t;

int      mmu_init(dethv_vm_t *vm);
uint64_t mmu_alloc_phys_page(dethv_vm_t *vm);
int      mmu_map_page(dethv_vm_t *vm, uint64_t vaddr, uint64_t paddr, uint64_t pte_flags);
int      mmu_unmap_page(dethv_vm_t *vm, uint64_t vaddr);
int      mmu_protect_page(dethv_vm_t *vm, uint64_t vaddr, uint64_t pte_flags);
uint64_t mmu_virt_to_phys(const dethv_vm_t *vm, uint64_t vaddr, uint64_t *pte_out);
uint64_t mmu_mmap_region(dethv_vm_t *vm, uint64_t hint, size_t len, uint32_t prot, uint32_t flags, bool populate);
int      mmu_munmap_region(dethv_vm_t *vm, uint64_t addr, size_t len);
int      mmu_mprotect_region(dethv_vm_t *vm, uint64_t addr, size_t len, uint32_t prot);
uint64_t mmu_brk(dethv_vm_t *vm, uint64_t new_brk);
bool     mmu_handle_page_fault(dethv_vm_t *vm, uint64_t cr2, uint64_t errcode);
int      mmu_copy_to_guest(dethv_vm_t *vm, uint64_t dst_vaddr, const void *src, size_t len);
int      mmu_copy_from_guest(const dethv_vm_t *vm, void *dst, uint64_t src_vaddr, size_t len);
int      mmu_read_cstring(const dethv_vm_t *vm, uint64_t vaddr, char *buf, size_t max_len);

/* ================= x86_64 Instruction Patching (RDRAND/RDSEED/BP/COV) ================= */

typedef enum {
    PATCH_NONE = 0,
    PATCH_RDRAND,
    PATCH_RDSEED,
    PATCH_SNAPSHOT_BP,
    PATCH_COV_BP
} patch_kind_t;

typedef struct {
    uint64_t     vaddr;
    patch_kind_t kind;
    uint8_t      orig_byte;
    uint8_t      insn_len;
    uint8_t      reg_idx;       /* 0..15 (RAX..R15) */
    uint8_t      op_bits;       /* 16, 32, or 64 */
    uint8_t      hit;           /* For one-shot coverage breakpoints */
} patch_entry_t;

typedef struct {
    uint32_t      count;
    uint64_t      cov_hits;
    patch_entry_t entries[DETHV_MAX_PATCHES];
} patch_table_t;

int            x86_scan_and_patch_range(dethv_vm_t *vm, uint64_t vaddr, size_t len);
patch_entry_t *x86_patch_find(patch_table_t *pt, uint64_t vaddr);
int            x86_patch_add_bp(dethv_vm_t *vm, uint64_t vaddr, patch_kind_t kind);
bool           x86_handle_bp_patch(dethv_vm_t *vm, uint64_t bp_rip);

/* ================= ELF Symbol Table ================= */

typedef struct {
    char     name[96];
    uint64_t addr;
    uint64_t size;
} elf_sym_t;

typedef struct {
    uint32_t  count;
    elf_sym_t syms[DETHV_MAX_SYMBOLS];
} sym_table_t;

/* ================= Deterministic Virtual Filesystem ================= */

typedef enum {
    FD_NONE = 0,
    FD_STDIN,
    FD_STDOUT,
    FD_STDERR,
    FD_DEV_NULL,
    FD_DEV_ZERO,
    FD_DEV_URANDOM,
    FD_PROC_VFILE,
    FD_MEM_VFILE,
    FD_HOST_RO,
    FD_PIPE_READ,
    FD_PIPE_WRITE,
    FD_EVENTFD
} fd_kind_t;

typedef struct {
    bool      used;
    fd_kind_t kind;
    int       flags;            /* O_RDONLY, O_WRONLY, O_NONBLOCK, O_CLOEXEC, etc. */
    int       host_fd;          /* Only for FD_HOST_RO (reopened on disk snapshot load!) */
    uint64_t  offset;
    uint32_t  ref_idx;          /* Index into vfiles[] or pipes[] */
    uint64_t  eventfd_val;      /* For FD_EVENTFD */
    char      path[256];
    uint64_t  cached_size;
    uint32_t  cached_mode;
} vfd_t;

typedef struct {
    bool     used;
    char     path[256];
    uint32_t mode;
    size_t   len;
    size_t   cap;
    uint8_t *data;              /* Heap buffer (copied on snapshot!) */
} vfile_t;

typedef struct {
    bool     used;
    uint32_t read_pos;
    uint32_t write_pos;
    uint32_t count;
    bool     write_closed;
    bool     read_closed;
    uint8_t  buf[DETHV_PIPE_BUF_SIZE];
} vpipe_t;

typedef struct {
    vfd_t    fds[DETHV_MAX_FDS];
    vpipe_t  pipes[DETHV_MAX_PIPES];
    /* Captured stdout/stderr + virtual stdin */
    uint8_t *stdin_buf;
    size_t   stdin_len;
    size_t   stdin_cap;
    size_t   stdin_pos;
    uint8_t *stdout_buf;
    size_t   stdout_len;
    uint8_t *stderr_buf;
    size_t   stderr_len;
    /* Virtual overlay files (COW writes, /proc, fuzz input files) */
    vfile_t  vfiles[DETHV_MAX_VFILES];
    char     cwd[256];
    char     exe_path[256];
    uint32_t umask_val;
    /* Dirty tracking flags for ultra-fast snapshot restore! */
    bool     fds_dirty;
    bool     pipes_dirty;
    bool     vfiles_dirty;
    bool     cwd_dirty;
} vfs_state_t;

int     vfs_init(dethv_vm_t *vm);
void    vfs_destroy(vfs_state_t *vfs);
int     vfs_clone(vfs_state_t *dst, const vfs_state_t *src);
int     vfs_restore_fast(vfs_state_t *dst, const vfs_state_t *src);
int     vfs_openat(dethv_vm_t *vm, int dirfd, const char *path, int flags, uint32_t mode);
int64_t vfs_read(dethv_vm_t *vm, int fd, void *buf, size_t count);
int64_t vfs_write(dethv_vm_t *vm, int fd, const void *buf, size_t count);
int64_t vfs_pread(dethv_vm_t *vm, int fd, void *buf, size_t count, int64_t off);
int64_t vfs_lseek(dethv_vm_t *vm, int fd, int64_t off, int whence);
int     vfs_close(dethv_vm_t *vm, int fd);
int     vfs_dup(dethv_vm_t *vm, int oldfd, int newfd, int flags, bool exact);
int     vfs_fstat(dethv_vm_t *vm, int fd, void *statbuf_out);
int     vfs_stat_path(dethv_vm_t *vm, int dirfd, const char *path, void *statbuf_out, int flags);
int     vfs_pipe(dethv_vm_t *vm, int fds_out[2], int flags);
int     vfs_eventfd(dethv_vm_t *vm, uint64_t initval, int flags);
int     vfs_set_vfile_data(vfs_state_t *vfs, const char *path, const void *data, size_t len);

/* ================= Deterministic Multithreaded Scheduler ================= */

typedef enum {
    THREAD_FREE = 0,
    THREAD_RUNNABLE,
    THREAD_BLOCKED_FUTEX,
    THREAD_BLOCKED_SLEEP,
    THREAD_EXITED
} thread_state_t;

typedef struct {
    uint64_t sa_handler;
    uint64_t sa_flags;
    uint64_t sa_restorer;
    uint64_t sa_mask;
} ksigaction_t;

typedef struct {
    thread_state_t   state;
    int32_t          tid;
    user_regs_t      regs;
    uint64_t         fs_base;
    uint64_t         gs_base;
    struct kvm_xsave xsave;
    uint64_t         clear_child_tid;
    uint64_t         robust_list_head;
    uint64_t         robust_list_len;
    uint64_t         sigmask;
    uint64_t         branch_budget;
    /* Blocking metadata */
    uint64_t         futex_addr;
    uint32_t         futex_bitset;
    uint64_t         wake_time_ns;      /* 0 = no timeout */
    bool             has_timeout;
    int64_t          pending_ret;       /* Return value when woken */
    bool             has_pending_ret;
} guest_thread_t;

typedef struct {
    int32_t        pid;
    int32_t        next_tid;
    int32_t        current_idx;
    uint32_t       total_spawned;
    uint32_t       used_slots;
    bool           sigactions_dirty;
    guest_thread_t threads[DETHV_MAX_THREADS];
    ksigaction_t   sigactions[DETHV_MAX_SIGNALS];
} sched_state_t;

void     sched_init(dethv_vm_t *vm);
int      sched_num_runnable(const sched_state_t *sc);
int      sched_num_alive(const sched_state_t *sc);
void     sched_save_current(dethv_vm_t *vm);
void     sched_load_current(dethv_vm_t *vm);
int      sched_create_thread(dethv_vm_t *vm, uint64_t flags, uint64_t child_stack,
                             uint64_t ptid_vaddr, uint64_t ctid_vaddr, uint64_t tls_val);
bool     sched_switch_next(dethv_vm_t *vm, bool current_yielded);
int      sched_futex_wait(dethv_vm_t *vm, uint64_t uaddr, uint32_t val, uint32_t bitset,
                          bool has_timeout, uint64_t timeout_ns, bool abs_time);
int      sched_futex_wake(dethv_vm_t *vm, uint64_t uaddr, int max_wake, uint32_t bitset);
int      sched_futex_requeue(dethv_vm_t *vm, uint64_t uaddr, int nr_wake, int nr_requeue,
                             uint64_t uaddr2, bool check_val3, uint32_t val3);
void     sched_sleep_current(dethv_vm_t *vm, uint64_t wake_time_ns);
bool     sched_exit_current_thread(dethv_vm_t *vm, int exit_code);
void     sched_prepare_pmu(dethv_vm_t *vm);
void     sched_account_pmu(dethv_vm_t *vm);

/* ================= Main Hypervisor VM Struct ================= */

struct dethv_vm {
    dethv_config_t         cfg;

    /* KVM handles */
    int                    kvm_fd;
    int                    vm_fd;
    int                    vcpu_fd;
    struct kvm_run        *kvm_run;
    size_t                 kvm_run_size;
    struct kvm_dirty_gfn  *dirty_ring;
    uint32_t               dirty_ring_entries;
    uint32_t               dirty_ring_head;
    bool                   use_dirty_ring;
    bool                   dirty_ring_overflow;

    /* Host-VMM dirty physical page tracker (catches VMM memcpy writes that bypass NPT!) */
    uint32_t               host_dirty_gfns[DETHV_MAX_HOST_DIRTY];
    uint32_t               host_dirty_count;
    bool                   host_dirty_overflow;
    uint8_t               *host_dirty_bitmap;
    size_t                 host_dirty_bitmap_bytes;
    uint64_t               loaded_snap_id;
    dethv_snapshot_t      *active_cov_snap;

    /* Guest physical RAM */
    uint8_t               *mem;
    size_t                 ram_size;
    guest_shared_t        *shared;     /* Points to mem + GUEST_SHARED_PHYS */

    /* Cached vCPU state for fast SYNC_REGS */
    uint64_t               current_fs_base;
    bool                   fs_base_dirty;
    bool                   sregs_dirty;
    bool                   sregs_changed_since_snap;
    bool                   lapic_touched;
    bool                   pmu_available;
    uint32_t               pmu_event_ctl_pmi;
    uint32_t               pmu_event_ctl_nopmi;
    struct kvm_xsave       initial_xsave;
    struct kvm_xcrs        initial_xcrs;
    struct kvm_lapic_state initial_lapic;

    /* Core deterministic subsystems (all saved/restored in snapshots!) */
    det_state_t            det;
    mmu_state_t            mmu;
    sched_state_t          sched;
    vfs_state_t            vfs;
    patch_table_t          patches;
    sym_table_t            syms;

    /* Snapshot trigger settings */
    uint64_t               snap_trigger_addr;
    bool                   snap_on_stdin;
    bool                   snap_on_stdin_armed;
    char                   snap_on_open_substr[128];
    bool                   snap_on_open_armed;

    /* Run status */
    bool                   running;
    dethv_stop_reason_t    stop_reason;
    int                    exit_code;
    int                    crash_signal;
    uint64_t               fault_rip;
    uint64_t               fault_addr;
    uint64_t               fault_errcode;
    uint64_t               last_dirty_pages;
};

/* Writable leaf PTE entry cached at snapshot time for zero-VMEXIT hardware PTE_D dirty tracking! */
typedef struct {
    uint32_t pte_offset;   /* Byte offset of uint64_t PTE in guest RAM */
    uint32_t phys_offset;  /* Byte offset of backed 4KB physical page in guest RAM */
} snap_wpte_t;

/* Snapshot structure */
struct dethv_snapshot {
    uint32_t               magic;
    uint32_t               version;
    uint64_t               id;
    size_t                 ram_size;
    size_t                 phys_used;
    uint8_t               *mem;         /* Copy of [0 .. phys_used) */
    snap_wpte_t           *wptes;       /* Compact list of writable PTEs for O(dirty) PTE_D reset */
    uint32_t               num_wptes;

    /* Full vCPU architectural state */
    struct kvm_regs        regs;
    struct kvm_sregs       sregs;
    struct kvm_vcpu_events events;
    struct kvm_xsave       xsave;
    struct kvm_xcrs        xcrs;
    struct kvm_lapic_state lapic;

    /* Full deterministic VMM subsystem state */
    det_state_t            det;
    mmu_state_t            mmu;
    sched_state_t          sched;
    vfs_state_t            vfs;
    patch_table_t          patches;
    sym_table_t            syms;
    uint64_t               current_fs_base;
};

/* Syscall & Exception dispatchers */
void dethv_handle_syscall(dethv_vm_t *vm);
void dethv_handle_exception(dethv_vm_t *vm);

/* Fast O(1) host-VMM dirty page marker */
static inline void vmm_mark_phys_dirty(dethv_vm_t *vm, uint64_t phys_addr) {
    if (!vm->host_dirty_bitmap || vm->host_dirty_overflow) return;
    uint64_t gfn = phys_addr >> 12;
    size_t byte_idx = (size_t)(gfn >> 3);
    if (byte_idx >= vm->host_dirty_bitmap_bytes) return;
    uint8_t bit = (uint8_t)(1U << (gfn & 7));
    if (vm->host_dirty_bitmap[byte_idx] & bit) return;
    vm->host_dirty_bitmap[byte_idx] |= bit;
    if (vm->host_dirty_count < DETHV_MAX_HOST_DIRTY) {
        vm->host_dirty_gfns[vm->host_dirty_count++] = (uint32_t)gfn;
    } else {
        vm->host_dirty_overflow = true;
    }
}

/* Embedded Ring-0 guest kernel binary (built from src/guest_stub.S) */
extern const uint8_t guest_stub_bin[];
extern const uint32_t guest_stub_bin_len;

/* Fixed entry points exported by guest_stub.S (offsets from GUEST_STUB_VADDR) */
#define STUB_OFF_ENTER_USER     0x0000
#define STUB_OFF_SYSCALL_ENTRY  0x0200
#define STUB_OFF_ISR_PMI        0x0400
#define STUB_OFF_ISR_DB         0x0600
#define STUB_OFF_ISR_GP         0x0900
#define STUB_OFF_ISR_COMMON     0x0B00
#define STUB_OFF_ISR_TABLE      0x0E00  /* 32 exception stubs, 16 bytes each */

#endif /* DETHV_INTERNAL_H */
