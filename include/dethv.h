#ifndef DETHV_H
#define DETHV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dethv_vm dethv_vm_t;
typedef struct dethv_snapshot dethv_snapshot_t;

typedef enum {
    DETHV_STOP_NONE = 0,
    DETHV_STOP_EXITED,          /* Normal exit / exit_group */
    DETHV_STOP_CRASH_SEGV,      /* SIGSEGV (#PF / #GP) */
    DETHV_STOP_CRASH_ILL,       /* SIGILL (#UD) */
    DETHV_STOP_CRASH_FPE,       /* SIGFPE (#DE / #XF) */
    DETHV_STOP_CRASH_ABRT,      /* SIGABRT (tgkill/kill/abort) */
    DETHV_STOP_CRASH_BUS,       /* SIGBUS (#AC / #SS) */
    DETHV_STOP_CRASH_TRAP,      /* SIGTRAP (unhandled int3 / #DB) */
    DETHV_STOP_SNAPSHOT,        /* Hit configured snapshot trigger */
    DETHV_STOP_STEP,            /* Reached virtual time step deadline (dethv_run_step) */
    DETHV_STOP_NET_TX,          /* Guest transmitted UDP packet to external virtual peer */
    DETHV_STOP_TIMEOUT,         /* Exceeded deterministic syscall/branch budget */
    DETHV_STOP_DEADLOCK,        /* All threads blocked with no wakeups */
    DETHV_STOP_ERROR            /* Internal hypervisor error */
} dethv_stop_reason_t;

typedef struct {
    size_t   ram_size;          /* Guest physical RAM size (default 256MB) */
    uint64_t seed;              /* Master deterministic PRNG seed */
    uint64_t start_time_ns;     /* Initial deterministic UNIX epoch (ns) */
    uint64_t preempt_quantum;   /* Retired conditional branches per thread slice (default 20000) */
    uint64_t max_syscalls;      /* Deterministic timeout budget (0 = unlimited) */
    uint64_t max_preempts;      /* Deterministic preempt budget (0 = unlimited) */
    bool     trace_syscalls;    /* Print syscall trace */
    bool     capture_output;    /* Capture stdout/stderr into internal buffers instead of host tty */
    bool     enable_pmu;        /* Enable hardware ExRetCond zero-skid preemption (default true) */
    bool     patch_rdrand;      /* Scan & patch RDRAND/RDSEED in executable pages (default true) */
    bool     allow_host_ro;     /* Allow read-only access to host files/shared libs (default true) */
} dethv_config_t;

typedef struct {
    dethv_stop_reason_t reason;
    int      exit_code;         /* Process exit status if EXITED */
    int      signal;            /* Crash signal number if CRASH_* */
    uint64_t fault_rip;         /* RIP at stop/crash */
    uint64_t fault_addr;        /* CR2 faulting address (for SEGV) */
    uint64_t fault_errcode;     /* Exception error code */
    uint64_t syscalls;          /* Total syscalls executed */
    uint64_t preempts;          /* Total deterministic thread preemptions */
    uint64_t rdtsc_traps;       /* Total RDTSC/RDTSCP traps emulated */
    uint64_t rdrand_traps;      /* Total RDRAND/RDSEED instructions emulated */
    uint64_t getrandom_calls;   /* Total getrandom/urandom reads emulated */
    uint64_t total_threads;     /* Total threads spawned */
    uint64_t pmu_overshoots;    /* Should always be 0 */
    uint64_t dirty_pages;       /* Dirty pages touched since snapshot restore */
    uint64_t state_hash;        /* FNV-1a/SipHash digest of final regs + stdout + stderr */
    uint64_t stdout_hash;       /* Hash of captured stdout */
    size_t   stdout_len;
    size_t   stderr_len;
} dethv_run_result_t;

/* Default configuration */
void dethv_config_default(dethv_config_t *cfg);

/* Create / destroy VM */
dethv_vm_t *dethv_create(const dethv_config_t *cfg);
void        dethv_destroy(dethv_vm_t *vm);

/* Load unmodified Linux ELF binary (static or dynamic!) */
int dethv_load_elf(dethv_vm_t *vm, const char *path, int argc, char **argv, char **envp);

/* Resolve an ELF symbol address (returns 0 if not found) */
uint64_t dethv_lookup_symbol(dethv_vm_t *vm, const char *sym_name);

/* Configure snapshot trigger */
int  dethv_set_snapshot_addr(dethv_vm_t *vm, uint64_t vaddr);
void dethv_set_snapshot_on_stdin(dethv_vm_t *vm, bool enable);
void dethv_set_snapshot_on_open(dethv_vm_t *vm, const char *path_substr);
void dethv_set_snapshot_on_hc(dethv_vm_t *vm, bool enable);

/* Input / Virtual file injection (useful after snapshot reload for fuzzing!) */
int  dethv_set_stdin(dethv_vm_t *vm, const void *data, size_t len);
int  dethv_set_input(dethv_vm_t *vm, const void *data, size_t len);
void dethv_get_input_info(const dethv_vm_t *vm, uint64_t *guest_buf_vaddr, size_t *guest_max_len);
int  dethv_set_vfile(dethv_vm_t *vm, const char *path, const void *data, size_t len);
int  dethv_set_vdir(dethv_vm_t *vm, const char *path);
int  dethv_import_host_dir(dethv_vm_t *vm, const char *host_dir, const char *guest_dir);

/* Read/write guest virtual memory */
int dethv_read_virt(dethv_vm_t *vm, uint64_t vaddr, void *dst, size_t len);
int dethv_write_virt(dethv_vm_t *vm, uint64_t vaddr, const void *src, size_t len);

/* Access captured output & optional live streaming callback */
const uint8_t *dethv_get_stdout(const dethv_vm_t *vm, size_t *len_out);
const uint8_t *dethv_get_stderr(const dethv_vm_t *vm, size_t *len_out);
typedef void (*dethv_output_cb_t)(void *ctx, int fd, const uint8_t *data, size_t len);
void dethv_set_output_cb(dethv_vm_t *vm, dethv_output_cb_t cb, void *ctx);

/* Deterministic virtual clocks (nanoseconds) */
uint64_t dethv_get_vmono_ns(const dethv_vm_t *vm);
uint64_t dethv_get_vtime_ns(const dethv_vm_t *vm);

/* Deterministic Virtual Network Peer Bridge (for host-side mock peers/validators) */
typedef struct {
    uint32_t src_ip;            /* Host byte order (e.g., 0x0a000002 = 10.0.0.2) */
    uint16_t src_port;          /* Host byte order */
    uint32_t dst_ip;            /* Host byte order (e.g., 0x0a000001 = 10.0.0.1) */
    uint16_t dst_port;          /* Host byte order */
    uint64_t vmono_ns;          /* Guest deterministic monotonic timestamp when sent */
    uint32_t len;
    uint8_t  data[1600];
} dethv_udp_pkt_t;

void   dethv_net_set_peer_ip(dethv_vm_t *vm, uint32_t guest_ip_host_order, uint32_t peer_ip_host_order);
int    dethv_net_inject_udp(dethv_vm_t *vm,
                            uint32_t src_ip, uint16_t src_port,
                            uint32_t dst_ip, uint16_t dst_port,
                            const void *data, size_t len);
int    dethv_net_pop_tx(dethv_vm_t *vm, dethv_udp_pkt_t *out);
size_t dethv_net_get_bound_udp_ports(const dethv_vm_t *vm, uint16_t *ports_out, size_t max_ports);

/* Run guest until exit, crash, timeout, or snapshot trigger */
int dethv_run(dethv_vm_t *vm, dethv_run_result_t *res);

/* Run guest deterministically until virtual monotonic clock reaches `until_vmono_ns`
 * or an external peer TX packet is sent (when `stop_on_tx` is true). */
int dethv_run_step(dethv_vm_t *vm, uint64_t until_vmono_ns, bool stop_on_tx, dethv_run_result_t *res);

/* Snapshot management (ultra-fast in-memory + persistent disk save/load) */
dethv_snapshot_t *dethv_snapshot_take(dethv_vm_t *vm);
int               dethv_snapshot_restore(dethv_vm_t *vm, const dethv_snapshot_t *snap);
void              dethv_snapshot_free(dethv_snapshot_t *snap);
int               dethv_snapshot_save_file(const dethv_snapshot_t *snap, const char *path);
dethv_snapshot_t *dethv_snapshot_load_file(const char *path);

/* Lightweight one-shot coverage breakpoints for unmodified ELF fuzzing */
int      dethv_cov_install_symbols(dethv_vm_t *vm, dethv_snapshot_t *snap);
uint64_t dethv_cov_get_count(const dethv_vm_t *vm);

/* Utility: string name for stop reason */
const char *dethv_stop_reason_str(dethv_stop_reason_t reason);

#ifdef __cplusplus
}
#endif

#endif /* DETHV_H */
