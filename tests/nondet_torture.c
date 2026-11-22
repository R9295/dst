/*
 * Non-Determinism Torture Test Binary (Unmodified Standard Linux C Program)
 *
 * Intentionally exercises EVERY notorious source of non-determinism in Linux:
 *   1. Multithreading:
 *      - 6 pthreads running concurrently
 *      - Shared unprotected & atomic work interleaved under preemptive scheduling
 *      - pthread_mutex, pthread_cond, pthread_barrier synchronization
 *      - Atomic spinlock (busy-waiting without syscalls -> tests hardware preemption!)
 *      - Thread-local storage (__thread) + FPU/SSE/AVX floating point across context switches
 *      - Dynamic malloc/free across multiple threads
 *   2. Randomness & Hardware Entropy:
 *      - getrandom(2) syscall
 *      - /dev/urandom & /dev/random reads
 *      - Direct inline-assembly RDRAND (16-bit, 32-bit, 64-bit) — ignoring CPUID!
 *      - Direct inline-assembly RDSEED (16-bit, 32-bit, 64-bit) — ignoring CPUID!
 *      - AT_RANDOM auxiliary vector bytes (getauxval)
 *      - /proc/sys/kernel/random/uuid
 *      - srand(time ^ clock ^ rdtsc) + rand()
 *   3. Clocks & Timers:
 *      - Direct inline-assembly RDTSC and RDTSCP
 *      - clock_gettime(CLOCK_REALTIME & CLOCK_MONOTONIC)
 *      - gettimeofday() and time()
 *      - nanosleep() (real sleep on host, instant deterministic virtual sleep in DetHV!)
 *   4. OS / Memory / ASLR State:
 *      - Stack address, heap malloc address, mmap address, code & libc addresses
 *      - getpid(), gettid(), uname()
 *      - Pipe & temporary file write/read I/O
 *
 * On native Linux: produces wildly different outputs & hashes on EVERY run!
 * Inside DetHV:    MUST produce 100.000% BIT-FOR-BIT IDENTICAL output & hash!
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define NUM_WORKERS 6

static uint64_t fnv1a_u64(uint64_t h, uint64_t v) {
    const uint8_t *p = (const uint8_t *)&v;
    for (int i = 0; i < 8; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static inline uint64_t do_rdtsc(void) {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t do_rdtscp(uint32_t *aux) {
    uint32_t lo, hi, c;
    __asm__ volatile("rdtscp" : "=a"(lo), "=d"(hi), "=c"(c));
    if (aux) *aux = c;
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t do_rdrand64(void) {
    uint64_t val = 0;
    unsigned char ok = 0;
    for (int i = 0; i < 16 && !ok; i++) {
        __asm__ volatile("rdrand %0; setc %1" : "=r"(val), "=qm"(ok));
    }
    return val;
}

static inline uint32_t do_rdrand32(void) {
    uint32_t val = 0;
    unsigned char ok = 0;
    for (int i = 0; i < 16 && !ok; i++) {
        __asm__ volatile("rdrand %0; setc %1" : "=r"(val), "=qm"(ok));
    }
    return val;
}

static inline uint16_t do_rdrand16(void) {
    uint16_t val = 0;
    unsigned char ok = 0;
    for (int i = 0; i < 16 && !ok; i++) {
        __asm__ volatile("rdrand %0; setc %1" : "=r"(val), "=qm"(ok));
    }
    return val;
}

static inline uint64_t do_rdseed64(void) {
    uint64_t val = 0;
    unsigned char ok = 0;
    for (int i = 0; i < 32 && !ok; i++) {
        __asm__ volatile("rdseed %0; setc %1" : "=r"(val), "=qm"(ok));
    }
    return val;
}

/* Shared multithreading torture state */
static pthread_mutex_t   g_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t    g_cv  = PTHREAD_COND_INITIALIZER;
static pthread_barrier_t g_barrier;

static atomic_int        g_spin_lock = 0;
static atomic_int        g_ready_count = 0;
static atomic_int        g_go_flag = 0;

/* Order-sensitive log (sensitive to exact thread interleaving!) */
#define ORDER_LOG_LEN 64
static int               g_order_log[ORDER_LOG_LEN];
static int               g_order_idx = 0;
static uint64_t          g_shared_mix = 0x123456789ABCDEF0ULL;
static int               g_cond_turn = 0;

static __thread uint64_t tls_acc = 0;
static uint64_t          g_worker_results[NUM_WORKERS];

static void spin_acquire(atomic_int *lk) {
    int expected = 0;
    while (!atomic_compare_exchange_weak_explicit(lk, &expected, 1,
                                                  memory_order_acquire,
                                                  memory_order_relaxed)) {
        expected = 0;
        /* Pure CPU spin loop (no syscall!) — forces hardware preemptive scheduling! */
        for (volatile int d = 0; d < 8; d++) {}
    }
}

static void spin_release(atomic_int *lk) {
    atomic_store_explicit(lk, 0, memory_order_release);
}

static void *worker_fn(void *arg) {
    int id = (int)(intptr_t)arg;
    pid_t tid = (pid_t)syscall(SYS_gettid);
    tls_acc = 0xCAFEBABE00000000ULL ^ (uint64_t)id ^ ((uint64_t)tid << 16);

    /* Wait until main flips g_go_flag using a pure busy spin (tests preemption!) */
    atomic_fetch_add(&g_ready_count, 1);
    while (!atomic_load_explicit(&g_go_flag, memory_order_acquire)) {
        for (volatile int k = 0; k < 5; k++) {}
    }

    /* Barrier sync */
    pthread_barrier_wait(&g_barrier);

    /* Phase 1: Pure CPU-bound work + SSE/AVX FP + atomic spinlock interleaving */
    double fp = 1.0 + (double)id * 0.37;
    for (int round = 0; round < 6; round++) {
        /* CPU-heavy conditional branch loop (triggers deterministic ExRetCond preemption!) */
        uint64_t work = tls_acc + (uint64_t)round * 131;
        for (int iter = 0; iter < 12000; iter++) {
            if ((work ^ (uint64_t)iter) & 1) {
                work = (work * 6364136223846793005ULL) + 1442695040888963407ULL;
                fp = fp * 1.0000013 + 0.0000007 * (double)(iter & 7);
            } else {
                work ^= (work >> 17) ^ (work << 7);
                fp = fp * 0.9999991 + 0.0000003 * (double)(id + 1);
            }
        }
        tls_acc = work;

        /* Acquire spinlock & record exact interleaving order + randomness + rdtsc! */
        spin_acquire(&g_spin_lock);
        uint64_t r64 = do_rdrand64();
        uint64_t tsc = do_rdtsc();
        uint64_t gr  = 0;
        if (getrandom(&gr, sizeof(gr), 0) != sizeof(gr)) gr = 0xBAD;
        g_shared_mix = fnv1a_u64(g_shared_mix, (uint64_t)id);
        g_shared_mix = fnv1a_u64(g_shared_mix, r64 ^ tsc ^ gr ^ tls_acc);
        if (g_order_idx < ORDER_LOG_LEN) {
            g_order_log[g_order_idx++] = id * 10 + round;
        }
        spin_release(&g_spin_lock);
    }

    /* Phase 2: Mutex + Condvar baton passing + per-thread malloc */
    pthread_mutex_lock(&g_mtx);
    while (g_cond_turn != id) {
        pthread_cond_wait(&g_cv, &g_mtx);
    }
    uint8_t *buf = malloc(256 + (size_t)id * 37);
    memset(buf, (uint8_t)(0x40 + id), 256);
    uint64_t ptr_val = (uint64_t)(uintptr_t)buf;
    uint64_t fp_bits = 0;
    memcpy(&fp_bits, &fp, sizeof(fp_bits));
    g_worker_results[id] = fnv1a_u64(tls_acc ^ fp_bits, ptr_val ^ (uint64_t)tid);
    free(buf);
    g_cond_turn++;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mtx);

    /* Short virtual sleep */
    struct timespec slp = { .tv_sec = 0, .tv_nsec = 5000000 }; /* 5 ms */
    nanosleep(&slp, NULL);

    return (void *)(uintptr_t)g_worker_results[id];
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    uint64_t digest = 0xcbf29ce484222325ULL;

    /* 1. Process / ASLR / Memory addresses */
    int stack_var = 42;
    void *heap_ptr = malloc(128);
    void *mmap_ptr = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint64_t addr_stack = (uint64_t)(uintptr_t)&stack_var;
    uint64_t addr_heap  = (uint64_t)(uintptr_t)heap_ptr;
    uint64_t addr_mmap  = (uint64_t)(uintptr_t)mmap_ptr;
    uint64_t addr_main  = (uint64_t)(uintptr_t)&main;
    pid_t pid = getpid();
    pid_t tid = (pid_t)syscall(SYS_gettid);
    struct utsname uts;
    uname(&uts);

    /* 2. AT_RANDOM */
    uint64_t at_rand[2] = {0, 0};
    const uint8_t *aux_rand = (const uint8_t *)getauxval(AT_RANDOM);
    if (aux_rand) memcpy(at_rand, aux_rand, 16);

    /* 3. Randomness: getrandom, /dev/urandom, /dev/random, RDRAND 16/32/64, RDSEED 64, /proc uuid */
    uint64_t gr1 = 0, ur1 = 0, rd1 = 0;
    if (getrandom(&gr1, sizeof(gr1), 0) != sizeof(gr1)) gr1 = 0;

    int ufd = open("/dev/urandom", O_RDONLY);
    if (ufd >= 0) { ssize_t n = read(ufd, &ur1, sizeof(ur1)); (void)n; close(ufd); }

    int rfd = open("/dev/random", O_RDONLY);
    if (rfd >= 0) { ssize_t n = read(rfd, &rd1, sizeof(rd1)); (void)n; close(rfd); }

    uint64_t rdr64 = do_rdrand64();
    uint32_t rdr32 = do_rdrand32();
    uint16_t rdr16 = do_rdrand16();
    uint64_t rds64 = do_rdseed64();

    char uuid_buf[64] = "none";
    int pfd = open("/proc/sys/kernel/random/uuid", O_RDONLY);
    if (pfd >= 0) {
        ssize_t n = read(pfd, uuid_buf, sizeof(uuid_buf) - 1);
        if (n > 0) {
            uuid_buf[n] = '\0';
            while (n > 0 && (uuid_buf[n-1] == '\n' || uuid_buf[n-1] == '\r')) uuid_buf[--n] = '\0';
        }
        close(pfd);
    }

    /* 4. Time: RDTSC, RDTSCP, clock_gettime, gettimeofday, time, nanosleep */
    uint32_t tsc_aux = 0;
    uint64_t tsc1 = do_rdtsc();
    uint64_t tsc2 = do_rdtscp(&tsc_aux);
    struct timespec ts_rt = {0}, ts_mono = {0};
    clock_gettime(CLOCK_REALTIME, &ts_rt);
    clock_gettime(CLOCK_MONOTONIC, &ts_mono);
    struct timeval tv = {0};
    gettimeofday(&tv, NULL);
    time_t tnow = time(NULL);

    /* Virtual sleep of 10ms */
    struct timespec slp = { .tv_sec = 0, .tv_nsec = 10000000 };
    nanosleep(&slp, NULL);
    struct timespec ts_mono2 = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts_mono2);

    /* Classic srand/rand seeded from time + rdtsc + pid */
    srand((unsigned int)(tnow ^ tsc1 ^ (uint64_t)pid ^ gr1));
    int libc_r1 = rand(), libc_r2 = rand();

    /* 5. Pipe & virtual file I/O */
    int p[2] = {-1, -1};
    char pipe_rx[32] = {0};
    if (pipe(p) == 0) {
        const char *msg = "DETHV_PIPE_OK";
        ssize_t w = write(p[1], msg, strlen(msg)); (void)w;
        ssize_t r = read(p[0], pipe_rx, sizeof(pipe_rx) - 1); (void)r;
        close(p[0]); close(p[1]);
    }

    /* 6. Multithreaded torture test! */
    pthread_barrier_init(&g_barrier, NULL, NUM_WORKERS);
    pthread_t threads[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++) {
        if (pthread_create(&threads[i], NULL, worker_fn, (void *)(intptr_t)i) != 0) {
            fprintf(stderr, "pthread_create(%d) failed!\n", i);
            return 1;
        }
    }
    /* Busy-spin waiting for all workers to enter before releasing g_go_flag */
    while (atomic_load(&g_ready_count) < NUM_WORKERS) {
        for (volatile int k = 0; k < 20; k++) {}
    }
    atomic_store_explicit(&g_go_flag, 1, memory_order_release);

    for (int i = 0; i < NUM_WORKERS; i++) {
        void *ret = NULL;
        pthread_join(threads[i], &ret);
        digest = fnv1a_u64(digest, (uint64_t)(uintptr_t)ret);
    }
    pthread_barrier_destroy(&g_barrier);

    /* Fold EVERYTHING into final deterministic digest */
    digest = fnv1a_u64(digest, addr_stack);
    digest = fnv1a_u64(digest, addr_heap);
    digest = fnv1a_u64(digest, addr_mmap);
    digest = fnv1a_u64(digest, addr_main);
    digest = fnv1a_u64(digest, (uint64_t)pid ^ ((uint64_t)tid << 32));
    digest = fnv1a_u64(digest, at_rand[0] ^ at_rand[1]);
    digest = fnv1a_u64(digest, gr1);
    digest = fnv1a_u64(digest, ur1);
    digest = fnv1a_u64(digest, rd1);
    digest = fnv1a_u64(digest, rdr64);
    digest = fnv1a_u64(digest, ((uint64_t)rdr32 << 16) | rdr16);
    digest = fnv1a_u64(digest, rds64);
    digest = fnv1a_u64(digest, tsc1);
    digest = fnv1a_u64(digest, tsc2 ^ tsc_aux);
    digest = fnv1a_u64(digest, (uint64_t)ts_rt.tv_sec * 1000000000ULL + (uint64_t)ts_rt.tv_nsec);
    digest = fnv1a_u64(digest, (uint64_t)ts_mono.tv_sec * 1000000000ULL + (uint64_t)ts_mono.tv_nsec);
    digest = fnv1a_u64(digest, (uint64_t)ts_mono2.tv_sec * 1000000000ULL + (uint64_t)ts_mono2.tv_nsec);
    digest = fnv1a_u64(digest, (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec);
    digest = fnv1a_u64(digest, (uint64_t)libc_r1 ^ ((uint64_t)libc_r2 << 32));
    digest = fnv1a_u64(digest, g_shared_mix);
    for (int i = 0; i < g_order_idx; i++) {
        digest = fnv1a_u64(digest, (uint64_t)g_order_log[i]);
    }

    printf("=== DetHV Non-Determinism Torture Test ===\n");
    printf("PID/TID    : %d / %d (host=%s)\n", (int)pid, (int)tid, uts.nodename);
    printf("ADDRS      : main=0x%lx stack=0x%lx heap=0x%lx mmap=0x%lx\n",
           (unsigned long)addr_main, (unsigned long)addr_stack,
           (unsigned long)addr_heap, (unsigned long)addr_mmap);
    printf("AT_RANDOM  : %016lx%016lx\n", (unsigned long)at_rand[0], (unsigned long)at_rand[1]);
    printf("GETRANDOM  : 0x%016lx  /dev/urandom=0x%016lx  /dev/random=0x%016lx\n",
           (unsigned long)gr1, (unsigned long)ur1, (unsigned long)rd1);
    printf("HW_RNG     : rdrand64=0x%016lx rdrand32=0x%08x rdrand16=0x%04x rdseed64=0x%016lx\n",
           (unsigned long)rdr64, rdr32, rdr16, (unsigned long)rds64);
    printf("UUID/RAND  : uuid=%s rand()=(%d, %d)\n", uuid_buf, libc_r1, libc_r2);
    printf("CLOCKS     : rdtsc=%lu rdtscp=%lu(aux=%u) rt=%ld.%09ld mono=%ld.%09ld->%ld.%09ld\n",
           (unsigned long)tsc1, (unsigned long)tsc2, tsc_aux,
           (long)ts_rt.tv_sec, ts_rt.tv_nsec,
           (long)ts_mono.tv_sec, ts_mono.tv_nsec,
           (long)ts_mono2.tv_sec, ts_mono2.tv_nsec);
    printf("PIPE       : %s\n", pipe_rx);
    printf("THREADS    : %d workers, order_events=%d, shared_mix=0x%016lx\n",
           NUM_WORKERS, g_order_idx, (unsigned long)g_shared_mix);
    printf("ORDER[0..15]:");
    for (int i = 0; i < 16 && i < g_order_idx; i++) printf(" %d", g_order_log[i]);
    printf("\n");
    printf("FINAL_DIGEST: 0x%016lx\n", (unsigned long)digest);

    free(heap_ptr);
    munmap(mmap_ptr, 8192);
    return 0;
}
