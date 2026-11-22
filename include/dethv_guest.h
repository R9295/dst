/*
 * DetHV Guest-Side Hypercall Header (x86_64 Linux)
 *
 * Include this header in a C/C++ fuzzing harness to request fuzzing input,
 * trigger automatic snapshotting, finish iterations instantly without libc
 * teardown, or report custom invariant failures to DetHV.
 *
 * Uses dedicated x86_64 `syscall` numbers (0x44455400..0x44455404) so:
 *   - Works identically on both AMD SVM and Intel VMX
 *   - Safe on native host Linux (returns -ENOSYS without crashing)
 *   - Zero extra setup; auto-snapshots cleanly right at dethv_get_input()
 *
 * Rust equivalent (inline asm):
 *   unsafe fn dethv_get_input(buf: *mut u8, max_len: usize) -> isize {
 *       let ret: isize;
 *       core::arch::asm!(
 *           "syscall",
 *           inlateout("rax") 0x44455401usize => ret,
 *           in("rdi") buf,
 *           in("rsi") max_len,
 *           in("rdx") 0usize,
 *           lateout("rcx") _,
 *           lateout("r11") _,
 *           options(nostack),
 *       );
 *       ret
 *   }
 */

#ifndef DETHV_GUEST_H
#define DETHV_GUEST_H

#include <stddef.h>
#include <stdint.h>

/* Hypercall syscall numbers ("DET\0" base) */
#define DETHV_HC_PING           0x44455400ULL
#define DETHV_HC_GET_INPUT      0x44455401ULL
#define DETHV_HC_SNAPSHOT       0x44455402ULL
#define DETHV_HC_DONE           0x44455403ULL
#define DETHV_HC_PANIC          0x44455404ULL

/* Returned by DETHV_HC_PING when running inside DetHV ("DETHV") */
#define DETHV_HC_MAGIC          0x4445544856ULL

/* Flags for dethv_get_input_ex() */
#define DETHV_HC_FLAG_NO_SNAP   (1ULL << 0) /* Do not trigger auto-snapshot on this call */
#define DETHV_HC_FLAG_PEEK      (1ULL << 1) /* Read input without advancing cursor */
#define DETHV_HC_FLAG_REWIND    (1ULL << 2) /* Reset input cursor to 0 before reading */

#if defined(__x86_64__) && defined(__GNUC__)

static inline int64_t dethv_hypercall3(uint64_t nr, uint64_t a1, uint64_t a2, uint64_t a3) {
    int64_t ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

/* Returns 1 if executing inside DetHV, 0 on native host Linux. */
static inline int dethv_is_present(void) {
    return dethv_hypercall3(DETHV_HC_PING, 0, 0, 0) == (int64_t)DETHV_HC_MAGIC;
}

/*
 * Fetch up to `max_len` bytes of fuzzing input from DetHV into `buf`.
 * Automatically triggers snapshot capture on the first call when snapshot
 * mode is enabled (rewinding RIP so every snapshot restore re-executes this
 * call with the fuzzer's next mutated input).
 *
 * Pass buf=NULL, max_len=0 to query remaining input length in bytes.
 * Returns number of bytes copied (>= 0), or negative errno (-ENOSYS on native Linux).
 */
static inline int64_t dethv_get_input_ex(void *buf, size_t max_len, uint64_t flags) {
    return dethv_hypercall3(DETHV_HC_GET_INPUT, (uint64_t)(uintptr_t)buf, (uint64_t)max_len, flags);
}

static inline int64_t dethv_get_input(void *buf, size_t max_len) {
    return dethv_get_input_ex(buf, max_len, 0);
}

/*
 * Explicitly trigger an auto-snapshot at this point (without fetching input).
 * Returns 1 when resumed from a snapshot, 0 if snapshotting was not armed,
 * or -ENOSYS on native Linux.
 */
static inline int64_t dethv_snapshot(void) {
    return dethv_hypercall3(DETHV_HC_SNAPSHOT, 0, 0, 0);
}

/*
 * Immediately complete the current fuzzing iteration cleanly with `exit_code`,
 * skipping libc atexit/stdio teardown for maximum snapshot-fuzzing throughput.
 */
static inline void dethv_done(int exit_code) {
    (void)dethv_hypercall3(DETHV_HC_DONE, (uint64_t)(int64_t)exit_code, 0, 0);
}

/*
 * Immediately report a harness-detected invariant violation / bug as a crash
 * (DETHV_STOP_CRASH_ABRT with fault_addr = code).
 */
static inline void dethv_panic(uint64_t code, const char *msg, size_t msg_len) {
    (void)dethv_hypercall3(DETHV_HC_PANIC, code, (uint64_t)(uintptr_t)msg, (uint64_t)msg_len);
}

#endif /* __x86_64__ && __GNUC__ */
#endif /* DETHV_GUEST_H */
