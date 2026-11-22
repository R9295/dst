/*
 * DetHV Hypercall Snapshot-Fuzzing Target
 *
 * Demonstrates using `include/dethv_guest.h`:
 *   - Expensive startup init (worker thread + S-box + getrandom) runs ONCE.
 *   - `dethv_get_input(buf, sizeof(buf))` automatically triggers a snapshot
 *     right before receiving fuzz input; every fuzz iteration reloads straight
 *     to this call with the fuzzer's next mutated input!
 *   - Safe on native host Linux: `dethv_is_present()` returns 0 and falls back
 *     to reading stdin cleanly.
 *   - Finishes iterations instantaneously with `dethv_done(0)` (zero libc
 *     teardown overhead).
 *   - 4 reachable deterministic bugs:
 *       1. SIGSEGV NULL deref:        "DF" + byte[2]=='!' + byte[3]==0x42
 *       2. SIGFPE div-by-zero:        "DZ" + byte[2]==0x00 + byte[3]==0x7f
 *       3. SIGABRT abort():           "DA" + byte[2]=='Z'  + xor checksum
 *       4. dethv_panic() invariant:   "DP" + byte[2]=='!'  + byte[3]=='!'
 */

#include "dethv_guest.h"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

static uint32_t g_sbox[256];
static uint64_t g_session_key = 0;

static void *init_worker(void *arg) {
    (void)arg;
    uint32_t x = 0x9E3779B9U;
    for (int r = 0; r < 200; r++) {
        for (int i = 0; i < 256; i++) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            g_sbox[i] ^= x + (uint32_t)r;
        }
    }
    return NULL;
}

__attribute__((noinline))
static int hc_stage_segv_step2(const uint8_t *buf) {
    if (buf[3] == 0x42) {
        volatile int *p = NULL;
        return *p;
    }
    return 11;
}

__attribute__((noinline))
static int hc_stage_segv(const uint8_t *buf, size_t n) {
    if (n >= 4 && buf[2] == '!') {
        return hc_stage_segv_step2(buf);
    }
    return 1;
}

__attribute__((noinline))
static int hc_stage_fpe_step2(const uint8_t *buf) {
    if (buf[3] == 0x7f) {
        volatile int denom = (int)buf[2];
        volatile int num = 1337;
        return num / denom;
    }
    return 22;
}

__attribute__((noinline))
static int hc_stage_fpe(const uint8_t *buf, size_t n) {
    if (n >= 4 && buf[2] == 0x00) {
        return hc_stage_fpe_step2(buf);
    }
    return 2;
}

__attribute__((noinline))
static int hc_stage_abrt_step2(const uint8_t *buf) {
    if ((uint8_t)(buf[0] ^ buf[1] ^ buf[2]) == buf[3]) {
        abort();
    }
    return 33;
}

__attribute__((noinline))
static int hc_stage_abrt(const uint8_t *buf, size_t n) {
    if (n >= 4 && buf[2] == 'Z') {
        return hc_stage_abrt_step2(buf);
    }
    return 3;
}

__attribute__((noinline))
static int hc_stage_panic_step2(const uint8_t *buf) {
    if (buf[3] == '!') {
        static const char msg[] = "DetHV invariant violated!";
        if (dethv_is_present()) {
            dethv_panic(0xBAD1ULL, msg, sizeof(msg) - 1);
        }
        abort();
    }
    return 44;
}

__attribute__((noinline))
static int hc_stage_panic(const uint8_t *buf, size_t n) {
    if (n >= 4 && buf[2] == '!') {
        return hc_stage_panic_step2(buf);
    }
    return 4;
}

__attribute__((noinline))
int hc_parse_input(const uint8_t *buf, size_t n) {
    if (n < 2) return 0;

    uint32_t acc = (uint32_t)(g_session_key ^ g_sbox[buf[0]]);
    for (size_t i = 0; i < n; i++) {
        acc = (acc * 33U) ^ g_sbox[buf[i]];
    }

    if (buf[0] == 'D') {
        if (buf[1] == 'F') return hc_stage_segv(buf, n);
        if (buf[1] == 'Z') return hc_stage_fpe(buf, n);
        if (buf[1] == 'A') return hc_stage_abrt(buf, n);
        if (buf[1] == 'P') return hc_stage_panic(buf, n);
    }

    return (int)(acc & 0x7f);
}

int main(void) {
    /* Expensive startup initialization skipped on every fuzz reload! */
    pthread_t th;
    pthread_create(&th, NULL, init_worker, NULL);
    if (getrandom(&g_session_key, sizeof(g_session_key), 0) != sizeof(g_session_key)) {
        g_session_key = 0x1122334455667788ULL;
    }
    pthread_join(th, NULL);

    uint8_t buf[256];
    int64_t n;
    int in_dethv = dethv_is_present();
    if (in_dethv) {
        /* Auto-snapshots right here on first call! */
        n = dethv_get_input(buf, sizeof(buf));
    } else {
        n = read(STDIN_FILENO, buf, sizeof(buf));
    }

    if (n < 0) return 1;

    int rc = hc_parse_input(buf, (size_t)n);

    if (in_dethv) {
        /* Instant iteration finish — skips libc atexit/stdio teardown! */
        dethv_done(0);
    }
    printf("NATIVE_OK len=%lld rc=%d\n", (long long)n, rc & 0x7f);
    return 0;
}
