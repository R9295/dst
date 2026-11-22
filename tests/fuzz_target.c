/*
 * Realistic Unmodified Linux Fuzzing Target
 *
 * Simulates a real server/parser binary:
 *   1. Expensive startup initialization (builds lookup tables, hashes, spawns a
 *      helper thread, reads randomness/time) — skipped on every fuzz iteration
 *      thanks to DetHV snapshotting right at parse_input() or first read(0)!
 *   2. Reads structured binary input from stdin.
 *   3. Parses multi-stage conditions with 3 reachable deterministic crashes:
 *      - Crash 1 (SIGSEGV NULL deref):  "DF" + byte[2]=='!' + byte[3]==0x42
 *      - Crash 2 (SIGFPE div-by-zero):  "DZ" + byte[2]==0x00 + byte[3]==0x7f
 *      - Crash 3 (SIGABRT abort()):     "DA" + checksum match
 */

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

static uint32_t g_sbox[256];
static uint64_t g_session_key = 0;
static volatile int g_init_done = 0;

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
    g_init_done = 1;
    return NULL;
}

__attribute__((noinline))
static int stage_segv(const uint8_t *buf, size_t n) {
    if (n >= 4 && buf[2] == '!') {
        printf("stage_segv_step1\n");
        if (buf[3] == 0x42) {
            volatile int *p = NULL;
            return *p; /* Reachable deterministic SIGSEGV! */
        }
    }
    return 1;
}

__attribute__((noinline))
static int stage_fpe(const uint8_t *buf, size_t n) {
    if (n >= 4 && buf[2] == 0x00) {
        printf("stage_fpe_step1\n");
        if (buf[3] == 0x7f) {
            volatile int denom = (int)(buf[2]);
            volatile int num = 1337;
            return num / denom; /* Reachable deterministic SIGFPE! */
        }
    }
    return 2;
}

__attribute__((noinline))
static int stage_abrt(const uint8_t *buf, size_t n) {
    if (n >= 4 && buf[2] == 'Z') {
        printf("stage_abrt_step1\n");
        if ((uint8_t)(buf[0] ^ buf[1] ^ buf[2]) == buf[3]) {
            abort(); /* Reachable deterministic SIGABRT! */
        }
    }
    return 3;
}

__attribute__((noinline))
int parse_input(const uint8_t *buf, size_t n) {
    if (n < 2) return 0;

    /* Mix deterministic session randomness into processing (still 100% deterministic!) */
    uint32_t acc = (uint32_t)(g_session_key ^ g_sbox[buf[0]]);
    for (size_t i = 0; i < n; i++) {
        acc = (acc * 33U) ^ g_sbox[buf[i]];
    }

    if (buf[0] == 'D') {
        printf("magic_D\n");
        if (buf[1] == 'F') return stage_segv(buf, n);
        if (buf[1] == 'Z') return stage_fpe(buf, n);
        if (buf[1] == 'A') return stage_abrt(buf, n);
    }

    return (int)(acc & 0x7f);
}

int main(void) {
    /* Expensive startup initialization that snapshot fuzzing completely skips! */
    pthread_t th;
    pthread_create(&th, NULL, init_worker, NULL);
    if (getrandom(&g_session_key, sizeof(g_session_key), 0) != sizeof(g_session_key)) {
        g_session_key = 0x1122334455667788ULL;
    }
    pthread_join(th, NULL);

    uint8_t buf[256];
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
    if (n <= 0) return 0;

    int rc = parse_input(buf, (size_t)n);
    return rc & 0x7f;
}
