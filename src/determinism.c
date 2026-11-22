#include "internal.h"
#include <string.h>

static uint64_t splitmix64(uint64_t *state) {
    uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static inline uint64_t rotl64(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

void det_init(det_state_t *det, uint64_t seed, uint64_t start_time_ns) {
    memset(det, 0, sizeof(*det));
    det->seed = seed;
    uint64_t sm = seed ^ 0x243F6A8885A308D3ULL;
    det->s[0] = splitmix64(&sm);
    det->s[1] = splitmix64(&sm);
    det->s[2] = splitmix64(&sm);
    det->s[3] = splitmix64(&sm);
    det->vtime_ns = start_time_ns;
    det->vmono_ns = 1000000000ULL; /* Start monotonic clock at 1.000000000 s */
}

/* xoshiro256** - fast, high-quality, 100% deterministic PRNG */
uint64_t det_rand64(det_state_t *det) {
    uint64_t *s = det->s;
    const uint64_t result = rotl64(s[1] * 5ULL, 7) * 9ULL;
    const uint64_t t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl64(s[3], 45);
    return result;
}

void det_rand_bytes(det_state_t *det, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    while (len >= 8) {
        uint64_t v = det_rand64(det);
        memcpy(p, &v, 8);
        p += 8;
        len -= 8;
    }
    if (len > 0) {
        uint64_t v = det_rand64(det);
        memcpy(p, &v, len);
    }
}

void det_advance_time(det_state_t *det, uint64_t delta_ns) {
    det->vtime_ns += delta_ns;
    det->vmono_ns += delta_ns;
}

uint64_t det_hash_bytes(uint64_t h, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    if (h == 0) h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)p[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

uint64_t det_hash_u64(uint64_t h, uint64_t v) {
    return det_hash_bytes(h, &v, sizeof(v));
}
