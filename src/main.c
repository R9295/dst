#include "dethv.h"
#include "internal.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t wall_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "DetHV - 100%% Deterministic KVM Hypervisor for Snapshot Fuzzing (x86_64, 1 vCPU)\n\n"
        "Usage: %s [options] [--] <guest_elf> [guest_args...]\n"
        "       %s --load-snap <file.dhvs> [options]\n\n"
        "Options:\n"
        "  --seed <u64>          Master deterministic PRNG seed (default: 0xde7e415700000001)\n"
        "  --ram <MB>            Guest RAM in MiB (default: 256)\n"
        "  --quantum <N>         Retired cond-branches per thread slice (default: 20000)\n"
        "  --max-syscalls <N>    Deterministic syscall timeout budget (0 = unlimited)\n"
        "  --stdin <file>        Feed file contents as guest stdin\n"
        "  --stdin-str <str>     Feed literal string as guest stdin\n"
        "  --trace               Trace all guest syscalls\n"
        "  --quiet               Do not print guest stdout/stderr\n"
        "  --stats               Print execution & determinism statistics\n"
        "  --verify <N>          Run N independent fresh VMs and assert 100%% bit-for-bit determinism\n"
        "  --snap-sym <name>     Take snapshot upon hitting ELF symbol <name>\n"
        "  --snap-addr <hex>     Take snapshot upon hitting virtual address <hex>\n"
        "  --snap-on-stdin       Take snapshot right before first read(0, ...) from stdin\n"
        "  --save-snap <file>    Save taken snapshot to disk (.dhvs)\n"
        "  --load-snap <file>    Reload VM directly from saved disk snapshot (.dhvs)\n"
        "  --bench-snap <N>      Take snapshot and benchmark N ultra-fast reload+execute iterations\n"
        "  --fuzz <N>            Run deterministic snapshot fuzzer for N iterations\n"
        "  --fuzz-seed <u64>     Deterministic fuzzer mutation PRNG seed\n"
        "  --fuzz-max-len <N>    Max fuzzer input length in bytes (default: 64)\n"
        "  --no-pmu              Disable hardware ExRetCond preemptive scheduling\n"
        "  -h, --help            Show this help\n",
        prog, prog);
}

static uint8_t *read_entire_file(const char *path, size_t *len_out) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror(path); return NULL; }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return NULL; }
    fseek(fp, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    if (sz > 0 && fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); return NULL;
    }
    buf[sz] = 0;
    fclose(fp);
    *len_out = (size_t)sz;
    return buf;
}

static void print_stats(const dethv_run_result_t *r, double elapsed_ms) {
    fprintf(stderr,
        "[dethv] stop=%s exit=%d sig=%d rip=0x%" PRIx64 " cr2=0x%" PRIx64 " time=%.3fms\n"
        "        syscalls=%" PRIu64 " preempts=%" PRIu64 " threads=%" PRIu64
        " rdtsc=%" PRIu64 " rdrand=%" PRIu64 " getrandom=%" PRIu64
        " pmu_overshoots=%" PRIu64 " dirty_pages=%" PRIu64 "\n"
        "        stdout_len=%zu stdout_hash=0x%016" PRIx64 " state_hash=0x%016" PRIx64 "\n",
        dethv_stop_reason_str(r->reason), r->exit_code, r->signal,
        r->fault_rip, r->fault_addr, elapsed_ms,
        r->syscalls, r->preempts, r->total_threads,
        r->rdtsc_traps, r->rdrand_traps, r->getrandom_calls,
        r->pmu_overshoots, r->dirty_pages,
        r->stdout_len, r->stdout_hash, r->state_hash);
}

/* ================= Built-in Fast Deterministic Snapshot Fuzzer ================= */

typedef struct {
    uint8_t *data;
    size_t   len;
} corpus_entry_t;

static uint64_t fuzzer_rng(uint64_t *s) {
    uint64_t x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    return x;
}

static size_t mutate_input(uint64_t *rng, const uint8_t *src, size_t src_len,
                           uint8_t *dst, size_t max_len) {
    size_t len = src_len;
    if (len > max_len) len = max_len;
    if (len > 0) memcpy(dst, src, len);

    int mutations = 1 + (int)(fuzzer_rng(rng) % 4);
    for (int m = 0; m < mutations; m++) {
        uint64_t op = fuzzer_rng(rng) % 7;
        if (len == 0 || op == 0) {
            /* Append / grow random bytes */
            if (len < max_len) {
                dst[len++] = (uint8_t)fuzzer_rng(rng);
            }
        } else if (op == 1) {
            /* Bit flip */
            size_t pos = fuzzer_rng(rng) % len;
            dst[pos] ^= (uint8_t)(1U << (fuzzer_rng(rng) & 7));
        } else if (op == 2) {
            /* Byte replace */
            size_t pos = fuzzer_rng(rng) % len;
            dst[pos] = (uint8_t)fuzzer_rng(rng);
        } else if (op == 3) {
            /* Arithmetic +/- small delta */
            size_t pos = fuzzer_rng(rng) % len;
            int delta = (int)(fuzzer_rng(rng) % 33) - 16;
            dst[pos] = (uint8_t)(dst[pos] + delta);
        } else if (op == 4) {
            /* Interesting byte values */
            static const uint8_t interesting[] = {
                0x00, 0x01, 0x7f, 0x80, 0xff, 'A', 'D', 'E', 'T', 'F', 'U', 'Z', '!', '\n'
            };
            size_t pos = fuzzer_rng(rng) % len;
            dst[pos] = interesting[fuzzer_rng(rng) % sizeof(interesting)];
        } else if (op == 5 && len >= 4) {
            /* 32-bit interesting int / magic word */
            size_t pos = fuzzer_rng(rng) % (len - 3);
            uint32_t v = (uint32_t)fuzzer_rng(rng);
            if ((v & 3) == 0) v = 0;
            else if ((v & 3) == 1) v = 0xFFFFFFFFU;
            else if ((v & 3) == 2) v = 0x7FFFFFFFU;
            memcpy(dst + pos, &v, 4);
        } else if (op == 6 && len > 1) {
            /* Shrink or splice */
            if (fuzzer_rng(rng) & 1) {
                len = 1 + (fuzzer_rng(rng) % len);
            } else {
                size_t p1 = fuzzer_rng(rng) % len;
                size_t p2 = fuzzer_rng(rng) % len;
                uint8_t tmp = dst[p1]; dst[p1] = dst[p2]; dst[p2] = tmp;
            }
        }
    }
    return len;
}

static int run_snapshot_fuzzer(dethv_vm_t *vm, dethv_snapshot_t *snap,
                               const uint8_t *seed_in, size_t seed_len,
                               uint64_t iters, uint64_t fuzz_seed, size_t max_len) {
    /* Install one-shot ELF symbol coverage breakpoints into live VM & snapshot */
    int cov_bps = dethv_cov_install_symbols(vm, snap);
    fprintf(stderr, "[dethv-fuzz] Installed %d one-shot symbol coverage breakpoints\n", cov_bps);

    /* Initialize corpus with seed input (or empty 4-byte seed) */
    corpus_entry_t corpus[256];
    int corpus_cnt = 0;
    uint8_t default_seed[8] = "SEED\x00\x00\x00\x00";
    if (!seed_in || seed_len == 0) {
        seed_in = default_seed;
        seed_len = 8;
    }
    corpus[corpus_cnt].data = malloc(seed_len);
    memcpy(corpus[corpus_cnt].data, seed_in, seed_len);
    corpus[corpus_cnt].len = seed_len;
    corpus_cnt++;

    /* Track unique output hashes & unique crash RIPs */
    uint64_t seen_hashes[512];
    int seen_hash_cnt = 0;
    uint64_t crash_rips[64];
    dethv_stop_reason_t crash_reasons[64];
    int unique_crashes = 0;
    uint64_t total_crashes = 0;
    uint64_t total_dirty_pages = 0;
    uint64_t rng = fuzz_seed ? fuzz_seed : 0xF022123456789ABULL;

    uint8_t *mut = malloc(max_len + 16);
    uint64_t t0 = wall_ns();

    for (uint64_t i = 0; i < iters; i++) {
        const corpus_entry_t *base = &corpus[fuzzer_rng(&rng) % (uint64_t)corpus_cnt];
        size_t mlen = (i == 0) ? base->len : mutate_input(&rng, base->data, base->len, mut, max_len);
        if (i == 0) memcpy(mut, base->data, mlen);

        if (dethv_snapshot_restore(vm, snap) < 0) {
            fprintf(stderr, "[dethv-fuzz] snapshot restore failed at iter %" PRIu64 "\n", i);
            break;
        }
        dethv_set_stdin(vm, mut, mlen);

        uint64_t prev_cov = dethv_cov_get_count(vm);
        dethv_run_result_t res;
        dethv_run(vm, &res);
        total_dirty_pages += res.dirty_pages;

        bool interesting = false;
        if (dethv_cov_get_count(vm) > prev_cov) {
            interesting = true;
        }

        /* Also use stdout_hash + syscall_count feedback (helps guide multi-stage checks!) */
        uint64_t beh_hash = det_hash_u64(res.stdout_hash, res.syscalls);
        bool hash_new = true;
        for (int k = 0; k < seen_hash_cnt; k++) {
            if (seen_hashes[k] == beh_hash) { hash_new = false; break; }
        }
        if (hash_new && seen_hash_cnt < 512) {
            seen_hashes[seen_hash_cnt++] = beh_hash;
            interesting = true;
        }

        if (res.reason == DETHV_STOP_CRASH_SEGV ||
            res.reason == DETHV_STOP_CRASH_ABRT ||
            res.reason == DETHV_STOP_CRASH_FPE  ||
            res.reason == DETHV_STOP_CRASH_ILL  ||
            res.reason == DETHV_STOP_CRASH_BUS) {
            total_crashes++;
            bool dup = false;
            for (int c = 0; c < unique_crashes; c++) {
                if (crash_rips[c] == res.fault_rip && crash_reasons[c] == res.reason) {
                    dup = true;
                    break;
                }
            }
            if (!dup && unique_crashes < 64) {
                crash_rips[unique_crashes] = res.fault_rip;
                crash_reasons[unique_crashes] = res.reason;
                unique_crashes++;
                fprintf(stderr, "[dethv-fuzz] NEW CRASH #%d at iter %" PRIu64 ": %s rip=0x%" PRIx64
                                " cr2=0x%" PRIx64 " len=%zu hex=",
                        unique_crashes, i, dethv_stop_reason_str(res.reason),
                        res.fault_rip, res.fault_addr, mlen);
                for (size_t b = 0; b < mlen && b < 24; b++) fprintf(stderr, "%02x", mut[b]);
                fprintf(stderr, "\n");

                /* Verify 100% deterministic crash reproducibility immediately! */
                dethv_snapshot_restore(vm, snap);
                dethv_set_stdin(vm, mut, mlen);
                dethv_run_result_t repro;
                dethv_run(vm, &repro);
                if (repro.reason != res.reason || repro.fault_rip != res.fault_rip ||
                    repro.state_hash != res.state_hash) {
                    fprintf(stderr, "[dethv-fuzz] ERROR: CRASH REPRO MISMATCH! orig=0x%" PRIx64 " repro=0x%" PRIx64 "\n",
                            res.state_hash, repro.state_hash);
                    return 1;
                }
            }
        }

        if (interesting && corpus_cnt < 256) {
            corpus[corpus_cnt].data = malloc(mlen ? mlen : 1);
            if (mlen > 0) memcpy(corpus[corpus_cnt].data, mut, mlen);
            corpus[corpus_cnt].len = mlen;
            corpus_cnt++;
        }
    }

    double secs = (double)(wall_ns() - t0) / 1e9;
    double exec_per_sec = secs > 0 ? ((double)iters / secs) : 0.0;
    fprintf(stderr,
        "[dethv-fuzz] Done: %" PRIu64 " execs in %.3fs (%.1f exec/s) | "
        "avg_dirty=%.1f pages | cov=%" PRIu64 "/%d | corpus=%d | "
        "unique_crashes=%d (total=%" PRIu64 ")\n",
        iters, secs, exec_per_sec,
        (double)total_dirty_pages / (double)(iters ? iters : 1),
        dethv_cov_get_count(vm), cov_bps, corpus_cnt,
        unique_crashes, total_crashes);

    free(mut);
    for (int i = 0; i < corpus_cnt; i++) free(corpus[i].data);
    return 0;
}

int main(int argc, char **argv) {
    dethv_config_t cfg;
    dethv_config_default(&cfg);

    const char *stdin_file = NULL;
    const char *stdin_str  = NULL;
    const char *snap_sym   = NULL;
    uint64_t    snap_addr  = 0;
    bool        snap_on_stdin = false;
    const char *save_snap_path = NULL;
    const char *load_snap_path = NULL;
    int         verify_runs = 0;
    uint64_t    bench_snap_iters = 0;
    uint64_t    fuzz_iters = 0;
    uint64_t    fuzz_seed  = 0xF0220001ULL;
    size_t      fuzz_max_len = 64;
    bool        quiet = false;
    bool        show_stats = false;

    int argi = 1;
    while (argi < argc) {
        const char *a = argv[argi];
        if (strcmp(a, "--") == 0) { argi++; break; }
        if (a[0] != '-') break;

        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(a, "--seed") == 0 && argi + 1 < argc) {
            cfg.seed = strtoull(argv[++argi], NULL, 0);
        } else if (strcmp(a, "--ram") == 0 && argi + 1 < argc) {
            cfg.ram_size = strtoull(argv[++argi], NULL, 0) * 1024ULL * 1024ULL;
        } else if (strcmp(a, "--quantum") == 0 && argi + 1 < argc) {
            cfg.preempt_quantum = strtoull(argv[++argi], NULL, 0);
        } else if (strcmp(a, "--max-syscalls") == 0 && argi + 1 < argc) {
            cfg.max_syscalls = strtoull(argv[++argi], NULL, 0);
        } else if (strcmp(a, "--stdin") == 0 && argi + 1 < argc) {
            stdin_file = argv[++argi];
        } else if (strcmp(a, "--stdin-str") == 0 && argi + 1 < argc) {
            stdin_str = argv[++argi];
        } else if (strcmp(a, "--trace") == 0) {
            cfg.trace_syscalls = true;
        } else if (strcmp(a, "--quiet") == 0) {
            quiet = true;
        } else if (strcmp(a, "--stats") == 0) {
            show_stats = true;
        } else if (strcmp(a, "--no-pmu") == 0) {
            cfg.enable_pmu = false;
        } else if (strcmp(a, "--verify") == 0 && argi + 1 < argc) {
            verify_runs = atoi(argv[++argi]);
        } else if (strcmp(a, "--snap-sym") == 0 && argi + 1 < argc) {
            snap_sym = argv[++argi];
        } else if (strcmp(a, "--snap-addr") == 0 && argi + 1 < argc) {
            snap_addr = strtoull(argv[++argi], NULL, 0);
        } else if (strcmp(a, "--snap-on-stdin") == 0) {
            snap_on_stdin = true;
        } else if (strcmp(a, "--save-snap") == 0 && argi + 1 < argc) {
            save_snap_path = argv[++argi];
        } else if (strcmp(a, "--load-snap") == 0 && argi + 1 < argc) {
            load_snap_path = argv[++argi];
        } else if (strcmp(a, "--bench-snap") == 0 && argi + 1 < argc) {
            bench_snap_iters = strtoull(argv[++argi], NULL, 0);
        } else if (strcmp(a, "--fuzz") == 0 && argi + 1 < argc) {
            fuzz_iters = strtoull(argv[++argi], NULL, 0);
        } else if (strcmp(a, "--fuzz-seed") == 0 && argi + 1 < argc) {
            fuzz_seed = strtoull(argv[++argi], NULL, 0);
        } else if (strcmp(a, "--fuzz-max-len") == 0 && argi + 1 < argc) {
            fuzz_max_len = (size_t)strtoull(argv[++argi], NULL, 0);
        } else {
            fprintf(stderr, "Unknown option: %s\n", a);
            print_usage(argv[0]);
            return 1;
        }
        argi++;
    }

    const char *guest_path = (argi < argc) ? argv[argi] : NULL;
    int guest_argc = (argi < argc) ? (argc - argi) : 0;
    char **guest_argv = (argi < argc) ? &argv[argi] : NULL;

    if (!guest_path && !load_snap_path) {
        print_usage(argv[0]);
        return 1;
    }

    uint8_t *stdin_data = NULL;
    size_t stdin_len = 0;
    if (stdin_file) {
        stdin_data = read_entire_file(stdin_file, &stdin_len);
        if (!stdin_data) return 1;
    } else if (stdin_str) {
        stdin_len = strlen(stdin_str);
        stdin_data = malloc(stdin_len + 1);
        memcpy(stdin_data, stdin_str, stdin_len + 1);
    }

    /* Mode 1: Determinism verification across N independent fresh KVM VMs */
    if (verify_runs > 0) {
        if (!guest_path) {
            fprintf(stderr, "--verify requires a guest ELF path\n");
            return 1;
        }
        cfg.capture_output = true;
        dethv_run_result_t ref;
        memset(&ref, 0, sizeof(ref));
        uint8_t *ref_out = NULL;
        size_t ref_out_len = 0;

        uint64_t t0 = wall_ns();
        for (int i = 0; i < verify_runs; i++) {
            dethv_vm_t *vm = dethv_create(&cfg);
            if (!vm) return 1;
            if (dethv_load_elf(vm, guest_path, guest_argc, guest_argv, NULL) < 0) {
                dethv_destroy(vm);
                return 1;
            }
            if (stdin_data) dethv_set_stdin(vm, stdin_data, stdin_len);

            dethv_run_result_t r;
            dethv_run(vm, &r);

            size_t olen = 0;
            const uint8_t *obuf = dethv_get_stdout(vm, &olen);

            if (i == 0) {
                ref = r;
                ref_out_len = olen;
                ref_out = malloc(olen ? olen : 1);
                if (olen) memcpy(ref_out, obuf, olen);
                if (!quiet && olen > 0) {
                    fwrite(obuf, 1, olen, stdout);
                    fflush(stdout);
                }
            } else {
                bool ok = (r.reason == ref.reason &&
                           r.exit_code == ref.exit_code &&
                           r.state_hash == ref.state_hash &&
                           r.stdout_hash == ref.stdout_hash &&
                           olen == ref_out_len &&
                           (olen == 0 || memcmp(obuf, ref_out, olen) == 0));
                if (!ok) {
                    fprintf(stderr,
                        "[dethv-verify] NON-DETERMINISM DETECTED on run %d/%d!\n"
                        "  ref:   stop=%s exit=%d syscalls=%" PRIu64 " preempts=%" PRIu64 " state=0x%016" PRIx64 " out=0x%016" PRIx64 "\n"
                        "  run%d: stop=%s exit=%d syscalls=%" PRIu64 " preempts=%" PRIu64 " state=0x%016" PRIx64 " out=0x%016" PRIx64 "\n",
                        i + 1, verify_runs,
                        dethv_stop_reason_str(ref.reason), ref.exit_code, ref.syscalls, ref.preempts, ref.state_hash, ref.stdout_hash,
                        i + 1, dethv_stop_reason_str(r.reason), r.exit_code, r.syscalls, r.preempts, r.state_hash, r.stdout_hash);
                    dethv_destroy(vm);
                    free(ref_out);
                    free(stdin_data);
                    return 2;
                }
            }
            dethv_destroy(vm);
        }
        double total_ms = (double)(wall_ns() - t0) / 1e6;
        fprintf(stderr,
            "[dethv-verify] PASS: %d/%d independent KVM runs 100%% BIT-FOR-BIT IDENTICAL! (%.2f ms total, %.2f ms/run)\n",
            verify_runs, verify_runs, total_ms, total_ms / (double)verify_runs);
        print_stats(&ref, total_ms / (double)verify_runs);
        free(ref_out);
        free(stdin_data);
        return 0;
    }

    /* Create primary VM */
    cfg.capture_output = (quiet || bench_snap_iters > 0 || fuzz_iters > 0);
    dethv_vm_t *vm = dethv_create(&cfg);
    if (!vm) return 1;

    dethv_snapshot_t *snap = NULL;

    if (load_snap_path) {
        snap = dethv_snapshot_load_file(load_snap_path);
        if (!snap) {
            fprintf(stderr, "[dethv] Failed to load snapshot '%s'\n", load_snap_path);
            dethv_destroy(vm);
            return 1;
        }
        if (dethv_snapshot_restore(vm, snap) < 0) {
            fprintf(stderr, "[dethv] Failed to restore snapshot '%s'\n", load_snap_path);
            dethv_snapshot_free(snap);
            dethv_destroy(vm);
            return 1;
        }
        if (stdin_data) dethv_set_stdin(vm, stdin_data, stdin_len);
    } else {
        if (dethv_load_elf(vm, guest_path, guest_argc, guest_argv, NULL) < 0) {
            dethv_destroy(vm);
            return 1;
        }
        if (stdin_data) dethv_set_stdin(vm, stdin_data, stdin_len);

        /* Configure snapshot trigger if requested */
        bool want_snap = (snap_sym != NULL || snap_addr != 0 || snap_on_stdin ||
                          save_snap_path != NULL || bench_snap_iters > 0 || fuzz_iters > 0);
        if (snap_sym) {
            uint64_t addr = dethv_lookup_symbol(vm, snap_sym);
            if (!addr) {
                fprintf(stderr, "[dethv] Symbol '%s' not found in ELF!\n", snap_sym);
                dethv_destroy(vm);
                return 1;
            }
            fprintf(stderr, "[dethv] Snapshot trigger set at symbol '%s' (0x%" PRIx64 ")\n", snap_sym, addr);
            dethv_set_snapshot_addr(vm, addr);
        } else if (snap_addr) {
            dethv_set_snapshot_addr(vm, snap_addr);
        } else if (snap_on_stdin || bench_snap_iters > 0 || fuzz_iters > 0) {
            dethv_set_snapshot_on_stdin(vm, true);
        }

        if (want_snap) {
            dethv_run_result_t boot_res;
            uint64_t tb0 = wall_ns();
            dethv_run(vm, &boot_res);
            double boot_ms = (double)(wall_ns() - tb0) / 1e6;
            if (boot_res.reason != DETHV_STOP_SNAPSHOT) {
                fprintf(stderr, "[dethv] Target stopped (%s) before reaching snapshot trigger!\n",
                        dethv_stop_reason_str(boot_res.reason));
                print_stats(&boot_res, boot_ms);
                dethv_destroy(vm);
                return 1;
            }
            snap = dethv_snapshot_take(vm);
            if (!snap) {
                fprintf(stderr, "[dethv] Failed to capture snapshot!\n");
                dethv_destroy(vm);
                return 1;
            }
            fprintf(stderr, "[dethv] Snapshot captured in %.2fms (used_ram=%.2f MiB, rip=0x%" PRIx64 ", syscalls=%" PRIu64 ")\n",
                    boot_ms, (double)snap->phys_used / (1024.0 * 1024.0),
                    vm->shared->regs.rip, boot_res.syscalls);

            if (save_snap_path) {
                if (dethv_snapshot_save_file(snap, save_snap_path) < 0) {
                    fprintf(stderr, "[dethv] Failed to save snapshot to '%s'\n", save_snap_path);
                    dethv_snapshot_free(snap);
                    dethv_destroy(vm);
                    return 1;
                }
                fprintf(stderr, "[dethv] Saved snapshot to '%s'\n", save_snap_path);
            }
        }
    }

    /* Mode 2: Snapshot Reload Benchmark + Determinism Check */
    if (bench_snap_iters > 0 && snap) {
        dethv_run_result_t ref;
        memset(&ref, 0, sizeof(ref));
        uint64_t total_dirty = 0;
        uint64_t t0 = wall_ns();

        for (uint64_t i = 0; i < bench_snap_iters; i++) {
            if (dethv_snapshot_restore(vm, snap) < 0) return 1;
            if (stdin_data) dethv_set_stdin(vm, stdin_data, stdin_len);
            dethv_run_result_t r;
            dethv_run(vm, &r);
            total_dirty += r.dirty_pages;
            if (i == 0) {
                ref = r;
            } else if (r.state_hash != ref.state_hash || r.stdout_hash != ref.stdout_hash) {
                fprintf(stderr, "[dethv-bench] NON-DETERMINISM ON SNAPSHOT RELOAD iter %" PRIu64 "!\n"
                                "  ref: 0x%016" PRIx64 " vs cur: 0x%016" PRIx64 "\n",
                        i, ref.state_hash, r.state_hash);
                dethv_snapshot_free(snap);
                dethv_destroy(vm);
                free(stdin_data);
                return 2;
            }
        }
        double secs = (double)(wall_ns() - t0) / 1e9;
        double rate = secs > 0 ? ((double)bench_snap_iters / secs) : 0.0;
        fprintf(stderr,
            "[dethv-bench] %" PRIu64 " snapshot reload+exec iters in %.3fs -> %.1f exec/s (%.2f us/iter)\n"
            "              100%% DETERMINISTIC (state_hash=0x%016" PRIx64 ", avg_dirty=%.1f pages)\n",
            bench_snap_iters, secs, rate, (secs * 1e6) / (double)bench_snap_iters,
            ref.state_hash, (double)total_dirty / (double)bench_snap_iters);

        dethv_snapshot_free(snap);
        dethv_destroy(vm);
        free(stdin_data);
        return 0;
    }

    /* Mode 3: Snapshot Fuzzer */
    if (fuzz_iters > 0 && snap) {
        int rc = run_snapshot_fuzzer(vm, snap, stdin_data, stdin_len, fuzz_iters, fuzz_seed, fuzz_max_len);
        dethv_snapshot_free(snap);
        dethv_destroy(vm);
        free(stdin_data);
        return rc;
    }

    /* Mode 4: Run to completion (from start or from snapshot) */
    uint64_t t0 = wall_ns();
    dethv_run_result_t res;
    dethv_run(vm, &res);
    double ms = (double)(wall_ns() - t0) / 1e6;

    if (show_stats) print_stats(&res, ms);

    int exit_rc = (res.reason == DETHV_STOP_EXITED) ? res.exit_code : 1;
    if (snap) dethv_snapshot_free(snap);
    dethv_destroy(vm);
    free(stdin_data);
    return exit_rc;
}
