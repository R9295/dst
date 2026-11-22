# DetHV — 100% Deterministic KVM Hypervisor for Snapshot Fuzzing

**DetHV** is a lightweight, single-vCPU x86_64 KVM hypervisor designed to execute **unmodified Linux ELF binaries** (both statically and dynamically linked, including glibc + pthreads) **100% deterministically** with ultra-fast snapshot take/reload for snapshot fuzzing.

## Key Capabilities

- **Runs unmodified Linux x86_64 ELF binaries**: Supports both static (`-static`) and dynamic (`PT_INTERP` / `ld-linux-x86-64.so.2` + `libc.so.6`) binaries directly inside KVM hardware virtualization (Ring-0 guest kernel stub + Ring-3 unmodified user ELF).
- **100% Deterministic Execution** (single vCPU):
  - **Time & TSC**: `CR4.TSD = 1` traps `RDTSC` and `RDTSCP` in Ring 3 and emulates them directly inside Ring 0 (~60 ns, zero VMEXITs) against a deterministic virtual TSC. `CR4.PCE = 0` traps `RDPMC`; `#UD` traps AMD `RDPRU`. No vDSO (`AT_SYSINFO_EHDR` omitted), so `clock_gettime`, `gettimeofday`, `time`, and `nanosleep` route through the deterministic virtual clock (virtual sleeps complete instantaneously without wall-clock waiting).
  - **Randomness & Hardware RNG**: Deterministic `xoshiro256**` PRNG seeded via `--seed` mocks `getrandom(2)`, `/dev/urandom`, `/dev/random`, `/dev/hwrng`, `/proc/sys/kernel/random/uuid`, and `AT_RANDOM`. `RDRAND`/`RDSEED` are masked in `CPUID` **and** automatically scanned & patched in all executable pages (`src/x86_patch.c`, carefully distinguishing `RDSEED` from `RDPID`) so even binaries executing inline `rdrand`/`rdseed` without checking CPUID are 100% deterministically mocked on AMD SVM.
  - **Zero-Skid Deterministic Multithreading**: Full Linux thread support (`clone`, `clone3`, `futex` wait/wake/bitset/requeue/wake_op, TLS `FS_BASE`, per-thread `XSAVE` FPU/SSE/AVX state, `pthread_mutex`, `pthread_cond`, `pthread_barrier`, atomic spinlocks). When multiple threads are runnable, uses AMD hardware `ExRetCond` (`0xD1` Retired Conditional Branches, `USR=1, OS=0`) LAPIC PMI overflow combined with a pure Ring-0 `#DB` single-step landing phase (zero VMEXITs) to preempt at the **exact** deterministic branch count with zero skid. Single-threaded execution pays zero PMU overhead.
  - **Deterministic Memory & OS State**: Fixed non-ASLR memory layout, deterministic PID/TID (`1000+`), sanitized environment & `uname`, deterministic `stat`/`statx` metadata, copy-on-write in-memory virtual filesystem (guest writes never touch host disk and roll back cleanly on snapshot reload), `CR4.UMIP = 1` traps `SGDT`/`SIDT`/`SLDT`/`SMSW`/`STR`.
- **Ultra-Fast Snapshot Fuzzing (~48,000–50,000 exec/s on 1 vCPU)**:
  - Uses **x86_64 hardware guest `PTE_D` dirty-bit tracking** + a compact host-VMM dirty-page tracker (`host_dirty_gfns`) + a ~30 ns Ring-0 `CR3` TLB reload instead of expensive KVM NPT write-protect `#NPF` faults.
  - Restores CPU registers via zero-ioctl `KVM_SYNC_X86_REGS`.
  - Supports snapshot triggers by ELF symbol (`--snap-sym`), virtual address (`--snap-addr`), or automatically right before the first `read(0, ...)` (`--snap-on-stdin`).
  - Supports **persistent disk snapshots** (`--save-snap` / `--load-snap` `.dhvs` files) that reload bit-for-bit deterministically in fresh OS processes.
  - Built-in deterministic snapshot fuzzer (`--fuzz`) with one-shot ELF symbol breakpoint coverage and automatic crash reproducibility verification.

## Build & Test

```bash
make -j
make test
```

## CLI Usage

```bash
# Run an unmodified binary deterministically with stats
./build/dethv --stats ./build/nondet_torture_dyn

# Verify 100% bit-for-bit determinism across 10 fresh KVM VMs
./build/dethv --verify 10 ./build/nondet_torture_dyn

# Capture a snapshot at symbol 'main' and save to disk
./build/dethv --snap-sym main --save-snap snap.dhvs ./build/nondet_torture_dyn

# Reload from saved disk snapshot in a fresh process
./build/dethv --load-snap snap.dhvs

# Benchmark 50,000 snapshot reloads + executions
./build/dethv --snap-on-stdin --stdin-str "HELLO_WORLD" --bench-snap 50000 ./build/fuzz_target_dyn

# Run built-in deterministic snapshot fuzzer (100k iterations)
./build/dethv --snap-on-stdin --fuzz 100000 --fuzz-seed 0x1337 --fuzz-max-len 16 ./build/fuzz_target_dyn
```

## Architecture

| File | Responsibility |
| --- | --- |
| `include/dethv.h` | Public C API for embedding DetHV in custom fuzzers |
| `include/guest_shared.h` | Shared Ring-0 <-> VMM trap frame, vTSC, PMU, TLB-flush state |
| `src/guest_stub.S` | Ring-0 guest kernel (`SYSCALL`, fast Ring-0 `RDTSC`/`RDTSCP`, zero-skid PMI + `#DB` landing, `CR3` flush) |
| `src/vmm.c` | KVM VM/vCPU setup, deterministic CPUID, XSAVE, exception handling, run loop |
| `src/mmu.c` | 4-level x86_64 guest page tables, VMA tracking, demand paging, host-dirty tracking |
| `src/x86_patch.c` | Executable-page `RDRAND`/`RDSEED` patcher + snapshot & one-shot coverage breakpoints |
| `src/elf_loader.c` | Static & dynamic (`PT_INTERP`) ELF loader, symbol parser, deterministic stack & `auxv` |
| `src/determinism.c` | `xoshiro256**` PRNG, deterministic virtual clock, state hashing |
| `src/scheduler.c` | Single-vCPU deterministic multithreaded scheduler (`clone`/`clone3`, `futex`, `ExRetCond` PMU) |
| `src/vfs.c` | Virtual FD table, `/dev/urandom`, `/proc/*`, pipes, eventfd, COW virtual files, fast restore |
| `src/syscall.c` | x86_64 Linux syscall emulation |
| `src/snapshot.c` | Zero-VMEXIT `PTE_D` snapshot take/restore + `.dhvs` disk serialization |
| `src/main.c` | CLI runner, determinism verifier, snapshot benchmark, built-in snapshot fuzzer |
| `tests/nondet_torture.c` | Comprehensive multithreaded + RNG + clock + ASLR non-determinism torture test |
| `tests/fuzz_target.c` | Unmodified Linux C binary with multi-stage crashes (`SIGFPE`, `SIGSEGV`, `SIGABRT`) |
