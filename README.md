# DetHV — 100% Deterministic KVM Hypervisor for Snapshot Fuzzing

**DetHV** is a lightweight, single-vCPU x86_64 KVM hypervisor designed to execute **unmodified Linux ELF binaries** (both statically and dynamically linked, including glibc + pthreads) **100% deterministically** with ultra-fast snapshot take/reload for snapshot fuzzing.

## Key Capabilities

- **Runs unmodified Linux x86_64 ELF binaries**: Supports both static (`-static`) and dynamic (`PT_INTERP` / `ld-linux-x86-64.so.2` + `libc.so.6`) binaries directly inside KVM hardware virtualization (Ring-0 guest kernel stub + Ring-3 unmodified user ELF).
- **100% Deterministic Execution** (single vCPU):
  - **Time & TSC**: `CR4.TSD = 1` traps `RDTSC` and `RDTSCP` in Ring 3 and emulates them directly inside Ring 0 (~60 ns, zero VMEXITs) against a deterministic virtual TSC. `CR4.PCE = 0` traps `RDPMC`; `#UD` traps AMD `RDPRU`. No vDSO (`AT_SYSINFO_EHDR` omitted), so `clock_gettime`, `gettimeofday`, `time`, and `nanosleep` route through the deterministic virtual clock (virtual sleeps complete instantaneously without wall-clock waiting).
  - **Randomness & Hardware RNG**: Deterministic `xoshiro256**` PRNG seeded via `--seed` mocks `getrandom(2)`, `/dev/urandom`, `/dev/random`, `/dev/hwrng`, `/proc/sys/kernel/random/uuid`, and `AT_RANDOM`. `RDRAND`/`RDSEED` are masked in `CPUID` **and** automatically scanned & patched in all executable pages (`src/x86_patch.c`, carefully distinguishing `RDSEED` from `RDPID`) so even binaries executing inline `rdrand`/`rdseed` without checking CPUID are 100% deterministically mocked on AMD SVM.
  - **Zero-Skid Deterministic Multithreading**: Full Linux thread support (`clone`, `clone3`, `futex` wait/wake/bitset/requeue/wake_op, TLS `FS_BASE`, per-thread `XSAVE` FPU/SSE/AVX state, `pthread_mutex`, `pthread_cond`, `pthread_barrier`, atomic spinlocks). When multiple threads are runnable, uses AMD hardware `ExRetCond` (`0xD1` Retired Conditional Branches, `USR=1, OS=0`) LAPIC PMI overflow combined with a pure Ring-0 `#DB` single-step landing phase (zero VMEXITs) to preempt at the **exact** deterministic branch count with zero skid. Single-threaded execution pays zero PMU overhead.
  - **Deterministic Memory, Networking, `io_uring`, & VFS**:
    - Fixed non-ASLR memory layout, split KVM memory slots around the 3–4 GiB x86 MMIO/LAPIC hole (supporting multi-GiB guests like Solana Agave with `--ram 4096`), physical page recycling on `munmap`, coherent `MAP_SHARED` file mappings.
    - Deterministic PID/TID (`1000+`), sanitized environment (`--env K=V`) & `uname`, deterministic `stat`/`statx` metadata, isolated in-memory VFS (directories, `getdents64`, `rename`/`unlink`/`truncate`, `/proc/*`, `/sys/*`, `/etc/hosts`, zero writes to host disk and zero host `/proc`/`/sys`/`/dev`/`/tmp` leakage), `CR4.UMIP = 1`.
    - Deterministic virtual networking (`src/net.c`: `AF_INET`/`AF_INET6` UDP & TCP, `AF_UNIX` `socketpair`, `sendmmsg`/`recvmmsg`, `epoll` including edge-triggered `EPOLLET`, `timerfd`, plus host-side virtual peer UDP bridge `dethv_net_set_peer_ip` / `dethv_net_inject_udp` / `dethv_net_pop_tx` and bounded virtual-time stepping `dethv_run_step`) and synchronous deterministic `io_uring` (`src/iouring.c`).
- **Embeddable C Static Library (`build/libdethv.a`)**:
  - Link `build/libdethv.a` against any C/C++/Rust harness or fuzzer (`include/dethv.h`), with host directory VFS import (`dethv_import_host_dir`), guest output streaming callback (`dethv_set_output_cb`), and full network/`io_uring`/pipe `.dhvs` v3 snapshots.
- **Ultra-Fast Snapshot Fuzzing (~46,000–49,000 exec/s on 1 vCPU)**:
  - Uses **x86_64 hardware guest `PTE_D` dirty-bit tracking** + a compact host-VMM dirty-page tracker (`host_dirty_gfns`) + a ~30 ns Ring-0 `CR3` TLB reload instead of expensive KVM NPT write-protect `#NPF` faults.
  - Restores CPU registers via zero-ioctl `KVM_SYNC_X86_REGS`.
  - Supports snapshot triggers by ELF symbol (`--snap-sym`), virtual address (`--snap-addr`), first `read(0, ...)` (`--snap-on-stdin`), or **automatically on the guest's `dethv_get_input()` / `dethv_snapshot()` hypercall** (`--snap-on-hc`, auto-armed by default for `--fuzz` / `--bench-snap` / `--save-snap`).
  - Guest-side hypercall header (`include/dethv_guest.h`) using dedicated x86_64 `syscall` numbers (`0x44455400..0x44455404`, returning `-ENOSYS` safely on native Linux): `dethv_is_present()`, `dethv_get_input(buf, max_len)` (auto-snapshots + injects input), `dethv_snapshot()`, `dethv_done(rc)` (instant iteration exit skipping libc teardown), and `dethv_panic(code, msg, len)` (report harness invariant violations).
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

# Run built-in deterministic snapshot fuzzer (auto-snapshots on dethv_get_input() or read(0))
./build/dethv --fuzz 100000 --fuzz-seed 0x1337 --fuzz-max-len 16 ./build/fuzz_hc_target_dyn

# Auto-snapshot at dethv_get_input(), save to disk, and replay any input in a fresh process
./build/dethv --save-snap hc.dhvs ./build/fuzz_hc_target_dyn
./build/dethv --load-snap hc.dhvs --input-str "DF!B" --stats

# Run an unmodified Solana Agave local_cluster test 100% deterministically (4 GiB RAM)
./build/dethv --ram 4096 --quantum 200000 --env RUST_LOG=info --verify 3 -- \
  ./agave/target/release/deps/local_cluster-* test_local_cluster_start_and_exit --exact --nocapture --test-threads=1

# Build the embeddable DetHV static library (for external harnesses/fuzzers)
make -j build/libdethv.a
```

## Architecture

| File | Responsibility |
| --- | --- |
| `include/dethv.h` | Public C API for embedding DetHV in custom fuzzers |
| `include/dethv_guest.h` | Header-only guest hypercall API (`dethv_get_input`, `dethv_snapshot`, `dethv_done`, `dethv_panic`) |
| `include/guest_shared.h` | Shared Ring-0 <-> VMM trap frame, vTSC, PMU, TLB-flush state |
| `src/guest_stub.S` | Ring-0 guest kernel (`SYSCALL`, fast Ring-0 `RDTSC`/`RDTSCP`, zero-skid PMI + `#DB` landing, `CR3` flush) |
| `src/vmm.c` | KVM VM/vCPU setup, split 3–4 GiB MMIO hole RAM slots, deterministic CPUID, XSAVE, exception handling, run loop |
| `src/mmu.c` | 4-level x86_64 guest page tables, VMA tracking, demand paging, page free-list, `MAP_SHARED` sync, host-dirty tracking |
| `src/x86_patch.c` | O(1) hash-indexed `RDRAND`/`RDSEED` patcher + snapshot & one-shot coverage breakpoints |
| `src/elf_loader.c` | Static & dynamic (`PT_INTERP`) ELF loader, symbol parser, deterministic stack & `auxv` |
| `src/determinism.c` | `xoshiro256**` PRNG, deterministic virtual clock, state hashing |
| `src/scheduler.c` | Single-vCPU deterministic multithreaded scheduler (`clone`/`clone3`, `futex`, `ExRetCond` PMU, I/O blocking) |
| `src/vfs.c` | Virtual FD table, isolated in-memory VFS + directories, `/dev/urandom`, `/proc/*`, `/sys/*`, pipes, eventfd, fast restore |
| `src/net.c` | Deterministic virtual loopback UDP/TCP/Unix sockets, `epoll` (level & `EPOLLET`), `timerfd` |
| `src/iouring.c` | Deterministic synchronous virtual `io_uring` (`setup`/`enter`/`register` + ring `mmap`) |
| `src/syscall.c` | x86_64 Linux syscall emulation |
| `src/snapshot.c` | Zero-VMEXIT `PTE_D` snapshot take/restore + `.dhvs` disk serialization |
| `src/main.c` | CLI runner, determinism verifier, snapshot benchmark, built-in snapshot fuzzer |
| `tests/nondet_torture.c` | Comprehensive multithreaded + RNG + clock + ASLR non-determinism torture test |
| `tests/fuzz_target.c` | Unmodified Linux C binary with multi-stage crashes (`SIGFPE`, `SIGSEGV`, `SIGABRT`) |
