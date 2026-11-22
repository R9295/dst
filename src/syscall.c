#include "internal.h"
#include "syscalls.h"
#include <asm/prctl.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/sched.h>
#include <linux/stat.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static void fill_statx_from_stat(struct statx *sx, const struct stat *st) {
    memset(sx, 0, sizeof(*sx));
    sx->stx_mask            = STATX_BASIC_STATS;
    sx->stx_blksize         = (uint32_t)st->st_blksize;
    sx->stx_nlink           = (uint32_t)st->st_nlink;
    sx->stx_uid             = st->st_uid;
    sx->stx_gid             = st->st_gid;
    sx->stx_mode            = (uint16_t)st->st_mode;
    sx->stx_ino             = st->st_ino;
    sx->stx_size            = (uint64_t)st->st_size;
    sx->stx_blocks          = (uint64_t)st->st_blocks;
    sx->stx_atime.tv_sec    = st->st_atim.tv_sec;
    sx->stx_ctime.tv_sec    = st->st_ctim.tv_sec;
    sx->stx_mtime.tv_sec    = st->st_mtim.tv_sec;
    sx->stx_btime.tv_sec    = st->st_ctim.tv_sec;
    sx->stx_dev_major       = 0;
    sx->stx_dev_minor       = 1;
}

void dethv_handle_syscall(dethv_vm_t *vm) {
    user_regs_t *r = &vm->shared->regs;
    uint64_t nr = r->rax;
    uint64_t a1 = r->rdi;
    uint64_t a2 = r->rsi;
    uint64_t a3 = r->rdx;
    uint64_t a4 = r->r10;
    uint64_t a5 = r->r8;
    uint64_t a6 = r->r9;

    /* Snapshot trigger before first stdin read (re-executes this syscall after snapshot restore!) */
    if (vm->snap_on_stdin_armed && nr == LINUX_SYS_read && (int)a1 == 0) {
        vm->snap_on_stdin_armed = false;
        /* Rewind RIP back 2 bytes (size of `syscall` opcode 0F 05) so snapshot resumes AT read(0,...)! */
        r->rip -= 2;
        vm->running = false;
        vm->stop_reason = DETHV_STOP_SNAPSHOT;
        return;
    }

    /* Snapshot trigger before opening a matching path */
    if (vm->snap_on_open_armed &&
        (nr == LINUX_SYS_open || nr == LINUX_SYS_openat || nr == LINUX_SYS_openat2)) {
        char pbuf[256] = {0};
        uint64_t path_ptr = (nr == LINUX_SYS_open) ? a1 : a2;
        if (mmu_read_cstring(vm, path_ptr, pbuf, sizeof(pbuf)) >= 0 &&
            strstr(pbuf, vm->snap_on_open_substr) != NULL) {
            vm->snap_on_open_armed = false;
            r->rip -= 2;
            vm->running = false;
            vm->stop_reason = DETHV_STOP_SNAPSHOT;
            return;
        }
    }

    vm->det.syscall_count++;
    det_advance_time(&vm->det, 1000); /* +1 us deterministic virtual time per syscall */
    vm->shared->vtsc += DETHV_VTSC_STEP_SYSCALL;

    if (vm->cfg.max_syscalls && vm->det.syscall_count >= vm->cfg.max_syscalls) {
        vm->running = false;
        vm->stop_reason = DETHV_STOP_TIMEOUT;
        return;
    }

    int64_t ret = -ENOSYS;
    bool switched = false;

    switch (nr) {
        /* ==================== I/O & Filesystem ==================== */
        case LINUX_SYS_read: {
            int fd = (int)a1;
            size_t count = (size_t)a3;
            if (count == 0) { ret = 0; break; }
            if (count > 16 * 1024 * 1024) count = 16 * 1024 * 1024;
            uint8_t sbuf[4096];
            uint8_t *tmp = (count <= sizeof(sbuf)) ? sbuf : malloc(count);
            if (!tmp) { ret = -ENOMEM; break; }
            ret = vfs_read(vm, fd, tmp, count);
            if (ret > 0) {
                if (mmu_copy_to_guest(vm, a2, tmp, (size_t)ret) < 0) ret = -EFAULT;
            }
            if (tmp != sbuf) free(tmp);
            break;
        }

        case LINUX_SYS_pread64: {
            int fd = (int)a1;
            size_t count = (size_t)a3;
            int64_t off = (int64_t)a4;
            if (count == 0) { ret = 0; break; }
            if (count > 16 * 1024 * 1024) count = 16 * 1024 * 1024;
            uint8_t sbuf[4096];
            uint8_t *tmp = (count <= sizeof(sbuf)) ? sbuf : malloc(count);
            if (!tmp) { ret = -ENOMEM; break; }
            ret = vfs_pread(vm, fd, tmp, count, off);
            if (ret > 0) {
                if (mmu_copy_to_guest(vm, a2, tmp, (size_t)ret) < 0) ret = -EFAULT;
            }
            if (tmp != sbuf) free(tmp);
            break;
        }

        case LINUX_SYS_write: {
            int fd = (int)a1;
            size_t count = (size_t)a3;
            if (count == 0) { ret = 0; break; }
            if (count > 16 * 1024 * 1024) count = 16 * 1024 * 1024;
            uint8_t sbuf[4096];
            uint8_t *tmp = (count <= sizeof(sbuf)) ? sbuf : malloc(count);
            if (!tmp) { ret = -ENOMEM; break; }
            if (mmu_copy_from_guest(vm, tmp, a2, count) < 0) {
                ret = -EFAULT;
            } else {
                ret = vfs_write(vm, fd, tmp, count);
            }
            if (tmp != sbuf) free(tmp);
            break;
        }

        case LINUX_SYS_writev: {
            int fd = (int)a1;
            int iovcnt = (int)a3;
            if (iovcnt < 0 || iovcnt > 1024) { ret = -EINVAL; break; }
            int64_t total = 0;
            for (int i = 0; i < iovcnt; i++) {
                struct iovec iov;
                if (mmu_copy_from_guest(vm, &iov, a2 + (uint64_t)i * sizeof(iov), sizeof(iov)) < 0) {
                    total = -EFAULT;
                    break;
                }
                if (iov.iov_len == 0) continue;
                uint8_t *tmp = malloc(iov.iov_len);
                if (!tmp) { total = -ENOMEM; break; }
                if (mmu_copy_from_guest(vm, tmp, (uint64_t)iov.iov_base, iov.iov_len) < 0) {
                    free(tmp);
                    total = -EFAULT;
                    break;
                }
                int64_t w = vfs_write(vm, fd, tmp, iov.iov_len);
                free(tmp);
                if (w < 0) { total = w; break; }
                total += w;
            }
            ret = total;
            break;
        }

        case LINUX_SYS_readv: {
            int fd = (int)a1;
            int iovcnt = (int)a3;
            if (iovcnt < 0 || iovcnt > 1024) { ret = -EINVAL; break; }
            int64_t total = 0;
            for (int i = 0; i < iovcnt; i++) {
                struct iovec iov;
                if (mmu_copy_from_guest(vm, &iov, a2 + (uint64_t)i * sizeof(iov), sizeof(iov)) < 0) {
                    total = -EFAULT;
                    break;
                }
                if (iov.iov_len == 0) continue;
                uint8_t *tmp = malloc(iov.iov_len);
                if (!tmp) { total = -ENOMEM; break; }
                int64_t n = vfs_read(vm, fd, tmp, iov.iov_len);
                if (n > 0) {
                    if (mmu_copy_to_guest(vm, (uint64_t)iov.iov_base, tmp, (size_t)n) < 0) {
                        free(tmp);
                        total = -EFAULT;
                        break;
                    }
                    total += n;
                }
                free(tmp);
                if (n < 0) { if (total == 0) total = n; break; }
                if ((size_t)n < iov.iov_len) break;
            }
            ret = total;
            break;
        }

        case LINUX_SYS_open: {
            char path[256];
            if (mmu_read_cstring(vm, a1, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_openat(vm, AT_FDCWD, path, (int)a2, (uint32_t)a3);
            break;
        }

        case LINUX_SYS_openat: {
            char path[256];
            if (mmu_read_cstring(vm, a2, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_openat(vm, (int)a1, path, (int)a3, (uint32_t)a4);
            break;
        }

        case LINUX_SYS_openat2: {
            char path[256];
            struct { uint64_t flags, mode, resolve; } how;
            if (mmu_read_cstring(vm, a2, path, sizeof(path)) < 0 ||
                mmu_copy_from_guest(vm, &how, a3, sizeof(how)) < 0) {
                ret = -EFAULT;
                break;
            }
            ret = vfs_openat(vm, (int)a1, path, (int)how.flags, (uint32_t)how.mode);
            break;
        }

        case LINUX_SYS_close:
            ret = vfs_close(vm, (int)a1);
            break;

        case LINUX_SYS_close_range: {
            unsigned int first = (unsigned int)a1, last = (unsigned int)a2;
            if (last >= DETHV_MAX_FDS) last = DETHV_MAX_FDS - 1;
            for (unsigned int i = first; i <= last; i++) {
                if (vm->vfs.fds[i].used) vfs_close(vm, (int)i);
            }
            ret = 0;
            break;
        }

        case LINUX_SYS_lseek:
            ret = vfs_lseek(vm, (int)a1, (int64_t)a2, (int)a3);
            break;

        case LINUX_SYS_fstat: {
            struct stat st;
            ret = vfs_fstat(vm, (int)a1, &st);
            if (ret == 0 && mmu_copy_to_guest(vm, a2, &st, sizeof(st)) < 0) ret = -EFAULT;
            break;
        }

        case LINUX_SYS_stat:
        case LINUX_SYS_lstat: {
            char path[256];
            struct stat st;
            if (mmu_read_cstring(vm, a1, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_stat_path(vm, AT_FDCWD, path, &st, (nr == LINUX_SYS_lstat) ? AT_SYMLINK_NOFOLLOW : 0);
            if (ret == 0 && mmu_copy_to_guest(vm, a2, &st, sizeof(st)) < 0) ret = -EFAULT;
            break;
        }

        case LINUX_SYS_newfstatat: {
            char path[256];
            struct stat st;
            if (mmu_read_cstring(vm, a2, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_stat_path(vm, (int)a1, path, &st, (int)a4);
            if (ret == 0 && mmu_copy_to_guest(vm, a3, &st, sizeof(st)) < 0) ret = -EFAULT;
            break;
        }

        case LINUX_SYS_statx: {
            char path[256];
            struct stat st;
            struct statx sx;
            if (mmu_read_cstring(vm, a2, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_stat_path(vm, (int)a1, path, &st, (int)a3);
            if (ret == 0) {
                fill_statx_from_stat(&sx, &st);
                if (mmu_copy_to_guest(vm, a5, &sx, sizeof(sx)) < 0) ret = -EFAULT;
            }
            break;
        }

        case LINUX_SYS_access:
        case LINUX_SYS_faccessat:
        case LINUX_SYS_faccessat2: {
            char path[256];
            struct stat st;
            int dirfd = (nr == LINUX_SYS_access) ? AT_FDCWD : (int)a1;
            uint64_t pptr = (nr == LINUX_SYS_access) ? a1 : a2;
            if (mmu_read_cstring(vm, pptr, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = (vfs_stat_path(vm, dirfd, path, &st, 0) == 0) ? 0 : -ENOENT;
            break;
        }

        case LINUX_SYS_readlink:
        case LINUX_SYS_readlinkat: {
            char path[256];
            uint64_t pptr = (nr == LINUX_SYS_readlink) ? a1 : a2;
            uint64_t buf  = (nr == LINUX_SYS_readlink) ? a2 : a3;
            size_t bufsz  = (nr == LINUX_SYS_readlink) ? (size_t)a3 : (size_t)a4;
            if (mmu_read_cstring(vm, pptr, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            if (strcmp(path, "/proc/self/exe") == 0) {
                size_t n = strlen(vm->vfs.exe_path);
                if (n > bufsz) n = bufsz;
                if (mmu_copy_to_guest(vm, buf, vm->vfs.exe_path, n) < 0) ret = -EFAULT;
                else ret = (int64_t)n;
            } else {
                ret = -EINVAL;
            }
            break;
        }

        case LINUX_SYS_getcwd: {
            size_t len = strlen(vm->vfs.cwd) + 1;
            if (len > (size_t)a2) { ret = -ERANGE; break; }
            if (mmu_copy_to_guest(vm, a1, vm->vfs.cwd, len) < 0) ret = -EFAULT;
            else ret = (int64_t)len;
            break;
        }

        case LINUX_SYS_chdir: {
            char path[256];
            if (mmu_read_cstring(vm, a1, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            snprintf(vm->vfs.cwd, sizeof(vm->vfs.cwd), "%s", path);
            vm->vfs.cwd_dirty = true;
            ret = 0;
            break;
        }

        case LINUX_SYS_dup:
            ret = vfs_dup(vm, (int)a1, 0, 0, false);
            break;
        case LINUX_SYS_dup2:
            ret = vfs_dup(vm, (int)a1, (int)a2, 0, true);
            break;
        case LINUX_SYS_dup3:
            ret = vfs_dup(vm, (int)a1, (int)a2, (int)a3, true);
            break;

        case LINUX_SYS_pipe:
        case LINUX_SYS_pipe2: {
            int fds[2];
            int fl = (nr == LINUX_SYS_pipe2) ? (int)a2 : 0;
            ret = vfs_pipe(vm, fds, fl);
            if (ret == 0 && mmu_copy_to_guest(vm, a1, fds, sizeof(fds)) < 0) ret = -EFAULT;
            break;
        }

        case LINUX_SYS_eventfd:
        case LINUX_SYS_eventfd2:
            ret = vfs_eventfd(vm, a1, (nr == LINUX_SYS_eventfd2) ? (int)a2 : 0);
            break;

        case LINUX_SYS_fcntl: {
            int fd = (int)a1, cmd = (int)a2;
            if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used) { ret = -EBADF; break; }
            vfd_t *f = &vm->vfs.fds[fd];
            if (cmd == F_DUPFD) ret = vfs_dup(vm, fd, (int)a3, 0, false);
            else if (cmd == F_DUPFD_CLOEXEC) ret = vfs_dup(vm, fd, (int)a3, O_CLOEXEC, false);
            else if (cmd == F_GETFD) ret = (f->flags & O_CLOEXEC) ? FD_CLOEXEC : 0;
            else if (cmd == F_SETFD) { if (a3 & FD_CLOEXEC) f->flags |= O_CLOEXEC; else f->flags &= ~O_CLOEXEC; ret = 0; }
            else if (cmd == F_GETFL) ret = f->flags;
            else if (cmd == F_SETFL) { f->flags = (f->flags & O_ACCMODE) | ((int)a3 & ~O_ACCMODE); ret = 0; }
            else ret = 0;
            break;
        }

        case LINUX_SYS_ioctl:
            /* Deterministic non-TTY behavior (prevents glibc stdout buffering surprises) */
            ret = -ENOTTY;
            break;

        case LINUX_SYS_unlink:
        case LINUX_SYS_unlinkat:
        case LINUX_SYS_mkdir:
        case LINUX_SYS_mkdirat:
        case LINUX_SYS_fsync:
        case LINUX_SYS_fdatasync:
        case LINUX_SYS_fadvise64:
        case LINUX_SYS_flock:
            ret = 0;
            break;

        case LINUX_SYS_umask:
            ret = vm->vfs.umask_val;
            vm->vfs.umask_val = (uint32_t)(a1 & 0777);
            vm->vfs.cwd_dirty = true;
            break;

        case LINUX_SYS_poll:
        case LINUX_SYS_ppoll: {
            /* Deterministic poll: check immediate readiness for pipes/stdin/stdout */
            nfds_t nfds = (nfds_t)a2;
            int ready = 0;
            for (nfds_t i = 0; i < nfds && i < 64; i++) {
                struct pollfd pfd;
                if (mmu_copy_from_guest(vm, &pfd, a1 + i * sizeof(pfd), sizeof(pfd)) < 0) {
                    ret = -EFAULT;
                    goto done_syscall;
                }
                pfd.revents = 0;
                if (pfd.fd >= 0 && pfd.fd < DETHV_MAX_FDS && vm->vfs.fds[pfd.fd].used) {
                    vfd_t *f = &vm->vfs.fds[pfd.fd];
                    if ((pfd.events & POLLIN) &&
                        (f->kind == FD_STDIN || f->kind == FD_DEV_URANDOM || f->kind == FD_DEV_ZERO ||
                         f->kind == FD_MEM_VFILE || f->kind == FD_HOST_RO ||
                         (f->kind == FD_PIPE_READ && (vm->vfs.pipes[f->ref_idx].count > 0 || vm->vfs.pipes[f->ref_idx].write_closed))))
                        pfd.revents |= POLLIN;
                    if ((pfd.events & POLLOUT) &&
                        (f->kind == FD_STDOUT || f->kind == FD_STDERR || f->kind == FD_DEV_NULL ||
                         f->kind == FD_MEM_VFILE ||
                         (f->kind == FD_PIPE_WRITE && vm->vfs.pipes[f->ref_idx].count < DETHV_PIPE_BUF_SIZE)))
                        pfd.revents |= POLLOUT;
                }
                if (pfd.revents) ready++;
                mmu_copy_to_guest(vm, a1 + i * sizeof(pfd), &pfd, sizeof(pfd));
            }
            ret = ready;
            break;
        }

        /* ==================== Memory Management ==================== */
        case LINUX_SYS_brk:
            ret = (int64_t)mmu_brk(vm, a1);
            break;

        case LINUX_SYS_mmap: {
            uint64_t addr = a1;
            size_t   len  = (size_t)a2;
            uint32_t prot = (uint32_t)a3;
            uint32_t flags = (uint32_t)a4;
            int      fd   = (int)a5;
            int64_t  off  = (int64_t)a6;

            bool is_anon = (flags & MAP_ANONYMOUS) != 0;
            /* Populate file-backed mappings immediately; demand-page anonymous mappings! */
            uint64_t mapped = mmu_mmap_region(vm, addr, len, prot, flags, !is_anon);
            if ((int64_t)mapped < 0) {
                ret = (int64_t)mapped;
                break;
            }
            if (!is_anon && fd >= 0) {
                /* Copy file bytes into mapped guest memory! */
                size_t aligned_len = PAGE_ALIGN_UP(len);
                uint8_t *tmp = calloc(1, aligned_len);
                if (!tmp) { ret = -ENOMEM; break; }
                int64_t nr_read = vfs_pread(vm, fd, tmp, len, off);
                if (nr_read > 0) {
                    mmu_copy_to_guest(vm, mapped, tmp, (size_t)nr_read);
                }
                free(tmp);
                /* If executable file mapping (e.g. libc.so.6!), scan & patch RDRAND/RDSEED! */
                if ((prot & PROT_EXEC) && vm->cfg.patch_rdrand) {
                    x86_scan_and_patch_range(vm, mapped, len);
                }
            }
            ret = (int64_t)mapped;
            break;
        }

        case LINUX_SYS_munmap:
            ret = mmu_munmap_region(vm, a1, (size_t)a2);
            break;

        case LINUX_SYS_mprotect:
            ret = mmu_mprotect_region(vm, a1, (size_t)a2, (uint32_t)a3);
            break;

        case LINUX_SYS_mremap: {
            uint64_t old_addr = a1;
            size_t   old_size = (size_t)a2;
            size_t   new_size = (size_t)a3;
            uint32_t flags    = (uint32_t)a4;
            if (new_size <= old_size) {
                ret = (int64_t)old_addr;
                break;
            }
            if (!(flags & MREMAP_MAYMOVE)) {
                ret = -ENOMEM;
                break;
            }
            uint64_t naddr = mmu_mmap_region(vm, 0, new_size, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS, false);
            if ((int64_t)naddr < 0) { ret = (int64_t)naddr; break; }
            /* Copy existing mapped pages */
            uint8_t pbuf[PAGE_SIZE];
            for (size_t off = 0; off < old_size; off += PAGE_SIZE) {
                if (mmu_virt_to_phys(vm, old_addr + off, NULL) != 0) {
                    mmu_copy_from_guest(vm, pbuf, old_addr + off, PAGE_SIZE);
                    mmu_copy_to_guest(vm, naddr + off, pbuf, PAGE_SIZE);
                }
            }
            mmu_munmap_region(vm, old_addr, old_size);
            ret = (int64_t)naddr;
            break;
        }

        case LINUX_SYS_madvise: {
            if ((int)a3 == MADV_DONTNEED) {
                /* glibc malloc & pthread stacks rely on MADV_DONTNEED zeroing anonymous pages! */
                uint64_t start = PAGE_ALIGN_DOWN(a1);
                uint64_t end   = PAGE_ALIGN_UP(a1 + a2);
                for (uint64_t va = start; va < end; va += PAGE_SIZE) {
                    uint64_t pa = mmu_virt_to_phys(vm, va, NULL);
                    if (pa != 0) {
                        vmm_mark_phys_dirty(vm, pa);
                        memset(vm->mem + (pa & PAGE_MASK), 0, PAGE_SIZE);
                    }
                }
            }
            ret = 0;
            break;
        }

        case LINUX_SYS_mlock:
        case LINUX_SYS_munlock:
        case LINUX_SYS_msync:
        case LINUX_SYS_membarrier:
            ret = 0;
            break;

        /* ==================== Deterministic Randomness ==================== */
        case LINUX_SYS_getrandom: {
            size_t buflen = (size_t)a2;
            if (buflen > 1024 * 1024) buflen = 1024 * 1024;
            uint8_t *tmp = malloc(buflen ? buflen : 1);
            if (!tmp) { ret = -ENOMEM; break; }
            det_rand_bytes(&vm->det, tmp, buflen);
            vm->det.getrandom_count++;
            if (buflen > 0 && mmu_copy_to_guest(vm, a1, tmp, buflen) < 0)
                ret = -EFAULT;
            else
                ret = (int64_t)buflen;
            free(tmp);
            break;
        }

        /* ==================== Deterministic Time & Clocks ==================== */
        case LINUX_SYS_clock_gettime: {
            int clk = (int)a1;
            uint64_t ns = (clk == CLOCK_REALTIME || clk == CLOCK_REALTIME_COARSE)
                          ? vm->det.vtime_ns : vm->det.vmono_ns;
            det_advance_time(&vm->det, 100); /* Monotonically advancing by deterministic 100ns */
            struct timespec ts = {
                .tv_sec  = (time_t)(ns / 1000000000ULL),
                .tv_nsec = (long)(ns % 1000000000ULL)
            };
            ret = (mmu_copy_to_guest(vm, a2, &ts, sizeof(ts)) == 0) ? 0 : -EFAULT;
            break;
        }

        case LINUX_SYS_clock_getres: {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 1 };
            if (a2) ret = (mmu_copy_to_guest(vm, a2, &ts, sizeof(ts)) == 0) ? 0 : -EFAULT;
            else ret = 0;
            break;
        }

        case LINUX_SYS_gettimeofday: {
            uint64_t ns = vm->det.vtime_ns;
            det_advance_time(&vm->det, 100);
            if (a1) {
                struct timeval tv = {
                    .tv_sec  = (time_t)(ns / 1000000000ULL),
                    .tv_usec = (suseconds_t)((ns % 1000000000ULL) / 1000ULL)
                };
                if (mmu_copy_to_guest(vm, a1, &tv, sizeof(tv)) < 0) { ret = -EFAULT; break; }
            }
            if (a2) {
                struct timezone tz = { 0, 0 };
                if (mmu_copy_to_guest(vm, a2, &tz, sizeof(tz)) < 0) { ret = -EFAULT; break; }
            }
            ret = 0;
            break;
        }

        case LINUX_SYS_time: {
            time_t sec = (time_t)(vm->det.vtime_ns / 1000000000ULL);
            det_advance_time(&vm->det, 100);
            if (a1 && mmu_copy_to_guest(vm, a1, &sec, sizeof(sec)) < 0) { ret = -EFAULT; break; }
            ret = (int64_t)sec;
            break;
        }

        case LINUX_SYS_nanosleep:
        case LINUX_SYS_clock_nanosleep: {
            uint64_t req_ptr = (nr == LINUX_SYS_nanosleep) ? a1 : a3;
            int flags        = (nr == LINUX_SYS_clock_nanosleep) ? (int)a2 : 0;
            struct timespec req;
            if (mmu_copy_from_guest(vm, &req, req_ptr, sizeof(req)) < 0) { ret = -EFAULT; break; }
            if (req.tv_sec < 0 || req.tv_nsec < 0 || req.tv_nsec >= 1000000000L) { ret = -EINVAL; break; }
            uint64_t req_ns = (uint64_t)req.tv_sec * 1000000000ULL + (uint64_t)req.tv_nsec;
            uint64_t wake_ns;
            if (flags & TIMER_ABSTIME) {
                int clk = (int)a1;
                if (clk == CLOCK_REALTIME) {
                    wake_ns = (req_ns > vm->det.vtime_ns)
                              ? (vm->det.vmono_ns + (req_ns - vm->det.vtime_ns))
                              : vm->det.vmono_ns;
                } else {
                    wake_ns = req_ns;
                }
            } else {
                wake_ns = vm->det.vmono_ns + req_ns;
            }
            /* Cooperative virtual sleep: lets other runnable threads run, or fast-forwards instantly! */
            sched_sleep_current(vm, wake_ns);
            switched = true;
            break;
        }

        case LINUX_SYS_times: {
            struct tms t;
            memset(&t, 0, sizeof(t));
            t.tms_utime = (clock_t)(vm->det.vmono_ns / 10000000ULL);
            if (a1 && mmu_copy_to_guest(vm, a1, &t, sizeof(t)) < 0) { ret = -EFAULT; break; }
            ret = (int64_t)t.tms_utime;
            break;
        }

        case LINUX_SYS_getrusage: {
            struct rusage ru;
            memset(&ru, 0, sizeof(ru));
            ru.ru_utime.tv_sec  = (time_t)(vm->det.vmono_ns / 1000000000ULL);
            ru.ru_utime.tv_usec = (suseconds_t)((vm->det.vmono_ns % 1000000000ULL) / 1000ULL);
            ru.ru_maxrss        = (long)(vm->mmu.next_phys / 1024);
            ret = (mmu_copy_to_guest(vm, a2, &ru, sizeof(ru)) == 0) ? 0 : -EFAULT;
            break;
        }

        case LINUX_SYS_getcpu: {
            uint32_t cpu = 0, node = 0;
            if (a1 && mmu_copy_to_guest(vm, a1, &cpu, sizeof(cpu)) < 0) { ret = -EFAULT; break; }
            if (a2 && mmu_copy_to_guest(vm, a2, &node, sizeof(node)) < 0) { ret = -EFAULT; break; }
            ret = 0;
            break;
        }

        /* ==================== Multithreading & Synchronization ==================== */
        case LINUX_SYS_arch_prctl: {
            int code = (int)a1;
            if (code == ARCH_SET_FS) {
                vm->current_fs_base = a2;
                vm->fs_base_dirty = true;
                vm->sregs_changed_since_snap = true;
                vm->sched.threads[vm->sched.current_idx].fs_base = a2;
                ret = 0;
            } else if (code == ARCH_GET_FS) {
                ret = (mmu_copy_to_guest(vm, a2, &vm->current_fs_base, 8) == 0) ? 0 : -EFAULT;
            } else if (code == ARCH_SET_GS) {
                vm->sched.threads[vm->sched.current_idx].gs_base = a2;
                ret = 0;
            } else {
                ret = -EINVAL; /* e.g., ARCH_CET_STATUS -> not enabled */
            }
            break;
        }

        case LINUX_SYS_set_tid_address: {
            guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];
            cur->clear_child_tid = a1;
            ret = cur->tid;
            break;
        }

        case LINUX_SYS_set_robust_list: {
            guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];
            cur->robust_list_head = a1;
            cur->robust_list_len  = a2;
            ret = 0;
            break;
        }

        case LINUX_SYS_get_robust_list: {
            guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];
            if (a2) mmu_copy_to_guest(vm, a2, &cur->robust_list_head, 8);
            if (a3) mmu_copy_to_guest(vm, a3, &cur->robust_list_len, 8);
            ret = 0;
            break;
        }

        case LINUX_SYS_rseq:
            ret = -ENOSYS; /* Standard: glibc cleanly disables rseq on ENOSYS */
            break;

        case LINUX_SYS_clone: {
            /* x86_64 clone(flags, stack, ptid, ctid, tls) */
            ret = sched_create_thread(vm, a1, a2, a3, a4, a5);
            break;
        }

        case LINUX_SYS_clone3: {
            struct clone_args cl;
            memset(&cl, 0, sizeof(cl));
            size_t csz = (size_t)a2;
            if (csz > sizeof(cl)) csz = sizeof(cl);
            if (mmu_copy_from_guest(vm, &cl, a1, csz) < 0) { ret = -EFAULT; break; }
            uint64_t stack_top = cl.stack ? (cl.stack + cl.stack_size) : 0;
            ret = sched_create_thread(vm, cl.flags, stack_top, cl.parent_tid, cl.child_tid, cl.tls);
            break;
        }

        case LINUX_SYS_futex: {
            uint64_t uaddr = a1;
            int      op    = (int)a2 & ~FUTEX_PRIVATE_FLAG & ~FUTEX_CLOCK_REALTIME;
            bool     is_rt = ((int)a2 & FUTEX_CLOCK_REALTIME) != 0;
            uint32_t val   = (uint32_t)a3;
            uint64_t timeout_ptr = a4;
            uint64_t uaddr2 = a5;
            uint32_t val3  = (uint32_t)a6;

            switch (op) {
                case FUTEX_WAIT:
                case FUTEX_WAIT_BITSET: {
                    bool has_to = false;
                    uint64_t to_ns = 0;
                    bool abs_time = (op == FUTEX_WAIT_BITSET);
                    if (timeout_ptr != 0) {
                        struct timespec ts;
                        if (mmu_copy_from_guest(vm, &ts, timeout_ptr, sizeof(ts)) < 0) {
                            ret = -EFAULT;
                            break;
                        }
                        has_to = true;
                        to_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
                        if (abs_time && is_rt) {
                            /* Convert realtime deadline to monotonic deadline */
                            to_ns = (to_ns > vm->det.vtime_ns)
                                    ? (vm->det.vmono_ns + (to_ns - vm->det.vtime_ns))
                                    : vm->det.vmono_ns;
                        }
                    }
                    uint32_t bitset = (op == FUTEX_WAIT_BITSET) ? val3 : 0xFFFFFFFFU;
                    int r_fw = sched_futex_wait(vm, uaddr, val, bitset, has_to, to_ns, abs_time);
                    if (r_fw == 1) {
                        switched = true;
                    } else {
                        ret = r_fw;
                    }
                    break;
                }
                case FUTEX_WAKE:
                    ret = sched_futex_wake(vm, uaddr, (int)val, 0xFFFFFFFFU);
                    break;
                case FUTEX_WAKE_BITSET:
                    ret = sched_futex_wake(vm, uaddr, (int)val, val3);
                    break;
                case FUTEX_REQUEUE:
                    ret = sched_futex_requeue(vm, uaddr, (int)val, (int)a4, uaddr2, false, 0);
                    break;
                case FUTEX_CMP_REQUEUE:
                    ret = sched_futex_requeue(vm, uaddr, (int)val, (int)a4, uaddr2, true, val3);
                    break;
                case FUTEX_WAKE_OP: {
                    /* Atomic op on uaddr2, then wake uaddr and optionally uaddr2 */
                    uint32_t op_val = val3;
                    int op_code = (op_val >> 28) & 0xF;
                    int cmp     = (op_val >> 24) & 0xF;
                    int oparg   = (int32_t)((op_val >> 12) & 0xFFF);
                    if (oparg & 0x800) oparg |= ~0xFFF; /* sign extend 12-bit */
                    int cmparg  = (int32_t)(op_val & 0xFFF);
                    if (cmparg & 0x800) cmparg |= ~0xFFF;
                    if (op_code & FUTEX_OP_OPARG_SHIFT) {
                        op_code &= ~FUTEX_OP_OPARG_SHIFT;
                        oparg = 1 << (oparg & 31);
                    }
                    uint32_t oldval = 0;
                    if (mmu_copy_from_guest(vm, &oldval, uaddr2, 4) < 0) { ret = -EFAULT; break; }
                    uint32_t newval = oldval;
                    switch (op_code) {
                        case FUTEX_OP_SET:   newval = (uint32_t)oparg; break;
                        case FUTEX_OP_ADD:   newval = oldval + (uint32_t)oparg; break;
                        case FUTEX_OP_OR:    newval = oldval | (uint32_t)oparg; break;
                        case FUTEX_OP_ANDN:  newval = oldval & ~(uint32_t)oparg; break;
                        case FUTEX_OP_XOR:   newval = oldval ^ (uint32_t)oparg; break;
                    }
                    mmu_copy_to_guest(vm, uaddr2, &newval, 4);
                    int w = sched_futex_wake(vm, uaddr, (int)val, 0xFFFFFFFFU);
                    bool cond = false;
                    switch (cmp) {
                        case FUTEX_OP_CMP_EQ: cond = ((int32_t)oldval == cmparg); break;
                        case FUTEX_OP_CMP_NE: cond = ((int32_t)oldval != cmparg); break;
                        case FUTEX_OP_CMP_LT: cond = ((int32_t)oldval <  cmparg); break;
                        case FUTEX_OP_CMP_LE: cond = ((int32_t)oldval <= cmparg); break;
                        case FUTEX_OP_CMP_GT: cond = ((int32_t)oldval >  cmparg); break;
                        case FUTEX_OP_CMP_GE: cond = ((int32_t)oldval >= cmparg); break;
                    }
                    if (cond) w += sched_futex_wake(vm, uaddr2, (int)a4, 0xFFFFFFFFU);
                    ret = w;
                    break;
                }
                default:
                    ret = -ENOSYS;
                    break;
            }
            break;
        }

        case LINUX_SYS_sched_yield: {
            r->rax = 0; /* Set return value for yielding thread before context switch! */
            sched_switch_next(vm, true);
            switched = true;
            break;
        }

        case LINUX_SYS_sched_getaffinity: {
            size_t len = (size_t)a2;
            if (len < 8) { ret = -EINVAL; break; }
            uint8_t mask[128] = {0};
            mask[0] = 0x01; /* Strictly 1 single vCPU (CPU 0) */
            size_t copy = len < sizeof(mask) ? len : sizeof(mask);
            ret = (mmu_copy_to_guest(vm, a3, mask, copy) == 0) ? (int64_t)copy : -EFAULT;
            break;
        }

        case LINUX_SYS_sched_setaffinity:
        case LINUX_SYS_sched_setparam:
        case LINUX_SYS_sched_getparam:
        case LINUX_SYS_sched_setscheduler:
        case LINUX_SYS_sched_getscheduler:
            ret = 0;
            break;
        case LINUX_SYS_sched_get_priority_max:
            ret = 99;
            break;
        case LINUX_SYS_sched_get_priority_min:
            ret = 1;
            break;

        /* ==================== Process, Identity & System Info ==================== */
        case LINUX_SYS_getpid:  ret = vm->sched.pid; break;
        case LINUX_SYS_getppid: ret = 1; break;
        case LINUX_SYS_getpgrp: ret = vm->sched.pid; break;
        case LINUX_SYS_gettid:  ret = vm->sched.threads[vm->sched.current_idx].tid; break;
        case LINUX_SYS_getuid:
        case LINUX_SYS_geteuid:
        case LINUX_SYS_getgid:
        case LINUX_SYS_getegid:
            ret = 1000;
            break;

        case LINUX_SYS_uname: {
            struct utsname u;
            memset(&u, 0, sizeof(u));
            strcpy(u.sysname,  "Linux");
            strcpy(u.nodename, "dethv");
            strcpy(u.release,  "6.8.0-dethv");
            strcpy(u.version,  "#1 SMP DETERMINISTIC");
            strcpy(u.machine,  "x86_64");
            ret = (mmu_copy_to_guest(vm, a1, &u, sizeof(u)) == 0) ? 0 : -EFAULT;
            break;
        }

        case LINUX_SYS_sysinfo: {
            struct sysinfo si;
            memset(&si, 0, sizeof(si));
            si.uptime    = (long)(vm->det.vmono_ns / 1000000000ULL);
            si.totalram  = vm->ram_size;
            si.freeram   = vm->ram_size - vm->mmu.next_phys;
            si.procs     = (unsigned short)sched_num_alive(&vm->sched);
            si.mem_unit  = 1;
            ret = (mmu_copy_to_guest(vm, a1, &si, sizeof(si)) == 0) ? 0 : -EFAULT;
            break;
        }

        case LINUX_SYS_getrlimit:
        case LINUX_SYS_prlimit64: {
            int resource = (nr == LINUX_SYS_getrlimit) ? (int)a1 : (int)a2;
            uint64_t old_ptr = (nr == LINUX_SYS_getrlimit) ? a2 : a4;
            if (old_ptr != 0) {
                struct rlimit rl = { 64ULL * 1024 * 1024, 64ULL * 1024 * 1024 };
                if (resource == RLIMIT_STACK)  { rl.rlim_cur = GUEST_STACK_SIZE; rl.rlim_max = GUEST_STACK_SIZE; }
                if (resource == RLIMIT_NOFILE) { rl.rlim_cur = DETHV_MAX_FDS;    rl.rlim_max = DETHV_MAX_FDS; }
                if (resource == RLIMIT_AS || resource == RLIMIT_DATA) { rl.rlim_cur = RLIM_INFINITY; rl.rlim_max = RLIM_INFINITY; }
                if (mmu_copy_to_guest(vm, old_ptr, &rl, sizeof(rl)) < 0) { ret = -EFAULT; break; }
            }
            ret = 0;
            break;
        }

        case LINUX_SYS_setrlimit:
        case LINUX_SYS_prctl:
            ret = 0;
            break;

        /* ==================== Signals & Exit ==================== */
        case LINUX_SYS_rt_sigaction: {
            int sig = (int)a1;
            if (sig <= 0 || sig >= DETHV_MAX_SIGNALS) { ret = -EINVAL; break; }
            if (a3 != 0) {
                if (mmu_copy_to_guest(vm, a3, &vm->sched.sigactions[sig], sizeof(ksigaction_t)) < 0) {
                    ret = -EFAULT; break;
                }
            }
            if (a2 != 0) {
                if (mmu_copy_from_guest(vm, &vm->sched.sigactions[sig], a2, sizeof(ksigaction_t)) < 0) {
                    ret = -EFAULT; break;
                }
                vm->sched.sigactions_dirty = true;
            }
            ret = 0;
            break;
        }

        case LINUX_SYS_rt_sigprocmask: {
            guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];
            if (a3 != 0) {
                if (mmu_copy_to_guest(vm, a3, &cur->sigmask, 8) < 0) { ret = -EFAULT; break; }
            }
            if (a2 != 0) {
                uint64_t set = 0;
                if (mmu_copy_from_guest(vm, &set, a2, 8) < 0) { ret = -EFAULT; break; }
                if (a1 == SIG_BLOCK)        cur->sigmask |= set;
                else if (a1 == SIG_UNBLOCK) cur->sigmask &= ~set;
                else if (a1 == SIG_SETMASK) cur->sigmask = set;
            }
            ret = 0;
            break;
        }

        case LINUX_SYS_sigaltstack:
            ret = 0;
            break;

        case LINUX_SYS_tgkill:
        case LINUX_SYS_tkill: {
            int sig = (nr == LINUX_SYS_tgkill) ? (int)a3 : (int)a2;
            if (sig == SIGABRT || sig == SIGKILL || sig == SIGSEGV || sig == SIGILL || sig == SIGFPE) {
                vm->running = false;
                vm->crash_signal = sig;
                vm->fault_rip = r->rip;
                vm->stop_reason = (sig == SIGABRT) ? DETHV_STOP_CRASH_ABRT :
                                  (sig == SIGSEGV) ? DETHV_STOP_CRASH_SEGV :
                                  (sig == SIGFPE)  ? DETHV_STOP_CRASH_FPE  :
                                  (sig == SIGILL)  ? DETHV_STOP_CRASH_ILL  : DETHV_STOP_CRASH_ABRT;
                return;
            }
            ret = 0;
            break;
        }

        case LINUX_SYS_exit:
            sched_exit_current_thread(vm, (int)(a1 & 0xFF));
            return;

        case LINUX_SYS_exit_group:
            vm->exit_code   = (int)(a1 & 0xFF);
            vm->stop_reason = DETHV_STOP_EXITED;
            vm->running     = false;
            return;

        default:
            if (vm->cfg.trace_syscalls) {
                fprintf(stderr, "[dethv] Unimplemented syscall %llu (a1=0x%llx a2=0x%llx)\n",
                        (unsigned long long)nr, (unsigned long long)a1, (unsigned long long)a2);
            }
            ret = -ENOSYS;
            break;
    }

done_syscall:
    if (vm->cfg.trace_syscalls) {
        fprintf(stderr, "[dethv tid=%d] sys_%llu(0x%llx, 0x%llx, 0x%llx) = %lld\n",
                vm->sched.threads[vm->sched.current_idx].tid,
                (unsigned long long)nr, (unsigned long long)a1,
                (unsigned long long)a2, (unsigned long long)a3, (long long)ret);
    }

    if (!switched) {
        r->rax = (uint64_t)ret;
        /* If running multithreaded and this thread's branch budget is depleted, deterministically switch! */
        if (vm->pmu_available && sched_num_runnable(&vm->sched) > 1 &&
            vm->sched.threads[vm->sched.current_idx].branch_budget <= DETHV_PMU_SLACK) {
            sched_switch_next(vm, true);
        }
    }
}
