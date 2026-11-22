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
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/times.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

static void fill_statx_from_stat(struct statx *sx, const struct stat *st) {
    memset(sx, 0, sizeof(*sx));
    sx->stx_mask         = STATX_BASIC_STATS;
    sx->stx_blksize      = (uint32_t)st->st_blksize;
    sx->stx_nlink        = (uint32_t)st->st_nlink;
    sx->stx_uid          = st->st_uid;
    sx->stx_gid          = st->st_gid;
    sx->stx_mode         = (uint16_t)st->st_mode;
    sx->stx_ino          = st->st_ino;
    sx->stx_size         = (uint64_t)st->st_size;
    sx->stx_blocks       = (uint64_t)st->st_blocks;
    sx->stx_atime.tv_sec = st->st_atim.tv_sec;
    sx->stx_ctime.tv_sec = st->st_ctim.tv_sec;
    sx->stx_mtime.tv_sec = st->st_mtim.tv_sec;
    sx->stx_btime.tv_sec = st->st_ctim.tv_sec;
    sx->stx_dev_major    = 0;
    sx->stx_dev_minor    = 1;
}

static void fill_det_statfs(struct statfs *sf) {
    memset(sf, 0, sizeof(*sf));
    sf->f_type    = 0x01021994; /* TMPFS_MAGIC */
    sf->f_bsize   = 4096;
    sf->f_blocks  = 26214400;   /* 100 GiB deterministic virtual disk */
    sf->f_bfree   = 25000000;
    sf->f_bavail  = 25000000;
    sf->f_files   = 1000000;
    sf->f_ffree   = 990000;
    sf->f_namelen = 255;
    sf->f_frsize  = 4096;
}

/* Helper for sendmsg / sendmmsg */
static int64_t handle_one_sendmsg(dethv_vm_t *vm, int fd, uint64_t msg_ptr, int flags) {
    struct msghdr msg;
    if (mmu_copy_from_guest(vm, &msg, msg_ptr, sizeof(msg)) < 0) return -EFAULT;

    uint8_t addr_buf[128];
    uint32_t addrlen = msg.msg_namelen;
    if (addrlen > sizeof(addr_buf)) addrlen = sizeof(addr_buf);
    if (msg.msg_name && addrlen > 0) {
        if (mmu_copy_from_guest(vm, addr_buf, (uint64_t)msg.msg_name, addrlen) < 0) return -EFAULT;
    }

    size_t total_len = 0;
    struct iovec iovs[64];
    size_t iovcnt = msg.msg_iovlen < 64 ? msg.msg_iovlen : 64;
    for (size_t i = 0; i < iovcnt; i++) {
        if (mmu_copy_from_guest(vm, &iovs[i], (uint64_t)msg.msg_iov + i * sizeof(struct iovec), sizeof(struct iovec)) < 0)
            return -EFAULT;
        total_len += iovs[i].iov_len;
    }

    uint8_t sbuf[4096];
    uint8_t *flat = (total_len <= sizeof(sbuf)) ? sbuf : malloc(total_len ? total_len : 1);
    if (!flat) return -ENOMEM;
    size_t off = 0;
    for (size_t i = 0; i < iovcnt; i++) {
        if (iovs[i].iov_len > 0) {
            if (mmu_copy_from_guest(vm, flat + off, (uint64_t)iovs[i].iov_base, iovs[i].iov_len) < 0) {
                if (flat != sbuf) free(flat);
                return -EFAULT;
            }
            off += iovs[i].iov_len;
        }
    }

    int64_t r = net_sys_sendto(vm, fd, flat, total_len, flags,
                               (msg.msg_name && addrlen > 0) ? addr_buf : NULL, addrlen);
    if (flat != sbuf) free(flat);
    return r;
}

/* Helper for recvmsg / recvmmsg */
static int64_t handle_one_recvmsg(dethv_vm_t *vm, int fd, uint64_t msg_ptr, int flags,
                                  bool *would_block, uint64_t *timeout_ns_out) {
    struct msghdr msg;
    if (mmu_copy_from_guest(vm, &msg, msg_ptr, sizeof(msg)) < 0) return -EFAULT;

    size_t total_cap = 0;
    struct iovec iovs[64];
    size_t iovcnt = msg.msg_iovlen < 64 ? msg.msg_iovlen : 64;
    for (size_t i = 0; i < iovcnt; i++) {
        if (mmu_copy_from_guest(vm, &iovs[i], (uint64_t)msg.msg_iov + i * sizeof(struct iovec), sizeof(struct iovec)) < 0)
            return -EFAULT;
        total_cap += iovs[i].iov_len;
    }

    uint8_t sbuf[4096];
    uint8_t *flat = (total_cap <= sizeof(sbuf)) ? sbuf : malloc(total_cap ? total_cap : 1);
    if (!flat) return -ENOMEM;

    uint8_t addr_buf[128];
    uint32_t addrlen = msg.msg_namelen;
    if (addrlen > sizeof(addr_buf)) addrlen = sizeof(addr_buf);

    int64_t n = net_sys_recvfrom(vm, fd, flat, total_cap, flags,
                                 msg.msg_name ? addr_buf : NULL,
                                 msg.msg_name ? &addrlen : NULL,
                                 would_block, timeout_ns_out);
    if (n >= 0) {
        size_t rem = (size_t)n;
        size_t off = 0;
        for (size_t i = 0; i < iovcnt && rem > 0; i++) {
            size_t c = rem < iovs[i].iov_len ? rem : iovs[i].iov_len;
            if (c > 0 && mmu_copy_to_guest(vm, (uint64_t)iovs[i].iov_base, flat + off, c) < 0) {
                if (flat != sbuf) free(flat);
                return -EFAULT;
            }
            off += c;
            rem -= c;
        }
        if (msg.msg_name && addrlen > 0) {
            uint32_t wlen = addrlen < msg.msg_namelen ? addrlen : msg.msg_namelen;
            mmu_copy_to_guest(vm, (uint64_t)msg.msg_name, addr_buf, wlen);
            msg.msg_namelen = addrlen;
        }
        msg.msg_controllen = 0;
        msg.msg_flags = 0;
        mmu_copy_to_guest(vm, msg_ptr, &msg, sizeof(msg));
    }
    if (flat != sbuf) free(flat);
    return n;
}

void dethv_handle_syscall(dethv_vm_t *vm) {
    user_regs_t *r = &vm->shared->regs;
    guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];
    uint64_t nr = r->rax;
    uint64_t a1 = r->rdi;
    uint64_t a2 = r->rsi;
    uint64_t a3 = r->rdx;
    uint64_t a4 = r->r10;
    uint64_t a5 = r->r8;
    uint64_t a6 = r->r9;

    if (vm->snap_on_stdin_armed && nr == LINUX_SYS_read && (int)a1 == 0) {
        vm->snap_on_stdin_armed = false;
        r->rip -= 2;
        vm->running = false;
        vm->stop_reason = DETHV_STOP_SNAPSHOT;
        return;
    }

    if (vm->snap_on_open_armed &&
        (nr == LINUX_SYS_open || nr == LINUX_SYS_openat || nr == LINUX_SYS_openat2)) {
        char pbuf[512] = {0};
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
    cur->last_sys = nr;
    det_advance_time(&vm->det, 1000);
    vm->shared->vtsc += DETHV_VTSC_STEP_SYSCALL;
    if ((vm->det.syscall_count & 255) == 0) {
        sched_wake_expired_timers(vm);
    }

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

            if (fd >= 0 && fd < DETHV_MAX_FDS && vm->vfs.fds[fd].used &&
                vm->vfs.fds[fd].kind == FD_SOCKET) {
                bool wb = false; uint64_t to_ns = 0;
                ret = net_sys_recvfrom(vm, fd, tmp, count, 0, NULL, NULL, &wb, &to_ns);
                if (wb) {
                    if (cur->io_waiting && cur->io_timed_out) {
                        cur->io_waiting = false; cur->io_timed_out = false;
                        ret = -EAGAIN;
                    } else {
                        if (tmp != sbuf) free(tmp);
                        sched_block_io_current(vm, to_ns > 0, vm->det.vmono_ns + to_ns);
                        return;
                    }
                } else {
                    cur->io_waiting = false; cur->io_timed_out = false;
                }
            } else {
                ret = vfs_read(vm, fd, tmp, count);
                if (ret == -EAGAIN && fd >= 0 && fd < DETHV_MAX_FDS && vm->vfs.fds[fd].used &&
                    !(vm->vfs.fds[fd].flags & O_NONBLOCK) &&
                    (vm->vfs.fds[fd].kind == FD_PIPE_READ ||
                     vm->vfs.fds[fd].kind == FD_EVENTFD ||
                     vm->vfs.fds[fd].kind == FD_TIMERFD)) {
                    if (tmp != sbuf) free(tmp);
                    sched_block_io_current(vm, false, 0);
                    return;
                }
                cur->io_waiting = false; cur->io_timed_out = false;
            }
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

        case LINUX_SYS_pwrite64: {
            int fd = (int)a1;
            size_t count = (size_t)a3;
            int64_t off = (int64_t)a4;
            if (count == 0) { ret = 0; break; }
            if (count > 16 * 1024 * 1024) count = 16 * 1024 * 1024;
            uint8_t sbuf[4096];
            uint8_t *tmp = (count <= sizeof(sbuf)) ? sbuf : malloc(count);
            if (!tmp) { ret = -ENOMEM; break; }
            if (mmu_copy_from_guest(vm, tmp, a2, count) < 0) ret = -EFAULT;
            else ret = vfs_pwrite(vm, fd, tmp, count, off);
            if (tmp != sbuf) free(tmp);
            break;
        }

        case LINUX_SYS_writev:
        case LINUX_SYS_pwritev:
        case LINUX_SYS_pwritev2: {
            int fd = (int)a1;
            int iovcnt = (int)a3;
            bool is_p = (nr != LINUX_SYS_writev);
            int64_t off = is_p ? (int64_t)a4 : 0;
            if (iovcnt < 0 || iovcnt > 1024) { ret = -EINVAL; break; }
            int64_t total = 0;
            for (int i = 0; i < iovcnt; i++) {
                struct iovec iov;
                if (mmu_copy_from_guest(vm, &iov, a2 + (uint64_t)i * sizeof(iov), sizeof(iov)) < 0) {
                    total = -EFAULT; break;
                }
                if (iov.iov_len == 0) continue;
                uint8_t *tmp = malloc(iov.iov_len);
                if (!tmp) { total = -ENOMEM; break; }
                if (mmu_copy_from_guest(vm, tmp, (uint64_t)iov.iov_base, iov.iov_len) < 0) {
                    free(tmp); total = -EFAULT; break;
                }
                int64_t w = is_p ? vfs_pwrite(vm, fd, tmp, iov.iov_len, off + total)
                                 : vfs_write(vm, fd, tmp, iov.iov_len);
                free(tmp);
                if (w < 0) { if (total == 0) total = w; break; }
                total += w;
            }
            ret = total;
            break;
        }

        case LINUX_SYS_readv:
        case LINUX_SYS_preadv:
        case LINUX_SYS_preadv2: {
            int fd = (int)a1;
            int iovcnt = (int)a3;
            bool is_p = (nr != LINUX_SYS_readv);
            int64_t off = is_p ? (int64_t)a4 : 0;
            if (iovcnt < 0 || iovcnt > 1024) { ret = -EINVAL; break; }
            int64_t total = 0;
            for (int i = 0; i < iovcnt; i++) {
                struct iovec iov;
                if (mmu_copy_from_guest(vm, &iov, a2 + (uint64_t)i * sizeof(iov), sizeof(iov)) < 0) {
                    total = -EFAULT; break;
                }
                if (iov.iov_len == 0) continue;
                uint8_t *tmp = malloc(iov.iov_len);
                if (!tmp) { total = -ENOMEM; break; }
                int64_t n = is_p ? vfs_pread(vm, fd, tmp, iov.iov_len, off + total)
                                 : vfs_read(vm, fd, tmp, iov.iov_len);
                if (n > 0) {
                    if (mmu_copy_to_guest(vm, (uint64_t)iov.iov_base, tmp, (size_t)n) < 0) {
                        free(tmp); total = -EFAULT; break;
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
            char path[512];
            if (mmu_read_cstring(vm, a1, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_openat(vm, AT_FDCWD, path, (int)a2, (uint32_t)a3);
            break;
        }

        case LINUX_SYS_creat: {
            char path[512];
            if (mmu_read_cstring(vm, a1, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_openat(vm, AT_FDCWD, path, O_CREAT | O_WRONLY | O_TRUNC, (uint32_t)a2);
            break;
        }

        case LINUX_SYS_openat: {
            char path[512];
            if (mmu_read_cstring(vm, a2, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_openat(vm, (int)a1, path, (int)a3, (uint32_t)a4);
            break;
        }

        case LINUX_SYS_openat2: {
            char path[512];
            struct { uint64_t flags, mode, resolve; } how;
            if (mmu_read_cstring(vm, a2, path, sizeof(path)) < 0 ||
                mmu_copy_from_guest(vm, &how, a3, sizeof(how)) < 0) {
                ret = -EFAULT; break;
            }
            ret = vfs_openat(vm, (int)a1, path, (int)how.flags, (uint32_t)how.mode);
            break;
        }

        case LINUX_SYS_memfd_create: {
            char name[128] = "memfd";
            mmu_read_cstring(vm, a1, name, sizeof(name));
            char vpath[256];
            snprintf(vpath, sizeof(vpath), "/tmp/.memfd_%llu_%s", (unsigned long long)vm->det.syscall_count, name);
            ret = vfs_openat(vm, AT_FDCWD, vpath, O_RDWR | O_CREAT | O_TRUNC, 0600);
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

        case LINUX_SYS_ftruncate:
            ret = vfs_ftruncate(vm, (int)a1, (int64_t)a2);
            break;

        case LINUX_SYS_truncate: {
            char path[512];
            if (mmu_read_cstring(vm, a1, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_truncate_path(vm, path, (int64_t)a2);
            break;
        }

        case LINUX_SYS_fallocate: {
            int fd = (int)a1;
            int64_t end = (int64_t)a3 + (int64_t)a4;
            if (fd >= 0 && fd < DETHV_MAX_FDS && vm->vfs.fds[fd].used && vm->vfs.fds[fd].kind == FD_MEM_VFILE) {
                vfile_t *vf = &vm->vfs.vfiles[vm->vfs.fds[fd].ref_idx];
                if (end > (int64_t)vf->len) ret = vfs_ftruncate(vm, fd, end);
                else ret = 0;
            } else {
                ret = 0;
            }
            break;
        }

        case LINUX_SYS_copy_file_range: {
            int fd_in = (int)a1, fd_out = (int)a3;
            size_t len = (size_t)a5;
            if (len > 16 * 1024 * 1024) len = 16 * 1024 * 1024;
            uint8_t *tmp = malloc(len ? len : 1);
            if (!tmp) { ret = -ENOMEM; break; }
            int64_t nr_r;
            if (a2) {
                int64_t off_in = 0;
                mmu_copy_from_guest(vm, &off_in, a2, 8);
                nr_r = vfs_pread(vm, fd_in, tmp, len, off_in);
                if (nr_r > 0) { off_in += nr_r; mmu_copy_to_guest(vm, a2, &off_in, 8); }
            } else {
                nr_r = vfs_read(vm, fd_in, tmp, len);
            }
            if (nr_r <= 0) { ret = nr_r; free(tmp); break; }
            if (a4) {
                int64_t off_out = 0;
                mmu_copy_from_guest(vm, &off_out, a4, 8);
                ret = vfs_pwrite(vm, fd_out, tmp, (size_t)nr_r, off_out);
                if (ret > 0) { off_out += ret; mmu_copy_to_guest(vm, a4, &off_out, 8); }
            } else {
                ret = vfs_write(vm, fd_out, tmp, (size_t)nr_r);
            }
            free(tmp);
            break;
        }

        case LINUX_SYS_fstat: {
            struct stat st;
            ret = vfs_fstat(vm, (int)a1, &st);
            if (ret == 0 && mmu_copy_to_guest(vm, a2, &st, sizeof(st)) < 0) ret = -EFAULT;
            break;
        }

        case LINUX_SYS_stat:
        case LINUX_SYS_lstat: {
            char path[512];
            struct stat st;
            if (mmu_read_cstring(vm, a1, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_stat_path(vm, AT_FDCWD, path, &st, (nr == LINUX_SYS_lstat) ? AT_SYMLINK_NOFOLLOW : 0);
            if (ret == 0 && mmu_copy_to_guest(vm, a2, &st, sizeof(st)) < 0) ret = -EFAULT;
            break;
        }

        case LINUX_SYS_newfstatat: {
            char path[512];
            struct stat st;
            if (mmu_read_cstring(vm, a2, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_stat_path(vm, (int)a1, path, &st, (int)a4);
            if (ret == 0 && mmu_copy_to_guest(vm, a3, &st, sizeof(st)) < 0) ret = -EFAULT;
            break;
        }

        case LINUX_SYS_statx: {
            char path[512];
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

        case LINUX_SYS_statfs:
        case LINUX_SYS_fstatfs: {
            struct statfs sf;
            fill_det_statfs(&sf);
            ret = (mmu_copy_to_guest(vm, a2, &sf, sizeof(sf)) == 0) ? 0 : -EFAULT;
            break;
        }

        case LINUX_SYS_access:
        case LINUX_SYS_faccessat:
        case LINUX_SYS_faccessat2: {
            char path[512];
            struct stat st;
            int dirfd = (nr == LINUX_SYS_access) ? AT_FDCWD : (int)a1;
            uint64_t pptr = (nr == LINUX_SYS_access) ? a1 : a2;
            if (mmu_read_cstring(vm, pptr, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = (vfs_stat_path(vm, dirfd, path, &st, 0) == 0) ? 0 : -ENOENT;
            break;
        }

        case LINUX_SYS_readlink:
        case LINUX_SYS_readlinkat: {
            char path[512];
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

        case LINUX_SYS_getdents64: {
            size_t count = (size_t)a3;
            if (count > 1024 * 1024) count = 1024 * 1024;
            uint8_t *tmp = malloc(count ? count : 1);
            if (!tmp) { ret = -ENOMEM; break; }
            ret = vfs_getdents64(vm, (int)a1, tmp, count);
            if (ret > 0 && mmu_copy_to_guest(vm, a2, tmp, (size_t)ret) < 0) ret = -EFAULT;
            free(tmp);
            break;
        }

        case LINUX_SYS_mkdir: {
            char path[512];
            if (mmu_read_cstring(vm, a1, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_mkdir(vm, AT_FDCWD, path, (uint32_t)a2);
            break;
        }
        case LINUX_SYS_mkdirat: {
            char path[512];
            if (mmu_read_cstring(vm, a2, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_mkdir(vm, (int)a1, path, (uint32_t)a3);
            break;
        }
        case LINUX_SYS_rmdir: {
            char path[512];
            if (mmu_read_cstring(vm, a1, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_rmdir(vm, AT_FDCWD, path);
            break;
        }
        case LINUX_SYS_unlink: {
            char path[512];
            if (mmu_read_cstring(vm, a1, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_unlink(vm, AT_FDCWD, path, 0);
            break;
        }
        case LINUX_SYS_unlinkat: {
            char path[512];
            if (mmu_read_cstring(vm, a2, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            ret = vfs_unlink(vm, (int)a1, path, (int)a3);
            break;
        }
        case LINUX_SYS_rename: {
            char p1[512], p2[512];
            if (mmu_read_cstring(vm, a1, p1, sizeof(p1)) < 0 ||
                mmu_read_cstring(vm, a2, p2, sizeof(p2)) < 0) { ret = -EFAULT; break; }
            ret = vfs_rename(vm, AT_FDCWD, p1, AT_FDCWD, p2);
            break;
        }
        case LINUX_SYS_renameat:
        case LINUX_SYS_renameat2: {
            char p1[512], p2[512];
            if (mmu_read_cstring(vm, a2, p1, sizeof(p1)) < 0 ||
                mmu_read_cstring(vm, a4, p2, sizeof(p2)) < 0) { ret = -EFAULT; break; }
            ret = vfs_rename(vm, (int)a1, p1, (int)a3, p2);
            break;
        }
        case LINUX_SYS_link: {
            char p1[512], p2[512];
            if (mmu_read_cstring(vm, a1, p1, sizeof(p1)) < 0 ||
                mmu_read_cstring(vm, a2, p2, sizeof(p2)) < 0) { ret = -EFAULT; break; }
            ret = vfs_link(vm, AT_FDCWD, p1, AT_FDCWD, p2);
            break;
        }
        case LINUX_SYS_linkat: {
            char p1[512], p2[512];
            if (mmu_read_cstring(vm, a2, p1, sizeof(p1)) < 0 ||
                mmu_read_cstring(vm, a4, p2, sizeof(p2)) < 0) { ret = -EFAULT; break; }
            ret = vfs_link(vm, (int)a1, p1, (int)a3, p2);
            break;
        }
        case LINUX_SYS_symlink:
        case LINUX_SYS_symlinkat:
            ret = 0;
            break;

        case LINUX_SYS_getcwd: {
            size_t len = strlen(vm->vfs.cwd) + 1;
            if (len > (size_t)a2) { ret = -ERANGE; break; }
            if (mmu_copy_to_guest(vm, a1, vm->vfs.cwd, len) < 0) ret = -EFAULT;
            else ret = (int64_t)len;
            break;
        }

        case LINUX_SYS_chdir: {
            char path[512], full[512];
            if (mmu_read_cstring(vm, a1, path, sizeof(path)) < 0) { ret = -EFAULT; break; }
            vfs_resolve_path(&vm->vfs, AT_FDCWD, path, full, sizeof(full));
            snprintf(vm->vfs.cwd, sizeof(vm->vfs.cwd), "%s", full);
            vm->vfs.cwd_dirty = true;
            ret = 0;
            break;
        }

        case LINUX_SYS_fchdir: {
            int fd = (int)a1;
            if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used) { ret = -EBADF; break; }
            snprintf(vm->vfs.cwd, sizeof(vm->vfs.cwd), "%s", vm->vfs.fds[fd].path);
            vm->vfs.cwd_dirty = true;
            ret = 0;
            break;
        }

        case LINUX_SYS_dup:  ret = vfs_dup(vm, (int)a1, 0, 0, false); break;
        case LINUX_SYS_dup2: ret = vfs_dup(vm, (int)a1, (int)a2, 0, true); break;
        case LINUX_SYS_dup3: ret = vfs_dup(vm, (int)a1, (int)a2, (int)a3, true); break;

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
            ret = net_ioctl(vm, (int)a1, a2, a3);
            break;

        case LINUX_SYS_fsync:
        case LINUX_SYS_fdatasync: {
            int fd = (int)a1;
            if (fd >= 0 && fd < DETHV_MAX_FDS && vm->vfs.fds[fd].used && vm->vfs.fds[fd].kind == FD_MEM_VFILE) {
                mmu_sync_vfile_from_vmas(vm, (int32_t)vm->vfs.fds[fd].ref_idx);
            }
            ret = 0;
            break;
        }

        case LINUX_SYS_fadvise64:
        case LINUX_SYS_flock:
        case LINUX_SYS_chmod:
        case LINUX_SYS_fchmod:
        case LINUX_SYS_fchmodat:
        case LINUX_SYS_chown:
        case LINUX_SYS_fchown:
        case LINUX_SYS_lchown:
        case LINUX_SYS_utimensat:
        case LINUX_SYS_sync_file_range:
            ret = 0;
            break;

        case LINUX_SYS_umask:
            ret = vm->vfs.umask_val;
            vm->vfs.umask_val = (uint32_t)(a1 & 0777);
            vm->vfs.cwd_dirty = true;
            break;

        /* ==================== Virtual Loopback Networking, Epoll & TimerFD ==================== */
        case LINUX_SYS_socket:
            ret = net_sys_socket(vm, (int)a1, (int)a2, (int)a3);
            break;

        case LINUX_SYS_socketpair: {
            int sv[2];
            ret = net_sys_socketpair(vm, (int)a1, (int)a2, (int)a3, sv);
            if (ret == 0 && mmu_copy_to_guest(vm, a4, sv, sizeof(sv)) < 0) ret = -EFAULT;
            break;
        }

        case LINUX_SYS_bind: {
            uint8_t abuf[128];
            uint32_t alen = (uint32_t)a3;
            if (alen > sizeof(abuf)) alen = sizeof(abuf);
            if (mmu_copy_from_guest(vm, abuf, a2, alen) < 0) { ret = -EFAULT; break; }
            ret = net_sys_bind(vm, (int)a1, abuf, alen);
            break;
        }

        case LINUX_SYS_listen:
            ret = net_sys_listen(vm, (int)a1, (int)a2);
            break;

        case LINUX_SYS_connect: {
            uint8_t abuf[128];
            uint32_t alen = (uint32_t)a3;
            if (alen > sizeof(abuf)) alen = sizeof(abuf);
            if (mmu_copy_from_guest(vm, abuf, a2, alen) < 0) { ret = -EFAULT; break; }
            ret = net_sys_connect(vm, (int)a1, abuf, alen);
            break;
        }

        case LINUX_SYS_accept:
        case LINUX_SYS_accept4: {
            int fd = (int)a1;
            int flags = (nr == LINUX_SYS_accept4) ? (int)a4 : 0;
            uint8_t abuf[128];
            uint32_t alen = sizeof(abuf);
            if (a3 && mmu_copy_from_guest(vm, &alen, a3, 4) < 0) { ret = -EFAULT; break; }
            if (alen > sizeof(abuf)) alen = sizeof(abuf);
            ret = net_sys_accept(vm, fd, a2 ? abuf : NULL, a3 ? &alen : NULL, flags);
            if (ret == -EAGAIN && fd >= 0 && fd < DETHV_MAX_FDS && vm->vfs.fds[fd].used &&
                !(vm->vfs.fds[fd].flags & O_NONBLOCK)) {
                sched_block_io_current(vm, false, 0);
                return;
            }
            cur->io_waiting = false; cur->io_timed_out = false;
            if (ret >= 0 && a2 && a3) {
                uint32_t orig_len = 0;
                mmu_copy_from_guest(vm, &orig_len, a3, 4);
                uint32_t copy = alen < orig_len ? alen : orig_len;
                mmu_copy_to_guest(vm, a2, abuf, copy);
                mmu_copy_to_guest(vm, a3, &alen, 4);
            }
            break;
        }

        case LINUX_SYS_getsockname:
        case LINUX_SYS_getpeername: {
            uint8_t abuf[128];
            uint32_t orig_len = 0;
            if (mmu_copy_from_guest(vm, &orig_len, a3, 4) < 0) { ret = -EFAULT; break; }
            uint32_t alen = orig_len < sizeof(abuf) ? orig_len : (uint32_t)sizeof(abuf);
            ret = net_sys_getsockname(vm, (int)a1, abuf, &alen, nr == LINUX_SYS_getpeername);
            if (ret == 0) {
                uint32_t copy = alen < orig_len ? alen : orig_len;
                mmu_copy_to_guest(vm, a2, abuf, copy);
                mmu_copy_to_guest(vm, a3, &alen, 4);
            }
            break;
        }

        case LINUX_SYS_setsockopt: {
            uint8_t obuf[128];
            uint32_t olen = (uint32_t)a5;
            if (olen > sizeof(obuf)) olen = sizeof(obuf);
            if (a4 && olen > 0 && mmu_copy_from_guest(vm, obuf, a4, olen) < 0) { ret = -EFAULT; break; }
            ret = net_sys_setsockopt(vm, (int)a1, (int)a2, (int)a3, a4 ? obuf : NULL, olen);
            break;
        }

        case LINUX_SYS_getsockopt: {
            uint8_t obuf[128];
            uint32_t orig_len = 0;
            if (mmu_copy_from_guest(vm, &orig_len, a5, 4) < 0) { ret = -EFAULT; break; }
            uint32_t olen = orig_len < sizeof(obuf) ? orig_len : (uint32_t)sizeof(obuf);
            ret = net_sys_getsockopt(vm, (int)a1, (int)a2, (int)a3, obuf, &olen);
            if (ret == 0) {
                uint32_t copy = olen < orig_len ? olen : orig_len;
                if (copy > 0) mmu_copy_to_guest(vm, a4, obuf, copy);
                mmu_copy_to_guest(vm, a5, &olen, 4);
            }
            break;
        }

        case LINUX_SYS_shutdown:
            ret = net_sys_shutdown(vm, (int)a1, (int)a2);
            break;

        case LINUX_SYS_sendto: {
            size_t len = (size_t)a3;
            if (len > 16 * 1024 * 1024) len = 16 * 1024 * 1024;
            uint8_t sbuf[4096];
            uint8_t *tmp = (len <= sizeof(sbuf)) ? sbuf : malloc(len ? len : 1);
            if (!tmp) { ret = -ENOMEM; break; }
            if (len > 0 && mmu_copy_from_guest(vm, tmp, a2, len) < 0) {
                ret = -EFAULT;
            } else {
                uint8_t abuf[128];
                uint32_t alen = (uint32_t)a6;
                if (alen > sizeof(abuf)) alen = sizeof(abuf);
                if (a5 && alen > 0 && mmu_copy_from_guest(vm, abuf, a5, alen) < 0) {
                    ret = -EFAULT;
                } else {
                    ret = net_sys_sendto(vm, (int)a1, tmp, len, (int)a4, (a5 && alen > 0) ? abuf : NULL, alen);
                }
            }
            if (tmp != sbuf) free(tmp);
            break;
        }

        case LINUX_SYS_recvfrom: {
            size_t len = (size_t)a3;
            if (len > 16 * 1024 * 1024) len = 16 * 1024 * 1024;
            uint8_t sbuf[4096];
            uint8_t *tmp = (len <= sizeof(sbuf)) ? sbuf : malloc(len ? len : 1);
            if (!tmp) { ret = -ENOMEM; break; }
            uint8_t abuf[128];
            uint32_t orig_alen = 0, alen = sizeof(abuf);
            if (a5 && a6) {
                if (mmu_copy_from_guest(vm, &orig_alen, a6, 4) < 0) {
                    if (tmp != sbuf) free(tmp);
                    ret = -EFAULT; break;
                }
                alen = orig_alen < sizeof(abuf) ? orig_alen : (uint32_t)sizeof(abuf);
            }
            bool wb = false; uint64_t to_ns = 0;
            ret = net_sys_recvfrom(vm, (int)a1, tmp, len, (int)a4,
                                   (a5 && a6) ? abuf : NULL, (a5 && a6) ? &alen : NULL,
                                   &wb, &to_ns);
            if (wb) {
                if (cur->io_waiting && cur->io_timed_out) {
                    cur->io_waiting = false; cur->io_timed_out = false;
                    ret = -EAGAIN;
                } else {
                    if (tmp != sbuf) free(tmp);
                    sched_block_io_current(vm, to_ns > 0, vm->det.vmono_ns + to_ns);
                    return;
                }
            } else {
                cur->io_waiting = false; cur->io_timed_out = false;
            }
            if (ret > 0) {
                size_t cp = (size_t)ret < len ? (size_t)ret : len;
                if (mmu_copy_to_guest(vm, a2, tmp, cp) < 0) ret = -EFAULT;
            }
            if (ret >= 0 && a5 && a6) {
                uint32_t cp = alen < orig_alen ? alen : orig_alen;
                if (cp > 0) mmu_copy_to_guest(vm, a5, abuf, cp);
                mmu_copy_to_guest(vm, a6, &alen, 4);
            }
            if (tmp != sbuf) free(tmp);
            break;
        }

        case LINUX_SYS_sendmsg:
            ret = handle_one_sendmsg(vm, (int)a1, a2, (int)a3);
            break;

        case LINUX_SYS_sendmmsg: {
            int fd = (int)a1;
            unsigned int vlen = (unsigned int)a3;
            int flags = (int)a4;
            int sent = 0;
            for (unsigned int i = 0; i < vlen && i < 256; i++) {
                uint64_t mh_ptr = a2 + (uint64_t)i * sizeof(struct mmsghdr);
                int64_t r = handle_one_sendmsg(vm, fd, mh_ptr, flags);
                if (r < 0) { if (sent == 0) { ret = r; goto done_syscall; } break; }
                uint32_t mlen = (uint32_t)r;
                mmu_copy_to_guest(vm, mh_ptr + offsetof(struct mmsghdr, msg_len), &mlen, 4);
                sent++;
            }
            ret = sent;
            break;
        }

        case LINUX_SYS_recvmsg: {
            bool wb = false; uint64_t to_ns = 0;
            ret = handle_one_recvmsg(vm, (int)a1, a2, (int)a3, &wb, &to_ns);
            if (wb) {
                if (cur->io_waiting && cur->io_timed_out) {
                    cur->io_waiting = false; cur->io_timed_out = false;
                    ret = -EAGAIN;
                } else {
                    sched_block_io_current(vm, to_ns > 0, vm->det.vmono_ns + to_ns);
                    return;
                }
            } else {
                cur->io_waiting = false; cur->io_timed_out = false;
            }
            break;
        }

        case LINUX_SYS_recvmmsg: {
            int fd = (int)a1;
            unsigned int vlen = (unsigned int)a3;
            int flags = (int)a4;
            int got = 0;
            bool wb = false; uint64_t to_ns = 0;
            for (unsigned int i = 0; i < vlen && i < 256; i++) {
                uint64_t mh_ptr = a2 + (uint64_t)i * sizeof(struct mmsghdr);
                int f2 = (i > 0) ? (flags | MSG_DONTWAIT) : flags;
                int64_t r = handle_one_recvmsg(vm, fd, mh_ptr, f2, &wb, &to_ns);
                if (r < 0) {
                    if (got == 0 && wb) {
                        if (a5 != 0) {
                            struct timespec ts;
                            if (mmu_copy_from_guest(vm, &ts, a5, sizeof(ts)) == 0) {
                                uint64_t tns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
                                if (to_ns == 0 || tns < to_ns) to_ns = tns;
                            }
                        }
                        if (cur->io_waiting && cur->io_timed_out) {
                            cur->io_waiting = false; cur->io_timed_out = false;
                            ret = -EAGAIN;
                            goto done_syscall;
                        }
                        sched_block_io_current(vm, to_ns > 0, vm->det.vmono_ns + to_ns);
                        return;
                    }
                    if (got == 0) { cur->io_waiting = false; ret = r; goto done_syscall; }
                    break;
                }
                uint32_t mlen = (uint32_t)r;
                mmu_copy_to_guest(vm, mh_ptr + offsetof(struct mmsghdr, msg_len), &mlen, 4);
                got++;
            }
            cur->io_waiting = false; cur->io_timed_out = false;
            ret = got;
            break;
        }

        case LINUX_SYS_epoll_create:  ret = net_sys_epoll_create(vm, 0); break;
        case LINUX_SYS_epoll_create1: ret = net_sys_epoll_create(vm, (int)a1); break;

        case LINUX_SYS_epoll_ctl: {
            struct epoll_event ev = {0};
            if (a4 && mmu_copy_from_guest(vm, &ev, a4, sizeof(ev)) < 0) { ret = -EFAULT; break; }
            ret = net_sys_epoll_ctl(vm, (int)a1, (int)a2, (int)a3, ev.events, ev.data.u64);
            break;
        }

        case LINUX_SYS_epoll_wait:
        case LINUX_SYS_epoll_pwait:
        case LINUX_SYS_epoll_pwait2: {
            int epfd = (int)a1, maxev = (int)a3;
            bool has_to = false;
            uint64_t to_ns = 0;
            if (nr == LINUX_SYS_epoll_pwait2) {
                if (a4 != 0) {
                    struct timespec ts;
                    if (mmu_copy_from_guest(vm, &ts, a4, sizeof(ts)) < 0) { ret = -EFAULT; break; }
                    has_to = true;
                    to_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
                }
            } else {
                int timeout_ms = (int)a4;
                if (timeout_ms >= 0) {
                    has_to = true;
                    to_ns = (uint64_t)timeout_ms * 1000000ULL;
                }
            }

            int n = net_sys_epoll_wait(vm, epfd, a2, maxev);
            if (n != 0) {
                cur->io_waiting = false; cur->io_timed_out = false;
                ret = n;
                break;
            }
            if ((has_to && to_ns == 0) || (cur->io_waiting && cur->io_timed_out)) {
                cur->io_waiting = false; cur->io_timed_out = false;
                ret = 0;
                break;
            }
            sched_block_io_current(vm, has_to, vm->det.vmono_ns + to_ns);
            return;
        }

        case LINUX_SYS_timerfd_create:
            ret = net_sys_timerfd_create(vm, (int)a1, (int)a2);
            break;

        case LINUX_SYS_timerfd_settime: {
            struct itimerspec its;
            if (mmu_copy_from_guest(vm, &its, a3, sizeof(its)) < 0) { ret = -EFAULT; break; }
            uint64_t val_ns = (uint64_t)its.it_value.tv_sec * 1000000000ULL + (uint64_t)its.it_value.tv_nsec;
            uint64_t int_ns = (uint64_t)its.it_interval.tv_sec * 1000000000ULL + (uint64_t)its.it_interval.tv_nsec;
            bool abs_t = ((int)a2 & TFD_TIMER_ABSTIME) != 0;
            if (a4) {
                struct itimerspec old = {0};
                mmu_copy_to_guest(vm, a4, &old, sizeof(old));
            }
            ret = net_sys_timerfd_settime(vm, (int)a1, (int)a2, val_ns, int_ns, abs_t);
            break;
        }

        case LINUX_SYS_timerfd_gettime: {
            struct itimerspec cur_ts = {0};
            ret = (mmu_copy_to_guest(vm, a2, &cur_ts, sizeof(cur_ts)) == 0) ? 0 : -EFAULT;
            break;
        }

        case LINUX_SYS_io_uring_setup:
            ret = iouring_sys_setup(vm, (uint32_t)a1, a2);
            break;

        case LINUX_SYS_io_uring_enter:
            ret = iouring_sys_enter(vm, (int)a1, (uint32_t)a2, (uint32_t)a3, (uint32_t)a4);
            break;

        case LINUX_SYS_io_uring_register:
            ret = iouring_sys_register(vm, (int)a1, (uint32_t)a2, a3, (uint32_t)a4);
            break;

        case LINUX_SYS_poll:
        case LINUX_SYS_ppoll: {
            nfds_t nfds = (nfds_t)a2;
            bool has_to = false;
            uint64_t to_ns = 0;
            if (nr == LINUX_SYS_poll) {
                int to_ms = (int)a3;
                if (to_ms >= 0) { has_to = true; to_ns = (uint64_t)to_ms * 1000000ULL; }
            } else if (a3 != 0) {
                struct timespec ts;
                if (mmu_copy_from_guest(vm, &ts, a3, sizeof(ts)) < 0) { ret = -EFAULT; break; }
                has_to = true;
                to_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
            }

            int ready = 0;
            for (nfds_t i = 0; i < nfds && i < 256; i++) {
                struct pollfd pfd;
                if (mmu_copy_from_guest(vm, &pfd, a1 + i * sizeof(pfd), sizeof(pfd)) < 0) {
                    ret = -EFAULT; goto done_syscall;
                }
                pfd.revents = 0;
                if (pfd.fd >= 0) {
                    uint32_t rev = net_fd_poll_events(vm, pfd.fd);
                    pfd.revents = (short)(rev & ((uint32_t)pfd.events | POLLERR | POLLHUP | POLLNVAL));
                }
                if (pfd.revents) ready++;
                mmu_copy_to_guest(vm, a1 + i * sizeof(pfd), &pfd, sizeof(pfd));
            }
            if (ready > 0 || (has_to && to_ns == 0) || (cur->io_waiting && cur->io_timed_out)) {
                cur->io_waiting = false; cur->io_timed_out = false;
                ret = ready;
                break;
            }
            sched_block_io_current(vm, has_to, vm->det.vmono_ns + to_ns);
            return;
        }

        case LINUX_SYS_select:
        case LINUX_SYS_pselect6: {
            int nfds = (int)a1;
            if (nfds < 0) { ret = -EINVAL; break; }
            if (nfds > 1024) nfds = 1024;
            bool has_to = false;
            uint64_t to_ns = 0;
            if (a5 != 0) {
                if (nr == LINUX_SYS_select) {
                    struct timeval tv;
                    if (mmu_copy_from_guest(vm, &tv, a5, sizeof(tv)) < 0) { ret = -EFAULT; break; }
                    has_to = true;
                    to_ns = (uint64_t)tv.tv_sec * 1000000000ULL + (uint64_t)tv.tv_usec * 1000ULL;
                } else {
                    struct timespec ts;
                    if (mmu_copy_from_guest(vm, &ts, a5, sizeof(ts)) < 0) { ret = -EFAULT; break; }
                    has_to = true;
                    to_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
                }
            }
            fd_set rfds, wfds, efds, r_out, w_out, e_out;
            FD_ZERO(&r_out); FD_ZERO(&w_out); FD_ZERO(&e_out);
            if (a2) mmu_copy_from_guest(vm, &rfds, a2, sizeof(fd_set));
            if (a3) mmu_copy_from_guest(vm, &wfds, a3, sizeof(fd_set));
            if (a4) mmu_copy_from_guest(vm, &efds, a4, sizeof(fd_set));
            int ready = 0;
            for (int fd = 0; fd < nfds; fd++) {
                uint32_t rev = 0;
                bool want = (a2 && FD_ISSET(fd, &rfds)) || (a3 && FD_ISSET(fd, &wfds)) || (a4 && FD_ISSET(fd, &efds));
                if (!want) continue;
                rev = net_fd_poll_events(vm, fd);
                if (a2 && FD_ISSET(fd, &rfds) && (rev & (EPOLLIN | EPOLLHUP))) { FD_SET(fd, &r_out); ready++; }
                if (a3 && FD_ISSET(fd, &wfds) && (rev & EPOLLOUT))            { FD_SET(fd, &w_out); ready++; }
                if (a4 && FD_ISSET(fd, &efds) && (rev & EPOLLERR))            { FD_SET(fd, &e_out); ready++; }
            }
            if (ready > 0 || (has_to && to_ns == 0) || (cur->io_waiting && cur->io_timed_out)) {
                cur->io_waiting = false; cur->io_timed_out = false;
                if (a2) mmu_copy_to_guest(vm, a2, &r_out, sizeof(fd_set));
                if (a3) mmu_copy_to_guest(vm, a3, &w_out, sizeof(fd_set));
                if (a4) mmu_copy_to_guest(vm, a4, &e_out, sizeof(fd_set));
                ret = ready;
                break;
            }
            sched_block_io_current(vm, has_to, vm->det.vmono_ns + to_ns);
            return;
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
            if (!is_anon && fd >= 0 && fd < DETHV_MAX_FDS && vm->vfs.fds[fd].used &&
                vm->vfs.fds[fd].kind == FD_IO_URING) {
                ret = (int64_t)iouring_mmap(vm, fd, addr, len, prot, flags, off);
                break;
            }
            uint64_t mapped = mmu_mmap_region(vm, addr, len, prot, flags, !is_anon);
            if ((int64_t)mapped < 0) { ret = (int64_t)mapped; break; }

            if (!is_anon && fd >= 0) {
                if (fd < DETHV_MAX_FDS && vm->vfs.fds[fd].used &&
                    vm->vfs.fds[fd].kind == FD_MEM_VFILE && (flags & MAP_SHARED)) {
                    mmu_set_vma_vfile(vm, mapped, (int32_t)vm->vfs.fds[fd].ref_idx, (uint64_t)off);
                }
                size_t aligned_len = PAGE_ALIGN_UP(len);
                uint8_t *tmp = calloc(1, aligned_len);
                if (!tmp) { ret = -ENOMEM; break; }
                int64_t nr_read = vfs_pread(vm, fd, tmp, len, off);
                if (nr_read > 0) {
                    mmu_copy_to_guest(vm, mapped, tmp, (size_t)nr_read);
                }
                free(tmp);
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

        case LINUX_SYS_msync:
            mmu_sync_all_shared_vmas_in_range(vm, a1, a1 + a2);
            ret = 0;
            break;

        case LINUX_SYS_mremap: {
            uint64_t old_addr = a1;
            size_t   old_size = (size_t)a2;
            size_t   new_size = (size_t)a3;
            uint32_t flags    = (uint32_t)a4;
            if (new_size <= old_size) { ret = (int64_t)old_addr; break; }
            if (!(flags & MREMAP_MAYMOVE)) { ret = -ENOMEM; break; }
            uint64_t naddr = mmu_mmap_region(vm, 0, new_size, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS, false);
            if ((int64_t)naddr < 0) { ret = (int64_t)naddr; break; }
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
        case LINUX_SYS_membarrier:
            ret = 0;
            break;

        /* ==================== Deterministic Randomness ==================== */
        case LINUX_SYS_getrandom: {
            size_t buflen = (size_t)a2;
            if (buflen > 1024 * 1024) buflen = 1024 * 1024;
            uint8_t sbuf[256];
            uint8_t *tmp = (buflen <= sizeof(sbuf)) ? sbuf : malloc(buflen ? buflen : 1);
            if (!tmp) { ret = -ENOMEM; break; }
            det_rand_bytes(&vm->det, tmp, buflen);
            vm->det.getrandom_count++;
            if (buflen > 0 && mmu_copy_to_guest(vm, a1, tmp, buflen) < 0) ret = -EFAULT;
            else ret = (int64_t)buflen;
            if (tmp != sbuf) free(tmp);
            break;
        }

        /* ==================== Deterministic Time & Clocks ==================== */
        case LINUX_SYS_clock_gettime: {
            int clk = (int)a1;
            uint64_t ns = (clk == CLOCK_REALTIME || clk == CLOCK_REALTIME_COARSE)
                          ? vm->det.vtime_ns : vm->det.vmono_ns;
            det_advance_time(&vm->det, 100);
            struct timespec ts = {
                .tv_sec  = (time_t)(ns / 1000000000ULL),
                .tv_nsec = (long)(ns % 1000000000ULL)
            };
            ret = (mmu_copy_to_guest(vm, a2, &ts, sizeof(ts)) == 0) ? 0 : -EFAULT;
            break;
        }

        case LINUX_SYS_clock_getres: {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 1 };
            ret = a2 ? ((mmu_copy_to_guest(vm, a2, &ts, sizeof(ts)) == 0) ? 0 : -EFAULT) : 0;
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
                cur->fs_base = a2;
                ret = 0;
            } else if (code == ARCH_GET_FS) {
                ret = (mmu_copy_to_guest(vm, a2, &vm->current_fs_base, 8) == 0) ? 0 : -EFAULT;
            } else if (code == ARCH_SET_GS) {
                cur->gs_base = a2;
                ret = 0;
            } else {
                ret = -EINVAL;
            }
            break;
        }

        case LINUX_SYS_set_tid_address:
            cur->clear_child_tid = a1;
            ret = cur->tid;
            break;

        case LINUX_SYS_set_robust_list:
            cur->robust_list_head = a1;
            cur->robust_list_len  = a2;
            ret = 0;
            break;

        case LINUX_SYS_get_robust_list:
            if (a2) mmu_copy_to_guest(vm, a2, &cur->robust_list_head, 8);
            if (a3) mmu_copy_to_guest(vm, a3, &cur->robust_list_len, 8);
            ret = 0;
            break;

        case LINUX_SYS_rseq:
            ret = -ENOSYS;
            break;

        case LINUX_SYS_clone:
            ret = sched_create_thread(vm, a1, a2, a3, a4, a5);
            break;

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
                            ret = -EFAULT; break;
                        }
                        has_to = true;
                        to_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
                        if (abs_time && is_rt) {
                            to_ns = (to_ns > vm->det.vtime_ns)
                                    ? (vm->det.vmono_ns + (to_ns - vm->det.vtime_ns))
                                    : vm->det.vmono_ns;
                        }
                    }
                    uint32_t bitset = (op == FUTEX_WAIT_BITSET) ? val3 : 0xFFFFFFFFU;
                    int r_fw = sched_futex_wait(vm, uaddr, val, bitset, has_to, to_ns, abs_time);
                    if (r_fw == 1) switched = true;
                    else ret = r_fw;
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
                    uint32_t op_val = val3;
                    int op_code = (op_val >> 28) & 0xF;
                    int cmp     = (op_val >> 24) & 0xF;
                    int oparg   = (int32_t)((op_val >> 12) & 0xFFF);
                    if (oparg & 0x800) oparg |= ~0xFFF;
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
                        case FUTEX_OP_SET:  newval = (uint32_t)oparg; break;
                        case FUTEX_OP_ADD:  newval = oldval + (uint32_t)oparg; break;
                        case FUTEX_OP_OR:   newval = oldval | (uint32_t)oparg; break;
                        case FUTEX_OP_ANDN: newval = oldval & ~(uint32_t)oparg; break;
                        case FUTEX_OP_XOR:  newval = oldval ^ (uint32_t)oparg; break;
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

        case LINUX_SYS_sched_yield:
            r->rax = 0;
            sched_switch_next(vm, true);
            switched = true;
            break;

        case LINUX_SYS_sched_getaffinity: {
            size_t len = (size_t)a2;
            if (len < 8) { ret = -EINVAL; break; }
            uint8_t mask[128] = {0};
            mask[0] = 0x01;
            size_t copy = len < sizeof(mask) ? len : sizeof(mask);
            ret = (mmu_copy_to_guest(vm, a3, mask, copy) == 0) ? (int64_t)copy : -EFAULT;
            break;
        }

        case LINUX_SYS_sched_setaffinity:
        case LINUX_SYS_sched_setparam:
        case LINUX_SYS_sched_getparam:
        case LINUX_SYS_sched_setscheduler:
        case LINUX_SYS_sched_getscheduler:
        case LINUX_SYS_sched_setattr:
        case LINUX_SYS_sched_getattr:
        case LINUX_SYS_setpriority:
        case LINUX_SYS_getpriority:
            ret = 0;
            break;
        case LINUX_SYS_sched_get_priority_max: ret = 99; break;
        case LINUX_SYS_sched_get_priority_min: ret = 1; break;

        /* ==================== Process, Identity & System Info ==================== */
        case LINUX_SYS_getpid:  ret = vm->sched.pid; break;
        case LINUX_SYS_getppid: ret = 1; break;
        case LINUX_SYS_getpgrp: ret = vm->sched.pid; break;
        case LINUX_SYS_gettid:  ret = cur->tid; break;
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
            si.uptime   = (long)(vm->det.vmono_ns / 1000000000ULL);
            si.totalram = vm->ram_size;
            si.freeram  = vm->ram_size - vm->mmu.next_phys;
            si.procs    = (unsigned short)sched_num_alive(&vm->sched);
            si.mem_unit = 1;
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
                if (resource == RLIMIT_NOFILE) { rl.rlim_cur = 1000000;          rl.rlim_max = 1000000; }
                if (resource == RLIMIT_AS || resource == RLIMIT_DATA || resource == RLIMIT_MEMLOCK) {
                    rl.rlim_cur = RLIM_INFINITY; rl.rlim_max = RLIM_INFINITY;
                }
                if (mmu_copy_to_guest(vm, old_ptr, &rl, sizeof(rl)) < 0) { ret = -EFAULT; break; }
            }
            ret = 0;
            break;
        }

        case LINUX_SYS_setrlimit:
            ret = 0;
            break;

        case LINUX_SYS_prctl:
            if ((int)a1 == 15 /* PR_SET_NAME */ && a2 != 0) {
                mmu_read_cstring(vm, a2, cur->name, sizeof(cur->name));
            }
            ret = 0;
            break;

        /* ==================== Signals & Exit ==================== */
        case LINUX_SYS_rt_sigaction: {
            int sig = (int)a1;
            if (sig <= 0 || sig >= DETHV_MAX_SIGNALS) { ret = -EINVAL; break; }
            if (a3 != 0 && mmu_copy_to_guest(vm, a3, &vm->sched.sigactions[sig], sizeof(ksigaction_t)) < 0) {
                ret = -EFAULT; break;
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
            if (a3 != 0 && mmu_copy_to_guest(vm, a3, &cur->sigmask, 8) < 0) { ret = -EFAULT; break; }
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
        if (vm->pmu_available && sched_num_runnable(&vm->sched) > 1 &&
            vm->sched.threads[vm->sched.current_idx].branch_budget <= DETHV_PMU_SLACK) {
            sched_switch_next(vm, true);
        }
    }
}
