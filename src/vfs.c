#include "internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Deterministic fixed epoch timestamp for all stat() calls */
#define DET_STAT_SEC  1700000000L

static void fill_det_stat(struct stat *st, const char *path, uint32_t mode, uint64_t size) {
    memset(st, 0, sizeof(*st));
    uint64_t h = det_hash_bytes(0, path ? path : "", path ? strlen(path) : 0);
    st->st_dev     = 1;
    st->st_ino     = (ino_t)(1000 + (h & 0xFFFFFF));
    st->st_mode    = mode;
    st->st_nlink   = 1;
    st->st_uid     = 1000;
    st->st_gid     = 1000;
    st->st_size    = (off_t)size;
    st->st_blksize = 4096;
    st->st_blocks  = (blkcnt_t)((size + 511) / 512);
    st->st_atim.tv_sec = DET_STAT_SEC;
    st->st_mtim.tv_sec = DET_STAT_SEC;
    st->st_ctim.tv_sec = DET_STAT_SEC;
}

int vfs_init(dethv_vm_t *vm) {
    vfs_state_t *vfs = &vm->vfs;
    memset(vfs, 0, sizeof(*vfs));
    for (int i = 0; i < DETHV_MAX_FDS; i++) {
        vfs->fds[i].host_fd = -1;
    }

    vfs->stdout_buf = calloc(1, DETHV_OUT_CAP);
    vfs->stderr_buf = calloc(1, DETHV_OUT_CAP);
    if (!vfs->stdout_buf || !vfs->stderr_buf) return -1;

    /* Standard fds 0, 1, 2 */
    vfs->fds[0] = (vfd_t){ .used = true, .kind = FD_STDIN,  .flags = O_RDONLY, .host_fd = -1, .path = "/dev/stdin" };
    vfs->fds[1] = (vfd_t){ .used = true, .kind = FD_STDOUT, .flags = O_WRONLY, .host_fd = -1, .path = "/dev/stdout" };
    vfs->fds[2] = (vfd_t){ .used = true, .kind = FD_STDERR, .flags = O_WRONLY, .host_fd = -1, .path = "/dev/stderr" };

    strcpy(vfs->cwd, "/");
    strcpy(vfs->exe_path, "/guest");
    vfs->umask_val = 0022;
    return 0;
}

void vfs_destroy(vfs_state_t *vfs) {
    for (int i = 0; i < DETHV_MAX_FDS; i++) {
        if (vfs->fds[i].used && vfs->fds[i].host_fd >= 0) {
            close(vfs->fds[i].host_fd);
            vfs->fds[i].host_fd = -1;
        }
    }
    for (int i = 0; i < DETHV_MAX_VFILES; i++) {
        free(vfs->vfiles[i].data);
        vfs->vfiles[i].data = NULL;
    }
    free(vfs->stdin_buf);  vfs->stdin_buf  = NULL;
    free(vfs->stdout_buf); vfs->stdout_buf = NULL;
    free(vfs->stderr_buf); vfs->stderr_buf = NULL;
}

/* Deep copy vfs_state_t (used for snapshot take / restore — super fast!) */
int vfs_clone(vfs_state_t *dst, const vfs_state_t *src) {
    /* Close any existing host_fds in dst that differ */
    for (int i = 0; i < DETHV_MAX_FDS; i++) {
        if (dst->fds[i].used && dst->fds[i].host_fd >= 0) {
            close(dst->fds[i].host_fd);
            dst->fds[i].host_fd = -1;
        }
    }

    /* Copy scalar tables */
    memcpy(dst->fds, src->fds, sizeof(dst->fds));
    for (int i = 0; i < DETHV_MAX_PIPES; i++) {
        if (src->pipes[i].used || dst->pipes[i].used) {
            dst->pipes[i] = src->pipes[i];
        }
    }
    memcpy(dst->cwd, src->cwd, sizeof(dst->cwd));
    memcpy(dst->exe_path, src->exe_path, sizeof(dst->exe_path));
    dst->umask_val = src->umask_val;
    dst->fds_dirty = false;
    dst->pipes_dirty = false;
    dst->vfiles_dirty = false;
    dst->cwd_dirty = false;

    /* Reopen or dup host_fds cleanly so dst owns independent descriptors */
    for (int i = 0; i < DETHV_MAX_FDS; i++) {
        if (dst->fds[i].used && dst->fds[i].kind == FD_HOST_RO) {
            if (src->fds[i].host_fd >= 0) {
                dst->fds[i].host_fd = open(dst->fds[i].path, O_RDONLY | O_CLOEXEC);
            } else if (dst->fds[i].path[0]) {
                dst->fds[i].host_fd = open(dst->fds[i].path, O_RDONLY | O_CLOEXEC);
            }
        } else {
            dst->fds[i].host_fd = -1;
        }
    }

    /* Copy stdout / stderr (reuse existing buffers if allocated!) */
    if (!dst->stdout_buf) dst->stdout_buf = malloc(DETHV_OUT_CAP);
    if (!dst->stderr_buf) dst->stderr_buf = malloc(DETHV_OUT_CAP);
    if (!dst->stdout_buf || !dst->stderr_buf) return -1;
    if (src->stdout_len > 0) memcpy(dst->stdout_buf, src->stdout_buf, src->stdout_len);
    dst->stdout_len = src->stdout_len;
    if (src->stderr_len > 0) memcpy(dst->stderr_buf, src->stderr_buf, src->stderr_len);
    dst->stderr_len = src->stderr_len;

    /* Copy stdin */
    if (src->stdin_len > 0 && src->stdin_buf) {
        if (dst->stdin_cap < src->stdin_len || !dst->stdin_buf) {
            free(dst->stdin_buf);
            dst->stdin_cap = src->stdin_len;
            dst->stdin_buf = malloc(dst->stdin_cap);
            if (!dst->stdin_buf) return -1;
        }
        memcpy(dst->stdin_buf, src->stdin_buf, src->stdin_len);
    }
    dst->stdin_len = src->stdin_len;
    dst->stdin_pos = src->stdin_pos;

    /* Copy virtual overlay files */
    for (int i = 0; i < DETHV_MAX_VFILES; i++) {
        if (!src->vfiles[i].used) {
            dst->vfiles[i].used = false;
            dst->vfiles[i].len = 0;
            continue;
        }
        dst->vfiles[i].used = true;
        memcpy(dst->vfiles[i].path, src->vfiles[i].path, sizeof(dst->vfiles[i].path));
        dst->vfiles[i].mode = src->vfiles[i].mode;
        dst->vfiles[i].len  = src->vfiles[i].len;
        if (src->vfiles[i].len > 0 && src->vfiles[i].data) {
            if (dst->vfiles[i].cap < src->vfiles[i].len || !dst->vfiles[i].data) {
                free(dst->vfiles[i].data);
                dst->vfiles[i].cap = src->vfiles[i].len;
                dst->vfiles[i].data = malloc(dst->vfiles[i].cap);
                if (!dst->vfiles[i].data) return -1;
            }
            memcpy(dst->vfiles[i].data, src->vfiles[i].data, src->vfiles[i].len);
        }
    }

    return 0;
}

/* Ultra-fast O(modified) VFS restore for snapshot fuzzing! */
int vfs_restore_fast(vfs_state_t *dst, const vfs_state_t *src) {
    if (dst->fds_dirty) {
        for (int i = 0; i < DETHV_MAX_FDS; i++) {
            if (dst->fds[i].used && dst->fds[i].host_fd >= 0) {
                close(dst->fds[i].host_fd);
                dst->fds[i].host_fd = -1;
            }
        }
        memcpy(dst->fds, src->fds, sizeof(dst->fds));
        for (int i = 0; i < DETHV_MAX_FDS; i++) {
            if (dst->fds[i].used && dst->fds[i].kind == FD_HOST_RO && dst->fds[i].path[0]) {
                dst->fds[i].host_fd = open(dst->fds[i].path, O_RDONLY | O_CLOEXEC);
            } else {
                dst->fds[i].host_fd = -1;
            }
        }
        dst->fds_dirty = false;
    } else {
        /* Even if no fds opened/closed, restore offsets of open fds */
        for (int i = 0; i < DETHV_MAX_FDS; i++) {
            if (dst->fds[i].used) {
                dst->fds[i].offset      = src->fds[i].offset;
                dst->fds[i].flags       = src->fds[i].flags;
                dst->fds[i].eventfd_val = src->fds[i].eventfd_val;
            }
        }
    }

    if (dst->pipes_dirty) {
        for (int i = 0; i < DETHV_MAX_PIPES; i++) {
            if (src->pipes[i].used || dst->pipes[i].used) {
                dst->pipes[i] = src->pipes[i];
            }
        }
        dst->pipes_dirty = false;
    }

    if (dst->vfiles_dirty) {
        for (int i = 0; i < DETHV_MAX_VFILES; i++) {
            if (!src->vfiles[i].used) {
                dst->vfiles[i].used = false;
                dst->vfiles[i].len = 0;
                continue;
            }
            dst->vfiles[i].used = true;
            memcpy(dst->vfiles[i].path, src->vfiles[i].path, sizeof(dst->vfiles[i].path));
            dst->vfiles[i].mode = src->vfiles[i].mode;
            dst->vfiles[i].len  = src->vfiles[i].len;
            if (src->vfiles[i].len > 0 && src->vfiles[i].data) {
                if (dst->vfiles[i].cap < src->vfiles[i].len || !dst->vfiles[i].data) {
                    free(dst->vfiles[i].data);
                    dst->vfiles[i].cap = src->vfiles[i].len;
                    dst->vfiles[i].data = malloc(dst->vfiles[i].cap);
                    if (!dst->vfiles[i].data) return -1;
                }
                memcpy(dst->vfiles[i].data, src->vfiles[i].data, src->vfiles[i].len);
            }
        }
        dst->vfiles_dirty = false;
    }

    if (dst->cwd_dirty) {
        memcpy(dst->cwd, src->cwd, sizeof(dst->cwd));
        dst->umask_val = src->umask_val;
        dst->cwd_dirty = false;
    }

    /* Reset stdout/stderr lengths in O(1) (only copy snapshot prefix if non-empty) */
    if (src->stdout_len > 0) memcpy(dst->stdout_buf, src->stdout_buf, src->stdout_len);
    dst->stdout_len = src->stdout_len;
    if (src->stderr_len > 0) memcpy(dst->stderr_buf, src->stderr_buf, src->stderr_len);
    dst->stderr_len = src->stderr_len;

    if (src->stdin_len > 0 && src->stdin_buf) {
        if (dst->stdin_cap < src->stdin_len || !dst->stdin_buf) {
            free(dst->stdin_buf);
            dst->stdin_cap = src->stdin_len;
            dst->stdin_buf = malloc(dst->stdin_cap);
            if (!dst->stdin_buf) return -1;
        }
        memcpy(dst->stdin_buf, src->stdin_buf, src->stdin_len);
    }
    dst->stdin_len = src->stdin_len;
    dst->stdin_pos = src->stdin_pos;
    return 0;
}

int dethv_set_stdin(dethv_vm_t *vm, const void *data, size_t len) {
    vm->vfs.stdin_len = 0;
    vm->vfs.stdin_pos = 0;
    if (len > 0 && data) {
        if (len > vm->vfs.stdin_cap || !vm->vfs.stdin_buf) {
            size_t ncap = len < 256 ? 256 : len;
            uint8_t *nb = realloc(vm->vfs.stdin_buf, ncap);
            if (!nb) return -1;
            vm->vfs.stdin_buf = nb;
            vm->vfs.stdin_cap = ncap;
        }
        memcpy(vm->vfs.stdin_buf, data, len);
        vm->vfs.stdin_len = len;
    }
    return 0;
}

static vfile_t *find_vfile(vfs_state_t *vfs, const char *path) {
    for (int i = 0; i < DETHV_MAX_VFILES; i++) {
        if (vfs->vfiles[i].used && strcmp(vfs->vfiles[i].path, path) == 0)
            return &vfs->vfiles[i];
    }
    return NULL;
}

static int find_vfile_idx(vfs_state_t *vfs, const char *path) {
    for (int i = 0; i < DETHV_MAX_VFILES; i++) {
        if (vfs->vfiles[i].used && strcmp(vfs->vfiles[i].path, path) == 0)
            return i;
    }
    return -1;
}

static int alloc_vfile(vfs_state_t *vfs, const char *path, uint32_t mode) {
    int idx = find_vfile_idx(vfs, path);
    if (idx >= 0) return idx;
    for (int i = 0; i < DETHV_MAX_VFILES; i++) {
        if (!vfs->vfiles[i].used) {
            vfs->vfiles[i].used = true;
            strncpy(vfs->vfiles[i].path, path, sizeof(vfs->vfiles[i].path) - 1);
            vfs->vfiles[i].path[sizeof(vfs->vfiles[i].path) - 1] = '\0';
            vfs->vfiles[i].mode = mode ? mode : (S_IFREG | 0644);
            vfs->vfiles[i].len = 0;
            return i;
        }
    }
    return -1;
}

int vfs_set_vfile_data(vfs_state_t *vfs, const char *path, const void *data, size_t len) {
    int idx = alloc_vfile(vfs, path, S_IFREG | 0644);
    if (idx < 0) return -1;
    vfile_t *vf = &vfs->vfiles[idx];
    if (len > vf->cap) {
        uint8_t *nb = realloc(vf->data, len);
        if (!nb) return -1;
        vf->data = nb;
        vf->cap = len;
    }
    if (len > 0 && data) memcpy(vf->data, data, len);
    vf->len = len;
    return 0;
}

int dethv_set_vfile(dethv_vm_t *vm, const char *path, const void *data, size_t len) {
    vm->vfs.vfiles_dirty = true;
    return vfs_set_vfile_data(&vm->vfs, path, data, len);
}

static int alloc_fd(vfs_state_t *vfs, int min_fd) {
    for (int i = min_fd; i < DETHV_MAX_FDS; i++) {
        if (!vfs->fds[i].used) return i;
    }
    return -EMFILE;
}

/* Resolve relative paths cleanly against cwd or dirfd */
static void resolve_path(const vfs_state_t *vfs, int dirfd, const char *path, char *out, size_t out_sz) {
    if (path[0] == '/') {
        strncpy(out, path, out_sz - 1);
        out[out_sz - 1] = '\0';
        return;
    }
    const char *base = vfs->cwd;
    if (dirfd != AT_FDCWD && dirfd >= 0 && dirfd < DETHV_MAX_FDS && vfs->fds[dirfd].used) {
        base = vfs->fds[dirfd].path;
    }
    if (strcmp(base, "/") == 0) {
        snprintf(out, out_sz, "/%.*s", (int)(out_sz - 2), path);
    } else {
        size_t blen = strlen(base);
        if (blen + 2 >= out_sz) {
            snprintf(out, out_sz, "%.*s", (int)(out_sz - 1), base);
        } else {
            snprintf(out, out_sz, "%s/%.*s", base, (int)(out_sz - blen - 2), path);
        }
    }
}

/* Generate deterministic /proc virtual file contents */
static bool generate_proc_file(dethv_vm_t *vm, const char *path, char *buf, size_t cap, size_t *len_out) {
    if (strcmp(path, "/proc/sys/kernel/random/uuid") == 0 ||
        strcmp(path, "/proc/sys/kernel/random/boot_id") == 0) {
        uint8_t b[16];
        det_rand_bytes(&vm->det, b, 16);
        b[6] = (b[6] & 0x0F) | 0x40;
        b[8] = (b[8] & 0x3F) | 0x80;
        *len_out = (size_t)snprintf(buf, cap,
            "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
            b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],
            b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
        return true;
    }
    if (strcmp(path, "/proc/cpuinfo") == 0) {
        *len_out = (size_t)snprintf(buf, cap,
            "processor\t: 0\nvendor_id\t: DetHV\nmodel name\t: DetHV Deterministic vCPU\n"
            "cpu MHz\t\t: 2500.000\ncpu cores\t: 1\nsiblings\t: 1\n\n");
        return true;
    }
    if (strcmp(path, "/proc/uptime") == 0) {
        double secs = (double)vm->det.vmono_ns / 1e9;
        *len_out = (size_t)snprintf(buf, cap, "%.2f %.2f\n", secs, secs * 0.5);
        return true;
    }
    if (strcmp(path, "/proc/stat") == 0) {
        *len_out = (size_t)snprintf(buf, cap,
            "cpu  100 0 100 1000 0 0 0 0 0 0\n"
            "cpu0 100 0 100 1000 0 0 0 0 0 0\n"
            "btime 1700000000\nprocesses 1000\nprocs_running 1\n");
        return true;
    }
    if (strcmp(path, "/proc/self/stat") == 0) {
        *len_out = (size_t)snprintf(buf, cap,
            "%d (guest) R 1 %d %d 0 -1 4194304 100 0 0 0 10 10 0 0 20 0 %d 0 1 1048576 256\n",
            vm->sched.pid, vm->sched.pid, vm->sched.pid, sched_num_alive(&vm->sched));
        return true;
    }
    if (strcmp(path, "/proc/self/cmdline") == 0) {
        size_t n = strlen(vm->vfs.exe_path) + 1;
        if (n > cap) n = cap;
        memcpy(buf, vm->vfs.exe_path, n);
        *len_out = n;
        return true;
    }
    if (strcmp(path, "/proc/self/maps") == 0) {
        size_t off = 0;
        for (uint32_t i = 0; i < vm->mmu.num_vmas && off + 128 < cap; i++) {
            vma_t *v = &vm->mmu.vmas[i];
            off += (size_t)snprintf(buf + off, cap - off, "%012lx-%012lx %c%c%cp 00000000 00:00 0\n",
                (unsigned long)v->start, (unsigned long)v->end,
                (v->prot & PROT_READ) ? 'r' : '-',
                (v->prot & PROT_WRITE) ? 'w' : '-',
                (v->prot & PROT_EXEC) ? 'x' : '-');
        }
        *len_out = off;
        return true;
    }
    if (strcmp(path, "/sys/devices/system/cpu/online") == 0 ||
        strcmp(path, "/sys/devices/system/cpu/possible") == 0) {
        *len_out = (size_t)snprintf(buf, cap, "0\n");
        return true;
    }
    return false;
}

int vfs_openat(dethv_vm_t *vm, int dirfd, const char *path, int flags, uint32_t mode) {
    char full[256];
    resolve_path(&vm->vfs, dirfd, path, full, sizeof(full));

    /* Check special deterministic devices first! */
    int fd = alloc_fd(&vm->vfs, 0);
    if (fd < 0) return fd;

    vfd_t *f = &vm->vfs.fds[fd];
    memset(f, 0, sizeof(*f));
    f->host_fd = -1;
    f->flags = flags;
    memcpy(f->path, full, sizeof(f->path));
    f->path[sizeof(f->path) - 1] = '\0';
    vm->vfs.fds_dirty = true;

    if (strcmp(full, "/dev/urandom") == 0 || strcmp(full, "/dev/random") == 0 ||
        strcmp(full, "/dev/hwrng") == 0) {
        f->used = true;
        f->kind = FD_DEV_URANDOM;
        f->cached_mode = S_IFCHR | 0666;
        return fd;
    }
    if (strcmp(full, "/dev/null") == 0) {
        f->used = true;
        f->kind = FD_DEV_NULL;
        f->cached_mode = S_IFCHR | 0666;
        return fd;
    }
    if (strcmp(full, "/dev/zero") == 0) {
        f->used = true;
        f->kind = FD_DEV_ZERO;
        f->cached_mode = S_IFCHR | 0666;
        return fd;
    }
    if (strcmp(full, "/dev/stdin") == 0) {
        f->used = true;
        f->kind = FD_STDIN;
        f->cached_mode = S_IFIFO | 0600;
        return fd;
    }

    /* Deterministic /proc & /sys virtual files */
    char pbuf[4096];
    size_t plen = 0;
    /* Generate proc file */
    if (generate_proc_file(vm, full, pbuf, sizeof(pbuf), &plen)) {
        vm->vfs.vfiles_dirty = true;
        int vf_idx = alloc_vfile(&vm->vfs, full, S_IFREG | 0444);
        if (vf_idx < 0) return -ENOSPC;
        vfs_set_vfile_data(&vm->vfs, full, pbuf, plen);
        f->used = true;
        f->kind = FD_PROC_VFILE;
        f->ref_idx = (uint32_t)vf_idx;
        f->cached_mode = S_IFREG | 0444;
        f->cached_size = plen;
        return fd;
    }

    /* Block host-specific preload/non-deterministic files */
    if (strcmp(full, "/etc/ld.so.preload") == 0) {
        return -ENOENT;
    }

    /* Check existing virtual overlay files first (including fuzz input files!) */
    int vf_idx = find_vfile_idx(&vm->vfs, full);
    if (vf_idx >= 0) {
        if (flags & O_TRUNC) vm->vfs.vfiles[vf_idx].len = 0;
        f->used = true;
        f->kind = FD_MEM_VFILE;
        f->ref_idx = (uint32_t)vf_idx;
        f->cached_mode = vm->vfs.vfiles[vf_idx].mode;
        f->cached_size = vm->vfs.vfiles[vf_idx].len;
        if (flags & O_APPEND) f->offset = vm->vfs.vfiles[vf_idx].len;
        return fd;
    }

    /* If writing / creating -> create in-memory virtual file (NEVER writes host disk!) */
    int accmode = flags & O_ACCMODE;
    if ((flags & O_CREAT) || accmode == O_WRONLY || accmode == O_RDWR) {
        vm->vfs.vfiles_dirty = true;
        /* Copy-on-write if host file exists and not O_TRUNC */
        int nidx = alloc_vfile(&vm->vfs, full, S_IFREG | (mode ? (mode & 0777) : 0644));
        if (nidx < 0) return -ENOSPC;
        if (!(flags & O_TRUNC) && vm->cfg.allow_host_ro) {
            int hfd = open(full, O_RDONLY);
            if (hfd >= 0) {
                struct stat st;
                if (fstat(hfd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 && st.st_size < 4 * 1024 * 1024) {
                    uint8_t *tmp = malloc((size_t)st.st_size);
                    if (tmp) {
                        ssize_t nr = read(hfd, tmp, (size_t)st.st_size);
                        if (nr > 0) vfs_set_vfile_data(&vm->vfs, full, tmp, (size_t)nr);
                        free(tmp);
                    }
                }
                close(hfd);
            }
        }
        f->used = true;
        f->kind = FD_MEM_VFILE;
        f->ref_idx = (uint32_t)nidx;
        f->cached_mode = vm->vfs.vfiles[nidx].mode;
        f->cached_size = vm->vfs.vfiles[nidx].len;
        if (flags & O_APPEND) f->offset = vm->vfs.vfiles[nidx].len;
        return fd;
    }

    /* Otherwise: read-only access to host files (needed for ld.so, libc.so.6, etc.) */
    if (vm->cfg.allow_host_ro) {
        int hfd = open(full, O_RDONLY | O_CLOEXEC);
        if (hfd >= 0) {
            struct stat st;
            if (fstat(hfd, &st) == 0) {
                if ((flags & O_DIRECTORY) && !S_ISDIR(st.st_mode)) {
                    close(hfd);
                    return -ENOTDIR;
                }
                f->used = true;
                f->kind = FD_HOST_RO;
                f->host_fd = hfd;
                f->cached_size = (uint64_t)st.st_size;
                f->cached_mode = st.st_mode;
                return fd;
            }
            close(hfd);
        }
    }

    return -ENOENT;
}

int64_t vfs_read(dethv_vm_t *vm, int fd, void *buf, size_t count) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used) return -EBADF;
    vfd_t *f = &vm->vfs.fds[fd];

    switch (f->kind) {
        case FD_STDIN: {
            if (vm->vfs.stdin_pos >= vm->vfs.stdin_len) return 0;
            size_t avail = vm->vfs.stdin_len - vm->vfs.stdin_pos;
            size_t n = count < avail ? count : avail;
            memcpy(buf, vm->vfs.stdin_buf + vm->vfs.stdin_pos, n);
            vm->vfs.stdin_pos += n;
            return (int64_t)n;
        }
        case FD_DEV_NULL:
            return 0;
        case FD_DEV_ZERO:
            memset(buf, 0, count);
            return (int64_t)count;
        case FD_DEV_URANDOM:
            det_rand_bytes(&vm->det, buf, count);
            vm->det.getrandom_count++;
            return (int64_t)count;
        case FD_PROC_VFILE:
        case FD_MEM_VFILE: {
            vm->vfs.vfiles_dirty = true;
            vfile_t *vf = &vm->vfs.vfiles[f->ref_idx];
            if (f->offset >= vf->len) return 0;
            size_t avail = vf->len - (size_t)f->offset;
            size_t n = count < avail ? count : avail;
            memcpy(buf, vf->data + f->offset, n);
            f->offset += n;
            return (int64_t)n;
        }
        case FD_HOST_RO: {
            if (f->host_fd < 0) return -EBADF;
            ssize_t n = pread(f->host_fd, buf, count, (off_t)f->offset);
            if (n < 0) return -errno;
            f->offset += (uint64_t)n;
            return (int64_t)n;
        }
        case FD_PIPE_READ: {
            vm->vfs.pipes_dirty = true;
            vpipe_t *p = &vm->vfs.pipes[f->ref_idx];
            if (p->count == 0) {
                if (p->write_closed) return 0;
                return -EAGAIN;
            }
            size_t n = count < p->count ? count : p->count;
            uint8_t *dst = (uint8_t *)buf;
            for (size_t i = 0; i < n; i++) {
                dst[i] = p->buf[p->read_pos];
                p->read_pos = (p->read_pos + 1) % DETHV_PIPE_BUF_SIZE;
                p->count--;
            }
            return (int64_t)n;
        }
        case FD_EVENTFD: {
            if (count < 8) return -EINVAL;
            if (f->eventfd_val == 0) return -EAGAIN;
            uint64_t v = f->eventfd_val;
            f->eventfd_val = 0;
            memcpy(buf, &v, 8);
            return 8;
        }
        default:
            return -EBADF;
    }
}

int64_t vfs_pread(dethv_vm_t *vm, int fd, void *buf, size_t count, int64_t off) {
    if (off < 0) return -EINVAL;
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used) return -EBADF;
    vfd_t *f = &vm->vfs.fds[fd];
    uint64_t saved = f->offset;
    f->offset = (uint64_t)off;
    int64_t r = vfs_read(vm, fd, buf, count);
    f->offset = saved;
    return r;
}

int64_t vfs_write(dethv_vm_t *vm, int fd, const void *buf, size_t count) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used) return -EBADF;
    vfd_t *f = &vm->vfs.fds[fd];

    switch (f->kind) {
        case FD_STDOUT: {
            if (!vm->cfg.capture_output) {
                ssize_t w = write(STDOUT_FILENO, buf, count);
                (void)w;
            }
            size_t space = DETHV_OUT_CAP - vm->vfs.stdout_len;
            size_t copy = count < space ? count : space;
            if (copy > 0) {
                memcpy(vm->vfs.stdout_buf + vm->vfs.stdout_len, buf, copy);
                vm->vfs.stdout_len += copy;
            }
            return (int64_t)count;
        }
        case FD_STDERR: {
            if (!vm->cfg.capture_output) {
                ssize_t w = write(STDERR_FILENO, buf, count);
                (void)w;
            }
            size_t space = DETHV_OUT_CAP - vm->vfs.stderr_len;
            size_t copy = count < space ? count : space;
            if (copy > 0) {
                memcpy(vm->vfs.stderr_buf + vm->vfs.stderr_len, buf, copy);
                vm->vfs.stderr_len += copy;
            }
            return (int64_t)count;
        }
        case FD_DEV_NULL:
        case FD_DEV_ZERO:
        case FD_DEV_URANDOM:
            return (int64_t)count;
        case FD_MEM_VFILE: {
            vm->vfs.vfiles_dirty = true;
            vfile_t *vf = &vm->vfs.vfiles[f->ref_idx];
            if (f->flags & O_APPEND) f->offset = vf->len;
            size_t end = (size_t)f->offset + count;
            if (end > 16 * 1024 * 1024) return -EFBIG;
            if (end > vf->cap) {
                size_t ncap = vf->cap ? vf->cap * 2 : 4096;
                while (ncap < end) ncap *= 2;
                uint8_t *nb = realloc(vf->data, ncap);
                if (!nb) return -ENOSPC;
                if (ncap > vf->cap) memset(nb + vf->cap, 0, ncap - vf->cap);
                vf->data = nb;
                vf->cap = ncap;
            }
            memcpy(vf->data + f->offset, buf, count);
            f->offset += count;
            if (f->offset > vf->len) vf->len = (size_t)f->offset;
            f->cached_size = vf->len;
            return (int64_t)count;
        }
        case FD_PIPE_WRITE: {
            vm->vfs.pipes_dirty = true;
            vpipe_t *p = &vm->vfs.pipes[f->ref_idx];
            if (p->read_closed) return -EPIPE;
            size_t space = DETHV_PIPE_BUF_SIZE - p->count;
            if (space == 0) return -EAGAIN;
            size_t n = count < space ? count : space;
            const uint8_t *src = (const uint8_t *)buf;
            for (size_t i = 0; i < n; i++) {
                p->buf[p->write_pos] = src[i];
                p->write_pos = (p->write_pos + 1) % DETHV_PIPE_BUF_SIZE;
                p->count++;
            }
            return (int64_t)n;
        }
        case FD_EVENTFD: {
            if (count < 8) return -EINVAL;
            uint64_t v = 0;
            memcpy(&v, buf, 8);
            f->eventfd_val += v;
            return 8;
        }
        default:
            return -EBADF;
    }
}

int64_t vfs_lseek(dethv_vm_t *vm, int fd, int64_t off, int whence) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used) return -EBADF;
    vfd_t *f = &vm->vfs.fds[fd];
    if (f->kind == FD_PIPE_READ || f->kind == FD_PIPE_WRITE ||
        f->kind == FD_STDIN || f->kind == FD_STDOUT || f->kind == FD_STDERR)
        return -ESPIPE;

    int64_t size = (int64_t)f->cached_size;
    if (f->kind == FD_MEM_VFILE || f->kind == FD_PROC_VFILE)
        size = (int64_t)vm->vfs.vfiles[f->ref_idx].len;

    int64_t npos = 0;
    if (whence == SEEK_SET) npos = off;
    else if (whence == SEEK_CUR) npos = (int64_t)f->offset + off;
    else if (whence == SEEK_END) npos = size + off;
    else return -EINVAL;

    if (npos < 0) return -EINVAL;
    f->offset = (uint64_t)npos;
    return npos;
}

int vfs_close(dethv_vm_t *vm, int fd) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used) return -EBADF;
    vfd_t *f = &vm->vfs.fds[fd];
    vm->vfs.fds_dirty = true;
    if (f->host_fd >= 0) {
        close(f->host_fd);
        f->host_fd = -1;
    }
    if (f->kind == FD_PIPE_READ)  { vm->vfs.pipes[f->ref_idx].read_closed = true;  vm->vfs.pipes_dirty = true; }
    if (f->kind == FD_PIPE_WRITE) { vm->vfs.pipes[f->ref_idx].write_closed = true; vm->vfs.pipes_dirty = true; }
    f->used = false;
    return 0;
}

int vfs_dup(dethv_vm_t *vm, int oldfd, int newfd, int flags, bool exact) {
    if (oldfd < 0 || oldfd >= DETHV_MAX_FDS || !vm->vfs.fds[oldfd].used) return -EBADF;
    vm->vfs.fds_dirty = true;
    int dst_fd;
    if (exact) {
        if (newfd < 0 || newfd >= DETHV_MAX_FDS) return -EBADF;
        if (newfd == oldfd) return newfd;
        if (vm->vfs.fds[newfd].used) vfs_close(vm, newfd);
        dst_fd = newfd;
    } else {
        dst_fd = alloc_fd(&vm->vfs, newfd >= 0 ? newfd : 0);
        if (dst_fd < 0) return dst_fd;
    }
    vm->vfs.fds[dst_fd] = vm->vfs.fds[oldfd];
    if (vm->vfs.fds[oldfd].host_fd >= 0) {
        vm->vfs.fds[dst_fd].host_fd = open(vm->vfs.fds[oldfd].path, O_RDONLY | O_CLOEXEC);
    }
    if (flags & O_CLOEXEC) vm->vfs.fds[dst_fd].flags |= O_CLOEXEC;
    return dst_fd;
}

int vfs_fstat(dethv_vm_t *vm, int fd, void *statbuf_out) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used) return -EBADF;
    vfd_t *f = &vm->vfs.fds[fd];
    struct stat st;

    switch (f->kind) {
        case FD_STDIN:
            fill_det_stat(&st, f->path, S_IFIFO | 0600, vm->vfs.stdin_len);
            break;
        case FD_STDOUT:
        case FD_STDERR:
            fill_det_stat(&st, f->path, S_IFIFO | 0600, 0);
            break;
        case FD_DEV_NULL:
        case FD_DEV_ZERO:
        case FD_DEV_URANDOM:
            fill_det_stat(&st, f->path, S_IFCHR | 0666, 0);
            break;
        case FD_PROC_VFILE:
        case FD_MEM_VFILE:
            fill_det_stat(&st, f->path, vm->vfs.vfiles[f->ref_idx].mode, vm->vfs.vfiles[f->ref_idx].len);
            break;
        case FD_HOST_RO:
            fill_det_stat(&st, f->path, f->cached_mode, f->cached_size);
            break;
        case FD_PIPE_READ:
        case FD_PIPE_WRITE:
        case FD_EVENTFD:
            fill_det_stat(&st, f->path, S_IFIFO | 0600, 0);
            break;
        default:
            return -EBADF;
    }
    memcpy(statbuf_out, &st, sizeof(st));
    return 0;
}

int vfs_stat_path(dethv_vm_t *vm, int dirfd, const char *path, void *statbuf_out, int flags) {
    if ((flags & AT_EMPTY_PATH) && path[0] == '\0') {
        return vfs_fstat(vm, dirfd, statbuf_out);
    }
    char full[256];
    resolve_path(&vm->vfs, dirfd, path, full, sizeof(full));

    struct stat st;
    if (strcmp(full, "/dev/urandom") == 0 || strcmp(full, "/dev/random") == 0 ||
        strcmp(full, "/dev/null") == 0 || strcmp(full, "/dev/zero") == 0) {
        fill_det_stat(&st, full, S_IFCHR | 0666, 0);
        memcpy(statbuf_out, &st, sizeof(st));
        return 0;
    }

    vfile_t *vf = find_vfile(&vm->vfs, full);
    if (vf) {
        fill_det_stat(&st, full, vf->mode, vf->len);
        memcpy(statbuf_out, &st, sizeof(st));
        return 0;
    }

    char pbuf[4096];
    size_t plen = 0;
    if (generate_proc_file(vm, full, pbuf, sizeof(pbuf), &plen)) {
        fill_det_stat(&st, full, S_IFREG | 0444, plen);
        memcpy(statbuf_out, &st, sizeof(st));
        return 0;
    }

    if (vm->cfg.allow_host_ro) {
        struct stat hst;
        int rc = (flags & AT_SYMLINK_NOFOLLOW) ? lstat(full, &hst) : stat(full, &hst);
        if (rc == 0) {
            fill_det_stat(&st, full, hst.st_mode, (uint64_t)hst.st_size);
            memcpy(statbuf_out, &st, sizeof(st));
            return 0;
        }
    }
    return -ENOENT;
}

int vfs_pipe(dethv_vm_t *vm, int fds_out[2], int flags) {
    vm->vfs.fds_dirty = true;
    vm->vfs.pipes_dirty = true;
    int p_idx = -1;
    for (int i = 0; i < DETHV_MAX_PIPES; i++) {
        if (!vm->vfs.pipes[i].used) { p_idx = i; break; }
    }
    if (p_idx < 0) return -EMFILE;

    int rfd = alloc_fd(&vm->vfs, 0);
    if (rfd < 0) return rfd;
    vm->vfs.fds[rfd].used = true;
    int wfd = alloc_fd(&vm->vfs, rfd + 1);
    if (wfd < 0) { vm->vfs.fds[rfd].used = false; return wfd; }

    memset(&vm->vfs.pipes[p_idx], 0, sizeof(vpipe_t));
    vm->vfs.pipes[p_idx].used = true;

    vm->vfs.fds[rfd] = (vfd_t){ .used = true, .kind = FD_PIPE_READ,  .flags = flags, .host_fd = -1, .ref_idx = (uint32_t)p_idx, .path = "pipe:[r]" };
    vm->vfs.fds[wfd] = (vfd_t){ .used = true, .kind = FD_PIPE_WRITE, .flags = flags, .host_fd = -1, .ref_idx = (uint32_t)p_idx, .path = "pipe:[w]" };
    fds_out[0] = rfd;
    fds_out[1] = wfd;
    return 0;
}

int vfs_eventfd(dethv_vm_t *vm, uint64_t initval, int flags) {
    vm->vfs.fds_dirty = true;
    int fd = alloc_fd(&vm->vfs, 0);
    if (fd < 0) return fd;
    vm->vfs.fds[fd] = (vfd_t){
        .used = true, .kind = FD_EVENTFD, .flags = flags,
        .host_fd = -1, .eventfd_val = initval, .path = "anon_inode:[eventfd]"
    };
    return fd;
}
