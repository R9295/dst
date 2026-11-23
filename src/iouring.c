/*
 * DetHV 100% Deterministic Virtual io_uring Implementation
 *
 * Implements io_uring_setup(425), io_uring_enter(426), io_uring_register(427)
 * and mmap() of IORING_OFF_SQ_RING / IORING_OFF_CQ_RING / IORING_OFF_SQES.
 *
 * Sets IORING_SQ_NEED_WAKEUP when IORING_SETUP_SQPOLL is requested so guest
 * code always submits synchronously via io_uring_enter(), executing every SQE
 * deterministically in-order against DetHV's in-memory VFS with zero host
 * kernel threads or non-deterministic async completions!
 */

#include "internal.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <linux/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>

static uint32_t next_pow2(uint32_t v) {
    if (v <= 1) return 1;
    v--;
    v |= v >> 1; v |= v >> 2; v |= v >> 4; v |= v >> 8; v |= v >> 16;
    return v + 1;
}

/* Read/write bytes from a ring's non-contiguous physical page list */
static void ring_read_bytes(const dethv_vm_t *vm, const uint64_t *pages, uint32_t npages,
                            size_t off, void *dst, size_t len) {
    uint8_t *dp = (uint8_t *)dst;
    while (len > 0) {
        uint32_t pg = (uint32_t)(off >> 12);
        size_t po = off & (PAGE_SIZE - 1);
        size_t chunk = PAGE_SIZE - po;
        if (chunk > len) chunk = len;
        if (pg < npages) {
            memcpy(dp, vm->mem + pages[pg] + po, chunk);
        }
        dp += chunk; off += chunk; len -= chunk;
    }
}

static void ring_write_bytes(dethv_vm_t *vm, const uint64_t *pages, uint32_t npages,
                             size_t off, const void *src, size_t len) {
    const uint8_t *sp = (const uint8_t *)src;
    while (len > 0) {
        uint32_t pg = (uint32_t)(off >> 12);
        size_t po = off & (PAGE_SIZE - 1);
        size_t chunk = PAGE_SIZE - po;
        if (chunk > len) chunk = len;
        if (pg < npages) {
            vmm_mark_phys_dirty(vm, pages[pg]);
            memcpy(vm->mem + pages[pg] + po, sp, chunk);
        }
        sp += chunk; off += chunk; len -= chunk;
    }
}

static uint32_t ring_read_u32(const dethv_vm_t *vm, const viouring_t *ur, size_t off) {
    uint32_t v = 0;
    ring_read_bytes(vm, ur->ring_phys, ur->ring_npages, off, &v, 4);
    return v;
}

static void ring_write_u32(dethv_vm_t *vm, const viouring_t *ur, size_t off, uint32_t v) {
    ring_write_bytes(vm, ur->ring_phys, ur->ring_npages, off, &v, 4);
}

int iouring_init(dethv_vm_t *vm) {
    vm->iourings = calloc(DETHV_MAX_IOURINGS, sizeof(viouring_t));
    return vm->iourings ? 0 : -1;
}

void iouring_free_array(viouring_t *arr) {
    if (!arr) return;
    for (int i = 0; i < DETHV_MAX_IOURINGS; i++) {
        free(arr[i].ring_phys);
        free(arr[i].sqe_phys);
    }
    free(arr);
}

void iouring_destroy(dethv_vm_t *vm) {
    iouring_free_array(vm->iourings);
    vm->iourings = NULL;
}

int iouring_clone(viouring_t **dst_out, const viouring_t *src) {
    if (!*dst_out) {
        *dst_out = calloc(DETHV_MAX_IOURINGS, sizeof(viouring_t));
        if (!*dst_out) return -1;
    }
    viouring_t *dst = *dst_out;
    for (int i = 0; i < DETHV_MAX_IOURINGS; i++) {
        free(dst[i].ring_phys); dst[i].ring_phys = NULL;
        free(dst[i].sqe_phys);  dst[i].sqe_phys  = NULL;
        dst[i].used = false;
        if (!src || !src[i].used) continue;
        dst[i] = src[i];
        dst[i].ring_phys = NULL;
        dst[i].sqe_phys  = NULL;
        if (src[i].ring_npages > 0 && src[i].ring_phys) {
            dst[i].ring_phys = malloc(src[i].ring_npages * sizeof(uint64_t));
            if (!dst[i].ring_phys) return -1;
            memcpy(dst[i].ring_phys, src[i].ring_phys, src[i].ring_npages * sizeof(uint64_t));
        }
        if (src[i].sqe_npages > 0 && src[i].sqe_phys) {
            dst[i].sqe_phys = malloc(src[i].sqe_npages * sizeof(uint64_t));
            if (!dst[i].sqe_phys) return -1;
            memcpy(dst[i].sqe_phys, src[i].sqe_phys, src[i].sqe_npages * sizeof(uint64_t));
        }
    }
    return 0;
}

int iouring_restore(dethv_vm_t *vm, const viouring_t *src) {
    int rc = iouring_clone(&vm->iourings, src);
    vm->iouring_dirty = false;
    return rc;
}

void iouring_close(dethv_vm_t *vm, uint32_t idx) {
    if (!vm->iourings || idx >= DETHV_MAX_IOURINGS) return;
    viouring_t *ur = &vm->iourings[idx];
    if (!ur->used) return;
    free(ur->ring_phys); ur->ring_phys = NULL;
    free(ur->sqe_phys);  ur->sqe_phys  = NULL;
    ur->used = false;
    vm->iouring_dirty = true;
}

/* Ring header fixed offsets inside single-mmap ring region */
#define UR_OFF_SQ_HEAD      0x00
#define UR_OFF_SQ_TAIL      0x04
#define UR_OFF_SQ_MASK      0x08
#define UR_OFF_SQ_ENTRIES   0x0C
#define UR_OFF_SQ_FLAGS     0x10
#define UR_OFF_SQ_DROPPED   0x14
#define UR_OFF_CQ_HEAD      0x18
#define UR_OFF_CQ_TAIL      0x1C
#define UR_OFF_CQ_MASK      0x20
#define UR_OFF_CQ_ENTRIES   0x24
#define UR_OFF_CQ_OVERFLOW  0x28
#define UR_OFF_CQ_FLAGS     0x2C
#define UR_OFF_SQ_ARRAY     0x40

int iouring_sys_setup(dethv_vm_t *vm, uint32_t entries, uint64_t params_guest) {
    if (entries == 0 || entries > 4096) return -EINVAL;
    struct io_uring_params p;
    if (mmu_copy_from_guest(vm, &p, params_guest, sizeof(p)) < 0) return -EFAULT;

    int idx = -1;
    for (int i = 0; i < DETHV_MAX_IOURINGS; i++) {
        if (!vm->iourings[i].used) { idx = i; break; }
    }
    if (idx < 0) return -ENOMEM;

    int fd = vfs_alloc_fd(&vm->vfs, 0);
    if (fd < 0) return fd;

    uint32_t sq_entries = next_pow2(entries);
    if (sq_entries > 4096) sq_entries = 4096;
    uint32_t cq_entries = (p.flags & IORING_SETUP_CQSIZE) && p.cq_entries > 0
                          ? next_pow2(p.cq_entries) : (sq_entries * 2);
    if (cq_entries < sq_entries) cq_entries = sq_entries;
    if (cq_entries > 8192) cq_entries = 8192;

    size_t sq_array_bytes = (size_t)sq_entries * sizeof(uint32_t);
    size_t cqes_off       = (UR_OFF_SQ_ARRAY + sq_array_bytes + 63) & ~63ULL;
    size_t ring_bytes     = PAGE_ALIGN_UP(cqes_off + (size_t)cq_entries * sizeof(struct io_uring_cqe));
    size_t sqes_bytes     = PAGE_ALIGN_UP((size_t)sq_entries * sizeof(struct io_uring_sqe));

    uint32_t ring_npages = (uint32_t)(ring_bytes / PAGE_SIZE);
    uint32_t sqe_npages  = (uint32_t)(sqes_bytes / PAGE_SIZE);

    viouring_t *ur = &vm->iourings[idx];
    memset(ur, 0, sizeof(*ur));
    ur->ring_phys = calloc(ring_npages, sizeof(uint64_t));
    ur->sqe_phys  = calloc(sqe_npages,  sizeof(uint64_t));
    if (!ur->ring_phys || !ur->sqe_phys) {
        free(ur->ring_phys); free(ur->sqe_phys);
        return -ENOMEM;
    }

    for (uint32_t i = 0; i < ring_npages; i++) {
        ur->ring_phys[i] = mmu_alloc_phys_page(vm);
        if (!ur->ring_phys[i]) { iouring_close(vm, (uint32_t)idx); return -ENOMEM; }
    }
    for (uint32_t i = 0; i < sqe_npages; i++) {
        ur->sqe_phys[i] = mmu_alloc_phys_page(vm);
        if (!ur->sqe_phys[i]) { iouring_close(vm, (uint32_t)idx); return -ENOMEM; }
    }

    ur->used        = true;
    ur->sq_entries  = sq_entries;
    ur->cq_entries  = cq_entries;
    ur->setup_flags = p.flags;
    ur->ring_npages = ring_npages;
    ur->sqe_npages  = sqe_npages;
    ur->cqes_off    = (uint32_t)cqes_off;

    /* Initialize ring metadata in shared guest physical pages */
    ring_write_u32(vm, ur, UR_OFF_SQ_HEAD,     0);
    ring_write_u32(vm, ur, UR_OFF_SQ_TAIL,     0);
    ring_write_u32(vm, ur, UR_OFF_SQ_MASK,     sq_entries - 1);
    ring_write_u32(vm, ur, UR_OFF_SQ_ENTRIES,  sq_entries);
    /* Always set IORING_SQ_NEED_WAKEUP when SQPOLL requested so guest calls io_uring_enter! */
    ring_write_u32(vm, ur, UR_OFF_SQ_FLAGS,    (p.flags & IORING_SETUP_SQPOLL) ? IORING_SQ_NEED_WAKEUP : 0);
    ring_write_u32(vm, ur, UR_OFF_SQ_DROPPED,  0);
    ring_write_u32(vm, ur, UR_OFF_CQ_HEAD,     0);
    ring_write_u32(vm, ur, UR_OFF_CQ_TAIL,     0);
    ring_write_u32(vm, ur, UR_OFF_CQ_MASK,     cq_entries - 1);
    ring_write_u32(vm, ur, UR_OFF_CQ_ENTRIES,  cq_entries);
    ring_write_u32(vm, ur, UR_OFF_CQ_OVERFLOW, 0);
    ring_write_u32(vm, ur, UR_OFF_CQ_FLAGS,    0);

    for (uint32_t i = 0; i < sq_entries; i++) {
        ring_write_u32(vm, ur, UR_OFF_SQ_ARRAY + (size_t)i * 4, i);
    }

    /* Populate struct io_uring_params for guest */
    p.sq_entries = sq_entries;
    p.cq_entries = cq_entries;
    p.features   = IORING_FEAT_SINGLE_MMAP |
                   IORING_FEAT_NODROP |
                   IORING_FEAT_SUBMIT_STABLE |
                   IORING_FEAT_RW_CUR_POS |
                   IORING_FEAT_SQPOLL_NONFIXED |
                   IORING_FEAT_EXT_ARG;
    p.sq_off.head         = UR_OFF_SQ_HEAD;
    p.sq_off.tail         = UR_OFF_SQ_TAIL;
    p.sq_off.ring_mask    = UR_OFF_SQ_MASK;
    p.sq_off.ring_entries = UR_OFF_SQ_ENTRIES;
    p.sq_off.flags        = UR_OFF_SQ_FLAGS;
    p.sq_off.dropped      = UR_OFF_SQ_DROPPED;
    p.sq_off.array        = UR_OFF_SQ_ARRAY;
    p.sq_off.resv1        = 0;
    p.sq_off.user_addr    = 0;

    p.cq_off.head         = UR_OFF_CQ_HEAD;
    p.cq_off.tail         = UR_OFF_CQ_TAIL;
    p.cq_off.ring_mask    = UR_OFF_CQ_MASK;
    p.cq_off.ring_entries = UR_OFF_CQ_ENTRIES;
    p.cq_off.overflow     = UR_OFF_CQ_OVERFLOW;
    p.cq_off.cqes         = (uint32_t)cqes_off;
    p.cq_off.flags        = UR_OFF_CQ_FLAGS;
    p.cq_off.resv1        = 0;
    p.cq_off.user_addr    = 0;

    if (mmu_copy_to_guest(vm, params_guest, &p, sizeof(p)) < 0) {
        iouring_close(vm, (uint32_t)idx);
        return -EFAULT;
    }

    vfd_t *f = &vm->vfs.fds[fd];
    memset(f, 0, sizeof(*f));
    f->used    = true;
    f->kind    = FD_IO_URING;
    f->flags   = O_RDWR | O_CLOEXEC;
    f->host_fd = -1;
    f->ref_idx = (uint32_t)idx;
    snprintf(f->path, sizeof(f->path), "anon_inode:[io_uring]");
    vm->vfs.fds_dirty = true;
    vm->iouring_dirty = true;
    return fd;
}

uint64_t iouring_mmap(dethv_vm_t *vm, int fd, uint64_t hint, size_t len, uint32_t prot, uint32_t flags, int64_t off) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_IO_URING)
        return (uint64_t)-EBADF;
    viouring_t *ur = &vm->iourings[vm->vfs.fds[fd].ref_idx];
    if (!ur->used) return (uint64_t)-EBADF;

    uint64_t *phys_list = NULL;
    uint32_t npages = 0;
    if ((uint64_t)off == IORING_OFF_SQ_RING || (uint64_t)off == IORING_OFF_CQ_RING) {
        phys_list = ur->ring_phys;
        npages    = ur->ring_npages;
    } else if ((uint64_t)off == IORING_OFF_SQES) {
        phys_list = ur->sqe_phys;
        npages    = ur->sqe_npages;
    } else {
        return (uint64_t)-EINVAL;
    }

    size_t aligned_len = PAGE_ALIGN_UP(len);
    uint64_t mapped = mmu_mmap_region(vm, hint, aligned_len, prot, flags, false);
    if ((int64_t)mapped < 0) return mapped;

    uint64_t pte_flags = PTE_P | PTE_U | PTE_W | PTE_NX;
    uint32_t map_pages = (uint32_t)(aligned_len / PAGE_SIZE);
    for (uint32_t i = 0; i < map_pages && i < npages; i++) {
        if (mmu_map_page(vm, mapped + (uint64_t)i * PAGE_SIZE, phys_list[i], pte_flags) < 0)
            return (uint64_t)-ENOMEM;
    }
    return mapped;
}

static int32_t execute_sqe(dethv_vm_t *vm, const struct io_uring_sqe *sqe) {
    switch (sqe->opcode) {
        case IORING_OP_NOP:
            return 0;

        case IORING_OP_OPENAT: {
            char path[512];
            if (mmu_read_cstring(vm, sqe->addr, path, sizeof(path)) < 0) return -EFAULT;
            return (int32_t)vfs_openat(vm, sqe->fd, path, (int)sqe->open_flags, sqe->len);
        }

        case IORING_OP_CLOSE:
            return (int32_t)vfs_close(vm, sqe->fd);

        case IORING_OP_UNLINKAT: {
            char path[512];
            if (mmu_read_cstring(vm, sqe->addr, path, sizeof(path)) < 0) return -EFAULT;
            return (int32_t)vfs_unlink(vm, sqe->fd, path, (int)sqe->unlink_flags);
        }

        case IORING_OP_MKDIRAT: {
            char path[512];
            if (mmu_read_cstring(vm, sqe->addr, path, sizeof(path)) < 0) return -EFAULT;
            return (int32_t)vfs_mkdir(vm, sqe->fd, path, sqe->len);
        }

        case IORING_OP_RENAMEAT: {
            char p1[512], p2[512];
            if (mmu_read_cstring(vm, sqe->addr, p1, sizeof(p1)) < 0 ||
                mmu_read_cstring(vm, sqe->addr2, p2, sizeof(p2)) < 0) return -EFAULT;
            return (int32_t)vfs_rename(vm, sqe->fd, p1, (int)sqe->len, p2);
        }

        case IORING_OP_READ:
        case IORING_OP_READ_FIXED: {
            size_t len = sqe->len;
            if (len == 0) return 0;
            if (len > 16 * 1024 * 1024) len = 16 * 1024 * 1024;
            uint8_t sbuf[4096];
            uint8_t *tmp = (len <= sizeof(sbuf)) ? sbuf : malloc(len);
            if (!tmp) return -ENOMEM;
            int64_t r = ((int64_t)sqe->off == -1)
                        ? vfs_read(vm, sqe->fd, tmp, len)
                        : vfs_pread(vm, sqe->fd, tmp, len, (int64_t)sqe->off);
            if (r > 0 && mmu_copy_to_guest(vm, sqe->addr, tmp, (size_t)r) < 0) r = -EFAULT;
            if (tmp != sbuf) free(tmp);
            return (int32_t)r;
        }

        case IORING_OP_WRITE:
        case IORING_OP_WRITE_FIXED: {
            size_t len = sqe->len;
            if (len == 0) return 0;
            if (len > 16 * 1024 * 1024) len = 16 * 1024 * 1024;
            uint8_t sbuf[4096];
            uint8_t *tmp = (len <= sizeof(sbuf)) ? sbuf : malloc(len);
            if (!tmp) return -ENOMEM;
            int64_t r;
            if (mmu_copy_from_guest(vm, tmp, sqe->addr, len) < 0) {
                r = -EFAULT;
            } else {
                r = ((int64_t)sqe->off == -1)
                    ? vfs_write(vm, sqe->fd, tmp, len)
                    : vfs_pwrite(vm, sqe->fd, tmp, len, (int64_t)sqe->off);
            }
            if (tmp != sbuf) free(tmp);
            return (int32_t)r;
        }

        case IORING_OP_FSYNC:
            if (sqe->fd >= 0 && sqe->fd < DETHV_MAX_FDS && vm->vfs.fds[sqe->fd].used &&
                vm->vfs.fds[sqe->fd].kind == FD_MEM_VFILE) {
                mmu_sync_vfile_from_vmas(vm, (int32_t)vm->vfs.fds[sqe->fd].ref_idx);
            }
            return 0;

        case IORING_OP_FALLOCATE:
            return 0;

#ifdef IORING_OP_FTRUNCATE
        case IORING_OP_FTRUNCATE:
            return (int32_t)vfs_ftruncate(vm, sqe->fd, (int64_t)sqe->off);
#endif

        case IORING_OP_STATX: {
            char path[512];
            struct stat st;
            if (mmu_read_cstring(vm, sqe->addr, path, sizeof(path)) < 0) return -EFAULT;
            int rc = vfs_stat_path(vm, sqe->fd, path, &st, (int)sqe->statx_flags);
            if (rc == 0) {
                struct statx sx;
                memset(&sx, 0, sizeof(sx));
                sx.stx_mask     = STATX_BASIC_STATS;
                sx.stx_blksize  = (uint32_t)st.st_blksize;
                sx.stx_nlink    = (uint32_t)st.st_nlink;
                sx.stx_uid      = st.st_uid;
                sx.stx_gid      = st.st_gid;
                sx.stx_mode     = (uint16_t)st.st_mode;
                sx.stx_ino      = st.st_ino;
                sx.stx_size     = (uint64_t)st.st_size;
                sx.stx_blocks   = (uint64_t)st.st_blocks;
                sx.stx_atime.tv_sec = st.st_atim.tv_sec;
                sx.stx_mtime.tv_sec = st.st_mtim.tv_sec;
                sx.stx_ctime.tv_sec = st.st_ctim.tv_sec;
                if (mmu_copy_to_guest(vm, sqe->off, &sx, sizeof(sx)) < 0) return -EFAULT;
            }
            return rc;
        }

        default:
            return -EOPNOTSUPP;
    }
}

int iouring_sys_enter(dethv_vm_t *vm, int fd, uint32_t to_submit, uint32_t min_complete, uint32_t flags) {
    (void)min_complete; (void)flags;
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_IO_URING)
        return -EBADF;
    viouring_t *ur = &vm->iourings[vm->vfs.fds[fd].ref_idx];
    if (!ur->used) return -EBADF;

    uint32_t sq_head = ring_read_u32(vm, ur, UR_OFF_SQ_HEAD);
    uint32_t sq_tail = ring_read_u32(vm, ur, UR_OFF_SQ_TAIL);
    uint32_t cq_tail = ring_read_u32(vm, ur, UR_OFF_CQ_TAIL);
    uint32_t sq_mask = ur->sq_entries - 1;
    uint32_t cq_mask = ur->cq_entries - 1;

    uint32_t submitted = 0;
    /* In SQPOLL mode, to_submit may be 0 while sq_tail > sq_head; always drain up to sq_tail! */
    uint32_t limit = (ur->setup_flags & IORING_SETUP_SQPOLL) ? (sq_tail - sq_head) : to_submit;

    while (submitted < limit && sq_head != sq_tail) {
        uint32_t slot = sq_head & sq_mask;
        uint32_t sqe_idx = (ur->setup_flags & IORING_SETUP_NO_SQARRAY)
                           ? slot
                           : ring_read_u32(vm, ur, UR_OFF_SQ_ARRAY + (size_t)slot * 4);
        sq_head++;
        submitted++;

        struct io_uring_sqe sqe;
        if (sqe_idx < ur->sq_entries) {
            ring_read_bytes(vm, ur->sqe_phys, ur->sqe_npages,
                            (size_t)sqe_idx * sizeof(sqe), &sqe, sizeof(sqe));
            int32_t res = execute_sqe(vm, &sqe);

            struct io_uring_cqe cqe = {
                .user_data = sqe.user_data,
                .res       = res,
                .flags     = 0
            };
            uint32_t cslot = cq_tail & cq_mask;
            ring_write_bytes(vm, ur->ring_phys, ur->ring_npages,
                             ur->cqes_off + (size_t)cslot * sizeof(cqe), &cqe, sizeof(cqe));
            cq_tail++;
        }
    }

    ring_write_u32(vm, ur, UR_OFF_SQ_HEAD, sq_head);
    ring_write_u32(vm, ur, UR_OFF_CQ_TAIL, cq_tail);
    return (int)submitted;
}

int iouring_sys_register(dethv_vm_t *vm, int fd, uint32_t opcode, uint64_t arg, uint32_t nr_args) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_IO_URING)
        return -EBADF;
    if (opcode == IORING_REGISTER_PROBE && arg != 0) {
        struct io_uring_probe probe;
        if (mmu_copy_from_guest(vm, &probe, arg, sizeof(probe)) < 0) return -EFAULT;
        probe.last_op = IORING_OP_LAST - 1;
        probe.ops_len = (uint8_t)(nr_args > 255 ? 255 : nr_args);
        mmu_copy_to_guest(vm, arg, &probe, sizeof(probe));
        for (uint32_t i = 0; i < nr_args && i < IORING_OP_LAST; i++) {
            struct io_uring_probe_op op = { .op = (uint8_t)i, .flags = IO_URING_OP_SUPPORTED };
            mmu_copy_to_guest(vm, arg + sizeof(probe) + (uint64_t)i * sizeof(op), &op, sizeof(op));
        }
        return 0;
    }
    /* Accept buffer registration, iowq_max_workers, etc. cleanly */
    return 0;
}
