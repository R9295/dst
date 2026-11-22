#include "internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#define DETHV_SNAP_MAGIC   0x53564844U /* "DHVS" */
#define DETHV_SNAP_VERSION 2U

static uint64_t g_next_snap_id = 1;

static void reset_host_dirty(dethv_vm_t *vm) {
    if (vm->host_dirty_overflow) {
        memset(vm->host_dirty_bitmap, 0, vm->host_dirty_bitmap_bytes);
    } else {
        for (uint32_t i = 0; i < vm->host_dirty_count; i++) {
            uint32_t gfn = vm->host_dirty_gfns[i];
            vm->host_dirty_bitmap[gfn >> 3] &= (uint8_t)~(1U << (gfn & 7));
        }
    }
    vm->host_dirty_count = 0;
    vm->host_dirty_overflow = false;
    vm->dirty_ring_overflow = false;
}

static int build_wpte_table(dethv_snapshot_t *snap, uint8_t *live_mem) {
    uint32_t cap = 1024;
    snap->wptes = malloc(cap * sizeof(snap_wpte_t));
    if (!snap->wptes) return -1;
    snap->num_wptes = 0;

    uint64_t pml4_off = snap->mmu.pml4_phys;
    if (pml4_off + PAGE_SIZE > snap->phys_used) return 0;
    uint64_t *pml4 = (uint64_t *)(snap->mem + pml4_off);

    for (uint64_t i4 = 0; i4 < 512; i4++) {
        if (!(pml4[i4] & PTE_P)) continue;
        uint64_t pdpt_off = pml4[i4] & PTE_ADDR_MASK;
        if (pdpt_off + PAGE_SIZE > snap->phys_used) continue;
        uint64_t *pdpt = (uint64_t *)(snap->mem + pdpt_off);

        for (uint64_t i3 = 0; i3 < 512; i3++) {
            if (!(pdpt[i3] & PTE_P) || (pdpt[i3] & PTE_PS)) continue;
            uint64_t pd_off = pdpt[i3] & PTE_ADDR_MASK;
            if (pd_off + PAGE_SIZE > snap->phys_used) continue;
            uint64_t *pd = (uint64_t *)(snap->mem + pd_off);

            for (uint64_t i2 = 0; i2 < 512; i2++) {
                if (!(pd[i2] & PTE_P) || (pd[i2] & PTE_PS)) continue;
                uint64_t pt_off = pd[i2] & PTE_ADDR_MASK;
                if (pt_off + PAGE_SIZE > snap->phys_used) continue;
                uint64_t *pt = (uint64_t *)(snap->mem + pt_off);

                for (uint64_t i1 = 0; i1 < 512; i1++) {
                    uint64_t e = pt[i1];
                    if ((e & (PTE_P | PTE_W)) != (PTE_P | PTE_W)) continue;
                    uint64_t pa = e & PTE_ADDR_MASK;
                    if (pa >= snap->phys_used || pa == GUEST_SHARED_PHYS) continue;

                    uint64_t pte_byte_off = pt_off + i1 * 8;
                    pt[i1] = e & ~PTE_D;
                    if (live_mem) {
                        *(uint64_t *)(live_mem + pte_byte_off) &= ~PTE_D;
                    }

                    if (snap->num_wptes >= cap) {
                        cap *= 2;
                        snap_wpte_t *nw = realloc(snap->wptes, cap * sizeof(snap_wpte_t));
                        if (!nw) return -1;
                        snap->wptes = nw;
                    }
                    snap->wptes[snap->num_wptes++] = (snap_wpte_t){
                        .pte_offset  = pte_byte_off,
                        .phys_offset = pa
                    };
                }
            }
        }
    }
    return 0;
}

dethv_snapshot_t *dethv_snapshot_take(dethv_vm_t *vm) {
    dethv_snapshot_t *snap = calloc(1, sizeof(dethv_snapshot_t));
    if (!snap) return NULL;

    snap->magic     = DETHV_SNAP_MAGIC;
    snap->version   = DETHV_SNAP_VERSION;
    snap->id        = g_next_snap_id++;
    snap->ram_size  = vm->ram_size;
    snap->phys_used = vm->mmu.next_phys;

    snap->mem = malloc(snap->phys_used);
    if (!snap->mem) { free(snap); return NULL; }
    memcpy(snap->mem, vm->mem, snap->phys_used);

    guest_shared_t *snap_shared = (guest_shared_t *)(snap->mem + GUEST_SHARED_PHYS);
    snap_shared->flush_tlb = 1;
    vm->shared->flush_tlb  = 1;

    if (ioctl(vm->vcpu_fd, KVM_GET_REGS, &snap->regs) < 0 ||
        ioctl(vm->vcpu_fd, KVM_GET_SREGS, &snap->sregs) < 0 ||
        ioctl(vm->vcpu_fd, KVM_GET_VCPU_EVENTS, &snap->events) < 0 ||
        ioctl(vm->vcpu_fd, KVM_GET_XSAVE, &snap->xsave) < 0 ||
        ioctl(vm->vcpu_fd, KVM_GET_XCRS, &snap->xcrs) < 0 ||
        ioctl(vm->vcpu_fd, KVM_GET_LAPIC, &snap->lapic) < 0) {
        perror("dethv_snapshot_take KVM_GET_*");
        dethv_snapshot_free(snap);
        return NULL;
    }

    snap->det             = vm->det;
    snap->mmu             = vm->mmu;
    snap->sched           = vm->sched;
    snap->syms            = vm->syms;
    snap->current_fs_base = vm->current_fs_base;

    if (x86_patch_clone(&snap->patches, &vm->patches) < 0) {
        dethv_snapshot_free(snap);
        return NULL;
    }

    for (int i = 0; i < DETHV_MAX_FDS; i++) snap->vfs.fds[i].host_fd = -1;
    if (vfs_clone(&snap->vfs, &vm->vfs) < 0) {
        dethv_snapshot_free(snap);
        return NULL;
    }

    if (build_wpte_table(snap, vm->mem) < 0) {
        dethv_snapshot_free(snap);
        return NULL;
    }

    reset_host_dirty(vm);
    vm->loaded_snap_id  = snap->id;
    vm->snap_phys_floor = snap->phys_used;
    vm->phys_free_count = 0;
    vm->lapic_touched   = false;
    vm->sregs_changed_since_snap = false;
    vm->vfs.fds_dirty    = false;
    vm->vfs.pipes_dirty  = false;
    vm->vfs.vfiles_dirty = false;
    vm->vfs.cwd_dirty    = false;
    vm->sched.sigactions_dirty = false;

    return snap;
}

int dethv_snapshot_restore(dethv_vm_t *vm, const dethv_snapshot_t *snap) {
    if (!vm || !snap || snap->magic != DETHV_SNAP_MAGIC) return -1;
    if (snap->phys_used > vm->ram_size) return -1;

    uint64_t dirty_pages = 0;
    bool fast_path = (vm->loaded_snap_id == snap->id &&
                      snap->wptes != NULL &&
                      !vm->host_dirty_overflow);

    if (fast_path) {
        const snap_wpte_t *wptes = snap->wptes;
        uint32_t nw = snap->num_wptes;
        uint8_t *live = vm->mem;
        const uint8_t *base = snap->mem;
        for (uint32_t i = 0; i < nw; i++) {
            uint64_t *pte = (uint64_t *)(live + wptes[i].pte_offset);
            if (*pte & PTE_D) {
                *pte &= ~PTE_D;
                uint64_t poff = wptes[i].phys_offset;
                memcpy(live + poff, base + poff, PAGE_SIZE);
                dirty_pages++;
            }
        }

        for (uint32_t i = 0; i < vm->host_dirty_count; i++) {
            uint64_t gfn = vm->host_dirty_gfns[i];
            uint64_t off = gfn * PAGE_SIZE;
            if (off < snap->phys_used) {
                size_t sz = (off + PAGE_SIZE <= snap->phys_used) ? PAGE_SIZE : (snap->phys_used - off);
                memcpy(live + off, base + off, sz);
            } else if (off < vm->ram_size) {
                memset(live + off, 0, PAGE_SIZE);
            }
            vm->host_dirty_bitmap[gfn >> 3] &= (uint8_t)~(1U << (gfn & 7));
        }
        dirty_pages += (uint64_t)vm->host_dirty_count;
        vm->host_dirty_count = 0;

        memcpy(live + GUEST_SHARED_PHYS, base + GUEST_SHARED_PHYS, sizeof(guest_shared_t));
        if (vm->mmu.next_phys > snap->phys_used) {
            memset(live + snap->phys_used, 0, vm->mmu.next_phys - snap->phys_used);
        }
        vm->phys_free_count = 0;

        vm->kvm_run->s.regs.regs   = snap->regs;
        vm->kvm_run->s.regs.events = snap->events;
        vm->kvm_run->kvm_valid_regs = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS | KVM_SYNC_X86_EVENTS;
        if (vm->sregs_changed_since_snap) {
            vm->kvm_run->s.regs.sregs = snap->sregs;
            vm->kvm_run->kvm_dirty_regs = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS | KVM_SYNC_X86_EVENTS;
            vm->sregs_changed_since_snap = false;
        } else {
            vm->kvm_run->kvm_dirty_regs = KVM_SYNC_X86_REGS | KVM_SYNC_X86_EVENTS;
        }

        if (ioctl(vm->vcpu_fd, KVM_SET_XSAVE, &snap->xsave) < 0) return -1;
        if (vm->lapic_touched) {
            ioctl(vm->vcpu_fd, KVM_SET_LAPIC, &snap->lapic);
            /* Force Ring-0 stub to cleanly disable/reprogram HW PERF_CTL0 if it was left running */
            vm->shared->pmu_hw_on = 1;
            vm->shared->pmu_need_prog = 1;
            vm->lapic_touched = false;
        }

        vm->det = snap->det;

        vm->mmu.pml4_phys    = snap->mmu.pml4_phys;
        vm->mmu.next_phys    = snap->mmu.next_phys;
        vm->mmu.ram_size     = snap->mmu.ram_size;
        vm->mmu.brk_start    = snap->mmu.brk_start;
        vm->mmu.brk_curr     = snap->mmu.brk_curr;
        vm->mmu.mmap_cursor  = snap->mmu.mmap_cursor;
        vm->mmu.stack_bottom = snap->mmu.stack_bottom;
        vm->mmu.stack_limit  = snap->mmu.stack_limit;
        vm->mmu.num_vmas     = snap->mmu.num_vmas;
        if (snap->mmu.num_vmas > 0) {
            memcpy(vm->mmu.vmas, snap->mmu.vmas, snap->mmu.num_vmas * sizeof(vma_t));
        }

        uint32_t slots = vm->sched.used_slots > snap->sched.used_slots
                         ? vm->sched.used_slots : snap->sched.used_slots;
        vm->sched.pid           = snap->sched.pid;
        vm->sched.next_tid      = snap->sched.next_tid;
        vm->sched.current_idx   = snap->sched.current_idx;
        vm->sched.total_spawned = snap->sched.total_spawned;
        vm->sched.used_slots    = snap->sched.used_slots;
        if (slots == 1) {
            guest_thread_t *dt = &vm->sched.threads[0];
            const guest_thread_t *st = &snap->sched.threads[0];
            dt->state            = st->state;
            dt->tid              = st->tid;
            dt->regs             = st->regs;
            dt->fs_base          = st->fs_base;
            dt->gs_base          = st->gs_base;
            dt->clear_child_tid  = st->clear_child_tid;
            dt->robust_list_head = st->robust_list_head;
            dt->robust_list_len  = st->robust_list_len;
            dt->sigmask          = st->sigmask;
            dt->branch_budget    = st->branch_budget;
            dt->futex_addr       = st->futex_addr;
            dt->futex_bitset     = st->futex_bitset;
            dt->wake_time_ns     = st->wake_time_ns;
            dt->has_timeout      = st->has_timeout;
            dt->io_waiting       = st->io_waiting;
            dt->io_timed_out     = st->io_timed_out;
            dt->pending_ret      = st->pending_ret;
            dt->has_pending_ret  = st->has_pending_ret;
        } else if (slots > 0) {
            memcpy(vm->sched.threads, snap->sched.threads, slots * sizeof(guest_thread_t));
        }
        if (vm->sched.sigactions_dirty) {
            memcpy(vm->sched.sigactions, snap->sched.sigactions, sizeof(snap->sched.sigactions));
            vm->sched.sigactions_dirty = false;
        }

        /* Restore compact patch entries (preserving coverage hit counter) */
        uint64_t saved_cov = vm->patches.cov_hits;
        if (vm->patches.count != snap->patches.count) {
            x86_patch_clone(&vm->patches, &snap->patches);
        } else if (snap->patches.count > 0) {
            memcpy(vm->patches.entries, snap->patches.entries, snap->patches.count * sizeof(patch_entry_t));
        }
        vm->patches.cov_hits = saved_cov > snap->patches.cov_hits ? saved_cov : snap->patches.cov_hits;

        vm->current_fs_base     = snap->current_fs_base;
        vm->fs_base_dirty       = false;
        vm->sregs_dirty         = false;
        vm->snap_on_stdin_armed = false;
        vm->snap_on_open_armed  = false;

        if (vfs_restore_fast(&vm->vfs, &snap->vfs) < 0) return -1;
    } else {
        memcpy(vm->mem, snap->mem, snap->phys_used);
        if (vm->mmu.next_phys > snap->phys_used) {
            memset(vm->mem + snap->phys_used, 0, vm->mmu.next_phys - snap->phys_used);
        }
        vm->shared->flush_tlb = 1;
        reset_host_dirty(vm);
        ioctl(vm->vcpu_fd, KVM_SET_XCRS, &snap->xcrs);
        ioctl(vm->vcpu_fd, KVM_SET_LAPIC, &snap->lapic);
        vm->loaded_snap_id  = snap->id;
        vm->snap_phys_floor = snap->phys_used;
        vm->phys_free_count = 0;
        vm->lapic_touched   = false;
        vm->sregs_changed_since_snap = false;
        dirty_pages = snap->phys_used / PAGE_SIZE;

        vm->kvm_run->s.regs.regs   = snap->regs;
        vm->kvm_run->s.regs.sregs  = snap->sregs;
        vm->kvm_run->s.regs.events = snap->events;
        vm->kvm_run->kvm_valid_regs = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS | KVM_SYNC_X86_EVENTS;
        vm->kvm_run->kvm_dirty_regs = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS | KVM_SYNC_X86_EVENTS;
        if (ioctl(vm->vcpu_fd, KVM_SET_XSAVE, &snap->xsave) < 0) return -1;

        vm->det             = snap->det;
        vm->mmu             = snap->mmu;
        vm->sched           = snap->sched;
        uint64_t saved_cov  = vm->patches.cov_hits;
        x86_patch_clone(&vm->patches, &snap->patches);
        if (saved_cov > vm->patches.cov_hits) vm->patches.cov_hits = saved_cov;
        vm->syms            = snap->syms;
        vm->current_fs_base = snap->current_fs_base;
        vm->fs_base_dirty   = true;
        vm->sregs_dirty     = false;
        vm->snap_on_stdin_armed = false;
        vm->snap_on_open_armed  = false;

        if (vfs_clone(&vm->vfs, &snap->vfs) < 0) return -1;
    }

    vm->last_dirty_pages = dirty_pages;
    return 0;
}

void dethv_snapshot_free(dethv_snapshot_t *snap) {
    if (!snap) return;
    vfs_destroy(&snap->vfs);
    x86_patch_destroy(&snap->patches);
    free(snap->wptes);
    free(snap->mem);
    free(snap);
}

/* ==================== Persistent Disk Snapshot Save / Load (.dhvs) ==================== */

static int write_all(FILE *fp, const void *buf, size_t n) {
    return (n == 0 || fwrite(buf, 1, n, fp) == n) ? 0 : -1;
}

static int read_all(FILE *fp, void *buf, size_t n) {
    return (n == 0 || fread(buf, 1, n, fp) == n) ? 0 : -1;
}

int dethv_snapshot_save_file(const dethv_snapshot_t *snap, const char *path) {
    FILE *fp = fopen(path, "wb");
    if (!fp) { perror("fopen snapshot save"); return -1; }

    if (write_all(fp, &snap->magic, sizeof(snap->magic)) ||
        write_all(fp, &snap->version, sizeof(snap->version)) ||
        write_all(fp, &snap->ram_size, sizeof(snap->ram_size)) ||
        write_all(fp, &snap->phys_used, sizeof(snap->phys_used)) ||
        write_all(fp, &snap->regs, sizeof(snap->regs)) ||
        write_all(fp, &snap->sregs, sizeof(snap->sregs)) ||
        write_all(fp, &snap->events, sizeof(snap->events)) ||
        write_all(fp, &snap->xsave, sizeof(snap->xsave)) ||
        write_all(fp, &snap->xcrs, sizeof(snap->xcrs)) ||
        write_all(fp, &snap->lapic, sizeof(snap->lapic)) ||
        write_all(fp, &snap->det, sizeof(snap->det)) ||
        write_all(fp, &snap->mmu, sizeof(snap->mmu)) ||
        write_all(fp, &snap->sched, sizeof(snap->sched)) ||
        write_all(fp, &snap->patches.count, sizeof(snap->patches.count)) ||
        write_all(fp, &snap->patches.cov_hits, sizeof(snap->patches.cov_hits)) ||
        write_all(fp, snap->patches.entries, snap->patches.count * sizeof(patch_entry_t)) ||
        write_all(fp, &snap->syms, sizeof(snap->syms)) ||
        write_all(fp, &snap->current_fs_base, sizeof(snap->current_fs_base))) {
        fclose(fp);
        return -1;
    }

    if (write_all(fp, &snap->vfs.max_fd_used, sizeof(snap->vfs.max_fd_used)) ||
        write_all(fp, snap->vfs.fds, snap->vfs.max_fd_used * sizeof(vfd_t)) ||
        write_all(fp, snap->vfs.cwd, sizeof(snap->vfs.cwd)) ||
        write_all(fp, snap->vfs.exe_path, sizeof(snap->vfs.exe_path)) ||
        write_all(fp, &snap->vfs.umask_val, sizeof(snap->vfs.umask_val)) ||
        write_all(fp, &snap->vfs.stdin_len, sizeof(snap->vfs.stdin_len)) ||
        write_all(fp, &snap->vfs.stdin_pos, sizeof(snap->vfs.stdin_pos)) ||
        write_all(fp, snap->vfs.stdin_buf, snap->vfs.stdin_len) ||
        write_all(fp, &snap->vfs.stdout_len, sizeof(snap->vfs.stdout_len)) ||
        write_all(fp, snap->vfs.stdout_buf, snap->vfs.stdout_len) ||
        write_all(fp, &snap->vfs.stderr_len, sizeof(snap->vfs.stderr_len)) ||
        write_all(fp, snap->vfs.stderr_buf, snap->vfs.stderr_len) ||
        write_all(fp, &snap->vfs.max_vfile_used, sizeof(snap->vfs.max_vfile_used))) {
        fclose(fp);
        return -1;
    }

    for (uint32_t i = 0; i < snap->vfs.max_vfile_used; i++) {
        const vfile_t *vf = &snap->vfs.vfiles[i];
        uint8_t used = vf->used ? 1 : 0;
        if (write_all(fp, &used, 1)) { fclose(fp); return -1; }
        if (used) {
            uint8_t is_dir = vf->is_dir ? 1 : 0;
            if (write_all(fp, &is_dir, 1) ||
                write_all(fp, vf->path, sizeof(vf->path)) ||
                write_all(fp, &vf->mode, sizeof(vf->mode)) ||
                write_all(fp, &vf->len, sizeof(vf->len)) ||
                write_all(fp, vf->data, vf->len)) {
                fclose(fp);
                return -1;
            }
        }
    }

    if (write_all(fp, snap->mem, snap->phys_used)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

dethv_snapshot_t *dethv_snapshot_load_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror("fopen snapshot load"); return NULL; }

    dethv_snapshot_t *snap = calloc(1, sizeof(dethv_snapshot_t));
    if (!snap) { fclose(fp); return NULL; }
    snap->id = g_next_snap_id++;

    if (read_all(fp, &snap->magic, sizeof(snap->magic)) ||
        read_all(fp, &snap->version, sizeof(snap->version)) ||
        snap->magic != DETHV_SNAP_MAGIC || snap->version != DETHV_SNAP_VERSION ||
        read_all(fp, &snap->ram_size, sizeof(snap->ram_size)) ||
        read_all(fp, &snap->phys_used, sizeof(snap->phys_used)) ||
        read_all(fp, &snap->regs, sizeof(snap->regs)) ||
        read_all(fp, &snap->sregs, sizeof(snap->sregs)) ||
        read_all(fp, &snap->events, sizeof(snap->events)) ||
        read_all(fp, &snap->xsave, sizeof(snap->xsave)) ||
        read_all(fp, &snap->xcrs, sizeof(snap->xcrs)) ||
        read_all(fp, &snap->lapic, sizeof(snap->lapic)) ||
        read_all(fp, &snap->det, sizeof(snap->det)) ||
        read_all(fp, &snap->mmu, sizeof(snap->mmu)) ||
        read_all(fp, &snap->sched, sizeof(snap->sched)) ||
        read_all(fp, &snap->patches.count, sizeof(snap->patches.count)) ||
        read_all(fp, &snap->patches.cov_hits, sizeof(snap->patches.cov_hits)) ||
        snap->patches.count > DETHV_MAX_PATCHES) {
        fclose(fp); dethv_snapshot_free(snap); return NULL;
    }

    snap->patches.cap = snap->patches.count < 1024 ? 1024 : snap->patches.count;
    snap->patches.entries = calloc(snap->patches.cap, sizeof(patch_entry_t));
    if (!snap->patches.entries ||
        read_all(fp, snap->patches.entries, snap->patches.count * sizeof(patch_entry_t)) ||
        read_all(fp, &snap->syms, sizeof(snap->syms)) ||
        read_all(fp, &snap->current_fs_base, sizeof(snap->current_fs_base))) {
        fclose(fp); dethv_snapshot_free(snap); return NULL;
    }
    x86_patch_rebuild_ht(&snap->patches);

    snap->vfs.pipes      = calloc(DETHV_MAX_PIPES,  sizeof(vpipe_t));
    snap->vfs.vfiles     = calloc(DETHV_MAX_VFILES, sizeof(vfile_t));
    snap->vfs.stdout_buf = calloc(1, DETHV_OUT_CAP);
    snap->vfs.stderr_buf = calloc(1, DETHV_OUT_CAP);
    if (!snap->vfs.pipes || !snap->vfs.vfiles || !snap->vfs.stdout_buf || !snap->vfs.stderr_buf) {
        fclose(fp); dethv_snapshot_free(snap); return NULL;
    }

    if (read_all(fp, &snap->vfs.max_fd_used, sizeof(snap->vfs.max_fd_used)) ||
        snap->vfs.max_fd_used > DETHV_MAX_FDS ||
        read_all(fp, snap->vfs.fds, snap->vfs.max_fd_used * sizeof(vfd_t)) ||
        read_all(fp, snap->vfs.cwd, sizeof(snap->vfs.cwd)) ||
        read_all(fp, snap->vfs.exe_path, sizeof(snap->vfs.exe_path)) ||
        read_all(fp, &snap->vfs.umask_val, sizeof(snap->vfs.umask_val)) ||
        read_all(fp, &snap->vfs.stdin_len, sizeof(snap->vfs.stdin_len)) ||
        read_all(fp, &snap->vfs.stdin_pos, sizeof(snap->vfs.stdin_pos))) {
        fclose(fp); dethv_snapshot_free(snap); return NULL;
    }
    for (int i = 0; i < DETHV_MAX_FDS; i++) snap->vfs.fds[i].host_fd = -1;

    if (snap->vfs.stdin_len > 0) {
        snap->vfs.stdin_buf = malloc(snap->vfs.stdin_len);
        snap->vfs.stdin_cap = snap->vfs.stdin_len;
        if (!snap->vfs.stdin_buf || read_all(fp, snap->vfs.stdin_buf, snap->vfs.stdin_len)) {
            fclose(fp); dethv_snapshot_free(snap); return NULL;
        }
    }
    if (read_all(fp, &snap->vfs.stdout_len, sizeof(snap->vfs.stdout_len)) ||
        snap->vfs.stdout_len > DETHV_OUT_CAP ||
        read_all(fp, snap->vfs.stdout_buf, snap->vfs.stdout_len) ||
        read_all(fp, &snap->vfs.stderr_len, sizeof(snap->vfs.stderr_len)) ||
        snap->vfs.stderr_len > DETHV_OUT_CAP ||
        read_all(fp, snap->vfs.stderr_buf, snap->vfs.stderr_len) ||
        read_all(fp, &snap->vfs.max_vfile_used, sizeof(snap->vfs.max_vfile_used)) ||
        snap->vfs.max_vfile_used > DETHV_MAX_VFILES) {
        fclose(fp); dethv_snapshot_free(snap); return NULL;
    }

    for (uint32_t i = 0; i < snap->vfs.max_vfile_used; i++) {
        uint8_t used = 0;
        if (read_all(fp, &used, 1)) { fclose(fp); dethv_snapshot_free(snap); return NULL; }
        if (used) {
            vfile_t *vf = &snap->vfs.vfiles[i];
            vf->used = true;
            uint8_t is_dir = 0;
            if (read_all(fp, &is_dir, 1) ||
                read_all(fp, vf->path, sizeof(vf->path)) ||
                read_all(fp, &vf->mode, sizeof(vf->mode)) ||
                read_all(fp, &vf->len, sizeof(vf->len))) {
                fclose(fp); dethv_snapshot_free(snap); return NULL;
            }
            vf->is_dir = (is_dir != 0);
            if (vf->len > 0) {
                vf->data = malloc(vf->len);
                vf->cap = vf->len;
                if (!vf->data || read_all(fp, vf->data, vf->len)) {
                    fclose(fp); dethv_snapshot_free(snap); return NULL;
                }
            }
        }
    }

    snap->mem = malloc(snap->phys_used);
    if (!snap->mem || read_all(fp, snap->mem, snap->phys_used)) {
        fclose(fp); dethv_snapshot_free(snap); return NULL;
    }

    if (build_wpte_table(snap, NULL) < 0) {
        fclose(fp); dethv_snapshot_free(snap); return NULL;
    }

    fclose(fp);
    return snap;
}

int dethv_cov_install_symbols(dethv_vm_t *vm, dethv_snapshot_t *snap) {
    int installed = 0;
    for (uint32_t i = 0; i < vm->syms.count; i++) {
        uint64_t addr = vm->syms.syms[i].addr;
        if (vm->syms.syms[i].size < 2) continue;
        if (addr == vm->shared->regs.rip) continue;
        uint64_t pte = 0;
        uint64_t pa = mmu_virt_to_phys(vm, addr, &pte);
        if (!pa || (pte & PTE_NX)) continue;
        if (x86_patch_find(&vm->patches, addr)) continue;
        if (x86_patch_add_bp(vm, addr, PATCH_COV_BP) == 0) {
            if (snap && pa < snap->phys_used) snap->mem[pa] = 0xCC;
            installed++;
        }
    }
    if (snap) {
        x86_patch_clone(&snap->patches, &vm->patches);
        vm->active_cov_snap = snap;
    }
    return installed;
}

uint64_t dethv_cov_get_count(const dethv_vm_t *vm) {
    return vm->patches.cov_hits;
}
