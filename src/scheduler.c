#include "internal.h"
#include <errno.h>
#include <linux/sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

void sched_init(dethv_vm_t *vm) {
    sched_state_t *sc = &vm->sched;
    memset(sc, 0, sizeof(*sc));
    sc->pid           = 1000;
    sc->next_tid      = 1001;
    sc->current_idx   = 0;
    sc->total_spawned = 1;
    sc->used_slots    = 1;

    guest_thread_t *t0 = &sc->threads[0];
    t0->state         = THREAD_RUNNABLE;
    t0->tid           = 1000;
    t0->xsave         = vm->initial_xsave;
    t0->branch_budget = vm->cfg.preempt_quantum;
}

int sched_num_runnable(const sched_state_t *sc) {
    int n = 0;
    for (uint32_t i = 0; i < sc->used_slots; i++) {
        if (sc->threads[i].state == THREAD_RUNNABLE) n++;
    }
    return n;
}

int sched_num_alive(const sched_state_t *sc) {
    int n = 0;
    for (uint32_t i = 0; i < sc->used_slots; i++) {
        if (sc->threads[i].state != THREAD_FREE && sc->threads[i].state != THREAD_EXITED)
            n++;
    }
    return n;
}

void sched_save_current(dethv_vm_t *vm) {
    guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];
    cur->regs = vm->shared->regs;
    cur->fs_base = vm->current_fs_base;
    ioctl(vm->vcpu_fd, KVM_GET_XSAVE, &cur->xsave);
}

void sched_load_current(dethv_vm_t *vm) {
    guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];
    vm->shared->regs = cur->regs;
    if (cur->has_pending_ret) {
        vm->shared->regs.rax = (uint64_t)cur->pending_ret;
        cur->has_pending_ret = false;
    }
    if (vm->current_fs_base != cur->fs_base) {
        vm->current_fs_base = cur->fs_base;
        vm->fs_base_dirty = true;
        vm->sregs_changed_since_snap = true;
    }
    ioctl(vm->vcpu_fd, KVM_SET_XSAVE, &cur->xsave);
}

void sched_prepare_pmu(dethv_vm_t *vm) {
    int runnable = sched_num_runnable(&vm->sched);
    if (!vm->pmu_available || runnable <= 1 || vm->cfg.preempt_quantum == 0) {
        vm->shared->pmu_armed = 0;
        vm->shared->pmu_in_landing = 0;
        vm->shared->pmu_need_prog = 0;
        return;
    }

    if (vm->shared->pmu_in_landing) {
        vm->shared->pmu_armed = 1;
        return;
    }

    /* Fast path: if already armed & running in HW for the current thread, ZERO reprogramming! */
    if (vm->shared->pmu_armed && vm->shared->pmu_hw_on && !vm->shared->pmu_need_prog) {
        return;
    }

    guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];
    if (cur->branch_budget <= DETHV_PMU_SLACK) {
        cur->branch_budget = vm->cfg.preempt_quantum;
    }

    uint64_t pmi_dist = cur->branch_budget - DETHV_PMU_SLACK;
    uint64_t init_ctr = ((1ULL << 48) - pmi_dist) & ((1ULL << 48) - 1);
    vm->shared->pmu_init_ctr   = init_ctr;
    vm->shared->pmu_exit_ctr   = init_ctr;
    vm->shared->pmu_slack      = DETHV_PMU_SLACK;
    vm->shared->pmu_in_landing = 0;
    vm->shared->pmu_armed      = 1;
    vm->shared->pmu_need_prog  = 1;
    vm->lapic_touched          = true;
}

void sched_account_pmu(dethv_vm_t *vm) {
    /* Only account on thread switches (avoids rdmsr/wrmsr on every same-thread syscall!) */
    (void)vm;
}

bool sched_wake_expired_timers(dethv_vm_t *vm) {
    bool woke = false;
    uint64_t now = vm->det.vmono_ns;
    bool timerfd_fired = (net_earliest_timer_ns(vm) <= now);

    for (uint32_t i = 0; i < vm->sched.used_slots; i++) {
        guest_thread_t *t = &vm->sched.threads[i];
        if ((t->state == THREAD_BLOCKED_SLEEP || t->state == THREAD_BLOCKED_FUTEX) &&
            t->has_timeout && now >= t->wake_time_ns) {
            t->pending_ret     = (t->state == THREAD_BLOCKED_FUTEX) ? -ETIMEDOUT : 0;
            t->has_pending_ret = true;
            t->has_timeout     = false;
            t->state           = THREAD_RUNNABLE;
            t->branch_budget   = vm->cfg.preempt_quantum;
            woke = true;
        } else if (t->state == THREAD_BLOCKED_IO) {
            if (t->has_timeout && now >= t->wake_time_ns) {
                t->io_timed_out  = true;
                t->has_timeout   = false;
                t->state         = THREAD_RUNNABLE;
                t->branch_budget = vm->cfg.preempt_quantum;
                woke = true;
            } else if (timerfd_fired) {
                t->state         = THREAD_RUNNABLE;
                t->branch_budget = vm->cfg.preempt_quantum;
                woke = true;
            }
        }
    }
    return woke;
}

bool sched_switch_next(dethv_vm_t *vm, bool current_yielded) {
    sched_state_t *sc = &vm->sched;
    int old_idx = sc->current_idx;
    guest_thread_t *old_t = &sc->threads[old_idx];

    sched_save_current(vm);
    if (current_yielded && old_t->state == THREAD_RUNNABLE) {
        old_t->branch_budget = vm->cfg.preempt_quantum;
    }
    /* Always cancel any in-progress #DB landing and force fresh PERF_CTR0
     * programming across every cooperative switch/yield so host PMI skid timing
     * can never leak a partially-consumed/overflowed counter into another thread! */
    vm->shared->pmu_in_landing = 0;
    vm->shared->pmu_need_prog  = 1;

    sched_wake_expired_timers(vm);

    uint32_t slots = sc->used_slots ? sc->used_slots : 1;
    int next_idx = -1;
    for (uint32_t step = 1; step <= slots; step++) {
        int idx = (int)(((uint32_t)old_idx + step) % slots);
        if (sc->threads[idx].state == THREAD_RUNNABLE) {
            next_idx = idx;
            break;
        }
    }

    if (next_idx < 0) {
        /* Fast-forward virtual clock deterministically to earliest timer across threads & timerfds! */
        uint64_t earliest = net_earliest_timer_ns(vm);
        for (uint32_t i = 0; i < slots; i++) {
            guest_thread_t *t = &sc->threads[i];
            if ((t->state == THREAD_BLOCKED_SLEEP ||
                 t->state == THREAD_BLOCKED_FUTEX ||
                 t->state == THREAD_BLOCKED_IO) &&
                t->has_timeout && t->wake_time_ns < earliest) {
                earliest = t->wake_time_ns;
            }
        }
        if (earliest != UINT64_MAX) {
            if (earliest > vm->det.vmono_ns) {
                uint64_t delta = earliest - vm->det.vmono_ns;
                det_advance_time(&vm->det, delta);
                vm->shared->vtsc += (delta * 25) / 10;
            }
            sched_wake_expired_timers(vm);
            for (uint32_t step = 1; step <= slots; step++) {
                int idx = (int)(((uint32_t)old_idx + step) % slots);
                if (sc->threads[idx].state == THREAD_RUNNABLE) {
                    next_idx = idx;
                    break;
                }
            }
        }
    }

    if (next_idx < 0) {
        vm->running = false;
        vm->stop_reason = (sched_num_alive(sc) == 0) ? DETHV_STOP_EXITED : DETHV_STOP_DEADLOCK;
        return false;
    }

    sc->current_idx = next_idx;
    if (next_idx != old_idx) {
        sched_load_current(vm);
    } else if (sc->threads[next_idx].has_pending_ret) {
        vm->shared->regs.rax = (uint64_t)sc->threads[next_idx].pending_ret;
        sc->threads[next_idx].has_pending_ret = false;
    }
    return true;
}

int sched_create_thread(dethv_vm_t *vm, uint64_t flags, uint64_t child_stack,
                        uint64_t ptid_vaddr, uint64_t ctid_vaddr, uint64_t tls_val) {
    sched_state_t *sc = &vm->sched;
    int slot = -1;
    for (int i = 0; i < DETHV_MAX_THREADS; i++) {
        if (sc->threads[i].state == THREAD_FREE || sc->threads[i].state == THREAD_EXITED) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return -EAGAIN;

    sched_save_current(vm);
    guest_thread_t *parent = &sc->threads[sc->current_idx];
    guest_thread_t *child  = &sc->threads[slot];

    int32_t tid = sc->next_tid++;
    sc->total_spawned++;
    if ((uint32_t)(slot + 1) > sc->used_slots) sc->used_slots = (uint32_t)(slot + 1);

    memset(child, 0, sizeof(*child));
    child->state         = THREAD_RUNNABLE;
    child->tid           = tid;
    child->regs          = parent->regs;
    child->regs.rax      = 0;
    if (child_stack != 0) child->regs.rsp = child_stack;
    child->xsave         = parent->xsave;
    child->fs_base       = (flags & CLONE_SETTLS) ? tls_val : parent->fs_base;
    child->gs_base       = parent->gs_base;
    child->sigmask       = parent->sigmask;
    child->branch_budget = vm->cfg.preempt_quantum;

    if (flags & CLONE_PARENT_SETTID)  mmu_copy_to_guest(vm, ptid_vaddr, &tid, sizeof(tid));
    if (flags & CLONE_CHILD_SETTID)   mmu_copy_to_guest(vm, ctid_vaddr, &tid, sizeof(tid));
    if (flags & CLONE_CHILD_CLEARTID) child->clear_child_tid = ctid_vaddr;

    return tid;
}

int sched_futex_wait(dethv_vm_t *vm, uint64_t uaddr, uint32_t val, uint32_t bitset,
                     bool has_timeout, uint64_t timeout_ns, bool abs_time) {
    uint32_t cur_val = 0;
    if (mmu_copy_from_guest(vm, &cur_val, uaddr, sizeof(cur_val)) < 0) return -EFAULT;
    if (cur_val != val) return -EAGAIN;

    guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];
    cur->state        = THREAD_BLOCKED_FUTEX;
    cur->futex_addr   = uaddr;
    cur->futex_bitset = bitset ? bitset : 0xFFFFFFFFU;
    cur->has_timeout  = has_timeout;
    cur->wake_time_ns = has_timeout ? (abs_time ? timeout_ns : (vm->det.vmono_ns + timeout_ns)) : 0;

    sched_switch_next(vm, true);
    return 1;
}

int sched_futex_wake(dethv_vm_t *vm, uint64_t uaddr, int max_wake, uint32_t bitset) {
    if (max_wake <= 0) return 0;
    if (bitset == 0) bitset = 0xFFFFFFFFU;
    int woken = 0;

    for (uint32_t i = 0; i < vm->sched.used_slots && woken < max_wake; i++) {
        guest_thread_t *t = &vm->sched.threads[i];
        if (t->state == THREAD_BLOCKED_FUTEX &&
            t->futex_addr == uaddr &&
            (t->futex_bitset & bitset) != 0) {
            t->state           = THREAD_RUNNABLE;
            t->has_timeout     = false;
            t->pending_ret     = 0;
            t->has_pending_ret = true;
            t->branch_budget   = vm->cfg.preempt_quantum;
            woken++;
        }
    }
    return woken;
}

int sched_futex_requeue(dethv_vm_t *vm, uint64_t uaddr, int nr_wake, int nr_requeue,
                        uint64_t uaddr2, bool check_val3, uint32_t val3) {
    if (check_val3) {
        uint32_t cur = 0;
        if (mmu_copy_from_guest(vm, &cur, uaddr, sizeof(cur)) < 0) return -EFAULT;
        if (cur != val3) return -EAGAIN;
    }
    int woken = sched_futex_wake(vm, uaddr, nr_wake, 0xFFFFFFFFU);
    int requeued = 0;
    for (uint32_t i = 0; i < vm->sched.used_slots && requeued < nr_requeue; i++) {
        guest_thread_t *t = &vm->sched.threads[i];
        if (t->state == THREAD_BLOCKED_FUTEX && t->futex_addr == uaddr) {
            t->futex_addr = uaddr2;
            requeued++;
        }
    }
    return woken + requeued;
}

void sched_sleep_current(dethv_vm_t *vm, uint64_t wake_time_ns) {
    guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];
    cur->state        = THREAD_BLOCKED_SLEEP;
    cur->has_timeout  = true;
    cur->wake_time_ns = wake_time_ns;
    sched_switch_next(vm, true);
}

/* Rewind RIP back 2 bytes to `syscall` and block until I/O event or timeout! */
void sched_block_io_current(dethv_vm_t *vm, bool has_timeout, uint64_t deadline_ns) {
    guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];
    vm->shared->regs.rip -= 2;
    cur->state = THREAD_BLOCKED_IO;
    if (!cur->io_waiting) {
        cur->io_waiting   = true;
        cur->io_timed_out = false;
        cur->has_timeout  = has_timeout;
        cur->wake_time_ns = has_timeout ? deadline_ns : 0;
    }
    sched_switch_next(vm, true);
}

bool sched_exit_current_thread(dethv_vm_t *vm, int exit_code) {
    guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];

    if (cur->clear_child_tid != 0) {
        int32_t zero = 0;
        mmu_copy_to_guest(vm, cur->clear_child_tid, &zero, sizeof(zero));
        sched_futex_wake(vm, cur->clear_child_tid, 1, 0xFFFFFFFFU);
        cur->clear_child_tid = 0;
    }

    cur->state = THREAD_EXITED;
    if (sched_num_alive(&vm->sched) == 0) {
        vm->exit_code   = exit_code;
        vm->stop_reason = DETHV_STOP_EXITED;
        vm->running     = false;
        return false;
    }

    return sched_switch_next(vm, true);
}
