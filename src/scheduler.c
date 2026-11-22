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
    for (int i = 0; i < DETHV_MAX_THREADS; i++) {
        if (sc->threads[i].state == THREAD_RUNNABLE) n++;
    }
    return n;
}

int sched_num_alive(const sched_state_t *sc) {
    int n = 0;
    for (int i = 0; i < DETHV_MAX_THREADS; i++) {
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

/* Arm or disarm AMD ExRetCond zero-skid PMU preemption before KVM_RUN */
void sched_prepare_pmu(dethv_vm_t *vm) {
    int runnable = sched_num_runnable(&vm->sched);
    if (!vm->pmu_available || runnable <= 1 || vm->cfg.preempt_quantum == 0) {
        vm->shared->pmu_armed = 0;
        vm->shared->pmu_in_landing = 0;
        return;
    }

    guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];
    if (cur->branch_budget <= DETHV_PMU_SLACK) {
        cur->branch_budget = vm->cfg.preempt_quantum;
    }

    if (vm->shared->pmu_in_landing) {
        /* Resuming an interrupted landing phase (e.g. after demand #PF or patched #BP) */
        vm->shared->pmu_armed = 1;
        return;
    }

    uint64_t pmi_dist = cur->branch_budget - DETHV_PMU_SLACK;
    /* 48-bit negative count so overflow triggers LAPIC PMI after pmi_dist branches */
    uint64_t init_ctr = ((1ULL << 48) - pmi_dist) & ((1ULL << 48) - 1);
    vm->shared->pmu_init_ctr   = init_ctr;
    vm->shared->pmu_exit_ctr   = init_ctr;
    vm->shared->pmu_slack      = DETHV_PMU_SLACK;
    vm->shared->pmu_in_landing = 0;
    vm->shared->pmu_armed      = 1;
    vm->lapic_touched          = true;
}

/* Account retired conditional branches after SYSCALL or exception exit */
void sched_account_pmu(dethv_vm_t *vm) {
    if (!vm->shared->pmu_armed) return;
    guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];

    uint64_t elapsed = 0;
    if (vm->shared->pmu_exit_ctr == UINT64_MAX) {
        /* Exited during landing phase! */
        uint64_t pmi_dist = (cur->branch_budget > DETHV_PMU_SLACK)
                            ? (cur->branch_budget - DETHV_PMU_SLACK) : 0;
        uint64_t landed = (DETHV_PMU_SLACK > vm->shared->pmu_landing_rem)
                          ? (DETHV_PMU_SLACK - vm->shared->pmu_landing_rem) : 0;
        elapsed = pmi_dist + landed;
    } else {
        uint64_t mask = (1ULL << 48) - 1;
        elapsed = (vm->shared->pmu_exit_ctr - vm->shared->pmu_init_ctr) & mask;
        /* Guard against wrap if slightly over budget */
        if (elapsed > cur->branch_budget + DETHV_PMU_SLACK) {
            elapsed = cur->branch_budget;
        }
    }

    vm->det.total_branches += elapsed;
    if (elapsed >= cur->branch_budget) {
        cur->branch_budget = 0;
    } else {
        cur->branch_budget -= elapsed;
    }
}

/* Check and wake any sleeping/timed-out threads whose virtual wake time arrived */
static bool wake_expired_timers(dethv_vm_t *vm) {
    bool woke = false;
    uint64_t now = vm->det.vmono_ns;
    for (int i = 0; i < DETHV_MAX_THREADS; i++) {
        guest_thread_t *t = &vm->sched.threads[i];
        if ((t->state == THREAD_BLOCKED_SLEEP || t->state == THREAD_BLOCKED_FUTEX) &&
            t->has_timeout && now >= t->wake_time_ns) {
            t->pending_ret = (t->state == THREAD_BLOCKED_FUTEX) ? -ETIMEDOUT : 0;
            t->has_pending_ret = true;
            t->has_timeout = false;
            t->state = THREAD_RUNNABLE;
            t->branch_budget = vm->cfg.preempt_quantum;
            woke = true;
        }
    }
    return woke;
}

/* Deterministic round-robin switch to the next runnable thread */
bool sched_switch_next(dethv_vm_t *vm, bool current_yielded) {
    sched_state_t *sc = &vm->sched;
    int old_idx = sc->current_idx;
    guest_thread_t *old_t = &sc->threads[old_idx];

    /* Save outgoing thread state */
    sched_save_current(vm);
    if (current_yielded && old_t->state == THREAD_RUNNABLE) {
        old_t->branch_budget = vm->cfg.preempt_quantum;
    }

    /* Reset any in-flight landing state when switching threads */
    vm->shared->pmu_in_landing = 0;

    /* First wake any threads whose virtual timer expired */
    wake_expired_timers(vm);

    /* Round-robin search strictly after old_idx for deterministic fairness! */
    int next_idx = -1;
    for (int step = 1; step <= DETHV_MAX_THREADS; step++) {
        int idx = (old_idx + step) % DETHV_MAX_THREADS;
        if (sc->threads[idx].state == THREAD_RUNNABLE) {
            next_idx = idx;
            break;
        }
    }

    /* If nobody is runnable right now, fast-forward deterministic virtual clock to earliest timer! */
    if (next_idx < 0) {
        uint64_t earliest = UINT64_MAX;
        for (int i = 0; i < DETHV_MAX_THREADS; i++) {
            guest_thread_t *t = &sc->threads[i];
            if ((t->state == THREAD_BLOCKED_SLEEP || t->state == THREAD_BLOCKED_FUTEX) &&
                t->has_timeout && t->wake_time_ns < earliest) {
                earliest = t->wake_time_ns;
            }
        }
        if (earliest != UINT64_MAX) {
            if (earliest > vm->det.vmono_ns) {
                uint64_t delta = earliest - vm->det.vmono_ns;
                det_advance_time(&vm->det, delta);
                vm->shared->vtsc += (delta * 25) / 10; /* ~2.5 GHz virtual TSC */
            }
            wake_expired_timers(vm);
            for (int step = 1; step <= DETHV_MAX_THREADS; step++) {
                int idx = (old_idx + step) % DETHV_MAX_THREADS;
                if (sc->threads[idx].state == THREAD_RUNNABLE) {
                    next_idx = idx;
                    break;
                }
            }
        }
    }

    if (next_idx < 0) {
        /* All alive threads deadlocked with no timers! */
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

    /* Snapshot parent's current FPU/SSE/AVX & regs */
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
    child->regs.rax      = 0; /* clone() returns 0 in child! */
    if (child_stack != 0) {
        child->regs.rsp  = child_stack;
    }
    child->xsave         = parent->xsave;
    child->fs_base       = (flags & CLONE_SETTLS) ? tls_val : parent->fs_base;
    child->gs_base       = parent->gs_base;
    child->sigmask       = parent->sigmask;
    child->branch_budget = vm->cfg.preempt_quantum;

    if (flags & CLONE_PARENT_SETTID) {
        mmu_copy_to_guest(vm, ptid_vaddr, &tid, sizeof(tid));
    }
    if (flags & CLONE_CHILD_SETTID) {
        mmu_copy_to_guest(vm, ctid_vaddr, &tid, sizeof(tid));
    }
    if (flags & CLONE_CHILD_CLEARTID) {
        child->clear_child_tid = ctid_vaddr;
    }

    return tid;
}

int sched_futex_wait(dethv_vm_t *vm, uint64_t uaddr, uint32_t val, uint32_t bitset,
                     bool has_timeout, uint64_t timeout_ns, bool abs_time) {
    uint32_t cur_val = 0;
    if (mmu_copy_from_guest(vm, &cur_val, uaddr, sizeof(cur_val)) < 0)
        return -EFAULT;
    if (cur_val != val)
        return -EAGAIN;

    guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];
    cur->state        = THREAD_BLOCKED_FUTEX;
    cur->futex_addr   = uaddr;
    cur->futex_bitset = bitset ? bitset : 0xFFFFFFFFU;
    cur->has_timeout  = has_timeout;
    if (has_timeout) {
        cur->wake_time_ns = abs_time ? timeout_ns : (vm->det.vmono_ns + timeout_ns);
    } else {
        cur->wake_time_ns = 0;
    }

    /* Switch to another runnable thread (or fast-forward to timeout) */
    sched_switch_next(vm, true);
    /* Return value was already written to new current thread's regs; caller must NOT overwrite RAX! */
    return 1; /* Special signal: switched threads */
}

int sched_futex_wake(dethv_vm_t *vm, uint64_t uaddr, int max_wake, uint32_t bitset) {
    if (max_wake <= 0) return 0;
    if (bitset == 0) bitset = 0xFFFFFFFFU;
    int woken = 0;

    /* Deterministic wake order: ascending slot index */
    for (int i = 0; i < DETHV_MAX_THREADS && woken < max_wake; i++) {
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
    for (int i = 0; i < DETHV_MAX_THREADS && requeued < nr_requeue; i++) {
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

bool sched_exit_current_thread(dethv_vm_t *vm, int exit_code) {
    guest_thread_t *cur = &vm->sched.threads[vm->sched.current_idx];

    /* Handle CLONE_CHILD_CLEARTID / set_tid_address (used by pthread_join!) */
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
