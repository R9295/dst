#ifndef DETHV_GUEST_SHARED_H
#define DETHV_GUEST_SHARED_H

#ifndef __ASSEMBLER__
#include <stdint.h>
#endif

/* Fixed Ring-0 Guest Kernel Physical & Virtual Addresses */
#define GUEST_KERN_VIRT_OFFSET  0xFFFFFFFF80000000ULL
#define GUEST_STUB_PHYS         0x00010000ULL
#define GUEST_STUB_VADDR        (GUEST_KERN_VIRT_OFFSET + GUEST_STUB_PHYS)
#define GUEST_GDT_PHYS          0x00018000ULL
#define GUEST_GDT_VADDR         (GUEST_KERN_VIRT_OFFSET + GUEST_GDT_PHYS)
#define GUEST_TSS_PHYS          0x00018100ULL
#define GUEST_TSS_VADDR         (GUEST_KERN_VIRT_OFFSET + GUEST_TSS_PHYS)
#define GUEST_IDT_PHYS          0x00019000ULL
#define GUEST_IDT_VADDR         (GUEST_KERN_VIRT_OFFSET + GUEST_IDT_PHYS)
#define GUEST_SHARED_PHYS       0x0001A000ULL
#define GUEST_SHARED_VADDR      (GUEST_KERN_VIRT_OFFSET + GUEST_SHARED_PHYS)
#define GUEST_KSTACK_PHYS       0x0001C000ULL
#define GUEST_KSTACK_TOP_VADDR  (GUEST_KERN_VIRT_OFFSET + 0x00020000ULL)

#define GUEST_LAPIC_PHYS        0xFEE00000ULL
#define GUEST_LAPIC_VADDR       0xFFFFFFFFFEE00000ULL

#define GUEST_PHYS_ALLOC_START  0x00020000ULL

/* Segment Selectors (must match GDT & STAR MSR!)
 * Note for SYSCALL/SYSRET:
 *   STAR[47:32] = 0x0008 -> Kernel CS = 0x08, Kernel SS = 0x10
 *   STAR[63:48] = 0x0013 -> (User CS32=0x13, User SS=0x1b, User CS64=0x23)
 */
#define GDT_SEL_KCODE           0x08
#define GDT_SEL_KDATA           0x10
#define GDT_SEL_UDATA           0x1B  /* index 3, RPL 3 */
#define GDT_SEL_UCODE           0x23  /* index 4, RPL 3 */
#define GDT_SEL_TSS             0x28  /* index 5..6 */

/* Hypercall I/O port */
#define DETHV_HC_PORT           0xD0

/* Exit reasons written to guest_shared.exit_reason */
#define DETHV_EXIT_NONE         0
#define DETHV_EXIT_SYSCALL      1
#define DETHV_EXIT_EXCEPTION    2
#define DETHV_EXIT_PREEMPT      3
#define DETHV_EXIT_PANIC        4

/* PMU config */
#define DETHV_PMI_VECTOR        0xFE
#define DETHV_PMU_SLACK         1024  /* Safe margin above worst-case AMD Zen 4 tight-loop PMI skid */
#define DETHV_VTSC_STEP_RDTSC   100
#define DETHV_VTSC_STEP_SYSCALL 1000

/* Exact byte offsets in guest_shared_t (verified via _Static_assert) */
#define GS_OFF_RAX              0x00
#define GS_OFF_RBX              0x08
#define GS_OFF_RCX              0x10
#define GS_OFF_RDX              0x18
#define GS_OFF_RSI              0x20
#define GS_OFF_RDI              0x28
#define GS_OFF_RBP              0x30
#define GS_OFF_RSP              0x38
#define GS_OFF_R8               0x40
#define GS_OFF_R9               0x48
#define GS_OFF_R10              0x50
#define GS_OFF_R11              0x58
#define GS_OFF_R12              0x60
#define GS_OFF_R13              0x68
#define GS_OFF_R14              0x70
#define GS_OFF_R15              0x78
#define GS_OFF_RIP              0x80
#define GS_OFF_RFLAGS           0x88

#define GS_OFF_KERN_RSP         0x90
#define GS_OFF_EXIT_REASON      0x98
#define GS_OFF_EXC_VECTOR       0xA0
#define GS_OFF_EXC_ERRCODE      0xA8
#define GS_OFF_EXC_CR2          0xB0

#define GS_OFF_VTSC             0xB8
#define GS_OFF_RDTSC_TRAPS      0xC0

/* PMU zero-skid preemption state */
#define GS_OFF_PMU_ARMED        0xC8
#define GS_OFF_PMU_INIT_CTR     0xD0
#define GS_OFF_PMU_EXIT_CTR     0xD8
#define GS_OFF_PMU_SLACK        0xE0
#define GS_OFF_PMU_IN_LANDING   0xE8
#define GS_OFF_PMU_LANDING_REM  0xF0
#define GS_OFF_PMU_PREV_RIP     0xF8
#define GS_OFF_PMU_OVERSHOOTS   0x100
#define GS_OFF_PMU_LANDING_STEPS 0x108
#define GS_OFF_LAPIC_INIT_DONE  0x110
#define GS_OFF_PMU_CTL_PMI      0x118
#define GS_OFF_PMU_CTL_NO_PMI   0x120
#define GS_OFF_FLUSH_TLB        0x128
#define GS_OFF_PMU_NEED_PROG    0x130
#define GS_OFF_PMU_HW_ON        0x138

#ifndef __ASSEMBLER__

typedef struct {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t rflags;
} user_regs_t;

typedef struct {
    user_regs_t regs;            /* 0x00 .. 0x8F */

    uint64_t kern_rsp;           /* 0x90 */
    uint64_t exit_reason;        /* 0x98 */
    uint64_t exc_vector;         /* 0xA0 */
    uint64_t exc_errcode;        /* 0xA8 */
    uint64_t exc_cr2;            /* 0xB0 */

    uint64_t vtsc;               /* 0xB8 */
    uint64_t rdtsc_traps;        /* 0xC0 */

    uint64_t pmu_armed;          /* 0xC8 */
    uint64_t pmu_init_ctr;       /* 0xD0 */
    uint64_t pmu_exit_ctr;       /* 0xD8 */
    uint64_t pmu_slack;          /* 0xE0 */
    uint64_t pmu_in_landing;     /* 0xE8 */
    uint64_t pmu_landing_rem;    /* 0xF0 */
    uint64_t pmu_prev_rip;       /* 0xF8 */
    uint64_t pmu_overshoots;     /* 0x100 */
    uint64_t pmu_landing_steps;  /* 0x108 */
    uint64_t lapic_init_done;    /* 0x110 */
    uint64_t pmu_ctl_pmi;        /* 0x118 */
    uint64_t pmu_ctl_no_pmi;     /* 0x120 */
    uint64_t flush_tlb;          /* 0x128 */
    uint64_t pmu_need_prog;      /* 0x130: 1 = reprogram PERF_CTR0/CTL0 on next enter */
    uint64_t pmu_hw_on;          /* 0x138: 1 = PERF_CTL0 is currently enabled in HW */
} guest_shared_t;

#include <stddef.h>
_Static_assert(offsetof(guest_shared_t, regs.rax)        == GS_OFF_RAX, "RAX offset");
_Static_assert(offsetof(guest_shared_t, regs.rip)        == GS_OFF_RIP, "RIP offset");
_Static_assert(offsetof(guest_shared_t, regs.rflags)     == GS_OFF_RFLAGS, "RFLAGS offset");
_Static_assert(offsetof(guest_shared_t, kern_rsp)        == GS_OFF_KERN_RSP, "KERN_RSP offset");
_Static_assert(offsetof(guest_shared_t, exit_reason)     == GS_OFF_EXIT_REASON, "EXIT_REASON offset");
_Static_assert(offsetof(guest_shared_t, exc_cr2)         == GS_OFF_EXC_CR2, "EXC_CR2 offset");
_Static_assert(offsetof(guest_shared_t, vtsc)            == GS_OFF_VTSC, "VTSC offset");
_Static_assert(offsetof(guest_shared_t, pmu_armed)       == GS_OFF_PMU_ARMED, "PMU_ARMED offset");
_Static_assert(offsetof(guest_shared_t, pmu_ctl_no_pmi)  == GS_OFF_PMU_CTL_NO_PMI, "PMU_CTL_NO_PMI offset");
_Static_assert(offsetof(guest_shared_t, flush_tlb)       == GS_OFF_FLUSH_TLB, "FLUSH_TLB offset");
_Static_assert(offsetof(guest_shared_t, pmu_need_prog)   == GS_OFF_PMU_NEED_PROG, "PMU_NEED_PROG offset");
_Static_assert(offsetof(guest_shared_t, pmu_hw_on)       == GS_OFF_PMU_HW_ON, "PMU_HW_ON offset");

#endif /* !__ASSEMBLER__ */
#endif /* DETHV_GUEST_SHARED_H */
