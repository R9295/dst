/*
 * DetHV Ring-0 Guest Kernel Stub (x86_64)
 *
 * Loaded at GUEST_STUB_VADDR (0xFFFFFFFF80010000).
 * Shared state sits at GUEST_SHARED_VADDR (0xFFFFFFFF8001A000).
 *
 * Fixed entry-point offsets:
 *   +0x000: stub_enter_user   - Resume Ring-3 from guest_shared.regs
 *   +0x200: stub_syscall      - LSTAR SYSCALL entry -> HC_SYSCALL
 *   +0x400: stub_isr_pmi      - Vector 0xFE: AMD ExRetCond PMI -> start #DB landing
 *   +0x600: stub_isr_db       - Vector 1 (#DB): Zero-VMEXIT exact branch landing
 *   +0x900: stub_isr_gp       - Vector 13 (#GP): Fast Ring-0 RDTSC/RDTSCP emulation
 *   +0xB00: stub_isr_common   - Generic exception exit to VMM
 *   +0xE00: stub_isr_table    - 32 exception entry stubs (16 bytes each)
 */

#include "guest_shared.h"

.code64
.section .text

.macro LOAD_SHARED reg
    movabsq $GUEST_SHARED_VADDR, \reg
.endm

/* =========================================================================
 * +0x000: stub_enter_user
 * ========================================================================= */
.org 0x0000
.global stub_enter_user
stub_enter_user:
    LOAD_SHARED %rax
    movq GS_OFF_KERN_RSP(%rax), %rsp

    /* Fast Ring-0 hardware TLB flush (~30ns, ZERO VMEXITs on AMD NPT!) */
    cmpq $0, GS_OFF_FLUSH_TLB(%rax)
    je .Lno_tlb_flush
    movq $0, GS_OFF_FLUSH_TLB(%rax)
    movq %cr3, %rcx
    movq %rcx, %cr3
.Lno_tlb_flush:

    cmpq $0, GS_OFF_PMU_ARMED(%rax)
    je .Lno_pmu

    /* In exact landing phase: IF=0, TF=1 (counter already stopped on PMI!) */
    cmpq $0, GS_OFF_PMU_IN_LANDING(%rax)
    jne .Larm_landing

    /* Fast path: if PMU is already programmed & running in HW for this thread,
     * skip ALL wrmsr calls! (ExRetCond USR=1/OS=0 automatically froze in Ring 0!) */
    cmpq $0, GS_OFF_PMU_NEED_PROG(%rax)
    je .Lpmu_already_running

    movq $0, GS_OFF_PMU_NEED_PROG(%rax)
    movq %rax, %rbx

    /* One-time LAPIC init for LVT PERFMON -> vector 0xFE */
    cmpq $0, GS_OFF_LAPIC_INIT_DONE(%rbx)
    jne .Llapic_ready
    movabsq $GUEST_LAPIC_VADDR, %rdx
    movl $0x1FF, 0x0F0(%rdx)                /* LAPIC SVR */
    movl $DETHV_PMI_VECTOR, 0x340(%rdx)     /* LVT PERFMON */
    movq $1, GS_OFF_LAPIC_INIT_DONE(%rbx)
.Llapic_ready:
    /* Stop PERF_CTL0 only if currently enabled */
    cmpq $0, GS_OFF_PMU_HW_ON(%rbx)
    je .Lprog_ctr
    movl $0xC0010000, %ecx
    xorl %eax, %eax
    xorl %edx, %edx
    wrmsr
.Lprog_ctr:
    /* Program PERF_CTR0 = pmu_init_ctr (48-bit) */
    movl $0xC0010004, %ecx
    movl GS_OFF_PMU_INIT_CTR(%rbx), %eax
    movl GS_OFF_PMU_INIT_CTR+4(%rbx), %edx
    wrmsr

    /* Program PERF_CTL0 = pmu_ctl_pmi (ExRetCond, USR=1, OS=0, INT=1, EN=1) */
    movl $0xC0010000, %ecx
    movl GS_OFF_PMU_CTL_PMI(%rbx), %eax
    movl GS_OFF_PMU_CTL_PMI+4(%rbx), %edx
    wrmsr
    movq $1, GS_OFF_PMU_HW_ON(%rbx)
    movq %rbx, %rax

.Lpmu_already_running:
    /* Enable IF=1, TF=0 */
    orq  $0x200, GS_OFF_RFLAGS(%rax)
    andq $~0x100, GS_OFF_RFLAGS(%rax)
    jmp .Ldo_iret

.Larm_landing:
    /* Exact landing phase: IF=0, TF=1 */
    movq GS_OFF_RIP(%rax), %rcx
    movq %rcx, GS_OFF_PMU_PREV_RIP(%rax)
    andq $~0x200, GS_OFF_RFLAGS(%rax)
    orq  $0x100, GS_OFF_RFLAGS(%rax)
    jmp .Ldo_iret

.Lno_pmu:
    /* Turn off PERF_CTL0 ONLY if it was enabled in HW */
    cmpq $0, GS_OFF_PMU_HW_ON(%rax)
    je .Lno_pmu_flags
    movq %rax, %rbx
    movl $0xC0010000, %ecx
    xorl %eax, %eax
    xorl %edx, %edx
    wrmsr
    movq $0, GS_OFF_PMU_HW_ON(%rbx)
    movq %rbx, %rax
.Lno_pmu_flags:
    andq $~0x300, GS_OFF_RFLAGS(%rax)

.Ldo_iret:
    LOAD_SHARED %rax
    pushq $GDT_SEL_UDATA
    pushq GS_OFF_RSP(%rax)
    movq  GS_OFF_RFLAGS(%rax), %rcx
    orq   $0x2, %rcx
    pushq %rcx
    pushq $GDT_SEL_UCODE
    pushq GS_OFF_RIP(%rax)

    movq GS_OFF_RBX(%rax), %rbx
    movq GS_OFF_RCX(%rax), %rcx
    movq GS_OFF_RDX(%rax), %rdx
    movq GS_OFF_RSI(%rax), %rsi
    movq GS_OFF_RDI(%rax), %rdi
    movq GS_OFF_RBP(%rax), %rbp
    movq GS_OFF_R8(%rax),  %r8
    movq GS_OFF_R9(%rax),  %r9
    movq GS_OFF_R10(%rax), %r10
    movq GS_OFF_R11(%rax), %r11
    movq GS_OFF_R12(%rax), %r12
    movq GS_OFF_R13(%rax), %r13
    movq GS_OFF_R14(%rax), %r14
    movq GS_OFF_R15(%rax), %r15
    movq GS_OFF_RAX(%rax), %rax
    iretq

/* =========================================================================
 * +0x200: stub_syscall (LSTAR)
 * ========================================================================= */
.org 0x0200
.global stub_syscall
stub_syscall:
    swapgs
    movq %rsp, %gs:GS_OFF_RSP
    movq %gs:GS_OFF_KERN_RSP, %rsp
    movq %rax, %gs:GS_OFF_RAX
    movq %rbx, %gs:GS_OFF_RBX
    movq %rcx, %gs:GS_OFF_RCX
    movq %rcx, %gs:GS_OFF_RIP
    movq %rdx, %gs:GS_OFF_RDX
    movq %rsi, %gs:GS_OFF_RSI
    movq %rdi, %gs:GS_OFF_RDI
    movq %rbp, %gs:GS_OFF_RBP
    movq %r8,  %gs:GS_OFF_R8
    movq %r9,  %gs:GS_OFF_R9
    movq %r10, %gs:GS_OFF_R10
    movq %r11, %gs:GS_OFF_R11
    andq $~0x300, %r11
    movq %r11, %gs:GS_OFF_RFLAGS
    movq %r12, %gs:GS_OFF_R12
    movq %r13, %gs:GS_OFF_R13
    movq %r14, %gs:GS_OFF_R14
    movq %r15, %gs:GS_OFF_R15
    swapgs

    /* ZERO wrmsr/rdmsr on syscall! ExRetCond (USR=1, OS=0) automatically
     * froze on CPL 3->0 transition and resumes seamlessly on IRETQ! */
    LOAD_SHARED %rbx
    movq $DETHV_EXIT_SYSCALL, GS_OFF_EXIT_REASON(%rbx)
    movb $DETHV_EXIT_SYSCALL, %al
    outb %al, $DETHV_HC_PORT
    jmp stub_enter_user

/* =========================================================================
 * +0x400: stub_isr_pmi (Vector 0xFE - ExRetCond Overflow)
 * ========================================================================= */
.org 0x0400
.global stub_isr_pmi
stub_isr_pmi:
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx

    /* Stop PERF_CTL0 immediately */
    movl $0xC0010000, %ecx
    xorl %eax, %eax
    xorl %edx, %edx
    wrmsr

    LOAD_SHARED %rbx
    movq $0, GS_OFF_PMU_HW_ON(%rbx)

    /* LAPIC EOI & unmask LVT PERFMON (x86 LAPIC auto-masks on PMI) */
    movabsq $GUEST_LAPIC_VADDR, %rax
    movl $0, 0x0B0(%rax)
    movl $DETHV_PMI_VECTOR, 0x340(%rax)

    /* Read PERF_CTR0 */
    movl $0xC0010004, %ecx
    rdmsr
    shlq $32, %rdx
    orq  %rax, %rdx

    movq %rdx, GS_OFF_PMU_EXIT_CTR(%rbx)

    /* Guard against spurious pre-overflow PMI (bit 47 set) */
    btq  $47, %rdx
    jc .Lpmi_spurious

    movq GS_OFF_PMU_SLACK(%rbx), %rax
    cmpq %rax, %rdx
    jae .Lpmi_overshoot

    /* Exact remaining conditional branches = slack - ctr_after */
    subq %rdx, %rax
    movq %rax, GS_OFF_PMU_LANDING_REM(%rbx)
    movq $1, GS_OFF_PMU_IN_LANDING(%rbx)

    /* Stack: [rsp+0]=rdx, +8=rcx, +16=rbx, +24=rax, +32=RIP, +40=CS, +48=RFLAGS */
    movq 32(%rsp), %rcx
    movq %rcx, GS_OFF_PMU_PREV_RIP(%rbx)
    andq $~0x200, 48(%rsp)
    orq  $0x100, 48(%rsp)

    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    iretq

.Lpmi_spurious:
    /* Re-enable counter and continue */
    movl $0xC0010000, %ecx
    movl GS_OFF_PMU_CTL_PMI(%rbx), %eax
    movl GS_OFF_PMU_CTL_PMI+4(%rbx), %edx
    wrmsr
    movq $1, GS_OFF_PMU_HW_ON(%rbx)
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    iretq

.Lpmi_overshoot:
    incq GS_OFF_PMU_OVERSHOOTS(%rbx)
    movq $0, GS_OFF_PMU_IN_LANDING(%rbx)
    movq $0, GS_OFF_PMU_LANDING_REM(%rbx)
    andq $~0x300, 48(%rsp)
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    jmp .Ldo_preempt_exit

/* =========================================================================
 * +0x600: stub_isr_db (Vector 1 - #DB Zero-VMEXIT Exact Branch Landing)
 * ========================================================================= */
.org 0x0600
.global stub_isr_db
stub_isr_db:
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    /* Stack: [rsp+0]=rsi, +8=rdx, +16=rcx, +24=rbx, +32=rax,
     *        +40=RIP, +48=CS, +56=RFLAGS, +64=RSP, +72=SS */

    LOAD_SHARED %rbx
    cmpq $0, GS_OFF_PMU_IN_LANDING(%rbx)
    je .Ldb_not_landing

    incq GS_OFF_PMU_LANDING_STEPS(%rbx)

    /* Decode instruction at pmu_prev_rip to detect conditional branch */
    movq GS_OFF_PMU_PREV_RIP(%rbx), %rsi
    movl $15, %ecx
.Ldb_pfx_loop:
    movzbl (%rsi), %eax
    movl %eax, %edx
    andl $0xF0, %edx
    cmpl $0x40, %edx                        /* REX 0x40..0x4F */
    je .Ldb_skip_pfx
    cmpl $0x66, %eax
    je .Ldb_skip_pfx
    cmpl $0x67, %eax
    je .Ldb_skip_pfx
    cmpl $0x2E, %eax
    je .Ldb_skip_pfx
    cmpl $0x3E, %eax
    je .Ldb_skip_pfx
    cmpl $0x26, %eax
    je .Ldb_skip_pfx
    cmpl $0x36, %eax
    je .Ldb_skip_pfx
    cmpl $0x64, %eax
    je .Ldb_skip_pfx
    cmpl $0x65, %eax
    je .Ldb_skip_pfx
    cmpl $0xF0, %eax
    je .Ldb_skip_pfx
    cmpl $0xF2, %eax
    je .Ldb_skip_pfx
    cmpl $0xF3, %eax
    je .Ldb_skip_pfx
    jmp .Ldb_check_opcode

.Ldb_skip_pfx:
    incq %rsi
    decl %ecx
    jnz .Ldb_pfx_loop
    jmp .Ldb_not_branch

.Ldb_check_opcode:
    /* 0x70..0x7F: short jcc */
    movl %eax, %edx
    andl $0xF0, %edx
    cmpl $0x70, %edx
    je .Ldb_is_branch
    /* 0xE0..0xE3: loopne/loope/loop/jrcxz */
    cmpl $0xE0, %eax
    jb .Ldb_chk_0f
    cmpl $0xE3, %eax
    jbe .Ldb_is_branch
.Ldb_chk_0f:
    /* 0x0F 0x80..0x8F: near jcc */
    cmpl $0x0F, %eax
    jne .Ldb_not_branch
    movzbl 1(%rsi), %eax
    andl $0xF0, %eax
    cmpl $0x80, %eax
    je .Ldb_is_branch

.Ldb_not_branch:
    movq 40(%rsp), %rax                     /* new user RIP */
    movq %rax, GS_OFF_PMU_PREV_RIP(%rbx)
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    iretq

.Ldb_is_branch:
    decq GS_OFF_PMU_LANDING_REM(%rbx)
    jnz .Ldb_not_branch

    /* Exact deterministic branch quantum reached! */
    movq $0, GS_OFF_PMU_IN_LANDING(%rbx)
    andq $~0x300, 56(%rsp)                   /* Clear TF & IF in saved RFLAGS */
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    jmp .Ldo_preempt_exit

.Ldb_not_landing:
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    pushq $0
    pushq $1
    jmp stub_isr_common

.Ldo_preempt_exit:
    pushq %rax
    LOAD_SHARED %rax
    movq %rbx, GS_OFF_RBX(%rax)
    movq %rcx, GS_OFF_RCX(%rax)
    movq %rdx, GS_OFF_RDX(%rax)
    movq %rsi, GS_OFF_RSI(%rax)
    movq %rdi, GS_OFF_RDI(%rax)
    movq %rbp, GS_OFF_RBP(%rax)
    movq %r8,  GS_OFF_R8(%rax)
    movq %r9,  GS_OFF_R9(%rax)
    movq %r10, GS_OFF_R10(%rax)
    movq %r11, GS_OFF_R11(%rax)
    movq %r12, GS_OFF_R12(%rax)
    movq %r13, GS_OFF_R13(%rax)
    movq %r14, GS_OFF_R14(%rax)
    movq %r15, GS_OFF_R15(%rax)
    popq %rbx
    movq %rbx, GS_OFF_RAX(%rax)
    movq 0(%rsp), %rbx
    movq %rbx, GS_OFF_RIP(%rax)
    movq 16(%rsp), %rbx
    andq $~0x300, %rbx
    movq %rbx, GS_OFF_RFLAGS(%rax)
    movq 24(%rsp), %rbx
    movq %rbx, GS_OFF_RSP(%rax)
    movq $DETHV_EXIT_PREEMPT, GS_OFF_EXIT_REASON(%rax)
    movb $DETHV_EXIT_PREEMPT, %al
    outb %al, $DETHV_HC_PORT
    jmp stub_enter_user

/* =========================================================================
 * +0x900: stub_isr_gp (Vector 13 - #GP: Fast Ring-0 RDTSC / RDTSCP)
 * ========================================================================= */
.org 0x0900
.global stub_isr_gp
stub_isr_gp:
    /* Stack: [rsp+0]=errcode, +8=RIP, +16=CS, +24=RFLAGS, +32=RSP, +40=SS */
    cmpq $0, 0(%rsp)
    jne .Lgp_slow
    testq $3, 16(%rsp)
    jz .Lgp_slow

    pushq %rsi
    pushq %rbx
    movq 24(%rsp), %rsi
    cmpb $0x0F, (%rsi)
    jne .Lgp_not_tsc

    cmpb $0x31, 1(%rsi)
    je .Lgp_emul_rdtsc

    cmpb $0x01, 1(%rsi)
    jne .Lgp_not_tsc
    cmpb $0xF9, 2(%rsi)
    jne .Lgp_not_tsc

    /* Emulate RDTSCP (0F 01 F9) */
    LOAD_SHARED %rbx
    movq GS_OFF_VTSC(%rbx), %rax
    addq $DETHV_VTSC_STEP_RDTSC, %rax
    movq %rax, GS_OFF_VTSC(%rbx)
    incq GS_OFF_RDTSC_TRAPS(%rbx)
    movq %rax, %rdx
    shrq $32, %rdx
    movl %eax, %eax
    xorl %ecx, %ecx
    addq $3, 24(%rsp)
    movq 24(%rsp), %rsi
    movq %rsi, GS_OFF_PMU_PREV_RIP(%rbx)
    popq %rbx
    popq %rsi
    addq $8, %rsp
    iretq

.Lgp_emul_rdtsc:
    /* Emulate RDTSC (0F 31) */
    LOAD_SHARED %rbx
    movq GS_OFF_VTSC(%rbx), %rax
    addq $DETHV_VTSC_STEP_RDTSC, %rax
    movq %rax, GS_OFF_VTSC(%rbx)
    incq GS_OFF_RDTSC_TRAPS(%rbx)
    movq %rax, %rdx
    shrq $32, %rdx
    movl %eax, %eax
    addq $2, 24(%rsp)
    movq 24(%rsp), %rsi
    movq %rsi, GS_OFF_PMU_PREV_RIP(%rbx)
    popq %rbx
    popq %rsi
    addq $8, %rsp
    iretq

.Lgp_not_tsc:
    popq %rbx
    popq %rsi
.Lgp_slow:
    pushq $13
    jmp stub_isr_common

/* =========================================================================
 * +0xB00: stub_isr_common
 * ========================================================================= */
.org 0x0B00
.global stub_isr_common
stub_isr_common:
    pushq %rax
    LOAD_SHARED %rax
    movq %rbx, GS_OFF_RBX(%rax)
    movq %rcx, GS_OFF_RCX(%rax)
    movq %rdx, GS_OFF_RDX(%rax)
    movq %rsi, GS_OFF_RSI(%rax)
    movq %rdi, GS_OFF_RDI(%rax)
    movq %rbp, GS_OFF_RBP(%rax)
    movq %r8,  GS_OFF_R8(%rax)
    movq %r9,  GS_OFF_R9(%rax)
    movq %r10, GS_OFF_R10(%rax)
    movq %r11, GS_OFF_R11(%rax)
    movq %r12, GS_OFF_R12(%rax)
    movq %r13, GS_OFF_R13(%rax)
    movq %r14, GS_OFF_R14(%rax)
    movq %r15, GS_OFF_R15(%rax)
    popq %rbx
    movq %rbx, GS_OFF_RAX(%rax)

    popq %rbx
    movq %rbx, GS_OFF_EXC_VECTOR(%rax)
    popq %rbx
    movq %rbx, GS_OFF_EXC_ERRCODE(%rax)

    movq %cr2, %rbx
    movq %rbx, GS_OFF_EXC_CR2(%rax)

    movq 0(%rsp), %rbx
    movq %rbx, GS_OFF_RIP(%rax)
    movq 16(%rsp), %rbx
    andq $~0x300, %rbx
    movq %rbx, GS_OFF_RFLAGS(%rax)
    movq 24(%rsp), %rbx
    movq %rbx, GS_OFF_RSP(%rax)

    testq $3, 8(%rsp)
    jz .Lring0_panic

    movq $DETHV_EXIT_EXCEPTION, GS_OFF_EXIT_REASON(%rax)
    movb $DETHV_EXIT_EXCEPTION, %al
    outb %al, $DETHV_HC_PORT
    jmp stub_enter_user

.Lring0_panic:
    movq $DETHV_EXIT_PANIC, GS_OFF_EXIT_REASON(%rax)
    movb $DETHV_EXIT_PANIC, %al
    outb %al, $DETHV_HC_PORT
    hlt

/* =========================================================================
 * +0xE00: stub_isr_table (32 exception stubs, 16 bytes each)
 * ========================================================================= */
.macro ISR_NOERR vec
.org (0x0E00 + (\vec) * 16)
    pushq $0
    pushq $\vec
    jmp stub_isr_common
.endm

.macro ISR_ERR vec
.org (0x0E00 + (\vec) * 16)
    pushq $\vec
    jmp stub_isr_common
.endm

ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_ERR   21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_NOERR 29
ISR_NOERR 30
ISR_NOERR 31

.org 0x1000
