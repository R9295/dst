#include "internal.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop_requested = 0;
static void handle_stop_sig(int sig) { (void)sig; g_stop_requested = 1; }

/* MSR indices */
#define MSR_EFER            0xC0000080U
#define MSR_STAR            0xC0000081U
#define MSR_LSTAR           0xC0000082U
#define MSR_CSTAR           0xC0000083U
#define MSR_SFMASK          0xC0000084U
#define MSR_FS_BASE         0xC0000100U
#define MSR_GS_BASE         0xC0000101U
#define MSR_KERNEL_GS_BASE  0xC0000102U
#define MSR_TSC_AUX         0xC0000103U

void dethv_config_default(dethv_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->ram_size        = 256ULL * 1024 * 1024;
    cfg->seed            = 0xDE7E415700000001ULL;
    cfg->start_time_ns   = 1700000000000000000ULL; /* 2023-11-14 22:13:20 UTC */
    cfg->preempt_quantum = 20000;                  /* 20k conditional branches/slice */
    cfg->max_syscalls    = 0;
    cfg->max_preempts    = 0;
    cfg->trace_syscalls  = false;
    cfg->capture_output  = true;
    cfg->enable_pmu      = true;
    cfg->patch_rdrand    = true;
    cfg->allow_host_ro   = true;
}

const char *dethv_stop_reason_str(dethv_stop_reason_t reason) {
    switch (reason) {
        case DETHV_STOP_NONE:       return "NONE";
        case DETHV_STOP_EXITED:     return "EXITED";
        case DETHV_STOP_CRASH_SEGV: return "CRASH_SIGSEGV";
        case DETHV_STOP_CRASH_ILL:  return "CRASH_SIGILL";
        case DETHV_STOP_CRASH_FPE:  return "CRASH_SIGFPE";
        case DETHV_STOP_CRASH_ABRT: return "CRASH_SIGABRT";
        case DETHV_STOP_CRASH_BUS:  return "CRASH_SIGBUS";
        case DETHV_STOP_CRASH_TRAP: return "CRASH_SIGTRAP";
        case DETHV_STOP_SNAPSHOT:   return "SNAPSHOT";
        case DETHV_STOP_TIMEOUT:    return "TIMEOUT";
        case DETHV_STOP_DEADLOCK:   return "DEADLOCK";
        case DETHV_STOP_ERROR:      return "ERROR";
    }
    return "UNKNOWN";
}

static void write_idt_entry(uint8_t *idt, int vec, uint64_t handler, uint8_t dpl) {
    uint8_t *e = idt + vec * 16;
    *(uint16_t *)(e + 0) = (uint16_t)(handler & 0xFFFF);
    *(uint16_t *)(e + 2) = GDT_SEL_KCODE;
    e[4] = 0; /* IST = 0 */
    e[5] = (uint8_t)(0x8E | ((dpl & 3) << 5)); /* Present, Interrupt Gate */
    *(uint16_t *)(e + 6) = (uint16_t)((handler >> 16) & 0xFFFF);
    *(uint32_t *)(e + 8) = (uint32_t)((handler >> 32) & 0xFFFFFFFF);
    *(uint32_t *)(e + 12) = 0;
}

static int setup_deterministic_cpuid(dethv_vm_t *vm) {
    struct {
        struct kvm_cpuid2 hdr;
        struct kvm_cpuid_entry2 entries[256];
    } cpuid;
    memset(&cpuid, 0, sizeof(cpuid));
    cpuid.hdr.nent = 256;
    if (ioctl(vm->kvm_fd, KVM_GET_SUPPORTED_CPUID, &cpuid) < 0) {
        perror("KVM_GET_SUPPORTED_CPUID");
        return -1;
    }

    for (uint32_t i = 0; i < cpuid.hdr.nent; i++) {
        struct kvm_cpuid_entry2 *e = &cpuid.entries[i];
        switch (e->function) {
            case 0x01:
                /* Deterministic single vCPU, APIC ID 0, clear RDRAND (ECX[30]) & HTT (EDX[28]) */
                e->ebx = (e->ebx & 0x0000FFFFU) | (1U << 16);
                e->ecx &= ~(1U << 30); /* Clear RDRAND */
                e->ecx &= ~(1U << 31); /* Clear Hypervisor bit if desired */
                e->edx &= ~(1U << 28); /* Clear HTT */
                break;
            case 0x07:
                if (e->index == 0) {
                    e->ebx &= ~(1U << 18); /* Clear RDSEED */
                    e->ecx &= ~(1U << 22); /* Clear RDPID */
                    e->ebx &= ~(1U << 20); /* Clear SMAP (keep Ring-0 fast access to user rip) */
                    e->ebx &= ~(1U << 7);  /* Clear SMEP */
                    /* Clear AVX-512 bits so XSAVE stays compact & glibc uses fast AVX2 */
                    e->ebx &= ~((1U << 16) | (1U << 17) | (1U << 21) | (1U << 26) |
                                (1U << 27) | (1U << 28) | (1U << 30) | (1U << 31));
                    e->ecx &= ~((1U << 1) | (1U << 6) | (1U << 11) | (1U << 12) | (1U << 14));
                }
                break;
            case 0x0B:
            case 0x1F:
                /* Single logical processor topology, APIC ID = 0 */
                e->edx = 0;
                break;
            case 0x0D:
                if (e->index == 0) {
                    /* Support x87 | SSE | AVX (XCR0 = 0x7) */
                    e->eax &= 0x7U;
                    e->edx = 0;
                    e->ebx = 832;
                    e->ecx = 832;
                }
                break;
            case 0x80000001:
                /* Keep NX, LM, SYSCALL, RDTSCP (we emulate RDTSCP deterministically!) */
                break;
            case 0x80000008:
                /* Clear RDPRU (EBX[4]), 1 CPU core (ECX[7:0]=0) */
                e->ebx &= ~(1U << 4);
                e->ecx &= ~0xFFU;
                break;
            case 0x8000001E:
                /* Single core APIC ID = 0 */
                e->eax = 0;
                e->ebx = 0;
                e->ecx = 0;
                break;
        }
    }

    if (ioctl(vm->vcpu_fd, KVM_SET_CPUID2, &cpuid) < 0) {
        perror("KVM_SET_CPUID2");
        return -1;
    }
    return 0;
}

static int setup_guest_kernel_structures(dethv_vm_t *vm) {
    /* Copy assembled Ring-0 stub into physical 0x10000 */
    if (guest_stub_bin_len > 0x4000) {
        fprintf(stderr, "[dethv] guest_stub.bin too large (%u bytes)\n", guest_stub_bin_len);
        return -1;
    }
    memcpy(vm->mem + GUEST_STUB_PHYS, guest_stub_bin, guest_stub_bin_len);

    /* GDT at GUEST_GDT_PHYS (0x18000) */
    uint64_t *gdt = (uint64_t *)(vm->mem + GUEST_GDT_PHYS);
    memset(gdt, 0, 64);
    gdt[0] = 0;
    gdt[1] = 0x00AF9A000000FFFFULL; /* 0x08: 64-bit Kernel CS (DPL=0) */
    gdt[2] = 0x00CF92000000FFFFULL; /* 0x10: Kernel DS (DPL=0) */
    gdt[3] = 0x00CFF2000000FFFFULL; /* 0x1B: User DS (DPL=3) */
    gdt[4] = 0x00AFFA000000FFFFULL; /* 0x23: 64-bit User CS (DPL=3) */
    /* 16-byte TSS descriptor at 0x28..0x37 -> GUEST_TSS_VADDR */
    uint64_t tss_base = GUEST_TSS_VADDR;
    uint64_t tss_limit = 0x67;
    gdt[5] = (tss_limit & 0xFFFFULL) |
             ((tss_base & 0xFFFFFFULL) << 16) |
             (0x89ULL << 40) |
             (((tss_limit >> 16) & 0xFULL) << 48) |
             (((tss_base >> 24) & 0xFFULL) << 56);
    gdt[6] = (tss_base >> 32) & 0xFFFFFFFFULL;

    /* TSS at GUEST_TSS_PHYS (0x18100): RSP0 = GUEST_KSTACK_TOP_VADDR */
    uint8_t *tss = vm->mem + GUEST_TSS_PHYS;
    memset(tss, 0, 0x68);
    *(uint64_t *)(tss + 4) = GUEST_KSTACK_TOP_VADDR;
    *(uint16_t *)(tss + 0x66) = 0x68; /* I/O map base beyond limit */

    /* IDT at GUEST_IDT_PHYS (0x19000) */
    uint8_t *idt = vm->mem + GUEST_IDT_PHYS;
    memset(idt, 0, PAGE_SIZE);
    for (int v = 0; v < 32; v++) {
        uint8_t dpl = (v == 3 || v == 4) ? 3 : 0; /* Allow Ring-3 INT3 / INTO */
        write_idt_entry(idt, v, GUEST_STUB_VADDR + STUB_OFF_ISR_TABLE + (uint64_t)v * 16, dpl);
    }
    /* Specialized fast-path handlers */
    write_idt_entry(idt, 1,                GUEST_STUB_VADDR + STUB_OFF_ISR_DB,  0);
    write_idt_entry(idt, 13,               GUEST_STUB_VADDR + STUB_OFF_ISR_GP,  0);
    write_idt_entry(idt, DETHV_PMI_VECTOR, GUEST_STUB_VADDR + STUB_OFF_ISR_PMI, 0);

    /* Initialize guest_shared_t at GUEST_SHARED_PHYS */
    vm->shared = (guest_shared_t *)(vm->mem + GUEST_SHARED_PHYS);
    memset(vm->shared, 0, sizeof(guest_shared_t));
    vm->shared->kern_rsp      = GUEST_KSTACK_TOP_VADDR;
    vm->shared->vtsc          = 1000000ULL;
    vm->shared->pmu_slack     = DETHV_PMU_SLACK;
    /* AMD Zen ExRetCond (0xD1): USR=1(bit16), OS=0, INT=1(bit20), EN=1(bit22) */
    vm->pmu_event_ctl_pmi     = 0x005100D1U;
    vm->pmu_event_ctl_nopmi   = 0x004100D1U;
    vm->shared->pmu_ctl_pmi   = vm->pmu_event_ctl_pmi;
    vm->shared->pmu_ctl_no_pmi = vm->pmu_event_ctl_nopmi;
    return 0;
}

static int setup_vcpu_initial_state(dethv_vm_t *vm) {
    /* 1. SREGS: 64-bit Long Mode, Ring 0, CR4.TSD=1 (trap RDTSC/RDTSCP!),
     *    CR4.PCE=0 (trap RDPMC!), CR4.UMIP=1 (trap SGDT/SIDT/SLDT/SMSW/STR!),
     *    CR4.OSFXSR=1, CR4.OSXMMEXCPT=1, CR4.OSXSAVE=1 */
    struct kvm_sregs sregs;
    if (ioctl(vm->vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
        perror("KVM_GET_SREGS");
        return -1;
    }

    sregs.cr3  = vm->mmu.pml4_phys;
    sregs.cr0  = (1ULL << 0)  /* PE */
               | (1ULL << 1)  /* MP */
               | (1ULL << 4)  /* ET */
               | (1ULL << 5)  /* NE */
               | (1ULL << 16) /* WP */
               | (1ULL << 18) /* AM */
               | (1ULL << 31);/* PG */
    sregs.cr4  = (1ULL << 2)  /* TSD: Trap RDTSC & RDTSCP in Ring 3! */
               | (1ULL << 5)  /* PAE */
               | (1ULL << 9)  /* OSFXSR */
               | (1ULL << 10) /* OSXMMEXCPT */
               | (1ULL << 11) /* UMIP: Trap SGDT/SIDT/SLDT/SMSW/STR in Ring 3! */
               | (1ULL << 18);/* OSXSAVE */
               /* Note: CR4.PCE (bit 8) = 0 -> Trap RDPMC in Ring 3! */
    sregs.efer = (1ULL << 0)  /* SCE (SYSCALL/SYSRET) */
               | (1ULL << 8)  /* LME */
               | (1ULL << 10) /* LMA */
               | (1ULL << 11);/* NXE */

    sregs.gdt.base  = GUEST_GDT_VADDR;
    sregs.gdt.limit = 7 * 8 - 1;
    sregs.idt.base  = GUEST_IDT_VADDR;
    sregs.idt.limit = 256 * 16 - 1;

    struct kvm_segment kcs = {
        .base = 0, .limit = 0xFFFFFFFFU, .selector = GDT_SEL_KCODE,
        .type = 11, .present = 1, .dpl = 0, .db = 0, .s = 1, .l = 1, .g = 1
    };
    struct kvm_segment kds = {
        .base = 0, .limit = 0xFFFFFFFFU, .selector = GDT_SEL_KDATA,
        .type = 3, .present = 1, .dpl = 0, .db = 1, .s = 1, .l = 0, .g = 1
    };
    struct kvm_segment tr = {
        .base = GUEST_TSS_VADDR, .limit = 0x67, .selector = GDT_SEL_TSS,
        .type = 11, .present = 1, .dpl = 0, .s = 0
    };
    sregs.cs = kcs;
    sregs.ss = sregs.ds = sregs.es = sregs.fs = sregs.gs = kds;
    sregs.tr = tr;
    sregs.ldt.unusable = 1;

    if (ioctl(vm->vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
        perror("KVM_SET_SREGS");
        return -1;
    }

    /* 2. XCR0 = 0x7 (x87 | SSE | AVX) */
    struct kvm_xcrs xcrs;
    memset(&xcrs, 0, sizeof(xcrs));
    xcrs.nr_xcrs = 1;
    xcrs.xcrs[0].xcr = 0;
    xcrs.xcrs[0].value = 0x7ULL;
    if (ioctl(vm->vcpu_fd, KVM_SET_XCRS, &xcrs) < 0) {
        perror("KVM_SET_XCRS");
        return -1;
    }
    vm->initial_xcrs = xcrs;

    /* 3. Deterministic clean FPU/SSE/AVX XSAVE state (FCW=0x037F, MXCSR=0x1F80) */
    memset(&vm->initial_xsave, 0, sizeof(vm->initial_xsave));
    uint8_t *xs = (uint8_t *)vm->initial_xsave.region;
    *(uint16_t *)(xs + 0)  = 0x037F; /* x87 FCW */
    *(uint32_t *)(xs + 24) = 0x1F80; /* SSE MXCSR */
    *(uint32_t *)(xs + 28) = 0xFFFF; /* MXCSR_MASK */
    if (ioctl(vm->vcpu_fd, KVM_SET_XSAVE, &vm->initial_xsave) < 0) {
        perror("KVM_SET_XSAVE");
        return -1;
    }

    /* 4. SYSCALL/SWAPGS/TSC_AUX MSRs */
    struct {
        struct kvm_msrs hdr;
        struct kvm_msr_entry entries[8];
    } msrs;
    memset(&msrs, 0, sizeof(msrs));
    msrs.hdr.nmsrs = 7;
    /* STAR[47:32] = KCODE (0x08), STAR[63:48] = 0x13 (UDATA-8) */
    msrs.entries[0] = (struct kvm_msr_entry){ .index = MSR_STAR,           .data = ((uint64_t)0x0013 << 48) | ((uint64_t)0x0008 << 32) };
    msrs.entries[1] = (struct kvm_msr_entry){ .index = MSR_LSTAR,          .data = GUEST_STUB_VADDR + STUB_OFF_SYSCALL_ENTRY };
    msrs.entries[2] = (struct kvm_msr_entry){ .index = MSR_CSTAR,          .data = GUEST_STUB_VADDR + STUB_OFF_SYSCALL_ENTRY };
    msrs.entries[3] = (struct kvm_msr_entry){ .index = MSR_SFMASK,         .data = 0x4700ULL }; /* Clear IF, TF, DF, NT on SYSCALL */
    msrs.entries[4] = (struct kvm_msr_entry){ .index = MSR_FS_BASE,        .data = 0 };
    msrs.entries[5] = (struct kvm_msr_entry){ .index = MSR_GS_BASE,        .data = 0 };
    msrs.entries[6] = (struct kvm_msr_entry){ .index = MSR_KERNEL_GS_BASE, .data = GUEST_SHARED_VADDR };
    if (ioctl(vm->vcpu_fd, KVM_SET_MSRS, &msrs) < 0) {
        perror("KVM_SET_MSRS");
        return -1;
    }

    /* Set MSR_TSC_AUX = 0 (deterministic RDPID/RDTSCP) */
    struct {
        struct kvm_msrs hdr;
        struct kvm_msr_entry entry;
    } tsc_aux = { .hdr = { .nmsrs = 1 }, .entry = { .index = MSR_TSC_AUX, .data = 0 } };
    ioctl(vm->vcpu_fd, KVM_SET_MSRS, &tsc_aux); /* best effort */

    /* Save clean initial LAPIC state */
    if (ioctl(vm->vcpu_fd, KVM_GET_LAPIC, &vm->initial_lapic) < 0) {
        perror("KVM_GET_LAPIC");
        return -1;
    }

    /* 5. Initial Ring-0 RIP -> stub_enter_user */
    struct kvm_regs regs;
    memset(&regs, 0, sizeof(regs));
    regs.rip    = GUEST_STUB_VADDR + STUB_OFF_ENTER_USER;
    regs.rsp    = GUEST_KSTACK_TOP_VADDR;
    regs.rflags = 0x2;
    if (ioctl(vm->vcpu_fd, KVM_SET_REGS, &regs) < 0) {
        perror("KVM_SET_REGS");
        return -1;
    }

    /* Enable fast SYNC_REGS on every KVM_RUN! */
    vm->kvm_run->kvm_valid_regs = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS | KVM_SYNC_X86_EVENTS;
    vm->kvm_run->kvm_dirty_regs = 0;

    return 0;
}

dethv_vm_t *dethv_create(const dethv_config_t *cfg_in) {
    dethv_vm_t *vm = calloc(1, sizeof(dethv_vm_t));
    if (!vm) return NULL;

    if (cfg_in) vm->cfg = *cfg_in;
    else dethv_config_default(&vm->cfg);
    if (vm->cfg.ram_size < 16ULL * 1024 * 1024)
        vm->cfg.ram_size = 16ULL * 1024 * 1024;
    vm->ram_size = PAGE_ALIGN_UP(vm->cfg.ram_size);
    vm->kvm_fd = vm->vm_fd = vm->vcpu_fd = -1;

    vm->kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (vm->kvm_fd < 0) {
        perror("open(/dev/kvm)");
        goto fail;
    }

    vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
    if (vm->vm_fd < 0) {
        perror("KVM_CREATE_VM");
        goto fail;
    }

    if (ioctl(vm->vm_fd, KVM_SET_TSS_ADDR, 0xFFFBD000UL) < 0) {
        perror("KVM_SET_TSS_ADDR");
        goto fail;
    }
    if (ioctl(vm->vm_fd, KVM_CREATE_IRQCHIP) < 0) {
        perror("KVM_CREATE_IRQCHIP");
        goto fail;
    }

    /* We use zero-VMEXIT hardware guest PTE_D dirty tracking (no NPT write-protect faults!) */
    vm->use_dirty_ring = false;

    /* Split guest physical RAM around the x86 3GB..4GB MMIO/LAPIC/TSS hole!
     * Keep vm->mem indexed 1:1 by guest_phys_addr (the 1GB hole is untouched virtual space = 0 RSS). */
    const uint64_t MMIO_HOLE_START = 0xC0000000ULL; /* 3 GiB */
    const uint64_t MMIO_HOLE_END   = 0x100000000ULL; /* 4 GiB */
    size_t low_ram  = vm->ram_size <= MMIO_HOLE_START ? vm->ram_size : MMIO_HOLE_START;
    size_t high_ram = vm->ram_size >  MMIO_HOLE_START ? (vm->ram_size - MMIO_HOLE_START) : 0;
    size_t map_span = high_ram > 0 ? (MMIO_HOLE_END + high_ram) : low_ram;
    vm->ram_size = map_span;

    vm->mem = mmap(NULL, vm->ram_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (vm->mem == MAP_FAILED) {
        vm->mem = NULL;
        perror("mmap guest ram");
        goto fail;
    }

    struct kvm_userspace_memory_region region0 = {
        .slot            = 0,
        .flags           = 0,
        .guest_phys_addr = 0,
        .memory_size     = low_ram,
        .userspace_addr  = (uint64_t)vm->mem
    };
    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region0) < 0) {
        perror("KVM_SET_USER_MEMORY_REGION slot 0");
        goto fail;
    }
    if (high_ram > 0) {
        struct kvm_userspace_memory_region region1 = {
            .slot            = 1,
            .flags           = 0,
            .guest_phys_addr = MMIO_HOLE_END,
            .memory_size     = high_ram,
            .userspace_addr  = (uint64_t)(vm->mem + MMIO_HOLE_END)
        };
        if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region1) < 0) {
            perror("KVM_SET_USER_MEMORY_REGION slot 1");
            goto fail;
        }
    }

    vm->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vm->vcpu_fd < 0) {
        perror("KVM_CREATE_VCPU");
        goto fail;
    }

    if (setup_deterministic_cpuid(vm) < 0) goto fail;

    int mmap_sz = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (mmap_sz < 0) { perror("KVM_GET_VCPU_MMAP_SIZE"); goto fail; }
    vm->kvm_run_size = (size_t)mmap_sz;
    vm->kvm_run = mmap(NULL, vm->kvm_run_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED, vm->vcpu_fd, 0);
    if (vm->kvm_run == MAP_FAILED) {
        vm->kvm_run = NULL;
        perror("mmap kvm_run");
        goto fail;
    }

    if (vm->use_dirty_ring) {
        long ps = sysconf(_SC_PAGESIZE);
        vm->dirty_ring = mmap(NULL, DETHV_DIRTY_RING_BYTES, PROT_READ | PROT_WRITE,
                              MAP_SHARED, vm->vcpu_fd,
                              (off_t)KVM_DIRTY_LOG_PAGE_OFFSET * ps);
        if (vm->dirty_ring == MAP_FAILED) {
            vm->dirty_ring = NULL;
            vm->use_dirty_ring = false;
        }
    }

    /* Allocate host-dirty tracking bitmap & physical page free list */
    vm->host_dirty_bitmap_bytes = ((vm->ram_size / PAGE_SIZE) + 7) / 8;
    vm->host_dirty_bitmap = calloc(1, vm->host_dirty_bitmap_bytes);
    vm->phys_free_list = malloc(DETHV_MAX_FREE_PAGES * sizeof(uint64_t));
    if (!vm->host_dirty_bitmap || !vm->phys_free_list) goto fail;

    /* Check if AMD vPMU is available */
    vm->pmu_available = vm->cfg.enable_pmu;

    /* Initialize core deterministic subsystems */
    det_init(&vm->det, vm->cfg.seed, vm->cfg.start_time_ns);
    if (x86_patch_init(&vm->patches) < 0) goto fail;
    if (mmu_init(vm) < 0) goto fail;
    if (setup_guest_kernel_structures(vm) < 0) goto fail;
    if (setup_vcpu_initial_state(vm) < 0) goto fail;
    if (vfs_init(vm) < 0) goto fail;
    if (net_init(vm) < 0) goto fail;
    if (iouring_init(vm) < 0) goto fail;
    sched_init(vm);

    return vm;

fail:
    dethv_destroy(vm);
    return NULL;
}

void dethv_destroy(dethv_vm_t *vm) {
    if (!vm) return;
    iouring_destroy(vm);
    net_destroy(&vm->net);
    vfs_destroy(&vm->vfs);
    x86_patch_destroy(&vm->patches);
    free(vm->hc_input_buf);
    free(vm->host_dirty_bitmap);
    free(vm->phys_free_list);
    if (vm->dirty_ring) munmap(vm->dirty_ring, DETHV_DIRTY_RING_BYTES);
    if (vm->kvm_run)    munmap(vm->kvm_run, vm->kvm_run_size);
    if (vm->mem)        munmap(vm->mem, vm->ram_size);
    if (vm->vcpu_fd >= 0) close(vm->vcpu_fd);
    if (vm->vm_fd >= 0)   close(vm->vm_fd);
    if (vm->kvm_fd >= 0)  close(vm->kvm_fd);
    free(vm);
}

int dethv_set_snapshot_addr(dethv_vm_t *vm, uint64_t vaddr) {
    vm->snap_trigger_addr = vaddr;
    return x86_patch_add_bp(vm, vaddr, PATCH_SNAPSHOT_BP);
}

void dethv_set_snapshot_on_stdin(dethv_vm_t *vm, bool enable) {
    vm->snap_on_stdin = enable;
    vm->snap_on_stdin_armed = enable;
}

void dethv_set_snapshot_on_open(dethv_vm_t *vm, const char *path_substr) {
    if (path_substr && path_substr[0]) {
        strncpy(vm->snap_on_open_substr, path_substr, sizeof(vm->snap_on_open_substr) - 1);
        vm->snap_on_open_substr[sizeof(vm->snap_on_open_substr) - 1] = '\0';
        vm->snap_on_open_armed = true;
    } else {
        vm->snap_on_open_substr[0] = '\0';
        vm->snap_on_open_armed = false;
    }
}

void dethv_set_snapshot_on_hc(dethv_vm_t *vm, bool enable) {
    vm->snap_on_hc = enable;
    vm->snap_on_hc_armed = enable;
}

int dethv_set_input(dethv_vm_t *vm, const void *data, size_t len) {
    vm->hc_input_len = 0;
    vm->hc_input_pos = 0;
    vm->hc_input_set = true;
    if (len > 0 && data) {
        if (len > vm->hc_input_cap || !vm->hc_input_buf) {
            size_t ncap = len < 256 ? 256 : len;
            uint8_t *nb = realloc(vm->hc_input_buf, ncap);
            if (!nb) return -1;
            vm->hc_input_buf = nb;
            vm->hc_input_cap = ncap;
        }
        memcpy(vm->hc_input_buf, data, len);
        vm->hc_input_len = len;
    }
    return 0;
}

void dethv_get_input_info(const dethv_vm_t *vm, uint64_t *guest_buf_vaddr, size_t *guest_max_len) {
    if (guest_buf_vaddr) *guest_buf_vaddr = vm->hc_input_vaddr;
    if (guest_max_len)   *guest_max_len   = vm->hc_input_max_len;
}

int dethv_read_virt(dethv_vm_t *vm, uint64_t vaddr, void *dst, size_t len) {
    return mmu_copy_from_guest(vm, dst, vaddr, len);
}

int dethv_write_virt(dethv_vm_t *vm, uint64_t vaddr, const void *src, size_t len) {
    return mmu_copy_to_guest(vm, vaddr, src, len);
}

const uint8_t *dethv_get_stdout(const dethv_vm_t *vm, size_t *len_out) {
    if (len_out) *len_out = vm->vfs.stdout_len;
    return vm->vfs.stdout_buf;
}

const uint8_t *dethv_get_stderr(const dethv_vm_t *vm, size_t *len_out) {
    if (len_out) *len_out = vm->vfs.stderr_len;
    return vm->vfs.stderr_buf;
}

/* Handle CPU exceptions reported by Ring-0 stub_isr_common */
void dethv_handle_exception(dethv_vm_t *vm) {
    uint64_t vec = vm->shared->exc_vector;
    uint64_t err = vm->shared->exc_errcode;
    uint64_t cr2 = vm->shared->exc_cr2;
    uint64_t rip = vm->shared->regs.rip;

    /* Account PMU branches before handling exception */
    sched_account_pmu(vm);

    switch (vec) {
        case 14: /* #PF Page Fault */
            if (mmu_handle_page_fault(vm, cr2, err)) {
                return; /* Resolved via demand paging / stack growth -> retry! */
            }
            vm->running = false;
            vm->stop_reason = DETHV_STOP_CRASH_SEGV;
            vm->crash_signal = SIGSEGV;
            vm->fault_rip = rip;
            vm->fault_addr = cr2;
            vm->fault_errcode = err;
            return;

        case 3: { /* #BP INT3 (RIP points right AFTER 0xCC) */
            uint64_t bp_rip = rip - 1;
            if (x86_handle_bp_patch(vm, bp_rip)) {
                return;
            }
            vm->running = false;
            vm->stop_reason = DETHV_STOP_CRASH_TRAP;
            vm->crash_signal = SIGTRAP;
            vm->fault_rip = bp_rip;
            return;
        }

        case 13: { /* #GP (non-RDTSC/RDTSCP; check RDPMC = 0F 33) */
            uint8_t insn[4] = {0};
            if (err == 0 && mmu_copy_from_guest(vm, insn, rip, 2) == 0 &&
                insn[0] == 0x0F && insn[1] == 0x33) {
                /* Deterministic RDPMC -> return vtsc */
                uint64_t v = vm->shared->vtsc;
                vm->shared->regs.rax = (uint32_t)v;
                vm->shared->regs.rdx = (uint32_t)(v >> 32);
                vm->shared->regs.rip = rip + 2;
                vm->shared->pmu_prev_rip = vm->shared->regs.rip;
                return;
            }
            vm->running = false;
            vm->stop_reason = DETHV_STOP_CRASH_SEGV;
            vm->crash_signal = SIGSEGV;
            vm->fault_rip = rip;
            vm->fault_errcode = err;
            return;
        }

        case 6: { /* #UD (check RDPRU = 0F 01 FD) */
            uint8_t insn[4] = {0};
            if (mmu_copy_from_guest(vm, insn, rip, 3) == 0 &&
                insn[0] == 0x0F && insn[1] == 0x01 && insn[2] == 0xFD) {
                /* Deterministic RDPRU -> return vtsc */
                vm->shared->vtsc += DETHV_VTSC_STEP_RDTSC;
                vm->shared->rdtsc_traps++;
                uint64_t v = vm->shared->vtsc;
                vm->shared->regs.rax = (uint32_t)v;
                vm->shared->regs.rdx = (uint32_t)(v >> 32);
                vm->shared->regs.rip = rip + 3;
                vm->shared->pmu_prev_rip = vm->shared->regs.rip;
                return;
            }
            vm->running = false;
            vm->stop_reason = DETHV_STOP_CRASH_ILL;
            vm->crash_signal = SIGILL;
            vm->fault_rip = rip;
            return;
        }

        case 0:  /* #DE Divide Error */
        case 16: /* #MF x87 FP */
        case 19: /* #XM SIMD FP */
            vm->running = false;
            vm->stop_reason = DETHV_STOP_CRASH_FPE;
            vm->crash_signal = SIGFPE;
            vm->fault_rip = rip;
            return;

        case 12: /* #SS Stack Fault */
        case 17: /* #AC Alignment Check */
            vm->running = false;
            vm->stop_reason = DETHV_STOP_CRASH_BUS;
            vm->crash_signal = SIGBUS;
            vm->fault_rip = rip;
            return;

        default:
            vm->running = false;
            vm->stop_reason = DETHV_STOP_CRASH_SEGV;
            vm->crash_signal = SIGSEGV;
            vm->fault_rip = rip;
            vm->fault_errcode = err;
            return;
    }
}

static uint64_t compute_state_hash(const dethv_vm_t *vm) {
    uint64_t h = 0xcbf29ce484222325ULL;
    h = det_hash_u64(h, (uint64_t)vm->stop_reason);
    h = det_hash_u64(h, (uint64_t)vm->exit_code);
    h = det_hash_u64(h, (uint64_t)vm->crash_signal);
    h = det_hash_u64(h, vm->fault_rip);
    h = det_hash_u64(h, vm->fault_addr);
    h = det_hash_bytes(h, &vm->shared->regs, sizeof(vm->shared->regs));
    h = det_hash_u64(h, vm->shared->vtsc);
    h = det_hash_u64(h, vm->det.vtime_ns);
    h = det_hash_u64(h, vm->det.syscall_count);
    h = det_hash_u64(h, vm->det.preempt_count);
    h = det_hash_u64(h, vm->det.rdrand_count);
    h = det_hash_u64(h, vm->det.getrandom_count);
    h = det_hash_bytes(h, vm->vfs.stdout_buf, vm->vfs.stdout_len);
    h = det_hash_bytes(h, vm->vfs.stderr_buf, vm->vfs.stderr_len);
    return h;
}

int dethv_run(dethv_vm_t *vm, dethv_run_result_t *res) {
    vm->running      = true;
    vm->stop_reason  = DETHV_STOP_NONE;
    vm->exit_code    = 0;
    vm->crash_signal = 0;
    vm->fault_rip    = 0;
    vm->fault_addr   = 0;
    vm->fault_errcode = 0;
    g_stop_requested = 0;
    signal(SIGTERM, handle_stop_sig);
    signal(SIGINT,  handle_stop_sig);

    while (vm->running) {
        if (g_stop_requested) {
            int n_run = 0, n_futex = 0, n_sleep = 0, n_io = 0;
            for (uint32_t i = 0; i < vm->sched.used_slots; i++) {
                switch (vm->sched.threads[i].state) {
                    case THREAD_RUNNABLE:      n_run++;   break;
                    case THREAD_BLOCKED_FUTEX: n_futex++; break;
                    case THREAD_BLOCKED_SLEEP: n_sleep++; break;
                    case THREAD_BLOCKED_IO:    n_io++;    break;
                    default: break;
                }
            }
            struct { struct kvm_msrs hdr; struct kvm_msr_entry e[2]; } pmu_m;
            memset(&pmu_m, 0, sizeof(pmu_m));
            pmu_m.hdr.nmsrs = 2;
            pmu_m.e[0].index = 0xC0010000;
            pmu_m.e[1].index = 0xC0010004;
            ioctl(vm->vcpu_fd, KVM_GET_MSRS, &pmu_m);
            struct kvm_lapic_state lap;
            ioctl(vm->vcpu_fd, KVM_GET_LAPIC, &lap);
            uint32_t lvt_pmi = *(uint32_t *)(lap.regs + 0x340);
            uint32_t svr     = *(uint32_t *)(lap.regs + 0x0F0);
            fprintf(stderr,
                "\n[dethv] INTERRUPTED: tid=%d(%s) rip=0x%llx last_sys=%llu vmono=%.6fs syscalls=%llu preempts=%llu rdtsc=%llu\n"
                "        threads: slots=%u runnable=%d futex=%d sleep=%d io=%d | pmu_armed=%llu landing=%llu steps=%llu\n"
                "        PMU: ctl=0x%llx ctr=0x%llx init=0x%llx budget=%llu | LAPIC: svr=0x%x lvt_pmi=0x%x lapic_init=%llu\n",
                vm->sched.threads[vm->sched.current_idx].tid,
                vm->sched.threads[vm->sched.current_idx].name[0] ? vm->sched.threads[vm->sched.current_idx].name : "main",
                (unsigned long long)vm->shared->regs.rip,
                (unsigned long long)vm->sched.threads[vm->sched.current_idx].last_sys,
                (double)vm->det.vmono_ns / 1e9,
                (unsigned long long)vm->det.syscall_count,
                (unsigned long long)vm->det.preempt_count,
                (unsigned long long)vm->shared->rdtsc_traps,
                vm->sched.used_slots, n_run, n_futex, n_sleep, n_io,
                (unsigned long long)vm->shared->pmu_armed,
                (unsigned long long)vm->shared->pmu_in_landing,
                (unsigned long long)vm->shared->pmu_landing_steps,
                (unsigned long long)pmu_m.e[0].data,
                (unsigned long long)pmu_m.e[1].data,
                (unsigned long long)vm->shared->pmu_init_ctr,
                (unsigned long long)vm->sched.threads[vm->sched.current_idx].branch_budget,
                svr, lvt_pmi,
                (unsigned long long)vm->shared->lapic_init_done);
            for (uint32_t i = 0; i < vm->sched.used_slots; i++) {
                guest_thread_t *t = &vm->sched.threads[i];
                if (t->state == THREAD_RUNNABLE || t->state == THREAD_BLOCKED_SLEEP || t->state == THREAD_BLOCKED_IO) {
                    fprintf(stderr, "          tid=%d(%s) state=%d last_sys=%llu wake=%.3fs\n",
                            t->tid, t->name[0] ? t->name : "main", (int)t->state,
                            (unsigned long long)t->last_sys, (double)t->wake_time_ns / 1e9);
                }
            }
            vm->stop_reason = DETHV_STOP_TIMEOUT;
            vm->running = false;
            break;
        }
        /* Prepare deterministic PMU preemption if >1 thread runnable */
        sched_prepare_pmu(vm);

        /* Sync FS_BASE / TLB flush (CR3) via zero-ioctl SYNC_REGS when needed */
        vm->kvm_run->kvm_valid_regs = KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS | KVM_SYNC_X86_EVENTS;
        if (vm->fs_base_dirty || vm->sregs_dirty) {
            if (vm->fs_base_dirty) {
                /* Must write MSR_FS_BASE cleanly so sregs.fs.base matches */
                struct {
                    struct kvm_msrs hdr;
                    struct kvm_msr_entry entry;
                } fs_msr = {
                    .hdr = { .nmsrs = 1 },
                    .entry = { .index = MSR_FS_BASE, .data = vm->current_fs_base }
                };
                ioctl(vm->vcpu_fd, KVM_SET_MSRS, &fs_msr);
                vm->fs_base_dirty = false;
            }
            if (vm->sregs_dirty) {
                /* Zero-ioctl Ring-0 CR3 reload flushes guest TLB in ~30ns! */
                vm->shared->flush_tlb = 1;
                vm->sregs_dirty = false;
            }
        }

        int rc = ioctl(vm->vcpu_fd, KVM_RUN, 0);
        if (rc < 0) {
            if (errno == EINTR) {
                if (g_stop_requested) {
                    struct kvm_regs kregs;
                    if (ioctl(vm->vcpu_fd, KVM_GET_REGS, &kregs) == 0) {
                        fprintf(stderr, "\n[dethv] INTERRUPTED IN KVM_RUN: guest_rip=0x%llx rsp=0x%llx rflags=0x%llx\n",
                                (unsigned long long)kregs.rip, (unsigned long long)kregs.rsp, (unsigned long long)kregs.rflags);
                    }
                }
                continue;
            }
            perror("KVM_RUN");
            vm->stop_reason = DETHV_STOP_ERROR;
            vm->running = false;
            break;
        }

        switch (vm->kvm_run->exit_reason) {
            case KVM_EXIT_IO: {
                if (vm->kvm_run->io.port != DETHV_HC_PORT) {
                    fprintf(stderr, "[dethv] Unexpected I/O port 0x%x\n", vm->kvm_run->io.port);
                    vm->stop_reason = DETHV_STOP_ERROR;
                    vm->running = false;
                    break;
                }
                uint64_t reason = vm->shared->exit_reason;
                vm->shared->exit_reason = DETHV_EXIT_NONE;

                if (reason == DETHV_EXIT_SYSCALL) {
                    sched_account_pmu(vm);
                    dethv_handle_syscall(vm);
                } else if (reason == DETHV_EXIT_EXCEPTION) {
                    dethv_handle_exception(vm);
                } else if (reason == DETHV_EXIT_PREEMPT) {
                    vm->det.preempt_count++;
                    vm->det.total_branches += vm->cfg.preempt_quantum;
                    vm->shared->pmu_need_prog = 1;
                    /* Advance virtual clock proportionally to simulated CPU work (5ns/branch) */
                    uint64_t slice_ns = vm->cfg.preempt_quantum * 5ULL;
                    if (slice_ns < 10000) slice_ns = 10000;
                    det_advance_time(&vm->det, slice_ns);
                    vm->shared->vtsc += (slice_ns * 25) / 10;
                    if (vm->cfg.max_preempts && vm->det.preempt_count >= vm->cfg.max_preempts) {
                        vm->stop_reason = DETHV_STOP_TIMEOUT;
                        vm->running = false;
                    } else {
                        sched_switch_next(vm, true);
                    }
                } else if (reason == DETHV_EXIT_PANIC) {
                    fprintf(stderr, "[dethv] RING-0 PANIC vec=%llu err=0x%llx cr2=0x%llx rip=0x%llx\n",
                            (unsigned long long)vm->shared->exc_vector,
                            (unsigned long long)vm->shared->exc_errcode,
                            (unsigned long long)vm->shared->exc_cr2,
                            (unsigned long long)vm->shared->regs.rip);
                    vm->stop_reason = DETHV_STOP_ERROR;
                    vm->running = false;
                }
                break;
            }

            case KVM_EXIT_DIRTY_RING_FULL:
                vm->dirty_ring_overflow = true;
                if (vm->use_dirty_ring) {
                    while (__atomic_load_n(&vm->dirty_ring[vm->dirty_ring_head].flags, __ATOMIC_ACQUIRE) & KVM_DIRTY_GFN_F_DIRTY) {
                        __atomic_store_n(&vm->dirty_ring[vm->dirty_ring_head].flags, KVM_DIRTY_GFN_F_RESET, __ATOMIC_RELEASE);
                        vm->dirty_ring_head = (vm->dirty_ring_head + 1) % vm->dirty_ring_entries;
                    }
                    ioctl(vm->vm_fd, KVM_RESET_DIRTY_RINGS, 0);
                }
                break;

            case KVM_EXIT_HLT:
                vm->stop_reason = DETHV_STOP_ERROR;
                vm->running = false;
                break;

            case KVM_EXIT_SHUTDOWN:
                fprintf(stderr, "[dethv] KVM_EXIT_SHUTDOWN (triple fault!)\n");
                vm->stop_reason = DETHV_STOP_ERROR;
                vm->running = false;
                break;

            default:
                fprintf(stderr, "[dethv] Unexpected KVM exit reason %u\n", vm->kvm_run->exit_reason);
                vm->stop_reason = DETHV_STOP_ERROR;
                vm->running = false;
                break;
        }
    }

    if (res) {
        memset(res, 0, sizeof(*res));
        res->reason          = vm->stop_reason;
        res->exit_code       = vm->exit_code;
        res->signal          = vm->crash_signal;
        res->fault_rip       = vm->fault_rip;
        res->fault_addr      = vm->fault_addr;
        res->fault_errcode   = vm->fault_errcode;
        res->syscalls        = vm->det.syscall_count;
        res->preempts        = vm->det.preempt_count;
        res->rdtsc_traps     = vm->shared->rdtsc_traps;
        res->rdrand_traps    = vm->det.rdrand_count;
        res->getrandom_calls = vm->det.getrandom_count;
        res->total_threads   = vm->sched.total_spawned;
        res->pmu_overshoots  = vm->shared->pmu_overshoots;
        res->dirty_pages     = vm->last_dirty_pages;
        res->stdout_len      = vm->vfs.stdout_len;
        res->stderr_len      = vm->vfs.stderr_len;
        res->stdout_hash     = det_hash_bytes(0, vm->vfs.stdout_buf, vm->vfs.stdout_len);
        res->state_hash      = compute_state_hash(vm);
    }

    return (vm->stop_reason == DETHV_STOP_ERROR) ? -1 : 0;
}
