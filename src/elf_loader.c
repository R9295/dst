#include "internal.h"
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static uint32_t pf_to_prot(uint32_t p_flags) {
    uint32_t prot = 0;
    if (p_flags & PF_R) prot |= PROT_READ;
    if (p_flags & PF_W) prot |= PROT_WRITE;
    if (p_flags & PF_X) prot |= PROT_EXEC;
    return prot;
}

static uint8_t *read_host_file(const char *path, size_t *size_out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[dethv] Cannot open ELF '%s': %s\n", path, strerror(errno));
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size <= 0) {
        close(fd);
        return NULL;
    }
    size_t sz = (size_t)st.st_size;
    uint8_t *buf = malloc(sz);
    if (!buf) { close(fd); return NULL; }
    size_t got = 0;
    while (got < sz) {
        ssize_t n = read(fd, buf + got, sz - got);
        if (n <= 0) { free(buf); close(fd); return NULL; }
        got += (size_t)n;
    }
    close(fd);
    *size_out = sz;
    return buf;
}

typedef struct {
    uint64_t load_bias;
    uint64_t entry;
    uint64_t phdr_vaddr;
    uint16_t phent;
    uint16_t phnum;
    uint64_t max_vaddr;
    char     interp_path[256];
} loaded_elf_t;

static void parse_elf_symbols(dethv_vm_t *vm, const uint8_t *buf, size_t sz, uint64_t load_bias) {
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)buf;
    if (eh->e_shoff == 0 || eh->e_shnum == 0 ||
        eh->e_shoff + (size_t)eh->e_shnum * eh->e_shentsize > sz)
        return;

    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(buf + eh->e_shoff);
    for (uint16_t i = 0; i < eh->e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_SYMTAB && shdrs[i].sh_type != SHT_DYNSYM)
            continue;
        if (shdrs[i].sh_link >= eh->e_shnum) continue;
        const Elf64_Shdr *str_sh = &shdrs[shdrs[i].sh_link];
        if (shdrs[i].sh_offset + shdrs[i].sh_size > sz) continue;
        if (str_sh->sh_offset + str_sh->sh_size > sz) continue;

        const char *strtab = (const char *)(buf + str_sh->sh_offset);
        size_t str_sz = str_sh->sh_size;
        size_t nsyms = shdrs[i].sh_size / sizeof(Elf64_Sym);
        const Elf64_Sym *syms = (const Elf64_Sym *)(buf + shdrs[i].sh_offset);

        for (size_t s = 0; s < nsyms; s++) {
            if (syms[s].st_shndx == SHN_UNDEF || syms[s].st_value == 0) continue;
            uint8_t st_type = ELF64_ST_TYPE(syms[s].st_info);
            if (st_type != STT_FUNC && st_type != STT_OBJECT && st_type != STT_NOTYPE)
                continue;
            if (syms[s].st_name == 0 || syms[s].st_name >= str_sz) continue;
            const char *name = strtab + syms[s].st_name;
            if (!name[0]) continue;
            if (vm->syms.count >= DETHV_MAX_SYMBOLS) return;

            /* Avoid duplicates */
            bool dup = false;
            for (uint32_t k = 0; k < vm->syms.count; k++) {
                if (strcmp(vm->syms.syms[k].name, name) == 0) {
                    dup = true;
                    break;
                }
            }
            if (dup) continue;

            elf_sym_t *dst = &vm->syms.syms[vm->syms.count++];
            strncpy(dst->name, name, sizeof(dst->name) - 1);
            dst->name[sizeof(dst->name) - 1] = '\0';
            dst->addr = syms[s].st_value + load_bias;
            dst->size = syms[s].st_size;
        }
    }
}

static int map_elf_image(dethv_vm_t *vm, const uint8_t *buf, size_t sz,
                         uint64_t pie_base, bool record_syms, loaded_elf_t *out) {
    memset(out, 0, sizeof(*out));
    if (sz < sizeof(Elf64_Ehdr)) return -1;
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)buf;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 ||
        eh->e_ident[EI_CLASS] != ELFCLASS64 ||
        eh->e_machine != EM_X86_64) {
        fprintf(stderr, "[dethv] Unsupported ELF (need x86_64 ELF64)\n");
        return -1;
    }

    uint64_t load_bias = (eh->e_type == ET_DYN) ? pie_base : 0;
    out->load_bias = load_bias;
    out->entry     = eh->e_entry + load_bias;
    out->phent     = eh->e_phentsize;
    out->phnum     = eh->e_phnum;

    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(buf + eh->e_phoff);
    uint64_t min_vaddr = UINT64_MAX;
    uint64_t max_vaddr = 0;

    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type == PT_INTERP && ph->p_filesz > 0 && ph->p_offset + ph->p_filesz <= sz) {
            size_t n = ph->p_filesz < sizeof(out->interp_path) - 1 ? ph->p_filesz : sizeof(out->interp_path) - 1;
            memcpy(out->interp_path, buf + ph->p_offset, n);
            out->interp_path[n] = '\0';
        }
        if (ph->p_type == PT_LOAD) {
            if (ph->p_vaddr < min_vaddr) min_vaddr = ph->p_vaddr;
            if (ph->p_vaddr + ph->p_memsz > max_vaddr) max_vaddr = ph->p_vaddr + ph->p_memsz;
        }
    }

    /* Map all PT_LOAD segments */
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD || ph->p_memsz == 0) continue;

        uint64_t seg_vaddr = ph->p_vaddr + load_bias;
        uint64_t map_start = PAGE_ALIGN_DOWN(seg_vaddr);
        uint64_t map_end   = PAGE_ALIGN_UP(seg_vaddr + ph->p_memsz);
        uint32_t prot      = pf_to_prot(ph->p_flags);

        /* Map pages (populate immediately so we can copy file data cleanly) */
        for (uint64_t va = map_start; va < map_end; va += PAGE_SIZE) {
            uint64_t pte_flags = PTE_P | PTE_U | PTE_W; /* Temp writable while loading */
            if (!(prot & PROT_EXEC)) pte_flags |= PTE_NX;

            uint64_t pa = mmu_virt_to_phys(vm, va, NULL);
            if (!pa) {
                pa = mmu_alloc_phys_page(vm);
                if (!pa) return -1;
            }
            if (mmu_map_page(vm, va, pa, pte_flags) < 0) return -1;
        }

        /* Copy initialized bytes from ELF file */
        if (ph->p_filesz > 0 && ph->p_offset + ph->p_filesz <= sz) {
            if (mmu_copy_to_guest(vm, seg_vaddr, buf + ph->p_offset, ph->p_filesz) < 0)
                return -1;
        }

        /* Locate in-memory PHDR virtual address */
        if (ph->p_offset <= eh->e_phoff && eh->e_phoff < ph->p_offset + ph->p_filesz) {
            out->phdr_vaddr = seg_vaddr + (eh->e_phoff - ph->p_offset);
        }

        /* Record VMA & finalize page protections */
        if (vm->mmu.num_vmas < DETHV_MAX_VMAS) {
            vm->mmu.vmas[vm->mmu.num_vmas++] = (vma_t){
                .start = map_start, .end = map_end, .prot = prot, .flags = MAP_PRIVATE,
                .vfile_idx = -1, .file_off = 0
            };
        }
    }

    /* Second pass: apply final page protections (handles overlapping page edges cleanly!) */
    for (uint16_t i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD || ph->p_memsz == 0) continue;
        uint64_t seg_vaddr = ph->p_vaddr + load_bias;
        uint64_t map_start = PAGE_ALIGN_DOWN(seg_vaddr);
        uint64_t map_end   = PAGE_ALIGN_UP(seg_vaddr + ph->p_memsz);
        uint32_t prot      = pf_to_prot(ph->p_flags);
        uint64_t pte_flags = PTE_P | PTE_U;
        if (prot & PROT_WRITE) pte_flags |= PTE_W;
        if (!(prot & PROT_EXEC)) pte_flags |= PTE_NX;

        for (uint64_t va = map_start; va < map_end; va += PAGE_SIZE) {
            /* If another segment sharing this boundary page needed W or X, OR permissions! */
            uint64_t cur_pte = 0;
            if (mmu_virt_to_phys(vm, va, &cur_pte) != 0) {
                uint64_t final_flags = pte_flags;
                /* Check if any other PT_LOAD covers this page with W or X */
                for (uint16_t j = 0; j < eh->e_phnum; j++) {
                    if (j == i || phdrs[j].p_type != PT_LOAD) continue;
                    uint64_t s2 = PAGE_ALIGN_DOWN(phdrs[j].p_vaddr + load_bias);
                    uint64_t e2 = PAGE_ALIGN_UP(phdrs[j].p_vaddr + load_bias + phdrs[j].p_memsz);
                    if (va >= s2 && va < e2) {
                        if (phdrs[j].p_flags & PF_W) final_flags |= PTE_W;
                        if (phdrs[j].p_flags & PF_X) final_flags &= ~PTE_NX;
                    }
                }
                mmu_protect_page(vm, va, final_flags);
            }
        }
    }

    /* Scan & patch RDRAND/RDSEED in executable sections (prefer SHF_EXECINSTR sections to avoid rodata!) */
    if (vm->cfg.patch_rdrand) {
        bool scanned_sections = false;
        if (eh->e_shoff && eh->e_shnum &&
            eh->e_shoff + (size_t)eh->e_shnum * eh->e_shentsize <= sz) {
            const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(buf + eh->e_shoff);
            for (uint16_t i = 0; i < eh->e_shnum; i++) {
                if ((shdrs[i].sh_flags & SHF_EXECINSTR) && shdrs[i].sh_size >= 3 && shdrs[i].sh_addr) {
                    x86_scan_and_patch_range(vm, shdrs[i].sh_addr + load_bias, shdrs[i].sh_size);
                    scanned_sections = true;
                }
            }
        }
        if (!scanned_sections) {
            for (uint16_t i = 0; i < eh->e_phnum; i++) {
                const Elf64_Phdr *ph = &phdrs[i];
                if (ph->p_type == PT_LOAD && (ph->p_flags & PF_X) && ph->p_filesz >= 3) {
                    x86_scan_and_patch_range(vm, ph->p_vaddr + load_bias, ph->p_filesz);
                }
            }
        }
    }

    if (record_syms) {
        parse_elf_symbols(vm, buf, sz, load_bias);
    }

    out->max_vaddr = PAGE_ALIGN_UP(max_vaddr + load_bias);
    return 0;
}

uint64_t dethv_lookup_symbol(dethv_vm_t *vm, const char *sym_name) {
    for (uint32_t i = 0; i < vm->syms.count; i++) {
        if (strcmp(vm->syms.syms[i].name, sym_name) == 0)
            return vm->syms.syms[i].addr;
    }
    return 0;
}

static uint64_t stack_push_bytes(dethv_vm_t *vm, uint64_t sp, const void *data, size_t len) {
    sp -= len;
    mmu_copy_to_guest(vm, sp, data, len);
    return sp;
}

static uint64_t stack_push_u64(dethv_vm_t *vm, uint64_t sp, uint64_t val) {
    sp -= 8;
    mmu_copy_to_guest(vm, sp, &val, 8);
    return sp;
}

int dethv_load_elf(dethv_vm_t *vm, const char *path, int argc, char **argv, char **envp) {
    size_t main_sz = 0;
    uint8_t *main_buf = read_host_file(path, &main_sz);
    if (!main_buf) return -1;

    /* Canonical deterministic exe path */
    char resolved[PATH_MAX];
    if (realpath(path, resolved)) {
        snprintf(vm->vfs.exe_path, sizeof(vm->vfs.exe_path), "%.*s",
                 (int)(sizeof(vm->vfs.exe_path) - 1), resolved);
    } else {
        snprintf(vm->vfs.exe_path, sizeof(vm->vfs.exe_path), "%.*s",
                 (int)(sizeof(vm->vfs.exe_path) - 1), path);
    }

    loaded_elf_t main_elf;
    if (map_elf_image(vm, main_buf, main_sz, GUEST_PIE_BASE, true, &main_elf) < 0) {
        free(main_buf);
        return -1;
    }
    free(main_buf);

    /* Initialize heap (brk) deterministically right after main ELF */
    vm->mmu.brk_start = PAGE_ALIGN_UP(main_elf.max_vaddr + PAGE_SIZE);
    vm->mmu.brk_curr  = vm->mmu.brk_start;

    /* Load dynamic linker (PT_INTERP) if dynamically linked! */
    uint64_t initial_rip = main_elf.entry;
    uint64_t interp_base = 0;
    if (main_elf.interp_path[0] != '\0') {
        size_t interp_sz = 0;
        uint8_t *interp_buf = read_host_file(main_elf.interp_path, &interp_sz);
        if (!interp_buf) {
            fprintf(stderr, "[dethv] Failed to load PT_INTERP '%s'\n", main_elf.interp_path);
            return -1;
        }
        loaded_elf_t interp_elf;
        if (map_elf_image(vm, interp_buf, interp_sz, GUEST_INTERP_BASE, false, &interp_elf) < 0) {
            free(interp_buf);
            return -1;
        }
        free(interp_buf);
        interp_base = interp_elf.load_bias;
        initial_rip = interp_elf.entry;
    }

    /* Map initial main thread stack (demand-growable down to GUEST_STACK_TOP - GUEST_STACK_SIZE) */
    vm->mmu.stack_limit  = GUEST_STACK_TOP - GUEST_STACK_SIZE;
    vm->mmu.stack_bottom = GUEST_STACK_TOP - GUEST_STACK_INIT_PAGES * PAGE_SIZE;
    for (uint64_t va = vm->mmu.stack_bottom; va < GUEST_STACK_TOP; va += PAGE_SIZE) {
        uint64_t pa = mmu_alloc_phys_page(vm);
        if (!pa) return -1;
        if (mmu_map_page(vm, va, pa, PTE_P | PTE_W | PTE_U | PTE_NX) < 0) return -1;
    }
    if (vm->mmu.num_vmas < DETHV_MAX_VMAS) {
        vm->mmu.vmas[vm->mmu.num_vmas++] = (vma_t){
            .start = vm->mmu.stack_limit,
            .end   = GUEST_STACK_TOP,
            .prot  = PROT_READ | PROT_WRITE,
            .flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
            .vfile_idx = -1,
            .file_off  = 0
        };
    }

    /* Build deterministic Linux x86_64 initial stack layout:
     *   [high] strings (argv, envp, platform "x86_64", execfn)
     *          16 deterministic AT_RANDOM bytes
     *          auxv[] (NO AT_SYSINFO_EHDR -> disables vDSO so clocks go via syscall!)
     *          envp[] + NULL
     *          argv[] + NULL
     *   [RSP]  argc (16-byte aligned!)
     */
    uint64_t sp = GUEST_STACK_TOP - 16;

    /* Default sanitized deterministic environment if caller passes NULL */
    static char *default_env[] = {
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "HOME=/root",
        "USER=root",
        "LANG=C",
        "LC_ALL=C",
        "TZ=UTC",
        NULL
    };
    char **use_env = envp ? envp : default_env;

    int envc = 0;
    while (use_env[envc]) envc++;
    if (argc <= 0) argc = 1;

    uint64_t argv_ptrs[64];
    uint64_t envp_ptrs[64];
    if (argc > 63) argc = 63;
    if (envc > 63) envc = 63;

    /* Push execfn & platform string */
    uint64_t execfn_addr = stack_push_bytes(vm, sp, vm->vfs.exe_path, strlen(vm->vfs.exe_path) + 1);
    sp = execfn_addr;
    uint64_t plat_addr = stack_push_bytes(vm, sp, "x86_64", 7);
    sp = plat_addr;

    /* Push 16 deterministic AT_RANDOM bytes */
    uint8_t at_random_bytes[16];
    det_rand_bytes(&vm->det, at_random_bytes, sizeof(at_random_bytes));
    sp &= ~15ULL;
    uint64_t random_addr = stack_push_bytes(vm, sp, at_random_bytes, 16);
    sp = random_addr;

    /* Push env strings */
    for (int i = envc - 1; i >= 0; i--) {
        sp = stack_push_bytes(vm, sp, use_env[i], strlen(use_env[i]) + 1);
        envp_ptrs[i] = sp;
    }
    /* Push argv strings */
    for (int i = argc - 1; i >= 0; i--) {
        const char *s = (argv && argv[i]) ? argv[i] : vm->vfs.exe_path;
        sp = stack_push_bytes(vm, sp, s, strlen(s) + 1);
        argv_ptrs[i] = sp;
    }

    /* Align stack so final RSP (pointing at argc) is 16-byte aligned! */
    sp &= ~15ULL;

    typedef struct { uint64_t type; uint64_t val; } auxv_entry_t;
    auxv_entry_t auxv[] = {
        { AT_PHDR,     main_elf.phdr_vaddr },
        { AT_PHENT,    main_elf.phent },
        { AT_PHNUM,    main_elf.phnum },
        { AT_PAGESZ,   PAGE_SIZE },
        { AT_BASE,     interp_base },
        { AT_FLAGS,    0 },
        { AT_ENTRY,    main_elf.entry },
        { AT_UID,      1000 },
        { AT_EUID,     1000 },
        { AT_GID,      1000 },
        { AT_EGID,     1000 },
        { AT_CLKTCK,   100 },
        { AT_SECURE,   0 },
        { AT_RANDOM,   random_addr },
        { AT_PLATFORM, plat_addr },
        { AT_EXECFN,   execfn_addr },
        { AT_HWCAP,    0x178BFBFFULL }, /* Deterministic SSE2/FXSR/MMX/CMOV */
        { AT_HWCAP2,   0 },
        { AT_NULL,     0 }
    };
    int auxc = (int)(sizeof(auxv) / sizeof(auxv[0]));

    /* Total qwords pushed below current sp: 1 (argc) + argc + 1 + envc + 1 + 2*auxc */
    size_t total_qwords = 1 + (size_t)argc + 1 + (size_t)envc + 1 + (size_t)auxc * 2;
    if (total_qwords & 1) {
        sp -= 8; /* Pad so final RSP % 16 == 0 per x86_64 SysV ABI */
    }

    /* Push auxv (reverse order) */
    for (int i = auxc - 1; i >= 0; i--) {
        sp = stack_push_u64(vm, sp, auxv[i].val);
        sp = stack_push_u64(vm, sp, auxv[i].type);
    }
    /* Push envp + NULL */
    sp = stack_push_u64(vm, sp, 0);
    for (int i = envc - 1; i >= 0; i--) {
        sp = stack_push_u64(vm, sp, envp_ptrs[i]);
    }
    /* Push argv + NULL */
    sp = stack_push_u64(vm, sp, 0);
    for (int i = argc - 1; i >= 0; i--) {
        sp = stack_push_u64(vm, sp, argv_ptrs[i]);
    }
    /* Push argc */
    sp = stack_push_u64(vm, sp, (uint64_t)argc);

    /* Set main thread initial registers */
    guest_thread_t *t0 = &vm->sched.threads[0];
    memset(&t0->regs, 0, sizeof(t0->regs));
    t0->regs.rip    = initial_rip;
    t0->regs.rsp    = sp;
    t0->regs.rflags = 0x202;
    vm->shared->regs = t0->regs;
    vm->sregs_dirty = true;

    return 0;
}
