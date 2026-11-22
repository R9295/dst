#include "internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static uint64_t prot_to_pte(uint32_t prot) {
    uint64_t flags = PTE_P | PTE_U;
    if (prot & PROT_WRITE) flags |= PTE_W;
    if (!(prot & PROT_EXEC)) flags |= PTE_NX;
    return flags;
}

uint64_t mmu_alloc_phys_page(dethv_vm_t *vm) {
    /* Recycle unmapped physical page if available (safe: always >= snap_phys_floor) */
    if (vm->phys_free_list && vm->phys_free_count > 0) {
        uint64_t p = vm->phys_free_list[--vm->phys_free_count];
        memset(vm->mem + p, 0, PAGE_SIZE);
        return p;
    }
    if (vm->mmu.next_phys == 0xC0000000ULL) {
        vm->mmu.next_phys = 0x100000000ULL; /* Skip 3GB..4GB MMIO/LAPIC hole! */
    }
    if (vm->mmu.next_phys + PAGE_SIZE > vm->mmu.ram_size) {
        fprintf(stderr, "[dethv] OUT OF GUEST PHYSICAL MEMORY (used=%llu MiB, max=%llu MiB)\n",
                (unsigned long long)(vm->mmu.next_phys >> 20),
                (unsigned long long)(vm->mmu.ram_size >> 20));
        return 0;
    }
    uint64_t p = vm->mmu.next_phys;
    vm->mmu.next_phys += PAGE_SIZE;
    memset(vm->mem + p, 0, PAGE_SIZE);
    return p;
}

static void mmu_free_phys_page(dethv_vm_t *vm, uint64_t pa) {
    if (!vm->phys_free_list) return;
    if (pa < GUEST_PHYS_ALLOC_START || pa < vm->snap_phys_floor) return;
    if (vm->phys_free_count < DETHV_MAX_FREE_PAGES) {
        vm->phys_free_list[vm->phys_free_count++] = pa & PAGE_MASK;
    }
}

static uint64_t *get_or_alloc_table(dethv_vm_t *vm, uint64_t table_phys, uint64_t idx, bool user) {
    uint64_t *table = (uint64_t *)(vm->mem + table_phys);
    uint64_t *parent_entry = &table[idx];
    if (!(*parent_entry & PTE_P)) {
        uint64_t pt_phys = mmu_alloc_phys_page(vm);
        if (!pt_phys) return NULL;
        vmm_mark_phys_dirty(vm, table_phys);
        *parent_entry = pt_phys | PTE_P | PTE_W | (user ? PTE_U : 0);
    } else if (user && !(*parent_entry & PTE_U)) {
        vmm_mark_phys_dirty(vm, table_phys);
        *parent_entry |= PTE_U;
    }
    return (uint64_t *)(vm->mem + (*parent_entry & PTE_ADDR_MASK));
}

int mmu_init(dethv_vm_t *vm) {
    memset(&vm->mmu, 0, sizeof(vm->mmu));
    vm->mmu.ram_size = vm->ram_size;
    vm->mmu.next_phys = GUEST_PHYS_ALLOC_START;
    vm->mmu.mmap_cursor = GUEST_MMAP_TOP;

    uint64_t pml4_phys = mmu_alloc_phys_page(vm);
    if (!pml4_phys) return -1;
    vm->mmu.pml4_phys = pml4_phys;

    for (uint64_t off = 0x10000; off < 0x20000; off += PAGE_SIZE) {
        uint64_t vaddr = GUEST_KERN_VIRT_OFFSET + off;
        if (mmu_map_page(vm, vaddr, off, PTE_P | PTE_W) < 0)
            return -1;
    }

    if (mmu_map_page(vm, GUEST_LAPIC_VADDR, GUEST_LAPIC_PHYS,
                     PTE_P | PTE_W | PTE_PCD | PTE_PWT | PTE_NX) < 0)
        return -1;

    return 0;
}

int mmu_map_page(dethv_vm_t *vm, uint64_t vaddr, uint64_t paddr, uint64_t pte_flags) {
    bool is_user = (pte_flags & PTE_U) != 0;
    uint64_t i4 = (vaddr >> 39) & 0x1FF;
    uint64_t i3 = (vaddr >> 30) & 0x1FF;
    uint64_t i2 = (vaddr >> 21) & 0x1FF;
    uint64_t i1 = (vaddr >> 12) & 0x1FF;

    uint64_t *pdpt = get_or_alloc_table(vm, vm->mmu.pml4_phys, i4, is_user);
    if (!pdpt) return -1;
    uint64_t pdpt_phys = ((uint64_t *)(vm->mem + vm->mmu.pml4_phys))[i4] & PTE_ADDR_MASK;
    uint64_t *pd = get_or_alloc_table(vm, pdpt_phys, i3, is_user);
    if (!pd) return -1;
    uint64_t pd_phys = pdpt[i3] & PTE_ADDR_MASK;
    uint64_t *pt = get_or_alloc_table(vm, pd_phys, i2, is_user);
    if (!pt) return -1;
    uint64_t pt_phys = pd[i2] & PTE_ADDR_MASK;

    vmm_mark_phys_dirty(vm, pt_phys);
    pt[i1] = (paddr & PTE_ADDR_MASK) | pte_flags;
    vm->sregs_dirty = true;
    vm->sregs_changed_since_snap = true;
    return 0;
}

int mmu_unmap_page(dethv_vm_t *vm, uint64_t vaddr) {
    uint64_t *pml4 = (uint64_t *)(vm->mem + vm->mmu.pml4_phys);
    uint64_t i4 = (vaddr >> 39) & 0x1FF;
    if (!(pml4[i4] & PTE_P)) return 0;
    uint64_t *pdpt = (uint64_t *)(vm->mem + (pml4[i4] & PTE_ADDR_MASK));
    uint64_t i3 = (vaddr >> 30) & 0x1FF;
    if (!(pdpt[i3] & PTE_P)) return 0;
    uint64_t *pd = (uint64_t *)(vm->mem + (pdpt[i3] & PTE_ADDR_MASK));
    uint64_t i2 = (vaddr >> 21) & 0x1FF;
    if (!(pd[i2] & PTE_P)) return 0;
    uint64_t pt_phys = pd[i2] & PTE_ADDR_MASK;
    uint64_t *pt = (uint64_t *)(vm->mem + pt_phys);
    uint64_t i1 = (vaddr >> 12) & 0x1FF;
    if (pt[i1] & PTE_P) {
        uint64_t old_pa = pt[i1] & PTE_ADDR_MASK;
        if (pt[i1] & PTE_D) vmm_mark_phys_dirty(vm, old_pa);
        vmm_mark_phys_dirty(vm, pt_phys);
        pt[i1] = 0;
        mmu_free_phys_page(vm, old_pa);
        vm->sregs_dirty = true;
        vm->sregs_changed_since_snap = true;
    }
    return 0;
}

int mmu_protect_page(dethv_vm_t *vm, uint64_t vaddr, uint64_t pte_flags) {
    uint64_t *pml4 = (uint64_t *)(vm->mem + vm->mmu.pml4_phys);
    uint64_t i4 = (vaddr >> 39) & 0x1FF;
    if (!(pml4[i4] & PTE_P)) return -1;
    uint64_t *pdpt = (uint64_t *)(vm->mem + (pml4[i4] & PTE_ADDR_MASK));
    uint64_t i3 = (vaddr >> 30) & 0x1FF;
    if (!(pdpt[i3] & PTE_P)) return -1;
    uint64_t *pd = (uint64_t *)(vm->mem + (pdpt[i3] & PTE_ADDR_MASK));
    uint64_t i2 = (vaddr >> 21) & 0x1FF;
    if (!(pd[i2] & PTE_P)) return -1;
    uint64_t pt_phys = pd[i2] & PTE_ADDR_MASK;
    uint64_t *pt = (uint64_t *)(vm->mem + pt_phys);
    uint64_t i1 = (vaddr >> 12) & 0x1FF;
    if (!(pt[i1] & PTE_P)) return -1;
    if (pt[i1] & PTE_D) vmm_mark_phys_dirty(vm, pt[i1] & PTE_ADDR_MASK);
    vmm_mark_phys_dirty(vm, pt_phys);
    pt[i1] = (pt[i1] & PTE_ADDR_MASK) | pte_flags;
    vm->sregs_dirty = true;
    vm->sregs_changed_since_snap = true;
    return 0;
}

uint64_t mmu_virt_to_phys(const dethv_vm_t *vm, uint64_t vaddr, uint64_t *pte_out) {
    uint64_t *pml4 = (uint64_t *)(vm->mem + vm->mmu.pml4_phys);
    uint64_t e4 = pml4[(vaddr >> 39) & 0x1FF];
    if (!(e4 & PTE_P)) return 0;
    uint64_t *pdpt = (uint64_t *)(vm->mem + (e4 & PTE_ADDR_MASK));
    uint64_t e3 = pdpt[(vaddr >> 30) & 0x1FF];
    if (!(e3 & PTE_P)) return 0;
    uint64_t *pd = (uint64_t *)(vm->mem + (e3 & PTE_ADDR_MASK));
    uint64_t e2 = pd[(vaddr >> 21) & 0x1FF];
    if (!(e2 & PTE_P)) return 0;
    uint64_t *pt = (uint64_t *)(vm->mem + (e2 & PTE_ADDR_MASK));
    uint64_t e1 = pt[(vaddr >> 12) & 0x1FF];
    if (!(e1 & PTE_P)) return 0;
    if (pte_out) *pte_out = e1;
    return (e1 & PTE_ADDR_MASK) | (vaddr & (PAGE_SIZE - 1));
}

/* Sync a MAP_SHARED VMA's mapped guest memory back into its backing vfile! */
static void sync_single_shared_vma(dethv_vm_t *vm, const vma_t *v) {
    if (v->vfile_idx < 0 || !(v->flags & MAP_SHARED) || !(v->prot & PROT_WRITE)) return;
    if ((uint32_t)v->vfile_idx >= vm->vfs.max_vfile_used) return;
    vfile_t *vf = &vm->vfs.vfiles[v->vfile_idx];
    if (!vf->used || vf->is_dir) return;

    for (uint64_t va = v->start; va < v->end; va += PAGE_SIZE) {
        uint64_t pte = 0;
        uint64_t pa = mmu_virt_to_phys(vm, va, &pte);
        if (!pa) continue;
        uint64_t foff = v->file_off + (va - v->start);
        if (foff >= vf->len) break;
        size_t chunk = PAGE_SIZE;
        if (foff + chunk > vf->len) chunk = (size_t)(vf->len - foff);
        memcpy(vf->data + foff, vm->mem + (pa & PAGE_MASK), chunk);
    }
}

void mmu_sync_vfile_from_vmas(dethv_vm_t *vm, int32_t vfile_idx) {
    if (vfile_idx < 0) return;
    for (uint32_t i = 0; i < vm->mmu.num_vmas; i++) {
        if (vm->mmu.vmas[i].vfile_idx == vfile_idx) {
            sync_single_shared_vma(vm, &vm->mmu.vmas[i]);
        }
    }
}

void mmu_sync_all_shared_vmas_in_range(dethv_vm_t *vm, uint64_t start, uint64_t end) {
    for (uint32_t i = 0; i < vm->mmu.num_vmas; i++) {
        vma_t *v = &vm->mmu.vmas[i];
        if (v->vfile_idx >= 0 && v->start < end && start < v->end) {
            sync_single_shared_vma(vm, v);
        }
    }
}

static void vma_remove_range(mmu_state_t *mmu, uint64_t start, uint64_t end) {
    for (uint32_t i = 0; i < mmu->num_vmas; ) {
        vma_t *v = &mmu->vmas[i];
        if (v->end <= start || v->start >= end) { i++; continue; }
        if (v->start >= start && v->end <= end) {
            mmu->vmas[i] = mmu->vmas[--mmu->num_vmas];
            continue;
        }
        if (v->start < start && v->end > end) {
            if (mmu->num_vmas < DETHV_MAX_VMAS) {
                vma_t right = *v;
                right.start = end;
                if (right.vfile_idx >= 0) right.file_off += (end - v->start);
                v->end = start;
                mmu->vmas[mmu->num_vmas++] = right;
            }
            i++;
        } else if (v->start < start) {
            v->end = start;
            i++;
        } else {
            if (v->vfile_idx >= 0) v->file_off += (end - v->start);
            v->start = end;
            i++;
        }
    }
}

static const vma_t *vma_find_overlap(const mmu_state_t *mmu, uint64_t start, uint64_t end) {
    for (uint32_t i = 0; i < mmu->num_vmas; i++) {
        if (mmu->vmas[i].start < end && start < mmu->vmas[i].end)
            return &mmu->vmas[i];
    }
    return NULL;
}

static void vma_add(mmu_state_t *mmu, uint64_t start, uint64_t end, uint32_t prot, uint32_t flags, int32_t vf_idx, uint64_t foff) {
    vma_remove_range(mmu, start, end);
    if (mmu->num_vmas < DETHV_MAX_VMAS) {
        mmu->vmas[mmu->num_vmas++] = (vma_t){
            .start = start, .end = end, .prot = prot, .flags = flags,
            .vfile_idx = vf_idx, .file_off = foff
        };
    }
}

static vma_t *vma_find(mmu_state_t *mmu, uint64_t addr) {
    for (uint32_t i = 0; i < mmu->num_vmas; i++) {
        if (addr >= mmu->vmas[i].start && addr < mmu->vmas[i].end)
            return &mmu->vmas[i];
    }
    return NULL;
}

void mmu_set_vma_vfile(dethv_vm_t *vm, uint64_t start, int32_t vfile_idx, uint64_t file_off) {
    vma_t *v = vma_find(&vm->mmu, start);
    if (v) {
        v->vfile_idx = vfile_idx;
        v->file_off  = file_off;
    }
}

uint64_t mmu_mmap_region(dethv_vm_t *vm, uint64_t hint, size_t len, uint32_t prot, uint32_t flags, bool populate) {
    if (len == 0) return (uint64_t)-22;
    size_t aligned_len = PAGE_ALIGN_UP(len);
    uint64_t base = 0;

    if (flags & MAP_FIXED) {
        if (hint & (PAGE_SIZE - 1)) return (uint64_t)-22;
        base = hint;
        mmu_sync_all_shared_vmas_in_range(vm, base, base + aligned_len);
        for (uint64_t va = base; va < base + aligned_len; va += PAGE_SIZE) {
            mmu_unmap_page(vm, va);
        }
    } else if (hint && !(hint & (PAGE_SIZE - 1)) &&
               hint >= 0x10000ULL && hint + aligned_len < GUEST_STACK_TOP - GUEST_STACK_SIZE &&
               !vma_find_overlap(&vm->mmu, hint, hint + aligned_len)) {
        base = hint;
    } else {
        /* Deterministic top-down allocation with O(1) overlap jump */
        uint64_t cand = (vm->mmu.mmap_cursor > aligned_len) ? PAGE_ALIGN_DOWN(vm->mmu.mmap_cursor - aligned_len) : 0;
        const vma_t *ov;
        while (cand >= 0x10000000ULL && (ov = vma_find_overlap(&vm->mmu, cand, cand + aligned_len)) != NULL) {
            if (ov->start <= aligned_len) { cand = 0; break; }
            cand = PAGE_ALIGN_DOWN(ov->start - aligned_len);
        }
        /* Wrap around to top of mmap arena if cursor reached bottom (reclaims unmapped gaps!) */
        if (cand < 0x10000000ULL) {
            cand = PAGE_ALIGN_DOWN(GUEST_MMAP_TOP - aligned_len);
            while (cand >= 0x10000000ULL && (ov = vma_find_overlap(&vm->mmu, cand, cand + aligned_len)) != NULL) {
                if (ov->start <= aligned_len) { cand = 0; break; }
                cand = PAGE_ALIGN_DOWN(ov->start - aligned_len);
            }
        }
        if (cand < 0x10000000ULL) return (uint64_t)-12;
        base = cand;
        vm->mmu.mmap_cursor = base;
    }

    vma_add(&vm->mmu, base, base + aligned_len, prot, flags, -1, 0);

    if (populate && prot != PROT_NONE) {
        uint64_t pte_flags = prot_to_pte(prot);
        for (uint64_t va = base; va < base + aligned_len; va += PAGE_SIZE) {
            uint64_t pa = mmu_alloc_phys_page(vm);
            if (!pa) return (uint64_t)-12;
            if (mmu_map_page(vm, va, pa, pte_flags) < 0) return (uint64_t)-12;
        }
    }
    return base;
}

int mmu_munmap_region(dethv_vm_t *vm, uint64_t addr, size_t len) {
    if ((addr & (PAGE_SIZE - 1)) || len == 0) return -22;
    size_t aligned_len = PAGE_ALIGN_UP(len);
    mmu_sync_all_shared_vmas_in_range(vm, addr, addr + aligned_len);
    vma_remove_range(&vm->mmu, addr, addr + aligned_len);
    for (uint64_t va = addr; va < addr + aligned_len; va += PAGE_SIZE) {
        mmu_unmap_page(vm, va);
    }
    return 0;
}

int mmu_mprotect_region(dethv_vm_t *vm, uint64_t addr, size_t len, uint32_t prot) {
    if (addr & (PAGE_SIZE - 1)) return -22;
    if (len == 0) return 0;
    size_t aligned_len = PAGE_ALIGN_UP(len);
    uint64_t end = addr + aligned_len;

    for (uint32_t i = 0; i < vm->mmu.num_vmas; i++) {
        vma_t *v = &vm->mmu.vmas[i];
        if (v->end <= addr || v->start >= end) continue;
        uint64_t ov_start  = v->start > addr ? v->start : addr;
        uint64_t ov_end    = v->end < end ? v->end : end;
        uint32_t old_prot  = v->prot;
        uint32_t old_flags = v->flags;
        int32_t  old_vf    = v->vfile_idx;
        uint64_t old_foff  = v->file_off;
        uint64_t old_start = v->start;
        uint64_t old_end   = v->end;
        if (ov_start == old_start && ov_end == old_end) {
            v->prot = prot;
        } else {
            vma_remove_range(&vm->mmu, old_start, old_end);
            if (old_start < ov_start)
                vma_add(&vm->mmu, old_start, ov_start, old_prot, old_flags, old_vf, old_foff);
            vma_add(&vm->mmu, ov_start, ov_end, prot, old_flags, old_vf, old_vf >= 0 ? old_foff + (ov_start - old_start) : 0);
            if (ov_end < old_end)
                vma_add(&vm->mmu, ov_end, old_end, old_prot, old_flags, old_vf, old_vf >= 0 ? old_foff + (ov_end - old_start) : 0);
            i = (uint32_t)-1;
        }
    }

    uint64_t pte_flags = prot_to_pte(prot);
    for (uint64_t va = addr; va < end; va += PAGE_SIZE) {
        if (prot == PROT_NONE) {
            mmu_unmap_page(vm, va);
        } else {
            uint64_t pte = 0;
            uint64_t pa = mmu_virt_to_phys(vm, va, &pte);
            if (pa != 0) {
                if (prot & PROT_WRITE) vmm_mark_phys_dirty(vm, pa);
                mmu_protect_page(vm, va, pte_flags);
            }
        }
    }

    if ((prot & PROT_EXEC) && vm->cfg.patch_rdrand) {
        x86_scan_and_patch_range(vm, addr, aligned_len);
    }
    return 0;
}

uint64_t mmu_brk(dethv_vm_t *vm, uint64_t new_brk) {
    if (new_brk == 0 || new_brk < vm->mmu.brk_start) return vm->mmu.brk_curr;
    if (new_brk > vm->mmu.brk_start + (2ULL * 1024 * 1024 * 1024)) return vm->mmu.brk_curr;
    uint64_t old_top = PAGE_ALIGN_UP(vm->mmu.brk_curr);
    uint64_t new_top = PAGE_ALIGN_UP(new_brk);
    if (new_top > old_top) {
        for (uint64_t va = old_top; va < new_top; va += PAGE_SIZE) {
            uint64_t pa = mmu_alloc_phys_page(vm);
            if (!pa) return vm->mmu.brk_curr;
            if (mmu_map_page(vm, va, pa, PTE_P | PTE_W | PTE_U | PTE_NX) < 0)
                return vm->mmu.brk_curr;
        }
        vma_add(&vm->mmu, vm->mmu.brk_start, new_top, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0);
    }
    vm->mmu.brk_curr = new_brk;
    return vm->mmu.brk_curr;
}

bool mmu_handle_page_fault(dethv_vm_t *vm, uint64_t cr2, uint64_t errcode) {
    bool present  = (errcode & 1) != 0;
    bool is_write = (errcode & 2) != 0;
    bool is_exec  = (errcode & 16) != 0;
    if (present) return false;

    uint64_t page_va = PAGE_ALIGN_DOWN(cr2);
    vma_t *vma = vma_find(&vm->mmu, page_va);
    if (!vma) {
        if (page_va >= vm->mmu.stack_limit && page_va < vm->mmu.stack_bottom) {
            uint64_t pa = mmu_alloc_phys_page(vm);
            if (!pa) return false;
            if (mmu_map_page(vm, page_va, pa, PTE_P | PTE_W | PTE_U | PTE_NX) < 0) return false;
            if (page_va < vm->mmu.stack_bottom) vm->mmu.stack_bottom = page_va;
            return true;
        }
        return false;
    }

    if (vma->prot == PROT_NONE) return false;
    if (is_write && !(vma->prot & PROT_WRITE)) return false;
    if (is_exec  && !(vma->prot & PROT_EXEC))  return false;

    uint64_t pa = mmu_alloc_phys_page(vm);
    if (!pa) return false;
    if (mmu_map_page(vm, page_va, pa, prot_to_pte(vma->prot)) < 0) return false;
    return true;
}

int mmu_copy_to_guest(dethv_vm_t *vm, uint64_t dst_vaddr, const void *src, size_t len) {
    const uint8_t *sp = (const uint8_t *)src;
    while (len > 0) {
        uint64_t page_off = dst_vaddr & (PAGE_SIZE - 1);
        size_t chunk = PAGE_SIZE - page_off;
        if (chunk > len) chunk = len;

        uint64_t pa = mmu_virt_to_phys(vm, dst_vaddr, NULL);
        if (!pa) {
            if (!mmu_handle_page_fault(vm, dst_vaddr, 2)) return -14;
            pa = mmu_virt_to_phys(vm, dst_vaddr, NULL);
            if (!pa) return -14;
        }
        vmm_mark_phys_dirty(vm, pa);
        memcpy(vm->mem + pa, sp, chunk);
        dst_vaddr += chunk;
        sp += chunk;
        len -= chunk;
    }
    return 0;
}

int mmu_copy_from_guest(const dethv_vm_t *vm, void *dst, uint64_t src_vaddr, size_t len) {
    uint8_t *dp = (uint8_t *)dst;
    while (len > 0) {
        uint64_t page_off = src_vaddr & (PAGE_SIZE - 1);
        size_t chunk = PAGE_SIZE - page_off;
        if (chunk > len) chunk = len;

        uint64_t pa = mmu_virt_to_phys(vm, src_vaddr, NULL);
        if (!pa) {
            if (!mmu_handle_page_fault((dethv_vm_t *)vm, src_vaddr, 0)) return -14;
            pa = mmu_virt_to_phys(vm, src_vaddr, NULL);
            if (!pa) return -14;
        }
        memcpy(dp, vm->mem + pa, chunk);
        src_vaddr += chunk;
        dp += chunk;
        len -= chunk;
    }
    return 0;
}

int mmu_read_cstring(const dethv_vm_t *vm, uint64_t vaddr, char *buf, size_t max_len) {
    if (max_len == 0) return -22;
    for (size_t i = 0; i < max_len - 1; i++) {
        uint8_t c = 0;
        if (mmu_copy_from_guest(vm, &c, vaddr + i, 1) < 0) return -14;
        buf[i] = (char)c;
        if (c == '\0') return (int)i;
    }
    buf[max_len - 1] = '\0';
    return (int)(max_len - 1);
}
