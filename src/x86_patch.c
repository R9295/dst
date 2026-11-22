/*
 * x86_64 Executable-Page Scanner & Deterministic Patcher (O(1) Hash Table)
 *
 * Scans executable code ranges for RDRAND (0F C7 /6, mod=11) and RDSEED
 * (0F C7 /7, mod=11) — distinguishing RDSEED from RDPID (F3 0F C7 /7) —
 * patches them to 0xCC (INT3), and emulates them with deterministic PRNG
 * + exact x86_64 register/flag semantics.
 */

#include "internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline uint32_t patch_hash(uint64_t vaddr) {
    vaddr ^= vaddr >> 33;
    vaddr *= 0xff51afd7ed558ccdULL;
    vaddr ^= vaddr >> 33;
    return (uint32_t)(vaddr & (DETHV_PATCH_HT_SIZE - 1));
}

int x86_patch_init(patch_table_t *pt) {
    memset(pt, 0, sizeof(*pt));
    pt->cap = 1024;
    pt->entries = calloc(pt->cap, sizeof(patch_entry_t));
    pt->ht = malloc(DETHV_PATCH_HT_SIZE * sizeof(int32_t));
    if (!pt->entries || !pt->ht) return -1;
    memset(pt->ht, -1, DETHV_PATCH_HT_SIZE * sizeof(int32_t));
    return 0;
}

void x86_patch_destroy(patch_table_t *pt) {
    free(pt->entries); pt->entries = NULL;
    free(pt->ht);      pt->ht = NULL;
    pt->count = 0;
    pt->cap = 0;
}

static void ht_insert(patch_table_t *pt, uint64_t vaddr, int32_t idx) {
    uint32_t slot = patch_hash(vaddr);
    for (uint32_t step = 0; step < DETHV_PATCH_HT_SIZE; step++) {
        uint32_t pos = (slot + step) & (DETHV_PATCH_HT_SIZE - 1);
        if (pt->ht[pos] == -1 || pt->entries[pt->ht[pos]].vaddr == vaddr) {
            pt->ht[pos] = idx;
            return;
        }
    }
}

void x86_patch_rebuild_ht(patch_table_t *pt) {
    if (!pt->ht) pt->ht = malloc(DETHV_PATCH_HT_SIZE * sizeof(int32_t));
    if (!pt->ht) return;
    memset(pt->ht, -1, DETHV_PATCH_HT_SIZE * sizeof(int32_t));
    for (uint32_t i = 0; i < pt->count; i++) {
        ht_insert(pt, pt->entries[i].vaddr, (int32_t)i);
    }
}

int x86_patch_clone(patch_table_t *dst, const patch_table_t *src) {
    if (dst->cap < src->count) {
        uint32_t ncap = src->count < 1024 ? 1024 : src->count;
        patch_entry_t *ne = realloc(dst->entries, ncap * sizeof(patch_entry_t));
        if (!ne) return -1;
        dst->entries = ne;
        dst->cap = ncap;
    }
    dst->count = src->count;
    dst->cov_hits = src->cov_hits;
    if (src->count > 0) {
        memcpy(dst->entries, src->entries, src->count * sizeof(patch_entry_t));
    }
    if (!dst->ht) dst->ht = malloc(DETHV_PATCH_HT_SIZE * sizeof(int32_t));
    if (!dst->ht) return -1;
    if (src->ht) {
        memcpy(dst->ht, src->ht, DETHV_PATCH_HT_SIZE * sizeof(int32_t));
    } else {
        x86_patch_rebuild_ht(dst);
    }
    return 0;
}

static patch_entry_t *patch_append(patch_table_t *pt, uint64_t vaddr) {
    if (pt->count >= DETHV_MAX_PATCHES) return NULL;
    if (pt->count >= pt->cap) {
        uint32_t ncap = pt->cap ? pt->cap * 2 : 1024;
        if (ncap > DETHV_MAX_PATCHES) ncap = DETHV_MAX_PATCHES;
        patch_entry_t *ne = realloc(pt->entries, ncap * sizeof(patch_entry_t));
        if (!ne) return NULL;
        pt->entries = ne;
        pt->cap = ncap;
    }
    int32_t idx = (int32_t)pt->count++;
    patch_entry_t *e = &pt->entries[idx];
    memset(e, 0, sizeof(*e));
    e->vaddr = vaddr;
    ht_insert(pt, vaddr, idx);
    return e;
}

patch_entry_t *x86_patch_find(patch_table_t *pt, uint64_t vaddr) {
    if (!pt->ht || pt->count == 0) return NULL;
    uint32_t slot = patch_hash(vaddr);
    for (uint32_t step = 0; step < DETHV_PATCH_HT_SIZE; step++) {
        uint32_t pos = (slot + step) & (DETHV_PATCH_HT_SIZE - 1);
        int32_t idx = pt->ht[pos];
        if (idx == -1) return NULL;
        if (pt->entries[idx].vaddr == vaddr) return &pt->entries[idx];
    }
    return NULL;
}

static uint64_t *get_reg_ptr(user_regs_t *r, uint8_t reg_idx) {
    switch (reg_idx & 0xF) {
        case 0:  return &r->rax;
        case 1:  return &r->rcx;
        case 2:  return &r->rdx;
        case 3:  return &r->rbx;
        case 4:  return &r->rsp;
        case 5:  return &r->rbp;
        case 6:  return &r->rsi;
        case 7:  return &r->rdi;
        case 8:  return &r->r8;
        case 9:  return &r->r9;
        case 10: return &r->r10;
        case 11: return &r->r11;
        case 12: return &r->r12;
        case 13: return &r->r13;
        case 14: return &r->r14;
        case 15: return &r->r15;
    }
    return &r->rax;
}

int x86_patch_add_bp(dethv_vm_t *vm, uint64_t vaddr, patch_kind_t kind) {
    patch_entry_t *existing = x86_patch_find(&vm->patches, vaddr);
    if (existing) {
        if (kind == PATCH_SNAPSHOT_BP) existing->kind = PATCH_SNAPSHOT_BP;
        return 0;
    }
    uint8_t orig = 0;
    if (mmu_copy_from_guest(vm, &orig, vaddr, 1) < 0) return -1;
    uint8_t cc = 0xCC;
    if (mmu_copy_to_guest(vm, vaddr, &cc, 1) < 0) return -1;

    patch_entry_t *e = patch_append(&vm->patches, vaddr);
    if (!e) return -1;
    e->kind = kind;
    e->orig_byte = orig;
    e->insn_len = 1;
    return 0;
}

static bool match_rdrand_rdseed(const uint8_t *buf, size_t len, size_t pos,
                                patch_kind_t *kind_out, uint8_t *insn_len_out,
                                uint8_t *reg_out, uint8_t *bits_out) {
    size_t i = pos;
    bool has_66 = false;
    bool has_rex = false;
    uint8_t rex = 0;

    if (i < len && buf[i] == 0x66) { has_66 = true; i++; }
    if (i < len && (buf[i] & 0xF0) == 0x40) { has_rex = true; rex = buf[i]; i++; }
    if (i + 2 >= len) return false;
    if (buf[i] != 0x0F || buf[i + 1] != 0xC7) return false;

    uint8_t modrm = buf[i + 2];
    if (modrm < 0xF0) return false;
    if (pos > 0 && (buf[pos - 1] == 0xF3 || buf[pos - 1] == 0xF2)) return false;
    if (!has_66 && pos > 0 && buf[pos - 1] == 0x66) return false;
    if (!has_66 && !has_rex && pos > 0 && (buf[pos - 1] & 0xF0) == 0x40) return false;

    *kind_out = (modrm <= 0xF7) ? PATCH_RDRAND : PATCH_RDSEED;
    *reg_out  = (modrm & 0x07) | ((has_rex && (rex & 0x01)) ? 8 : 0);
    if (has_rex && (rex & 0x08))      *bits_out = 64;
    else if (has_66)                  *bits_out = 16;
    else                              *bits_out = 32;
    *insn_len_out = (uint8_t)((i + 3) - pos);
    return true;
}

int x86_scan_and_patch_range(dethv_vm_t *vm, uint64_t vaddr, size_t len) {
    if (!vm->cfg.patch_rdrand || len < 3) return 0;
    int patched = 0;
    uint8_t buf[4096 + 16];
    size_t off = 0;
    while (off < len) {
        size_t chunk = 4096;
        if (off + chunk > len) chunk = len - off;
        size_t read_len = chunk;
        if (off + read_len + 8 <= len) read_len += 8;

        if (mmu_virt_to_phys(vm, vaddr + off, NULL) == 0) {
            off += PAGE_SIZE - ((vaddr + off) & (PAGE_SIZE - 1));
            continue;
        }
        size_t avail = 0;
        while (avail < read_len) {
            uint64_t cur = vaddr + off + avail;
            if (mmu_virt_to_phys(vm, cur, NULL) == 0) break;
            size_t to_end = PAGE_SIZE - (cur & (PAGE_SIZE - 1));
            size_t step = (avail + to_end <= read_len) ? to_end : (read_len - avail);
            if (mmu_copy_from_guest(vm, buf + avail, cur, step) < 0) break;
            avail += step;
        }
        if (avail < 3) { off += chunk; continue; }

        size_t scan_end = chunk < avail ? chunk : avail;
        for (size_t i = 0; i < scan_end; i++) {
            patch_kind_t kind;
            uint8_t insn_len, reg_idx, op_bits;
            if (match_rdrand_rdseed(buf, avail, i, &kind, &insn_len, &reg_idx, &op_bits)) {
                uint64_t target_va = vaddr + off + i;
                if (!x86_patch_find(&vm->patches, target_va)) {
                    uint8_t cc = 0xCC;
                    if (mmu_copy_to_guest(vm, target_va, &cc, 1) == 0) {
                        patch_entry_t *e = patch_append(&vm->patches, target_va);
                        if (e) {
                            e->kind = kind;
                            e->orig_byte = buf[i];
                            e->insn_len = insn_len;
                            e->reg_idx = reg_idx;
                            e->op_bits = op_bits;
                            patched++;
                        }
                    }
                }
                i += insn_len - 1;
            }
        }
        off += chunk;
    }
    return patched;
}

bool x86_handle_bp_patch(dethv_vm_t *vm, uint64_t bp_rip) {
    patch_entry_t *e = x86_patch_find(&vm->patches, bp_rip);
    if (!e) return false;

    if (e->kind == PATCH_RDRAND || e->kind == PATCH_RDSEED) {
        uint64_t rval = det_rand64(&vm->det);
        vm->det.rdrand_count++;

        uint64_t *reg = get_reg_ptr(&vm->shared->regs, e->reg_idx);
        if (e->op_bits == 64)      *reg = rval;
        else if (e->op_bits == 32) *reg = (uint32_t)rval;
        else                       *reg = (*reg & ~0xFFFFULL) | (rval & 0xFFFFULL);

        const uint64_t clear_mask = (1ULL << 11) | (1ULL << 7) | (1ULL << 6) |
                                    (1ULL << 4)  | (1ULL << 2);
        vm->shared->regs.rflags = (vm->shared->regs.rflags & ~clear_mask) | 1ULL;
        vm->shared->regs.rip = bp_rip + e->insn_len;
        vm->shared->pmu_prev_rip = vm->shared->regs.rip;
        return true;
    }

    if (e->kind == PATCH_SNAPSHOT_BP) {
        mmu_copy_to_guest(vm, bp_rip, &e->orig_byte, 1);
        vm->shared->regs.rip = bp_rip;
        e->kind = PATCH_NONE;
        vm->running = false;
        vm->stop_reason = DETHV_STOP_SNAPSHOT;
        return true;
    }

    if (e->kind == PATCH_COV_BP) {
        mmu_copy_to_guest(vm, bp_rip, &e->orig_byte, 1);
        if (vm->active_cov_snap) {
            uint64_t pa = mmu_virt_to_phys(vm, bp_rip, NULL);
            if (pa && pa < vm->active_cov_snap->phys_used) {
                vm->active_cov_snap->mem[pa] = e->orig_byte;
            }
            patch_entry_t *se = x86_patch_find(&vm->active_cov_snap->patches, bp_rip);
            if (se) se->hit = 1;
        }
        vm->shared->regs.rip = bp_rip;
        if (!e->hit) {
            e->hit = 1;
            vm->patches.cov_hits++;
        }
        return true;
    }

    return false;
}
