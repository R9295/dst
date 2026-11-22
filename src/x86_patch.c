/*
 * x86_64 Executable-Page Scanner & Deterministic Patcher
 *
 * On AMD SVM (KVM), clearing RDRAND/RDSEED in CPUID does NOT cause hardware
 * traps when an unmodified binary executes RDRAND or RDSEED directly.
 * This module cleanly scans executable code ranges for RDRAND (0F C7 /6, mod=11)
 * and RDSEED (0F C7 /7, mod=11) — carefully distinguishing RDSEED from RDPID
 * (F3 0F C7 /7) — replaces the first byte with 0xCC (INT3), and emulates them
 * with our deterministic PRNG + exact x86_64 register/flag semantics!
 *
 * Also manages snapshot breakpoints and one-shot coverage breakpoints.
 */

#include "internal.h"
#include <stdio.h>
#include <string.h>

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

patch_entry_t *x86_patch_find(patch_table_t *pt, uint64_t vaddr) {
    for (uint32_t i = 0; i < pt->count; i++) {
        if (pt->entries[i].vaddr == vaddr)
            return &pt->entries[i];
    }
    return NULL;
}

int x86_patch_add_bp(dethv_vm_t *vm, uint64_t vaddr, patch_kind_t kind) {
    if (vm->patches.count >= DETHV_MAX_PATCHES) return -1;
    patch_entry_t *existing = x86_patch_find(&vm->patches, vaddr);
    if (existing) {
        if (kind == PATCH_SNAPSHOT_BP) {
            existing->kind = PATCH_SNAPSHOT_BP;
            return 0;
        }
        return 0;
    }
    uint8_t orig = 0;
    if (mmu_copy_from_guest(vm, &orig, vaddr, 1) < 0)
        return -1;
    uint8_t cc = 0xCC;
    if (mmu_copy_to_guest(vm, vaddr, &cc, 1) < 0)
        return -1;

    patch_entry_t *e = &vm->patches.entries[vm->patches.count++];
    memset(e, 0, sizeof(*e));
    e->vaddr = vaddr;
    e->kind = kind;
    e->orig_byte = orig;
    e->insn_len = 1;
    return 0;
}

/*
 * Check if bytes starting at buf[pos..len) encode a valid RDRAND or RDSEED:
 *   Optional prefix 0x66 (16-bit operand size)
 *   Optional REX prefix 0x40..0x4F (REX.W -> 64-bit, REX.B -> r8..r15)
 *   Opcode: 0x0F 0xC7
 *   ModRM:  0xF0..0xF7 -> RDRAND (mod=11, reg=6, rm=0..7)
 *           0xF8..0xFF -> RDSEED (mod=11, reg=7, rm=0..7)
 *   NOTE: MUST NOT be preceded by 0xF3 (which would be RDPID!) or 0xF2!
 */
static bool match_rdrand_rdseed(const uint8_t *buf, size_t len, size_t pos,
                                patch_kind_t *kind_out, uint8_t *insn_len_out,
                                uint8_t *reg_out, uint8_t *bits_out) {
    /* Look for 0F C7 F0..FF at pos (with optional 66 and/or REX immediately before) */
    size_t i = pos;
    bool has_66 = false;
    bool has_rex = false;
    uint8_t rex = 0;

    if (i < len && buf[i] == 0x66) {
        has_66 = true;
        i++;
    }
    if (i < len && (buf[i] & 0xF0) == 0x40) {
        has_rex = true;
        rex = buf[i];
        i++;
    }
    if (i + 2 >= len) return false;
    if (buf[i] != 0x0F || buf[i + 1] != 0xC7) return false;

    uint8_t modrm = buf[i + 2];
    if (modrm < 0xF0) return false;

    /* Reject if immediately preceded by F2/F3 (e.g. F3 0F C7 F8 = RDPID!) */
    if (pos > 0 && (buf[pos - 1] == 0xF3 || buf[pos - 1] == 0xF2))
        return false;
    /* Also reject if REX was preceded by 66 (we should match starting at 66, not REX!) */
    if (!has_66 && pos > 0 && buf[pos - 1] == 0x66)
        return false;
    if (!has_66 && !has_rex && pos > 0 && (buf[pos - 1] & 0xF0) == 0x40)
        return false;

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

    /* Scan in chunks (up to 64 KB with 8-byte overlap for page boundaries) */
    uint8_t buf[4096 + 16];
    size_t off = 0;
    while (off < len) {
        size_t chunk = 4096;
        if (off + chunk > len) chunk = len - off;
        size_t read_len = chunk;
        if (off + read_len + 8 <= len) read_len += 8;

        /* Skip unmapped pages */
        if (mmu_virt_to_phys(vm, vaddr + off, NULL) == 0) {
            off += PAGE_SIZE - ((vaddr + off) & (PAGE_SIZE - 1));
            continue;
        }
        /* Clamp read_len to contiguous mapped pages */
        size_t avail = 0;
        while (avail < read_len) {
            uint64_t cur = vaddr + off + avail;
            if (mmu_virt_to_phys(vm, cur, NULL) == 0) break;
            size_t to_end = PAGE_SIZE - (cur & (PAGE_SIZE - 1));
            size_t step = (avail + to_end <= read_len) ? to_end : (read_len - avail);
            if (mmu_copy_from_guest(vm, buf + avail, cur, step) < 0) break;
            avail += step;
        }
        if (avail < 3) {
            off += chunk;
            continue;
        }

        size_t scan_end = chunk < avail ? chunk : avail;
        for (size_t i = 0; i < scan_end; i++) {
            patch_kind_t kind;
            uint8_t insn_len, reg_idx, op_bits;
            if (match_rdrand_rdseed(buf, avail, i, &kind, &insn_len, &reg_idx, &op_bits)) {
                uint64_t target_va = vaddr + off + i;
                if (!x86_patch_find(&vm->patches, target_va) &&
                    vm->patches.count < DETHV_MAX_PATCHES) {
                    uint8_t cc = 0xCC;
                    if (mmu_copy_to_guest(vm, target_va, &cc, 1) == 0) {
                        patch_entry_t *e = &vm->patches.entries[vm->patches.count++];
                        memset(e, 0, sizeof(*e));
                        e->vaddr = target_va;
                        e->kind = kind;
                        e->orig_byte = buf[i];
                        e->insn_len = insn_len;
                        e->reg_idx = reg_idx;
                        e->op_bits = op_bits;
                        patched++;
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
        if (e->op_bits == 64) {
            *reg = rval;
        } else if (e->op_bits == 32) {
            /* 32-bit write zero-extends upper 32 bits on x86_64 */
            *reg = (uint32_t)rval;
        } else {
            /* 16-bit write preserves upper 48 bits */
            *reg = (*reg & ~0xFFFFULL) | (rval & 0xFFFFULL);
        }

        /* x86 RDRAND/RDSEED semantics: CF=1 (success), OF=SF=ZF=AF=PF=0 */
        const uint64_t clear_mask = (1ULL << 11) | (1ULL << 7) | (1ULL << 6) |
                                    (1ULL << 4)  | (1ULL << 2);
        vm->shared->regs.rflags = (vm->shared->regs.rflags & ~clear_mask) | 1ULL;
        vm->shared->regs.rip = bp_rip + e->insn_len;
        vm->shared->pmu_prev_rip = vm->shared->regs.rip;
        return true;
    }

    if (e->kind == PATCH_SNAPSHOT_BP) {
        /* Restore original instruction byte & rewind RIP so execution continues cleanly! */
        mmu_copy_to_guest(vm, bp_rip, &e->orig_byte, 1);
        vm->shared->regs.rip = bp_rip;
        e->kind = PATCH_NONE; /* One-shot trigger */
        vm->running = false;
        vm->stop_reason = DETHV_STOP_SNAPSHOT;
        return true;
    }

    if (e->kind == PATCH_COV_BP) {
        /* One-shot coverage breakpoint: restore original byte in live RAM & snapshot, record hit! */
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
