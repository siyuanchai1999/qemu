/*
 *  x86 exception helpers - sysemu code
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/log.h"
#include "tcg/helper-tcg.h"

#include "excp_helper.h"
#include "ECPT_hash.h"
#include "ECPT.h"

#define QEMU_LOG_TRANSLATE(gdb, MASK, FMT, ...)   \
    do {                                                \
        if (likely(!gdb)) {       \
            qemu_log_mask(MASK, FMT, ## __VA_ARGS__);              \
        }                                               \
    } while (0)

int get_pg_mode(CPUX86State *env)
{
    int pg_mode = 0;
    if (env->cr[0] & CR0_WP_MASK) {
        pg_mode |= PG_MODE_WP;
    }
    if (env->cr[4] & CR4_PAE_MASK) {
        pg_mode |= PG_MODE_PAE;
    }
    if (env->cr[4] & CR4_PSE_MASK) {
        pg_mode |= PG_MODE_PSE;
    }
    if (env->cr[4] & CR4_PKE_MASK) {
        pg_mode |= PG_MODE_PKE;
    }
    if (env->cr[4] & CR4_PKS_MASK) {
        pg_mode |= PG_MODE_PKS;
    }
    if (env->cr[4] & CR4_SMEP_MASK) {
        pg_mode |= PG_MODE_SMEP;
    }
    if (env->cr[4] & CR4_LA57_MASK) {
        pg_mode |= PG_MODE_LA57;
    }
    if (env->hflags & HF_LMA_MASK) {
        pg_mode |= PG_MODE_LMA;
    }
    if (env->efer & MSR_EFER_NXE) {
        pg_mode |= PG_MODE_NXE;
    }
    return pg_mode;
}

#define PG_ERROR_OK (-1)

typedef hwaddr (*MMUTranslateFunc)(CPUState *cs, hwaddr gphys, MMUAccessType access_type,
				int *prot);

#define GET_HPHYS(cs, gpa, access_type, prot)  \
	(get_hphys_func ? get_hphys_func(cs, gpa, access_type, prot) : gpa)

#ifdef TARGET_X86_64_ECPT


static uint64_t gen_hash(uint64_t vpn, uint64_t size) {
    uint64_t hash = hash_wrapper(vpn);
    hash = hash % size;
    if (hash > size) {
        printf("Hash value %lu, size %lu\n", hash, size);
        assert(1 == 0 && "Hash value is larger than index\n");
    }

    return hash;
}

/**
     *  crc_64_multi_hash applies hash for n times, where n is the way number
     *  For example,
     *  For way 0: hash = crc64_be(VA)
     *  For way 1: hash = crc64_be(crc64_be(VA))
     *  For way 2: hash = crc64_be(crc64_be(crc64_be(VA)))
     */
// static uint64_t crc_64_multi_hash(uint64_t vpn, uint64_t size, int n) {
//     uint64_t hash = 0, i = 0;
//     // hash = crc64_be(0, &vpn, 5);
//     // for (i = 0; i < n; i++) {
//     //     hash = crc64_be(hash, &vpn, 5);
//     // }

//     hash = crc64_be(0, &vpn, 5); /* at most we need five of them */ 
//     for (i = 0; i < n; i++) {
//         hash = crc64_be(0, &hash, 5);
//     }
//     return hash;
// }

static uint64_t gen_hash64(uint64_t vpn, uint64_t size, uint32_t way) {
    
    // uint64_t hash = crc_64_multi_hash(vpn, size, way);
    uint64_t hash = ecpt_crc64_hash(vpn, way);
    hash = hash % size;

    if (hash > size) {
        printf("Hash value %lu, size %lu\n", hash, size);
        assert(1 == 0 && "Hash value is larger than index\n");
    }

    return hash;
}

static void load_helper(CPUState *cs, void * entry, hwaddr addr, int size) {
	int32_t loaded = 0;
	int32_t needed = size;
	
	void * ptr = (void *) entry;

	while(loaded < needed) {
		if (needed - loaded >= 8) {
			uint64_t * quad_ptr = (uint64_t *) ptr;
			*quad_ptr = x86_ldq_phys(cs, addr);

			ptr += 8;
			loaded += 8;
			addr += 8;
		} else if (needed - loaded >= 4) {
			uint32_t * long_ptr = (uint32_t *) ptr;
			*long_ptr = x86_ldl_phys(cs, addr);

			ptr += 4;
			loaded += 4;
			addr += 4;
		} else if (needed - loaded >= 2) {
			uint16_t * word_ptr = (uint16_t *) ptr;
			*word_ptr = x86_lduw_phys(cs, addr);

			ptr += 2;
			loaded += 2;
			addr += 2;
		} else {
			uint8_t * word_ptr = (uint8_t *) ptr;
			*word_ptr = x86_ldub_phys(cs, addr);

			ptr += 1;
			loaded += 1;
			addr += 1;
		}
	}
}

static inline hwaddr get_pte_addr(hwaddr entry_addr, ecpt_entry_t * entry_p, uint64_t * pte_p) {
    return entry_addr + (uint64_t) (((void *) pte_p) - ((void *) entry_p));
}

static int mmu_translate_ECPT(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                         int is_write1, int mmu_idx, int pg_mode, int gdb,
                         hwaddr *xlat, int *page_size, int *prot)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    int error_code = 0;
    int is_dirty;
    int is_write = is_write1 & 1;
    int is_user = (mmu_idx == MMU_USER_IDX);
    uint64_t rsvd_mask = PG_ADDRESS_MASK & ~MAKE_64BIT_MASK(0, cpu->phys_bits);
    uint32_t page_offset;
    uint32_t pkr;

    /**
     * TODO: support more granularity
     */
    enum Granularity gran = page_4KB;

    // QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "ECPT Translate: addr=%" VADDR_PRIx " w=%d mmu=%d\n",
    //        addr, is_write1, mmu_idx);

    /**
     * TODO: 
     *  unclear meaning of a20_mask
     */
    int32_t a20_mask = x86_get_a20_mask(env);

    /**
     * @brief 
     * cr3 structure for now:
     *      51-12 bits base address for hash page table
     *      11-0 bits #of entries the hash page table can contain
     *      size of the page table obtained by 
     * 
     */
    int w;
    uint64_t vpn, size, hash, cr, pte = 0, rehash_ptr;
    uint64_t * pte_pointer = NULL;
    hwaddr entry_addr = 0, pte_addr = 0;
	ecpt_entry_t * ecpt_base;
	ecpt_entry_t entry;


	for (w = 0; w < ECPT_TOTAL_WAY; w++) {
		


		/* go through all the ways to search for matching tag  */
		/* In real hardware, this should be done in parallel */
		if (w < ECPT_4K_WAY) {
            gran = page_4KB;
            vpn = ADDR_TO_PAGE_NUM_4KB(addr); 
        } 
        else if (w < ECPT_4K_WAY + ECPT_2M_WAY) {
            gran = page_2MB;
			vpn = ADDR_TO_PAGE_NUM_2MB(addr);
        } 
        else if (w < ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY) {
            gran = page_1GB;
			vpn = ADDR_TO_PAGE_NUM_1GB(addr);
        } 
        else if (w < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY) {
            gran = page_4KB;
            vpn = ADDR_TO_PAGE_NUM_4KB(addr);  
        } 
        else if (w < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY) {
            gran = page_2MB;
			vpn = ADDR_TO_PAGE_NUM_2MB(addr);
        } 
        else if (w < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY + ECPT_1G_USER_WAY) {
            gran = page_1GB;
			vpn = ADDR_TO_PAGE_NUM_1GB(addr);
        } else {
            assert(0);
        }

		cr = env->cr[way_to_crN[w]];

		size = GET_HPT_SIZE(cr);

        if (!size) {
            /**
             *  this way is being constructed lazily,
             *      so we don't bother checking this way 
             */ 
            continue;
        }

		hash = gen_hash64(vpn, size, w);
		QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    Translate: w=%d hash=0x%lx vpn =0x%lx size=0x%lx\n",w, hash, vpn, size);

        rehash_ptr = 0;

        if (hash < rehash_ptr) {
            /* not supported for resizing now */
            /* rehash_ptr MBZ right now */
            assert(0);
        } else {
            /* stay with current hash table */

            ecpt_base = (ecpt_entry_t * ) GET_HPT_BASE(cr);
            entry_addr = (uint64_t) &ecpt_base[hash];
            // QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    Translate: load from 0x%016lx\n", entry_addr);

            /* do nothing for now, cuz nested paging is not enabled */
            entry_addr = GET_HPHYS(cs, entry_addr, MMU_DATA_STORE, NULL);

            load_helper(cs, (void *) &entry, entry_addr, sizeof(ecpt_entry_t));
            
            if (ecpt_entry_match_vpn(&entry, vpn)) {
                /* found */
                if (gran == page_4KB) {
                    pte_pointer = pte_offset_from_ecpt_entry(&entry, addr);
                    *page_size = PAGE_SIZE_4KB;
                } else if (gran == page_2MB) {
                    pte_pointer = pmd_offset_from_ecpt_entry(&entry, addr);
                    *page_size = PAGE_SIZE_2MB;
                } else if (gran == page_1GB) {
                    pte_pointer = pud_offset_from_ecpt_entry(&entry, addr);
                    *page_size = PAGE_SIZE_1GB;
                } else {
                    assert(0);
                }
				break;
            } else {
                /* not found move on */
            }
        }
	}

    
    if (w < ECPT_TOTAL_WAY) {
        /* If vpn is matched w must < ECPT_TOTAL_WAY  */
        pte = *pte_pointer;
        pte_addr = get_pte_addr(entry_addr, &entry, pte_pointer);
        QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "ECPT Translate: load from entry at 0x%016lx pte at 0x%016lx pte=0x%016lx way=%d\n", 
            entry_addr, pte_addr, pte, w);
    } else {
        /* This will lead to a page fault */
        pte = 0;
        pte_pointer = NULL;
        pte_addr = 0;
    }
    

    uint64_t ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
    ptep &= pte;
    
    if (!(pte & PG_PRESENT_MASK)) {
		QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    fault triggered. Page not Present!\n");
        goto do_fault;
    }
    
    /**
     * don't need these two symbols here since, we go to the following code if we are arriving at the leaf of the page table
     * 
     */
// do_check_protect:
    rsvd_mask |= (*page_size - 1) & PG_ADDRESS_MASK & ~PG_PSE_PAT_MASK;
// do_check_protect_pse36:
    if (pte & rsvd_mask) {
        goto do_fault_rsvd;
    }
    // ptep ^= PG_NX_MASK;

    /* can the page can be put in the TLB?  prot will tell us */
    if (is_user && !(ptep & PG_USER_MASK)) {
        goto do_fault_protect;
    }

    *prot = 0;
    if (mmu_idx != MMU_KSMAP_IDX || !(ptep & PG_USER_MASK)) {
        *prot |= PAGE_READ;
        if ((ptep & PG_RW_MASK) || !(is_user || (pg_mode & PG_MODE_WP))) {
            *prot |= PAGE_WRITE;
        }
    }
    if (!(ptep & PG_NX_MASK) &&
        (mmu_idx == MMU_USER_IDX ||
         !((pg_mode & PG_MODE_SMEP) && (ptep & PG_USER_MASK)))) {
        *prot |= PAGE_EXEC;
    }

    if (!(env->hflags & HF_LMA_MASK)) {
        pkr = 0;
    } else if (ptep & PG_USER_MASK) {
        pkr = pg_mode & PG_MODE_PKE ? env->pkru : 0;
    } else {
        pkr = pg_mode & PG_MODE_PKS ? env->pkrs : 0;
    }
    if (pkr) {
        uint32_t pk = (pte & PG_PKRU_MASK) >> PG_PKRU_BIT;
        uint32_t pkr_ad = (pkr >> pk * 2) & 1;
        uint32_t pkr_wd = (pkr >> pk * 2) & 2;
        uint32_t pkr_prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;

        if (pkr_ad) {
            pkr_prot &= ~(PAGE_READ | PAGE_WRITE);
        } else if (pkr_wd && (is_user || (pg_mode & PG_MODE_WP))) {
            pkr_prot &= ~PAGE_WRITE;
        }

        *prot &= pkr_prot;
        if ((pkr_prot & (1 << is_write1)) == 0) {
            assert(is_write1 != 2);
            error_code |= PG_ERROR_PK_MASK;
            goto do_fault_protect;
        }
    }

    if ((*prot & (1 << is_write1)) == 0) {
        goto do_fault_protect;
    }

    /* yes, it can! */
    is_dirty = is_write && !(pte & PG_DIRTY_MASK);
    if (!(pte & PG_ACCESSED_MASK) || is_dirty) {
        pte |= PG_ACCESSED_MASK;
        if (is_dirty) {
            pte |= PG_DIRTY_MASK;
        }
        // hwaddr pte_addr = get_pte_addr(entry_addr, addr);
        QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    update dirty at %lx pte=%lx!\n", pte_addr, pte );
        x86_stl_phys_notdirty(cs, pte_addr, pte);
    }

    if (!(pte & PG_DIRTY_MASK)) {
        /* only set write access if already dirty... otherwise wait
           for dirty access */
        assert(!is_write);
        *prot &= ~PAGE_WRITE;
    }

    pte = pte & a20_mask;

    /* align to page_size */
    // pte &= PG_ADDRESS_MASK & ~(*page_size - 1);
    if (gran == page_4KB) {
        page_offset = ADDR_TO_OFFSET_4KB(addr);
        pte = PAGE_NUM_TO_ADDR_4KB(ADDR_TO_PAGE_NUM_4KB(pte));
    } else if (gran == page_2MB) {
        page_offset = ADDR_TO_OFFSET_2MB(addr);
        pte = PAGE_NUM_TO_ADDR_2MB(ADDR_TO_PAGE_NUM_2MB(pte));
    } else {
        /* gran == page_1GB */
        page_offset = ADDR_TO_OFFSET_1GB(addr);
        pte = PAGE_NUM_TO_ADDR_1GB(ADDR_TO_PAGE_NUM_1GB(pte));
    }
    
    pte = pte & PG_ADDRESS_MASK;
    *xlat = GET_HPHYS(cs, pte + page_offset, is_write1, prot);
    return PG_ERROR_OK;

 do_fault_rsvd:
    error_code |= PG_ERROR_RSVD_MASK;
 do_fault_protect:
    error_code |= PG_ERROR_P_MASK;
 do_fault:
    error_code |= (is_write << PG_ERROR_W_BIT);
    if (is_user)
        error_code |= PG_ERROR_U_MASK;
    if (is_write1 == 2 &&
        (((pg_mode & PG_MODE_NXE) && (pg_mode & PG_MODE_PAE)) ||
         (pg_mode & PG_MODE_SMEP)))
        error_code |= PG_ERROR_I_D_MASK;
    return error_code;
}


static int mmu_translate_2M_basic(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                         uint64_t cr3, int is_write1, int mmu_idx, int pg_mode, int gdb,
                         hwaddr *xlat, int *page_size, int *prot)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    int error_code = 0;
    int is_dirty;
    int is_write = is_write1 & 1;
    int is_user = (mmu_idx == MMU_USER_IDX);
    uint64_t rsvd_mask = PG_ADDRESS_MASK & ~MAKE_64BIT_MASK(0, cpu->phys_bits);
    uint32_t page_offset;
    uint32_t pkr;

    // QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "2M_basic Translate: addr=%" VADDR_PRIx " w=%d mmu=%d cr3=0x%016lx\n",
        //    addr, is_write1, mmu_idx, cr3);
    // printf("Translate: addr=%" VADDR_PRIx " w=%d mmu=%d cr3=0x%16lx\n",
        //    addr, is_write1, mmu_idx, cr3);

    /**
     * TODO: 
     *  unclear meaning of a20_mask
     */
    int32_t a20_mask = x86_get_a20_mask(env);

    /**
     * @brief 
     * cr3 structure for now:
     *      51-12 bits base address for hash page table
     *      11-0 bits #of entries the hash page table can contain
     *      size of the page table obtained by 
     * 
     *  TODO:
     *      translation only for 2MB right now
     */
    uint64_t size = GET_HPT_SIZE(cr3);
    uint64_t hash = gen_hash(ADDR_REMOVE_OFFSET_SHIFT_2MB(addr) , size);
    
    hwaddr pte_addr = GET_HPT_BASE(cr3)                /* page table base */
                            + (hash << 3);           /*  offset; */
	// QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    Translate: load from 0x%016lx\n", pte_addr);
    pte_addr = GET_HPHYS(cs, pte_addr, MMU_DATA_STORE, NULL);
    uint64_t pte = x86_ldq_phys(cs, pte_addr);


    QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "2M_basic Translate: load from 0x%016lx pte=0x%016lx\n", pte_addr, pte);

    uint64_t ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
    ptep &= pte;
    *page_size = PAGE_SIZE_2MB;
    /*  */
    if (!(pte & PG_PRESENT_MASK)) {
		QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "    fault triggered. Page not Present!\n");
        goto do_fault;
    }

/* TODO: fix legacy from paging's protection check */
    /**
     * don't need these two symbols here since, we go to the following code if we are arriving at the leaf of the page table
     * 
     */
// do_check_protect:
    rsvd_mask |= (*page_size - 1) & PG_ADDRESS_MASK & ~PG_PSE_PAT_MASK;
// do_check_protect_pse36:
    if (pte & rsvd_mask) {
        goto do_fault_rsvd;
    }
    // ptep ^= PG_NX_MASK;

    /* can the page can be put in the TLB?  prot will tell us */
    if (is_user && !(ptep & PG_USER_MASK)) {
        goto do_fault_protect;
    }

    *prot = 0;
    if (mmu_idx != MMU_KSMAP_IDX || !(ptep & PG_USER_MASK)) {
        *prot |= PAGE_READ;
        if ((ptep & PG_RW_MASK) || !(is_user || (pg_mode & PG_MODE_WP))) {
            *prot |= PAGE_WRITE;
        }
    }
    if (!(ptep & PG_NX_MASK) &&
        (mmu_idx == MMU_USER_IDX ||
         !((pg_mode & PG_MODE_SMEP) && (ptep & PG_USER_MASK)))) {
        *prot |= PAGE_EXEC;
    }

    if (!(env->hflags & HF_LMA_MASK)) {
        pkr = 0;
    } else if (ptep & PG_USER_MASK) {
        pkr = pg_mode & PG_MODE_PKE ? env->pkru : 0;
    } else {
        pkr = pg_mode & PG_MODE_PKS ? env->pkrs : 0;
    }
    if (pkr) {
        uint32_t pk = (pte & PG_PKRU_MASK) >> PG_PKRU_BIT;
        uint32_t pkr_ad = (pkr >> pk * 2) & 1;
        uint32_t pkr_wd = (pkr >> pk * 2) & 2;
        uint32_t pkr_prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;

        if (pkr_ad) {
            pkr_prot &= ~(PAGE_READ | PAGE_WRITE);
        } else if (pkr_wd && (is_user || (pg_mode & PG_MODE_WP))) {
            pkr_prot &= ~PAGE_WRITE;
        }

        *prot &= pkr_prot;
        if ((pkr_prot & (1 << is_write1)) == 0) {
            assert(is_write1 != 2);
            error_code |= PG_ERROR_PK_MASK;
            goto do_fault_protect;
        }
    }

    if ((*prot & (1 << is_write1)) == 0) {
        goto do_fault_protect;
    }

    /* yes, it can! */
    is_dirty = is_write && !(pte & PG_DIRTY_MASK);
    if (!(pte & PG_ACCESSED_MASK) || is_dirty) {
        pte |= PG_ACCESSED_MASK;
        if (is_dirty) {
            pte |= PG_DIRTY_MASK;
        }
        x86_stl_phys_notdirty(cs, pte_addr, pte);
    }

    if (!(pte & PG_DIRTY_MASK)) {
        /* only set write access if already dirty... otherwise wait
           for dirty access */
        assert(!is_write);
        *prot &= ~PAGE_WRITE;
    }

    pte = pte & a20_mask;

    /* align to page_size */
    // pte &= PG_ADDRESS_MASK & ~(*page_size - 1);
    page_offset = ADDR_TO_OFFSET_2MB(addr);
    pte = SHIFT_TO_ADDR_2MB(ADDR_REMOVE_OFFSET_SHIFT_2MB(pte));
    pte = pte & PG_ADDRESS_MASK;
    *xlat = GET_HPHYS(cs, pte + page_offset, is_write1, prot);
    return PG_ERROR_OK;

 do_fault_rsvd:
    error_code |= PG_ERROR_RSVD_MASK;
 do_fault_protect:
    error_code |= PG_ERROR_P_MASK;
 do_fault:
    error_code |= (is_write << PG_ERROR_W_BIT);
    if (is_user)
        error_code |= PG_ERROR_U_MASK;
    if (is_write1 == 2 &&
        (((pg_mode & PG_MODE_NXE) && (pg_mode & PG_MODE_PAE)) ||
         (pg_mode & PG_MODE_SMEP)))
        error_code |= PG_ERROR_I_D_MASK;
    return error_code;
}

static int mmu_translate(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                         uint64_t cr3, int is_write1, int mmu_idx, int pg_mode, int gdb,
                         hwaddr *xlat, int *page_size, int *prot) {

    // X86CPU *cpu = X86_CPU(cs);
    // CPUX86State *env = &cpu->env;

    // int after_transition = !!(env->cr[4] & CR4_ECPT_MASK);
    int after_transition = !!(cr3 & CR3_TRANSITION_BIT);

    if (after_transition) {
        return mmu_translate_ECPT(cs, addr, get_hphys_func, is_write1, mmu_idx, pg_mode, gdb, xlat, page_size, prot);
    } else {
        return mmu_translate_2M_basic(cs, addr, get_hphys_func, cr3, is_write1, mmu_idx, pg_mode, gdb, xlat, page_size, prot);
    }
}

#else 
static int mmu_translate(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                         uint64_t cr3, int is_write1, int mmu_idx, int pg_mode,
                         hwaddr *xlat, int *page_size, int *prot)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    uint64_t ptep, pte;
    int32_t a20_mask;
    target_ulong pde_addr, pte_addr;
    int error_code = 0;
    int is_dirty, is_write, is_user;
    uint64_t rsvd_mask = PG_ADDRESS_MASK & ~MAKE_64BIT_MASK(0, cpu->phys_bits);
    uint32_t page_offset;
    uint32_t pkr;

    is_user = (mmu_idx == MMU_USER_IDX);
    is_write = is_write1 & 1;
    a20_mask = x86_get_a20_mask(env);

    if (!(pg_mode & PG_MODE_NXE)) {
        rsvd_mask |= PG_NX_MASK;
    }

    if (pg_mode & PG_MODE_PAE) {
        uint64_t pde, pdpe;
        target_ulong pdpe_addr;

#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK) {
            bool la57 = pg_mode & PG_MODE_LA57;
            uint64_t pml5e_addr, pml5e;
            uint64_t pml4e_addr, pml4e;
            int32_t sext;

            /* test virtual address sign extension */
            sext = la57 ? (int64_t)addr >> 56 : (int64_t)addr >> 47;
            if (get_hphys_func && sext != 0 && sext != -1) {
                env->error_code = 0;
                cs->exception_index = EXCP0D_GPF;
                return 1;
            }

            if (la57) {
                pml5e_addr = ((cr3 & ~0xfff) +
                        (((addr >> 48) & 0x1ff) << 3)) & a20_mask;
                pml5e_addr = GET_HPHYS(cs, pml5e_addr, MMU_DATA_STORE, NULL);
                pml5e = x86_ldq_phys(cs, pml5e_addr);
                if (!(pml5e & PG_PRESENT_MASK)) {
                    goto do_fault;
                }
                if (pml5e & (rsvd_mask | PG_PSE_MASK)) {
                    goto do_fault_rsvd;
                }
                if (!(pml5e & PG_ACCESSED_MASK)) {
                    pml5e |= PG_ACCESSED_MASK;
                    x86_stl_phys_notdirty(cs, pml5e_addr, pml5e);
                }
                ptep = pml5e ^ PG_NX_MASK;
            } else {
                pml5e = cr3;
                ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
            }

            pml4e_addr = ((pml5e & PG_ADDRESS_MASK) +
                    (((addr >> 39) & 0x1ff) << 3)) & a20_mask;
            pml4e_addr = GET_HPHYS(cs, pml4e_addr, MMU_DATA_STORE, NULL);
            pml4e = x86_ldq_phys(cs, pml4e_addr);
            if (!(pml4e & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pml4e & (rsvd_mask | PG_PSE_MASK)) {
                goto do_fault_rsvd;
            }
            if (!(pml4e & PG_ACCESSED_MASK)) {
                pml4e |= PG_ACCESSED_MASK;
                x86_stl_phys_notdirty(cs, pml4e_addr, pml4e);
            }
            ptep &= pml4e ^ PG_NX_MASK;
            pdpe_addr = ((pml4e & PG_ADDRESS_MASK) + (((addr >> 30) & 0x1ff) << 3)) &
                a20_mask;
            pdpe_addr = GET_HPHYS(cs, pdpe_addr, MMU_DATA_STORE, NULL);
            pdpe = x86_ldq_phys(cs, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            if (pdpe & rsvd_mask) {
                goto do_fault_rsvd;
            }
            ptep &= pdpe ^ PG_NX_MASK;
            if (!(pdpe & PG_ACCESSED_MASK)) {
                pdpe |= PG_ACCESSED_MASK;
                x86_stl_phys_notdirty(cs, pdpe_addr, pdpe);
            }
            if (pdpe & PG_PSE_MASK) {
                /* 1 GB page */
                *page_size = 1024 * 1024 * 1024;
                pte_addr = pdpe_addr;
                pte = pdpe;
                goto do_check_protect;
            }
        } else
#endif
        {
            /* XXX: load them when cr3 is loaded ? */
            pdpe_addr = ((cr3 & ~0x1f) + ((addr >> 27) & 0x18)) &
                a20_mask;
            pdpe_addr = GET_HPHYS(cs, pdpe_addr, MMU_DATA_STORE, NULL);
            pdpe = x86_ldq_phys(cs, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                goto do_fault;
            }
            rsvd_mask |= PG_HI_USER_MASK;
            if (pdpe & (rsvd_mask | PG_NX_MASK)) {
                goto do_fault_rsvd;
            }
            ptep = PG_NX_MASK | PG_USER_MASK | PG_RW_MASK;
        }

        pde_addr = ((pdpe & PG_ADDRESS_MASK) + (((addr >> 21) & 0x1ff) << 3)) &
            a20_mask;
        pde_addr = GET_HPHYS(cs, pde_addr, MMU_DATA_STORE, NULL);
        pde = x86_ldq_phys(cs, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pde & rsvd_mask) {
            goto do_fault_rsvd;
        }
        ptep &= pde ^ PG_NX_MASK;
        if (pde & PG_PSE_MASK) {
            /* 2 MB page */
            *page_size = 2048 * 1024;
            pte_addr = pde_addr;
            pte = pde;
            goto do_check_protect;
        }
        /* 4 KB page */
        if (!(pde & PG_ACCESSED_MASK)) {
            pde |= PG_ACCESSED_MASK;
            x86_stl_phys_notdirty(cs, pde_addr, pde);
        }
        pte_addr = ((pde & PG_ADDRESS_MASK) + (((addr >> 12) & 0x1ff) << 3)) &
            a20_mask;
        pte_addr = GET_HPHYS(cs, pte_addr, MMU_DATA_STORE, NULL);
        pte = x86_ldq_phys(cs, pte_addr);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        if (pte & rsvd_mask) {
            goto do_fault_rsvd;
        }
        /* combine pde and pte nx, user and rw protections */

        /* pte[63] -> if page non executable */
        /* ptep[63] -> if page executable */
        /* A page is executable only if ALL of its parent page entries has NX bit as 0 */
        /* the logic is reversed here to simplify the AND logic */

        ptep &= pte ^ PG_NX_MASK;
        
        
        *page_size = 4096;
    } else {
        uint32_t pde;

        /* page directory entry */
        pde_addr = ((cr3 & ~0xfff) + ((addr >> 20) & 0xffc)) &
            a20_mask;
        pde_addr = GET_HPHYS(cs, pde_addr, MMU_DATA_STORE, NULL);
        pde = x86_ldl_phys(cs, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        ptep = pde | PG_NX_MASK;

        /* if PSE bit is set, then we use a 4MB page */
        if ((pde & PG_PSE_MASK) && (pg_mode & PG_MODE_PSE)) {
            *page_size = 4096 * 1024;
            pte_addr = pde_addr;

            /* Bits 20-13 provide bits 39-32 of the address, bit 21 is reserved.
             * Leave bits 20-13 in place for setting accessed/dirty bits below.
             */
            pte = pde | ((pde & 0x1fe000LL) << (32 - 13));
            rsvd_mask = 0x200000;
            goto do_check_protect_pse36;
        }

        if (!(pde & PG_ACCESSED_MASK)) {
            pde |= PG_ACCESSED_MASK;
            x86_stl_phys_notdirty(cs, pde_addr, pde);
        }

        /* page directory entry */
        pte_addr = ((pde & ~0xfff) + ((addr >> 10) & 0xffc)) &
            a20_mask;
        pte_addr = GET_HPHYS(cs, pte_addr, MMU_DATA_STORE, NULL);
        pte = x86_ldl_phys(cs, pte_addr);
        if (!(pte & PG_PRESENT_MASK)) {
            goto do_fault;
        }
        /* combine pde and pte user and rw protections */
        ptep &= pte | PG_NX_MASK;
        *page_size = 4096;
        rsvd_mask = 0;
    }

do_check_protect:
    rsvd_mask |= (*page_size - 1) & PG_ADDRESS_MASK & ~PG_PSE_PAT_MASK;
do_check_protect_pse36:
    if (pte & rsvd_mask) {
        goto do_fault_rsvd;
    }
    ptep ^= PG_NX_MASK;

    /* can the page can be put in the TLB?  prot will tell us */
    if (is_user && !(ptep & PG_USER_MASK)) {
        goto do_fault_protect;
    }

    *prot = 0;
    if (mmu_idx != MMU_KSMAP_IDX || !(ptep & PG_USER_MASK)) {
        *prot |= PAGE_READ;
        if ((ptep & PG_RW_MASK) || !(is_user || (pg_mode & PG_MODE_WP))) {
            *prot |= PAGE_WRITE;
        }
    }
    if (!(ptep & PG_NX_MASK) &&
        (mmu_idx == MMU_USER_IDX ||
         !((pg_mode & PG_MODE_SMEP) && (ptep & PG_USER_MASK)))) {
        *prot |= PAGE_EXEC;
    }

    if (!(env->hflags & HF_LMA_MASK)) {
        pkr = 0;
    } else if (ptep & PG_USER_MASK) {
        pkr = pg_mode & PG_MODE_PKE ? env->pkru : 0;
    } else {
        pkr = pg_mode & PG_MODE_PKS ? env->pkrs : 0;
    }
    if (pkr) {
        uint32_t pk = (pte & PG_PKRU_MASK) >> PG_PKRU_BIT;
        uint32_t pkr_ad = (pkr >> pk * 2) & 1;
        uint32_t pkr_wd = (pkr >> pk * 2) & 2;
        uint32_t pkr_prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;

        if (pkr_ad) {
            pkr_prot &= ~(PAGE_READ | PAGE_WRITE);
        } else if (pkr_wd && (is_user || (pg_mode & PG_MODE_WP))) {
            pkr_prot &= ~PAGE_WRITE;
        }

        *prot &= pkr_prot;
        if ((pkr_prot & (1 << is_write1)) == 0) {
            assert(is_write1 != 2);
            error_code |= PG_ERROR_PK_MASK;
            goto do_fault_protect;
        }
    }

    if ((*prot & (1 << is_write1)) == 0) {
        goto do_fault_protect;
    }

    /* yes, it can! */
    is_dirty = is_write && !(pte & PG_DIRTY_MASK);
    if (!(pte & PG_ACCESSED_MASK) || is_dirty) {
        pte |= PG_ACCESSED_MASK;
        if (is_dirty) {
            pte |= PG_DIRTY_MASK;
        }
        x86_stl_phys_notdirty(cs, pte_addr, pte);
    }

    if (!(pte & PG_DIRTY_MASK)) {
        /* only set write access if already dirty... otherwise wait
           for dirty access */
        assert(!is_write);
        *prot &= ~PAGE_WRITE;
    }

    pte = pte & a20_mask;

    /* align to page_size */
    pte &= PG_ADDRESS_MASK & ~(*page_size - 1);
    page_offset = addr & (*page_size - 1);
    *xlat = GET_HPHYS(cs, pte + page_offset, is_write1, prot);
    return PG_ERROR_OK;

 do_fault_rsvd:
    error_code |= PG_ERROR_RSVD_MASK;
 do_fault_protect:
    error_code |= PG_ERROR_P_MASK;
 do_fault:
    error_code |= (is_write << PG_ERROR_W_BIT);
    if (is_user)
        error_code |= PG_ERROR_U_MASK;
    if (is_write1 == 2 &&
        (((pg_mode & PG_MODE_NXE) && (pg_mode & PG_MODE_PAE)) ||
         (pg_mode & PG_MODE_SMEP)))
        error_code |= PG_ERROR_I_D_MASK;
    return error_code;
}
#endif

hwaddr get_hphys(CPUState *cs, hwaddr gphys, MMUAccessType access_type,
                        int *prot)
{
    CPUX86State *env = &X86_CPU(cs)->env;
    uint64_t exit_info_1;
    int page_size;
    int next_prot;
    hwaddr hphys;

	// qemu_log_mask(CPU_LOG_MMU, "\tNested Paging turned on=%d\n",
    //        (env->hflags2 & HF2_NPT_MASK));
	/* nested paging not turned on for now */


    if (likely(!(env->hflags2 & HF2_NPT_MASK))) {
        return gphys;
    }

    exit_info_1 = mmu_translate(cs, gphys, NULL, env->nested_cr3, 
                               access_type, MMU_USER_IDX, env->nested_pg_mode, 0 /* gdb */, 
                               &hphys, &page_size, &next_prot);
    if (exit_info_1 == PG_ERROR_OK) {
        if (prot) {
            *prot &= next_prot;
        }
        return hphys;
    }

    x86_stq_phys(cs, env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2),
                 gphys);
    if (prot) {
        exit_info_1 |= SVM_NPTEXIT_GPA;
    } else { /* page table access */
        exit_info_1 |= SVM_NPTEXIT_GPT;
    }
    cpu_vmexit(env, SVM_EXIT_NPF, exit_info_1, env->retaddr);
}

/* return value:
 * -1 = cannot handle fault
 * 0  = nothing more to do
 * 1  = generate PF fault
 */
static int handle_mmu_fault(CPUState *cs, vaddr addr, int size,
                            int is_write1, int mmu_idx)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    int error_code = PG_ERROR_OK;
    int pg_mode, prot, page_size;
    hwaddr paddr;
    hwaddr vaddr;

#if defined(DEBUG_MMU)
    printf("MMU fault: addr=%" VADDR_PRIx " w=%d mmu=%d eip=" TARGET_FMT_lx "\n",
           addr, is_write1, mmu_idx, env->eip);
#endif
    qemu_log_mask(CPU_LOG_MMU, "MMU fault: addr=%" VADDR_PRIx " w=%d mmu=%d eip=" TARGET_FMT_lx "\n",
           addr, is_write1, mmu_idx, env->eip);
    // printf("MMU fault: addr=%" VADDR_PRIx " w=%d mmu=%d eip=" TARGET_FMT_lx "\n",
        //    addr, is_write1, mmu_idx, env->eip);

    if (!(env->cr[0] & CR0_PG_MASK)) {
        paddr = addr;
#ifdef TARGET_X86_64
        if (!(env->hflags & HF_LMA_MASK)) {
            /* Without long mode we can only address 32bits in real mode */
            paddr = (uint32_t)paddr;
        }
#endif
        prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        page_size = 4096;
    } else {
        pg_mode = get_pg_mode(env);
        error_code = mmu_translate(cs, addr, get_hphys, env->cr[3], is_write1,
                                   mmu_idx, pg_mode, 0 /* gdb */, 
                                   &paddr, &page_size, &prot);
        qemu_log_mask(CPU_LOG_MMU, "Translation Result: paddr=%" VADDR_PRIx " page_size=0x%x prot=0x%x err=%x\n",
           paddr, page_size, prot, error_code);
        // printf("Translation Result: paddr=%" VADDR_PRIx " page_size=%d prot=0x%x\n",
        //    paddr, page_size, prot);
    }

    if (error_code == PG_ERROR_OK) {
        /* Even if 4MB pages, we map only one 4KB page in the cache to
           avoid filling it too fast */
        vaddr = addr & TARGET_PAGE_MASK;
        paddr &= TARGET_PAGE_MASK;

        assert(prot & (1 << is_write1));
        tlb_set_page_with_attrs(cs, vaddr, paddr, cpu_get_mem_attrs(env),
                                prot, mmu_idx, page_size);
        return 0;
    } else {
        if (env->intercept_exceptions & (1 << EXCP0E_PAGE)) {
            /* cr2 is not modified in case of exceptions */
            x86_stq_phys(cs,
                     env->vm_vmcb + offsetof(struct vmcb, control.exit_info_2),
                     addr);
        } else {
            env->cr[2] = addr;
        }
        env->error_code = error_code;
        cs->exception_index = EXCP0E_PAGE;
        return 1;
    }
}

bool x86_cpu_tlb_fill(CPUState *cs, vaddr addr, int size,
                      MMUAccessType access_type, int mmu_idx,
                      bool probe, uintptr_t retaddr)
{
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;

    env->retaddr = retaddr;
    if (handle_mmu_fault(cs, addr, size, access_type, mmu_idx)) {
        /* FIXME: On error in get_hphys we have already jumped out.  */
        g_assert(!probe);
        raise_exception_err_ra(env, cs->exception_index,
                               env->error_code, retaddr);
    }
    return true;
}

int mmu_translate_wrapper(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                         uint64_t cr3, int is_write1, int mmu_idx, int pg_mode,
                         hwaddr *xlat, int *page_size, int *prot) {
    return mmu_translate(cs, addr, get_hphys_func, cr3, is_write1, mmu_idx, pg_mode, 1 /* gdb */, xlat, page_size, prot);
}
