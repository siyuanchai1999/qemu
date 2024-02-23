#include "ECPT.h"
#include "qemu/log.h"

#include "ECPT_utils.h"

#define QEMU_LOG_TRANSLATE(FMT, ...)   \
    do {                                                \
            qemu_log_mask(CPU_LOG_MMU, FMT, ## __VA_ARGS__); \
    } while (0)

// uint32_t way_to_crN[ECPT_MAX_WAY]= {3,1,5,6,7,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23};
uint32_t way_to_crN[ECPT_MAX_WAY]= {3,1,5,6,7,9,10,11,12,13,14,15};

uint32_t find_rehash_way(uint32_t way)
{
	uint32_t base = 0;
	
	if (way < ECPT_4K_WAY) {
		base = 0;
	} else if (way < ECPT_4K_WAY + ECPT_2M_WAY) {
		base = ECPT_4K_WAY;
	} else if (way < ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY) {
		base = ECPT_4K_WAY + ECPT_2M_WAY;
	} else if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY) {
		base = ECPT_KERNEL_WAY;
	} else if (way <
		   ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY) {
		base = ECPT_KERNEL_WAY + ECPT_4K_USER_WAY;
	} else if (way < ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY +
				 ECPT_1G_USER_WAY) {
		base = ECPT_KERNEL_WAY + ECPT_4K_USER_WAY + ECPT_2M_USER_WAY;
	} else {
        assert(0);
		return 0;
	}

	assert(way - base < ECPT_REHASH_WAY);
	return ECPT_TOTAL_WAY + way - base;
}

static cwt_entry_t __cwc_pud[CWC_PUD_SIZE] = {};
static cwt_entry_t __cwc_pmd[CWC_PMD_SIZE] = {};

static uint64_t __cwc_pud_priorities[CWC_PUD_SIZE] = {};
static uint64_t __cwc_pmd_priorities[CWC_PMD_SIZE] = {};

cwc_cache_t cwc_pud = {
	.capacity = CWC_PUD_SIZE,
	.accesses = 0,
	.misses = 0,
	.lru_gen_counter = 0,
	.lru_priorities = &__cwc_pud_priorities[0],
	.entries = &__cwc_pud[0],
};

cwc_cache_t cwc_pmd = {
	.capacity = CWC_PMD_SIZE,
	.accesses = 0,
	.misses = 0,
	.lru_gen_counter = 0,
	.lru_priorities = &__cwc_pmd_priorities[0],
	.entries = &__cwc_pmd[0],
};

static uint64_t cwt_get_vpn(uint64_t vaddr, CWTGranularity cwt_gran) 
{
	if (cwt_gran == CWT_2MB) {
		return VADDR_TO_CWT_VPN_2MB(vaddr);
	} else if (cwt_gran == CWT_1GB) {
		return VADDR_TO_CWT_VPN_1GB(vaddr);
	} else {
		assert(0);
		return 0;
	}
}

static uint64_t cwt_entry_get_vpn(cwt_entry_t * e) 
{
	uint64_t vpn = 0;
	uint16_t i = 0;
	cwt_header_t * header;
	for (; i < CWT_N_BYTES_FOR_VPN; i++) {
		header = &e->sec_headers[i];
		vpn |= (header->partial_vpn << (i * CWT_VPN_BITS_PER_BYTE));
	}
	return vpn;
}

static inline int cwt_entry_match_vpn(cwt_entry_t *entry, uint64_t vpn)
{
	return cwt_entry_get_vpn(entry) == vpn;
}

static uint16_t cwt_entry_get_valid_header_num(cwt_entry_t *e)
{
	uint32_t valid_num = 0;
	uint16_t i = 0;
	cwt_header_t * header;
	for (; i < CWT_N_SECTION_VALID_NUM_LEN; i++) {
		header = &e->sec_headers[i + CWT_N_SECTION_VALID_NUM_START];
		valid_num |= (header->partial_vpn << (i * CWT_VALID_NUM_BITS_PER_BYTE));
	}
	return valid_num;
}

static uint64_t cwt_get_idx_from_vaddr(uint64_t vaddr, CWTGranularity cwt_gran)
{
	if (cwt_gran == CWT_1GB) {
		return VADDR_TO_CWT_1G_HEADER_IDX(vaddr);
	} else if (cwt_gran == CWT_2MB) {
		return VADDR_TO_CWT_2M_HEADER_IDX(vaddr);
	} else {
		assert(0);
		return -1;
	}
}

static inline void cwt_update_hit(cwc_cache_t *cwc, int i_entry) 
{
	cwc->lru_gen_counter++;
	cwc->lru_priorities[i_entry] = cwc->lru_gen_counter;
	assert(i_entry < cwc->capacity);
}

/* Find the one with lowest priority */
static uint32_t get_lru_entry(cwc_cache_t *cwc)
{
	uint32_t i = 0;
	uint32_t lru_entry = 0;
	uint64_t lru_priority = UINT64_MAX;
	for (; i < cwc->capacity; i++) {
		if (cwc->lru_priorities[i] < lru_priority) {
			lru_priority = cwc->lru_priorities[i];
			lru_entry = i;
		}
	}
	return lru_entry;
}


static void cwt_select_way(uint64_t vaddr, CWTGranularity cwt_gran, bool is_kernel, /* input */
		       uint32_t *way_start, uint32_t *way_end,
		       uint64_t *vpn /* output */) 
{
	*vpn = cwt_get_vpn(vaddr, cwt_gran);

	if (is_kernel) {
		if (cwt_gran == CWT_2MB) {
			*way_start = 0;
			*way_end = CWT_2MB_KERNEL_N_WAY;

		} else if (cwt_gran == CWT_1GB) {
			*way_start = CWT_2MB_KERNEL_N_WAY;
			*way_end = CWT_2MB_KERNEL_N_WAY + CWT_1GB_KERNEL_N_WAY;

		} else {
			warn_report("cwt_select_way doesn't support cwt_gran=%d", cwt_gran);
			assert(0);
		} 
	} else {
		if (cwt_gran == CWT_2MB) {
			*way_start = CWT_KERNEL_WAY;
			*way_end = CWT_KERNEL_WAY + CWT_2MB_USER_N_WAY;
		} else if (cwt_gran == CWT_1GB) {
			*way_start = CWT_KERNEL_WAY + CWT_2MB_USER_N_WAY;
			*way_end = CWT_KERNEL_WAY + CWT_2MB_USER_N_WAY + CWT_1GB_USER_N_WAY;
		} else {
			warn_report("cwt_select_way doesn't support cwt_gran=%d", cwt_gran);
			assert(0);
		}
	}
}

static inline void do_cwt_update(cwc_cache_t *cwc, cwt_entry_t * replacement, uint32_t i_entry) 
{
	
	cwc->entries[i_entry] = *replacement;
	cwc->lru_gen_counter++;
	cwc->lru_priorities[i_entry] = cwc->lru_gen_counter;
}

static void cwt_update_miss_helper(cwc_cache_t *cwc, cwt_entry_t * replacement) 
{
	
	uint32_t lru_entry = get_lru_entry(cwc);
	do_cwt_update(cwc, replacement, lru_entry);

	QEMU_LOG_TRANSLATE("CWT: update miss lru_entry=%d replace_vpn=%lx\n",
					   lru_entry, cwt_entry_get_vpn(replacement));
}

static int cwc_get_stale_entry(cwc_cache_t *cwc, uint64_t vpn)
{
	int i = 0;
	for (; i < cwc->capacity; i++) {
		if (cwt_entry_match_vpn(&cwc->entries[i], vpn)) {
			return i;
		}
	}
	return -1;
}

static void cwc_update_stale_helper(cwc_cache_t *cwc, cwt_entry_t * replacement, uint64_t vaddr, CWTGranularity gran)
{
	int i = cwc_get_stale_entry(cwc, cwt_get_vpn(vaddr, gran));

	assert(i >= 0);
	do_cwt_update(cwc, replacement, (uint32_t) i);
	QEMU_LOG_TRANSLATE("CWT: update stale stale_entry=%d replace_vpn=%lx\n", i, cwt_entry_get_vpn(replacement));
}

// void cwc_update_stale()

int fetch_from_cwt(CPUState *cs, cwc_cache_t *cwc, uint64_t vaddr, CWTGranularity gran, bool cwc_stale)
{
	X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
	/* get lru entry to be replaced */
	
	
	/* get the way range */
	uint32_t way_start = 0, way_end = 0, way = 0;
	uint64_t vpn = 0;
	cwt_select_way(vaddr, gran, is_kernel_addr(env, vaddr), &way_start,
					&way_end, &vpn);
	
	cwt_entry_t cwt_entry = {0};
	cwt_entry_t matched_entries[CWT_TOTAL_N_WAY] = {0};
	uint32_t n_matched_entries = 0;

	for (way = way_start; way < way_end; way++) {
		uint64_t cr = 0, size = 0, hash = 0;
		uint64_t rehash_ptr = 0;
		hwaddr cwt_entry_addr = 0;
		cwt_entry_t *cwt_base = NULL;

		cr = env->cwt_msr[way];
		size = GET_HPT_SIZE(cr);

		if (!size) {
			/* no cwt associated */
            continue;
        }
		hash = gen_hash64(vpn, size, way);

		QEMU_LOG_TRANSLATE("\tCWT: w=%d cr=%lx hash=0x%lx vaddr=%lx vpn =0x%lx size=0x%lx\n",
		 					way, cr, hash, vaddr, vpn, size);

		if (hash < rehash_ptr) {
			warn_report("cwt rehash not supported yet!\n");
			assert(0);
		} else {
			cwt_base = (cwt_entry_t *) GET_HPT_BASE(cr);
			cwt_entry_addr = (hwaddr) &cwt_base[hash];
		}
		
		load_helper(cs, (void *) &cwt_entry, cwt_entry_addr, sizeof(cwt_entry_t));

		QEMU_LOG_TRANSLATE(
			"\tCWT: base at 0x%016lx load from 0x%016lx entry_vpn=%lx valid_num=%d\n",
			(uint64_t)cwt_base, (uint64_t)cwt_entry_addr, cwt_entry_get_vpn(&cwt_entry), cwt_entry_get_valid_header_num(&cwt_entry));

		if (cwt_entry_match_vpn(&cwt_entry, vpn) && cwt_entry_get_valid_header_num(&cwt_entry) > 0) {
			/* this should only have one matched entries, but record all for error checking */
			matched_entries[n_matched_entries++] = cwt_entry;
		}
    }
	
	assert(n_matched_entries <= 1);

	if (n_matched_entries == 0) {
		QEMU_LOG_TRANSLATE("no matched entry found in CWT for vaddr=%lx vpn=0x%lx\n", vaddr, vpn);
		return -1;
	} else {
		
		if (cwc_stale) {
			cwc_update_stale_helper(cwc, &matched_entries[0], vaddr, gran);
		} else {
			cwt_update_miss_helper(cwc, &matched_entries[0]);
		}
		return 0;
	}
}

static inline void print_cwt_entries(cwc_cache_t * cwc)
{
	uint64_t entry_start[8] = {0};
	for (int i = 0; i < cwc->capacity; i++) {
		cwt_entry_t * entry = &cwc->entries[i];
		memcpy(&entry_start[0], entry,   sizeof(cwt_entry_t) );

		QEMU_LOG_TRANSLATE("CWC: entry[%d] vpn=%lx valid_num=%d\n (%016lx %016lx %016lx %016lx %016lx %016lx %016lx %016lx) \n",
			i, cwt_entry_get_vpn(entry), cwt_entry_get_valid_header_num(entry),
			entry_start[0], entry_start[1], entry_start[2], entry_start[3], entry_start[4], entry_start[5], entry_start[6], entry_start[7]);
	}
}


bool cwc_lookup(cwc_cache_t *cwc, uint64_t vaddr, CWTGranularity gran, cwt_header_t * res)
{
	uint64_t vpn = cwt_get_vpn(vaddr, gran);
	uint16_t entry_valid_num = 0;
	uint64_t entry_vpn = 0;
	unsigned int idx = 0;
	cwt_header_t empty_header = {0};

	// print_cwt_entries(cwc);

	for (int i = 0; i < cwc->capacity; i++) {
		entry_valid_num = cwt_entry_get_valid_header_num(&cwc->entries[i]);
		entry_vpn = cwt_entry_get_vpn(&cwc->entries[i]);
		
		if (entry_vpn == vpn && entry_valid_num > 0) {
			/* cache hit */
			
			cwt_update_hit(cwc, i);
			idx = cwt_get_idx_from_vaddr(vaddr, gran);
			*res = cwc->entries[i].sec_headers[idx];
			QEMU_LOG_TRANSLATE(
				"\t CWC: load from entry %d vpn=%lx idx=%d header=%x \n", i, entry_vpn, idx, res->byte);
			return true;
			// return cwc->entries[i].sec_headers[idx];
		}
	}

	QEMU_LOG_TRANSLATE(
				"\t CWC: NO load vpn=%lx \n", vpn);

	*res = empty_header;
	return false;
}

