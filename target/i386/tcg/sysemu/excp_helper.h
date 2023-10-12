#ifndef EXCP_HELPER_H
#define EXCP_HELPER_H

#include "cpu.h"
#include <stdint.h>

// Note: this typedef has a duplication in excp_helper.c
typedef hwaddr (*MMUTranslateFunc)(CPUState *cs, hwaddr gphys, MMUAccessType access_type, int size, int *prot);

#define RADIX_LEVEL 4
struct radix_trans_info {
    uint64_t vaddr;
    uint64_t PTEs[RADIX_LEVEL];
    uint64_t paddr;
    int32_t access_type;
    uint32_t access_size;
    int32_t success;
};

#define WALK_INFO_BUF_SIZE (16 * 1024 * 1024)

int init_walk_info_fp(void);
void close_walk_info_fp(void);

// also duplicated
#define PG_ERROR_OK (-1)

int mmu_translate_wrapper(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                          uint64_t cr3, int is_write1, int mmu_idx, int pg_mode,
                          hwaddr *xlat, int *page_size, int *prot);

#endif
