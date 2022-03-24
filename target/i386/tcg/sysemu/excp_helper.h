#ifndef EXCP_HELPER_H
#define EXCP_HELPER_H

#include "cpu.h"

// Note: this typedef has a duplication in excp_helper.c
typedef hwaddr (*MMUTranslateFunc)(CPUState *cs, hwaddr gphys, MMUAccessType access_type, int *prot);

// also duplicated
#define PG_ERROR_OK (-1)

int mmu_translate_wrapper(CPUState *cs, hwaddr addr, MMUTranslateFunc get_hphys_func,
                          uint64_t cr3, int is_write1, int mmu_idx, int pg_mode,
                          hwaddr *xlat, int *page_size, int *prot);

#endif
