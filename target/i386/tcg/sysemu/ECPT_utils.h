#ifndef ECPT_UTILS_H
#define ECPT_UTILS_H

#include "ECPT.h"
#include "cpu.h"


/* ECPT unitlities */
uint64_t gen_hash64(uint64_t vpn, uint64_t size, uint32_t way);
void load_helper(CPUState *cs, void * entry, hwaddr addr, int size);

static inline bool is_kernel_addr(CPUX86State *env, hwaddr addr) 
{
    return addr >= env->kernel_start;
}

#endif /* ECPT_UTILS_H */