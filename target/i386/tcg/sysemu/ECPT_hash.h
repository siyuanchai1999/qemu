#ifndef ECPT_HASH_H
#define ECPT_HASH_H

#include "qemu/osdep.h"
#include "exec/log.h"
#include "ECPT.h"

uint32_t hash_wrapper(uint32_t addr);

uint64_t crc64_be(uint64_t crc, const void* p, uint64_t len);

#endif /* ECPT_HASH_H */