#ifndef ECPT_HASH_H
#define ECPT_HASH_H

#include "qemu/osdep.h"
#include "exec/log.h"
#include "ECPT.h"

#define NUM_CRC64_TABLE 4

uint32_t hash_wrapper(uint32_t addr);

/**
 * @brief compute crc64 hash function legacy
 * 
 * @param crc 
 * @param p 
 * @param len 
 * @return uint64_t 
 */

uint64_t crc64_be(uint64_t crc, const void* p, uint64_t len);

/**
 * @brief Select crc polynomials based on way
 * 
 * @param vpn at most 5 bytes long
 * @param way way number
 * @return uint64_t hash function
 */
uint64_t ecpt_crc64_hash(uint64_t vpn, uint32_t way);

#endif /* ECPT_HASH_H */