#ifndef ECPT_H
#define ECPT_H

#include "qemu/osdep.h"
#include "exec/log.h"

// #define PAGE_HEADER_MASK (0xffff000000000000)
// #define PAGE_TAIL_MASK_4KB (0xfff)
// #define PAGE_TAIL_MASK_2MB (0x1fffff)
// #define PAGE_TAIL_MASK_1GB (0x3fffffff)


// #define PAGE_SHIFT_4KB (12)
// #define PAGE_SHIFT_2MB (21)
// #define PAGE_SHIFT_1GB (30)

// #define PAGE_SIZE_4KB (1UL << PAGE_SHIFT_4KB)
// #define PAGE_SIZE_2MB (1UL << PAGE_SHIFT_2MB)
// #define PAGE_SIZE_1GB (1UL << PAGE_SHIFT_1GB)

// #define ADDR_TO_PAGE_NUM_4KB(x)   (((x) & ~ PAGE_HEADER_MASK) >> PAGE_SHIFT_4KB)
// #define ADDR_TO_PAGE_NUM_2MB(x)   (((x) & ~ PAGE_HEADER_MASK) >> PAGE_SHIFT_2MB)
// #define ADDR_TO_PAGE_NUM_1GB(x)   (((x) & ~ PAGE_HEADER_MASK) >> PAGE_SHIFT_1GB)

// #define ADDR_TO_OFFSET_4KB(x)   ((x) & PAGE_TAIL_MASK_4KB)
// #define ADDR_TO_OFFSET_2MB(x)   ((x) &     PAGE_TAIL_MASK_2MB)
// #define ADDR_TO_OFFSET_1GB(x)   ((x) &   PAGE_TAIL_MASK_1GB)

// #define PAGE_NUM_TO_ADDR_4KB(x)   (((hwaddr)x) << PAGE_SHIFT_4KB)
// #define PAGE_NUM_TO_ADDR_2MB(x)   (((hwaddr)x) << PAGE_SHIFT_2MB)
// #define PAGE_NUM_TO_ADDR_1GB(x)   (((hwaddr)x) << PAGE_SHIFT_1GB)

enum Granularity {page_4KB, page_2MB, page_1GB}; 
 

#define PAGE_HEADER_MASK (0xffff000000000000)
#define PAGE_TAIL_MASK_4KB (0xfff)
#define PAGE_TAIL_MASK_2MB (0x1fffff)
#define PAGE_TAIL_MASK_1GB (0x3fffffff)
#define PAGE_TAIL_MASK_512GB (0x7fffffffff)

#define PAGE_SHIFT_4KB (12)
#define PAGE_SHIFT_2MB (21)
#define PAGE_SHIFT_1GB (30)
#define PAGE_SHIFT_512GB (39)

#define ECPT_CLUSTER_NBITS 3
#define ECPT_CLUSTER_FACTOR (1 << ECPT_CLUSTER_NBITS)

#define PAGE_SIZE_4KB (1UL << PAGE_SHIFT_4KB)
#define PAGE_SIZE_2MB (1UL << PAGE_SHIFT_2MB)
#define PAGE_SIZE_1GB (1UL << PAGE_SHIFT_1GB)
#define PAGE_SIZE_512GB (1UL << PAGE_SHIFT_512GB)

#define ADDR_REMOVE_OFFSET_4KB(x)   (((x) & ~PAGE_TAIL_MASK_4KB) & PG_ADDRESS_MASK)
#define ADDR_REMOVE_OFFSET_2MB(x)   (((x) & ~PAGE_TAIL_MASK_2MB) & PG_ADDRESS_MASK)
#define ADDR_REMOVE_OFFSET_1GB(x)   (((x) & ~PAGE_TAIL_MASK_1GB) & PG_ADDRESS_MASK)

#define ADDR_TO_OFFSET_4KB(x)   ((x) & PAGE_TAIL_MASK_4KB)
#define ADDR_TO_OFFSET_2MB(x)   ((x) & PAGE_TAIL_MASK_2MB)
#define ADDR_TO_OFFSET_1GB(x)   ((x) & PAGE_TAIL_MASK_1GB)

#define ADDR_REMOVE_OFFSET_SHIFT_4KB(x)   ((ADDR_REMOVE_OFFSET_4KB(x)) >> (PAGE_SHIFT_4KB ))
#define ADDR_REMOVE_OFFSET_SHIFT_2MB(x)   ((ADDR_REMOVE_OFFSET_2MB(x)) >> (PAGE_SHIFT_2MB ))
#define ADDR_REMOVE_OFFSET_SHIFT_1GB(x)   ((ADDR_REMOVE_OFFSET_1GB(x)) >> (PAGE_SHIFT_1GB ))

#define SHIFT_TO_ADDR_4KB(x)   (((uint64_t) x) << (PAGE_SHIFT_4KB))
#define SHIFT_TO_ADDR_2MB(x)   (((uint64_t) x) << (PAGE_SHIFT_2MB))
#define SHIFT_TO_ADDR_1GB(x)   (((uint64_t) x) << (PAGE_SHIFT_1GB))

#define ADDR_TO_PAGE_NUM_4KB(x)   ((ADDR_REMOVE_OFFSET_SHIFT_4KB(x)) >> (ECPT_CLUSTER_NBITS))
#define ADDR_TO_PAGE_NUM_2MB(x)   ((ADDR_REMOVE_OFFSET_SHIFT_2MB(x)) >> (ECPT_CLUSTER_NBITS))
#define ADDR_TO_PAGE_NUM_1GB(x)   ((ADDR_REMOVE_OFFSET_SHIFT_1GB(x)) >> (ECPT_CLUSTER_NBITS))

#define PAGE_NUM_TO_ADDR_4KB(x)   (SHIFT_TO_ADDR_4KB(x) << (ECPT_CLUSTER_NBITS))
#define PAGE_NUM_TO_ADDR_2MB(x)   (SHIFT_TO_ADDR_2MB(x) << (ECPT_CLUSTER_NBITS))
#define PAGE_NUM_TO_ADDR_1GB(x)   (SHIFT_TO_ADDR_1GB(x) << (ECPT_CLUSTER_NBITS))

#define HPT_SIZE_MASK (0xfff)      	/* 16 * cr3[0:11] for number of entries */
#define HPT_SIZE_HIDDEN_BITS (4)    
// #define HPT_CR3_TO_NUM_ENTRIES(cr3) ((((uint64_t) cr3 ) & HPT_SIZE_MASK) << HPT_SIZE_HIDDEN_BITS)
#define HPT_NUM_ENTRIES_TO_CR3(size) (((uint64_t) cr3 ) >> HPT_SIZE_HIDDEN_BITS)
// #define HPT_REHASH_PTR_MASK (0xfff0000000000000UL)
#define HPT_BASE_MASK (0x000ffffffffff000UL)
#define GET_HPT_SIZE(cr3) ((((uint64_t) cr3) & HPT_SIZE_MASK ) << HPT_SIZE_HIDDEN_BITS)
#define GET_HPT_BASE(cr3) (((uint64_t) cr3) & HPT_BASE_MASK )
// #define GET_HPT_REHASH_PTR(cr3) ((((uint64_t) cr3) & HPT_REHASH_PTR_MASK ) >> (52 - HPT_SIZE_HIDDEN_BITS))

#define CR3_TRANSITION_SHIFT (52)
#define CR3_TRANSITION_BIT (1ULL << CR3_TRANSITION_SHIFT)


#define ECPT_4K_WAY 2
#define ECPT_2M_WAY 2
#define ECPT_1G_WAY 0

#define ECPT_4K_USER_WAY 2
#define ECPT_2M_USER_WAY 0
#define ECPT_1G_USER_WAY 0

#define ECPT_KERNEL_WAY (ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY)
#define ECPT_USER_WAY (ECPT_4K_USER_WAY + ECPT_2M_USER_WAY + ECPT_1G_USER_WAY)

#define ECPT_TOTAL_WAY (ECPT_KERNEL_WAY + ECPT_USER_WAY)

/* ECPT_TOTAL_WAY <= ECPT_MAX_WAY*/
#define ECPT_MAX_WAY 9

/**
 *  
 *	for i = [0, ECPT_4K_WAY), cr_N where N = way_to_crN[i] correspond to way i of 4K ECPT  
 *  for i = [ECPT_4K_WAY, ECPT_4K_WAY + ECPT_2M_WAY),
 * 		cr_N where N = way_to_crN[i] correspond to way i - ECPT_4K_WAY of 2M ECPT
 * 	for i = [ECPT_4K_WAY + ECPT_2M_WAY, ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY),
 * 		cr_N where N = way_to_crN[i] correspond to way i - ECPT_4K_WAY + ECPT_2M_WAY of 2M ECPT
 */

/**
 * @brief 
 * 	
 * 
 * 	way_to_crN
 * 	4K  4K  2M	2M  2M  2M	1G
 * 	|	|	|	|	| 	|	|
 * 	x	x 	x 	x	x	x	x	
 * 	ECPT_4K_WAY = 2
 * 	ECPT_2M_WAY = 4
 * 	ECPT_1G_WAY = 1
 */

extern uint32_t way_to_crN[ECPT_MAX_WAY];

typedef struct ecpt_entry{
    uint64_t VPN_tag;
    uint64_t pte[ECPT_CLUSTER_FACTOR];
} ecpt_entry_t;

static inline unsigned long ecpt_pte_index(uint64_t addr) 
{
	return (addr >> PAGE_SHIFT_4KB) & (ECPT_CLUSTER_FACTOR - 1);
}

static inline unsigned long ecpt_pmd_index(uint64_t addr) 
{
	return (addr >> PAGE_SHIFT_2MB) & (ECPT_CLUSTER_FACTOR - 1);
}

static inline unsigned long ecpt_pud_index(uint64_t addr)
{
	return (addr >> PAGE_SHIFT_1GB) & (ECPT_CLUSTER_FACTOR - 1);
}

static inline uint64_t * pte_offset_from_ecpt_entry(struct ecpt_entry *entry, uint64_t addr) 
{
	return (uint64_t *) &entry->pte[ecpt_pte_index(addr)];
}

static inline uint64_t * pmd_offset_from_ecpt_entry(struct ecpt_entry *entry, uint64_t addr) 
{
	return (uint64_t *) &entry->pte[ecpt_pmd_index(addr)];
}

static inline uint64_t * pud_offset_from_ecpt_entry(struct ecpt_entry *entry, uint64_t addr)
{
	return (uint64_t *) &entry->pte[ecpt_pud_index(addr)];
}

static inline uint64_t ecpt_entry_get_vpn(ecpt_entry_t * e) 
{
	return e->VPN_tag;
}

static inline int ecpt_entry_match_vpn(ecpt_entry_t *entry, uint64_t vpn) {
	return ecpt_entry_get_vpn(entry) == vpn;
}

#endif /* ECPT_H */