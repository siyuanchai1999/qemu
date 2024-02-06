#ifndef ECPT_H
#define ECPT_H

#include "qemu/osdep.h"
#include <stdint.h>

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

/**
 *  number of bits reproposed for VPN
 * 		starting from bits 52 until 57
 * 		where bits 58 to 52 are marked as available from AMD manual
 * 		note that bit 58 is already used by linux kernel as #define _PAGE_BIT_DEVMAP	_PAGE_BIT_SOFTW4
  */
#define PTE_REPROPOSE_VPN_BITS 5

#if (PTE_REPROPOSE_VPN_BITS * ECPT_CLUSTER_FACTOR) < (48 - PAGE_SHIFT_4KB - ECPT_CLUSTER_NBITS)
#error Insufficient PTE_REPROPOSE_VPN_BITS
#endif

#if PTE_REPROPOSE_VPN_BITS > 6
#error PTE_REPROPOSE_VPN_BITS overflow
#endif

#if PTE_REPROPOSE_VPN_BITS > 0

#if PTE_REPROPOSE_VPN_BITS == 5
	#define PTE_VPN_MASK (0x01f0000000000000LL)
	#define VPN_TAIL_MASK (0x000000000000001fLL)
	#define PTE_VPN_SHIFT (52)

	/* start from e->pte[PTE_IDX_FOR_COUNT] to e->pte[ECPT_CLUSTER_FACTOR] 
		will be used to count how many valid ptes are in the entry*/
	#define PTE_IDX_FOR_COUNT (7)
#endif	


#define GET_PARTIAL_VPN_BASE(pte) ( (pte & PTE_VPN_MASK) >> PTE_VPN_SHIFT )
#define GET_PARTIAL_VPN_SHIFTED(pte, idx) (GET_PARTIAL_VPN_BASE(pte) << (idx * PTE_REPROPOSE_VPN_BITS))
#define GET_VALID_PTE_COUNT(pte) GET_PARTIAL_VPN_BASE(pte)


#endif

#define VIRTUAL_ADDR_MASK (0x0000ffffffffffffLL)

#define PAGE_SIZE_4KB (1UL << PAGE_SHIFT_4KB)
#define PAGE_SIZE_2MB (1UL << PAGE_SHIFT_2MB)
#define PAGE_SIZE_1GB (1UL << PAGE_SHIFT_1GB)
#define PAGE_SIZE_512GB (1UL << PAGE_SHIFT_512GB)

#define VADDR_TO_PAGE_NUM_NO_CLUSTER_4KB(x)   (((x) & VIRTUAL_ADDR_MASK) >> (PAGE_SHIFT_4KB))
#define VADDR_TO_PAGE_NUM_NO_CLUSTER_2MB(x)   (((x) & VIRTUAL_ADDR_MASK) >> (PAGE_SHIFT_2MB))
#define VADDR_TO_PAGE_NUM_NO_CLUSTER_1GB(x)   (((x) & VIRTUAL_ADDR_MASK) >> (PAGE_SHIFT_1GB))

#define VADDR_TO_PAGE_NUM_4KB(x)   (VADDR_TO_PAGE_NUM_NO_CLUSTER_4KB(x) >> ECPT_CLUSTER_NBITS)
#define VADDR_TO_PAGE_NUM_2MB(x)   (VADDR_TO_PAGE_NUM_NO_CLUSTER_2MB(x) >> ECPT_CLUSTER_NBITS)
#define VADDR_TO_PAGE_NUM_1GB(x)   (VADDR_TO_PAGE_NUM_NO_CLUSTER_1GB(x) >> ECPT_CLUSTER_NBITS)


#define PTE_TO_PADDR(pte)   ((pte) & PG_ADDRESS_MASK)
#define PTE_TO_PADDR_4KB(pte)   (((pte) & ~PAGE_TAIL_MASK_4KB) & PG_ADDRESS_MASK)
#define PTE_TO_PADDR_2MB(pte)   (((pte) & ~PAGE_TAIL_MASK_2MB) & PG_ADDRESS_MASK)
#define PTE_TO_PADDR_1GB(pte)   (((pte) & ~PAGE_TAIL_MASK_1GB) & PG_ADDRESS_MASK)

// #define ADDR_REMOVE_OFFSET_4KB(x)   (((x) & ~PAGE_TAIL_MASK_4KB) & VIRTUAL_ADDR_MASK)
// #define ADDR_REMOVE_OFFSET_2MB(x)   (((x) & ~PAGE_TAIL_MASK_2MB) & VIRTUAL_ADDR_MASK)
// #define ADDR_REMOVE_OFFSET_1GB(x)   (((x) & ~PAGE_TAIL_MASK_1GB) & VIRTUAL_ADDR_MASK)

#define ADDR_TO_OFFSET_4KB(x)   ((x) & PAGE_TAIL_MASK_4KB)
#define ADDR_TO_OFFSET_2MB(x)   ((x) & PAGE_TAIL_MASK_2MB)
#define ADDR_TO_OFFSET_1GB(x)   ((x) & PAGE_TAIL_MASK_1GB)

// #define ADDR_REMOVE_OFFSET_SHIFT_4KB(x)   ((ADDR_REMOVE_OFFSET_4KB(x)) >> (PAGE_SHIFT_4KB ))
// #define ADDR_REMOVE_OFFSET_SHIFT_2MB(x)   ((ADDR_REMOVE_OFFSET_2MB(x)) >> (PAGE_SHIFT_2MB ))
// #define ADDR_REMOVE_OFFSET_SHIFT_1GB(x)   ((ADDR_REMOVE_OFFSET_1GB(x)) >> (PAGE_SHIFT_1GB ))

// #define SHIFT_TO_ADDR_4KB(x)   (((uint64_t) x) << (PAGE_SHIFT_4KB))
// #define SHIFT_TO_ADDR_2MB(x)   (((uint64_t) x) << (PAGE_SHIFT_2MB))
// #define SHIFT_TO_ADDR_1GB(x)   (((uint64_t) x) << (PAGE_SHIFT_1GB))

// #define ADDR_TO_PAGE_NUM_4KB(x)   ((ADDR_REMOVE_OFFSET_SHIFT_4KB(x)) >> (ECPT_CLUSTER_NBITS))
// #define ADDR_TO_PAGE_NUM_2MB(x)   ((ADDR_REMOVE_OFFSET_SHIFT_2MB(x)) >> (ECPT_CLUSTER_NBITS))
// #define ADDR_TO_PAGE_NUM_1GB(x)   ((ADDR_REMOVE_OFFSET_SHIFT_1GB(x)) >> (ECPT_CLUSTER_NBITS))

// #define PAGE_NUM_TO_ADDR_4KB(x)   (SHIFT_TO_ADDR_4KB(x) << (ECPT_CLUSTER_NBITS))
// #define PAGE_NUM_TO_ADDR_2MB(x)   (SHIFT_TO_ADDR_2MB(x) << (ECPT_CLUSTER_NBITS))
// #define PAGE_NUM_TO_ADDR_1GB(x)   (SHIFT_TO_ADDR_1GB(x) << (ECPT_CLUSTER_NBITS))

#define HPT_SIZE_MASK (0xfff)      	/* 16 * cr3[0:11] for number of entries */
#define HPT_SIZE_HIDDEN_BITS (4)    
// #define HPT_CR3_TO_NUM_ENTRIES(cr3) ((((uint64_t) cr3 ) & HPT_SIZE_MASK) << HPT_SIZE_HIDDEN_BITS)
#define HPT_NUM_ENTRIES_TO_CR3(size) (((uint64_t) cr3 ) >> HPT_SIZE_HIDDEN_BITS)
// #define HPT_REHASH_PTR_MASK (0xfff0000000000000UL)
#define HPT_BASE_MASK (0x000ffffffffff000UL)
#define GET_HPT_SIZE(cr3) ((((uint64_t) cr3) & HPT_SIZE_MASK ) << HPT_SIZE_HIDDEN_BITS)
#define GET_HPT_BASE(cr3) (((uint64_t) cr3) & HPT_BASE_MASK )
// #define GET_HPT_REHASH_PTR(cr3) ((((uint64_t) cr3) & HPT_REHASH_PTR_MASK ) >> (52 - HPT_SIZE_HIDDEN_BITS))

#define CR3_TRANSITION_SHIFT (63)
#define CR3_TRANSITION_BIT (1ULL << CR3_TRANSITION_SHIFT)
/* Note: technically we eat one bit of available physical address
	This can be avoided by define ECPT_DESC_SHIFT to (12 - 3)
	where 2^3 is the size of long long int, which is the minimum alignment from kmalloc.
 */
#define ECPT_DESC_SHIFT (PAGE_SHIFT_4KB)
#define ECPT_DESC_PA_TO_CR3_FORMAT(x)                                          \
	(((x) << ECPT_DESC_SHIFT) | CR3_TRANSITION_BIT)

#define ECPT_4K_WAY 3
#define ECPT_2M_WAY 3
#define ECPT_1G_WAY 0

#define ECPT_4K_USER_WAY 3
#define ECPT_2M_USER_WAY 3
#define ECPT_1G_USER_WAY 0

#define ECPT_KERNEL_WAY (ECPT_4K_WAY + ECPT_2M_WAY + ECPT_1G_WAY)
#define ECPT_USER_WAY (ECPT_4K_USER_WAY + ECPT_2M_USER_WAY + ECPT_1G_USER_WAY)

#define ECPT_TOTAL_WAY (ECPT_KERNEL_WAY + ECPT_USER_WAY)

#define ECPT_REHASH_WAY 3
/* ECPT_TOTAL_WAY <= ECPT_MAX_WAY*/
#define ECPT_MAX_WAY 24

#if ECPT_MAX_WAY < ECPT_TOTAL_WAY + ECPT_REHASH_WAY 
	#error "ECPT_MAX_WAY exceeded"
#endif

#define HPT_REHASH_SHIFT (53)
#define REHASH_MASK (~((1ULL << HPT_REHASH_SHIFT) - 1))
#define GET_HPT_REHASH_PTR(cr) GET_HPT_SIZE(((uint64_t) cr) >> HPT_REHASH_SHIFT)

#define REHASH_PTR_MAX (1 << (64 - HPT_REHASH_SHIFT))
#define REHASH_PTR_TO_CR(ptr) (((uint64_t) ptr) << HPT_REHASH_SHIFT)
#define GET_CR_WITHOUT_REHASH(cr) (cr & (~REHASH_MASK))

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
    uint64_t pte[ECPT_CLUSTER_FACTOR];
} ecpt_entry_t;

static inline int ecpt_pte_is_empty(uint64_t pte) {
#ifdef PTE_VPN_MASK
	return (pte & ~(PTE_VPN_MASK))  == 0;
#else
	return (pte.pte & ~(_PAGE_KNL_ERRATUM_MASK))  == 0;
#endif
}

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
	uint64_t vpn = 0;
	for (uint16_t i = 0; i < ECPT_CLUSTER_FACTOR && i < PTE_IDX_FOR_COUNT; i++) {
		vpn |= GET_PARTIAL_VPN_SHIFTED(e->pte[i], i);
	}
	return vpn;
}

static inline uint16_t ecpt_entry_get_pte_num(ecpt_entry_t * e) 
{
	return GET_VALID_PTE_COUNT(e->pte[PTE_IDX_FOR_COUNT]);
}

static inline int ecpt_entry_match_vpn(ecpt_entry_t *entry, uint64_t vpn) {
	return ecpt_entry_get_vpn(entry) == vpn;
}

#define REP0(X)
#define REP1(X) X
#define REP2(X) REP1(X) X
#define REP3(X) REP2(X) X
#define REP4(X) REP3(X) X
#define REP5(X) REP4(X) X
#define REP6(X) REP5(X) X
#define REP7(X) REP6(X) X
#define REP8(X) REP7(X) X
#define REP9(X) REP8(X) X
#define REP10(X) REP9(X) X

#define PTE_0(e) (e)->pte[0]
#define PTE_1(e) PTE_0(e), (e)->pte[1]
#define PTE_2(e) PTE_1(e), (e)->pte[2]
#define PTE_3(e) PTE_2(e), (e)->pte[3]
#define PTE_4(e) PTE_3(e), (e)->pte[4]
#define PTE_5(e) PTE_4(e), (e)->pte[5]
#define PTE_6(e) PTE_5(e), (e)->pte[6]
#define PTE_7(e) PTE_6(e), (e)->pte[7]


#define PTE_ARRAY_FMT REP8("%016lx ")
#define PTE_ARRAY_PRINT(e) PTE_7(e)

#define PRINT_ECPT_ENTRY(e) \
	do { \
    	QEMU_LOG_TRANSLATE(gdb, CPU_LOG_MMU, "\t\t{.vpn=%lx .pte={" PTE_ARRAY_FMT "}}\n",\
			ecpt_entry_get_vpn(e), PTE_ARRAY_PRINT(e) \
		); \
  	} while (0)


uint32_t find_rehash_way(uint32_t way);

#define CWT_2MB_KERNEL_N_WAY 2
#define CWT_1GB_KERNEL_N_WAY 2
#define CWT_2MB_USER_N_WAY 2
#define CWT_1GB_USER_N_WAY 2
#define CWT_TOTAL_N_WAY                                                        \
        (CWT_2MB_KERNEL_N_WAY + CWT_1GB_KERNEL_N_WAY + CWT_2MB_USER_N_WAY +    \
         CWT_1GB_USER_N_WAY)

#define CWT_MAX_WAY 10
#if CWT_MAX_WAY < CWT_TOTAL_N_WAY
#error "CWT_MAX_WAY exceeded"
#endif

#define CWT_N_SECTION_HEADERS 64
typedef union cwt_header_byte
{
    struct  {
        /* header info */
        unsigned int present_1GB : 1;
        unsigned int present_2MB : 1;
        unsigned int present_4KB : 1;
        unsigned int way_in_ecpt : 2;

        /* bits for partial info */
        unsigned int partial_vpn : 3;
    } __attribute__((packed));
    unsigned char byte;
} cwt_header_t;

typedef struct cwt_entry {
	cwt_header_t sec_headers[CWT_N_SECTION_HEADERS];
} __attribute__((packed)) cwt_entry_t;

#define CWC_PUD_SIZE 2
#define CWC_PMD_SIZE 16

#endif /* ECPT_H */