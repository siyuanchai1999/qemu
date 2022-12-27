#include "ECPT.h"
#include "ECPT_hash.h"

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