#include <stdio.h>
#include <stdint.h>

#define PAGE_TABLE_LEAVES 4

#define BIN_RECORD_TYPE_MEM 'M' // User memory access, use MemRecord
#define BIN_RECORD_TYPE_FEC 'F' // InsFetcher memory access, use MemRecord
#define BIN_RECORD_TYPE_INS 'I' // InsDecoder record, use InsRecord

typedef struct MemRecord
{
	uint8_t header;
	uint8_t access_rw;
	uint16_t access_cpu;
	uint32_t access_sz;
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t pte;
	uint64_t leaves[PAGE_TABLE_LEAVES];
} MemRecord;

// typedef struct InsRecord
// {
// 	uint8_t header;
// 	uint8_t cpu;
// 	uint16_t length;
// 	uint32_t opcode;
// 	uint64_t vaddr;
// 	uint64_t counter;
// 	// char disassembly[length];
// } InsRecord;

// typedef union BinaryRecord
// {
// 	InsRecord ins;
// 	MemRecord mem;
// } BinaryRecord;

// char* open_read(char* path)
// {
//     // 
// }

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s <path>\n", argv[0]);
        return 1;
    }

    char* path = argv[1];

    FILE* fp = fopen(path, "rb");
    if (fp == NULL) {
        printf("Error opening file %s\n", path);
        return 1;
    }

    MemRecord record;
    while (fread(&record, sizeof(MemRecord), 1, fp) == 1) {
        if (record.header == BIN_RECORD_TYPE_MEM) {
            printf("%s: access_cpu=%04x, access_sz=%02x, vaddr=%016lx, paddr=%016lx, pte=%016lx, leaves=[%016lx, %016lx, %016lx, %016lx]\n",
                record.access_rw ? "Load " : "Store", record.access_cpu, record.access_sz, record.vaddr, record.paddr, record.pte,
                record.leaves[0], record.leaves[1], record.leaves[2], record.leaves[3]);
        } else if (record.header == BIN_RECORD_TYPE_FEC) {
            printf("Fetch: access_cpu=%04x, access_sz=%02x, vaddr=%016lx, paddr=%016lx, pte=%016lx, leaves=[%016lx, %016lx, %016lx, %016lx]\n",
                record.access_cpu, record.access_sz, record.vaddr, record.paddr, record.pte,
                record.leaves[0], record.leaves[1], record.leaves[2], record.leaves[3]);
        } else {
            printf("Unknown record type: %d\n", record.header);
        }
    }

    fclose(fp);
    return 0;
}