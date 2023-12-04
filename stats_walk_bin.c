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

struct log_stats {
    uint64_t read;
    uint64_t write;
    uint64_t fetch;
};


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

    struct log_stats kernel_stats = {0};
    struct log_stats user_stats = {0};

    struct log_stats * stats = NULL;
    MemRecord record;
    while (fread(&record, sizeof(MemRecord), 1, fp) == 1) {

        if (record.vaddr >= 0xffff000000000000ULL) {
            stats = &kernel_stats;
        } else {
            stats = &user_stats;
        }

        if (record.header == BIN_RECORD_TYPE_MEM) {
            
            /* store: 0, load: 1*/
            if (record.access_rw) {
                stats->read++;
            } else {
                stats->write++;
            }
        } else if (record.header == BIN_RECORD_TYPE_FEC) {
            stats->fetch++;
        } else {
            printf("Unknown record type: %d\n", record.header);
        }
    }

    fclose(fp);
    
    printf("kernel: read: %lu, write: %lu, fetch: %lu\n", kernel_stats.read, kernel_stats.write, kernel_stats.fetch);
    printf("user: read: %lu, write: %lu, fetch: %lu\n", user_stats.read, user_stats.write, user_stats.fetch);
    printf("Total: read: %lu, write: %lu, fetch: %lu\n", kernel_stats.read + user_stats.read, kernel_stats.write + user_stats.write, kernel_stats.fetch + user_stats.fetch);
    return 0;
}