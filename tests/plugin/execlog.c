/*
 * Copyright (C) 2021, Alexandre Iooss <erdnaxe@crans.org>
 *
 * Log instruction execution with memory access.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

#include <glib.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qemu-plugin.h>

#include <assert.h>
#include <linux/limits.h>


QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define BIN_LOG

#ifdef BIN_LOG

//
// Configurations
//

// Maximum number of CPU in the system
#ifndef MAX_CPU_COUNT
#define MAX_CPU_COUNT 64
#endif
                       
// Maximum number of instruction recorded
// #define MAX_INS_COUNT (1000000000UL) // 1 billion
#ifndef MAX_INS_COUNT
#define MAX_INS_COUNT (3000000000UL) // 3 billion
#endif

// CPU instruction fetcher batch size
#ifndef FRONTEND_FETCH_SIZE
#define FRONTEND_FETCH_SIZE (16UL)
#endif

// Name of the log file
#ifndef DEFAULT_BIN_RECORD_FILE_NAME
#define DEFAULT_BIN_RECORD_FILE_NAME "walk_log.bin"
#endif

static char bin_record_file_name[PATH_MAX];
static unsigned long target_cr3;

// Whether to include instruction decode results
#ifndef BIN_RECORD_INCL_DECD
#define BIN_RECORD_INCL_DECD false
#endif

//
// Hacks
//

#if UINTPTR_MAX == UINT32_MAX
# define HOST_LONG_BITS 32
#elif UINTPTR_MAX == UINT64_MAX
# define HOST_LONG_BITS 64
#else
# error Unknown pointer size
#endif

#include "exec/memop.h"
#include "../target/i386/tcg/sysemu/MemRecord.h"
/* #define DEBUG_EXECLOG */


typedef uint32_t MemOpIdx;
static inline MemOp get_memop(MemOpIdx oi)
{
	return oi >> 4;
}

static inline enum qemu_plugin_mem_rw
get_plugin_meminfo_rw(qemu_plugin_meminfo_t i)
{
	return i >> 16;
}

//
// Constants
//

#define FRONTEND_FETCH_MASK (~(FRONTEND_FETCH_SIZE - 1))

#define BIN_RECORD_TYPE_MEM 'M' // User memory access, use MemRecord
#define BIN_RECORD_TYPE_FEC 'F' // InsFetcher memory access, use MemRecord
#define BIN_RECORD_TYPE_INS 'I' // InsDecoder record, use InsRecord

//
// Types
//

typedef struct FileHandle
{
	FILE* fp;
} FileHandle;

typedef struct InsRecord
{
	uint8_t header;
	uint8_t cpu;
	uint16_t length;
	uint32_t opcode;
	uint64_t vaddr;
	uint64_t counter;
	// char disassembly[length];
} InsRecord;

typedef union BinaryRecord
{
	InsRecord ins;
	MemRecord mem;
} BinaryRecord;

//
// Globals
//

static bool start_logging = false;
static FileHandle log_handle = { 0 };
static uint64_t user_ins_counter = 0;
static uint64_t kernel_ins_counter = 0;
static uint64_t ins_fetched[MAX_CPU_COUNT] = { 0 };

//
// Helpers
//

static inline void instant_suicide(void)
{
	// Prepare our tombstone
	printf(
		"\n"
		"Ave Musica... Fall, you'll fall (Fortuna)\n"
		"Ave Musica... To a place you cannot return from (Lacrima)\n"
		"Don't worry, there's nothing to fear (trust yourself to me)\n"
		"Let's begin (eternity) with you (my eternity)\n"
		"\n"
		"Unhandled exception at "__FILE__ ":%d\n", __LINE__
	);
	fflush(stdout);

	// On Linux this should instantly crash any process
	//   with a super cool last word of "Illegal instruction (core dumped)"
	// It is unique enough that no one will confuse it with
	//   the everyday old friend "Segmentation fault (core dumped)"
	asm volatile ("ud2" ::: "memory"); // #UD
	// asm volatile ("int1" ::: "memory"); // #DB
	asm volatile ("int3" ::: "memory"); // #BP
	asm volatile ("hlt" ::: "memory"); // #GP
	asm volatile ("xorq %%rax, %%rax\n\tidivq %%rax" ::: "memory"); // #DE
	abort();
}

static int flush_to_disk(FILE *fp)
{
    int ret;
    if (fp == NULL) {
        return -1;
    }

    ret = fflush(fp);
    if (ret != 0)
        return -1;

    ret = fsync(fileno(fp));
    if (ret < 0)
         return -1;

    return 0;
}

static inline void open_bin_record(void)
{
	log_handle.fp = fopen(bin_record_file_name, "wb");

	if (!log_handle.fp) {
		fprintf(stderr, "failed to open %s", bin_record_file_name);
		perror("fopen");

		instant_suicide();
		return;
	}
	printf("[Sim Plugin] Created binary log at %s\n", bin_record_file_name);
}

static inline void close_bin_record(void)
{   
	if (log_handle.fp) {
        flush_to_disk(log_handle.fp);
		fclose(log_handle.fp);

        printf("[Sim Plugin] Closed binary log file descriptor\n");
	}
}

static inline void write_bin_log(uint64_t size, void* data)
{
	uint64_t written = 0;

	if (!log_handle.fp) {
		return;
	}

	written = fwrite(data, size, 1, log_handle.fp);
	if (written <= 0) {
		qemu_plugin_outs("write bin record failed\n");
	}
}

static inline void write_mem_record(MemRecord *rec)
{
	rec->header = BIN_RECORD_TYPE_MEM;
	write_bin_log(sizeof(MemRecord), rec);
}

static inline void write_ins_record(InsRecord *rec, char* dias)
{
	uint64_t len = strlen(dias);

	len = len > 65535 ? 65535 : len;

	rec->header = BIN_RECORD_TYPE_INS;
	rec->length = len;

	write_bin_log(sizeof(InsRecord), rec);
	// write_bin_log(len, dias);
}

static inline void write_ins_fetch(MemRecord *rec)
{
	rec->header = BIN_RECORD_TYPE_FEC;
	write_bin_log(sizeof(MemRecord), rec);

#ifdef DEBUG_EXECLOG    
    char buf[1024];
    sprintf(buf, "Record Fetch: vaddr=%016lx\n", rec->vaddr);
    qemu_plugin_outs(buf);
#endif
}

static int should_do_logging(void)
{
    if (!start_logging){
        return 0;
    }

    if (qemu_plugin_read_cr3() != target_cr3) {
#ifdef DEBUG_EXECLOG    
        char buf[256];
        sprintf(buf, "[Sim Plugin] vcpu_mem: cr3=%lx, target_cr3=%lx\n", qemu_plugin_read_cr3(), target_cr3);
        qemu_plugin_outs(buf);
#endif
        return 0;
    }
    
    return 1;
}

/**
* Add memory read or write information to current instruction log
*/
static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
					uint64_t vaddr, void *udata)
{
	MemRecord rec = { 0 };

    if (!should_do_logging()) {
        return;
    }

	/* store: 0, load: 1*/
	rec.access_rw = !qemu_plugin_mem_is_store(info);
	rec.access_cpu = cpu_index % MAX_CPU_COUNT; /* dummy field for now. introduced because of different QEMU version @jiyuan */
	rec.access_sz = 1 << qemu_plugin_mem_size_shift(info);
	rec.vaddr = vaddr;
    rec.paddr = qemu_plugin_pa_by_va(vaddr,
                                     (void *)&rec);
    // printf("Radix Translate: vaddr=%lx PTE0=%lx PTE1=%lx PTE2=%lx "
    //          "PTE3=%lx paddr=%lx access_rw=%d access_cpu=%d access_sz=%d\n",
    //          rec.vaddr, rec.leaves[0], rec.leaves[1], rec.leaves[2], rec.leaves[3],
    //          rec.paddr,
    //          rec.access_rw,
    //          rec.access_cpu,
    //          rec.access_sz);

#ifdef DEBUG_EXECLOG 
    char buf[1024];
    sprintf(buf, "Record Load/Store: vaddr=%016lx read=%d pc=%016lx\n", rec.vaddr, rec.access_rw, (uint64_t) udata);
    qemu_plugin_outs(buf);
#endif

	write_mem_record(&rec);
}

#define IS_KERNEL_ADDR(addr) ((addr) >= 0xffff800000000000UL)
static void do_ins_counting(uint64_t ins_pc)
{
    if (IS_KERNEL_ADDR(ins_pc)) {
        /* skip counting for kernel insts */
        kernel_ins_counter++;
        return;
    }

	user_ins_counter++;
    
    if(user_ins_counter % 5000UL == 0) { // every 5 million instr
        printf("[Sim Plugin] Reached  %lu user instrs %lu kernel insts\n", 
            user_ins_counter, kernel_ins_counter);
    }

	if (user_ins_counter > MAX_INS_COUNT) {
		start_logging = false;
		user_ins_counter = 0;

		printf("[Sim Plugin] # of instructions is over %ld, stop logging now\n", MAX_INS_COUNT);

        close_bin_record();

        printf("[Sim Plugin] Preparing to die\n");
        sleep(5);

        /* There could be more elegant way to shut this down, but I didn't yet figure out. */
        /* If you want to do so, find qemu_plugin_vm_shutdown impl in plugins/api.c  */
        qemu_plugin_vm_shutdown ();
	}
}

/**
* Log instruction execution
*/
static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
    
	struct qemu_plugin_insn *ins = (struct qemu_plugin_insn *) udata;
	char *dias = qemu_plugin_insn_disas(ins);
	InsRecord rec;

    if (!start_logging){
        return;
    }
        

	rec.cpu = cpu_index;
	rec.opcode = *((uint32_t *)qemu_plugin_insn_data(ins));
	rec.vaddr = qemu_plugin_insn_vaddr(ins);
	rec.counter = user_ins_counter;

	write_ins_record(&rec, dias);
}

/**
* Log frontend instruction fetch
*/
static void vcpu_insn_fetch(unsigned int cpu_index, void *udata)
{
	uint32_t cpu = cpu_index % MAX_CPU_COUNT;
	uint64_t ins_pc = (uint64_t) udata;
    uint64_t ins_line = ins_pc & FRONTEND_FETCH_MASK;
    MemRecord rec = { 0 };

    if (!should_do_logging()) {
        return;
    }

	do_ins_counting(ins_pc);

	if (ins_fetched[cpu] == ins_line) {
	    if (BIN_RECORD_INCL_DECD) {
            vcpu_insn_exec(cpu_index, udata);
        }
	    return;
	}

	ins_fetched[cpu] = ins_line;

	rec.access_rw = 1;
	rec.access_cpu = cpu;
	rec.access_sz = FRONTEND_FETCH_SIZE;
	rec.vaddr = ins_line;
    rec.paddr = qemu_plugin_pa_by_va(ins_line,
                                     (void *)&rec);

    write_ins_fetch(&rec);

	if (BIN_RECORD_INCL_DECD)
		vcpu_insn_exec(cpu_index, udata);
}

/**
* Log Toggling
*/

static void vcpu_magic_r10(unsigned int cpu, void *udata) {
	start_logging = true;
    printf("[Sim Plugin] magic instruction r10 is executed!\n");
}

static void vcpu_magic_r11(unsigned int cpu, void *udata) {
	start_logging = false;
    printf("[Sim Plugin] magic instruction r11 is executed!\n");
    if (flush_to_disk(log_handle.fp) < 0) {
        instant_suicide();
    }
}

/**
* On translation block new translation
*
* QEMU convert code by translation block (TB). By hooking here we can then hook
* a callback on each instruction and memory access.
*/
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
	struct qemu_plugin_insn *insn;

	size_t n = qemu_plugin_tb_n_insns(tb);
	for (size_t i = 0; i < n; i++) {
		// Hopefully this lives long enough
		insn = qemu_plugin_tb_get_insn(tb, i);

        /**
         * Note: we cannot pass insn directly to vcpu_insn_fetch call back
         *  becaue qemu_plugin_tb and ptb->insn are shared across translations in QEMU.
         * More elegantly, we can define a custom data structure called insn_fetch_udata
         * which wraps all data we need.
         * For now, the only data we need is the pc of a insn (insn_vaddr here),
         * so we did a bit dirty hack which code pc as address udata ptr. 
        */
        uint64_t insn_vaddr = qemu_plugin_insn_vaddr(insn);

		uint32_t raw_insn = (*((uint32_t *)qemu_plugin_insn_data(insn))) & 0x00FFFFFFU;
		if (raw_insn == 0xD2874DU) {
			// xchg R10, R10
            target_cr3 = qemu_plugin_read_cr3();
            printf("[Sim Plugin] Begin simulation, cr3=%lx\n", target_cr3);
            printf("[Sim Plugin] MemRecord size=%lu\n", sizeof(MemRecord)); 
			qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_magic_r10,
												QEMU_PLUGIN_CB_NO_REGS,
												NULL);
		} else if(raw_insn == 0xDB874DU) {
			// XCHG R11, R11
			qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_magic_r11,
												QEMU_PLUGIN_CB_NO_REGS,
												NULL);
		} else {
            
            /**
             * Note: we have to register all ins before start_logging becomes true
             * because this function is being called at translation time.
             * Otherwise, the the translation blocks translated before start_logging=true
             * will not be logged since it will not be translated again.
            */

            /* Register callback on memory read or write */
            qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem,
                                            QEMU_PLUGIN_CB_NO_REGS,
                                            QEMU_PLUGIN_MEM_RW, (void *) insn_vaddr);

            /* Register callback on instruction */

            qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_fetch,
                                                QEMU_PLUGIN_CB_NO_REGS, (void *) insn_vaddr);
		}
	}
}
////////////////////////////////////////////////////////////////////////////////
// Argument parsing logic
////////////////////////////////////////////////////////////////////////////////

#define SYSEXPECT(expr) do { if(!(expr)) { perror(__func__); assert(0); exit(1); } } while(0)
#define SYSEXPECT_FILE(expr, path) do { if(!(expr)) { printf("File operation failed with path: \"%s\"\n", path); perror(__func__); assert(0); exit(1); } } while(0)
#define error_exit(fmt, ...) do { fprintf(stderr, "%s error: " fmt, __func__, ##__VA_ARGS__); assert(0); exit(1); } while(0);

inline static int streq(const char *a, const char *b) { return strcmp(a, b) == 0; } 

// This is the node of argv which forms a linked list
typedef struct argv_node {
    char *key;     // Must not duplicate -- check on insertion
    char *value;   // Could be NULL
    int index;
    struct argv_node *next;
} argv_node_t;

// Linked list head of options
static argv_node_t *options = NULL;

static void process_argv(int argc, char **argv) {
    for(int i = 0;i < argc;i++) {
        char *arg = argv[i];
        int len = strlen(arg);
        // Parse key and argument
        char *equal_sign = arg;
        while(*equal_sign != '=' && *equal_sign != '\0') {
            equal_sign++;
        }
        // Check for errors
        if(*arg == '\0') {
            error_exit("[Sim Plugin] Argument on index %d is empty (without value)\n", i);
        } else if(arg == equal_sign) {
            error_exit("[Sim Plugin] Argument on index %d is empty (with value)\n", i);
        }
        char *key;
        char *value;
        int key_len = equal_sign - arg;
        int value_len = len - (equal_sign + 1 - arg);
        if(*equal_sign == '\0') {
            value = NULL;
        } else {
            value = (char *)malloc(value_len + 1);
            SYSEXPECT(value != NULL);
            memcpy(value, equal_sign + 1, value_len);
            value[value_len] = '\0';
        }
        key = (char *)malloc(key_len + 1);
        SYSEXPECT(key != NULL);
        memcpy(key, arg, key_len);
        key[key_len] = '\0';
        argv_node_t *node = (argv_node_t *)malloc(sizeof(argv_node_t));
        SYSEXPECT(node != NULL);
        node->key = key;
        node->value = value;
        node->next = NULL;
        node->index = i;
        // Insert the node into the end of the linked list
        // We check key duplication along the way as well
        if(options == NULL) {
            options = node;
        } else {
            argv_node_t *curr = options;
            while(1) {
                if(streq(curr->key, key) == 1) {
                    error_exit("Key on index %d duplicates with key on index %d, key = \"%s\"\n", 
                        i, curr->index, key);
                }
                if(curr->next == NULL) {
                    curr->next = node;
                    break;
                }
                curr = curr->next;
            }
        }
    }
    // Print all options
    printf("[Sim Plugin] The plugin is loaded with the following options:\n");
    argv_node_t *curr = options;
    while(curr != NULL) {
        printf("[Sim Plugin] Index %d key \"%s\" value \"%s\"\n", curr->index, curr->key, curr->value);
        curr = curr->next;
    }
}

// This function searches the options list, and finds the one with the matching key
// If the key is found, return 1, and value is set to the value
// Otherwise, return 0, and value is always NULL
// Note that the value read remain valid strings during the run
static int find_option(const char *key, char **value) {
    argv_node_t *node = options;
    while(node != NULL) {
        if(strcmp(node->key, key) == 0) {
            *value = node->value;
            return 1;
        }
        node = node->next;
    }
    *value = NULL;
    return 0;
}
static void setup_bin_record_name(void) {
    char *input_filename;
    int found = find_option("filename", &input_filename);
    if(found == 0) {
        printf("[Sim Plugin] Did not find plugin argument filename, use default filename \"" DEFAULT_BIN_RECORD_FILE_NAME "\"\n");
		strcpy(bin_record_file_name, DEFAULT_BIN_RECORD_FILE_NAME);
    } else {
		if(strlen(input_filename) >= PATH_MAX) {
			error_exit("[Sim Plugin] Log filename too long (>= PATH_MAX)\n");
		}
        printf("[Sim Plugin] Set log file to \"%s\"\n", input_filename);
		strcpy(bin_record_file_name, input_filename);
    }
}


static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    printf("[Sim Plugin] Closed binary log filexxxxxx\n");
	close_bin_record();
    qemu_plugin_vm_shutdown();
}

// static void plugin_exit(qemu_plugin_id_t id, unsigned int vcpu_index)
// {
//     printf("[Sim Plugin] Closed binary log filexxxxxx\n");
// 	close_bin_record();
//     instant_suicide();
// }

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
										const qemu_info_t *info, int argc,
										char **argv)
{
    process_argv(argc, argv);
	setup_bin_record_name();

	open_bin_record();

	/* Register translation block and exit callbacks */
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    // qemu_plugin_register_vcpu_exit_cb(id, plugin_exit);
	
    /* NOTE: this atexit call back has not been called when ./shutdown finished */
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

	return 0;
}

#else

/* Store last executed instruction on each vCPU as a GString */
GArray *last_exec;

/**
 * Add memory read or write information to current instruction log
 */
static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *udata)
{
    GString *s;

    /* Find vCPU in array */
    g_assert(cpu_index < last_exec->len);
    s = g_array_index(last_exec, GString *, cpu_index);

    /* Indicate type of memory access */
    if (qemu_plugin_mem_is_store(info)) {
        g_string_append(s, ", store");
    } else {
        g_string_append(s, ", load");
    }

    /* If full system emulation log physical address and device name */
    struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(info, vaddr);
    if (hwaddr) {
        uint64_t addr = qemu_plugin_hwaddr_phys_addr(hwaddr);
        const char *name = qemu_plugin_hwaddr_device_name(hwaddr);
        g_string_append_printf(s, ", 0x%08"PRIx64", %s", addr, name);
    } else {
        g_string_append_printf(s, ", 0x%08"PRIx64, vaddr);
    }
}

/**
 * Log instruction execution
 */
static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
    GString *s;

    /* Find or create vCPU in array */
    while (cpu_index >= last_exec->len) {
        s = g_string_new(NULL);
        g_array_append_val(last_exec, s);
    }
    s = g_array_index(last_exec, GString *, cpu_index);

    /* Print previous instruction in cache */
    if (s->len) {
        qemu_plugin_outs(s->str);
        qemu_plugin_outs("\n");
    }

    /* Store new instruction in cache */
    /* vcpu_mem will add memory access information to last_exec */
    g_string_printf(s, "%u, ", cpu_index);
    g_string_append(s, (char *)udata);
}

/**
 * On translation block new translation
 *
 * QEMU convert code by translation block (TB). By hooking here we can then hook
 * a callback on each instruction and memory access.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    struct qemu_plugin_insn *insn;
    uint64_t insn_vaddr;
    uint32_t insn_opcode;
    char *insn_disas;

    size_t n = qemu_plugin_tb_n_insns(tb);
    for (size_t i = 0; i < n; i++) {
        /*
         * `insn` is shared between translations in QEMU, copy needed data here.
         * `output` is never freed as it might be used multiple times during
         * the emulation lifetime.
         * We only consider the first 32 bits of the instruction, this may be
         * a limitation for CISC architectures.
         */
        insn = qemu_plugin_tb_get_insn(tb, i);
        insn_vaddr = qemu_plugin_insn_vaddr(insn);
        insn_opcode = *((uint32_t *)qemu_plugin_insn_data(insn));
        insn_disas = qemu_plugin_insn_disas(insn);
        char *output = g_strdup_printf("0x%"PRIx64", 0x%"PRIx32", \"%s\"",
                                       insn_vaddr, insn_opcode, insn_disas);

        /* Register callback on memory read or write */
        qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, NULL);

        /* Register callback on instruction */
        qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
                                               QEMU_PLUGIN_CB_NO_REGS, output);
    }
}

/**
 * On plugin exit, print last instruction in cache
 */
static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    guint i;
    GString *s;
    for (i = 0; i < last_exec->len; i++) {
        s = g_array_index(last_exec, GString *, i);
        if (s->str) {
            qemu_plugin_outs(s->str);
            qemu_plugin_outs("\n");
        }
    }
}

/**
 * Install the plugin
 */
QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info, int argc,
                                           char **argv)
{
    /*
     * Initialize dynamic array to cache vCPU instruction. In user mode
     * we don't know the size before emulation.
     */
    last_exec = g_array_new(FALSE, FALSE, sizeof(GString *));

    /* Register translation block and exit callbacks */
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}

#endif
