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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define BIN_LOG

#ifdef BIN_LOG

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

#define PAGE_TABLE_LEAVES 4
#define BIN_RECORD_FILE_NAME "walk_log.bin"

#define BIN_RECORD_TYPE_MEM 'M'
#define BIN_RECORD_TYPE_INS 'I'

//
// Types
//

typedef struct FileHandle
{
	FILE* fp;
} FileHandle;

typedef struct MemRecord
{
	uint8_t header;
	uint8_t access_rw;
	uint16_t access_op;
	uint32_t access_sz;
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t pte;
	uint64_t leaves[PAGE_TABLE_LEAVES];
} MemRecord;

typedef struct InsRecord
{
	uint8_t header;
	uint8_t cpu;
	uint16_t length;
	uint32_t opcode;
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t pte;
	uint64_t leaves[PAGE_TABLE_LEAVES];
	// uint64_t counter;
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

static FileHandle log_handle = { 0 };
static uint64_t ins_counter = 0;

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
	asm volatile ("int1" ::: "memory"); // #DB
	asm volatile ("int3" ::: "memory"); // #BP
	asm volatile ("hlt" ::: "memory"); // #GP
	asm volatile ("xorq %%rax, %%rax\n\tidivq %%rax" ::: "memory"); // #DE
	abort();
}

static inline void open_bin_record(void)
{
	log_handle.fp = fopen(BIN_RECORD_FILE_NAME, "wb");

	if (!log_handle.fp) {
		perror("fail to open " BIN_RECORD_FILE_NAME);

		instant_suicide();
		return;
	}

	qemu_plugin_outs("created binary log at " BIN_RECORD_FILE_NAME "\n");
}

static inline void close_bin_record(void)
{
	if (log_handle.fp) {
		fflush(log_handle.fp);
		fclose(log_handle.fp);
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

/**
* Add memory read or write information to current instruction log
*/
static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
					uint64_t vaddr, void *udata)
{
	MemRecord rec;
	uint32_t discard;

	/* store: 0, load: 1*/
	rec.access_rw = !qemu_plugin_mem_is_store(info);
	rec.access_op = get_memop(info);
	rec.access_sz = memop_size(rec.access_op);
	rec.vaddr = vaddr;
	rec.paddr = qemu_plugin_pa_by_va(vaddr,
					&rec.leaves[0],
					&rec.leaves[1],
					&rec.leaves[2],
					&rec.leaves[3],
					&discard,
					&rec.pte
				);
    // printf("Radix Translate: vaddr=%lx PTE0=%lx PTE1=%lx PTE2=%lx "
    //          "PTE3=%lx paddr=%lx access_rw=%d access_op=%d access_sz=%d\n",
    //          rec.vaddr, rec.leaves[0], rec.leaves[1], rec.leaves[2], rec.leaves[3],
    //          rec.paddr,
    //          rec.access_rw,
    //          rec.access_op,
    //          rec.access_sz);

	write_mem_record(&rec);
}

/**
* Log instruction execution
*/
static void vcpu_insn_exec(unsigned int cpu_index, void *udata)
{
	struct qemu_plugin_insn *ins = (struct qemu_plugin_insn *) udata;
	char *dias = qemu_plugin_insn_disas(ins);
    uint32_t discard;
	InsRecord rec;

    ins_counter++;
    
	rec.cpu = cpu_index;
	rec.opcode = *((uint32_t *)qemu_plugin_insn_data(ins));
	rec.vaddr = qemu_plugin_insn_vaddr(ins);
	// rec.counter = ins_counter;
    rec.paddr = qemu_plugin_pa_by_va(rec.vaddr,
					&rec.leaves[0],
					&rec.leaves[1],
					&rec.leaves[2],
					&rec.leaves[3],
					&discard,
					&rec.pte
				);

	write_ins_record(&rec, dias);
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
		// TODO: @fan please test this
		insn = qemu_plugin_tb_get_insn(tb, i);

		/* Register callback on memory read or write */
		qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem,
										QEMU_PLUGIN_CB_NO_REGS,
										QEMU_PLUGIN_MEM_RW, NULL);

		/* Register callback on instruction */
		qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_insn_exec,
											QEMU_PLUGIN_CB_NO_REGS, insn);
	}
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
	close_bin_record();
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
										const qemu_info_t *info, int argc,
										char **argv)
{
	open_bin_record();

	/* Register translation block and exit callbacks */
	qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
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
