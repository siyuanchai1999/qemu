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

#define RADIX_LEVEL 4
struct radix_trans_info {
    uint64_t vaddr;
    uint64_t PTEs[RADIX_LEVEL];
    uint64_t paddr;
    int32_t access_type;
    uint32_t access_size;
    int32_t success;
    /* from CMU simulator  */
    uint64_t page_table_entry;
};
enum {
    ACCESS_LOAD,
    ACCESS_STORE
};

/* Store last executed instruction on each vCPU as a GString */
GArray *last_exec;

/**
 * Add memory read or write information to current instruction log
 */
static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t info,
                     uint64_t vaddr, void *udata)
{
    GString *s;
    struct radix_trans_info trans_info;

    /* Find vCPU in array */
    g_assert(cpu_index < last_exec->len);
    s = g_array_index(last_exec, GString *, cpu_index);

    /* Indicate type of memory access */
    if (qemu_plugin_mem_is_store(info)) {
        // g_string_append(s, ", store");
        trans_info.access_type = ACCESS_STORE;
    } else {
        // g_string_append(s, ", load");
        trans_info.access_type = ACCESS_LOAD;
    }

    /* If full system emulation log physical address and device name */
    struct qemu_plugin_hwaddr *hwaddr = qemu_plugin_get_hwaddr(info, vaddr);

    if (hwaddr) {
        uint64_t addr = qemu_plugin_hwaddr_phys_addr(hwaddr);
        const char *name = qemu_plugin_hwaddr_device_name(hwaddr);
        // g_string_append_printf(s, ", 0x%08"PRIx64", %s", addr, name);
    } else {
        // g_string_append_printf(s, ", 0x%08"PRIx64, vaddr);
    }

    trans_info.vaddr = vaddr;
    trans_info.paddr = qemu_plugin_pa_by_va(vaddr,
                                            &trans_info.PTEs[0],
                                            &trans_info.PTEs[1],
                                            &trans_info.PTEs[2],
                                            &trans_info.PTEs[3],
                                            &trans_info.access_size,
                                            &trans_info.page_table_entry);


    g_string_append_printf(s, "Radix Translate: vaddr=%lx PTE0=%lx PTE1=%lx PTE2=%lx "
            "PTE3=%lx paddr=%lx access=%d size=%d\n",
            trans_info.vaddr, trans_info.PTEs[0], trans_info.PTEs[1], trans_info.PTEs[2],
            trans_info.PTEs[3], trans_info.paddr, trans_info.access_type,
            trans_info.access_size);

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
    // g_string_printf(s, "%u, ", cpu_index);
    // g_string_append(s, (char *)udata);
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
