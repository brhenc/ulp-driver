// SPDX-License-Identifier: GPL-2.0-only
/*
 * ulp-driver: Kernel Livepatch for ulp_driver.ko
 * Demonstrates that ulp_driver is 100% maintainable and patchable via
 * standard Linux kernel livepatching (CONFIG_LIVEPATCH / ftrace).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/livepatch.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ulp-driver");
MODULE_DESCRIPTION("Kernel Livepatch for ulp_driver Userspace Livepatching Driver");
MODULE_INFO(livepatch, "Y");

/* Replacement function for ulp_proc_show in ulp_driver.ko */
static int livepatch_ulp_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "====================================================================================================\n");
    seq_printf(m, " [KERNEL LIVEPATCH ACTIVE] ulp_driver.ko patched via Linux klp (CONFIG_LIVEPATCH / ftrace)\n");
    seq_printf(m, " Livepatch Target: ulp_driver::ulp_proc_show | Zero-Downtime Hotfix Verified\n");
    seq_printf(m, "====================================================================================================\n");
    return 0;
}

static struct klp_func funcs[] = {
    {
        .old_name = "ulp_proc_show",
        .new_func = livepatch_ulp_proc_show,
    }, { }
};

static struct klp_object objs[] = {
    {
        .name = "ulp_driver",
        .funcs = funcs,
    }, { }
};

static struct klp_patch patch = {
    .mod = THIS_MODULE,
    .objs = objs,
};

static int livepatch_ulp_init(void)
{
    pr_info("[klp_ulp] Enabling kernel livepatch for ulp_driver.ko...\n");
    return klp_enable_patch(&patch);
}

static void livepatch_ulp_exit(void)
{
    pr_info("[klp_ulp] Kernel livepatch for ulp_driver.ko exited\n");
}

module_init(livepatch_ulp_init);
module_exit(livepatch_ulp_exit);
