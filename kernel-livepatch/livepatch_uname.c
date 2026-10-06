#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/livepatch.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");

static int livepatch_version_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Linux version 7.3.0-LIVEPATCHED (fkernel-dev#1) (gcc 16.2) #1 SMP PREEMPT_DYNAMIC\n");
    return 0;
}

static struct klp_func funcs[] = {
    {
        .old_name = "version_proc_show",
        .new_func = livepatch_version_proc_show,
    }, { }
};

static struct klp_object objs[] = {
    {
        .funcs = funcs,
    }, { }
};

static struct klp_patch patch = {
    .mod = THIS_MODULE,
    .objs = objs,
};

static int livepatch_init(void)
{
    return klp_enable_patch(&patch);
}

static void livepatch_exit(void)
{
}

module_init(livepatch_init);
module_exit(livepatch_exit);
