//go:build ignore

// labmod is an inert kernel module for the telltale lab. It prints one line
// when it loads and one when it unloads, and does nothing else: no hooks, no
// hiding, no files, no network. It exists so that telltale has a module that
// belongs to no package to find.
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

static int __init labmod_init(void)
{
	pr_info("labmod: loaded (telltale lab, inert)\n");
	return 0;
}

static void __exit labmod_exit(void)
{
	pr_info("labmod: unloaded\n");
}

module_init(labmod_init);
module_exit(labmod_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Inert module for the telltale lab");
