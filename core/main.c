#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

struct perf_event * __percpu *hw_bp_ctx;

static ulong hw_bp_addr;

module_param(hw_bp_addr, ulong, S_IRUSR);
MODULE_PARM_DESC(hw_bp_addr, "bp address");

static void hw_bp_ctx_handler(struct perf_event *bp,
			      struct perf_sample_data *data,
			      struct pt_regs *regs)
{
	dump_stack();
	printk(KERN_INFO "Dump stack from hw_bp_ctx_handler\n");
}

static int __init hw_break_module_init(void)
{
	int ret;
	struct perf_event_attr attr;

	if (!hw_bp_addr) {
		printk(KERN_INFO "bp addr is not set\n");
		return -EINVAL;
	}

	hw_breakpoint_init(&attr);
	attr.bp_addr = hw_bp_addr;
	attr.bp_len = HW_BREAKPOINT_LEN_8;
	attr.bp_type = HW_BREAKPOINT_W;

	hw_bp_ctx = register_wide_hw_breakpoint(&attr, hw_bp_ctx_handler,
						  NULL);
	if (IS_ERR((void __force *)hw_bp_ctx)) {
		ret = PTR_ERR((void __force *)hw_bp_ctx);
		goto fail;
	}

	printk(KERN_INFO "HW Breakpoint installed at addr 0x%llx\n",
	       attr.bp_addr);

	return 0;

fail:
	printk(KERN_INFO "Breakpoint registration failed\n");

	return ret;
}

static void __exit hw_break_module_exit(void)
{
	unregister_wide_hw_breakpoint(hw_bp_ctx);
	printk(KERN_INFO "HW Breakpoint uninstalled\n");
}

module_init(hw_break_module_init);
module_exit(hw_break_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("hw breakpoint");
