#include <linux/init.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
#include <asm/debugreg.h>
#include "linux/mm.h"

#define ASSERT(x)                                        \
do {	if (x) break;                                    \
	pr_emerg("### ASSERTION FAILED %s %s @ %d: %s\n",    \
		__FILE__, __func__, __LINE__, #x); dump_stack(); \
} while (0)

static unsigned long watch_address = 0;
static struct kobject *watch_kobj;
module_param(watch_address, ulong, 0644);
MODULE_PARM_DESC(watch_address, "Memory address to set the watchpoint");

#if defined(__x86_64__) || defined(__aarch64__)
    // These support 64bit length
    #define HW_BREAKPOINT_LEN HW_BREAKPOINT_LEN_8
#else
    // Fallback to safe length
    #define HW_BREAKPOINT_LEN HW_BREAKPOINT_LEN_4
#endif

#if defined(__aarch64__) || defined(__arm__) || defined(__riscv) || defined(__powerpc__)
    // Architectures that support HW_BREAKPOINT_R (read-exclusive) properly afaik
    #define HAS_READ_EXCLUSIVE_HW_BP 1
#else	// x86, mips, i386, etc.
    #define HAS_READ_EXCLUSIVE_HW_BP 0
#endif

#if HAS_READ_EXCLUSIVE_HW_BP
static struct perf_event *__percpu *hw_breakpoint_R;
static struct perf_event *__percpu *hw_breakpoint_W;
#else
static struct perf_event *__percpu *hw_breakpoint_RW;
#endif

static void __attribute__((unused)) print_user_registers(struct pt_regs *regs) {
	struct pt_regs *r = regs;
	pr_info("%s:\n"
			"bp=0x%lx | bx=0x%lx | r12=0x%lx | r13=0x%lx | r14=0x%lx | r15=0x%lx\n"
			"di=0x%lx | si=0x%lx | dx=0x%lx | cx=0x%lx | ax=0x%lx | r8=0x%lx | r9=0x%lx | r10=0x%lx | r11=0x%lx\n"
			"sp=0x%lx | ip=0x%lx\n"
			"\n",
			user_mode(regs) ? "USER REGS" : "REGS",
			r->bp, r->bx, r->r12, r->r13, r->r14, r->r15,
			r->di, r->si, r->dx, r->cx, r->ax, r->r8, r->r9, r->r10, r->r11,
			r->sp, r->ip
	);
}

static void print_debug_registers(void) {
	unsigned long dr[6];

	get_debugreg(dr[0], 0);
	get_debugreg(dr[1], 1);
	get_debugreg(dr[2], 2);
	get_debugreg(dr[3], 3);
	get_debugreg(dr[4], 6);
	get_debugreg(dr[5], 7);

	pr_info("Debug registers:  DR0=0x%lx\tDR1=0x%lx\tDR2=0x%lx\n"
						"\t\t\tDR3=0x%lx\tDR6=0x%lx\tDR7=0x%lx\n",
			dr[0], dr[1], dr[2], dr[3], dr[4], dr[5]);
}

static u8 get_hw_bp_slots(void) {
	static u8 slots;

	if (!slots)
		slots = hw_breakpoint_slots(TYPE_DATA);

	return slots;
}

#if HAS_READ_EXCLUSIVE_HW_BP
static void read_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
	struct perf_event_attr attr = bp->attr;
	struct hw_perf_event hw = bp->hw;

	pr_info("Watchpoint triggered at address: %p with READ access by: $(ip)%lx"
			"\n.bp_type %s | .type %d | state %d | htype %d | hwi %llu\n\n",
			(void*)watch_address, regs->ip, (attr.bp_type == HW_BREAKPOINT_R ? "READ" : "GARBAGE"),
			attr.type, hw.state, hw.info.type, hw.interrupts);

	//dump_stack();
}

static void write_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
	struct perf_event_attr attr = bp->attr;
	struct hw_perf_event hw = bp->hw;

	pr_info("Watchpoint triggered at address: %p with WRITE access by: $(ip)%lx"
			"\n.bp_type %s | .type %d | state %d | htype %d | hwi %llu\n\n",
			(void*)watch_address, regs->ip, (attr.bp_type == HW_BREAKPOINT_W ? "WRITE" : "GARBAGE"),
			attr.type, hw.state, hw.info.type, hw.interrupts);

	//dump_stack();
}
#else
static DEFINE_PER_CPU(unsigned long, last_bp_ip);
static DEFINE_PER_CPU(u8[8], watched_mem);

enum type { A_READ = 0, A_WRITE =1 };
static s8 access_type = 0;

static inline s32 snapshot_mem(void* dst) {
	if (access_ok((const void __user *)watch_address, sizeof(dst))) {
		 copy_from_user_nofault(dst, (const void __user*)watch_address, sizeof(dst));
	} else {
		copy_from_kernel_nofault(dst, (void *)watch_address, sizeof(dst));
	}
	pr_info("Got memory sample @ 0x%lx value = %#08x\n", watch_address, *(u32 *)dst);
	return 0;
}

static void breakpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
	preempt_disable();
	this_cpu_write(last_bp_ip, instruction_pointer(regs));
	u8 *mem_prev = this_cpu_ptr(watched_mem);
	preempt_enable();

	u8 mem_curr[8];
	snapshot_mem(&mem_curr);
	access_type = memcmp(mem_prev, mem_curr, sizeof(mem_curr)) == 0 ? 
		A_READ : A_WRITE;
	
	pr_info("Watchpoint triggered at address: 0x%llx with %s acess type\n"
		"\t\t\t\t\t\tprev mem state: %#08x | curr mem state: %#08x\n"
		"\t\t\t\t\t\tregs->sp: 0x%lx | regs->ip: 0x%lx\n",
			bp->attr.bp_addr, access_type == 1 ? "WRITE" : "READ",
			(u32)*mem_prev, (u32)*mem_curr,
			regs->sp, regs->ip);

	//print_user_registers(regs);
	memcpy(mem_prev, mem_curr, sizeof(mem_curr));
}
#endif

static s32 set_watchpoint(void) {
	s32 slots_needed = HAS_READ_EXCLUSIVE_HW_BP ? 2 : 1;
	if (get_hw_bp_slots() < slots_needed) {
		pr_err("No available hardware breakpoint slots\n");
		return -1;
	}
	ASSERT(watch_address);
	ASSERT(watch_address % HW_BREAKPOINT_LEN == 0);

#if HAS_READ_EXCLUSIVE_HW_BP
	struct perf_event_attr attr_R = {
		.type = PERF_TYPE_BREAKPOINT,
		.size = sizeof(attr_R),
		.bp_addr = (unsigned long)watch_address,
		.bp_len = HW_BREAKPOINT_LEN,
		.bp_type = HW_BREAKPOINT_R,
		.pinned = 1,
		.sample_period = 1,
	};

	struct perf_event_attr attr_W = {
		.type = PERF_TYPE_BREAKPOINT,
		.size = sizeof(attr_R),
		.bp_addr = (unsigned long)watch_address,
		.bp_len = HW_BREAKPOINT_LEN,
		.bp_type = HW_BREAKPOINT_W,
		 .pinned = 1,
		.sample_period = 1,
	};
#else
	struct perf_event_attr attr_RW = {
		.type = PERF_TYPE_BREAKPOINT,
		.size = sizeof(attr_RW),
		.bp_addr = (unsigned long)watch_address,
		.bp_len = HW_BREAKPOINT_LEN,
		.bp_type = HW_BREAKPOINT_RW,
		 .pinned = 1,
		.sample_period = 1,
		.exclude_kernel = 1,
	};
#endif

#if HAS_READ_EXCLUSIVE_HW_BP
	hw_breakpoint_R = register_wide_hw_breakpoint(&attr_R, read_handler, NULL);
	if (IS_ERR(hw_breakpoint_R)) {
		s32 ret = PTR_ERR(hw_breakpoint_R);
		pr_err("Failed to register READ breakpoint: %d\n", ret);
		hw_breakpoint_R = NULL;
	}
	hw_breakpoint_W = register_wide_hw_breakpoint(&attr_W, write_handler, NULL);
	if (IS_ERR(hw_breakpoint_W)) {
		s32 ret = PTR_ERR(hw_breakpoint_W);
		pr_err("Failed to register WRITE breakpoint: %d\n", ret);
		hw_breakpoint_W = NULL;
	}
#else
	preempt_disable();
	u8 *mem_prev = this_cpu_ptr(watched_mem);
	snapshot_mem(mem_prev);
	preempt_enable();
	hw_breakpoint_RW = register_wide_hw_breakpoint(&attr_RW, breakpoint_handler, NULL);
	if (IS_ERR(hw_breakpoint_RW)) {
		s32 ret = PTR_ERR(hw_breakpoint_RW);
		pr_err("Failed to register R|W breakpoint: %d\n", ret);
		hw_breakpoint_RW = NULL;
	}
#endif

	pr_info("Watchpoint set at address: 0x%lx\n", watch_address);
	print_debug_registers();
	return 0;
}

static void clear_watchpoint(void) {
	s32 cpu;
#if HAS_READ_EXCLUSIVE_HW_BP
	if (hw_breakpoint_R) {
		for_each_possible_cpu(cpu) {
			struct perf_event **bp = per_cpu_ptr(hw_breakpoint_R, cpu);
			if (*bp)
				unregister_hw_breakpoint(*bp);
		}
		free_percpu(hw_breakpoint_R);
		hw_breakpoint_R = NULL;
	}

	if (hw_breakpoint_W) {
		for_each_possible_cpu(cpu) {
			struct perf_event **bp = per_cpu_ptr(hw_breakpoint_W, cpu);
			if (*bp)
				unregister_hw_breakpoint(*bp);
		}
		free_percpu(hw_breakpoint_W);
		hw_breakpoint_W = NULL;
	}
#else
	if (hw_breakpoint_RW) {
		for_each_possible_cpu(cpu) {
			struct perf_event **bp = per_cpu_ptr(hw_breakpoint_RW, cpu);
			if (*bp)
				unregister_hw_breakpoint(*bp);
		}
		free_percpu(hw_breakpoint_RW);
		hw_breakpoint_RW = NULL;
	}
#endif
	pr_info("Watchpoints cleared\n");
}

static ssize_t watch_address_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	return sprintf(buf, "%p\n", (void*)watch_address);
}

static ssize_t watch_address_store(struct kobject *kobj, struct kobj_attribute *attr,
								   const char *buf, size_t count) {
	s32 ret = kstrtoul(buf, 0, &watch_address);
	if (ret)
		return ret;
	clear_watchpoint();
	set_watchpoint();
	return count;
}

static struct kobj_attribute watch_attr = __ATTR(watch_address, 0644, watch_address_show, watch_address_store);

static s32 __init watchpoint_init(void) {

	s32 ret = 0;
	pr_info("Watchpoint kernel module loaded successfully.\n");

	watch_kobj = kobject_create_and_add("watchpoint", kernel_kobj);
	ASSERT(watch_kobj);

	ret = sysfs_create_file(watch_kobj, &watch_attr.attr);
	ASSERT(ret == 0);

	return 0;
}

static void __exit watchpoint_exit(void) {
	clear_watchpoint();
	if (watch_kobj) {
		sysfs_remove_file(watch_kobj, &watch_attr.attr);
		kobject_put(watch_kobj);
	}
	pr_info("Watchpoint kernel module exited.\n");
}

module_init(watchpoint_init);
module_exit(watchpoint_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("danylo-volchenko");
MODULE_DESCRIPTION("Watchpoint Kernel Module");
