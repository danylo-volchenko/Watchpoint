/*
  * watchpoint-km is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * watchpoint-km is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.*
 *
 * file: watchpoint.c
 * author: danylo volchenko <danylo.volchenko@gmail.com>
 * $2025-07-05
 *
 * vim: set ts=4 sw=4 noet tw=120:
 */


/**********************************************************
* Include files
**********************************************************/
#include <asm/debugreg.h>
#include <linux/hw_breakpoint.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/sysfs.h>
#include <linux/uaccess.h>
/**********************************************************
* Macro definitions
**********************************************************/
#define ASSERT(x)                                                                            \
	do {                                                                                     \
		if (x)                                                                               \
			break;                                                                           \
		pr_emerg("### ASSERTION FAILED %s %s @ %d: %s\n", __FILE__, __func__, __LINE__, #x); \
		dump_stack();                                                                        \
	} while (0)

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

#define AVAIL_SLOTS hw_breakpoint_slots(TYPE_DATA)
/**********************************************************
* Function Prototypes
**********************************************************/
static ssize_t watch_address_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf);
static ssize_t watch_address_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count);
/**********************************************************
* Variable declarations
**********************************************************/
static struct watchpoint {
	s32 idx;
	ulong addr;
	struct kobj_attribute attr;
} watchpoints[AVAIL_SLOTS] = {0,};
static ulong watch_addrs[AVAIL_SLOTS] = {0,};
static s32 num_addrs = 0;
static struct kobject *watch_kobj = NULL;
static struct kobj_attribute watch_attr = __ATTR(watch_address, 0644, watch_address_show, watch_address_store);

module_param_array_named(watch_addresses, watch_addrs, ulong, &num_addrs, 0644);
MODULE_PARM_DESC(watch_addresses, "Memory addresses to set the watchpoints");

#if HAS_READ_EXCLUSIVE_HW_BP
static struct perf_event *__percpu *hw_breakpoint_R[AVAIL_SLOTS/2] = {0,};
static struct perf_event *__percpu *hw_breakpoint_W[AVAIL_SLOTS/2] = {0,};
#else
static struct perf_event *__percpu *hw_breakpoint_RW[AVAIL_SLOTS] = {0,};
#endif
/**********************************************************
 * Functions
 **********************************************************/
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
static DEFINE_PER_CPU(u8[AVAIL_SLOTS][8], watched_mem);

enum type { A_READ = 0, A_WRITE =1 };
static s8 access_type = 0;

static inline s32 match_entry(ulong addr) {
	for (int i = 0; i < AVAIL_SLOTS; i++) {
		if (addr == watchpoints[i].addr)
			return watchpoints[i].idx;
	}
	return -1;
}

static inline s32 snapshot_mem(void *dst, ulong addr) {
	if (access_ok((const void __user *)addr, sizeof(dst))) {
		copy_from_user_nofault(dst, (const void __user *)addr, sizeof(dst));
	} else {
		copy_from_kernel_nofault(dst, (void *)addr, sizeof(dst));
	}
	pr_info("Got memory sample @ 0x%lx value = %#08x\n", addr, *(u32 *)dst);
	return 0;
}

static void breakpoint_handler(struct perf_event *bp, struct perf_sample_data *data, struct pt_regs *regs) {
	preempt_disable();
		s32 idx = match_entry(bp->attr.bp_addr);
		u8 *mem_prev = this_cpu_ptr(watched_mem[idx]);
	preempt_enable();

	u8 mem_curr[8];
	snapshot_mem(&mem_curr, bp->attr.bp_addr);
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

static s32 set_watchpoint(s32 idx, ulong addr) {
	ASSERT(addr && idx);
	ASSERT(addr % HW_BREAKPOINT_LEN == 0);

#if HAS_READ_EXCLUSIVE_HW_BP
	struct perf_event_attr attr_R = {
		.type = PERF_TYPE_BREAKPOINT,
		.size = sizeof(struct perf_event_attr),
		.bp_addr = addr,
		.bp_len = HW_BREAKPOINT_LEN,
		.bp_type = HW_BREAKPOINT_R,
		.pinned = 1,
		.sample_period = 1,
	};

	struct perf_event_attr attr_W = {
		.type = PERF_TYPE_BREAKPOINT,
		.size = sizeof(struct perf_event_attr),
		.bp_addr = addr,
		.bp_len = HW_BREAKPOINT_LEN,
		.bp_type = HW_BREAKPOINT_W,
		 .pinned = 1,
		.sample_period = 1,
	};
#else
	struct perf_event_attr attr_RW = {
		.type = PERF_TYPE_BREAKPOINT,
		.size = sizeof(struct perf_event_attr),
		.bp_addr = addr,
		.bp_len = HW_BREAKPOINT_LEN,
		.bp_type = HW_BREAKPOINT_RW,
		 .pinned = 1,
		.sample_period = 1,
		.exclude_kernel = 1,
	};
#endif

#if HAS_READ_EXCLUSIVE_HW_BP
	hw_breakpoint_R[idx] = register_wide_hw_breakpoint(&attr_R, read_handler, NULL);
	if (IS_ERR(hw_breakpoint_R[idx])) {
		s32 ret = PTR_ERR(hw_breakpoint_R[idx]);
		pr_err("Failed to register READ breakpoint: %d\n", ret);
		hw_breakpoint_R[idx] = NULL;
	}
	hw_breakpoint_W[idx] = register_wide_hw_breakpoint(&attr_W, write_handler, NULL);
	if (IS_ERR(hw_breakpoint_W[idx])) {
		s32 ret = PTR_ERR(hw_breakpoint_W[idx]);
		pr_err("Failed to register WRITE breakpoint: %d\n", ret);
		hw_breakpoint_W[idx] = NULL;
	}
#else
	preempt_disable();
		u8 *mem_prev = this_cpu_ptr(watched_mem[idx]);
		snapshot_mem(mem_prev, addr);
	preempt_enable();
	hw_breakpoint_RW[idx] = register_wide_hw_breakpoint(&attr_RW, breakpoint_handler, NULL);
	if (IS_ERR(hw_breakpoint_RW[idx])) {
		s32 ret = PTR_ERR(hw_breakpoint_RW[idx]);
		pr_err("Failed to register R|W breakpoint: %d\n", ret);
		hw_breakpoint_RW[idx] = NULL;
	}
#endif

	pr_info("Watchpoint #%d set at address: 0x%lx\n", idx, addr);
	print_debug_registers();
	return 0;
}

static void clear_watchpoint(s32 idx) {
	s32 cpu;
#if HAS_READ_EXCLUSIVE_HW_BP
	if (hw_breakpoint_R[idx]) {
		for_each_possible_cpu(cpu) {
			struct perf_event **bp = per_cpu_ptr(hw_breakpoint_R[idx], cpu);
			if (*bp)
				unregister_hw_breakpoint(*bp);
		}
		free_percpu(hw_breakpoint_R[idx]);
		hw_breakpoint_R[idx] = NULL;
	}

	if (hw_breakpoint_W[idx]) {
		for_each_possible_cpu(cpu) {
			struct perf_event **bp = per_cpu_ptr(hw_breakpoint_W[idx], cpu);
			if (*bp)
				unregister_hw_breakpoint(*bp);
		}
		free_percpu(hw_breakpoint_W[idx]);
		hw_breakpoint_W[idx] = NULL;
	}
#else
	if (hw_breakpoint_RW[idx]) {
		for_each_possible_cpu(cpu) {
			struct perf_event **bp = per_cpu_ptr(hw_breakpoint_RW[idx], cpu);
			if (*bp)
				unregister_hw_breakpoint(*bp);
		}
		free_percpu(hw_breakpoint_RW[idx]);
		hw_breakpoint_RW[idx] = NULL;
	}
#endif
	pr_info("Watchpoint cleared [idx@%d]\n",idx);
}

static ssize_t watch_address_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
	struct watchpoint *wp = container_of(attr, struct watchpoint, attr);
	return sprintf(buf, "0x%lx\n", wp->addr);
}

static ssize_t watch_address_store(struct kobject *kobj, struct kobj_attribute *attr,
								   const char *buf, size_t count) {
	struct watchpoint *wp = container_of(attr, struct watchpoint, attr);
	unsigned long val = 0x0;
	if (kstrtoul(buf, 0, &val))
		return -EINVAL;

	pr_info("Updated watchpoint[%d] from 0x%lx to 0x%lx\n", wp->idx, wp->addr, val);
	wp->addr = val;
	set_watchpoint(wp->idx, val);
	return count;
}

static s32 __init watchpoint_init(void) {
	pr_info("Watchpoint kernel module loaded successfully.\n");

	watch_kobj = kobject_create_and_add("watchpoint", kernel_kobj);
	ASSERT(watch_kobj);

	for (int idx = 0; idx < AVAIL_SLOTS; idx++) {
		struct watchpoint *wp = &watchpoints[idx];
		char name[8] = {0, };

		wp->idx	 = idx;
		wp->addr = (idx < num_addrs) ? watch_addrs[idx] : 0;

		sysfs_attr_init(&wp->attr.attr);
		snprintf(name, sizeof(name), "watch_%d", idx);

		wp->attr.attr.name = kstrdup(name, GFP_KERNEL);
		wp->attr.attr.mode = 0644;
		wp->attr.show	   = watch_address_show;
		wp->attr.store	   = watch_address_store;

		if (sysfs_create_file(watch_kobj, &wp->attr.attr))
			pr_warn("Failed to create sysfs entry for watchpoint #%d\n", idx);
	}

	return 0;
}

static void __exit watchpoint_exit(void) {
	for (int idx = 0; idx < AVAIL_SLOTS; idx++)
		clear_watchpoint(idx);
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
