// SPDX-License-Identifier: GPL-2.0
/*
 * hwbp.c — 硬件断点子系统（BP_INIT/INST/UNINST/MODIFY/GET_HITS...）
 *
 * 实现方式：perf_event_create_kernel_counter(PERF_TYPE_BREAKPOINT)。
 * debug exception 在目标线程上下文触发，overflow handler 拿到的
 * pt_regs * 就是该线程的用户态异常帧 —— 直接改它，异常返回后生效；
 * 此时内核还没碰过 FPSIMD，q0-q31 硬件里就是目标线程的用户值，
 * 用 str qN 抓下来即"命中瞬间完整的 128 位向量寄存器现场"。
 *
 * 已知边界（TwT 同样存在）：
 *  - 目标进程退出时 perf 会自动销毁挂在其上的 event，此时再
 *    bp_uninst 会对悬垂指针操作 —— 退出前应先 uninst；
 *  - exclude_kernel=1：只在用户态触发，避免内核态调试异常。
 */
#define pr_fmt(fmt) "lyz_drv: " fmt	/* 必须在所有 include 之前（printk.h 是 #ifndef pr_fmt 保护） */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/ktime.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <asm/ptrace.h>

#include "lyz_drv.h"
#include "abi.h"

#define TWT_MAX_BP 64
#define TWT_RING_DEFAULT 256

/* hw_breakpoint_slots() 的槽位索引约定（arch/arm64/kernel/hw_breakpoint.c）:
 * 0 = BRP（执行断点）数量，非 0 = WRP（数据观察点）数量 */
#define LYZ_SLOT_BREAK 0
#define LYZ_SLOT_WATCH 1

struct lyz_bp_entry {
	struct perf_event *event;
	struct bp_user_pt_regs regs_to_set;
	u64 reg_mask;
	u64 fp_mask;
	u32 flags;
	struct bp_hit_item *ring;
	u32 ring_cap;
	u32 ring_head;
	u32 ring_count;
	atomic64_t total_hits;
	spinlock_t lock;
};

static struct lyz_bp_entry *g_bp[TWT_MAX_BP];
static DEFINE_MUTEX(g_bp_mutex);
static bool g_bp_ready;

/* hw_breakpoint_slots 在 arm64 上未导出（kernel/events KMI 列表外），
 * 经 kallsyms 拿地址后按函数指针调用 */
static int (*g_bp_slots)(int type);

/* ---------------- NEON 寄存器读写（inline asm 直访 q0-q31） ---------------- */

/* 抓取全部 32 个 128 位向量寄存器（内核 general-regs 约束不影响 asm 文本） */
static void save_vregs(__uint128_t *v)
{
	/* 汇编器门禁：内核 -mgeneral-regs-only 连带禁了汇编器的 NEON 助记符。
	 * 只放行汇编器（.arch_extension simd，同 asm/lse.h 的 __LSE_PREAMBLE
	 * 惯用法）；编译器侧约束保持——本文件 C 代码仍无权自发用向量寄存器，
	 * 防止异常入口到抓取之间污染目标线程现场 */
	asm volatile(
	".arch_extension simd\n"
	"	str	q0,  [%0, #0]\n"
	"	str	q1,  [%0, #16]\n"
	"	str	q2,  [%0, #32]\n"
	"	str	q3,  [%0, #48]\n"
	"	str	q4,  [%0, #64]\n"
	"	str	q5,  [%0, #80]\n"
	"	str	q6,  [%0, #96]\n"
	"	str	q7,  [%0, #112]\n"
	"	str	q8,  [%0, #128]\n"
	"	str	q9,  [%0, #144]\n"
	"	str	q10, [%0, #160]\n"
	"	str	q11, [%0, #176]\n"
	"	str	q12, [%0, #192]\n"
	"	str	q13, [%0, #208]\n"
	"	str	q14, [%0, #224]\n"
	"	str	q15, [%0, #240]\n"
	"	str	q16, [%0, #256]\n"
	"	str	q17, [%0, #272]\n"
	"	str	q18, [%0, #288]\n"
	"	str	q19, [%0, #304]\n"
	"	str	q20, [%0, #320]\n"
	"	str	q21, [%0, #336]\n"
	"	str	q22, [%0, #352]\n"
	"	str	q23, [%0, #368]\n"
	"	str	q24, [%0, #384]\n"
	"	str	q25, [%0, #400]\n"
	"	str	q26, [%0, #416]\n"
	"	str	q27, [%0, #432]\n"
	"	str	q28, [%0, #448]\n"
	"	str	q29, [%0, #464]\n"
	"	str	q30, [%0, #480]\n"
	"	str	q31, [%0, #496]\n"
	: : "r"(v) : "memory");
}

#define LYZ_WRITE_Q(N) \
	case N: \
		asm volatile(".arch_extension simd\n" \
			     "ins v" #N ".d[0], %0\n" \
			     "ins v" #N ".d[1], %1" \
			     : : "r"(lo), "r"(hi)); \
		return;

/* 改写第 n 个向量寄存器（lo/hi 各占低/高 64 位） */
static void write_vreg(int n, u64 lo, u64 hi)
{
	switch (n) {
	LYZ_WRITE_Q(0)
	LYZ_WRITE_Q(1)
	LYZ_WRITE_Q(2)
	LYZ_WRITE_Q(3)
	LYZ_WRITE_Q(4)
	LYZ_WRITE_Q(5)
	LYZ_WRITE_Q(6)
	LYZ_WRITE_Q(7)
	LYZ_WRITE_Q(8)
	LYZ_WRITE_Q(9)
	LYZ_WRITE_Q(10)
	LYZ_WRITE_Q(11)
	LYZ_WRITE_Q(12)
	LYZ_WRITE_Q(13)
	LYZ_WRITE_Q(14)
	LYZ_WRITE_Q(15)
	LYZ_WRITE_Q(16)
	LYZ_WRITE_Q(17)
	LYZ_WRITE_Q(18)
	LYZ_WRITE_Q(19)
	LYZ_WRITE_Q(20)
	LYZ_WRITE_Q(21)
	LYZ_WRITE_Q(22)
	LYZ_WRITE_Q(23)
	LYZ_WRITE_Q(24)
	LYZ_WRITE_Q(25)
	LYZ_WRITE_Q(26)
	LYZ_WRITE_Q(27)
	LYZ_WRITE_Q(28)
	LYZ_WRITE_Q(29)
	LYZ_WRITE_Q(30)
	LYZ_WRITE_Q(31)
	}
}

/* ---------------- perf overflow handler ---------------- */

static void lyz_bp_overflow(struct perf_event *event,
			    struct perf_sample_data *data,
			    struct pt_regs *regs)
{
	struct lyz_bp_entry *e = event->overflow_handler_context;
	struct bp_hit_item item;
	unsigned long flags;
	u32 pos;
	int i;

	atomic64_inc(&e->total_hits);

	/* ---- 寄存器改写：直接改异常帧，返回用户态即生效 ---- */
	if (e->reg_mask) {
		for (i = 0; i < 31; i++)
			if (e->reg_mask & (1ULL << i))
				regs->regs[i] = e->regs_to_set.regs[i];
		if (e->reg_mask & REG_MODIFY_SP)
			regs->sp = e->regs_to_set.sp;
		if (e->reg_mask & REG_MODIFY_PC)
			regs->pc = e->regs_to_set.pc;
		if (e->reg_mask & REG_MODIFY_PSTATE)
			regs->pstate = e->regs_to_set.pstate;
	}
	if (e->fp_mask) {
		for (i = 0; i < 32; i++)
			if (e->fp_mask & (1ULL << i))
				write_vreg(i,
					(u64)(e->regs_to_set.vregs[i] &
					      0xffffffffffffffffULL),
					(u64)(e->regs_to_set.vregs[i] >> 64));
	}

	if (!(e->flags & BP_FLAG_RECORD))
		return;

	/* ---- 记录命中现场 ----
	 * arm64 pt_regs 前 288 字节（regs[31]/sp/pc/pstate/orig_x0/
	 * syscallno）与 bp_user_pt_regs 逐字段对齐，可直接 memcpy。
	 */
	item.task_id = (u64)current->pid;
	item.hit_addr = regs->pc;
	item.hit_time = ktime_get_ns();
	memcpy(&item.regs_info, regs,
	       offsetof(struct bp_user_pt_regs, vregs));
	save_vregs(item.regs_info.vregs);

	spin_lock_irqsave(&e->lock, flags);
	if (e->ring_count < e->ring_cap) {
		pos = (e->ring_head + e->ring_count) % e->ring_cap;
		memcpy(&e->ring[pos], &item, sizeof(item));
		e->ring_count++;
	}
	spin_unlock_irqrestore(&e->lock, flags);
}

/* ---------------- 安装 / 卸载 / 控制 ---------------- */

/* 调用方需持 g_bp_mutex；成功时 handle 写回 ua->addr */
static long lyz_bp_install(struct bp_inst_args *ua)
{
	struct lyz_bp_entry *e;
	struct perf_event_attr attr;
	struct task_struct *task;
	struct perf_event *ev;
	u32 bp_len;
	int slot, ret;

	for (slot = 0; slot < TWT_MAX_BP; slot++)
		if (!g_bp[slot])
			break;
	if (slot == TWT_MAX_BP)
		return -EBUSY;

	if (ua->pid <= 0 || !ua->addr)
		return -EINVAL;
	if (ua->bp_type != HW_BREAKPOINT_X && ua->bp_type != HW_BREAKPOINT_R &&
	    ua->bp_type != HW_BREAKPOINT_W && ua->bp_type != HW_BREAKPOINT_RW)
		return -EINVAL;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;
	spin_lock_init(&e->lock);
	atomic64_set(&e->total_hits, 0);

	e->ring_cap = TWT_RING_DEFAULT;
	e->ring = kvmalloc_array(e->ring_cap, sizeof(struct bp_hit_item),
				 GFP_KERNEL);
	if (!e->ring) {
		kfree(e);
		return -ENOMEM;
	}

	e->reg_mask = ua->reg_modify_mask;
	e->fp_mask = ua->fp_reg_modify_mask;
	e->flags = ua->flags;

	if (e->reg_mask || e->fp_mask) {
		if (!ua->regs_to_set_ptr) {
			ret = -EINVAL;
			goto err;
		}
		if (copy_from_user(&e->regs_to_set,
				   (void __user *)(unsigned long)ua->regs_to_set_ptr,
				   sizeof(e->regs_to_set))) {
			ret = -EFAULT;
			goto err;
		}
	}

	/* arm64 硬件约束：执行断点长度恒 4；观察点 1~8 字节 */
	bp_len = (ua->bp_type == HW_BREAKPOINT_X)
			? HW_BREAKPOINT_LEN_4
			: clamp_t(u32, ua->bp_len, 1, 8);

	/* 必须清零：栈上 attr 的 config/sample_type 等字段带着垃圾会被
	 * perf 核心按用户配置解释，行为未定义 */
	memset(&attr, 0, sizeof(attr));
	attr.type = PERF_TYPE_BREAKPOINT;
	attr.size = sizeof(attr);
	attr.bp_type = ua->bp_type;
	attr.bp_addr = ua->addr;
	attr.bp_len = bp_len;
	attr.sample_period = 1;		/* 每次命中都触发 */
	attr.exclude_kernel = 1;	/* 仅用户态触发 */

	task = lyz_get_task(ua->pid);
	if (!task) {
		ret = -ESRCH;
		goto err;
	}
	/* cpu=-1 + task 非 NULL → 跟随任务的 per-task 事件 */
	ev = perf_event_create_kernel_counter(&attr, -1, task,
					      lyz_bp_overflow, e);
	put_task_struct(task);
	if (IS_ERR(ev)) {
		ret = PTR_ERR(ev);
		goto err;
	}

	e->event = ev;
	g_bp[slot] = e;

	ua->addr = slot + 1;	/* handle：1~TWT_MAX_BP，0 表示无效 */
	pr_info("bp installed: handle=%d pid=%d addr=0x%llx type=%u len=%u\n",
		slot + 1, ua->pid, (unsigned long long)attr.bp_addr,
		ua->bp_type, bp_len);
	return 0;

err:
	kvfree(e->ring);
	kfree(e);
	return ret;
}

/* 调用方需持 g_bp_mutex */
static long lyz_bp_uninstall(u64 handle)
{
	struct lyz_bp_entry *e;

	if (!handle || handle > TWT_MAX_BP)
		return -EINVAL;
	e = g_bp[handle - 1];
	if (!e)
		return -EINVAL;
	g_bp[handle - 1] = NULL;

	if (e->event) {
		perf_event_release_kernel(e->event);
		e->event = NULL;
	}
	/* 尽力等待在飞的 overflow 回调退出 */
	synchronize_rcu();

	kvfree(e->ring);
	kfree(e);
	pr_info("bp uninstalled: handle=%llu\n",
		(unsigned long long)handle);
	return 0;
}

/* ---------------- ioctl 分发（main.c default 转发到这里） ---------------- */

long lyz_bp_ioctl(unsigned int nr, unsigned long arg)
{
	switch (nr) {
	case NR_BP_INIT:
	case NR_BP_CHECK_INITED:
		return g_bp_ready ? 0 : -ENODEV;

	case NR_BP_GET_NUM_BRPS:
		return g_bp_slots ? g_bp_slots(LYZ_SLOT_BREAK) : -ENOENT;

	case NR_BP_GET_NUM_WRPS:
		return g_bp_slots ? g_bp_slots(LYZ_SLOT_WATCH) : -ENOENT;

	case NR_BP_INST: {
		struct bp_inst_args ua;
		long ret;

		if (copy_from_user(&ua, (void __user *)arg, sizeof(ua)))
			return -EFAULT;
		mutex_lock(&g_bp_mutex);
		ret = lyz_bp_install(&ua);
		mutex_unlock(&g_bp_mutex);
		if (ret)
			return ret;
		/* handle 回写进 args.addr —— R3 从这里读取 */
		if (copy_to_user((void __user *)arg, &ua, sizeof(ua)))
			return -EFAULT;
		return 0;
	}

	case NR_BP_UNINST: {
		u64 h;
		long ret;

		if (copy_from_user(&h, (void __user *)arg, sizeof(h)))
			return -EFAULT;
		mutex_lock(&g_bp_mutex);
		ret = lyz_bp_uninstall(h);
		mutex_unlock(&g_bp_mutex);
		return ret;
	}

	case NR_BP_SUSPEND:
	case NR_BP_RESUME: {
		u64 h;
		struct lyz_bp_entry *e;

		if (copy_from_user(&h, (void __user *)arg, sizeof(h)))
			return -EFAULT;
		if (!h || h > TWT_MAX_BP)
			return -EINVAL;

		mutex_lock(&g_bp_mutex);
		e = g_bp[h - 1];
		if (!e || !e->event) {
			mutex_unlock(&g_bp_mutex);
			return -EINVAL;
		}
		if (nr == NR_BP_SUSPEND)
			perf_event_disable(e->event);
		else
			perf_event_enable(e->event);
		mutex_unlock(&g_bp_mutex);
		return 0;
	}

	case NR_BP_GET_HIT_COUNT: {
		struct bp_get_hit_count_arg ca;
		struct lyz_bp_entry *e;
		unsigned long flags;

		if (copy_from_user(&ca, (void __user *)arg, sizeof(ca)))
			return -EFAULT;
		if (!ca.handle || ca.handle > TWT_MAX_BP)
			return -EINVAL;

		mutex_lock(&g_bp_mutex);
		e = g_bp[ca.handle - 1];
		mutex_unlock(&g_bp_mutex);
		if (!e)
			return -EINVAL;

		spin_lock_irqsave(&e->lock, flags);
		ca.hit_total_count = (u64)atomic64_read(&e->total_hits);
		ca.hit_item_arr_count = e->ring_count;
		spin_unlock_irqrestore(&e->lock, flags);

		if (copy_to_user((void __user *)arg, &ca, sizeof(ca)))
			return -EFAULT;
		return 0;
	}

	case NR_BP_MODIFY: {
		struct bp_modify_args ma;
		struct bp_user_pt_regs regs;
		struct lyz_bp_entry *e;
		unsigned long flags;

		if (copy_from_user(&ma, (void __user *)arg, sizeof(ma)))
			return -EFAULT;
		if (!ma.handle || ma.handle > TWT_MAX_BP)
			return -EINVAL;
		if (ma.reg_modify_mask || ma.fp_reg_modify_mask) {
			if (!ma.regs_to_set_ptr)
				return -EINVAL;
			if (copy_from_user(&regs,
					   (void __user *)(unsigned long)ma.regs_to_set_ptr,
					   sizeof(regs)))
				return -EFAULT;
		}

		mutex_lock(&g_bp_mutex);
		e = (ma.handle <= TWT_MAX_BP) ? g_bp[ma.handle - 1] : NULL;
		if (!e) {
			mutex_unlock(&g_bp_mutex);
			return -EINVAL;
		}
		spin_lock_irqsave(&e->lock, flags);
		e->reg_mask = ma.reg_modify_mask;
		e->fp_mask = ma.fp_reg_modify_mask;
		if (ma.reg_modify_mask || ma.fp_reg_modify_mask)
			memcpy(&e->regs_to_set, &regs, sizeof(regs));
		spin_unlock_irqrestore(&e->lock, flags);
		mutex_unlock(&g_bp_mutex);
		return 0;
	}

	case NR_BP_GET_HIT_ITEMS: {
		struct bp_get_hit_items_args ia;
		struct lyz_bp_entry *e;
		struct bp_hit_item *kbuf;
		size_t max_items, bytes;
		unsigned long flags;
		u32 n, i;

		if (copy_from_user(&ia, (void __user *)arg, sizeof(ia)))
			return -EFAULT;
		if (!ia.handle || ia.handle > TWT_MAX_BP ||
		    !ia.user_buffer_ptr || !ia.max_bytes)
			return -EINVAL;

		max_items = ia.max_bytes / sizeof(struct bp_hit_item);
		if (max_items > TWT_RING_DEFAULT)
			max_items = TWT_RING_DEFAULT;
		if (!max_items)
			return -EINVAL;

		/* copy_to_user 可能睡眠，绝不能持自旋锁；
		 * 先在锁内搬到内核缓冲，锁外再拷给用户 */
		kbuf = kvmalloc_array(max_items, sizeof(struct bp_hit_item),
				      GFP_KERNEL);
		if (!kbuf)
			return -ENOMEM;

		mutex_lock(&g_bp_mutex);
		e = g_bp[ia.handle - 1];
		if (!e) {
			mutex_unlock(&g_bp_mutex);
			kvfree(kbuf);
			return -EINVAL;
		}

		spin_lock_irqsave(&e->lock, flags);
		n = min_t(size_t, max_items, e->ring_count);
		for (i = 0; i < n; i++) {
			u32 pos = (e->ring_head + i) % e->ring_cap;

			memcpy(&kbuf[i], &e->ring[pos], sizeof(kbuf[i]));
		}
		e->ring_head = (e->ring_head + n) % e->ring_cap;
		e->ring_count -= n;
		spin_unlock_irqrestore(&e->lock, flags);
		mutex_unlock(&g_bp_mutex);

		bytes = (size_t)n * sizeof(struct bp_hit_item);
		if (bytes &&
		    copy_to_user((void __user *)(unsigned long)ia.user_buffer_ptr,
				 kbuf, bytes)) {
			kvfree(kbuf);
			return -EFAULT;
		}
		kvfree(kbuf);

		/* R3 语义：items_copied 是"条数"，不是字节数 */
		ia.items_copied = n;
		if (copy_to_user((void __user *)arg, &ia, sizeof(ia)))
			return -EFAULT;
		return 0;
	}

	default:
		return -ENOTTY;
	}
}

int lyz_bp_init(void)
{
	g_bp_slots = (int (*)(int))lyz_kln("hw_breakpoint_slots");
	if (!g_bp_slots) {
		pr_err("hw_breakpoint_slots not found, BP subsystem off\n");
		return -ENOENT;
	}

	g_bp_ready = true;
	pr_info("hw breakpoint subsystem ready (max %d, ring %d/item %zuB)\n",
		TWT_MAX_BP, TWT_RING_DEFAULT, sizeof(struct bp_hit_item));
	return 0;
}

void lyz_bp_exit(void)
{
	int i;

	mutex_lock(&g_bp_mutex);
	for (i = 0; i < TWT_MAX_BP; i++)
		if (g_bp[i])
			lyz_bp_uninstall(i + 1);
	mutex_unlock(&g_bp_mutex);
	g_bp_ready = false;
}
