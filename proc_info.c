// SPDX-License-Identifier: GPL-2.0
/*
 * proc_info.c — 进程查找(GET_PID) / 模块基址(MODULE_BASE/BSS)
 *               / 线程TLS(GET_THREAD_TLS) / PACGA执行(EXEC_PACGA)
 */
#define pr_fmt(fmt) "lyz_drv: " fmt	/* 必须在所有 include 之前（printk.h 是 #ifndef pr_fmt 保护） */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/ptrace.h>
#include <asm/sysreg.h>

#include "lyz_drv.h"
#include "abi.h"

#define LYZ_MAX_CAND 512	/* 快照进程数上限，超过则只查前 512 个 */

/* ---------------- GET_PID ---------------- */

/*
 * 用 /proc/<pid>/cmdline 的 argv[0] basename 匹配（完整包名会超 15 字符，
 * comm 放不下，Android 的 ps 显示的正是 cmdline）。
 * 注意：get_task_mm/access_process_vm/mmput 都可能睡眠，
 * 必须在 rcu_read_lock 之外调用 —— 所以先快照再匹配。
 */
static bool cmdline_basename_match(struct task_struct *t, const char *name)
{
	struct mm_struct *mm;
	char buf[256];
	int len, i, base = 0, nlen, rem;
	bool match = false;

	nlen = strnlen(name, sizeof(buf) - 1);

	mm = get_task_mm(t);
	if (!mm)
		return false;

	len = mm->arg_end - mm->arg_start;
	if (len <= 0 || len > sizeof(buf))
		goto out;
	if (access_process_vm(t, mm->arg_start, buf, len, FOLL_FORCE) != len)
		goto out;

	/* argv[0] 的 basename：最后一个 '/' 之后 */
	for (i = 0; i < len && buf[i]; i++) {
		if (buf[i] == '/')
			base = i + 1;
	}
	rem = i - base;
	if (rem == nlen && memcmp(buf + base, name, nlen) == 0)
		match = true;

out:
	mmput(mm);
	return match;
}

long lyz_get_pid(struct twt_request *req)
{
	char name[256];
	struct task_struct *t, *hit = NULL;
	struct task_struct *cands[LYZ_MAX_CAND];
	int n = 0, i;
	size_t copy_len;

	if (!req->buffer)
		return -EINVAL;

	copy_len = req->size ? min_t(u64, req->size, sizeof(name))
			     : sizeof(name);
	if (copy_from_user(name, (void __user *)(unsigned long)req->buffer,
			   copy_len))
		return -EFAULT;
	name[sizeof(name) - 1] = '\0';
	if (!name[0])
		return -EINVAL;

	/* 快照：rcu 内只做 get_task_struct（原子操作），睡眠操作移出锁外 */
	rcu_read_lock();
	for_each_process(t) {
		if (n < LYZ_MAX_CAND) {
			get_task_struct(t);
			cands[n++] = t;
		}
	}
	rcu_read_unlock();

	/* 第一轮：comm 精确匹配（短名，如 "main"、守护进程名） */
	for (i = 0; i < n && !hit; i++) {
		if (strcmp(cands[i]->comm, name) == 0)
			hit = cands[i];
	}
	/* 第二轮：cmdline argv[0] basename 匹配（完整包名） */
	for (i = 0; i < n && !hit; i++) {
		if (cmdline_basename_match(cands[i], name))
			hit = cands[i];
	}

	for (i = 0; i < n; i++) {
		if (cands[i] != hit)
			put_task_struct(cands[i]);
	}

	if (!hit)
		return -ESRCH;

	req->pid = hit->pid;
	put_task_struct(hit);
	return 0;
}

/* ---------------- MODULE_BASE / MODULE_BSS ---------------- */

static bool vma_name_match(struct vm_area_struct *vma,
			   const char *name, int nlen)
{
	struct qstr *q;

	if (!vma->vm_file)
		return false;
	q = &vma->vm_file->f_path.dentry->d_name;
	if (q->len != nlen)
		return false;
	return memcmp(q->name, name, nlen) == 0;
}

long lyz_module_base(struct twt_request *req, bool bss)
{
	char name[256];
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	int nlen;
	u64 base = 0, end = 0;
	long ret = -ESRCH;

	if (!req->buffer)
		return -EINVAL;
	if (copy_from_user(name, (void __user *)(unsigned long)req->buffer,
			   sizeof(name)))
		return -EFAULT;
	name[sizeof(name) - 1] = '\0';
	nlen = strnlen(name, sizeof(name) - 1);
	if (!nlen)
		return -EINVAL;

	task = lyz_get_task(req->pid);
	if (!task)
		return -ESRCH;

	mm = get_task_mm(task);
	if (!mm)
		goto put_task;

	mmap_read_lock(mm);
	/* [家族适配点] 6.1 起 VMA 链表（mm->mmap / vma->vm_next）已被 maple
	 * tree 取代，mm_types.h 里 vm_next 字段根本不存在。VMA_ITERATOR 升序
	 * 遍历与旧链表语义一致（首个匹配 = 最低地址 = 模块基址）。
	 * 底层依赖 mas_find（已确认在 GKI KMI 符号列表内）。
	 * 5.10 / 5.15 家族：maple tree 尚未接管 VMA，此处须改回
	 * mm->mmap + vma->vm_next 链表遍历（移植清单见 BUILD.md 附录A）。 */
	{
		VMA_ITERATOR(vmi, mm, 0);

		for_each_vma(vmi, vma) {
			if (vma_name_match(vma, name, nlen)) {
				if (!base)
					base = vma->vm_start;	/* 首个映射 = 模块基址 */
				end = vma->vm_end;		/* 记录最后一个的结尾 */
			}
		}
	}
	if (base) {
		if (bss) {
			/*
			 * .bss = 紧跟最后一个文件映射的匿名 VMA
			 * （动态链接器把 .bss 单独映射为匿名页）
			 */
			vma = find_vma(mm, end);
			req->addr = (vma && vma->vm_start == end &&
				     !vma->vm_file) ? vma->vm_start : 0;
		} else {
			req->addr = base;
		}
		ret = 0;
	}
	mmap_read_unlock(mm);

	mmput(mm);
put_task:
	put_task_struct(task);
	return ret;
}

/* ---------------- GET_THREAD_TLS ---------------- */

long lyz_get_thread_tls(struct twt_tls_request *req)
{
	struct task_struct *group, *t;
	bool found = false;
	u64 tls = 0;

	/* R3 语义：result 为 0 成功，非 0 为负 errno，ioctl 返回值恒 0 */
	req->result = 0;

	if (req->pid <= 0 || req->tid <= 0) {
		req->result = -EINVAL;
		return 0;
	}

	group = lyz_get_task(req->pid);
	if (!group) {
		req->result = -ESRCH;
		return 0;
	}

	rcu_read_lock();
	/*
	 * task_struct 走 RCU 释放，rcu_read_lock 内直接读字段安全。
	 * 内核在上下文切换时会把 TPIDR_EL0 备份到这里 ——
	 * 所以读到的值 == 该线程用户态实际看到的 TLS 基址。
	 */
	for_each_thread(group, t) {
		if (t->pid == req->tid) {
			tls = t->thread.uw.tp_value;
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	put_task_struct(group);

	if (!found) {
		req->result = -ESRCH;
		return 0;
	}
	req->tls_value = tls;
	return 0;
}

/* ---------------- EXEC_PACGA ---------------- */

long lyz_exec_pacga(struct twt_pacga_request *req)
{
#ifdef CONFIG_ARM64_PTR_AUTH
	struct task_struct *task;
	u64 save_lo, save_hi, out;

	if (req->pid <= 0)
		return -EINVAL;

	task = lyz_get_task(req->pid);
	if (!task)
		return -ESRCH;

	/*
	 * pacga 用 APGAKEY_EL1（当前线程的 key）计算地址签名。
	 * 要以目标进程的 key 计算：临时换成目标 task 保存的 key，
	 * 执行 pacga，再立刻换回 —— 必须关抢占，防止中途被切出去
	 * 导致切换代码把"目标 key"误存进当前线程的 keys_user。
	 */
	preempt_disable();

	save_lo = read_sysreg_s(SYS_APGAKEYLO_EL1);
	save_hi = read_sysreg_s(SYS_APGAKEYHI_EL1);

	write_sysreg_s(task->thread.keys_user.apga.lo, SYS_APGAKEYLO_EL1);
	write_sysreg_s(task->thread.keys_user.apga.hi, SYS_APGAKEYHI_EL1);
	isb();

	/* 汇编器门禁：内核只带 -mbranch-protection=pac-ret（编译器可生成
	 * paciasp/autiasp），不带 +pauth（汇编器不认 pacga 助记符）——
	 * 用 .arch_extension 放行，同 asm/lse.h 的 __LSE_PREAMBLE 惯用法 */
	asm volatile(".arch_extension pauth\n"
		     "pacga %0, %1, %2"
		     : "=r"(out)
		     : "r"(req->value), "r"(req->modifier));

	write_sysreg_s(save_lo, SYS_APGAKEYLO_EL1);
	write_sysreg_s(save_hi, SYS_APGAKEYHI_EL1);
	isb();

	preempt_enable();

	put_task_struct(task);

	req->result_pac = out;
	req->ok = 1;
	return 0;
#else
	/* SoC 不支持指针认证（PAC），pacga 等价 NOP，签名无意义 */
	return -EOPNOTSUPP;
#endif
}
