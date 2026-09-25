// SPDX-License-Identifier: GPL-2.0
/*
 * fh.c — 符号解析 + kprobe 劫持框架
 *
 * 为什么用 kprobe 而不是 ftrace：
 *   出厂 GKI 内核没有函数级 ftrace——gki_defconfig 未开 CONFIG_FUNCTION_TRACER，
 *   ftrace_set_filter_ip / register_ftrace_function 也不在 GKI KMI 符号列表
 *   (android/abi_gki_aarch64.stg) 里，模块链接期就会失败。
 *   而 CONFIG_KPROBES=y 是 GKI defconfig 显式配置，register_kprobe 在 KMI 列
 *   表中——这也是 KernelSU 全系选择 kprobes 的原因（它同样在
 *   __arm64_sys_reboot 上挂 kprobe 做 supercall 入口）。
 *
 * 重定向机制（arm64 kernel/probes/kprobes.c kprobe_handler 原文注释）：
 *   "If we have a pre-handler and it returned non-zero, it will modify the
 *    execution path and no need to single stepping."
 *   pre_handler 返回非零 → 跳过被探测指令的单步执行，异常按（已被修改的）
 *   pt_regs 直接返回。我们设置 regs->pc = 替换函数，ERET 后就进入替换函数：
 *   它以正常内核 C 上下文运行（可睡眠），x0 仍是原函数的第一个参数
 *   （__arm64_sys_* 系列即用户 pt_regs 指针），LR 是 invoke_syscall 的返回
 *   地址，其返回值就是 syscall 返回值。这正是被移除的 jprobe 机制的核心，
 *   在 5.10/5.15/6.1 上行为一致。
 *
 * 为什么还需要 kallsyms_lookup_name：
 *   kprobe 的 .symbol_name 只能解析代码符号；input_dev_list / input_mutex
 *   这类静态数据符号要用 kallsyms_lookup_name，它 5.7 起不再导出，但注册
 *   一个同名 kprobe 即可从 kp.addr 拿到地址。
 */
#define pr_fmt(fmt) "lyz_drv: " fmt	/* 必须在所有 include 之前（printk.h 是 #ifndef pr_fmt 保护） */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/delay.h>
#include <asm/ptrace.h>

#include "lyz_drv.h"

static unsigned long (*g_kln)(const char *name);

/* 空 pre_handler，仅为了合法注册 kprobe 拿地址 */
static int kln_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

int lyz_setup_kallsyms(void)
{
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
		.pre_handler = kln_pre_handler,
	};
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe(kallsyms_lookup_name) failed: %d\n", ret);
		return ret;
	}
	g_kln = (void *)kp.addr;
	unregister_kprobe(&kp);

	if (!g_kln) {
		pr_err("kallsyms_lookup_name resolved to NULL\n");
		return -ENOENT;
	}
	lyz_info("kallsyms_lookup_name @ 0x%lx\n", (unsigned long)g_kln);
	return 0;
}

unsigned long lyz_kln(const char *name)
{
	if (!g_kln)
		return 0;
	return g_kln(name);
}

/* ---------------- kprobe 重定向框架 ---------------- */

/*
 * 通用 pre_handler。被探测的是 __arm64_sys_* 包装函数：
 *   断点处 x0 = 包装函数的第一个参数 = 用户态 pt_regs 指针。
 * intercept() 只允许做无锁的寄存器/原子读判断——此处处于调试异常上下文，
 * 不可睡眠。返回真则把 pc 换成替换函数并跳过原指令。
 */
static int lyz_kp_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct lyz_hook *hook = container_of(p, struct lyz_hook, kp);
	struct pt_regs *sregs = (struct pt_regs *)regs->regs[0];

	if (!sregs || !hook->intercept)
		return 0;

	if (hook->intercept(sregs)) {
		instruction_pointer_set(regs,
					(unsigned long)hook->replacement);
		return 1;
	}
	return 0;
}
NOKPROBE_SYMBOL(lyz_kp_pre);

int lyz_hook_install(struct lyz_hook *hook)
{
	int ret;

	hook->kp.symbol_name = hook->name;
	hook->kp.pre_handler = lyz_kp_pre;

	ret = register_kprobe(&hook->kp);
	if (ret < 0) {
		pr_err("register_kprobe(%s): %d\n", hook->name, ret);
		return ret;
	}

	/* hook 目标与替换函数地址是最敏感的取证指纹，quiet=1 时静默 */
	lyz_info("hooked %s @ 0x%lx -> 0x%lx\n", hook->name,
		(unsigned long)hook->kp.addr,
		(unsigned long)hook->replacement);
	return 0;
}

void lyz_hook_remove(struct lyz_hook *hook)
{
	unregister_kprobe(&hook->kp);
	/* 断点已移除；等在飞的 pre_handler（含异常返回窗口）排空 */
	synchronize_rcu();
	/* 等已进入替换函数的执行流退出，之后才允许释放模块文本 */
	while (atomic_read(hook->inflight))
		msleep(10);
}
