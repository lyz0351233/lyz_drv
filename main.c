// SPDX-License-Identifier: GPL-2.0
/*
 * main.c — lyz_drv 驱动入口
 *
 * 对接方式（与 TwT 完全兼容）：
 *   R3 通过 MY_CALL 宏直接 svc 一个 __NR_reboot，x0/x1/x2 带暗号，
 *   我们 kprobe 劫持 __arm64_sys_reboot（KernelSU 同款挂点），pre_handler
 *   命中暗号就把 pc 重定向到替换函数：发一个 anon_inode:<anon_name> 的 fd
 *   回去（x3 指向的 int 写回 fd 号，返回值也是 fd）。之后 ioctl 走这个 fd。
 *
 * 兜底设备（隐身化，吸收自 kernel_hack V5.0 的技巧）：
 *   - 原生 cdev + 自建 class（不用 misc → 不出现在 /proc/misc）
 *   - device_create 后立即 unregister_chrdev_region → /proc/devices 不可见
 *     （cdev_map 仍能解析，open 照常工作）
 *   - open 时销毁 /dev 节点与 class，close 时重建 → 使用期间全系统扫不到
 *   - nodev=1 时整条设备链不建：无 /dev 节点、无 /sys/class 目录、无
 *     device_create 的 uevent 广播。握手路径从不依赖设备节点，部署态
 *     推荐开（km_read 教训：模块隐藏但设备节点常驻 → 被扫 /dev 的 AC 抓）
 *
 * fd 上下文：每个 fd（握手 anon_inode 与兜底 cdev 两类）带一份目标
 *   mm 缓存（struct lyz_fd_ctx），v2 读写热路径免逐次解析 pid；
 *   fd 关闭时随 release 放 pin（实现与语义见 mem.c / lyz_drv.h）。
 *
 * 模块隐藏（hide=1 时启用，恢复用 ioctl _IO('T', 62)）：
 *   list_del 摘出 modules 链（lsmod / /proc/modules / kallsyms 模块符号
 *   全不可见）+ kobject_del 摘 /sys/module/<name>。
 *   注意：隐藏状态下 rmmod 会因找不到模块而失败，先 ioctl 恢复再卸载。
 *
 * 反查杀（私有扩展 NR 64，ioctl _IOW('T', 64, int)）：
 *   保护一个进程：发往它的 SIGKILL/SIGTERM（含 kill(-pid) 组击杀，
 *   am force-stop 最终走这里）被吞掉且 syscall 返回 0 伪装成功。
 *   按需挂 __arm64_sys_kill 的第二个 kprobe——不启用保护时该断点在
 *   系统里根本不存在（常驻指纹最小化）；保护随设置它的 fd 关闭而
 *   自动解除（防 pid 回收后误伤无辜进程）。
 *
 * v2 物理写（私有扩展 NR 63）：与 read_v2 对称的无痕写，仅匿名页，
 *   文件/共享页 -EOPNOTSUPP → R3 回退普通写（COW 语义）。
 *
 * quiet=1 加载参数：静默所有信息级 dmesg 输出（错误仍打印）。
 *
 * 版本体系（v1.5.0 起）：lyz_version.h 是唯一版本真源——驱动自身版本宏 +
 * 内核家族探测宏（5.10/5.15/6.1/6.6/6.12/6.18）。对标商用驱动"按内核
 * 家族分发"：一个家族一份 .ko（家族内 sublevel 差异被 KMI 吸收，家族之间
 * KMI 世代不同 → CRC 必不同），未适配家族在编译期 #error 点名。
 */
#define pr_fmt(fmt) "lyz_drv: " fmt	/* 必须在所有 include 之前（printk.h 是 #ifndef pr_fmt 保护） */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/anon_inodes.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <linux/signal.h>
#include <linux/kdev_t.h>
#include <linux/version.h>
#include <asm/ptrace.h>

#include "lyz_drv.h"
#include "abi.h"

/* 模块参数（insmod 时指定，例: insmod lyz_drv.ko hide=1）
 * 变量是 g_ 前缀、对外参数名保持原名 → 一律 module_param_named */
static bool g_hide;				/* 隐藏模块自身，默认关 */
module_param_named(hide, g_hide, bool, 0444);
MODULE_PARM_DESC(hide, "hide module from lsmod//proc/modules//sys/module (unhide via ioctl _IO('T',62) before rmmod)");

static char *g_anon_name = "TwT_driver";	/* 改名会破坏 TwT R3 兼容 */
module_param_named(anon_name, g_anon_name, charp, 0444);
MODULE_PARM_DESC(anon_name, "anon_inode name handed out via reboot channel");

static char *g_dev_name = "lyz_drv";		/* 兜底 /dev 节点名 */
module_param_named(dev_name, g_dev_name, charp, 0444);
MODULE_PARM_DESC(dev_name, "fallback cdev node name under /dev");

/* 不建兜底设备链（部署态推荐）：/dev 节点、/sys/class 目录、
 * device_create 的 uevent 广播全部不存在。km_read（可过 PUBGM/三角洲、
 * 过不了暗区的同类驱动）的教训——模块隐藏了但设备节点常驻，扫 /dev
 * 与 uevent 的 AC 一抓一个准。我们的握手路径从不依赖设备节点，
 * nodev=1 的唯一代价是"暗号握手失败时无 /dev 兜底"，而握手是我们
 * 自己实现的，正常加载必然可用 */
static bool g_nodev;
module_param_named(nodev, g_nodev, bool, 0444);
MODULE_PARM_DESC(nodev, "skip fallback cdev entirely: no /dev node, no /sys/class dir, no uevent (recommended for deployment)");

/* 静默模式：关掉所有信息级 dmesg 输出（pr_err/pr_warn 仍打印）。
 * 加载/卸载的日志、hook 地址、anon 名——这些是取证侧最廉价的指纹。
 * 注意：quiet 下拿不到兜底设备号，需要 mknod 调试时先跑一次非 quiet */
bool lyz_quiet;
module_param_named(quiet, lyz_quiet, bool, 0444);
MODULE_PARM_DESC(quiet, "silence informational dmesg output (errors still printed)");

/* ---------------- fd 上下文（目标 mm 缓存载体） ---------------- */

static struct lyz_fd_ctx *lyz_ctx_alloc(bool is_cdev)
{
	struct lyz_fd_ctx *ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);

	if (ctx) {
		mutex_init(&ctx->lock);
		ctx->is_cdev = is_cdev;
	}
	return ctx;
}

/* ---------------- reboot 劫持：暗号换 fd ---------------- */

static atomic_t g_reboot_inflight = ATOMIC_INIT(0);

/* kprobe pre_handler 调用（调试异常上下文，禁睡眠）：只做寄存器比较 */
static bool lyz_reboot_intercept(const struct pt_regs *sregs)
{
	/* 真实 reboot 的 magic1 是 0xfee1dead，与 0x114514 无冲突 */
	return sregs->regs[0] == TWT_MAGIC1 &&
	       sregs->regs[1] == TWT_MAGIC2 &&
	       sregs->regs[2] == TWT_CMD_BIND;
}

/* 替换函数体（syscall 上下文，可睡眠） */
static long lyz_reboot_body(const struct pt_regs *regs)
{
	struct lyz_fd_ctx *ctx;
	struct file *file;
	int fd;

	/* R3 的 MY_CALL 把 &fd 放在 x3 —— 先验可写再装机 */
	if (!access_ok((void __user *)regs->regs[3], sizeof(fd)))
		return -EFAULT;

	/* 每个 fd 一份目标缓存（v2 热路径用），随 fd 关闭释放 */
	ctx = lyz_ctx_alloc(false);
	if (!ctx)
		return -ENOMEM;

	file = anon_inode_getfile(g_anon_name, &lyz_fops, ctx, O_RDWR);
	if (IS_ERR(file)) {
		kfree(ctx);
		return PTR_ERR(file);
	}

	fd = get_unused_fd_flags(O_RDWR);
	if (fd < 0) {
		fput(file);
		return fd;
	}

	fd_install(fd, file);
	if (copy_to_user((void __user *)regs->regs[3], &fd, sizeof(fd)))
		return -EFAULT;	/* fd 已装好，R3 仍可从返回值拿到 */

	return fd;
}

/*
 * 替换函数：与 __arm64_sys_reboot 同形参（x0 = 用户 pt_regs 指针），
 * 由 pre_handler 改 pc 进入，返回值即 syscall 返回值。
 * in/out 计数用于模块卸载时排空在飞执行流。
 */
static asmlinkage long lyz_reboot_repl(const struct pt_regs *regs)
{
	long ret;

	atomic_inc(&g_reboot_inflight);
	ret = lyz_reboot_body(regs);
	atomic_dec(&g_reboot_inflight);
	return ret;
}
NOKPROBE_SYMBOL(lyz_reboot_repl);

static struct lyz_hook g_reboot_hook = {
	.name = "__arm64_sys_reboot",
	.intercept = lyz_reboot_intercept,
	.replacement = (void *)lyz_reboot_repl,
	.inflight = &g_reboot_inflight,
};

/* ---------------- 反查杀（私有扩展 NR 64） ---------------- */

static atomic_t g_prot_pid = ATOMIC_INIT(0);	/* 受保护 pid；0 = 关闭 */
static struct file *g_prot_owner;		/* 启用保护的 fd，关闭即解除 */
static bool g_kill_hook_installed;
static atomic_t g_kill_inflight = ATOMIC_INIT(0);
static DEFINE_MUTEX(g_prot_lock);
static struct lyz_hook g_kill_hook;

/*
 * __arm64_sys_kill 的用户 pt_regs：x0 = pid, x1 = sig。
 * 调试异常上下文（禁睡眠），只做原子读 + 比较返回：
 *   - 只吞 SIGKILL / SIGTERM（其余信号原样放行，系统行为零改变）
 *   - pid 与 -pid 都拦（后者是 kill_process_group 的组击杀方式）
 */
static bool lyz_kill_intercept(const struct pt_regs *sregs)
{
	int prot = atomic_read(&g_prot_pid);
	long pid = (long)sregs->regs[0];

	if (!prot)
		return false;
	if (pid != (long)prot && pid != -(long)prot)
		return false;
	return sregs->regs[1] == SIGKILL || sregs->regs[1] == SIGTERM;
}

/*
 * 吞掉击杀并伪装成功。比返回 -EPERM 隐蔽：同 uid 进程的正常 kill 不会
 * 得到 EPERM，报错本身就等于宣告"这个进程被保护了"。
 */
static asmlinkage long lyz_kill_repl(const struct pt_regs *regs)
{
	(void)regs;
	/* 空体也计在飞数：函数自身就是模块文本，卸载排空依赖它 */
	atomic_inc(&g_kill_inflight);
	atomic_dec(&g_kill_inflight);
	return 0;
}
NOKPROBE_SYMBOL(lyz_kill_repl);

/* 清除保护并摘除断点（调用方持 g_prot_lock；内部可睡眠） */
static void lyz_protect_clear_locked(void)
{
	atomic_set(&g_prot_pid, 0);
	g_prot_owner = NULL;
	if (g_kill_hook_installed) {
		lyz_hook_remove(&g_kill_hook);
		g_kill_hook_installed = false;
	}
}

/*
 * ioctl(NR_LYZ_PROTECT) 实现：pid > 0 保护（单槽，后设置覆盖前设置），
 * pid == 0 解除。断点只在第一次启用时挂上、彻底解除时摘下——
 * 平时不启用保护的话，__arm64_sys_kill 处根本不存在我们的痕迹。
 */
static long lyz_protect_set(struct file *owner, int pid)
{
	long ret = 0;

	if (pid < 0)
		return -EINVAL;

	mutex_lock(&g_prot_lock);
	if (!pid) {
		lyz_protect_clear_locked();
	} else if (!g_kill_hook_installed) {
		g_kill_hook.name = "__arm64_sys_kill";
		g_kill_hook.intercept = lyz_kill_intercept;
		g_kill_hook.replacement = (void *)lyz_kill_repl;
		g_kill_hook.inflight = &g_kill_inflight;
		ret = lyz_hook_install(&g_kill_hook);
		if (ret)
			goto out;
		g_kill_hook_installed = true;
		atomic_set(&g_prot_pid, pid);
		g_prot_owner = owner;
	} else {
		atomic_set(&g_prot_pid, pid);
		g_prot_owner = owner;
	}
out:
	mutex_unlock(&g_prot_lock);
	return ret;
}

/* fd 关闭时解除由它启用的保护（防 pid 回收后误伤无关进程） */
static void lyz_protect_release(struct file *file)
{
	mutex_lock(&g_prot_lock);
	if (g_prot_owner == file)
		lyz_protect_clear_locked();
	mutex_unlock(&g_prot_lock);
}

/* ---------------- 模块隐藏 ---------------- */

static struct mutex *g_module_mutex;	/* kernel/module/main.c 全局锁，kallsyms 解析 */
static struct list_head *g_mod_list_prev;
static bool g_mod_hidden;

static void lyz_module_hide(void)
{
	if (g_mod_hidden)
		return;

	/* modules 链表全程由 module_mutex 保护，按规矩持锁再动 */
	g_module_mutex = (struct mutex *)lyz_kln("module_mutex");
	if (g_module_mutex)
		mutex_lock(g_module_mutex);

	g_mod_list_prev = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);		/* lsmod / /proc/modules / kallsyms */

	if (g_module_mutex)
		mutex_unlock(g_module_mutex);

	/* /sys/module/<name> 整目录摘除；卸载路径对已 del 的 kobj 是宽容的 */
	kobject_del(&THIS_MODULE->mkobj.kobj);

	g_mod_hidden = true;
	lyz_info("module hidden — unhide with ioctl(fd, _IO('T', 62), 0) before rmmod\n");
}

static void lyz_module_unhide(void)
{
	if (!g_mod_hidden)
		return;

	if (g_module_mutex)
		mutex_lock(g_module_mutex);
	list_add(&THIS_MODULE->list, g_mod_list_prev);
	if (g_module_mutex)
		mutex_unlock(g_module_mutex);

	g_mod_hidden = false;
	lyz_info("module visible again — rmmod now works\n");
}

/* ---------------- 兜底 cdev 设备（隐身化） ---------------- */

static dev_t g_devt;
static struct cdev g_cdev;
static bool g_cdev_ready;	/* cdev 已注册（nodev=1 时恒为 false） */
static struct class *g_dev_class;
static bool g_dev_hidden;	/* open 时已销毁，等待 close 重建 */

static struct class *lyz_class_create(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	return class_create(g_dev_name);
#else
	return class_create(THIS_MODULE, g_dev_name);
#endif
}

/*
 * open → 销毁 /dev 节点与 class；持 fd 期间全系统扫不到。
 * 两类 fd 都带 fd 上下文（mm 缓存）；is_cdev 区分来源——
 * anon_inode 通道（reboot 暗号拿到的 fd）不走 .open，
 * 只有 cdev fd 会进到这里。
 */
static int lyz_open(struct inode *inode, struct file *file)
{
	struct lyz_fd_ctx *ctx = lyz_ctx_alloc(true);

	if (!ctx)
		return -ENOMEM;
	file->private_data = ctx;

	if (g_dev_class) {
		device_destroy(g_dev_class, g_devt);
		class_destroy(g_dev_class);
		g_dev_class = NULL;
		g_dev_hidden = true;
	}
	return 0;
}

/* close → 放掉 mm 缓存 pin 与上下文；cdev fd 再重建节点供下一次 open */
static int lyz_release(struct inode *inode, struct file *file)
{
	struct lyz_fd_ctx *ctx = file->private_data;

	/* 反查杀保护随启用它的 fd 关闭而解除（防 pid 回收后误伤） */
	lyz_protect_release(file);

	if (ctx) {
		lyz_mm_cache_drop(ctx);
		if (ctx->is_cdev && g_dev_hidden) {
			g_dev_class = lyz_class_create();
			if (!IS_ERR(g_dev_class)) {
				if (IS_ERR(device_create(g_dev_class, NULL, g_devt,
							 NULL, "%s", g_dev_name))) {
					class_destroy(g_dev_class);
					g_dev_class = NULL;
					pr_warn("device re-create failed\n");
				}
			} else {
				g_dev_class = NULL;
				pr_warn("class re-create failed\n");
			}
			g_dev_hidden = false;
		}
		kfree(ctx);
	}
	return 0;
}

/* ---------------- ioctl 总分发 ---------------- */

static long lyz_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned int nr = _IOC_NR(cmd);

	if (_IOC_TYPE(cmd) != TWT_MARK)
		return -ENOTTY;

	switch (nr) {
	case NR_GET_PID: {
		struct twt_request req;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		{
			long ret = lyz_get_pid(&req);

			if (ret)
				return ret;
		}
		if (copy_to_user((void __user *)arg, &req, sizeof(req)))
			return -EFAULT;
		return 0;
	}

	case NR_MODULE_BASE:
	case NR_MODULE_BSS: {
		struct twt_request req;
		long ret;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		ret = lyz_module_base(&req, nr == NR_MODULE_BSS);
		if (ret)
			return ret;
		if (copy_to_user((void __user *)arg, &req, sizeof(req)))
			return -EFAULT;
		return 0;
	}

	case NR_READ_MEM:
	case NR_READ_MEM_V2: {
		struct twt_request req;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		return lyz_read_mem(file, &req, nr == NR_READ_MEM_V2);
	}

	case NR_WRITE_MEM:
	case NR_LYZ_WRITE_V2: {
		struct twt_request req;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		/* NR 5 = 普通写（COW 语义）；私有 NR 63 = v2 物理写（无痕，
		 * 仅匿名页，文件页 -EOPNOTSUPP 由 R3 回退 NR 5）*/
		return lyz_write_mem(file, &req, nr == NR_LYZ_WRITE_V2);
	}

	case NR_TOUCH_INIT: {
		struct twt_touch_event te;
		long ret;

		if (copy_from_user(&te, (void __user *)arg, sizeof(te)))
			return -EFAULT;
		ret = lyz_touch_init(&te.slot);
		if (ret == -EALREADY) {
			/* 回写当前模式，R3 在 EALREADY 分支打印它 */
			if (copy_to_user((void __user *)arg, &te, sizeof(te)))
				return -EFAULT;
		}
		return ret;
	}

	case NR_TOUCH_DOWN: {
		struct twt_touch_event te;

		if (copy_from_user(&te, (void __user *)arg, sizeof(te)))
			return -EFAULT;
		return lyz_touch_down(te.slot, te.x, te.y);
	}

	case NR_TOUCH_UP: {
		struct twt_touch_event te;

		if (copy_from_user(&te, (void __user *)arg, sizeof(te)))
			return -EFAULT;
		return lyz_touch_up(te.slot);
	}

	case NR_GYRO_INIT: {
		int m;
		long ret;

		if (copy_from_user(&m, (void __user *)arg, sizeof(m)))
			return -EFAULT;
		ret = lyz_gyro_init(&m);
		if (ret == -EALREADY) {
			if (copy_to_user((void __user *)arg, &m, sizeof(m)))
				return -EFAULT;
		}
		return ret;
	}

	case NR_GYRO_CONFIG: {
		struct twt_gyro_config gc;

		if (copy_from_user(&gc, (void __user *)arg, sizeof(gc)))
			return -EFAULT;
		return lyz_gyro_modify(gc.enable, gc.x, gc.y);
	}

	case NR_GET_THREAD_TLS: {
		struct twt_tls_request req;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		lyz_get_thread_tls(&req);
		/* result 字段自带负 errno，ioctl 返回值恒 0（R3 语义） */
		if (copy_to_user((void __user *)arg, &req, sizeof(req)))
			return -EFAULT;
		return 0;
	}

	case NR_EXEC_PACGA: {
		struct twt_pacga_request req;
		long ret;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		ret = lyz_exec_pacga(&req);
		if (ret)
			return ret;
		if (copy_to_user((void __user *)arg, &req, sizeof(req)))
			return -EFAULT;
		return 0;
	}

	case NR_FILE_HIDE_SET:
		return lyz_hide_ioctl_set(arg);

	case NR_FILE_HIDE_CLEAR:
		return lyz_hide_ioctl_clear();

	case NR_FILE_HIDE_STATUS:
		return lyz_hide_ioctl_status(arg);

	case NR_LYZ_UNHIDE:
		/* 私有扩展：隐藏模式恢复可见性（卸载前必调） */
		lyz_module_unhide();
		return 0;

	case NR_LYZ_PROTECT: {
		int pid;

		if (copy_from_user(&pid, (void __user *)arg, sizeof(pid)))
			return -EFAULT;
		return lyz_protect_set(file, pid);
	}

	default:
		/* BP_* 全部交给 hwbp 子系统 */
		return lyz_bp_ioctl(nr, arg);
	}
}

const struct file_operations lyz_fops = {
	.owner = THIS_MODULE,	/* fd 未关闭时 rmmod 会被拒，防 UAF */
	.open = lyz_open,
	.release = lyz_release,
	.unlocked_ioctl = lyz_ioctl,
	/* 32 位兼容模式不支持（ABI 含 64 位指针字段），NULL → -ENOTTY */
	.compat_ioctl = NULL,
};

/* ---------------- 模块入口 ---------------- */

static int __init lyz_init(void)
{
	int ret;

	lyz_info("loading %s — kprobe base, hide=%d\n", LYZ_DRV_BANNER, g_hide);

	ret = lyz_setup_kallsyms();
	if (ret) {
		pr_err("kallsyms setup failed: %d\n", ret);
		return ret;
	}

	ret = lyz_hook_install(&g_reboot_hook);
	if (ret) {
		pr_err("reboot hook install failed: %d\n", ret);
		return ret;
	}

	/* 兜底 cdev：节点名可控、/proc/devices 不可见；nodev=1 时整条
	 * 设备链都不建（无 /dev 节点、无 /sys/class 目录、无 uevent） */
	if (!g_nodev) {
		ret = alloc_chrdev_region(&g_devt, 0, 1, g_dev_name);
		if (ret) {
			pr_err("alloc_chrdev_region failed: %d\n", ret);
			goto err_hook;
		}
		cdev_init(&g_cdev, &lyz_fops);
		g_cdev.owner = THIS_MODULE;
		ret = cdev_add(&g_cdev, g_devt, 1);
		if (ret) {
			pr_err("cdev_add failed: %d\n", ret);
			goto err_region;
		}
		g_cdev_ready = true;

		g_dev_class = lyz_class_create();
		if (IS_ERR(g_dev_class)) {
			ret = PTR_ERR(g_dev_class);
			g_dev_class = NULL;
			pr_err("class_create failed: %d\n", ret);
			goto err_cdev;
		}
		{
			struct device *devp = device_create(g_dev_class, NULL, g_devt,
							    NULL, "%s", g_dev_name);

			if (IS_ERR(devp)) {
				ret = PTR_ERR(devp);
				pr_err("device_create failed: %d\n", ret);
				goto err_cdev;	/* g_dev_class 仍有效，走统一清理 */
			}
		}

		/* 关键一步：注销区域 → /proc/devices 隐身，cdev_map 仍可 open。
		 * 代价是 major 可能被后来的 insmod 复用（研究用途可接受） */
		unregister_chrdev_region(g_devt, 1);
		/* 兜底设备号只打在 dmesg（/proc/devices 看不到是特性）；
		 * quiet=1 时不打印——需要 mknod 调试就先跑一次非 quiet */
		lyz_info("fallback dev: /dev/%s (c%d:%d) — mknod /dev/%s c %d %d\n",
			 g_dev_name, MAJOR(g_devt), MINOR(g_devt),
			 g_dev_name, MAJOR(g_devt), MINOR(g_devt));
	}

	/* 可选子系统：失败只关功能，不阻塞加载 */
	if (lyz_hide_init())
		pr_warn("file hide disabled\n");
	if (lyz_input_init())
		pr_warn("input inject disabled\n");
	if (lyz_bp_init())
		pr_warn("hw breakpoint disabled\n");

	if (g_hide)
		lyz_module_hide();

	if (g_nodev)
		lyz_info("loaded — fd: anon_inode:%s | no fallback device (nodev=1)\n",
			 g_anon_name);
	else
		lyz_info("loaded — fd: anon_inode:%s | misc fallback: /dev/%s\n",
			 g_anon_name, g_dev_name);
	return 0;

err_cdev:
	if (g_dev_class) {
		device_destroy(g_dev_class, g_devt);
		class_destroy(g_dev_class);
		g_dev_class = NULL;
	}
	if (g_cdev_ready) {
		cdev_del(&g_cdev);
		g_cdev_ready = false;
	}
err_region:
	unregister_chrdev_region(g_devt, 1);
err_hook:
	lyz_hook_remove(&g_reboot_hook);
	return ret;
}

static void __exit lyz_exit(void)
{
	/* 反查杀收尾（fops.owner 保证此时已无 fd，防御性清理并摘除断点） */
	mutex_lock(&g_prot_lock);
	lyz_protect_clear_locked();
	mutex_unlock(&g_prot_lock);

	lyz_bp_exit();
	lyz_input_exit();
	lyz_hide_exit();

	/* 兜底设备收尾（隐藏中说明 fd 已全部关闭，节点应已重建或直接清；
	 * nodev=1 时设备链从未创建，全跳过） */
	if (g_dev_class) {
		device_destroy(g_dev_class, g_devt);
		class_destroy(g_dev_class);
		g_dev_class = NULL;
	}
	if (g_cdev_ready) {
		cdev_del(&g_cdev);
		g_cdev_ready = false;
		unregister_chrdev_region(g_devt, 1);
	}

	/* 到这里说明模块可见（rmmod 能找到才进得来）；防御性再还一次 */
	lyz_module_unhide();

	lyz_hook_remove(&g_reboot_hook);
	pr_info("unloaded\n");
}

module_init(lyz_init);
module_exit(lyz_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lyz");
MODULE_DESCRIPTION("lyz_drv — TwT-ABI compatible arm64 R/W driver (kprobe based, "
		   LYZ_KERN_FAMILY_STR " family)");
MODULE_VERSION(LYZ_DRV_VERSION_STR);
