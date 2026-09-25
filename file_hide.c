// SPDX-License-Identifier: GPL-2.0
/*
 * file_hide.c — getdents64 目录项关键字过滤（FILE_HIDE_SET/CLEAR/STATUS）
 *
 * GKI 内核已删掉 set_fs，不能在内核里"借用"用户页直接写，所以这里完整
 * 复刻 6.1 fs/readdir.c 的 getdents64（fdget_pos + iterate_dir + 自定义
 * filldir64），在 filldir 回调里对文件名做 strnstr 关键字过滤。
 * 过滤是全局的：所有进程遍历该目录都会被过滤（R3 测试正是在自身
 * 进程里验证 directory_contains）。
 *
 * 克隆保真度（对照 6.1.176 fs/readdir.c 逐行）：
 *   - filldir64 返回 bool，verify_dirent_name 名字合法性检查
 *   - prev_reclen 机制：每条记录写完重写"上一条"的 d_off，
 *     信号 pending 时提前截断，尾部条目 d_off 由 syscall 侧修补
 *   - 放不下第一条时返回 -EINVAL（老内核语义在这里会错误地返回 0=EOF，
 *     导致用户态以为目录结束而丢条目）
 *   - 名字命中关键字 → 直接 return true（不写、不推进游标、不动
 *     prev_reclen，相当于该条目不存在）
 */
#define pr_fmt(fmt) "lyz_drv: " fmt	/* 必须在所有 include 之前（printk.h 是 #ifndef pr_fmt 保护） */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/dirent.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/kprobes.h>
#include <asm/ptrace.h>

#include "lyz_drv.h"
#include "abi.h"

/* fdget_pos/fdput_pos 的底层 __fdget_pos/__f_unlock_pos 没进 GKI KMI 导出
 * 表——照 fs/file.c 的 __fdget_pos 原样克隆（含 file_needs_f_pos_lock 的
 * 目录锁条件），底座换成已导出的 __fdget */
static struct fd lyz_fdget_pos(unsigned int fd)
{
	unsigned long v = __fdget(fd);
	struct file *file = (struct file *)(v & ~3);

	if (file && (file->f_mode & FMODE_ATOMIC_POS) &&
	    (file_count(file) > 1 || S_ISDIR(file_inode(file)->i_mode))) {
		v |= FDPUT_POS_UNLOCK;
		mutex_lock(&file->f_pos_lock);
	}
	return __to_fd(v);
}

static void lyz_fdput_pos(struct fd f)
{
	if (f.flags & FDPUT_POS_UNLOCK)
		mutex_unlock(&f.file->f_pos_lock);
	fdput(f);
}

struct lyz_hide_state {
	spinlock_t lock;
	bool valid;	/* dir 路径已解析 */
	bool active;	/* 正在过滤 */
	struct path dir;
	char keyword[TWT_FILE_HIDE_KEYWORD_MAX];
	char directory[TWT_FILE_HIDE_DIRECTORY_MAX];
};

static struct lyz_hide_state g_hide = {
	.lock = __SPIN_LOCK_UNLOCKED(g_hide.lock),
};

static atomic_t g_getdents_inflight = ATOMIC_INIT(0);

struct lyz_dir_buf {
	struct dir_context ctx;
	struct linux_dirent64 __user *current_dir;
	int prev_reclen;
	int count;
	int error;
	char kw[TWT_FILE_HIDE_KEYWORD_MAX];
};

/* ---------------- filldir64 克隆（含关键字过滤） ---------------- */

static int lyz_verify_name(const char *name, int len)
{
	if (len <= 0 || len >= PATH_MAX)
		return -EIO;
	if (memchr(name, '/', len))
		return -EIO;
	return 0;
}

static bool lyz_filldir64(struct dir_context *ctx, const char *name,
			  int namlen, loff_t offset, u64 ino,
			  unsigned int d_type)
{
	struct lyz_dir_buf *buf =
		container_of(ctx, struct lyz_dir_buf, ctx);
	struct linux_dirent64 __user *dirent, *prev;
	int reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + namlen + 1,
			   sizeof(u64));
	int prev_reclen;

	/* 命中关键字 → 隐藏：不写、不推进游标，继续迭代下一条 */
	if (buf->kw[0] && strnstr(name, buf->kw, namlen))
		return true;

	buf->error = lyz_verify_name(name, namlen);
	if (unlikely(buf->error))
		return false;
	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > buf->count)
		return false;
	prev_reclen = buf->prev_reclen;
	if (prev_reclen && signal_pending(current))
		return false;
	dirent = buf->current_dir;
	prev = (void __user *)dirent - prev_reclen;
	if (!user_write_access_begin(prev, reclen + prev_reclen))
		goto efault;

	/* This might be 'dirent->d_off', but if so it will get overwritten */
	unsafe_put_user(offset, &prev->d_off, efault_end);
	unsafe_put_user(ino, &dirent->d_ino, efault_end);
	unsafe_put_user(reclen, &dirent->d_reclen, efault_end);
	unsafe_put_user(d_type, &dirent->d_type, efault_end);
	unsafe_copy_to_user(dirent->d_name, name, namlen, efault_end);
	unsafe_put_user(0, dirent->d_name + namlen, efault_end);
	user_write_access_end();

	buf->prev_reclen = reclen;
	buf->current_dir = (void __user *)dirent + reclen;
	buf->count -= reclen;
	return true;

efault_end:
	user_write_access_end();
efault:
	buf->error = -EFAULT;
	return false;
}

/* ---------------- getdents64 替换函数 ---------------- */

/* kprobe pre_handler 调用（调试异常上下文，禁睡眠）：无锁原子读 */
static bool lyz_hide_intercept(const struct pt_regs *sregs)
{
	return READ_ONCE(g_hide.valid) && READ_ONCE(g_hide.active);
}

static long lyz_getdents_body(const struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];
	struct linux_dirent64 __user *dirent =
		(struct linux_dirent64 __user *)regs->regs[1];
	unsigned int count = (unsigned int)regs->regs[2];
	struct lyz_dir_buf buf = {
		.ctx.actor = lyz_filldir64,
		.current_dir = dirent,
		.count = count,
	};
	struct path snap;
	bool filter = false;
	char kw[TWT_FILE_HIDE_KEYWORD_MAX] = "";
	unsigned long flags;
	struct fd f;
	int error;

	/* 快照目标目录 + 关键字（锁内拿引用，锁外慢操作） */
	spin_lock_irqsave(&g_hide.lock, flags);
	if (g_hide.valid && g_hide.active) {
		path_get(&g_hide.dir);	/* 防并发 clear 释放 */
		snap = g_hide.dir;
		strscpy(kw, g_hide.keyword, sizeof(kw));
		filter = true;
	}
	spin_unlock_irqrestore(&g_hide.lock, flags);

	f = lyz_fdget_pos(fd);
	if (!f.file)
		return -EBADF;

	/* fd 指向的目录不匹配 → 关键字置空 = 直通（行为同真实 syscall） */
	if (filter && (f.file->f_path.dentry != snap.dentry ||
		       f.file->f_path.mnt != snap.mnt))
		kw[0] = '\0';
	if (kw[0])
		strscpy(buf.kw, kw, sizeof(buf.kw));

	error = iterate_dir(f.file, &buf.ctx);
	if (error >= 0)
		error = buf.error;
	if (buf.prev_reclen) {
		struct linux_dirent64 __user *lastdirent;
		typeof(lastdirent->d_off) d_off = buf.ctx.pos;

		lastdirent = (void __user *)buf.current_dir - buf.prev_reclen;
		if (put_user(d_off, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.count;
	}
	lyz_fdput_pos(f);

	if (filter)
		path_put(&snap);
	return error;
}

static asmlinkage long lyz_getdents_repl(const struct pt_regs *regs)
{
	long ret;

	atomic_inc(&g_getdents_inflight);
	ret = lyz_getdents_body(regs);
	atomic_dec(&g_getdents_inflight);
	return ret;
}
NOKPROBE_SYMBOL(lyz_getdents_repl);

static struct lyz_hook g_getdents_hook = {
	.name = "__arm64_sys_getdents64",
	.intercept = lyz_hide_intercept,
	.replacement = (void *)lyz_getdents_repl,
	.inflight = &g_getdents_inflight,
};

/* ---------------- ioctl 处理 ---------------- */

long lyz_hide_ioctl_set(unsigned long arg)
{
	struct twt_file_hide_config cfg;
	struct path path, old;
	bool had_old = false;
	unsigned long flags;

	if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg)))
		return -EFAULT;
	cfg.keyword[sizeof(cfg.keyword) - 1] = '\0';
	cfg.directory[sizeof(cfg.directory) - 1] = '\0';
	if (!cfg.keyword[0] || !cfg.directory[0])
		return -EINVAL;

	if (kern_path(cfg.directory, LOOKUP_DIRECTORY, &path))
		return -ENOENT;

	spin_lock_irqsave(&g_hide.lock, flags);
	if (g_hide.valid) {
		old = g_hide.dir;
		had_old = true;
	}
	g_hide.dir = path;
	g_hide.valid = true;
	g_hide.active = !!cfg.enabled;
	strscpy(g_hide.keyword, cfg.keyword, sizeof(g_hide.keyword));
	strscpy(g_hide.directory, cfg.directory, sizeof(g_hide.directory));
	spin_unlock_irqrestore(&g_hide.lock, flags);

	/* path_put 可能睡眠，必须在锁外 */
	if (had_old)
		path_put(&old);
	return 0;
}

long lyz_hide_ioctl_clear(void)
{
	struct path old;
	bool had_old = false;
	unsigned long flags;

	spin_lock_irqsave(&g_hide.lock, flags);
	if (g_hide.valid) {
		old = g_hide.dir;
		had_old = true;
	}
	g_hide.valid = false;
	g_hide.active = false;
	g_hide.keyword[0] = '\0';
	g_hide.directory[0] = '\0';
	spin_unlock_irqrestore(&g_hide.lock, flags);

	if (had_old)
		path_put(&old);
	return 0;
}

long lyz_hide_ioctl_status(unsigned long arg)
{
	struct twt_file_hide_status st;
	unsigned long flags;

	memset(&st, 0, sizeof(st));

	spin_lock_irqsave(&g_hide.lock, flags);
	st.enabled = g_hide.active;
	st.hook_active = g_hide.valid && g_hide.active;
	strscpy(st.directory, g_hide.directory, sizeof(st.directory));
	strscpy(st.keyword, g_hide.keyword, sizeof(st.keyword));
	spin_unlock_irqrestore(&g_hide.lock, flags);

	if (copy_to_user((void __user *)arg, &st, sizeof(st)))
		return -EFAULT;
	return 0;
}

/* ---------------- 初始化 / 退出 ---------------- */

int lyz_hide_init(void)
{
	return lyz_hook_install(&g_getdents_hook);
}

void lyz_hide_exit(void)
{
	/* 先关状态（intercept 立刻开始返回假），再摘钩子、排空在飞流 */
	lyz_hide_ioctl_clear();
	lyz_hook_remove(&g_getdents_hook);
}
