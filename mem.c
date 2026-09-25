// SPDX-License-Identifier: GPL-2.0
/*
 * mem.c — 跨进程内存读写（READ_MEM / READ_MEM_V2 / WRITE_MEM）
 *
 * v1: access_process_vm（内核标准远程内存接口，内部走 GUP，能处理
 *     缺页、COW、zRAM 换入；写只读私有页走 FOLL_FORCE 强制 COW，语义同 ptrace）
 * v2: 手工四级页表 walk + linear map 直访物理页（零缺页、零副作用，
 *     读被暂停/被 ptrace 的进程最稳；目标页已被换出时返回失败，R3 应回退 v1）
 *     目标 mm 由 fd 级缓存 pin 住（struct lyz_fd_ctx，吸收自 km_read 的
 *     热路径缓存思路并重构为 fd 私有），同 fd 同 pid 的热路径零原子操作。
 *
 * v2 写的语义是"物理写"：绕过 COW 直接改物理页、不置脏位（无痕）。
 * 但文件页/共享页直写会污染页缓存——改动对所有映射同一文件的进程可
 * 见，且回收不落盘即丢。因此 v2 写只接受匿名页（PageAnon 门禁，见
 * lyz_rw_v2），文件/共享页返回 -EOPNOTSUPP，R3 回退 v1（FOLL_FORCE 走
 * COW，ptrace 语义）即可拿到安全且正确的结果。
 */
#define pr_fmt(fmt) "lyz_drv: " fmt	/* 必须在所有 include 之前（printk.h 是 #ifndef pr_fmt 保护） */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <asm/pgtable.h>
#include <asm/memory.h>
#include <asm/cacheflush.h>

#include "lyz_drv.h"

#define LYZ_MAX_CHUNK SZ_1M

/* 写完目标页后失效 I-cache：arm64 的 D-cache 与 I-cache 不一致，
 * 内核别名写入后用户态执行前必须 icache invalidate（同时顺带 clean D-cache）。
 * icache_inval_pou(5.18+) 与 __flush_icache_range(老家族) 都没进 GKI KMI
 * 导出表——kln 解析直调（fh.c 既有架构），先试新名再回退老名 */
static void (*g_icache_flush)(unsigned long, unsigned long);

static void lyz_flush_code(unsigned long p, unsigned long s)
{
	if (!g_icache_flush) {
		g_icache_flush = (void *)lyz_kln("icache_inval_pou");
		if (!g_icache_flush)
			g_icache_flush = (void *)lyz_kln("__flush_icache_range");
	}
	if (g_icache_flush)
		g_icache_flush(p, p + s);
}

#define LYZ_FLUSH_CODE(p, s) \
	lyz_flush_code((unsigned long)(p), (unsigned long)(s))

/* 通过 vpid 找 task 并加引用，返回 NULL 表示不存在。调用者负责 put_task_struct */
struct task_struct *lyz_get_task(int pid)
{
	struct task_struct *task;

	if (pid <= 0)
		return NULL;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();
	return task;
}

/* ---------------- v1: access_process_vm ---------------- */

static long lyz_rw_v1(struct task_struct *task, u64 addr,
		      void __user *ubuf, u64 size, bool write)
{
	void *kbuf;
	u64 chunk_cap;
	u64 done = 0;
	long ret = 0;

	/* 大块连续物理页在碎片化机器上可能拿不到，逐级降级 */
	kbuf = kmalloc(LYZ_MAX_CHUNK, GFP_KERNEL | __GFP_NOWARN);
	chunk_cap = LYZ_MAX_CHUNK;
	if (!kbuf) {
		kbuf = kmalloc(SZ_256K, GFP_KERNEL | __GFP_NOWARN);
		chunk_cap = SZ_256K;
	}
	if (!kbuf) {
		kbuf = kmalloc(SZ_64K, GFP_KERNEL);
		chunk_cap = SZ_64K;
	}
	if (!kbuf)
		return -ENOMEM;

	while (done < size) {
		u64 chunk = min_t(u64, size - done, chunk_cap);
		long n;

		if (write) {
			if (copy_from_user(kbuf, (u8 __user *)ubuf + done,
					   chunk)) {
				ret = -EFAULT;
				break;
			}
			n = access_process_vm(task, addr + done, kbuf,
					      (int)chunk,
					      FOLL_FORCE | FOLL_WRITE);
		} else {
			n = access_process_vm(task, addr + done, kbuf,
					      (int)chunk, FOLL_FORCE);
			if (n > 0 &&
			    copy_to_user((u8 __user *)ubuf + done, kbuf, n)) {
				ret = -EFAULT;
				break;
			}
		}

		if (n <= 0) {
			/* 首块就失败 → 真错误；中途失败 → 部分成功 */
			if (!done)
				ret = (n < 0) ? n : -EFAULT;
			break;
		}
		done += n;
		if (n < chunk)
			break;	/* 遇到不可映射边界 */
	}

	kfree(kbuf);
	return ret ? ret : (long)done;
}

/* ---------------- v2: 手工页表 walk + fd 级 mm 缓存 ---------------- */

/*
 * 解析一个虚拟地址：输出物理地址 + 从该地址起连续可直访的长度。
 * 全程只读页表（调用方持 mmap_read_lock），不触发缺页。
 *
 * leaf 判断用 arm64 描述符类型位（PMD_TYPE_SECT / PUD_TYPE_SECT），
 * 不用 pmd_leaf()/pud_leaf()：后者是 5.10 之后才逐步引入的，
 * 位判断在 5.10/5.15/6.1 上行为完全一致。
 */
static int lyz_walk_one(struct mm_struct *mm, u64 addr,
			u64 *paddr, u64 *plen)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return -EFAULT;

	p4d = p4d_offset(pgd, addr);	/* arm64 折叠层，恒为合法 */
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return -EFAULT;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return -EFAULT;
	if ((pud_val(*pud) & PUD_TYPE_MASK) == PUD_TYPE_SECT) {
		/* 1GB 大页（PUD section） */
		u64 off = addr & (PUD_SIZE - 1);

		*paddr = ((pud_val(*pud) & PHYS_MASK) & PUD_MASK) + off;
		*plen = PUD_SIZE - off;
		return 0;
	}
	if (pud_bad(*pud))
		return -EFAULT;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return -EFAULT;
	if ((pmd_val(*pmd) & PMD_TYPE_MASK) == PMD_TYPE_SECT) {
		/* 2MB 大页（PMD section，THP/hugetlb） */
		u64 off = addr & (PMD_SIZE - 1);

		*paddr = ((pmd_val(*pmd) & PHYS_MASK) & PMD_MASK) + off;
		*plen = PMD_SIZE - off;
		return 0;
	}
	if (pmd_bad(*pmd))
		return -EFAULT;

	pte = pte_offset_kernel(pmd, addr);
	if (!pte_present(*pte))
		return -EFAULT;	/* 已换出（zRAM）或不存在 → 回退 v1 */

	*paddr = ((pte_val(*pte) & PHYS_MASK) & PAGE_MASK) +
		 (addr & (PAGE_SIZE - 1));
	*plen = PAGE_SIZE - (addr & (PAGE_SIZE - 1));
	return 0;
}

/*
 * 取目标 mm：fd 缓存命中直接用（引用归 ctx，调用方不放），未命中在
 * 锁内解析 task 并换 pin。返回 NULL = pid 不存在或无地址空间。
 *
 * 热路径（同 fd 同 pid）完全无锁——多线程并发读同一目标安全；
 * 换目标仅在同一 fd 被并发喂不同 pid 时才会与在飞读者竞争，该用法
 * 不支持（见 lyz_fd_ctx 注释：km_read 的全局缓存支持它，代价是 UAF）。
 */
static struct mm_struct *lyz_v2_mm(struct lyz_fd_ctx *ctx, int pid)
{
	struct mm_struct *mm;

	/* 快路径：同 fd 同 pid —— 零原子操作、零 pid 解析 */
	mm = READ_ONCE(ctx->mm);
	if (mm && READ_ONCE(ctx->pid) == pid)
		return mm;

	mutex_lock(&ctx->lock);
	/* 双检：另一线程可能刚在锁内换好 */
	mm = READ_ONCE(ctx->mm);
	if (!mm || READ_ONCE(ctx->pid) != pid) {
		struct task_struct *task = lyz_get_task(pid);
		struct mm_struct *newmm = NULL;

		if (task) {
			newmm = get_task_mm(task);
			put_task_struct(task);
		}
		if (newmm) {
			/* 先放旧 pin 再上架新的；旧 mm 的在飞读者语义见头注释 */
			if (ctx->mm)
				mmput(ctx->mm);
			WRITE_ONCE(ctx->mm, newmm);
			WRITE_ONCE(ctx->pid, pid);
			mm = newmm;
		} else {
			mm = NULL;
		}
	}
	mutex_unlock(&ctx->lock);
	return mm;
}

/* fd 关闭：放掉缓存的 mm pin（main.c 的 release 调用） */
void lyz_mm_cache_drop(struct lyz_fd_ctx *ctx)
{
	mutex_lock(&ctx->lock);
	if (ctx->mm) {
		mmput(ctx->mm);
		ctx->mm = NULL;
	}
	ctx->pid = 0;
	mutex_unlock(&ctx->lock);
}

static long lyz_rw_v2(struct lyz_fd_ctx *ctx, int pid, u64 addr,
		      void __user *ubuf, u64 size, bool write)
{
	struct mm_struct *mm;
	bool per_call_pin = false;	/* ctx 缺失的降级路径才逐次 pin */
	u64 done = 0;
	long ret = 0;

	/* MTE 标签防御性剥离（位 63:56）：硬件翻译本就忽略该字节（TBI），
	 * 剥掉让地址运算与硬件行为一致（吸收自 km_read） */
	addr &= 0x00FFFFFFFFFFFFFFULL;

	if (ctx) {
		mm = lyz_v2_mm(ctx, pid);
		if (!mm)
			return -ESRCH;
	} else {
		/* ctx 分配失败的降级：与无缓存版本行为一致，每次现解析 */
		struct task_struct *task = lyz_get_task(pid);

		if (!task)
			return -ESRCH;
		mm = get_task_mm(task);
		put_task_struct(task);
		if (!mm)
			return -ESRCH;
		per_call_pin = true;
	}

	mmap_read_lock(mm);
	while (done < size) {
		u64 paddr, plen, chunk;
		void *kv;

		if (lyz_walk_one(mm, addr + done, &paddr, &plen)) {
			if (!done)
				ret = -EFAULT;
			break;
		}

		/* 只接受正常 RAM 页，防止 phys_to_virt 踩到 IO 区 */
		if (!pfn_valid(paddr >> PAGE_SHIFT)) {
			if (!done)
				ret = -EFAULT;
			break;
		}

		if (write) {
			/* 物理写只允许匿名页：文件页/共享页（含 shmem）直写会
			 * 污染页缓存——改动对所有映射该文件的进程可见，且回收
			 * 即丢。compound_head 兼容 THP 大页（尾页 PageAnon 会
			 * 误读 compound_head 字段，必须先归一到头页）。
			 * 拒绝 → R3 回退 v1（FOLL_FORCE 走 COW，ptrace 语义）*/
			struct page *page =
				compound_head(pfn_to_page(paddr >> PAGE_SHIFT));

			if (!PageAnon(page)) {
				if (!done)
					ret = -EOPNOTSUPP;
				break;
			}
		}

		chunk = min_t(u64, size - done, plen);
		kv = phys_to_virt(paddr);

		if (write) {
			if (copy_from_user(kv, (u8 __user *)ubuf + done,
					   chunk)) {
				ret = -EFAULT;
				break;
			}
			LYZ_FLUSH_CODE(kv, chunk);
		} else {
			if (copy_to_user((u8 __user *)ubuf + done, kv,
					 chunk)) {
				ret = -EFAULT;
				break;
			}
		}
		done += chunk;
	}
	mmap_read_unlock(mm);

	if (per_call_pin)
		mmput(mm);	/* fd 缓存路径的引用归 ctx，不放 */
	return ret ? ret : (long)done;
}

/* ---------------- ioctl 入口 ---------------- */

long lyz_read_mem(struct file *file, struct twt_request *req, bool v2)
{
	long ret;

	if (!req->buffer || !req->size)
		return -EINVAL;

	if (v2) {
		/* v2 走 fd 级 mm 缓存，pid 解析只在缓存未命中时做 */
		ret = lyz_rw_v2(file->private_data, req->pid, req->addr,
				(void __user *)(unsigned long)req->buffer,
				req->size, false);
	} else {
		struct task_struct *task = lyz_get_task(req->pid);

		if (!task)
			return -ESRCH;
		ret = lyz_rw_v1(task, req->addr,
				(void __user *)(unsigned long)req->buffer,
				req->size, false);
		put_task_struct(task);
	}

	/* R3 语义：整块读满才算成功 */
	if (ret == (long)req->size)
		return 0;
	return (ret < 0) ? ret : -EFAULT;
}

long lyz_write_mem(struct file *file, struct twt_request *req, bool v2)
{
	long ret;

	if (!req->buffer || !req->size)
		return -EINVAL;

	if (v2) {
		ret = lyz_rw_v2(file->private_data, req->pid, req->addr,
				(void __user *)(unsigned long)req->buffer,
				req->size, true);
	} else {
		struct task_struct *task = lyz_get_task(req->pid);

		if (!task)
			return -ESRCH;
		ret = lyz_rw_v1(task, req->addr,
				(void __user *)(unsigned long)req->buffer,
				req->size, true);
		put_task_struct(task);
	}

	if (ret == (long)req->size)
		return 0;
	return (ret < 0) ? ret : -EFAULT;
}
