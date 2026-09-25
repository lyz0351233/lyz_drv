/* lyz_drv.h — 内部函数声明 */
#ifndef LYZ_DRV_H
#define LYZ_DRV_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/mutex.h>
#include <linux/kprobes.h>

#include "abi.h"
#include "lyz_version.h"	/* 版本真源：驱动版本 + 内核家族宏（全体 .c 生效） */

/* main.c 定义（模块参数 quiet=1 时为真）：静默信息级 dmesg 输出。
 * dmesg 里的模块名 / hook 地址 / anon 名是最廉价的取证指纹；
 * 错误（pr_err/pr_warn）不受影响，永远打印。 */
extern bool lyz_quiet;
#define lyz_info(fmt, ...) \
	do { if (!lyz_quiet) pr_info(fmt, ##__VA_ARGS__); } while (0)

/*
 * kprobe 劫持描述符：
 *   name        目标符号（__arm64_sys_* 包装函数）
 *   intercept   无锁快速判断（调试异常上下文，禁睡眠），真 = 重定向
 *   replacement 替换函数（正常内核 C 上下文，可睡眠），签名须与目标一致
 *               （__arm64_sys_* 系 = asmlinkage long (const struct pt_regs *)）
 *   inflight    在飞替换函数计数，卸载时排空防 UAF
 *   kp          kprobe 注册块
 */
struct lyz_hook {
	const char *name;
	bool (*intercept)(const struct pt_regs *sregs);
	void *replacement;
	atomic_t *inflight;
	struct kprobe kp;
};

/* fh.c */
int  lyz_setup_kallsyms(void);
unsigned long lyz_kln(const char *name);
int  lyz_hook_install(struct lyz_hook *hook);
void lyz_hook_remove(struct lyz_hook *hook);

/* mem.c */
struct task_struct *lyz_get_task(int pid);

/*
 * fd 级目标缓存（吸收自 km_read 的"pid→mm 缓存"思路，重构为 fd 私有）：
 * TwT 风格 R3 一帧会对同一进程发上百次小读取，每次 v2 都走
 * find_task_by_vpid → get_task_mm 全链太浪费。每个 fd 首次 v2 访问某
 * pid 时 pin 住它的 mm（get_task_mm 加引用），此后热路径零原子操作、
 * 零 pid 解析；换目标在锁内换 pin；fd 关闭时放引用。
 *
 * 生命周期语义（如实记录）：pin 的 mm 在目标进程退出后不释放
 * （exit_mmap 要等 mm_users 归零才拆页表），读"尸体"内存反而可行，
 * 代价是死进程地址空间滞留。同 fd 多线程并发读同一 pid 安全；
 * 并发换不同 pid 不支持（km_read 的全局缓存支持该模式，但那正是
 * 它释放竞态 UAF 的来源——快路径无锁抓 pgd，与换目标线程的
 * mmput 竞争，pgd 可能已进伙伴系统）。
 */
struct lyz_fd_ctx {
	struct mm_struct *mm;	/* pin 的目标 mm；NULL = 未缓存 */
	int pid;		/* mm 对应的 pid */
	bool is_cdev;		/* true = 兜底 cdev fd（open 需销毁设备节点） */
	struct mutex lock;	/* 仅保护缓存切换，热路径无锁 */
};

void lyz_mm_cache_drop(struct lyz_fd_ctx *ctx);	/* fd 关闭时放掉 pin */
long lyz_read_mem(struct file *file, struct twt_request *req, bool v2);
long lyz_write_mem(struct file *file, struct twt_request *req, bool v2);

/* proc_info.c */
long lyz_get_pid(struct twt_request *req);
long lyz_module_base(struct twt_request *req, bool bss);
long lyz_get_thread_tls(struct twt_tls_request *req);
long lyz_exec_pacga(struct twt_pacga_request *req);

/* file_hide.c */
int  lyz_hide_init(void);
void lyz_hide_exit(void);
long lyz_hide_ioctl_set(unsigned long arg);
long lyz_hide_ioctl_clear(void);
long lyz_hide_ioctl_status(unsigned long arg);

/* input_inject.c */
int  lyz_input_init(void);
void lyz_input_exit(void);
int  lyz_touch_init(int *mode);      /* 成功 0；已初始化 -EALREADY 并回写当前模式 */
int  lyz_touch_down(int slot, int x, int y);
int  lyz_touch_up(int slot);
int  lyz_gyro_init(int *method);     /* 成功 0；已初始化 -EALREADY 并回写当前模式 */
int  lyz_gyro_modify(u32 enable, u32 xbits, u32 ybits);

/* hwbp.c */
int  lyz_bp_init(void);
void lyz_bp_exit(void);
long lyz_bp_ioctl(unsigned int nr, unsigned long arg);

/* main.c 导出（替换函数绑定 fd 用） */
extern const struct file_operations lyz_fops;

#endif /* LYZ_DRV_H */
