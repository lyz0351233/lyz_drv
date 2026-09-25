/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LYZ_VERSION_H
#define _LYZ_VERSION_H

/*
 * lyz_version.h — 版本真源（v1.5.0 起，全项目唯一改版本号的地方）
 *
 * 两层版本体系，对标商用驱动"按内核家族分发"的模式（KernelSU 同款）：
 *
 *   1. 驱动自身版本 LYZ_DRV_VERSION_* —— 我们的发布号，与内核无关。
 *      MAJOR：ABI 破坏性变更（TwT ABI 钉死，正常永远不动）
 *      MINOR：新功能（v1.5 = 家族体系 + BUILD.md + lyz_check.sh）
 *      PATCH：修 bug / 家族移植
 *      （不用 __DATE__/__TIME__ 打构建戳：树 Makefile:1110 开着
 *        -Werror=date-time，写了直接编译报错；构建区分靠版本号。）
 *
 *   2. 内核家族：GKI 基线版本。一部手机归属一个家族，一个家族一份 .ko。
 *      家族内 sublevel 差异（6.1.128 vs 6.1.176）由 KMI 吸收——
 *      MODVERSIONS 下 same_magic() 只比 vermagic 旗标段、版本 token 跳过
 *      （kernel/module/version.c），符号 CRC 由 KMI 世代冻结；
 *      家族之间 KMI 世代不同 → CRC 必不同 → 必须各用各的树各编各的。
 *
 *      家族     GKI 分支           状态
 *      5.10     android12-5.10     未适配（VMA 链表 / filldir64 旧语义）
 *      5.15     android13-5.15     未适配（同上）
 *      6.1      android14-6.1      当前实机目标（KMI 第 11 世代）
 *      6.6      android15-6.6      未适配（移植面小，重验为主）
 *      6.12     android16-6.12     未适配（移植面小，重验为主）
 *      6.18     尚无 GKI 基线      预留位
 *
 * 判断设备归属哪个家族看 `uname -r` 的内核版本（6.1.128-android14-11 →
 * 6.1 家族），**不要看 Android 版本号**——本机就是 Android 15 却跑
 * 6.1 内核的活例子。非 GKI 基线版本（6.2~6.5 等）会被下面的区间匹配
 * 拒绝，而不是错误地并进某个家族。
 *
 * 未适配家族在预处理期 #error 点名，移植完成后删除对应 #error。
 * 移植点清单与流程见 BUILD.md 附录A。
 */

/* ---------------- 驱动自身版本 ---------------- */
#define LYZ_DRV_NAME		"lyz_drv"
#define LYZ_DRV_VERSION_MAJOR	1
#define LYZ_DRV_VERSION_MINOR	5
#define LYZ_DRV_VERSION_PATCH	0
#define LYZ_DRV_VERSION_STR	"1.5.0"

/* ---------------- 内核家族探测（编译时） ---------------- */
#include <linux/version.h>

/* 精确家族区间匹配 [maj.min.0, maj.(min+1).0) */
#define LYZ_KERN_IS(maj, min)						\
	(LINUX_VERSION_CODE >= KERNEL_VERSION(maj, min, 0) &&		\
	 LINUX_VERSION_CODE <  KERNEL_VERSION(maj, (min) + 1, 0))

#if LYZ_KERN_IS(5, 10)
# define LYZ_KERN_5_10 1
#elif LYZ_KERN_IS(5, 15)
# define LYZ_KERN_5_15 1
#elif LYZ_KERN_IS(6, 1)
# define LYZ_KERN_6_1 1
#elif LYZ_KERN_IS(6, 6)
# define LYZ_KERN_6_6 1
#elif LYZ_KERN_IS(6, 12)
# define LYZ_KERN_6_12 1
#elif LYZ_KERN_IS(6, 18)
# define LYZ_KERN_6_18 1
#endif

#if defined(LYZ_KERN_6_1)
# define LYZ_KERN_FAMILY_SUPPORTED	1
# define LYZ_KERN_FAMILY_STR		"6.1"
# define LYZ_KERN_FAMILY_DESC		"android14-6.1 (KMI gen 11, on-device verified)"
#else
# define LYZ_KERN_FAMILY_SUPPORTED	0
# if defined(LYZ_KERN_5_10)
#  error "lyz_drv: 5.10 家族 (android12-5.10) 未适配。移植点见 BUILD.md 附录A：proc_info.c VMA 遍历改回 vm_next 链表、file_hide.c filldir64 按目标树重克隆、mem.c icache 接口。完成后删除本 #error。"
# elif defined(LYZ_KERN_5_15)
#  error "lyz_drv: 5.15 家族 (android13-5.15) 未适配。移植点见 BUILD.md 附录A：proc_info.c VMA 遍历改回 vm_next 链表、file_hide.c filldir64 按目标树重克隆、mem.c icache 接口。完成后删除本 #error。"
# elif defined(LYZ_KERN_6_6)
#  error "lyz_drv: 6.6 家族 (android15-6.6) 未适配。以 6.1 实现为基线逐项重验（VMA_ITERATOR/filldir64/icache 均沿用，重点核对结构体漂移与 KMI 符号），见 BUILD.md 附录A。完成后删除本 #error。"
# elif defined(LYZ_KERN_6_12)
#  error "lyz_drv: 6.12 家族 (android16-6.12) 未适配。以 6.1 实现为基线逐项重验，见 BUILD.md 附录A。完成移植后删除本 #error。"
# elif defined(LYZ_KERN_6_18)
#  error "lyz_drv: 6.18 尚无 Android GKI 基线（预留位）。有真实设备与 GKI 分支后再适配，流程见 BUILD.md 附录A。"
# else
#  error "lyz_drv: 不支持的内核版本（非 GKI 基线家族）。本驱动按家族分发：5.10 / 5.15 / 6.1 / 6.6 / 6.12 / 6.18，见 BUILD.md 附录A。"
# endif
#endif

/* 对外标识行：dmesg 加载横幅 / MODULE_DESCRIPTION 都用这串 */
#define LYZ_DRV_BANNER		LYZ_DRV_NAME " v" LYZ_DRV_VERSION_STR " (" LYZ_KERN_FAMILY_STR ")"

#endif /* _LYZ_VERSION_H */
