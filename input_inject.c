// SPDX-License-Identifier: GPL-2.0
/*
 * input_inject.c — 触摸 / 陀螺仪注入（TOUCH_INIT/DOWN/UP, GYRO_INIT/CONFIG）
 *
 * 原理：经 kallsyms 拿到内核全局 input_dev_list 和 input_mutex
 * （drivers/input/input.c 的注释原文："input_mutex protects access to both
 * input_dev_list and input_handler_list"），持锁遍历按能力位挑选真实
 * 触摸屏 / 陀螺仪设备，直接调用 input_report_abs/input_sync 注入事件。
 * 引用在锁内拿（input_get_device），杜绝"遍历到一半设备被注销"的 UAF。
 *
 * 触摸协议：设备支持 ABS_MT_SLOT → 协议 B（slot + tracking id），
 *           否则 → 协议 A（input_mt_sync）。
 * 陀螺仪：内核禁用浮点单元，float→int 用纯位运算软件转换（×1000 定点）。
 *
 * 设备挑选是启发式的，不同机型可能需要调整 find_touch_dev /
 * find_gyro_dev 的匹配条件（cat /proc/bus/input/devices 看名字）。
 */
#define pr_fmt(fmt) "lyz_drv: " fmt	/* 必须在所有 include 之前（printk.h 是 #ifndef pr_fmt 保护） */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/input.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/slab.h>

#include "lyz_drv.h"
#include "abi.h"

#define LYZ_MAX_SLOTS 16

/* 内核没有 INT_MAX/INT_MIN，自己定义 */
#define LYZ_INT_MAX  2147483647
#define LYZ_INT_MIN  (-LYZ_INT_MAX - 1)

static struct list_head *g_input_dev_list;
static struct mutex *g_input_mutex;

static struct input_dev *g_touch_dev;
static int g_touch_mode;
static int g_tracking_id[LYZ_MAX_SLOTS];

static struct input_dev *g_gyro_dev;
static int g_gyro_method;

int lyz_input_init(void)
{
	g_input_dev_list = (struct list_head *)lyz_kln("input_dev_list");
	g_input_mutex = (struct mutex *)lyz_kln("input_mutex");
	if (!g_input_dev_list || !g_input_mutex) {
		pr_err("input_dev_list/input_mutex 未找到，触摸/陀螺仪功能不可用\n");
		g_input_dev_list = NULL;
		g_input_mutex = NULL;
		return -ENOENT;
	}
	pr_info("input_dev_list @ 0x%lx, input_mutex @ 0x%lx\n",
		(unsigned long)g_input_dev_list, (unsigned long)g_input_mutex);
	return 0;
}

void lyz_input_exit(void)
{
	if (g_touch_dev) {
		input_put_device(g_touch_dev);
		g_touch_dev = NULL;
	}
	if (g_gyro_dev) {
		input_put_device(g_gyro_dev);
		g_gyro_dev = NULL;
	}
}

/* ---------------- 设备挑选（全程持 input_mutex，锁内拿引用） ---------------- */

static struct input_dev *find_touch_dev(int mode)
{
	struct input_dev *dev, *hit = NULL;

	mutex_lock(g_input_mutex);
	list_for_each_entry(dev, g_input_dev_list, node) {
		if (!test_bit(EV_ABS, dev->evbit))
			continue;
		if (!test_bit(ABS_MT_POSITION_X, dev->absbit))
			continue;
		/* mode 0: 严格（协议B真触摸屏）；mode 1: 宽松 */
		if (mode == 0 && !test_bit(BTN_TOUCH, dev->keybit))
			continue;
		/* 多候选时优先打开计数大的（正在被使用的真实触屏） */
		if (!hit || dev->users > hit->users)
			hit = dev;
	}
	if (hit)
		input_get_device(hit);
	mutex_unlock(g_input_mutex);
	return hit;
}

static struct input_dev *find_gyro_dev(int method)
{
	struct input_dev *dev, *by_name = NULL, *by_axes = NULL, *hit;

	mutex_lock(g_input_mutex);
	list_for_each_entry(dev, g_input_dev_list, node) {
		if (method == 0 && dev->name) {
			size_t nlen = strlen(dev->name);

			if (strnstr(dev->name, "gyro", nlen) ||
			    strnstr(dev->name, "Gyro", nlen)) {
				if (!by_name || dev->users > by_name->users)
					by_name = dev;
			}
		}
		/* 方式1：按 ABS_RX/ABS_RY 轴能力兜底匹配 */
		if (test_bit(EV_ABS, dev->evbit) &&
		    test_bit(ABS_RX, dev->absbit) &&
		    test_bit(ABS_RY, dev->absbit)) {
			if (!by_axes || dev->users > by_axes->users)
				by_axes = dev;
		}
	}
	hit = (method == 0) ? (by_name ? by_name : by_axes)
			    : (by_axes ? by_axes : by_name);
	if (hit)
		input_get_device(hit);
	mutex_unlock(g_input_mutex);
	return hit;
}

static bool touch_is_type_b(struct input_dev *dev)
{
	return test_bit(ABS_MT_SLOT, dev->absbit);
}

/* ---------------- 触摸 ---------------- */

int lyz_touch_init(int *mode)
{
	int m = *mode;
	struct input_dev *dev;

	if (m < 0 || m > 1)
		return -EINVAL;

	if (g_touch_dev) {
		*mode = g_touch_mode;	/* 回写当前模式供 R3 打印 */
		return -EALREADY;
	}

	dev = find_touch_dev(m);
	if (!dev)
		return -ENODEV;

	g_touch_dev = dev;
	g_touch_mode = m;
	memset(g_tracking_id, 0, sizeof(g_tracking_id));
	pr_info("touch dev: '%s' (mode %d, %s)\n",
		dev->name ? dev->name : "?", m,
		touch_is_type_b(dev) ? "协议B" : "协议A");
	return 0;
}

int lyz_touch_down(int slot, int x, int y)
{
	struct input_dev *dev = g_touch_dev;

	if (!dev)
		return -ENODEV;
	if (slot < 0 || slot >= LYZ_MAX_SLOTS)
		return -EINVAL;

	if (touch_is_type_b(dev)) {
		input_report_abs(dev, ABS_MT_SLOT, slot);
		g_tracking_id[slot]++;
		input_report_abs(dev, ABS_MT_TRACKING_ID, g_tracking_id[slot]);
		input_report_abs(dev, ABS_MT_POSITION_X, x);
		input_report_abs(dev, ABS_MT_POSITION_Y, y);
		input_report_abs(dev, ABS_MT_TOUCH_MAJOR, 0x30);
		if (test_bit(BTN_TOUCH, dev->keybit))
			input_report_key(dev, BTN_TOUCH, 1);
		input_sync(dev);
	} else {
		/* 协议 A：无 slot 概念，input_mt_sync 分隔触点 */
		input_report_abs(dev, ABS_MT_POSITION_X, x);
		input_report_abs(dev, ABS_MT_POSITION_Y, y);
		input_report_abs(dev, ABS_MT_TOUCH_MAJOR, 0x30);
		input_mt_sync(dev);
		if (test_bit(BTN_TOUCH, dev->keybit))
			input_report_key(dev, BTN_TOUCH, 1);
		input_sync(dev);
	}
	return 0;
}

int lyz_touch_up(int slot)
{
	struct input_dev *dev = g_touch_dev;

	if (!dev)
		return -ENODEV;
	if (slot < 0 || slot >= LYZ_MAX_SLOTS)
		return -EINVAL;

	if (touch_is_type_b(dev)) {
		input_report_abs(dev, ABS_MT_SLOT, slot);
		input_report_abs(dev, ABS_MT_TRACKING_ID, -1);
		if (test_bit(BTN_TOUCH, dev->keybit))
			input_report_key(dev, BTN_TOUCH, 0);
		input_sync(dev);
	} else {
		input_mt_sync(dev);
		if (test_bit(BTN_TOUCH, dev->keybit))
			input_report_key(dev, BTN_TOUCH, 0);
		input_sync(dev);
	}
	return 0;
}

/* ---------------- 陀螺仪 ---------------- */

/*
 * IEEE754 float 位模式 → round(value × 1000) 的纯整数实现。
 * arm64 内核以 -mgeneral-regs-only 编译，源码里禁用浮点运算。
 */
static int lyz_float_bits_x1000(u32 bits)
{
	u32 exp_field = (bits >> 23) & 0xff;
	u64 m;
	int e, sh;
	bool neg = (bits >> 31) != 0;
	u64 v;

	if (exp_field == 0xff || exp_field == 0)
		return 0;	/* NaN/Inf/0/denormal 一律按 0 处理 */

	/* value = (1.m) × 2^(exp-127) = man × 2^(exp-127-23) */
	m = ((u64)(bits & 0x7fffff) | (1ULL << 23)) * 1000ULL;
	e = (int)exp_field - 127 - 23;

	if (e >= 0) {
		if (e > 40)
			return neg ? LYZ_INT_MIN : LYZ_INT_MAX;
		v = m << e;
	} else {
		sh = -e;
		if (sh >= 64)
			return 0;
		v = (m >> sh) | ((m >> (sh - 1)) & 1);	/* 四舍五入 */
	}

	if (v > (u64)LYZ_INT_MAX)
		return neg ? LYZ_INT_MIN : LYZ_INT_MAX;
	return neg ? -(int)v : (int)v;
}

int lyz_gyro_init(int *method)
{
	int m = *method;
	struct input_dev *dev;

	if (m < 0 || m > 1)
		return -EINVAL;

	if (g_gyro_dev) {
		*method = g_gyro_method;
		return -EALREADY;
	}

	dev = find_gyro_dev(m);
	if (!dev)
		return -ENODEV;

	g_gyro_dev = dev;
	g_gyro_method = m;
	pr_info("gyro dev: '%s' (method %d)\n",
		dev->name ? dev->name : "?", m);
	return 0;
}

int lyz_gyro_modify(u32 enable, u32 xbits, u32 ybits)
{
	struct input_dev *dev = g_gyro_dev;

	if (!dev)
		return -ENODEV;
	if (!enable)
		return 0;	/* R3 的 gyro_disable：直接空操作成功 */

	/* 常见陀螺仪上报的是 mdps（毫度/秒），float 值 ×1000 转整数 */
	input_report_abs(dev, ABS_RX, lyz_float_bits_x1000(xbits));
	input_report_abs(dev, ABS_RY, lyz_float_bits_x1000(ybits));
	input_sync(dev);
	return 0;
}
