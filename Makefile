# lyz_drv — 对标 TwT ABI 的自研 Android arm64 内核驱动
#
# 用法（树外编译，需先完整编过一遍目标内核树拿到 Module.symvers）:
#
#   make KDIR=/path/to/kernel-src KOUT=/path/to/kernel-out \
#        ARCH=arm64 LLVM=1
#
# 说明:
#   - KDIR = 内核源码树；KOUT = 该树用 O= 编出的产物目录（含 Module.symvers
#     和生成的头文件）。树是 in-tree 编译（没用 O=）时 KOUT 留空即可。
#   - 版本匹配的真实判据：MODVERSIONS 下 same_magic 只比 vermagic 旗标段
#     （SMP preempt mod_unload modversions），版本 token（含 sublevel 和
#     -g 后缀）不参与；符号 CRC 必须一致——完整树编译自动生成。KMI 世代
#     一致时 sublevel 差异可被吸收。
#   - GKI 内核必须用 LLVM=1（clang）编译；把 clang 所在目录加进 PATH。
#
# MODULE_NAME: 产物 .ko 的模块名（默认 lyz_drv）。每次换名编译可抹掉最
#   外层的文件名/模块名特征（lsmod、/sys/module/<name>、kallsyms 模块名
#   段）——注意这只是改名，不是加密/混淆；anon 名 "TwT_driver" 由 ABI
#   钉死，改名也藏不住它。
#   用法: make MODULE_NAME=xyz KDIR=...  （产物 xyz.ko，insmod 名即 xyz）
#
# 家族分发（v1.5.0 起，版本真源 = lyz_version.h）:
#   GKI 家族 = 5.10 / 5.15 / 6.1 / 6.6 / 6.12 / 6.18（对应
#   android12/13/14/15/16/未来 GKI 分支）。一个家族一份 .ko：
#   家族内 sublevel 差异被 KMI 吸收（same_magic 只比旗标段 + CRC），
#   家族之间 KMI 世代不同、CRC 必不同，必须各用各的树各编各的。
#   当前实机目标 = 6.1；其他家族编译期 lyz_version.h 会 #error 点名未
#   适配（移植点清单见 BUILD.md 附录A，移植完成后删对应 #error 即可）。

MODULE_NAME ?= lyz_drv

obj-m += $(MODULE_NAME).o

$(MODULE_NAME)-y := main.o fh.o mem.o proc_info.o file_hide.o input_inject.o hwbp.o

KDIR ?= $(ANDROID_KERNEL_SRC)
KOUT ?=
ARCH ?= arm64
CROSS_COMPILE ?= aarch64-linux-gnu-

all:
	$(MAKE) -C $(KDIR) $(if $(KOUT),O=$(KOUT)) M=$(CURDIR) ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) LLVM=1 modules

clean:
	$(MAKE) -C $(KDIR) $(if $(KOUT),O=$(KOUT)) M=$(CURDIR) ARCH=$(ARCH) \
		CROSS_COMPILE=$(CROSS_COMPILE) LLVM=1 clean

.PHONY: all clean
