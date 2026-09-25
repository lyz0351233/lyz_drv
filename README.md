# lyz_drv — 对标 TwT ABI 的自研 Android arm64 内核驱动

从零逆向 TwT 闭源驱动的 R3 对接层（`kernel.h` + `main.cpp`），凭 ABI 行为
复刻出一套**功能等价、可自行维护**的内核模块。R3 侧代码（包括 TwT 官方
`main.cpp` 测试程序）**不做任何修改**即可对接本驱动。

```
对接链路（与 TwT 完全一致）:
  R3: MY_CALL(0x114514, 0x1919810, 0x2778, &fd)   ← svc __NR_reboot 带暗号
  R0: kprobe 挂 __arm64_sys_reboot，pre_handler 命中暗号
      → regs->pc 重定向到替换函数 → anon_inode_getfile("TwT_driver")
      + fd_install，fd 写回 x3 指向的 int
  之后所有功能都走这个 fd 的 ioctl（type = 'T'，按 _IOC_NR 分发）
```

## 文件清单

| 文件 | 职责 |
|---|---|
| `abi.h` | 内核侧 ABI：全部结构体/命令号/暗号，带编译期大小自检 |
| `lyz_drv.h` | 子系统对外原型 + kprobe 劫持描述符 |
| `main.c` | 入口：reboot 暗号劫持、ioctl 总分发、模块隐藏、反查杀、隐身 cdev 兜底（nodev 可关）、fd 上下文、quiet 静默 |
| `fh.c` | kprobe 劫持框架 + kprobe 解析 `kallsyms_lookup_name` |
| `mem.c` | 内存读写 v1（access_process_vm）/ v2（四级页表直读，fd 级 mm 缓存） |
| `proc_info.c` | 进程名找 pid、模块基址/bss、TLS 读取、PACGA 代理执行 |
| `file_hide.c` | getdents64 目录项关键字过滤（6.1.176 逐行保真克隆） |
| `input_inject.c` | 触摸 / 陀螺仪注入 |
| `hwbp.c` | 硬件断点（perf_event）+ 寄存器改写 + NEON 现场捕获 |
| `test_lyz.cpp` | R3 自测程序（复用 TwT 的 kernel.h） |
| `dbl_loader.cpp` | R3 加载器：控制台 UI（伪3D DBL logo）+ insmod + 握手验证 + 失败自动拉 dmesg |
| `unhide.c` | R3 卸载辅助：hide=1 时经握手 fd 发 NR_LYZ_UNHIDE 恢复模块链表 |
| `lyz_version.h` | 版本真源（v1.5.0）：驱动版本宏 + 内核家族探测（5.10/5.15/6.1/6.6/6.12/6.18），未适配家族编译期 #error 点名 |
| `BUILD.md` | 编译→上机完整指南：三房间地图 / 单 tar 过桥 / 瘦身集 / 报错采集协议 / 四轮测试 / 故障字典 / 家族移植清单 |
| `lyz_check.sh` | 对接自检脚本：找/编 test_lyz → 跑 → 按结果行判读 + 环境体检 |
| `Makefile` | 树外编译 |

## 为什么是 kprobe（不是 ftrace / 不是改 sys_call_table）

对着 6.1.176 GKI 源码树逐项验证过（参考 `../Book/` 下的源码与项目）：

| 依赖 | 出厂 GKI 实况 | 证据 |
|---|---|---|
| `register_ftrace_function` 等 ftrace 接口 | **不存在** | `gki_defconfig` 没开 `CONFIG_FUNCTION_TRACER`；这些符号不在 KMI 列表 `android/abi_gki_aarch64.stg` 里，模块链接期就失败 |
| `CONFIG_KPROBES` / `register_kprobe` | **有保障** | defconfig 显式 `CONFIG_KPROBES=y`；`register_kprobe` 在 KMI 列表。KernelSU 全系也用 kprobes（supercall 同样挂 `__arm64_sys_reboot`） |
| `CONFIG_PROFILING=y` → `PERF_EVENTS` | **有保障** | defconfig 第 48 行；`perf_event_create_kernel_counter` 在 KMI 列表 |
| 改 `sys_call_table` | 不可行 | rodata 只读，需要 stop_machine + fixmap 顶风改（KernelSU-Next 的 patch_memory.c 就是这么干的，还要绕 MTK MKP），动静大 |

重定向机制依据 arm64 `kernel/probes/kprobes.c` `kprobe_handler` 原文注释：
*"If we have a pre-handler and it returned non-zero, it will modify the
execution path and no need to single stepping."* —— pre_handler 返回 1 时
跳过被探测指令、按（已改过的）pt_regs 返回异常。我们把 `regs->pc` 指到
替换函数：替换函数以正常内核 C 上下文运行（**可睡眠**），x0 仍是原函数
首参（`__arm64_sys_*` = 用户 pt_regs 指针），返回值即 syscall 返回值。
这正是被移除的 jprobe 机制的核心，5.10/5.15/6.1 行为一致，且**彻底免掉
ftrace 的版本地狱**（6.1.176 已回灌 ftrace_regs API、`RECURSION_SAFE`
改名等坑全部无关了）。

## R3 线索 → 内核实现对照

| kernel.h / main.cpp 里的线索 | lyz_drv 实现 | 文件 |
|---|---|---|
| `MY_CALL` svc `__NR_reboot`，`(0x114514, 0x1919810, 0x2778, &fd)` | kprobe 挂 `__arm64_sys_reboot`，暗号命中 → `anon_inode:TwT_driver` fd | main.c |
| `getFd` 扫 `/proc/self/fd` 找 `anon_inode:TwT_driver` | `anon_inode_getfile("TwT_driver")`；另挂 misc 设备 `/dev/lyz_drv` 兜底 | main.c |
| `read`/`write`（req 32B：pid+addr+buffer+size） | `access_process_vm`（COW 语义，同 ptrace） | mem.c |
| `read_v2` | 手工走 pgd→p4d→pud→pmd→pte，`phys_to_virt` 直读，写后 icache 失效 | mem.c |
| `get_name_pid`（size 参数从不检查 → 恒 0） | comm 匹配 + `/proc/<pid>/cmdline` basename 匹配，两级扫描 | proc_info.c |
| `get_module_base/bss` | VMA 的 `d_name` 按 len+memcmp 匹配；bss = 紧邻文件尾的匿名 VMA | proc_info.c |
| `get_thread_tls` 的 `result` 负 errno、ioctl 恒返 0 | `task->thread.uw.tp_value`，RCU 下读取 | proc_info.c |
| `exec_pacga`（确定性、结果在高位 32bit） | 抢占禁用下换目标进程 `APGAKEY`，执行 `pacga` 指令后还原 | proc_info.c |
| `file_hide_set/clear/status` 的 `hook_active` 字段 | kprobe 挂 `__arm64_sys_getdents64`，克隆 6.1.176 的 filldir64 + 关键字 `strnstr` 过滤 | file_hide.c |
| `touch_down/up`（协议 B/A 自适应） | `input_dev_list` 持 `input_mutex` 遍历（均 kallsyms 解析），按能力位挑真实触屏 | input_inject.c |
| `gyro_config` 的 float 位模式 | 内核禁浮点 → 纯整数 IEEE754 位运算 ×1000 定点上报 ABS_RX/RY | input_inject.c |
| `bp_inst` 返回 handle、`items_copied` 是条数、`EALREADY` 回写当前模式 | `perf_event_create_kernel_counter` 硬件断点；overflow 直接改异常帧；`str qN` 抓 NEON 现场 | hwbp.c |

## 已对照真源码逐项核验的 API（6.1.176 GKI 树）

`access_process_vm`（签名+GPL 导出）、`find_task_by_vpid`/`find_pid_ns`/
`get_task_mm`/`init_task`/`strnstr`/`kvfree`/`iterate_dir`/`kern_path`/
`anon_inode_getfile`/`fd_install`/`get_unused_fd_flags`/`misc_register`
（全部导出且在 KMI 列表）；`kvmalloc_array`/`input_report_abs`/
`input_mt_sync`（static inline，无需导出）；`thread.uw.tp_value`、
`keys_user.apga.lo/.hi`、`SYS_APGAKEYLO/HI_EL1`、`PMD/PUD_TYPE_SECT`、
`pte_offset_kernel`、`icache_inval_pou`（≥5.18）/`__flush_icache_range`
（<5.18）、`instruction_pointer_set`、`struct linux_dirent64`
（include/linux/dirent.h）、`VMA_ITERATOR`/`for_each_vma`
（mm_types.h/mm.h 宏，v1.4 修正 proc_info.c 后补验；底层 `mas_find`
已确认在 KMI 列表）。

**勘误（v1.4）**：此前版本的 `proc_info.c` 用 `mm->mmap`/`vma->vm_next`
遍历 VMA——6.1 起 VMA 链表已被 maple tree 取代（mm_types.h 无该字段，
编译必失败），该遗漏由 km_read 对照发现，已改 `VMA_ITERATOR`。

**未导出、走 kallsyms 函数指针的**：`hw_breakpoint_slots`（arm64 无
EXPORT）、`input_dev_list`/`input_mutex`（static 数据符号）。

## 内核配置要求（出厂 GKI 全部满足，无需改内核）

```
CONFIG_KPROBES=y              # gki_defconfig 显式开启；KMI 列表有 register_kprobe
CONFIG_PROFILING=y            # → PERF_EVENTS=y（BP 子系统；defconfig 第 48 行）
CONFIG_ARM64_PTR_AUTH=y       # default y（PACGA；缺了仅该功能返回错误）
CONFIG_ANON_INODES=y          # default y
CONFIG_ARCH_HAS_SYSCALL_WRAPPER  # arm64 恒有 → __arm64_sys_* 符号存在
```

目标内核：按 GKI 家族划分 —— 5.10 / 5.15 / 6.1 / 6.6 / 6.12 / 6.18
（`lyz_version.h` 是家族真源；当前实机目标 = **6.1 家族**，android14-6.1，
KMI 第 11 世代）。一个家族一份 .ko：家族内 sublevel 差异被 KMI 吸收，
家族之间 KMI 世代不同、CRC 必不同，必须各用各的树各编各的（完整流程与
移植清单见 BUILD.md §0 与附录A）。经 7.2.6 主线树复核，上述所有 API
在新版依然同名同签名（wrapper 命名、`uw.tp_value`、`icache_inval_pou`、
`access_process_vm` 全部未变），跨家族移植面很小。

## 编译

> 完整逐步操作（WSL2 从零到上机、工具链、瘦身、报错排查、四轮测试、
> 故障字典、家族移植清单）见 **BUILD.md**；本节只是速览。

版本匹配的真实判据（MODVERSIONS 下）：`same_magic` 只比 vermagic **旗标段**
（SMP preempt mod_unload modversions），版本 token（sublevel、`-g` 后缀）不参与；
符号 CRC 必须一致——用同 KMI 世代的树完整编译一次自动生成（只 `modules_prepare`
不出 Module.symvers，模块会缺 `__versions`，加载时退化为精确比对必死）。
目标设备的活证据：SukiSU 泛 GKI 构建的 ksu.ko 能在本机加载 = CRC 表与
通用 GKI gen-11 一致。

```bash
# 0. 从设备抓完整 config（judge 上面的旗标段、KASAN/CFI/LTO 全靠它）
adb shell su -c "zcat /proc/config.gz > /data/local/tmp/device.config"
adb pull /data/local/tmp/device.config

# 1. WSL2 里拷树离 /mnt/c（9p 慢 5-10 倍），用 device.config 起完整编译
mkdir -p ~/kbuild && cp -r /mnt/c/.../Book/Android/kernel-common ~/kbuild/
cd ~/kbuild/kernel-common && mkdir out && cp ~/kbuild/device.config out/.config
make ARCH=arm64 LLVM=1 O=out olddefconfig
make ARCH=arm64 LLVM=1 O=out -j$(nproc)          # 产物 out/Module.symvers 必须存在

# 2. 树外编译模块（KDIR=源码树, KOUT=产物目录; clang 加入 PATH）
make -C ~/kbuild/lyz_drv KDIR=~/kbuild/kernel-common KOUT=~/kbuild/kernel-common/out
# 产物: lyz_drv.ko
```

## 部署

```bash
adb push lyz_drv.ko /data/local/tmp/
adb shell su -c "insmod /data/local/tmp/lyz_drv.ko"          # 常规
adb shell su -c "insmod /data/local/tmp/lyz_drv.ko hide=1"   # 隐藏模式
adb shell su -c "insmod /data/local/tmp/lyz_drv.ko hide=1 quiet=1"   # 隐藏+静默 dmesg
adb shell su -c "insmod /data/local/tmp/lyz_drv.ko hide=1 quiet=1 nodev=1"   # 部署满配
adb shell dmesg | grep lyz_drv
# 应看到: hooked __arm64_sys_reboot @ ... 和 loaded 一行
# （quiet=1 时这两行故意不存在——它们本身就是取证指纹）
```

`nodev=1`（部署推荐）：整条兜底设备链不建——/dev 节点、/sys/class 目录、
device_create 的 uevent 广播全部不存在。同类驱动 km_read 的实测教训：
模块隐藏了但设备节点常驻，能过 PUBGM/三角洲的 ACE 却过不了暗区——
扫 /dev 与 uevent 的 AC 一抓一个准。我们的握手路径从不依赖设备节点，
nodev=1 唯一代价是"暗号握手失败时无 /dev 兜底"，而握手是自己实现的。

### DBLKernel 加载器（dbl_loader.cpp）

控制台 UI（横幅 / 金色伪3D DBL logo / [!] 信息区 / 成功提示）属于 **R3
用户态加载器**——内核模块只能 printk 到 dmesg（无颜色无定位），商用加载器
的 UI 也全部在用户态。Termux 里编译运行：

```bash
# Termux 里编译（源码在 /data/local/tmp 布局，见下方"测试"节）:
clang++ -O2 -o ~/dbl_loader /data/local/tmp/lyz_drv/dbl_loader.cpp
~/dbl_loader                              # 默认加载 /data/local/tmp/lyz_drv.ko（满配参数）
~/dbl_loader /sdcard/Download/lyz_drv.ko  # 或指定其他 .ko
```

流程：握手探测（防重复 insmod 报 EEXIST）→ `su -c insmod ... hide=1
quiet=1 nodev=1` → MY_CALL 握手验证 → "驱动加载成功"。失败时自动拉取
`dmesg | tail -20` 并给出三种典型原因对照。tg 地址等文案在源码顶部
`g_info[]` 数组里填。注意：加载成功只证明握手活着，功能正确性仍以
test_lyz 全绿为准。

### 隐身特性（吸收自 kernel_hack V5.0 并修正/补全）

| 特性 | 实现 | 说明 |
|---|---|---|
| `/proc/devices` 不可见 | 原生 cdev + `device_create` 后立即 `unregister_chrdev_region` | cdev_map 仍能解析 dev_t，open 照常；代价是 major 理论上可被后来的 insmod 复用 |
| `/proc/misc` 不出现 | 不用 misc，自建 class | — |
| 兜底设备链整体不存在 | `nodev=1` 加载参数（部署推荐） | 无 /dev 节点、无 /sys/class 目录、无 uevent 广播。km_read 教训：常驻设备节点是被扫 /dev 的 AC（暗区）抓住的弱点；我们的握手路径不依赖设备 |
| 使用期间 `/dev` 节点消失 | open 时 `device_destroy`+`class_destroy`，close 时重建 | 持 fd 期间全系统扫不到节点；进程崩溃退出时 fd 自动释放 → release 重建 |
| `lsmod` / `/proc/modules` / `/sys/module` 不可见 | `hide=1`：持 module_mutex 做 `list_del` + `kobject_del(mkobj)` | kernel_hack 特性文件宣称但源码未实现的部分，此处补全；module_mutex 经 kallsyms 解析 |
| dmesg 信息级输出静默 | `quiet=1` 加载参数（`pr_err`/`pr_warn` 仍打印） | 加载/卸载日志、hook 地址、kallsyms 地址这些最廉价的取证指纹全部消失；需要 mknod 兜底时先跑一次非 quiet 拿设备号 |
| 反查杀 | 私有 NR 64：吞发往保护进程的 SIGKILL/SIGTERM 并返回 0 伪装成功 | **按需**挂 `__arm64_sys_kill` 第二个 kprobe，不启用保护时该断点不存在；保护随启用 fd 关闭自动解除 |
| kprobe 指纹被 KSU 掩护 | 挂点选 `__arm64_sys_reboot`（KernelSU supercall 同款挂点） | KSU 设备上该函数头**本来就有** BRK（kprobe 支持同址聚合），扫描器看到断点也无法归因到我们 |
| 文件名/模块名特征 | `make MODULE_NAME=xyz` 换名编译 | 只抹最外层名字特征，不是混淆；`anon_inode:TwT_driver` 名由 ABI 钉死，改名也藏不住 |
| 隐藏工具进程的 `/proc/<pid>` 条目 | 复用 file_hide：`directory=/proc`，`keyword=<pid 十进制串>` | 关键字是子串匹配：pid "12345" 也会命中 "123456"，选用完整 pid 串可基本避开 |

**隐藏模式的卸载流程**（模块不在链表里，直接 rmmod 会报 "No such module"）：

```c
ioctl(fd, _IO('T', 62), 0);   // NR_LYZ_UNHIDE：恢复链表，然后才能 rmmod
close(fd);
```

### 私有扩展命令详解（NR 62 / 63 / 64）

TwT 的 kernel.h 不认识这些命令——它们是 lyz_drv 自有工具（test_lyz 等）
的按需扩展，**不碰任何 TwT 命令号**，兼容性零影响。

**NR 63 — v2 物理写**（与 `READ_MEM_V2`(11) 对称的无痕写）：

```c
struct twt_request req = { .pid = pid, .addr = addr,
                           .buffer = (uintptr_t)buf, .size = len };
ioctl(fd, _IOW('T', 63, struct twt_request), &req);
```

不走 COW、不置脏位、不触发缺页——A/D 位金丝雀全失效。**只接受匿名页**
（堆/栈/已 COW 的私有页）：文件映射/共享页返回 `-EOPNOTSUPP`，上层收到
失败回退普通 `WRITE_MEM`(5) 即可——那条路走 FOLL_FORCE 强制 COW（ptrace
语义），永远不会污染页缓存。整段写要求全是匿名页，中途遇到文件页按失败
处理（回退 v1 重写整段）。

**NR 64 — 反查杀**：

```c
int pid = getpid();
ioctl(fd, _IOW('T', 64, int), &pid);   // >0：保护；0：解除
```

发往该进程的 `kill(pid/-pid, SIGKILL|SIGTERM)` 被吞掉且 syscall 返回 0
（伪装成功——同 uid 进程正常 kill 拿不到 EPERM，报错本身就是指纹）。
`am force-stop` / `Process.killProcess` 最终都走 kill(pid, SIGKILL)。
注意：

- 只拦 kill(2) 族（含 `kill(-pid)` 组击杀）；tgkill / pidfd_send_signal
  未拦（要拦加同款 hook 即可，每多一个 hook 多一处常驻指纹，默认不加）
- 工具进程应先 `setsid()` 脱离进程组，躲开 `kill(0, sig)` 全组打击
- 单槽设计：后设置覆盖前设置；保护目标退出后及时 `protect(0)`（pid
  会被回收，不解除的话下一个拿到该 pid 的无辜进程将杀不死）
- 保护与"启用它的 fd"生命周期绑定：fd 关闭自动解除；fork 会复制该 fd，
  子进程持有副本会延长保护的生命周期

### 故意不做的"商业特性"（以及为什么）

| 宣传项 | 我们的做法 | 原因 |
|---|---|---|
| 页表级隐藏自身代码 | 不做；以 `quiet=1` + `MODULE_NAME=` 替代 | 模块文本在 hook 存续期间**必须可执行**：PTE 上做手脚要么破坏执行稳定性，要么只能防静态扫描——本质是混淆，拿稳定性换窄收益。且 `anon_inode:TwT_driver` 名字是 ABI 钉死的常驻字符串，代码藏得再好也藏不住它；真到 R0 对抗层，比拼的是特征码对抗而不是架构 |
| root 环境隐藏 | 不做；设备侧用 DenyList + Shamiko | 游戏反作弊看到的是 KernelSU/Magisk 的挂载、su、SELinux 上下文——**在我们驱动被看到之前很久就看到了**。这是另一层的成熟方案，在驱动里半吊子实现只会引入新指纹 |
| 加壳 / 每机随机化 | 不做；`MODULE_NAME=` 改名是接受的上限 | 商业驱动的做法是自身文本加密、调用时解密——每条路径都增加崩溃面；对研究代码的可读性是自杀。研究项目的对抗终点是"知道自己在哪个层面会输"，不是无限军备 |

### 兜底设备节点

主通道是 reboot 暗号 + `anon_inode:TwT_driver`，**不依赖任何 /dev 节点**（TwT 的
R3 也从不 open /dev）。cdev 兜底仅供调试：名字由 `dev_name=` 参数控制（默认
`lyz_drv`），major:minor 打印在 dmesg（`/proc/devices` 里看不到，这是特性）：

```bash
adb shell su -c 'mknod /dev/lyz_drv c <major> <minor>'   # 号在 dmesg loaded 行
```

`anon_name=` 参数可改 anon_inode 名字——改名会破坏 TwT R3 的 getFd 回退匹配，
仅配合自定义 R3 做研究用。

## 测试

```bash
# A. 快速自测（写自身 → 双路径读回 → 模块基址 → ELF 魔数 → 反查 pid
#    → 二次握手 → v2 物理写 + 文件页门禁 → 反查杀 自我/跨进程
#    → v2 跨进程读 + fd 级缓存切换 + nodev 自检信息）
$TC/bin/aarch64-linux-android29-clang++ -O2 -static \
    -o test_lyz lyz_drv/test_lyz.cpp
adb push test_lyz /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/test_lyz
adb shell /data/local/tmp/test_lyz          # 期望全部 [PASS]

# A2. 一键自检脚本（自动找/编 test_lyz → 跑 → 按"== 结果 =="行判读，
#     外加 dmesg / 模块可见性 / .ko 版本指纹体检，规则见其文件头）:
adb push lyz_drv /data/local/tmp/                    # 整目录（含脚本）
adb shell sh /data/local/tmp/lyz_drv/lyz_check.sh    # 退出码 0 = 对接成功

# B. 原版 TwT 官方测试（不修改一行，直接编译运行 —— 终极兼容性验证）
$TC/bin/aarch64-linux-android29-clang++ -O2 -static -o twt_test main.cpp
adb push twt_test /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/twt_test
adb shell /data/local/tmp/twt_test
```

原版 `main.cpp` 覆盖：TLS（主线程/工作线程，须等于 TPIDR_EL0）、PACGA
（本进程/远程进程，密钥须被正确还原）、文件隐藏（`hook_active` 状态机、
清除后两边都归零）等深层行为，比 test_lyz 严格得多。

## ioctl 速查（type = 'T'，内核按 _IOC_NR 分发）

| NR | 名称 | 载荷 |
|---|---|---|
| 0 | GET_PID | request（名字入、pid 出） |
| 1 / 3 | MODULE_BASE / MODULE_BSS | request（模块名入、基址出） |
| 4 / 11 | READ_MEM / READ_MEM_V2 | request（v1 失败时换 v2） |
| 5 | WRITE_MEM | request |
| 6 / 7 / 8 | TOUCH_INIT / DOWN / UP | touch_event_base |
| 9 / 10 | GYRO_INIT / GYRO_CONFIG | int / gyro_config |
| 12 | GET_THREAD_TLS | twt_tls_request（errno 走 result 字段） |
| 13 | EXEC_PACGA | twt_pacga_request |
| 19–28 | BP_INIT / GET_NUM_BRPS / GET_NUM_WRPS / INST / UNINST / SUSPEND / RESUME / GET_HIT_COUNT / MODIFY / GET_HIT_ITEMS | hwbp.c（handle=槽位+1，0 无效） |
| 30 | BP_CHECK_INITED | 无 |
| 31 / 32 / 33 | FILE_HIDE_SET / CLEAR / STATUS | file_hide.c |
| 62 | LYZ_UNHIDE（私有） | 无（隐藏模式恢复可见性，卸载前必调） |
| 63 | LYZ_WRITE_V2（私有） | request（v2 物理写，仅匿名页，失败回退 NR 5） |
| 64 | LYZ_PROTECT（私有） | int（pid>0 保护 / 0 解除） |

## 已知限制（与 TwT 同级或为其固有边界）

1. **仅支持 wrapper 式 syscall 内核**：非 `CONFIG_ARCH_HAS_SYSCALL_WRAPPER`
   的老内核（部分 4.x/5.4 厂商内核）没有 `__arm64_sys_*` 符号。
2. **v2 读不到被换出的页**（zRAM swap）→ 上层应在 v2 失败时回退 v1。
3. **v2 写文件映射且"干净"的页不回写文件**（只改内存）—— 对读游戏数据无影响。
4. **目标进程退出前必须 `bp_uninst`**：否则 perf 随任务销毁 event，句柄悬垂。
5. **触摸/陀螺仪设备挑选是启发式**：机型差异大，先
   `cat /proc/bus/input/devices` 看名字，必要时调整
   `find_touch_dev` / `find_gyro_dev` 的匹配条件。
6. **仅 64 位 R3**：ABI 含 64 位指针字段，无 32 位 compat 支持。
7. **文件隐藏只作用于 getdents64**：已知完整路径仍可 open（与 TwT 行为一致）。
8. v1 读写单次上限 1 MiB（内核 staging 缓冲分块，碎片化时自动降级 256K/64K）。
9. 文件隐藏激活期间，系统里**所有**进程对该目录的 getdents64 都会走克隆路径。
10. v2 写只接受匿名页；文件/共享页 `-EOPNOTSUPP` → 回退 v1（COW 语义）。
    门禁在页级判断（`PageAnon(compound_head(page))`，兼容 THP），非 VMA 级。
11. 反查杀只拦 kill(2) 的 SIGKILL/SIGTERM；tgkill / pidfd_send_signal /
    ptrace 路径不拦。保护目标退出后 pid 会被回收，须及时 `protect(0)`。
12. v2 写改的是物理页且不标脏：页面回收/迁移的窗口极小（写全程持
    mmap_read_lock），但上层写完应回读校验，失败重写。
13. fd 级 mm 缓存把目标地址空间 pin 到 fd 关闭为止：目标进程退出后
    其内存不释放（exit_mmap 等 mm_users 归零），读"尸体"内存反而可行，
    代价是死进程 RSS 滞留 + R0 侧扫描器可见的孤儿 mm。多工具进程各持
    fd 时各 pin 一份。
14. 同一 fd 并发换不同 pid 不支持（多线程并发读**同一** pid 安全）：
    缓存切换会 mmput 旧 pin，与在飞读者竞争。TwT 官方 R3 是单 fd 单
    目标用法；km_read 的全局缓存支持该模式，但那正是它 UAF 的来源。

## 设计要点备忘

- **kprobe 重定向**：断点命中时 x0 = 包装函数首参 = 用户 pt_regs 指针，
  pre_handler 只做无锁判断（调试异常上下文禁睡眠），替换函数才是干活的地方
  （正常 syscall 上下文，可睡眠）。真实 reboot（magic=0xfee1dead）不匹配
  暗号 → pre_handler 返回 0 → 原路径单步执行，行为零改变。
- **卸载安全**：`fops.owner=THIS_MODULE` 保 ioctl 路径；每个替换函数带
  in-flight 原子计数，`lyz_hook_remove` 先摘 kprobe → `synchronize_rcu`
  排空 pre_handler → 自旋等计数归零，之后才允许释放模块文本。
- **kallsyms_lookup_name**：5.7 起不导出，注册同名 kprobe 从 `kp.addr`
  拿地址；text 符号则直接用 `register_kprobe(.symbol_name=...)`，KASLR 无感。
- **并发纪律**：自旋锁内绝不 `copy_to_user`/`kvmalloc`/`path_put`（会睡眠），
  一律锁内快照、锁外慢操作；跨进程任务指针全部走 RCU + `get_task_struct`。
- **BP 改寄存器**：overflow handler 就跑在目标线程上下文，拿到的 `pt_regs*`
  是活体异常帧，改完异常返回即生效；此刻内核还没碰过 FPSIMD，`str qN`
  抓到的就是目标用户态的真实现场。
- **filldir64 克隆保真**：bool 返回、`verify_dirent_name`、`prev_reclen`
  尾条目 d_off 修补、信号截断、`unsafe_put_user` 快路径，与 6.1.176
  fs/readdir.c 逐行对齐；隐藏 = 回调 return true 且不写不推进。
- **v2 物理写的页级门禁**：只允许 `PageAnon(compound_head(page))` 页
  （compound_head 归一兼容 THP 尾页）；文件/共享页直写会污染页缓存
  （改动对所有映射该文件的进程可见、回收即丢），宁可 -EOPNOTSUPP 让
  R3 回退 v1 的 COW 语义。
- **反查杀的指纹经济学**：断点按需挂（不用不存）、吞信号返回 0 伪装成功
  （EPERM 本身是指纹）、保护随 fd 关闭解除（防 pid 回收误伤）、单槽
  语义简单可推理。宁可少拦路径（tgkill 等不拦），不多留常驻痕迹。
- **`quiet` 是参数不是编译选项**：同一份 .ko 在调试（verbose）和实战
  （quiet）两种形态间切换，不用维护两个构建。
- **fd 级 mm 缓存**（v1.4，吸收自 km_read 的热路径思路并重构）：每个 fd
  首次 v2 访问某 pid 时 `get_task_mm` pin 住 mm，热路径（同 fd 同 pid）
  零原子操作、零 pid 解析——TwT 风格 R3 一帧上百次小读取的主要开销就
  在逐次 `find_task_by_vpid→get_task_mm`。**做成 fd 私有而不是全局槽**：
  生命周期天然绑定 fd（close 即放 pin），多 fd 互不干扰，且换目标在
  ctx 锁内串行——km_read 的全局缓存快路径无锁抓 pgd_phys，与换目标
  线程的 `mmput` 竞争，pgd 页可能已进伙伴系统（UAF），我们不复制这个洞。
- **VMA 遍历按 6.1 实况**：6.1 起 VMA 链表（`mm->mmap`/`vma->vm_next`）
  已被 maple tree 取代（mm_types.h 里 vm_next 字段不存在，旧写法编译
  不过），用 `VMA_ITERATOR`+`for_each_vma` 升序遍历，底层 `mas_find`
  已确认在 GKI KMI 符号列表。

## 参考（./Book 目录）

- `Book/Android/kernel-common` — 6.1.176 GKI 内核源码（本项目的主对照标准）
- `Book/Linux-Source` — 7.2.6 主线（前向兼容复核）
- `Book/Projects/KernelSU` — kprobe 挂 `__arm64_sys_reboot` 的实证
  （supercall/supercall.c）；pre_handler 禁睡眠 → task_work 推迟的模式
- `Book/Projects/KernelSU-Next` — fixmap+stop_machine 直改 syscall 表的
  备选方案（hook/arm64/patch_memory.c），以及 ni_syscall 空槽 dispatcher
- `Book/Projects/随机驱动读写源码V5.0_修复6.1读取模块` — 兜底设备隐身三件套
  （cdev+随机名、open 删节点、unregister_chrdev_region）的出处
- `../km_driver_v0.1.0_20260923` — 乱穿烟的实战驱动（GPT 生成，可过
  PUBGM/三角洲 ACE、过不了暗区），v1.4 三项吸收的出处
- `Book/ARM/abi-aa` — ARM ARM（PACGA/调试断点/异常返回语义）

### 从 kernel_hack V5.0 吸收了什么 / 拒绝了什么

吸收（已按 6.1 源码修正）：
- cdev+自建 class 替代 misc（`/proc/misc` 不出现）；
  `device_create` 后 `unregister_chrdev_region`（`/proc/devices` 不可见）；
  open 销毁节点 / close 重建
- 特性文件宣称但该源码未实现的模块隐藏，按标准做法补全（module_mutex 下
  `list_del` + `kobject_del`，并补上"unhide ioctl → 才能 rmmod"的恢复路径，
  原理见上文隐身表）

**拒绝吸收**（均为该项目的缺陷或风险，不采用）：
- `verify.h` 的卡密授权：内核态 RC4 + `sock_create_kern` 远程连接
  `64.112.43.2:31828` 验证——等于在驱动里内置别人家的远程开关（对方可
  遥控禁用、可统计使用者），且该版本里已是死代码
- 页表 walk 完全不持 `mmap_read_lock`（与 munmap 并发有 UAF 风险）；我们的
  v2 读同是物理直读、零触碰目标 PTE，但持读锁
- PMD/PUD 大页（section）不判断就 `pte_offset_kernel`（THP 开启即崩）；
  Android 默认关 THP 才没炸
- 每页 `ioremap_cache`+`iounmap`（慢且占 vmalloc 空间）；我们用 linear map
  的 `phys_to_virt`
- `get_module_base` 里 rcu 解锁后继续用 task（引用计数缺失）

### 从 km_read 吸收了什么 / 拒绝了什么（v1.4）

km_read（`../km_driver_v0.1.0_20260923`）：GPT-6-astra 生成、kheaders +
手写 mod.c 硬编码 CRC 手搓编译的纯读驱动，常驻设备节点 `/dev/msm_thermal_q`
（chmod 666）。实测可过 PUBGM / 三角洲的 ACE，过不了暗区。GPT 的构建方式
本身就是一份情报：无内核树也能出 .ko——头文件可从设备 `/proc/kheaders`
拿，符号 CRC 可从任意一次全树构建的 `Module.symvers` 或现成 .ko 的
`__versions` 段收割（km_read 的手写 mod.c 正是这么来的）；我们不采用
（有全树 kbuild 没必要），但值得知道。

吸收（按我们的正确性标准重构）：

- **pid→mm 缓存热路径**（v2 读写同 fd 同 pid 零解析开销）——重构为
  fd 私有 `lyz_fd_ctx`：km_read 是全局单槽，快路径无锁抓 `cached_pgd_phys`
  与换目标线程的 `drop_cached_mm()+mmput` 竞争，旧 pgd 可能已进伙伴系统
  （UAF）；fd 私有 + 切换在锁内 + 引用归 ctx，天然无此洞
- **MTE 标签剥离**（`addr &= 0x00FFFFFFFFFFFFFF`，位 63:56）——v2 入口
  一行防御，与硬件 TBI 行为对齐
- **"过不了暗区"的教训**：km_read 模块隐藏了，但 /dev 节点、/sys/class
  目录、uevent、/proc/devices 条目全部常驻——能过 PUBGM/三角洲说明那两
  个 ACE 不扫设备节点，暗区扫。→ 我们加 `nodev=1`，部署态整条兜底设备
  链不建（握手路径本就不依赖它）

对照 km_read 顺带发现并修掉的**自身 bug**：

- `proc_info.c` 的 VMA 遍历还在用 6.1 已删除的 `mm->mmap`/`vma->vm_next`
  链表（mm_types.h 里字段已不存在，**编译都过不了**）——改用
  `VMA_ITERATOR`+`for_each_vma`（6.1 标准）。km_read 用 maple tree 才是
  6.1 的正确姿势，它的用法反过来提醒我们查证了自己的这段代码

**拒绝吸收**（均为该项目的缺陷，不采用）：

- 全局缓存的无锁快路径（上述 UAF）
- 页表 walk 无 `pfn_valid` 门禁：目标进程里 VM_PFNMAP 设备映射
  （GPU/ION 共享内存）的 PTE 指向非 RAM 物理地址，`phys_to_virt` 出
  linear map 覆盖范围 → 读到即内核 panic。我们有页级门禁，拒绝时
  返回 -EFAULT
- walk 全程不持 `mmap_read_lock`（与 munmap/exit_mmap 并发有 UAF 面）
- 常驻设备节点 + chmod 666（任何 App 都能 open 它的驱动）——架构级
  检测面，正是它过不了暗区的原因
- `find_pid` 逐 pid 扫 1..32768（每次 rcu+哈希+原子）——我们的
  `for_each_process` 单趟遍历快约两个数量级
- 纯读驱动（无写路径）是它的产品选择，不算缺陷，但写路径的 COW 语义 /
  PageAnon 门禁这些坑它躲过去了不等于不存在
