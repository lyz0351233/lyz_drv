/* abi.h — 内核侧 ABI 定义，必须与 R3 侧 kernel.h 二进制布局完全一致
 *
 * 目标平台: Android GKI 内核 5.10 / 5.15 / 6.1, arm64
 * 要求: CONFIG_ARCH_HAS_SYSCALL_WRAPPER=y (GKI 默认)
 */
#ifndef LYZ_ABI_H
#define LYZ_ABI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define TWT_MARK 'T'

/* reboot 劫持暗号（与 R3 侧 MY_CALL 宏一致） */
#define TWT_MAGIC1     0x114514
#define TWT_MAGIC2     0x1919810
#define TWT_CMD_BIND   0x2778

/* 布局必须与 R3 侧一致: pid(4)+pad(4)+addr(8)+buffer(8)+size(8) = 32 字节 */
struct twt_request {
	s32   pid;
	u32  __pad;
	u64  addr;
	u64  buffer;   /* 用户态指针 */
	u64  size;
};

struct twt_touch_event {
	s32 slot;
	s32 x;
	s32 y;
};

struct twt_gyro_config {
	u32 enable;
	u32 x;         /* float 的位模式 */
	u32 y;
};

struct twt_tls_request {
	s32  pid;
	s32  tid;
	u64 tls_value;
	s32  result;
	u32 reserved;
};

struct twt_pacga_request {
	s32  pid;
	u32 reserved0;
	u64 value;
	u64 modifier;
	u64 result_pac;
	s32  ok;
	u32 reserved1;
};

#define TWT_FILE_HIDE_DIRECTORY_MAX 256
#define TWT_FILE_HIDE_KEYWORD_MAX   128

struct twt_file_hide_config {
	char     directory[TWT_FILE_HIDE_DIRECTORY_MAX];
	char     keyword[TWT_FILE_HIDE_KEYWORD_MAX];
	u32 enabled;
};

struct twt_file_hide_status {
	char     directory[TWT_FILE_HIDE_DIRECTORY_MAX];
	char     keyword[TWT_FILE_HIDE_KEYWORD_MAX];
	u32 enabled;
	u32 hook_active;
};

/* ---------- 硬件断点 ABI ---------- */
#define HW_BREAKPOINT_LEN_1 1
#define HW_BREAKPOINT_LEN_2 2
#define HW_BREAKPOINT_LEN_3 3
#define HW_BREAKPOINT_LEN_4 4
#define HW_BREAKPOINT_LEN_5 5
#define HW_BREAKPOINT_LEN_6 6
#define HW_BREAKPOINT_LEN_7 7
#define HW_BREAKPOINT_LEN_8 8

#define HW_BREAKPOINT_EMPTY 0
#define HW_BREAKPOINT_R     1
#define HW_BREAKPOINT_W     2
#define HW_BREAKPOINT_RW    (HW_BREAKPOINT_R | HW_BREAKPOINT_W)
#define HW_BREAKPOINT_X     4

#define REG_MODIFY_X(N)     (1ULL << (N))
#define REG_MODIFY_SP       (1ULL << 31)
#define REG_MODIFY_PC       (1ULL << 32)
#define REG_MODIFY_PSTATE   (1ULL << 33)

#define BP_FLAG_RECORD      0x1

/* R3 侧 kernel.h 中以下结构体位于 #pragma pack(1) 区域，此处必须完全一致：
 * 注意 bp_inst_args 的 pid 之后没有对齐填充，addr 直接位于 offset 4！ */
#pragma pack(1)
struct bp_user_pt_regs {
	u64 regs[31];
	u64 sp;
	u64 pc;
	u64 pstate;
	u64 orig_x0;
	u64 syscallno;
	__uint128_t vregs[32];
};

struct bp_hit_item {
	u64 task_id;
	u64 hit_addr;
	u64 hit_time;
	struct bp_user_pt_regs regs_info;
};

struct bp_get_hit_count_arg {
	u64 handle;
	u64 hit_total_count;
	u64 hit_item_arr_count;
};

struct bp_get_hit_items_args {
	u64 handle;
	u64 user_buffer_ptr;
	u64 max_bytes;
	u64 items_copied;
};

struct bp_inst_args {
	s32  pid;              /* offset 0 */
	u64 addr;             /* offset 4 —— pack(1)，无填充！ */
	u32 bp_len;           /* offset 12 */
	u32 bp_type;          /* offset 16 */
	u64 reg_modify_mask;
	u64 fp_reg_modify_mask;
	u64 regs_to_set_ptr;   /* 用户态指针 */
	u32 flags;
};

struct bp_modify_args {
	u64 handle;
	u64 reg_modify_mask;
	u64 fp_reg_modify_mask;
	u64 regs_to_set_ptr;   /* 用户态指针 */
};
#pragma pack()

/* ABI 大小编译期自检（gnu89 兼容写法，与 kernel.h 的 static_assert 对应） */
typedef char lyz_abi_chk_req  [(sizeof(struct twt_request) == 32)  ? 1 : -1];
typedef char lyz_abi_chk_tls  [(sizeof(struct twt_tls_request) == 24) ? 1 : -1];
typedef char lyz_abi_chk_pac  [(sizeof(struct twt_pacga_request) == 40) ? 1 : -1];
typedef char lyz_abi_chk_cfg  [(sizeof(struct twt_file_hide_config) == 388) ? 1 : -1];
typedef char lyz_abi_chk_st   [(sizeof(struct twt_file_hide_status) == 392) ? 1 : -1];
typedef char lyz_abi_chk_regs [(sizeof(struct bp_user_pt_regs) == 800) ? 1 : -1];
typedef char lyz_abi_chk_item [(sizeof(struct bp_hit_item) == 824) ? 1 : -1];
typedef char lyz_abi_chk_cnt  [(sizeof(struct bp_get_hit_count_arg) == 24) ? 1 : -1];
typedef char lyz_abi_chk_its  [(sizeof(struct bp_get_hit_items_args) == 32) ? 1 : -1];
typedef char lyz_abi_chk_ins  [(sizeof(struct bp_inst_args) == 48) ? 1 : -1];
typedef char lyz_abi_chk_mod  [(sizeof(struct bp_modify_args) == 32) ? 1 : -1];

/* ioctl 命令号（NR 与 R3 一致；内核侧只按 NR 分发，不校验 size 编码） */
#define TWT_GET_PID          _IOW(TWT_MARK, 0,  struct twt_request)
#define TWT_MODULE_BASE      _IOW(TWT_MARK, 1,  struct twt_request)
#define TWT_MODULE_BSS       _IOW(TWT_MARK, 3,  struct twt_request)
#define TWT_READ_MEM         _IOW(TWT_MARK, 4,  struct twt_request)
#define TWT_READ_MEM_V2      _IOW(TWT_MARK, 11, struct twt_request)
#define TWT_WRITE_MEM        _IOW(TWT_MARK, 5,  struct twt_request)
#define TWT_TOUCH_INIT       _IOW(TWT_MARK, 6,  struct twt_touch_event)
#define TWT_TOUCH_DOWN       _IOW(TWT_MARK, 7,  struct twt_touch_event)
#define TWT_TOUCH_UP         _IOW(TWT_MARK, 8,  struct twt_touch_event)
#define TWT_GYRO_INIT        _IOW(TWT_MARK, 9,  int)
#define TWT_GYRO_CONFIG      _IOWR(TWT_MARK, 10, struct twt_gyro_config)
#define TWT_GET_THREAD_TLS   _IOWR(TWT_MARK, 12, struct twt_tls_request)
#define TWT_EXEC_PACGA       _IOWR(TWT_MARK, 13, struct twt_pacga_request)

#define TWT_FILE_HIDE_SET    _IOW(TWT_MARK, 31, struct twt_file_hide_config)
#define TWT_FILE_HIDE_CLEAR  _IO(TWT_MARK, 32)
#define TWT_FILE_HIDE_STATUS _IOR(TWT_MARK, 33, struct twt_file_hide_status)

#define TWT_BP_INIT_CMD      _IO(TWT_MARK, 19)
#define TWT_BP_CHECK_INITED  _IO(TWT_MARK, 30)
#define TWT_BP_GET_NUM_BRPS  _IO(TWT_MARK, 20)
#define TWT_BP_GET_NUM_WRPS  _IO(TWT_MARK, 21)
#define TWT_BP_INST          _IOWR(TWT_MARK, 22, char *)
#define TWT_BP_UNINST        _IOW(TWT_MARK, 23, char *)
#define TWT_BP_SUSPEND       _IOW(TWT_MARK, 24, char *)
#define TWT_BP_RESUME        _IOW(TWT_MARK, 25, char *)
#define TWT_BP_GET_HIT_COUNT _IOWR(TWT_MARK, 26, char *)
#define TWT_BP_MODIFY        _IOW(TWT_MARK, 27, char *)
#define TWT_BP_GET_HIT_ITEMS _IOWR(TWT_MARK, 28, char *)

/* ioctl NR 常量（switch 分发用） */
#define NR_GET_PID          0
#define NR_MODULE_BASE      1
#define NR_MODULE_BSS       3
#define NR_READ_MEM         4
#define NR_WRITE_MEM        5
#define NR_TOUCH_INIT       6
#define NR_TOUCH_DOWN       7
#define NR_TOUCH_UP         8
#define NR_GYRO_INIT        9
#define NR_GYRO_CONFIG      10
#define NR_READ_MEM_V2      11
#define NR_GET_THREAD_TLS   12
#define NR_EXEC_PACGA       13
#define NR_BP_INIT          19
#define NR_BP_GET_NUM_BRPS  20
#define NR_BP_GET_NUM_WRPS  21
#define NR_BP_INST          22
#define NR_BP_UNINST        23
#define NR_BP_SUSPEND       24
#define NR_BP_RESUME        25
#define NR_BP_GET_HIT_COUNT 26
#define NR_BP_MODIFY        27
#define NR_BP_GET_HIT_ITEMS 28
#define NR_BP_CHECK_INITED  30
#define NR_FILE_HIDE_SET    31
#define NR_FILE_HIDE_CLEAR  32
#define NR_FILE_HIDE_STATUS 33

/* ---------- 私有扩展（TwT ABI 之外的 lyz_drv 自有命令） ----------
 * R3 侧 kernel.h 不认识这些命令——只影响"不改 TwT 兼容性"这个前提下的
 * 自有工具（test_lyz 等）。全部按需选用。
 *
 * 62: 恢复模块可见性。hide=1 加载后模块从 modules 链表摘除，rmmod 找不
 *     到它；卸载前必须先 ioctl(fd, _IO('T', 62), 0)。
 *
 * 63: v2 物理写——与 READ_MEM_V2(11) 对称的无痕写：不走 COW、不置脏位、
 *     不触发缺页。只接受匿名页（堆/栈/已 COW 的私有页）；文件映射/共享
 *     页返回 -EOPNOTSUPP，R3 收到失败应回退普通 WRITE_MEM(5)——那条路
 *     走 FOLL_FORCE 强制 COW，语义同 ptrace，绝不会污染页缓存。
 *     注意写的是物理页且不标脏：目标页回收/迁移窗口极小（写全程持
 *     mmap_read_lock），上层写完回读校验即可。
 *
 * 64: 反查杀。载荷 int pid：pid>0 保护该进程——发往它的 SIGKILL/SIGTERM
 *     （含 kill(-pid) 进程组击杀，am force-stop 最终走这里）被吞掉且
 *     syscall 返回 0 伪装成功；pid=0 解除。按需挂 __arm64_sys_kill 的
 *     kprobe——不启用保护时该断点在系统里根本不存在。保护随"设置它的
 *     fd"关闭而自动解除（防 pid 回收后误伤无辜进程）；单槽设计，后设
 *     置覆盖前设置。目标进程退出后应及时 protect(0)。 */
#define NR_LYZ_UNHIDE       62
#define TWT_LYZ_UNHIDE      _IO(TWT_MARK, 62)

#define NR_LYZ_WRITE_V2     63
#define TWT_LYZ_WRITE_V2    _IOW(TWT_MARK, 63, struct twt_request)

#define NR_LYZ_PROTECT      64
#define TWT_LYZ_PROTECT     _IOW(TWT_MARK, 64, int)

#endif /* LYZ_ABI_H */
