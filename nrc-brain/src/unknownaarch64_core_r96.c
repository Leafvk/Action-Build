/* nrc_shadow.c v3.2 — R^X 无痕代码页 + prctl 控制 + BRK#7 无痕断点
 *
 * prctl 接口 (option 0x4e52xx):
 *   0x01 install    (pid, va)               安装 shadow 页 (work 异步)
 *   0x02 patch      (pid, va, 0, inst32)     写 shadow 页 (内核直写)
 *   0x03 activate   (pid, va)                切 shadow 态 (work + stop_machine)
 *   0x04 deactivate (pid, va)                切 orig 态
 *   0x05 release    (pid, va)                释放
 *   0x06 status     (pid, va, &u64)          查询
 *   0x07 bpset      (pid, va, x0_val)        写 BRK#7 + 登记无痕断点 (work + 全核 ic)
 *   0x08 bpdel      (pid, va)                恢复原指令 (work + 全核 ic)
 *
 * 特性: fault 跷跷板 (do_handle_mm_fault) + GUP 隐藏 (__access_remote_vm)
 *       + BRK#7 用户断点 (register_user_break_hook, kallsyms 解析)
 * 生命周期加固: rmmod 先退 break_hook, flush workqueue 后再销毁 (防 unregister-kretprobe race)
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/highmem.h>
#include <linux/stop_machine.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/notifier.h>
#include <linux/smp.h>
#include <asm/pgtable.h>
#include <asm/barrier.h>
#include <asm/debug-monitors.h>
#include <linux/capability.h>
#include <linux/uidgid.h>

#define TAG "NRCSHADOW: "

#define NRC_PR_INSTALL    0x4e5201
#define NRC_PR_PATCH_OFF  0x4e5202
#define NRC_PR_ACTIVATE   0x4e5203
#define NRC_PR_DEACTIVATE 0x4e5204
#define NRC_PR_RELEASE    0x4e5205
#define NRC_PR_STATUS     0x4e5206
#define NRC_PR_BP_SET     0x4e5207
#define NRC_PR_BP_DEL     0x4e5208
#define NRC_PR_PREP       0x4e5209  /* (pid,va) 就位到 shadow rw- */
#define NRC_PR_RETIRE     0x4e520a  /* (pid,va) 退休 -> DORMANT */
#define NRC_PR_SET_TLB    0x4e520b  /* (mode) 设置 TLB flush 策略 */
#define NRC_PR_GET_TLB    0x4e520c  /* (mode*) 读回 TLB flush 策略 */
#define NRC_PR_KREAD      0x4e520d  /* (pid,va,ubuf,len) 页表直译读物理页, 绕过GUP/shadow */

/* P5-E 状态机: ORIG(原始页) / PREP(shadow rw- 待写) / SHADOW(--x 激活) / DORMANT(恢复原页,保留shadow) */
#define NRC_ST_ORIG    0
#define NRC_ST_PREP    1
#define NRC_ST_SHADOW  2
#define NRC_ST_DORMANT 3
#define NRC_ST_STEPPING 4

#define NRC_BRK7     0xD42000E0u
#define NRC_BRK_IMM  7

/* arm64 PTE */
#define NRC_PTE_VALID   (((u64)1) << 0)
#define NRC_PTE_USER    (((u64)1) << 6)
#define NRC_PTE_RDONLY  (((u64)1) << 7)
#define NRC_PTE_UXN     (((u64)1) << 54)
#define NRC_PTE_ADDR    0x0000FFFFFFFFF000ULL

#define NRC_FF_WRITE       0x01
#define NRC_FF_INSTRUCTION 0x100

#define NRC_MAX_SLOTS 64

/* nrc_core v5 — 内核层注入: task_work改pc + SC1(mmap)+SC2(memfd+dlopen) + kprobe(getpid)恢复 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/string.h>
#include <linux/elf.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/task_work.h>
#include <linux/namei.h>
#include <linux/xattr.h>
#include <linux/user_namespace.h>
#include <linux/mnt_idmapping.h>
#include <asm/processor.h>
#define TAG "NRCCORE"

/* ===== P5-D: 统一动作门 ===== */
static int action = 0; module_param(action, int, 0444);
#define NRC_ACTION_NONE    0
#define NRC_ACTION_DEPLOY  3
#define NRC_ACTION_DECRYPT 4
#define NRC_ACTION_CLEAN   5
#define NRC_ACTION_INJECT  6
#define NRC_ACTION_WIPE    7

static unsigned long base = 0;
module_param(base, ulong, 0644);
static unsigned long scanlen = 0;
module_param(scanlen, ulong, 0644);
static char pat[80] = "";
module_param_string(pat, pat, sizeof(pat), 0644);
static int mode = 0;
module_param(mode, int, 0644);
static unsigned long dlbase = 0;
module_param(dlbase, ulong, 0644);
static char sodec[128] = "";
module_param_string(sodec, sodec, sizeof(sodec), 0644);
static unsigned long solen = 0;
module_param(solen, ulong, 0644);
static unsigned long scaddr = 0;
module_param(scaddr, ulong, 0644);
static unsigned long caller = 0;
module_param(caller, ulong, 0644);
/* ===== mode=3: 内核部署参数 ===== */
static char mntpath[160] = ""; module_param_string(mntpath, mntpath, sizeof(mntpath), 0644);
static char dst1[192] = "";    module_param_string(dst1, dst1, sizeof(dst1), 0644);
static char src2[192] = "";    module_param_string(src2, src2, sizeof(src2), 0644);
static char dst2[192] = "";    module_param_string(dst2, dst2, sizeof(dst2), 0644);
static char stpath[160] = "";  module_param_string(stpath, stpath, sizeof(stpath), 0644);
static char ldpath[160] = "";  module_param_string(ldpath, ldpath, sizeof(ldpath), 0644);
static char flist[640] = "";   module_param_string(flist, flist, sizeof(flist), 0644);
static char gctx[96] = "";     module_param_string(gctx, gctx, sizeof(gctx), 0644);
static int guid = 0;           module_param(guid, int, 0644);
/* ===== mode=4: 内核 ChaCha20 解密参数 ===== */
static char chsrc[192] = ""; module_param_string(chsrc, chsrc, sizeof(chsrc), 0644);
static char chdst[192] = ""; module_param_string(chdst, chdst, sizeof(chdst), 0644);
static char chkey[80] = "";  module_param_string(chkey, chkey, sizeof(chkey), 0644);
static char chnon[40] = "";  module_param_string(chnon, chnon, sizeof(chnon), 0644);
/* ===== mode=5: 内核 ACE 清理参数 (逗号分隔路径, 目录递归) ===== */
static char rmpath[2048] = ""; module_param_string(rmpath, rmpath, sizeof(rmpath), 0644);
/* ===== mode=3 扩展: init.lua 占位符替换 (fold into copy) ===== */
static char s1f[80] = ""; module_param_string(s1f, s1f, sizeof(s1f), 0644);
static char s1r[80] = ""; module_param_string(s1r, s1r, sizeof(s1r), 0644);
/* 内核堆分配间接层 (EXPORT 符号, 走 lookup_sym 避免 MODVERSIONS 链接风险) */
static void *(*g_va)(unsigned long, gfp_t);
static void (*g_vfe)(const void *);


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/rcupdate.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/seq_file.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/mount.h>

#define PRFX "KLOG6: "

extern struct task_struct *find_task_by_vpid(pid_t nr);

/* Android 13 apex linker64 文件布局（离线 ELF 解析实测） */
#define GAP_FOFF      0x198070UL  /* 段尾零区起点（本机 linker64 r-x 段尾实测，BuildID 043f6beb） */
#define DLOPEN_FOFF   0x88124UL   /* __loader_dlopen */

/* shellcode 布局（绝对地址 = linker64 r-x base + 偏移） */
#define SC_SLOT_A     0x80   /* u64 __loader_dlopen 绝对地址 */
#define SC_SLOT_B     0x88   /* u64 path 绝对地址 */
#define SC_SLOT_C     0x90   /* u64 caller(libUE4 r-x 起点) */
#define SC_PATH_OFF   0x98   /* path 字符串 */
#define SC_LEN        0x100  /* 写入总长（页尾 0x140 以内） */

#define PAYLOAD_PFX   "libGVoice_" /* 游戏自身天然命名前缀(干净启动已存在)，避免伪系统库名 */

/*
 * ARM64 shellcode v3.3（纯只读执行流；正确 ABI）：
 *   __loader_dlopen(const char* filename, int flags, const void* caller_addr)
 *   -> x0=path, x1=flags, x2=caller（v3.2 曾把 caller 放 x1、flags 放 x2 = 传参错序，
 *      caller=0x2 找不到 linkmap -> namespace 解析失败返回 NULL）
 *   0x00 bti c
 *   0x04 ldr  x9,  [pc,#0x7C]   -> 0x80 dlopen   [0x580003E9]
 *   0x08 ldr  x0,  [pc,#0x80]   -> 0x88 path     [0x58000400]
 *   0x0C mov  w1, #2            RTLD_NOW         [0x52800041]
 *   0x10 ldr  x2,  [pc,#0x80]   -> 0x90 caller   [0x58000402]
 *   0x14 blr  x9                                [0xD63F0120]
 *   0x18 mov  w8, #139          __NR_rt_sigreturn[0x52801168]
 *   0x1C svc  #0                                [0xD4000001]
 * （ARM64 LDR literal: target = 本条指令地址 + imm19*4）
 */
static const u32 scw[] = {
	0xD503245F, 0x580003E9, 0x58000400, 0x52800041,
	0x58000402, 0xD63F0120, 0x52801168, 0xD4000001,
};

static int p_pid;
static int p_sig;
static int wipe;   /* =1: 只擦 gap 不注入 */
static char p_path[176];
module_param(p_pid, int, 0);
module_param(p_sig, int, 0);
module_param(wipe, int, 0);
static int p_sw;
module_param(p_sw, int, 0);  /* 1=restore 前 8s 吞窗 (bridge 注入用) */
module_param_string(path, p_path, sizeof(p_path), 0);

static struct task_struct *s_g_task;   /* group leader，exit 时还原用 */
static struct k_sigaction g_old;
static int g_old_sig;
static bool g_installed;

static const char *vma_name(struct vm_area_struct *v)
{
	if (!v->vm_file)
		return NULL;
	return v->vm_file->f_path.dentry->d_name.name;
}

static int find_named_x_vma(struct mm_struct *mm, const char *want, int prefix,
			    struct vm_area_struct **out)
{
	VMA_ITERATOR(vmi, mm, 0);
	struct vm_area_struct *v;

	for_each_vma(vmi, v) {
		const char *nm = vma_name(v);

		if (!nm || !(v->vm_flags & VM_EXEC))
			continue;
		if (prefix ? !strncmp(nm, want, strlen(want)) : !strcmp(nm, want)) {
			*out = v;
			return 0;
		}
	}
	return -ENOENT;
}

/* payload 加载判定：mm 里出现 libhwui_ 且带 VM_WRITE 的段（= dlopen 成功） */
static int payload_loaded(struct mm_struct *mm)
{
	VMA_ITERATOR(vmi, mm, 0);
	struct vm_area_struct *v;
	int found = 0;

	down_read(&mm->mmap_lock);
	for_each_vma(vmi, v) {
		const char *nm = vma_name(v);

		if (nm && (v->vm_flags & VM_WRITE) && !(v->vm_flags & VM_SHARED) &&
		    !strncmp(nm, PAYLOAD_PFX, strlen(PAYLOAD_PFX))) {
			found = 1;
			break;
		}
	}
	up_read(&mm->mmap_lock);
	return found;
}

/* 选信号投递目标线程：空闲可中断睡眠的非主线程；
 * 排除 main（可能持 dl_mutex）与 Signal Catcher（ART sigchain/sigwait 干扰）。
 * 回退：第一个非主线程 → leader。
 */
static struct task_struct *pick_recipient(struct task_struct *leader)
{
	struct task_struct *t, *any_other = NULL, *pick = NULL;

	rcu_read_lock();
	for_each_thread(leader, t) {
		if (t == leader)
			continue;
		if (!strncmp(t->comm, "Signal Catcher", 14))
			continue;
		if (!any_other)
			any_other = t;
		if ((t->__state & TASK_INTERRUPTIBLE) && !(t->__state & TASK_WAKEKILL)) {
			pick = t;
			break;
		}
	}
	if (pick || any_other)
		get_task_struct(pick ? pick : any_other);
	rcu_read_unlock();

	return pick ? pick : (any_other ? any_other : leader);
}

static void install_handler(struct task_struct *t, int sig, unsigned long gap)
{
	unsigned long fl;
	struct k_sigaction na;

	spin_lock_irqsave(&t->sighand->siglock, fl);
	g_old = t->sighand->action[sig - 1];
	na = g_old;
	na.sa.sa_handler = (__sighandler_t)gap;
	na.sa.sa_flags = 0; /* 走 vdso sigtramp，避免残留 SA_RESTORER 垃圾地址 */
	t->sighand->action[sig - 1] = na;
	spin_unlock_irqrestore(&t->sighand->siglock, fl);
	g_old_sig = sig;
	g_installed = true;
}

static void restore_handler(struct task_struct *t, int sig)
{
	unsigned long fl;

	if (!t || !t->sighand)
		return;
	spin_lock_irqsave(&t->sighand->siglock, fl);
	t->sighand->action[sig - 1] = g_old;
	spin_unlock_irqrestore(&t->sighand->siglock, fl);
	g_installed = false;
}


static unsigned int copy_str(u8 *dst, unsigned int cap, const char *src)
{
	unsigned int i;

	for (i = 0; i + 1 < cap && src[i]; i++)
		dst[i] = (u8)src[i];
	dst[i] = 0;
	return i + 1;
}


typedef long (*avm_t)(struct task_struct *, unsigned long, void *, int, unsigned int);
typedef int (*twa_t)(struct task_struct *, struct callback_head *, enum task_work_notify_mode);
typedef struct file *(*flo_t)(const char *, int, umode_t);
typedef ssize_t (*kr_t)(struct file *, void *, size_t, loff_t *);
typedef int (*fc_t)(struct file *, void *);
static avm_t g_avm;
static twa_t g_twa;
static flo_t g_flo;
static kr_t g_kr;
static fc_t g_fc;
static int (*g_send_sig)(int, struct task_struct *, int);
static ssize_t (*g_kw)(struct file *, const void *, size_t, loff_t *);
static int (*g_kp)(const char *, unsigned, struct path *);
static int (*g_pm)(const char *, struct path *, const char *, unsigned long, void *);
static int (*g_vm)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t);
static struct dentry *(*g_l1)(const char *, struct dentry *, int);
static int (*g_nc)(struct mnt_idmap *, struct dentry *, struct iattr *, struct inode **);
static int (*g_sx)(struct mnt_idmap *, struct dentry *, const char *, const void *, size_t, int);
static __sighandler_t g_old_h;
static struct task_struct *g_task;
static volatile int g_run = 1;
static unsigned long g_hb;
static struct task_struct *g_kthr;



static int mvm_is_victim(struct vm_area_struct *vma);
/* [r96] /proc/PID/map_files entry scrub - NON-SLEEPING design.
 * r95 hooked show_map_vma/show_smap only; map_files entries are emitted by
 * proc_map_files_readdir -> proc_fill_cache -> dir_emit(ctx->actor). At that
 * point the kernel has ALREADY dropped mmap_lock and mmput() the mm, so we
 * must neither sleep nor touch task->mm without our own reference. A kretprobe
 * handler runs with preemption disabled, so down_read() is illegal here
 * (scheduling-while-atomic BUG) and a bare mm->mmap walk is a use-after-free.
 * We therefore match the emitted "<hex>-<hex>" name purely against an in-memory
 * table of injected ranges (zero locks, zero mm access) and swap ctx->actor
 * for a dropping actor when it is one of our payloads. The table is filled:
 *   (1) at init, and (2) lazily on first address-range entry via
 *   task->mm + down_read_trylock() only (both atomic-safe); a lost
 *   trylock simply leaves the previous table in place (never loses a fill).
 * No mmap_lock is ever taken on the hot path. */
#define NRC_PFC_MAX 512
struct nrc_rng { unsigned long s, e; };
static struct nrc_rng nrc_rngs[NRC_PFC_MAX];
static int nrc_nrng;
static int nrc_tbl_built;   /* set once the injected-range table is filled */
static void nrc_rng_reset(void) { nrc_nrng = 0; }
static void nrc_rng_add(unsigned long s, unsigned long e)
{
    int i;
    if (nrc_nrng >= NRC_PFC_MAX) return;
    for (i = 0; i < nrc_nrng; i++)
        if (nrc_rngs[i].s == s && nrc_rngs[i].e == e) return;
    nrc_rngs[nrc_nrng].s = s;
    nrc_rngs[nrc_nrng].e = e;
    nrc_nrng++;
}
static int nrc_pfc_hit(unsigned long s, unsigned long e)
{
    int i;
    for (i = 0; i < nrc_nrng; i++)
        if (nrc_rngs[i].s == s && nrc_rngs[i].e == e) return 1;
    return 0;
}
static int nrc_rng_build_table(struct task_struct *task)
{
    struct mm_struct *mm;
    struct vm_area_struct *v;
    if (!task) return 0;
    /* The readdir caller pins task (and mm_get lands before this emitter
     * path), so task->mm stays live for the walk; trylock never sleeps and a
     * lost race only skips this fill (retried on the next address entry). */
    mm = READ_ONCE(task->mm);
    if (!mm) return 0;
    if (down_read_trylock(&mm->mmap_lock)) {
        unsigned long p;
        VMA_ITERATOR(vmi, mm, 0);
        nrc_rng_reset();
        for_each_vma(vmi, v) {
            if (!v->vm_file) continue;
            if (!mvm_is_victim(v)) continue;
            p = v->vm_end - (((v->vm_flags >> 60) & 0xFUL) << PAGE_SHIFT);
            nrc_rng_add(v->vm_start, p);
        }
        up_read(&mm->mmap_lock);
    }
    return nrc_nrng > 0;
}
struct pfc_save { struct dir_context *ctx; filldir_t orig; };
static bool nrc_drop_filldir(struct dir_context *ctx, const char *name,
                            int namlen, loff_t off, u64 ino, unsigned t)
{
    (void)ctx; (void)name; (void)namlen; (void)off; (void)ino; (void)t;
    return false;
}
static int nrc_addr_range(const char *nm, unsigned long *ps, unsigned long *pe)
{
    unsigned long s = 0, e = 0;
    const char *p = nm;
    int nd = 0;
    if (!p) return 0;
    while (*p) {
        char c = *p;
        if (c >= '0' && c <= '9')      { s = (s << 4) | (unsigned long)(c - '0'); nd++; p++; }
        else if (c >= 'a' && c <= 'f') { s = (s << 4) | (unsigned long)(c - 'a' + 10); nd++; p++; }
        else break;
    }
    if (nd == 0 || *p != '-') return 0;
    p++;
    nd = 0;
    while (*p) {
        char c = *p;
        if (c >= '0' && c <= '9')      { e = (e << 4) | (unsigned long)(c - '0'); nd++; p++; }
        else if (c >= 'a' && c <= 'f') { e = (e << 4) | (unsigned long)(c - 'a' + 10); nd++; p++; }
        else return 0;
    }
    if (nd == 0) return 0;
    *ps = s;
    *pe = e;
    return 1;
}
static int nrc_pfc_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pfc_save *sv = (struct pfc_save *)ri->data;
    struct dir_context *ctx = (void *)regs->regs[1];
    const char *name = (const char *)regs->regs[2];
    struct task_struct *task = (struct task_struct *)regs->regs[5];
    unsigned long s, e;
    sv->ctx = 0;
    sv->orig = 0;
    /* return 1 => skip recording a return instance for non-matching entries,
     * so nrc_pfc_ret only ever runs on the hit path where sv is populated.
     * (A bare return 0 here still registers a ret call, and sv->ctx would be
     *  stale garbage -> fault; that was the panic.) */
    if (!ctx || !name || !task) return 1;
    if (!nrc_addr_range(name, &s, &e)) return 1;
    if (!nrc_tbl_built) {
        if (!nrc_rng_build_table(task)) return 1;  /* trylock lost -> retry next entry */
        nrc_tbl_built = 1;
    }
    if (!nrc_pfc_hit(s, e)) return 1;
    sv->ctx = ctx;
    sv->orig = ctx->actor;
    ctx->actor = nrc_drop_filldir;
    return 0;
}
static int nrc_pfc_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct pfc_save *sv = (struct pfc_save *)ri->data;
    if (sv->ctx && sv->orig && sv->ctx->actor == nrc_drop_filldir)
        sv->ctx->actor = sv->orig;
    return 0;
}
static struct kretprobe krp_pfc = {
    .handler = nrc_pfc_ret,
    .entry_handler = nrc_pfc_entry,
    .kp.symbol_name = "proc_fill_cache",
    .data_size = sizeof(struct pfc_save),
    .maxactive = 512,
};
static unsigned long lookup_sym(const char *name){
    struct kprobe kp = { .symbol_name = name };
    unsigned long addr = 0;
    if (register_kprobe(&kp) == 0){ addr = (unsigned long)kp.addr; unregister_kprobe(&kp); }
    return addr;
}

struct nrc_slot {
    struct mm_struct *mm;
    unsigned long va;
    unsigned long pfn_orig;
    struct page *pg_shadow;
    u64 pte_tmpl;
    int shadow_active;
    int state;          /* P5-E: NRC_ST_* */
    struct list_head list;
};
static LIST_HEAD(g_slots);
static DEFINE_SPINLOCK(g_lock);
static int g_nr;

struct nrc_bp {
    struct mm_struct *mm;
    unsigned long va;
    unsigned long base;
    unsigned long x0_val;
    int reg_idx;        /* P5-E: 命中改哪个通用寄存器 0..30 */
    int step;           /* P5-F②: 1=单步执行原指令(不跳过) */
    u32 orig_inst;
    int active;
    struct list_head list;
};
static LIST_HEAD(g_bps);
static DEFINE_SPINLOCK(g_bp_lock);

static void (*g_register_user_break_hook)(struct break_hook *hook);
static void (*g_unregister_user_break_hook)(struct break_hook *hook);

struct nrc_work {
    struct work_struct w;
    int op;
    struct mm_struct *mm;
    unsigned long va;
    unsigned long arg;
    unsigned long arg2;     /* P5-E: 第二参数 */
    int done;
    int rc;
};
static struct workqueue_struct *nrc_wq;
static int g_tlb_mode = 0;                       /* P5-F①: 0=mm 1=all */
static void (*g_register_user_step_hook)(struct step_hook *);
static void (*g_unregister_user_step_hook)(struct step_hook *);

static struct nrc_slot *nrc_find(struct mm_struct *mm, unsigned long va)
{
    struct nrc_slot *s;
    list_for_each_entry(s, &g_slots, list)
        if (s->mm == mm && s->va == va) return s;
    return NULL;
}

static u64 *nrc_get_pte(struct mm_struct *m, unsigned long va)
{
    pgd_t *pgd; p4d_t *p4d; pud_t *pud; pmd_t *pmd; pte_t *ptep;

    pgd = pgd_offset(m, va);
    if (pgd_none(READ_ONCE(*pgd)) || pgd_bad(READ_ONCE(*pgd))) return NULL;
    p4d = p4d_offset(pgd, va);
    if (p4d_none(READ_ONCE(*p4d)) || p4d_bad(READ_ONCE(*p4d))) return NULL;
    pud = pud_offset(p4d, va);
    if (pud_none(READ_ONCE(*pud)) || pud_bad(READ_ONCE(*pud))) return NULL;
    pmd = pmd_offset(pud, va);
    if (pmd_none(READ_ONCE(*pmd)) || pmd_bad(READ_ONCE(*pmd))) return NULL;
    ptep = pte_offset_map(pmd, va);
    if (!ptep) return NULL;
    if (pte_none(READ_ONCE(*ptep))) { pte_unmap(ptep); return NULL; }
    return (u64 *)ptep;
}

/* NRC_PR_KREAD: 页表直译读物理页——绕过 __access_remote_vm/GUP 的 shadow 隐藏 */
static long nrc_kread_mm(struct mm_struct *mm, unsigned long va, char __user *ubuf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        unsigned long cur = va + done;
        size_t pg_off = cur & ~PAGE_MASK;
        size_t n = PAGE_SIZE - pg_off;
        u64 *ptep; u64 pte; unsigned long pa; struct page *pg; void *kp;
        if (n > len - done) n = len - done;
        ptep = nrc_get_pte(mm, cur);
        if (!ptep) break;
        pte = READ_ONCE(*ptep);
        pa = pte & NRC_PTE_ADDR;
        pte_unmap((pte_t *)ptep);
        if (!pa) break;
        /* [FIX2] 强校验：pfn 必须合法，且 page_address 结果必须落
         * 在 arm64 线性映射区 [0xffffff8000000000, +128TB)。否则特殊页
         * (vmalloc/设备/保留 pfn) 会返回无效地址导致 copy_to_user 源 fault panic。 */
        pg = pfn_to_page(pa >> PAGE_SHIFT);
        if (!pg) break;
        kp = page_address(pg);
        if (!kp) break;
        /* arm64 线性映射从 0xffffff8000000000 开始。只检查下界（避免相加溢出）。 */
        if ((unsigned long)kp < 0xffffff8000000000UL) break;
        /* copy_to_user 只读源地址，源已经过 pfn_valid + 线性区校验，
         * 目标（ubuf）是 prctl 参数指向的用户缓冲，由 copy_to_user 自带的
         * uaccess 保护处理（不会 Oops，失败返非零）。 */
        if (copy_to_user(ubuf + done, (char *)kp + pg_off, n))
            return done ? (long)done : -EFAULT;
        done += n;
    }
    return (long)done;
}
static void nrc_write_pte_raw(struct mm_struct *m, unsigned long va, u64 val)
{
    u64 *p = nrc_get_pte(m, va);
    if (!p) return;
    WRITE_ONCE(*p, val);
    dsb(ishst);
    pte_unmap((pte_t *)p);
}

static void nrc_tlb_flush_va(struct mm_struct *m, unsigned long va)
{
    if (g_tlb_mode == 1) flush_tlb_all();   /* P5-F①: 更暴力策略 */
    else flush_tlb_mm(m);
}

static u64 nrc_pte_shadow_exec(struct nrc_slot *s)
{
    u64 pte = (s->pte_tmpl & ~NRC_PTE_ADDR) | ((u64)page_to_pfn(s->pg_shadow) << PAGE_SHIFT);
    pte |= NRC_PTE_RDONLY;
    pte &= ~NRC_PTE_UXN;
    pte &= ~NRC_PTE_USER;
    return pte;
}

static u64 nrc_pte_orig_readable(struct nrc_slot *s)
{
    u64 pte = (s->pte_tmpl & ~NRC_PTE_ADDR) | (s->pfn_orig << PAGE_SHIFT);
    pte |= NRC_PTE_RDONLY | NRC_PTE_UXN | NRC_PTE_USER;
    return pte;
}

/* P5-E: shadow rw- (用户态可写待命, 不可执行) */
static u64 nrc_pte_shadow_rw(struct nrc_slot *s)
{
    u64 pte = (s->pte_tmpl & ~NRC_PTE_ADDR) | ((u64)page_to_pfn(s->pg_shadow) << PAGE_SHIFT);
    pte &= ~NRC_PTE_RDONLY;
    pte |= NRC_PTE_UXN;
    pte |= NRC_PTE_USER;
    return pte;
}

static void nrc_sync_icache(void *kaddr, size_t len)
{
    unsigned long ca, b, e;
    b = (unsigned long)kaddr & ~((unsigned long)SMP_CACHE_BYTES - 1);
    e = ((unsigned long)kaddr + len + SMP_CACHE_BYTES - 1) & ~((unsigned long)SMP_CACHE_BYTES - 1);
    for (ca = b; ca < e; ca += SMP_CACHE_BYTES)
        asm volatile("dc cvau, %0" :: "r"(ca) : "memory");
    dsb(ishst);
    for (ca = b; ca < e; ca += SMP_CACHE_BYTES)
        asm volatile("ic ivau, %0" :: "r"(ca) : "memory");
    dsb(ishst);
    isb();
}

struct nrc_icarg { void *addr; size_t len; };
static void nrc_ic_flush_cpu(void *info)
{
    struct nrc_icarg *a = info;
    nrc_sync_icache(a->addr, a->len);
}

static void nrc_patch_shadow_sync(struct nrc_slot *s, size_t off, u32 inst)
{
    void *dst;
    struct nrc_icarg a;
    if (off + 4 > PAGE_SIZE) return;
    dst = kmap_local_page(s->pg_shadow);
    *(u32 *)((char *)dst + off) = inst;
    a.addr = (char *)dst + off;
    a.len = 4;
    kunmap_local(dst);
    on_each_cpu(nrc_ic_flush_cpu, &a, 1);
}

static void nrc_do_patch_locked(struct nrc_slot *s, size_t off, u32 inst)
{
    void *dst;
    if (off + 4 > PAGE_SIZE) return;
    dst = kmap_local_page(s->pg_shadow);
    *(u32 *)((char *)dst + off) = inst;
    nrc_sync_icache((char *)dst + off, 4);
    kunmap_local(dst);
}

static void nrc_switch_pte(struct mm_struct *mm, unsigned long va, u64 pte)
{
    nrc_write_pte_raw(mm, va, pte);
    nrc_tlb_flush_va(mm, va);
}

struct sw_arg { struct mm_struct *mm; unsigned long va; u64 pte; };
static int nrc_sm_switch_fn(void *data)
{
    struct sw_arg *sw = data;
    nrc_write_pte_raw(sw->mm, sw->va, sw->pte);
    nrc_tlb_flush_va(sw->mm, sw->va);
    return 0;
}

/* BRK#7 断点 hook: 匹配 (esr&0xffff)==imm7, 命中改 x0 并跳过 BRK */
static int nrc_bp_hook(struct pt_regs *regs, unsigned long esr)
{
    struct nrc_bp *bp;
    unsigned long pc = regs->pc;
    unsigned long f;
    int hit = 0;
    unsigned int imm = esr & 0xffffu;   /* ESR ISS comment 在低16位, 非移位 */

    if (imm != NRC_BRK_IMM)
        return -1;

    spin_lock_irqsave(&g_bp_lock, f);
    list_for_each_entry(bp, &g_bps, list) {
        if (bp->active && bp->va == pc && bp->mm == current->mm) {
            if (bp->reg_idx >= 0 && bp->reg_idx <= 30)
                regs->regs[bp->reg_idx] = bp->x0_val;
            else
                regs->regs[0] = bp->x0_val;
            if (bp->step) {
                struct nrc_slot *ss;
                spin_lock_irqsave(&g_lock, f);
                ss = nrc_find(bp->mm, bp->base);
                if (ss) { nrc_write_pte_raw(bp->mm, bp->base, ss->pte_tmpl); nrc_tlb_flush_va(bp->mm, bp->base); ss->shadow_active = 0; ss->state = NRC_ST_STEPPING; }
                spin_unlock_irqrestore(&g_lock, f);
                regs->pstate |= DBG_SPSR_SS;
                set_thread_flag(TIF_SINGLESTEP);
            } else {
                regs->pc = pc + 4;
            }
            hit = 1;
            break;
        }
    }
    spin_unlock_irqrestore(&g_bp_lock, f);
    return hit ? 0 : -1;
}

static struct break_hook nrc_break_hook = {
    .fn = nrc_bp_hook,
    .imm = NRC_BRK_IMM,
    .mask = 0,   /* 匹配是 (comment & ~mask)==imm; mask=0 → 精确匹配 imm16=7 */
};

/* P5-F②: 单步 handler — 原指令执行完后切回 shadow 并清 SS */
static int nrc_step_hook(struct pt_regs *regs, unsigned long esr)
{
    struct nrc_bp *bp;
    struct nrc_slot *s;
    unsigned long pc = regs->pc, f;
    int hit = 0;

    (void)esr;
    spin_lock_irqsave(&g_bp_lock, f);
    list_for_each_entry(bp, &g_bps, list) {
        if (bp->active && bp->step && bp->mm == current->mm &&
            pc == (bp->va + 4)) { hit = 1; break; }
    }
    spin_unlock_irqrestore(&g_bp_lock, f);
    if (!hit) return 1;   /* DBG_HOOK_ERROR: 非本模块引发的单步 */
    spin_lock_irqsave(&g_lock, f);
    s = nrc_find(bp->mm, bp->base);
    if (s) { nrc_write_pte_raw(bp->mm, bp->base, nrc_pte_shadow_exec(s)); nrc_tlb_flush_va(bp->mm, bp->base); s->shadow_active = 1; s->state = NRC_ST_SHADOW; }
    spin_unlock_irqrestore(&g_lock, f);
    regs->pstate &= ~DBG_SPSR_SS;
    clear_thread_flag(TIF_SINGLESTEP);   /* 关单步 */
    return 0;
}

static struct step_hook nrc_step_hook_s = {
    .fn = nrc_step_hook,
};

static void nrc_work_fn(struct work_struct *w)
{
    struct nrc_work *nw = container_of(w, struct nrc_work, w);
    struct nrc_slot *s;
    unsigned long flags;
    int rc = -ENOENT;

    switch (nw->op) {
    case 1: { /* install */
        u64 pte = 0;
        void *so, *oo;
        struct page *op;
        struct nrc_slot *ns;
        u64 *p;

        p = nrc_get_pte(nw->mm, nw->va);
        if (!p) { rc = -EFAULT; break; }
        pte = READ_ONCE(*p);
        pte_unmap((pte_t *)p);
        if (!(pte & NRC_PTE_VALID)) { rc = -EFAULT; break; }

        spin_lock_irqsave(&g_lock, flags);
        if (nrc_find(nw->mm, nw->va)) { spin_unlock_irqrestore(&g_lock, flags); rc = -EEXIST; break; }
        if (g_nr >= NRC_MAX_SLOTS) { spin_unlock_irqrestore(&g_lock, flags); rc = -ENOSPC; break; }
        spin_unlock_irqrestore(&g_lock, flags);

        ns = kzalloc(sizeof(*ns), GFP_KERNEL);
        if (!ns) { rc = -ENOMEM; break; }
        ns->mm = nw->mm;
        ns->va = nw->va;
        ns->pte_tmpl = pte;
        ns->pfn_orig = (pte & NRC_PTE_ADDR) >> PAGE_SHIFT;
        ns->pg_shadow = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if (!ns->pg_shadow) { kfree(ns); rc = -ENOMEM; break; }
        mmgrab(nw->mm);   /* P5-E: 持 mm_count, 不阻 exit_mmap */

        so = kmap_local_page(ns->pg_shadow);
        op = pfn_to_page(ns->pfn_orig);
        oo = kmap_local_page(op);
        memcpy(so, oo, PAGE_SIZE);
        nrc_sync_icache(so, PAGE_SIZE);
        kunmap_local(oo);
        kunmap_local(so);

        spin_lock_irqsave(&g_lock, flags);
        list_add(&ns->list, &g_slots);
        g_nr++;
        spin_unlock_irqrestore(&g_lock, flags);
        rc = 0;
        pr_info(TAG "install va=%lx orig_pfn=%lx shadow_pfn=%lx\n",
                nw->va, ns->pfn_orig, page_to_pfn(ns->pg_shadow));
        break;
    }
    case 2: { /* activate */
        struct sw_arg sw;
        int found = 0;
        spin_lock_irqsave(&g_lock, flags);
        s = nrc_find(nw->mm, nw->va);
        if (s) { sw.mm = nw->mm; sw.va = s->va; sw.pte = nrc_pte_shadow_exec(s); found = 1; }
        spin_unlock_irqrestore(&g_lock, flags);
        if (!found) { rc = -ENOENT; break; }
        stop_machine(nrc_sm_switch_fn, &sw, NULL);
        spin_lock_irqsave(&g_lock, flags);
        if (s) { s->shadow_active = 1; s->state = NRC_ST_SHADOW; }
        spin_unlock_irqrestore(&g_lock, flags);
        rc = 0;
        pr_info(TAG "activate va=%lx (--x)\n", nw->va);
        break;
    }
    case 3: { /* deactivate */
        struct sw_arg sw;
        int found = 0;
        spin_lock_irqsave(&g_lock, flags);
        s = nrc_find(nw->mm, nw->va);
        if (s) { sw.mm = nw->mm; sw.va = s->va; sw.pte = nrc_pte_orig_readable(s); found = 1; }
        spin_unlock_irqrestore(&g_lock, flags);
        if (!found) { rc = -ENOENT; break; }
        stop_machine(nrc_sm_switch_fn, &sw, NULL);
        spin_lock_irqsave(&g_lock, flags);
        if (s) { s->shadow_active = 0; s->state = NRC_ST_ORIG; }
        spin_unlock_irqrestore(&g_lock, flags);
        rc = 0;
        break;
    }
    case 4: { /* release */
        int found = 0;
        spin_lock_irqsave(&g_lock, flags);
        list_for_each_entry(s, &g_slots, list) {
            if (s->mm == nw->mm && s->va == nw->va) { list_del(&s->list); g_nr--; found = 1; break; }
        }
        spin_unlock_irqrestore(&g_lock, flags);
        if (!found) { rc = -ENOENT; break; }
        nrc_switch_pte(nw->mm, nw->va, s->pte_tmpl);
        __free_page(s->pg_shadow);
        kfree(s);
        mmdrop(nw->mm);
        rc = 0;
        pr_info(TAG "release va=%lx\n", nw->va);
        break;
    }
    case 7: { /* P5-E prep: 切 shadow rw- 待命 */
        struct sw_arg sw;
        int found = 0;
        spin_lock_irqsave(&g_lock, flags);
        s = nrc_find(nw->mm, nw->va);
        if (s) { sw.mm = nw->mm; sw.va = s->va; sw.pte = nrc_pte_shadow_rw(s); found = 1; }
        spin_unlock_irqrestore(&g_lock, flags);
        if (!found) { rc = -ENOENT; break; }
        stop_machine(nrc_sm_switch_fn, &sw, NULL);
        spin_lock_irqsave(&g_lock, flags);
        if (s) { s->state = NRC_ST_PREP; s->shadow_active = 1; }
        spin_unlock_irqrestore(&g_lock, flags);
        rc = 0;
        pr_info(TAG "prep va=%lx (rw-)\n", nw->va);
        break;
    }
    case 8: { /* P5-E retire: 恢复原始页, 保留 shadow -> DORMANT */
        struct sw_arg sw;
        int found = 0;
        spin_lock_irqsave(&g_lock, flags);
        s = nrc_find(nw->mm, nw->va);
        if (s) { sw.mm = nw->mm; sw.va = s->va; sw.pte = s->pte_tmpl; found = 1; }
        spin_unlock_irqrestore(&g_lock, flags);
        if (!found) { rc = -ENOENT; break; }
        stop_machine(nrc_sm_switch_fn, &sw, NULL);
        spin_lock_irqsave(&g_lock, flags);
        if (s) { s->state = NRC_ST_DORMANT; s->shadow_active = 0; }
        spin_unlock_irqrestore(&g_lock, flags);
        rc = 0;
        pr_info(TAG "retire va=%lx -> DORMANT\n", nw->va);
        break;
    }
    case 5: { /* bpset */
        struct nrc_slot *sl = NULL;
        size_t off = (size_t)(nw->va & ~PAGE_MASK);
        u32 orig_inst = 0;
        spin_lock_irqsave(&g_lock, flags);
        list_for_each_entry(sl, &g_slots, list)
            if (sl->mm == nw->mm && sl->va == (nw->va & PAGE_MASK)) break;
        spin_unlock_irqrestore(&g_lock, flags);
        if (!sl || sl->mm != nw->mm || sl->va != (nw->va & PAGE_MASK)) { rc = -ENOENT; break; }
        {
            void *dst = kmap_local_page(sl->pg_shadow);
            orig_inst = *(u32 *)((char *)dst + off);
            kunmap_local(dst);
        }
        nrc_patch_shadow_sync(sl, off, NRC_BRK7);
        {
            struct nrc_bp *nb = kzalloc(sizeof(*nb), GFP_KERNEL);
            if (!nb) { rc = -ENOMEM; break; }
            nb->mm = nw->mm; nb->va = nw->va; nb->base = nw->va & PAGE_MASK;
            nb->x0_val = nw->arg; nb->reg_idx = (int)(nw->arg2 & 0x3f);
            nb->step = (int)((nw->arg2 >> 6) & 1);
            nb->orig_inst = orig_inst; nb->active = 1;
            spin_lock_irqsave(&g_bp_lock, flags);
            list_add(&nb->list, &g_bps);
            spin_unlock_irqrestore(&g_bp_lock, flags);
            pr_info(TAG "bpset va=%lx x0=%lx orig=%08x\n", nw->va, nw->arg, orig_inst);
            rc = 0;
        }
        break;
    }
    case 6: { /* bpdel */
        struct nrc_slot *sl = NULL;
        struct nrc_bp *nb, *tmp;
        size_t off = (size_t)(nw->va & ~PAGE_MASK);
        u32 restore = 0;
        spin_lock_irqsave(&g_bp_lock, flags);
        list_for_each_entry_safe(nb, tmp, &g_bps, list) {
            if (nb->mm == nw->mm && nb->va == nw->va) {
                restore = nb->orig_inst; list_del(&nb->list); kfree(nb); break;
            }
        }
        spin_unlock_irqrestore(&g_bp_lock, flags);
        if (!restore) { rc = -ENOENT; break; }
        spin_lock_irqsave(&g_lock, flags);
        list_for_each_entry(sl, &g_slots, list)
            if (sl->mm == nw->mm && sl->va == (nw->va & PAGE_MASK)) break;
        spin_unlock_irqrestore(&g_lock, flags);
        if (!sl || sl->mm != nw->mm) { rc = -ENOENT; break; }
        nrc_patch_shadow_sync(sl, off, restore);
        pr_info(TAG "bpdel va=%lx restore=%08x\n", nw->va, restore);
        rc = 0;
        break;
    }
    }
    nw->rc = rc;
    mmput(nw->mm);
    smp_wmb();
    nw->done = 1;
}

/* prctl hook */
struct prctl_saved {
    unsigned long opt;
    long a2;
    unsigned long a3, a4, a5;
    int matched;
};

static int nrc_prctl_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct prctl_saved *ps = (struct prctl_saved *)ri->data;
    struct pt_regs *uregs = (struct pt_regs *)regs->regs[0];
    unsigned long opt, a3, a4, a5;
    long a2;

    if (!uregs) return 1;
    opt = uregs->regs[0];
    if (opt < NRC_PR_INSTALL || opt > NRC_PR_KREAD) return 1;
    a2 = (long)uregs->regs[1];
    a3 = uregs->regs[2];
    a4 = uregs->regs[3];
    a5 = uregs->regs[4];

    ps->opt = opt; ps->a2 = a2; ps->a3 = a3; ps->a4 = a4; ps->a5 = a5;
    ps->matched = 1;
    return 0;
}

static struct mm_struct *nrc_get_mm(long pid)
{
    struct task_struct *t;
    struct mm_struct *mm = NULL;
    rcu_read_lock();
    t = find_task_by_vpid((pid_t)pid);
    if (t) get_task_struct(t);
    rcu_read_unlock();
    if (!t) return NULL;
    mm = t->mm;
    if (mm) mmget(mm);
    put_task_struct(t);
    return mm;
}

static int nrc_prctl_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct prctl_saved *ps = (struct prctl_saved *)ri->data;
    struct nrc_slot *s;
    unsigned long flags;
    int rc = 0;

    if (!ps->matched) return 0;

    if (ps->opt == NRC_PR_PATCH_OFF) {
        unsigned long base = ps->a3 & PAGE_MASK;
        size_t off = (size_t)((ps->a3 & ~PAGE_MASK) + ps->a4);
        spin_lock_irqsave(&g_lock, flags);
        list_for_each_entry(s, &g_slots, list) {
            if (s->va == base) {
                u32 *sp, cur;
                nrc_do_patch_locked(s, off, (u32)ps->a5);
                sp = kmap_local_page(s->pg_shadow);
                cur = *(u32 *)((char *)sp + off);
                kunmap_local(sp);
                pr_info(TAG "patch_off va=%lx off=%zu write=%08x readback=%08x %s\n",
                        base, off, (u32)ps->a5, cur, cur == (u32)ps->a5 ? "OK" : "MISMATCH");
                rc = 0;
                break;
            }
        }
        spin_unlock_irqrestore(&g_lock, flags);
        regs->regs[0] = (unsigned long)rc;
        return 0;
    }

    if (ps->opt == NRC_PR_SET_TLB) { g_tlb_mode = (int)ps->a3; pr_info(TAG "set tlb_mode=%d\n", g_tlb_mode); regs->regs[0] = 0; return 0; }
    if (ps->opt == NRC_PR_GET_TLB) {
        if (put_user((int)g_tlb_mode, (int __user *)ps->a3)) { regs->regs[0] = -EFAULT; return 0; }
        regs->regs[0] = 0; return 0;
    }

    if (ps->opt == NRC_PR_KREAD) {
        struct mm_struct *kmm = nrc_get_mm(ps->a2);
        long r;
        if (!kmm) { regs->regs[0] = -ESRCH; return 0; }
        r = nrc_kread_mm(kmm, ps->a3, (char __user *)ps->a4, (size_t)ps->a5);
        mmput(kmm);
        regs->regs[0] = (unsigned long)r;
        return 0;
    }
    if (ps->opt == NRC_PR_STATUS) {
        u64 st = 0;
        int found = 0;
        struct mm_struct *tmm = nrc_get_mm(ps->a2);
        if (!tmm) { regs->regs[0] = -ESRCH; return 0; }
        spin_lock_irqsave(&g_lock, flags);
        list_for_each_entry(s, &g_slots, list) {
            if (s->mm == tmm && s->va == (ps->a3 & PAGE_MASK)) {
                st = 1; if (s->shadow_active) st |= 2; found = 1; break;
            }
        }
        spin_unlock_irqrestore(&g_lock, flags);
        mmput(tmm);
        if (!found) { regs->regs[0] = -ENOENT; return 0; }
        if (put_user(st, (u64 __user *)ps->a4)) { regs->regs[0] = -EFAULT; return 0; }
        regs->regs[0] = 0;
        return 0;
    }

    {
        struct nrc_work *nw;
        struct mm_struct *mm = nrc_get_mm(ps->a2);
        int op = 0;
        if (!mm) { regs->regs[0] = -ESRCH; return 0; }
        if (ps->opt == NRC_PR_INSTALL) op = 1;
        else if (ps->opt == NRC_PR_ACTIVATE) op = 2;
        else if (ps->opt == NRC_PR_DEACTIVATE) op = 3;
        else if (ps->opt == NRC_PR_RELEASE) op = 4;
        else if (ps->opt == NRC_PR_BP_SET) op = 5;
        else if (ps->opt == NRC_PR_BP_DEL) op = 6;
        else if (ps->opt == NRC_PR_PREP) op = 7;
        else if (ps->opt == NRC_PR_RETIRE) op = 8;
        nw = kmalloc(sizeof(*nw), GFP_ATOMIC);
        if (!nw) { mmput(mm); regs->regs[0] = -ENOMEM; return 0; }
        INIT_WORK(&nw->w, nrc_work_fn);
        nw->op = op;
        nw->mm = mm;
        nw->va = (op == 5 || op == 6) ? ps->a3 : (ps->a3 & PAGE_MASK);
        nw->arg = ps->a4;
        nw->arg2 = ps->a5;
        nw->done = 0;
        nw->rc = 0;
        queue_work(nrc_wq, &nw->w);
        regs->regs[0] = 0;
        return 0;
    }
}

static struct kretprobe krp_prctl = {
    .handler = nrc_prctl_ret,
    .entry_handler = nrc_prctl_entry,
    .kp.symbol_name = "__arm64_sys_prctl",
    .data_size = sizeof(struct prctl_saved),
    .maxactive = 64,
};

static int kfault_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct vm_area_struct *vma = (void *)regs->regs[0];
    unsigned long addr = regs->regs[1];
    unsigned int flags = (unsigned int)regs->regs[2];
    struct mm_struct *mm;
    struct nrc_slot *s;
    unsigned long a, f;

    if (!vma) return 0;
    mm = vma->vm_mm;
    if (!mm) return 0;
    a = addr & PAGE_MASK;

    spin_lock_irqsave(&g_lock, f);
    s = nrc_find(mm, a);
    if (s && (s->state == NRC_ST_PREP || s->state == NRC_ST_DORMANT || s->state == NRC_ST_STEPPING)) {
        spin_unlock_irqrestore(&g_lock, f);
        return 0;   /* P5-E: PREP/DORMANT 期间不跷跷板 */
    }
    if (s) {
        if (flags & NRC_FF_WRITE) {
            nrc_write_pte_raw(mm, a, s->pte_tmpl);
            nrc_tlb_flush_va(mm, a);
            s->shadow_active = 0;
        } else if (flags & NRC_FF_INSTRUCTION) {
            nrc_write_pte_raw(mm, a, nrc_pte_shadow_exec(s));
            nrc_tlb_flush_va(mm, a);
            s->shadow_active = 1;
        } else {
            nrc_write_pte_raw(mm, a, nrc_pte_orig_readable(s));
            nrc_tlb_flush_va(mm, a);
            s->shadow_active = 0;
        }
    }
    spin_unlock_irqrestore(&g_lock, f);
    return 0;
}

static struct kprobe kp_fault = {
    .symbol_name = "do_handle_mm_fault",
    .pre_handler = kfault_pre,
};

static int kaccess_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct mm_struct *mm = (void *)regs->regs[0];
    struct nrc_slot *s;
    unsigned long f;

    if (!mm) return 1;
    *(struct mm_struct **)ri->data = mm;
    spin_lock_irqsave(&g_lock, f);
    list_for_each_entry(s, &g_slots, list) {
        if (s->mm == mm && s->shadow_active &&
            s->state != NRC_ST_PREP && s->state != NRC_ST_DORMANT && s->state != NRC_ST_STEPPING) {
            nrc_write_pte_raw(mm, s->va, nrc_pte_orig_readable(s));
            s->shadow_active = 0;
        }
    }
    spin_unlock_irqrestore(&g_lock, f);
    return 0;
}

static int kaccess_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct mm_struct *mm = *(struct mm_struct **)ri->data;
    struct nrc_slot *s;
    unsigned long f;

    if (!mm) return 0;
    spin_lock_irqsave(&g_lock, f);
    list_for_each_entry(s, &g_slots, list) {
        if (s->mm == mm && !s->shadow_active &&
            s->state != NRC_ST_PREP && s->state != NRC_ST_DORMANT && s->state != NRC_ST_STEPPING) {
            nrc_write_pte_raw(mm, s->va, nrc_pte_shadow_exec(s));
            s->shadow_active = 1;
        }
    }
    spin_unlock_irqrestore(&g_lock, f);
    return 0;
}

static struct kretprobe krp_access = {
    .handler = kaccess_ret,
    .entry_handler = kaccess_entry,
    .kp.symbol_name = "__access_remote_vm",
    .data_size = sizeof(struct mm_struct *),
    .maxactive = 32,
};

/* ============================================================
 * 输出层隐形: kretprobe seq_file_path (EXPORT_SYMBOL)
 * show_map_vma() 对带 vm_file 的 vma 调 seq_file_path(m,file,"\n")
 * -> 本层在输出时刻把命中标记的整段路径改写为 fake_path
 * 不改 dentry / 不动挂载表 / 不 umount -> 磁盘与挂载层零痕迹
 * ============================================================ */
static char fake_path[160] = "";
module_param_string(fake_path, fake_path, sizeof(fake_path), 0644);
static char hide_mark[64] = ".cache_";
module_param_string(hide_mark, hide_mark, sizeof(hide_mark), 0644);
static char hide_mark2[64] = "nrc_rostr";
module_param_string(hide_mark2, hide_mark2, sizeof(hide_mark2), 0644);

struct sfp_save {
    struct seq_file *m;
    size_t start;
};

static int sfp_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct seq_file *m = (void *)regs->regs[0];
    struct sfp_save *sv = (struct sfp_save *)ri->data;
    sv->m = m;
    sv->start = (m && m->buf) ? m->count : 0;
    return 0;
}

static int sfp_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sfp_save *sv = (struct sfp_save *)ri->data;
    struct seq_file *m = sv->m;
    size_t start = sv->start;
    size_t len, i, fl;
    char *p;
    if (!m || !m->buf || !fake_path[0]) return 0;
    if (m->count <= start) return 0;
    len = m->count - start;
    p = m->buf + start;
    fl = strlen(fake_path);
    if (start + fl + 1 > m->size) return 0;
    for (i = 0; i + 1 < len; i++) {
        int hit = 0;
        if (hide_mark[0] && i + strlen(hide_mark) <= len &&
            !strncmp(p + i, hide_mark, strlen(hide_mark))) hit = 1;
        else if (hide_mark2[0] && i + strlen(hide_mark2) <= len &&
                 !strncmp(p + i, hide_mark2, strlen(hide_mark2))) {
            if (i + 7 <= len && !strncmp(p + i, "nrc_log", 7)) continue; /* 游戏自身日志 */
            hit = 1;
        }
        if (hit) { memcpy(p, fake_path, fl); m->count = start + fl; break; }
    }
    return 0;
}

static struct kretprobe krp_sfp = {
    .handler = sfp_ret,
    .entry_handler = sfp_entry,
    .kp.symbol_name = "seq_path",
    .data_size = sizeof(struct sfp_save),
    .maxactive = 128,
};

/* ============================================================
 * 输出层隐形②: kretprobe d_path (EXPORT_SYMBOL)
 * d_path() 是 seq_path() 的底层; /proc/PID/map_files/<rng> 经
 * map_files_get_link -> d_path() 直出, 不经 seq_path。
 * 在返回点把命中标记的路径改写/收缩:
 *   - 空间够 -> 写 fake_path
 *   - 空间不够 -> 就地删掉 ".mnt_xxxx" 目录段 (仅缩短, 绝不越界)
 * 只在 path 落在 tmpfs 且 dentry 链含标记时激活 (防高频开销)
 * ============================================================ */
#define NRC_TMPFS_MAGIC 0x01021994

struct dpath_save {
    char *buf;
    int   buflen;
};

/* R90CACHE_BEGIN */
#define NRC_MC_BITS  10
#define NRC_MC_SIZE  (1u << NRC_MC_BITS)
struct nrc_mark_ent {
    const void *d;
    const void *nm;
    const void *par;
    short       res;
};
static struct nrc_mark_ent nrc_mc[NRC_MC_SIZE] __read_mostly;

static inline unsigned nrc_mc_slot(const void *d)
{
    unsigned long k = (unsigned long)d;
    k ^= k >> 16; k ^= k >> 33; k *= 0xff51afd7ed558ccdUL; k ^= k >> 29;
    return (unsigned)(k & (NRC_MC_SIZE - 1));
}

static int nrc_dentry_has_mark(struct dentry *d);

static inline int nrc_dentry_mark_cached(struct dentry *d)
{
    unsigned ix;
    struct nrc_mark_ent *e;
    int r;
    if (!d) return 0;
    ix = nrc_mc_slot(d);
    e = &nrc_mc[ix];
    if (e->d == d && e->nm == (const void *)d->d_name.name &&
        e->par == (const void *)d->d_parent)
        return e->res;
    r = nrc_dentry_has_mark(d);
    e->d = d;
    e->nm = (const void *)d->d_name.name;
    e->par = (const void *)d->d_parent;
    e->res = (short)r;
    return r;
}
/* R90CACHE_END */

static int nrc_dentry_has_mark(struct dentry *d)
{
    int depth = 0;
    while (d && depth++ < 10) {
        const unsigned char *nm = d->d_name.name;
        if (nm) {
            if (hide_mark[0]  && strstr((char *)nm, hide_mark))  return 1;
            if (hide_mark2[0] && strstr((char *)nm, hide_mark2)) {
                /* [r96] exempt game's own nrc_log_* files (no false stat tell) */
                if (!(nm[0]=='n'&&nm[1]=='r'&&nm[2]=='c'&&nm[3]=='_'&&
                      nm[4]=='l'&&nm[5]=='o'&&nm[6]=='g'))
                    return 1;
            }
        }
        if (d == d->d_parent) break;
        d = d->d_parent;
    }
    return 0;
}

static int dpath_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct dpath_save *sv = (struct dpath_save *)ri->data;
    struct path *path = (void *)regs->regs[0];
    if (!fake_path[0]) return 1;
    if (!path || !path->mnt || !path->dentry) return 1;
    /* v4.5: 去掉 tmpfs 过滤 — nrc_* 载荷落在 /data (非 tmpfs) 也需覆盖 map_files/fd */
    sv->buf    = (void *)regs->regs[1];
    sv->buflen = (int)regs->regs[2];
    return 0;
}

static int dpath_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct dpath_save *sv = (struct dpath_save *)ri->data;
    char *rp = (void *)regs->regs[0];
    size_t olen, fl, i, ml, ml2, avail, off, mi = 0, mi2 = 0;
    int found = 0, found2 = 0;
    if (!rp || !sv->buf || sv->buflen <= 0) return 0;
    if (rp < sv->buf) return 0;
    off = (size_t)(rp - sv->buf);
    if (off >= (size_t)sv->buflen) return 0;
    avail = (size_t)sv->buflen - off;
    olen = strnlen(rp, avail < 255 ? avail : 255);
    if (olen == 0 || olen >= 255) return 0;
    fl  = strlen(fake_path);
    ml  = strlen(hide_mark);
    ml2 = strlen(hide_mark2);
    for (i = 0; i + 1 < olen; i++) {
        if (!found  && ml  && i + ml  <= olen && !strncmp(rp + i, hide_mark,  ml )) { mi  = i; found  = 1; }
        if (!found2 && ml2 && i + ml2 <= olen && !strncmp(rp + i, hide_mark2, ml2)) { mi2 = i; found2 = 1; }
    }
    if (!found && !found2) return 0;
    /* 排除游戏自身日志 nrc_log_ (非我方产物, 不隐藏) */
    if (found2 && !found && mi2 + 7 <= olen && !strncmp(rp + mi2, "nrc_log", 7)) return 0;
    /* v4.5 首选: 利用 rp 前的空闲区写完整 fake_path, 改返回值指向它 (map_files/maps 路径一致) */
    if (off >= fl + 1) {
        char *np = rp - (fl + 1);
        memcpy(np, fake_path, fl + 1);
        regs->regs[0] = (unsigned long)np;
        return 0;
    }
    if (fl + 1 <= avail) {                       /* 次选: 原地写 fake */
        memcpy(rp, fake_path, fl + 1);
        return 0;
    }
    if (found) {   /* .mnt_ 目录段: 就地删除 "/<markdir>" 段 (仅缩短) */
        size_t a, b, mlen;
        mlen = ml;
        a = mi;
        while (a > 0 && rp[a] != '/') a--;      /* a = 标记前 '/' 的位置 */
        b = mi + mlen;
        while (b < olen && rp[b] != '/') b++;    /* b = 标记后 '/' 的位置 */
        if (a < olen && b < olen && rp[a] == '/' && rp[b] == '/') {
            memmove(rp + a, rp + b, olen - b + 1);   /* 含结尾 NUL */
        }
    } else {       /* nrc_* 载荷文件: basename 替换为 fake 的 basename (降级) */
        size_t slash = 0, fb, bnl;
        const char *bn = strrchr(fake_path, '/');
        bn = bn ? bn + 1 : fake_path;
        bnl = strlen(bn);
        for (i = 0; i < olen; i++) if (rp[i] == '/') slash = i;
        fb = slash + 1;
        if (fb + bnl + 1 <= avail) {
            memcpy(rp + fb, bn, bnl);
            rp[fb + bnl] = 0;
        }
    }
    /* 去掉内核追加的 " (deleted)" 后缀 */
    {
        size_t nl = strlen(rp);
        if (nl > 10 && !strcmp(rp + nl - 10, " (deleted)"))
            rp[nl - 10] = 0;
    }
    return 0;
}

static struct kretprobe krp_dpath = {
    .handler = dpath_ret,
    .entry_handler = dpath_entry,
    .kp.symbol_name = "d_path",
    .data_size = sizeof(struct dpath_save),
    .maxactive = 256,
};

/* ============================================================
 * [r89] 输出层隐形④: stat inode 统一 (map_files 深度加固)
 * ACE 逐映射 open /proc/PID/map_files/<rng> 后 fstat:
 *   - d_path 层已把路径改写为 fake_path (libApmBacktrace.so)
 *   - 但 fstat 拿到的仍是 tmpfs 真实 inode/dev, 与 stat(fake_path)
 *     的官方 inode 不一致 → 可区分
 * 修复: kretprobe vfs_getattr_nosec 返回点, 命中 mark 的 dentry
 * 改写 kstat->ino/dev/size 为 fake 文件的预取真值。
 * fake 真值在模块加载时 (fake_path 非空) 预取缓存。
 * ============================================================ */
static u64 g_fino;            /* fake 文件 inode  */
static u32 g_fdev_major, g_fdev_minor;   /* fake 文件 dev    */
static u64 g_fsize;
static int g_fino_valid;

static void nrc_prefetch_fake_stat(void)
{
    struct kstat ks;
    int r;
    if (!fake_path[0]) return;
    /* vfs_getattr_nosec(path, stat, request_mask, query_flags) 需先拿 path;
     * 内核态用 filp_open + vfs_getattr 太绕, 直接 kern_path + vfs_getattr_nosec */
    {
        struct path p;
        typeof(vfs_getattr_nosec) *f = (void *)lookup_sym("vfs_getattr_nosec");
        if (!f) { pr_warn(TAG "vfs_getattr_nosec missing, inode fake off\n"); return; }
        if (lookup_sym("kern_path") == 0) return;
        /* kern_path 在部署段已由 g_kp 解析, 但常驻态未解析 — 重新解析一次 */
        r = ((int (*)(const char *, unsigned, struct path *))lookup_sym("kern_path"))(fake_path, 0, &p);
        if (r) { pr_warn(TAG "prefetch kern_path fail %d\n", r); return; }
        r = f(&p, &ks, STATX_INO | STATX_SIZE, 0);
        path_put(&p);
    }
    if (r == 0) {
        g_fino = ks.ino;
        g_fdev_major = MAJOR(ks.dev);
        g_fdev_minor = MINOR(ks.dev);
        g_fsize = ks.size;
        g_fino_valid = 1;
        pr_info(TAG "fake stat ino=%llu dev=%u:%u size=%llu\n",
                (unsigned long long)ks.ino, g_fdev_major, g_fdev_minor, (unsigned long long)ks.size);
    }
}

/* [r93] sysfs 模块目录隐形: getattr 命中 /sys/module/<hide_mark*> 目录时,
 * 非 root 调用者返回 -ENOENT (与 readdir 隐藏一致), 堵住 direct lookup 泄露。
 * root (action.sh/hidewatch) 保留直读, 不影响 [ -d ] 判定。 */
struct stat_save { struct kstat *ks; int hide; };

static inline int nrc_moddir_name_match(const char *nm)
{
    if (!nm) return 0;
    if (hide_mark2[0] && strstr((char *)nm, hide_mark2)) return 1;
    if (hide_mark[0]  && strstr((char *)nm, hide_mark))  return 1;
    return 0;
}

/* [r94] 覆盖 /sys/module/<mark*> 目录本身 *及其所有子项*
 * (sections/holders/parameters/notes/...), 消除 "父MISS子EXISTS" 矛盾指纹。 */
static inline int nrc_is_hidden_modpath(struct dentry *d)
{
    struct dentry *p;
    if (!d) return 0;
    if (d->d_parent && d->d_parent->d_name.name &&
        strcmp(d->d_parent->d_name.name, "module") == 0)
        return nrc_moddir_name_match(d->d_name.name);
    p = d;
    while (p && p->d_parent && p->d_parent != p) {
        if (p->d_parent->d_name.name &&
            strcmp(p->d_parent->d_name.name, "module") == 0)
            return nrc_moddir_name_match(p->d_name.name);
        p = p->d_parent;
    }
    return 0;
}

static inline int nrc_trusted_caller(void)
{
    return uid_eq(current_euid(), GLOBAL_ROOT_UID);
}

static int getattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct stat_save *sv = (struct stat_save *)ri->data;
    struct path *path = (void *)regs->regs[0];
    sv->ks = NULL;
    sv->hide = 0;
    if (!path || !path->dentry) return 1;
    /* [r93] sysfs 模块目录: 非 root 调用者 -> -ENOENT (与 readdir 隐藏一致) */
    if (nrc_is_hidden_modpath(path->dentry)) {
        sv->hide = nrc_trusted_caller() ? 0 : 1;
        return 0;
    }
    if (!g_fino_valid || !fake_path[0]) return 1;
    if (!nrc_dentry_mark_cached(path->dentry)) return 1;
    sv->ks = (struct kstat *)regs->regs[1];   /* r90: 命中后才取, 减少无用读 */
    return 0;
}

static int getattr_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct stat_save *sv = (struct stat_save *)ri->data;
    struct kstat *ks = sv->ks;
    if (sv->hide) {
        /* [r93] 非 root 看不到 sysfs 模块目录 -> -ENOENT */
        regs->regs[0] = (unsigned long)(long)-ENOENT;
        return 0;
    }
    if (!ks || !g_fino_valid) return 0;
    /* 调用者要 ino 才改 (查 STATX_INO 不必要, 无害直接改) */
    ks->ino = g_fino;
    ks->dev = MKDEV(g_fdev_major, g_fdev_minor);
    if (ks->result_mask & STATX_SIZE) ks->size = g_fsize;
    return 0;
}

static struct kretprobe krp_getattr = {
    .handler = getattr_ret,
    .entry_handler = getattr_entry,
    .kp.symbol_name = "vfs_getattr_nosec",
    .data_size = sizeof(struct stat_save),
    .maxactive = 64,
};

/* ============================================================
 * 输出层隐形③: 整行消除 (mounts / modules / kallsyms)
 * 这些展示面不走 d_path/seq_path 的路径改写, 而是逐行输出。
 * 在每行输出函数返回点检查本行是否含标记, 命中则整行丢弃
 * (m->count 回退到行首)。
 * ============================================================ */
/* [r95] maps/smaps inject-vma scrub.
 * show_map_vma is the shared line writer for /proc/PID/maps (show_map) and
 * /proc/PID/smaps (show_smap -> show_map_vma). When the vma is backed by our
 * injected payload the emitted region is rolled back through m->count, so the
 * injected mapping disappears from maps/smaps completely. One shot closes all
 * four structural tells: segment-count anomaly, multi-inode, offset overflow,
 * private-mapping inode sharing.
 * Victim test = injected dentry name prefix OR dentry-chain mark. It never
 * relies on dev alone (real /data .so share dev fe:2f with the payload), so
 * genuine game .so vmas pass through untouched. */
struct mvm_save { struct seq_file *m; size_t start; int victim; };

static int mvm_is_victim(struct vm_area_struct *vma)
{
    struct dentry *d;
    const char *nm;

    if (!vma || !vma->vm_file) return 0;
    d = vma->vm_file->f_path.dentry;
    if (!d) return 0;
    nm = d->d_name.name;
    if (nm && nm[0] == 'n' && nm[1] == 'r' && nm[2] == 'c' && nm[3] == '_')
        return 1;
    if (nrc_dentry_mark_cached(d)) return 1;
    return 0;
}

static int mvm_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct mvm_save *sv = (struct mvm_save *)ri->data;
    struct seq_file *m = (void *)regs->regs[0];
    struct vm_area_struct *vma = (void *)regs->regs[1];

    sv->m = m;
    sv->start = (m && m->buf) ? m->count : 0;
    sv->victim = vma ? mvm_is_victim(vma) : 0;
    return 0;
}

static int mvm_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct mvm_save *sv = (struct mvm_save *)ri->data;
    struct seq_file *m = sv->m;

    if (!sv->victim || !m || !m->buf) return 0;
    if (m->count >= sv->start) m->count = sv->start;
    return 0;
}

static struct kretprobe krp_mvm = {
    .handler = mvm_ret,
    .entry_handler = mvm_entry,
    .kp.symbol_name = "show_map_vma",
    .data_size = sizeof(struct mvm_save),
    .maxactive = 256,
};

static struct kretprobe krp_msm = {
    .handler = mvm_ret,
    .entry_handler = mvm_entry,
    .kp.symbol_name = "show_smap",
    .data_size = sizeof(struct mvm_save),
    .maxactive = 256,
};

static int nrc_scrub_line(struct seq_file *m, size_t start, const char *mark)
{
    size_t ml, i, len;
    if (!m || !m->buf || m->count <= start || !mark || !mark[0]) return 0;
    ml = strlen(mark);
    len = m->count - start;
    if (len < ml) return 0;
    for (i = 0; i + ml <= len; i++) {
        if (!strncmp(m->buf + start + i, mark, ml)) { m->count = start; return 1; }
    }
    return 0;
}

#define NRC_LINE_HOOK(_n, _sym, _mark) \
static int _n##_entry(struct kretprobe_instance *ri, struct pt_regs *regs) \
{ \
    struct seq_file *m = (void *)regs->regs[0]; \
    struct sfp_save *sv = (struct sfp_save *)ri->data; \
    sv->m = m; \
    sv->start = (m && m->buf) ? m->count : 0; \
    return 0; \
} \
static int _n##_ret(struct kretprobe_instance *ri, struct pt_regs *regs) \
{ \
    struct sfp_save *sv = (struct sfp_save *)ri->data; \
    nrc_scrub_line(sv->m, sv->start, (_mark)); \
    return 0; \
} \
static struct kretprobe _n = { \
    .handler = _n##_ret, \
    .entry_handler = _n##_entry, \
    .kp.symbol_name = _sym, \
    .data_size = sizeof(struct sfp_save), \
    .maxactive = 64, \
};

NRC_LINE_HOOK(krp_mod,     "m_show",          "nrc_merged")
NRC_LINE_HOOK(krp_ksym,    "s_show",          "nrc_merged")
NRC_LINE_HOOK(krp_vfsmnt,  "show_vfsmnt",     ".mnt_")
NRC_LINE_HOOK(krp_mntinfo, "show_mountinfo",  ".mnt_")

/* ============================================================
 * v4.7: /sys/module/nrc_merged 目录项隐藏
 * dir_emit 为 inline, 直接间接调用 ctx->actor (挂 filldir64 符号无效),
 * 故 kprobe kernfs_fop_readdir 入口替换 ctx->actor 为过滤 actor:
 * 命中 "nrc_merged" 返回 0 (跳过该项, 继续迭代), 其余转发原 actor。
 * 不触碰 kobject/kernfs 生命周期, rmmod 路径零影响。
 * ============================================================ */
static filldir_t g_orig_filldir;
static bool nrc_filter_filldir(struct dir_context *ctx, const char *name,
                              int namlen, loff_t off, u64 ino, unsigned t)
{
    /* r90-opt4: 首字节前置筛查。绝大多数目录项首字符既不是 'n' 也不是 '.',
     * 可在 1 次比较内短路, 避免两次 strncmp 的函数调用与长度比较。 */
    if (name) {
        char c0 = name[0];
        if (c0 != 'n' && c0 != '.') goto pass;
        if ((namlen == 10 && !strncmp(name, "nrc_merged", 10)) ||
            (namlen >= 5 && !strncmp(name, ".mnt_", 5)))
            return true;
    }
pass:
    if (g_orig_filldir)
        return g_orig_filldir(ctx, name, namlen, off, ino, t);
    return true;
}
static int nrc_readdir_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct dir_context *ctx = (void *)regs->regs[1];
    if (!ctx || !ctx->actor) return 0;
    /* r90: 已在位则不再写; 无谓成为 filter 时不注册 global 状态竞争 */
    if (ctx->actor != nrc_filter_filldir) {
        if (!g_orig_filldir)
            g_orig_filldir = ctx->actor;
        ctx->actor = nrc_filter_filldir;
    }
    return 0;
}
static struct kprobe kp_readdir = {
    .symbol_name = "kernfs_fop_readdir",
    .pre_handler = nrc_readdir_pre,
};

/* v4.8: f2fs/其他 fs 的 .mnt_ 挂载点目录项隐藏 (统一 VFS 入口 iterate_dir) */
static struct kprobe kp_iterdir = {
    .symbol_name = "iterate_dir",
    .pre_handler = nrc_readdir_pre,
};



/* P5-F③: fork 时子进程继承 shadow slot */
static int kfork_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct task_struct *child = (void *)regs->regs[0];
    struct nrc_slot *s;
    unsigned long f;
    int n = 0;

    if (!child || !child->mm) return 1;
    spin_lock_irqsave(&g_lock, f);
    list_for_each_entry(s, &g_slots, list) {
        struct nrc_slot *ns;
        void *so, *oo;
        if (s->mm == child->mm) continue;   /* 已存在 */
        if (g_nr >= NRC_MAX_SLOTS) break;
        ns = kzalloc(sizeof(*ns), GFP_ATOMIC);
        if (!ns) break;
        ns->mm = child->mm; ns->va = s->va; ns->pte_tmpl = s->pte_tmpl;
        ns->pfn_orig = s->pfn_orig; ns->state = s->state;
        ns->shadow_active = 0;
        ns->pg_shadow = alloc_page(GFP_ATOMIC | __GFP_ZERO);
        if (!ns->pg_shadow) { kfree(ns); break; }
        so = kmap_atomic(ns->pg_shadow);
        oo = kmap_atomic(pfn_to_page(ns->pfn_orig));
        memcpy(so, oo, PAGE_SIZE);
        kunmap_atomic(oo); kunmap_atomic(so);
        mmgrab(ns->mm);
        list_add(&ns->list, &g_slots);
        g_nr++;
        n++;
    }
    spin_unlock_irqrestore(&g_lock, f);
    if (n) pr_info(TAG "fork: inherited %d slot(s) to child mm\n", n);
    return 0;
}

static struct kretprobe krp_fork = {
    .entry_handler = kfork_entry,
    .kp.symbol_name = "copy_process",
    .data_size = sizeof(void *),
    .maxactive = 16,
};

/* P5-E: 进程 mm 销毁时清理 slot (防悬挂 -> UAF) */
static int kexitmm_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct mm_struct *mm = (void *)regs->regs[0];
    struct nrc_slot *s, *tmp;
    unsigned long f;
    int n = 0;

    if (!mm) return 1;
    *(struct mm_struct **)ri->data = mm;
    spin_lock_irqsave(&g_lock, f);
    list_for_each_entry_safe(s, tmp, &g_slots, list) {
        if (s->mm == mm) {
            list_del(&s->list);
            g_nr--;
            __free_page(s->pg_shadow);
            kfree(s);
            n++;
        }
    }
    spin_unlock_irqrestore(&g_lock, f);
    if (n) pr_info(TAG "exit_mmap: purged %d slot(s)\n", n);
    return 0;
}

static struct kretprobe krp_exitmm = {
    .entry_handler = kexitmm_entry,
    .kp.symbol_name = "exit_mmap",
    .data_size = sizeof(struct mm_struct *),
    .maxactive = 16,
};


/* ===== mode=3: 内核部署 (mount tmpfs + file copy + chown + selinux ctx) ===== */
static int kfile_copy(const char *src, const char *dst){
    struct file *f, *o;
    loff_t pos = 0, wpos = 0;
    unsigned char *kb;
    ssize_t nr, nw;
    long long tot = 0;
    int rc = 0;
    f = g_flo(src, O_RDONLY, 0);
    if (IS_ERR(f)){ pr_err(TAG " DEP open src FAIL %s err=%ld\n", src, (long)PTR_ERR(f)); return PTR_ERR(f); }
    o = g_flo(dst, O_WRONLY | O_CREAT | O_TRUNC, 0660);
    if (IS_ERR(o)){ pr_err(TAG " DEP open dst FAIL %s err=%ld\n", dst, (long)PTR_ERR(o)); g_fc(f, NULL); return PTR_ERR(o); }
    kb = kmalloc(4096, GFP_KERNEL);
    if (!kb){ g_fc(o, NULL); g_fc(f, NULL); return -ENOMEM; }
    while ((nr = g_kr(f, kb, 4096, &pos)) > 0){
        nw = g_kw(o, kb, (size_t)nr, &wpos);
        if (nw != nr){ pr_err(TAG " DEP write FAIL %s nw=%zd nr=%zd\n", dst, nw, nr); rc = -EIO; break; }
        tot += nw;
    }
    if (nr < 0) rc = (int)nr;
    kfree(kb); g_fc(o, NULL); g_fc(f, NULL);
    pr_info(TAG " DEP copy %s -> %s %lld bytes rc=%d\n", src, dst, tot, rc);
    return rc;
}
static void kset_ctx(const char *path, const char *ctx){
    struct path p;
    int r;
    if (!ctx || !ctx[0]) return;
    r = g_kp(path, 0, &p);
    if (r){ pr_err(TAG " DEP ctx kern_path FAIL %s r=%d\n", path, r); return; }
    /* 注意: vfs_setxattr 内部自持 inode_lock, 外层不得再加 (同线程递归=自死锁) */
    r = g_sx(&nop_mnt_idmap, p.dentry, "security.selinux", ctx, strlen(ctx), 0);
    pr_info(TAG " DEP ctx %s r=%d\n", path, r);
    path_put(&p);
}
static void kset_owner(const char *path, umode_t mode){
    struct path p;
    struct iattr at;
    int r;
    if (guid <= 0) return;
    r = g_kp(path, 0, &p);
    if (r){ pr_err(TAG " DEP own kern_path FAIL %s r=%d\n", path, r); return; }
    memset(&at, 0, sizeof(at));
    at.ia_valid = ATTR_UID | ATTR_GID | ATTR_MODE;
    at.ia_uid = KUIDT_INIT((uid_t)guid);
    at.ia_gid = KGIDT_INIT((gid_t)guid);
    /* 关键: 保留 S_IFMT 文件类型位, 否则目录变 FIFO (chmod 同款合并) */
    at.ia_mode = (mode & 07777) | (p.dentry->d_inode->i_mode & S_IFMT);
    /* FUSE(fuse_set_nowrite)/VFS setattr 要求持 inode_lock, 否则 BUG_ON (这是本次重启根因) */
    inode_lock(p.dentry->d_inode);
    r = g_nc(&nop_mnt_idmap, p.dentry, &at, NULL);
    inode_unlock(p.dentry->d_inode);
    pr_info(TAG " DEP own %s uid=%d mode=%o r=%d\n", path, guid, mode, r);
    path_put(&p);
}

/* ===== #3: init.lua 占位符内核替换 (替代 shell sed -i) ===== */
static int krep_inplace(const char *path, const char *find, const char *rep){
    struct file *f;
    loff_t pos = 0, wpos = 0;
    ssize_t nr;
    size_t cap = 65536, len = 0, fl = strlen(find), rl = strlen(rep);
    long outlen;
    int cnt = 0, rc = 0;
    unsigned char *b, *o;
    if (!find[0]) return 0;
    if (!g_va || !g_vfe) return -ENOENT;
    f = g_flo(path, O_RDONLY, 0);
    if (IS_ERR(f)){ pr_err(TAG " REP open FAIL %s %ld\n", path, (long)PTR_ERR(f)); return PTR_ERR(f); }
    b = g_va(cap, GFP_KERNEL);
    if (!b){ g_fc(f, NULL); return -ENOMEM; }
    while ((nr = g_kr(f, b + len, cap - len, &pos)) > 0){
        len += (size_t)nr;
        if (cap - len < 4096){
            unsigned char *nb;
            if (cap > (2u << 20)){ pr_err(TAG " REP too big %s\n", path); rc = -EFBIG; break; }
            cap <<= 1; nb = g_va(cap, GFP_KERNEL);
            if (!nb){ rc = -ENOMEM; break; }
            memcpy(nb, b, len); g_vfe(b); b = nb;
        }
    }
    if (!rc && nr < 0) rc = (int)nr;
    g_fc(f, NULL);
    if (rc){ g_vfe(b); return rc; }
    /* 统计替换次数 */
    { size_t i = 0; while (fl && i + fl <= len){ if (!memcmp(b + i, find, fl)){ cnt++; i += fl; } else i++; } }
    if (!cnt){ pr_info(TAG " REP %s marker not found (len=%zu)\n", path, len); g_vfe(b); return 0; }
    outlen = (long)len + (long)cnt * ((long)rl - (long)fl);
    if (outlen <= 0){ g_vfe(b); return -EINVAL; }
    o = g_va((size_t)outlen + 1, GFP_KERNEL);
    if (!o){ g_vfe(b); return -ENOMEM; }
    /* 单趟重建 */
    { size_t si = 0, di = 0;
      while (si < len){
          if (fl && si + fl <= len && !memcmp(b + si, find, fl)){ memcpy(o + di, rep, rl); di += rl; si += fl; }
          else o[di++] = b[si++];
      }
      outlen = (long)di;
    }
    g_vfe(b);
    f = g_flo(path, O_WRONLY | O_TRUNC, 0660);
    if (IS_ERR(f)){ pr_err(TAG " REP rewrite FAIL %s %ld\n", path, (long)PTR_ERR(f)); g_vfe(o); return PTR_ERR(f); }
    nr = g_kw(f, o, (size_t)outlen, &wpos);
    g_fc(f, NULL);
    if (nr != outlen){ pr_err(TAG " REP write short %s\n", path); g_vfe(o); return -EIO; }
    pr_info(TAG " REP %s %d hits %zu -> %ld bytes\n", path, cnt, len, outlen);
    g_vfe(o);
    return 0;
}
/* ===== #4: 内核文件/目录删除 (替代 shell rm/find -delete) ===== */
typedef int (*vu_t)(struct mnt_idmap *, struct inode *, struct dentry *, struct inode **);
typedef int (*vr_t)(struct mnt_idmap *, struct inode *, struct dentry *);
typedef int (*itd_t)(struct file *, struct dir_context *);
static vu_t g_vu; static vr_t g_vr; static itd_t g_itd;
struct rmctx { struct dir_context ctx; char *names; size_t len, cap; };
static bool rm_actor(struct dir_context *c, const char *name, int namelen, loff_t pos, u64 ino, unsigned type){
    struct rmctx *r = container_of(c, struct rmctx, ctx);
    (void)pos; (void)ino; (void)type;
    if (!strcmp(name, ".") || !strcmp(name, "..")) return true;
    if (r->len + namelen + 2 >= r->cap) return false;
    memcpy(r->names + r->len, name, (size_t)namelen);
    r->len += (size_t)namelen; r->names[r->len++] = 0;
    return true;
}
static int krm_leaf(const char *path, int isdir){
    struct path pp;
    struct dentry *nd;
    char tmp[256];
    char *sl;
    int r;
    if (!g_kp || !g_l1 || !g_vu || !g_vr) return -ENOENT;
    strncpy(tmp, path, sizeof(tmp) - 1); tmp[sizeof(tmp) - 1] = 0;
    sl = strrchr(tmp, '/');
    if (!sl || !sl[1] || sl == tmp) return -EINVAL;
    *sl = 0;
    r = g_kp(tmp, 0, &pp);
    if (r) return r;
    inode_lock(pp.dentry->d_inode);
    nd = g_l1(sl + 1, pp.dentry, (int)strlen(sl + 1));
    if (!IS_ERR(nd)){
        r = isdir ? g_vr(&nop_mnt_idmap, pp.dentry->d_inode, nd)
                  : g_vu(&nop_mnt_idmap, pp.dentry->d_inode, nd, NULL);
        dput(nd);
    } else r = (int)PTR_ERR(nd);
    inode_unlock(pp.dentry->d_inode);
    path_put(&pp);
    return r;
}
static int krm_tree(const char *path, int depth){
    struct path p;
    struct file *f;
    struct rmctx rc;
    int r, isdir;
    if (depth > 6) return -ELOOP;
    if (!g_kp) return -ENOENT;
    r = g_kp(path, 0, &p);
    if (r) return r;
    isdir = S_ISDIR(p.dentry->d_inode->i_mode);
    path_put(&p);
    if (!isdir) return krm_leaf(path, 0);
    /* 目录: 列举子项递归删除 */
    f = g_flo(path, O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(f)) return PTR_ERR(f);
    memset(&rc, 0, sizeof(rc));
    rc.ctx.actor = rm_actor; rc.cap = 4096;
    rc.names = kmalloc(rc.cap, GFP_KERNEL);
    if (!rc.names){ g_fc(f, NULL); return -ENOMEM; }
    r = g_itd(f, &rc.ctx);
    g_fc(f, NULL);
    if (r < 0){ kfree(rc.names); return r; }
    { size_t i = 0;
      while (i < rc.len){
          char child[512];
          int n = snprintf(child, sizeof(child), "%s/%s", path, rc.names + i);
          if (n > 0 && n < (int)sizeof(child)) krm_tree(child, depth + 1);
          i += strlen(rc.names + i) + 1;
      }
    }
    kfree(rc.names);
    r = krm_leaf(path, 1);
    pr_info(TAG " RM dir %s r=%d\n", path, r);
    return r;
}
static int do_clean(void){
    char *buf, *p, *tok;
    int n = 0, r;
    if (!rmpath[0]) return 0;
    if (!g_itd){ g_itd = (void *)lookup_sym("iterate_dir"); }
    if (!g_vu){ g_vu = (vu_t)lookup_sym("vfs_unlink"); }
    if (!g_vr){ g_vr = (vr_t)lookup_sym("vfs_rmdir"); }
    if (!g_itd || !g_vu || !g_vr){ pr_err(TAG " CLEAN sym FAIL itd=%p vu=%p vr=%p\n", (void*)g_itd, (void*)g_vu, (void*)g_vr); return -ENOENT; }
    buf = kstrdup(rmpath, GFP_KERNEL);
    if (!buf) return -ENOMEM;
    p = buf;
    while ((tok = strsep(&p, ",")) != NULL){
        if (!tok[0]) continue;
        r = krm_tree(tok, 0);
        if (r == -ENOENT){ pr_info(TAG " CLEAN miss %s (ignored)\n", tok); continue; }
        pr_info(TAG " CLEAN %s r=%d\n", tok, r);
        n++;
    }
    kfree(buf);
    pr_info(TAG " CLEAN done %d paths\n", n);
    return 0;
}

static int do_deploy(void){
    int r, ncopy = 0;
    /* 1) mkdir mountpoint + mount tmpfs */
    if (mntpath[0]){
        struct path p;
        r = g_kp(mntpath, 0, &p);
        if (r == -ENOENT){
            /* kern_path_create: 创建末级目录 */
            char tmp[160]; char *sl;
            strncpy(tmp, mntpath, sizeof(tmp)-1); tmp[sizeof(tmp)-1]=0;
            sl = strrchr(tmp, '/');
            if (sl && sl[1]){
                *sl = 0;
                { struct path pp; struct dentry *nd;
                  if (g_kp(tmp, 0, &pp) == 0){
                      inode_lock(pp.dentry->d_inode);
                      nd = g_l1(sl+1, pp.dentry, strlen(sl+1));
                      if (!IS_ERR(nd)){
                          r = g_vm(&nop_mnt_idmap, pp.dentry->d_inode, nd, 0770);
                          pr_info(TAG " DEP mkdir %s r=%d\n", mntpath, r);
                          dput(nd);
                      } else { pr_err(TAG " DEP lookup FAIL %ld\n", PTR_ERR(nd)); }
                      inode_unlock(pp.dentry->d_inode);
                      path_put(&pp);
                  } }
            }
            r = g_kp(mntpath, 0, &p);
        }
        if (r){ pr_err(TAG " DEP mntpath FAIL %s r=%d\n", mntpath, r); return r; }
        { char *dn = (char *)kstrdup("tmpfs", GFP_KERNEL);
          char *dp = (char *)kstrdup("size=64m,seclabel", GFP_KERNEL);
          if (!dn || !dp){ kfree(dn); kfree(dp); path_put(&p); return -ENOMEM; }
          r = g_pm(dn, &p, dn, 0, dp);
          pr_info(TAG " DEP mount tmpfs %s r=%d\n", mntpath, r);
          kfree(dn); kfree(dp); }
        path_put(&p);
        /* 关键: 挂载点目录必须设 ctx(含 MLS category), 否则游戏 search 被 SELinux 拒 */
        if (r == 0){ kset_ctx(mntpath, gctx); kset_owner(mntpath, 0770); }
        /* mount 已回写 r, 失败回退到 dst1 直写（dst1 已指向目标文件） */
    }
    /* 2) so copy */
    if (sodec[0] && dst1[0]){
        r = kfile_copy(sodec, dst1);
        if (r) return r;
        kset_owner(dst1, 0660);
        kset_ctx(dst1, gctx);
        ncopy++;
    }
    /* 3) init.lua copy */
    if (src2[0] && dst2[0]){
        /* #3: init.lua 占位符内核替换 (替代 shell sed -i) */
        if (s1f[0]){
            if (!g_va) g_va = (void *)lookup_sym("__vmalloc");
            if (!g_vfe) g_vfe = (void *)lookup_sym("vfree");
            if (g_va && g_vfe){ r = krep_inplace(src2, s1f, s1r); pr_info(TAG " DEP rep rc=%d\n", r); }
            else pr_err(TAG " DEP vmalloc sym FAIL\n");
        }
        r = kfile_copy(src2, dst2);
        if (r) return r;
        kset_owner(dst2, 0600);
        kset_ctx(dst2, gctx);
        ncopy++;
    }
    /* 4) 批量 lua (stpath -> ldpath, flist 逗号分隔) */
    if (stpath[0] && ldpath[0] && flist[0]){
        char list[640]; char *tok;
        strncpy(list, flist, sizeof(list)-1); list[sizeof(list)-1]=0;
        tok = list;
        while (tok && *tok){
            char *nx = strchr(tok, ',');
            if (nx){ *nx = 0; nx++; }
            char s5[320], d5[320];
            snprintf(s5, sizeof(s5), "%s/%s", stpath, tok);
            snprintf(d5, sizeof(d5), "%s/%s", ldpath, tok);
            r = (strcmp(stpath, ldpath) == 0) ? 0 : kfile_copy(s5, d5);
            if (r){ pr_err(TAG " DEP lua FAIL %s r=%d\n", tok, r); return r; }
            kset_owner(d5, 0600);
            kset_ctx(d5, gctx);
            ncopy++;
            tok = nx;
        }
    }
    /* 5) 目录 owner */
    if (ldpath[0]){ kset_owner(ldpath, 0700); kset_ctx(ldpath, gctx); }
    if (mntpath[0]) kset_owner(mntpath, 0770);
    pr_info(TAG " DEPLOY DONE files=%d\n", ncopy);
    return 0;
}

/* ===== mode=4: 内核 ChaCha20 (RFC8439, ctr=0, LE) ===== */
static u32 rotr32(u32 x, int n){ return (x << n) | (x >> (32 - n)); } /* RFC8439: ROTL */
#define QR(a,b,c,d) do { \
    a += b; d ^= a; d = rotr32(d,16); \
    c += d; b ^= c; b = rotr32(b,12); \
    a += b; d ^= a; d = rotr32(d, 8); \
    c += d; b ^= c; b = rotr32(b, 7); } while (0)
static void chacha20_block(const u32 in[16], u8 out[64]){
    u32 x[16]; int i;
    for (i = 0; i < 16; i++) x[i] = in[i];
    for (i = 0; i < 10; i++){
        QR(x[0], x[4], x[8],  x[12]); QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]); QR(x[3], x[4], x[9],  x[14]);
    }
    for (i = 0; i < 16; i++){ u32 v = x[i] + in[i]; out[4*i]=(u8)v; out[4*i+1]=(u8)(v>>8); out[4*i+2]=(u8)(v>>16); out[4*i+3]=(u8)(v>>24); }
}
static int hx1(char c){
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int hx2bin(const char *hs, u8 *out, int maxn){
    int n = 0, hi = -1;
    while (*hs){
        int v = hx1(*hs++);
        if (v < 0) continue;
        if (hi < 0){ hi = v; } else { if (n >= maxn) return -1; out[n++] = (u8)((hi << 4) | v); hi = -1; }
    }
    return (hi >= 0) ? -1 : n;
}
static int do_decrypt(void){
    struct file *fi, *fo;
    u8 kb[32], nb[12];
    u32 st[16];
    unsigned char *buf, *blk;
    loff_t pos = 0, wpos = 0;
    u32 ctr = 0;
    ssize_t nr;
    long long tot = 0;
    int rc, i, last = -1;
    static const u8 sig[16] = "expand 32-byte k";
    if (hx2bin(chkey, kb, 32) != 32){ pr_err(TAG " DEC bad key\n"); return -EINVAL; }
    if (hx2bin(chnon, nb, 12) != 12){ pr_err(TAG " DEC bad nonce\n"); return -EINVAL; }
    for (i = 0; i < 4; i++) st[i] = *(const u32 *)(sig + 4*i);
    for (i = 0; i < 8; i++) st[4+i] = *(const u32 *)(kb + 4*i);
    st[12] = 0;
    for (i = 0; i < 3; i++) st[13+i] = *(const u32 *)(nb + 4*i);
    fi = g_flo(chsrc, O_RDONLY, 0);
    if (IS_ERR(fi)){ pr_err(TAG " DEC open src FAIL %s %ld\n", chsrc, (long)PTR_ERR(fi)); return PTR_ERR(fi); }
    fo = g_flo(chdst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (IS_ERR(fo)){ pr_err(TAG " DEC open dst FAIL %s %ld\n", chdst, (long)PTR_ERR(fo)); g_fc(fi, NULL); return PTR_ERR(fo); }
    buf = kmalloc(4096, GFP_KERNEL); blk = kmalloc(64, GFP_KERNEL);
    if (!buf || !blk){ kfree(buf); kfree(blk); g_fc(fo, NULL); g_fc(fi, NULL); return -ENOMEM; }
    while ((nr = g_kr(fi, buf, 4096, &pos)) > 0){
        for (i = 0; i < (int)nr; i++){
            int bi = i & 63;
            if (bi == 0){ st[12] = ctr; chacha20_block(st, blk); ctr++; }
            buf[i] ^= blk[bi];
        }
        if (g_kw(fo, buf, (size_t)nr, &wpos) != nr){ rc = -EIO; goto out; }
        tot += nr; last = i;
    }
    rc = 0;
out:
    kfree(buf); kfree(blk); g_fc(fo, NULL); g_fc(fi, NULL);
    pr_info(TAG " DEC done %s -> %s %lld bytes rc=%d\n", chsrc, chdst, tot, rc);
    return rc;
}


static int sndbuf_run(void)
{
	static const int cands[] = { 46, 45, 44, 43, 42, 41, 40, 39, 38, 37 };
	struct task_struct *t, *rcpt;
	struct mm_struct *mm;
	struct vm_area_struct *lv = NULL, *uv = NULL;
	unsigned long base = 0, gap = 0, caller = 0;
	unsigned int wr, rd, i, sig = 0;
	u8 buf[SC_LEN], rb[SC_LEN];

	if (wipe && p_pid > 0) {
		struct task_struct *w;
		struct mm_struct *wmm;
		struct vm_area_struct *wv = NULL;
		unsigned long wbase = 0, wgap;
		unsigned int k;
		u8 chk[SC_LEN];
		int bad;

		w = find_task_by_vpid(p_pid);
		if (!w) {
			pr_err(PRFX "wipe: no task %d\n", p_pid);
			return -ENODEV;
		}
		get_task_struct(w);
		wmm = w->mm;
		if (!wmm) {
			pr_err(PRFX "wipe: no mm\n");
			put_task_struct(w);
			return -ENODEV;
		}
		if (down_read_killable(&wmm->mmap_lock)) {
			put_task_struct(w);
			return -EINTR;
		}
		find_named_x_vma(wmm, "linker64", 0, &wv);
		if (wv)
			wbase = wv->vm_start - (wv->vm_pgoff << PAGE_SHIFT);
		up_read(&wmm->mmap_lock);
		if (!wbase) {
			pr_err(PRFX "wipe: linker64 not found\n");
			put_task_struct(w);
			return -ENOENT;
		}
		wgap = wbase + GAP_FOFF;
		memset(chk, 0, sizeof(chk));
		access_process_vm(w, wgap, chk, SC_LEN, FOLL_WRITE | FOLL_FORCE);
		memset(chk, 0, sizeof(chk));
		access_process_vm(w, wgap, chk, SC_LEN, 0);
		bad = 0;
		for (k = 0; k < SC_LEN; k++)
			if (chk[k]) {
				bad = 1;
				break;
			}
		pr_info(PRFX "wipe: gap=%px %s\n", (void *)wgap,
			bad ? "READBACK_NOT_ZERO" : "erased ok");
		put_task_struct(w);
		return 0;
	}

	if (p_pid <= 0 || !p_path[0]) {
		pr_err(PRFX "params: p_pid=%d path=%s\n", p_pid, p_path);
		return -EINVAL;
	}

	t = find_task_by_vpid(p_pid);
	if (!t) {
		pr_err(PRFX "no task pid=%d\n", p_pid);
		return -ENODEV;
	}
	get_task_struct(t);
	s_g_task = t;
	mm = t->mm;
	if (!mm) {
		pr_err(PRFX "task %d has no mm\n", p_pid);
		return -ENODEV;
	}

	/* 投递目标：空闲守护线程（排除 main / Signal Catcher） */
	rcpt = pick_recipient(t);
	if (!rcpt) {
		pr_err(PRFX "no recipient\n");
		return -ECHILD;
	}

	/* 选信号：目标线程未屏蔽 + sighand(全进程共享) 为 SIG_DFL */
	if (p_sig > 0) {
		sig = p_sig;
	} else {
		for (i = 0; i < ARRAY_SIZE(cands); i++) {
			int k = cands[i];

			if (sigismember(&rcpt->blocked, k))
				continue;
			if (t->sighand->action[k - 1].sa.sa_handler == SIG_DFL) {
				sig = k;
				break;
			}
		}
		if (!sig) {
			for (i = 0; i < ARRAY_SIZE(cands); i++)
				if (!sigismember(&rcpt->blocked, cands[i])) {
					sig = cands[i];
					break;
				}
		}
	}
	if (!sig) {
		pr_err(PRFX "no deliverable signal\n");
		put_task_struct(rcpt);
		return -EINVAL;
	}

	if (down_read_killable(&mm->mmap_lock)) {
		pr_err(PRFX "mmap_lock interrupted\n");
		put_task_struct(rcpt);
		return -EINTR;
	}
	find_named_x_vma(mm, "linker64", 0, &lv);
	find_named_x_vma(mm, "libUE4", 1, &uv);
	if (lv) {
		base = lv->vm_start - (lv->vm_pgoff << PAGE_SHIFT);
		gap = base + GAP_FOFF;
	}
	if (uv)
		caller = uv->vm_start;
	up_read(&mm->mmap_lock);

	if (!lv || gap < lv->vm_start || gap + SC_LEN > lv->vm_end) {
		pr_err(PRFX "linker64 exec vma not found (lv=%px)\n", lv);
		put_task_struct(rcpt);
		return -ENOENT;
	}
	if (!caller) {
		pr_err(PRFX "libUE4 exec vma not found\n");
		put_task_struct(rcpt);
		return -ENOENT;
	}

	/* 组装 shellcode 缓冲 */
	memset(buf, 0, sizeof(buf));
	memcpy(buf, scw, sizeof(scw));
	{
		u64 a = base + DLOPEN_FOFF, b = gap + SC_PATH_OFF, c = caller;

		memcpy(buf + SC_SLOT_A, &a, 8);
		memcpy(buf + SC_SLOT_B, &b, 8);
		memcpy(buf + SC_SLOT_C, &c, 8);
	}
	copy_str(buf + SC_PATH_OFF, SC_LEN - SC_PATH_OFF, p_path);

	/* GUP FOLL_FORCE|FOLL_WRITE 写 r-x 段尾（内核侧写 OK：kmap+memcpy，
	 * 仅用户态 str 会因 vma 无 VM_WRITE 被 maybe_mkwrite 拒绝 —— v3.2 已删写指令） */
	wr = access_process_vm(t, gap, buf, SC_LEN, FOLL_WRITE | FOLL_FORCE);
	if (wr != SC_LEN) {
		pr_err(PRFX "write short %u/%u gap=%px\n", wr, SC_LEN, (void *)gap);
		put_task_struct(rcpt);
		return -EIO;
	}
	memset(rb, 0, sizeof(rb));
	rd = access_process_vm(t, gap, rb, SC_LEN, 0);
	if (rd != SC_LEN) {
		pr_err(PRFX "readback short rd=%u gap=%px\n", rd, (void *)gap);
		put_task_struct(rcpt);
		return -EIO;
	}
	for (i = 0; i < SC_LEN; i++) {
		if (buf[i] != rb[i]) {
			pr_err(PRFX "readback mismatch @%u gap=%px\n", i, (void *)gap);
			put_task_struct(rcpt);
			return -EIO;
		}
	}


	/* 换 handler → 逐个 caller 候选触发 → 轮询 payload vma → 还原 */
	install_handler(t, sig, gap);
	pr_info(PRFX "pid=%d rcpt=%d comm=%s gap=%px dlopen=%px sig=%d\n",
		p_pid, rcpt->pid, rcpt->comm, (void *)gap,
		(void *)(base + DLOPEN_FOFF), sig);

	{
		unsigned long callers[3];
		int ci, ok = 0;

		callers[0] = gap;     /* sc 地址位于 linker64 -> linker linkmap/默认 ns */
		callers[1] = caller;  /* libUE4 起点 -> classloader ns */
		callers[2] = 0;       /* NULL caller 路径 */
		for (ci = 0; ci < 3 && !ok; ci++) {
			u64 cv = callers[ci];

			access_process_vm(t, gap + SC_SLOT_C, &cv, 8,
					  FOLL_WRITE | FOLL_FORCE);
			pr_info(PRFX "try caller[%d]=%px\n", ci, (void *)callers[ci]);
			if (send_sig_info(sig, SEND_SIG_NOINFO, rcpt) < 0) {
				pr_err(PRFX "send_sig_info failed\n");
				continue;
			}
			for (i = 0; i < 250; i++) {
				if (payload_loaded(mm)) {
					ok = 1;
					break;
				}
				msleep(10);
			}
		}
		if (!ok) {
			/* 超时：还原 handler（该线程不会再跳 sc），action.sh 回退 ptrace */
			restore_handler(t, sig);
			pr_warn(PRFX "all callers timeout, handler restored (sig=%d)\n",
				sig);
			put_task_struct(rcpt);
			return -ETIMEDOUT;
		}
	}

	/* 成功吞窗：主杀因=恢复后晚到同号信号打原 handler，窗内 trampoline 幂等吞掉 */
	if (p_sw) {
	pr_info(PRFX "swallow window 8s before restore (sig=%d)\n", sig);
	msleep(8000);
	}
	restore_handler(t, sig);
	pr_info(PRFX "payload loaded, handler restored, rt_sigreturn ok\n");
	put_task_struct(rcpt);
	return 0;
}


static void sndbuf_cleanup(void)
{
	if (s_g_task) {
		if (g_installed)
			restore_handler(s_g_task, g_old_sig ? g_old_sig : 46);
		put_task_struct(s_g_task);
		s_g_task = NULL;
	}
	pr_info(PRFX "exit ok\n");
}


/* ================= P5-D 统一 init/exit ================= */
static int __init nrc_merged_init(void)
{
    int kr;
    /* ---- 注入 / 擦除 (原 sndbuf) ---- */
    if (action == NRC_ACTION_INJECT || action == NRC_ACTION_WIPE) {
        wipe = (action == NRC_ACTION_WIPE) ? 1 : 0;
        return sndbuf_run();
    }
    /* ---- 一次性内核文件动作 (原 core mode3/4/5) ---- */
    if (action == NRC_ACTION_DEPLOY || action == NRC_ACTION_DECRYPT || action == NRC_ACTION_CLEAN) {
        g_flo = (void *)lookup_sym("filp_open");
        g_kr  = (void *)lookup_sym("kernel_read");
        g_fc  = (void *)lookup_sym("filp_close");
        g_kw  = (void *)lookup_sym("kernel_write");
        g_kp  = (void *)lookup_sym("kern_path");
        g_l1  = (void *)lookup_sym("lookup_one_len");
        if (action == NRC_ACTION_DECRYPT) {
            if (!g_flo || !g_kr || !g_fc || !g_kw) { pr_err(TAG "DEC sym FAIL\n"); return -ENOENT; }
            kr = do_decrypt();
            if (kr) { pr_err(TAG "DECRYPT rc=%d\n", kr); return -EINVAL; }
            return 0;
        }
        if (action == NRC_ACTION_CLEAN) {
            g_itd = (void *)lookup_sym("iterate_dir");
            g_vu  = (vu_t)lookup_sym("vfs_unlink");
            g_vr  = (vr_t)lookup_sym("vfs_rmdir");
            if (!g_kp || !g_l1 || !g_flo || !g_fc) { pr_err(TAG "CLEAN sym FAIL\n"); return -ENOENT; }
            kr = do_clean();
            if (kr) { pr_err(TAG "CLEAN rc=%d\n", kr); return -EINVAL; }
            return 0;
        }
        g_pm = (void *)lookup_sym("path_mount");
        g_vm = (void *)lookup_sym("vfs_mkdir");
        g_nc = (void *)lookup_sym("notify_change");
        g_sx = (void *)lookup_sym("vfs_setxattr");
        pr_info(TAG "deploy syms kw=%p kp=%p pm=%p vm=%p nc=%p sx=%p\n",
                (void*)g_kw, (void*)g_kp, (void*)g_pm, (void*)g_vm, (void*)g_nc, (void*)g_sx);
        if (!g_kw || !g_kp || !g_pm || !g_flo || !g_kr || !g_fc || !g_nc) {
            pr_err(TAG "DEP sym FAIL\n"); return -ENOENT;
        }
        kr = do_deploy();
        if (kr) { pr_err(TAG "DEPLOY rc=%d\n", kr); return -EINVAL; }
        return 0;
    }
    /* ---- 常驻 shadow 服务 ---- */
    nrc_wq = alloc_workqueue("nrc_wq", WQ_UNBOUND | WQ_HIGHPRI, 1);
    if (!nrc_wq) return -ENOMEM;
    kr = register_kretprobe(&krp_prctl);
    if (kr) { pr_err(TAG "kretprobe prctl fail=%d\n", kr); destroy_workqueue(nrc_wq); return kr; }
    kr = register_kprobe(&kp_fault);
    if (kr) pr_warn(TAG "kprobe fault fail=%d (fault seesaw degraded)\n", kr);
    kr = register_kretprobe(&krp_access);
    if (kr) { pr_err(TAG "kretprobe access fail=%d\n", kr); unregister_kprobe(&kp_fault); unregister_kretprobe(&krp_prctl); destroy_workqueue(nrc_wq); return kr; }
    kr = register_kretprobe(&krp_sfp);
    if (kr) pr_warn(TAG "kretprobe seq_file_path fail=%d (hide degraded)\n", kr);
    kr = register_kretprobe(&krp_dpath);
    if (kr) pr_warn(TAG "kretprobe d_path fail=%d (map_files hide degraded)\n", kr);
    kr = register_kretprobe(&krp_getattr);
    if (kr) pr_warn(TAG "kretprobe getattr fail=%d (stat inode fake degraded)\n", kr);
    else { nrc_prefetch_fake_stat(); pr_info(TAG "stat inode fake ON\n"); }
    kr = register_kretprobe(&krp_mod);     if (kr) pr_warn(TAG "krp_mod fail=%d\n", kr);
    kr = register_kretprobe(&krp_ksym);    if (kr) pr_warn(TAG "krp_ksym fail=%d\n", kr);
    kr = register_kretprobe(&krp_vfsmnt);  if (kr) pr_warn(TAG "krp_vfsmnt fail=%d\n", kr);
    kr = register_kretprobe(&krp_mntinfo); if (kr) pr_warn(TAG "krp_mntinfo fail=%d\n", kr);
    kr = register_kretprobe(&krp_mvm); if (kr) pr_warn(TAG "krp_mvm fail=%d\n", kr); else pr_info(TAG "maps/smaps inject-vma scrub ON\n");
    kr = register_kretprobe(&krp_msm); if (kr) pr_warn(TAG "krp_msm fail=%d\n", kr);
    kr = register_kprobe(&kp_readdir); if (kr) pr_warn(TAG "kprobe kernfs_fop_readdir fail=%d\n", kr);
    kr = register_kprobe(&kp_iterdir); if (kr) pr_warn(TAG "kprobe iterate_dir fail=%d\n", kr);
    kr = register_kretprobe(&krp_pfc); if (kr) pr_warn(TAG "krp_pfc fail=%d (map_files scrub degraded)\n", kr); else pr_info(TAG "map_files entry scrub ON\n");
    kr = register_kretprobe(&krp_exitmm);
    if (kr) { pr_err(TAG "kretprobe exit_mmap fail=%d\n", kr); unregister_kretprobe(&krp_access); unregister_kprobe(&kp_fault); unregister_kretprobe(&krp_prctl); destroy_workqueue(nrc_wq); return kr; }
    kr = register_kretprobe(&krp_fork);
    if (kr) { pr_err(TAG "kretprobe copy_process fail=%d\n", kr); unregister_kretprobe(&krp_exitmm); unregister_kretprobe(&krp_access); unregister_kprobe(&kp_fault); unregister_kretprobe(&krp_prctl); destroy_workqueue(nrc_wq); return kr; }
    {
        struct kprobe kp1 = { .symbol_name = "register_user_break_hook" };
        struct kprobe kp2 = { .symbol_name = "unregister_user_break_hook" };
        if (register_kprobe(&kp1) == 0) {
            g_register_user_break_hook = (void (*)(struct break_hook *))kp1.addr;
            unregister_kprobe(&kp1);
        }
        if (register_kprobe(&kp2) == 0) {
            g_unregister_user_break_hook = (void (*)(struct break_hook *))kp2.addr;
            unregister_kprobe(&kp2);
        }
        if (g_register_user_break_hook) {
            g_register_user_break_hook(&nrc_break_hook);
            pr_debug(TAG "user_break_hook registered\n");
        } else {
            pr_err(TAG "cannot resolve register_user_break_hook\n");
        }
        {
            struct kprobe ks1 = { .symbol_name = "register_user_step_hook" };
            struct kprobe ks2 = { .symbol_name = "unregister_user_step_hook" };
            if (register_kprobe(&ks1) == 0) { g_register_user_step_hook = (void (*)(struct step_hook *))ks1.addr; unregister_kprobe(&ks1); }
            if (register_kprobe(&ks2) == 0) { g_unregister_user_step_hook = (void (*)(struct step_hook *))ks2.addr; unregister_kprobe(&ks2); }
            if (g_register_user_step_hook) { g_register_user_step_hook(&nrc_step_hook_s); pr_debug(TAG "user_step_hook registered (P5-F)\n"); }
            else pr_err(TAG "cannot resolve register_user_step_hook\n");
        }
    }
    pr_debug(TAG "nrc v5 init OK (shadow + deploy/decrypt/clean + inject/wipe)\n");
    return 0;
}

static void __exit nrc_merged_exit(void)
{
    struct nrc_bp *nb, *nbtmp;
    unsigned long flags;
    if (action != NRC_ACTION_NONE) {
        if (action == NRC_ACTION_INJECT || action == NRC_ACTION_WIPE) sndbuf_cleanup();
        pr_info(TAG "action=%d exit\n", action);
        return;
    }
    if (g_unregister_user_step_hook)
        g_unregister_user_step_hook(&nrc_step_hook_s);
    if (g_unregister_user_break_hook)
        g_unregister_user_break_hook(&nrc_break_hook);
    flush_workqueue(nrc_wq);
    unregister_kretprobe(&krp_fork);
    unregister_kretprobe(&krp_exitmm);
    unregister_kretprobe(&krp_getattr);
    unregister_kretprobe(&krp_access);
    unregister_kretprobe(&krp_sfp);
    unregister_kretprobe(&krp_dpath);
    unregister_kretprobe(&krp_msm);
    unregister_kretprobe(&krp_mvm);
    unregister_kretprobe(&krp_mntinfo);
    unregister_kprobe(&kp_readdir);
    unregister_kretprobe(&krp_pfc);
    unregister_kprobe(&kp_iterdir);
    unregister_kretprobe(&krp_vfsmnt);
    unregister_kretprobe(&krp_ksym);
    unregister_kretprobe(&krp_mod);
    unregister_kprobe(&kp_fault);
    unregister_kretprobe(&krp_prctl);
    destroy_workqueue(nrc_wq);
    spin_lock_irqsave(&g_bp_lock, flags);
    list_for_each_entry_safe(nb, nbtmp, &g_bps, list) { list_del(&nb->list); kfree(nb); }
    spin_unlock_irqrestore(&g_bp_lock, flags);
    {
        struct mm_struct *mms[NRC_MAX_SLOTS];
        int nm = 0, i;
        spin_lock_irqsave(&g_lock, flags);
        {
            struct nrc_slot *s, *tmp;
            list_for_each_entry_safe(s, tmp, &g_slots, list) {
                list_del(&s->list);
                g_nr--;
                nrc_write_pte_raw(s->mm, s->va, s->pte_tmpl);
                nrc_tlb_flush_va(s->mm, s->va);
                __free_page(s->pg_shadow);
                if (nm < NRC_MAX_SLOTS) mms[nm++] = s->mm;
                kfree(s);
            }
        }
        spin_unlock_irqrestore(&g_lock, flags);
        for (i = 0; i < nm; i++) mmdrop(mms[i]);   /* P5-E: 配对 mmgrab */
    }
    pr_info(TAG "exit\n");
}

module_init(nrc_merged_init);
module_exit(nrc_merged_exit);
MODULE_LICENSE("GPL");