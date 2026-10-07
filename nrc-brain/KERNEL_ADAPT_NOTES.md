# NRC 内核模块适配笔记（haotian 6.6.77 实战总结）

> 目标：把某一机型编好的 ko，移植到另一台内核不同的设备。
> 场景：Xiaomi 15 Pro (haotian) / 6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k
> 结论先行：**最优先的不是"能不能编译过"，而是"每条 lookup_sym 的函数指针原型对不对"。**

---

## 心法（先读这条，能省一天）

工程为调用**非导出**内核函数（vmalloc / vfs_* / notify_change 等多数无 EXPORT_SYMBOL），
采用 `kprobe` 解析符号地址 → 转函数指针 → 强转调用。
这绕过了链接器符号校验与 GKI/KMI 白名单 —— **能调到任何函数，但丢掉编译期类型检查**。

平时没事。一旦内核开了 `CONFIG_CFI_CLANG`（Android 14+ / 6.1+ 基本都开），
这些"无保护间接调用"会被 kCFI 在**运行期**逐个校验，原型差一个类型就 `brk` → panic 重启。

判断要不要担心：
```
zcat /proc/config.gz | grep -E 'CFI_CLANG|CFI_PERMISSIVE'
```
`CFI_CLANG=y` 且 `PERMISSIVE` 未设 → **必须**逐一对齐。

先确认前提：平板内核若禁了 kprobe 或开了 lockdown，`lookup_sym` 全返回 0
→ 不崩但功能全废。先用一条 `lookup_sym("vmalloc")` 试通再往下做。

---

## 阶段 0：三条命门（不匹配 = insmod 直接被拒）

| 项 | 抓取 | 要点 |
|---|---|---|
| vermagic | `cat /proc/version` | 必须**逐字相同**，含 `SMP preempt mod_unload modversions aarch64` 后缀；编时用 `LOCALVERSION=` 精确喂 |
| modversions | `zcat /proc/config.gz \| grep MODVERSIONS` | =y 时符号 CRC 必须匹配；没有目标的 Module.symvers 很难生成正确 CRC |
| 签名 | `grep MODULE_SIG /proc/config.gz` | 非 FORCE 时未签名模块仍可加载 |
| GKI/KMI | 看是否 GKI | GKI 只放行 KMI 白名单符号 —— 这正是本工程要用 kprobe 绕的原因 |

优先级：**先保命**（能加载）→ **再保稳**（别写坏内存）→ **再保活**（别 panic）→ **最后保功能**。

---

## 阶段 1：机型常量（不匹配 = 写坏别人内存 = 崩）

**源码里所有硬编码地址一个都别信，全部本机重算。**

### 1) linker64 偏移（GAP_FOFF / DLOPEN_FOFF）
- 源码写死的是别的机型/Android 版本的值，换机后可能差一倍以上
- 用 `tools/recalc_linker64_offsets.py` 现场重算（本目录下）
- 注意：
  - Android 14+ 是 `/apex/com.android.runtime/bin/linker64`，13 是 `/system/bin/linker64`（常为 symlink，要 realpath）
  - 32 位环境要用 32 位 linker，偏移体系完全不同
  - 要抓**目标注入进程实际加载的那个** linker
  - 校验：gap 必须落在 r-x 段的**页尾零填充区**内，且 `gap + SC_LEN <= vma_end`

### 2) 其它机型量
prctl 号、`do_handle_mm_fault` 探针、`__access_remote_vm` 相关偏移等。

---

## 阶段 2：KCFI 原型对齐（头号杀手）

### 规则（懂这个就不瞎改）
- 哈希**只由参数类型序列决定**；与返回类型、函数名、参数名无关
- **不同结构体指针算不同类型**：`struct mnt_idmap *` ≠ `struct user_namespace *`
- typedef 展开等价即相同：`gfp_t` ≡ `unsigned int`
- **只校验间接调用**（走函数指针），直接调用不检查
- type id 存于函数**入口前 4 字节**的 `.word`，不是入口处

### 做法
1. 列出工程里**所有** `lookup_sym("...")` 的符号
2. 逐个到目标内核头抠真实原型（`grep -rn` 头文件）
3. 把对应函数指针声明改成**逐字一致**（含每个结构体指针类型）
4. 别漏**回调注册**类：`filldir_t`、`break_hook.fn`、`step_hook.fn`
   —— 内核**反过来**用它的原型调你的函数，签名错一样崩

### 本次查获的不匹配（平板大概率同款）

| 符号 | 工程里的错误声明 | 真实原型（6.6.77） |
|---|---|---|
| `vmalloc` | `void *(unsigned long, gfp_t)` | `void *(unsigned long)` ← **崩点**；要 2 参就改调 `__vmalloc(u64, gfp_t)` |
| `vfs_mkdir` / `notify_change` / `vfs_setxattr` / `vfs_unlink` / `vfs_rmdir` | 首参 `struct user_namespace *` | 先进内核是 `struct mnt_idmap *`（调用传 `&nop_mnt_idmap`） |

### 现场测哈希（换机后自己复现，别记死值）
见 `tools/audit_kcfi_proto.py`：写一个探针 C，同时放"模块侧指针声明+调用"和"真实内核函数调用"，
编译后自动提取两者的 kCFI type id 并比对。

单点手测：
```c
#include <linux/module.h>
#include <linux/vmalloc.h>
static void *(*g_va)(unsigned long, gfp_t);
noinline void *useit(unsigned long s){ return g_va(s, GFP_KERNEL); }        // 模块侧调用点
noinline void *def1(unsigned long s, gfp_t g){ return __vmalloc(s, g); }   // 内核侧真实签名
```
编完 `llvm-objdump -d`，看各函数体末尾（下一个函数入口前 4 字节）的 `.word`。
**useit 哈希 == def1 哈希 → 安全；不等 → 必崩。**

### 调试神器
```
echo 0 > /proc/sys/kernel/panic_on_oops
```
`panic_on_oops=1` 时一次 oops 立刻重启、现场全丢。临时关掉能保住现场，调完记得恢复。

### 不要走"关 CFI"这条路（实测无效）
- `-fno-sanitize=cfi` / `cfi-icall` 是**错的写法，不生效**；正确名是 `-fno-sanitize=kcfi`
- 即便关掉，只解决"模块→内核"方向；"内核→模块"的回调（filldir/hook）
  会因你的函数缺 type preamble 而**反而崩**。**改原型才是正解。**

---

## 阶段 3：API 适配（编译期，逐版本不同）

本次 5.15 → 6.6.77 改了 9 处：
- `VMA_ITERATOR` + `for_each_vma` 替代裸 vma 遍历（×3）
- `filldir_t` 返回 `int → bool`（×4）
- ESR 读参 `u32 → unsigned long`（×2）
- 探针 `do_handle_mm_fault` 失败要**降级为非致命 `pr_warn`**，否则 insmod 直接失败

换机若是 4.x/5.x/6.1，**必须对着它的内核头重新 grep**，别照抄。

---

## 阶段 4：构建链

- **modpost**：缺 `Module.symvers` 会报错；可 `KBUILD_MODPOST_WARN=1` + 手工链接绕：
```
ld.lld -r -EL -maarch64elf -z norelro --compress-debug-sections=zstd \
  -z noexecstack --build-id=sha1 -T <kernel>/scripts/module.lds \
  -o out.ko core.o mod.o
```
- `.cmd` 链不全会导致 make 拒绝产出 ko，需凑齐
- **clang 版本要与内核一致**：kCFI 的 type hash 是编译器实现细节，
  跨大版本可能不同 → 全崩。用与内核相同/相近的 clang（AOSP prebuilt）
- `-mbranch-protection`、stack-protector guard offset 由内核 cflags 自带，别手动覆盖

---

## 阶段 5：崩溃取证（日志位置因厂商而异）

**pstore 常常是空的，别只盯一个地方。**

| 位置 | 说明 |
|---|---|
| `/sys/fs/pstore/` | 通用，但常空 |
| `/data/vendor/diag/last_kmsg*` | 高通专用 ← 本次真栈在这 |
| `/dev/block/by-name/oops` | 小米/高通，MTD 环形缓冲（如 16MB，0x200000 一块） |
| `/proc/last_kmsg` | 部分机型（多数 MTK / 旧内核） |
| `/data/system/dropbox/` | SYSTEM_BOOT* 重启记录 |
| `dmesg` | 没重启时最快 |

找法：
```
find /data /dev/block/by-name -iname '*kmsg*' -o -iname '*oops*' 2>/dev/null
```

崩溃行形如：
```
CFI failure at <你的函数>+0x.. (target: <目标函数>; expected type: 0x........)
```
`target` 直接点名**是哪个函数指针**出的问题。其它类型崩溃见
`Internal error: Oops - CFI`、`Unable to handle kernel NULL pointer dereference`。

---

## 阶段 6：免重启验证（省重启次数）

- 先跑**非注入路径**烟测（本次 action=4 双路解密通过后才碰注入）
- 反汇编自检：`llvm-objdump -d out.ko | grep -A6 '<你的函数>:'`
  看 CFI check 的立即数是否 == 目标签名的哈希
- 运行时验证：action=6 做 vma 边界校验、action=7 对牺牲进程 wipe
- 每次**只改一个变量**，改完立刻验

---

## 方法论教训（比技术细节值钱）

1. **旧包不崩 ≠ 代码对**。旧版的同一条声明**同样是错的**，只是旧 `action.sh`
   从不执行那条路径，雷一直埋着；新增一条调用后当场炸。
   "没崩"很可能只是"没走到"。
2. **别把"排除一个可疑变量"当成"找到根因"**。修完偏移就交付 = 逻辑跳步。
3. **原型问题必须全量审计**，修一个崩一个最费时间。
4. **以现场证据为准，别猜**。pstore 空就换地方找；日志里 `target:` 写得明明白白。
5. 优先级：vermagic/签名 → 机型常量 → KCFI 原型 → API → 功能。
