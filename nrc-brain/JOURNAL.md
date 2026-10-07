# NRC 内核适配 · 共享大脑（JOURNAL）

> **用途**：三台手机共同维护的 append-only 流水账。
> 任何一台机做完适配/踩完坑，都往这里追加一条。另两台 `git pull` 即同步。
> 这是记忆跨设备可用的**唯一可靠载体**——因为 Operit 的记忆库是二进制（ObjectBox `data.mdb`），直接拷会打架。

---
## 格式约定（每条一段，倒序追加到"记录"区顶部）

```
### [<日期>][<机型>] <一句话标题>
- 内核: <uname -r>
- 结论: <做了什么 / 学到什么>
- 坑: <踩到的坑，怎么解>
- 相关文件: <路径>
```

---

## 记录

### [2026-10-07][haotian / Xiaomi 15 Pro] r98c 适配成功——根因是 KCFI，不是偏移
- 内核: 6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k
- 结论: v4.10 成品包（魅族20/5.15.41）适配到本机。真凶是 **kCFI 类型检查失败**：
  `g_va` 声明 2 参 `void *(unsigned long, gfp_t)`，但 `lookup_sym("vmalloc")` 拿到的是 1 参 `void *(unsigned long)`。
  `CONFIG_CFI_CLANG=y` 且无 PERMISSIVE → `brk #0x8228` → `panic_on_oops=1` → 重启。
  修复：改查 2 参的 `__vmalloc(unsigned long, gfp_t)`；并把 VFS 指针首参 `struct user_namespace*` → `struct mnt_idmap*`（调用传 `&nop_mnt_idmap`）。
- 坑:
  1. **偏移只是干扰项**。第一版只修了 linker64 偏移（魅族 0x1208C0/0x381A8 → haotian 0x198070/0x88124）仍重启。别把"排除一个变量"当"找到根因"。
  2. 崩溃日志不在 pstore（空的），在 `/data/vendor/diag/last_kmsg*`。日志行直接点名 `target: vmalloc; expected type: 0x1d7a58e3`。
  3. `-fno-sanitize=cfi` / `cfi-icall` 是**无效写法**，正确名 `-fno-sanitize=kcfi`；且关 CFI 只解决单向，回调方向反而崩。改原型才对。
  4. 旧包不崩 ≠ 代码对：旧版 `g_va` 声明同样是错的，只是旧 action.sh 从不走 krep_inplace。
- 相关文件: `/sdcard/Download/KERNEL_ADAPT_NOTES.md`、`tools/recalc_linker64_offsets.py`、`src/core_r96.c`
- 产物: `NRC-mod-v4.10-haotian6.6.77-r98c.zip`（md5 0133587dbb613a908e0410c0f9a94fa7）

### [2026-10-07][unknownaarch64] haotian r98c 验证通过：KCFI 修复 + 实测哈希对齐
- 内核: 6.6.77-android15-8-gca30f3b4bef6-abogki440974771-4k
- 结论: haotian r98c 验证通过：KCFI 修复 + 实测哈希对齐
- 记录者: unknownaarch64 @ 2026-10-07 17:19:38
