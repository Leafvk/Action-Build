#!/usr/bin/env sh
# kcfi_probe.sh — 给另一台机械体检：开了没 KCFI？
# 用法: sh audit_kcfi.sh        (需 root + 能读 /proc/config.gz)
set -u
CFG=""
if [ -r /proc/config.gz ]; then CFG="$(zcat /proc/config.gz 2>/dev/null)"; fi
[ -z "$CFG" ] && CFG="$(grep -E '^CONFIG_' /boot/config* /proc/config* /sys/kernel/debug/config 2>/dev/null)"
echo "=== 内核 ==="; uname -a; echo
echo "=== KCFI 配置（有 CONFIG_CFI_CLANG=y 且无 PERMISSIVE → 必须对齐原型）==="
echo "$CFG" | grep -E '^CONFIG_CFI_(CLANG|PERMISSIVE)' || echo '（读不到 /proc/config.gz 或 grep 为空）'
echo
echo "=== modversions / 签名 / 锁定 ==="
echo "$CFG" | grep -E '^CONFIG_MODVERSIONS=|^CONFIG_MODULE_SIG' || true
echo "kptr_restrict: $(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)"
[ -d /proc/sys/kernel/lockdown ] && echo "lockdown: $(cat /proc/sys/kernel/lockdown 2>/dev/null)"
echo
echo "=== 崩溃日志位置候选 ==="
ls /data/vendor/diag/last_kmsg* /dev/block/by-name/oops /proc/last_kmsg /sys/fs/pstore 2>&1 | head
echo
echo "=== linker64 位置候选 ==="
ls /apex/com.android.runtime/bin/linker64 /system/bin/linker64 2>&1
echo
echo "=== kprobe 可用性（试一个 lookup_sym 的符号能否注册）==="
echo "提示：直接 insmod 一行 'static int __init i(void){struct kprobe k={.symbol_name=\"vmalloc\"};int r=register_kprobe(&k);unregister_kprobe(&k);return r;}' 看返回"