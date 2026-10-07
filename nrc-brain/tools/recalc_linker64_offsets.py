#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recalc_linker64_offsets.py —— NRC 内核注入 · 机型相关偏移现场重算工具

算两个量（随 linker64 版本变化，禁止复用旧值）:
  GAP_FOFF    : r-x 段 shellcode 落点。取 r-x 段末尾零填充区起点,
                需满足 gap + SC_LEN(0x100) <= r-x vma 内存末尾(页对齐后)。
  DLOPEN_FOFF : 动态符号 __loader_dlopen 的文件偏移。

用法:
  # 1) 设备上抓一份当前 linker64(路径随系统版本可能不同, 先 ls 确认)
  #    adb/sh: cp /apex/com.android.runtime/bin/linker64 /data/local/tmp/linker64.now
  # 2) 在 Ubuntu 环境跑:
  python3 recalc_linker64_offsets.py /data/local/tmp/linker64.now

输出末尾直接给出两行 #define，复制进 core_r96.c 覆盖旧值即可。
"""

import struct
import sys

SC_LEN = 0x100
PAGE = 0x1000


def parse_elf(path):
    d = open(path, "rb").read()
    assert d[:4] == b"\x7fELF" and d[4] == 2, "not a 64-bit ELF"
    e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", d, 0x36)[0]
    e_phnum = struct.unpack_from("<H", d, 0x38)[0]
    ph = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from("<II", d, o)
        p_off, p_va, _, p_fsz, p_msz = struct.unpack_from("<QQQQQ", d, o + 8)
        ph.append(dict(type=p_type, flags=p_flags, off=p_off, va=p_va,
                       fsz=p_fsz, msz=p_msz))
    return d, ph


def round_up(x, a):
    return (x + a - 1) // a * a


def pick_rx_text_gap(d, ph):
    """r-x PT_LOAD: 段文件末尾之后到页对齐内存末尾之间的零填充区起点。"""
    best = None
    for p in ph:
        if p["type"] != 1 or not (p["flags"] & 1):
            continue
        seg_file_end = p["off"] + p["fsz"]          # 代码/数据结束(文件)
        vma_mem_end = p["off"] + round_up(p["msz"], PAGE)  # vma 内存末尾(相对 base)
        tail = vma_mem_end - seg_file_end           # 零填充可用区长度
        if tail < SC_LEN:
            continue
        # 起点再往后靠: 文件中该段末尾可能已有若干零字节, 取最后一个非零之后
        # 但保守起见直接以 seg_file_end 为起点(该处必然已是零填充)。
        cand = seg_file_end
        if best is None or tail > best["tail"]:
            best = dict(gap=cand, tail=tail, seg=p, mem_end=vma_mem_end,
                        file_end=seg_file_end)
    return best


def dynsym_info(d, ph):
    dyn = [p for p in ph if p["type"] == 2]
    if not dyn:
        return None
    o, sz = dyn[0]["off"], dyn[0]["fsz"]

    def v2o(v):
        for p in ph:
            if p["type"] == 1 and p["va"] <= v < p["va"] + p["fsz"]:
                return p["off"] + (v - p["va"])
        return None

    symtab = strtab = None
    syment = 24
    i = 0
    while i < sz:
        tag, val = struct.unpack_from("<qQ", d, o + i)
        if tag == 0:
            break
        if tag == 6:
            symtab = val
        elif tag == 5:
            strtab = val
        elif tag == 11:
            syment = val
        i += 16
    if symtab is None or strtab is None:
        return None
    return v2o(symtab), v2o(strtab), syment


def find_sym(d, ph, name):
    info = dynsym_info(d, ph)
    if not info:
        return None
    so, to, syment = info
    if so is None or to is None:
        return None
    i = 0
    while so + (i + 1) * syment <= len(d):
        o = so + i * syment
        st_name = struct.unpack_from("<I", d, o)[0]
        st_value = struct.unpack_from("<Q", d, o + 8)[0]
        ns = to + st_name
        if ns >= len(d):
            break
        ne = d.find(b"\x00", ns)
        if ne < 0:
            break
        if d[ns:ne].decode("ascii", "replace") == name:
            return st_value
        i += 1
    return None


def vaddr_to_off(ph, v):
    for p in ph:
        if p["type"] == 1 and p["va"] <= v < p["va"] + p["fsz"]:
            return p["off"] + (v - p["va"])
    return None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/data/local/tmp/linker64.now"
    d, ph = parse_elf(path)
    print("== %s ==" % path)
    print("size = %d (0x%X)\n" % (len(d), len(d)))

    print("-- PT_LOAD --")
    for p in ph:
        if p["type"] == 1:
            f = ("R" if p["flags"] & 4 else "-") + \
                ("W" if p["flags"] & 2 else "-") + \
                ("X" if p["flags"] & 1 else "-")
            print("  %s off=0x%-7X va=0x%-7X fsz=0x%-7X msz=0x%X"
                  % (f, p["off"], p["va"], p["fsz"], p["msz"]))
    print()

    ok = True

    g = pick_rx_text_gap(d, ph)
    if g:
        print("-- GAP_FOFF (r-x 末尾零填充落点) --")
        print("  code_end(file)   = 0x%X" % g["file_end"])
        print("  vma_end(mem,rel) = 0x%X" % g["mem_end"])
        print("  usable_tail      = 0x%X (%d B)" % (g["tail"], g["tail"]))
        print("  -> GAP_FOFF      = 0x%X" % g["gap"])
        if g["gap"] + SC_LEN > g["mem_end"]:
            print("  !! FAIL: gap+0x%X 超出 r-x vma" % SC_LEN)
            ok = False
        else:
            print("  ok: gap+0x%X (=0x%X) <= vma_end"
                  % (SC_LEN, g["gap"] + SC_LEN))
    else:
        print("-- GAP_FOFF: NOT FOUND (无 >=0x%X 的零填充尾部!) --" % SC_LEN)
        ok = False
    print()

    v = find_sym(d, ph, "__loader_dlopen")
    if v is not None:
        fo = vaddr_to_off(ph, v)
        print("-- DLOPEN_FOFF --")
        print("  __loader_dlopen va = 0x%X  file_off = 0x%X" % (v, fo))
    else:
        print("-- DLOPEN_FOFF: __loader_dlopen NOT FOUND --")
        ok = False
    print()

    print("-- 建议写入 core_r96.c --")
    if g:
        print("  #define GAP_FOFF      0x%XUL" % g["gap"])
    if v is not None:
        print("  #define DLOPEN_FOFF   0x%XUL" % fo)
    print()
    print("* 偏移随 linker64 版本变化; 每次换内核/系统更新后必须重跑本脚本。")
    print("* SC_LEN 若改动, 请同步修改本脚本常量。")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
