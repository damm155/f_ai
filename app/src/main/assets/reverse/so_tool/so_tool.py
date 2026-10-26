#!/usr/bin/env python3
"""FBox SO 原生库分析工具（python3-pyelftools + capstone，只读分析，不修改文件）。

容器内统一入口，由 Android 侧 LinuxViewModel 经 shell 调用：
    python3 /root/so-tool/so_tool.py <子命令> <参数...>

与 patch_so 协同：so_symbols / so_jni / so_disasm 产出的函数虚拟地址，
可直接作为 patch_so 的 address 参数打 asm/hex 补丁。

子命令一览（输出统一为 UTF-8 文本，✓/✗ 标记成败，供 AI 直接阅读）：
  info <so>                       ELF 摘要：架构/PIE/NX/RELRO/节区/依赖库
  symbols <so> [grep]             函数符号清单（地址+大小+名字，Java_ 静态注册在内）
  jni <so>                        定位 RegisterNatives 动态注册（Java方法名+签名+函数地址）
  disasm <so> <addr|符号> [len]   反汇编（capstone，默认 64 字节，上限 4096）
  cfg <so> <addr|符号> [len]      单函数控制流图（基本块 + 分支边，默认按符号 size 或首个 ret 截断）
  strings <so> [min_len] [grep]   字符串提取（带虚拟地址+文件偏移）

addr 支持 0x 十六进制（不带 0x 也按十六进制解析）或符号名；len 按十进制。
so 路径为容器内绝对路径（如 /root/out/libxxx.so 或 /root/apk/xxx/lib/arm64-v8a/libxxx.so）。
"""
import os
import re
import sys
import json
import shutil

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    sys.exit("✗ 缺少 python3-pyelftools：容器内执行 apt-get install -y python3-pyelftools 后重试")

try:
    import capstone
except ImportError:
    capstone = None  # 仅 disasm 子命令需要

MAX_HITS = 200          # symbols/strings 输出上限，防大 so 刷屏
MAX_DISASM = 4096       # disasm 单次最大字节数
MAX_STR_LEN = 256       # C 字符串读取上限
DEFAULT_DISASM_LEN = 64

SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

# R_*_RELATIVE 重定位类型值（按架构）
RELATIVE_TYPE = {
    "EM_AARCH64": 1027,
    "EM_X86_64": 8,
    "EM_ARM": 23,
    "EM_386": 42,
}

MACHINE_LABEL = {
    "EM_AARCH64": "AArch64 (arm64)",
    "EM_ARM": "ARM (32位)",
    "EM_X86_64": "x86_64",
    "EM_386": "x86 (32位)",
}


def so_path(name: str) -> str:
    # 先按原样探测（本地调试/相对 cwd 场景），再按容器根路径语义解析
    if os.path.isfile(name):
        return name
    p = name if name.startswith("/") else "/" + name.lstrip("/")
    if not os.path.isfile(p):
        sys.exit("✗ SO 不存在: %s（可用 run_terminal_command: find /root -name '*.so' 定位）" % p)
    return p


def parse_addr(s: str) -> int:
    """地址一律十六进制（0x 前缀可选）。"""
    try:
        return int(s, 16)
    except ValueError:
        sys.exit("✗ 无效地址: %s（十六进制，如 0x12340）" % s)


def parse_len(s: str) -> int:
    """长度按十进制。"""
    try:
        return int(s, 10)
    except ValueError:
        sys.exit("✗ 无效长度: %s（十进制字节数）" % s)


class SoCtx:
    """ELF 上下文缓存：ALLOC 节表 + 双符号表 + 文件句柄。"""

    def __init__(self, path: str):
        self.path = path
        self.f = open(path, "rb")
        self.elf = ELFFile(self.f)
        self.machine = self.elf.header["e_machine"]
        self.bits = self.elf.elfclass
        # 可加载节缓存: [(addr, size, file_off, name, flags)]
        self.maps = []
        for sec in self.elf.iter_sections():
            fl = sec["sh_flags"]
            if fl & SHF_ALLOC and sec["sh_size"] > 0:
                self.maps.append((sec["sh_addr"], sec["sh_size"], sec["sh_offset"], sec.name, fl))
        # 回退：加固 SO 常抹掉/伪造节区表（SHF_EXECINSTR 缺失 → is_exec 恒 False，
        # disasm/strings 全废）。此时改由程序头 PT_LOAD 段重建映射，p_flags 映射到
        # SHF_* 语义（PF_X→EXECINSTR / PF_W→WRITE / PF_R→ALLOC），节名统一记 "LOAD"。
        if not any(m[4] & SHF_EXECINSTR for m in self.maps):
            self._build_maps_from_segments()
        # 符号表: {name: (addr, size)} 与按地址排序的 [(addr, size, name)]
        self.sym_by_name = {}
        self.sym_by_addr = []
        self._load_symbols()

    def _build_maps_from_segments(self):
        """节区表不可信时，按 PT_LOAD 程序头重建 vaddr→file_off 映射。"""
        segs = []
        for seg in self.elf.iter_segments():
            if seg["p_type"] != "PT_LOAD" or seg["p_filesz"] == 0:
                continue
            flags = 0
            pf = seg["p_flags"]
            if pf & PF_R:
                flags |= SHF_ALLOC
            if pf & PF_W:
                flags |= SHF_WRITE
            if pf & PF_X:
                flags |= SHF_EXECINSTR
            segs.append((seg["p_vaddr"], seg["p_filesz"], seg["p_offset"], "LOAD", flags))
        # PT_LOAD 段按 vaddr 升序排列，便于 find() 命中
        segs.sort(key=lambda m: m[0])
        if segs:
            self.maps = segs

    def _load_symbols(self):
        seen = set()
        for sname in (".symtab", ".dynsym"):
            sec = self.elf.get_section_by_name(sname)
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                if sym["st_info"]["type"] != "STT_FUNC" or sym["st_shndx"] == "SHN_UNDEF":
                    continue
                addr, size, name = sym["st_value"], sym["st_size"], sym.name
                if not name or addr == 0 or (addr, name) in seen:
                    continue
                seen.add((addr, name))
                self.sym_by_name[name] = (addr, size)
                self.sym_by_addr.append((addr, size, name))
        self.sym_by_addr.sort()

    def find(self, vaddr: int):
        """虚拟地址 → (节 addr, size, file_off, name) 或 None。"""
        for m in self.maps:
            if m[0] <= vaddr < m[0] + m[1]:
                return m
        return None

    def vaddr_to_off(self, vaddr: int):
        m = self.find(vaddr)
        if m is None:
            return None, None
        return m[2] + (vaddr - m[0]), m[3]

    def is_exec(self, vaddr: int) -> bool:
        m = self.find(vaddr)
        return m is not None and (m[4] & SHF_EXECINSTR) != 0

    def read(self, vaddr: int, size: int) -> bytes:
        off, _ = self.vaddr_to_off(vaddr)
        if off is None:
            return b""
        self.f.seek(off)
        return self.f.read(size)

    def read_cstr(self, vaddr: int, maxlen: int = MAX_STR_LEN):
        """按虚拟地址读 C 字符串，非可打印 ASCII 返回 None。"""
        b = self.read(vaddr, maxlen)
        if not b:
            return None
        i = b.find(b"\x00")
        if i >= 0:
            b = b[:i]
        if not b:
            return None
        try:
            s = b.decode("ascii")
        except UnicodeDecodeError:
            return None
        if not all(0x20 <= ord(c) <= 0x7E for c in s):
            return None
        return s

    def symbolize(self, vaddr: int):
        """地址符号化：精确命中或落在符号体内 → (name, offset)；否则 (None, 0)。"""
        lo, hi = 0, len(self.sym_by_addr)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.sym_by_addr[mid][0] <= vaddr:
                lo = mid + 1
            else:
                hi = mid
        for i in (lo - 1, lo - 2):
            if 0 <= i < len(self.sym_by_addr):
                addr, size, name = self.sym_by_addr[i]
                if addr <= vaddr < addr + max(size, 4):
                    return name, vaddr - addr
        return None, 0


# ---------------------------------------------------------------- 子命令实现

def cmd_info(args):
    ctx = SoCtx(so_path(args[0]))
    hdr = ctx.elf.header
    etype = hdr["e_type"]
    machine = MACHINE_LABEL.get(ctx.machine, ctx.machine)

    # NX：PT_GNU_STACK 段存在且不含 X → 启用
    nx = "未知（无 PT_GNU_STACK 段，栈默认可执行）"
    relro_seg = False
    for seg in ctx.elf.iter_segments():
        pt = seg["p_type"]
        if pt == "PT_GNU_STACK":
            nx = "启用" if (seg["p_flags"] & PF_X) == 0 else "✗ 禁用（栈可执行）"
        elif pt == "PT_GNU_RELRO":
            relro_seg = True

    # RELRO：GNU_RELRO + BIND_NOW → Full
    bind_now = False
    needed = []
    for seg in ctx.elf.iter_segments():
        if seg["p_type"] != "PT_DYNAMIC":
            continue
        for tag in seg.iter_tags():
            dt = tag.entry.d_tag
            if dt == "DT_NEEDED":
                needed.append(tag.needed)
            elif dt == "DT_BIND_NOW":
                bind_now = True
            elif dt == "DT_FLAGS" and (tag.entry.d_val & 0x8):
                bind_now = True
            elif dt == "DT_FLAGS_1" and (tag.entry.d_val & 0x1):
                bind_now = True
    if relro_seg and bind_now:
        relro = "Full（GNU_RELRO + BIND_NOW）"
    elif relro_seg:
        relro = "Partial（GNU_RELRO，无 BIND_NOW）"
    else:
        relro = "无"

    print("✓ ELF 摘要: %s" % ctx.path)
    print("  架构: %s，%d 位，%s端" % (machine, ctx.bits, "小" if ctx.elf.little_endian else "大"))
    print("  类型: %s%s" % (etype, "（PIE/共享库）" if etype == "ET_DYN" else "（固定地址可执行）"))
    print("  NX: %s" % nx)
    print("  RELRO: %s" % relro)
    print("  函数符号: %d 个（.symtab %s / .dynsym %s）" % (
        len(ctx.sym_by_addr),
        "有" if isinstance(ctx.elf.get_section_by_name(".symtab"), SymbolTableSection) else "已 strip",
        "有" if isinstance(ctx.elf.get_section_by_name(".dynsym"), SymbolTableSection) else "无"))
    if needed:
        print("  依赖库 (DT_NEEDED): %s" % ", ".join(needed))

    # 节区表（全部列出，超 40 个截断）
    print("  节区（%d 个，S=可写 X=可执行）:" % len(list(ctx.elf.iter_sections())))
    lines = []
    for m in sorted(ctx.maps, key=lambda x: x[0]):
        fl = ("W" if m[4] & SHF_WRITE else "-") + ("X" if m[4] & SHF_EXECINSTR else "-")
        lines.append("    %-20s 0x%08x-0x%08x (0x%x) [%s]" % (m[3], m[0], m[0] + m[1], m[1], fl))
    for ln in lines[:40]:
        print(ln)
    if len(lines) > 40:
        print("    …（其余 %d 个省略）" % (len(lines) - 40))


def cmd_symbols(args):
    ctx = SoCtx(so_path(args[0]))
    pat = args[1] if len(args) > 1 else ""
    rx = re.compile(pat, re.IGNORECASE) if pat else None

    hits = []
    for addr, size, name in ctx.sym_by_addr:
        if rx is None or rx.search(name):
            hits.append((addr, size, name))

    if not hits:
        tail = "（过滤: %s）" % pat if pat else ""
        sys.exit("✗ 无匹配函数符号%s。so 可能已 strip，可用 so_jni 定位动态注册，或 so_strings 搜字符串。" % tail)

    print("✓ 函数符号（%d 个%s）:" % (len(hits), ("，过滤: %s" % pat) if pat else ""))
    java_n = 0
    for addr, size, name in hits[:MAX_HITS]:
        tag = ""
        if name.startswith("Java_"):
            java_n += 1
            tag = "  ← Java静态注册"
        print("  0x%08x  0x%-6x %s%s" % (addr, size, name, tag))
    if java_n:
        print("✓ 其中 Java_ 静态注册 %d 个（JNI 命名规则可直接对应 Java native 方法）" % java_n)
    if len(hits) > MAX_HITS:
        print("…（共 %d 个，仅显示前 %d，请用 grep 参数收窄）" % (len(hits), MAX_HITS))
    print("提示: 地址可直接作为 patch_so 的 address 参数。")


def _collect_relative(ctx):
    """收集 R_*_RELATIVE 重定位: {字段虚拟地址: 指针值}。"""
    rtype = RELATIVE_TYPE.get(ctx.machine)
    if rtype is None:
        return None
    out = {}
    for sec in ctx.elf.iter_sections():
        if not isinstance(sec, RelocationSection) or not sec.is_RELA():
            continue
        for rel in sec.iter_relocations():
            if rel["r_info_type"] == rtype:
                out[rel["r_offset"]] = rel["r_addend"]
    return out


def cmd_jni(args):
    """定位 RegisterNatives 动态注册。

    原理：PIE so 中 JNINativeMethod{name*, sig*, fnPtr} 数组位于 .data.rel.ro，
    三个指针槽全部由 R_*_RELATIVE 重定位填充（addend=目标虚拟地址）。
    滑窗扫描三连槽：name/sig 指向合法 C 字符串（签名形如 "(...)..."），
    fn 指向可执行节 → 判定为一条 JNINativeMethod。
    """
    ctx = SoCtx(so_path(args[0]))
    if ctx.machine not in RELATIVE_TYPE:
        sys.exit("✗ 暂不支持该架构: %s（支持 AArch64/x86_64/ARM/x86）" % ctx.machine)

    reloc = _collect_relative(ctx)
    slot = ctx.bits // 8
    # JNINativeMethod 数组所在候选节
    cand = [m for m in ctx.maps if m[3] in (".data.rel.ro", ".data.rel.ro.local", ".data")]

    hits = []
    if reloc:
        for m in cand:
            base, size, off, name, _ = m
            ctx.f.seek(off)
            buf = ctx.f.read(size)
            for i in range(0, len(buf) - 3 * slot + 1, slot):
                p_name = reloc.get(base + i)
                p_sig = reloc.get(base + i + slot)
                p_fn = reloc.get(base + i + 2 * slot)
                if p_name is None or p_sig is None or p_fn is None:
                    continue
                if _try_jni_entry(ctx, p_name, p_sig, p_fn, hits):
                    pass
    else:
        # 非 PIE（ET_EXEC）：指针直接裸编码在数据节
        if ctx.elf.header["e_type"] != "ET_EXEC":
            sys.exit("✗ 未找到 RELATIVE 重定位，无法扫描")
        import struct
        fmt = "<Q" if ctx.bits == 64 else "<I"
        for m in cand:
            base, size, off, name, _ = m
            ctx.f.seek(off)
            buf = ctx.f.read(size)
            for i in range(0, len(buf) - 3 * slot + 1, slot):
                p_name = struct.unpack_from(fmt, buf, i)[0]
                p_sig = struct.unpack_from(fmt, buf, i + slot)[0]
                p_fn = struct.unpack_from(fmt, buf, i + 2 * slot)[0]
                if _try_jni_entry(ctx, p_name, p_sig, p_fn, hits):
                    pass

    if not hits:
        sys.exit("✗ 未发现 RegisterNatives 动态注册（可能全部用 Java_ 静态注册，或 so 加固/加密）。\n"
                 "  建议先 so_symbols 查 Java_ 前缀导出；加固 so 可查 so_info 依赖与节区是否异常。")

    print("✓ RegisterNatives 动态注册（%d 个，扫描 .data.rel.ro/.data 三连指针槽）:" % len(hits))
    for nm, sig, fn in hits:
        sym, off2 = ctx.symbolize(fn)
        where = sym if (sym and off2 == 0) else ((sym + "+0x%x" % off2) if sym else "")
        print("  %-28s %-28s → 0x%08x %s" % (nm, sig, fn, ("(%s)" % where) if where else ""))
    print("提示: fn 地址可直接作为 patch_so 的 address 参数（RET 置零类补丁同静态注册一致）。")


def _try_jni_entry(ctx, p_name, p_sig, p_fn, hits):
    """校验三元组是否合法 JNINativeMethod，命中则追加到 hits。"""
    if p_name == p_sig or p_name == p_fn or p_sig == p_fn:
        return False
    name = ctx.read_cstr(p_name)
    if not name or len(name) > 128 or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        return False
    sig = ctx.read_cstr(p_sig, 64)
    # JNI 方法签名: "(" 参数 ")" 返回类型，字符集受限
    if not sig or not re.fullmatch(r"\([ZBCSIJFDLV\[]*\)(V|[ZBCSIJFDL\[])", sig):
        return False
    if not ctx.is_exec(p_fn):
        return False
    hits.append((name, sig, p_fn))
    return True


def _resolve_addr(ctx, target):
    """地址解析：符号名优先（含模糊匹配），否则按十六进制（0x 前缀可选）。
    返回 (addr, label)；label 为空串表示纯地址。"""
    if target in ctx.sym_by_name:
        return ctx.sym_by_name[target][0], target
    if re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+", target):
        addr = parse_addr(target)
        sym, _ = ctx.symbolize(addr)
        return addr, sym or ""
    cand = [(a, s, n) for a, s, n in ctx.sym_by_addr if target in n]
    if not cand:
        sys.exit("✗ 无法解析目标: %s（既非十六进制地址也非已知符号）" % target)
    addr, _, label = cand[0]
    if len(cand) > 1:
        print("ℹ 符号模糊匹配 %d 个，取第 1 个: %s（其余: %s）" % (
            len(cand), label, ", ".join(n for _, _, n in cand[1:4])))
    return addr, label


def cmd_disasm(args):
    if capstone is None:
        sys.exit("✗ 缺少 python3-capstone：容器内执行 apt-get install -y python3-capstone 后重试")
    ctx = SoCtx(so_path(args[0]))
    target = args[1]
    size = parse_len(args[2]) if len(args) > 2 else DEFAULT_DISASM_LEN
    if size <= 0 or size > MAX_DISASM:
        sys.exit("✗ 长度超限: %d（1-%d 字节）" % (size, MAX_DISASM))

    addr, label = _resolve_addr(ctx, target)
    if not ctx.is_exec(addr):
        sec = ctx.find(addr)
        sys.exit("✗ 0x%x 不在可执行节（落在 %s）。请核对地址或用 so_symbols 查符号。" % (addr, sec[3] if sec else "未映射区域"))

    md = _make_disassembler(ctx)
    code = ctx.read(addr, size)
    if not code:
        sys.exit("✗ 读取 0x%x 处 %d 字节失败（节边界溢出？）" % (addr, size))

    where = ("(%s)" % label) if label else ""
    print("✓ 反汇编 %s @ 0x%x %s（%d 字节）:" % (os.path.basename(ctx.path), addr, where, len(code)))
    for insn in md.disasm(code, addr):
        note = ""
        mn, op = insn.mnemonic, insn.op_str
        # Debian apt 版 python3-capstone 的 mnemonic/op_str 返回 bytes（pip 版返回 str），
        # 统一转 str，否则真机输出会带 b'' 前缀
        if isinstance(mn, bytes):
            mn = mn.decode("utf-8", "replace")
        if isinstance(op, bytes):
            op = op.decode("utf-8", "replace")
        # 分支/调用目标符号化注释
        if mn in ("bl", "b", "blr") and op.startswith("#"):
            try:
                t = int(op[1:], 16)
                s2, o2 = ctx.symbolize(t)
                if s2:
                    note = "   ; → %s%s" % (s2, ("+0x%x" % o2) if o2 else "")
            except ValueError:
                pass
        print("  0x%08x: %-12s %-8s %s%s" % (insn.address, insn.bytes.hex(), mn, op, note))
    print("提示: 可用 patch_so 在任意上述地址打 asm/hex 补丁。")


def _make_disassembler(ctx):
    if ctx.machine == "EM_AARCH64":
        return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    if ctx.machine == "EM_X86_64":
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    if ctx.machine == "EM_386":
        return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    if ctx.machine == "EM_ARM":
        # ARM32 Thumb 位由地址 bit0 决定，交给 symbolize/调用方保证对齐
        return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_LITTLE_ENDIAN)
    sys.exit("✗ 暂不支持反汇编该架构: %s" % ctx.machine)


def cmd_strings(args):
    ctx = SoCtx(so_path(args[0]))
    min_len = 6
    if len(args) > 1:
        try:
            min_len = int(args[1], 10)
        except ValueError:
            sys.exit("✗ 无效 min_len: %s（十进制）" % args[1])
    if min_len < 4 or min_len > 64:
        sys.exit("✗ min_len 超限（4-64）: %d" % min_len)
    pat = args[2] if len(args) > 2 else ""
    rx = re.compile(pat, re.IGNORECASE) if pat else None

    lines = []
    for m in sorted(ctx.maps, key=lambda x: x[0]):
        if len(lines) >= MAX_HITS:
            break
        ctx.f.seek(m[2])
        data = ctx.f.read(m[1])
        for mo in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
            s = mo.group().decode("ascii")
            if rx is not None and not rx.search(s):
                continue
            off = m[2] + mo.start()
            vaddr = m[0] + mo.start()
            lines.append("  0x%08x (文件 0x%08x) [%s] %s" % (vaddr, off, m[3], s))
            if len(lines) >= MAX_HITS:
                lines.append("…（达到上限 %d 条，请用 grep 参数收窄或提高 min_len）" % MAX_HITS)
                break

    if not lines:
        tail = "（过滤: %s）" % pat if pat else ""
        sys.exit("✗ 无匹配字符串%s。可降低 min_len 或去掉 grep 重试。" % tail)
    tail = ("，过滤: %s" % pat) if pat else ""
    print("✓ 字符串提取 %d 条（min_len=%d%s）" % (len(lines), min_len, tail))
    print("\n".join(lines))


# 无条件跳转 / 返回类助记符（划分块尾 + 终止后继）
_JUMP_MN = {"b", "br", "jmp", "ret", "retq", "bx", "brk"}
# 条件分支助记符（块尾 + 条件后继 + fallthrough 后继）
_COND_MN = {
    "b.eq", "b.ne", "b.cs", "b.hs", "b.cc", "b.lo", "b.mi", "b.pl", "b.vs", "b.vc",
    "b.hi", "b.ls", "b.ge", "b.lt", "b.gt", "b.le", "b.al", "b.nv",
    "cbz", "cbnz", "tbz", "tbnz",
    "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe",
    "jo", "jno", "js", "jns", "jp", "jpe", "jnp", "jpo", "jc", "jcxz", "jecxz", "jrcxz",
    "beq", "bne", "bcs", "bhs", "bcc", "blo", "bmi", "bpl", "bvs", "bvc",
    "bhi", "bls", "bge", "blt", "bgt", "ble",
}
# 调用类（作为块尾边界但不改控制流，尾调用除外）
_CALL_MN = {"bl", "blr", "call", "callq"}


def _branch_target(insn, machine):
    """提取分支指令的绝对跳转目标地址；无则返回 None。

    capstone 对 ARM64/ARM 的 b/cbz 等给出 IMM 操作数（绝对地址），
    对 x86 的 jmp/je 给出相对偏移（imm 是相对值），需用 size+address 校正为绝对地址。
    统一用通用常量 CS_OP_IMM 判断操作数类型，避免依赖 capstone.arm64/x86 子模块
    （Debian apt 打包的 python3-capstone 可能裁剪这些子模块导入）。
    """
    if not insn.operands:
        return None
    op0 = insn.operands[0]
    if op0.type != capstone.CS_OP_IMM:
        return None
    if machine in ("EM_X86_64", "EM_386"):
        # x86 相对跳转：目标 = 下一条指令地址 + imm
        return insn.address + insn.size + op0.imm
    return op0.imm


def _build_cfg(ctx, addr, size_hint):
    """线性反汇编函数体，产出基本块与边。

    返回 (blocks, edges)：
      blocks = [(id, start_addr, end_addr, insns)]  insns 为 [(addr, mnemonic, op_str)]
      edges  = [(from_id, to_id, kind)]  kind: 'fall'/'branch'/'cond'
    """
    md = _make_disassembler(ctx)
    md.detail = True
    # 符号有 size 时精确限定；否则按 size_hint，再截到首个 ret
    end = addr + size_hint if size_hint else None
    sym, _ = ctx.symbolize(addr)
    if sym:
        s_addr, s_size = ctx.sym_by_name.get(sym, (addr, 0))
        if s_size:
            end = s_addr + s_size

    code = ctx.read(addr, max(end - addr, 64) if end else 64)
    if not code:
        sys.exit("✗ 读取 0x%x 处代码失败" % addr)
    if end:
        code = code[:end - addr]

    insns = []          # 线性反汇编全部指令
    leaders = {0}       # 基本块起始的 code offset（相对 addr）
    for insn in md.disasm(code, addr):
        off = insn.address - addr
        mn = insn.mnemonic
        if isinstance(mn, bytes):
            mn = mn.decode("utf-8", "replace")
        op_str = insn.op_str
        if isinstance(op_str, bytes):
            op_str = op_str.decode("utf-8", "replace")
        insns.append((insn.address, mn, op_str, insn))
        # 分支目标作为新的 leader
        t = _branch_target(insn, ctx.machine)
        if t is not None:
            toff = t - addr
            if 0 <= toff < len(code):
                leaders.add(toff)
        # 分支/返回/调用后的下一条指令是新块起始
        if mn in _JUMP_MN or mn in _COND_MN or mn in _CALL_MN:
            nxt = off + insn.size
            if nxt < len(code):
                leaders.add(nxt)
        # 无条件跳转/返回终止线性扫描（后面是另一个函数或数据）
        if mn in _JUMP_MN and mn not in _COND_MN:
            break

    if not insns:
        sys.exit("✗ 0x%x 处反汇编无结果" % addr)

    # 按 leader 切块
    leaders_sorted = sorted(leaders)
    block_ranges = []
    for i, lo in enumerate(leaders_sorted):
        hi = leaders_sorted[i + 1] if i + 1 < len(leaders_sorted) else (insns[-1][0] - addr + insns[-1][3].size)
        block_ranges.append((lo, hi))

    blocks = []
    block_of = {}   # code offset -> block id
    for bid, (lo, hi) in enumerate(block_ranges):
        body = [(a, mn, os_, ins) for a, mn, os_, ins in insns if lo <= (a - addr) < hi]
        if not body:
            continue
        end_addr = body[-1][0] + body[-1][3].size
        blocks.append((bid, body[0][0], end_addr, body))
        for a, _, _, _ in body:
            block_of[a - addr] = bid

    # 建边
    edges = []
    for bid, lo, hi in [(i, r[0], r[1]) for i, r in enumerate(block_ranges)]:
        body = [(a, mn, os_, ins) for a, mn, os_, ins in insns if lo <= (a - addr) < hi]
        if not body:
            continue
        last_insn = body[-1][3]
        mn = body[-1][1]
        t = _branch_target(last_insn, ctx.machine)
        # fallthrough
        if mn not in _JUMP_MN:
            nxt = last_insn.address + last_insn.size - addr
            if nxt in block_of:
                edges.append((bid, block_of[nxt], "cond" if mn in _COND_MN else "fall"))
        # 分支目标
        if t is not None:
            toff = t - addr
            if toff in block_of:
                edges.append((bid, block_of[toff], "cond" if mn in _COND_MN else "branch"))

    return blocks, edges


def cmd_cfg(args):
    if capstone is None:
        sys.exit("✗ 缺少 python3-capstone：容器内执行 apt-get install -y python3-capstone 后重试")
    ctx = SoCtx(so_path(args[0]))
    target = args[1]
    size_hint = parse_len(args[2]) if len(args) > 2 else 0

    addr, label = _resolve_addr(ctx, target)
    if not ctx.is_exec(addr):
        sec = ctx.find(addr)
        sys.exit("✗ 0x%x 不在可执行节（落在 %s）。请核对地址或用 so_symbols 查符号。" % (addr, sec[3] if sec else "未映射区域"))

    blocks, edges = _build_cfg(ctx, addr, size_hint)

    where = ("(%s)" % label) if label else ""
    print("✓ 控制流图 %s @ 0x%x %s（%d 个基本块，%d 条边）:" % (
        os.path.basename(ctx.path), addr, where, len(blocks), len(edges)))
    for bid, start, end, body in blocks:
        print("  BB%d: 0x%08x-0x%08x (%d 条指令)" % (bid, start, end, len(body)))
    print("  边（控制流）:")
    for frm, to, kind in sorted(edges):
        arrow = {"fall": "→", "cond": "?→", "branch": "⇒"}[kind]
        print("    BB%d %s BB%d" % (frm, arrow, to))
    print("提示: 用 so_disasm <so> <addr> 查看某块指令细节；分支目标地址可直接作 patch_so address。")


# ============================================================ 知识库（/root/knowledge/，持久 bind）
# 对齐 FBox 的 save_experience / query_experience。跨会话积累逆向经验，文件格式与 FBox 一致：
#   {id, time, apk, task, summary, details, keywords, result, rate}
# 检索：summary/details/keywords/apk/task 全字段大小写不敏感关键词打分，按命中数排序。

KB_DIR = "/root/knowledge"


def cmd_exp_save(args):
    """exp-save <摘要> [详细过程] [关键词逗号分隔] [apk名] [任务类型] [结果success|failed] [评分1-5]

    例：exp-save "会员状态由 isVip() 控制" "定位: dex-strings 搜 isVip → refs → method 反汇编…" \
        "isVip,vip,会员" "JavDB.apk" "解锁会员" success 5
    """
    if not args:
        sys.exit("✗ 缺少摘要")
    import time as _t
    now = _t.localtime()
    rid = _t.strftime("%Y%m%d_%H%M%S") + ("_%03d" % (_t.time() % 1000))
    rec = {
        "id": rid,
        "time": _t.strftime("%Y-%m-%d %H:%M:%S", now),
        "apk": args[3] if len(args) > 3 else "",
        "task": args[4] if len(args) > 4 else "分析流程",
        "summary": args[0],
        "details": args[1] if len(args) > 1 else "",
        "keywords": args[2] if len(args) > 2 else "",
        "result": (args[5] if len(args) > 5 else "success"),
        "rate": int(args[6]) if len(args) > 6 else 3,
    }
    if rec["result"] not in ("success", "failed"):
        rec["result"] = "success"
    rec["rate"] = max(1, min(5, rec["rate"]))
    os.makedirs(KB_DIR, exist_ok=True)
    path = os.path.join(KB_DIR, rid + ".json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False, indent=1)
    print("✓ 经验已入库：%s（共 %d 条）" % (rid, len(os.listdir(KB_DIR))))
    _finish(0)


def cmd_exp_query(args):
    """exp-query [关键词...]   检索经验（多关键词=OR，按命中字段数排序；无参=最近 10 条）"""
    if not os.path.isdir(KB_DIR):
        print("（知识库为空：%s 不存在）" % KB_DIR)
        _finish(0)
    recs = []
    for fn in os.listdir(KB_DIR):
        if not fn.endswith(".json"):
            continue
        try:
            recs.append(json.load(open(os.path.join(KB_DIR, fn), encoding="utf-8")))
        except Exception:
            pass
    if not recs:
        print("（知识库为空）")
        _finish(0)
    kws = [k.lower() for k in args if k.strip()]
    if kws:
        def score(r):
            hay = " ".join(str(r.get(f, "")) for f in
                           ("summary", "details", "keywords", "apk", "task")).lower()
            return sum(1 for k in kws if k in hay)
        scored = [(score(r), r) for r in recs]
        scored = [t for t in scored if t[0] > 0]
        scored.sort(key=lambda t: (-t[0], t[1].get("time", "")))
        picked = scored
        if not picked:
            print("无命中（%d 条经验里找不到 %s）。可换关键词或省略参数看最近记录。" % (len(recs), " ".join(kws)))
            _finish(0)
    else:
        picked = [(0, r) for r in sorted(recs, key=lambda r: r.get("time", ""), reverse=True)[:10]]
    for sc, r in picked[:10]:
        print("[%s] %s | %s | %s | %s/5" % (
            r.get("result", "?"), r.get("id", "?"), r.get("apk") or "-",
            r.get("task") or "-", r.get("rate", "?")))
        print("  摘要: %s" % r.get("summary", ""))
        if r.get("details"):
            print("  详情: %s" % r["details"][:400])
        if r.get("keywords"):
            print("  关键词: %s" % r["keywords"])
        print()
    _finish(0)


# ---------------------------------------------------------------- 入口

# ============================================================ patch（写字节补丁）

def _parse_patch_arg(spec: str):
    """解析 "地址:hex字节" 补丁项。地址十六进制（0x 可选），字节偶数长 hex。
    示例: 0x1A2B3C:20008052  或  1A2B3C:1F2003D5 (小端指令请自行按字节序给出)
    """
    if ":" not in spec:
        sys.exit("✗ 补丁项格式错误: %r（应为 地址:hex字节，如 0x1A2B3C:20008052）" % spec)
    a, h = spec.split(":", 1)
    addr = parse_addr(a.strip())
    h = h.strip().lower().replace(" ", "")
    if len(h) == 0 or len(h) % 2 != 0:
        sys.exit("✗ hex 字节长度必须为偶数: %r" % h)
    try:
        data = bytes.fromhex(h)
    except ValueError:
        sys.exit("✗ hex 字节不合法: %r" % h)
    return addr, data


def cmd_patch(args):
    """用法: patch <so> <addr:hex>[:addr:hex...] [--dry]

    在 SO 上打字节补丁（虚拟地址自动换算文件偏移，复用 SoCtx 的 PT_LOAD 回退，
    加固 so 也能定位）。默认先写 .orig 备份（幂等，仅首次）：
      <so>.orig   —— 首次 patch 前的原始字节，供回滚（patch --restore <so>）
    多个补丁项以冒号续接；--dry 只显示将改动的内容，不落盘。
    """
    # 回滚分支: patch <so> --restore
    if "--restore" in args[1:]:
        if len(args) != 2:
            sys.exit("✗ --restore 用法: patch <so> --restore")
        cmd_patch_restore(args)
    path = so_path(args[0])
    specs = [a for a in args[1:] if a not in ("--dry", "--restore")]
    if not specs:
        sys.exit("✗ 缺少补丁项（地址:hex字节）")
    dry = "--dry" in args[1:]
    patches = [_parse_patch_arg(sp) for sp in specs]

    ctx = SoCtx(path)

    # 统一先换算并校验，全部通过才动文件
    plan = []
    for addr, data in patches:
        off, sec = ctx.vaddr_to_off(addr)
        if off is None:
            sys.exit("✗ 0x%x 不在任何可加载节（加固 SO 已按 PT_LOAD 重建映射，仍找不到）" % addr)
        old = ctx.read(addr, len(data))
        if len(old) != len(data):
            sys.exit("✗ 0x%x 读取 %d 字节失败（节边界溢出）" % (addr, len(data)))
        plan.append((addr, off, old, data, sec))

    # 展示计划
    print("补丁计划（%s）:" % ("DRY" if dry else "将写入"))
    for addr, off, old, data, sec in plan:
        note = ""
        name, delta = ctx.symbolize(addr)
        if name:
            note = " (%s+0x%x)" % (name, delta)
        print("  0x%-8x → off 0x%-6x [%s]%s  %s → %s" %
              (addr, off, sec or "?", note, old.hex(" "), data.hex(" ")))
    if dry:
        print("（--dry，未写盘）")
        _finish(0)

    # 备份（幂等：只在首次打补丁时留 .orig；之后补丁的基线始终是 .orig）
    orig = path + ".orig"
    if not os.path.isfile(orig):
        shutil.copyfile(path, orig)
        print("✓ 已备份原始文件 → %s" % orig)

    # 写盘（r+ 定位写，不整文件重写）
    with open(path, "r+b") as f:
        for addr, off, old, data, sec in plan:
            f.seek(off)
            f.write(data)
    print("✓ 已写入 %d 处补丁 → %s" % (len(plan), path))
    try:
        rid = _record_patch(path, plan)
        print("✓ 已记入补丁柜：%s（patch-list 查看 / patch-status 改状态 / patch-rollback 回滚）" % rid)
    except Exception as e:
        print("⚠ 补丁柜记录失败（不影响补丁本身）: %s" % e)
    _finish(0)


# ============================================================ 补丁柜（/root/patches/，持久 bind）
# 对齐 FBox 的 list_patches / read_patch / patch_status / rollback_patch / delete_patch。
# 目录结构：/root/patches/<so文件名去扩展>/<时间戳>_<addr>.json
# 记录内容：目标 so、虚拟地址/文件偏移、原始字节、新字节、.orig 路径、状态(active/broken/superseded/failed)、备注

PATCH_CABINET_DIR = "/root/patches"

def _cabinet_dir_for(so_path: str) -> str:
    base = os.path.splitext(os.path.basename(so_path))[0]
    d = os.path.join(PATCH_CABINET_DIR, base)
    os.makedirs(d, exist_ok=True)
    return d


def _record_patch(so_path: str, patches: list) -> str:
    """patch 成功写入后调用：一次记录一条 JSON（一个补丁批次）。返回记录 id。"""
    import time as _t
    ts = _t.strftime("%Y%m%d_%H%M%S")
    d = _cabinet_dir_for(so_path)
    rid = "%s_%s" % (ts, ("_".join("%x" % a for a, *_ in patches[:2]))[:24])
    rec = {
        "id": rid,
        "so": so_path,
        "orig": so_path + ".orig",
        "time": _t.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "active",
        "note": "",
        "patches": [
            {"addr": "0x%x" % a, "offset": "0x%x" % o,
             "old": old.hex(" "), "new": dat.hex(" ")}
            for a, o, old, dat, _sec in patches
        ],
    }
    with open(os.path.join(d, rid + ".json"), "w", encoding="utf-8") as f:
        json.dump(rec, f, ensure_ascii=False, indent=1)
    return rid


def _load_record(rid_or_path: str):
    """按 id 或直接路径读补丁记录。返回 (rec, path) 或 (None, None)。"""
    p = rid_or_path
    if not p.endswith(".json"):
        # 在柜子里搜
        hits = []
        if os.path.isdir(PATCH_CABINET_DIR):
            for sub in os.listdir(PATCH_CABINET_DIR):
                cand = os.path.join(PATCH_CABINET_DIR, sub, rid_or_path + ".json")
                if os.path.isfile(cand):
                    hits.append(cand)
        if not hits:
            return None, None
        p = hits[0]
    if not os.path.isfile(p):
        return None, None
    try:
        return json.load(open(p, encoding="utf-8")), p
    except Exception:
        return None, None


def cmd_patch_list(args):
    """patch-list [so文件名]   列出补丁记录（不传 = 全部）"""
    if not os.path.isdir(PATCH_CABINET_DIR):
        print("（补丁柜为空：%s 不存在）" % PATCH_CABINET_DIR)
        _finish(0)
    subs = sorted(os.listdir(PATCH_CABINET_DIR))
    want = args[0] if args else None
    total = 0
    for sub in subs:
        if want and want not in sub:
            continue
        sdir = os.path.join(PATCH_CABINET_DIR, sub)
        for fn in sorted(os.listdir(sdir)):
            if not fn.endswith(".json"):
                continue
            rec, _ = _load_record(os.path.join(sdir, fn))
            if not rec:
                continue
            total += 1
            addrs = ", ".join(p["addr"] for p in rec["patches"])
            mark = {"active": "●", "broken": "✗", "superseded": "⚪", "failed": "✗"}.get(rec.get("status"), "·")
            print("%s %s  %s  [%s]  %s%s" % (
                mark, rec["id"], rec.get("time", ""),
                rec.get("status", "?"), addrs,
                ("  // " + rec["note"]) if rec.get("note") else ""))
    print(("\n共 %d 条记录" % total) if total else "（无记录）")
    _finish(0)


def cmd_patch_read(args):
    """patch-read <记录id>   查看一条补丁记录详情"""
    rec, path = _load_record(args[0])
    if not rec:
        sys.exit("✗ 找不到补丁记录: %s" % args[0])
    print(json.dumps(rec, ensure_ascii=False, indent=1))
    _finish(0)


def cmd_patch_status(args):
    """patch-status <记录id> <active|broken|superseded|failed> [备注]"""
    rec, path = _load_record(args[0])
    if not rec:
        sys.exit("✗ 找不到补丁记录: %s" % args[0])
    st = args[1]
    if st not in ("active", "broken", "superseded", "failed"):
        sys.exit("✗ 状态必须是 active|broken|superseded|failed")
    rec["status"] = st
    if len(args) > 2:
        rec["note"] = args[2]
    json.dump(rec, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("✓ %s 状态 → %s%s" % (rec["id"], st, ("（" + rec["note"] + "）") if rec.get("note") else ""))
    _finish(0)


def cmd_patch_rollback(args):
    """patch-rollback <记录id|all>   按记录回滚（恢复 .orig 到 so，并清全部该 so 的记录）"""
    if args[0] == "all":
        # 回滚所有记录涉及的 so（按 .orig 恢复，清记录）
        if not os.path.isdir(PATCH_CABINET_DIR):
            sys.exit("✗ 补丁柜为空")
        dones = set()
        for sub in os.listdir(PATCH_CABINET_DIR):
            sdir = os.path.join(PATCH_CABINET_DIR, sub)
            for fn in os.listdir(sdir):
                rec, p = _load_record(os.path.join(sdir, fn))
                if rec and rec["so"] not in dones:
                    orig = rec["orig"]
                    if os.path.isfile(orig):
                        shutil.copyfile(orig, rec["so"])
                        shutil.rmtree(sdir, ignore_errors=True)
                        print("✓ 已回滚 %s（清 %s）" % (rec["so"], sub))
                        dones.add(rec["so"])
        print("完成，共回滚 %d 个 so" % len(dones))
        _finish(0)
    rec, path = _load_record(args[0])
    if not rec:
        sys.exit("✗ 找不到补丁记录: %s" % args[0])
    orig = rec["orig"]
    if not os.path.isfile(orig):
        sys.exit("✗ .orig 备份不存在: %s（无法回滚）" % orig)
    shutil.copyfile(orig, rec["so"])
    sdir = os.path.dirname(path)
    shutil.rmtree(sdir, ignore_errors=True)
    print("✓ 已回滚 %s ← %s（补丁记录已清：%s）" % (rec["so"], orig, sdir))
    _finish(0)


def cmd_patch_delete(args):
    """patch-delete <记录id>   仅删除记录（不动 so）"""
    rec, path = _load_record(args[0])
    if not rec:
        sys.exit("✗ 找不到补丁记录: %s" % args[0])
    os.remove(path)
    sdir = os.path.dirname(path)
    if not os.listdir(sdir):
        os.rmdir(sdir)
    print("✓ 已删除记录 %s（so 未动）" % args[0])
    _finish(0)


def cmd_patch_restore(args):
    """用法: patch --restore <so>   （从 .orig 恢复并删除备份）"""
    path = so_path(args[0])
    orig = path + ".orig"
    if not os.path.isfile(orig):
        sys.exit("✗ 无备份可恢复: %s 不存在（该文件从未打过补丁？）" % orig)
    shutil.copyfile(orig, path)
    os.remove(orig)
    print("✓ 已从 %s 恢复 %s（备份已清）" % (orig, path))
    _finish(0)


COMMANDS = {
    "patch": (cmd_patch, 2, "<so> <addr:hex>[:addr:hex...] [--dry]"),
    "patch-list": (cmd_patch_list, 0, "[so文件名]"),
    "patch-read": (cmd_patch_read, 1, "<记录id>"),
    "patch-status": (cmd_patch_status, 2, "<记录id> <active|broken|superseded|failed> [备注]"),
    "patch-rollback": (cmd_patch_rollback, 1, "<记录id|all>"),
    "patch-delete": (cmd_patch_delete, 1, "<记录id>"),
    "exp-save": (cmd_exp_save, 1, "<摘要> [详情] [关键词] [apk] [任务类型] [success|failed] [评分1-5]"),
    "exp-query": (cmd_exp_query, 0, "[关键词...]"),
    "info": (cmd_info, 1, "<so>"),
    "symbols": (cmd_symbols, 1, "<so> [grep]"),
    "jni": (cmd_jni, 1, "<so>"),
    "disasm": (cmd_disasm, 2, "<so> <addr|符号> [len]"),
    "cfg": (cmd_cfg, 2, "<so> <addr|符号> [len]"),
    "strings": (cmd_strings, 1, "<so> [min_len] [grep]"),
}


def _finish(code):
    """flush 后直接 os._exit：容器 python3-capstone 的 C 库在解释器 teardown 阶段
    会 SIGSEGV（proot 报 signal 11），跳过析构即可规避；本工具只读分析无清理需求。"""
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    finally:
        os._exit(code)


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        print("用法: so_tool.py <子命令> <参数>")
        for k, (_, _, usage) in sorted(COMMANDS.items()):
            print("  %-10s %s" % (k, usage))
        _finish(0)
    cmd = sys.argv[1]
    entry = COMMANDS.get(cmd)
    if entry is None:
        sys.exit("✗ 未知子命令: %s（--help 查看全部）" % cmd)
    fn, argc, usage = entry
    if len(sys.argv) - 2 < argc:
        sys.exit("✗ 参数不足: %s %s" % (cmd, usage))
    try:
        fn(sys.argv[2:])
    except SystemExit as e:
        # sys.exit("✗ 信息") 会到这里：信息打印到 stderr，退出码 1
        if isinstance(e.code, str):
            print(e.code, file=sys.stderr)
            _finish(1)
        _finish(e.code if isinstance(e.code, int) else 0)
    except Exception as e:
        print("✗ %s: %s" % (type(e).__name__, e), file=sys.stderr)
        _finish(1)
    _finish(0)


if __name__ == "__main__":
    main()
